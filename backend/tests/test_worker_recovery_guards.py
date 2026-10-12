"""Public retries must preserve uncertain writes and bounded due work must advance."""

import json
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
import requests
from app.aws import AwsFailure, AwsGateway
from app.database import SessionLocal
from app.models import (
    AwsAccount,
    GroupJob,
    ManagedGroup,
    NativeGroupGrant,
    NativeGroupOperation,
    Proxy,
    RecordOperation,
    Subscription,
    now,
)
from app.security import encrypt
from botocore.exceptions import ClientError
from sqlalchemy import select
from test_account_dispatcher import family_work, sso
from test_lifecycle import LifecycleGateway
from test_native_groups import native as native
from test_native_groups import cancel_group, seed_group, subscribe


def bind_original_proxy():
    with SessionLocal() as db:
        db.add(
            Proxy(
                id=1,
                name="original",
                host="127.0.0.1",
                port=9801,
                auth_encrypted=encrypt({"username": "u", "password": "p"}),
            )
        )
        db.flush()
        db.get(AwsAccount, 1).proxy_id = 1
        db.commit()


def change_proxy(admin, monkeypatch, proxy_id):
    from app import aws
    from app.schemas import AwsInput

    with SessionLocal() as db:
        account = db.get(AwsAccount, 1)
        body = {
            key: getattr(account, key)
            for key in AwsInput.model_fields
            if key not in ("access_key_id", "secret_access_key")
        }
    body["proxy_id"] = proxy_id

    class VerifyOnly:
        def __init__(self, account):
            self.account = account

        def verify(self):
            return self.account.aws_account_id

    with monkeypatch.context() as patch:
        patch.setattr(aws, "AwsGateway", VerifyOnly)
        response = admin.put("/api/admin/aws/1", json=body)
    assert response.status_code == 200, response.text


@pytest.mark.parametrize(
    "kind", ["update_sso", "reset_password", "legacy_ready_update"]
)
def test_public_lifecycle_retry_keeps_original_route(alice, admin, monkeypatch, kind):
    from app.lifecycle import run_operation

    _, rid = family_work("lifecycle", 1, alice)
    bind_original_proxy()
    with SessionLocal() as db:
        db.get(RecordOperation, rid).kind = (
            "update_sso" if kind == "legacy_ready_update" else kind
        )
        db.commit()
    writes, constructions = [], []
    confirmed = False

    class LostReply(LifecycleGateway):
        def __init__(self, account):
            self.account = account
            constructions.append(account.proxy_id)

        def user_info(self, record):
            return {
                "UserId": record.sso_user_id,
                "DisplayName": "Updated" if confirmed else "Before",
                "Emails": [{"Value": "new@example.org", "Primary": True}],
            }

        def update_user(self, *args):
            writes.append(self.account.proxy_id)
            raise AwsFailure("response lost", uncertain=True)

        def password(self, record):
            writes.append(self.account.proxy_id)
            if not confirmed:
                raise AwsFailure("response lost", uncertain=True)
            return "ExplicitNewPassword1!"

    assert run_operation(LostReply, account_id=1)
    with SessionLocal() as db:
        saved_hash = json.loads(db.get(RecordOperation, rid).payload)[
            "worker_config_hash"
        ]
    change_proxy(admin, monkeypatch, None)
    retry_url = f"/api/subscriptions/{rid}/operations/{rid}/retry"
    if kind == "legacy_ready_update":
        # Older public retries could persist ready while retaining a pending
        # fingerprint. A background restart must still recognize that intent.
        with SessionLocal() as db:
            op = db.get(RecordOperation, rid)
            op.state, op.phase = "queued", "ready"
            db.commit()
    else:
        assert alice.post(retry_url, json={"confirm_username": rid}).status_code == 202
    assert run_operation(LostReply, account_id=1)
    with SessionLocal() as db:
        op = db.get(RecordOperation, rid)
        assert op.state == "needs_review"
        assert json.loads(op.payload)["worker_config_hash"] == saved_hash
    assert writes == constructions == [1]

    change_proxy(admin, monkeypatch, 1)
    confirmed = True
    assert alice.post(retry_url, json={"confirm_username": rid}).status_code == 202
    assert run_operation(LostReply, account_id=1)
    assert writes == ([1, 1] if kind == "reset_password" else [1])
    with SessionLocal() as db:
        assert db.get(RecordOperation, rid).state == "completed"


def real_gateway(monkeypatch, rid, stage, *, rejection=False, lookup_failure=False):
    """Actual CreateUser and signed OTP methods, with only wire boundaries stubbed."""
    calls, constructions, lookups = [], [], []
    remote = {"exists": stage == "password", "reject": rejection, "password_ok": False}

    class Identity:
        def __init__(self, account):
            self.account = account

        def get_user_id(self, **kwargs):
            lookups.append(self.account.proxy_id)
            if lookup_failure:
                raise ClientError(
                    {
                        "Error": {"Code": "InternalServerException"},
                        "ResponseMetadata": {"HTTPStatusCode": 500},
                    },
                    "GetUserId",
                )
            if not remote["exists"]:
                raise ClientError(
                    {"Error": {"Code": "ResourceNotFoundException"}}, "GetUserId"
                )
            return {"UserId": "confirmed-user"}

        def describe_user(self, **kwargs):
            return {"UserId": "confirmed-user", "DisplayName": f"Kiro Console {rid}"}

        def create_user(self, **kwargs):
            calls.append(("create", self.account.proxy_id))
            if not remote["reject"]:
                remote["exists"] = True
            raise ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException"
                        if remote["reject"]
                        else "InternalServerException"
                    },
                    "ResponseMetadata": {
                        "HTTPStatusCode": 403 if remote["reject"] else 500
                    },
                },
                "CreateUser",
            )

    def post(session, url, **kwargs):
        assert kwargs["headers"]["X-Amz-Target"] == "SWBUPService.UpdatePassword"
        calls.append(("password", 1 if session.proxies else None))
        if remote["password_ok"]:
            return SimpleNamespace(
                status_code=200,
                headers={},
                json=lambda: {"Password": "RecoveredPassword1!"},
            )
        if remote["reject"]:
            return SimpleNamespace(
                status_code=403,
                headers={},
                json=lambda: {"__type": "AccessDeniedException"},
            )
        raise requests.ReadTimeout("response lost after write")

    monkeypatch.setattr(requests.Session, "post", post)

    def factory(account):
        constructions.append(account.proxy_id)
        gateway = AwsGateway(account)
        gateway.identity = Identity(account)
        gateway.verify_identity = lambda: None
        return gateway

    return factory, calls, constructions, lookups, remote


@pytest.mark.parametrize("stage", ["create_user", "password"])
def test_initial_sso_uncertain_wire_is_frozen_and_recovery_is_readonly(
    alice, admin, monkeypatch, stage
):
    from app.worker import run_one

    rid = sso(1)
    bind_original_proxy()
    if stage == "password":
        with SessionLocal() as db:
            r = db.get(Subscription, rid)
            r.sso_user_id, r.step = "confirmed-user", "password"
            db.commit()
    factory, calls, constructions, lookups, remote = real_gateway(
        monkeypatch, rid, stage
    )
    assert run_one(factory, account_id=1)
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        assert r.state == ("queued" if stage == "create_user" else "needs_review")
        assert r.step == stage + "_pending"
        assert r.worker_config_hash
        original_hash = r.worker_config_hash
    change_proxy(admin, monkeypatch, None)
    if stage == "create_user":
        from app.retry_models import AutomaticRetry
        from test_automatic_retries import due

        with SessionLocal() as db:
            retry = db.get(AutomaticRetry, ("sso", rid))
            assert retry.mode == "reconcile" and retry.config_hash == original_hash
            assert retry.next_retry_at > now()
        assert not run_one(factory, account_id=1)
        due("sso", rid)
    else:
        assert alice.post(f"/api/subscriptions/{rid}/retry").status_code == 202
    assert run_one(factory, account_id=1)
    assert calls == [("create" if stage == "create_user" else stage, 1)]
    assert constructions == [1]
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        assert r.state == "needs_review" and r.worker_config_hash == original_hash

    change_proxy(admin, monkeypatch, 1)
    assert alice.post(f"/api/subscriptions/{rid}/retry").status_code == 202
    assert run_one(factory, account_id=1)
    assert len(calls) == 1
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        if stage == "create_user":
            assert r.sso_user_id == "confirmed-user"
            assert r.state == "queued" and r.step == "password"
            assert lookups == [1, 1]
        else:
            assert r.state == "needs_review" and r.step == "password_pending"
            assert r.password_encrypted is None
            assert "重置" in r.error


@pytest.mark.parametrize("stage", ["create_user", "password"])
def test_proven_rejection_allows_initial_sso_fresh_config_retry(
    alice, admin, monkeypatch, stage
):
    from app.worker import run_one

    rid = sso(1)
    bind_original_proxy()
    if stage == "password":
        with SessionLocal() as db:
            r = db.get(Subscription, rid)
            r.sso_user_id, r.step = "confirmed-user", "password"
            db.commit()
    factory, calls, _, _, _ = real_gateway(monkeypatch, rid, stage, rejection=True)
    assert run_one(factory, account_id=1)
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        assert r.state == "failed" and r.step == stage
        assert r.worker_config_hash is None
    change_proxy(admin, monkeypatch, None)
    assert alice.post(f"/api/subscriptions/{rid}/retry").status_code == 202
    assert run_one(factory, account_id=1)
    assert [proxy for _, proxy in calls] == [1, None]


def test_create_user_lookup_failure_is_provably_unsent(monkeypatch):
    from app.worker import run_one
    from app.retry_models import AutomaticRetry
    from test_automatic_retries import due

    rid = sso(1)
    factory, calls, _, lookups, _ = real_gateway(
        monkeypatch, rid, "create_user", lookup_failure=True
    )
    assert run_one(factory, account_id=1)
    assert calls == []
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        retry = db.get(AutomaticRetry, ("sso", rid))
        assert r.state == "queued" and r.step == "create_user"
        assert retry.config_hash == r.worker_config_hash
        assert retry.next_retry_at > now() and retry.mode == "retry"
    assert not run_one(factory, account_id=1)
    for _ in range(5):
        due("sso", rid)
        assert run_one(factory, account_id=1)
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        assert r.state == "failed" and r.worker_config_hash is None
        retry = db.get(AutomaticRetry, ("sso", rid))
        assert r.attempts == 6 and retry.retry_count == 5 and retry.exhausted
    assert calls == [] and len(lookups) == 6


def test_initial_lost_otp_can_use_explicit_reset_then_continue(
    alice, admin, monkeypatch
):
    from app.lifecycle import run_operation
    from app.worker import run_one

    rid = sso(1, sso_user_id="confirmed-user", step="password")
    bind_original_proxy()
    factory, calls, _, _, remote = real_gateway(monkeypatch, rid, "password")
    assert run_one(factory, account_id=1)
    body = {
        "kind": "reset_password",
        "request_key": str(uuid.uuid4()),
        "confirm_username": rid,
    }
    response = alice.post(f"/api/subscriptions/{rid}/operations", json=body)
    assert response.status_code == 202, response.text
    op_id = response.json()["id"]
    # Explicit recovery inherits the original uncertain intent's route.
    change_proxy(admin, monkeypatch, None)
    assert run_operation(factory, account_id=1)
    assert calls == [("password", 1)]
    change_proxy(admin, monkeypatch, 1)
    remote["password_ok"] = True
    assert (
        alice.post(
            f"/api/subscriptions/{rid}/operations/{op_id}/retry",
            json={"confirm_username": rid},
        ).status_code
        == 202
    )
    assert run_operation(factory, account_id=1)
    assert calls == [("password", 1), ("password", 1)]
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        assert (
            r.state == "queued"
            and r.password_encrypted
            and r.active_operation_id is None
        )
        assert r.worker_config_hash is None
    assert run_one(factory, account_id=1)
    assert len(calls) == 2
    with SessionLocal() as db:
        assert db.get(Subscription, rid).state == "completed"
    replay = alice.post(f"/api/subscriptions/{rid}/operations", json=body)
    assert replay.status_code == 202 and replay.json()["id"] == op_id


@pytest.mark.parametrize("revoke", [None, "binding", "deadline"])
def test_initial_native_otp_reset_preserves_creation_lock_quota_and_guards(
    alice, native, monkeypatch, revoke
):
    from app.lifecycle import run_operation
    from app.models import Binding, GroupMemberActivation
    from app.worker import run_one
    from test_native_groups import activate, counter

    activate(alice)
    original_count = counter()
    password_calls = []

    def password(self, record):
        password_calls.append(record.id)
        if len(password_calls) == 1:
            raise AwsFailure("OTP response lost", uncertain=True)
        return "RecoveredNative1!"

    monkeypatch.setattr(native, "verify_identity", lambda self: None, raising=False)
    monkeypatch.setattr(
        native, "create_user", lambda self, record: "sso-" + record.id, raising=False
    )
    monkeypatch.setattr(native, "password", password, raising=False)
    result = alice.post(
        "/api/batches/create",
        json={
            "kind": "sso",
            "aws_account_id": 1,
            "group_id": "group-1",
            "items": [{"username": "lost-otp"}],
            "request_key": str(uuid.uuid4()),
        },
    )
    assert result.status_code == 202, result.text
    rid = result.json()["items"][0]["id"]
    assert run_one(native, account_id=1)
    pending_count = (original_count[0], original_count[1] + 1, original_count[2])
    assert counter() == pending_count
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        assert record.state == "needs_review" and record.step == "password_pending"
        username = record.username
    reset = alice.post(
        f"/api/subscriptions/{rid}/operations",
        json={
            "kind": "reset_password",
            "request_key": str(uuid.uuid4()),
            "confirm_username": username,
        },
    )
    assert reset.status_code == 202, reset.text
    if revoke:
        with SessionLocal() as db:
            if revoke == "binding":
                db.delete(db.get(Binding, (2, 1)))
            else:
                grant = db.scalar(
                    select(NativeGroupGrant).where(
                        NativeGroupGrant.group_id == "group-1"
                    )
                )
                grant.stop_at = now() - timedelta(seconds=1)
            db.commit()
    assert run_operation(native, account_id=1)
    assert counter() == pending_count
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        activation = db.scalar(
            select(GroupMemberActivation).where(GroupMemberActivation.record_id == rid)
        )
        assert activation.reserved and not activation.counted
        assert activation.operation_id == rid
        assert activation.write_requested_at is None
        assert record.group_id == "group-1" and record.group_membership_id is None
        assert db.get(ManagedGroup, "group-1").active_job_id is None
        if revoke:
            assert record.state == "needs_review" and record.password_encrypted is None
            assert len(password_calls) == 1
        else:
            assert record.state == "queued" and record.active_operation_id is None
            assert len(password_calls) == 2
    if not revoke:
        assert run_one(native, account_id=1)
        assert counter() == (
            original_count[0] + 1,
            original_count[1],
            original_count[2] + 1,
        )
        assert len(password_calls) == 2


@pytest.mark.parametrize(
    "blocked", ["lost_cancel", "manual_group_job", "existing_revision"]
)
def test_bounded_native_due_reaches_later_group_without_duplicate(
    alice, native, blocked
):
    from app.group_subscription_worker import enqueue_due, run_one

    a, b = seed_group(n=0, gid="oldest-blocked"), seed_group(n=0, gid="later-ready")
    for gid in (a, b):
        assert subscribe(alice, gid).status_code == 202
        assert run_one(native, account_id=1)
    with SessionLocal() as db:
        for minutes, gid in ((2, a), (1, b)):
            grant = db.scalar(
                select(NativeGroupGrant).where(NativeGroupGrant.group_id == gid)
            )
            grant.stop_at, grant.policy_revision = now() - timedelta(minutes=minutes), 1
        db.commit()
    if blocked == "manual_group_job":
        with SessionLocal() as db:
            job = GroupJob(
                id="manual-rename",
                group_id=a,
                actor_id=2,
                kind="rename",
                request_key="manual-rename",
                payload=json.dumps({"name": "Changed"}),
            )
            db.add(job)
            db.get(ManagedGroup, a).active_job_id = job.id
            db.commit()
    else:
        assert enqueue_due(limit=1, account_id=1) == 1
        native.uncertain = True
        assert run_one(native, account_id=1)
        native.uncertain = False
        if blocked == "existing_revision":
            with SessionLocal() as db:
                db.get(ManagedGroup, a).active_job_id = None
                db.commit()
    assert enqueue_due(limit=1, account_id=1) == 1
    with SessionLocal() as db:
        rows = list(
            db.scalars(
                select(NativeGroupOperation).where(
                    NativeGroupOperation.kind == "cancel"
                )
            )
        )
        assert sum(row.group_id == b for row in rows) == 1
        assert sum(row.group_id == a for row in rows) == (
            0 if blocked == "manual_group_job" else 1
        )
    assert (
        enqueue_due(limit=1, account_id=1) == enqueue_due(limit=100, account_id=1) == 0
    )


def test_bounded_native_due_rotates_past_member_validation_block(alice, native):
    from app.group_subscription_worker import enqueue_due, run_one

    for index, gid in enumerate(("blocked-member", "ready-member")):
        seed_group(n=1, gid=gid)
        assert subscribe(alice, gid).status_code == 202
        assert run_one(native, account_id=1)
        with SessionLocal() as db:
            grant = db.scalar(
                select(NativeGroupGrant).where(NativeGroupGrant.group_id == gid)
            )
            grant.stop_at, grant.policy_revision = (
                now() - timedelta(minutes=2 - index),
                1,
            )
            if index == 0:
                record = db.get(Subscription, gid + "-record-0")
                record.active_operation_id = "manual-update"
                db.add(
                    RecordOperation(
                        id="manual-update",
                        record_id=record.id,
                        actor_id=2,
                        kind="update_sso",
                        request_key="manual-update",
                        payload="{}",
                    )
                )
            db.commit()
    counts = [enqueue_due(limit=1, account_id=1) for _ in range(3)]
    with SessionLocal() as db:
        cancellations = list(
            db.scalars(
                select(NativeGroupOperation).where(
                    NativeGroupOperation.kind == "cancel"
                )
            )
        )
        assert [op.group_id for op in cancellations] == ["ready-member"], counts


@pytest.mark.parametrize(
    "blocked", ["uncertain_expiry", "group_lock", "member_lock", "existing_expiry"]
)
def test_bounded_native_expiry_reaches_later_group_readonly(alice, native, blocked):
    from app.group_subscription_worker import reconcile_due, run_one

    with SessionLocal() as db:
        db.get(AwsAccount, 1).control_plane = "kiro"
        db.commit()
    for gid in ("expiry-first", "expiry-later"):
        seed_group(n=1, gid=gid)
        assert subscribe(alice, gid).status_code == 202
        assert run_one(native, account_id=1)
        assert (
            cancel_group(alice, gid, cancellation_mode="END_OF_PERIOD").status_code
            == 202
        )
        assert run_one(native, account_id=1)
    with SessionLocal() as db:
        for grant in db.scalars(select(NativeGroupGrant)):
            assert grant.state == "cancel_scheduled"
            grant.access_ends_at = now() - timedelta(seconds=1)
        db.commit()
    for assignment in native.assignments.values():
        assignment["expires_at"] = now() - timedelta(seconds=1)

    class Recovery(native):
        def group_subscription_info(self, group):
            if group.id == "expiry-first":
                raise AwsFailure("original expiry read unavailable", uncertain=True)
            return super().group_subscription_info(group)

    if blocked in ("uncertain_expiry", "existing_expiry"):
        assert reconcile_due(Recovery, limit=1, account_id=1) == 1
        with SessionLocal() as db:
            op = db.scalar(
                select(NativeGroupOperation).where(
                    NativeGroupOperation.group_id == "expiry-first",
                    NativeGroupOperation.request_key.like("native-expiry:%"),
                )
            )
            assert op.state == "needs_review" and op.phase == "pending"
            if blocked == "existing_expiry":
                # Even after locks are released, the original expiry request is
                # not recreated and cannot monopolize bounded admission.
                db.get(ManagedGroup, "expiry-first").active_job_id = None
                db.get(Subscription, "expiry-first-record-0").active_operation_id = None
                db.commit()
    else:
        with SessionLocal() as db:
            if blocked == "group_lock":
                db.add(
                    GroupJob(
                        id="expiry-group-lock",
                        group_id="expiry-first",
                        actor_id=2,
                        kind="rename",
                        request_key="expiry-group-lock",
                        payload="{}",
                    )
                )
                db.get(ManagedGroup, "expiry-first").active_job_id = "expiry-group-lock"
            else:
                db.add(
                    RecordOperation(
                        id="expiry-member-lock",
                        record_id="expiry-first-record-0",
                        actor_id=2,
                        kind="update_sso",
                        request_key="expiry-member-lock",
                        payload="{}",
                    )
                )
                db.get(
                    Subscription, "expiry-first-record-0"
                ).active_operation_id = "expiry-member-lock"
            db.commit()
    writes_before = list(native.writes)
    admissions = [reconcile_due(Recovery, limit=1, account_id=1) for _ in range(5)]
    assert all(count <= 1 for count in admissions)
    assert sum(admissions) == 1
    assert native.writes == writes_before
    with SessionLocal() as db:
        later = db.scalar(
            select(NativeGroupGrant).where(NativeGroupGrant.group_id == "expiry-later")
        )
        assert later.state == "cancelled"
        operations = list(
            db.scalars(
                select(NativeGroupOperation).where(
                    NativeGroupOperation.request_key.like("native-expiry:%")
                )
            )
        )
        assert sum(op.group_id == "expiry-later" for op in operations) == 1
        assert sum(op.group_id == "expiry-first" for op in operations) == (
            1 if blocked in ("uncertain_expiry", "existing_expiry") else 0
        )
    assert reconcile_due(Recovery, limit=100, account_id=1) == 0
    assert native.writes == writes_before
