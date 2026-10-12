"""Regressions for independently reproduced native GROUP lifecycle findings."""

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.aws import AwsFailure, AwsGateway
from app.database import SessionLocal
from app.group_jobs import run_group_job
from app.lifecycle import run_operation
from app.models import (
    AwsAccount,
    NativeGroupGrant,
    PlanCounter,
    RecordOperation,
    Subscription,
    now,
)
from test_native_groups import (
    PRO,
    activate,
    cancel_group,
    counter,
    run_native,
    seed_group,
    subscribe,
)
from test_native_groups import native as native


def standalone(rid, *, subscribed=False):
    with SessionLocal() as db:
        db.add(Subscription(
            id=rid, owner_id=2, aws_account_id=1, request_key=rid, username=rid,
            email=rid + "@example.com", portal_url="https://example.com",
            state="completed", step="sso_ready", provision_only=not subscribed,
            reserved=False, sso_user_id="sso-" + rid, counted=subscribed,
            plan_id=1 if subscribed else None,
            plan_name_snapshot="Kiro Pro" if subscribed else None,
            subscription_type=PRO if subscribed else None,
            subscribed_at=now() if subscribed else None,
            subscription_status="active" if subscribed else "not_subscribed",
        ))
        db.commit()


def bulk_cancel(client, ids):
    result = client.post("/api/subscription-cancellations", json={
        "record_ids": ids, "cancellation_mode": "IMMEDIATE",
        "request_key": str(uuid.uuid4()),
    })
    assert result.status_code == 202, result.text
    return result.json()


def attach(client):
    result = client.post("/api/groups/group-1/jobs", json={
        "kind": "attach", "record_id": "late", "expected_revision": 1,
        "request_key": str(uuid.uuid4()),
    })
    assert result.status_code == 202, result.text
    return result.json()


def test_uncertain_detach_skips_same_group_queue_without_starving_user_work(
    alice, native, monkeypatch
):
    activate(alice, 2)
    grouped = bulk_cancel(alice, ["group-1-record-0", "group-1-record-1"])

    def lost(self, membership_id):
        raise AwsFailure("unconfirmed detach", uncertain=True)

    monkeypatch.setattr(native, "delete_group_membership", lost)
    assert run_operation(native)
    standalone("unrelated", subscribed=True)
    unrelated = bulk_cancel(alice, ["unrelated"])
    assert run_operation(native)
    view = alice.get("/api/lifecycle-batches/" + unrelated["id"]).json()
    assert view["states"]["completed"] == 1
    group_view = alice.get("/api/lifecycle-batches/" + grouped["id"]).json()
    assert group_view["states"]["needs_review"] == 1
    assert group_view["states"]["queued"] == 1
    assert not run_operation(native)


@pytest.mark.parametrize("automatic", [False, True])
def test_group_grown_past_admission_limit_can_still_cancel(alice, native, automatic):
    from app.group_subscription_worker import enqueue_due

    with SessionLocal() as db:
        db.get(PlanCounter, 1).limit_count = 101
        db.commit()
    activate(alice, 100)
    standalone("late")
    attach(alice)
    assert counter() == (100, 1, 100)
    assert run_group_job(native)
    assert len(native.members) == 101
    assert counter() == (101, 0, 101)
    if automatic:
        with SessionLocal() as db:
            db.scalar(select(NativeGroupGrant)).stop_at = now() - timedelta(seconds=1)
            db.commit()
        assert enqueue_due() == 1
    else:
        result = cancel_group(alice)
        assert result.status_code == 202, result.text
    assert run_native()
    assert counter() == (101, 0, 101)
    assert [w[0] for w in native.writes].count("cancel") == 1
    assert not any(w[0] == "USER_cancel" for w in native.writes)
    with SessionLocal() as db:
        assert {r.subscription_status for r in db.scalars(select(Subscription))} == {"cancelled"}


@pytest.mark.parametrize("pending", [False, True])
def test_group_only_blocks_new_user_cancel_but_allows_confirmed_absent_user_recovery(
    alice, native, pending
):
    standalone("unmanaged", subscribed=True)
    native.user_claims["sso-unmanaged"] = [{
        "source": "GROUP", "group_id": "remote-unmanaged", "status": "active",
        "subscription_type": PRO, "expires_at": None,
    }]
    batch = bulk_cancel(alice, ["unmanaged"])
    if pending:
        with SessionLocal() as db:
            operation = db.get(RecordOperation, batch["items"][0]["operation_id"])
            operation.phase = "pending"
            operation.created_at = now() - timedelta(minutes=20)
            db.commit()
    assert run_operation(native)
    view = alice.get("/api/lifecycle-batches/" + batch["id"]).json()
    assert view["states"]["completed" if pending else "failed"] == 1
    assert view["states"]["completed"] == (1 if pending else 0)
    assert not native.writes
    assert alice.get("/api/subscriptions/unmanaged").json()["subscription_status"] == "active"


def test_user_source_check_retains_access_during_pending_user_downgrade():
    from types import SimpleNamespace

    gateway = object.__new__(AwsGateway)
    gateway._claims = lambda token: {"claims": [{
        "principal": {"user": "u"},
        "type": {"amazonQ": "KIRO_ENTERPRISE_PRO_PLUS"},
        "newType": {"amazonQ": "KIRO_ENTERPRISE_PRO"},
        "expirationDate": (now() + timedelta(days=2)).isoformat(),
    }]}
    claims = gateway.user_subscription_sources(SimpleNamespace(sso_user_id="u"))
    assert len(claims) == 1
    assert claims[0]["source"] == "USER"
    assert claims[0]["status"] == "active"
    assert claims[0]["expires_at"] is None


def test_independent_group_appearing_after_user_cancel_remains_active(
    alice, native, monkeypatch
):
    standalone("unmanaged", subscribed=True)
    original = native.cancel_subscription

    def changed(self, record, mode):
        result = original(self, record, mode)
        native.user_claims[record.sso_user_id] = [{
            "source": "GROUP", "group_id": "external", "status": "active",
            "subscription_type": PRO, "expires_at": None,
        }]
        return result

    monkeypatch.setattr(native, "cancel_subscription", changed)
    batch = bulk_cancel(alice, ["unmanaged"])
    assert run_operation(native)
    view = alice.get("/api/lifecycle-batches/" + batch["id"]).json()
    assert view["states"]["completed"] == 1
    assert alice.get("/api/subscriptions/unmanaged").json()["subscription_status"] == "active"
    assert [w[0] for w in native.writes] == ["USER_cancel"]


def test_pending_native_target_does_not_replace_aws_observation(alice, native):
    seed_group(1)
    assert subscribe(alice, plan_id=2).status_code == 202
    view = alice.get("/api/subscriptions/group-1-record-0").json()
    assert view["effective_subscription_source"] is None
    assert view["current_plan"]["plan_id"] is None
    assert view["native_group_subscription"]["plan_id"] == 2
    run_native()
    assert cancel_group(alice).status_code == 202
    run_native()
    assert subscribe(alice, plan_id=1).status_code == 202
    view = alice.get("/api/subscriptions/group-1-record-0").json()
    assert view["effective_subscription_source"] is None
    assert view["current_plan"]["plan_id"] is None  # AWS no longer returns effective access.
    assert view["native_group_subscription"]["plan_id"] == 1


def test_late_attach_rechecks_binding_at_persisted_intent(alice, admin, native, monkeypatch):
    activate(alice)
    standalone("late")
    attach(alice)
    original = native.get_group_membership
    calls = []

    def membership(self, gid, uid):
        result = original(self, gid, uid)
        if uid == "sso-late":
            calls.append(uid)
            if len(calls) == 2:
                result = admin.put("/api/admin/users/2/bindings", json={"account_ids": []})
                assert result.status_code == 200, result.text
                return None
        return result

    monkeypatch.setattr(native, "get_group_membership", membership)
    assert run_group_job(native)
    assert not any(w[0] == "attach" for w in native.writes)
    assert counter() == (1, 0, 1)


@pytest.mark.parametrize("phase", ["create", "join"])
def test_native_sso_provision_rechecks_binding_before_each_write(
    alice, admin, native, monkeypatch, phase
):
    from app.worker import run_one

    activate(alice)
    created = []

    def revoke():
        result = admin.put("/api/admin/users/2/bindings", json={"account_ids": []})
        assert result.status_code == 200, result.text

    def verify(self):
        if phase == "create":
            revoke()

    def create(self, record):
        created.append(record.id)
        return "sso-" + record.id

    def password(self, record):
        return "test-only-password"

    original = native.user_subscription_sources

    def sources(self, record):
        result = original(self, record)
        if phase == "join":
            revoke()
        return result

    monkeypatch.setattr(native, "verify_identity", verify, raising=False)
    monkeypatch.setattr(native, "create_user", create, raising=False)
    monkeypatch.setattr(native, "password", password, raising=False)
    monkeypatch.setattr(native, "user_subscription_sources", sources)
    result = alice.post("/api/batches/create", json={
        "kind": "sso", "aws_account_id": 1, "group_id": "group-1",
        "items": [{"username": "late"}], "request_key": str(uuid.uuid4()),
    })
    assert result.status_code == 202, result.text
    assert run_one(native)
    assert bool(created) == (phase == "join")
    assert not any(w[0] == "attach" for w in native.writes)
    assert counter() == (1, 0, 1)


@pytest.mark.parametrize("failure", ["drift", "settlement"])
def test_successful_join_keeps_intent_and_quota_until_readonly_recovery(
    alice, admin, native, monkeypatch, failure
):
    import app.worker as worker
    from app.models import GroupMemberActivation, ManagedGroup

    activate(alice)
    monkeypatch.setattr(native, "verify_identity", lambda *_: None, raising=False)
    monkeypatch.setattr(native, "create_user", lambda self, r: "sso-" + r.id, raising=False)
    monkeypatch.setattr(native, "password", lambda *_: "test-password", raising=False)
    original_join, original_finish = native.create_group_membership, worker.finish_sso

    def join(self, gid, uid):
        result = original_join(self, gid, uid)
        if failure == "drift":
            self.members[(gid, "unmanaged")] = "unmanaged-mid"
        return result

    def finish(*args):
        raise AwsFailure("settlement unavailable")

    monkeypatch.setattr(native, "create_group_membership", join)
    if failure == "settlement":
        monkeypatch.setattr(worker, "finish_sso", finish)
    result = alice.post("/api/batches/create", json={
        "kind": "sso", "aws_account_id": 1, "group_id": "group-1",
        "items": [{"username": "late"}], "request_key": str(uuid.uuid4()),
    })
    assert result.status_code == 202, result.text
    rid = result.json()["items"][0]["id"]
    assert worker.run_one(native)
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        activation = db.scalar(select(GroupMemberActivation).where(GroupMemberActivation.record_id == rid))
        assert record.state == "needs_review"
        assert record.step == ("group_membership_pending" if failure == "drift" else "group_entitlement_pending")
        assert activation.reserved and not activation.counted
        assert db.get(ManagedGroup, "group-1").active_job_id == (rid if failure == "drift" else None)
    assert counter() == (1, 1, 1)
    native.members.pop(("remote-group-1", "unmanaged"), None)
    monkeypatch.setattr(worker, "finish_sso", original_finish)
    assert admin.put("/api/admin/users/2/bindings", json={"account_ids": []}).status_code == 200
    result = admin.post(f"/api/subscriptions/{rid}/retry")
    assert result.status_code == 202, result.text
    assert worker.run_one(native)
    assert counter() == (2, 0, 2)
    assert [w[0] for w in native.writes].count("attach") == 1


@pytest.mark.parametrize("expiry", ["future", "expired", "expires_while_queued"])
def test_common_deadline_shortens_live_period_cancel_and_never_repeats_expiry_write(
    alice, native, expiry
):
    from app.group_subscription_worker import enqueue_due, reconcile_due

    with SessionLocal() as db:
        db.get(AwsAccount, 1).control_plane = "kiro"
        db.commit()
    activate(alice)
    policy_revision = alice.get("/api/groups/group-1").json()["policy"]["revision"]
    result = alice.put("/api/groups/group-1/policy", json={
        "expected_revision": policy_revision, "policy": {"mode": "days", "days": 1},
    })
    assert result.status_code == 200, result.text
    assert cancel_group(alice, cancellation_mode="END_OF_PERIOD").status_code == 202
    assert run_native()
    assert cancel_group(alice).status_code == 409
    with SessionLocal() as db:
        grant = db.scalar(select(NativeGroupGrant))
        grant.stop_at = now() - timedelta(seconds=1)
        if expiry == "expired":
            grant.access_ends_at = now() - timedelta(seconds=1)
            native.assignments["remote-group-1"]["expires_at"] = grant.access_ends_at
        db.commit()
    if expiry == "expired":
        assert enqueue_due() == 0
        assert reconcile_due(native) == 1
    else:
        assert enqueue_due() == 1
        assert enqueue_due() == 0
        if expiry == "expires_while_queued":
            native.assignments["remote-group-1"]["expires_at"] = now() - timedelta(seconds=1)
        assert run_native()
    assert alice.get("/api/groups/group-1").json()["native_subscription"]["state"] == "cancelled"
    cancellations = [w[2] for w in native.writes if w[0] == "cancel"]
    assert cancellations == (["END_OF_PERIOD", "IMMEDIATE"] if expiry == "future" else ["END_OF_PERIOD"])
    assert enqueue_due() == reconcile_due(native) == 0
    assert counter() == (1, 0, 1)


def test_existing_earlier_member_deadline_survives_group_period_cancel_and_sync(alice, native):
    from app.models import StopSchedule
    from app.schedules import enqueue_due

    with SessionLocal() as db:
        db.get(AwsAccount, 1).control_plane = "kiro"
        db.commit()
    activate(alice, 2)
    rid = "group-1-record-0"
    result = alice.put(f"/api/subscriptions/{rid}/stop-schedule", json={
        "expected_revision": 0,
        "policy": {"mode": "at", "stop_at": (now() + timedelta(hours=1)).isoformat() + "Z"},
    })
    assert result.status_code == 200, result.text
    assert cancel_group(alice, cancellation_mode="END_OF_PERIOD").status_code == 202
    assert run_native()
    assert alice.get(f"/api/subscriptions/{rid}").json()["stop_schedule"]["state"] == "scheduled"
    result = alice.post(f"/api/subscriptions/{rid}/operations", json={
        "kind": "sync_status", "request_key": str(uuid.uuid4()),
    })
    assert result.status_code == 202, result.text
    assert run_operation(native)
    assert alice.get(f"/api/subscriptions/{rid}").json()["stop_schedule"]["state"] == "scheduled"
    with SessionLocal() as db:
        db.get(StopSchedule, rid).stop_at = now() - timedelta(seconds=1)
        db.commit()
    assert enqueue_due() == 1
    assert run_operation(native)
    assert ("remote-group-1", "sso-" + rid) not in native.members
    assert ("remote-group-1", "sso-group-1-record-1") in native.members
    assert alice.get("/api/groups/group-1").json()["native_subscription"]["state"] == "cancel_scheduled"
    assert not any(w[0] == "USER_cancel" for w in native.writes)
