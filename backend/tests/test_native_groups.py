"""Native principal writes and durable per-member accounting; never touch AWS."""

import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.aws import AwsFailure, AwsGateway
from app.database import SessionLocal
from app.models import AwsAccount, ManagedGroup, PlanCounter, Subscription, now

PRO = "Q_DEVELOPER_STANDALONE_PRO"


class NativeGateway:
    assignments = {}
    members = {}
    user_claims = {}
    writes = []
    uncertain = False
    effective_rows = None

    def __init__(self, account):
        self.account = account

    def verify(self):
        return "123456789012"

    def list_group_memberships(self, gid):
        return [
            {"id": mid, "user_id": uid}
            for (g, uid), mid in self.members.items()
            if g == gid
        ]

    def group_subscription_info(self, group):
        return self.assignments.get(
            group.remote_id,
            {"status": "not_subscribed", "subscription_type": None, "expires_at": None},
        )

    def user_subscription_sources(self, record):
        from app.group_subscription_state import active_info

        claims = list(self.user_claims.get(record.sso_user_id, []))
        for (gid, uid), _ in self.members.items():
            info = self.assignments.get(gid)
            if uid == record.sso_user_id and info and active_info(info):
                claims.append({"source": "GROUP", "group_id": gid, **info})
        return claims

    def report_subscriptions(self):
        if self.effective_rows is not None:
            return self.effective_rows
        users = {uid for _, uid in self.members} | set(self.user_claims)
        result = []
        for uid in users:
            claims = self.user_subscription_sources(SimpleNamespace(sso_user_id=uid))
            if not claims:
                continue
            assert len(claims) == 1, "Multiple-source tests must provide explicit AWS effective_rows"
            c = claims[0]
            result.append({"principal": {"user": uid}, "type": {"amazonQ": c["subscription_type"]},
                           "status": "ACTIVE" if c["status"] == "active" else "CANCELLED",
                           "aggregatedSubscriptionType": "GROUP" if c["source"] == "GROUP" else "INDIVIDUAL",
                           "expirationDate": c.get("expires_at").isoformat() if c.get("expires_at") else None})
        return result

    def subscribe_group(self, group, subscription_type):
        self.writes.append(("create", group.remote_id, subscription_type))
        self.assignments[group.remote_id] = {
            "status": "active",
            "subscription_type": subscription_type,
            "expires_at": None,
        }
        if self.uncertain:
            raise AwsFailure("response lost", uncertain=True)
        return "group-create-request"

    def cancel_group_subscription(self, group, mode):
        self.writes.append(("cancel", group.remote_id, mode))
        self.assignments[group.remote_id] = {
            "status": "cancelled",
            "subscription_type": self.assignments[group.remote_id]["subscription_type"],
            "expires_at": now() + timedelta(days=2)
            if mode == "END_OF_PERIOD"
            else now(),
        }
        if self.uncertain:
            raise AwsFailure("response lost", uncertain=True)
        return "group-cancel-request"

    def get_group_membership(self, gid, uid):
        return self.members.get((gid, uid))

    def create_group_membership(self, gid, uid):
        self.writes.append(("attach", gid, uid))
        self.members[(gid, uid)] = "member-" + uid
        if self.uncertain:
            raise AwsFailure("membership response lost", uncertain=True)
        return self.members[(gid, uid)]

    def delete_group_membership(self, mid):
        self.writes.append(("detach", mid))
        for key, value in list(self.members.items()):
            if mid == value:
                del self.members[key]
        if self.uncertain:
            raise AwsFailure("membership response lost", uncertain=True)

    def subscription_info(self, record):
        return {
            "status": "not_subscribed",
            "subscription_type": None,
            "expires_at": None,
        }

    def user_info(self, record):
        return {"UserId": record.sso_user_id, "DisplayName": record.username}

    def cancel_subscription(self, record, mode):
        self.writes.append(("USER_cancel", record.id, mode))
        return "user-cancel"


@pytest.fixture
def native(monkeypatch):
    NativeGateway.effective_rows = None
    NativeGateway.assignments, NativeGateway.members, NativeGateway.user_claims = (
        {},
        {},
        {},
    )
    NativeGateway.writes, NativeGateway.uncertain = [], False
    import app.group_subscriptions as api

    monkeypatch.setattr(api, "AwsGateway", NativeGateway)
    return NativeGateway


def seed_group(n=2, owner=2, gid="group-1"):
    with SessionLocal() as db:
        group = ManagedGroup(
            id=gid,
            owner_id=owner,
            aws_account_id=1,
            aws_scope="123456789012:d-1234567890",
            request_key=str(uuid.uuid4()),
            payload_hash="seed",
            name=gid,
            marker=gid,
            remote_id="remote-" + gid,
            state="ready",
        )
        db.add(group)
        db.flush()
        for i in range(n):
            rid = f"{gid}-record-{i}"
            db.add(
                Subscription(
                    id=rid,
                    owner_id=owner,
                    aws_account_id=1,
                    request_key=rid,
                    username=rid,
                    email=f"{rid}@example.com",
                    portal_url="https://example.com",
                    state="completed",
                    step="sso_ready",
                    provision_only=True,
                    reserved=False,
                    sso_user_id=f"sso-{rid}",
                    group_id=gid,
                    group_membership_id=f"member-{rid}",
                )
            )
            NativeGateway.members[(group.remote_id, f"sso-{rid}")] = f"member-{rid}"
        db.commit()
    return gid


def subscribe(client, gid="group-1", **extra):
    return client.post(
        "/api/group-subscriptions",
        json={
            "group_ids": [gid],
            "plan_id": 1,
            "request_key": str(uuid.uuid4()),
            **extra,
        },
    )


def run_native():
    from app.group_subscription_worker import run_one

    return run_one(NativeGateway)


def counter():
    with SessionLocal() as db:
        c = db.get(PlanCounter, 1)
        return c.used_count, c.pending_count, c.lifetime_count


def test_protocol_uses_group_principal_and_keeps_legacy_immediate_only():
    with SessionLocal() as db:
        account = db.get(AwsAccount, 1)
        account.control_plane = "kiro"
        account.subscription_region = "eu-central-1"
        gateway = object.__new__(AwsGateway)
        gateway.account = account
        sent = []
        gateway._call = lambda *args: (sent.append(args) or {}, "rid")
        group = SimpleNamespace(remote_id="real-aws-group")
        assert gateway.subscribe_group(group, PRO) == "rid"
        assert sent[-1] == (
            "eu-central-1",
            "management.eu-central-1.kiro.dev",
            "q",
            "KiroControlPlaneQDeveloperService.CreateAssignment",
            {
                "principalId": "real-aws-group",
                "principalType": "GROUP",
                "subscriptionType": PRO,
            },
        )
        gateway.cancel_group_subscription(group, "IMMEDIATE")
        assert sent[-1][-1] == {
            "principalId": "real-aws-group",
            "principalType": "GROUP",
            "deletionMode": "IMMEDIATE",
        }
        account.control_plane = "legacy"
        with pytest.raises(AwsFailure):
            gateway.cancel_group_subscription(group, "END_OF_PERIOD")
        assert len(sent) == 2


def test_native_snapshot_reserves_and_settles_exactly_once(alice, native):
    gid = seed_group()
    key = str(uuid.uuid4())
    result = subscribe(alice, gid, request_key=key)
    assert result.status_code == 202, result.text
    assert counter() == (0, 2, 0)
    assert not native.writes
    assert run_native()
    assert counter() == (2, 0, 2)
    assert native.writes == [("create", "remote-group-1", PRO)]
    replay = subscribe(alice, gid, request_key=key)
    assert replay.json()["id"] == result.json()["id"]
    assert not run_native()
    assert counter() == (2, 0, 2)
    assert subscribe(alice, gid, request_key=key, plan_id=2).status_code == 409
    view = alice.get(f"/api/groups/{gid}").json()
    assert view["native_subscription"]["state"] == "active"
    assert all(
        r["subscription_source"] == "GROUP"
        and r["current_plan"]["subscription_type"] == PRO
        for r in view["members"]
    )


def test_quota_exhaustion_is_atomic_before_write(alice, native):
    seed_group(3)
    response = subscribe(alice)
    assert response.status_code == 409, response.text
    assert counter() == (0, 0, 0)
    assert not native.writes


@pytest.mark.parametrize("drift", ["unmanaged", "missing", "USER"])
def test_admission_rejects_remote_drift_and_malformed_user_claim(alice, native, drift):
    seed_group(1)
    if drift == "unmanaged":
        native.members[("remote-group-1", "foreign")] = "foreign-membership"
    elif drift == "missing":
        native.members.clear()
    else:
        native.user_claims["sso-group-1-record-0"] = [
            {
                "status": "active",
                "subscription_type": PRO,
                "source": "USER" if drift == "USER" else "GROUP",
                "group_id": "other",
            }
        ]
    response = subscribe(alice)
    assert response.status_code == 409, response.text
    assert counter() == (0, 0, 0)
    assert not native.writes


def test_unknown_write_only_reconciles_and_keeps_quota(alice, native):
    seed_group(1)
    response = subscribe(alice)
    assert response.status_code == 202, response.text
    native.uncertain = True
    run_native()
    detail = alice.get(f"/api/lifecycle-batches/{response.json()['id']}").json()
    assert detail["items"][0]["state"] == "needs_review"
    assert counter() == (0, 1, 0)
    op_id = detail["items"][0]["operation_id"]
    assert alice.post(f"/api/group-subscriptions/{op_id}/recheck").status_code == 202
    run_native()
    assert len(native.writes) == 1
    assert counter() == (1, 0, 1)


def test_owner_isolation(alice, bob, native):
    seed_group(1)
    assert subscribe(bob).status_code == 404
    response = subscribe(alice)
    assert response.status_code == 202, response.text
    assert bob.get(f"/api/lifecycle-batches/{response.json()['id']}").status_code == 404


def cancel_group(client, gid="group-1", **extra):
    return client.post(
        "/api/group-subscriptions/cancel",
        json={
            "group_ids": [gid],
            "cancellation_mode": "IMMEDIATE",
            "request_key": str(uuid.uuid4()),
            **extra,
        },
    )


def activate(client, n=1):
    seed_group(n)
    result = subscribe(client)
    assert result.status_code == 202, result.text
    run_native()
    return result.json()


def test_group_cancel_then_resubscribe_retains_history_and_first_opening(alice, native):
    activate(alice)
    original = alice.get("/api/subscriptions/group-1-record-0").json()
    response = cancel_group(alice)
    assert response.status_code == 202, response.text
    run_native()
    assert counter() == (1, 0, 1)
    with SessionLocal() as db:
        r = db.get(Subscription, "group-1-record-0")
        assert r.sso_deleted_at is None and r.group_membership_id
    assert subscribe(alice).status_code == 202
    run_native()
    assert counter() == (2, 0, 2)
    current = alice.get("/api/subscriptions/group-1-record-0").json()
    assert current["subscribed_at"] == original["subscribed_at"]
    history = alice.get("/api/groups/group-1/native-subscriptions").json()
    assert len(history["grants"]) == 2
    assert [g["state"] for g in history["grants"]] == ["active", "cancelled"]


def test_individual_native_cancel_detaches_member_without_user_assignment(
    alice, native
):
    from app.lifecycle import run_operation

    activate(alice)
    result = alice.post(
        "/api/subscriptions/group-1-record-0/operations",
        json={
            "kind": "cancel_subscription",
            "cancellation_mode": "IMMEDIATE",
            "confirm_username": "group-1-record-0",
            "request_key": str(uuid.uuid4()),
        },
    )
    assert result.status_code == 202, result.text
    run_operation(native)
    r = alice.get("/api/subscriptions/group-1-record-0").json()
    assert r["subscription_status"] == "cancelled" and r["group_id"] is None
    assert r["sso_deleted_at"] is None
    assert len(native.members) == 0
    assert native.writes[-1][0] == "detach"
    assert counter() == (1, 0, 1)
    assert native.assignments["remote-group-1"]["status"] == "active"


def test_individual_group_end_of_period_is_rejected(alice, native):
    activate(alice)
    with SessionLocal() as db:
        db.get(AwsAccount, 1).control_plane = "kiro"
        db.commit()
    result = alice.post(
        "/api/subscriptions/group-1-record-0/operations",
        json={
            "kind": "cancel_subscription",
            "cancellation_mode": "END_OF_PERIOD",
            "confirm_username": "group-1-record-0",
            "request_key": str(uuid.uuid4()),
        },
    )
    assert result.status_code == 409, result.text


def test_bulk_user_cancel_is_durable_and_replay_safe(alice, native):
    from app.lifecycle import run_operation

    seed_group(2)
    with SessionLocal() as db:
        for r in db.scalars(select(Subscription)):
            r.group_id = r.group_membership_id = None
            r.counted, r.provision_only = True, False
            r.plan_id, r.subscription_type, r.plan_name_snapshot = 1, PRO, "Kiro Pro"
            r.subscribed_at, r.subscription_status = now(), "active"
        db.commit()
    body = {
        "record_ids": ["group-1-record-0", "group-1-record-1"],
        "cancellation_mode": "IMMEDIATE",
        "request_key": str(uuid.uuid4()),
    }
    response = alice.post("/api/subscription-cancellations", json=body)
    assert response.status_code == 202, response.text
    run_operation(native)
    run_operation(native)
    detail = alice.get(f"/api/lifecycle-batches/{response.json()['id']}").json()
    assert detail["states"]["completed"] == 2
    assert (
        alice.post("/api/subscription-cancellations", json=body).json()["id"]
        == detail["id"]
    )
    assert (
        alice.post(
            "/api/subscription-cancellations",
            json=body | {"record_ids": ["group-1-record-0"]},
        ).status_code
        == 409
    )
    assert [w[0] for w in native.writes] == ["USER_cancel", "USER_cancel"]


def test_native_plan_change_blocked_and_admin_counts_not_duplicated(
    alice, admin, native, monkeypatch
):
    from app.config import settings

    monkeypatch.setattr(settings, "plan_changes_enabled", True)
    activate(alice)
    options = alice.get("/api/subscriptions/group-1-record-0/plan-options").json()
    assert "分组" in options["unavailable_reason"]
    summary = admin.get("/api/overview").json()["member_summary"]
    user = next(u for u in summary["users"] if u["id"] == 2)
    assert next(c for c in user["counters"] if c["plan_id"] == 1)["lifetime_count"] == 1
    history = admin.get("/api/admin/users/2/plan-history?plan_id=1").json()
    assert history["total"] == 1
    assert history["items"][0]["event_kind"] == "group_activation"


def test_active_group_attach_reserves_before_join(alice, native):
    from app.group_jobs import run_group_job

    activate(alice)
    with SessionLocal() as db:
        db.add(
            Subscription(
                id="late",
                owner_id=2,
                aws_account_id=1,
                request_key="late",
                username="late",
                email="late@example.com",
                portal_url="https://example.com",
                state="completed",
                step="sso_ready",
                provision_only=True,
                reserved=False,
                sso_user_id="sso-late",
            )
        )
        db.commit()
    body = {
        "kind": "attach",
        "record_id": "late",
        "expected_revision": 1,
        "request_key": str(uuid.uuid4()),
    }
    response = alice.post("/api/groups/group-1/jobs", json=body)
    assert response.status_code == 202, response.text
    assert counter() == (1, 1, 1)
    run_group_job(native)
    assert counter() == (2, 0, 2)
    assert alice.get("/api/subscriptions/late").json()["subscription_source"] == "GROUP"


def test_active_group_create_sso_reserves_before_user_creation(alice, native):
    activate(alice)
    response = alice.post(
        "/api/batches/create",
        json={
            "kind": "sso",
            "aws_account_id": 1,
            "group_id": "group-1",
            "items": [{"username": "late"}, {"username": "exhausted"}],
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 409, response.text
    assert counter() == (1, 0, 1)
    with SessionLocal() as db:
        assert len(list(db.scalars(select(Subscription)))) == 1


def test_group_pending_blocks_credential_and_member_tasks(alice, native):
    seed_group(1)
    assert subscribe(alice).status_code == 202
    response = alice.post(
        "/api/subscriptions/group-1-record-0/operations",
        json={
            "kind": "reset_password",
            "confirm_username": "group-1-record-0",
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 409
    response = alice.post(
        "/api/groups/group-1/jobs",
        json={
            "kind": "rename",
            "name": "changed",
            "expected_revision": 1,
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 409


def test_native_deadline_common_anchor_edit_and_single_group_cancel(alice, native):
    from app.group_subscription_worker import enqueue_due as enqueue_groups
    from app.schedules import enqueue_due
    from app.models import (
        NativeGroupGrant,
        NativeGroupOperation,
        RecordOperation,
        StopSchedule,
    )

    seed_group(2)
    response = alice.put(
        "/api/groups/group-1/policy",
        json={"policy": {"mode": "days", "days": 3}, "expected_revision": 0},
    )
    assert response.status_code == 200, response.text
    assert subscribe(alice).status_code == 202
    run_native()
    with SessionLocal() as db:
        grant = db.scalar(select(NativeGroupGrant))
        due = grant.activated_at + timedelta(days=3)
        assert grant.stop_at == due
        assert {s.stop_at for s in db.scalars(select(StopSchedule))} == {due}
    response = alice.put(
        "/api/groups/group-1/policy",
        json={"policy": {"mode": "days", "days": 5}, "expected_revision": 1},
    )
    assert response.status_code == 200, response.text
    with SessionLocal() as db:
        grant = db.scalar(select(NativeGroupGrant))
        assert grant.stop_at == grant.activated_at + timedelta(days=5)
        grant.stop_at = now() - timedelta(minutes=1)
        for schedule in db.scalars(select(StopSchedule)):
            schedule.stop_at = grant.stop_at
        db.commit()
    assert enqueue_due() == 0
    assert enqueue_groups() == 1
    assert enqueue_groups() == 0
    with SessionLocal() as db:
        assert len(list(db.scalars(select(NativeGroupOperation)))) == 2
        assert not list(db.scalars(select(RecordOperation)))
    run_native()
    assert native.writes[-1] == ("cancel", "remote-group-1", "IMMEDIATE")


def test_individual_override_cannot_extend_controlling_group_deadline(alice, native):
    seed_group(1)
    assert (
        alice.put(
            "/api/groups/group-1/policy",
            json={"policy": {"mode": "days", "days": 3}, "expected_revision": 0},
        ).status_code
        == 200
    )
    assert subscribe(alice).status_code == 202
    run_native()
    r = alice.get("/api/subscriptions/group-1-record-0").json()
    response = alice.put(
        "/api/subscriptions/group-1-record-0/stop-schedule",
        json={
            "policy": {"mode": "days", "days": 4},
            "expected_revision": r["stop_schedule"]["revision"],
        },
    )
    assert response.status_code == 409, response.text


def test_confirmed_refusal_releases_reservations_once(alice, native, monkeypatch):
    seed_group(1)
    result = subscribe(alice)

    def refused(*_):
        raise AwsFailure(
            "AWS CreateAssignment: AccessDenied (HTTP 403)", uncertain=False
        )

    monkeypatch.setattr(native, "subscribe_group", refused)
    run_native()
    item = alice.get(f"/api/lifecycle-batches/{result.json()['id']}").json()["items"][0]
    assert item["state"] == "failed"
    assert counter() == (0, 0, 0)
    assert not run_native()
    assert counter() == (0, 0, 0)


def test_native_group_sync_uses_inherited_claim(alice, native):
    from app.lifecycle import run_operation

    activate(alice)
    result = alice.post(
        "/api/subscriptions/group-1-record-0/operations",
        json={"kind": "sync_status", "request_key": str(uuid.uuid4())},
    )
    assert result.status_code == 202, result.text
    run_operation(native)
    view = alice.get("/api/subscriptions/group-1-record-0").json()
    assert view["subscription_status"] == "active"
    assert view["observed_subscription_type"] == PRO


def test_native_group_sync_preserves_scheduled_cancellation(alice, native):
    from app.lifecycle import run_operation

    with SessionLocal() as db:
        db.get(AwsAccount, 1).control_plane = "kiro"
        db.commit()
    activate(alice)
    assert cancel_group(alice, cancellation_mode="END_OF_PERIOD").status_code == 202
    run_native()
    previous = alice.get("/api/subscriptions/group-1-record-0").json()
    result = alice.post(
        "/api/subscriptions/group-1-record-0/operations",
        json={"kind": "sync_status", "request_key": str(uuid.uuid4())},
    )
    assert result.status_code == 202, result.text
    run_operation(native)
    view = alice.get("/api/subscriptions/group-1-record-0").json()
    assert view["subscription_status"] == "cancel_scheduled"
    assert view["access_ends_at"] == previous["access_ends_at"]
    assert view["effective_subscription_source"] == "GROUP"
    from app.models import RecordOperation

    with SessionLocal() as db:
        assert db.get(RecordOperation, result.json()["id"]).state == "completed"


def test_empty_active_group_protects_group_and_plan_deletion(alice, admin, native):
    seed_group(0)
    assert subscribe(alice).status_code == 202
    run_native()
    response = alice.post(
        "/api/groups/group-1/jobs",
        json={
            "kind": "delete",
            "expected_revision": 1,
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 409
    assert (
        admin.request(
            "DELETE", "/api/admin/plans/1", json={"confirm_name": "Kiro Pro"}
        ).status_code
        == 409
    )


def test_wire_read_empty_group_alias_and_bounded_pagination():
    gateway = object.__new__(AwsGateway)
    group = SimpleNamespace(remote_id="g")
    pages = [
        {"claims": [], "nextToken": "two"},
        {
            "claims": [
                {
                    "principal": {"group": "g"},
                    "type": {"amazonQ": "KIRO_ENTERPRISE_PRO"},
                    "status": "PENDING",
                }
            ]
        },
    ]
    gateway._claims = lambda _: pages.pop(0)
    assert gateway.group_subscription_info(group) == {
        "status": "active",
        "subscription_type": PRO,
        "expires_at": None,
        "pending_type": None,
        "expected_effective_at": None,
    }
    gateway._claims = lambda _: {"claims": [], "nextToken": "same"}
    with pytest.raises(AwsFailure):
        gateway.group_subscription_info(group)


def test_join_uncertain_does_not_replay_and_keeps_reservation(alice, native):
    from app.group_jobs import run_group_job

    activate(alice)
    with SessionLocal() as db:
        db.add(
            Subscription(
                id="late",
                owner_id=2,
                aws_account_id=1,
                request_key="late",
                username="late",
                email="late@example.com",
                portal_url="https://example.com",
                state="completed",
                step="sso_ready",
                provision_only=True,
                reserved=False,
                sso_user_id="sso-late",
            )
        )
        db.commit()
    response = alice.post(
        "/api/groups/group-1/jobs",
        json={
            "kind": "attach",
            "record_id": "late",
            "expected_revision": 1,
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 202, response.text
    native.uncertain = True
    run_group_job(native)
    assert counter() == (1, 1, 1)
    assert alice.post("/api/groups/group-1/retry").status_code == 202
    run_group_job(native)
    assert counter() == (2, 0, 2)
    assert [w[0] for w in native.writes].count("attach") == 1


def test_native_provision_join_charges_group_plan_and_common_deadline(alice, native):
    from app.worker import run_one

    activate(alice)
    native.verify_identity = lambda self: None
    native.create_user = lambda self, r: "sso-" + r.id
    native.password = lambda self, r: "Test-only-password"
    response = alice.post(
        "/api/batches/create",
        json={
            "kind": "sso",
            "aws_account_id": 1,
            "group_id": "group-1",
            "items": [{"username": "late"}],
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 202, response.text
    assert counter() == (1, 1, 1)
    run_one(native)
    rid = response.json()["items"][0]["id"]
    view = alice.get(f"/api/subscriptions/{rid}").json()
    assert view["state"] == "completed", view
    assert view["subscription_source"] == "GROUP"
    assert counter() == (2, 0, 2)


def test_unmanaged_remote_assignment_blocks_sso_creation(alice, native):
    from app.worker import run_one

    seed_group(0)
    response = alice.post(
        "/api/batches/create",
        json={
            "kind": "sso",
            "aws_account_id": 1,
            "group_id": "group-1",
            "items": [{"username": "late"}],
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 202
    native.assignments["remote-group-1"] = {
        "status": "active",
        "subscription_type": PRO,
        "expires_at": None,
    }
    native.create_user = lambda *_: pytest.fail(
        "must not create SSO under unmanaged assignment"
    )
    run_one(native)
    view = alice.get(f"/api/subscriptions/{response.json()['items'][0]['id']}").json()
    assert view["state"] == "failed" and view["sso_user_id"] is None


def test_before_wire_rechecks_members_permissions_and_proxy(alice, native):
    seed_group(1)
    result = subscribe(alice)
    native.members[("remote-group-1", "foreign")] = "foreign-mid"
    run_native()
    assert not native.writes
    assert counter() == (0, 0, 0)
    assert (
        alice.get(f"/api/lifecycle-batches/{result.json()['id']}").json()["items"][0][
            "state"
        ]
        == "failed"
    )


def test_scheduled_native_override_detaches_one_member(alice, native):
    from app.schedules import enqueue_due
    from app.lifecycle import run_operation
    from app.models import StopSchedule

    activate(alice, 2)
    result = alice.put(
        "/api/subscriptions/group-1-record-0/stop-schedule",
        json={"policy": {"mode": "days", "days": 1}, "expected_revision": 1},
    )
    # No policy was configured at seed time, so create the first override.
    if result.status_code == 409:
        result = alice.put(
            "/api/subscriptions/group-1-record-0/stop-schedule",
            json={"policy": {"mode": "days", "days": 1}, "expected_revision": 0},
        )
    assert result.status_code == 200, result.text
    with SessionLocal() as db:
        db.get(StopSchedule, "group-1-record-0").stop_at = now() - timedelta(seconds=1)
        db.commit()
    assert enqueue_due() == 1
    run_operation(native)
    assert len(native.members) == 1
    assert native.assignments["remote-group-1"]["status"] == "active"
    assert not any(w[0] == "USER_cancel" for w in native.writes)


def test_update_native_rule_supersedes_unclaimed_group_cancel(alice, native):
    from app.group_subscription_worker import enqueue_due
    from app.models import NativeGroupGrant

    activate(alice)
    with SessionLocal() as db:
        group = db.get(ManagedGroup, "group-1")
        group.policy_mode, group.policy_days, group.policy_revision = "days", 1, 1
        grant = db.scalar(select(NativeGroupGrant))
        grant.stop_at, grant.policy_revision = now() - timedelta(seconds=1), 1
        db.commit()
    assert enqueue_due() == 1
    response = alice.put(
        "/api/groups/group-1/policy",
        json={"policy": {"mode": "days", "days": 2}, "expected_revision": 1},
    )
    assert response.status_code == 200, response.text
    assert not run_native()
    assert [w[0] for w in native.writes] == ["create"]


def test_cancelled_group_provenance_never_becomes_user(alice, native):
    activate(alice)
    assert cancel_group(alice).status_code == 202
    run_native()
    view = alice.get("/api/subscriptions/group-1-record-0").json()
    assert view["subscription_source"] == "GROUP"
    assert view["effective_subscription_source"] is None


def test_active_group_join_rejects_unmanaged_remote_member_before_join(alice, native):
    from app.group_jobs import run_group_job

    activate(alice)
    with SessionLocal() as db:
        db.add(
            Subscription(
                id="late",
                owner_id=2,
                aws_account_id=1,
                request_key="late",
                username="late",
                email="late@example.com",
                portal_url="https://example.com",
                state="completed",
                step="sso_ready",
                provision_only=True,
                reserved=False,
                sso_user_id="sso-late",
            )
        )
        db.commit()
    response = alice.post(
        "/api/groups/group-1/jobs",
        json={
            "kind": "attach",
            "record_id": "late",
            "expected_revision": 1,
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 202
    native.members[("remote-group-1", "foreign")] = "foreign-mid"
    run_group_job(native)
    assert not any(w[0] == "attach" for w in native.writes)
    assert counter() == (1, 0, 1)


def test_native_end_of_period_keeps_access_until_readonly_expiry(alice, native):
    from app.group_subscription_worker import reconcile_due
    from app.models import NativeGroupGrant

    with SessionLocal() as db:
        db.get(AwsAccount, 1).control_plane = "kiro"
        db.commit()
    activate(alice)
    assert cancel_group(alice, cancellation_mode="END_OF_PERIOD").status_code == 202
    run_native()
    view = alice.get("/api/subscriptions/group-1-record-0").json()
    assert view["subscription_status"] == "cancel_scheduled"
    assert view["effective_subscription_source"] == "GROUP"
    assert cancel_group(alice).status_code == 409
    with SessionLocal() as db:
        grant = db.scalar(select(NativeGroupGrant))
        grant.access_ends_at = now() - timedelta(seconds=1)
        db.commit()
    native.assignments["remote-group-1"]["expires_at"] = now() - timedelta(seconds=1)
    assert reconcile_due(native) == 1
    assert len(native.writes) == 2
    assert (
        alice.get("/api/subscriptions/group-1-record-0").json()["subscription_status"]
        == "cancelled"
    )
    assert counter() == (1, 0, 1)


def test_expired_native_write_lease_only_reads(alice, native):
    from app.models import NativeGroupOperation

    seed_group(1)
    response = subscribe(alice)
    with SessionLocal() as db:
        op = db.scalar(select(NativeGroupOperation))
        op.state, op.phase = "running", "pending"
        op.lease_token, op.lease_until = "dead-worker", now() - timedelta(seconds=1)
        op.write_requested_at = now()
        db.commit()
    native.assignments["remote-group-1"] = {
        "status": "active",
        "subscription_type": PRO,
        "expires_at": None,
    }
    run_native()
    assert not native.writes
    assert counter() == (1, 0, 1)
    assert (
        alice.get(f"/api/lifecycle-batches/{response.json()['id']}").json()["items"][0][
            "state"
        ]
        == "completed"
    )


def test_migration_v10_keeps_every_existing_value(tmp_path):
    from sqlalchemy import create_engine, inspect
    from app.database import Base
    from app.migrations import migrate, VERSION
    from app.models import SchemaVersion

    engine = create_engine(f"sqlite:///{tmp_path / 'migration.db'}")
    native_tables = {
        "console_native_group_grants",
        "console_native_group_operations",
        "console_group_member_activations",
        "console_lifecycle_batches",
        "console_lifecycle_batch_items",
    }
    Base.metadata.create_all(
        engine,
        tables=[t for t in Base.metadata.sorted_tables if t.name not in native_tables],
    )
    with engine.begin() as conn:
        conn.execute(SchemaVersion.__table__.insert(), {"version": 10})
    # Copy all old rows from the realistic shared test fixture, retaining all columns.
    from app.database import engine as source_engine

    with source_engine.connect() as source, engine.begin() as target:
        for table in Base.metadata.sorted_tables:
            if (
                table.name not in native_tables
                and table.name != "console_schema_version"
            ):
                rows = [dict(r) for r in source.execute(table.select()).mappings()]
                if rows:
                    target.execute(table.insert(), rows)
    with engine.connect() as conn:
        before = {
            name: conn.exec_driver_sql(f'SELECT * FROM "{name}"').fetchall()
            for name in inspect(conn).get_table_names()
            if name != "console_schema_version"
        }
    migrate(engine)
    migrate(engine)
    with engine.connect() as conn:
        for name, rows in before.items():
            assert conn.exec_driver_sql(f'SELECT * FROM "{name}"').fetchall() == rows
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
        assert (
            conn.exec_driver_sql("SELECT version FROM console_schema_version").scalar()
            == VERSION
        )
        assert native_tables <= set(inspect(conn).get_table_names())


def test_native_provisioning_claim_parallelizes_credentials_and_serializes_members(alice, native):
    from app.worker import claim

    activate(alice, 0)
    response = alice.post(
        "/api/batches/create",
        json={
            "kind": "sso",
            "aws_account_id": 1,
            "group_id": "group-1",
            "items": [{"username": "one"}, {"username": "two"}],
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 202
    ids = [item['id'] for item in response.json()['items']]
    assert {claim()[0], claim()[0]} == set(ids)
    assert claim() is None
    with SessionLocal() as db:
        assert db.get(ManagedGroup, 'group-1').active_job_id is None
        for rid in ids:
            record = db.get(Subscription, rid)
            record.state, record.step = 'queued', 'subscribe'
            record.lease_token = record.lease_until = None
        db.commit()
    first = claim()
    assert first and first[0] in ids
    with SessionLocal() as db:
        assert db.get(ManagedGroup, 'group-1').active_job_id == first[0]
    assert claim() is None


def test_native_join_failure_then_retry_rereserves_quota(alice, native, monkeypatch):
    from app.worker import run_one

    activate(alice)
    response = alice.post(
        "/api/batches/create",
        json={
            "kind": "sso",
            "aws_account_id": 1,
            "group_id": "group-1",
            "items": [{"username": "late"}],
            "request_key": str(uuid.uuid4()),
        },
    )
    rid = response.json()["items"][0]["id"]
    monkeypatch.setattr(
        native,
        "verify_identity",
        lambda *_: (_ for _ in ()).throw(AwsFailure("refused")),
        raising=False,
    )
    run_one(native)
    assert counter() == (1, 0, 1)
    assert alice.post(f"/api/subscriptions/{rid}/retry").status_code == 202
    assert counter() == (1, 1, 1)


def test_aws_membership_pagination_rejects_repeated_cursor():
    gateway = object.__new__(AwsGateway)
    gateway.account = SimpleNamespace(identity_store_id="d")
    calls = []

    def page(**kwargs):
        calls.append(kwargs)
        if len(calls) > 3:
            raise AssertionError("unbounded membership pagination")
        return {"GroupMemberships": [], "NextToken": "same"}

    gateway.identity = SimpleNamespace(list_group_memberships=page)
    with pytest.raises(AwsFailure):
        gateway.list_group_memberships("g")


def test_group_directory_account_and_fuzzy_filters_intersect(alice, native):
    seed_group(1, gid="red-team")
    seed_group(1, gid="blue-team")
    assert [
        g["id"]
        for g in alice.get("/api/groups?aws_account_id=1&q=red&member_q=record").json()
    ] == ["red-team"]
    assert alice.get("/api/groups?aws_account_id=999&q=red").json() == []


def test_individual_cancel_replays_original_body_after_native_detach(alice, native):
    from app.lifecycle import run_operation

    activate(alice)
    body = {
        "kind": "cancel_subscription",
        "cancellation_mode": "IMMEDIATE",
        "confirm_username": "group-1-record-0",
        "request_key": str(uuid.uuid4()),
    }
    first = alice.post("/api/subscriptions/group-1-record-0/operations", json=body)
    run_operation(native)
    replay = alice.post("/api/subscriptions/group-1-record-0/operations", json=body)
    assert replay.status_code == 202, replay.text
    assert replay.json()["id"] == first.json()["id"]


def test_group_resubscribe_other_plan_keeps_original_and_changes_effective_plan(
    alice, native, monkeypatch
):
    from app.config import settings

    monkeypatch.setattr(settings, "plan_changes_enabled", True)
    activate(alice)
    assert cancel_group(alice).status_code == 202
    run_native()
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    view = alice.get("/api/subscriptions/group-1-record-0").json()
    assert view["plan_id"] == 1 and view["current_plan"]["plan_id"] == 2
    options = alice.get("/api/subscriptions/group-1-record-0/plan-options").json()
    assert options["current_plan"]["plan_id"] is None
    assert options["effective_plan"]["plan_id"] == 2
    assert options["unavailable_reason"]


def test_plan_usage_counts_current_native_grant_on_its_effective_plan(alice, admin, native):
    activate(alice)
    assert cancel_group(alice).status_code == 202
    run_native()
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    views = {p["id"]: p for p in admin.get("/api/plans").json()}
    assert views[1]["usage"]["records"] == 1
    assert views[1]["usage"]["subscriptions_active"] == 0
    assert views[2]["usage"]["subscriptions_active"] == 1


def test_group_member_history_preserves_each_counted_activation(alice, native):
    activate(alice)
    assert cancel_group(alice).status_code == 202
    run_native()
    assert subscribe(alice).status_code == 202
    run_native()
    response = alice.get("/api/subscriptions/group-1-record-0/group-activations")
    assert response.status_code == 200, response.text
    assert len(response.json()) == 2
    assert all(a["counted"] for a in response.json())


def test_ssos_expose_pending_native_operation(alice, native):
    seed_group(1)
    assert subscribe(alice).status_code == 202
    r = alice.get("/api/subscriptions/group-1-record-0").json()
    assert r["operation"]["principal_type"] == "GROUP"
    assert r["operation"]["state"] == "queued"
    assert r["effective_subscription_source"] is None


def test_bulk_native_partial_failure_keeps_per_item_results_and_counts(
    alice, native, monkeypatch
):
    seed_group(1)
    seed_group(1, gid="group-2")
    body = {
        "group_ids": ["group-1", "group-2"],
        "plan_id": 1,
        "request_key": str(uuid.uuid4()),
    }
    result = alice.post("/api/group-subscriptions", json=body)
    assert result.status_code == 202, result.text
    assert counter() == (0, 2, 0)
    original = native.subscribe_group

    def partial(self, group, plan):
        if group.id == "group-2":
            raise AwsFailure("explicit second principal refusal")
        return original(self, group, plan)

    monkeypatch.setattr(native, "subscribe_group", partial)
    run_native()
    run_native()
    detail = alice.get(f"/api/lifecycle-batches/{result.json()['id']}").json()
    assert detail["states"]["completed"] == 1 and detail["states"]["failed"] == 1
    assert counter() == (1, 0, 1)
    monkeypatch.setattr(native, "subscribe_group", original)
    assert subscribe(alice, "group-2").status_code == 202
    run_native()
    assert counter() == (2, 0, 2)


def test_admin_native_history_counts_each_activation_once(admin, native):
    seed_group(2, owner=1)
    assert subscribe(admin).status_code == 202
    run_native()
    summary = admin.get("/api/overview").json()["member_summary"]
    actor = next(u for u in summary["users"] if u["id"] == 1)
    assert (
        next(c for c in actor["counters"] if c["plan_id"] == 1)["lifetime_count"] == 2
    )
    history = admin.get("/api/admin/users/1/plan-history?plan_id=1").json()
    assert history["total"] == 2
    assert all(h["event_kind"] == "group_activation" for h in history["items"])


@pytest.mark.parametrize("change", ["binding", "account", "plan", "proxy"])
def test_saved_native_operation_rechecks_authority_and_configuration(
    alice, native, change
):
    from app.models import Binding, Plan, Proxy
    from app.security import encrypt

    seed_group(1)
    assert subscribe(alice).status_code == 202
    with SessionLocal() as db:
        if change == "binding":
            db.delete(db.get(Binding, (2, 1)))
        elif change == "account":
            db.get(AwsAccount, 1).active = False
        elif change == "plan":
            db.get(Plan, 1).active = False
        else:
            proxy = Proxy(
                name="new-proxy",
                host="127.0.0.1",
                port=1080,
                auth_encrypted=encrypt({"username": "", "password": ""}),
            )
            db.add(proxy)
            db.flush()
            db.get(AwsAccount, 1).proxy_id = proxy.id
        db.commit()
    run_native()
    assert not native.writes
    assert counter() == (0, 0, 0)


def test_accepted_aws_request_id_survives_delayed_readback(alice, native, monkeypatch):
    from app.models import NativeGroupOperation

    seed_group(1)
    assert subscribe(alice).status_code == 202
    original = native.subscribe_group

    def delayed(self, group, plan):
        rid = original(self, group, plan)
        native.assignments.clear()
        return rid

    monkeypatch.setattr(native, "subscribe_group", delayed)
    run_native()
    with SessionLocal() as db:
        op = db.scalar(select(NativeGroupOperation))
        assert op.state == "needs_review"
        assert op.aws_request_id == "group-create-request"
    assert counter() == (0, 1, 0)


def test_resubscribe_reanchors_expired_inherited_days(alice, native):
    from app.models import StopSchedule

    seed_group(1)
    assert (
        alice.put(
            "/api/groups/group-1/policy",
            json={"policy": {"mode": "days", "days": 1}, "expected_revision": 0},
        ).status_code
        == 200
    )
    assert subscribe(alice).status_code == 202
    run_native()
    assert cancel_group(alice).status_code == 202
    run_native()
    with SessionLocal() as db:
        schedule = db.get(StopSchedule, "group-1-record-0")
        schedule.stop_at = now() - timedelta(days=1)
        db.commit()
    result = subscribe(alice)
    assert result.status_code == 202, result.text
    run_native()
    view = alice.get("/api/subscriptions/group-1-record-0").json()
    assert view["stop_schedule"]["state"] == "scheduled"


def test_sources_use_paginated_member_lookup_and_fresh_claim_read_scopes():
    gateway = object.__new__(AwsGateway)
    gateway.account = SimpleNamespace(identity_store_id="d")
    reads = {"claims": 0, "members": []}
    current = [
        {"principal": {"group": f"g{i}"}, "type": {"amazonQ": "KIRO_ENTERPRISE_PRO"}}
        for i in range(100)
    ]

    def claims(token):
        reads["claims"] += 1
        return {"claims": list(current)}

    def memberships(**body):
        reads["members"].append(body)
        if not body.get("NextToken"):
            return {
                "GroupMemberships": [{"GroupId": "g1", "MembershipId": "m1"}],
                "NextToken": "page2",
            }
        return {"GroupMemberships": [{"GroupId": "g3", "MembershipId": "m3"}]}

    gateway._claims = claims
    gateway.identity = SimpleNamespace(list_group_memberships_for_member=memberships)
    with gateway.claim_snapshot():
        assert (
            gateway.group_subscription_info(SimpleNamespace(remote_id="g1"))["status"]
            == "active"
        )
        source = gateway.user_subscription_sources(SimpleNamespace(sso_user_id="u1"))
        assert {c["group_id"] for c in source} == {"g1", "g3"}
    assert reads["claims"] == 1
    assert len(reads["members"]) == 2
    assert reads["members"][0] == {
        "IdentityStoreId": "d",
        "MemberId": {"UserId": "u1"},
        "MaxResults": 100,
    }
    current.clear()
    with gateway.claim_snapshot():
        assert (
            gateway.user_subscription_sources(SimpleNamespace(sso_user_id="u1")) == []
        )
    assert reads["claims"] == 2


def test_native_group_cancellation_capability_available_for_empty_group(alice, native):
    seed_group(0)
    result = alice.get("/api/groups/group-1").json()
    assert result["supports_scheduled_cancellation"] is False
    with SessionLocal() as db:
        db.get(AwsAccount, 1).control_plane = "kiro"
        db.commit()
    assert alice.get("/api/groups").json()[0]["supports_scheduled_cancellation"] is True


def test_pending_native_provision_join_reconciles_after_owner_disabled(
    alice, admin, native, monkeypatch
):
    from app.worker import run_one
    from app.models import User

    activate(alice)
    monkeypatch.setattr(native, "verify_identity", lambda *_: None, raising=False)
    monkeypatch.setattr(
        native, "create_user", lambda self, r: "sso-" + r.id, raising=False
    )
    monkeypatch.setattr(
        native, "password", lambda *_: "Test-only-password", raising=False
    )
    result = alice.post(
        "/api/batches/create",
        json={
            "kind": "sso",
            "aws_account_id": 1,
            "group_id": "group-1",
            "items": [{"username": "late"}],
            "request_key": str(uuid.uuid4()),
        },
    )
    rid = result.json()["items"][0]["id"]
    native.uncertain = True
    run_one(native)
    with SessionLocal() as db:
        db.get(User, 2).active = False
        db.commit()
    response = admin.post(f"/api/subscriptions/{rid}/retry")
    assert response.status_code == 202, response.text
    run_one(native)
    assert counter() == (2, 0, 2)
    assert [w[0] for w in native.writes].count("attach") == 1
