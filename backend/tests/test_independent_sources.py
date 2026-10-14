"""GROUP settlement must never replace independent access or USER history."""

import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.aws import AwsFailure, AwsGateway
from app.database import SessionLocal
from app.models import GroupMemberActivation, NativeGroupGrant, StopSchedule, Subscription, now
from test_native_groups import NativeGateway, native, seed_group, subscribe, cancel_group, run_native, counter

PRO = "Q_DEVELOPER_STANDALONE_PRO"
PLUS = "Q_DEVELOPER_STANDALONE_PRO_PLUS"
RID = "group-1-record-0"
UID = "sso-" + RID


def claim(source="USER", kind=PRO, group_id=None, **kw):
    return dict(source=source, group_id=group_id, status="active", subscription_type=kind,
                expires_at=None, **kw)


def aggregate(kind=PRO, source="INDIVIDUAL_AND_GROUP", status="ACTIVE", **kw):
    return dict(principal={"user": UID}, type={"amazonQ": kind}, status=status,
                aggregatedSubscriptionType=source, **kw)


def independent(native, source):
    seed_group(1)
    native.user_claims[UID] = [claim(source, PRO, "independent-group" if source == "GROUP" else None)]
    native.effective_rows = [aggregate(PRO, "INDIVIDUAL_AND_GROUP" if source == "USER" else "GROUP")]
    with SessionLocal() as db:
        r = db.get(Subscription, RID)
        r.counted, r.subscription_status, r.observed_subscription_type = True, "active", PRO
        r.plan_id, r.subscription_type, r.plan_name_snapshot = 1, PRO, "Original Pro"
        r.subscribed_at = now() - timedelta(days=8)
        db.add(StopSchedule(record_id=RID, actor_id=2, mode="at", state="scheduled",
                            individual_override=True, stop_at=now() + timedelta(days=10)))
        db.commit()


@pytest.mark.parametrize("source", ["USER", "GROUP"])
@pytest.mark.parametrize("ending", ["cancel", "detach", "individual"])
def test_group_opening_and_removal_preserve_independent_access(alice, native, source, ending):
    independent(native, source)
    before = alice.get(f"/api/subscriptions/{RID}").json()
    result = subscribe(alice, plan_id=2)
    assert result.status_code == 202, result.text
    run_native()
    opened = alice.get(f"/api/subscriptions/{RID}").json()
    # Deliberately lower than the GROUP tier: only the AWS aggregate is authoritative.
    assert opened["current_plan"]["subscription_type"] == PRO
    assert opened["effective_subscription_source"] == ("USER_AND_GROUP" if source == "USER" else "GROUP")
    assert opened["direct_user_plan"]["subscription_type"] == (PRO if source == "USER" else None)
    assert opened["native_group_subscription"]["subscription_type"] == PLUS
    native.effective_rows = [aggregate(PRO, "INDIVIDUAL" if source == "USER" else "GROUP")]
    if ending == "cancel":
        assert cancel_group(alice).status_code == 202
        run_native()
    elif ending == "detach":
        from app.group_jobs import run_group_job
        result = alice.post("/api/groups/group-1/jobs", json={"kind": "detach", "record_id": RID,
                           "expected_revision": 1, "request_key": str(uuid.uuid4())})
        assert result.status_code == 202, result.text
        run_group_job(native)
    else:
        from app.lifecycle import run_operation
        result = alice.post(f"/api/subscriptions/{RID}/operations", json={"kind": "cancel_subscription",
                           "confirm_username": RID, "cancellation_mode": "IMMEDIATE", "request_key": str(uuid.uuid4())})
        assert result.status_code == 202, result.text
        run_operation(native)
    after = alice.get(f"/api/subscriptions/{RID}").json()
    assert after["operation"]["state"] == "completed" if after.get("operation") else True
    assert after["subscription_status"] == "active"
    assert after["current_plan"]["subscription_type"] == PRO
    assert after["effective_subscription_source"] == source
    assert after["cancelled_at"] is None and after["access_ends_at"] is None
    assert after["stop_schedule"]["state"] == "scheduled"
    assert after["stop_schedule"]["stop_at"] == before["stop_schedule"]["stop_at"]
    for field in ("plan_id", "subscription_type", "subscribed_at"):
        assert after[field] == before[field]
    assert not any(w[0] == "USER_cancel" for w in native.writes)
    with SessionLocal() as db:
        activation = db.scalar(select(GroupMemberActivation))
        assert activation.counted and activation.state == "cancelled" and not activation.first_opening


@pytest.mark.parametrize("source", ["USER", "GROUP"])
def test_subscribed_group_join_accepts_confirmed_independent_source(alice, native, source):
    from app.group_jobs import run_group_job
    seed_group(0)
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    with SessionLocal() as db:
        db.add(Subscription(id=RID, owner_id=2, aws_account_id=1, request_key=RID,
                            username=RID, email="join@example.com", portal_url="https://example.com",
                            state="completed", step="done", reserved=False, counted=True,
                            sso_user_id=UID, plan_id=1, subscription_type=PRO,
                            subscription_status="active", observed_subscription_type=PRO))
        db.commit()
    native.user_claims[UID] = [claim(source, PRO, "other" if source == "GROUP" else None)]
    native.effective_rows = [aggregate(PRO, "INDIVIDUAL_AND_GROUP" if source == "USER" else "GROUP")]
    response = alice.post("/api/groups/group-1/jobs", json={"kind": "attach", "record_id": RID,
                         "expected_revision": 1, "request_key": str(uuid.uuid4())})
    assert response.status_code == 202, response.text
    run_group_job(native)
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["group_membership_id"]
    assert view["current_plan"]["subscription_type"] == PRO
    assert view["subscription_status"] == "active"
    assert [w[0] for w in native.writes] == ["create", "attach"]


@pytest.mark.parametrize("bad", [
    [claim(), claim()],
    [claim("GROUP", group_id=None)],
    [dict(claim(), status="pending")],
    [dict(claim(), subscription_type="UNKNOWN")],
])
def test_opening_remains_conservative_for_ambiguous_claims(alice, native, bad):
    seed_group(1)
    native.user_claims[UID] = bad
    assert subscribe(alice).status_code == 409
    assert not native.writes and counter() == (0, 0, 0)


@pytest.mark.parametrize("source", ["user", "group"])
def test_claim_observation_preserves_pending_tier_and_boundary(source):
    gateway = object.__new__(AwsGateway)
    boundary = now() + timedelta(days=12)
    gateway._claims = lambda token: {"claims": [{"principal": {source: "principal"},
        "type": {"amazonQ": "KIRO_ENTERPRISE_PRO_PLUS"},
        "newType": {"amazonQ": "KIRO_ENTERPRISE_PRO"}, "expirationDate": boundary.isoformat()}]}
    gateway.list_user_memberships = lambda uid: {"principal": "membership"}
    observed = (gateway.group_subscription_info(SimpleNamespace(remote_id="principal")) if source == "group"
                else gateway.user_subscription_sources(SimpleNamespace(sso_user_id="principal"))[0])
    assert observed["status"] == "active" and observed["expires_at"] is None
    assert observed["subscription_type"] == PLUS
    assert observed["pending_type"] == PRO
    assert observed["expected_effective_at"] == boundary


def test_sync_reads_aws_aggregate_not_latest_group_history(alice, native):
    from app.lifecycle import run_operation
    independent(native, "USER")
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    native.effective_rows = [aggregate(PLUS)]
    result = alice.post(f"/api/subscriptions/{RID}/operations", json={"kind": "sync_status",
                       "confirm_username": RID, "request_key": str(uuid.uuid4())})
    assert result.status_code == 202
    run_operation(native)
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["current_plan"]["subscription_type"] == PLUS
    assert view["direct_user_plan"]["subscription_type"] == PRO
    assert view["effective_subscription_source"] == "USER_AND_GROUP"


def test_missing_aggregate_after_write_keeps_reservation_for_readonly_recovery(alice, native):
    from app.retry_models import AutomaticRetry
    from test_automatic_retries import due

    seed_group(1)
    native.effective_rows = []
    result = subscribe(alice)
    assert result.status_code == 202
    run_native()
    assert counter() == (0, 1, 0)
    batch = alice.get(f"/api/lifecycle-batches/{result.json()['id']}").json()
    item = batch["items"][0]
    assert item["state"] == "queued"
    with SessionLocal() as db:
        retry = db.get(AutomaticRetry, ("native", item["operation_id"]))
        assert retry.mode == "reconcile" and retry.retry_count == 0
        assert retry.propagation_check_count == 1 and retry.propagation_started_at
    assert len(native.writes) == 1
    native.effective_rows = None
    due("native", item["operation_id"])
    run_native()
    batch = alice.get(f"/api/lifecycle-batches/{result.json()['id']}").json()
    assert batch["items"][0]["state"] == "completed"
    assert counter() == (1, 0, 1) and len(native.writes) == 1


def test_personal_user_deadline_runs_while_group_grant_remains(alice, native, monkeypatch):
    from app.schedules import enqueue_due
    from app.lifecycle import run_operation
    independent(native, "USER")
    with SessionLocal() as db:
        db.get(StopSchedule, RID).individual_override = False
        db.commit()
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    with SessionLocal() as db:
        db.get(StopSchedule, RID).stop_at = now() - timedelta(seconds=1)
        db.commit()
    monkeypatch.setattr(native, "subscription_info", lambda self, r: self.user_claims[r.sso_user_id][0])
    def cancel(self, r, mode):
        self.writes.append(("USER_cancel", r.id, mode))
        self.user_claims[r.sso_user_id][0].update(status="cancelled", expires_at=now())
        type(self).effective_rows = [aggregate(PLUS, "GROUP")]
        return "user-cancel"
    monkeypatch.setattr(native, "cancel_subscription", cancel)
    assert enqueue_due() == 1
    run_operation(native)
    after = alice.get(f"/api/subscriptions/{RID}").json()
    assert alice.get(f"/api/subscriptions/{RID}/operations").json()[0]["state"] == "completed"
    assert after["subscription_status"] == "active"
    assert after["effective_subscription_source"] == "GROUP"
    assert after["stop_schedule"]["state"] == "completed"
    assert ("remote-group-1", UID) in native.members
    assert [w[0] for w in native.writes] == ["create", "USER_cancel"]


def test_aggregate_pending_is_confirmed_access_and_read_once_per_group(alice, native, monkeypatch):
    seed_group(2)
    reads = []
    report = native.report_subscriptions
    def observed(self):
        reads.append("read")
        return [dict(row, status="PENDING") for row in report(self)]
    monkeypatch.setattr(native, "report_subscriptions", observed)
    assert subscribe(alice).status_code == 202
    run_native()
    assert counter() == (2, 0, 2)
    assert reads == ["read"]
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["subscription_status"] == "active"
    assert view["aws_subscription_status"] == "PENDING"


def test_personal_user_deadline_can_extend_beyond_independent_group_deadline(alice, native):
    from app.models import ManagedGroup
    independent(native, "USER")
    with SessionLocal() as db:
        group = db.get(ManagedGroup, "group-1")
        group.policy_mode, group.policy_days = "days", 1
        db.commit()
    assert subscribe(alice).status_code == 202
    run_native()
    result = alice.put(f"/api/subscriptions/{RID}/stop-schedule", json={
        "expected_revision": 1, "policy": {"mode": "at", "stop_at": (now() + timedelta(days=20)).isoformat() + "Z"}})
    assert result.status_code == 200, result.text
    assert result.json()["state"] == "scheduled"


@pytest.mark.parametrize("bad_status", ["pending", "unknown"])
def test_opening_blocks_unconfirmed_local_subscription(alice, native, bad_status):
    seed_group(1)
    with SessionLocal() as db:
        db.get(Subscription, RID).subscription_status = bad_status
        db.commit()
    assert subscribe(alice).status_code == 409
    assert not native.writes


@pytest.mark.parametrize("target_claims", [[], [claim("GROUP", PRO, "different")], [claim("GROUP", PLUS, "target")]])
def test_target_group_must_exist_with_exact_plan_even_when_user_remains(target_claims):
    from app.group_subscription_state import verify_member_sources
    gateway = SimpleNamespace(user_subscription_sources=lambda record: [claim()] + target_claims)
    with pytest.raises(AwsFailure):
        verify_member_sources(gateway, SimpleNamespace(), SimpleNamespace(remote_id="target"), PRO)


def test_version_eleven_migration_adds_nullable_snapshot_without_changing_old_rows(tmp_path):
    from sqlalchemy import create_engine, inspect
    from app.database import Base
    from app.migrations import migrate, VERSION
    from app.models import SchemaVersion
    engine = create_engine(f"sqlite:///{tmp_path / 'sources.db'}")
    Base.metadata.create_all(engine)
    with engine.begin() as c:
        c.exec_driver_sql("ALTER TABLE console_subscriptions DROP COLUMN subscription_observation")
        c.exec_driver_sql("ALTER TABLE console_stop_schedules DROP COLUMN principal_type")
        c.execute(SchemaVersion.__table__.insert(), {"version": 11})
        c.exec_driver_sql("INSERT INTO console_subscriptions (id, owner_id, aws_account_id, request_key, username, email, state, step, credential_state, credential_revision, portal_url, counted, reserved, attempts, created_at, updated_at, subscription_status, provision_only) VALUES ('legacy', 2, 1, 'legacy', 'legacy', 'legacy@example.com', 'completed', 'done', 'one_time', 1, 'https://example.com', 0, 0, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'not_subscribed', 1)")
        # Populate referenced parents from the realistic test database.
        with SessionLocal() as source:
            for name in ("console_users", "console_aws_accounts"):
                table = Base.metadata.tables[name]
                rows = [dict(row) for row in source.execute(table.select()).mappings()]
                c.execute(table.insert(), rows)
        c.exec_driver_sql("INSERT INTO console_stop_schedules (record_id, actor_id, revision, individual_override, mode, days, state, created_at, updated_at) VALUES ('legacy', 2, 1, 1, 'days', 30, 'waiting', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)")
        columns = [x["name"] for x in inspect(c).get_columns("console_subscriptions")]
        schedule_columns = [x["name"] for x in inspect(c).get_columns("console_stop_schedules")]
        before = c.exec_driver_sql("SELECT * FROM console_subscriptions").fetchall()
        schedules_before = c.exec_driver_sql("SELECT * FROM console_stop_schedules").fetchall()
    migrate(engine)
    migrate(engine)
    with engine.connect() as c:
        selected = ','.join('"' + name + '"' for name in columns)
        assert c.exec_driver_sql(f"SELECT {selected} FROM console_subscriptions").fetchall() == before
        assert c.exec_driver_sql("SELECT subscription_observation FROM console_subscriptions").scalar() is None
        selected = ','.join('"' + name + '"' for name in schedule_columns)
        assert c.exec_driver_sql(f"SELECT {selected} FROM console_stop_schedules").fetchall() == schedules_before
        assert c.exec_driver_sql("SELECT principal_type FROM console_stop_schedules").scalar() is None
        assert c.exec_driver_sql("SELECT version FROM console_schema_version").scalar() == VERSION
        assert c.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []


@pytest.mark.parametrize("source", ["USER", "GROUP"])
def test_group_period_end_reconciliation_preserves_independent_access(alice, native, source):
    from app.group_subscription_worker import reconcile_due
    from app.models import AwsAccount
    independent(native, source)
    with SessionLocal() as db:
        db.get(AwsAccount, 1).control_plane = "kiro"
        db.commit()
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    assert cancel_group(alice, cancellation_mode="END_OF_PERIOD").status_code == 202
    run_native()
    before = alice.get(f"/api/subscriptions/{RID}").json()
    assert before["subscription_status"] == "active"
    assert before["native_group_subscription"]["state"] == "cancel_scheduled"
    assert before["stop_schedule"]["state"] == "scheduled"
    native.assignments["remote-group-1"]["expires_at"] = now() - timedelta(seconds=1)
    native.effective_rows = [aggregate(PRO, "INDIVIDUAL" if source == "USER" else "GROUP")]
    with SessionLocal() as db:
        db.scalar(select(NativeGroupGrant)).access_ends_at = now() - timedelta(seconds=1)
        db.commit()
    assert reconcile_due(native) == 1
    after = alice.get(f"/api/subscriptions/{RID}").json()
    assert after["subscription_status"] == "active" and after["observed_subscription_type"] == PRO
    assert after["native_group_subscription"]["state"] == "cancelled"
    assert after["stop_schedule"]["state"] == "scheduled"
    assert [w[0] for w in native.writes] == ["create", "cancel"]


def test_group_cancel_completes_only_its_inherited_schedule(alice, native):
    independent(native, "USER")
    with SessionLocal() as db:
        schedule = db.get(StopSchedule, RID)
        schedule.source_group_id, schedule.individual_override = "group-1", False
        db.commit()
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    native.effective_rows = [aggregate(PRO, "INDIVIDUAL")]
    assert cancel_group(alice).status_code == 202
    run_native()
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["stop_schedule"]["state"] == "completed"
    assert view["subscription_status"] == "active" and view["cancelled_at"] is None


def test_reopening_group_keeps_original_group_provenance(alice, native):
    seed_group(1)
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    assert cancel_group(alice).status_code == 202
    run_native()
    assert subscribe(alice).status_code == 202
    run_native()
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["subscription_source"] == "GROUP"
    assert view["subscription_type"] == PLUS
    assert view["current_plan"]["subscription_type"] == PRO


@pytest.mark.parametrize("missing", [False, True])
def test_user_deadline_never_becomes_group_detach_after_external_user_cancellation(alice, native, monkeypatch, missing):
    from app.schedules import enqueue_due
    from app.lifecycle import run_operation
    independent(native, "USER")
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    native.user_claims[UID][0].update(status="cancelled", expires_at=now() - timedelta(seconds=1))
    if missing:
        native.user_claims[UID] = []
    native.effective_rows = [aggregate(PLUS, "GROUP")]
    monkeypatch.setattr(native, "subscription_info", lambda self, r: self.user_claims[r.sso_user_id][0]
                        if self.user_claims[r.sso_user_id] else {"status": "not_subscribed", "subscription_type": None, "expires_at": None})
    response = alice.post(f"/api/subscriptions/{RID}/operations", json={"kind": "sync_status", "request_key": str(uuid.uuid4())})
    assert response.status_code == 202
    run_operation(native)
    with SessionLocal() as db:
        db.get(StopSchedule, RID).stop_at = now() - timedelta(seconds=1)
        db.commit()
    assert enqueue_due() == 1
    run_operation(native)
    assert ("remote-group-1", UID) in native.members
    assert [w[0] for w in native.writes] == ["create"]
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["subscription_status"] == "active"
    assert view["stop_schedule"]["principal_type"] == "USER"
    assert view["stop_schedule"]["state"] == "completed"


def test_ambiguous_legacy_personal_deadline_waits_for_explicit_scope(alice, native):
    from app.schedules import enqueue_due
    seed_group(1)
    assert subscribe(alice).status_code == 202
    run_native()
    native.user_claims[UID] = [claim()]
    native.effective_rows = [aggregate(PRO)]
    from app.subscription_sources import observe_subscription, apply_observation
    from app.models import AwsAccount
    with SessionLocal() as db:
        record = db.get(Subscription, RID)
        apply_observation(record, observe_subscription(native(db.get(AwsAccount, 1)), record))
        db.add(StopSchedule(record_id=RID, actor_id=2, mode="at", state="scheduled", individual_override=True,
                            stop_at=now() - timedelta(seconds=1)))
        db.commit()
    assert enqueue_due() == 0
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["stop_schedule"]["state"] == "blocked"
    assert "主体" in view["stop_schedule"]["error"]
    assert [w[0] for w in native.writes] == ["create"]


def test_immediate_user_cancel_keeps_pending_group_access_and_boundary(alice, native, monkeypatch):
    from app.lifecycle import run_operation
    from app.schedules import enqueue_due
    independent(native, "USER")
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    boundary = now() + timedelta(days=7)
    native.assignments["remote-group-1"].update(status="cancelled", expires_at=boundary)
    monkeypatch.setattr(native, "subscription_info", lambda self, r: self.user_claims[r.sso_user_id][0])
    def cancel(self, r, mode):
        self.writes.append(("USER_cancel", r.id, mode))
        self.user_claims[UID][0].update(status="cancelled", expires_at=now())
        type(self).effective_rows = [aggregate(PLUS, "GROUP", "PENDING_REMOVAL", expirationDate=boundary.isoformat())]
    monkeypatch.setattr(native, "cancel_subscription", cancel)
    with SessionLocal() as db:
        db.get(StopSchedule, RID).stop_at = now() - timedelta(seconds=1)
        db.commit()
    assert enqueue_due() == 1
    run_operation(native)
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["subscription_status"] == "cancel_scheduled"
    assert view["access_ends_at"] == boundary.isoformat()
    assert view["effective_subscription_source"] == "GROUP"
    assert view["cancellation_mode"] == "END_OF_PERIOD"
    assert view["cancelled_at"] is None
    assert ("remote-group-1", UID) in native.members


@pytest.mark.parametrize("ending", ["group", "individual"])
def test_group_removal_keeps_user_period_boundary_and_personal_deadline(alice, native, ending):
    from app.lifecycle import run_operation
    independent(native, "USER")
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    boundary = now() + timedelta(days=8)
    user_cancelled = now() - timedelta(hours=2) if ending == "group" else None
    native.user_claims[UID][0].update(status="cancelled", expires_at=boundary)
    native.effective_rows = [aggregate(PRO, "INDIVIDUAL", "CANCELLED", expirationDate=boundary.isoformat())]
    with SessionLocal() as db:
        record = db.get(Subscription, RID)
        record.cancelled_at, record.cancellation_mode = user_cancelled, "END_OF_PERIOD"
        schedule = db.get(StopSchedule, RID)
        schedule.stop_at = now() + timedelta(days=2)
        deadline = schedule.stop_at
        db.commit()
    if ending == "group":
        assert cancel_group(alice).status_code == 202
        run_native()
    else:
        result = alice.post(f"/api/subscriptions/{RID}/operations", json={"kind": "cancel_subscription",
                            "confirm_username": RID, "cancellation_mode": "IMMEDIATE", "request_key": str(uuid.uuid4())})
        assert result.status_code == 202, result.text
        run_operation(native)
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["subscription_status"] == "cancel_scheduled"
    assert view["access_ends_at"] == boundary.isoformat()
    assert view["effective_subscription_source"] == "USER"
    assert view["cancellation_mode"] == "END_OF_PERIOD"
    assert view["cancelled_at"] == (user_cancelled.isoformat() if user_cancelled else None)
    assert view["stop_schedule"]["state"] == "scheduled"
    assert view["stop_schedule"]["stop_at"] == deadline.isoformat()
    assert not any(w[0] == "USER_cancel" for w in native.writes)


def test_personal_group_deadline_does_not_follow_member_to_another_group(alice, native):
    from app.group_jobs import run_group_job
    from app.schedules import enqueue_due
    seed_group(1)
    seed_group(0, gid="group-2")
    assert subscribe(alice).status_code == 202
    run_native()
    assert subscribe(alice, gid="group-2").status_code == 202
    run_native()
    result = alice.put(f"/api/subscriptions/{RID}/stop-schedule", json={
        "expected_revision": 0, "policy": {"mode": "at", "stop_at": (now() + timedelta(days=2)).isoformat() + "Z"}})
    assert result.status_code == 200, result.text
    assert result.json()["principal_type"] == "GROUP"
    for gid, action in (("group-1", "detach"), ("group-2", "attach")):
        result = alice.post(f"/api/groups/{gid}/jobs", json={"kind": action, "record_id": RID,
                            "expected_revision": 1, "request_key": str(uuid.uuid4())})
        assert result.status_code == 202, result.text
        run_group_job(native)
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["group_id"] == "group-2"
    assert view["stop_schedule"]["state"] == "completed"
    with SessionLocal() as db:
        db.get(StopSchedule, RID).stop_at = now() - timedelta(seconds=1)
        db.commit()
    assert enqueue_due() == 0
    assert ("remote-group-2", UID) in native.members


def test_personal_schedule_edit_keeps_user_target_until_explicit_group_reset(alice, native):
    independent(native, "USER")
    assert subscribe(alice).status_code == 202
    run_native()
    def edit(revision):
        return alice.put(f"/api/subscriptions/{RID}/stop-schedule", json={
            "expected_revision": revision, "policy": {"mode": "days", "days": 30}})
    result = edit(1)
    assert result.status_code == 200, result.text
    assert result.json()["principal_type"] == "USER"
    group = alice.get("/api/groups/group-1").json()
    result = alice.post(f"/api/subscriptions/{RID}/stop-schedule/reset-to-group", json={
        "expected_revision": result.json()["revision"], "expected_group_revision": group["policy"]["revision"]})
    assert result.status_code == 200, result.text
    assert result.json()["principal_type"] == "GROUP"
    result = edit(result.json()["revision"])
    assert result.status_code == 200, result.text
    assert result.json()["principal_type"] == "GROUP"


def test_due_user_deadline_cancels_only_user_even_when_renewal_was_already_cancelled(alice, native, monkeypatch):
    from app.schedules import enqueue_due
    from app.lifecycle import run_operation
    independent(native, "USER")
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    native.user_claims[UID][0].update(status="cancelled", expires_at=now() + timedelta(days=8))
    native.effective_rows = [aggregate(PLUS, "GROUP")]
    monkeypatch.setattr(native, "subscription_info", lambda self, r: self.user_claims[r.sso_user_id][0])
    def cancel(self, r, mode):
        self.writes.append(("USER_cancel", r.id, mode))
        self.user_claims[UID][0]["expires_at"] = now()
    monkeypatch.setattr(native, "cancel_subscription", cancel)
    with SessionLocal() as db:
        db.get(StopSchedule, RID).stop_at = now() - timedelta(seconds=1)
        db.commit()
    assert enqueue_due() == 1
    run_operation(native)
    assert [w[0] for w in native.writes] == ["create", "USER_cancel"]
    assert native.writes[-1][-1] == "IMMEDIATE"
    assert ("remote-group-1", UID) in native.members
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["stop_schedule"]["state"] == "completed"
    assert view["subscription_status"] == "active"


def test_resaved_group_deadline_without_group_target_never_falls_back_to_user(alice, native, monkeypatch):
    from app.schedules import enqueue_due
    from app.lifecycle import run_operation
    seed_group(1)
    assert subscribe(alice).status_code == 202
    run_native()
    result = alice.put(f"/api/subscriptions/{RID}/stop-schedule", json={
        "expected_revision": 0, "policy": {"mode": "days", "days": 3}})
    assert result.status_code == 200, result.text
    native.user_claims[UID] = [claim()]
    native.effective_rows = [aggregate(PRO, "INDIVIDUAL")]
    assert cancel_group(alice).status_code == 202
    run_native()
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["stop_schedule"]["state"] == "completed"
    result = alice.put(f"/api/subscriptions/{RID}/stop-schedule", json={
        "expected_revision": result.json()["revision"], "policy": {"mode": "days", "days": 4}})
    assert result.status_code == 200, result.text
    with SessionLocal() as db:
        db.get(StopSchedule, RID).stop_at = now() - timedelta(seconds=1)
        db.commit()
    monkeypatch.setattr(native, "subscription_info", lambda self, r: self.user_claims[r.sso_user_id][0])
    monkeypatch.setattr(native, "cancel_subscription", lambda self, r, mode: self.writes.append(("USER_cancel", r.id, mode)))
    assert enqueue_due() == 0
    assert not run_operation(native)
    assert not any(w[0] == "USER_cancel" for w in native.writes)
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["stop_schedule"]["principal_type"] == "GROUP"
    assert view["stop_schedule"]["state"] in ("completed", "blocked")


@pytest.mark.parametrize("mismatch", ["USER", "GROUP"])
def test_worker_rejects_cancellation_payload_whose_principal_disagrees_with_target(alice, native, mismatch):
    from app.lifecycle import run_operation
    from app.models import RecordOperation
    import json
    independent(native, "USER")
    assert subscribe(alice).status_code == 202
    run_native()
    response = alice.post(f"/api/subscriptions/{RID}/operations", json={"kind": "cancel_subscription",
                          "confirm_username": RID, "cancellation_mode": "IMMEDIATE", "request_key": str(uuid.uuid4())})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        op = db.get(RecordOperation, response.json()["id"])
        payload = json.loads(op.payload)
        payload["principal_type"] = mismatch
        if mismatch == "GROUP":
            del payload["native_activation_id"]
        op.payload = json.dumps(payload)
        db.commit()
    run_operation(native)
    assert ("remote-group-1", UID) in native.members
    assert [w[0] for w in native.writes] == ["create"]
    op = alice.get(f"/api/subscriptions/{RID}/operations").json()[0]
    assert op["state"] == "failed"
    assert "主体" in op["error"]


def test_principal_metadata_does_not_change_cancellation_http_idempotency(alice, native):
    independent(native, "USER")
    assert subscribe(alice).status_code == 202
    run_native()
    body = {"kind": "cancel_subscription", "confirm_username": RID,
            "cancellation_mode": "IMMEDIATE", "request_key": str(uuid.uuid4())}
    first = alice.post(f"/api/subscriptions/{RID}/operations", json=body)
    repeated = alice.post(f"/api/subscriptions/{RID}/operations", json=body)
    assert first.status_code == repeated.status_code == 202, repeated.text
    assert first.json()["id"] == repeated.json()["id"]
    assert [w[0] for w in native.writes] == ["create"]


@pytest.mark.parametrize("ending", ["cancel", "expiry", "detach"])
def test_confirmed_immediate_user_billing_tail_does_not_return_after_group_access_ends(alice, native, monkeypatch, ending):
    from app.lifecycle import run_operation
    from app.schedules import enqueue_due
    from app.group_subscription_worker import reconcile_due
    from app.group_jobs import run_group_job
    from app.models import AwsAccount
    independent(native, "USER")
    with SessionLocal() as db:
        db.get(AwsAccount, 1).control_plane = "kiro"
        db.commit()
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    billing_end = now() + timedelta(days=5)
    monkeypatch.setattr(native, "subscription_info", lambda self, r: dict(self.user_claims[r.sso_user_id][0]))
    def cancel_user(self, r, mode):
        self.writes.append(("USER_cancel", r.id, mode))
        self.user_claims[UID][0].update(status="cancelled", expires_at=billing_end)
        type(self).effective_rows = [aggregate(PLUS, "GROUP")]
    monkeypatch.setattr(native, "cancel_subscription", cancel_user)
    with SessionLocal() as db:
        db.get(StopSchedule, RID).stop_at = now() - timedelta(seconds=1)
        db.commit()
    assert enqueue_due() == 1
    run_operation(native)
    for _ in range(2):
        assert alice.post(f"/api/subscriptions/{RID}/operations", json={"kind": "sync_status", "request_key": str(uuid.uuid4())}).status_code == 202
        run_operation(native)
        view = alice.get(f"/api/subscriptions/{RID}").json()
        assert view["subscription_status"] == "active"
        assert view["effective_subscription_source"] == "GROUP"
    billing = aggregate(PRO, "INDIVIDUAL", "CANCELLED", expirationDate=billing_end.isoformat())
    if ending == "expiry":
        group_end = now() + timedelta(days=2)
        cancel = native.cancel_group_subscription
        def cancel_group_at_boundary(self, group, mode):
            result = cancel(self, group, mode)
            self.assignments[group.remote_id]["expires_at"] = group_end
            return result
        monkeypatch.setattr(native, "cancel_group_subscription", cancel_group_at_boundary)
        # Some aggregate rows omit expiry. The actual GROUP boundary must win
        # over the distinct, known USER billing tail when normalizing that row.
        native.effective_rows = [aggregate(PLUS, "GROUP", "PENDING_REMOVAL")]
        assert cancel_group(alice, cancellation_mode="END_OF_PERIOD").status_code == 202
        run_native()
        view = alice.get(f"/api/subscriptions/{RID}").json()
        assert view["subscription_status"] == "cancel_scheduled"
        assert view["access_ends_at"] == group_end.isoformat()
        assert view["cancellation_mode"] == "END_OF_PERIOD"
        assert view["effective_subscription_source"] == "GROUP"
        native.assignments["remote-group-1"]["expires_at"] = now() - timedelta(seconds=1)
        with SessionLocal() as db:
            db.scalar(select(NativeGroupGrant)).access_ends_at = now() - timedelta(seconds=1)
            db.commit()
        native.effective_rows = [billing]
        assert reconcile_due(native) == 1
    elif ending == "cancel":
        native.effective_rows = [billing]
        assert cancel_group(alice).status_code == 202
        run_native()
    else:
        native.effective_rows = [billing]
        result = alice.post("/api/groups/group-1/jobs", json={"kind": "detach", "record_id": RID,
                           "expected_revision": 1, "request_key": str(uuid.uuid4())})
        assert result.status_code == 202, result.text
        run_group_job(native)
    for _ in range(2):
        view = alice.get(f"/api/subscriptions/{RID}").json()
        assert view["subscription_status"] == "cancelled"
        assert view["access_ends_at"] is None
        assert view["effective_subscription_source"] is None
        assert alice.post(f"/api/subscriptions/{RID}/operations", json={"kind": "sync_status", "request_key": str(uuid.uuid4())}).status_code == 202
        run_operation(native)
    assert len([w for w in native.writes if w[0] == "USER_cancel"]) == 1


def test_legacy_group_detach_is_not_evidence_of_user_immediate_cancellation(alice, native):
    from app.lifecycle import run_operation
    seed_group(1)
    assert subscribe(alice).status_code == 202
    run_native()
    result = alice.post(f"/api/subscriptions/{RID}/operations", json={"kind": "cancel_subscription",
                        "confirm_username": RID, "cancellation_mode": "IMMEDIATE", "request_key": str(uuid.uuid4())})
    assert result.status_code == 202
    run_operation(native)
    boundary = now() + timedelta(days=5)
    native.user_claims[UID] = [dict(claim(), status="cancelled", expires_at=boundary)]
    native.effective_rows = [aggregate(PRO, "INDIVIDUAL", "CANCELLED", expirationDate=boundary.isoformat())]
    with SessionLocal() as db:
        row = db.get(Subscription, RID)
        assert row.group_id is None
        assert row.cancellation_mode == "IMMEDIATE"
        row.subscription_observation = None
        db.commit()
    assert alice.post(f"/api/subscriptions/{RID}/operations", json={"kind": "sync_status", "request_key": str(uuid.uuid4())}).status_code == 202
    run_operation(native)
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["subscription_status"] == "cancel_scheduled"
    assert view["cancellation_mode"] == "END_OF_PERIOD"
    assert view["access_ends_at"] == boundary.isoformat()
    assert view["effective_subscription_source"] == "USER"
    assert [w[0] for w in native.writes] == ["create", "detach"]


@pytest.mark.parametrize("group_observation", ["legacy_active", "source_snapshot", "legacy_after_period_cancel"])
def test_later_group_active_observation_does_not_erase_legacy_user_stop(alice, native, monkeypatch, group_observation):
    import json
    from app.group_jobs import run_group_job
    from app.lifecycle import run_operation
    from app.models import AwsAccount, RecordOperation
    independent(native, "USER")
    with SessionLocal() as db:
        db.get(AwsAccount, 1).control_plane = "kiro"
        db.commit()
    billing_end = now() + timedelta(days=5)
    monkeypatch.setattr(native, "subscription_info", lambda self, row: dict(self.user_claims[row.sso_user_id][0]))

    def cancel_user(self, row, mode):
        self.writes.append(("USER_cancel", row.id, mode))
        self.user_claims[UID][0].update(status="cancelled", expires_at=billing_end)
        type(self).effective_rows = [aggregate(PRO, "INDIVIDUAL", "CANCELLED", expirationDate=billing_end.isoformat())]

    monkeypatch.setattr(native, "cancel_subscription", cancel_user)
    stopped = alice.post(f"/api/subscriptions/{RID}/operations", json={"kind": "cancel_subscription",
                         "confirm_username": RID, "cancellation_mode": "IMMEDIATE", "request_key": str(uuid.uuid4())})
    assert stopped.status_code == 202
    run_operation(native)
    with SessionLocal() as db:
        op = db.get(RecordOperation, stopped.json()["id"])
        result = json.loads(op.result)
        op.payload = json.dumps({"cancellation_mode": "IMMEDIATE"})
        op.result = json.dumps({k: result[k] for k in ("subscription_status", "access_ends_at", "cancelled_at", "cancellation_mode")})
        db.get(Subscription, RID).subscription_observation = None
        db.commit()
    native.effective_rows = [aggregate(PLUS, "GROUP")]
    assert subscribe(alice, plan_id=2).status_code == 202
    run_native()
    if group_observation == "legacy_after_period_cancel":
        group_end = now() + timedelta(days=30)
        native.effective_rows = [aggregate(PLUS, "GROUP", "CANCELLED", expirationDate=group_end.isoformat())]
        assert cancel_group(alice, cancellation_mode="END_OF_PERIOD").status_code == 202
        run_native()
        with SessionLocal() as db:
            activation = db.scalar(select(GroupMemberActivation))
            grant = db.get(NativeGroupGrant, activation.grant_id)
            assert activation.cancelled_at < now() < grant.access_ends_at
        # AWS can subsequently confirm a renewed GROUP while the local EOP
        # history still has an earlier cancelled_at and a future access end.
        native.assignments["remote-group-1"].update(status="active", expires_at=None)
        native.effective_rows = [aggregate(PLUS, "GROUP")]
    active = alice.post(f"/api/subscriptions/{RID}/operations", json={"kind": "sync_status", "request_key": str(uuid.uuid4())})
    assert active.status_code == 202
    run_operation(native)
    assert alice.get(f"/api/subscriptions/{RID}").json()["subscription_status"] == "active"
    if group_observation != "source_snapshot":
        with SessionLocal() as db:
            op = db.get(RecordOperation, active.json()["id"])
            result = json.loads(op.result)
            op.result = json.dumps({k: result[k] for k in ("subscription_status", "observed_subscription_type", "access_ends_at", "last_synced_at")})
            db.commit()
    native.effective_rows = [aggregate(PRO, "INDIVIDUAL", "CANCELLED", expirationDate=billing_end.isoformat())]
    detached = alice.post("/api/groups/group-1/jobs", json={"kind": "detach", "record_id": RID,
                         "expected_revision": 1, "request_key": str(uuid.uuid4())})
    assert detached.status_code == 202
    run_group_job(native)
    with SessionLocal() as db:
        db.get(Subscription, RID).subscription_observation = None
        db.commit()
    assert alice.post(f"/api/subscriptions/{RID}/operations", json={"kind": "sync_status", "request_key": str(uuid.uuid4())}).status_code == 202
    run_operation(native)
    view = alice.get(f"/api/subscriptions/{RID}").json()
    assert view["subscription_status"] == "cancelled"
    assert view["access_ends_at"] is None
    assert view["effective_subscription_source"] is None
    assert len([w for w in native.writes if w[0] == "USER_cancel"]) == 1


@pytest.mark.parametrize("ending", ["individual_detach", "group_job_detach", "group_immediate_cancel"])
def test_legacy_user_sync_after_confirmed_group_end_invalidates_old_user_stop(alice, native, ending):
    import json
    from app.group_jobs import run_group_job
    from app.lifecycle import run_operation
    from app.models import RecordOperation
    from test_lifecycle import LifecycleGateway, record as standalone_record, operation, get
    row = standalone_record.__wrapped__(alice)
    stopped = operation(alice, row, "cancel_subscription", cancellation_mode="IMMEDIATE")
    assert stopped.status_code == 202
    run_operation(LifecycleGateway)
    with SessionLocal() as db:
        op = db.get(RecordOperation, stopped.json()["id"])
        result = json.loads(op.result)
        op.payload = json.dumps({"cancellation_mode": "IMMEDIATE"})
        op.result = json.dumps({k: result[k] for k in ("subscription_status", "access_ends_at", "cancelled_at", "cancellation_mode")})
        db.get(Subscription, row["id"]).subscription_observation = None
        db.commit()
    seed_group(0)
    assert subscribe(alice).status_code == 202
    run_native()
    attached = alice.post("/api/groups/group-1/jobs", json={"kind": "attach", "record_id": row["id"],
                          "expected_revision": 1, "request_key": str(uuid.uuid4())})
    assert attached.status_code == 202
    run_group_job(native)
    if ending == "individual_detach":
        detached = operation(alice, row, "cancel_subscription", cancellation_mode="IMMEDIATE")
        assert detached.status_code == 202
        run_operation(native)
        with SessionLocal() as db:
            op = db.get(RecordOperation, detached.json()["id"])
            assert op.state == "completed" and json.loads(op.payload)["native_activation_id"]
            result = json.loads(op.result)
            op.result = json.dumps({k: result[k] for k in ("subscription_status", "access_ends_at", "cancelled_at", "cancellation_mode")})
            db.commit()
    elif ending == "group_job_detach":
        revision = alice.get("/api/groups/group-1").json()["revision"]
        detached = alice.post("/api/groups/group-1/jobs", json={"kind": "detach", "record_id": row["id"],
                              "expected_revision": revision, "request_key": str(uuid.uuid4())})
        assert detached.status_code == 202
        run_group_job(native)
    else:
        assert cancel_group(alice).status_code == 202
        run_native()
    LifecycleGateway.info.update(status="active", expires_at=None)
    active = operation(alice, row, "sync_status")
    assert active.status_code == 202
    run_operation(LifecycleGateway)
    with SessionLocal() as db:
        op = db.get(RecordOperation, active.json()["id"])
        result = json.loads(op.result)
        assert result["subscription_status"] == "active"
        op.result = json.dumps({k: result[k] for k in ("subscription_status", "observed_subscription_type", "access_ends_at", "last_synced_at")})
        db.get(Subscription, row["id"]).subscription_observation = None
        db.commit()
    boundary = now() + timedelta(days=20)
    LifecycleGateway.info.update(status="cancelled", expires_at=boundary)
    assert operation(alice, row, "sync_status").status_code == 202
    run_operation(LifecycleGateway)
    view = get(alice, row)
    assert view["subscription_status"] == "cancel_scheduled"
    assert view["access_ends_at"] == boundary.isoformat()
    assert view["effective_subscription_source"] == "USER"
    assert LifecycleGateway.calls == ["cancel"]
