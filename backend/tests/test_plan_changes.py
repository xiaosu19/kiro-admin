"""Plan changes account for verified AWS outcomes without rewriting opening history."""

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.aws import AwsFailure
from app.config import settings
from app.database import SessionLocal
from app.models import (
    Binding,
    Plan,
    PlanCounter,
    RecordOperation,
    StopSchedule,
    Subscription,
    User,
    now,
)
from app.security import encrypt

PRO = "Q_DEVELOPER_STANDALONE_PRO"
PLUS = "Q_DEVELOPER_STANDALONE_PRO_PLUS"
MAX = "Q_DEVELOPER_STANDALONE_PRO_MAX"


@pytest.fixture(autouse=True)
def enable_plan_changes(monkeypatch):
    monkeypatch.setattr(settings, "plan_changes_enabled", True)


def test_authenticated_capability_reflects_enabled_site(alice):
    assert alice.get("/api/auth/me").json()["capabilities"] == {"plan_changes_enabled": True}


class Gateway:
    current = PRO
    pending = None
    status = "active"
    calls = []
    failure = None
    lag = False
    cancelled = False
    effective_type = None
    additional_sources = []

    def __init__(self, account):
        self.account = account

    def plan_change_info(self, record):
        return dict(
            status=self.status,
            current_type=self.current,
            pending_type=self.pending,
            expected_effective_at=now() + timedelta(days=20) if self.pending else None,
        )

    def update_assignment(self, record, target):
        self.calls.append(target)
        if self.failure == "denied":
            raise AwsFailure("AccessDenied")
        if not self.lag:
            if target == self.current:
                type(self).pending = None
            elif [PRO, PLUS, MAX].index(target) > [PRO, PLUS, MAX].index(self.current):
                type(self).current, type(self).pending = target, None
            else:
                type(self).pending = target
        if self.failure == "timeout":
            raise AwsFailure("timeout", uncertain=True)
        return "aws-plan-change"

    def subscription_info(self, record):
        return dict(status=self.status, subscription_type=self.current, expires_at=None)

    def user_subscription_sources(self, record):
        self.observed_record = record
        return [{"source": "USER", "group_id": None, **self.subscription_info(record)}] + self.additional_sources

    def report_subscriptions(self):
        return [{"principal": {"user": self.observed_record.sso_user_id},
                 "type": {"amazonQ": self.effective_type or self.current},
                 "status": "ACTIVE" if self.additional_sources else self.status.upper(),
                 "aggregatedSubscriptionType": ("INDIVIDUAL_AND_GROUP" if self.status == "active" else "GROUP")
                 if self.additional_sources else "INDIVIDUAL"}]

    def cancel_subscription(self, record, mode):
        self.calls.append("cancel")
        type(self).status, type(self).pending = "cancelled", None
        return "aws-cancel"

    def user_info(self, record):
        return {
            "DisplayName": record.sso_display_name,
            "Emails": [{"Value": record.email, "Primary": True}],
        }


@pytest.fixture
def record():
    Gateway.effective_type, Gateway.additional_sources = None, []
    Gateway.current, Gateway.pending, Gateway.status = PRO, None, "active"
    Gateway.calls, Gateway.failure, Gateway.lag = [], None, False
    rid = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(Plan(id=3, name="Kiro Max", code="max", subscription_type=MAX))
        db.add(PlanCounter(id=4, user_id=2, plan_id=3, limit_count=3))
        db.add(
            Subscription(
                id=rid,
                owner_id=2,
                aws_account_id=1,
                plan_id=1,
                counter_id=1,
                cycle_number=1,
                request_key=str(uuid.uuid4()),
                username="same-sso-user",
                email="same@example.com",
                state="completed",
                step="done",
                sso_user_id="sso-existing",
                password_encrypted=encrypt("saved"),
                credential_state="persistent",
                credential_recovery_encrypted=encrypt("recovery"),
                portal_url="https://example.awsapps.com/start",
                subscription_type=PRO,
                plan_name_snapshot="Original Pro",
                counted=True,
                reserved=False,
                subscription_status="active",
                observed_subscription_type=PRO,
                subscribed_at=now() - timedelta(days=7),
                sso_display_name="Same Name",
            )
        )
        db.get(PlanCounter, 1).used_count = 1
        db.get(PlanCounter, 1).lifetime_count = 1
        db.add(
            StopSchedule(
                record_id=rid,
                actor_id=2,
                mode="days",
                days=30,
                stop_at=now() + timedelta(days=23),
                state="scheduled",
            )
        )
        db.commit()
    return dict(id=rid, username="same-sso-user")


def request(client, record, target=2, source=PRO, key=None):
    return client.post(
        f"/api/subscriptions/{record['id']}/plan-changes",
        json={
            "target_plan_id": target,
            "expected_current_type": source,
            "confirm_username": record["username"],
            "request_key": key or str(uuid.uuid4()),
        },
    )


def run():
    from app.plan_change_worker import run_plan_change

    assert run_plan_change(Gateway)


def change(cid):
    from app.models import PlanChange

    with SessionLocal() as db:
        return db.get(PlanChange, cid)


def counter(cid):
    with SessionLocal() as db:
        c = db.get(PlanCounter, cid)
        return c.used_count, c.pending_count, c.lifetime_count, c.cycle_number


def record_snapshot(record):
    with SessionLocal() as db:
        r = db.get(Subscription, record["id"])
        return {
            c.name: getattr(r, c.name)
            for c in Subscription.__table__.columns
            if c.name
            not in {
                "active_operation_id",
                "updated_at",
                "observed_subscription_type",
                "subscription_observation",
                "last_synced_at",
            }
        }


def upgrade(client, record, target=2, source=PRO):
    response = request(client, record, target, source)
    assert response.status_code == 202, response.text
    run()
    return response.json()


def downgrade(client, record):
    upgrade(client, record)
    response = request(client, record, 1, PLUS)
    assert response.status_code == 202, response.text
    run()
    return response.json()


def test_upgrade_preserves_opening_credentials_schedule_and_original_counts(
    alice, record
):
    before = record_snapshot(record)
    result = request(alice, record)
    assert result.status_code == 202, result.text
    assert counter(2) == (0, 1, 0, 1)
    run()
    assert change(result.json()["id"]).state == "applied"
    assert counter(2) == (1, 0, 1, 1)
    assert counter(1) == (1, 0, 1, 1)
    assert record_snapshot(record) == before
    detail = alice.get(f"/api/subscriptions/{record['id']}").json()
    assert detail["current_plan"]["subscription_type"] == PLUS
    assert detail["subscription_type"] == PRO
    assert detail["stop_schedule"]["days"] == 30
    assert detail["operation_pending"] is False
    assert Gateway.calls == [PLUS]


def test_downgrade_reserves_and_reconciles_exactly_once_across_month(alice, record):
    c = downgrade(alice, record)
    assert change(c["id"]).state == "scheduled"
    assert counter(1) == (1, 1, 1, 1)
    assert (
        alice.get(f"/api/subscriptions/{record['id']}").json()["operation_pending"]
        is False
    )
    from app.plan_change_worker import reconcile_due

    assert reconcile_due(Gateway, force=True) == 1
    assert counter(1) == (1, 1, 1, 1)
    Gateway.current, Gateway.pending = PRO, None
    assert reconcile_due(Gateway, force=True) == 1
    assert reconcile_due(Gateway, force=True) == 0
    assert counter(1) == (2, 0, 2, 1)
    assert change(c["id"]).state == "applied"
    assert Gateway.calls == [PLUS, PRO]


def test_idempotency_actor_payload_conflict_and_record_lock(alice, admin, record):
    key = str(uuid.uuid4())
    first = request(alice, record, key=key)
    assert first.status_code == 202
    assert request(alice, record, key=key).json()["id"] == first.json()["id"]
    assert request(admin, record, key=key).status_code == 409
    assert request(alice, record, 3, key=key).status_code == 409
    assert request(alice, record, 3).status_code == 409
    assert counter(2) == (0, 1, 0, 1)
    assert counter(4) == (0, 0, 0, 1)


def test_admin_for_member_uses_owner_counter_and_history_is_visible(
    alice, admin, bob, record
):
    c = upgrade(admin, record)
    assert counter(2) == (1, 0, 1, 1)
    history = alice.get(f"/api/subscriptions/{record['id']}/plan-changes").json()
    assert history[0]["id"] == c["id"]
    assert "actor_id" not in history[0]
    assert bob.get(f"/api/subscriptions/{record['id']}/plan-changes").status_code == 404
    assert bob.get(f"/api/subscriptions/{record['id']}/plan-options").status_code == 404
    with SessionLocal() as db:
        db.get(PlanCounter, 4).limit_count = 0
        db.commit()
    assert request(admin, record, 3, PLUS).status_code == 409


@pytest.mark.parametrize(
    "invalid",
    [
        "same",
        "inactive",
        "deleted",
        "unsupported",
        "unbound_owner",
        "disabled_owner",
        "cancelled",
        "deleted_sso",
        "stale",
    ],
)
def test_invalid_admission_is_atomic(alice, admin, record, invalid):
    with SessionLocal() as db:
        if invalid in {"inactive", "deleted", "unsupported"}:
            p = db.get(Plan, 2)
            if invalid == "inactive":
                p.active = False
            if invalid == "deleted":
                p.deleted_at = now()
            if invalid == "unsupported":
                p.subscription_type = "UNKNOWN"
        if invalid == "unbound_owner":
            db.delete(db.get(Binding, (2, 1)))
        if invalid == "disabled_owner":
            db.get(User, 2).active = False
        if invalid == "cancelled":
            db.get(Subscription, record["id"]).cancelled_at = now()
        if invalid == "deleted_sso":
            db.get(Subscription, record["id"]).sso_deleted_at = now()
        db.commit()
    result = request(
        admin,
        record,
        1 if invalid == "same" else 2,
        PLUS if invalid == "stale" else PRO,
    )
    assert result.status_code in (403, 404, 409)
    assert counter(2) == (0, 0, 0, 1)
    assert counter(1) == (1, 0, 1, 1)


def test_timeout_holds_lock_and_readonly_recheck_does_not_repeat_write(alice, record):
    Gateway.failure, Gateway.lag = "timeout", True
    response = request(alice, record)
    assert response.status_code == 202
    c = response.json()
    run()
    assert change(c["id"]).state == "needs_review"
    assert counter(2) == (0, 1, 0, 1)
    assert alice.get(f"/api/subscriptions/{record['id']}").json()["operation_pending"]
    result = alice.post(
        f"/api/subscriptions/{record['id']}/plan-changes/{c['id']}/recheck",
        json={"confirm_username": record["username"]},
    )
    assert result.status_code == 202
    Gateway.current, Gateway.failure = PLUS, None
    run()
    assert Gateway.calls == [PLUS]
    assert counter(2) == (1, 0, 1, 1)


def test_definite_failure_releases_only_new_reservation(alice, record):
    Gateway.failure = "denied"
    c = upgrade(alice, record)
    assert change(c["id"]).state == "failed"
    assert counter(2) == (0, 0, 0, 1)
    assert counter(1) == (1, 0, 1, 1)


def test_withdraw_scheduled_releases_without_extra_quota(alice, record):
    c = downgrade(alice, record)
    result = alice.post(
        f"/api/subscriptions/{record['id']}/plan-changes/{c['id']}/withdraw",
        json={
            "request_key": str(uuid.uuid4()),
            "confirm_username": record["username"],
            "expected_current_type": PLUS,
        },
    )
    assert result.status_code == 202, result.text
    run()
    assert change(c["id"]).state == "withdrawn"
    assert change(result.json()["id"]).state == "withdrawn"
    assert counter(1) == (1, 0, 1, 1)
    assert counter(2) == (1, 0, 1, 1)
    assert Gateway.calls == [PLUS, PRO, PLUS]


def test_replacement_keeps_old_reservation_until_remote_confirmation(alice, record):
    upgrade(alice, record, 3)
    first = request(alice, record, 1, MAX)
    assert first.status_code == 202
    run()
    Gateway.lag = True
    second = request(alice, record, 2, MAX)
    assert second.status_code == 202
    run()
    assert change(second.json()["id"]).state == "needs_review"
    assert counter(1)[1] == 1 and counter(2)[1] == 1
    Gateway.pending = PLUS
    alice.post(
        f"/api/subscriptions/{record['id']}/plan-changes/{second.json()['id']}/recheck",
        json={"confirm_username": record["username"]},
    )
    run()
    assert change(first.json()["id"]).state == "superseded"
    assert change(second.json()["id"]).state == "scheduled"
    assert counter(1)[1] == 0 and counter(2)[1] == 1


def test_accepted_downgrade_reconciles_after_owner_actor_unbound_disabled(
    alice, record
):
    c = downgrade(alice, record)
    with SessionLocal() as db:
        db.get(User, 2).active = False
        db.delete(db.get(Binding, (2, 1)))
        db.commit()
    Gateway.current, Gateway.pending = PRO, None
    from app.plan_change_worker import reconcile_due

    reconcile_due(Gateway, force=True)
    assert change(c["id"]).state == "applied"
    assert counter(1) == (2, 0, 2, 1)


def test_generic_retry_cannot_reset_plan_change_phase(alice, record):
    Gateway.failure, Gateway.lag = "timeout", True
    c = upgrade(alice, record)
    result = alice.post(
        f"/api/subscriptions/{record['id']}/operations/{c['operation_id']}/retry",
        json={"confirm_username": record["username"]},
    )
    assert result.status_code == 404
    with SessionLocal() as db:
        assert db.get(RecordOperation, c["operation_id"]).phase == "pending"


def test_current_plan_used_by_cancellation_and_pending_reservation_released(
    alice, record
):
    c = downgrade(alice, record)
    response = alice.post(
        f"/api/subscriptions/{record['id']}/operations",
        json={
            "kind": "cancel_subscription",
            "request_key": str(uuid.uuid4()),
            "confirm_username": record["username"],
            "cancellation_mode": "IMMEDIATE",
        },
    )
    assert response.status_code == 202
    from app.lifecycle import run_operation

    run_operation(Gateway)
    assert Gateway.calls[-1] == "cancel"
    assert change(c["id"]).state == "cancelled"
    assert counter(1) == (1, 0, 1, 1)


def test_pending_schedule_blocks_reset_delete_role_change_and_target_type_edit(
    alice, admin, record
):
    c = downgrade(alice, record)
    response = admin.post(
        "/api/admin/counters/1/reset",
        json={"limit_count": 5, "reason": "manual reset now"},
    )
    assert response.status_code == 409
    assert "套餐变更" in response.json()["detail"]
    assert admin.patch("/api/admin/users/2", json={"role": "admin"}).status_code == 409
    result = admin.put(
        "/api/admin/plans/2",
        json={
            "name": "Changed",
            "code": "pro_plus",
            "subscription_type": "Q_DEVELOPER_STANDALONE_POWER",
            "active": True,
        },
    )
    assert result.status_code == 409
    assert (
        admin.request(
            "DELETE", "/api/admin/plans/2", json={"confirm_name": "Kiro Pro+"}
        ).status_code
        == 409
    )
    assert change(c["id"]).reserved


def test_admin_unlimited_changes_enter_lifetime_when_demoted(admin, record):
    from conftest import login

    with SessionLocal() as db:
        r = db.get(Subscription, record["id"])
        r.owner_id, r.counter_id, r.cycle_number = 3, None, None
        db.get(User, 3).role = "admin"
        db.commit()
    client = login("bob")
    c = upgrade(client, record)
    assert change(c["id"]).counted and change(c["id"]).counter_id is None
    assert admin.patch("/api/admin/users/3", json={"role": "member"}).status_code == 200
    with SessionLocal() as db:
        counter_row = db.scalar(
            select(PlanCounter).where(
                PlanCounter.user_id == 3, PlanCounter.plan_id == 2
            )
        )
        assert counter_row is not None and counter_row.lifetime_count == 1
        assert counter_row.used_count == 0


def test_v9_migration_adds_only_new_ledger_preserving_every_old_row(record):
    from sqlalchemy import inspect, text
    from app.database import engine
    from app.migrations import migrate, VERSION

    with engine.begin() as conn:
        conn.execute(text("INSERT INTO console_schema_version(version) VALUES (9)"))
        conn.execute(text("DROP TABLE console_plan_changes"))
        tables = [
            t for t in inspect(conn).get_table_names() if t != "console_schema_version"
        ]
        before = {
            t: conn.exec_driver_sql(f'SELECT * FROM "{t}"').fetchall() for t in tables
        }
    migrate(engine)
    migrate(engine)
    with engine.connect() as conn:
        assert (
            conn.exec_driver_sql("SELECT version FROM console_schema_version").scalar()
            == VERSION
        )
        assert (
            conn.exec_driver_sql("SELECT count(*) FROM console_plan_changes").scalar()
            == 0
        )
        assert {
            t: conn.exec_driver_sql(f'SELECT * FROM "{t}"').fetchall() for t in tables
        } == before
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []


def test_fresh_read_requires_explicit_delayed_release_and_never_rewrites(alice, record):
    Gateway.lag = True
    c = upgrade(alice, record)
    cid = c["id"]
    url = f"/api/subscriptions/{record['id']}/plan-changes/{cid}/confirm-not-applied"
    body = {
        "confirm_username": record["username"],
        "reason": "AWS has no requested assignment",
        "acknowledge_not_applied": True,
    }
    assert alice.post(url, json=body).status_code == 409
    from app.models import PlanChange

    with SessionLocal() as db:
        db.get(PlanChange, cid).write_requested_at = now() - timedelta(minutes=11)
        db.commit()
    assert (
        alice.post(url, json={**body, "acknowledge_not_applied": False}).status_code
        == 409
    )
    assert alice.post(url, json=body).status_code == 202
    run()
    assert change(cid).state == "not_applied"
    assert counter(2) == (0, 0, 0, 1)
    assert Gateway.calls == [PLUS]


def test_delayed_recovery_counts_late_success_instead_of_releasing(alice, record):
    Gateway.lag = True
    c = upgrade(alice, record)
    from app.models import PlanChange

    with SessionLocal() as db:
        db.get(PlanChange, c["id"]).write_requested_at = now() - timedelta(minutes=11)
        db.commit()
    result = alice.post(
        f"/api/subscriptions/{record['id']}/plan-changes/{c['id']}/confirm-not-applied",
        json={
            "confirm_username": record["username"],
            "reason": "Request did not seem to take effect",
            "acknowledge_not_applied": True,
        },
    )
    assert result.status_code == 202
    Gateway.current = PLUS
    run()
    assert change(c["id"]).state == "applied"
    assert counter(2) == (1, 0, 1, 1)
    assert len(Gateway.calls) == 1


def test_replacement_rejection_preserves_accepted_old_change(alice, record):
    upgrade(alice, record, 3)
    first = request(alice, record, 1, MAX)
    assert first.status_code == 202
    run()
    Gateway.failure = "denied"
    second = upgrade(alice, record, 2, MAX)
    assert change(second["id"]).state == "failed"
    assert change(first.json()["id"]).state == "scheduled"
    assert counter(1)[1] == 1 and counter(2)[1] == 0
    assert Gateway.pending == PRO


def test_old_downgrade_applied_before_replacement_is_counted_and_source_rejected(
    alice, record
):
    upgrade(alice, record, 3)
    first = request(alice, record, 1, MAX)
    assert first.status_code == 202
    run()
    Gateway.current, Gateway.pending = PRO, None
    second = upgrade(alice, record, 2, MAX)
    assert change(second["id"]).state == "failed"
    assert change(first.json()["id"]).state == "applied"
    assert counter(1) == (2, 0, 2, 1)
    assert counter(2)[1] == 0
    assert Gateway.calls == [MAX, PRO]


def test_downgrade_applied_before_cancellation_consumes_count(alice, record):
    c = downgrade(alice, record)
    Gateway.current, Gateway.pending = PRO, None
    response = alice.post(
        f"/api/subscriptions/{record['id']}/operations",
        json={
            "kind": "cancel_subscription",
            "request_key": str(uuid.uuid4()),
            "confirm_username": record["username"],
            "cancellation_mode": "IMMEDIATE",
        },
    )
    assert response.status_code == 202
    from app.lifecycle import run_operation

    assert run_operation(Gateway)
    assert Gateway.calls[-1] == "cancel"
    assert change(c["id"]).state == "applied"
    assert counter(1) == (2, 0, 2, 1)


def test_scheduled_cancellation_uses_managed_tier_and_settles_pending(alice, record):
    c = downgrade(alice, record)
    with SessionLocal() as db:
        db.get(StopSchedule, record["id"]).stop_at = now() - timedelta(seconds=1)
        db.get(User, 2).active = False
        db.commit()
    from app.schedules import enqueue_due
    from app.lifecycle import run_operation

    assert enqueue_due() == 1
    assert run_operation(Gateway)
    assert Gateway.calls[-1] == "cancel"
    assert change(c["id"]).state == "cancelled"
    assert counter(1)[1] == 0


@pytest.mark.parametrize(
    "action", ["reset_password", "update_sso", "delete_sso", "cancel_subscription"]
)
def test_unknown_write_holds_existing_lifecycle_mutex(alice, record, action):
    Gateway.lag = True
    upgrade(alice, record)
    body = {
        "kind": action,
        "request_key": str(uuid.uuid4()),
        "confirm_username": record["username"],
        "acknowledge_subscription": True,
    }
    if action == "update_sso":
        body.update(display_name="New Name", email="new@example.com")
    response = alice.post(f"/api/subscriptions/{record['id']}/operations", json=body)
    assert response.status_code == 409, response.text


def test_accepted_change_does_not_lock_profile_operations(alice, record):
    downgrade(alice, record)
    response = alice.post(
        f"/api/subscriptions/{record['id']}/operations",
        json={
            "kind": "update_sso",
            "request_key": str(uuid.uuid4()),
            "display_name": "New Name",
            "email": "new@example.com",
        },
    )
    assert response.status_code == 202
    from app.plan_change_worker import reconcile_due

    assert reconcile_due(Gateway, force=True) == 0
    assert counter(1)[1] == 1


def test_enqueued_change_rechecks_owner_binding_and_target_enablement(alice, record):
    c = request(alice, record).json()
    with SessionLocal() as db:
        db.delete(db.get(Binding, (2, 1)))
        db.commit()
    run()
    assert change(c["id"]).state == "failed"
    assert counter(2)[1] == 0
    assert not Gateway.calls


def test_expired_lease_reconciles_and_stale_worker_cannot_settle(alice, record):
    from app.lifecycle import claim_operation
    from app.plan_change_state import KINDS
    from app.plan_change_worker import mark_pending, apply_observation

    c = request(alice, record).json()
    op_id, token = claim_operation(KINDS)
    mark_pending(op_id, token)
    with SessionLocal() as db:
        db.get(RecordOperation, op_id).lease_until = now() - timedelta(seconds=1)
        db.commit()
    Gateway.current = PLUS
    run()
    assert change(c["id"]).state == "applied"
    with pytest.raises(RuntimeError):
        apply_observation(op_id, token, Gateway(None).plan_change_info(None))
    assert counter(2) == (1, 0, 1, 1)
    assert Gateway.calls == []


def test_write_success_commit_failure_recovers_without_duplicate(
    monkeypatch, alice, record
):
    import app.plan_change_worker as worker

    c = request(alice, record).json()
    original = worker.apply_observation

    def interrupted(*args, **kwargs):
        raise RuntimeError("local commit unavailable")

    monkeypatch.setattr(worker, "apply_observation", interrupted)
    run()
    assert change(c["id"]).state == "needs_review"
    assert counter(2)[1] == 1
    monkeypatch.setattr(worker, "apply_observation", original)
    assert (
        alice.post(
            f"/api/subscriptions/{record['id']}/plan-changes/{c['id']}/recheck",
            json={"confirm_username": record["username"]},
        ).status_code
        == 202
    )
    run()
    assert counter(2) == (1, 0, 1, 1)
    assert Gateway.calls == [PLUS]


def test_concurrent_admission_reserves_only_once(alice, record):
    from concurrent.futures import ThreadPoolExecutor

    key = str(uuid.uuid4())
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(lambda _: request(alice, record, key=key), range(2))
        )
    assert [r.status_code for r in results] == [202, 202]
    assert len({r.json()["id"] for r in results}) == 1
    assert counter(2) == (0, 1, 0, 1)


def test_account_unavailable_retains_accepted_schedule_and_unblocks_sso(alice, record):
    from app.models import AwsAccount

    c = downgrade(alice, record)
    with SessionLocal() as db:
        db.get(AwsAccount, 1).active = False
        db.commit()
    from app.plan_change_worker import reconcile_due

    reads = []
    class ReadOnly(Gateway):
        def plan_change_info(self, r):
            reads.append(r.id)
            return super().plan_change_info(r)

        def update_assignment(self, *args):
            pytest.fail("Disabled accounts can reconcile accepted intent, never write")

    assert reconcile_due(ReadOnly, force=True) == 1
    assert reads == [record["id"]]
    assert change(c["id"]).state == "scheduled" and change(c["id"]).error is None
    assert counter(1)[1] == 1
    with SessionLocal() as db:
        assert db.get(Subscription, record["id"]).active_operation_id is None


def test_ambiguous_claim_drift_keeps_accepted_reservation(alice, record):
    c = downgrade(alice, record)
    Gateway.current, Gateway.pending = MAX, None
    from app.plan_change_worker import reconcile_due

    reconcile_due(Gateway, force=True)
    assert change(c["id"]).state == "scheduled" and change(c["id"]).error
    assert counter(1)[1] == 1


def test_successful_write_request_id_is_retained_when_readback_fails(
    monkeypatch, alice, record
):
    original = Gateway.plan_change_info
    calls = 0

    def read(self, record):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise AwsFailure("readback timeout", uncertain=True)
        return original(self, record)

    monkeypatch.setattr(Gateway, "plan_change_info", read)
    c = upgrade(alice, record)
    assert change(c["id"]).state == "needs_review"
    assert change(c["id"]).accepted_at is not None
    with SessionLocal() as db:
        assert (
            db.get(RecordOperation, c["operation_id"]).aws_request_id
            == "aws-plan-change"
        )


def test_missing_claim_does_not_release_accepted_downgrade_without_confirmed_cancel(
    alice, record
):
    c = downgrade(alice, record)
    Gateway.status, Gateway.current, Gateway.pending = "not_subscribed", None, None
    from app.plan_change_worker import reconcile_due

    reconcile_due(Gateway, force=True)
    assert change(c["id"]).state == "scheduled" and change(c["id"]).error
    assert counter(1)[1] == 1


def test_due_deadline_rejects_new_paid_change_but_allows_withdraw(alice, record):
    c = downgrade(alice, record)
    with SessionLocal() as db:
        db.get(StopSchedule, record["id"]).stop_at = now() - timedelta(seconds=1)
        db.commit()
    assert request(alice, record, 3, PLUS).status_code == 409
    assert counter(4)[1] == 0
    result = alice.post(
        f"/api/subscriptions/{record['id']}/plan-changes/{c['id']}/withdraw",
        json={
            "request_key": str(uuid.uuid4()),
            "confirm_username": record["username"],
            "expected_current_type": PLUS,
        },
    )
    assert result.status_code == 202
    run()
    assert change(c["id"]).state == "withdrawn"


def test_deadline_elapsed_after_enqueue_preserves_old_schedule_without_paid_write(
    alice, record
):
    c = downgrade(alice, record)
    next_change = request(alice, record, 3, PLUS)
    assert next_change.status_code == 202
    with SessionLocal() as db:
        db.get(StopSchedule, record["id"]).stop_at = now() - timedelta(seconds=1)
        db.commit()
    run()
    assert change(next_change.json()["id"]).state == "failed"
    assert change(c["id"]).state == "scheduled"
    assert Gateway.calls == [PLUS, PRO]
    assert counter(1)[1] == 1 and counter(4)[1] == 0


def test_accepted_schedule_missing_pending_can_be_explicitly_resolved_after_delay(
    alice, record
):
    c = downgrade(alice, record)
    from app.models import PlanChange

    with SessionLocal() as db:
        db.get(PlanChange, c["id"]).write_requested_at = now() - timedelta(minutes=11)
        db.commit()
    Gateway.pending = None
    from app.plan_change_worker import reconcile_due

    reconcile_due(Gateway, force=True)
    assert change(c["id"]).error
    result = alice.post(
        f"/api/subscriptions/{record['id']}/plan-changes/{c['id']}/confirm-not-applied",
        json={
            "confirm_username": record["username"],
            "reason": "AWS administrator withdrew the pending downgrade",
            "acknowledge_not_applied": True,
        },
    )
    assert result.status_code == 202, result.text
    run()
    assert change(c["id"]).state == "not_applied"
    assert counter(1) == (1, 0, 1, 1)
    assert Gateway.calls == [PLUS, PRO]


def test_idempotency_key_cannot_be_reused_on_another_record(alice, record):
    key = str(uuid.uuid4())
    assert request(alice, record, key=key).status_code == 202
    with SessionLocal() as db:
        r = db.get(Subscription, record["id"])
        values = {
            col.name: getattr(r, col.name) for col in Subscription.__table__.columns
        }
        values.update(
            id=str(uuid.uuid4()),
            username="another-sso",
            sso_user_id="other-sso-id",
            request_key=str(uuid.uuid4()),
            active_operation_id=None,
        )
        db.add(Subscription(**values))
        db.get(PlanCounter, 2).limit_count = 3
        db.commit()
    other = {"id": values["id"], "username": values["username"]}
    assert request(alice, other, key=key).status_code == 409
    assert counter(2)[1] == 1


def test_admin_summary_and_paginated_history_include_confirmed_changes(admin, record):
    from app.admin_reports import user_summary

    with SessionLocal() as db:
        r = db.get(Subscription, record["id"])
        r.owner_id, r.counter_id, r.cycle_number = 1, None, None
        db.commit()
    c = upgrade(admin, record)
    with SessionLocal() as db:
        summary = next(u for u in user_summary(db)["users"] if u["id"] == 1)
        target = next(p for p in summary["counters"] if p["plan_id"] == 2)
        assert target["lifetime_count"] == 1
    response = admin.get("/api/admin/users/1/plan-history", params={"plan_id": 2})
    assert response.status_code == 200
    assert response.json()["total"] == 1
    event = response.json()["items"][0]
    assert event["event_kind"] == "plan_change" and event["id"] == c["id"]
    assert event["occurred_at"] == event["applied_at"]
    assert event["subscribed_at"] != event["applied_at"]
    assert event["record_id"] == record["id"]


def test_history_merges_original_activation_and_later_same_tier_change(
    admin, alice, record
):
    c = downgrade(alice, record)
    Gateway.current, Gateway.pending = PRO, None
    from app.plan_change_worker import reconcile_due

    reconcile_due(Gateway, force=True)
    response = admin.get("/api/admin/users/2/plan-history", params={"plan_id": 1})
    events = response.json()["items"]
    assert response.json()["total"] == 2
    assert [e["event_kind"] for e in events] == ["plan_change", "subscription"]
    assert events[0]["id"] == c["id"]
    assert events[1]["id"] == record["id"]


def test_confirmed_observation_updates_observed_tier_and_sync_time(alice, record):
    upgrade(alice, record)
    response = alice.get(f"/api/subscriptions/{record['id']}").json()
    assert response["observed_subscription_type"] == PLUS
    assert response["last_synced_at"]


def test_preflight_pending_drift_releases_only_new_reservation_and_lock(alice, record):
    previous = downgrade(alice, record)
    Gateway.pending = None
    next_change = request(alice, record, 3, PLUS)
    assert next_change.status_code == 202
    run()
    newer = change(next_change.json()["id"])
    assert newer.write_requested_at is None
    assert newer.state == "failed"
    assert counter(4) == (0, 0, 0, 1)
    assert change(previous["id"]).state == "scheduled"
    assert counter(1) == (1, 1, 1, 1)
    with SessionLocal() as db:
        assert db.get(Subscription, record["id"]).active_operation_id is None
    from app.plan_change_worker import reconcile_due

    assert reconcile_due(Gateway, force=True) == 1
    assert Gateway.calls == [PLUS, PRO]
    assert change(previous["id"]).error


@pytest.mark.parametrize("failure", ["unknown_type", "ambiguous_claim", "read_timeout"])
def test_preflight_read_failure_never_creates_an_uncertain_paid_write(
    monkeypatch, alice, record, failure
):
    def read(self, record):
        if failure == "unknown_type":
            return {"status": "active", "current_type": "UNKNOWN", "pending_type": None}
        raise AwsFailure(failure, uncertain=True)

    monkeypatch.setattr(Gateway, "plan_change_info", read)
    c = request(alice, record).json()
    run()
    assert change(c["id"]).write_requested_at is None
    assert change(c["id"]).state == "failed"
    assert counter(2) == (0, 0, 0, 1)
    with SessionLocal() as db:
        assert db.get(Subscription, record["id"]).active_operation_id is None
    assert Gateway.calls == []


def test_unknown_replacement_recheck_settles_predecessor_before_delayed_release(
    alice, record
):
    previous = downgrade(alice, record)
    Gateway.failure, Gateway.lag = "timeout", True
    newer = upgrade(alice, record, 3, PLUS)
    assert change(newer["id"]).state == "needs_review"
    Gateway.current, Gateway.pending, Gateway.failure = PRO, None, None
    assert (
        alice.post(
            f"/api/subscriptions/{record['id']}/plan-changes/{newer['id']}/recheck",
            json={"confirm_username": record["username"]},
        ).status_code
        == 202
    )
    run()
    assert change(previous["id"]).state == "applied"
    assert counter(1) == (2, 0, 2, 1)
    assert change(newer["id"]).state == "needs_review"
    assert counter(4) == (0, 1, 0, 1)
    from app.models import PlanChange

    with SessionLocal() as db:
        db.get(PlanChange, newer["id"]).write_requested_at = now() - timedelta(
            minutes=11
        )
        db.commit()
    assert (
        alice.post(
            f"/api/subscriptions/{record['id']}/plan-changes/{newer['id']}/confirm-not-applied",
            json={
                "confirm_username": record["username"],
                "reason": "Old downgrade applied; new upgrade is absent",
                "acknowledge_not_applied": True,
            },
        ).status_code
        == 202
    )
    run()
    assert change(newer["id"]).state == "not_applied"
    assert counter(4) == (0, 0, 0, 1)
    assert Gateway.calls == [PLUS, PRO, MAX]
    assert (
        alice.get(f"/api/subscriptions/{record['id']}").json()["current_plan"][
            "subscription_type"
        ]
        == PRO
    )


def test_unknown_replacement_predecessor_settlement_does_not_preclude_late_success(
    alice, record
):
    previous = downgrade(alice, record)
    Gateway.failure, Gateway.lag = "timeout", True
    newer = upgrade(alice, record, 3, PLUS)
    Gateway.current, Gateway.pending, Gateway.failure = PRO, None, None
    endpoint = f"/api/subscriptions/{record['id']}/plan-changes/{newer['id']}/recheck"
    assert (
        alice.post(endpoint, json={"confirm_username": record["username"]}).status_code
        == 202
    )
    run()
    assert change(previous["id"]).state == "applied"
    Gateway.current = MAX
    assert (
        alice.post(endpoint, json={"confirm_username": record["username"]}).status_code
        == 202
    )
    run()
    assert change(newer["id"]).state == "applied"
    assert counter(1) == (2, 0, 2, 1)
    assert counter(4) == (1, 0, 1, 1)
    assert Gateway.calls == [PLUS, PRO, MAX]


def test_replacement_downgrade_can_be_observed_after_predecessor_applies(alice, record):
    upgrade(alice, record, 3)
    previous = request(alice, record, 2, MAX).json()
    run()
    Gateway.failure, Gateway.lag = "timeout", True
    newer = upgrade(alice, record, 1, MAX)
    Gateway.current, Gateway.pending, Gateway.failure = PLUS, PRO, None
    assert (
        alice.post(
            f"/api/subscriptions/{record['id']}/plan-changes/{newer['id']}/recheck",
            json={"confirm_username": record["username"]},
        ).status_code
        == 202
    )
    run()
    assert change(previous["id"]).state == "applied"
    assert change(newer["id"]).state == "scheduled"
    assert change(newer["id"]).from_type == MAX
    assert counter(2) == (1, 0, 1, 1)
    assert counter(1) == (1, 1, 1, 1)
    from app.plan_change_worker import reconcile_due

    assert reconcile_due(Gateway, force=True) == 1
    assert not change(newer["id"]).error
    Gateway.current, Gateway.pending = PRO, None
    assert reconcile_due(Gateway, force=True) == 1
    assert counter(1) == (2, 0, 2, 1)
    assert Gateway.calls == [MAX, PLUS, PRO]


@pytest.mark.parametrize(
    "kind", ["cancel_subscription", "sync_status", "automatic_cancel"]
)
def test_lifecycle_prewrite_pending_drift_releases_its_lock_and_preserves_schedule(
    alice, record, kind
):
    previous = downgrade(alice, record)
    Gateway.pending = None
    from app.lifecycle import run_operation

    if kind == "automatic_cancel":
        from app.schedules import enqueue_due

        with SessionLocal() as db:
            db.get(StopSchedule, record["id"]).stop_at = now() - timedelta(seconds=1)
            db.commit()
        assert enqueue_due() == 1
        with SessionLocal() as db:
            op_id = db.get(Subscription, record["id"]).active_operation_id
    else:
        response = alice.post(
            f"/api/subscriptions/{record['id']}/operations",
            json={
                "kind": kind,
                "request_key": str(uuid.uuid4()),
                "confirm_username": record["username"],
                "cancellation_mode": "IMMEDIATE",
            },
        )
        assert response.status_code == 202
        op_id = response.json()["id"]
    assert run_operation(Gateway)
    with SessionLocal() as db:
        assert db.get(RecordOperation, op_id).state == "failed"
        assert db.get(Subscription, record["id"]).active_operation_id is None
    assert change(previous["id"]).state == "scheduled"
    assert change(previous["id"]).error
    assert counter(1) == (1, 1, 1, 1)
    assert Gateway.calls == [PLUS, PRO]
    from app.models import PlanChange

    with SessionLocal() as db:
        db.get(PlanChange, previous["id"]).write_requested_at = now() - timedelta(
            minutes=11
        )
        db.commit()
    response = alice.post(
        f"/api/subscriptions/{record['id']}/plan-changes/{previous['id']}/confirm-not-applied",
        json={
            "confirm_username": record["username"],
            "reason": "AWS has withdrawn the pending downgrade",
            "acknowledge_not_applied": True,
        },
    )
    assert response.status_code == 202
    run()
    assert change(previous["id"]).state == "not_applied"
    assert counter(1) == (1, 0, 1, 1)


@pytest.mark.parametrize(
    "recovery", ["write_readback", "recheck", "confirm-not-applied"]
)
def test_confirmed_target_then_cancelled_is_counted_once(
    monkeypatch, alice, record, recovery
):
    before = record_snapshot(record)
    if recovery == "write_readback":
        original = Gateway.update_assignment

        def cancel_after_update(self, record, target):
            request_id = original(self, record, target)
            Gateway.status = "cancelled"
            return request_id

        monkeypatch.setattr(Gateway, "update_assignment", cancel_after_update)
    else:
        Gateway.failure, Gateway.lag = "timeout", True
    c = upgrade(alice, record)
    if recovery != "write_readback":
        assert change(c["id"]).state == "needs_review"
        from app.models import PlanChange

        with SessionLocal() as db:
            db.get(PlanChange, c["id"]).write_requested_at = now() - timedelta(
                minutes=11
            )
            db.commit()
        Gateway.current, Gateway.pending, Gateway.status = PLUS, None, "cancelled"
        body = {"confirm_username": record["username"]}
        if recovery == "confirm-not-applied":
            body.update(
                reason="Check whether unknown upgrade ever applied",
                acknowledge_not_applied=True,
            )
        response = alice.post(
            f"/api/subscriptions/{record['id']}/plan-changes/{c['id']}/{recovery}",
            json=body,
        )
        assert response.status_code == 202
        run()
    assert change(c["id"]).state == "applied"
    assert change(c["id"]).counted and not change(c["id"]).reserved
    assert counter(2) == (1, 0, 1, 1)
    assert Gateway.calls == [PLUS]
    assert record_snapshot(record) == before | {"subscription_status": "cancelled"}
    with SessionLocal() as db:
        assert db.get(Subscription, record["id"]).active_operation_id is None
        assert db.get(RecordOperation, c["operation_id"]).state == "completed"
    from app.plan_change_worker import run_plan_change

    assert run_plan_change(Gateway) is False
    assert counter(2) == (1, 0, 1, 1)


def test_due_reconciliation_limit_skips_locked_records_before_selecting_candidates():
    from app.models import PlanChange
    from app.plan_change_worker import reconcile_due

    Gateway.current, Gateway.pending, Gateway.status, Gateway.calls = (
        PRO,
        None,
        "active",
        [],
    )
    change_ids = []
    with SessionLocal() as db:
        for index in range(21):
            record_id, operation_id, change_id, blocker_id = [
                str(uuid.uuid4()) for _ in range(4)
            ]
            db.add(
                Subscription(
                    id=record_id,
                    owner_id=1,
                    aws_account_id=1,
                    plan_id=2,
                    request_key=str(uuid.uuid4()),
                    username=f"fair-queue-{index}",
                    email=f"fair{index}@example.com",
                    state="completed",
                    step="done",
                    sso_user_id=f"sso-fair-{index}",
                    portal_url="https://example.awsapps.com/start",
                    subscription_type=PLUS,
                    counted=True,
                    reserved=False,
                    subscription_status="active",
                    subscribed_at=now() - timedelta(days=10),
                    active_operation_id=blocker_id if index < 20 else None,
                )
            )
            db.flush()
            db.add(
                RecordOperation(
                    id=operation_id,
                    record_id=record_id,
                    actor_id=1,
                    kind="change_plan",
                    request_key=f"fair-plan:{change_id}",
                    payload="{}",
                    state="completed",
                    phase="done",
                )
            )
            if index < 20:
                db.add(
                    RecordOperation(
                        id=blocker_id,
                        record_id=record_id,
                        actor_id=1,
                        kind="cancel_subscription",
                        request_key=f"fair-block:{change_id}",
                        payload="{}",
                        state="needs_review",
                        phase="pending",
                    )
                )
            db.flush()
            db.add(
                PlanChange(
                    id=change_id,
                    record_id=record_id,
                    operation_id=operation_id,
                    actor_id=1,
                    owner_id=1,
                    request_key=str(uuid.uuid4()),
                    payload_hash="test",
                    direction="downgrade",
                    from_plan_id=2,
                    from_plan_name="Plus",
                    from_type=PLUS,
                    to_plan_id=1,
                    to_plan_name="Pro",
                    to_type=PRO,
                    reserved=False,
                    counted=False,
                    state="scheduled",
                    scheduled_record_id=record_id,
                    write_requested_at=now() - timedelta(days=1),
                    accepted_at=now() - timedelta(days=1),
                    next_check_at=now() - timedelta(minutes=30 - index),
                )
            )
            change_ids.append(change_id)
        db.commit()
    assert reconcile_due(Gateway) == 1
    assert change(change_ids[-1]).state == "applied"
    assert all(change(cid).state == "scheduled" for cid in change_ids[:-1])
    assert Gateway.calls == []


def test_reconciliation_rechecks_lock_after_candidate_query(monkeypatch, alice, record):
    import app.plan_change_worker as worker

    c = downgrade(alice, record)
    actual_session = worker.SessionLocal
    calls = 0
    blocker_id = str(uuid.uuid4())

    def racing_session():
        nonlocal calls
        calls += 1
        if calls == 2:
            with actual_session() as db:
                db.add(
                    RecordOperation(
                        id=blocker_id,
                        record_id=record["id"],
                        actor_id=1,
                        kind="update_sso",
                        request_key=str(uuid.uuid4()),
                        payload="{}",
                        state="queued",
                        phase="ready",
                    )
                )
                db.get(Subscription, record["id"]).active_operation_id = blocker_id
                db.commit()
        return actual_session()

    monkeypatch.setattr(worker, "SessionLocal", racing_session)
    Gateway.current, Gateway.pending = PRO, None
    assert worker.reconcile_due(Gateway, force=True) == 0
    assert change(c["id"]).state == "scheduled"
    assert counter(1) == (1, 1, 1, 1)
    with actual_session() as db:
        assert db.get(Subscription, record["id"]).active_operation_id == blocker_id
        assert db.get(RecordOperation, blocker_id).state == "queued"
        db.get(Subscription, record["id"]).active_operation_id = None
        db.commit()
    assert worker.reconcile_due(Gateway, force=True) == 1
    assert change(c["id"]).state == "applied"
    assert counter(1) == (2, 0, 2, 1)


@pytest.mark.parametrize("predecessor_applied", [False, True])
@pytest.mark.parametrize("recovery", ["recheck", "confirm-not-applied"])
def test_unknown_withdrawal_closes_after_cancellation_without_extra_quota(
    alice, record, predecessor_applied, recovery
):
    previous = downgrade(alice, record)
    before = record_snapshot(record)
    Gateway.failure, Gateway.lag = "timeout", True
    response = alice.post(
        f"/api/subscriptions/{record['id']}/plan-changes/{previous['id']}/withdraw",
        json={
            "request_key": str(uuid.uuid4()),
            "confirm_username": record["username"],
            "expected_current_type": PLUS,
        },
    )
    assert response.status_code == 202
    withdrawal = response.json()
    run()
    assert change(withdrawal["id"]).state == "needs_review"
    assert counter(1) == (1, 1, 1, 1)
    Gateway.current = PRO if predecessor_applied else PLUS
    Gateway.pending, Gateway.status, Gateway.failure = None, "cancelled", None
    from app.models import PlanChange

    with SessionLocal() as db:
        db.get(PlanChange, withdrawal["id"]).write_requested_at = now() - timedelta(
            minutes=11
        )
        db.commit()
    body = {"confirm_username": record["username"]}
    if recovery == "confirm-not-applied":
        body.update(
            reason="AWS cancelled the subscription while withdrawal outcome was unknown",
            acknowledge_not_applied=True,
        )
    response = alice.post(
        f"/api/subscriptions/{record['id']}/plan-changes/{withdrawal['id']}/{recovery}",
        json=body,
    )
    assert response.status_code == 202
    run()
    assert change(withdrawal["id"]).state == "cancelled"
    assert (
        not change(withdrawal["id"]).counted and not change(withdrawal["id"]).reserved
    )
    assert change(previous["id"]).state == (
        "applied" if predecessor_applied else "cancelled"
    )
    assert counter(1) == ((2, 0, 2, 1) if predecessor_applied else (1, 0, 1, 1))
    assert counter(2) == (1, 0, 1, 1)
    assert Gateway.calls == [PLUS, PRO, PLUS]
    assert record_snapshot(record) == before | {"subscription_status": "cancelled"}
    with SessionLocal() as db:
        assert db.get(Subscription, record["id"]).active_operation_id is None
        assert db.get(RecordOperation, withdrawal["operation_id"]).state == "completed"
    from app.plan_change_worker import run_plan_change, reconcile_due

    assert run_plan_change(Gateway) is False
    assert reconcile_due(Gateway, force=True) == 0
    assert Gateway.calls == [PLUS, PRO, PLUS]
