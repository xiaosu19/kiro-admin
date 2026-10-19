import concurrent.futures
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete, func, select, text

from app.database import SessionLocal, engine
from app.init_db import initialize
from app.lifecycle import run_operation
from app.models import (
    AwsAccount,
    Batch,
    Binding,
    RecordOperation,
    SchemaVersion,
    StopSchedule,
    Subscription,
    User,
    now,
)
from app.schedules import enqueue_due
from app.worker import run_one
from test_batches import complete_sso
import test_lifecycle
from test_lifecycle import LifecycleGateway, get, operation, retry
from test_workflows import Gateway, count


@pytest.fixture
def record(alice):
    return test_lifecycle.record.__wrapped__(alice)


def future(days=2):
    return (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()


def set_schedule(client, r, policy=None, revision=0):
    return client.put(
        f"/api/subscriptions/{r['id']}/stop-schedule",
        json={
            "policy": policy or {"mode": "days", "days": 30},
            "expected_revision": revision,
        },
    )


def due(r):
    with SessionLocal() as db:
        db.get(StopSchedule, r["id"]).stop_at = now() - timedelta(seconds=1)
        db.commit()


def test_owner_admin_revision_csrf_and_history(alice, bob, admin, record):
    assert set_schedule(bob, record).status_code == 404
    assert set_schedule(alice, record).status_code == 200
    assert set_schedule(admin, record).status_code == 409
    changed = set_schedule(admin, record, {"mode": "at", "stop_at": future()}, 1)
    assert changed.status_code == 200
    assert changed.json()["revision"] == 2
    assert (
        set_schedule(alice, record, {"mode": "none"}, 2).json()["state"] == "disabled"
    )
    assert get(alice, record)["subscribed_at"] == record["subscribed_at"]
    assert count() == (1, 0, 1, 1)
    own_audit = alice.get("/api/audit").json()["items"]
    assert all(e["actor_name"] != "admin" for e in own_audit)
    assert (
        alice.put(
            f"/api/subscriptions/{record['id']}/stop-schedule",
            json={"policy": {"mode": "none"}, "expected_revision": 3},
            headers={"X-CSRF-Token": "wrong"},
        ).status_code
        == 403
    )


@pytest.mark.parametrize(
    "policy",
    [
        {"mode": "days", "days": 0},
        {"mode": "days", "days": 3651},
        {"mode": "days"},
        {"mode": "none", "days": 3},
        {"mode": "at", "stop_at": "2026-01-01T10:00:00"},
        {"mode": "at", "stop_at": "2020-01-01T10:00:00Z"},
        {"mode": "at", "stop_at": "2100-01-01T10:00:00Z"},
        {"mode": "at", "stop_at": future(), "days": 1},
    ],
)
def test_invalid_policy_rolls_back(alice, record, policy):
    assert set_schedule(alice, record, policy).status_code == 422
    assert get(alice, record)["stop_schedule"] is None


def test_existing_days_uses_original_activation(alice, record):
    with SessionLocal() as db:
        r = db.get(Subscription, record["id"])
        r.subscribed_at = now() - timedelta(days=10)
        original = r.subscribed_at
        db.commit()
    assert set_schedule(alice, record, {"mode": "days", "days": 3}).status_code == 422
    response = set_schedule(alice, record, {"mode": "days", "days": 30})
    assert response.status_code == 200
    assert datetime.fromisoformat(response.json()["stop_at"]) == original + timedelta(
        days=30
    )


def test_extending_or_disabling_deadline_invalidates_old_time(
    alice, record, monkeypatch
):
    first_due = now() + timedelta(days=1)
    later_due = first_due + timedelta(days=30)
    assert (
        set_schedule(
            alice, record, {"mode": "at", "stop_at": first_due.isoformat() + "Z"}
        ).status_code
        == 200
    )
    assert (
        set_schedule(
            alice, record, {"mode": "at", "stop_at": later_due.isoformat() + "Z"}, 1
        ).status_code
        == 200
    )
    monkeypatch.setattr("app.schedules.now", lambda: first_due + timedelta(seconds=1))
    assert enqueue_due() == 0
    assert get(alice, record)["stop_schedule"]["revision"] == 2
    assert set_schedule(alice, record, {"mode": "none"}, 2).status_code == 200
    monkeypatch.setattr("app.schedules.now", lambda: later_due + timedelta(seconds=1))
    assert enqueue_due() == 0
    assert get(alice, record)["subscription_status"] == "active"
    assert LifecycleGateway.calls == []


def test_batch_sso_then_subscribe_timer_from_success_and_idempotency(alice):
    Gateway.mode = "ok"
    _, ids = complete_sso(alice)
    body = {
        "record_ids": ids,
        "plan_id": 1,
        "request_key": str(uuid.uuid4()),
        "stop_schedule": {"mode": "days", "days": 7},
    }
    response = alice.post("/api/batches/subscribe", json=body)
    assert response.status_code == 202, response.text
    assert (
        alice.post("/api/batches/subscribe", json=body).json()["id"]
        == response.json()["id"]
    )
    for rid in ids:
        schedule = get(alice, {"id": rid})["stop_schedule"]
        assert schedule["state"] == "waiting" and schedule["stop_at"] is None
    assert enqueue_due() == 0
    for rid in ids:
        run_one(Gateway)
        r = get(alice, {"id": rid})
        assert datetime.fromisoformat(
            r["stop_schedule"]["stop_at"]
        ) == datetime.fromisoformat(r["subscribed_at"]) + timedelta(days=7)
    body["stop_schedule"]["days"] = 8
    assert alice.post("/api/batches/subscribe", json=body).status_code == 409
    assert count() == (2, 0, 2, 1)


def test_legacy_batch_hash_replay_is_compatible(alice):
    Gateway.mode = "ok"
    batch, _ = complete_sso(alice)
    body = {
        "kind": "sso",
        "aws_account_id": 1,
        "plan_id": None,
        "items": [
            {"username": f"person{i}", "email": f"person{i}@example.com"}
            for i in range(2)
        ],
        "sequence": None,
    }
    with SessionLocal() as db:
        saved = db.get(Batch, batch["id"])
        assert (
            saved.payload_hash
            == hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        )
        body["request_key"] = saved.request_key
    body["stop_schedule"] = {"mode": "none"}
    assert alice.post("/api/batches/create", json=body).json()["id"] == batch["id"]


@pytest.mark.parametrize("kind", ["sso", "subscribed"])
def test_invalid_create_batch_is_atomic(alice, kind):
    body = {
        "kind": kind,
        "aws_account_id": 1,
        "plan_id": 1 if kind == "subscribed" else None,
        "items": [{"username": "first"}, {"username": "second"}],
        "request_key": str(uuid.uuid4()),
        "stop_schedule": {"mode": "at", "stop_at": "2020-01-01T00:00:00Z"},
    }
    assert alice.post("/api/batches/create", json=body).status_code == 422
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Subscription)) == 0
        assert db.scalar(select(func.count()).select_from(Batch)) == 0
        assert db.scalar(select(func.count()).select_from(StopSchedule)) == 0
    assert count() == (0, 0, 0, 1)


def test_due_single_admission_restart_and_preserved_history(alice, record):
    assert set_schedule(alice, record).status_code == 200
    assert enqueue_due() == 0
    due(record)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(lambda _: enqueue_due(), range(4))) == 1
    # No process memory is required between admission and execution.
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(RecordOperation)) == 1
    assert run_operation(LifecycleGateway)
    assert LifecycleGateway.calls == ["cancel"]
    assert enqueue_due() == 0 and not run_operation(LifecycleGateway)
    result = get(alice, record)
    assert result["stop_schedule"]["state"] == "completed"
    assert result["cancellation_mode"] == "IMMEDIATE"
    for field in (
        "sso_user_id",
        "subscribed_at",
        "plan_id",
        "plan_name",
        "counted",
        "password_generated_at",
    ):
        assert result[field] == record[field]
    assert result["sso_deleted_at"] is None and result["has_password"]
    assert count() == (1, 0, 1, 1)
    assert alice.get(f"/api/subscriptions/{record['id']}/operations").json()[0][
        "automatic"
    ]


def test_saved_intent_survives_disabled_creator_and_unbinding(alice, admin, record):
    set_schedule(alice, record)
    due(record)
    with SessionLocal() as db:
        user = db.get(User, 2)
        user.active = False
        user.deleted_at = now()
        db.execute(delete(Binding).where(Binding.user_id == 2))
        db.commit()
    assert enqueue_due() == 1 and run_operation(LifecycleGateway)
    assert get(admin, record)["stop_schedule"]["state"] == "completed"


def test_inactive_aws_blocks_and_resumes(alice, admin, record):
    set_schedule(alice, record)
    due(record)
    with SessionLocal() as db:
        db.get(AwsAccount, 1).active = False
        db.commit()
    assert enqueue_due() == 0
    assert get(alice, record)["stop_schedule"]["state"] == "blocked"
    assert alice.get("/api/sso-users?status=schedule_attention").json()["total"] == 1
    with SessionLocal() as db:
        db.get(AwsAccount, 1).active = True
        db.get(StopSchedule, record["id"]).next_check_at = now() - timedelta(seconds=1)
        db.commit()
    assert enqueue_due() == 1 and run_operation(LifecycleGateway)


def test_deleted_aws_preserves_subscription_and_blocks_scheduled_cancel(alice, admin, record):
    set_schedule(alice, record)
    due(record)
    assert admin.request("DELETE", "/api/admin/aws/1", json={"confirm_name": "测试 AWS"}).status_code == 200
    assert enqueue_due() == 0
    retained = get(admin, record)
    assert retained["account_deleted_at"] and not retained["sso_deleted_at"]
    assert retained["stop_schedule"]["state"] == "blocked"


def test_pending_manual_operation_defers_and_cancel_completes_schedule(alice, record):
    set_schedule(alice, record)
    due(record)
    assert (
        operation(
            alice, record, "cancel_subscription", cancellation_mode="IMMEDIATE"
        ).status_code
        == 202
    )
    assert enqueue_due() == 0
    assert set_schedule(alice, record, {"mode": "none"}, 1).status_code == 409
    run_operation(LifecycleGateway)
    assert get(alice, record)["stop_schedule"]["state"] == "completed"
    assert enqueue_due() == 0


def test_timeout_needs_review_never_blindly_replays(alice, record):
    set_schedule(alice, record)
    due(record)
    LifecycleGateway.failure = "timeout"
    enqueue_due()
    run_operation(LifecycleGateway)
    r = get(alice, record)
    assert r["stop_schedule"]["state"] == "needs_review"
    assert enqueue_due() == 0 and not run_operation(LifecycleGateway)
    LifecycleGateway.failure = None
    assert retry(alice, record, r["operation"]).status_code == 202
    assert get(alice, record)["stop_schedule"]["state"] == "queued"
    run_operation(LifecycleGateway)
    assert LifecycleGateway.calls == ["cancel"]
    assert get(alice, record)["stop_schedule"]["state"] == "completed"


def test_definite_failure_can_be_rescheduled(alice, record):
    set_schedule(alice, record)
    due(record)
    LifecycleGateway.failure = "denied"
    enqueue_due()
    run_operation(LifecycleGateway)
    assert get(alice, record)["stop_schedule"]["state"] == "failed"
    assert enqueue_due() == 0
    assert (
        set_schedule(alice, record, {"mode": "at", "stop_at": future()}, 1).status_code
        == 200
    )
    LifecycleGateway.failure = None
    due(record)
    assert enqueue_due() == 1
    run_operation(LifecycleGateway)
    assert get(alice, record)["stop_schedule"]["state"] == "completed"


def test_expired_date_prevents_new_aws_subscription_but_reconciles_previous(alice):
    Gateway.mode = "ok"
    _, ids = complete_sso(alice, 1)
    response = alice.post(
        "/api/batches/subscribe",
        json={
            "record_ids": ids,
            "plan_id": 1,
            "request_key": str(uuid.uuid4()),
            "stop_schedule": {"mode": "at", "stop_at": future()},
        },
    )
    assert response.status_code == 202
    r = {"id": ids[0]}
    due(r)
    Gateway.calls = 0
    run_one(Gateway)
    assert Gateway.calls == 0 and get(alice, r)["state"] == "failed"
    assert count() == (0, 0, 0, 1)
    # Changing to a future deadline allows the existing explicit retry flow.
    assert set_schedule(alice, r, {"mode": "days", "days": 7}, 1).status_code == 200
    assert alice.post(f"/api/subscriptions/{ids[0]}/retry").status_code == 202
    Gateway.mode = "unknown"
    run_one(Gateway)
    assert get(alice, r)["stop_schedule"]["state"] == "waiting"
    Gateway.mode = "reconciled"
    assert alice.post(f"/api/subscriptions/{ids[0]}/retry").status_code == 202
    run_one(Gateway)
    assert get(alice, r)["stop_schedule"]["state"] == "scheduled"
    assert count() == (1, 0, 1, 1)


def test_schedule_filters_and_export_are_owner_scoped(alice, bob, record):
    set_schedule(alice, record)
    assert alice.get("/api/sso-users?status=scheduled").json()["total"] == 1
    assert bob.get("/api/sso-users?status=scheduled").json()["total"] == 0
    exported = alice.post("/api/sso-users/export", json={"status": "scheduled"})
    assert exported.status_code == 200
    assert "定时停止时间(UTC)" in exported.text and "scheduled" in exported.text
    assert (
        bob.post("/api/sso-users/export", json={"status": "scheduled"}).status_code
        == 409
    )


def test_schema_five_upgrade_defaults_to_no_deadlines(record):
    from app.migrations import VERSION
    with SessionLocal() as db:
        original = {
            c.name: getattr(db.get(Subscription, record["id"]), c.name)
            for c in Subscription.__table__.columns
        }
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP TABLE console_stop_schedules")
        connection.execute(
            text("INSERT INTO console_schema_version (version) VALUES (5)")
        )
    initialize()
    initialize()
    with SessionLocal() as db:
        assert db.scalar(select(SchemaVersion.version)) == VERSION
        assert db.scalar(select(func.count()).select_from(StopSchedule)) == 0
        current = {
            c.name: getattr(db.get(Subscription, record["id"]), c.name)
            for c in Subscription.__table__.columns
        }
        assert current == original
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
