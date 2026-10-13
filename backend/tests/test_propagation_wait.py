"""Long AWS propagation waits remain durable, read-only and separate from errors."""
from datetime import timedelta

from sqlalchemy import create_engine, inspect

from app import automatic_retries as retries
from app.aws import AwsFailure
from app.database import SessionLocal
from app.migrations import migrate
from app.models import Subscription, now
from app.retry_models import AutomaticRetry
from test_automatic_retries import client_error, seed


def pending():
    return seed(step="group_entitlement_pending", sso_user_id="synthetic-sso")


def propagation():
    return AwsFailure("AWS subscription propagation", uncertain=True,
                      code="subscription_observation_propagating", retryable=True)


def test_wait_keeps_one_deadline_across_sessions_rechecks_and_stops(monkeypatch):
    rid, start = pending(), now()
    monkeypatch.setattr(retries, "now", lambda: start)
    with SessionLocal() as db:
        assert retries.schedule_retry(db, "sso", rid, propagation(), mode="reconcile", config_hash="frozen")
        db.commit()
    for hours in (1, 2, 4, 6, 8, 10, 12, 18, 23):
        current = start + timedelta(hours=hours)
        monkeypatch.setattr(retries, "now", lambda: current)
        with SessionLocal() as db:
            assert retries.schedule_retry(db, "sso", rid, propagation(), mode="reconcile", config_hash="changed")
            view = retries.retry_view(db, "sso", rid)
            assert view["propagation_state"] == "waiting"
            assert view["propagation_started_at"] == start
            assert view["propagation_deadline"] == start + timedelta(hours=24)
            assert current < view["next_retry_at"] <= current + timedelta(minutes=15)
            assert view["automatic_retry_count"] == 0
            assert db.get(AutomaticRetry, ("sso", rid)).config_hash == "frozen"
            assert db.get(Subscription, rid).subscription_status == "not_subscribed"
            db.commit()
    with SessionLocal() as db:
        assert not retries.schedule_retry(db, "sso", rid, propagation(), mode="reconcile", stopped=True)
        assert retries.retry_view(db, "sso", rid, active=False, state="stopped")["propagation_state"] is None
        db.commit()
    current = start + timedelta(hours=24)
    monkeypatch.setattr(retries, "now", lambda: current)
    for _ in range(2):
        with SessionLocal() as db:
            assert not retries.schedule_retry(db, "sso", rid, propagation(), mode="reconcile")
            assert retries.retry_view(db, "sso", rid, active=False, state="needs_review")["propagation_state"] == "timed_out"
            assert retries.retry_view(db, "sso", rid, active=False, state="completed")["propagation_state"] is None
            assert db.get(AutomaticRetry, ("sso", rid)).propagation_started_at == start
            db.commit()


def test_network_failures_keep_five_attempt_budget_during_propagation():
    rid = pending()
    with SessionLocal() as db:
        for _ in range(5):
            assert retries.schedule_retry(db, "sso", rid, client_error(), mode="reconcile")
            assert retries.schedule_retry(db, "sso", rid, propagation(), mode="reconcile")
        assert not retries.schedule_retry(db, "sso", rid, client_error(), mode="reconcile")
        row = db.get(AutomaticRetry, ("sso", rid))
        assert row.retry_count == 5 and row.propagation_check_count == 5
        assert row.next_retry_at is None and row.exhausted
        assert retries.retry_view(db, "sso", rid)["propagation_state"] is None


def test_schema18_retry_rows_upgrade_without_resetting_budget_or_intent(tmp_path):
    target = create_engine(f"sqlite:///{tmp_path / 'schema18.db'}")
    with target.begin() as db:
        db.exec_driver_sql("CREATE TABLE console_schema_version (version INTEGER)")
        db.exec_driver_sql("INSERT INTO console_schema_version VALUES (18)")
        db.exec_driver_sql("""CREATE TABLE console_automatic_retries (
            family VARCHAR(20), job_id VARCHAR(36), retry_count INTEGER CHECK(retry_count BETWEEN 0 AND 5),
            next_retry_at DATETIME, error_code VARCHAR(60), mode VARCHAR(20), config_hash VARCHAR(64),
            exhausted BOOLEAN, updated_at DATETIME, PRIMARY KEY(family,job_id))""")
        db.exec_driver_sql("INSERT INTO console_automatic_retries VALUES ('sso','original',5,NULL,'subscription_observation_propagating','reconcile','frozen',1,'2026-01-01')")
        original = db.exec_driver_sql("SELECT * FROM console_automatic_retries").one()
    migrate(target)
    migrate(target)
    with target.connect() as db:
        row = db.exec_driver_sql("SELECT * FROM console_automatic_retries").one()
        assert tuple(row[:9]) == tuple(original)
        assert tuple(row[9:]) == (None, None, 0)
        assert db.exec_driver_sql("SELECT version FROM console_schema_version").scalar() == 19
        assert db.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
    target.dispose()
