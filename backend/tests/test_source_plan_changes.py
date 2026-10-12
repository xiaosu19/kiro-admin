import json

import pytest

from app.database import SessionLocal
from app.models import AwsAccount, Subscription
from app.subscription_sources import observe_subscription, apply_observation
from test_plan_changes import record, enable_plan_changes, Gateway, request, run, change, PRO, PLUS, MAX


def observe_mixed(record):
    Gateway.effective_type = MAX
    Gateway.additional_sources = [{"source": "GROUP", "group_id": "external-group", "status": "active",
                                   "subscription_type": MAX, "expires_at": None}]
    with SessionLocal() as db:
        r = db.get(Subscription, record["id"])
        apply_observation(r, observe_subscription(Gateway(db.get(AwsAccount, 1)), r))
        db.commit()


def test_user_change_direction_and_worker_use_user_tier_while_effective_group_stays_max(alice, record):
    observe_mixed(record)
    options = alice.get(f"/api/subscriptions/{record['id']}/plan-options").json()
    assert options["current_plan"]["subscription_type"] == PRO
    target = next(t for t in options["targets"] if t["plan_id"] == 2)
    assert target["direction"] == "upgrade" and target["available"]
    result = request(alice, record, 2, PRO)
    assert result.status_code == 202, result.text
    run()
    c = change(result.json()["id"])
    assert c.state == "applied" and c.counted and c.from_type == PRO and c.to_type == PLUS
    view = alice.get(f"/api/subscriptions/{record['id']}").json()
    assert view["current_plan"]["subscription_type"] == MAX
    assert view["observed_subscription_type"] == MAX
    assert view["direct_user_plan"]["subscription_type"] == PLUS
    assert Gateway.calls == [PLUS]


def test_user_cancellation_leaves_external_group_and_effective_tier(alice, record):
    from app.lifecycle import run_operation
    from test_lifecycle import operation
    observe_mixed(record)
    result = operation(alice, record, "cancel_subscription", cancellation_mode="IMMEDIATE")
    assert result.status_code == 202, result.text
    run_operation(Gateway)
    view = alice.get(f"/api/subscriptions/{record['id']}").json()
    assert alice.get(f"/api/subscriptions/{record['id']}/operations").json()[0]["state"] == "completed"
    assert view["subscription_status"] == "active"
    assert view["observed_subscription_type"] == MAX
    assert view["effective_subscription_source"] == "GROUP"
    assert view["cancelled_at"] is None
    # The personal deadline completed its USER cancellation, irrespective of GROUP access.
    assert view["stop_schedule"]["state"] == "completed"
    assert Gateway.calls == ["cancel"]


@pytest.mark.parametrize("legacy_result", ["accepted", "readback"])
def test_legacy_upgraded_user_cancellation_restores_the_cancelled_tier(alice, record, monkeypatch, legacy_result):
    from app.models import RecordOperation
    from app.lifecycle import run_operation
    from test_lifecycle import LifecycleGateway, operation, get
    assert request(alice, record, 2, PRO).status_code == 202
    run()
    LifecycleGateway.calls, LifecycleGateway.exists, LifecycleGateway.failure = [], True, None
    LifecycleGateway.info = {"status": "active", "subscription_type": PLUS, "expires_at": None}
    LifecycleGateway.profile = {"DisplayName": "Original User"}
    monkeypatch.setattr(LifecycleGateway, "plan_change_info", lambda self, r: {
        "status": self.info["status"], "current_type": self.info["subscription_type"],
        "pending_type": None, "expected_effective_at": None}, raising=False)
    response = operation(alice, record, "cancel_subscription", cancellation_mode="IMMEDIATE")
    assert response.status_code == 202
    run_operation(LifecycleGateway)
    with SessionLocal() as db:
        row = db.get(Subscription, record["id"])
        assert row.subscription_type == PRO
        row.subscription_observation = None
        op = db.get(RecordOperation, response.json()["id"])
        payload, result = json.loads(op.payload), json.loads(op.result)
        payload.pop("principal_type", None)
        result.pop("subscription_observation", None)
        assert result["observed_subscription_type"] == PLUS
        if legacy_result == "accepted":
            result = {k: result[k] for k in ("subscription_status", "access_ends_at", "cancelled_at", "cancellation_mode")}
        op.payload, op.result = json.dumps(payload), json.dumps(result)
        db.commit()
    assert operation(alice, record, "sync_status").status_code == 202
    run_operation(LifecycleGateway)
    view = get(alice, record)
    assert view["subscription_status"] == "cancelled"
    assert view["cancellation_mode"] == "IMMEDIATE"
    assert view["access_ends_at"] is None
    assert view["subscription_type"] == PRO
    assert view["direct_user_plan"]["subscription_type"] == PLUS
    assert LifecycleGateway.calls == ["cancel"]


def test_upgraded_legacy_user_cancel_with_missing_claim_keeps_the_cancelled_tier(alice, record, monkeypatch):
    from app.lifecycle import run_operation
    from test_lifecycle import LifecycleGateway, operation, get
    assert request(alice, record, 2, PRO).status_code == 202
    run()
    with SessionLocal() as db:
        db.get(Subscription, record["id"]).subscription_observation = None
        db.commit()
    LifecycleGateway.calls, LifecycleGateway.exists, LifecycleGateway.failure = [], True, None
    LifecycleGateway.info = {"status": "active", "subscription_type": PLUS, "expires_at": None}
    LifecycleGateway.profile = {"DisplayName": "Original User"}
    monkeypatch.setattr(LifecycleGateway, "plan_change_info", lambda self, r: {
        "status": self.info["status"], "current_type": self.info["subscription_type"],
        "pending_type": None, "expected_effective_at": None}, raising=False)
    show_cancelled_claim = False

    def claims(self, row):
        self.observed_record = row
        return [{"source": "USER", "group_id": None, **self.subscription_info(row)}] if (
            self.info["status"] == "active" or show_cancelled_claim
        ) else []

    monkeypatch.setattr(LifecycleGateway, "user_subscription_sources", claims)
    assert operation(alice, record, "cancel_subscription", cancellation_mode="IMMEDIATE").status_code == 202
    run_operation(LifecycleGateway)
    assert get(alice, record)["subscription_status"] == "cancelled"
    show_cancelled_claim = True
    assert operation(alice, record, "sync_status").status_code == 202
    run_operation(LifecycleGateway)
    view = get(alice, record)
    assert view["subscription_status"] == "cancelled"
    assert view["cancellation_mode"] == "IMMEDIATE"
    assert view["access_ends_at"] is None
    assert view["effective_subscription_source"] is None
    assert view["subscription_type"] == PRO
    assert view["direct_user_plan"]["subscription_type"] == PLUS
    assert LifecycleGateway.calls == ["cancel"]


def test_later_applied_user_plan_cycle_invalidates_legacy_cancellation(alice, record, monkeypatch):
    from datetime import timedelta
    from app.lifecycle import run_operation
    from app.models import RecordOperation, now
    from app.plan_change_worker import reconcile_due
    from test_lifecycle import LifecycleGateway, operation, get
    LifecycleGateway.calls, LifecycleGateway.exists, LifecycleGateway.failure = [], True, None
    LifecycleGateway.info = {"status": "active", "subscription_type": PRO, "expires_at": None}
    LifecycleGateway.profile = {"DisplayName": "Original User"}
    monkeypatch.setattr(LifecycleGateway, "plan_change_info", lambda self, r: {
        "status": self.info["status"], "current_type": self.info["subscription_type"],
        "pending_type": None, "expected_effective_at": None}, raising=False)
    stopped = operation(alice, record, "cancel_subscription", cancellation_mode="IMMEDIATE")
    assert stopped.status_code == 202
    run_operation(LifecycleGateway)
    with SessionLocal() as db:
        op = db.get(RecordOperation, stopped.json()["id"])
        result = json.loads(op.result)
        op.payload = json.dumps({"cancellation_mode": "IMMEDIATE"})
        op.result = json.dumps({k: result[k] for k in ("subscription_status", "access_ends_at", "cancelled_at", "cancellation_mode")})
        row = db.get(Subscription, record["id"])
        # The next plan admission verifies the newly active external USER.
        row.subscription_observation, row.subscription_status = None, "active"
        row.cancelled_at = row.cancellation_mode = None
        db.commit()
    assert request(alice, record, 2, PRO).status_code == 202
    run()
    down = request(alice, record, 1, PLUS)
    assert down.status_code == 202
    run()
    Gateway.current, Gateway.pending = PRO, None
    assert reconcile_due(Gateway, force=True) == 1
    assert change(down.json()["id"]).state == "applied"
    with SessionLocal() as db:
        db.get(Subscription, record["id"]).subscription_observation = None
        db.commit()
    boundary = now() + timedelta(days=20)
    LifecycleGateway.info.update(status="cancelled", expires_at=boundary)
    assert operation(alice, record, "sync_status").status_code == 202
    run_operation(LifecycleGateway)
    view = get(alice, record)
    assert view["subscription_status"] == "cancel_scheduled"
    assert view["access_ends_at"] == boundary.isoformat()
    assert view["effective_subscription_source"] == "USER"
    assert LifecycleGateway.calls == ["cancel"]
