"""Stopped numbered batches resume through existing workers and quotas."""
# Imported pytest fixtures deliberately share names with fixture parameters.
# ruff: noqa: F811
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app import models, worker
from app.database import SessionLocal
from test_provisioning_admission import admit, ready, remote  # noqa: F401
from test_provisioning_coordinator import Gateway, body, coordinator_to_child, drive, fetch, gateway  # noqa: F401


def action(client, parent, kind, key):
    row = parent["accounts"][0]
    return client.post(f"/api/provisioning-batches/{parent['id']}/accounts/{row['id']}/{kind}",
                       json={"request_key": key})


@pytest.mark.parametrize("stage", ["admitted", "group", "native", "sso", "partial"])
def test_resume_stopped_preserves_completed_work_and_quotas(alice, gateway, stage):
    parent = admit(alice, body(quantity=2)).json()
    if stage != "admitted":
        coordinator_to_child(parent, "sso" if stage == "partial" else stage)
    if stage == "partial":
        assert worker.run_one(Gateway, account_id=1)
    stopped = action(alice, parent, "stop", "stop-before-resume-0001")
    assert stopped.status_code == 202, stopped.text
    assert stopped.json()["state"] == "stopped", stopped.text
    prior_events = list(gateway.events)
    row = stopped.json()["accounts"][0]
    assert "resume" in row["allowed_actions"]
    response = action(alice, parent, "resume", "resume-stopped-0001")
    assert response.status_code == 202, response.text
    replay = action(alice, parent, "resume", "resume-stopped-0001")
    assert replay.status_code == 202 and gateway.events == prior_events
    final = drive(parent, alice)
    assert final["state"] == "completed", final
    assert all(i["state"] == "completed" for i in final["accounts"][0]["items"])
    assert [e[0] for e in gateway.events].count("GROUP") == 1
    assert sorted(e for e in gateway.events if e[0] == "sso") == [
        ("sso", 1, "a-01-01"), ("sso", 1, "a-01-02")]
    with SessionLocal() as db:
        counter = db.get(models.PlanCounter, 1)
        assert (counter.used_count, counter.pending_count) == (2, 0)
        assert db.scalar(select(func.count()).select_from(models.Subscription)) == 2
        assert db.scalar(select(func.count()).select_from(models.ProvisioningAction).where(
            models.ProvisioningAction.kind == "resume")) == 1
    assert "resume" not in final["accounts"][0]["allowed_actions"]


@pytest.mark.parametrize("change", ["proxy", "session", "deleted_group", "cancelled_grant", "expired_grant", "uncertain_record", "quota"])
def test_resume_rechecks_scope_and_rolls_back_on_failure(alice, gateway, change):
    parent = admit(alice, body()).json()
    coordinator_to_child(parent, "sso")
    assert action(alice, parent, "stop", "stop-before-change-01").status_code == 202
    row = fetch(alice, parent)["accounts"][0]
    rid = row["items"][0]["record_id"]
    with SessionLocal() as db:
        if change == "proxy":
            db.get(models.Proxy, db.get(models.AwsAccount, 1).proxy_id).port += 1
        elif change == "session":
            db.get(models.ProvisioningBatch, parent["id"]).session_version += 1
        elif change == "deleted_group":
            db.get(models.ManagedGroup, row["group"]["id"]).deleted_at = models.now()
        elif change == "cancelled_grant":
            db.get(models.NativeGroupGrant, row["native_grant_id"]).state = "cancelled"
        elif change == "expired_grant":
            db.get(models.NativeGroupGrant, row["native_grant_id"]).stop_at = models.now() - timedelta(seconds=1)
        elif change == "uncertain_record":
            record = db.get(models.Subscription, rid)
            record.state, record.step = "needs_review", "group_membership_pending"
        elif change == "quota":
            db.get(models.PlanCounter, 1).limit_count = 0
        db.commit()
    before = list(gateway.events)
    response = action(alice, parent, "resume", "resume-after-change-01")
    assert response.status_code in (403, 409), response.text
    assert gateway.events == before
    with SessionLocal() as db:
        child = db.get(models.ProvisioningAccountBatch, row["id"])
        assert child.state == "stopped" and child.stop_requested_at
        assert db.get(models.ProvisioningItem, rid).state == "stopped"
        assert db.get(models.PlanCounter, 1).pending_count == 0
        assert not db.scalar(select(models.ProvisioningAction.id).where(models.ProvisioningAction.kind == "resume"))


def test_resume_is_scoped_and_repeat_stop_resume_uses_original_identity(alice, bob, gateway):
    parent = admit(alice, body()).json()
    assert action(alice, parent, "resume", "resume-before-stop-01").status_code == 409
    for n in range(2):
        assert action(alice, parent, "stop", f"stop-cycle-{n:04d}-key").status_code == 202
        assert action(bob, parent, "resume", f"foreign-cycle-{n:04d}").status_code == 404
        assert action(alice, parent, "resume", f"resume-cycle-{n:04d}-key").status_code == 202
    final = drive(parent, alice)
    assert final["state"] == "completed"
    assert [e for e in gateway.events if e[0] == "sso"] == [("sso", 1, "a-01-01")]


def test_stopped_after_opening_can_resume_only_unsubmitted_json(alice, gateway):
    request = body()
    request["accounts"][0]["exports"]["json"] = True
    parent = admit(alice, request).json()
    coordinator_to_child(parent, "sso")
    assert worker.run_one(Gateway, account_id=1)
    stopped = action(alice, parent, "stop", "stop-before-json-0001")
    assert stopped.status_code == 202, stopped.text
    row = stopped.json()["accounts"][0]
    assert row["items"][0]["state"] == "completed" and row["allowed_actions"] == ["resume"]
    before = list(gateway.events)
    assert action(alice, parent, "resume", "resume-json-only-0001").status_code == 202
    final = drive(parent, alice)
    assert final["state"] == "completed" and gateway.events == before
    assert final["accounts"][0]["items"][0]["auth_batch_id"]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(models.AuthBatch)) == 1
        assert db.get(models.PlanCounter, 1).used_count == 1
