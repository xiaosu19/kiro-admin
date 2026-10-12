"""Quality review regressions for native detach intent and failed provisioning."""

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.group_jobs import run_group_job
from app.lifecycle import run_operation
from app.models import (
    AwsAccount,
    GroupJob,
    ManagedGroup,
    NativeGroupGrant,
    RecordOperation,
    Subscription,
    now,
)
from test_native_group_review import bulk_cancel
from test_native_groups import PRO, activate, cancel_group, counter, run_native
from test_native_groups import native as native
from test_proxies import create_proxy


def detach_job(client):
    result = client.post("/api/groups/group-1/jobs", json={
        "kind": "detach", "record_id": "group-1-record-0", "expected_revision": 1,
        "request_key": str(uuid.uuid4()),
    })
    assert result.status_code == 202, result.text
    return result.json()["id"]


@pytest.mark.parametrize("route", ["individual", "bulk", "group"])
@pytest.mark.parametrize("drift", ["binding", "config"])
def test_native_detach_rechecks_authority_and_config_at_intent(
    alice, admin, native, monkeypatch, route, drift
):
    activate(alice)
    rid = "group-1-record-0"
    if route == "bulk":
        operation_id = bulk_cancel(alice, [rid])["items"][0]["operation_id"]
    elif route == "group":
        operation_id = detach_job(alice)
    else:
        result = alice.post(f"/api/subscriptions/{rid}/operations", json={
            "kind": "cancel_subscription", "confirm_username": rid,
            "cancellation_mode": "IMMEDIATE", "request_key": str(uuid.uuid4()),
        })
        assert result.status_code == 202, result.text
        operation_id = result.json()["id"]
    original = native.user_subscription_sources
    changed = []

    def sources(self, record):
        result = original(self, record)
        if not changed:
            if drift == "binding":
                response = admin.put("/api/admin/users/2/bindings", json={"account_ids": []})
                assert response.status_code == 200, response.text
            else:
                with SessionLocal() as db:
                    db.get(AwsAccount, 1).profile_arn += "-changed"
                    db.commit()
            changed.append(True)
        return result

    monkeypatch.setattr(native, "user_subscription_sources", sources)
    run = run_group_job if route == "group" else run_operation
    assert run(native)
    assert not any(w[0] == "detach" for w in native.writes)
    with SessionLocal() as db:
        model = GroupJob if route == "group" else RecordOperation
        assert db.get(model, operation_id).state == "failed"
        assert db.get(model, operation_id).phase == "ready"
        if route != "group":
            assert db.get(Subscription, rid).active_operation_id is None
            assert db.get(ManagedGroup, "group-1").active_job_id is None
    assert counter() == (1, 0, 1)


@pytest.mark.parametrize("route", ["bulk", "group"])
def test_accepted_detach_retains_intent_locks_and_reconciles_without_another_write(
    alice, admin, native, monkeypatch, route
):
    activate(alice)
    rid = "group-1-record-0"
    operation_id = (
        detach_job(alice) if route == "group"
        else bulk_cancel(alice, [rid])["items"][0]["operation_id"]
    )
    model = GroupJob if route == "group" else RecordOperation
    run = run_group_job if route == "group" else run_operation
    original = native.delete_group_membership

    def remove(self, membership_id):
        original(self, membership_id)
        native.user_claims["sso-" + rid] = [{
            "source": "GROUP", "group_id": "external", "status": "pending",
            "subscription_type": PRO, "expires_at": None,
        }]

    monkeypatch.setattr(native, "delete_group_membership", remove)
    assert run(native)
    with SessionLocal() as db:
        op = db.get(model, operation_id)
        assert (op.state, op.phase) == ("needs_review", "pending")
        assert db.get(Subscription, rid).active_operation_id == operation_id
        assert db.get(ManagedGroup, "group-1").active_job_id == operation_id
    native.user_claims.clear()
    assert admin.put("/api/admin/users/2/bindings", json={"account_ids": []}).status_code == 200
    result = (
        admin.post("/api/groups/group-1/retry") if route == "group"
        else admin.post(f"/api/subscriptions/{rid}/operations/{operation_id}/retry", json={"confirm_username": rid})
    )
    assert result.status_code == 202, result.text
    assert run(native)
    assert [w[0] for w in native.writes].count("detach") == 1
    with SessionLocal() as db:
        assert db.get(model, operation_id).state == "completed"
        assert db.get(Subscription, rid).group_id is None
        assert db.get(ManagedGroup, "group-1").active_job_id is None
    assert counter() == (1, 0, 1)


def test_group_detach_preserves_overlapping_user_source(alice, native):
    activate(alice)
    rid = "group-1-record-0"
    native.user_claims["sso-" + rid] = [{
        "source": "USER", "group_id": None, "status": "active",
        "subscription_type": PRO, "expires_at": None,
    }]
    operation_id = detach_job(alice)
    assert run_group_job(native)
    assert any(w[0] == "detach" for w in native.writes)
    assert not any(w[0] == "USER_cancel" for w in native.writes)
    with SessionLocal() as db:
        assert db.get(GroupJob, operation_id).state == "completed"
        record = db.get(Subscription, rid)
        assert record.subscription_status == "active" and record.group_id is None
        assert record.active_operation_id is None
    assert counter() == (1, 0, 1)


@pytest.mark.parametrize("automatic", [False, True])
def test_failed_unjoined_provision_does_not_block_existing_group_cancellation(
    alice, native, automatic
):
    from app.group_subscription_worker import enqueue_due
    from app.worker import run_one

    activate(alice)
    result = alice.post("/api/batches/create", json={
        "kind": "sso", "aws_account_id": 1, "group_id": "group-1",
        "items": [{"username": "late"}], "request_key": str(uuid.uuid4()),
    })
    assert result.status_code == 202, result.text
    rid = result.json()["items"][0]["id"]
    with SessionLocal() as db:
        db.scalar(select(NativeGroupGrant)).stop_at = now() - timedelta(seconds=1)
        db.commit()
    assert run_one(native)
    view = alice.get(f"/api/subscriptions/{rid}").json()
    assert view["state"] == "failed" and view["sso_user_id"] is None
    assert counter() == (1, 0, 1)
    if automatic:
        assert enqueue_due() == 1
    else:
        result = cancel_group(alice)
        assert result.status_code == 202, result.text
    assert run_native()
    assert alice.get("/api/groups/group-1").json()["native_subscription"]["state"] == "cancelled"
    assert [w[0] for w in native.writes].count("cancel") == 1
    assert counter() == (1, 0, 1)


def test_failed_nonmember_is_excluded_but_unexpected_remote_members_still_block(alice, native):
    from app.worker import run_one

    activate(alice)
    result = alice.post("/api/batches/create", json={
        "kind": "sso", "aws_account_id": 1, "group_id": "group-1",
        "items": [{"username": "late"}], "request_key": str(uuid.uuid4()),
    })
    assert result.status_code == 202, result.text
    with SessionLocal() as db:
        db.scalar(select(NativeGroupGrant)).stop_at = now() - timedelta(seconds=1)
        db.commit()
    assert run_one(native)
    native.members[("remote-group-1", "unexpected")] = "unknown-membership"
    result = cancel_group(alice)
    assert result.status_code == 409
    assert "AWS 分组成员" in result.json()["detail"]
    assert not any(w[0] == "cancel" for w in native.writes)


def configured_proxy(admin):
    response = create_proxy(admin)
    assert response.status_code == 201, response.text
    pid = response.json()["id"]
    with SessionLocal() as db:
        db.get(AwsAccount, 1).proxy_id = pid
        db.commit()
    return pid


def rename_proxy(admin, pid):
    response = admin.patch(f"/api/admin/proxies/{pid}", json={"name": "renamed-proxy"})
    assert response.status_code == 200, response.text


def test_confirmed_unsent_detach_reauthorizes_current_proxy_on_explicit_retry(alice, admin, native):
    pid = configured_proxy(admin)
    activate(alice)
    operation_id = detach_job(alice)
    rename_proxy(admin, pid)
    assert run_group_job(native)
    with SessionLocal() as db:
        job = db.get(GroupJob, operation_id)
        assert (job.state, job.phase) == ("failed", "ready")
        original_payload = job.payload
    assert not any(w[0] == "detach" for w in native.writes)
    response = alice.post("/api/groups/group-1/retry")
    assert response.status_code == 202, response.text
    assert run_group_job(native)
    with SessionLocal() as db:
        job = db.get(GroupJob, operation_id)
        assert (job.state, job.phase) == ("completed", "done")
        assert job.payload != original_payload
        assert db.get(ManagedGroup, "group-1").active_job_id is None
    assert [w[0] for w in native.writes].count("detach") == 1
    assert cancel_group(alice).status_code == 202
    assert run_native()
    assert counter() == (1, 0, 1)


@pytest.mark.parametrize("drift", ["owner", "group", "lock"])
def test_unsent_detach_retry_revalidates_current_scope_before_refresh(
    alice, admin, native, drift
):
    pid = configured_proxy(admin)
    activate(alice)
    operation_id = detach_job(alice)
    rename_proxy(admin, pid)
    assert run_group_job(native)
    with SessionLocal() as db:
        record = db.get(Subscription, "group-1-record-0")
        if drift == "owner":
            record.owner_id = 3
        elif drift == "group":
            record.group_id = None
        else:
            record.active_operation_id = None
        original_payload = db.get(GroupJob, operation_id).payload
        db.commit()
    response = admin.post("/api/groups/group-1/retry")
    assert response.status_code == 409, response.text
    with SessionLocal() as db:
        job = db.get(GroupJob, operation_id)
        assert (job.state, job.phase, job.payload) == ("failed", "ready", original_payload)
    assert not any(w[0] == "detach" for w in native.writes)


def test_pending_detach_retry_keeps_original_intent_after_proxy_change(alice, admin, native):
    pid = configured_proxy(admin)
    activate(alice)
    operation_id = detach_job(alice)
    native.uncertain = True
    assert run_group_job(native)
    with SessionLocal() as db:
        job = db.get(GroupJob, operation_id)
        assert (job.state, job.phase) == ("needs_review", "pending")
        original_payload = job.payload
    rename_proxy(admin, pid)
    response = alice.post("/api/groups/group-1/retry")
    assert response.status_code == 202, response.text
    native.uncertain = False
    assert run_group_job(native)
    with SessionLocal() as db:
        job = db.get(GroupJob, operation_id)
        assert (job.state, job.phase, job.payload) == ("needs_review", "pending", original_payload)
        assert db.get(ManagedGroup, "group-1").active_job_id == operation_id
    assert [w[0] for w in native.writes].count("detach") == 1


def test_confirmed_unsent_attach_retries_with_fresh_reservation_and_config(alice, admin, native):
    from test_native_group_review import attach, standalone

    pid = configured_proxy(admin)
    activate(alice)
    standalone("late")
    operation_id = attach(alice)["id"]
    rename_proxy(admin, pid)
    assert run_group_job(native)
    with SessionLocal() as db:
        job = db.get(GroupJob, operation_id)
        assert (job.state, job.phase) == ("failed", "ready")
    assert counter() == (1, 0, 1)
    response = alice.post("/api/groups/group-1/retry")
    assert response.status_code == 202, response.text
    assert counter() == (1, 1, 1)
    assert run_group_job(native)
    with SessionLocal() as db:
        assert db.get(GroupJob, operation_id).state == "completed"
    assert [w[0] for w in native.writes].count("attach") == 1
    assert counter() == (2, 0, 2)
