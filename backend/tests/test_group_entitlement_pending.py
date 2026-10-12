"""Confirmed member writes do not hold the group while AWS access propagates."""

import uuid
from datetime import timedelta

import pytest
import requests
from botocore.exceptions import ClientError
from sqlalchemy import select

from app import worker
from app.aws import AwsFailure
from app.database import SessionLocal
from app.models import (
    AwsAccount, GroupMemberActivation, ManagedGroup, NativeGroupGrant, PlanCounter,
    Subscription, now,
)
from app.retry_models import AutomaticRetry
from app.subscription_eligibility import has_confirmed_subscription_access
from test_automatic_retries import due
from test_native_groups import activate, cancel_group, counter
from test_native_groups import native as native
from test_provisioning_admission import ready, remote  # noqa: F401
from test_provisioning_coordinator import gateway as gateway


ENTITLEMENT_PENDING = "group_entitlement_pending"


def admit_members(client, native, monkeypatch, quantity=1):
    with SessionLocal() as db:
        db.get(PlanCounter, 1).limit_count = 100
        db.commit()
    activate(client, 0)

    def create(self, record):
        self.writes.append(("SSO", record.id))
        return "sso-" + record.id

    def password(self, record):
        self.writes.append(("OTP", record.id))
        return "SyntheticPassword123!"

    monkeypatch.setattr(native, "verify_identity", lambda self: self.account.aws_account_id, raising=False)
    monkeypatch.setattr(native, "create_user", create, raising=False)
    monkeypatch.setattr(native, "password", password, raising=False)
    native.effective_rows = []
    response = client.post("/api/batches/create", json={
        "kind": "sso", "aws_account_id": 1, "group_id": "group-1",
        "items": [{"username": f"propagating-{i}"} for i in range(quantity)],
        "request_key": str(uuid.uuid4()),
    })
    assert response.status_code == 202, response.text
    return [item["id"] for item in response.json()["items"]]


def stable_snapshot(db, record_id):
    record = db.get(Subscription, record_id)
    activation = db.scalar(select(GroupMemberActivation).where(GroupMemberActivation.record_id == record_id))
    return (
        record.sso_user_id, record.password_encrypted, record.credential_revision,
        record.credential_state, record.group_id, record.group_membership_id,
        record.worker_config_hash, activation.id, activation.operation_id,
        activation.request_key, activation.config_hash, activation.write_requested_at,
        activation.reserved, activation.counted,
    )


def assert_awaiting(db, record_id):
    record = db.get(Subscription, record_id)
    activation = db.scalar(select(GroupMemberActivation).where(GroupMemberActivation.record_id == record_id))
    assert record.step == ENTITLEMENT_PENDING
    assert record.group_membership_id
    assert record.worker_config_hash
    assert record.subscription_status == "not_subscribed"
    assert not has_confirmed_subscription_access(record, now())
    assert activation.reserved and not activation.counted
    return record, activation


def forbid_writes(native, monkeypatch):
    def rejected(*args, **kwargs):
        pytest.fail("An entitlement reconciliation must only read AWS")

    for name in ("create_user", "password", "create_group_membership", "delete_group_membership",
                 "subscribe", "subscribe_group", "cancel_subscription", "cancel_group_subscription"):
        monkeypatch.setattr(native, name, rejected, raising=False)


def read_failure(kind, operation):
    if kind == "connect_timeout":
        return requests.ConnectTimeout("Synthetic connection timeout")
    code, status = (("ThrottlingException", 429) if kind == "throttled"
                    else ("AccessDeniedException", 400))
    return ClientError({"Error": {"Code": code}, "ResponseMetadata": {
        "HTTPStatusCode": status, "RetryAttempts": 0,
    }}, operation)


@pytest.mark.parametrize("kind", ["throttled", "access_denied", "connect_timeout"])
@pytest.mark.parametrize("read", ["membership", "aggregate"])
def test_first_join_read_failure_preserves_readonly_checkpoint(alice, native, monkeypatch, kind, read):
    record_id = admit_members(alice, native, monkeypatch)[0]
    name = "get_group_membership" if read == "membership" else "report_subscriptions"
    operation = "GetGroupMembershipId" if read == "membership" else "ListUserSubscriptions"
    original = getattr(native, name)

    def unavailable(self, *args):
        with SessionLocal() as db:
            checkpointed = db.get(Subscription, record_id).step == ENTITLEMENT_PENDING
        if checkpointed:
            raise read_failure(kind, operation)
        return original(self, *args)

    monkeypatch.setattr(native, name, unavailable)
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record, _ = assert_awaiting(db, record_id)
        assert record.state == ("needs_review" if kind == "access_denied" else "queued")
        assert db.get(ManagedGroup, "group-1").active_job_id is None
        retry = db.get(AutomaticRetry, ("sso", record_id))
        if kind == "access_denied":
            assert retry is None or retry.next_retry_at is None
        else:
            assert retry.mode == "reconcile" and retry.retry_count == 1
        before = stable_snapshot(db, record_id)
    assert counter() == (0, 1, 0)
    membership = native.members.pop(("remote-group-1", "sso-" + record_id))
    writes = list(native.writes)
    monkeypatch.setattr(native, name, original)
    forbid_writes(native, monkeypatch)
    # A remote deletion after the failed read must stop reconciliation, never
    # send the already-accepted membership write again.
    if kind == "access_denied":
        assert alice.post(f"/api/subscriptions/{record_id}/retry").status_code == 202
    else:
        due("sso", record_id)
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record, _ = assert_awaiting(db, record_id)
        assert record.state == "needs_review"
        assert stable_snapshot(db, record_id) == before
    native.members[("remote-group-1", "sso-" + record_id)] = membership
    native.effective_rows = None
    assert alice.post(f"/api/subscriptions/{record_id}/retry").status_code == 202
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record = db.get(Subscription, record_id)
        assert record.state == "completed" and record.step == "sso_ready"
        assert has_confirmed_subscription_access(record, now())
        assert stable_snapshot(db, record_id)[:-2] == before[:-2]
    assert counter() == (1, 0, 1) and native.writes == writes


@pytest.mark.parametrize("kind", ["throttled", "access_denied", "connect_timeout"])
def test_accepted_join_read_failure_before_checkpoint_keeps_original_intent(alice, native, monkeypatch, kind):
    record_id = admit_members(alice, native, monkeypatch)[0]
    original = native.get_group_membership

    def unavailable(self, gid, uid):
        if (gid, uid) in self.members:
            raise read_failure(kind, "GetGroupMembershipId")
        return original(self, gid, uid)

    monkeypatch.setattr(native, "get_group_membership", unavailable)
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record = db.get(Subscription, record_id)
        activation = db.scalar(select(GroupMemberActivation).where(GroupMemberActivation.record_id == record_id))
        assert record.step == "group_membership_pending"
        assert record.state == ("needs_review" if kind == "access_denied" else "queued")
        assert record.worker_config_hash and activation.reserved and not activation.counted
        assert db.get(ManagedGroup, "group-1").active_job_id == record_id
        retry = db.get(AutomaticRetry, ("sso", record_id))
        if kind == "access_denied":
            assert retry is None or retry.next_retry_at is None
        else:
            assert retry.mode == "reconcile"
    assert ("remote-group-1", "sso-" + record_id) in native.members
    assert counter() == (0, 1, 0)
    writes = list(native.writes)
    monkeypatch.setattr(native, "get_group_membership", original)
    forbid_writes(native, monkeypatch)
    native.effective_rows = None
    if kind == "access_denied":
        assert alice.post(f"/api/subscriptions/{record_id}/retry").status_code == 202
    else:
        due("sso", record_id)
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record = db.get(Subscription, record_id)
        assert record.state == "completed" and has_confirmed_subscription_access(record, now())
    assert counter() == (1, 0, 1) and native.writes == writes


@pytest.mark.parametrize("kind", ["throttled", "access_denied"])
def test_failure_handler_cannot_downgrade_a_durable_entitlement_checkpoint(alice, native, monkeypatch, kind):
    record_id = admit_members(alice, native, monkeypatch)[0]
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        assert_awaiting(db, record_id)
        before = stable_snapshot(db, record_id)
    due("sso", record_id)
    _, token = worker.claim(record_id=record_id)
    worker.fail(record_id, token, "Synthetic read failure", uncertain=False,
                error=read_failure(kind, "ListUserSubscriptions"), frozen_config=before[6])
    with SessionLocal() as db:
        record, _ = assert_awaiting(db, record_id)
        assert record.state == ("needs_review" if kind == "access_denied" else "queued")
        assert stable_snapshot(db, record_id) == before
        assert db.get(ManagedGroup, "group-1").active_job_id is None
        retry = db.get(AutomaticRetry, ("sso", record_id))
        if kind == "access_denied":
            assert retry.next_retry_at is None
        else:
            assert retry.mode == "reconcile"
    assert counter() == (0, 1, 0)


def test_confirmed_join_releases_only_the_group_write_lock(alice, native, monkeypatch):
    record_id = admit_members(alice, native, monkeypatch)[0]
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record, _ = assert_awaiting(db, record_id)
        assert record.state == "queued"
        assert db.get(ManagedGroup, "group-1").active_job_id is None
        retry = db.get(AutomaticRetry, ("sso", record_id))
        assert retry.mode == "reconcile" and retry.retry_count == 1
        assert retry.error_code == "subscription_observation_propagating"
    assert counter() == (0, 1, 0)
    response = alice.post("/api/auth-batches", json={
        "kind": "json_export", "record_ids": [record_id], "request_key": str(uuid.uuid4()),
    })
    assert response.status_code == 409


def test_all_fifty_nine_siblings_join_before_the_first_aggregate_appears(alice, native, monkeypatch):
    record_ids = admit_members(alice, native, monkeypatch, quantity=60)
    for record_id in record_ids:
        assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        for record_id in record_ids:
            assert_awaiting(db, record_id)
        assert db.get(ManagedGroup, "group-1").active_job_id is None
    assert len(native.members) == 60
    assert len([write for write in native.writes if write[0] == "attach"]) == 60
    assert len([write for write in native.writes if write[0] == "create"]) == 1
    assert counter() == (0, 60, 0)


def test_old_uncertain_membership_moves_to_readonly_only_after_actual_confirmation(alice, native, monkeypatch):
    record_id = admit_members(alice, native, monkeypatch)[0]
    native.uncertain = True
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record = db.get(Subscription, record_id)
        assert record.step == "group_membership_pending" and record.state == "needs_review"
        assert db.get(ManagedGroup, "group-1").active_job_id == record_id
        frozen = record.worker_config_hash
    writes = list(native.writes)
    native.uncertain = False
    assert alice.post(f"/api/subscriptions/{record_id}/retry").status_code == 202
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record, _ = assert_awaiting(db, record_id)
        assert record.worker_config_hash == frozen
        assert db.get(ManagedGroup, "group-1").active_job_id is None
    assert native.writes == writes


def test_old_pending_confirmed_membership_id_cannot_be_replaced_during_migration(alice, native, monkeypatch):
    record_id = admit_members(alice, native, monkeypatch)[0]
    native.uncertain = True
    assert worker.run_one(native, record_id=record_id)
    native.uncertain = False
    key = ("remote-group-1", "sso-" + record_id)
    original_membership = native.members[key]
    with SessionLocal() as db:
        record = db.get(Subscription, record_id)
        assert record.step == "group_membership_pending"
        # The old worker could save the confirmed membership ID while keeping
        # the old pending step through aggregate propagation.
        record.group_membership_id = original_membership
        db.commit()
        before = stable_snapshot(db, record_id)
    native.members[key] = "synthetic-replacement-membership"
    writes = list(native.writes)
    forbid_writes(native, monkeypatch)
    assert alice.post(f"/api/subscriptions/{record_id}/retry").status_code == 202
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record = db.get(Subscription, record_id)
        assert record.state == "needs_review" and record.step == "group_membership_pending"
        assert stable_snapshot(db, record_id) == before
        assert db.get(ManagedGroup, "group-1").active_job_id == record_id
        assert not has_confirmed_subscription_access(record, now())
    assert counter() == (0, 1, 0) and native.writes == writes
    # Only the originally saved membership may migrate to the read-only stage.
    native.members[key] = original_membership
    assert alice.post(f"/api/subscriptions/{record_id}/retry").status_code == 202
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record, _ = assert_awaiting(db, record_id)
        assert record.state == "queued" and stable_snapshot(db, record_id) == before
        assert db.get(ManagedGroup, "group-1").active_job_id is None
    native.effective_rows = None
    due("sso", record_id)
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record = db.get(Subscription, record_id)
        assert record.state == "completed" and has_confirmed_subscription_access(record, now())
        assert stable_snapshot(db, record_id)[:-2] == before[:-2]
    assert counter() == (1, 0, 1) and native.writes == writes


@pytest.mark.parametrize("drift", ["membership_missing", "claim_missing", "unmanaged_member"])
def test_uncertain_membership_drift_never_releases_the_group_lock(alice, native, monkeypatch, drift):
    record_id = admit_members(alice, native, monkeypatch)[0]
    native.uncertain = True
    assert worker.run_one(native, record_id=record_id)
    native.uncertain = False
    if drift == "membership_missing":
        native.members.clear()
    elif drift == "claim_missing":
        monkeypatch.setattr(native, "user_subscription_sources", lambda *_: [])
    else:
        native.members[("remote-group-1", "unmanaged")] = "unmanaged-membership"
    writes = list(native.writes)
    assert alice.post(f"/api/subscriptions/{record_id}/retry").status_code == 202
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record = db.get(Subscription, record_id)
        assert record.step == "group_membership_pending" and record.state == "needs_review"
        assert db.get(ManagedGroup, "group-1").active_job_id == record_id
        activation = db.scalar(select(GroupMemberActivation).where(GroupMemberActivation.record_id == record_id))
        assert activation.reserved and not activation.counted
    assert native.writes == writes


def test_entitlement_reconciliation_is_readonly_and_settles_only_after_aggregate(alice, native, monkeypatch):
    record_id = admit_members(alice, native, monkeypatch)[0]
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        assert_awaiting(db, record_id)
        before = stable_snapshot(db, record_id)
    writes = list(native.writes)
    forbid_writes(native, monkeypatch)
    due("sso", record_id)
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        assert_awaiting(db, record_id)
        assert stable_snapshot(db, record_id) == before
    native.effective_rows = None
    due("sso", record_id)
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record = db.get(Subscription, record_id)
        activation = db.scalar(select(GroupMemberActivation).where(GroupMemberActivation.record_id == record_id))
        assert record.state == "completed" and record.step == "sso_ready"
        assert has_confirmed_subscription_access(record, now())
        assert activation.counted and not activation.reserved
        after = stable_snapshot(db, record_id)
        assert after[:-2] == before[:-2]
    assert counter() == (1, 0, 1) and native.writes == writes


@pytest.mark.parametrize("drift", ["membership_missing", "membership_changed", "claim_missing", "config",
                                   "remote_group", "foreign_lock", "group_state", "deleted_group",
                                   "owner", "expired_grant", "cancelled_grant"])
def test_readonly_entitlement_stops_on_scope_or_grant_drift(alice, native, monkeypatch, drift):
    record_id = admit_members(alice, native, monkeypatch)[0]
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record, activation = assert_awaiting(db, record_id)
        before = stable_snapshot(db, record_id)
        group, grant = db.get(ManagedGroup, record.group_id), db.get(NativeGroupGrant, activation.grant_id)
        if drift == "config":
            db.get(AwsAccount, 1).instance_arn += "-changed"
        elif drift == "remote_group":
            group.remote_id = "foreign-remote-group"
        elif drift == "foreign_lock":
            group.active_job_id = "foreign-operation"
        elif drift == "group_state":
            group.state = "updating"
        elif drift == "deleted_group":
            group.deleted_at, group.state = now(), "deleted"
        elif drift == "owner":
            group.owner_id = 3
        elif drift == "expired_grant":
            grant.stop_at = now() - timedelta(seconds=1)
        elif drift == "cancelled_grant":
            grant.state = "cancelled"
        db.commit()
    if drift == "membership_missing":
        native.members.clear()
    elif drift == "membership_changed":
        native.members[("remote-group-1", "sso-" + record_id)] = "replacement-membership"
    elif drift == "claim_missing":
        monkeypatch.setattr(native, "user_subscription_sources", lambda *_: [])
    native.effective_rows = None
    writes = list(native.writes)
    forbid_writes(native, monkeypatch)
    due("sso", record_id)
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record, _ = assert_awaiting(db, record_id)
        assert record.state == "needs_review"
        assert stable_snapshot(db, record_id) == before
        retry = db.get(AutomaticRetry, ("sso", record_id))
        assert retry.next_retry_at is None
        assert db.get(ManagedGroup, "group-1").active_job_id == (
            "foreign-operation" if drift == "foreign_lock" else None)
    assert native.writes == writes and counter() == (0, 1, 0)


def test_new_step_does_not_erase_a_sibling_write_lock_or_misread_its_inflight_member(alice, native, monkeypatch):
    first, second = admit_members(alice, native, monkeypatch, quantity=2)
    assert worker.run_one(native, record_id=first)
    # The second member has durable intent and a real AWS membership whose ID is
    # not saved yet. A first member's aggregate read must not mutate that lock.
    native.uncertain = True
    assert worker.run_one(native, record_id=second)
    native.uncertain = False
    writes = list(native.writes)
    forbid_writes(native, monkeypatch)
    native.effective_rows = None
    due("sso", first)
    assert worker.run_one(native, record_id=first)
    with SessionLocal() as db:
        assert db.get(Subscription, first).state == "completed"
        assert db.get(Subscription, second).step == "group_membership_pending"
        assert db.get(ManagedGroup, "group-1").active_job_id == second
    assert native.writes == writes and counter() == (1, 1, 1)


def test_lost_record_lease_never_releases_the_group_write_lock(alice, native, monkeypatch):
    record_id = admit_members(alice, native, monkeypatch)[0]
    original = native.user_subscription_sources

    def sources(self, record):
        result = original(self, record)
        if ("remote-group-1", record.sso_user_id) in self.members:
            with SessionLocal() as db:
                db.get(Subscription, record_id).lease_token = "replacement-lease"
                db.commit()
        return result

    monkeypatch.setattr(native, "user_subscription_sources", sources)
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        record = db.get(Subscription, record_id)
        assert record.step == "group_membership_pending"
        assert record.lease_token == "replacement-lease"
        assert db.get(ManagedGroup, "group-1").active_job_id == record_id
        activation = db.scalar(select(GroupMemberActivation).where(GroupMemberActivation.record_id == record_id))
        assert activation.reserved and not activation.counted


def test_unsettled_entitlement_still_blocks_group_mutations_and_deletion(alice, native, monkeypatch):
    record_id = admit_members(alice, native, monkeypatch)[0]
    assert worker.run_one(native, record_id=record_id)
    with SessionLocal() as db:
        assert_awaiting(db, record_id)
        assert db.get(ManagedGroup, "group-1").active_job_id is None
    writes = list(native.writes)
    assert cancel_group(alice).status_code == 409
    for kind in ("rename", "delete"):
        body = {"kind": kind, "expected_revision": 1, "request_key": str(uuid.uuid4())}
        if kind == "rename":
            body["name"] = "changed-group"
        assert alice.post("/api/groups/group-1/jobs", json=body).status_code == 409
    assert native.writes == writes


def test_numbered_stop_keeps_entitlement_intent_until_readonly_settlement_then_resumes_unsent(alice, gateway):
    from app import models
    from app.provisioning_coordinator import run_one as coordinate
    from test_provisioning_coordinator import Gateway, admit, body, coordinator_to_child, drive, fetch
    from test_provisioning_resume import action

    parent = admit(alice, body(quantity=2)).json()
    coordinator_to_child(parent, "sso")
    first, second = [item["record_id"] for item in parent["accounts"][0]["items"]]

    class DelayedAggregate(Gateway):
        visible = False

        def report_subscriptions(self):
            rows = super().report_subscriptions()
            return rows if self.visible else [r for r in rows if r["principal"]["user"] != "sso-" + first]

    assert worker.run_one(DelayedAggregate, record_id=first)
    with SessionLocal() as db:
        record, activation = assert_awaiting(db, first)
        group_id, grant_id = record.group_id, activation.grant_id
        before = stable_snapshot(db, first)
    assert action(alice, parent, "stop", "stop-entitlement-00001").status_code == 202
    assert action(alice, parent, "resume", "resume-entitlement-0001").status_code == 409
    due("sso", first)
    assert worker.run_one(DelayedAggregate, record_id=first)
    with SessionLocal() as db:
        record, _ = assert_awaiting(db, first)
        assert record.state == "needs_review" and stable_snapshot(db, first) == before
        assert db.get(AutomaticRetry, ("sso", first)).next_retry_at is None
        assert db.get(ManagedGroup, group_id).active_job_id is None
    before_events = list(gateway.events)
    DelayedAggregate.visible = True
    assert coordinate(account_id=1)
    response = action(alice, parent, "recheck", "recheck-entitlement-0001")
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        assert_awaiting(db, first)
        assert stable_snapshot(db, first) == before
    assert worker.run_one(DelayedAggregate, record_id=first)
    assert coordinate(account_id=1)
    assert fetch(alice, parent)["state"] == "stopped"
    assert gateway.events == before_events
    with SessionLocal() as db:
        assert db.get(Subscription, second).state == "failed"
        assert db.get(models.ProvisioningItem, second).state == "stopped"
        assert db.get(NativeGroupGrant, grant_id).state == "active"
    response = action(alice, parent, "resume", "resume-unsent-entitlement-01")
    assert response.status_code == 202, response.text
    assert drive(parent, alice)["state"] == "completed"
    assert len([event for event in gateway.events if event[0] == "GROUP"]) == 1
    assert len([event for event in gateway.events if event[0] == "sso"]) == 2
    assert len([event for event in gateway.events if event[0] == "join"]) == 2
    assert counter() == (2, 0, 2)
