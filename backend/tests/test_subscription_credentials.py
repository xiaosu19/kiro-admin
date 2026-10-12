"""Subscription-only work must never replace an existing SSO's credentials."""

import uuid
from datetime import timedelta

import pytest

from app.database import SessionLocal
from app.identity_login import AuthError
from app.models import Batch, ManagedGroup, Subscription, now
from app.security import decrypt
from app.worker import run_one
from test_auth_batches import PasswordAuth, admission, drain, record
from test_batches import create_batch, subscribe
from test_workflows import Gateway, count, create


def credential_snapshot(rid):
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        return {
            field: getattr(r, field)
            for field in (
                "credential_state",
                "credential_revision",
                "credential_recovery_encrypted",
                "password_encrypted",
                "password_generated_at",
            )
        }


def expire_lease(rid):
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        r.state, r.lease_token = "running", "previous-worker"
        r.lease_until = now() - timedelta(seconds=1)
        db.commit()


@pytest.mark.parametrize("phase", ["queued", "expired_lease", "membership_restart"])
def test_subscribe_after_lost_password_response_preserves_recovery(
    alice, monkeypatch, phase
):
    def lost(state):
        raise AuthError("transport_failed", uncertain=True)

    monkeypatch.setattr(PasswordAuth, "after_pending", staticmethod(lost))
    r = record(subscription_status="not_subscribed")
    response = admission(
        alice, [r], "custom_password", password="PossiblyAccepted9!"
    )
    assert response.status_code == 202, response.text
    auth_id = response.json()["id"]
    drain(PasswordAuth)
    assert (
        alice.get(f"/api/auth-batches/{auth_id}").json()["states"]["needs_review"]
        == 1
    )
    before = credential_snapshot(r.id)
    assert before["credential_state"] == "unknown"
    assert before["password_encrypted"] is None
    assert (
        decrypt(before["credential_recovery_encrypted"])["candidate"]
        == "PossiblyAccepted9!"
    )
    assert alice.post(f"/api/auth-batches/{auth_id}/cancel").status_code == 200
    assert credential_snapshot(r.id) == before

    class Existing(Gateway):
        mode = "ok"
        calls = user_writes = password_writes = member_writes = 0
        membership_id = None

        def create_user(self, record):
            type(self).user_writes += 1
            return super().create_user(record)

        def password(self, record):
            type(self).password_writes += 1
            return super().password(record)

        def get_group_membership(self, gid, uid):
            return self.membership_id

        def create_group_membership(self, gid, uid):
            type(self).member_writes += 1
            type(self).membership_id = "confirmed-membership"
            raise SystemExit("worker stopped after the remote membership write")

    if phase == "membership_restart":
        with SessionLocal() as db:
            gid = str(uuid.uuid4())
            db.add(
                ManagedGroup(
                    id=gid,
                    owner_id=2,
                    aws_account_id=1,
                    aws_scope="test-scope",
                    request_key=gid,
                    payload_hash="test-hash",
                    name="Existing SSO group",
                    marker="test-marker",
                    state="ready",
                    remote_id="remote-group",
                )
            )
            db.flush()
            saved = db.get(Subscription, r.id)
            saved.group_id, saved.group_membership_id = gid, "previous-membership"
            db.commit()
    response = subscribe(alice, [r.id])
    assert response.status_code == 202, response.text
    batch_id = response.json()["id"]
    assert credential_snapshot(r.id) == before
    with SessionLocal() as db:
        assert db.get(Batch, batch_id).kind == "subscribe_existing"

    if phase == "membership_restart":
        with pytest.raises(SystemExit):
            run_one(Existing)
        with SessionLocal() as db:
            saved = db.get(Subscription, r.id)
            assert saved.step == "group_membership_pending"
        assert credential_snapshot(r.id) == before
    if phase != "queued":
        expire_lease(r.id)

    assert run_one(Existing)
    assert (Existing.user_writes, Existing.password_writes, Existing.calls) == (0, 0, 1)
    assert credential_snapshot(r.id) == before
    completed = alice.get(f"/api/subscriptions/{r.id}").json()
    assert completed["state"] == "completed" and completed["counted"]
    assert completed["subscription_status"] == "active"
    assert completed["sso_user_id"] == r.sso_user_id
    assert not completed["has_password"]
    assert alice.post(f"/api/subscriptions/{r.id}/credentials").status_code == 409
    assert alice.get(f"/api/batches/{batch_id}").json()["states"]["completed"] == 1
    assert count() == (1, 0, 1, 1)
    if phase == "membership_restart":
        assert Existing.member_writes == 1
        assert completed["group_membership_id"] == "confirmed-membership"


@pytest.mark.parametrize("entrypoint", ["single", "sso", "subscribed"])
def test_creation_still_generates_initial_otp_and_retries_reuse_it(alice, entrypoint):
    class NewSso(Gateway):
        mode = "reject"
        calls = user_writes = password_writes = 0

        def create_user(self, record):
            type(self).user_writes += 1
            return super().create_user(record)

        def password(self, record):
            type(self).password_writes += 1
            return super().password(record)

    response = (
        create(alice)
        if entrypoint == "single"
        else create_batch(alice, 1, kind=entrypoint)
    )
    assert response.status_code == 202, response.text
    rid = (
        response.json()["id"]
        if entrypoint == "single"
        else response.json()["items"][0]["id"]
    )
    assert run_one(NewSso)
    initial = credential_snapshot(rid)
    assert decrypt(initial["password_encrypted"]) == "AWS-once-password-test"
    assert initial["credential_state"] == "one_time"
    if entrypoint != "sso":
        assert alice.get(f"/api/subscriptions/{rid}").json()["state"] == "failed"
        assert alice.post(f"/api/subscriptions/{rid}/retry").status_code == 202
        NewSso.mode = "ok"
        assert run_one(NewSso)
        assert credential_snapshot(rid) == initial
    assert (NewSso.user_writes, NewSso.password_writes) == (1, 1)
    assert alice.get(f"/api/subscriptions/{rid}").json()["state"] == "completed"


@pytest.mark.parametrize("entrypoint", ["single", "subscribed"])
def test_creation_retry_after_auth_change_preserves_unknown_credential(
    alice, monkeypatch, entrypoint
):
    class Retried(Gateway):
        mode = "reject"
        calls = password_writes = 0

        def password(self, record):
            type(self).password_writes += 1
            return super().password(record)

    response = (
        create(alice)
        if entrypoint == "single"
        else create_batch(alice, 1, kind="subscribed")
    )
    assert response.status_code == 202, response.text
    rid = (
        response.json()["id"]
        if entrypoint == "single"
        else response.json()["items"][0]["id"]
    )
    assert run_one(Retried)
    assert Retried.password_writes == 1
    assert alice.get(f"/api/subscriptions/{rid}").json()["state"] == "failed"

    def lost(state):
        raise AuthError("transport_failed", uncertain=True)

    monkeypatch.setattr(PasswordAuth, "after_pending", staticmethod(lost))
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        auth = admission(alice, [r], "custom_password", password="MaybeAccepted9!")
    assert auth.status_code == 202, auth.text
    drain(PasswordAuth)
    auth_id = auth.json()["id"]
    before = credential_snapshot(rid)
    assert before["credential_state"] == "unknown"
    assert before["password_encrypted"] is None
    assert alice.post(f"/api/auth-batches/{auth_id}/cancel").status_code == 200
    assert alice.post(f"/api/subscriptions/{rid}/retry").status_code == 202
    Retried.mode = "ok"
    assert run_one(Retried)
    assert Retried.password_writes == 1
    assert credential_snapshot(rid) == before
    assert alice.get(f"/api/subscriptions/{rid}").json()["state"] == "completed"
    assert count() == (1, 0, 1, 1)


@pytest.mark.parametrize("invalid_field", ["sso_user_id", "sso_deleted_at"])
def test_subscription_only_cannot_recreate_missing_or_deleted_sso(alice, invalid_field):
    r = record(subscription_status="not_subscribed")
    assert subscribe(alice, [r.id]).status_code == 202
    before = credential_snapshot(r.id)
    with SessionLocal() as db:
        saved = db.get(Subscription, r.id)
        setattr(saved, invalid_field, None if invalid_field == "sso_user_id" else now())
        db.commit()

    class InvalidSso(Gateway):
        mode = "ok"
        calls = user_writes = password_writes = 0

        def create_user(self, record):
            type(self).user_writes += 1
            return super().create_user(record)

        def password(self, record):
            type(self).password_writes += 1
            return super().password(record)

    assert run_one(InvalidSso)
    assert (InvalidSso.user_writes, InvalidSso.password_writes, InvalidSso.calls) == (
        0,
        0,
        0,
    )
    assert credential_snapshot(r.id) == before
    result = alice.get(f"/api/subscriptions/{r.id}").json()
    assert result["state"] == "failed" and not result["counted"]
    assert count() == (0, 0, 0, 1)
