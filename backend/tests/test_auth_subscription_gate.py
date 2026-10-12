"""JSON admission must not take the lock required to activate a subscription."""
import json
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.models import AuthBatch, AuthJob, AuthSecret, RecordOperation, Subscription, now
from app.external_auth_models import ExternalExportBatch, ExternalExportItem
from app.security import decrypt, encrypt
from test_auth_batches import DoneAuth, Gateway, admission, drain, record
from test_external_auth_batches import admit as external_admit


@pytest.mark.parametrize("status", ["not_subscribed", "pending", "unknown", "cancelled", "expired"])
@pytest.mark.parametrize("counted", [False, True])
def test_unsubscribed_json_rejected_without_taking_subscription_lock(alice, status, counted):
    r = record(subscription_status=status, counted=counted)
    response = admission(alice, [r])
    assert response.status_code == 409, response.text
    assert "订阅" in response.json()["detail"]
    with SessionLocal() as db:
        assert db.get(Subscription, r.id).active_operation_id is None
        assert not list(db.scalars(select(AuthBatch)))
        assert not list(db.scalars(select(AuthJob)))
        assert not list(db.scalars(select(RecordOperation)))


@pytest.mark.parametrize("status", ["active", "cancel_scheduled"])
def test_confirmed_unexpired_json_admitted_even_without_counted_flag(alice, status):
    r = record(subscription_status=status, access_ends_at=now() + timedelta(days=1), counted=False)
    assert admission(alice, [r]).status_code == 202


@pytest.mark.parametrize("status", ["active", "cancel_scheduled"])
def test_expired_subscription_access_rejected_before_auth_lock(alice, status):
    r = record(subscription_status=status, access_ends_at=now() - timedelta(seconds=1))
    assert admission(alice, [r]).status_code == 409
    with SessionLocal() as db:
        assert db.get(Subscription, r.id).active_operation_id is None


@pytest.mark.parametrize("kind", ["reset_password", "random_password", "custom_password"])
def test_password_maintenance_does_not_require_subscription(alice, kind):
    r = record(subscription_status="not_subscribed")
    extra = {"password": "Maintain8!"} if kind == "custom_password" else {}
    assert admission(alice, [r], kind, **extra).status_code == 202


def test_auth_queue_reports_missing_saved_password_without_claiming_an_otp(alice):
    row = record()
    with SessionLocal() as db:
        db.get(Subscription, row.id).password_encrypted = None
        db.commit()
    assert admission(alice, [row]).status_code == 409
    maintenance = admission(alice, [row], 'reset_password')
    assert maintenance.status_code == 202
    assert maintenance.json()['items'][0]['has_password'] is False


def test_worker_cancels_legacy_unsubscribed_json_before_wire_and_releases_lock(alice):
    r = record(subscription_status="active")
    batch = admission(alice, [r]).json()
    with SessionLocal() as db:
        db.get(Subscription, r.id).subscription_status = "not_subscribed"
        db.commit()

    class Forbidden(Gateway):
        def __init__(self, account):
            pytest.fail("unsubscribed JSON must stop before constructing an AWS gateway")

    drain(DoneAuth, Forbidden)
    with SessionLocal() as db:
        job = db.scalar(select(AuthJob).where(AuthJob.batch_id == batch["id"]))
        assert db.get(RecordOperation, job.id).state == "cancelled"
        assert db.get(Subscription, r.id).active_operation_id is None


def test_result_delivery_rechecks_subscription_access(alice):
    r = record(subscription_status="active")
    batch = admission(alice, [r]).json()
    drain()
    with SessionLocal() as db:
        db.get(Subscription, r.id).subscription_status = "cancelled"
        db.commit()
    response = alice.post(f"/api/auth-batches/{batch['id']}/download")
    assert response.status_code == 409
    assert "private-access-token" not in response.text
    with SessionLocal() as db:
        assert db.get(AuthBatch, batch["id"]).state == "active"
        assert db.scalar(select(AuthSecret)).result_encrypted


@pytest.mark.parametrize('state', ['queued', 'challenge'])
def test_legacy_unsubscribed_batch_cancel_releases_lock_and_keeps_confirmed_password(alice, state):
    r = record(subscription_status='active', credential_state='permanent')
    batch = admission(alice, [r]).json()
    with SessionLocal() as db:
        row = db.get(Subscription, r.id)
        row.subscription_status = 'not_subscribed'
        row.password_encrypted = encrypt('ConfirmedPermanent9!')
        op = db.get(RecordOperation, row.active_operation_id)
        op.state = state
        secret = db.get(AuthSecret, op.id)
        secret.workflow_encrypted = encrypt({'synthetic': 'challenge'})
        db.commit()
    assert alice.post(f"/api/auth-batches/{batch['id']}/cancel").status_code == 200
    with SessionLocal() as db:
        row = db.get(Subscription, r.id)
        assert row.active_operation_id is None
        assert row.credential_state == 'permanent'
        assert decrypt(row.password_encrypted) == 'ConfirmedPermanent9!'
        assert db.scalar(select(RecordOperation)).state == 'cancelled'
        assert db.scalar(select(AuthSecret)).workflow_encrypted is None


@pytest.mark.parametrize("status", ["not_subscribed", "pending", "unknown", "cancelled", "expired"])
def test_pasted_managed_login_cannot_bypass_subscription_gate(alice, status):
    r = record(username="ManagedAlice", subscription_status=status)
    text = json.dumps({"start_url": r.portal_url, "region": "us-east-1",
                       "username": "managedalice", "password": "Synthetic8!"})
    response = external_admit(alice, text=text)
    assert response.status_code == 409, response.text
    with SessionLocal() as db:
        assert not list(db.scalars(select(ExternalExportBatch)))
        assert not list(db.scalars(select(ExternalExportItem)))
        assert db.get(Subscription, r.id).active_operation_id is None


def test_pasted_managed_worker_rechecks_subscription_before_wire(alice):
    from app.external_auth_worker import run_one
    r = record(username="ManagedAlice", subscription_status="active")
    text = json.dumps({"start_url": r.portal_url, "region": "us-east-1",
                       "username": r.username, "password": "Synthetic8!"})
    response = external_admit(alice, text=text)
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        db.get(Subscription, r.id).subscription_status = "cancelled"
        db.commit()
    def forbidden(*args):
        pytest.fail("revoked managed subscription must stop before native AWS transport")
    assert run_one(gateway_factory=forbidden)
    with SessionLocal() as db:
        assert db.scalar(select(ExternalExportItem)).state == "cancelled"
