"""Durable pasted-login recovery and worker fences, using no real AWS calls."""
import json
import uuid
from datetime import timedelta
from threading import Event, Thread

import pytest
from app.database import SessionLocal
from app.external_auth_models import ExternalExportItem
from app.external_auth_worker import run_one
from app.external_enterprise import ExternalEnterpriseAuth
from app.models import now
from app.security import decrypt


def admit(client):
    text = json.dumps({
        "start_url": "https://d-1234567890.awsapps.com/start",
        "region": "us-east-1", "username": "alice", "password": "SyntheticOriginal9!",
    })
    preview = client.post("/api/external-auth-batches/preview", json={"text": text})
    assert preview.status_code == 200
    response = client.post("/api/external-auth-batches", json={
        "text": text, "request_key": str(uuid.uuid4()),
        "preview_fingerprint": preview.json()["preview_fingerprint"],
    })
    assert response.status_code == 202
    return response.json()


def test_cancel_during_password_write_retains_late_confirmed_recovery(alice):
    batch = admit(alice)

    class CancelInFlight(ExternalEnterpriseAuth):
        def _advance(self, state, answer):
            state["credential"].update(candidate="SyntheticCandidate9!", status="unknown")
            state.update(password_write_pending=True, inflight="password_change")
            self._emit(state, "password_pending", credential=True)
            assert alice.post(f"/api/external-auth-batches/{batch['id']}/cancel").status_code == 200
            # AWS may confirm a write after cancellation reached our server.
            state["credential"].update(current="SyntheticCandidate9!", status="confirmed")
            state.update(password_write_pending=False, inflight=None)
            self._emit(state, "password_confirmed", credential=True)

    assert run_one(auth_factory=CancelInFlight)
    assert run_one(auth_factory=CancelInFlight)
    assert not run_one(auth_factory=CancelInFlight)
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch["items"][0]["id"])
        assert item.state == "cancelled" and item.cancel_requested
        assert not any((item.input_encrypted, item.workflow_encrypted,
                        item.answer_encrypted, item.result_encrypted))
        assert item.lease_token is None and item.lease_until is None
        assert decrypt(item.credential_encrypted)["status"] == "confirmed"

    recovery = alice.post(f"/api/external-auth-batches/{batch['id']}/items/{batch['items'][0]['id']}/credential-recovery")
    assert recovery.status_code == 200 and recovery.headers["cache-control"] == "no-store"
    assert recovery.json()["current"] == "SyntheticCandidate9!"
    assert recovery.json()["status"] == "confirmed"
    public = alice.get(f"/api/external-auth-batches/{batch['id']}")
    assert "SyntheticCandidate9!" not in public.text and "SyntheticOriginal9!" not in public.text


def test_crash_after_password_intent_never_replays_unknown_credentials(alice):
    batch = admit(alice)
    writes = []

    class CrashInFlight(ExternalEnterpriseAuth):
        def _advance(self, state, answer):
            writes.append(1)
            state["credential"].update(candidate="SyntheticCandidate9!", status="unknown")
            state.update(password_write_pending=True, inflight="password_change")
            self._emit(state, "password_pending", credential=True)
            raise SystemExit("synthetic worker crash after durable password intent")

    assert run_one(auth_factory=CrashInFlight)
    with pytest.raises(SystemExit, match="synthetic worker crash"):
        run_one(auth_factory=CrashInFlight)
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch["items"][0]["id"])
        assert item.state == "running"
        assert decrypt(item.workflow_encrypted)["inflight"] == "password_change"
        assert decrypt(item.credential_encrypted)["status"] == "unknown"
        item.lease_until = now() - timedelta(seconds=1)
        db.commit()

    assert run_one(auth_factory=CrashInFlight)
    assert not run_one(auth_factory=CrashInFlight)
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch["items"][0]["id"])
        assert item.state == "needs_review" and item.error_code == "interrupted"
        assert item.retry_count == 0 and item.result_encrypted is None
        assert decrypt(item.credential_encrypted)["candidate"] == "SyntheticCandidate9!"
    assert writes == [1]
    retry = alice.post(f"/api/external-auth-batches/{batch['id']}/items/{batch['items'][0]['id']}/retry")
    assert retry.status_code == 409
    assert alice.post(f"/api/external-auth-batches/{batch['id']}/cancel").status_code == 200
    recovery = alice.post(f"/api/external-auth-batches/{batch['id']}/items/{batch['items'][0]['id']}/credential-recovery")
    assert recovery.status_code == 200
    assert recovery.json()["status"] == "unknown"
    assert recovery.json()["candidate"] == "SyntheticCandidate9!"


def test_expired_lease_cannot_overlap_live_worker_principal_fence(alice):
    batch = admit(alice)
    entered, release = Event(), Event()
    completed, errors, advances = [], [], []

    class BlockedAuth(ExternalEnterpriseAuth):
        def _advance(self, state, answer):
            advances.append(1)
            entered.set()
            assert release.wait(10), "test did not release its blocked worker"

    assert run_one(auth_factory=BlockedAuth)

    def first_worker():
        try:
            completed.append(run_one(auth_factory=BlockedAuth))
        except BaseException as error:
            errors.append(error)

    worker = Thread(target=first_worker)
    worker.start()
    try:
        assert entered.wait(5)
        with SessionLocal() as db:
            item = db.get(ExternalExportItem, batch["items"][0]["id"])
            original_token = item.lease_token
            assert item.state == "running" and original_token
            item.lease_until = now() - timedelta(seconds=1)
            db.commit()
        assert run_one(auth_factory=BlockedAuth) is False
        with SessionLocal() as db:
            item = db.get(ExternalExportItem, batch["items"][0]["id"])
            assert item.state == "running" and item.lease_token == original_token
        assert advances == [1]
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive() and not errors and completed == [True]
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch["items"][0]["id"])
        assert item.state == "queued" and item.lease_token is None and item.lease_until is None
