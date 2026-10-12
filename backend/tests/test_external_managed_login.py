"""Pasted console users share credentials, proxy routing and native login fences."""
import json
from datetime import timedelta
from threading import Event, Thread

import pytest
from app.database import SessionLocal
from app.external_auth_models import ExternalExportItem
from app.external_auth_worker import run_one
from app.external_enterprise import ExternalEnterpriseAuth, ExternalGateway
from app.identity_login import AuthError
from app.models import (
    AuthSecret,
    AwsAccount,
    Binding,
    Proxy,
    RecordOperation,
    Subscription,
    now,
)
from app.security import decrypt, encrypt
from test_auth_batches import admission, drain, record
from test_external_auth_batches import admit, result_for


def managed_record():
    row = record(username="alice")
    with SessionLocal() as db:
        db.get(Subscription, row.id).sso_user_id = "actual-user"
        db.commit()
    return row


def test_managed_admission_freezes_private_identity_and_uses_real_account_lane(alice):
    row = managed_record()
    response = admit(alice)
    assert response.status_code == 202
    batch = response.json()
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch["items"][0]["id"])
        configuration = json.loads(item.configuration)
        assert configuration["_managed_record_id"] == row.id
        assert configuration["_managed_account_id"] == 1
        assert configuration["_managed_credential_revision"] == 1
        assert configuration["expected_user_id"] == "actual-user"
        assert configuration["instance_arn"] == db.get(AwsAccount, 1).instance_arn
        assert "credentials_encrypted" not in configuration
        lane = item.lane_id
    assert "_managed" not in response.text and row.id not in response.text
    from app.auth_principals import active_external_login, login_key
    from app.external_auth_worker import candidate_tasks
    assert candidate_tasks() == [(1, "external", lane)]
    with SessionLocal() as db:
        assert active_external_login(db, db.get(Subscription, row.id))
    assert login_key("d-1234567890", "ALICE") == login_key("d-1234567890", "alice")


def test_managed_pasted_login_enforces_owner_binding_and_pending_operation(alice, bob):
    row = managed_record()
    assert admit(bob).status_code in (403, 404)
    with SessionLocal() as db:
        db.get(Subscription, row.id).active_operation_id = "pending-managed-operation"
        db.commit()
    assert admit(alice).status_code == 409
    with SessionLocal() as db:
        db.get(Subscription, row.id).active_operation_id = None
        db.delete(db.get(Binding, (2, 1)))
        db.commit()
    assert admit(alice).status_code == 403


@pytest.mark.parametrize("change", ["binding", "account", "owner", "revision", "config", "deleted"])
def test_managed_scope_revocation_prevents_every_wire_call(alice, change):
    row = managed_record()
    batch = admit(alice).json()
    with SessionLocal() as db:
        current, account = db.get(Subscription, row.id), db.get(AwsAccount, 1)
        if change == "binding":
            db.delete(db.get(Binding, (2, 1)))
        elif change == "account":
            account.active = False
        elif change == "owner":
            current.owner_id = 3
        elif change == "revision":
            current.credential_revision += 1
        elif change == "config":
            account.profile_arn += "-changed"
        else:
            current.sso_deleted_at = now()
        db.commit()
    reached = []
    assert run_one(gateway_factory=lambda *args: reached.append(1))
    assert not reached
    with SessionLocal() as db:
        assert db.get(ExternalExportItem, batch["items"][0]["id"]).state == "cancelled"


@pytest.mark.parametrize("cancel", [False, True, "binding"])
def test_managed_first_login_updates_credentials_and_recovery_even_after_cancel(alice, cancel):
    row = managed_record()
    batch = admit(alice).json()

    class FirstLogin(ExternalEnterpriseAuth):
        def _advance(self, state, answer):
            assert state["expected_user_id"] == "actual-user"
            state["credential"].update(candidate="SyntheticPermanent9!", status="unknown")
            state.update(inflight="password_change", password_write_pending=True)
            self._emit(state, "password_pending", credential=True)
            with SessionLocal() as db:
                current = db.get(Subscription, row.id)
                assert current.credential_state == "unknown" and current.credential_revision == 2
                recovery = decrypt(current.credential_recovery_encrypted)
                assert recovery["binding"]["account_id"] == 1
            if cancel == "binding":
                with SessionLocal() as db:
                    db.delete(db.get(Binding, (2, 1)))
                    db.commit()
            elif cancel:
                assert alice.post(f"/api/external-auth-batches/{batch['id']}/cancel").status_code == 200
            state["credential"].update(current="SyntheticPermanent9!", status="confirmed")
            state.update(inflight=None, password_write_pending=False)
            self._emit(state, "password_confirmed", credential=True)
            state.update(stage="usage", status="ready")

    assert run_one(auth_factory=FirstLogin)
    assert run_one(auth_factory=FirstLogin)
    with SessionLocal() as db:
        current = db.get(Subscription, row.id)
        assert current.credential_state == "permanent" and current.credential_revision == 2
        assert decrypt(current.password_encrypted) == "SyntheticPermanent9!"
        assert current.credential_recovery_encrypted is None
        item = db.get(ExternalExportItem, batch["items"][0]["id"])
        assert json.loads(item.configuration)["_managed_credential_revision"] == 2
        assert item.state == ("cancelled" if cancel else "queued")


def test_managed_password_change_invalidates_old_tokens_and_download_keeps_record_identity(alice):
    row = managed_record()
    original = admission(alice, [row])
    assert original.status_code == 202
    original_job = original.json()["items"][0]["operation_id"]
    drain()
    with SessionLocal() as db:
        assert db.get(AuthSecret, original_job).result_encrypted
    batch = admit(alice).json()

    class CompleteFirstLogin(ExternalEnterpriseAuth):
        def _advance(self, state, answer):
            if state["stage"] == "usage":
                from types import SimpleNamespace
                result = result_for(SimpleNamespace(region=state["binding"]["region"],
                    portal_url=state["binding"]["portal"], username=state["username"]))
                result["password"] = state["credential"]["current"]
                result["profile"]["arn"] = state["binding"]["profile_arn"]
                state.update(result=result, stage="done", status="done")
                return
            state["credential"].update(candidate="SyntheticPermanent9!", status="unknown")
            state.update(inflight="password_change", password_write_pending=True)
            self._emit(state, "password_pending", credential=True)
            state["credential"].update(current="SyntheticPermanent9!", status="confirmed")
            state.update(inflight=None, password_write_pending=False)
            self._emit(state, "password_confirmed", credential=True)
            state.update(stage="usage", status="ready")

    assert run_one(auth_factory=CompleteFirstLogin)
    assert run_one(auth_factory=CompleteFirstLogin)
    with SessionLocal() as db:
        assert db.get(AuthSecret, original_job).result_encrypted is None
        assert db.get(RecordOperation, original_job).state == "expired"
    assert run_one(auth_factory=CompleteFirstLogin)
    assert not run_one(auth_factory=CompleteFirstLogin)
    response = alice.post(f"/api/external-auth-batches/{batch['id']}/download?format=json&item_id={batch['items'][0]['id']}")
    assert response.status_code == 200
    assert response.json()[0]["id"] == row.id
    assert response.json()[0]["password"] == "SyntheticPermanent9!"
    with SessionLocal() as db:
        current = db.get(Subscription, row.id)
        assert current.credential_revision == 2 and current.credential_state == "permanent"


def test_managed_guard_rechecks_configuration_immediately_before_wire(alice):
    managed_record()
    batch = admit(alice).json()
    wire = []

    class ChangedDuringStep(ExternalEnterpriseAuth):
        def _advance(self, state, answer):
            with SessionLocal() as db:
                db.get(AwsAccount, 1).profile_arn += "-changed"
                db.commit()
            self.gateway._check_proxy()
            wire.append(1)

    assert run_one(auth_factory=ChangedDuringStep)
    assert run_one(auth_factory=ChangedDuringStep)
    assert not wire
    with SessionLocal() as db:
        assert db.get(ExternalExportItem, batch["items"][0]["id"]).state == "cancelled"


def test_managed_unknown_password_survives_crash_with_reusable_managed_recovery_binding(alice):
    row = managed_record()
    batch = admit(alice).json()
    attempts = []

    class CrashAfterPassword(ExternalEnterpriseAuth):
        def _advance(self, state, answer):
            attempts.append(1)
            state["credential"].update(candidate="SyntheticCandidate9!", status="unknown")
            state.update(inflight="password_change", password_write_pending=True)
            self._emit(state, "password_pending", credential=True)
            raise SystemExit("synthetic managed password crash")

    assert run_one(auth_factory=CrashAfterPassword)
    with pytest.raises(SystemExit, match="synthetic managed password crash"):
        run_one(auth_factory=CrashAfterPassword)
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch["items"][0]["id"])
        item.lease_until = now() - timedelta(seconds=1)
        db.commit()
    assert run_one(auth_factory=CrashAfterPassword)
    assert attempts == [1]
    with SessionLocal() as db:
        current = db.get(Subscription, row.id)
        recovery = current.credential_recovery_encrypted
        assert current.credential_state == "unknown" and current.credential_revision == 2
        assert decrypt(recovery)["binding"]["account_id"] == 1
        account = db.get(AwsAccount, 1)
        db.expunge(account)
    from types import SimpleNamespace

    from app.enterprise_auth import EnterpriseAuth
    adapter = EnterpriseAuth(SimpleNamespace(account=account), checkpoint=lambda _: None)
    resumed = adapter.begin("alice", "Synthetic8!", expected_user_id="actual-user", recovery=recovery)
    state = decrypt(resumed.sealed_state)
    assert state["recovering"] and state["credential"]["candidate"] == "SyntheticCandidate9!"
    assert admission(alice, [row]).status_code == 202


def test_official_manual_authorization_clears_obsolete_managed_password_candidate(alice):
    from app.enterprise_auth import forget_external_password
    row = managed_record()
    batch = admit(alice).json()

    class OfficialContinuation(ExternalEnterpriseAuth):
        def _advance(self, state, answer):
            state["credential"].update(candidate="SyntheticOldCandidate9!", status="unknown")
            state.update(inflight="password_change", password_write_pending=True)
            self._emit(state, "password_pending", credential=True)
            state["inflight"] = None
            forget_external_password(state)
            self._emit(state, "external_authorization", credential=True)
            state.update(stage="poll", status="polling", next_poll_at=self.clock() + 5)

    assert run_one(auth_factory=OfficialContinuation)
    assert run_one(auth_factory=OfficialContinuation)
    with SessionLocal() as db:
        current = db.get(Subscription, row.id)
        assert current.credential_state == "unknown" and current.credential_revision == 2
        assert current.password_encrypted is None and current.credential_recovery_encrypted is None
    assert alice.post(f"/api/external-auth-batches/{batch['id']}/cancel").status_code == 200
    # Old OTP/candidate cannot silently become a new managed recovery attempt.
    assert admission(alice, [row]).status_code == 409


def test_managed_proxy_is_reused_and_revision_change_never_falls_back_direct(alice, monkeypatch):
    managed_record()
    with SessionLocal() as db:
        proxy = Proxy(name="managed", host="127.0.0.1", port=1080,
                      auth_encrypted=encrypt({"username": "proxy-user", "password": "SyntheticProxy9!"}))
        db.add(proxy)
        db.flush()
        db.get(AwsAccount, 1).proxy_id = proxy.id
        proxy_id = proxy.id
        db.commit()
    batch = admit(alice).json()
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch["items"][0]["id"])
        configuration = json.loads(item.configuration)
        db.expunge(item)
    gateway = ExternalGateway(item, configuration, lambda: None)
    assert gateway.proxy.proxy_id == proxy_id
    assert gateway.proxy.url.startswith("socks5h://")
    calls = []
    monkeypatch.setattr("app.external_enterprise.boto3.client", lambda *args, **kwargs: object())
    monkeypatch.setattr("app.external_enterprise.configure_client_proxy",
                        lambda client, url, guard: calls.append((url, guard)) or client)
    gateway._client("sso-oidc", region_name="us-east-1")
    assert calls[0][0] == gateway.proxy.url
    with SessionLocal() as db:
        db.get(Proxy, proxy_id).revision += 1
        db.commit()
    with pytest.raises(AuthError) as caught:
        gateway._check_proxy()
    assert caught.value.code == "proxy_unavailable"
    assert "SyntheticProxy9!" not in alice.get(f"/api/external-auth-batches/{batch['id']}").text


@pytest.mark.parametrize("resource", ["record", "login", "account"])
def test_managed_and_external_workers_cannot_overlap_same_identity_or_exclusive_account(alice, resource):
    from app.account_dispatcher import account_fence, resource_fence
    from app.auth_principals import login_key
    row = managed_record()
    batch = admit(alice).json()
    entered, release = Event(), Event()
    key = row.id if resource == "record" else login_key("d-1234567890", "alice")

    def hold():
        fence = account_fence(1) if resource == "account" else resource_fence(resource, key)
        with fence as acquired:
            assert acquired
            entered.set()
            assert release.wait(10)

    thread = Thread(target=hold)
    thread.start()
    try:
        assert entered.wait(5)
        assert run_one(auth_factory=ExternalEnterpriseAuth) is False
        with SessionLocal() as db:
            assert db.get(ExternalExportItem, batch["items"][0]["id"]).state == "queued"
    finally:
        release.set()
        thread.join(5)
    assert not thread.is_alive()
    assert run_one(auth_factory=ExternalEnterpriseAuth)


def test_managed_auth_admission_rejects_live_pasted_login(alice):
    row = managed_record()
    assert admit(alice).status_code == 202
    assert admission(alice, [row]).status_code == 409


@pytest.mark.parametrize("actor_ids", [(2, 2), (2, 3)])
def test_concurrent_external_admission_serializes_the_principal(monkeypatch, actor_ids):
    from concurrent.futures import ThreadPoolExecutor

    from fastapi import HTTPException
    from sqlalchemy import select

    from app import external_auth
    from app.external_auth_models import ExternalExportBatch
    from app.models import User
    from test_external_auth_batches import TEXT

    entered, release, second_prepared = Event(), Event(), Event()
    original = external_auth.managed_configuration

    def preparing(db, pasted, actor):
        configuration = original(db, pasted, actor)
        if not entered.is_set():
            entered.set()
            assert release.wait(5)
        else:
            second_prepared.set()
        return configuration

    monkeypatch.setattr(external_auth, "managed_configuration", preparing)
    fingerprint = external_auth.digest(external_auth.parse(TEXT))

    def submit(actor_id, key):
        with SessionLocal() as db:
            try:
                external_auth.admit(external_auth.AdmissionInput(
                    text=TEXT, preview_fingerprint=fingerprint, request_key=key),
                    None, db.get(User, actor_id), db)
            except HTTPException as error:
                return error.status_code
            return 202

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(submit, actor_ids[0], "parallel-external-first")
        try:
            assert entered.wait(3)
            second = pool.submit(submit, actor_ids[1], "parallel-external-second")
            # The first admission has checked the principal but not committed it.
            # A writer lock keeps the second request before that same check.
            second_prepared.wait(0.3)
        finally:
            release.set()
        assert sorted([first.result(timeout=5), second.result(timeout=5)]) == [202, 409]
    with SessionLocal() as db:
        assert len(list(db.scalars(select(ExternalExportBatch)))) == 1
        assert len(list(db.scalars(select(ExternalExportItem)))) == 1


@pytest.mark.parametrize("first_kind", ["external", "managed"])
def test_parallel_managed_and_pasted_http_admission_accepts_only_one(alice, monkeypatch, first_kind):
    from concurrent.futures import ThreadPoolExecutor

    from sqlalchemy import select

    from app import auth_batches, external_auth
    from app.models import AuthJob
    from test_external_auth_batches import TEXT

    row = managed_record()
    preview = alice.post("/api/external-auth-batches/preview", json={"text": TEXT})
    external_body = {"text": TEXT, "request_key": "parallel-pasted-managed-001",
                     "preview_fingerprint": preview.json()["preview_fingerprint"]}
    entered, release, second_started = Event(), Event(), Event()
    module, name = ((external_auth, "managed_configuration") if first_kind == "external"
                    else (auth_batches, "validate_record"))
    original = getattr(module, name)

    def preparing(*args, **kwargs):
        value = original(*args, **kwargs)
        entered.set()
        assert release.wait(5)
        return value

    monkeypatch.setattr(module, name, preparing)

    def submit(kind, second=False):
        if second:
            second_started.set()
        if kind == "external":
            return alice.post("/api/external-auth-batches", json=external_body)
        return admission(alice, [row])

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(submit, first_kind)
        try:
            assert entered.wait(3)
            second = pool.submit(submit, "managed" if first_kind == "external" else "external", True)
            assert second_started.wait(3)
        finally:
            release.set()
        responses = [first.result(timeout=5), second.result(timeout=5)]
        assert sorted(response.status_code for response in responses) == [202, 409], [
            response.text for response in responses]
    with SessionLocal() as db:
        assert len(list(db.scalars(select(AuthJob)))) + len(list(db.scalars(select(ExternalExportItem)))) == 1
