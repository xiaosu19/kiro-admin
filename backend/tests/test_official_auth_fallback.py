"""Official-page continuation through the real API, worker and encrypted ZIP lifecycle."""

import io
import json
import time
import zipfile
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.enterprise_auth import EnterpriseAuth
from app.identity_login import NativeIdentityLogin
from app.models import (
    AuthJob,
    AuthSecret,
    AwsAccount,
    RecordOperation,
    Subscription,
    now,
)
from app.security import decrypt, encrypt
from test_auth_batches import Gateway, admission, drain, record
from test_identity_login import CDN, ams_token


class ExternalAuth(EnterpriseAuth):
    """AWS IO is synthetic; challenge, continuation, profile and usage logic are real."""

    wrong_identity = False

    def _advance(self, state, answer):
        if state["stage"] == "register":
            state.update(
                stage="workflow",
                registration={
                    "clientId": "private-client",
                    "clientSecret": "private-secret",
                    "clientSecretExpiresAt": self.clock() + 3600,
                },
                device={
                    "deviceCode": "private-device",
                    "userCode": "HUMAN-CODE",
                    "interval": 5,
                    "expires_at": self.clock() + 600,
                },
            )
            self._challenge(state, {"captchaToken": ams_token(), "captchaCDN": CDN})
        else:
            super()._advance(state, answer)

    def _sdk_call(self, state, operation, **kwargs):
        self._guard()
        assert state["stage"] == "poll" and operation == "create_token"
        assert kwargs["deviceCode"] == "private-device"
        if state["polls"] == 1:
            return {"pending": "AuthorizationPendingException"}
        return {
            "accessToken": "private-access",
            "refreshToken": "private-refresh",
            "expiresIn": 3600,
        }

    def _request(self, state, method, url, *, purpose, **kwargs):
        self._guard()
        if purpose == "profiles":
            return {
                "profiles": [
                    {
                        "arn": state["binding"]["profile_arn"],
                        "profileName": "Synthetic",
                        "identityDetails": {
                            "ssoIdentityDetails": {
                                "instanceArn": state["binding"]["instance"],
                                "ssoRegion": state["binding"]["region"],
                            }
                        },
                    }
                ]
            }
        assert purpose == "usage"
        return {
            "userInfo": {
                "userId": state["binding"]["directory"]
                + "."
                + ("another-user" if self.wrong_identity else state["expected_user_id"])
            }
        }


class LegacyExternalAuth(ExternalAuth):
    def _challenge(self, state, response):
        NativeIdentityLogin._challenge(self, state, response)


class PasswordAMS(NativeIdentityLogin):
    def _advance(self, state, answer):
        self._challenge(state, {"captchaToken": ams_token(), "captchaCDN": CDN})


def due(batch):
    with SessionLocal() as db:
        job = db.scalar(select(AuthJob).where(AuthJob.batch_id == batch["id"]))
        secret = db.get(AuthSecret, job.id)
        state = decrypt(secret.workflow_encrypted)
        state["next_poll_at"] = time.time() - 1
        secret.workflow_encrypted = encrypt(state)
        job.next_poll_at = now() - timedelta(seconds=1)
        db.commit()


def start(alice, *, adapter=ExternalAuth, r=None):
    r = r or record(username="official-user")
    batch = admission(alice, [r]).json()
    drain(adapter)
    base = f"/api/auth-batches/{batch['id']}/items/{r.id}"
    response = alice.get(base + "/challenge")
    assert response.status_code == 200, response.text
    return r, batch, base, response


def answer(response):
    challenge = response.json()
    return {
        "challenge_id": challenge["id"],
        "revision": challenge["revision"],
        "continue_authorization": True,
    }


@pytest.mark.parametrize("adapter", [ExternalAuth, LegacyExternalAuth])
def test_official_metadata_is_owner_private_reloadable_and_secret_free(
    alice, bob, adapter
):
    r, _, base, response = start(alice, adapter=adapter)
    challenge = response.json()
    assert response.headers["cache-control"] == "no-store"
    assert challenge["kind"] == "aws_authorization"
    assert (
        challenge["username"] == r.username and challenge["user_code"] == "HUMAN-CODE"
    )
    with SessionLocal() as db:
        portal = db.get(AwsAccount, r.aws_account_id).portal_url
        assert db.get(Subscription, r.id).password_encrypted
    assert (
        challenge["authorization_url"]
        == portal.rstrip("/") + "/#/device?user_code=HUMAN-CODE"
    )
    assert set(challenge) == {
        "operation_id",
        "kind",
        "id",
        "revision",
        "expires_at",
        "authorization_url",
        "user_code",
        "username",
    }
    assert "private-" not in response.text and "OldOTP" not in response.text
    assert alice.get(base + "/challenge").json() == challenge
    assert bob.get(base + "/challenge").status_code == 404


def test_official_continue_fences_old_credentials_results_and_preserves_current_job(
    alice, bob
):
    r = record(username="official-user")
    old = admission(alice, [r]).json()
    drain()
    _, batch, base, response = start(alice, r=r)
    body = answer(response)
    assert (
        alice.post(
            base + "/resume", json=body | {"revision": body["revision"] + 1}
        ).status_code
        == 409
    )
    for invalid in (
        {"continue_authorization": False},
        {"continue_authorization": "true"},
        {"guess": "bad"},
    ):
        assert alice.post(base + "/resume", json=body | invalid).status_code in (
            409,
            422,
        )
    assert bob.post(base + "/resume", json=body).status_code == 404
    with SessionLocal() as db:
        before = db.get(Subscription, r.id).credential_revision
        assert db.get(Subscription, r.id).password_encrypted
    token = alice.headers.pop("X-CSRF-Token")
    assert alice.post(base + "/resume", json=body).status_code == 403
    alice.headers["X-CSRF-Token"] = token
    accepted = alice.post(base + "/resume", json=body)
    assert accepted.status_code == 202, accepted.text
    assert alice.post(base + "/resume", json=body).status_code == 409
    with SessionLocal() as db:
        saved = db.get(Subscription, r.id)
        job = db.scalar(select(AuthJob).where(AuthJob.batch_id == batch["id"]))
        old_job = db.scalar(select(AuthJob).where(AuthJob.batch_id == old["id"]))
        assert saved.credential_state == "unknown" and not saved.password_encrypted
        assert saved.credential_recovery_encrypted is None
        assert saved.credential_revision == before + 1 == job.credential_revision
        assert saved.active_operation_id == job.id
        assert db.get(RecordOperation, old_job.id).state == "expired"
        assert not db.get(AuthSecret, old_job.id).result_encrypted
        assert "OldOTP1!" not in json.dumps(
            decrypt(db.get(AuthSecret, job.id).workflow_encrypted)
        )
    assert alice.post(f"/api/subscriptions/{r.id}/credentials").status_code == 409
    drain(ExternalAuth)
    public = alice.get(f"/api/auth-batches/{batch['id']}").json()
    assert public["states"]["polling"] == 1
    due(batch)
    drain(ExternalAuth)
    assert (
        alice.get(f"/api/auth-batches/{batch['id']}").json()["states"]["polling"] == 1
    )
    due(batch)
    drain(ExternalAuth)
    result = alice.post(f"/api/auth-batches/{batch['id']}/download")
    assert result.status_code == 200, result.text
    with zipfile.ZipFile(io.BytesIO(result.content)) as archive:
        assert archive.namelist() == ["official-user.json"]
        exported = json.loads(archive.read("official-user.json"))[0]
    assert exported["password"] is None and exported["userId"] == r.sso_user_id
    with SessionLocal() as db:
        secret = db.get(AuthSecret, job.id)
        assert not any(
            (
                secret.result_encrypted,
                secret.workflow_encrypted,
                secret.answer_encrypted,
                secret.payload_encrypted,
            )
        )
        assert db.get(Subscription, r.id).credential_state == "unknown"


def test_official_wrong_identity_cannot_enter_a_zip(alice):
    class WrongUser(ExternalAuth):
        wrong_identity = True

    r, batch, base, response = start(alice, adapter=WrongUser)
    assert alice.post(base + "/resume", json=answer(response)).status_code == 202
    drain(WrongUser)
    for _ in range(2):
        due(batch)
        drain(WrongUser)
    result = alice.get(f"/api/auth-batches/{batch['id']}").json()
    assert result["items"][0]["error_code"] == "identity_mismatch"
    assert result["success_count"] == 0
    assert alice.post(f"/api/auth-batches/{batch['id']}/download").status_code == 409
    with SessionLocal() as db:
        job = db.scalar(select(AuthJob).where(AuthJob.batch_id == batch["id"]))
        assert not db.get(AuthSecret, job.id).result_encrypted
        assert db.get(Subscription, r.id).password_encrypted is None


@pytest.mark.parametrize(
    "change", ["cancel", "expiry", "configuration", "permission", "credential"]
)
def test_official_continuation_preserves_revocation_fences(alice, change):
    from app.auth_credentials import invalidate_credentials
    from app.models import AuthBatch, Binding

    r, batch, base, response = start(alice)
    assert alice.post(base + "/resume", json=answer(response)).status_code == 202
    if change == "cancel":
        assert alice.post(base + "/cancel").status_code == 200
    else:
        with SessionLocal() as db:
            if change == "expiry":
                db.get(AuthBatch, batch["id"]).expires_at = now() - timedelta(seconds=1)
            elif change == "configuration":
                db.get(
                    AwsAccount, r.aws_account_id
                ).portal_url = "https://other.awsapps.com/start"
            elif change == "permission":
                db.delete(db.get(Binding, (2, 1)))
            else:
                invalidate_credentials(db, db.get(Subscription, r.id))
            db.commit()
    drain(ExternalAuth)
    with SessionLocal() as db:
        job = db.scalar(select(AuthJob).where(AuthJob.batch_id == batch["id"]))
        assert not db.get(AuthSecret, job.id).result_encrypted
        assert db.get(Subscription, r.id).password_encrypted is None
    assert alice.post(f"/api/auth-batches/{batch['id']}/download").status_code != 200


def test_official_expiry_and_unsafe_saved_link_fail_without_password_changes(alice):
    r, _, base, response = start(alice)
    with SessionLocal() as db:
        job = db.scalar(select(AuthJob).where(AuthJob.record_id == r.id))
        secret = db.get(AuthSecret, job.id)
        state = decrypt(secret.workflow_encrypted)
        state["device"]["verificationUriComplete"] = "https://evil.example/"
        secret.workflow_encrypted = encrypt(state)
        db.commit()
    assert alice.get(base + "/challenge").status_code == 409
    assert alice.post(base + "/resume", json=answer(response)).status_code == 409
    with SessionLocal() as db:
        assert db.get(Subscription, r.id).password_encrypted
        secret = db.get(AuthSecret, job.id)
        state = decrypt(secret.workflow_encrypted)
        state["device"].pop("verificationUriComplete")
        state["device"]["expires_at"] = 1
        secret.workflow_encrypted = encrypt(state)
        db.commit()
    assert alice.post(base + "/resume", json=answer(response)).status_code == 410


def test_password_only_ams_cannot_resume_from_official_oauth(alice):
    r = record()
    batch = admission(alice, [r], kind="random_password").json()
    drain(PasswordAMS)
    base = f"/api/auth-batches/{batch['id']}/items/{r.id}"
    response = alice.get(base + "/challenge")
    assert response.status_code == 200, response.text
    assert response.json()["kind"] == "manual_action"
    assert "frame_url" not in response.text and "redemption_token" not in response.text
    assert alice.post(base + "/resume", json=answer(response)).status_code == 409
    assert alice.get(f"/api/auth-batches/{batch['id']}").json()["success_count"] == 0


def test_external_export_checks_identity_again_and_never_uses_a_stored_otp(alice):
    from app.auth_export import account_json
    from test_auth_batches import native_result

    r = record()
    with SessionLocal() as db:
        account = db.get(AwsAccount, r.aws_account_id)
        state = EnterpriseAuth(Gateway(account), checkpoint=lambda _: None)._new_state(
            r.username, "OldOTP1!", expected_user_id=r.sso_user_id
        )
    result = native_result(state) | {
        "externalAuthorization": True,
        "identityStoreId": state["binding"]["directory"],
    }
    with pytest.raises(ValueError, match="identity"):
        account_json(r, result)
    result["usage"]["userInfo"]["userId"] = (
        state["binding"]["directory"] + "." + r.sso_user_id
    )
    assert account_json(r, result)[0]["password"] is None


def test_expired_external_tokens_refresh_without_restoring_or_resetting_password(alice):
    class Refresh(ExternalAuth):
        def _sdk_call(self, state, operation, **kwargs):
            if state["stage"] == "refresh":
                assert kwargs["refreshToken"] == "private-refresh"
                assert kwargs["grantType"] == "refresh_token"
                return {"accessToken": "private-new-access", "expiresIn": 3600}
            return super()._sdk_call(state, operation, **kwargs)

    r, batch, base, response = start(alice, adapter=Refresh)
    assert alice.post(base + "/resume", json=answer(response)).status_code == 202
    drain(Refresh)
    for _ in range(2):
        due(batch)
        drain(Refresh)
    with SessionLocal() as db:
        job = db.scalar(select(AuthJob).where(AuthJob.batch_id == batch["id"]))
        secret = db.get(AuthSecret, job.id)
        result = decrypt(secret.result_encrypted)
        result["expiresAt"] = 1
        secret.result_encrypted = encrypt(result)
        db.commit()
    assert alice.post(f"/api/auth-batches/{batch['id']}/download").status_code == 409
    public = alice.get(f"/api/auth-batches/{batch['id']}").json()["items"][0]
    assert public["error_code"] == "token_expired" and not public["requires_new_reset"]
    resets = Gateway.resets
    response = alice.post(base + "/retry", json={"mode": "resume"})
    assert response.status_code == 202, response.text
    drain(Refresh)
    assert Gateway.resets == resets
    with SessionLocal() as db:
        assert db.get(Subscription, r.id).password_encrypted is None
        result = decrypt(db.get(AuthSecret, job.id).result_encrypted)
        assert (
            result["accessToken"] == "private-new-access" and result["password"] is None
        )


def test_external_continue_discards_uncertain_native_password_candidate(alice):
    r, batch, base, response = start(alice)
    with SessionLocal() as db:
        job = db.scalar(select(AuthJob).where(AuthJob.batch_id == batch["id"]))
        secret = db.get(AuthSecret, job.id)
        state = decrypt(secret.workflow_encrypted)
        state["credential"].update(candidate="Unconfirmed9!", status="unknown")
        state["password_write_pending"] = True
        saved = db.get(Subscription, r.id)
        saved.credential_state = "unknown"
        saved.credential_recovery_encrypted = encrypt(state["credential"])
        secret.workflow_encrypted = encrypt(state)
        db.commit()
    assert alice.post(base + "/resume", json=answer(response)).status_code == 202
    drain(ExternalAuth)
    with SessionLocal() as db:
        saved = db.get(Subscription, r.id)
        state = decrypt(db.get(AuthSecret, job.id).workflow_encrypted)
        assert saved.credential_recovery_encrypted is None
        assert saved.password_encrypted is None
        assert state["stage"] == "poll" and not state["password_write_pending"]
        assert (
            state["credential"]["current"] is state["credential"]["candidate"] is None
        )


def test_official_continuation_audit_contains_no_link_or_secrets(alice):
    from app.models import AuditEvent

    r, batch, base, response = start(alice)
    assert alice.post(base + "/resume", json=answer(response)).status_code == 202
    drain(ExternalAuth)
    for _ in range(2):
        due(batch)
        drain(ExternalAuth)
    with SessionLocal() as db:
        events = list(db.scalars(select(AuditEvent)))
        text = str([event.__dict__ for event in events])
    for value in (
        "OldOTP1!",
        "private-access",
        "private-secret",
        "private-device",
        "HUMAN-CODE",
        response.json()["authorization_url"],
    ):
        assert value not in text


def test_official_proxy_failure_stops_before_polling_without_exposing_credentials(
    alice,
):
    from app.aws import AwsFailure

    class Unavailable(Gateway):
        def _check_proxy(self):
            raise AwsFailure("private-proxy-credentials")

    _, batch, base, response = start(alice)
    assert alice.post(base + "/resume", json=answer(response)).status_code == 202
    drain(ExternalAuth, gateway=Unavailable)
    public = alice.get(f"/api/auth-batches/{batch['id']}")
    assert public.json()["success_count"] == 0
    assert public.json()["items"][0]["state"] == "needs_review"
    assert "private-" not in public.text


def test_crash_after_official_continue_checkpoint_resumes_polling_without_reset(
    alice, monkeypatch
):
    from app import auth_jobs

    r, batch, base, response = start(alice)
    assert alice.post(base + "/resume", json=answer(response)).status_code == 202
    resets = Gateway.resets
    original_checkpoint = auth_jobs.checkpoint

    def crash_after_commit(job_id, token, value):
        original_checkpoint(job_id, token, value)
        if value.event == "external_authorization":
            raise SystemExit("synthetic crash after continuation commit")

    with monkeypatch.context() as crash:
        crash.setattr(auth_jobs, "checkpoint", crash_after_commit)
        with pytest.raises(SystemExit, match="synthetic crash"):
            auth_jobs.run_one(Gateway, ExternalAuth)

    with SessionLocal() as db:
        job = db.scalar(select(AuthJob).where(AuthJob.batch_id == batch["id"]))
        secret = db.get(AuthSecret, job.id)
        state = decrypt(secret.workflow_encrypted)
        assert state["stage"] == "poll" and state["status"] == "polling"
        assert state["inflight"] is state["challenge"] is None
        op = db.get(RecordOperation, job.id)
        assert op.state == "running"
        op.lease_until = now() - timedelta(seconds=1)
        db.commit()

    drain(ExternalAuth)
    public = alice.get(f"/api/auth-batches/{batch['id']}").json()
    assert public["states"]["polling"] == 1, public["items"]
    for _ in range(2):
        due(batch)
        drain(ExternalAuth)
    result = alice.post(f"/api/auth-batches/{batch['id']}/download")
    assert result.status_code == 200, result.text
    with zipfile.ZipFile(io.BytesIO(result.content)) as archive:
        exported = json.loads(archive.read("official-user.json"))[0]
    assert exported["password"] is None and exported["userId"] == r.sso_user_id
    assert Gateway.resets == resets
    with SessionLocal() as db:
        saved = db.get(Subscription, r.id)
        assert saved.credential_state == "unknown" and saved.password_encrypted is None
        assert db.get(AuthSecret, job.id).answer_encrypted is None
