"""Batch policy and durable auth plumbing; all transports are local fakes."""

import io
import json
import uuid
import zipfile
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.enterprise_auth import EnterpriseAuth
from app.identity_login import AuthError
from app.models import AwsAccount, Subscription, now
from app.security import decrypt, encrypt


def record(owner=2, username=None, **values):
    rid = str(uuid.uuid4())
    with SessionLocal() as db:
        r = Subscription(
            id=rid,
            owner_id=owner,
            aws_account_id=1,
            request_key=rid,
            username=username or "user-" + rid[:8],
            email="fake@example.org",
            state="completed",
            step="done",
            reserved=False,
            provision_only=True,
            sso_user_id="sso-" + rid,
            portal_url=db.get(AwsAccount, 1).portal_url,
            password_encrypted=encrypt("OldOTP1!"),
            **values,
        )
        db.add(r)
        db.commit()
        return r


def admission(client, records, kind="json_export", **kw):
    return client.post(
        "/api/auth-batches",
        json={
            "kind": kind,
            "record_ids": [r.id for r in records],
            "request_key": str(uuid.uuid4()),
            **kw,
        },
    )


class Gateway:
    resets = 0
    checks = 0

    def __init__(self, account):
        self.account = account
        self.proxy = None

    def _check_proxy(self):
        type(self).checks += 1

    def user_info(self, r):
        return {"UserId": r.sso_user_id}

    def password(self, r):
        type(self).resets += 1
        return "FreshOTP1!"


def native_result(state):
    return {
        "accessToken": "private-access-token",
        "refreshToken": "private-refresh-token",
        "expiresAt": 1988000000,
        "clientId": "real-client",
        "clientSecret": "private-client-secret",
        "authRegion": state["binding"]["region"],
        "apiRegion": state["binding"]["api_region"],
        "startUrl": state["binding"]["portal"],
        "userId": state["expected_user_id"],
        "username": state["username"],
        "password": state["credential"]["current"],
        "profile": {
            "arn": state["binding"]["profile_arn"],
            "profileName": "Actual profile",
        },
        "usage": {
            "limits": [],
            "daysUntilReset": 7,
            "usageBreakdownList": [],
            "userInfo": {},
        },
    }


class DoneAuth(EnterpriseAuth):
    def _advance(self, state, answer):
        state.update(status="done", stage="done", result=native_result(state))


def drain(native=DoneAuth, gateway=Gateway, limit=20):
    from app.auth_jobs import run_one

    for _ in range(limit):
        if not run_one(
            gateway_factory=gateway, auth_factory=native, identity_factory=native
        ):
            return
    pytest.fail("worker did not quiesce")


def test_owner_isolation_and_admin_record_permissions(alice, bob, admin):
    a, b = record(), record(3)
    response = admission(alice, [a])
    assert response.status_code == 202, response.text
    batch = response.json()
    assert admission(alice, [b]).status_code == 404
    assert admission(bob, [a]).status_code == 404
    assert bob.get("/api/auth-batches/" + batch["id"]).status_code == 404
    assert admin.get("/api/auth-batches/" + batch["id"]).status_code == 404
    assert admission(admin, [b]).status_code == 202
    assert bob.get("/api/auth-batches").json()["items"] == []
    for path in ("download", "cancel"):
        assert bob.post(f"/api/auth-batches/{batch['id']}/{path}").status_code == 404
    for path in ("challenge", "image"):
        assert (
            bob.get(
                f"/api/auth-batches/{batch['id']}/items/{a.id}/{path}?revision=1"
            ).status_code
            == 404
        )


def test_zip_lifecycle_private_array_and_single_use(alice, monkeypatch):
    r = record(username="export-user", credential_state="permanent")
    response = admission(alice, [r])
    assert response.status_code == 202, response.text
    batch = response.json()
    assert alice.post(f"/api/auth-batches/{batch['id']}/download").status_code == 409
    drain()
    from app.models import AuthSecret

    with SessionLocal() as db:
        sidecar = db.scalar(select(AuthSecret))
        assert (
            sidecar.result_encrypted
            and "private-access-token" not in sidecar.result_encrypted
        )
    public = alice.get("/api/auth-batches/" + batch["id"])
    assert "private-" not in public.text
    assert public.json()["states"]["completed"] == 1

    # ZIP/JSON delivery must be entirely in memory.
    def reject_file(*args, **kw):
        raise AssertionError("export attempted a file write")

    monkeypatch.setattr("tempfile.NamedTemporaryFile", reject_file)
    download = alice.post(f"/api/auth-batches/{batch['id']}/download")
    assert download.status_code == 200, download.text
    assert download.headers["cache-control"] == "no-store"
    assert download.headers["x-export-count"] == "1"
    assert download.headers["content-disposition"].startswith('attachment; filename="')
    with zipfile.ZipFile(io.BytesIO(download.content)) as archive:
        assert archive.namelist() == ["export-user.json"]
        exported = json.loads(archive.read("export-user.json"))
    assert isinstance(exported, list) and len(exported) == 1
    item = exported[0]
    assert item["accessToken"] == "private-access-token"
    assert item["password"] == "OldOTP1!"
    assert item["provider"] == "Enterprise" and item["authMethod"] == "IdC"
    assert item["region"] == item["authRegion"] == "us-east-1"
    assert item["apiRegion"] == "us-east-1"
    assert item["machineId"] == ""
    assert item["kiro_profile_raw"] == {
        "nextToken": None,
        "profiles": [
            native_result(
                {
                    "binding": {
                        "region": "",
                        "api_region": "",
                        "portal": "",
                        "profile_arn": "arn:aws:codewhisperer:us-east-1:123456789012:profile/TEST",
                    },
                    "expected_user_id": "",
                    "username": "",
                    "credential": {"current": ""},
                }
            )["profile"]
        ],
    }
    assert item["usageData"] == item["kiro_usage_raw"]
    with SessionLocal() as db:
        s = db.scalar(select(AuthSecret))
        assert not s.result_encrypted and not s.workflow_encrypted
    assert alice.post(f"/api/auth-batches/{batch['id']}/download").status_code == 410


def test_auth_admission_csrf_and_all_or_none(alice):
    a, b = record(), record(3)
    assert admission(alice, [a, b]).status_code == 404
    with SessionLocal() as db:
        assert db.get(Subscription, a.id).active_operation_id is None
    token = alice.headers.pop("X-CSRF-Token")
    assert admission(alice, [a]).status_code == 403
    alice.headers["X-CSRF-Token"] = token
    assert admission(alice, [a]).status_code == 202


def test_idempotency_hmac_custom_payload_and_lifecycle_exclusion(alice):
    from app.lifecycle import claim_operation
    from app.models import AuthBatch, AuthSecret, RecordOperation

    r = record()
    key = str(uuid.uuid4())
    first = admission(
        alice, [r], "custom_password", request_key=key, password="CustomPassword9!"
    )
    assert first.status_code == 202
    assert (
        admission(
            alice, [r], "custom_password", request_key=key, password="CustomPassword9!"
        ).json()["id"]
        == first.json()["id"]
    )
    assert (
        admission(
            alice, [r], "custom_password", request_key=key, password="Different9!"
        ).status_code
        == 409
    )
    with SessionLocal() as db:
        batch = db.scalar(select(AuthBatch))
        op = db.scalar(select(RecordOperation))
        secret = db.scalar(select(AuthSecret))
        assert (
            "CustomPassword9!"
            not in op.payload + batch.fingerprint + secret.payload_encrypted
        )
        assert decrypt(secret.payload_encrypted) == {"password": "CustomPassword9!"}
        import hashlib

        assert batch.fingerprint != hashlib.sha256(b"CustomPassword9!").hexdigest()
    assert claim_operation() is None


@pytest.mark.parametrize(
    "password",
    [
        "shortA1!",
        "lowercaseonly1!",
        "UPPERCASEONLY1!",
        "NoDigitsPassword!",
        "NoSymbols123",
        "A1!" + "x" * 62,
        "A1! xxxxx",
    ],
)
def test_custom_password_policy(alice, password):
    # shortA1! is exactly eight and valid; the remaining cases are invalid.
    expected = 202 if password == "shortA1!" else 422
    assert (
        admission(alice, [record()], "custom_password", password=password).status_code
        == expected
    )


def test_group_preview_and_frozen_explicit_membership(alice, bob):
    from app.models import ManagedGroup

    a, b = record(), record()
    with SessionLocal() as db:
        group = ManagedGroup(
            id=str(uuid.uuid4()),
            owner_id=2,
            aws_account_id=1,
            aws_scope="scope",
            request_key=str(uuid.uuid4()),
            payload_hash="h",
            name="group",
            marker="m",
            state="ready",
        )
        db.add(group)
        db.flush()
        for r in (a, b):
            db.get(Subscription, r.id).group_id = group.id
        db.commit()
        gid = group.id
    assert (
        bob.get("/api/auth-batches/preview", params={"group_id": gid}).status_code
        == 404
    )
    preview = alice.get("/api/auth-batches/preview", params={"group_id": gid}).json()
    assert set(preview["record_ids"]) == {a.id, b.id}
    with SessionLocal() as db:
        db.get(Subscription, b.id).group_id = None
        db.commit()
    assert admission(alice, [a, b], group_id=gid).status_code == 409
    batch = admission(alice, [a], group_id=gid).json()
    with SessionLocal() as db:
        db.get(Subscription, b.id).group_id = gid
        db.commit()
    assert [
        x["record_id"]
        for x in alice.get("/api/auth-batches/" + batch["id"]).json()["items"]
    ] == [a.id]


class ChallengeAuth(DoneAuth):
    def _advance(self, state, answer):
        if state.get("waiting"):
            assert answer == {"captchaGuess": "human-only", "captchaCES": "secret-ces"}
            assert state["cookies"] == [{"private-cookie": "same-cookie"}]
            return super()._advance(state, answer)
        state["waiting"] = True
        state["cookies"] = [{"private-cookie": "same-cookie"}]
        self._challenge(
            state,
            {
                "captchaURL": "https://us-east-1.signin.aws/platform/captcha/test",
                "captchaCES": "secret-ces",
            },
        )


def test_challenge_owner_revision_csrf_encrypted_answer_same_workflow(alice, bob):
    from app.models import AuthSecret

    r = record()
    batch = admission(alice, [r]).json()
    drain(ChallengeAuth)
    base = f"/api/auth-batches/{batch['id']}/items/{r.id}"
    response = alice.get(base + "/challenge")
    assert response.status_code == 200, response.text
    challenge = response.json()
    assert challenge["kind"] == "image"
    assert "secret-ces" not in response.text and "same-cookie" not in response.text
    answer = {
        "challenge_id": challenge["id"],
        "revision": challenge["revision"],
        "guess": "human-only",
    }
    assert bob.post(base + "/resume", json=answer).status_code == 404
    assert alice.post(base + "/resume", json=answer | {"revision": -1}).status_code in (
        409,
        422,
    )
    token = alice.headers.pop("X-CSRF-Token")
    assert alice.post(base + "/resume", json=answer).status_code == 403
    alice.headers["X-CSRF-Token"] = token
    assert alice.post(base + "/resume", json=answer).status_code == 202
    assert alice.post(base + "/resume", json=answer).status_code == 409
    with SessionLocal() as db:
        saved = db.scalar(select(AuthSecret))
        assert "human-only" not in saved.answer_encrypted
        assert decrypt(saved.answer_encrypted) == answer
    drain(ChallengeAuth)
    assert (
        alice.get("/api/auth-batches/" + batch["id"]).json()["states"]["completed"] == 1
    )


class PasswordAuth:
    """Use real checkpoint/event handling with a deterministic local adapter."""

    def __new__(cls, *args, **kwargs):
        from app.identity_login import NativeIdentityLogin

        class Change(NativeIdentityLogin):
            def _advance(self, state, answer):
                candidate = state["target_password"]
                state["credential"].update(candidate=candidate, status="candidate")
                self._emit(state, "password_candidate", credential=True)
                with SessionLocal() as db:
                    saved = db.scalar(
                        select(Subscription).where(
                            Subscription.username == state["username"]
                        )
                    )
                    assert (
                        decrypt(saved.credential_recovery_encrypted)["candidate"]
                        == candidate
                    )
                state["credential"]["status"] = "unknown"
                state["inflight"] = "password_change"
                self._emit(state, "password_pending", credential=True)
                PasswordAuth.after_pending(state)
                state["credential"].update(current=candidate, status="confirmed")
                state["inflight"] = None
                self._emit(state, "password_confirmed", credential=True)
                state.update(
                    status="done", stage="done", result={"password": candidate}
                )

        return Change(*args, **kwargs)

    after_pending = staticmethod(lambda state: None)


def test_permanent_password_resets_once_then_confirmed_and_subscription_unchanged(
    alice, monkeypatch
):
    r = record(subscription_type="original-plan", subscribed_at=now(), counted=True)
    original_time = r.subscribed_at
    Gateway.resets = 0
    batch = admission(alice, [r], "custom_password", password="ChosenPassword9!").json()
    drain(PasswordAuth)
    assert Gateway.resets == 1
    assert (
        alice.get("/api/auth-batches/" + batch["id"]).json()["states"]["completed"] == 1
    )
    credentials = alice.post(f"/api/subscriptions/{r.id}/credentials").json()
    assert (
        credentials["password"] == "ChosenPassword9!"
        and credentials["credential_state"] == "permanent"
    )
    with SessionLocal() as db:
        saved = db.get(Subscription, r.id)
        assert saved.subscription_type == "original-plan" and saved.counted
        assert saved.subscribed_at == original_time and saved.group_id is None


def test_uncertain_candidate_survives_cancel_expiry_and_is_never_exposed(
    alice, monkeypatch
):
    from app.auth_batches import close_batch
    from app.models import AuthBatch, AuthSecret

    def lost(state):
        raise AuthError("transport_failed", uncertain=True)

    monkeypatch.setattr(PasswordAuth, "after_pending", staticmethod(lost))
    r = record()
    batch = admission(
        alice, [r], "custom_password", password="UncertainPassword9!"
    ).json()
    drain(PasswordAuth)
    assert (
        alice.get("/api/auth-batches/" + batch["id"]).json()["states"]["needs_review"]
        == 1
    )
    creds = alice.post(f"/api/subscriptions/{r.id}/credentials")
    assert creds.status_code == 409 and "UncertainPassword9!" not in creds.text
    assert not alice.get("/api/subscriptions/" + r.id).json()["has_password"]
    assert alice.post("/api/auth-batches/" + batch["id"] + "/cancel").status_code == 200
    with SessionLocal() as db:
        saved = db.get(Subscription, r.id)
        assert saved.credential_state == "unknown"
        assert (
            decrypt(saved.credential_recovery_encrypted)["candidate"]
            == "UncertainPassword9!"
        )
        secret = db.scalar(select(AuthSecret))
        assert not any(
            (
                secret.payload_encrypted,
                secret.workflow_encrypted,
                secret.answer_encrypted,
                secret.result_encrypted,
            )
        )
        close_batch(db, db.get(AuthBatch, batch["id"]), "expired")
        db.commit()
    fresh = admission(alice, [r], "reset_password")
    assert fresh.status_code == 202
    drain()
    with SessionLocal() as db:
        saved = db.get(Subscription, r.id)
        assert (
            saved.credential_state == "one_time"
            and saved.credential_recovery_encrypted is None
        )


def test_confirmed_password_persisted_after_actor_revoked(alice, monkeypatch):
    from app.models import AuthSecret, User

    def revoke(state):
        with SessionLocal() as db:
            db.get(User, 2).session_version += 1
            db.commit()

    monkeypatch.setattr(PasswordAuth, "after_pending", staticmethod(revoke))
    r = record()
    admission(alice, [r], "custom_password", password="ConfirmedPassword9!")
    drain(PasswordAuth)
    with SessionLocal() as db:
        saved = db.get(Subscription, r.id)
        assert saved.credential_state == "permanent"
        assert decrypt(saved.password_encrypted) == "ConfirmedPassword9!"
        secret = db.scalar(select(AuthSecret))
        assert not secret.result_encrypted and not secret.workflow_encrypted
    assert alice.post(f"/api/subscriptions/{r.id}/credentials").status_code == 401


def test_cancel_inflight_keeps_lock_and_late_confirmed_password(alice, monkeypatch):
    r = record()
    batch = admission(
        alice, [r], "custom_password", password="ConfirmedPassword9!"
    ).json()

    def cancel_inflight(state):
        assert (
            alice.post("/api/auth-batches/" + batch["id"] + "/cancel").status_code
            == 200
        )
        with SessionLocal() as db:
            assert db.get(Subscription, r.id).active_operation_id
        assert admission(alice, [r], "reset_password").status_code == 409

    monkeypatch.setattr(PasswordAuth, "after_pending", staticmethod(cancel_inflight))
    drain(PasswordAuth)
    with SessionLocal() as db:
        saved = db.get(Subscription, r.id)
        assert saved.credential_state == "permanent"
        assert decrypt(saved.password_encrypted) == "ConfirmedPassword9!"
        assert saved.active_operation_id is None


def test_lost_otp_response_no_automatic_replay_explicit_retry(alice):
    from app.aws import AwsFailure

    class LostOTP(Gateway):
        def password(self, record):
            type(self).resets += 1
            raise AwsFailure("SECRET RESPONSE MUST NOT LEAK", uncertain=True)

    r = record()
    batch = admission(alice, [r], "random_password").json()
    LostOTP.resets = 0
    drain(gateway=LostOTP)
    result = alice.get("/api/auth-batches/" + batch["id"])
    assert result.json()["states"]["needs_review"] == 1
    assert "SECRET RESPONSE" not in result.text
    assert LostOTP.resets == 1
    base = f"/api/auth-batches/{batch['id']}/items/{r.id}"
    assert alice.post(base + "/retry", json={"mode": "resume"}).status_code == 409
    assert alice.post(base + "/retry", json={"mode": "new_reset"}).status_code == 202
    drain(PasswordAuth)
    assert (
        alice.get("/api/auth-batches/" + batch["id"]).json()["states"]["completed"] == 1
    )


def test_reset_and_delete_fence_old_auth_result(alice):
    from app.lifecycle import run_operation
    from test_lifecycle import LifecycleGateway, operation
    from app.models import AuthSecret

    r = record()
    batch = admission(alice, [r]).json()
    drain()
    with SessionLocal() as db:
        old_revision = db.get(Subscription, r.id).credential_revision
    LifecycleGateway.exists, LifecycleGateway.failure = True, None
    operation(alice, {"id": r.id, "username": r.username}, "reset_password")
    run_operation(LifecycleGateway)
    with SessionLocal() as db:
        saved = db.get(Subscription, r.id)
        assert saved.credential_revision > old_revision
        assert saved.credential_state == "one_time"
        assert db.scalar(select(AuthSecret)).result_encrypted is None
    assert (
        alice.post("/api/auth-batches/" + batch["id"] + "/download").status_code == 409
    )


def test_duplicate_worker_even_expired_lease_is_fenced_by_process_lock(alice):
    import concurrent.futures
    import threading
    from app.auth_jobs import run_one
    from app.models import RecordOperation

    entered, release = threading.Event(), threading.Event()

    class Waiting(DoneAuth):
        def _advance(self, state, answer):
            entered.set()
            assert release.wait(3)
            super()._advance(state, answer)

    r = record()
    admission(alice, [r])
    assert run_one(Gateway, Waiting)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run_one, Gateway, Waiting)
        assert entered.wait(3)
        with SessionLocal() as db:
            db.scalar(select(RecordOperation)).lease_until = now() - timedelta(
                seconds=1
            )
            db.commit()
        assert run_one(Gateway, Waiting) is False
        release.set()
        assert future.result()


def test_crash_after_otp_send_is_never_replayed(alice):
    from app.auth_jobs import run_one
    from app.models import RecordOperation

    class Crash(Gateway):
        calls = 0

        def password(self, r):
            type(self).calls += 1
            raise SystemExit("synthetic process crash")

    r = record()
    batch = admission(alice, [r], "reset_password").json()
    with pytest.raises(SystemExit):
        run_one(Crash)
    with SessionLocal() as db:
        op = db.scalar(select(RecordOperation))
        assert op.phase == "pending"
        op.lease_until = now() - timedelta(seconds=1)
        db.commit()
    assert run_one(Crash)
    assert Crash.calls == 1
    item = alice.get("/api/auth-batches/" + batch["id"]).json()["items"][0]
    assert item["requires_new_reset"] and item["error_code"] == "reset_unconfirmed"
    assert (
        alice.get("/api/auth-batches/" + batch["id"]).json()["states"]["needs_review"]
        == 1
    )


def test_native_password_confirmation_survives_oauth_failure(alice):
    class AcceptedThenOAuthFailed(DoneAuth):
        def _advance(self, state, answer):
            state["credential"].update(
                candidate="RealConfirmedPassword9!", status="unknown"
            )
            self._emit(state, "password_pending", credential=True)
            state["credential"].update(
                current="RealConfirmedPassword9!", status="confirmed"
            )
            self._emit(state, "password_confirmed", credential=True)
            raise AuthError("oauth_failed")

    r = record()
    batch = admission(alice, [r]).json()
    drain(AcceptedThenOAuthFailed)
    assert alice.get("/api/auth-batches/" + batch["id"]).json()["states"]["failed"] == 1
    assert (
        alice.post(f"/api/subscriptions/{r.id}/credentials").json()["password"]
        == "RealConfirmedPassword9!"
    )
    with SessionLocal() as db:
        assert db.get(Subscription, r.id).credential_recovery_encrypted is None


def test_active_batch_does_not_expire_early_success_then_short_window_purges(alice):
    from app.auth_jobs import expire_batches
    from app.models import AuthBatch, AuthJob, AuthSecret

    a, b = record(), record()
    batch = admission(alice, [a, b]).json()

    # Complete only first item and leave another user awaiting a human.
    class Mixed(ChallengeAuth):
        def _advance(self, state, answer):
            if state["username"] == a.username:
                return DoneAuth._advance(self, state, answer)
            return super()._advance(state, answer)

    drain(Mixed)
    with SessionLocal() as db:
        saved = db.get(AuthBatch, batch["id"])
        assert saved.completed_at is None and saved.download_expires_at is None
        first_job = db.scalar(select(AuthJob).where(AuthJob.record_id == a.id))
        assert db.get(AuthSecret, first_job.id).result_encrypted
    alice.post(f"/api/auth-batches/{batch['id']}/items/{b.id}/cancel")
    with SessionLocal() as db:
        saved = db.get(AuthBatch, batch["id"])
        assert saved.completed_at and saved.download_expires_at
        saved.download_expires_at = now() - timedelta(seconds=1)
        db.commit()
    expire_batches()
    with SessionLocal() as db:
        assert db.get(AuthBatch, batch["id"]).state == "expired"
        assert not db.get(AuthSecret, first_job.id).result_encrypted
    assert alice.post(f"/api/auth-batches/{batch['id']}/download").status_code == 410


def test_partial_zip_counts_collisions_paths_and_cross_region(alice):
    from app.auth_export import build_zip

    a, b, bad = (
        record(username="shared-name"),
        record(username="other"),
        record(username="failed"),
    )
    with SessionLocal() as db:
        db.get(AwsAccount, 1).region = "eu-west-1"
        db.commit()

    class Partial(DoneAuth):
        def _advance(self, state, answer):
            if state["username"] == "failed":
                raise AuthError("no_profile")
            super()._advance(state, answer)

    batch = admission(alice, [a, b, bad]).json()
    drain(Partial)
    response = alice.post(f"/api/auth-batches/{batch['id']}/download")
    assert response.status_code == 200
    assert (
        response.headers["x-export-count"] == "2"
        and response.headers["x-excluded-count"] == "1"
    )
    with zipfile.ZipFile(io.BytesIO(response.content)) as zipped:
        payload = json.loads(zipped.read("shared-name.json"))[0]
        assert payload["authRegion"] == payload["region"] == "eu-west-1"
        assert payload["apiRegion"] == "us-east-1"
    # Same basenames across AWS accounts keep the exact username basename in
    # stable account/record subdirectories; traversal-shaped names are sanitized.
    b.username = a.username
    b.aws_account_id = 2
    fake = lambda r: encrypt(
        native_result(
            {
                "binding": {
                    "region": "eu-west-1",
                    "api_region": "us-east-1",
                    "portal": r.portal_url,
                    "profile_arn": "actual-arn",
                },
                "username": r.username,
                "expected_user_id": r.sso_user_id,
                "credential": {"current": "pw"},
            }
        )
    )
    content = build_zip([(a, fake(a)), (b, fake(b))])
    with zipfile.ZipFile(io.BytesIO(content)) as zipped:
        assert set(zipped.namelist()) == {
            f"1/{a.id}/shared-name.json",
            f"2/{b.id}/shared-name.json",
        }
    a.username = "../../escape\\name"
    with zipfile.ZipFile(io.BytesIO(build_zip([(a, fake(a))]))) as zipped:
        assert all("/" not in name and "\\" not in name for name in zipped.namelist())


@pytest.mark.parametrize("revocation", ["binding", "account", "ownership", "session"])
def test_revalidate_permissions_before_worker_and_download(alice, revocation):
    from app.models import Binding, User

    a, b = record(), record()
    completed = admission(alice, [a]).json()
    drain()
    pending = admission(alice, [b]).json()
    with SessionLocal() as db:
        if revocation == "binding":
            db.delete(db.get(Binding, (2, 1)))
        elif revocation == "account":
            db.get(AwsAccount, 1).active = False
        elif revocation == "ownership":
            db.get(Subscription, a.id).owner_id = db.get(
                Subscription, b.id
            ).owner_id = 3
        else:
            db.get(User, 2).session_version += 1
        db.commit()

    class NoNetwork(Gateway):
        def __init__(self, a):
            raise AssertionError("revoked job constructed gateway")

    drain(gateway=NoNetwork)
    assert alice.post(
        "/api/auth-batches/" + completed["id"] + "/download"
    ).status_code in (401, 403, 404)
    from app.models import AuthJob, RecordOperation

    with SessionLocal() as db:
        job = db.scalar(select(AuthJob).where(AuthJob.batch_id == pending["id"]))
        assert db.get(RecordOperation, job.id).state == "cancelled"


def test_proxy_bound_failure_never_falls_back_or_changes_password(alice):
    from app.aws import AwsFailure

    class NoProxy(Gateway):
        resets = 0

        def _check_proxy(self):
            raise AwsFailure("proxy unavailable")

    r = record()
    batch = admission(alice, [r], "random_password").json()
    drain(gateway=NoProxy)
    assert NoProxy.resets == 0
    with SessionLocal() as db:
        assert decrypt(db.get(Subscription, r.id).password_encrypted) == "OldOTP1!"
    assert alice.get("/api/auth-batches/" + batch["id"]).json()["states"]["failed"] == 1


def test_csv_and_login_unknown_and_permanent_types(alice):
    import csv

    a, b = record(), record()
    with SessionLocal() as db:
        db.get(Subscription, a.id).credential_state = "unknown"
        db.get(Subscription, b.id).credential_state = "permanent"
        db.commit()
    assert alice.post(f"/api/subscriptions/{a.id}/credentials").status_code == 409
    response = alice.post("/api/sso-users/export", json={"record_ids": [a.id, b.id]})
    assert response.status_code == 200, response.text
    rows = list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))
    assert rows[0]["密码类型"] == "待核对" and rows[0]["密码"] == ""
    assert rows[1]["密码类型"] == "永久密码" and rows[1]["密码"] == "OldOTP1!"


def test_schema_eight_migrates_nondestructively(alice):
    from sqlalchemy import text
    from app.database import engine
    from app.init_db import initialize
    from app.models import SchemaVersion
    from app.migrations import VERSION

    r = record()
    with engine.begin() as conn:
        for table in (
            "console_auth_secrets",
            "console_auth_jobs",
            "console_auth_batches",
        ):
            conn.execute(text("DROP TABLE " + table))
        for column in (
            "credential_recovery_encrypted",
            "credential_revision",
            "credential_state",
        ):
            conn.execute(
                text("ALTER TABLE console_subscriptions DROP COLUMN " + column)
            )
        conn.execute(text("INSERT INTO console_schema_version(version) VALUES(8)"))
    initialize()
    with SessionLocal() as db:
        saved = db.get(Subscription, r.id)
        assert (
            saved.username == r.username
            and decrypt(saved.password_encrypted) == "OldOTP1!"
        )
        assert saved.credential_state == "one_time" and saved.credential_revision == 1
        assert db.scalar(select(SchemaVersion)).version == VERSION
    assert admission(alice, [r]).status_code == 202


def test_challenge_expiry_worker_clears_workflow_and_completes_partial_batch(alice):
    from app.auth_jobs import expire_batches
    from app.models import AuthSecret, AuthBatch

    r = record()
    batch = admission(alice, [r]).json()
    drain(ChallengeAuth)
    with SessionLocal() as db:
        saved = db.scalar(select(AuthSecret))
        state = decrypt(saved.workflow_encrypted)
        state["challenge"]["expires_at"] = 1
        saved.workflow_encrypted = encrypt(state)
        db.commit()
    expire_batches()
    with SessionLocal() as db:
        assert db.get(AuthBatch, batch["id"]).completed_at
        assert db.scalar(select(AuthSecret)).workflow_encrypted is None


def test_poll_schedule_prevents_early_wire_and_resume_keeps_result(alice):
    import time
    from app.auth_jobs import run_one
    from app.models import AuthJob

    class Poll(DoneAuth):
        calls = 0

        def _advance(self, state, answer):
            type(self).calls += 1
            if not state.get("polled"):
                state.update(
                    polled=True, status="polling", next_poll_at=time.time() + 100
                )
            else:
                super()._advance(state, answer)

    admission(alice, [record()])
    drain(Poll)
    assert Poll.calls == 1
    assert not run_one(Gateway, Poll)
    with SessionLocal() as db:
        db.scalar(select(AuthJob)).next_poll_at = now() - timedelta(seconds=1)
        db.commit()
    assert run_one(Gateway, Poll)
    assert Poll.calls == 2


def test_expired_export_tokens_are_excluded_and_explicit_retry_uses_refresh(alice):
    from app.models import AuthSecret

    r = record()
    batch = admission(alice, [r]).json()
    drain()
    with SessionLocal() as db:
        secret = db.scalar(select(AuthSecret))
        result = decrypt(secret.result_encrypted)
        result["expiresAt"] = 1
        secret.result_encrypted = encrypt(result)
        db.commit()
    response = alice.post("/api/auth-batches/" + batch["id"] + "/download")
    assert response.status_code == 409

    class Refreshed(DoneAuth):
        refresh_calls = 0

        def begin_refresh(self, sealed_state):
            type(self).refresh_calls += 1
            state = decrypt(sealed_state)
            state.update(status="ready", stage="refresh")
            return self._publish(state)

    base = f"/api/auth-batches/{batch['id']}/items/{r.id}"
    assert alice.post(base + "/retry", json={"mode": "resume"}).status_code == 202
    drain(Refreshed)
    assert Refreshed.refresh_calls == 1
    assert (
        alice.post("/api/auth-batches/" + batch["id"] + "/download").status_code == 200
    )


def test_unknown_credential_can_be_recovered_in_new_batch_after_cancel(
    alice, monkeypatch
):
    def lost(state):
        raise AuthError("transport_failed", uncertain=True)

    monkeypatch.setattr(PasswordAuth, "after_pending", staticmethod(lost))
    r = record()
    old = admission(
        alice, [r], "custom_password", password="RecoverablePassword9!"
    ).json()
    drain(PasswordAuth)
    alice.post("/api/auth-batches/" + old["id"] + "/cancel")
    fresh = admission(alice, [r])
    assert fresh.status_code == 202

    class Recover(DoneAuth):
        def _advance(self, state, answer):
            assert state["recovering"]
            candidate = self._choose_credential(state)
            assert candidate == "RecoverablePassword9!"
            state["credential"].update(current=candidate, status="confirmed")
            self._emit(state, "password_confirmed", credential=True)
            super()._advance(state, answer)

    Gateway.resets = 0
    drain(Recover)
    assert Gateway.resets == 0
    assert (
        alice.post(f"/api/subscriptions/{r.id}/credentials").json()["password"]
        == "RecoverablePassword9!"
    )


def test_delete_already_missing_sso_invalidates_results_and_revision(alice):
    from app.models import AuthSecret
    from test_lifecycle import LifecycleGateway, cascade, drain_lifecycle

    r = record()
    admission(alice, [r])
    drain()
    with SessionLocal() as db:
        before = db.get(Subscription, r.id).credential_revision
    LifecycleGateway.exists, LifecycleGateway.failure = False, None
    LifecycleGateway.info = dict(status='not_subscribed', subscription_type=None, expires_at=None)
    response = cascade(alice, {'id': r.id})
    assert response.status_code == 202
    drain_lifecycle()
    with SessionLocal() as db:
        saved = db.get(Subscription, r.id)
        assert saved.credential_revision > before
        assert db.scalar(select(AuthSecret)).result_encrypted is None


@pytest.mark.parametrize("kind", ["reset_password", "delete_sso"])
def test_failed_lifecycle_write_keeps_unresolved_recovery_candidate(alice, kind):
    from app.aws import AwsFailure
    from app.lifecycle import run_operation
    from test_lifecycle import LifecycleGateway, cascade, drain_lifecycle, operation

    r = record()
    recovery = encrypt(
        {"candidate": "PossiblyValid9!", "current": "OldOTP1!", "status": "unknown"}
    )
    with SessionLocal() as db:
        saved = db.get(Subscription, r.id)
        saved.credential_state = "unknown"
        saved.credential_recovery_encrypted = recovery
        db.commit()

    class Denied(LifecycleGateway):
        exists = True
        info = dict(status='not_subscribed', subscription_type=None, expires_at=None)

        def password(self, r):
            raise AwsFailure("denied")

        def delete_user(self, r):
            raise AwsFailure("denied")

    result = cascade(alice, {'id': r.id}, Denied) if kind == 'delete_sso' else operation(
        alice, {'id': r.id, 'username': r.username}, kind)
    assert result.status_code == 202, result.text
    drain_lifecycle(Denied)
    with SessionLocal() as db:
        assert db.get(Subscription, r.id).credential_recovery_encrypted == recovery


def test_otp_checkpoint_restart_finishes_without_native_login_or_second_reset(
    alice, monkeypatch
):
    from app import auth_jobs
    from app.models import AuthJob, RecordOperation

    r = record()
    batch = admission(alice, [r], "reset_password").json()
    real_finish = auth_jobs.finish_step

    def crash(*args):
        raise SystemExit("crash after durable OTP confirmation")

    monkeypatch.setattr(auth_jobs, "finish_step", crash)
    Gateway.resets = 0
    with pytest.raises(SystemExit):
        auth_jobs.run_one(Gateway)
    with SessionLocal() as db:
        job = db.scalar(select(AuthJob))
        assert job.reset_state == "done"
        db.get(RecordOperation, job.id).lease_until = now() - timedelta(seconds=1)
        db.commit()
    monkeypatch.setattr(auth_jobs, "finish_step", real_finish)

    class NoLogin:
        def __init__(self, *args, **kwargs):
            raise AssertionError("OTP job must never enter permanent login flow")

    assert auth_jobs.run_one(Gateway, identity_factory=NoLogin)
    assert Gateway.resets == 1
    assert (
        alice.get("/api/auth-batches/" + batch["id"]).json()["states"]["completed"] == 1
    )
