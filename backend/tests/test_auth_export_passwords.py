"""JSON credentials require a durable permanent-password confirmation."""

import io
import json
import zipfile

import pytest

from app.auth_credentials import apply_credential
from app.auth_export import account_json, build_zip
from app.database import SessionLocal
from app.identity_login import NativeIdentityLogin
from app.models import Subscription
from app.security import decrypt, encrypt
from test_auth_batches import native_result, record
from test_enterprise_auth import Oidc, add_profile, advance_poll, setup
from test_identity_login import key_context as key_context, run_ready


def result_for(row):
    return native_result({
        "binding": {"region": "us-east-1", "api_region": "us-east-1",
                    "portal": row.portal_url, "profile_arn": "arn:aws:codewhisperer:us-east-1:123456789012:profile/test"},
        "expected_user_id": row.sso_user_id, "username": row.username,
        "credential": {"current": "PayloadOldOTP9!"},
    })


@pytest.mark.parametrize("state,expected", [
    ("one_time", None), ("unknown", None), ("candidate", None),
    ("permanent", "ConfirmedPermanent9!"),
])
def test_json_and_zip_only_include_confirmed_permanent_record_password(state, expected):
    row = record(credential_state=state)
    row.password_encrypted = encrypt("ConfirmedPermanent9!")
    row.credential_recovery_encrypted = encrypt({"current": "OldOTP9!", "candidate": "Pending9!", "status": "unknown"})
    result = result_for(row)
    assert account_json(row, result)[0]["password"] == expected
    with zipfile.ZipFile(io.BytesIO(build_zip([(row, encrypt(result))]))) as archive:
        exported = json.loads(archive.read(archive.namelist()[0]))
    assert exported[0]["password"] == expected
    assert exported[0]["password"] != result["password"]


def test_official_authorization_omits_even_a_saved_permanent_password():
    row = record(credential_state="permanent")
    result = result_for(row)
    result.update(externalAuthorization=True, identityStoreId="d-1234567890",
                  usage={"userInfo": {"userId": "d-1234567890." + row.sso_user_id}})
    assert account_json(row, result)[0]["password"] is None


def test_native_first_login_commits_confirmation_before_oidc_token(monkeypatch, key_context):
    row = record(username="alice", credential_state="one_time")
    with SessionLocal() as db:
        db.get(Subscription, row.id).sso_user_id = "user-synthetic"
        db.commit()
    events, token_calls = [], []

    def checkpoint(value):
        if value.credential:
            with SessionLocal() as db:
                apply_credential(db.get(Subscription, row.id), value.credential)
                db.commit()
        events.append(value.event)

    class CheckedOidc(Oidc):
        def create_token(self, **kwargs):
            assert "password_confirmed" in events
            with SessionLocal() as db:
                saved = db.get(Subscription, row.id)
                assert saved.credential_state == "permanent"
                assert decrypt(saved.password_encrypted) == "Replacement9!"
                assert saved.credential_recovery_encrypted is None
            token_calls.append(kwargs["grantType"])
            return super().create_token(**kwargs)

    adapter, progress, script, _, clock = setup(
        monkeypatch, key_context[1], first_password=True,
        client=CheckedOidc(), checkpoint=checkpoint)
    assert isinstance(adapter, NativeIdentityLogin)
    add_profile(script, adapter.gateway)
    done = run_ready(adapter, advance_poll(adapter, progress, clock))
    assert done.status == "done" and not script.steps
    assert token_calls == ["urn:ietf:params:oauth:grant-type:device_code"]
    assert events.index("password_candidate") < events.index("password_pending") < events.index("password_confirmed")
    with SessionLocal() as db:
        exported = account_json(db.get(Subscription, row.id), done.result)
    assert exported[0]["password"] == "Replacement9!"
    assert exported[0]["accessToken"] == "access-secret"
