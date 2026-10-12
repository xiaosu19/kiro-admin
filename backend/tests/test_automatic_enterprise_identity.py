"""Private AMS answers keep native password and identity checks authoritative."""

import pytest

from app.enterprise_auth import EnterpriseAuth
from app.identity_login import AuthError
from app.security import decrypt
from test_enterprise_auth import Oidc, external_setup
from test_identity_login import (
    CDN,
    DP,
    EXECUTE,
    NOW,
    Gateway,
    Script,
    ams_token,
    key_context as key_context,
    opening,
    run_ready,
    success,
    workflow,
)


def private_answer(progress):
    original = decrypt(progress.sealed_state)["automation_challenge"]
    return {
        "challenge_id": original["id"],
        "revision": original["revision"],
        "access_code": "synthetic-official-completion",
    }


def test_private_ams_answer_restores_native_login_and_preserves_saved_password(
    monkeypatch, key_context
):
    adapter, paused, script, events, _ = external_setup(monkeypatch, key_context[1])
    initial = decrypt(paused.sealed_state)
    assert paused.challenge["kind"] == "aws_authorization"
    assert "redemption_token" not in paused.challenge
    assert "script_url" not in paused.challenge

    def inspect_submission(request):
        assert request["json"]["captchaRequest"] == {
            "captchaAccessCode": "synthetic-official-completion"
        }
        assert request["json"]["stepId"] == "get-password"

    script.add("POST", EXECUTE, success(), inspect=inspect_submission)
    progress = adapter.advance(paused.sealed_state, answer=private_answer(paused))
    state = decrypt(progress.sealed_state)

    assert progress.status == "ready" and progress.stage == "exchange"
    assert state["credential"]["current"] == initial["credential"]["current"]
    assert state["credential"]["status"] == initial["credential"]["status"]
    assert state["expected_user_id"] == initial["expected_user_id"]
    assert state["credential"]["tried"] == ["current"]
    assert not state.get("external_authorization")
    assert "automation_challenge" not in state and state["challenge"] is None
    assert progress.result is None
    assert "external_authorization" not in [event.event for event in events]
    assert not script.steps


def test_private_ams_completion_cannot_skip_wrong_whoami_identity(
    monkeypatch, key_context
):
    adapter, paused, script, _, _ = external_setup(monkeypatch, key_context[1])
    script.add("POST", EXECUTE, success())
    script.add("POST", DP + "/auth/sso-token", {"token": "synthetic-portal-token"})
    script.add(
        "GET",
        DP + "/token/whoAmI",
        {"userIdentifier": "another-user", "directoryId": "d-1234567890"},
    )

    resumed = adapter.advance(paused.sealed_state, answer=private_answer(paused))
    with pytest.raises(AuthError) as caught:
        run_ready(adapter, resumed)

    assert caught.value.code == "identity_mismatch"
    failed = decrypt(caught.value.sealed_state)
    assert not failed.get("result")
    assert not failed.get("external_authorization")
    assert script.calls[-1][1] == DP + "/token/whoAmI"
    assert all(call[1] != DP + "/session/device" for call in script.calls)
    assert all(operation != "token" for operation, _ in adapter.gateway.oidc.calls)


def test_private_ams_resume_keeps_password_confirmation_before_later_identity_failure(
    monkeypatch, key_context
):
    gateway = Gateway()
    gateway.oidc = Oidc()
    page = workflow(
        "get-new-password-for-change-password",
        key_context[1],
        {"captchaToken": ams_token(), "captchaCDN": CDN},
    )
    script = opening(Script(monkeypatch, gateway), page)
    events = []
    adapter = EnterpriseAuth(gateway, checkpoint=events.append, clock=lambda: NOW)
    paused = run_ready(
        adapter,
        adapter.begin(
            "alice",
            "synthetic-one-time-password",
            expected_user_id="user-synthetic",
            target_password="Replacement9!",
        ),
    )
    script.add("POST", EXECUTE, success())
    script.add("POST", DP + "/auth/sso-token", {"token": "synthetic-portal-token"})
    script.add(
        "GET",
        DP + "/token/whoAmI",
        {"userIdentifier": "another-user", "directoryId": "d-1234567890"},
    )

    resumed = adapter.advance(paused.sealed_state, answer=private_answer(paused))
    kinds = [event.event for event in events]
    assert kinds.index("password_candidate") < kinds.index("password_pending")
    assert kinds.index("password_pending") < kinds.index("password_confirmed")
    pending = next(event for event in events if event.event == "password_pending")
    confirmed = next(event for event in events if event.event == "password_confirmed")
    assert decrypt(pending.credential)["status"] == "unknown"
    saved = decrypt(confirmed.credential)
    assert saved["current"] == "Replacement9!" and saved["status"] == "confirmed"
    assert not decrypt(resumed.sealed_state)["password_write_pending"]

    with pytest.raises(AuthError) as caught:
        run_ready(adapter, resumed)
    assert caught.value.code == "identity_mismatch"
    assert decrypt(caught.value.credential) == saved
    assert not decrypt(caught.value.sealed_state).get("result")
    assert [event.event for event in events].count("password_pending") == 1
    assert sum(call[1] == EXECUTE for call in script.calls) == 1
    assert all(call[1] != DP + "/session/device" for call in script.calls)
