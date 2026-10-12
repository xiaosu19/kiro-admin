"""External profile discovery must retain the real, token-backed user identity."""
import pytest
from app.external_enterprise import ExternalEnterpriseAuth, ExternalGateway
from app.identity_login import AuthError
from app.security import decrypt
from test_enterprise_auth import Oidc
from test_external_enterprise import setup
from test_identity_login import (
    CDN,
    NOW,
    Gateway,
    Script,
    ams_token,
    opening,
    run_ready,
    workflow,
)
from test_identity_login import (
    key_context as key_context,
)


def finish(adapter, progress, clock):
    progress = run_ready(adapter, progress)
    assert progress.status == "polling"
    clock[0] = progress.next_poll_at
    return run_ready(adapter, adapter.advance(progress.sealed_state))


def test_empty_us_profiles_fall_back_to_real_eu_profile_without_reauth(monkeypatch, key_context):
    adapter, progress, script, clock = setup(monkeypatch, key_context[1])
    profile = {
        "arn": "arn:aws:codewhisperer:eu-central-1:123456789012:profile/actual-eu",
        "profileName": "Actual EU AWS profile", "identityDetails": None,
    }
    usage = {"userInfo": {"userId": "d-1234567890.actual-sso-id", "email": "actual@example.test"}}
    script.add("POST", "https://management.us-east-1.kiro.dev/ListAvailableProfiles", {"profiles": []})
    script.add("POST", "https://management.eu-central-1.kiro.dev/ListAvailableProfiles", {"profiles": [profile]})
    script.add("GET", "https://management.eu-central-1.kiro.dev/getUsageLimits", usage)

    done = finish(adapter, progress, clock)
    assert done.status == "done" and not script.steps
    assert done.result["authRegion"] == "us-east-1" and done.result["apiRegion"] == "eu-central-1"
    assert done.result["profile"] == profile and done.result["usage"] == usage
    assert done.result["userId"] == "actual-sso-id"
    assert done.result["accessToken"] == "access-secret"
    assert [name for name, _ in adapter.gateway.oidc.calls] == ["register", "device", "token"]


def test_pinned_eu_profile_selects_its_real_region_without_requiring_duplicate_api_region():
    from types import SimpleNamespace
    gateway = ExternalGateway(SimpleNamespace(id="external-item", region="us-east-1",
        portal_url="https://d-1234567890.awsapps.com/start"), {
        "directory": "d-1234567890", "profile_arn": "arn:aws:codewhisperer:eu-central-1:123456789012:profile/actual-eu",
    }, lambda: None)
    assert gateway.account.region == "us-east-1" and gateway.account.subscription_region == "eu-central-1"


@pytest.mark.parametrize("usage", [
    {"userInfo": {"userId": "d-9999999999.actual-sso-id"}},
    {"userInfo": {"userId": "d-1234567890.some-other-user"}},
    {"userInfo": {"userId": "actual-sso-id"}},
    {"userInfo": {"email": "actual@example.test"}},
    {"userInfo": None},
])
def test_usage_wrong_directory_or_user_never_produces_success(monkeypatch, key_context, usage):
    adapter, progress, script, clock = setup(monkeypatch, key_context[1])
    profile = {
        "arn": "arn:aws:codewhisperer:us-east-1:123456789012:profile/actual",
        "profileName": "Actual AWS profile",
    }
    script.add("POST", "https://management.us-east-1.kiro.dev/ListAvailableProfiles", {"profiles": [profile]})
    script.add("GET", "https://management.us-east-1.kiro.dev/getUsageLimits", usage)

    with pytest.raises(AuthError) as caught:
        finish(adapter, progress, clock)
    assert caught.value.code == "identity_mismatch" and not script.steps
    state = decrypt(caught.value.sealed_state)
    assert state["status"] == "failed" and not state.get("result")
    assert state["expected_user_id"] == "actual-sso-id"


def manual_challenge(monkeypatch, context, expected_user_id):
    gateway = Gateway()
    gateway.account.instance_arn = gateway.account.profile_arn = None
    gateway.account.subscription_region = "us-east-1"
    gateway.oidc = Oidc()
    page = workflow("get-password", context, {"captchaToken": ams_token(), "captchaCDN": CDN})
    script = opening(Script(monkeypatch, gateway), page)
    clock, events = [NOW], []
    adapter = ExternalEnterpriseAuth(gateway, checkpoint=events.append, clock=lambda: clock[0])
    paused = run_ready(adapter, adapter.begin("alice", "synthetic-otp", expected_user_id=expected_user_id))
    assert paused.status == "challenge"
    answer = {"challenge_id": paused.challenge["id"], "revision": paused.challenge["revision"],
              "continue_authorization": True}
    return adapter, paused, answer, script, events, clock


def test_known_user_manual_authorization_continues_existing_device_without_old_password(monkeypatch, key_context):
    adapter, paused, answer, script, events, clock = manual_challenge(monkeypatch, key_context[1], "actual-sso-id")
    assert paused.challenge["kind"] == "aws_authorization"
    before_login_calls = len(script.calls)
    profile = {"arn": "arn:aws:codewhisperer:us-east-1:123456789012:profile/actual", "profileName": "Actual"}
    script.add("POST", "https://management.us-east-1.kiro.dev/ListAvailableProfiles", {"profiles": [profile]})
    script.add("GET", "https://management.us-east-1.kiro.dev/getUsageLimits",
               {"userInfo": {"userId": "d-1234567890.actual-sso-id"}})
    polling = adapter.advance(paused.sealed_state, answer=answer)
    assert polling.status == "polling" and len(script.calls) == before_login_calls
    checkpoint = [event for event in events if event.event == "external_authorization"]
    assert len(checkpoint) == 1 and decrypt(checkpoint[0].credential)["current"] is None
    clock[0] = polling.next_poll_at
    done = run_ready(adapter, adapter.advance(polling.sealed_state))
    assert done.status == "done" and not script.steps
    assert done.result["userId"] == "actual-sso-id" and done.result["password"] is None
    assert done.result["externalAuthorization"] is True
    assert adapter.gateway.oidc.calls[-1][1]["deviceCode"] == "our-device"


def test_manual_authorization_without_known_user_identity_is_not_offered_or_polled(monkeypatch, key_context):
    adapter, paused, answer, script, _, _ = manual_challenge(monkeypatch, key_context[1], None)
    assert paused.challenge["kind"] == "requires_action"
    assert "authorization_url" not in paused.challenge and "user_code" not in paused.challenge
    before_login_calls, before_oidc_calls = len(script.calls), len(adapter.gateway.oidc.calls)
    with pytest.raises(AuthError) as caught:
        adapter.advance(paused.sealed_state, answer=answer)
    assert caught.value.code == "identity_mismatch"
    assert len(script.calls) == before_login_calls and len(adapter.gateway.oidc.calls) == before_oidc_calls
