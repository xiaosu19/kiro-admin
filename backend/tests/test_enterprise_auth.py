"""Cross-region OAuth and read-only Kiro HTTP protocol fixtures; no live AWS."""

import pytest
from botocore.exceptions import ClientError

from app.security import decrypt
from test_identity_login import (
    CDN,
    DP,
    EXECUTE,
    NOW,
    OIDC,
    PORTAL,
    Gateway,
    Script,
    key_context as key_context,
    module,
    opening,
    run_ready,
    success,
    workflow,
    ams_token,
)


class Oidc:
    def __init__(self, **overrides):
        self.calls = []
        self.registration = {
            "clientId": "our-client",
            "clientSecret": "client-secret",
            "clientSecretExpiresAt": NOW + 3600,
        }
        self.device = {
            "deviceCode": "our-device",
            "userCode": "OUR-CODE",
            "interval": 5,
            "expiresIn": 600,
            "verificationUri": "https://device.sso.us-east-1.amazonaws.com/",
        }
        self.tokens = [
            {
                "accessToken": "access-secret",
                "refreshToken": "refresh-secret",
                "expiresIn": 3600,
                "tokenType": "Bearer",
            }
        ]
        self.__dict__.update(overrides)

    def register_client(self, **kwargs):
        self.calls.append(("register", kwargs))
        return self.registration

    def start_device_authorization(self, **kwargs):
        self.calls.append(("device", kwargs))
        return self.device

    def create_token(self, **kwargs):
        self.calls.append(("token", kwargs))
        result = self.tokens.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def setup(monkeypatch, context, *, first_password=False, client=None, checkpoint=None):
    gateway = Gateway()
    gateway.oidc = client or Oidc()
    script = opening(Script(monkeypatch, gateway), workflow("get-password", context))
    if first_password:
        script.add(
            "POST", EXECUTE, workflow("get-new-password-for-change-password", context)
        )
    script.add("POST", EXECUTE, success())
    script.add("POST", DP + "/auth/sso-token", {"token": "portal-secret"})
    script.add(
        "GET",
        DP + "/token/whoAmI",
        {"userIdentifier": "user-synthetic", "directoryId": "d-1234567890"},
    )
    script.add("POST", DP + "/session/device", {"token": "session-secret"})
    script.add(
        "POST",
        OIDC + "/device_authorization/accept_user_code",
        {
            "deviceContext": {
                "deviceContextId": "our-context",
                "clientId": "our-client",
                "clientType": "public",
            },
        },
    )
    script.add("POST", OIDC + "/device_authorization/associate_token", {})
    clock = [NOW]
    events = []
    adapter = module("enterprise_auth").EnterpriseAuth(
        gateway, checkpoint=checkpoint or events.append, clock=lambda: clock[0]
    )
    progress = adapter.begin(
        "alice",
        "old-secret",
        expected_user_id="user-synthetic",
        target_password="Replacement9!",
    )
    return adapter, progress, script, events, clock


def add_profile(script, gateway, *, profiles=None, usage=None):
    profile = {
        "arn": gateway.account.profile_arn,
        "profileName": "Synthetic enterprise",
    }
    usage = (
        usage
        if usage is not None
        else {
            "usageBreakdownList": [
                {
                    "resourceType": "AGENTIC_REQUEST",
                    "currentUsage": 0,
                    "usageLimit": 1000,
                }
            ],
            "subscriptionInfo": {"subscriptionTitle": "KIRO PRO"},
        }
    )
    script.add(
        "POST",
        "https://management.eu-central-1.kiro.dev/ListAvailableProfiles",
        {"profiles": profiles if profiles is not None else [profile]},
    )
    script.add("GET", "https://management.eu-central-1.kiro.dev/getUsageLimits", usage)
    return profile, usage


def advance_poll(adapter, progress, clock):
    progress = run_ready(adapter, progress)
    assert progress.status == "polling"
    clock[0] = progress.next_poll_at
    return adapter.advance(progress.sealed_state)


def test_complete_cross_region_flow_returns_only_real_tokens_profile_and_usage(
    monkeypatch, key_context
):
    adapter, progress, script, events, clock = setup(monkeypatch, key_context[1])
    profile, usage = add_profile(script, adapter.gateway)
    done = run_ready(adapter, advance_poll(adapter, progress, clock))
    assert done.status == "done" and not script.steps
    assert (
        done.result["authRegion"] == "us-east-1"
        and done.result["apiRegion"] == "eu-central-1"
    )
    assert (
        done.result["accessToken"] == "access-secret"
        and done.result["refreshToken"] == "refresh-secret"
    )
    assert done.result["expiresAt"] == NOW + 5 + 3600
    assert done.result["profile"] == profile and done.result["usage"] == usage
    assert adapter.gateway.client_requests == [
        ("sso-oidc", {"region_name": "us-east-1"})
    ]
    register, device, token = adapter.gateway.oidc.calls
    assert register[1]["clientType"] == "public"
    assert set(register[1]["scopes"]) == {
        "codewhisperer:" + scope
        for scope in (
            "completions",
            "analysis",
            "conversations",
            "transformations",
            "taskassist",
        )
    }
    assert device[1]["clientId"] == token[1]["clientId"] == "our-client"
    assert token[1]["deviceCode"] == "our-device"
    usage_call = script.calls[-1][2]
    assert usage_call["params"] == {
        "profileArn": profile["arn"],
        "origin": "AI_EDITOR",
        "resourceType": "AGENTIC_REQUEST",
    }
    assert usage_call["headers"]["Authorization"] == "Bearer access-secret"
    for _, _, call in script.calls:
        assert "password" not in call.get("params", {})
    assert "secret" not in repr(done)


def test_identity_store_user_id_binds_real_portal_identity_before_oidc(
    monkeypatch, key_context
):
    adapter, progress, script, _, clock = setup(monkeypatch, key_context[1])
    identity = {
        "userIdentifier": "portal-specific-opaque-identifier",
        "identityStoreUserId": "user-synthetic",
        "directoryId": "d-1234567890",
    }
    index = next(
        i for i, step in enumerate(script.steps) if step[1] == DP + "/token/whoAmI"
    )
    method, url, _, status, headers, inspect = script.steps[index]
    script.steps[index] = (method, url, identity, status, headers, inspect)
    add_profile(script, adapter.gateway)

    done = run_ready(adapter, advance_poll(adapter, progress, clock))
    assert done.status == "done" and not script.steps
    assert done.result["userId"] == "user-synthetic"
    assert done.result["accessToken"] == "access-secret"
    assert decrypt(done.sealed_state)["portal_identity"] == identity


def test_password_confirmation_is_durable_even_when_later_oauth_fails(
    monkeypatch, key_context
):
    client = Oidc(
        tokens=[
            ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": "NEVER_PRINT secret",
                    }
                },
                "CreateToken",
            )
        ]
    )
    adapter, progress, script, events, clock = setup(
        monkeypatch, key_context[1], first_password=True, client=client
    )
    with pytest.raises(module().AuthError) as error:
        advance_poll(adapter, progress, clock)
    assert error.value.code == "oauth_failed" and "NEVER_PRINT" not in str(error.value)
    confirmed = [e for e in events if e.event == "password_confirmed"]
    assert (
        len(confirmed) == 1
        and decrypt(confirmed[0].credential)["current"] == "Replacement9!"
    )


def test_bounded_polling_respects_interval_slow_down_and_device_expiry(
    monkeypatch, key_context
):
    client = Oidc(
        tokens=[
            ClientError(
                {"Error": {"Code": "AuthorizationPendingException"}}, "CreateToken"
            ),
            ClientError({"Error": {"Code": "SlowDownException"}}, "CreateToken"),
        ]
    )
    adapter, progress, _, _, clock = setup(monkeypatch, key_context[1], client=client)
    progress = run_ready(adapter, progress)
    assert progress.status == "polling" and progress.next_poll_at == NOW + 5
    early = adapter.advance(progress.sealed_state)
    assert early.next_poll_at == progress.next_poll_at and len(client.calls) == 2
    clock[0] += 5
    pending = adapter.advance(early.sealed_state)
    assert pending.status == "polling" and pending.next_poll_at == NOW + 10
    clock[0] += 5
    slowed = adapter.advance(pending.sealed_state)
    assert slowed.next_poll_at == NOW + 20
    clock[0] = NOW + 600
    with pytest.raises(module().AuthError) as error:
        adapter.advance(slowed.sealed_state)
    assert error.value.code == "expired" and len(client.calls) == 4


@pytest.mark.parametrize(
    "field,value",
    [
        ("clientId", ""),
        ("clientSecret", ""),
        ("clientSecretExpiresAt", NOW),
        ("clientSecretExpiresAt", True),
    ],
)
def test_invalid_registration_fields_fail_before_native_http(
    monkeypatch, key_context, field, value
):
    client = Oidc()
    client.registration[field] = value
    adapter, progress, script, _, _ = setup(monkeypatch, key_context[1], client=client)
    with pytest.raises(module().AuthError):
        adapter.advance(progress.sealed_state)
    assert not script.calls


def test_own_client_context_required_before_association(monkeypatch, key_context):
    adapter, progress, script, _, _ = setup(monkeypatch, key_context[1])
    method, url, data, status, headers, inspect = script.steps[-2]
    data["deviceContext"]["clientId"] = "different-client"
    with pytest.raises(module().AuthError) as error:
        run_ready(adapter, progress)
    assert error.value.code == "device_mismatch"
    assert script.calls[-1][1].endswith("accept_user_code")


def test_missing_configured_profile_is_explicit_failure_without_usage_request(
    monkeypatch, key_context
):
    adapter, progress, script, _, clock = setup(monkeypatch, key_context[1])
    add_profile(script, adapter.gateway, profiles=[])
    with pytest.raises(module().AuthError) as error:
        run_ready(adapter, advance_poll(adapter, progress, clock))
    assert error.value.code == "no_profile"
    assert script.calls[-1][1].endswith("ListAvailableProfiles")


def test_profile_pagination_is_bounded_and_rejects_repeated_tokens(
    monkeypatch, key_context
):
    adapter, progress, script, _, clock = setup(monkeypatch, key_context[1])
    url = "https://management.eu-central-1.kiro.dev/ListAvailableProfiles"
    script.add("POST", url, {"profiles": [], "nextToken": "same-token"})
    script.add("POST", url, {"profiles": [], "nextToken": "same-token"})
    with pytest.raises(module().AuthError) as error:
        run_ready(adapter, advance_poll(adapter, progress, clock))
    assert error.value.code == "pagination_limit"
    assert script.calls[-1][2]["json"] == {"nextToken": "same-token"}


def test_registration_expires_cleanly_while_human_captcha_waits(
    monkeypatch, key_context
):
    client = Oidc()
    client.registration["clientSecretExpiresAt"] = NOW + 10
    adapter, progress, script, _, clock = setup(
        monkeypatch, key_context[1], client=client
    )
    # Replace password page with an AMS challenge before any password submission.
    from test_identity_login import LOGIN
    import base64
    import json

    page = workflow(
        "get-password", key_context[1], {"captchaToken": ams_token(), "captchaCDN": CDN}
    )
    script.steps[2] = (
        "GET",
        LOGIN,
        '<meta name="initial-workflow-state" content="'
        + base64.b64encode(json.dumps(page).encode()).decode()
        + '">',
        200,
        {},
        None,
    )
    paused = run_ready(adapter, progress)
    assert paused.status == "challenge" and paused.challenge["expires_at"] <= NOW + 10
    clock[0] = NOW + 11
    with pytest.raises(module().AuthError) as error:
        adapter.advance(
            paused.sealed_state,
            answer={
                "challenge_id": paused.challenge["id"],
                "revision": paused.challenge["revision"],
                "access_code": "human-code",
            },
        )
    assert error.value.code == "expired" and len(script.calls) == 3


@pytest.mark.parametrize(
    "field,value",
    [
        ("deviceCode", ""),
        ("userCode", ""),
        ("expiresIn", 0),
        ("interval", 0),
        ("interval", True),
        ("verificationUri", "https://evil.example/"),
    ],
)
def test_invalid_device_fields_stop_before_credentials_leave_adapter(
    monkeypatch, key_context, field, value
):
    client = Oidc()
    client.device[field] = value
    adapter, progress, script, _, _ = setup(monkeypatch, key_context[1], client=client)
    progress = adapter.advance(progress.sealed_state)
    with pytest.raises(module().AuthError):
        adapter.advance(progress.sealed_state)
    assert not script.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("accessToken", ""),
        ("refreshToken", ""),
        ("expiresIn", 0),
        ("expiresIn", True),
        ("tokenType", None),
        ("tokenType", "NotBearer"),
    ],
)
def test_invalid_token_fields_fail_without_profile_requests(
    monkeypatch, key_context, field, value
):
    client = Oidc()
    client.tokens[0][field] = value
    adapter, progress, script, _, clock = setup(
        monkeypatch, key_context[1], client=client
    )
    with pytest.raises(module().AuthError) as error:
        advance_poll(adapter, progress, clock)
    assert error.value.code == "token_invalid" and len(script.calls) == 9


def test_refresh_uses_own_saved_registration_and_actual_response_expiry(
    monkeypatch, key_context
):
    client = Oidc()
    client.registration["clientSecretExpiresAt"] = NOW + 7200
    adapter, progress, script, _, clock = setup(
        monkeypatch, key_context[1], client=client
    )
    add_profile(script, adapter.gateway)
    done = run_ready(adapter, advance_poll(adapter, progress, clock))
    clock[0] = done.result["expiresAt"] + 1
    client.tokens.append(
        {"accessToken": "refreshed-access", "expiresIn": 900, "tokenType": "Bearer"}
    )
    add_profile(script, adapter.gateway)
    refreshed = run_ready(adapter, adapter.begin_refresh(done.sealed_state))
    assert refreshed.result["refreshToken"] == "refresh-secret"
    assert refreshed.result["accessToken"] == "refreshed-access"
    assert refreshed.result["expiresAt"] == clock[0] + 900
    assert client.calls[-1] == (
        "token",
        {
            "clientId": "our-client",
            "clientSecret": "client-secret",
            "grantType": "refresh_token",
            "refreshToken": "refresh-secret",
        },
    )
    assert len(client.calls) == 4


def test_distinct_profile_pages_select_configured_arn_in_subscription_region(
    monkeypatch, key_context
):
    adapter, progress, script, _, clock = setup(monkeypatch, key_context[1])
    url = "https://management.eu-central-1.kiro.dev/ListAvailableProfiles"
    script.add(
        "POST",
        url,
        {
            "profiles": [
                {
                    "arn": "arn:aws:codewhisperer:us-east-1:123456789012:profile/wrong",
                    "profileName": "Wrong region",
                }
            ],
            "nextToken": "next-page",
        },
    )
    profile, usage = add_profile(script, adapter.gateway)
    done = run_ready(adapter, advance_poll(adapter, progress, clock))
    assert done.result["profile"] == profile and done.result["usage"] == usage


def test_finite_unique_pagination_cap_never_probes_unbounded_profiles(
    monkeypatch, key_context
):
    adapter, progress, script, _, clock = setup(monkeypatch, key_context[1])
    url = "https://management.eu-central-1.kiro.dev/ListAvailableProfiles"
    for i in range(adapter.MAX_PAGES):
        script.add("POST", url, {"profiles": [], "nextToken": str(i)})
    with pytest.raises(module().AuthError) as error:
        run_ready(adapter, advance_poll(adapter, progress, clock), limit=30)
    assert error.value.code == "pagination_limit" and not script.steps


def test_sdk_proxy_transport_revocation_error_is_redacted(monkeypatch, key_context):
    from app.aws import AwsFailure

    client = Oidc(tokens=[AwsFailure("NEVER_PRINT proxy secret")])
    adapter, progress, _, _, clock = setup(monkeypatch, key_context[1], client=client)
    with pytest.raises(module().AuthError) as error:
        advance_poll(adapter, progress, clock)
    assert error.value.code == "proxy_unavailable" and "NEVER_PRINT" not in str(
        error.value
    )


@pytest.mark.parametrize(
    "identity",
    [
        [],
        False,
        0,
        "",
        {"ssoIdentityDetails": []},
        {"ssoIdentityDetails": False},
        {"ssoIdentityDetails": 0},
        {"ssoIdentityDetails": ""},
        {"ssoIdentityDetails": {"ssoRegion": "other-region"}},
        {"ssoIdentityDetails": {"ssoRegion": None}},
        {"ssoIdentityDetails": {"instanceArn": None}},
    ],
)
def test_malformed_or_conflicting_profile_identity_is_safe_failure(
    monkeypatch, key_context, identity
):
    adapter, progress, script, _, clock = setup(monkeypatch, key_context[1])
    profile = {
        "arn": adapter.gateway.account.profile_arn,
        "profileName": "Synthetic",
        "identityDetails": identity,
    }
    add_profile(script, adapter.gateway, profiles=[profile])
    with pytest.raises(module().AuthError) as error:
        run_ready(adapter, advance_poll(adapter, progress, clock))
    assert error.value.code in {"invalid_response", "identity_mismatch"}
    assert script.calls[-1][1].endswith("ListAvailableProfiles")


@pytest.mark.parametrize("identity", [None, {"ssoIdentityDetails": None}])
def test_native_verified_identity_accepts_nullable_profile_metadata(
    monkeypatch, key_context, identity
):
    adapter, progress, script, _, clock = setup(monkeypatch, key_context[1])
    profile = {
        "arn": adapter.gateway.account.profile_arn,
        "profileName": "Synthetic enterprise",
        "identityDetails": identity,
        "status": None,
        "profileType": None,
    }
    _, usage = add_profile(script, adapter.gateway, profiles=[profile])
    done = run_ready(adapter, advance_poll(adapter, progress, clock))
    assert done.status == "done" and not script.steps
    assert done.result["profile"] == profile and done.result["usage"] == usage
    assert done.result["userId"] == "user-synthetic"


def test_sdk_transport_error_does_not_retry_or_continue_directly(
    monkeypatch, key_context
):
    from botocore.exceptions import EndpointConnectionError

    client = Oidc(
        tokens=[
            EndpointConnectionError(
                endpoint_url="https://secret.invalid/?token=NEVER_PRINT"
            )
        ]
    )
    adapter, progress, script, _, clock = setup(
        monkeypatch, key_context[1], client=client
    )
    with pytest.raises(module().AuthError) as error:
        advance_poll(adapter, progress, clock)
    assert error.value.code == "oauth_failed" and "NEVER_PRINT" not in str(error.value)
    with pytest.raises(module().AuthError) as resumed:
        adapter.advance(error.value.sealed_state)
    assert (
        resumed.value.code in {"interrupted", "invalid_state"}
        and len(client.calls) == 3
        and len(script.calls) == 9
    )


def test_device_uris_accept_only_observed_configured_portal_fragment_shape(
    monkeypatch, key_context
):
    client = Oidc()
    client.device.update(
        verificationUri=PORTAL + "/#/device",
        verificationUriComplete=PORTAL + "/#/device?user_code=OUR-CODE",
    )
    adapter, progress, script, _, clock = setup(
        monkeypatch, key_context[1], client=client
    )
    add_profile(script, adapter.gateway)
    done = run_ready(adapter, advance_poll(adapter, progress, clock))
    assert done.status == "done" and not script.steps


@pytest.mark.parametrize(
    "field,value,code",
    [
        (
            "verificationUri",
            "https://other.awsapps.com/start/#/device",
            "unsafe_destination",
        ),
        ("verificationUri", PORTAL + "#/device", "unsafe_destination"),
        ("verificationUri", PORTAL + "/#/unknown", "unsafe_destination"),
        (
            "verificationUri",
            PORTAL + "/?secret=NEVER_PRINT#/device",
            "unsafe_destination",
        ),
        (
            "verificationUri",
            PORTAL + "/#/device?user_code=OUR-CODE",
            "unsafe_destination",
        ),
        (
            "verificationUriComplete",
            PORTAL + "/#/device?user_code=OTHER-CODE",
            "device_mismatch",
        ),
        ("verificationUriComplete", PORTAL + "/#/device", "device_mismatch"),
        (
            "verificationUriComplete",
            PORTAL + "/#/device?user_code=OUR-CODE&user_code=OUR-CODE",
            "unsafe_destination",
        ),
        (
            "verificationUriComplete",
            PORTAL + "/#/device?user_code=OUR-CODE&secret=NEVER_PRINT",
            "unsafe_destination",
        ),
        (
            "verificationUriComplete",
            PORTAL + "/?user_code=OUR-CODE#/device",
            "unsafe_destination",
        ),
        (
            "verificationUriComplete",
            PORTAL + "/#/device?user_code=OUR-CODE#extra",
            "device_mismatch",
        ),
    ],
)
def test_portal_device_uri_rejects_unbound_origins_paths_queries_and_codes(
    monkeypatch, key_context, field, value, code
):
    client = Oidc()
    client.device.update(
        verificationUri=PORTAL + "/#/device",
        verificationUriComplete=PORTAL + "/#/device?user_code=OUR-CODE",
    )
    client.device[field] = value
    adapter, progress, script, _, _ = setup(monkeypatch, key_context[1], client=client)
    progress = adapter.advance(progress.sealed_state)
    with pytest.raises(module().AuthError) as error:
        adapter.advance(progress.sealed_state)
    assert error.value.code == code and not script.calls
    assert "NEVER_PRINT" not in str(error.value)


@pytest.mark.parametrize(
    "identity",
    [
        {},
        {"directoryId": "d-1234567890"},
        {"userIdentifier": "user-synthetic"},
        {"directoryId": None, "userIdentifier": "user-synthetic"},
        {"directoryId": "d-1234567890", "userIdentifier": None},
        {"directoryId": 123, "userIdentifier": "user-synthetic"},
        {"directoryId": "d-1234567890", "userIdentifier": ["user-synthetic"]},
        {"directoryId": "", "userIdentifier": "user-synthetic"},
        {"directoryId": "d-1234567890", "userIdentifier": " "},
        {"directoryId": " d-1234567890", "userIdentifier": "user-synthetic"},
        {"directoryId": "d-1234567890", "userIdentifier": "user-synthetic "},
        {"directoryId": "other-directory", "userIdentifier": "user-synthetic"},
        {"directoryId": "d-1234567890", "userIdentifier": "other-user"},
        {"directoryId": "d-1234567890", "userId": "user-synthetic"},
        *[
            {
                "directoryId": "d-1234567890",
                "userIdentifier": "user-synthetic",
                "identityStoreUserId": bad,
            }
            for bad in (None, "", " ", 123, ["user-synthetic"], "other-user", "user-synthetic ")
        ],
        *[
            {
                "directoryId": "d-1234567890",
                "userIdentifier": "portal-specific-opaque-identifier",
                "identityStoreUserId": "user-synthetic",
                **invalid,
            }
            for invalid in (
                {"directoryId": "other-directory"},
                {"userIdentifier": " "},
                {"userIdentifier": None},
                {"userId": "other-user"},
                {"username": "another-account"},
                {"userName": "another-account"},
            )
        ],
    ],
)
def test_whoami_requires_complete_matching_identity_before_device_session(
    monkeypatch, key_context, identity
):
    adapter, progress, script, _, _ = setup(monkeypatch, key_context[1])
    index = next(
        i for i, step in enumerate(script.steps) if step[1] == DP + "/token/whoAmI"
    )
    method, url, _, status, headers, inspect = script.steps[index]
    script.steps[index] = (method, url, identity, status, headers, inspect)
    with pytest.raises(module().AuthError) as error:
        run_ready(adapter, progress)
    assert error.value.code == "identity_mismatch"
    assert script.calls[-1][1] == DP + "/token/whoAmI"
    assert all(call[1] != DP + "/session/device" for call in script.calls)


def external_setup(monkeypatch, context, *, client=None):
    gateway = Gateway()
    gateway.oidc = client or Oidc()
    page = workflow(
        "get-password", context, {"captchaToken": ams_token(), "captchaCDN": CDN}
    )
    script = opening(Script(monkeypatch, gateway), page)
    clock, events = [NOW], []
    adapter = module("enterprise_auth").EnterpriseAuth(
        gateway, checkpoint=events.append, clock=lambda: clock[0]
    )
    paused = run_ready(
        adapter, adapter.begin("alice", "old-otp", expected_user_id="user-synthetic")
    )
    return adapter, paused, script, events, clock


def external_answer(progress, **changes):
    return {
        "challenge_id": progress.challenge["id"],
        "revision": progress.challenge["revision"],
        "continue_authorization": True,
        **changes,
    }


def add_external_profile(script, gateway, *, identity=None, usage=None):
    return add_profile(
        script,
        gateway,
        profiles=[
            {
                "arn": gateway.account.profile_arn,
                "profileName": "Synthetic enterprise",
                "identityDetails": {
                    "ssoIdentityDetails": identity
                    if identity is not None
                    else {
                        "instanceArn": gateway.account.instance_arn,
                        "ssoRegion": gateway.account.region,
                    }
                },
            }
        ],
        usage=usage
        if usage is not None
        else {
            "userInfo": {
                "userId": gateway.account.identity_store_id + ".user-synthetic"
            },
        },
    )


def test_external_challenge_saves_validated_urls_and_exposes_only_human_metadata(
    monkeypatch, key_context
):
    client = Oidc()
    client.device.update(
        verificationUri=PORTAL + "/#/device",
        verificationUriComplete=PORTAL + "/#/device?user_code=OUR-CODE",
    )
    adapter, paused, script, _, _ = external_setup(
        monkeypatch, key_context[1], client=client
    )
    assert paused.challenge == {
        "kind": "aws_authorization",
        "id": paused.challenge["id"],
        "revision": paused.challenge["revision"],
        "expires_at": NOW + 300,
        "authorization_url": client.device["verificationUriComplete"],
        "user_code": "OUR-CODE",
        "username": "alice",
    }
    state = decrypt(paused.sealed_state)
    assert state["device"]["verificationUri"] == client.device["verificationUri"]
    assert (
        state["device"]["verificationUriComplete"]
        == client.device["verificationUriComplete"]
    )
    assert len(script.calls) == 3 and len(client.calls) == 2
    before = len(script.calls)
    waiting = adapter.advance(paused.sealed_state)
    assert waiting.status == "challenge" and len(script.calls) == before
    assert "old-otp" not in str(paused.challenge) and "client-secret" not in str(
        paused.challenge
    )


@pytest.mark.parametrize(
    "usage,expected",
    [
        ({"userInfo": {"userId": "d-1234567890.user-synthetic"}}, True),
        ({"userInfo": {"userId": "d-1234567890.someone-else"}}, False),
        ({"userInfo": {"userId": "other.user-synthetic"}}, False),
        ({"userInfo": {"email": "alice@example.org"}}, False),
        ({"userInfo": {"userId": ["d-1234567890.user-synthetic"]}}, False),
        ({"userInfo": None}, False),
        ({}, False),
    ],
)
def test_external_identity_requires_exact_aws_directory_user_id(usage, expected):
    assert (
        module("enterprise_auth").verified_external_identity(
            usage, "d-1234567890", "user-synthetic"
        )
        is expected
    )


def test_external_continuation_polls_existing_device_and_exports_unknown_password(
    monkeypatch, key_context
):
    adapter, paused, script, events, clock = external_setup(monkeypatch, key_context[1])
    add_external_profile(script, adapter.gateway)
    polling = adapter.advance(paused.sealed_state, answer=external_answer(paused))
    assert polling.status == "polling" and polling.next_poll_at == NOW + 5
    assert len(script.calls) == 3 and len(adapter.gateway.oidc.calls) == 2
    unknown = [cp for cp in events if cp.event == "external_authorization"]
    assert len(unknown) == 1 and decrypt(unknown[0].credential)["current"] is None
    clock[0] = polling.next_poll_at
    done = run_ready(adapter, adapter.advance(polling.sealed_state))
    assert done.status == "done" and done.result["password"] is None
    assert done.result["userId"] == "user-synthetic"
    assert len(script.calls) == 5 and not script.steps
    assert adapter.gateway.oidc.calls[-1][1]["deviceCode"] == "our-device"


@pytest.mark.parametrize(
    "usage",
    [
        {"userInfo": {"userId": "d-1234567890.someone-else"}},
        {"userInfo": {"userId": "other.user-synthetic"}},
        {"userInfo": {"email": "alice@example.org"}},
        {},
    ],
)
def test_external_wrong_or_missing_identity_never_publishes_result(
    monkeypatch, key_context, usage
):
    adapter, paused, script, _, clock = external_setup(monkeypatch, key_context[1])
    add_external_profile(script, adapter.gateway, usage=usage)
    polling = adapter.advance(paused.sealed_state, answer=external_answer(paused))
    clock[0] = polling.next_poll_at
    with pytest.raises(module().AuthError) as error:
        run_ready(adapter, adapter.advance(polling.sealed_state))
    assert error.value.code == "identity_mismatch"
    assert not decrypt(error.value.sealed_state).get("result")


@pytest.mark.parametrize(
    "identity",
    [
        {},
        {
            "instanceArn": "arn:aws:sso:::instance/ssoins-other",
            "ssoRegion": "us-east-1",
        },
        {"instanceArn": "arn:aws:sso:::instance/ssoins-1234567890"},
    ],
)
def test_external_profile_requires_explicit_matching_instance_and_region(
    monkeypatch, key_context, identity
):
    adapter, paused, script, _, clock = external_setup(monkeypatch, key_context[1])
    add_external_profile(script, adapter.gateway, identity=identity)
    polling = adapter.advance(paused.sealed_state, answer=external_answer(paused))
    clock[0] = polling.next_poll_at
    with pytest.raises(module().AuthError) as error:
        run_ready(adapter, adapter.advance(polling.sealed_state))
    assert error.value.code == "identity_mismatch"
    assert script.calls[-1][1].endswith("ListAvailableProfiles")


@pytest.mark.parametrize("identity", [None, {"ssoIdentityDetails": None}])
def test_external_nullable_profile_identity_never_authorizes_usage_or_export(
    monkeypatch, key_context, identity
):
    adapter, paused, script, _, clock = external_setup(monkeypatch, key_context[1])
    profile = {
        "arn": adapter.gateway.account.profile_arn,
        "profileName": "Synthetic enterprise",
        "identityDetails": identity,
    }
    add_profile(script, adapter.gateway, profiles=[profile])
    polling = adapter.advance(paused.sealed_state, answer=external_answer(paused))
    clock[0] = polling.next_poll_at
    with pytest.raises(module().AuthError) as error:
        run_ready(adapter, adapter.advance(polling.sealed_state))
    assert error.value.code == "identity_mismatch"
    assert script.calls[-1][1].endswith("ListAvailableProfiles")
    assert not decrypt(error.value.sealed_state).get("result")


@pytest.mark.parametrize(
    "field,url",
    [
        (
            "verificationUri",
            "https://device.sso.us-east-1.amazonaws.com/?user_code=OTHER",
        ),
        (
            "verificationUriComplete",
            "https://device.sso.eu-central-1.amazonaws.com/?user_code=OUR-CODE",
        ),
        (
            "verificationUriComplete",
            "https://device.sso.us-east-1.amazonaws.com/?user_code=OTHER",
        ),
        (
            "verificationUriComplete",
            "https://device.sso.us-east-1.amazonaws.com/?user_code=OUR-CODE&redirect_uri=https%3A%2F%2Fevil.example",
        ),
    ],
)
def test_device_endpoint_rejects_base_codes_regions_and_redirects(
    monkeypatch, key_context, field, url
):
    client = Oidc()
    client.device[field] = url
    with pytest.raises(module().AuthError):
        external_setup(monkeypatch, key_context[1], client=client)


@pytest.mark.parametrize(
    "changes",
    [
        {"revision": 10000},
        {"continue_authorization": False},
        {"continue_authorization": "true"},
        {"access_code": "legacy-code"},
    ],
)
def test_external_continuation_rejects_stale_or_implicit_answers(
    monkeypatch, key_context, changes
):
    adapter, paused, script, _, _ = external_setup(monkeypatch, key_context[1])
    with pytest.raises(module().AuthError) as error:
        adapter.advance(paused.sealed_state, answer=external_answer(paused, **changes))
    assert error.value.code == "stale_challenge" and len(script.calls) == 3


def test_external_pending_slowdown_and_expiry_keep_bounded_polling(
    monkeypatch, key_context
):
    client = Oidc(
        tokens=[
            ClientError(
                {"Error": {"Code": "AuthorizationPendingException"}}, "CreateToken"
            ),
            ClientError({"Error": {"Code": "SlowDownException"}}, "CreateToken"),
        ]
    )
    adapter, paused, script, _, clock = external_setup(
        monkeypatch, key_context[1], client=client
    )
    progress = adapter.advance(paused.sealed_state, answer=external_answer(paused))
    for expected in (NOW + 10, NOW + 20):
        clock[0] = progress.next_poll_at
        progress = adapter.advance(progress.sealed_state)
        assert progress.status == "polling" and progress.next_poll_at == expected
    assert len(script.calls) == 3 and len(client.calls) == 4
    clock[0] = NOW + 600
    with pytest.raises(module().AuthError) as error:
        adapter.advance(progress.sealed_state)
    assert error.value.code == "expired" and len(client.calls) == 4


def test_legacy_ams_with_saved_device_recovers_from_configured_portal(
    monkeypatch, key_context
):
    from app.security import encrypt

    adapter, paused, script, _, clock = external_setup(monkeypatch, key_context[1])
    state = decrypt(paused.sealed_state)
    for key in ("verificationUri", "verificationUriComplete"):
        state["device"].pop(key, None)
    state["challenge"] = {
        key: state["challenge"][key] for key in ("id", "revision", "expires_at")
    }
    state["challenge"]["kind"] = "ams"
    public = module("enterprise_auth").official_authorization_challenge(state)
    assert public["authorization_url"] == PORTAL + "/#/device?user_code=OUR-CODE"
    add_external_profile(script, adapter.gateway)
    polling = adapter.advance(encrypt(state), answer=external_answer(paused))
    clock[0] = polling.next_poll_at
    done = run_ready(adapter, adapter.advance(polling.sealed_state))
    assert done.status == "done" and done.result["password"] is None
