"""Synthetic fixtures for the public AWS portal/sign-in JS protocol (2026-10-09).

These exercise our adapter, not a live AWS account or a third-party converter.
"""

import base64
import importlib
import importlib.util
import io
import json
from http.client import HTTPMessage
from types import SimpleNamespace
from urllib.parse import parse_qsl, quote, urlsplit

import pytest
import requests
from urllib3.response import HTTPResponse
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.security import decrypt


NOW = 1_800_000_000
PORTAL = "https://d-1234567890.awsapps.com/start"
DP = "https://portal.sso.us-east-1.amazonaws.com"
OIDC = "https://oidc.us-east-1.amazonaws.com"
SIGNIN = "https://us-east-1.signin.aws"
LOGIN = SIGNIN + "/platform/d-1234567890/login?workflowStateHandle=start-secret"
EXECUTE = SIGNIN + "/platform/d-1234567890/api/execute"
CDN = "https://cdn.us-east-1.threat-mitigation.aws.amazon.com/assets/consumer/consumer.min.js"


def module(name="identity_login"):
    assert importlib.util.find_spec("app." + name), (
        "Native authentication adapter is missing"
    )
    return importlib.import_module("app." + name)


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def ams_token(**overrides):
    return base64.b64encode(
        json.dumps(
            {
                "apiRoot": "us-east-1.threat-mitigation.aws.amazon.com",
                "region": "us-east-1",
                "envStage": "prod",
                "synthetic": "redemption-secret",
            }
            | overrides
        ).encode()
    ).decode()


def unb64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@pytest.fixture
def key_context():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = key.public_key().public_numbers()
    context = {
        "publicKey": {
            "kty": "RSA",
            "use": "enc",
            "alg": "RSA-OAEP-256",
            "kid": "synthetic-key",
            "n": b64(numbers.n.to_bytes(256, "big")),
            "e": b64(numbers.e.to_bytes(3, "big")),
        },
        "issuer": "signin",
        "audience": "AWSPasswordService",
        "region": "us-east-1",
    }
    return key, context


def decrypt_password(key, compact):
    protected, encrypted_key, iv, ciphertext, tag = compact.split(".")
    cek = key.decrypt(
        unb64(encrypted_key),
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    claims = AESGCM(cek).decrypt(
        unb64(iv), unb64(ciphertext) + unb64(tag), protected.encode()
    )
    return json.loads(unb64(protected)), json.loads(claims)


def workflow(step, context=None, captcha=None, **extra):
    value = {
        "stepId": step,
        "workflowStateHandle": "handle-" + step,
        "presentationContext": {"applicationType": "SSO"},
        "actionIdList": ["SUBMIT"],
    }
    if context:
        value["workflowResponseData"] = {"encryptionContextResponse": context}
    if captcha is not None:
        value["captchaResponse"] = captcha
    return value | extra


def success(**extra):
    return workflow(
        "end-of-workflow-success",
        redirect={
            "url": PORTAL + "?workflowResultHandle=result-secret&state=csrf-state",
            "method": "GET",
            "postParams": [],
        },
        **extra,
    )


def env_html(**extra):
    env = {
        "region": "us-east-1",
        "dpApiEndpoint": DP,
        "oidcApiEndpoint": OIDC,
        "signinEndpoint": SIGNIN,
        "dualstack": False,
    } | extra
    return '<script id="env" type="application/json">' + json.dumps(env) + "</script>"


class Gateway:
    def __init__(self):
        self.account = SimpleNamespace(
            id=42,
            region="us-east-1",
            subscription_region="eu-central-1",
            identity_store_id="d-1234567890",
            instance_arn="arn:aws:sso:::instance/ssoins-1234567890123456",
            portal_url=PORTAL,
            profile_arn="arn:aws:codewhisperer:eu-central-1:123456789012:profile/enterprise",
        )
        self.proxy = SimpleNamespace(url="socks5h://dummy:synthetic@proxy.invalid:1080")
        self.guard_count = 0
        self.denied = False
        self.client_requests = []

    def _check_proxy(self):
        self.guard_count += 1
        if self.denied:
            raise RuntimeError("proxy synthetic secret that must not escape")

    def _client(self, service, **kwargs):
        self.client_requests.append((service, kwargs))
        return self.oidc


class Script:
    def __init__(self, monkeypatch, gateway):
        self.steps, self.calls = [], []
        self.gateway = gateway
        monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", self.send)

    def add(self, method, url, data, *, status=200, headers=None, inspect=None):
        self.steps.append((method, url, data, status, headers or {}, inspect))
        return self

    def send(self, prepared, **transport):
        assert self.steps, "Unexpected network request"
        expected_method, expected_url, data, status, headers, inspect = self.steps.pop(
            0
        )
        method, parsed = prepared.method, urlsplit(prepared.url)
        assert method == expected_method
        url = (
            prepared.url
            if urlsplit(expected_url).query
            else parsed._replace(query="").geturl()
        )
        assert url == expected_url
        assert transport["verify"] is True and transport["stream"] is True
        assert transport["timeout"][0] == 5
        assert transport["proxies"] == {
            "http": self.gateway.proxy.url,
            "https": self.gateway.proxy.url,
        }
        kwargs = {**transport, "headers": dict(prepared.headers)}
        if parsed.query:
            kwargs["params"] = dict(parse_qsl(parsed.query))
        if prepared.body:
            if prepared.headers.get("Content-Type") == "application/json":
                kwargs["json"] = json.loads(prepared.body)
            else:
                kwargs["data"] = dict(parse_qsl(prepared.body))
        assert self.gateway.guard_count > len(self.calls)
        self.calls.append((method, url, kwargs))
        if inspect:
            inspect(kwargs)
        if isinstance(data, Exception):
            raise data
        response = requests.Response()
        response.status_code = status
        response.url, response.request = prepared.url, prepared
        response.headers.update(headers)
        payload = (
            data
            if isinstance(data, bytes)
            else (data.encode() if isinstance(data, str) else json.dumps(data).encode())
        )
        source = io.BytesIO(payload)
        response.raw = HTTPResponse(body=source, preload_content=False)
        cookie_headers = HTTPMessage()
        for name, value in headers.items():
            cookie_headers[name] = value
        response.raw._original_response = SimpleNamespace(
            msg=cookie_headers,
            isclosed=lambda: source.closed,
            close=source.close,
        )
        return response


def opening(script, first=None):
    script.add("GET", PORTAL, env_html())
    script.add("GET", DP + "/login", {"redirectUrl": LOGIN, "csrfToken": "login-csrf"})
    html = (
        "<html></html>"
        if first is None
        else (
            '<meta name="initial-workflow-state" content="'
            + base64.b64encode(json.dumps(first).encode()).decode()
            + '">'
        )
    )
    script.add("GET", LOGIN, html)
    return script


def run_ready(adapter, progress, limit=30):
    for _ in range(limit):
        if progress.status != "ready":
            return progress
        progress = adapter.advance(progress.sealed_state)
    pytest.fail("Adapter did not yield within bounded protocol steps")


def start_at_password(monkeypatch, context, captcha=None, **kwargs):
    gateway = Gateway()
    script = opening(
        Script(monkeypatch, gateway), workflow("get-password", context, captcha)
    )
    events = []
    adapter = module().NativeIdentityLogin(
        gateway, checkpoint=events.append, clock=lambda: NOW
    )
    progress = adapter.begin(
        "alice", "old-secret", expected_user_id="user-synthetic", **kwargs
    )
    for _ in range(3):
        progress = adapter.advance(progress.sealed_state)
    return adapter, progress, script, events


def test_jwe_decrypts_to_official_claims_and_headers(key_context):
    key, context = key_context
    compact = module().encrypt_password("synthetic-password", context, "us-east-1", NOW)
    header, claims = decrypt_password(key, compact)
    assert header == {
        "alg": "RSA-OAEP-256",
        "enc": "A256GCM",
        "kid": "synthetic-key",
        "cty": "enc",
        "typ": "application/aws+signin+jwe",
    }
    assert claims["password"] == "synthetic-password"
    assert (
        claims["iss"] == "us-east-1.signin"
        and claims["aud"] == "us-east-1.AWSPasswordService"
    )
    assert claims["iat"] == claims["nbf"] == NOW and claims["exp"] == NOW + 300
    assert claims["jti"]


@pytest.mark.parametrize(
    "bad",
    [
        "http://d-1234567890.awsapps.com/start",
        "https://evil.example/start",
        "https://d-1234567890.awsapps.com.evil.example/start",
        "https://user:secret@d-1234567890.awsapps.com/start",
        PORTAL + "?access_token=synthetic",
        PORTAL + "#password=synthetic",
        "https://d-1234567890.awsapps.com:8443/start",
    ],
)
def test_rejects_unsafe_configured_destination_without_network(bad, monkeypatch):
    auth = module()
    gateway = Gateway()
    gateway.account.portal_url = bad
    script = Script(monkeypatch, gateway)
    with pytest.raises(auth.AuthError) as error:
        auth.NativeIdentityLogin(gateway, checkpoint=lambda e: None).begin(
            "alice", "secret"
        )
    assert not script.calls and "secret" not in str(error.value)


@pytest.mark.parametrize(
    "captcha,kind",
    [
        (
            {
                "captchaURL": SIGNIN + "/platform/captcha/image?id=synthetic",
                "captchaCES": "ces-secret",
            },
            "image",
        ),
        ({"captchaURL": "", "captchaToken": ams_token(), "captchaCDN": CDN}, "ams"),
    ],
)
def test_classifies_and_resumes_same_human_challenge_across_new_adapter(
    monkeypatch, key_context, captcha, kind
):
    key, context = key_context
    adapter, progress, script, events = start_at_password(
        monkeypatch, context, captcha, password_only=True
    )
    assert progress.status == "challenge" and progress.challenge["kind"] == kind
    assert (
        "handle-get-password" not in repr(progress)
        and "old-secret" not in progress.sealed_state
    )
    assert "captchaCES" not in progress.challenge
    if kind == "ams":
        assert progress.challenge["script_url"] == CDN
        assert progress.challenge["redemption_token"] == ams_token()
        assert progress.challenge["callback"] == "initAMS"
    else:
        assert "image_url" not in progress.challenge
    saved = json.loads(json.dumps(progress.sealed_state))
    resumed = module().NativeIdentityLogin(
        adapter.gateway, checkpoint=events.append, clock=lambda: NOW
    )

    def check(kw):
        assert kw["json"]["captchaRequest"] == (
            {"captchaGuess": "human-answer", "captchaCES": "ces-secret"}
            if kind == "image"
            else {"captchaAccessCode": "human-access-code"}
        )
        inputs = kw["json"]["inputs"]
        assert (
            decrypt_password(key, inputs[0]["password"])[1]["password"] == "old-secret"
        )
        assert inputs[1] == {
            "input_type": "UserPreferencesRequestInput",
            "trustDevice": False,
        }
        assert "FingerprintRequestInput" not in json.dumps(kw)

    script.add("POST", EXECUTE, success(), inspect=check)
    answer = {
        "challenge_id": progress.challenge["id"],
        "revision": progress.challenge["revision"],
        ("guess" if kind == "image" else "access_code"): (
            "human-answer" if kind == "image" else "human-access-code"
        ),
    }
    done = resumed.advance(saved, answer=answer)
    assert done.status == "done" and not script.steps


@pytest.mark.parametrize("change", ["revision", "id", "expiry"])
def test_stale_or_expired_challenge_never_submits_password(
    monkeypatch, key_context, change
):
    _, context = key_context
    adapter, progress, script, _ = start_at_password(
        monkeypatch,
        context,
        {"captchaToken": ams_token(), "captchaCDN": CDN, "captchaURL": ""},
    )
    answer = {
        "challenge_id": progress.challenge["id"],
        "revision": progress.challenge["revision"],
        "access_code": "human-code",
    }
    if change == "revision":
        answer["revision"] += 1
    elif change == "id":
        answer["challenge_id"] = "other"
    else:
        adapter.clock = lambda: progress.challenge["expires_at"] + 1
    with pytest.raises(module().AuthError) as error:
        adapter.advance(progress.sealed_state, answer=answer)
    assert error.value.code in {"stale_challenge", "expired"}
    assert len(script.calls) == 3


@pytest.mark.parametrize(
    "captcha",
    [
        {"captchaToken": "token", "captchaCDN": CDN + "?x=token"},
        {
            "captchaToken": "token",
            "captchaCDN": CDN.replace("us-east-1", "eu-central-1"),
        },
        {"captchaToken": "token", "captchaCDN": "https://evil.example/consumer.min.js"},
        {"captchaCDN": CDN, "captchaURL": ""},
        {"captchaURL": "https://evil.example/captcha", "captchaCES": "ces"},
        {"captchaCES": "ces", "captchaURL": ""},
    ],
)
def test_untrusted_or_incomplete_challenge_fails_closed(
    monkeypatch, key_context, captcha
):
    with pytest.raises(module().AuthError) as error:
        start_at_password(monkeypatch, key_context[1], captcha)
    assert error.value.code in {"unsafe_destination", "unsupported_challenge"}


@pytest.mark.parametrize(
    "captcha",
    [
        {"challengeType": "unknown-human-challenge", "challengeRequired": True},
        {"captchaURL": "", "challengeRequired": True},
        {"captchaURL": False},
    ],
)
def test_unknown_challenge_fails_before_password_submission(
    monkeypatch, key_context, captcha
):
    gateway = Gateway()
    script = opening(
        Script(monkeypatch, gateway), workflow("get-password", key_context[1], captcha)
    )
    adapter = module().NativeIdentityLogin(
        gateway, checkpoint=lambda event: None, clock=lambda: NOW
    )
    progress = adapter.begin("alice", "old-secret")
    with pytest.raises(module().AuthError) as error:
        for _ in range(3):
            progress = adapter.advance(progress.sealed_state)
    assert error.value.code == "unsupported_challenge"
    with pytest.raises(module().AuthError):
        adapter.advance(error.value.sealed_state)
    assert len(script.calls) == 3 and all(call[0] == "GET" for call in script.calls)


@pytest.mark.parametrize(
    "captcha",
    [
        None,
        {},
        {"captchaURL": ""},
        {"captchaURL": "", "captchaCES": "", "captchaToken": None, "captchaCDN": None},
    ],
)
def test_known_empty_challenge_allows_password_submission(
    monkeypatch, key_context, captcha
):
    adapter, progress, script, _ = start_at_password(
        monkeypatch, key_context[1], captcha, password_only=True
    )
    assert progress.status == "ready" and progress.challenge is None

    def inspect(kw):
        assert "captchaRequest" not in kw["json"]
        assert kw["json"]["inputs"][0]["input_type"] == "PasswordRequestInput"

    script.add("POST", EXECUTE, success(), inspect=inspect)
    assert adapter.advance(progress.sealed_state).status == "done"


def test_first_password_is_checkpointed_before_write_and_confirmed_immediately(
    monkeypatch, key_context
):
    key, context = key_context
    adapter, progress, script, events = start_at_password(
        monkeypatch,
        context,
        target_password="New-Synthetic-password9!",
        password_only=True,
    )
    script.add(
        "POST", EXECUTE, workflow("get-new-password-for-change-password", context)
    )
    progress = adapter.advance(progress.sealed_state)

    def inspect(kw):
        credential_events = [event for event in events if event.credential is not None]
        assert [e.event for e in credential_events][-2:] == [
            "password_candidate",
            "password_pending",
        ]
        candidate = decrypt(credential_events[-1].credential)
        assert (
            candidate["candidate"] == "New-Synthetic-password9!"
            and candidate["status"] == "unknown"
        )
        assert kw["json"]["stepId"] == "get-new-password-for-change-password"
        assert (
            decrypt_password(key, kw["json"]["inputs"][0]["newPassword"])[1]["password"]
            == candidate["candidate"]
        )

    script.add("POST", EXECUTE, success(), inspect=inspect)
    done = adapter.advance(progress.sealed_state)
    assert done.status == "done"
    confirmed = [event for event in events if event.event == "password_confirmed"]
    assert len(confirmed) == 1
    assert decrypt(confirmed[0].credential)["current"] == "New-Synthetic-password9!"
    assert len(script.calls) == 5


@pytest.mark.parametrize(
    "failure_event", ["password_candidate", "password_pending", "password_confirmed"]
)
def test_storage_failure_stops_network_and_keeps_recoverable_credential(
    monkeypatch, key_context, failure_event
):
    adapter, progress, script, events = start_at_password(
        monkeypatch, key_context[1], password_only=True
    )
    script.add(
        "POST",
        EXECUTE,
        workflow("get-new-password-for-change-password", key_context[1]),
    )
    progress = adapter.advance(progress.sealed_state)
    if failure_event == "password_confirmed":
        script.add("POST", EXECUTE, success())

    def fail(event):
        events.append(event)
        if event.event == failure_event:
            raise RuntimeError("Storage error echoed password NEVER_PRINT")

    adapter.checkpoint = fail
    with pytest.raises(module().AuthError) as error:
        adapter.advance(progress.sealed_state)
    assert error.value.code == "checkpoint_failed" and "NEVER_PRINT" not in str(
        error.value
    )
    assert error.value.sealed_state and error.value.credential
    credential = decrypt(error.value.credential)
    assert credential["candidate"]
    assert credential["status"] == (
        "confirmed"
        if failure_event == "password_confirmed"
        else "unknown"
        if failure_event == "password_pending"
        else "candidate"
    )
    assert len(script.calls) == (5 if failure_event == "password_confirmed" else 4)


def test_lost_password_response_survives_restart_and_recovers_candidate_once(
    monkeypatch, key_context
):
    key, context = key_context
    adapter, progress, script, events = start_at_password(
        monkeypatch, context, target_password="Pending-Synthetic9!", password_only=True
    )
    script.add(
        "POST", EXECUTE, workflow("get-new-password-for-change-password", context)
    )
    progress = adapter.advance(progress.sealed_state)
    script.add(
        "POST", EXECUTE, requests.ReadTimeout("NEVER_PRINT request token and password")
    )
    with pytest.raises(module().AuthError) as failure:
        adapter.advance(progress.sealed_state)
    error = failure.value
    assert error.uncertain and error.credential and "NEVER_PRINT" not in str(error)
    assert decrypt(error.credential)["status"] == "unknown"
    # The pre-dispatch checkpoint already contains durable uncertainty if the process dies.
    pending = next(e for e in events if e.event == "password_pending")
    with pytest.raises(module().AuthError) as interrupted:
        adapter.advance(pending.sealed_state)
    assert interrupted.value.code == "interrupted" and len(script.calls) == 5
    opening(script, workflow("get-password", context))
    resumed = module().NativeIdentityLogin(
        adapter.gateway, checkpoint=events.append, clock=lambda: NOW
    )
    recovery = resumed.begin(
        "alice",
        "old-secret",
        expected_user_id="user-synthetic",
        password_only=True,
        recovery=error.credential,
    )

    def inspect(kw):
        assert (
            decrypt_password(key, kw["json"]["inputs"][0]["password"])[1]["password"]
            == "Pending-Synthetic9!"
        )

    script.add("POST", EXECUTE, success(), inspect=inspect)
    done = run_ready(resumed, recovery)
    assert done.status == "done"
    assert (
        decrypt([e for e in events if e.event == "password_confirmed"][-1].credential)[
            "current"
        ]
        == "Pending-Synthetic9!"
    )


@pytest.mark.parametrize(
    "step,code",
    [
        ("get-totp-login-credential", "unsupported_mfa"),
        ("get-saml-assertion-from-external-idp", "external_identity_provider"),
        ("new-private-step", "unsupported_step"),
        ("end-of-workflow-failure", "login_refused"),
    ],
)
def test_unsupported_steps_fail_with_redacted_errors(
    monkeypatch, key_context, step, code
):
    adapter, progress, script, _ = start_at_password(monkeypatch, key_context[1])
    script.add(
        "POST", EXECUTE, workflow(step, message={"text": "NEVER_PRINT password token"})
    )
    with pytest.raises(module().AuthError) as error:
        adapter.advance(progress.sealed_state)
    assert error.value.code == code
    assert "NEVER_PRINT" not in str(error.value) and "handle" not in str(error.value)


def test_proxy_guard_blocks_every_request_and_never_falls_back(
    monkeypatch, key_context
):
    adapter, progress, script, _ = start_at_password(monkeypatch, key_context[1])
    adapter.gateway.denied = True
    with pytest.raises(module().AuthError) as error:
        adapter.advance(progress.sealed_state)
    assert error.value.code == "proxy_unavailable" and len(script.calls) == 3
    assert "synthetic" not in str(error.value)


def test_bootstrap_empty_and_start_steps_follow_official_shape(
    monkeypatch, key_context
):
    gateway, events = Gateway(), []
    script = opening(Script(monkeypatch, gateway))

    def inspect(kw):
        body = kw["json"]
        assert body["stepId"] == "" and body["inputs"] == []
        assert (
            body["workflowStateHandle"] == body["startWorkflowHandle"] == "start-secret"
        )
        assert body["requestId"]

    script.add("POST", EXECUTE, workflow("start"), inspect=inspect)
    script.add("POST", EXECUTE, workflow("get-identity-user"))

    def username(kw):
        assert kw["json"]["inputs"] == [
            {"input_type": "UserRequestInput", "username": "alice"},
            {"input_type": "ApplicationTypeRequestInput", "applicationType": "SSO"},
        ]

    script.add(
        "POST",
        EXECUTE,
        workflow(
            "get-password",
            key_context[1],
            {"captchaToken": ams_token(), "captchaCDN": CDN},
        ),
        inspect=username,
    )
    adapter = module().NativeIdentityLogin(
        gateway, checkpoint=events.append, clock=lambda: NOW
    )
    paused = run_ready(adapter, adapter.begin("alice", "old-secret"))
    assert paused.status == "challenge" and len(script.calls) == 6


def test_cookie_state_bootstrap_is_urlencoded_json(monkeypatch, key_context):
    gateway = Gateway()
    script = opening(Script(monkeypatch, gateway))
    state = workflow(
        "get-password", key_context[1], {"captchaToken": ams_token(), "captchaCDN": CDN}
    )
    encoded = quote(json.dumps(state))
    method, url, payload, status, _, inspect = script.steps[-1]
    script.steps[-1] = (
        method,
        url,
        payload,
        status,
        {
            "Set-Cookie": "platform-workflow-state="
            + encoded
            + "; Domain=us-east-1.signin.aws; Path=/platform; Secure; HttpOnly",
        },
        inspect,
    )
    adapter = module().NativeIdentityLogin(
        gateway, checkpoint=lambda e: None, clock=lambda: NOW
    )
    paused = run_ready(adapter, adapter.begin("alice", "old-secret"))
    assert paused.status == "challenge" and len(script.calls) == 3
    assert (
        decrypt(paused.sealed_state)["cookies"][0]["name"] == "platform-workflow-state"
    )

    def inspect_cookie(kwargs):
        assert kwargs["headers"]["Cookie"] == "platform-workflow-state=" + encoded

    script.add("POST", EXECUTE, success(), inspect=inspect_cookie)
    resumed = module().NativeIdentityLogin(
        gateway, checkpoint=lambda e: None, clock=lambda: NOW
    )
    resumed.advance(
        paused.sealed_state,
        answer={
            "challenge_id": paused.challenge["id"],
            "revision": paused.challenge["revision"],
            "access_code": "human-cookie-test",
        },
    )


def test_classical_image_fetch_has_guard_size_mime_and_revision_checks(
    monkeypatch, key_context
):
    image_url = SIGNIN + "/platform/captcha/image?id=synthetic"
    adapter, progress, script, _ = start_at_password(
        monkeypatch, key_context[1], {"captchaURL": image_url, "captchaCES": "ces"}
    )
    content = b"\x89PNG\r\n\x1a\nsynthetic"
    script.add("GET", image_url, content, headers={"Content-Type": "image/png"})
    image = adapter.challenge_image(
        progress.sealed_state, progress.challenge["revision"]
    )
    assert image.content == content and image.content_type == "image/png"
    script.add(
        "GET",
        image_url,
        b"<svg>not a raster</svg>",
        headers={"Content-Type": "image/svg+xml"},
    )
    with pytest.raises(module().AuthError):
        adapter.challenge_image(progress.sealed_state, progress.challenge["revision"])
    script.add(
        "GET",
        image_url,
        b"\x89PNG\r\n\x1a\n" + b"x" * (1024 * 1024),
        headers={"Content-Type": "image/png"},
    )
    with pytest.raises(module().AuthError):
        adapter.challenge_image(progress.sealed_state, progress.challenge["revision"])


@pytest.mark.parametrize(
    "metadata",
    [
        {"apiRoot": "evil.example"},
        {"apiRoot": "us-east-1.threat-mitigation.aws.amazon.com/path"},
        {"region": "eu-central-1"},
        {"envStage": "beta"},
    ],
)
def test_ams_rejects_embedded_untrusted_widget_destinations(
    monkeypatch, key_context, metadata
):
    with pytest.raises(module().AuthError) as error:
        start_at_password(
            monkeypatch,
            key_context[1],
            {"captchaToken": ams_token(**metadata), "captchaCDN": CDN},
        )
    assert error.value.code == "unsupported_challenge"


@pytest.mark.parametrize(
    "changes",
    [
        {"region": "eu-central-1"},
        {"issuer": "other"},
        {"audience": "other"},
        {"publicKey": {"kty": "RSA", "alg": "RSA1_5", "use": "enc"}},
    ],
)
def test_encryption_context_must_match_intended_password_service(key_context, changes):
    with pytest.raises(module().AuthError) as error:
        module().encrypt_password("secret", key_context[1] | changes, "us-east-1", NOW)
    assert error.value.code == "invalid_encryption"


@pytest.mark.parametrize(
    "redirect",
    [
        LOGIN.replace("us-east-1.signin.aws", "evil.example"),
        LOGIN.replace("us-east-1.signin.aws", "eu-central-1.signin.aws"),
        LOGIN.replace("d-1234567890", "d-9999999999"),
        LOGIN + "&password=NEVER_PRINT",
        LOGIN + "&workflowStateHandle=second",
        LOGIN.replace("/login?", "/login/../api/execute?"),
    ],
)
def test_login_redirect_is_region_directory_and_query_specific(monkeypatch, redirect):
    gateway = Gateway()
    script = Script(monkeypatch, gateway)
    script.add("GET", PORTAL, env_html())
    script.add(
        "GET", DP + "/login", {"redirectUrl": redirect, "csrfToken": "csrf-secret"}
    )
    adapter = module().NativeIdentityLogin(
        gateway, checkpoint=lambda e: None, clock=lambda: NOW
    )
    with pytest.raises(module().AuthError) as error:
        run_ready(adapter, adapter.begin("alice", "old-secret"))
    assert error.value.code == "unsafe_destination" and len(script.calls) == 2
    assert "NEVER_PRINT" not in str(error.value)


@pytest.mark.parametrize(
    "redirect",
    [
        {
            "url": "https://evil.example/start?workflowResultHandle=secret",
            "method": "GET",
        },
        {
            "url": PORTAL + "?workflowResultHandle=secret&access_token=NEVER_PRINT",
            "method": "GET",
        },
        {"url": PORTAL + "?workflowResultHandle=secret", "method": "DELETE"},
        {
            "url": PORTAL,
            "method": "POST",
            "postParams": [{"name": "password", "value": "NEVER_PRINT"}],
        },
        {
            "url": PORTAL
            + "?workflowResultHandle=secret&wdc_csrf_token=one&wdc_csrf_token=two",
        },
        {"url": PORTAL + "?workflowResultHandle=secret&wdc_csrf_token="},
        {
            "url": PORTAL
            + "?workflowResultHandle=secret&wdc_csrf_token=NEVER_PRINT%0A",
        },
        {
            "url": PORTAL
            + "?workflowResultHandle=secret&wdc_csrf_token=extra&access_token=NEVER_PRINT",
        },
        {
            "url": PORTAL + "?workflowResultHandle=secret",
            "method": "POST",
            "postParams": [{"name": "wdc_csrf_token", "value": "NEVER_PRINT"}],
        },
    ],
)
def test_success_redirect_is_validated_before_token_exchange(
    monkeypatch, key_context, redirect
):
    adapter, progress, script, _ = start_at_password(monkeypatch, key_context[1])
    value = success()
    value["redirect"] = redirect
    script.add("POST", EXECUTE, value)
    with pytest.raises(module().AuthError) as error:
        adapter.advance(progress.sealed_state)
    assert error.value.code == "unsafe_destination" and len(script.calls) == 4
    assert "NEVER_PRINT" not in str(error.value)


def test_portal_redirect_accepts_wdc_metadata_without_forwarding_it(
    monkeypatch, key_context
):
    adapter, progress, script, _ = start_at_password(monkeypatch, key_context[1])
    value = success()
    value["redirect"]["url"] = (
        PORTAL + "/?state=csrf-state&workflowResultHandle=result-secret"
        "&wdc_csrf_token=browser-csrf-metadata"
    )
    script.add("POST", EXECUTE, value)

    def inspect(kw):
        assert kw["data"] == {
            "authCode": "result-secret",
            "orgId": "d-1234567890",
            "state": "csrf-state",
        }
        assert kw["headers"]["x-amz-sso-csrf-token"] == "login-csrf"
        assert "browser-csrf-metadata" not in str(kw)

    script.add(
        "POST", DP + "/auth/sso-token", {"token": "portal-secret"}, inspect=inspect
    )
    script.add(
        "GET",
        DP + "/token/whoAmI",
        {"userIdentifier": "user-synthetic", "directoryId": "d-1234567890"},
    )
    completed = run_ready(adapter, progress)
    assert completed.status == "done"
    assert completed.result["identity"]["userIdentifier"] == "user-synthetic"
    assert len(script.calls) == 6


def test_portal_post_redirect_uses_only_allowed_form_fields(monkeypatch, key_context):
    adapter, progress, script, _ = start_at_password(monkeypatch, key_context[1])
    value = success()
    value["redirect"] = {
        "url": PORTAL,
        "method": "POST",
        "postParams": [
            {"name": "workflowResultHandle", "value": "post-code"},
            {"name": "state", "value": "post-state"},
        ],
    }
    script.add("POST", EXECUTE, value)

    def inspect(kw):
        assert kw["data"] == {
            "authCode": "post-code",
            "orgId": "d-1234567890",
            "state": "post-state",
        }
        assert kw["headers"]["x-amz-sso-csrf-token"] == "login-csrf"

    script.add(
        "POST", DP + "/auth/sso-token", {"token": "portal-secret"}, inspect=inspect
    )
    script.add("GET", DP + "/token/whoAmI", {"userIdentifier": "wrong-identity"})
    with pytest.raises(module().AuthError) as error:
        run_ready(adapter, progress)
    assert error.value.code == "identity_mismatch"


def test_dualstack_uses_only_validated_portal_origin_apis(monkeypatch, key_context):
    gateway = Gateway()
    script = Script(monkeypatch, gateway)
    portal_origin = "https://d-1234567890.awsapps.com"
    script.add(
        "GET",
        PORTAL,
        env_html(
            dualstack=True,
            dpApiEndpoint="https://ignored.invalid",
            oidcApiEndpoint="https://ignored.invalid",
        ),
    )

    def inspect(kw):
        assert kw["params"] == {
            "redirect_url": PORTAL,
            "idc_instance_id": "ssoins-1234567890123456",
        }

    script.add(
        "GET",
        portal_origin + "/api/portal/login",
        {"redirectUrl": LOGIN, "csrfToken": "csrf"},
        inspect=inspect,
    )
    state = workflow(
        "get-password", key_context[1], {"captchaToken": ams_token(), "captchaCDN": CDN}
    )
    script.add(
        "GET",
        LOGIN,
        '<meta name="initial-workflow-state" content="'
        + base64.b64encode(json.dumps(state).encode()).decode()
        + '">',
    )
    adapter = module().NativeIdentityLogin(
        gateway, checkpoint=lambda e: None, clock=lambda: NOW
    )
    paused = run_ready(adapter, adapter.begin("alice", "old-secret"))
    assert paused.status == "challenge"
    assert decrypt(paused.sealed_state)["oidc"] == portal_origin + "/api/oidc"


def test_every_session_disables_env_proxy_retries_and_redirects(
    monkeypatch, key_context
):
    auth = module()
    original = auth.request_session
    seen = []

    def session(proxy):
        value = original(proxy)
        seen.append(value)
        assert not value.trust_env and value.verify is True
        assert value.proxies == {"http": proxy, "https": proxy}
        assert value.adapters["https://"].max_retries.total == 0
        return value

    monkeypatch.setattr(auth, "request_session", session)
    adapter, progress, script, _ = start_at_password(monkeypatch, key_context[1])
    script.add(
        "POST",
        EXECUTE,
        b"",
        status=302,
        headers={"Location": "https://evil.example/?password=secret"},
    )
    with pytest.raises(auth.AuthError) as error:
        adapter.advance(progress.sealed_state)
    assert (
        error.value.code == "unsafe_destination"
        and len(seen) == 4
        and len(script.calls) == 4
    )


@pytest.mark.parametrize(
    "malformed",
    [
        {
            "stepId": "get-password",
            "workflowStateHandle": "handle",
            "presentationContext": [],
        },
        {
            "stepId": "get-password",
            "workflowStateHandle": "handle",
            "presentationContext": None,
        },
        {
            "stepId": "get-password",
            "workflowStateHandle": "handle",
            "passwordStringContext": None,
        },
    ],
)
def test_malformed_nested_schema_returns_safe_error_not_python_exception(
    monkeypatch, key_context, malformed
):
    adapter, progress, script, _ = start_at_password(monkeypatch, key_context[1])
    script.add("POST", EXECUTE, malformed)
    with pytest.raises(module().AuthError):
        resumed = adapter.advance(progress.sealed_state)
        adapter.advance(resumed.sealed_state)


def unknown_password(monkeypatch, key_context):
    adapter, progress, script, events = start_at_password(
        monkeypatch, key_context[1], target_password="Candidate9!", password_only=True
    )
    script.add(
        "POST",
        EXECUTE,
        workflow("get-new-password-for-change-password", key_context[1]),
    )
    progress = adapter.advance(progress.sealed_state)
    script.add("POST", EXECUTE, {"unexpected": "NEVER_PRINT"})
    with pytest.raises(module().AuthError) as error:
        adapter.advance(progress.sealed_state)
    return adapter, script, events, error.value.credential


def test_recovery_tries_candidate_and_current_once_and_preserves_exhaustion(
    monkeypatch, key_context
):
    adapter, script, events, credential = unknown_password(monkeypatch, key_context)
    opening(script, workflow("get-password", key_context[1]))
    credentials = []

    def inspect(kw):
        credentials.append(
            decrypt_password(key_context[0], kw["json"]["inputs"][0]["password"])[1][
                "password"
            ]
        )

    for _ in range(2):
        script.add(
            "POST",
            EXECUTE,
            workflow("get-password", message={"code": "AUTHENTICATION_FAILED"}),
            inspect=inspect,
        )
    with pytest.raises(module().AuthError) as error:
        run_ready(
            adapter,
            adapter.begin(
                "alice",
                "old-secret",
                expected_user_id="user-synthetic",
                recovery=credential,
                password_only=True,
            ),
        )
    assert error.value.code == "credential_attempt_limit" and credentials == [
        "Candidate9!",
        "old-secret",
    ]
    credential = decrypt(error.value.credential)
    assert (
        credential["tried"] == ["candidate", "current"]
        and credential["status"] == "unknown"
    )
    opening(script, workflow("get-password", key_context[1]))
    with pytest.raises(module().AuthError) as exhausted:
        run_ready(
            adapter,
            adapter.begin(
                "alice",
                "old-secret",
                expected_user_id="user-synthetic",
                recovery=error.value.credential,
                password_only=True,
            ),
        )
    assert exhausted.value.code == "credential_attempt_limit" and not script.steps


def test_recovery_stops_on_challenge_before_attempting_saved_candidate(
    monkeypatch, key_context
):
    adapter, script, _, credential = unknown_password(monkeypatch, key_context)
    opening(
        script,
        workflow(
            "get-password",
            key_context[1],
            {"captchaToken": ams_token(), "captchaCDN": CDN},
        ),
    )
    paused = run_ready(
        adapter,
        adapter.begin(
            "alice",
            "old-secret",
            expected_user_id="user-synthetic",
            recovery=credential,
            password_only=True,
        ),
    )
    assert (
        paused.status == "challenge"
        and decrypt(paused.sealed_state)["credential"]["tried"] == []
    )


def test_native_workflow_cannot_be_resumed_as_a_different_account(
    monkeypatch, key_context
):
    adapter, progress, script, _ = start_at_password(monkeypatch, key_context[1])
    adapter.gateway.account.id = 43
    with pytest.raises(module().AuthError) as error:
        adapter.advance(progress.sealed_state)
    assert error.value.code == "invalid_state" and len(script.calls) == 3


@pytest.mark.parametrize("location", [PORTAL + "/", "/start/"])
def test_canonical_portal_redirect_is_one_explicit_guarded_get(
    monkeypatch, key_context, location
):
    gateway = Gateway()
    script = Script(monkeypatch, gateway)
    script.add("GET", PORTAL, b"", status=302, headers={"Location": location})
    script.add("GET", PORTAL + "/", env_html())

    def inspect(kw):
        assert kw["params"]["redirect_url"] == PORTAL + "/"

    script.add(
        "GET",
        DP + "/login",
        {"redirectUrl": LOGIN, "csrfToken": "csrf"},
        inspect=inspect,
    )
    adapter = module().NativeIdentityLogin(
        gateway, checkpoint=lambda e: None, clock=lambda: NOW
    )
    progress = adapter.begin("alice", "old-secret")
    progress = adapter.advance(progress.sealed_state)
    assert progress.status == "ready" and len(script.calls) == 1
    assert decrypt(progress.sealed_state)["portal_load_url"] == PORTAL + "/"
    progress = adapter.advance(progress.sealed_state)
    adapter.advance(progress.sealed_state)
    assert len(script.calls) == 3 and not script.steps


@pytest.mark.parametrize(
    "location",
    [
        "https://evil.example/start/",
        PORTAL + "/?password=NEVER_PRINT",
        PORTAL + "/#secret",
        PORTAL.replace("https://", "http://") + "/",
        PORTAL + "/../logout",
        PORTAL,
        "//d-1234567890.awsapps.com/start/",
        "start/",
        "/start",
        "/start/?password=NEVER_PRINT",
        "/start/#secret",
        "/other/../start/",
    ],
)
def test_canonical_portal_redirect_rejects_other_hosts_queries_and_loops(
    monkeypatch, location
):
    gateway = Gateway()
    script = Script(monkeypatch, gateway)
    script.add("GET", PORTAL, b"", status=302, headers={"Location": location})
    adapter = module().NativeIdentityLogin(
        gateway, checkpoint=lambda e: None, clock=lambda: NOW
    )
    with pytest.raises(module().AuthError) as error:
        adapter.advance(adapter.begin("alice", "old-secret").sealed_state)
    assert error.value.code == "unsafe_destination" and len(script.calls) == 1


@pytest.mark.parametrize("location", [PORTAL + "/", "/start/"])
def test_canonical_portal_redirect_cannot_repeat(monkeypatch, location):
    gateway = Gateway()
    script = Script(monkeypatch, gateway)
    script.add("GET", PORTAL, b"", status=302, headers={"Location": "/start/"})
    script.add("GET", PORTAL + "/", b"", status=302, headers={"Location": location})
    adapter = module().NativeIdentityLogin(
        gateway, checkpoint=lambda e: None, clock=lambda: NOW
    )
    progress = adapter.advance(adapter.begin("alice", "old-secret").sealed_state)
    with pytest.raises(module().AuthError) as error:
        adapter.advance(progress.sealed_state)
    assert error.value.code == "unsafe_destination" and len(script.calls) == 2


def test_unknown_exchange_response_cannot_be_replayed_by_resuming_error_state(
    monkeypatch, key_context
):
    adapter, progress, script, _ = start_at_password(monkeypatch, key_context[1])
    script.add("POST", EXECUTE, success())
    progress = adapter.advance(progress.sealed_state)
    script.add("POST", DP + "/auth/sso-token", b"malformed NEVER_PRINT")
    with pytest.raises(module().AuthError) as first:
        adapter.advance(progress.sealed_state)
    with pytest.raises(module().AuthError) as second:
        adapter.advance(first.value.sealed_state)
    assert (
        second.value.code in {"interrupted", "invalid_state"} and len(script.calls) == 5
    )


def test_progress_diagnostics_are_safe_internal_stage_names(monkeypatch, key_context):
    _, progress, _, _ = start_at_password(monkeypatch, key_context[1])
    assert progress.stage == "workflow"
    assert progress.revision > 0 and "handle" not in repr(progress)


def test_restart_after_saved_password_confirmation_never_replays_write(
    monkeypatch, key_context
):
    adapter, progress, script, events = start_at_password(
        monkeypatch, key_context[1], target_password="Candidate9!", password_only=True
    )
    script.add(
        "POST",
        EXECUTE,
        workflow("get-new-password-for-change-password", key_context[1]),
    )
    script.add("POST", EXECUTE, success())
    run_ready(adapter, progress)
    saved = next(e.sealed_state for e in events if e.event == "password_confirmed")
    resumed = module().NativeIdentityLogin(
        adapter.gateway, checkpoint=events.append, clock=lambda: NOW
    )
    done = resumed.advance(saved)
    assert (
        done.status == "done"
        and done.result["password"] == "Candidate9!"
        and len(script.calls) == 5
    )


def test_durable_credential_recovery_survives_subscription_profile_changes(
    monkeypatch, key_context
):
    adapter, script, _, credential = unknown_password(monkeypatch, key_context)
    adapter.gateway.account.profile_arn = (
        "arn:aws:codewhisperer:us-east-1:123456789012:profile/new-enterprise"
    )
    adapter.gateway.account.subscription_region = "us-east-1"
    opening(script, workflow("get-password", key_context[1]))
    script.add("POST", EXECUTE, success())
    done = run_ready(
        adapter,
        adapter.begin(
            "alice",
            "old-secret",
            expected_user_id="user-synthetic",
            recovery=credential,
            password_only=True,
        ),
    )
    assert done.status == "done" and done.result["password"] == "Candidate9!"


def test_only_new_human_answer_allows_normal_login_to_continue_after_captcha(
    monkeypatch, key_context
):
    adapter, progress, script, _ = start_at_password(
        monkeypatch, key_context[1], password_only=True
    )
    script.add(
        "POST",
        EXECUTE,
        workflow(
            "get-password",
            key_context[1],
            {"captchaToken": ams_token(), "captchaCDN": CDN},
        ),
    )
    paused = adapter.advance(progress.sealed_state)
    assert paused.status == "challenge"
    assert (
        adapter.advance(paused.sealed_state).status == "challenge"
        and len(script.calls) == 4
    )
    script.add("POST", EXECUTE, success())
    done = adapter.advance(
        paused.sealed_state,
        answer={
            "challenge_id": paused.challenge["id"],
            "revision": paused.challenge["revision"],
            "access_code": "human-new-answer",
        },
    )
    assert done.status == "done" and len(script.calls) == 5


def test_unknown_recovery_does_not_replay_tried_candidate_after_human_answer(
    monkeypatch, key_context
):
    adapter, script, _, credential = unknown_password(monkeypatch, key_context)
    opening(script, workflow("get-password", key_context[1]))
    script.add(
        "POST",
        EXECUTE,
        workflow(
            "get-password",
            key_context[1],
            {"captchaToken": ams_token(), "captchaCDN": CDN},
        ),
    )
    paused = run_ready(
        adapter,
        adapter.begin(
            "alice",
            "old-secret",
            expected_user_id="user-synthetic",
            recovery=credential,
            password_only=True,
        ),
    )
    assert paused.status == "challenge"
    with pytest.raises(module().AuthError) as error:
        adapter.advance(
            paused.sealed_state,
            answer={
                "challenge_id": paused.challenge["id"],
                "revision": paused.challenge["revision"],
                "access_code": "human-new-answer",
            },
        )
    assert error.value.code == "password_unresolved"
    assert (
        decrypt(error.value.credential)["tried"] == ["candidate"] and not script.steps
    )


def test_real_mfa_requests_administrator_action_while_ams_remains_a_challenge(
    monkeypatch, key_context
):
    adapter, progress, script, _ = start_at_password(monkeypatch, key_context[1])
    script.add("POST", EXECUTE, workflow("get-totp-login-credential"))
    with pytest.raises(module().AuthError) as error:
        adapter.advance(progress.sealed_state)
    assert error.value.code == "unsupported_mfa"
    assert "请管理员在对应的 AWS IAM Identity Center 关闭 MFA 后重试" in str(
        error.value
    )
    _, progress, _, _ = start_at_password(
        monkeypatch, key_context[1], {"captchaToken": ams_token(), "captchaCDN": CDN}
    )
    assert progress.status == "challenge" and progress.challenge["kind"] == "ams"


@pytest.mark.parametrize(
    "scenario",
    [
        "canonical",
        "canonical_relative",
        "rejected_redirect",
        "image_redirect",
        "large_image",
    ],
)
def test_real_session_does_not_prebuffer_redirects_or_oversized_images(
    monkeypatch, key_context, scenario
):
    if scenario in {"image_redirect", "large_image"}:
        with monkeypatch.context() as prepare:
            adapter, progress, _, _ = start_at_password(
                prepare,
                key_context[1],
                {
                    "captchaURL": SIGNIN + "/platform/captcha/image?id=synthetic",
                    "captchaCES": "ces",
                },
            )
    else:
        adapter = module().NativeIdentityLogin(
            Gateway(), checkpoint=lambda e: None, clock=lambda: NOW
        )
        progress = adapter.begin("alice", "old-secret")

    class CountedStream(io.BytesIO):
        read_bytes = 0

        def read(self, size=-1):
            value = super().read(size)
            self.read_bytes += len(value)
            return value

    source = CountedStream(b"\x89PNG\r\n\x1a\n" + b"x" * (6 * 1024 * 1024))
    calls = []

    def send(http_adapter, request, **kwargs):
        calls.append(request)
        assert kwargs["stream"] is True and kwargs["verify"] is True
        assert kwargs["timeout"][0] == 5
        assert kwargs["proxies"] == {
            "https": adapter.gateway.proxy.url,
            "http": adapter.gateway.proxy.url,
        }
        assert http_adapter.max_retries.total == 0
        response = requests.Response()
        response.request, response.url = request, request.url
        response.status_code = 200 if scenario == "large_image" else 302
        response.headers["Content-Type"] = "image/png"
        response.headers["Location"] = (
            "/start/"
            if scenario == "canonical_relative"
            else PORTAL + "/"
            if scenario == "canonical"
            else "https://evil.example/"
        )
        response.raw = HTTPResponse(body=source, preload_content=False)
        return response

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", send)
    try:
        if scenario in {"image_redirect", "large_image"}:
            result = adapter.challenge_image(
                progress.sealed_state, progress.challenge["revision"]
            )
        else:
            result = adapter.advance(progress.sealed_state)
    except module().AuthError as error:
        result = error
    assert len(calls) == 1
    assert source.read_bytes <= (
        adapter.MAX_IMAGE + 65536 if scenario == "large_image" else 0
    )
    if scenario in {"canonical", "canonical_relative"}:
        assert result.status == "ready"
        assert decrypt(result.sealed_state)["portal_load_url"] == PORTAL + "/"
    else:
        assert isinstance(result, module().AuthError)
        assert result.code == (
            "invalid_response" if scenario == "large_image" else "unsafe_destination"
        )
