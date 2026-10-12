"""Bounded native built-in-directory login, observed in official AWS JS, 2026-10-09.

No browser, fingerprint, solver, filesystem credentials, or implicit network retries.
Each ``advance`` makes at most one HTTP request and returns an encrypted checkpoint.
Only ``AuthProgress.challenge`` is suitable for an owner-scoped challenge endpoint;
``result`` and all decrypted state are private. Never log them.
Completed portal authentication requires an expected_user_id and matching whoAmI
identity-store user/directory IDs; a missing identity never authorizes a device.

The caller must serialize operations and persist Checkpoint.sealed_state atomically
before returning from the synchronous callback. Password events ALSO carry a separate
encrypted credential checkpoint: persist it on the SSO record, independently of the
short-lived export state. Do not purge an unresolved candidate on cancel/expiry.
``password_pending`` is emitted BEFORE dispatch and already records uncertainty.
After a crash, resume an in-flight write only through explicit credential recovery
(begin(recovery=...)); never resubmit the old HTTP request. Recovery tries candidate
then current at most once each, with durable attempt checkpoints.

Callback failure stops work and raises a redacted AuthError with encrypted recovery
data. In particular, a failed confirmation callback must not cause a password replay.
Job leases, actor permissions and CAS on checkpoint revisions belong to the job layer.
"""

import base64
import binascii
import json
import re
import secrets
import time
import uuid
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qsl, unquote_plus, urlsplit

import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .aws import AwsFailure
from .aws_transport import request_session
from .config import settings
from .security import decrypt, encrypt


MESSAGES = {
    "unsafe_destination": "AWS 登录目标不在受支持的 HTTPS 地址范围内",
    "invalid_configuration": "AWS 身份中心配置无效",
    "invalid_response": "AWS 返回的登录数据无法识别",
    "invalid_state": "登录状态无效，请安全地重新开始",
    "expired": "登录或设备授权已过期，请安全地重新开始",
    "interrupted": "上次认证请求结果未知，需恢复凭据或重新开始认证",
    "checkpoint_failed": "认证状态保存失败，已停止后续请求；请保留凭据恢复数据",
    "proxy_unavailable": "账号代理不可用，认证已停止",
    "transport_failed": "AWS 认证连接失败",
    "http_failed": "AWS 拒绝认证请求",
    "unsupported_challenge": "AWS 验证码形式或官方组件目标无法安全确认",
    "stale_challenge": "验证码回答与当前挑战不匹配，请刷新当前任务",
    "unsupported_mfa": "此登录需要 MFA。请管理员在对应的 AWS IAM Identity Center 关闭 MFA 后重试",
    "external_identity_provider": "此登录使用外部身份提供商，当前流程不支持",
    "unsupported_step": "AWS 返回了当前原生认证流程不支持的步骤",
    "login_refused": "AWS 拒绝登录，请检查当前凭据",
    "password_rejected": "AWS 未确认永久密码变更，请保留候选密码以核对",
    "password_unresolved": "密码结果仍需核对，已停止自动密码变更",
    "password_not_applied": "AWS 未要求密码变更，目标永久密码尚未设置",
    "credential_attempt_limit": "凭据恢复尝试已用完，已停止登录",
    "identity_mismatch": "AWS 门户身份与所选 SSO 用户不匹配",
    "invalid_encryption": "AWS 密码加密上下文无效",
    "step_limit": "AWS 登录步骤超过安全上限",
    "oauth_failed": "AWS OIDC 授权失败",
    "device_mismatch": "AWS 设备授权与本次注册客户端不匹配",
    "no_profile": "未找到配置的企业 Kiro profile，无法确认订阅可用",
    "pagination_limit": "Kiro profile 分页异常或超过安全上限",
    "token_invalid": "AWS OIDC 令牌响应或有效期无效",
    "paid_entitlement_unconfirmed": "AWS 用量响应未确认受支持的付费订阅，无法导出 JSON；请先完成订阅并核对状态",
}


class AuthError(AwsFailure):
    """Static public error; attached encrypted recovery data must stay private."""

    def __init__(self, code, *, uncertain=False, http_status=None, retryable=None,
                 proven_unsent=False, aws_code=None):
        self.code = code if code in MESSAGES else "invalid_response"
        self.sealed_state = None
        self.credential = None
        super().__init__(MESSAGES[self.code], uncertain=uncertain, code=self.code,
                         http_status=http_status, retryable=retryable,
                         proven_unsent=proven_unsent)
        self.aws_code = aws_code


@dataclass(frozen=True)
class Checkpoint:
    event: str
    sealed_state: str = field(repr=False)
    credential: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class AuthProgress:
    status: str
    sealed_state: str = field(repr=False)
    revision: int = 0
    challenge: dict | None = field(default=None, repr=False)
    next_poll_at: float | None = None
    result: dict | None = field(default=None, repr=False)
    stage: str = ""


@dataclass(frozen=True)
class ChallengeImage:
    content: bytes = field(repr=False)
    content_type: str


def require_text(value, *, maximum=16384, code="invalid_response"):
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise AuthError(code)
    return value


def require_number(value, *, minimum=0, maximum=10**12, code="invalid_response"):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not minimum <= value <= maximum
    ):
        raise AuthError(code)
    return value


def _url(value):
    require_text(value, maximum=32768, code="unsafe_destination")
    if "\\" in value or any(c.isspace() for c in value):
        raise AuthError("unsafe_destination")
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
        if (
            parsed.scheme != "https"
            or not host
            or parsed.username is not None
            or parsed.password is not None
            or port not in (None, 443)
            or parsed.netloc not in {host, host + ":443"}
        ):
            raise ValueError()
    except ValueError:
        raise AuthError("unsafe_destination") from None
    return parsed


def _query(value, allowed):
    try:
        pairs = parse_qsl(
            value, keep_blank_values=True, strict_parsing=True, max_num_fields=12
        )
    except ValueError:
        raise AuthError("unsafe_destination") from None
    result = dict(pairs)
    if len(result) != len(pairs) or not set(result) <= allowed:
        raise AuthError("unsafe_destination")
    for entry in result.values():
        require_text(entry, code="unsafe_destination")
    return result


def _b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _unb64(value):
    require_text(value, maximum=20000, code="invalid_encryption")
    return base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    )


def encrypt_password(password, context, region, now):
    """Create the official RSA-OAEP-256/A256GCM compact password JWE."""
    try:
        if not isinstance(context, dict) or (
            context.get("issuer"),
            context.get("audience"),
            context.get("region"),
        ) != ("signin", "AWSPasswordService", region):
            raise ValueError()
        jwk = context["publicKey"]
        if (jwk["kty"], jwk["use"], jwk["alg"]) != ("RSA", "enc", "RSA-OAEP-256"):
            raise ValueError()
        kid = require_text(jwk["kid"], maximum=256, code="invalid_encryption")
        key = rsa.RSAPublicNumbers(
            int.from_bytes(_unb64(jwk["e"]), "big"),
            int.from_bytes(_unb64(jwk["n"]), "big"),
        ).public_key()
        if not 2048 <= key.key_size <= 8192:
            raise ValueError()
        protected = _b64(
            json.dumps(
                {
                    "alg": "RSA-OAEP-256",
                    "enc": "A256GCM",
                    "kid": kid,
                    "cty": "enc",
                    "typ": "application/aws+signin+jwe",
                },
                separators=(",", ":"),
            ).encode()
        )
        issued = int(now)
        claims = {
            "iss": region + ".signin",
            "aud": region + ".AWSPasswordService",
            "iat": issued,
            "nbf": issued,
            "jti": str(uuid.uuid4()),
            "exp": issued + 300,
            "password": password,
        }
        cek, iv = secrets.token_bytes(32), secrets.token_bytes(12)
        encrypted = AESGCM(cek).encrypt(
            iv, json.dumps(claims, separators=(",", ":")).encode(), protected.encode()
        )
        encrypted_key = key.encrypt(
            cek,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None
            ),
        )
        return ".".join(
            (
                protected,
                _b64(encrypted_key),
                _b64(iv),
                _b64(encrypted[:-16]),
                _b64(encrypted[-16:]),
            )
        )
    except (ValueError, KeyError, TypeError, binascii.Error, AttributeError):
        raise AuthError("invalid_encryption") from None


class _BootstrapHTML(HTMLParser):
    def __init__(self):
        super().__init__()
        self.env_parts = []
        self.in_env = False
        self.env_count = 0
        self.workflow = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if (
            tag == "script"
            and attrs.get("id") == "env"
            and attrs.get("type") == "application/json"
        ):
            self.in_env = True
            self.env_count += 1
        if tag == "meta" and attrs.get("name") == "initial-workflow-state":
            if self.workflow is not None:
                raise AuthError("invalid_response")
            self.workflow = attrs.get("content", "")

    def handle_endtag(self, tag):
        if tag == "script":
            self.in_env = False

    def handle_data(self, value):
        if self.in_env:
            self.env_parts.append(value)


class NativeIdentityLogin:
    """Native portal or standalone permanent-password completion; no OAuth SDK."""

    kind = "identity"
    MAX_STEPS = 40
    MAX_BODY = 2 * 1024 * 1024
    MAX_IMAGE = 1024 * 1024

    def __init__(self, gateway, *, checkpoint, clock=time.time):
        if not callable(checkpoint):
            raise AuthError("invalid_configuration")
        self.gateway, self.checkpoint, self.clock = gateway, checkpoint, clock

    def _binding(self):
        a = self.gateway.account
        portal = _url(a.portal_url)
        if not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-\d", a.region) or not re.fullmatch(
            r"[a-zA-Z0-9-]{1,100}", a.identity_store_id
        ):
            raise AuthError("invalid_configuration")
        if not re.fullmatch(
            r"arn:aws:sso:::instance/ssoins-[a-zA-Z0-9]+", a.instance_arn
        ):
            raise AuthError("invalid_configuration")
        if (
            not re.fullmatch(
                r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:awsapps\.com|app\.aws)",
                portal.hostname,
            )
            or portal.path not in ("/start", "/start/")
            or portal.query
            or portal.fragment
        ):
            raise AuthError("unsafe_destination")
        return {
            "account_id": a.id,
            "region": a.region,
            "directory": a.identity_store_id,
            "instance": a.instance_arn,
            "portal": a.portal_url,
            "api_region": a.subscription_region,
            "profile_arn": a.profile_arn,
        }

    def _new_state(
        self,
        username,
        password,
        *,
        expected_user_id=None,
        target_password=None,
        recovery=None,
        password_only=False,
    ):
        binding = self._binding()
        credential_binding = {
            key: binding[key]
            for key in ("account_id", "region", "directory", "instance")
        }
        require_text(username, maximum=256, code="invalid_configuration")
        require_text(password, maximum=1024, code="invalid_configuration")
        if expected_user_id is not None:
            require_text(expected_user_id, maximum=256, code="invalid_configuration")
        if target_password is not None:
            require_text(target_password, maximum=64, code="invalid_configuration")
            if len(target_password) < 8:
                raise AuthError("invalid_configuration")
        credential = {
            "binding": credential_binding,
            "username": username,
            "expected_user_id": expected_user_id,
            "current": password,
            "candidate": None,
            "status": "current",
            "tried": [],
        }
        if recovery is not None:
            try:
                credential = decrypt(recovery)
                if (
                    credential["binding"] != credential_binding
                    or credential["username"] != username
                    or credential["expected_user_id"] != expected_user_id
                    or credential["status"] not in ("candidate", "unknown", "confirmed")
                    or not isinstance(credential["tried"], list)
                    or not set(credential["tried"]) <= {"candidate", "current"}
                ):
                    raise ValueError()
                require_text(credential["current"], maximum=1024)
                require_text(credential["candidate"], maximum=1024)
            except Exception:
                raise AuthError("invalid_state") from None
        return {
            "version": 1,
            "kind": self.kind,
            "binding": binding,
            "operation_id": str(uuid.uuid4()),
            "username": username,
            "expected_user_id": expected_user_id,
            "credential": credential,
            "recovering": recovery is not None,
            "target_password": target_password,
            "password_only": bool(password_only),
            "stage": "portal",
            "status": "ready",
            "expires_at": self.clock() + 900,
            "revision": 0,
            "steps": 0,
            "cookies": [],
            "inflight": None,
            "challenge": None,
            "password_changed": False,
        }

    def begin(self, username, password, **kwargs):
        return self._publish(self._new_state(username, password, **kwargs))

    def _load(self, sealed_state):
        try:
            state = decrypt(sealed_state)
            if (
                state["version"] != 1
                or state["kind"] != self.kind
                or state["binding"] != self._binding()
                or state["status"] not in {"ready", "challenge", "polling", "done"}
            ):
                raise ValueError()
        except Exception:
            raise AuthError("invalid_state") from None
        if self.clock() >= state["expires_at"]:
            raise self._context_error(AuthError("expired"), state)
        if state.get("inflight"):
            raise self._context_error(AuthError("interrupted", uncertain=True), state)
        return state

    def _context_error(self, error, state):
        error.sealed_state = encrypt(state)
        error.credential = encrypt(state["credential"])
        error.uncertain = error.uncertain or state["credential"]["status"] == "unknown"
        return error

    def _emit(self, state, event="state", *, credential=False):
        state["revision"] += 1
        checkpoint = Checkpoint(
            event, encrypt(state), encrypt(state["credential"]) if credential else None
        )
        try:
            self.checkpoint(checkpoint)
        except Exception:
            raise self._context_error(AuthError("checkpoint_failed"), state) from None
        return checkpoint.sealed_state

    def _publish(self, state):
        sealed = self._emit(state)
        return AuthProgress(
            state["status"],
            sealed,
            state["revision"],
            self._public_challenge(state),
            state.get("next_poll_at"),
            state.get("result"),
            stage=state["stage"],
        )

    def advance(self, sealed_state, *, answer=None):
        state = self._load(sealed_state)
        try:
            if state["status"] == "done":
                return self._publish(state)
            if state["steps"] >= self.MAX_STEPS:
                raise AuthError("step_limit")
            captcha_request = self._answer(state, answer)
            if state["status"] == "challenge" and answer is None:
                return self._publish(state)
            self._advance(state, captcha_request)
            return self._publish(state)
        except AuthError as error:
            raise self._fail(state, error) from None
        except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
            # Schema mismatches must never expose arbitrary response values or URLs.
            raise self._fail(state, AuthError("invalid_response")) from None

    def _fail(self, state, error):
        if error.code != "stale_challenge":
            state["status"] = "failed"
        if state.get("password_write_pending") and error.code != "checkpoint_failed":
            state["credential"]["status"] = "unknown"
            self._emit(state, "password_unknown", credential=True)
            error.uncertain = True
        return self._context_error(error, state)

    def _guard(self):
        try:
            self.gateway._check_proxy()
        except Exception:
            raise AuthError("proxy_unavailable") from None

    def _request(self, state, method, url, *, purpose, image=False, **kwargs):
        self._validate_target(state, url, purpose)
        self._guard()
        if method != "GET":
            state["inflight"] = state["stage"]
            self._emit(state, "request_pending")
        try:
            proxy = self.gateway.proxy
            with request_session(proxy.url if proxy else None) as session:
                for cookie in state["cookies"]:
                    if self._cookie_allowed(state, cookie):
                        session.cookies.set_cookie(
                            requests.cookies.create_cookie(**cookie)
                        )
                prepared = session.prepare_request(
                    requests.Request(method, url, **kwargs)
                )
                # The guard is immediately before every wire request, including images.
                self._guard()
                # Session.request/send internally pre-read redirect bodies even
                # with allow_redirects=False. Sending the prepared request through
                # its adapter avoids that hidden buffering and redirect processing.
                deadline = getattr(self, "request_deadline", None)
                if deadline is not None:
                    from .auth_deadline_transport import send

                    response = send(prepared, session, proxy=proxy.url if proxy else None,
                                    guard=self._guard, deadline=deadline,
                                    limit=self.MAX_IMAGE if image else self.MAX_BODY)
                else:
                    response = session.get_adapter(prepared.url).send(
                        prepared,
                        timeout=(5, settings.aws_timeout),
                        verify=True,
                        stream=True,
                        proxies=session.proxies,
                    )
                with response:
                    canonical = None
                    if response.status_code == 302 and purpose == "portal":
                        location = response.headers.get("Location")
                        # Observed portal canonicalization, not a general redirect follower.
                        # The next advance performs this one additional guarded GET.
                        if (
                            method != "GET"
                            or url != state["binding"]["portal"]
                            or _url(url).path != "/start"
                            or state.get("portal_load_url")
                            or location not in ("/start/", url + "/")
                        ):
                            raise AuthError("unsafe_destination")
                        canonical = url + "/"
                    elif not 200 <= response.status_code < 300:
                        raise AuthError(
                            "unsafe_destination"
                            if 300 <= response.status_code < 400
                            else "http_failed",
                            uncertain=method != "GET",
                            http_status=response.status_code,
                            retryable=response.status_code == 429 or response.status_code >= 500,
                            proven_unsent=(400 <= response.status_code < 500
                                           and response.status_code not in (408, 409, 425)),
                        )
                    limit = self.MAX_IMAGE if image else self.MAX_BODY
                    content = bytearray()
                    requests.cookies.extract_cookies_to_jar(
                        session.cookies, prepared, response.raw
                    )
                    # Canonical redirect bodies have no protocol meaning. Close
                    # without reading; the next advance performs the allowed GET.
                    if not canonical:
                        for chunk in response.iter_content(65536):
                            content.extend(chunk)
                            if len(content) > limit:
                                raise AuthError(
                                    "invalid_response", uncertain=method != "GET"
                                )
                    content_type = (
                        response.headers.get("Content-Type", "")
                        .split(";", 1)[0]
                        .lower()
                    )
                cookies = [
                    {
                        "name": c.name,
                        "value": c.value,
                        "domain": c.domain,
                        "path": c.path,
                        "secure": c.secure,
                        "expires": c.expires,
                        "rest": dict(c._rest),
                    }
                    for c in session.cookies
                ]
                if len(cookies) > 100:
                    raise AuthError("invalid_response")
                state["cookies"] = [
                    c for c in cookies if self._cookie_allowed(state, c)
                ]
        except requests.RequestException as error:
            from .aws import failure_metadata

            metadata = failure_metadata(error)
            raise AuthError("transport_failed", uncertain=method != "GET",
                            retryable=metadata["retryable"],
                            proven_unsent=metadata["proven_unsent"]) from None
        state["steps"] += 1
        state["inflight"] = None
        if canonical:
            return {"canonical_portal": canonical}
        if image:
            return bytes(content), content_type
        if purpose in {"portal", "signin"}:
            return bytes(content).decode("utf-8", errors="replace")
        try:
            value = json.loads(content)
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, UnicodeError):
            raise AuthError("invalid_response", uncertain=method != "GET") from None

    def _cookie_allowed(self, state, cookie):
        domain = cookie.get("domain", "").lstrip(".")
        hosts = {
            urlsplit(state["binding"]["portal"]).hostname,
            state["binding"]["region"] + ".signin.aws",
        }
        # Do not allow public suffix cookies or cookies for unrelated AWS accounts.
        return domain in hosts and cookie.get("path", "").startswith("/")

    def _validate_target(self, state, url, purpose):
        parsed = _url(url)
        b = state["binding"]
        signin = "https://" + b["region"] + ".signin.aws"
        if purpose == "portal":
            allowed = url == b["portal"] or (
                state.get("portal_load_url") == url == b["portal"].rstrip("/") + "/"
            )
        elif purpose == "signin":
            allowed = url == state["login_url"]
        elif purpose == "execute":
            allowed = url == state["execute_url"]
        elif purpose == "image":
            allowed = (
                parsed.scheme + "://" + parsed.netloc == signin
                and not parsed.fragment
                and parsed.path.startswith("/platform/captcha/")
                and "%" not in parsed.path
                and ".." not in parsed.path.split("/")
            )
            _query(parsed.query, {"id", "token", "captchaId", "captchaCES"})
        elif purpose in {
            "login",
            "exchange",
            "whoami",
            "device_session",
            "accept",
            "associate",
            "profiles",
            "usage",
        }:
            endpoints = {
                "login": ("dp", "/login"),
                "exchange": ("dp", "/auth/sso-token"),
                "whoami": ("dp", "/token/whoAmI"),
                "device_session": ("dp", "/session/device"),
                "accept": ("oidc", "/device_authorization/accept_user_code"),
                "associate": ("oidc", "/device_authorization/associate_token"),
            }
            if purpose in {"profiles", "usage"}:
                path = (
                    "/ListAvailableProfiles"
                    if purpose == "profiles"
                    else "/getUsageLimits"
                )
                allowed = (
                    url == "https://management." + b["api_region"] + ".kiro.dev" + path
                )
            else:
                endpoint, path = endpoints[purpose]
                allowed = url == state[endpoint] + path
        else:
            allowed = False
        if not allowed:
            raise AuthError("unsafe_destination")

    def _advance(self, state, captcha_request):
        stage = state["stage"]
        if stage == "portal":
            html = self._request(
                state,
                "GET",
                state.get("portal_load_url", state["binding"]["portal"]),
                purpose="portal",
            )
            if isinstance(html, dict):
                state["portal_load_url"] = html["canonical_portal"]
                return
            self._portal_env(state, html)
            state["stage"] = "login"
        elif stage == "login":
            params = {
                "redirect_url": state.get("portal_load_url", state["binding"]["portal"])
            }
            params["idc_instance_id" if state["dualstack"] else "directory_id"] = (
                state["binding"]["instance"].split("/")[-1]
                if state["dualstack"]
                else state["binding"]["directory"]
            )
            data = self._request(
                state, "GET", state["dp"] + "/login", purpose="login", params=params
            )
            self._login_url(state, data)
            state["stage"] = "signin"
        elif stage == "signin":
            html = self._request(state, "GET", state["login_url"], purpose="signin")
            self._bootstrap(state, html)
        elif stage == "workflow":
            self._execute(state, captcha_request)
        elif stage == "native_success":
            self._finish_success(state, state["native_result"])
        elif stage == "exchange":
            data = self._request(
                state,
                "POST",
                state["dp"] + "/auth/sso-token",
                purpose="exchange",
                data=state["exchange"],
                headers={
                    "x-amz-sso-csrf-token": state["csrf"],
                    "Accept": "application/json",
                },
            )
            state["portal_token"] = require_text(data.get("token"))
            state["stage"] = "whoami"
        elif stage == "whoami":
            data = self._request(
                state,
                "GET",
                state["dp"] + "/token/whoAmI",
                purpose="whoami",
                headers={
                    "Authorization": "Bearer " + state["portal_token"],
                    "Accept": "application/json",
                },
            )
            self._identity(state, data)
            self._authenticated(state)
        else:
            raise AuthError("invalid_state")

    def _portal_env(self, state, html):
        try:
            parser = _BootstrapHTML()
            parser.feed(html)
            env = json.loads("".join(parser.env_parts))
            if (
                parser.env_count != 1
                or env["region"] != state["binding"]["region"]
                or not isinstance(env.get("dualstack", False), bool)
            ):
                raise ValueError()
        except (ValueError, KeyError, TypeError):
            raise AuthError("invalid_response") from None
        b = state["binding"]
        state["dualstack"] = env.get("dualstack", False)
        if state["dualstack"]:
            portal = _url(b["portal"])
            state["dp"] = "https://" + portal.netloc + "/api/portal"
            state["oidc"] = "https://" + portal.netloc + "/api/oidc"
        else:
            for key, prefix in (
                ("dpApiEndpoint", "portal.sso."),
                ("oidcApiEndpoint", "oidc."),
            ):
                expected = "https://" + prefix + b["region"] + ".amazonaws.com"
                if env.get(key) not in {expected, expected + "/"}:
                    raise AuthError("unsafe_destination")
            state["dp"], state["oidc"] = (
                env["dpApiEndpoint"].rstrip("/"),
                env["oidcApiEndpoint"].rstrip("/"),
            )
        if (
            env.get("signinEndpoint")
            and env["signinEndpoint"].rstrip("/")
            != "https://" + b["region"] + ".signin.aws"
        ):
            raise AuthError("unsafe_destination")

    def _login_url(self, state, data):
        url = require_text(data.get("redirectUrl"))
        parsed = _url(url)
        b = state["binding"]
        prefixes = {
            "/platform/" + b["directory"],
            "/platform/" + b["instance"].split("/")[-1],
        }
        if (
            parsed.netloc != b["region"] + ".signin.aws"
            or parsed.path not in {p + "/login" for p in prefixes}
            or parsed.fragment
        ):
            raise AuthError("unsafe_destination")
        query = _query(parsed.query, {"workflowStateHandle"})
        state["start_handle"] = require_text(query.get("workflowStateHandle"))
        state["login_url"] = url
        state["execute_url"] = (
            "https://"
            + parsed.netloc
            + parsed.path.removesuffix("/login")
            + "/api/execute"
        )
        state["csrf"] = require_text(data.get("csrfToken"))

    def _bootstrap(self, state, html):
        try:
            parser = _BootstrapHTML()
            parser.feed(html)
            if parser.workflow is not None:
                value = json.loads(base64.b64decode(parser.workflow, validate=True))
            else:
                cookies = [
                    c
                    for c in state["cookies"]
                    if c["name"] == "platform-workflow-state"
                    and c["domain"].lstrip(".")
                    == state["binding"]["region"] + ".signin.aws"
                ]
                if len(cookies) > 1:
                    raise ValueError()
                value = (
                    json.loads(unquote_plus(cookies[0]["value"]))
                    if cookies
                    else {"stepId": "", "workflowStateHandle": state["start_handle"]}
                )
        except (ValueError, TypeError, UnicodeError):
            raise AuthError("invalid_response") from None
        state["stage"] = "workflow"
        self._workflow(state, value)

    def _workflow(self, state, value):
        if not isinstance(value, dict) or not isinstance(value.get("stepId"), str):
            raise AuthError("invalid_response")
        step = value["stepId"]
        # Confirmation must precede redirect/profile/OAuth processing and failures.
        success = step in {"end-of-workflow-success", "end-of-workflow-redirect"}
        if success and (state.get("password_write_pending") or state["recovering"]):
            selected = (
                state["credential"]["candidate"]
                if state.get("password_write_pending")
                else state["credential"][state["active_credential"]]
            )
            state["credential"]["current"] = selected
            state["credential"]["status"] = "confirmed"
            state["password_changed"] = bool(state.get("password_write_pending"))
            state["password_write_pending"] = False
            state["stage"] = "native_success"
            state["native_result"] = value
            self._emit(state, "password_confirmed", credential=True)
        if success:
            self._finish_success(state, value)
            return
        if step in {
            "get-saml-assertion-from-external-idp",
            "get-external-idp-response",
            "get-ext-idp-oidc-response",
            "verify-saml-assertion",
        }:
            raise AuthError("external_identity_provider")
        if any(
            word in step
            for word in (
                "totp",
                "webauthn",
                "mfa",
                "otp-login",
                "radius",
                "smartcard",
                "device-enrollment",
            )
        ):
            raise AuthError("unsupported_mfa")
        if step == "end-of-workflow-failure":
            raise AuthError("login_refused")
        if step not in {
            "",
            "start",
            "get-identity-user",
            "get-password",
            "get-new-password-for-change-password",
        }:
            raise AuthError("unsupported_step")
        require_text(value.get("workflowStateHandle"))
        state["workflow"] = value
        response_data = value.get("workflowResponseData") or {}
        if not isinstance(response_data, dict):
            raise AuthError("invalid_response")
        if response_data.get("encryptionContextResponse"):
            state["encryption"] = response_data["encryptionContextResponse"]
        presentation = value.get("presentationContext")
        if presentation is not None and not isinstance(presentation, dict):
            raise AuthError("invalid_response")
        if (presentation or {}).get("applicationType"):
            state["application_type"] = presentation["applicationType"]
        state["status"] = "ready"
        state["stage"] = "workflow"
        state["challenge"] = None
        self._challenge(state, value.get("captchaResponse"))
        if state["challenge"]:
            return
        message = value.get("message") or {}
        code = message.get("code") if isinstance(message, dict) else None
        if (
            code in {"AUTHENTICATION_FAILED", "INVALID_PASSWORD"}
            and step == "get-password"
        ):
            if not state["recovering"]:
                raise AuthError("login_refused")
            state.pop("active_credential", None)
        elif code or message:
            raise AuthError(
                "password_rejected"
                if state.get("password_write_pending")
                else "login_refused"
            )

    def _finish_success(self, state, value):
        if state["password_only"]:
            if (
                state["target_password"]
                and state["credential"]["current"] != state["target_password"]
            ):
                raise AuthError("password_not_applied")
            state["status"], state["stage"] = "done", "done"
            state["result"] = {
                "passwordChanged": state["password_changed"],
                "password": state["credential"]["current"],
            }
            return
        state["exchange"] = self._redirect(state, value.get("redirect"))
        state["stage"] = "exchange"
        state["status"] = "ready"

    def _challenge(self, state, response):
        if response is None or response == {}:
            return
        if not isinstance(response, dict):
            raise AuthError("unsupported_challenge")
        token, cdn = response.get("captchaToken"), response.get("captchaCDN")
        image_url, ces = response.get("captchaURL"), response.get("captchaCES")
        if not any((token, cdn, image_url, ces)):
            if set(response) - {
                "captchaToken",
                "captchaCDN",
                "captchaURL",
                "captchaCES",
            } or any(value is not None and value != "" for value in response.values()):
                raise AuthError("unsupported_challenge")
            return
        challenge = {
            "id": str(uuid.uuid4()),
            "revision": state["revision"] + 1,
            "expires_at": min(state["expires_at"], self.clock() + 300),
        }
        if token or cdn:
            region = state["binding"]["region"]
            expected_root = region + ".threat-mitigation.aws.amazon.com"
            expected_cdn = (
                "https://cdn." + expected_root + "/assets/consumer/consumer.min.js"
            )
            if cdn != expected_cdn:
                raise AuthError("unsafe_destination")
            try:
                require_text(token, maximum=20000, code="unsupported_challenge")
                metadata = json.loads(base64.b64decode(token, validate=True))
                if (
                    metadata["apiRoot"] != expected_root
                    or metadata["region"] != region
                    or str(metadata["envStage"]).lower() != "prod"
                ):
                    raise ValueError()
            except (ValueError, TypeError, KeyError, UnicodeError):
                raise AuthError("unsupported_challenge") from None
            challenge.update(
                kind="ams",
                script_url=cdn,
                redemption_token=token,
                widget_origin="https://cdn." + expected_root,
                region=region,
                stage="prod",
                callback="initAMS",
                container_id="captcha",
                locale="en-US",
                show_challenge_on_load=False,
            )
        elif image_url and ces:
            self._validate_target(state, image_url, "image")
            require_text(ces, code="unsupported_challenge")
            challenge.update(kind="image", image_url=image_url, ces=ces)
        else:
            raise AuthError("unsupported_challenge")
        state["challenge"], state["status"] = challenge, "challenge"

    def _public_challenge(self, state):
        challenge = state.get("challenge")
        if not challenge:
            return None
        return {
            key: value
            for key, value in challenge.items()
            if key not in {"image_url", "ces"}
        }

    def _answer(self, state, answer):
        challenge = state.get("challenge")
        if challenge and self.clock() >= challenge["expires_at"]:
            raise AuthError("expired")
        if answer is None:
            return None
        if (
            not isinstance(answer, dict)
            or not challenge
            or (answer.get("challenge_id"), answer.get("revision"))
            != (challenge["id"], challenge["revision"])
        ):
            raise AuthError("stale_challenge")
        expected = "guess" if challenge["kind"] == "image" else "access_code"
        if set(answer) != {"challenge_id", "revision", expected}:
            raise AuthError("stale_challenge")
        value = require_text(
            answer.get(expected),
            maximum=8192 if expected == "access_code" else 128,
            code="stale_challenge",
        )
        result = (
            {"captchaGuess": value, "captchaCES": challenge["ces"]}
            if expected == "guess"
            else {"captchaAccessCode": value}
        )
        state["challenge"] = None
        state["status"] = "ready"
        return result

    def _choose_credential(self, state, *, human_answer=False):
        credential = state["credential"]
        if human_answer and state.get("active_credential"):
            if state["recovering"]:
                # An unknown-password recovery never resets its attempt budget,
                # including after a human answer to a post-submission challenge.
                raise AuthError("password_unresolved")
            # Ordinary login may continue only after a NEW challenge answer;
            # no challenge means the one-attempt guard below still applies.
            return credential[state["active_credential"]]
        choices = ("candidate", "current") if state["recovering"] else ("current",)
        for name in choices:
            if credential.get(name) and name not in credential["tried"]:
                if (
                    name == "current"
                    and state["recovering"]
                    and credential["current"] == credential["candidate"]
                    and "candidate" in credential["tried"]
                ):
                    continue
                state["active_credential"] = name
                credential["tried"].append(name)
                self._emit(state, "credential_attempt", credential=True)
                return credential[name]
        raise AuthError("credential_attempt_limit")

    def _execute(self, state, captcha_request):
        workflow = state["workflow"]
        step = workflow["stepId"]
        body = {
            "stepId": step,
            "workflowStateHandle": workflow["workflowStateHandle"],
            "startWorkflowHandle": state["start_handle"],
            "inputs": [],
            "requestId": str(uuid.uuid4()),
        }
        if step == "get-identity-user":
            if state.get("application_type") != "SSO":
                raise AuthError("unsupported_step")
            body.update(
                actionId="SUBMIT",
                inputs=[
                    {"input_type": "UserRequestInput", "username": state["username"]},
                    {
                        "input_type": "ApplicationTypeRequestInput",
                        "applicationType": "SSO",
                    },
                ],
            )
        elif step in {"get-password", "get-new-password-for-change-password"}:
            password_context = workflow.get("passwordStringContext")
            if password_context is not None and not isinstance(password_context, dict):
                raise AuthError("invalid_response")
            if (password_context or {}).get("passwordStringRequired"):
                raise AuthError("unsupported_step")
            changing = step == "get-new-password-for-change-password"
            if changing:
                if state["recovering"] or state.get("password_write_pending"):
                    raise AuthError("password_unresolved")
                candidate = state["credential"].get("candidate")
                if candidate is None:
                    candidate = state[
                        "target_password"
                    ] or "Aa9!" + secrets.token_urlsafe(24)
                    state["credential"].update(
                        candidate=candidate, status="candidate", tried=[]
                    )
                    self._emit(state, "password_candidate", credential=True)
                password = candidate
            else:
                password = self._choose_credential(
                    state, human_answer=bool(captcha_request)
                )
            compact = encrypt_password(
                password,
                state.get("encryption"),
                state["binding"]["region"],
                self.clock(),
            )
            encrypted_input = {
                "input_type": "UpdatePasswordRequestInput"
                if changing
                else "PasswordRequestInput",
                "newPassword" if changing else "password": compact,
                "successfullyEncrypted": "SUCCESSFUL",
                "errorLog": None,
            }
            body.update(actionId="SUBMIT", inputs=[encrypted_input])
            if not changing:
                body["inputs"].append(
                    {"input_type": "UserPreferencesRequestInput", "trustDevice": False}
                )
            else:
                state["credential"]["status"] = "unknown"
                state["password_write_pending"] = True
                state["inflight"] = "password_change"
                self._emit(state, "password_pending", credential=True)
        if captcha_request:
            body["captchaRequest"] = captcha_request
        result = self._request(
            state, "POST", state["execute_url"], purpose="execute", json=body
        )
        self._workflow(state, result)

    def _redirect(self, state, redirect):
        if not isinstance(redirect, dict):
            raise AuthError("invalid_response")
        parsed, portal = _url(redirect.get("url")), _url(state["binding"]["portal"])
        if (
            parsed.netloc != portal.netloc
            or parsed.path.rstrip("/") != portal.path.rstrip("/")
            or parsed.fragment not in ("", "/")
        ):
            raise AuthError("unsafe_destination")
        # AWS also appends WDC browser metadata to this same-portal redirect.
        # The portal exchanges only the handle/state and retains the CSRF token
        # obtained from /login; never forward the WDC value to the token API.
        fields = _query(
            parsed.query, {"workflowResultHandle", "state", "wdc_csrf_token"}
        )
        method = redirect.get("method", "GET")
        params = redirect.get("postParams", [])
        if (
            method not in {"GET", "POST"}
            or not isinstance(params, list)
            or len(params) > 2
        ):
            raise AuthError("unsafe_destination")
        if method == "GET" and params:
            raise AuthError("unsafe_destination")
        for param in params:
            if (
                not isinstance(param, dict)
                or param.get("name") not in {"workflowResultHandle", "state"}
                or param["name"] in fields
            ):
                raise AuthError("unsafe_destination")
            fields[param["name"]] = require_text(param.get("value"))
        return {
            "authCode": require_text(fields.get("workflowResultHandle")),
            "orgId": state["binding"]["directory"],
            **({"state": fields["state"]} if fields.get("state") else {}),
        }

    def _identity(self, state, data):
        expected = require_text(
            state["expected_user_id"], maximum=256, code="identity_mismatch"
        )
        identifier = require_text(
            data.get("userIdentifier"), maximum=256, code="identity_mismatch"
        )
        # Current portals return a distinct opaque userIdentifier. The explicit
        # identity-store ID binds this portal session to our selected SSO user.
        # A present but invalid ID must never fall back to the legacy field.
        user = require_text(
            data["identityStoreUserId"] if "identityStoreUserId" in data else identifier,
            maximum=256,
            code="identity_mismatch",
        )
        directory = require_text(
            data.get("directoryId"), maximum=100, code="identity_mismatch"
        )
        if (
            not expected.strip()
            or expected != expected.strip()
            or not identifier.strip()
            or identifier != identifier.strip()
            or user != expected
            or directory != state["binding"]["directory"]
        ):
            raise AuthError("identity_mismatch")
        if data.get("userId") is not None and data["userId"] != expected:
            raise AuthError("identity_mismatch")
        for field_name in ("username", "userName"):
            if (
                data.get(field_name) is not None
                and data[field_name] != state["username"]
            ):
                raise AuthError("identity_mismatch")
        state["portal_identity"] = data

    def _authenticated(self, state):
        state["status"], state["stage"] = "done", "done"
        state["result"] = {
            "portalToken": state["portal_token"],
            "dpEndpoint": state["dp"],
            "oidcEndpoint": state["oidc"],
            "identity": state["portal_identity"],
        }

    def challenge_image(self, sealed_state, revision):
        state = self._load(sealed_state)
        challenge = state.get("challenge")
        try:
            if (
                not challenge
                or challenge["kind"] != "image"
                or revision != challenge["revision"]
            ):
                raise AuthError("stale_challenge")
            if self.clock() >= challenge["expires_at"]:
                raise AuthError("expired")
            content, mime = self._request(
                state, "GET", challenge["image_url"], purpose="image", image=True
            )
            valid = {
                "image/png": content.startswith(b"\x89PNG\r\n\x1a\n"),
                "image/jpeg": content.startswith(b"\xff\xd8\xff"),
                "image/gif": content.startswith((b"GIF87a", b"GIF89a")),
                "image/webp": content.startswith(b"RIFF") and content[8:12] == b"WEBP",
            }
            if not valid.get(mime, False):
                raise AuthError("unsupported_challenge")
            return ChallengeImage(content, mime)
        except AuthError as error:
            raise self._context_error(error, state) from None
