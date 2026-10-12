"""Official OIDC device/refresh grants and read-only Kiro profile/usage adapter.

AWS SDK calls use the account's Identity Center region and guarded gateway client;
Kiro bearer calls use management.<subscription_region>.kiro.dev. One advance is
one network operation. Pending/slow-down return an absolute next_poll_at; the
worker must schedule it, never sleep while holding a lease or a DB transaction.

AuthProgress.result contains REAL sensitive token data and raw returned profile/
usage. It is not a public status response. A matched profile plus read-only usage
response is not a promise that a paid subscription is active or a model usable.
No model, subscription, reset-OTP, or provisioning writes occur here.
"""

from urllib.parse import urlencode

from botocore.exceptions import BotoCoreError, ClientError

from .aws import AwsFailure
from .identity_login import (
    AuthError,
    NativeIdentityLogin,
    _query,
    _url,
    require_number,
    require_text,
)
from .security import decrypt


DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
SCOPES = [
    "codewhisperer:" + name
    for name in (
        "completions",
        "analysis",
        "conversations",
        "transformations",
        "taskassist",
    )
]


def verified_external_identity(usage, directory, user_id):
    """AWS usage identifies enterprise users as <identity store>.<SSO user ID>."""
    if any(
        not isinstance(value, str) or not value or any(c.isspace() for c in value)
        for value in (directory, user_id)
    ):
        return False
    info = usage.get("userInfo") if isinstance(usage, dict) else None
    return isinstance(info, dict) and info.get("userId") == directory + "." + user_id


def validated_verification_uris(state, response):
    """Only AWS's exact configured portal/device routes may leave the server."""
    portal = _url(state["binding"]["portal"])
    code = require_text(state["device"]["userCode"], maximum=256)
    result = {}
    for key in ("verificationUri", "verificationUriComplete"):
        if response.get(key) is None:
            continue
        parsed = _url(response[key])
        if parsed.netloc == portal.netloc:
            route, _, query = parsed.fragment.partition("?")
            if parsed.path != "/start/" or parsed.query or route != "/device":
                raise AuthError("unsafe_destination")
            if key == "verificationUri" and parsed.fragment != "/device":
                raise AuthError("unsafe_destination")
            values = _query(query, {"user_code"})
        elif (
            parsed.netloc
            == "device.sso." + state["binding"]["region"] + ".amazonaws.com"
            and parsed.path in {"", "/"}
            and not parsed.fragment
        ):
            if key == "verificationUri" and parsed.query:
                raise AuthError("unsafe_destination")
            values = _query(parsed.query, {"user_code"})
        else:
            raise AuthError("unsafe_destination")
        if key == "verificationUriComplete" and values.get("user_code") != code:
            raise AuthError("device_mismatch")
        result[key] = response[key]
    return result


def official_authorization_challenge(state):
    """Derive a small public challenge, including for encrypted legacy AMS jobs."""
    try:
        challenge = state["challenge"]
        if (
            state["kind"] != "enterprise"
            or state["password_only"]
            or challenge["kind"] not in {"ams", "aws_authorization"}
        ):
            raise AuthError("invalid_state")
        device = state["device"]
        uris = validated_verification_uris(state, device)
        url = uris.get("verificationUriComplete")
        if not url:
            # Old checkpoints did not retain the AWS URLs. Their encrypted
            # binding and device user code still identify this exact device flow.
            base = uris.get("verificationUri") or (
                state["binding"]["portal"].rstrip("/") + "/#/device"
            )
            url = base + "?" + urlencode({"user_code": device["userCode"]})
            validated_verification_uris(state, {"verificationUriComplete": url})
        return {
            "kind": "aws_authorization",
            "id": challenge["id"],
            "revision": challenge["revision"],
            "expires_at": min(
                require_number(value)
                for value in (
                    challenge["expires_at"],
                    state["expires_at"],
                    device["expires_at"],
                    state["registration"]["clientSecretExpiresAt"],
                )
            ),
            "authorization_url": url,
            "user_code": device["userCode"],
            "username": require_text(state["username"], maximum=256),
        }
    except (KeyError, TypeError, ValueError):
        raise AuthError("invalid_state") from None


def forget_external_password(state):
    """The official login can consume an OTP or change any previously saved password."""
    state["credential"].update(current=None, candidate=None, status="unknown", tried=[])
    state.update(
        external_authorization=True,
        target_password=None,
        recovering=False,
        password_write_pending=False,
        password_changed=False,
        result=None,
    )


class EnterpriseAuth(NativeIdentityLogin):
    kind = "enterprise"
    MAX_PAGES = 20
    MAX_STEPS = 100
    MAX_POLLS = 100

    def _new_state(self, *args, **kwargs):
        if kwargs.get("password_only"):
            raise AuthError("invalid_configuration")
        state = super()._new_state(*args, **kwargs)
        b = state["binding"]
        if b["api_region"] not in {"us-east-1", "eu-central-1"}:
            raise AuthError("invalid_configuration")
        arn = b["profile_arn"].split(":", 5)
        if (
            len(arn) != 6
            or arn[0:2] != ["arn", "aws"]
            or arn[2] not in {"codewhisperer", "q", "kiro"}
            or arn[3] != b["api_region"]
            or not arn[5].startswith("profile/")
        ):
            raise AuthError("invalid_configuration")
        state.update(
            stage="register",
            operation_expires_at=state["expires_at"],
            polls=0,
            pages=0,
            seen_pages=[],
            profiles=[],
        )
        return state

    def _sdk(self):
        if not hasattr(self, "_oidc"):
            try:
                self._oidc = self.gateway._client(
                    "sso-oidc", region_name=self.gateway.account.region
                )
            except Exception:
                raise AuthError("oauth_failed") from None
        return self._oidc

    def close(self):
        if hasattr(self, "_oidc"):
            self._oidc.close()

    def _sdk_call(self, state, operation, **kwargs):
        self._guard()
        state["inflight"] = state["stage"]
        self._emit(state, "request_pending")
        try:
            client = self._sdk()
            self._guard()
            value = getattr(client, operation)(**kwargs)
        except ClientError as error:
            from .aws import failure_metadata

            code = error.response.get("Error", {}).get("Code")
            state["inflight"] = None
            if (
                operation == "create_token"
                and state["stage"] == "poll"
                and code in {"AuthorizationPendingException", "SlowDownException"}
            ):
                state["steps"] += 1
                return {"pending": code}
            metadata = failure_metadata(error)
            raise AuthError(
                "expired"
                if code in {"ExpiredTokenException", "InvalidClientException"}
                else "oauth_failed",
                http_status=metadata["http_status"], aws_code=metadata["code"],
                retryable=metadata["retryable"], proven_unsent=metadata["proven_unsent"],
                uncertain=not metadata["proven_unsent"],
            ) from None
        except BotoCoreError as error:
            from .aws import failure_metadata

            metadata = failure_metadata(error)
            raise AuthError("oauth_failed", uncertain=True,
                            aws_code=metadata["code"], retryable=metadata["retryable"],
                            proven_unsent=metadata["proven_unsent"]) from None
        except AuthError:
            raise
        except AwsFailure:
            # A per-wire gateway guard can revoke the proxy after our first check.
            raise AuthError("proxy_unavailable") from None
        if not isinstance(value, dict):
            raise AuthError("invalid_response")
        state["inflight"] = None
        state["steps"] += 1
        return value

    def _advance(self, state, captcha_request):
        stage = state["stage"]
        if stage == "register":
            value = self._sdk_call(
                state,
                "register_client",
                clientName="Kiro Console",
                clientType="public",
                scopes=SCOPES,
                grantTypes=[DEVICE_GRANT, "refresh_token"],
            )
            registration = {
                "clientId": require_text(value.get("clientId")),
                "clientSecret": require_text(value.get("clientSecret")),
                "clientSecretExpiresAt": require_number(
                    value.get("clientSecretExpiresAt"), minimum=self.clock() + 1
                ),
            }
            state["registration"] = registration
            state["expires_at"] = min(
                state["expires_at"], registration["clientSecretExpiresAt"]
            )
            state["stage"] = "device"
        elif stage == "device":
            value = self._sdk_call(
                state,
                "start_device_authorization",
                **self._client_identity(state),
                startUrl=state["binding"]["portal"],
            )
            state["device"] = {
                "deviceCode": require_text(value.get("deviceCode")),
                "userCode": require_text(value.get("userCode"), maximum=256),
                "interval": require_number(
                    value.get("interval", 5), minimum=1, maximum=300
                ),
                "expires_at": self.clock()
                + require_number(value.get("expiresIn"), minimum=1, maximum=86400),
            }
            self._verification_uri(state, value)
            state["expires_at"] = min(
                state["expires_at"], state["device"]["expires_at"]
            )
            state["stage"] = "portal"
        elif stage == "device_session":
            value = self._request(
                state,
                "POST",
                state["dp"] + "/session/device",
                purpose="device_session",
                json={},
                headers={
                    "Authorization": "Bearer " + state["portal_token"],
                    "Accept": "application/json",
                },
            )
            state["user_session"] = require_text(value.get("token"))
            state["stage"] = "accept"
        elif stage == "accept":
            value = self._request(
                state,
                "POST",
                state["oidc"] + "/device_authorization/accept_user_code",
                purpose="accept",
                json={
                    "userCode": state["device"]["userCode"],
                    "userSessionId": state["user_session"],
                },
            )
            context = value.get("deviceContext")
            if (
                not isinstance(context, dict)
                or context.get("clientId") != state["registration"]["clientId"]
                or context.get("clientType") != "public"
            ):
                raise AuthError("device_mismatch")
            state["device_context"] = {
                "deviceContextId": require_text(context.get("deviceContextId")),
                "clientId": context["clientId"],
                "clientType": context["clientType"],
            }
            state["stage"] = "associate"
        elif stage == "associate":
            self._request(
                state,
                "POST",
                state["oidc"] + "/device_authorization/associate_token",
                purpose="associate",
                json={
                    "deviceContext": state["device_context"],
                    "userSessionId": state["user_session"],
                },
            )
            state.update(
                stage="poll",
                status="polling",
                next_poll_at=self.clock() + state["device"]["interval"],
            )
        elif stage == "poll":
            if self.clock() < state["next_poll_at"]:
                return
            if state["polls"] >= self.MAX_POLLS:
                raise AuthError("step_limit")
            state["polls"] += 1
            value = self._sdk_call(
                state,
                "create_token",
                **self._client_identity(state),
                grantType=DEVICE_GRANT,
                deviceCode=state["device"]["deviceCode"],
            )
            if value.get("pending"):
                if value["pending"] == "SlowDownException":
                    state["device"]["interval"] += 5
                state["next_poll_at"] = self.clock() + state["device"]["interval"]
                return
            self._tokens(state, value)
        elif stage == "refresh":
            value = self._sdk_call(
                state,
                "create_token",
                **self._client_identity(state),
                grantType="refresh_token",
                refreshToken=state["tokens"]["refreshToken"],
            )
            self._tokens(state, value, refresh=True)
        elif stage == "profiles":
            self._profiles(state)
        elif stage == "usage":
            usage = self._request(
                state,
                "GET",
                "https://management."
                + state["binding"]["api_region"]
                + ".kiro.dev/getUsageLimits",
                purpose="usage",
                headers={"Authorization": "Bearer " + state["tokens"]["accessToken"]},
                params={
                    "profileArn": state["binding"]["profile_arn"],
                    "origin": "AI_EDITOR",
                    "resourceType": "AGENTIC_REQUEST",
                },
            )
            if state.get("external_authorization") and not verified_external_identity(
                usage, state["binding"]["directory"], state["expected_user_id"]
            ):
                raise AuthError("identity_mismatch")
            state["result"] = {
                **state["tokens"],
                **state["registration"],
                "authRegion": state["binding"]["region"],
                "apiRegion": state["binding"]["api_region"],
                "startUrl": state["binding"]["portal"],
                "profile": state["profile"],
                "usage": usage,
                "username": state["username"],
                "userId": state["expected_user_id"],
                "password": state["credential"]["current"],
                "externalAuthorization": bool(state.get("external_authorization")),
                "identityStoreId": state["binding"]["directory"],
            }
            state["stage"], state["status"] = "done", "done"
        else:
            super()._advance(state, captcha_request)

    def _client_identity(self, state):
        registration = state["registration"]
        if self.clock() >= registration["clientSecretExpiresAt"]:
            raise AuthError("expired")
        return {key: registration[key] for key in ("clientId", "clientSecret")}

    def _authenticated(self, state):
        state["stage"] = "device_session"
        state["status"] = "ready"

    def _verification_uri(self, state, response):
        state["device"].update(validated_verification_uris(state, response))

    def _challenge(self, state, response):
        state.pop("automation_challenge", None)
        super()._challenge(state, response)
        if (state.get("challenge") or {}).get("kind") == "ams":
            # Keep the official widget inputs only in the encrypted workflow.
            # Public/manual continuation still exposes the validated AWS URL.
            state["automation_challenge"] = dict(state["challenge"])
            state["challenge"] = official_authorization_challenge(state)

    def _public_challenge(self, state):
        if (state.get("challenge") or {}).get("kind") in {"ams", "aws_authorization"}:
            return official_authorization_challenge(state)
        return super()._public_challenge(state)

    def _answer(self, state, answer):
        original = state.get("automation_challenge")
        challenge = state.get("challenge")
        if (
            isinstance(answer, dict)
            and set(answer) == {"challenge_id", "revision", "access_code"}
            and original and challenge
            and original["kind"] == "ams"
            and (original["id"], original["revision"])
                == (challenge["id"], challenge["revision"])
        ):
            # This internal path is never accepted by the public resume API.
            # Continue native login, retaining password checkpoints and whoAmI.
            state["challenge"] = original
            state.pop("automation_challenge", None)
            return super()._answer(state, answer)
        if (state.get("challenge") or {}).get("kind") not in {
            "ams",
            "aws_authorization",
        }:
            return super()._answer(state, answer)
        challenge = official_authorization_challenge(state)
        if self.clock() >= challenge["expires_at"]:
            raise AuthError("expired")
        if answer is None:
            return None
        if (
            not isinstance(answer, dict)
            or set(answer) != {"challenge_id", "revision", "continue_authorization"}
            or answer.get("continue_authorization") is not True
            or (answer["challenge_id"], answer["revision"])
            != (challenge["id"], challenge["revision"])
        ):
            raise AuthError("stale_challenge")
        self._guard()
        self._client_identity(state)
        state.pop("automation_challenge", None)
        forget_external_password(state)
        state.update(
            stage="poll",
            status="polling",
            challenge=None,
            next_poll_at=self.clock() + state["device"]["interval"],
        )
        self._emit(state, "external_authorization", credential=True)
        return None

    def _tokens(self, state, value, *, refresh=False):
        if (
            require_text(value.get("tokenType", "Bearer"), code="token_invalid").lower()
            != "bearer"
        ):
            raise AuthError("token_invalid")
        expires_in = require_number(
            value.get("expiresIn"), minimum=1, maximum=7 * 86400, code="token_invalid"
        )
        refresh_token = value.get("refreshToken")
        if refresh and refresh_token is None:
            refresh_token = state["tokens"]["refreshToken"]
        state["tokens"] = {
            "accessToken": require_text(value.get("accessToken"), code="token_invalid"),
            "refreshToken": require_text(refresh_token, code="token_invalid"),
            "tokenType": "Bearer",
            "expiresIn": expires_in,
            "expiresAt": self.clock() + expires_in,
        }
        # Once tokens exist, device expiry no longer controls read-only profile calls.
        state["expires_at"] = min(
            state["operation_expires_at"], state["tokens"]["expiresAt"]
        )
        state.update(
            stage="profiles",
            status="ready",
            next_poll_at=None,
            profiles=[],
            pages=0,
            seen_pages=[],
        )
        state.pop("next_page", None)

    def _profiles(self, state):
        if state["pages"] >= self.MAX_PAGES:
            raise AuthError("pagination_limit")
        data = self._request(
            state,
            "POST",
            "https://management."
            + state["binding"]["api_region"]
            + ".kiro.dev/ListAvailableProfiles",
            purpose="profiles",
            headers={"Authorization": "Bearer " + state["tokens"]["accessToken"]},
            json={"nextToken": state["next_page"]} if state.get("next_page") else {},
        )
        profiles = data.get("profiles")
        if (
            not isinstance(profiles, list)
            or len(profiles) > 1000
            or any(not isinstance(p, dict) for p in profiles)
        ):
            raise AuthError("invalid_response")
        state["pages"] += 1
        state["profiles"].extend(
            p for p in profiles if p.get("arn") == state["binding"]["profile_arn"]
        )
        next_token = data.get("nextToken")
        if next_token:
            require_text(next_token)
            if next_token in state["seen_pages"] or state["pages"] >= self.MAX_PAGES:
                raise AuthError("pagination_limit")
            state["seen_pages"].append(next_token)
            state["next_page"] = next_token
            return
        if len(state["profiles"]) != 1:
            raise AuthError("no_profile")
        profile = state["profiles"][0]
        require_text(profile.get("profileName"))
        details = profile.get("identityDetails", {})
        # The authenticated profile API serializes absent optional objects as
        # null. Preserve its raw response while validating them as missing.
        if details is None:
            details = {}
        if not isinstance(details, dict):
            raise AuthError("invalid_response")
        identity = details.get("ssoIdentityDetails", {})
        if identity is None:
            identity = {}
        if not isinstance(identity, dict):
            raise AuthError("invalid_response")
        if state.get("external_authorization") and (
            identity.get("instanceArn") != state["binding"]["instance"]
            or identity.get("ssoRegion") != state["binding"]["region"]
        ):
            raise AuthError("identity_mismatch")
        if identity and (
            identity.get("instanceArn", state["binding"]["instance"])
            != state["binding"]["instance"]
            or identity.get("ssoRegion", state["binding"]["region"])
            != state["binding"]["region"]
        ):
            raise AuthError("identity_mismatch")
        state["profile"] = profile
        state["stage"] = "usage"

    def begin_refresh(self, sealed_state):
        """Refresh a completed operation, using ONLY its saved client/token identity.

        Access-token expiry is expected here. Client registration expiry still fails
        cleanly; renewing a registration requires a new device authorization.
        """
        try:
            state = decrypt(sealed_state)
            if (
                state["version"] != 1
                or state["kind"] != self.kind
                or state["binding"] != self._binding()
                or state["status"] != "done"
                or state["inflight"]
            ):
                raise ValueError()
        except Exception:
            raise AuthError("invalid_state") from None
        self._client_identity(state)
        state.update(
            stage="refresh",
            status="ready",
            refresh_only=True,
            result=None,
            steps=0,
            operation_expires_at=self.clock() + 900,
            expires_at=min(
                self.clock() + 900, state["registration"]["clientSecretExpiresAt"]
            ),
        )
        return self._publish(state)
