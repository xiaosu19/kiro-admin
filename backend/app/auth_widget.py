"""Credential-free official human CAPTCHA host on a dedicated HTTPS origin."""

import base64
import json
import re
import secrets
from urllib.parse import urlencode, urlsplit
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse

from .config import settings
from .identity_login import AuthError

router = APIRouter()
REGION_PATTERN = r"^[a-z]{2}(?:-[a-z]+)+-\d$"
FIELDS = {
    "kind",
    "id",
    "revision",
    "expires_at",
    "region",
    "stage",
    "callback",
    "container_id",
    "locale",
    "show_challenge_on_load",
    "script_url",
    "widget_origin",
    "redemption_token",
}


def request_origin(request):
    return f"{request.url.scheme}://{request.url.netloc}"


def verification_host(request):
    # The hostname also isolates accidental HTTP access; only the exact configured
    # scheme/port is permitted to serve the frame itself.
    return request.url.hostname == urlsplit(settings.verify_origin).hostname


def public_challenge(challenge):
    if challenge.get("kind") == "image":
        return {k: challenge[k] for k in ("kind", "id", "revision", "expires_at")}
    try:
        region = challenge["region"]
        if not re.fullmatch(REGION_PATTERN, region):
            raise ValueError()
        root = region + ".threat-mitigation.aws.amazon.com"
        origin = "https://cdn." + root
        metadata = json.loads(
            base64.b64decode(challenge["redemption_token"], validate=True)
        )
        if (
            metadata["apiRoot"] != root
            or metadata["region"] != region
            or str(metadata["envStage"]).lower() != "prod"
            or challenge["script_url"] != origin + "/assets/consumer/consumer.min.js"
            or challenge["widget_origin"] != origin
            or challenge["kind"] != "ams"
        ):
            raise ValueError()
        return {key: challenge[key] for key in FIELDS}
    except (KeyError, ValueError, TypeError):
        raise AuthError("unsupported_challenge") from None


def frame_url(operation_id, challenge):
    return (
        settings.verify_origin
        + "/auth-widget?"
        + urlencode(
            {
                "operation_id": operation_id,
                "challenge_id": challenge["id"],
                "revision": challenge["revision"],
                "region": challenge["region"],
            }
        )
    )


SCRIPT = r"""
'use strict';
const config = __CONFIG__;
const {parentOrigin, operationId, challengeId, revision, region} = config;
const apiRoot = region + '.threat-mitigation.aws.amazon.com';
const widgetOrigin = 'https://cdn.' + apiRoot;
const scriptUrl = widgetOrigin + '/assets/consumer/consumer.min.js';
let initialized = false;
const keys = (o, expected) => o && typeof o === 'object' && !Array.isArray(o)
  && Object.keys(o).sort().join(',') === [...expected].sort().join(',');
const text = (s, n) => typeof s === 'string' && s.length > 0 && s.length <= n && !/[\x00-\x1f\x7f]/.test(s);
function report(type, extra = {}) {
  parent.postMessage({type, operation_id: operationId, challenge_id: challengeId, revision, ...extra}, parentOrigin);
}
addEventListener('message', event => {
  if (event.source !== parent || event.origin !== parentOrigin || parent === window || initialized) return;
  const value = event.data;
  if (!keys(value, ['type', 'operation_id', 'challenge_id', 'revision', 'challenge'])
      || value.type !== 'kiro-auth-init' || value.operation_id !== operationId
      || value.challenge_id !== challengeId || value.revision !== revision) return;
  const c = value.challenge;
  if (!keys(c, ['kind','id','revision','expires_at','region','stage','callback','container_id',
      'locale','show_challenge_on_load','script_url','widget_origin','redemption_token'])
      || c.kind !== 'ams' || c.id !== challengeId || c.revision !== revision
      || c.region !== region || c.stage !== 'prod' || c.callback !== 'initAMS'
      || c.container_id !== 'captcha' || c.locale !== 'en-US' || c.show_challenge_on_load !== false
      || c.script_url !== scriptUrl || c.widget_origin !== widgetOrigin
      || !Number.isFinite(c.expires_at) || c.expires_at <= Date.now()/1000
      || c.expires_at > Date.now()/1000 + 900 || !text(c.redemption_token, 20000)) return;
  try {
    const token = JSON.parse(atob(c.redemption_token));
    if (token.apiRoot !== apiRoot || token.region !== region || String(token.envStage).toLowerCase() !== 'prod') return;
  } catch { return; }
  initialized = true;
  window.initAMS = sdk => {
    if (!sdk || typeof sdk.init !== 'function') { report('kiro-auth-error', {code:'widget_failed'}); return; }
    sdk.init({redemptionToken:c.redemption_token, locale:'en-US', showChallengeOnLoad:false,
      onChallengeComplete: answer => {
        if (Date.now()/1000 < c.expires_at && answer && text(answer.accessCode, 8192)) {
          report('kiro-auth-complete', {access_code:answer.accessCode});
        }
      }, onError: () => report('kiro-auth-error', {code:'widget_failed'})});
  };
  const script = document.createElement('script');
  script.src = scriptUrl;
  script.onerror = () => report('kiro-auth-error', {code:'widget_failed'});
  document.head.appendChild(script);
});
report('kiro-auth-ready');
"""


@router.get("/auth-widget")
def widget(
    request: Request,
    operation_id: UUID,
    challenge_id: UUID,
    revision: int = Query(ge=1),
    region: str = Query(pattern=REGION_PATTERN),
):
    if request_origin(request) != settings.verify_origin:
        raise HTTPException(404)
    nonce = secrets.token_urlsafe(24)
    root = region + ".threat-mitigation.aws.amazon.com"
    origin = "https://cdn." + root
    config = json.dumps(
        {
            "parentOrigin": settings.app_origin,
            "operationId": str(operation_id),
            "challengeId": str(challenge_id),
            "revision": revision,
            "region": region,
        }
    ).replace("<", "\\u003c")
    body = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>Human verification</title></head><body><div id="captcha" data-callback="initAMS"></div>'
        f'<script nonce="{nonce}">'
        + SCRIPT.replace("__CONFIG__", config)
        + "</script></body></html>"
    )
    response = HTMLResponse(
        body,
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Content-Security-Policy": (
                f"default-src 'none'; script-src 'nonce-{nonce}' {origin}/assets/consumer/consumer.min.js; "
                f"style-src 'unsafe-inline' {origin}; img-src data: {origin}; "
                f"connect-src https://{root} {origin}; frame-src {origin}; "
                f"frame-ancestors {settings.app_origin}; base-uri 'none'; form-action 'none'"
            ),
        },
    )
    request.state.auth_widget = True
    return response
