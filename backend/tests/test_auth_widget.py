import base64
import json
import re
import uuid

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app


def frame_url():
    return f"{settings.verify_origin}/auth-widget?region=us-east-1&operation_id={uuid.uuid4()}&challenge_id={uuid.uuid4()}&revision=3"


def test_verification_origin_only_neutral_frame_no_console_api():
    client = TestClient(app)
    url = frame_url()
    response = client.get(url)
    assert response.status_code == 200, response.text
    assert "kiro_session" not in response.headers.get("set-cookie", "")
    assert response.headers["cache-control"] == "no-store"
    csp = response.headers["content-security-policy"]
    assert f"frame-ancestors {settings.app_origin}" in csp
    assert "default-src 'none'" in csp and "'nonce-" in csp
    assert "https://cdn.us-east-1.threat-mitigation.aws.amazon.com" in csp
    assert "x-frame-options" not in response.headers
    assert (
        client.get(url.replace(settings.verify_origin, settings.app_origin)).status_code
        == 404
    )
    for path in (
        "/api/auth/me",
        "/api/auth-batches",
        "/",
        "/assets/index.js",
        "/health",
    ):
        assert client.get(settings.verify_origin + path).status_code == 404
    assert client.post(url).status_code in (404, 405)
    console = client.get(settings.app_origin + "/health")
    assert console.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in console.headers["content-security-policy"]
    assert (
        f"frame-src {settings.verify_origin}"
        in console.headers["content-security-policy"]
    )
    assert "threat-mitigation" not in console.headers["content-security-policy"]


def test_widget_nonce_unique_and_invalid_target_rejected():
    client = TestClient(app)
    first, second = client.get(frame_url()), client.get(frame_url())
    assert first.status_code == second.status_code == 200
    assert (
        re.search(r"'nonce-([^']+)'", first.headers["content-security-policy"])[1]
        != re.search(r"'nonce-([^']+)'", second.headers["content-security-policy"])[1]
    )
    assert (
        client.get(
            frame_url().replace("region=us-east-1", "region=evil.example")
        ).status_code
        == 422
    )


def test_widget_metadata_validates_token_api_origin():
    from app.auth_widget import public_challenge

    region = "us-east-1"
    token = lambda root: base64.b64encode(
        json.dumps({"apiRoot": root, "region": region, "envStage": "prod"}).encode()
    ).decode()
    metadata = {
        "kind": "ams",
        "id": str(uuid.uuid4()),
        "revision": 3,
        "expires_at": 1900000000,
        "region": region,
        "stage": "prod",
        "callback": "initAMS",
        "container_id": "captcha",
        "locale": "en-US",
        "show_challenge_on_load": False,
        "script_url": "https://cdn.us-east-1.threat-mitigation.aws.amazon.com/assets/consumer/consumer.min.js",
        "widget_origin": "https://cdn.us-east-1.threat-mitigation.aws.amazon.com",
        "redemption_token": token("us-east-1.threat-mitigation.aws.amazon.com"),
    }
    assert public_challenge(metadata)["kind"] == "ams"
    with pytest.raises(Exception):
        public_challenge(metadata | {"redemption_token": token("evil.example")})


def test_config_requires_isolated_https_or_explicit_local_origins():
    from app.config import Settings
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(
            app_origin="http://evil.example", verify_origin="http://verify.evil.example"
        )
    with pytest.raises(ValidationError):
        Settings(
            app_origin="https://same.example", verify_origin="https://same.example"
        )
    config = Settings(
        app_origin="http://127.0.0.1:8791",
        verify_origin="http://localhost:8792",
        auth_allow_local_origins=True,
    )
    assert config.verify_origin == "http://localhost:8792"


def test_widget_messages_reject_wrong_source_shape_revision_and_token_origin():
    """Exercise the actual embedded JS without loading AWS assets."""
    import shutil
    import subprocess
    from app.auth_widget import SCRIPT

    node = shutil.which("node")
    if not node:
        pytest.skip("Node is used only for the isolated inline-JS security fixture")
    config = {
        "parentOrigin": settings.app_origin,
        "operationId": "operation",
        "challengeId": "challenge",
        "revision": 3,
        "region": "us-east-1",
    }
    script = SCRIPT.replace("__CONFIG__", json.dumps(config))
    harness = r"""
const vm = require('vm');
const assert = require('assert/strict');
const scripts = [], sent = [];
let listener, initialized;
const parent = {postMessage:(data, origin) => sent.push({data, origin})};
const context = {parent, Date, atob:s=>Buffer.from(s,'base64').toString('utf8'),
  addEventListener:(type, fn)=>listener=fn,
  document:{createElement:()=>({}), head:{appendChild:s=>scripts.push(s)}}};
context.window = context;
vm.runInNewContext(SCRIPT_SOURCE, context);
const root = 'us-east-1.threat-mitigation.aws.amazon.com';
const c = {kind:'ams', id:'challenge', revision:3, expires_at:Date.now()/1000+300,
  region:'us-east-1', stage:'prod', callback:'initAMS', container_id:'captcha', locale:'en-US',
  show_challenge_on_load:false, widget_origin:'https://cdn.'+root,
  script_url:'https://cdn.'+root+'/assets/consumer/consumer.min.js',
  redemption_token:Buffer.from(JSON.stringify({apiRoot:root,region:'us-east-1',envStage:'prod'})).toString('base64')};
const message = {type:'kiro-auth-init', operation_id:'operation', challenge_id:'challenge', revision:3, challenge:c};
const origin = PARENT_ORIGIN;
for (const event of [
  {source:{},origin,data:message}, {source:parent,origin:'https://evil.example',data:message},
  {source:parent,origin,data:{...message, revision:4}},
  {source:parent,origin,data:{...message, challenge:{...c,password:'forbidden'}}},
  {source:parent,origin,data:{...message, challenge:{...c,redemption_token:Buffer.from(JSON.stringify({apiRoot:'evil.example',region:'us-east-1',envStage:'prod'})).toString('base64')}}}
]) listener(event);
assert.equal(scripts.length,0);
listener({source:parent,origin,data:message});
assert.equal(scripts.length,1);
context.initAMS({init: options=>initialized=options});
assert.deepEqual(Object.keys(initialized).sort(), ['locale','onChallengeComplete','onError','redemptionToken','showChallengeOnLoad'].sort());
initialized.onChallengeComplete({accessCode:'human-code',password:'must-not-forward'});
const last = sent.at(-1);
assert.equal(last.origin,origin);
assert.deepEqual(Object.keys(last.data).sort(), ['type','operation_id','challenge_id','revision','access_code'].sort());
assert.equal(last.data.access_code,'human-code');
assert.equal(last.data.type,'kiro-auth-complete');
""".replace("SCRIPT_SOURCE", json.dumps(script)).replace(
        "PARENT_ORIGIN", json.dumps(settings.app_origin)
    )
    subprocess.run([node, "-e", harness], check=True, capture_output=True, text=True)
