"""Real Chromium fixtures and local SOCKS peers; no live AWS or OCR requests."""

import asyncio
import base64
import importlib.util
import json
import logging
import os
import select
import signal
import ssl
import struct
import threading
import time
import zlib
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from test_aws_transport import socks_server  # Reuse the authenticated local TLS/SOCKS peer.


ROOT = "us-east-1.threat-mitigation.aws.amazon.com"
CDN = "cdn." + ROOT
IMAGE_HOST = "amcs-captcha-prod-us-east-1.s3.dualstack.us-east-1.amazonaws.com"
IMAGE_URL = f"https://{IMAGE_HOST}/captcha.png?X-Amz-Signature=private-fixture-signature"
PROXY = "socks5h://fixture-user:fixture-password@127.0.0.1:1080"


def browser_module():
    assert importlib.util.find_spec("app.captcha_browser"), (
        "An isolated official AMS browser adapter is required"
    )
    from app import captcha_browser

    return captcha_browser


def challenge(**changes):
    return {
        "kind": "ams", "id": "local-challenge", "revision": 2,
        "expires_at": time.time() + 300, "region": "us-east-1", "stage": "prod",
        "callback": "initAMS", "container_id": "captcha", "locale": "en-US",
        "show_challenge_on_load": False,
        "script_url": f"https://{CDN}/assets/consumer/consumer.min.js",
        "widget_origin": f"https://{CDN}",
        "redemption_token": base64.b64encode(json.dumps({
            "apiRoot": ROOT, "region": "us-east-1", "envStage": "prod",
        }).encode()).decode(),
    } | changes


def png(width=120, height=40, color=(255, 255, 255), checkerboard=False):
    def chunk(kind, value):
        return (struct.pack(">I", len(value)) + kind + value
                + struct.pack(">I", zlib.crc32(kind + value)))

    pixels = ((b"\0" + bytes(color) * width) * height if not checkerboard else b"".join(
        b"\0" + b"".join(bytes([255 * ((x + y) % 2)]) * 3 for x in range(width))
        for y in range(height)))
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(pixels))
            + chunk(b"IEND", b""))


class Gateway:
    def __init__(self):
        self.proxy = SimpleNamespace(url=PROXY)
        self.checks = 0
        self.error = None

    def _check_proxy(self):
        self.checks += 1
        if self.error:
            raise self.error


class Vision:
    def __init__(self, answer="A7b93"):
        self.answer, self.images = answer, []

    async def arecognize(self, image, mime_type="image/png"):
        self.images.append((image, mime_type))
        return self.answer


class Widget:
    def __init__(self, mode="success"):
        self.mode, self.requests, self.options = mode, [], []

    def script(self):
        image_source = (IMAGE_URL if self.mode.startswith("s3") else
                        "data:image/png;base64," + base64.b64encode(png()).decode())
        html = ("<p>Unrelated private-looking page text must not reach OCR</p>"
                '<img hidden alt="CAPTCHA" src="data:image/png;base64,'
                + base64.b64encode(png()).decode() + '">'
                '<form><img alt="CAPTCHA" width="120" height="40" '
                'src="' + image_source
                + '"><label>Enter the characters shown<input name="captcha"></label>'
                '<button type="submit">Verify</button></form>')
        return r"""
        window.initAMS({init: c => {
          const mode = __MODE__, host = document.querySelector('#captcha');
          let imageRound = 0;
          if (c.locale !== 'en-US' || c.showChallengeOnLoad !== false
              || !c.redemptionToken || typeof c.onChallengeComplete !== 'function')
            throw new Error('fixture: bad SDK configuration');
          const render = () => {
            host.innerHTML = __HTML__;
            if (mode === 'reject') host.querySelector('form img').src = __REJECT_IMAGES__[imageRound++ % 4];
            if (mode === 'generic') host.querySelector('input').name = 'code';
            host.querySelector('form').onsubmit = async event => {
              event.preventDefault();
              const response = await fetch('https://__ROOT__/verify', {
                method:'POST', headers:{'content-type':'application/json'},
                body:JSON.stringify({answer:host.querySelector('input').value})});
              const result = await response.json();
              if (mode === 'disappeared') {host.innerHTML = '<h1>Success</h1>'; return;}
              if (mode === 'invalid_callback') {c.onChallengeComplete({accessCode:42}); return;}
              if (result.accessCode) c.onChallengeComplete(result);
              else render();
            };
          };
          if (mode === 'idle') return;
          if (mode === 'unsafe') {fetch('https://untrusted.invalid/private'); return;}
          if (mode === 'websocket') {new WebSocket('wss://__ROOT__/socket'); return;}
          if (mode === 'puzzle') {host.innerHTML='<p>Select all images with a bus</p><canvas></canvas><button>Verify</button>'; return;}
          if (mode.startsWith('iframe') || mode.startsWith('s3_iframe')) {
            addEventListener('message', event => {
              if(event.origin === 'https://__CDN__') c.onChallengeComplete(event.data);
            });
            host.innerHTML='<iframe title="CAPTCHA" src="https://__CDN__/frame"></iframe>'; return;
          }
          if (mode === 'opener') {host.innerHTML='<button>Begin</button>'; host.firstChild.onclick=render; return;}
          render();
          if (mode === 'otp') host.insertAdjacentHTML('beforeend', '<p>Enter the code sent to your email</p><input autocomplete="one-time-code" name="otp">');
          if (mode === 'password') host.insertAdjacentHTML('beforeend', '<input type="password">');
        }});
        """.replace("__MODE__", json.dumps(self.mode)).replace("__HTML__", json.dumps(html)).replace("__ROOT__", ROOT).replace("__CDN__", CDN).replace(
            "__REJECT_IMAGES__", json.dumps(["data:image/png;base64," + base64.b64encode(
                png(color=(level, level, level))).decode() for level in (255, 230, 205, 180)]))

    async def response(self, request):
        self.requests.append(request)
        assert request.url.host in {ROOT, CDN, IMAGE_HOST}
        assert "fixture-password" not in str(request.headers)
        if request.url.host == IMAGE_HOST:
            assert request.method in {"GET", "HEAD"}
            assert all(name not in request.headers for name in ("authorization", "cookie", "referer"))
            if self.mode.startswith("s3_iframe_delayed"):
                await asyncio.sleep(0.5)
            return httpx.Response(200, content=png(), headers={"content-type": "image/png"})
        if request.url.path in {"/assets/core/images/audio.svg", "/assets/core/images/refresh.svg"}:
            if self.mode == "s3_iframe_delayed_refresh" and request.url.path.endswith("refresh.svg"):
                await asyncio.sleep(0.5)
            return httpx.Response(200, text='<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24"/>',
                                  headers={"content-type": "image/svg+xml"})
        if request.url.path.endswith("consumer.min.js"):
            if self.mode == "redirect":
                return httpx.Response(307, headers={"location": "https://untrusted.invalid/private"})
            if self.mode == "oversize":
                return httpx.Response(200, headers={"content-length": "100000000"})
            return httpx.Response(200, text=self.script(), headers={"content-type": "application/javascript"})
        if request.url.path == "/verify":
            assert json.loads(request.content) == {"answer": "A7b93"}
            result = {} if self.mode == "reject" else {"accessCode": "official-fixture-access-code"}
            return httpx.Response(200, json=result, headers={"access-control-allow-origin": "*"})
        if request.method == "OPTIONS":
            return httpx.Response(204, headers={
                "access-control-allow-origin": "*", "access-control-allow-methods": "POST",
                "access-control-allow-headers": "content-type",
            })
        if request.url.path == "/frame":
            source = (IMAGE_URL if self.mode.startswith("s3_iframe") else
                      "data:image/png;base64," + base64.b64encode(png()).decode())
            extra = ""
            if self.mode == "iframe_icons" or self.mode.startswith("s3_iframe_delayed"):
                extra = (f'<button type="button"><img alt="Switch to audio captcha" src="https://{CDN}/assets/core/images/audio.svg"></button>'
                         f'<button type="button"><img alt="Refresh captcha image" src="https://{CDN}/assets/core/images/refresh.svg"></button>')
            elif self.mode == "iframe_icon_only":
                extra = f'<button type="button"><img alt="Refresh captcha image" src="https://{CDN}/assets/core/images/refresh.svg"></button>'
            elif self.mode == "iframe_duplicate":
                extra = f'<img alt="captcha" width="120" height="40" src="{source}">'
            character_image = f'<img alt="CAPTCHA" width="120" height="40" src="{source}">'
            if self.mode == "iframe_icon_only":
                character_image = ""
            if self.mode.startswith("s3_iframe_delayed"):
                # Official pg has no dimensions; mainDisplay uses this flex CSS.
                character_image = ('<div style="flex:1;display:flex;align-items:center;justify-content:center">'
                                   f'<img alt="CAPTCHA" src="{source}"></div>')
            return httpx.Response(200, headers={"content-type": "text/html"}, text=(
                '<form>' + character_image + extra + '<input aria-label="Enter the characters" name="captcha">'
                '<button>Verify</button></form><script>document.querySelector("form").onsubmit = e => {'
                'e.preventDefault(); if(document.querySelector("input").value === "A7b93") '
                'parent.postMessage({accessCode:"official-frame-access-code"},"*");};</script>'
            ))
        raise AssertionError("Unexpected local widget endpoint")


class AMCSRetryWidget(Widget):
    """Official SDK semantics: a rejected guess refreshes the same form/image."""

    def __init__(self, mode="refresh", rejection_status=400, accepts_on=2):
        super().__init__("iframe")
        self.retry_mode, self.rejection_status = mode, rejection_status
        self.accepts_on = accepts_on
        self.image_round, self.verifications = 0, 0

    def retry_frame(self):
        return r"""<form hidden><img alt="captcha"><label>Type the characters shown
        <input name="captchaGuess"></label><button type="submit">Submit</button><p id="error"></p></form>
        <script>
        const form=document.querySelector('form'), picture=form.querySelector('img');
        const field=form.querySelector('input'), button=form.querySelector('button'), mode=__MODE__;
        window.fixture={statuses:[],imageRound:0};
        async function post(path, body) {
          return fetch('https://__ROOT__'+path,{method:'POST',
            headers:{'content-type':'application/x-www-form-urlencoded'},body:JSON.stringify(body)});
        }
        async function refresh() {
          const response=await post('/amcs/image',{sessionId:'local-session'});
          const data=await response.json();
          picture.onload=()=>{window.fixture.imageRound=data.round;};
          if((mode==='same_source' || mode==='same_bytes') && data.round>1) {
            // Explicitly reload the same URL while retaining the DOM/input.
            // Assigning an identical src alone reuses Chromium's decoded image.
            picture.removeAttribute('src');
            await new Promise(resolve=>setTimeout(resolve,0));
          }
          picture.src=data.imageCdnUrl;
          form.hidden=false;
        }
        form.onsubmit=async event=>{
          event.preventDefault(); button.disabled=true;
          const response=await post('/amcs/verify',{guess:field.value,sessionId:'local-session'});
          window.fixture.statuses.push(response.status);
          const result=await response.json();
          if(result.amcsAccessCode) {
            const completed=await post('/submit',{challengeAccessCode:result.amcsAccessCode});
            const answer=await completed.json();
            if(mode!=='no_callback') parent.postMessage(answer,'*');
            return;
          }
          document.querySelector('#error').textContent="That wasn't quite right, please try again.";
          button.disabled=false;
          if(mode==='stale_clear') field.value='';
          if(mode.startsWith('stale')) return;
          // The error and old guess are visible before React's refresh effect.
          await new Promise(resolve=>setTimeout(resolve,350));
          await refresh();
        };
        refresh();
        </script>""".replace("__MODE__", json.dumps(self.retry_mode)).replace("__ROOT__", ROOT)

    async def response(self, request):
        path = request.url.path
        if path not in {"/frame", "/amcs/image", "/amcs/verify", "/submit"} and request.url.host != IMAGE_HOST:
            return await super().response(request)
        self.requests.append(request)
        cors = {"access-control-allow-origin": "*"}
        if path == "/frame":
            return httpx.Response(200, text=self.retry_frame(), headers={"content-type": "text/html"})
        if request.url.host == IMAGE_HOST:
            await asyncio.sleep(0.2)
            level = 255 if self.retry_mode == "same_bytes" else 255 - 25 * (self.image_round - 1)
            return httpx.Response(200, content=png(color=(level, level, level)), headers={
                "content-type": "image/png", "cache-control": "no-store",
            })
        assert request.method == "POST" and request.url.host == ROOT
        if path == "/amcs/image":
            self.image_round += 1
            url = IMAGE_URL if self.retry_mode in {"same_source", "same_bytes"} else IMAGE_URL + f"&round={self.image_round}"
            return httpx.Response(200, json={"imageCdnUrl": url, "round": self.image_round}, headers=cors)
        if path == "/amcs/verify":
            assert json.loads(request.content) == {"guess": "A7b93", "sessionId": "local-session"}
            self.verifications += 1
            if self.verifications < self.accepts_on or self.retry_mode == "always_reject" or self.retry_mode.startswith("stale"):
                return httpx.Response(self.rejection_status, json={"invalidGuess": True}, headers=cors)
            return httpx.Response(200, json={"amcsAccessCode": "local-amcs-code"}, headers=cors)
        return httpx.Response(200, json={"accessCode": "official-retry-access-code"}, headers=cors)


class CompletingFrameWidget(Widget):
    """The consumer replaces its iframe when the core reports completion."""

    def __init__(self, outcome="complete"):
        super().__init__("iframe")
        self.outcome = outcome

    def script(self):
        completed = "" if self.outcome == "no_callback" else "c.onChallengeComplete(event.data);"
        otp = ("host.insertAdjacentHTML('beforeend', '<p>Enter the code sent to your email</p>"
               "<input autocomplete=\"one-time-code\" name=\"otp\">');") if self.outcome == "otp" else ""
        return super().script().replace("c.onChallengeComplete(event.data);",
            "{" + completed + "host.querySelector('iframe').remove();" + otp + "}")

    async def response(self, request):
        response = await super().response(request)
        if request.url.path == "/frame":
            return httpx.Response(200, headers={"content-type": "text/html"}, text=response.text.replace(
                'parent.postMessage({accessCode:"official-frame-access-code"},"*");',
                "window.fixtureSubmitted=true;"))
        return response


async def complete_frame(contexts):
    page = contexts[0][1].pages[0]
    frame = page.frames[1]
    # wait_for_function uses eval and can trip the bootstrap page's strict CSP.
    async with page.expect_event("framedetached", predicate=lambda detached: detached == frame):
        await frame.evaluate('parent.postMessage({accessCode:"official-frame-access-code"},"*")')


@pytest.fixture(scope="module")
def chromium():
    playwright = pytest.importorskip("playwright.async_api", reason="Playwright is unavailable")
    executable = os.getenv("CAPTCHA_CHROMIUM_EXECUTABLE")
    chrome = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
    if not executable and Path(chrome).is_file():
        executable = chrome

    async def check():
        async with playwright.async_playwright() as api:
            try:
                browser = await api.chromium.launch(headless=True, executable_path=executable)
            except playwright.Error as exc:
                if "Executable doesn't exist" in str(exc):
                    pytest.skip("Chromium is not installed")
                raise
            await browser.close()

    asyncio.run(check())
    return executable


@pytest.fixture
def browser_fixture(monkeypatch, chromium):
    module = browser_module()
    from playwright.async_api import Browser, BrowserType

    if chromium:
        monkeypatch.setenv("CAPTCHA_CHROMIUM_EXECUTABLE", chromium)
    contexts, launches, clients = [], [], []
    original_context, original_launch = Browser.new_context, BrowserType.launch
    original_client = httpx.AsyncClient

    async def context(browser, *args, **kwargs):
        value = await original_context(browser, *args, **kwargs)
        contexts.append((browser, value, kwargs))
        return value

    async def launch(kind, *args, **kwargs):
        launches.append(kwargs)
        return await original_launch(kind, *args, **kwargs)

    monkeypatch.setattr(Browser, "new_context", context)
    monkeypatch.setattr(BrowserType, "launch", launch)

    def install(mode="success", widget=None, *, expected_proxy=PROXY):
        widget = widget or Widget(mode)

        def client(*args, **kwargs):
            widget.options.append(kwargs.copy())
            assert kwargs.pop("proxy") == expected_proxy
            if expected_proxy is None:
                from app.vision_transport import PublicEndpointTransport
                assert isinstance(kwargs.pop("transport"), PublicEndpointTransport)
            assert kwargs.get("trust_env") is False
            assert kwargs.get("follow_redirects") is False
            assert kwargs.get("max_redirects") == 0
            value = original_client(*args, **kwargs, transport=httpx.MockTransport(widget.response))
            clients.append(value)
            return value

        monkeypatch.setattr(module.httpx, "AsyncClient", client)
        return widget

    yield install, contexts, launches
    assert all(client.is_closed for client in clients)
    browser_states = [(browser.is_connected(), len(context.pages)) for browser, context, _ in contexts]
    assert browser_states == [(False, 0)] * len(contexts)


def run(module, gateway, vision, before, seconds=8, value=None):
    return module.solve_ams(value or challenge(), gateway, vision,
                            deadline=time.monotonic() + seconds, before_recognition=before)


@pytest.mark.parametrize("mode", ["success", "generic", "opener", "iframe"])
def test_real_browser_crops_characters_and_requires_official_callback(browser_fixture, mode):
    module = browser_module()
    install, contexts, launches = browser_fixture
    widget, gateway, vision, attempts = install(mode), Gateway(), Vision(), []
    result = run(module, gateway, vision, lambda: attempts.append("recognizing"))
    assert result == ("official-frame-access-code" if mode == "iframe" else "official-fixture-access-code")
    assert attempts == ["recognizing"]
    image, mime = vision.images[0]
    assert mime == "image/png" and struct.unpack(">II", image[16:24]) == (120, 40)
    assert len(image) < 2000
    assert gateway.checks >= len(widget.requests)
    assert launches[0]["headless"] is True
    assert launches[0]["proxy"]["server"] == "http://127.0.0.1:9"
    assert "--proxy-bypass-list=<-loopback>" in launches[0]["args"]
    assert contexts[0][2]["service_workers"] == "block"
    assert contexts[0][2]["accept_downloads"] is False


@pytest.mark.parametrize("mode", ["s3", "s3_iframe"])
def test_amcs_regional_s3_image_uses_guarded_proxy_and_only_crop_reaches_ocr(browser_fixture, caplog, mode):
    module = browser_module()
    install, _, _ = browser_fixture
    widget, gateway, vision = install(mode), Gateway(), Vision()
    with caplog.at_level(logging.DEBUG):
        result = run(module, gateway, vision, lambda: None)
    assert result == ("official-frame-access-code" if mode == "s3_iframe" else "official-fixture-access-code")
    image_requests = [request for request in widget.requests if request.url.host == IMAGE_HOST]
    assert len(image_requests) == len(vision.images) == 1
    assert image_requests[0].url == IMAGE_URL
    assert struct.unpack(">II", vision.images[0][0][16:24]) == (120, 40)
    assert gateway.checks >= len(widget.requests)
    assert "private-fixture-signature" not in caplog.text and IMAGE_HOST not in caplog.text


def test_official_image_form_icons_are_not_treated_as_additional_captchas(browser_fixture):
    module = browser_module()
    install, _, _ = browser_fixture
    widget, vision = install("iframe_icons"), Vision()
    assert run(module, Gateway(), vision, lambda: None) == "official-frame-access-code"
    assert len(vision.images) == 1 and struct.unpack(">II", vision.images[0][0][16:24]) == (120, 40)
    assert len([request for request in widget.requests if request.url.path.endswith(".svg")]) == 2


@pytest.mark.parametrize("mode", ["iframe_duplicate", "iframe_icon_only"])
def test_ambiguous_or_icon_only_character_images_are_rejected(browser_fixture, mode):
    module = browser_module()
    install, _, _ = browser_fixture
    install(mode)
    vision = Vision()
    with pytest.raises(module.BrowserChallengeError, match="^captcha_unsupported_challenge$"):
        run(module, Gateway(), vision, lambda: pytest.fail("Ambiguous images cannot reach OCR"))
    assert vision.images == []


@pytest.mark.parametrize("mode", ["s3_iframe_delayed", "s3_iframe_delayed_refresh"])
def test_delayed_official_image_is_loaded_before_ocr(browser_fixture, mode):
    module = browser_module()
    install, contexts, _ = browser_fixture
    install(mode)

    class LoadedVision(Vision):
        async def arecognize(self, *args, **kwargs):
            frame = contexts[0][1].pages[0].frames[1]
            assert await frame.locator('img[alt="CAPTCHA"]').evaluate(
                "el => el.complete && el.naturalWidth === 120 && el.naturalHeight === 40")
            return await super().arecognize(*args, **kwargs)

    vision = LoadedVision()
    assert run(module, Gateway(), vision, lambda: None) == "official-frame-access-code"
    assert len(vision.images) == 1


def test_image_completion_between_visibility_checks_cannot_drop_character_candidate(browser_fixture, monkeypatch):
    module = browser_module()
    from playwright.async_api import Locator

    install, _, _ = browser_fixture
    install("s3_iframe_delayed")
    original_visible = Locator.is_visible

    async def visibility(locator, *args, **kwargs):
        visible = await original_visible(locator, *args, **kwargs)
        if not visible and await locator.count() == 1 and await locator.evaluate(
            "el => el.tagName === 'IMG' && el.alt === 'CAPTCHA' && !el.complete"):
            # A valid interleaving: the image finishes after the visibility
            # observation but before any separate candidate metadata check.
            await locator.evaluate("el => el.decode()")
        return visible

    monkeypatch.setattr(Locator, "is_visible", visibility)
    vision = Vision()
    assert run(module, Gateway(), vision, lambda: None) == "official-frame-access-code"
    assert len(vision.images) == 1 and struct.unpack(">II", vision.images[0][0][16:24]) == (120, 40)


@pytest.mark.parametrize("method,resource_type,url,body", [
    ("POST", "image", IMAGE_URL, b"private"),
    ("OPTIONS", "image", IMAGE_URL, None),
    ("GET", "fetch", IMAGE_URL, None),
    ("GET", "script", IMAGE_URL, None),
    ("GET", "document", IMAGE_URL, None),
    ("GET", "image", IMAGE_URL, b"private"),
    ("GET", "image", IMAGE_URL.replace("us-east-1", "us-west-2"), None),
    ("GET", "image", IMAGE_URL.replace(IMAGE_HOST, IMAGE_HOST + ".evil.invalid"), None),
    ("GET", "image", IMAGE_URL.replace("amcs-captcha-prod-us-east-1", "other-bucket"), None),
])
def test_amcs_image_endpoint_rejects_other_regions_resources_and_writes(method, resource_type, url, body):
    module = browser_module()

    async def check():
        transport = module._ProxyHTTP(Gateway(), {ROOT, CDN}, time.monotonic() + 2, image_host=IMAGE_HOST)
        # No HTTP client exists: rejected requests cannot reach the wire.
        await transport.fetch(method, url, {}, body, resource_type)

    with pytest.raises(module.BrowserChallengeError, match="^captcha_unsafe_destination$"):
        asyncio.run(check())


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_amcs_image_request_strips_browser_and_client_jar_credentials(monkeypatch, method):
    module, gateway = browser_module(), Gateway()
    requests, original_client = [], httpx.AsyncClient

    async def respond(request):
        requests.append(request)
        assert all(name not in request.headers for name in ("cookie", "authorization", "referer"))
        return httpx.Response(200, content=png() if method == "GET" else b"", headers={
            "content-type": "image/png", "set-cookie": "image-session=private; Path=/",
        })

    def client(*args, **kwargs):
        assert kwargs.pop("proxy") == PROXY
        return original_client(*args, **kwargs, transport=httpx.MockTransport(respond))

    monkeypatch.setattr(module.httpx, "AsyncClient", client)

    async def check():
        async with module._ProxyHTTP(gateway, {ROOT, CDN}, time.monotonic() + 2, image_host=IMAGE_HOST) as transport:
            transport.client.cookies.set("prior-session", "private", domain=IMAGE_HOST)
            status, headers, _ = await transport.fetch(method, IMAGE_URL, {
                "cookie": "browser-session=private", "authorization": "Bearer private",
                "referer": "https://private.invalid/token",
            }, None, "image")
            assert status == 200 and "set-cookie" not in headers

    asyncio.run(check())
    assert len(requests) == 1 and gateway.checks >= 2


@pytest.mark.parametrize("status,headers,content,code", [
    (302, {"location": "https://other-bucket.s3.amazonaws.com/private"}, b"", "captcha_unsafe_destination"),
    (200, {"content-type": "text/html"}, b"<html>private</html>", "captcha_invalid_response"),
    (200, {"content-type": "image/svg+xml"}, b"<svg/>", "captcha_invalid_response"),
    (200, {}, b"opaque", "captcha_invalid_response"),
    (200, {"content-type": "image/png", "content-length": "2000001"}, b"", "captcha_invalid_response"),
    (200, {"content-type": "image/png"}, b"x" * 2_000_001, "captcha_invalid_response"),
])
def test_amcs_image_rejects_redirects_non_raster_and_large_responses(monkeypatch, status, headers, content, code):
    module, requests, original_client = browser_module(), [], httpx.AsyncClient

    async def respond(request):
        requests.append(request)
        response = httpx.Response(status, content=content, headers=headers)
        if "content-length" not in headers:
            response.headers.pop("content-length", None)
        return response

    def client(*args, **kwargs):
        assert kwargs.pop("proxy") == PROXY
        assert kwargs["follow_redirects"] is False and kwargs["max_redirects"] == 0
        return original_client(*args, **kwargs, transport=httpx.MockTransport(respond))

    monkeypatch.setattr(module.httpx, "AsyncClient", client)

    async def check():
        async with module._ProxyHTTP(Gateway(), {ROOT, CDN}, time.monotonic() + 2, image_host=IMAGE_HOST) as transport:
            await transport.fetch("GET", IMAGE_URL, {}, None, "image")

    with pytest.raises(module.BrowserChallengeError, match=f"^{code}$"):
        asyncio.run(check())
    assert len(requests) == 1


@pytest.mark.parametrize("mode", ["otp", "password", "puzzle"])
def test_unsupported_challenges_never_reach_ocr(browser_fixture, mode):
    module = browser_module()
    install, _, _ = browser_fixture
    install(mode)
    vision, attempts = Vision(), []
    with pytest.raises(module.BrowserChallengeError, match="^captcha_unsupported_challenge$"):
        run(module, Gateway(), vision, lambda: attempts.append(1))
    assert vision.images == attempts == []


@pytest.mark.parametrize("mode,code", [
    ("unsafe", "captcha_unsafe_destination"),
    ("redirect", "captcha_unsafe_destination"),
    ("websocket", "captcha_unsafe_destination"),
    ("oversize", "captcha_invalid_response"),
])
def test_network_is_closed_to_untrusted_destinations_and_unbounded_bodies(browser_fixture, mode, code):
    module = browser_module()
    install, _, _ = browser_fixture
    widget = install(mode)
    with pytest.raises(module.BrowserChallengeError, match=f"^{code}$"):
        run(module, Gateway(), Vision(), lambda: None)
    assert len(widget.requests) == 1


def test_six_rejected_character_submissions_bound_actual_ocr(browser_fixture):
    module = browser_module()
    install, _, _ = browser_fixture
    widget, vision, attempts = install("reject"), Vision(), []
    with pytest.raises(module.BrowserChallengeError, match="^captcha_attempt_limit$"):
        run(module, Gateway(), vision, lambda: attempts.append(1))
    assert len(vision.images) == len(attempts) == 6
    assert len([request for request in widget.requests if request.method == "POST"]) == 6


@pytest.mark.parametrize("mode,status", [("refresh", 400), ("refresh", 200), ("same_source", 400)])
def test_sdk_rejection_waits_for_new_ready_image_in_same_dom(browser_fixture, mode, status):
    module = browser_module()
    install, contexts, _ = browser_fixture
    widget = install(widget=AMCSRetryWidget(mode, rejection_status=status))
    snapshots, attempts = [], []

    class ReadyVision(Vision):
        async def arecognize(self, *args, **kwargs):
            frame = contexts[0][1].pages[0].frames[1]
            snapshots.append(await frame.evaluate("""() => ({
              round:window.fixture.imageRound, value:document.querySelector('input').value,
              src:document.querySelector('img').src, statuses:window.fixture.statuses,
              ready:document.querySelector('img').complete && document.querySelector('img').naturalWidth===120
            })"""))
            assert snapshots[-1]["ready"] and snapshots[-1]["round"] == len(snapshots)
            return await super().arecognize(*args, **kwargs)

    vision = ReadyVision()
    assert run(module, Gateway(), vision, lambda: attempts.append(1)) == "official-retry-access-code"
    assert len(vision.images) == len(attempts) == widget.verifications == 2
    assert snapshots[1]["value"] == "A7b93" and snapshots[1]["statuses"] == [status]
    assert vision.images[0][0] != vision.images[1][0]
    assert (snapshots[0]["src"] == snapshots[1]["src"]) is (mode == "same_source")
    assert len([request for request in widget.requests if request.url.path == "/submit"]) == 1


@pytest.mark.parametrize("mode", ["stale", "stale_clear"])
def test_rejection_text_or_cleared_input_without_new_image_does_not_repeat_ocr(browser_fixture, mode):
    module = browser_module()
    install, _, _ = browser_fixture
    widget = install(widget=AMCSRetryWidget(mode, rejection_status=200))
    vision, attempts = Vision(), []
    with pytest.raises(module.BrowserChallengeError, match="^captcha_timeout$"):
        run(module, Gateway(), vision, lambda: attempts.append(1), seconds=2)
    assert len(vision.images) == len(attempts) == widget.verifications == 1
    assert not any(request.url.path == "/submit" for request in widget.requests)


def test_error_layout_moving_identical_image_does_not_repeat_ocr(browser_fixture):
    module = browser_module()
    install, _, _ = browser_fixture
    source = "data:image/png;base64," + base64.b64encode(png(checkerboard=True)).decode()

    class LayoutWidget(Widget):
        def script(self):
            html = """
            <style>#captcha{display:flex;align-items:center;height:300px} form{margin:0}
            img{display:block} #error{margin:0;line-height:19px}</style>
            <form><img alt="captcha" width="120" height="40" src="__SOURCE__">
            <label>Enter the characters<input name="captcha"></label><button>Verify</button>
            <p id="error"></p></form>""".replace("__SOURCE__", source)
            return """window.initAMS({init:()=>{
            document.querySelector('#captcha').innerHTML=__HTML__;
            document.querySelector('form').onsubmit=async event=>{
              event.preventDefault();
              await fetch('https://__ROOT__/verify',{method:'POST',
                headers:{'content-type':'application/json'},
                body:JSON.stringify({answer:document.querySelector('input').value})});
              document.querySelector('#error').textContent="That wasn't quite right, please try again.";
            };}});""".replace("__HTML__", json.dumps(html)).replace("__ROOT__", ROOT)

    widget = install(widget=LayoutWidget())
    vision, attempts = Vision(), []
    with pytest.raises(module.BrowserChallengeError, match="^captcha_timeout$"):
        run(module, Gateway(), vision, lambda: attempts.append(1), seconds=2)
    assert len(vision.images) == len(attempts) == 1
    assert len([request for request in widget.requests if request.url.path == "/verify"]) == 1


def test_same_source_refresh_during_ocr_never_receives_stale_answer(browser_fixture):
    module = browser_module()
    install, contexts, _ = browser_fixture
    widget = install(widget=AMCSRetryWidget("same_source"))
    attempts = []

    class ChangingVision(Vision):
        async def arecognize(self, *args, **kwargs):
            if not self.images:
                widget.image_round = 2
                frame = contexts[0][1].pages[0].frames[1]
                await frame.evaluate("""async () => {
                  const image=document.querySelector('img'), source=image.src;
                  image.removeAttribute('src');
                  await new Promise(resolve=>setTimeout(resolve,30));
                  image.src=source; await image.decode();
                }""")
            return await super().arecognize(*args, **kwargs)

    vision = ChangingVision()
    with pytest.raises(module.BrowserChallengeError, match="^captcha_unsupported_challenge$"):
        run(module, Gateway(), vision, lambda: attempts.append(1), seconds=3)
    assert len(vision.images) == len(attempts) == 1
    assert len([request for request in widget.requests if request.url.host == IMAGE_HOST]) == 2
    assert widget.verifications == 0


def test_same_source_reload_of_identical_bytes_does_not_repeat_ocr(browser_fixture):
    module = browser_module()
    install, _, _ = browser_fixture
    widget = install(widget=AMCSRetryWidget("same_bytes"))
    vision, attempts = Vision(), []
    with pytest.raises(module.BrowserChallengeError, match="^captcha_timeout$"):
        run(module, Gateway(), vision, lambda: attempts.append(1), seconds=2.5)
    assert len(vision.images) == len(attempts) == widget.verifications == 1
    assert widget.image_round == 2
    assert len([request for request in widget.requests if request.url.host == IMAGE_HOST]) == 2


def test_same_source_refresh_during_screenshot_discards_old_crop_before_ocr(browser_fixture, monkeypatch):
    module = browser_module()
    from playwright.async_api import ElementHandle

    install, contexts, _ = browser_fixture
    widget = install(widget=AMCSRetryWidget("same_source"))
    original = ElementHandle.screenshot
    discarded, attempts = [], []

    async def screenshot(element, *args, **kwargs):
        cropped = await original(element, *args, **kwargs)
        if not discarded:
            discarded.append(cropped)
            widget.image_round = 2
            await contexts[0][1].pages[0].frames[1].evaluate("""async () => {
              const image=document.querySelector('img'), source=image.src;
              image.removeAttribute('src');
              await new Promise(resolve=>setTimeout(resolve,30));
              image.src=source; await image.decode();
            }""")
        return cropped

    monkeypatch.setattr(ElementHandle, "screenshot", screenshot)
    vision = Vision()
    assert run(module, Gateway(), vision, lambda: attempts.append(1)) == "official-retry-access-code"
    assert discarded and discarded[0] not in [crop for crop, _ in vision.images]
    assert len(vision.images) == len(attempts) == widget.verifications == 2


@pytest.mark.parametrize("limit", [1, 3, 6])
def test_sdk_400_rejections_stop_at_configured_recognition_limit(browser_fixture, monkeypatch, limit):
    from app.config import settings

    monkeypatch.setattr(settings, "captcha_max_attempts", limit)
    module = browser_module()
    install, _, _ = browser_fixture
    widget = install(widget=AMCSRetryWidget("always_reject"))
    vision, attempts = Vision(), []
    with pytest.raises(module.BrowserChallengeError, match="^captcha_attempt_limit$") as caught:
        run(module, Gateway(), vision, lambda: attempts.append(1), seconds=12)
    assert caught.value.last_failure_code == "captcha_answer_rejected"
    assert len(vision.images) == len(attempts) == widget.verifications == limit
    assert len({image for image, _ in vision.images}) == limit
    assert not any(request.url.path == "/submit" for request in widget.requests)


def test_sdk_character_challenge_can_succeed_on_sixth_recognition(browser_fixture):
    module = browser_module()
    install, _, launches = browser_fixture
    widget = install(widget=AMCSRetryWidget(accepts_on=6))
    vision, attempts = Vision(), []
    assert run(module, Gateway(), vision, lambda: attempts.append(1), seconds=12) == "official-retry-access-code"
    assert len(vision.images) == len(attempts) == widget.verifications == 6
    assert len({image for image, _ in vision.images}) == 6
    assert len(launches) == len([request for request in widget.requests if request.url.path == "/submit"]) == 1


def test_sdk_retry_still_requires_official_completion_callback(browser_fixture):
    module = browser_module()
    install, _, _ = browser_fixture
    widget = install(widget=AMCSRetryWidget("no_callback"))
    vision = Vision()
    with pytest.raises(module.BrowserChallengeError, match="^captcha_timeout$"):
        # Include browser startup and two real image/verify rounds on the
        # slower deployment hosts before testing the missing callback deadline.
        run(module, Gateway(), vision, lambda: None)
    assert len(vision.images) == widget.verifications == 2
    assert any(request.url.path == "/submit" for request in widget.requests)


@pytest.mark.parametrize("outcome", ["complete", "no_callback", "otp", "revoked"])
def test_detached_completion_frame_is_rescanned_before_callback(browser_fixture, monkeypatch, outcome):
    from playwright.async_api import Locator

    module = browser_module()
    install, contexts, _ = browser_fixture
    install(widget=CompletingFrameWidget(outcome))
    gateway, vision, triggered = Gateway(), Vision(), []
    revocation = RuntimeError("local revocation after frame completion")
    original = Locator.inner_text

    async def inner_text(locator, *args, **kwargs):
        if not triggered and locator._impl_obj._frame.url == f"https://{CDN}/frame":
            frame = contexts[0][1].pages[0].frames[1]
            if await frame.evaluate("!!window.fixtureSubmitted"):
                triggered.append(True)
                await complete_frame(contexts)
                if outcome == "revoked":
                    gateway.error = revocation
        return await original(locator, *args, **kwargs)

    monkeypatch.setattr(Locator, "inner_text", inner_text)
    if outcome == "complete":
        assert run(module, gateway, vision, lambda: None) == "official-frame-access-code"
    elif outcome == "revoked":
        with pytest.raises(RuntimeError) as caught:
            run(module, gateway, vision, lambda: None)
        assert caught.value is revocation
    else:
        code = "captcha_timeout" if outcome == "no_callback" else "captcha_unsupported_challenge"
        with pytest.raises(module.BrowserChallengeError, match=f"^{code}$"):
            run(module, gateway, vision, lambda: None, seconds=3)
    assert triggered and len(vision.images) == 1


def test_sdk_detaches_frame_before_submit_click_returns(browser_fixture, monkeypatch):
    from playwright.async_api import ElementHandle

    module = browser_module()
    install, contexts, _ = browser_fixture
    install(widget=CompletingFrameWidget())
    original = ElementHandle.click

    async def click(element, *args, **kwargs):
        frame = await element.owner_frame()
        await original(element, *args, **kwargs)
        await complete_frame(contexts)
        assert frame.is_detached()
        # A real protocol operation on the now-detached frame fails; the
        # consumer has already recorded its official completion callback.
        await frame.locator("button").inner_text()

    monkeypatch.setattr(ElementHandle, "click", click)
    vision = Vision()
    assert run(module, Gateway(), vision, lambda: None) == "official-frame-access-code"
    assert len(vision.images) == 1


def test_callback_and_otp_after_last_successful_frame_read_require_new_scan(browser_fixture, monkeypatch):
    from playwright.async_api import Locator

    module = browser_module()
    install, contexts, _ = browser_fixture
    install(widget=CompletingFrameWidget("otp"))
    vision, triggered = Vision(), []
    original = Locator.is_enabled

    async def is_enabled(locator, *args, **kwargs):
        enabled = await original(locator, *args, **kwargs)
        if not triggered and locator._impl_obj._frame.url == f"https://{CDN}/frame":
            is_submit = await locator.evaluate("el => el.tagName === 'BUTTON' && !!window.fixtureSubmitted")
            if is_submit:
                triggered.append(True)
                # The last frame read succeeded; no detached exception is needed.
                await complete_frame(contexts)
        return enabled

    monkeypatch.setattr(Locator, "is_enabled", is_enabled)
    with pytest.raises(module.BrowserChallengeError, match="^captcha_unsupported_challenge$"):
        run(module, Gateway(), vision, lambda: None)
    assert triggered and len(vision.images) == 1


def test_attached_frame_playwright_failure_is_not_ignored(browser_fixture, monkeypatch):
    from playwright.async_api import Error, Locator

    module = browser_module()
    install, contexts, _ = browser_fixture
    install("iframe")
    original = Locator.inner_text

    async def inner_text(locator, *args, **kwargs):
        if locator._impl_obj._frame.url == f"https://{CDN}/frame":
            assert not contexts[0][1].pages[0].frames[1].is_detached()
            raise Error("local unrelated protocol failure")
        return await original(locator, *args, **kwargs)

    monkeypatch.setattr(Locator, "inner_text", inner_text)
    vision = Vision()
    with pytest.raises(module.BrowserChallengeError, match="^captcha_browser_failed$"):
        run(module, Gateway(), vision, lambda: None)
    assert not vision.images


def test_other_attached_frame_error_is_not_hidden_by_current_frame_detach(browser_fixture, monkeypatch):
    from playwright.async_api import Error, Locator

    class OtherFrameWidget(CompletingFrameWidget):
        def script(self):
            return super().script().replace(f'src="https://{CDN}/frame"></iframe>',
                f'src="https://{CDN}/frame"></iframe><iframe title="other" src="https://{CDN}/other"></iframe>')

        async def response(self, request):
            if request.url.path == "/other":
                self.requests.append(request)
                return httpx.Response(200, text="<p>Status</p>", headers={"content-type": "text/html"})
            return await super().response(request)

    module = browser_module()
    install, contexts, _ = browser_fixture
    install(widget=OtherFrameWidget())
    vision, triggered = Vision(), []
    original = Locator.inner_text

    async def inner_text(locator, *args, **kwargs):
        if vision.images and not triggered and locator._impl_obj._frame.url == f"https://{CDN}/other":
            triggered.append(True)
            page = contexts[0][1].pages[0]
            current = page.frames[1]
            await complete_frame(contexts)
            assert current.is_detached() and not page.frames[1].is_detached()
            raise Error("local error belongs to the other attached frame")
        return await original(locator, *args, **kwargs)

    monkeypatch.setattr(Locator, "inner_text", inner_text)
    with pytest.raises(module.BrowserChallengeError, match="^captcha_browser_failed$"):
        run(module, Gateway(), vision, lambda: None)
    assert triggered and len(vision.images) == 1


@pytest.mark.parametrize("outcome", ["complete", "no_callback"])
def test_opener_click_frame_detach_still_requires_callback(browser_fixture, monkeypatch, outcome):
    from playwright.async_api import Locator

    class OpenerWidget(CompletingFrameWidget):
        async def response(self, request):
            if request.url.path == "/frame":
                self.requests.append(request)
                return httpx.Response(200, text="<button>Begin</button>", headers={"content-type": "text/html"})
            return await super().response(request)

    module = browser_module()
    install, contexts, _ = browser_fixture
    install(widget=OpenerWidget(outcome))
    original = Locator.click

    async def click(locator, *args, **kwargs):
        await original(locator, *args, **kwargs)
        await complete_frame(contexts)
        await locator.inner_text()

    monkeypatch.setattr(Locator, "click", click)
    vision, attempts = Vision(), []
    if outcome == "complete":
        assert run(module, Gateway(), vision, lambda: attempts.append(1)) == "official-frame-access-code"
    else:
        with pytest.raises(module.BrowserChallengeError, match="^captcha_timeout$"):
            run(module, Gateway(), vision, lambda: attempts.append(1), seconds=3)
    assert not vision.images and not attempts


@pytest.mark.parametrize("code", ["captcha_provider_failed", "captcha_timeout", "captcha_invalid_response"])
def test_temporary_vision_error_retries_same_ams_browser(browser_fixture, code):
    from app.vision_captcha import VisionError

    module = browser_module()
    install, _, launches = browser_fixture
    widget = install()
    attempts = []

    class RetryVision(Vision):
        async def arecognize(self, *args, **kwargs):
            answer = await super().arecognize(*args, **kwargs)
            if len(self.images) == 1:
                raise VisionError(code)
            return answer

    vision = RetryVision()
    assert run(module, Gateway(), vision, lambda: attempts.append(1)) == "official-fixture-access-code"
    assert len(vision.images) == len(attempts) == 2
    assert len(launches) == len([r for r in widget.requests if r.url.path.endswith("consumer.min.js")]) == 1
    assert len([r for r in widget.requests if r.url.path == "/verify"]) == 1


@pytest.mark.parametrize("code", ["captcha_unavailable", "captcha_invalid_configuration", "captcha_invalid_image"])
def test_fatal_vision_error_still_propagates_without_retry(browser_fixture, code):
    from app.vision_captcha import VisionError

    module = browser_module()
    install, _, launches = browser_fixture
    widget = install()
    failure, attempts = VisionError(code), []

    class FailingVision(Vision):
        async def arecognize(self, *args, **kwargs):
            await super().arecognize(*args, **kwargs)
            raise failure

    vision = FailingVision()
    with pytest.raises(VisionError) as caught:
        run(module, Gateway(), vision, lambda: attempts.append(1))
    assert caught.value is failure and len(vision.images) == len(attempts) == len(launches) == 1
    assert not any(r.url.path == "/verify" for r in widget.requests)


def test_temporary_vision_errors_still_stop_at_six_actual_attempts(browser_fixture):
    from app.vision_captcha import VisionError

    module = browser_module()
    install, _, launches = browser_fixture
    widget = install()
    attempts = []

    class FailingVision(Vision):
        async def arecognize(self, *args, **kwargs):
            await super().arecognize(*args, **kwargs)
            raise VisionError("captcha_provider_failed")

    vision = FailingVision()
    with pytest.raises(module.BrowserChallengeError, match="^captcha_attempt_limit$") as caught:
        run(module, Gateway(), vision, lambda: attempts.append(1))
    assert caught.value.last_failure_code == "captcha_provider_failed"
    assert len(vision.images) == len(attempts) == 6 and len(launches) == 1
    assert not any(r.url.path == "/verify" for r in widget.requests)


@pytest.mark.parametrize('limit,cause,first_rejected', [
    (1, 'captcha_provider_failed', False), (2, 'captcha_provider_failed', False),
    (1, 'captcha_answer_rejected', False), (2, 'captcha_answer_rejected', False),
    (2, 'captcha_provider_failed', True),
    (3, 'captcha_provider_failed', False), (6, 'captcha_provider_failed', False),
    (3, 'captcha_answer_rejected', False), (6, 'captcha_answer_rejected', False),
])
def test_global_ams_budget_preserves_last_safe_failure(browser_fixture, monkeypatch, limit, cause, first_rejected):
    from app.config import settings
    from app.security import decrypt
    from app.vision_captcha import VisionError
    from test_auth_automation import CaptchaLogin, solve

    module = browser_module()
    install, _, launches = browser_fixture
    install('reject' if cause == 'captcha_answer_rejected' or first_rejected else 'success')
    monkeypatch.setattr(settings, 'captcha_max_attempts', limit)

    class FailingVision(Vision):
        async def arecognize(self, *args, **kwargs):
            answer = await super().arecognize(*args, **kwargs)
            if cause == 'captcha_provider_failed' and (not first_rejected or len(self.images) > 1):
                raise VisionError(cause)
            return answer

    adapter, vision = CaptchaLogin(), FailingVision()
    adapter.gateway.proxy.url = PROXY
    def browser(_challenge, gateway, provider, *, deadline, before_recognition):
        return module.solve_ams(challenge(), gateway, provider, deadline=deadline,
                                before_recognition=before_recognition)
    result = solve(adapter, adapter.start(ams=True), vision, browser_solver=browser)
    automatic = decrypt(result.sealed_state)['captcha_automation']
    assert automatic['reason'] == 'captcha_attempt_limit'
    assert automatic.get('last_failure_code') == cause
    assert automatic['attempts'] == len(vision.images) == limit
    assert automatic['submissions'] == 0 and not adapter.answers
    assert len(launches) == 1
    following = solve(adapter, result, vision, browser_solver=browser)
    assert following.status == 'challenge' and len(vision.images) == limit


def test_vision_retry_shares_original_deadline(browser_fixture):
    from app.vision_captcha import VisionError

    module = browser_module()
    install, _, launches = browser_fixture
    install()
    attempts = []

    class SlowRetryVision(Vision):
        async def arecognize(self, *args, **kwargs):
            await super().arecognize(*args, **kwargs)
            if len(self.images) == 1:
                raise VisionError("captcha_timeout")
            await asyncio.sleep(10)

    vision = SlowRetryVision()
    started = time.monotonic()
    with pytest.raises(module.BrowserChallengeError, match="^captcha_timeout$"):
        run(module, Gateway(), vision, lambda: attempts.append(1), seconds=3)
    assert time.monotonic() - started < 3.5
    assert len(vision.images) == len(attempts) == 2 and len(launches) == 1


@pytest.mark.parametrize("change", ["revoked", "otp"])
def test_temporary_vision_error_rechecks_guard_and_challenge_before_retry(browser_fixture, change):
    from app.vision_captcha import VisionError

    module = browser_module()
    install, contexts, _ = browser_fixture
    widget = install()
    gateway, attempts = Gateway(), []
    revocation = RuntimeError("local revocation during provider failure")

    class ChangingVision(Vision):
        async def arecognize(self, *args, **kwargs):
            await super().arecognize(*args, **kwargs)
            if change == "revoked":
                gateway.error = revocation
            else:
                await contexts[0][1].pages[0].evaluate("""document.querySelector('#captcha')
                    .insertAdjacentHTML('beforeend','<input name="otp" autocomplete="one-time-code">')""")
            raise VisionError("captcha_provider_failed")

    vision = ChangingVision()
    if change == "revoked":
        with pytest.raises(RuntimeError) as caught:
            run(module, gateway, vision, lambda: attempts.append(1))
        assert caught.value is revocation
    else:
        with pytest.raises(module.BrowserChallengeError, match="^captcha_unsupported_challenge$"):
            run(module, gateway, vision, lambda: attempts.append(1))
    assert len(vision.images) == len(attempts) == 1
    assert not any(r.url.path == "/verify" for r in widget.requests)


def test_proxy_revocation_during_sdk_refresh_wait_is_preserved(browser_fixture):
    module = browser_module()
    install, _, _ = browser_fixture
    widget = install(widget=AMCSRetryWidget())
    gateway, vision = Gateway(), Vision()
    failure = RuntimeError("local revocation while waiting for new image")

    def guard():
        if widget.verifications:
            raise failure

    gateway._check_proxy = guard
    with pytest.raises(RuntimeError) as caught:
        run(module, gateway, vision, lambda: None)
    assert caught.value is failure and len(vision.images) == widget.verifications == 1


@pytest.mark.parametrize("host,method,path,status,code", [
    (ROOT, "POST", "/amcs/verify", 400, None),
    (CDN, "POST", "/amcs/verify", 400, "captcha_browser_failed"),
    (IMAGE_HOST, "GET", "/amcs/verify", 400, "captcha_browser_failed"),
    (ROOT, "GET", "/amcs/verify", 400, "captcha_browser_failed"),
    (ROOT, "POST", "/amcs/verify?extra=1", 400, "captcha_browser_failed"),
    (ROOT, "POST", "/amcs/verify/", 400, "captcha_browser_failed"),
    (ROOT, "POST", "/amcs/image", 400, "captcha_browser_failed"),
    (ROOT, "POST", "/challenge", 400, "captcha_browser_failed"),
    (ROOT, "POST", "/submit", 400, "captcha_browser_failed"),
    (ROOT, "POST", "/amcs/verify", 401, "captcha_browser_failed"),
    (ROOT, "POST", "/amcs/verify", 403, "captcha_browser_failed"),
    (ROOT, "POST", "/amcs/verify", 429, "captcha_browser_failed"),
    (ROOT, "POST", "/amcs/verify", 500, "captcha_browser_failed"),
    (ROOT, "POST", "/amcs/verify", 302, "captcha_unsafe_destination"),
])
def test_only_exact_ams_guess_rejection_is_forwarded_to_sdk(monkeypatch, host, method, path, status, code):
    module, original_client = browser_module(), httpx.AsyncClient
    requests = []
    body = b'{"invalidGuess":true}'

    async def respond(request):
        requests.append(request)
        return httpx.Response(status, content=body, headers={"content-type": "application/json"})

    def client(*args, **kwargs):
        assert kwargs.pop("proxy") == PROXY
        assert kwargs["follow_redirects"] is False and kwargs["max_redirects"] == 0
        return original_client(*args, **kwargs, transport=httpx.MockTransport(respond))

    monkeypatch.setattr(module.httpx, "AsyncClient", client)

    async def check():
        async with module._ProxyHTTP(Gateway(), {ROOT, CDN}, time.monotonic() + 2,
                                     image_host=IMAGE_HOST, api_host=ROOT) as transport:
            return await transport.fetch(method, f"https://{host}{path}", {},
                                         None if method == "GET" else b"{}",
                                         "image" if host == IMAGE_HOST else "fetch")

    if code:
        with pytest.raises(module.BrowserChallengeError, match=f"^{code}$"):
            asyncio.run(check())
    else:
        returned_status, headers, returned_body = asyncio.run(check())
        assert returned_status == 400 and returned_body == body
        assert headers["content-type"] == "application/json"
    assert len(requests) == 1


def test_disappearing_image_and_success_text_are_not_completion(browser_fixture):
    module = browser_module()
    install, _, _ = browser_fixture
    install("disappeared")
    with pytest.raises(module.BrowserChallengeError, match="^captcha_timeout$"):
        run(module, Gateway(), Vision(), lambda: None, seconds=1.8)


def test_invalid_official_callback_is_rejected(browser_fixture):
    module = browser_module()
    install, _, _ = browser_fixture
    install("invalid_callback")
    with pytest.raises(module.BrowserChallengeError, match="^captcha_invalid_response$"):
        run(module, Gateway(), Vision(), lambda: None)


def test_total_deadline_cancels_slow_ocr_and_closes_browser(browser_fixture):
    module = browser_module()
    install, _, _ = browser_fixture
    install()
    cancelled = []

    class SlowVision(Vision):
        async def arecognize(self, *args, **kwargs):
            try:
                await asyncio.sleep(10)
            finally:
                cancelled.append(True)

    started = time.monotonic()
    with pytest.raises(module.BrowserChallengeError, match="^captcha_timeout$"):
        run(module, Gateway(), SlowVision(), lambda: None, seconds=1.8)
    assert cancelled == [True] and time.monotonic() - started < 3.5


def test_revocation_while_widget_idle_propagates_unchanged(browser_fixture):
    module = browser_module()
    install, _, _ = browser_fixture
    install("idle")
    gateway = Gateway()
    failure = RuntimeError("local revocation sentinel")
    started = time.monotonic()

    def guard():
        if time.monotonic() - started > 0.8:
            raise failure

    gateway._check_proxy = guard
    with pytest.raises(RuntimeError) as caught:
        run(module, gateway, Vision(), lambda: None)
    assert caught.value is failure and time.monotonic() - started < 2


def test_ocr_hook_failure_is_not_retried_or_replaced(browser_fixture):
    module = browser_module()
    install, _, _ = browser_fixture
    install()
    failure, vision = RuntimeError("local attempt limit"), Vision()

    def before():
        raise failure

    with pytest.raises(RuntimeError) as caught:
        run(module, Gateway(), vision, before)
    assert caught.value is failure and vision.images == []


def test_revoked_proxy_after_ocr_stops_verify_wire(browser_fixture):
    module = browser_module()
    install, _, _ = browser_fixture
    widget, gateway = install(), Gateway()
    failure = RuntimeError("local revocation sentinel")

    class RevokingVision(Vision):
        async def arecognize(self, *args, **kwargs):
            gateway.error = failure
            return await super().arecognize(*args, **kwargs)

    with pytest.raises(RuntimeError) as caught:
        run(module, gateway, RevokingVision(), lambda: None)
    assert caught.value is failure
    assert not any(request.url.path == "/verify" for request in widget.requests)


@pytest.mark.parametrize("change", [
    {"script_url": "https://evil.invalid/sdk.js"}, {"region": "evil.invalid"},
    {"kind": "image"}, {"expires_at": 1}, {"stage": "test"},
    {"callback": "notAMS"}, {"container_id": "other"}, {"locale": "fr-FR"},
    {"show_challenge_on_load": True}, {"expires_at": float("nan")},
])
def test_invalid_metadata_is_rejected_before_browser_or_ocr(change):
    module, vision = browser_module(), Vision()
    with pytest.raises(module.BrowserChallengeError, match="^captcha_unsupported_challenge$"):
        run(module, Gateway(), vision, lambda: pytest.fail("OCR must not begin"), value=challenge(**change))
    assert vision.images == []


def test_proxy_cannot_be_missing_or_fall_back_to_direct():
    module, gateway = browser_module(), Gateway()
    gateway.proxy = None
    with pytest.raises(module.BrowserChallengeError, match="^captcha_unsafe_destination$"):
        run(module, gateway, Vision(), lambda: None)


def test_unmanaged_external_ams_uses_public_pinned_direct_https(browser_fixture):
    from app.external_enterprise import ExternalGateway
    from test_external_auth_batches import TEXT
    from app.external_export_input import parse_accounts
    module = browser_module()
    install, _, launches = browser_fixture
    widget = install(expected_proxy=None)
    account = parse_accounts(TEXT)[0]
    gateway = ExternalGateway(SimpleNamespace(id='external', portal_url=account.portal_url, region=account.region),
                              account.public(), lambda: None)
    vision, attempts = Vision(), []
    assert run(module, gateway, vision, lambda: attempts.append(1)) == 'official-fixture-access-code'
    assert len(vision.images) == len(attempts) == len(launches) == 1
    assert widget.requests and all(request.url.host in {ROOT, CDN, IMAGE_HOST} for request in widget.requests)


@pytest.mark.parametrize("untrusted", ["secret-url-and-body", None, {}, []])
def test_browser_errors_only_expose_static_codes(untrusted):
    module = browser_module()
    error = module.BrowserChallengeError(untrusted)
    assert str(error) == error.code == "captcha_browser_failed"


@pytest.mark.parametrize("url", [
    "http://" + ROOT + "/", "https://" + ROOT + ".evil.invalid/",
    "https://user:password@" + ROOT + "/", "https://" + ROOT + ":444/",
    "https://127.0.0.1/", "file:///tmp/private", "https://" + ROOT + "/#fragment",
    "https://" + ROOT + "\\@evil.invalid/", "https://" + ROOT + "/\nprivate",
])
def test_exact_https_allowlist_rejects_ambiguous_targets(url):
    module = browser_module()
    with pytest.raises(module.BrowserChallengeError, match="^captcha_unsafe_destination$"):
        module._allowed(url, {ROOT, CDN})


def test_otp_appearing_during_ocr_prevents_filling_or_submission(browser_fixture):
    module = browser_module()
    install, contexts, _ = browser_fixture
    widget = install()

    class ChangingVision(Vision):
        async def arecognize(self, *args, **kwargs):
            await contexts[0][1].pages[0].evaluate("""document.querySelector('#captcha')
                .insertAdjacentHTML('beforeend','<input name="otp" autocomplete="one-time-code">')""")
            return await super().arecognize(*args, **kwargs)

    with pytest.raises(module.BrowserChallengeError, match="^captcha_unsupported_challenge$"):
        run(module, Gateway(), ChangingVision(), lambda: None)
    assert not any(request.method == "POST" for request in widget.requests)


def test_replaced_image_during_ocr_never_receives_stale_answer(browser_fixture):
    module = browser_module()
    install, contexts, _ = browser_fixture
    widget = install()

    class ChangingVision(Vision):
        async def arecognize(self, *args, **kwargs):
            await contexts[0][1].pages[0].evaluate("""const form=document.querySelector('form');
                form.querySelector('img').outerHTML = form.querySelector('img').outerHTML;""")
            return await super().arecognize(*args, **kwargs)

    with pytest.raises(module.BrowserChallengeError, match="^captcha_unsupported_challenge$"):
        run(module, Gateway(), ChangingVision(), lambda: None)
    assert not any(request.method == "POST" for request in widget.requests)


def test_slow_browser_cleanup_is_bounded_and_preserves_revocation(browser_fixture, monkeypatch):
    module = browser_module()
    from playwright.async_api import BrowserContext

    install, _, _ = browser_fixture
    install("idle")
    original = BrowserContext.close

    async def slow_close(context, *args, **kwargs):
        await original(context, *args, **kwargs)
        await asyncio.sleep(10)

    monkeypatch.setattr(BrowserContext, "close", slow_close)
    gateway, failure = Gateway(), RuntimeError("local revocation sentinel")
    started = time.monotonic()

    def guard():
        if time.monotonic() - started > 0.8:
            raise failure

    gateway._check_proxy = guard
    with pytest.raises(RuntimeError) as caught:
        run(module, gateway, Vision(), lambda: None, seconds=1.8)
    assert caught.value is failure and time.monotonic() - started < 1.8


def test_stalled_route_abort_cannot_hold_browser_or_hide_revocation(browser_fixture, monkeypatch):
    module = browser_module()
    from playwright.async_api import Route

    install, _, _ = browser_fixture
    install()
    events, gateway = [], Gateway()
    failure = RuntimeError("local revocation during SDK request")

    async def stalled_fetch(*args):
        events.append("wire_started")
        await asyncio.sleep(10)

    async def stalled_abort(route, *args, **kwargs):
        events.append("abort_started")
        await asyncio.sleep(2)

    def guard():
        if "wire_started" in events:
            raise failure

    monkeypatch.setattr(module._ProxyHTTP, "fetch", stalled_fetch)
    monkeypatch.setattr(Route, "abort", stalled_abort)
    gateway._check_proxy = guard
    started = time.monotonic()
    with pytest.raises(RuntimeError) as caught:
        run(module, gateway, Vision(), lambda: None, seconds=1.8)
    assert caught.value is failure and "abort_started" in events
    assert time.monotonic() - started < 1.8
    # browser_fixture also requires Chromium disconnection and empty context.pages.


@pytest.mark.parametrize("stage", ["task", "asyncgen"])
def test_sync_wrapper_does_not_wait_past_deadline_for_finalizers(monkeypatch, stage):
    module = browser_module()
    loop = asyncio.new_event_loop()
    original_close = loop.close
    closed, retained = [], []
    failure = RuntimeError("local finalization sentinel")

    async def pending_task():
        try:
            await asyncio.sleep(10)
        finally:
            await asyncio.sleep(0.6)

    async def pending_generator():
        try:
            yield True
        finally:
            await asyncio.sleep(0.6)

    async def substitute(*args):
        if stage == "task":
            retained.append(asyncio.create_task(pending_task()))
            await asyncio.sleep(0)
        else:
            generator = pending_generator()
            retained.append(generator)
            await anext(generator)
        raise failure

    monkeypatch.setattr(module, "_solve", substitute)
    monkeypatch.setattr(module.asyncio, "new_event_loop", lambda: loop)
    # Keep this test's loop available to dispose deliberately stalled fixtures.
    monkeypatch.setattr(loop, "close", lambda: closed.append(True))
    started = time.monotonic()
    try:
        with pytest.raises(RuntimeError) as caught:
            run(module, Gateway(), Vision(), lambda: None, seconds=0.12)
        assert caught.value is failure and closed == [True]
        assert time.monotonic() - started < 0.3
    finally:
        pending = asyncio.all_tasks(loop)
        for task in pending:
            task.cancel()
        if pending:
            loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
        original_close()


def test_stalled_playwright_manager_shutdown_terminates_only_owned_driver(browser_fixture, monkeypatch):
    module = browser_module()
    from playwright.async_api._context_manager import PlaywrightContextManager

    install, _, _ = browser_fixture
    install()
    drivers, shutdown_started = [], []
    original_enter = PlaywrightContextManager.__aenter__

    async def cold_start(manager):
        # Cold driver startup is independent of the shutdown behavior under test.
        await asyncio.sleep(0.6)
        return await original_enter(manager)

    async def stalled_exit(manager, *args):
        drivers.append(manager._connection._transport._proc)
        shutdown_started.append(time.monotonic())
        await asyncio.sleep(10)

    monkeypatch.setattr(PlaywrightContextManager, "__aenter__", cold_start)
    monkeypatch.setattr(PlaywrightContextManager, "__aexit__", stalled_exit)
    started = time.monotonic()
    try:
        assert run(module, Gateway(), Vision(), lambda: None) == "official-fixture-access-code"
        finished = time.monotonic()
        assert finished - started < 8
        assert len(shutdown_started) == 1 and finished - shutdown_started[0] < 0.5
        assert len(drivers) == 1 and drivers[0].returncode is not None
    finally:
        for driver in drivers:
            if driver.returncode is None:
                driver.kill()


def test_already_expired_cleanup_budget_does_not_wait_for_cancellation():
    module = browser_module()
    events = []

    async def resistant():
        try:
            await asyncio.sleep(10)
        finally:
            events.append("finalizer_started")
            await asyncio.sleep(0.6)

    async def scenario():
        task = asyncio.create_task(resistant())
        await asyncio.sleep(0)
        started = time.monotonic()
        try:
            pending = await module._settle({task}, started - 1, cancel=True)
            assert time.monotonic() - started < 0.05
            assert pending == {task} and events == ["finalizer_started"]
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    asyncio.run(scenario())


def test_stalled_cdp_startup_detach_obeys_total_deadline(browser_fixture, monkeypatch):
    module = browser_module()
    from playwright.async_api import Browser, BrowserType

    install, _, _ = browser_fixture
    install()
    events, browsers = [], []
    original_launch = BrowserType.launch

    async def launch(kind, *args, **kwargs):
        browser = await original_launch(kind, *args, **kwargs)
        browsers.append(browser)
        return browser

    async def session(browser):
        async def send(*args):
            events.append("send_started")
            await asyncio.sleep(10)

        async def detach():
            events.append("detach_started")
            await asyncio.sleep(2)

        return SimpleNamespace(send=send, detach=detach)

    monkeypatch.setattr(BrowserType, "launch", launch)
    monkeypatch.setattr(Browser, "new_browser_cdp_session", session)
    started = time.monotonic()
    with pytest.raises(module.BrowserChallengeError, match="^captcha_timeout$"):
        run(module, Gateway(), Vision(), lambda: None, seconds=1.2)
    assert events == ["send_started", "detach_started"]
    assert time.monotonic() - started < 1.3
    assert browsers and not browsers[0].is_connected()


@pytest.mark.skipif(os.name != "posix", reason="Production browser process groups require POSIX")
def test_wedged_driver_channel_terminates_its_owned_chromium(chromium, monkeypatch):
    module = browser_module()
    from playwright.async_api import BrowserType

    if chromium:
        monkeypatch.setenv("CAPTCHA_CHROMIUM_EXECUTABLE", chromium)
    widget, owned, signals = Widget(), {}, []
    original_client, original_launch = httpx.AsyncClient, BrowserType.launch
    original_group, original_killpg = module._browser_process_group, os.killpg

    def client(*args, **kwargs):
        assert kwargs.pop("proxy") == PROXY
        return original_client(*args, **kwargs, transport=httpx.MockTransport(widget.response))

    async def launch(kind, *args, **kwargs):
        browser = await original_launch(kind, *args, **kwargs)
        owned["driver"] = browser._impl_obj._connection._transport._proc
        return browser

    async def group(browser, deadline):
        owned["group"] = await original_group(browser, deadline)
        return owned["group"]

    def killpg(pid, sig):
        signals.append((pid, sig))
        assert pid == owned["group"] and pid != os.getpgrp()
        original_killpg(pid, sig)

    class FreezeDriver(Vision):
        async def arecognize(self, *args, **kwargs):
            assert owned["group"] is not None
            os.kill(owned["driver"].pid, signal.SIGSTOP)
            return await super().arecognize(*args, **kwargs)

    monkeypatch.setattr(module.httpx, "AsyncClient", client)
    monkeypatch.setattr(BrowserType, "launch", launch)
    monkeypatch.setattr(module, "_browser_process_group", group)
    monkeypatch.setattr(module.os, "killpg", killpg)
    started = time.monotonic()
    try:
        with pytest.raises(module.BrowserChallengeError, match="^captcha_timeout$"):
            run(module, Gateway(), FreezeDriver(), lambda: None, seconds=2)
        assert time.monotonic() - started < 2.1
        assert owned["driver"].returncode is not None
        assert signals == [(owned["group"], signal.SIGKILL)]
        # A driver stuck before browser.close cannot acknowledge API closure;
        # verify the captured browser process itself has actually terminated.
        for _ in range(100):
            try:
                os.kill(owned["group"], 0)
            except ProcessLookupError:
                break
            time.sleep(0.01)
        else:
            pytest.fail("Owned Chromium survived driver termination")
    finally:
        if owned.get("group"):
            try:
                original_killpg(owned["group"], signal.SIGKILL)
            except ProcessLookupError:
                pass
        if owned.get("driver") and owned["driver"].returncode is None:
            owned["driver"].kill()


def test_private_widget_requests_are_not_logged(browser_fixture, caplog):
    module = browser_module()
    install, _, _ = browser_fixture
    install()
    caplog.set_level(logging.DEBUG, logger="httpx")
    caplog.set_level(logging.DEBUG, logger="httpcore")
    run(module, Gateway(), Vision(), lambda: None)
    assert ROOT not in caplog.text and "fixture-password" not in caplog.text


def test_bootstrap_is_local_but_sdk_posts_from_aws_signin_origin(browser_fixture):
    module = browser_module()
    install, _, _ = browser_fixture
    widget = install()
    run(module, Gateway(), Vision(), lambda: None)
    submissions = [request for request in widget.requests if request.method == "POST"]
    assert submissions[0].headers["origin"] == "https://us-east-1.signin.aws"
    assert {request.url.host for request in widget.requests} == {ROOT, CDN}


@pytest.mark.parametrize("framing", [None, "headers", "chunk"])
def test_real_authenticated_socks_dns_tls_and_total_wire_deadline(socks_server, tmp_path, monkeypatch, framing):
    module = browser_module()
    original_client = httpx.AsyncClient
    verification = ssl.create_default_context(cafile=str(tmp_path / "ca.pem"))

    def client(*args, **kwargs):
        assert kwargs["verify"] is True and kwargs["trust_env"] is False
        kwargs["verify"] = verification
        return original_client(*args, **kwargs)

    monkeypatch.setattr(module.httpx, "AsyncClient", client)
    closed = threading.Event()
    if framing:
        def respond(secure):
            try:
                prefix = (b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nX-Slow: " if framing == "headers"
                          else b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;")
                secure.sendall(prefix)
                for _ in range(30):
                    if select.select([secure], [], [], 0.03)[0]:
                        if secure.recv(1) == b"":
                            closed.set()
                            return
                    secure.sendall(b"a")
            except OSError:
                closed.set()

        socks_server.respond = respond
    gateway = Gateway()
    gateway.proxy.url = socks_server.proxy_url

    async def scenario():
        deadline = time.monotonic() + (0.3 if framing else 3)
        async with module._ProxyHTTP(gateway, {"ams.proxy.invalid"}, deadline) as transport:
            return await transport.fetch("GET", "https://ams.proxy.invalid/challenge", {}, None)

    started = time.monotonic()
    if framing:
        with pytest.raises(module.BrowserChallengeError, match="^captcha_timeout$"):
            asyncio.run(scenario())
        assert time.monotonic() - started < 1.2
        assert closed.wait(1)
    else:
        status, _, content = asyncio.run(scenario())
        assert status == 200 and json.loads(content)["Password"] == "test-one-time"
    assert socks_server.connections == [("ams.proxy.invalid", 443, 3)]
    assert gateway.checks >= 1


@pytest.mark.parametrize("revoke", [None, "during_stream", "last_chunk"])
def test_sdk_stream_checks_revocation_without_a_database_scan_per_chunk(monkeypatch, revoke):
    module, gateway = browser_module(), Gateway()
    clock = [time.monotonic()]
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: clock[0]))
    failure = RuntimeError("local stream revocation")
    chunks = []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for index in range(128):
                chunks.append(index)
                if revoke == "during_stream":
                    clock[0] += 0.03
                    if index == 2:
                        gateway.error = failure
                elif revoke == "last_chunk" and index == 127:
                    gateway.error = failure
                yield b"a" * 16384

    async def scenario():
        transport = module._ProxyHTTP(gateway, {CDN}, clock[0] + 10)
        async with httpx.AsyncClient(transport=httpx.MockTransport(
                lambda request: httpx.Response(200, stream=Stream()))) as client:
            transport.client = client
            return await transport.fetch("GET", f"https://{CDN}/sdk.js", {}, None)

    if revoke:
        with pytest.raises(RuntimeError) as caught:
            asyncio.run(scenario())
        assert caught.value is failure
        if revoke == "during_stream":
            assert len(chunks) <= 7
    else:
        status, _, body = asyncio.run(scenario())
        assert status == 200 and len(body) == 2 * 1024 * 1024
        assert gateway.checks == 2
