"""An ephemeral, credential-free browser for the validated official AMS widget.

Chromium has a dead proxy. Every HTTP request is explicitly fulfilled through
the account's authenticated SOCKS5h transport, or public pinned HTTPS for an
unmanaged external login; no browser route is continued.
Only a character image crop reaches OCR, and only the SDK callback can succeed.
"""

import asyncio
import hashlib
import json
import logging
import math
import os
import re
import signal
import time
from contextlib import suppress
from contextvars import ContextVar
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from .auth_widget import public_challenge
from .config import settings
from .identity_login import AuthError
from .vision_captcha import VisionError
from .captcha_errors import ActionRequired, safe_captcha_code
from .vision_transport import PublicEndpointTransport, UnsafeEndpointError


MAX_RESPONSE = 8 * 1024 * 1024
MAX_TRANSFER = 24 * 1024 * 1024
MAX_REQUEST = 256 * 1024
MAX_REQUESTS = 80
MAX_IMAGE = 2_000_000
GUARD_INTERVAL = 0.5
# A full safety scan requires several browser protocol round trips. Four scans
# per second avoid saturating the driver with unchanged waiting pages, while
# every network request, OCR submission and accepted callback still rechecks.
DOM_POLL_SECONDS = 0.25
SAFE_CODES = {
    "captcha_browser_unavailable", "captcha_browser_failed", "captcha_timeout",
    "captcha_attempt_limit", "captcha_unsupported_challenge",
    "captcha_unsafe_destination", "captcha_invalid_response",
}
_private_wire = ContextVar("captcha_private_wire", default=False)


class _PrivateWireLogFilter(logging.Filter):
    def filter(self, record):
        return not _private_wire.get()


# Third-party debug logs can contain query tokens and Set-Cookie headers. The
# context-local filter suppresses only this adapter's wire operations, without
# changing log levels or silencing unrelated HTTP clients in other worker tasks.
for _name in ("httpx", "httpcore.connection", "httpcore.proxy", "httpcore.socks",
              "httpcore.http11", "httpcore.http2"):
    logging.getLogger(_name).addFilter(_PrivateWireLogFilter())


class BrowserChallengeError(Exception):
    def __init__(self, code, *, last_failure_code=None):
        self.code = code if isinstance(code, str) and code in SAFE_CODES else "captcha_browser_failed"
        self.last_failure_code = safe_captcha_code(last_failure_code) if last_failure_code else None
        super().__init__(self.code)


def _challenge(value):
    try:
        checked = public_challenge(value)
        if (
            checked["kind"] != "ams" or checked["stage"] != "prod"
            or checked["callback"] != "initAMS" or checked["container_id"] != "captcha"
            or checked["locale"] != "en-US" or checked["show_challenge_on_load"] is not False
            or isinstance(checked["expires_at"], bool)
            or not isinstance(checked["expires_at"], (int, float))
            or not math.isfinite(checked["expires_at"])
            or not time.time() < checked["expires_at"] <= time.time() + 900
            or not isinstance(checked["redemption_token"], str)
            or not 0 < len(checked["redemption_token"]) <= 20000
        ):
            raise ValueError()
        return checked
    except (AuthError, AttributeError, KeyError, TypeError, ValueError, UnicodeError):
        raise BrowserChallengeError("captcha_unsupported_challenge") from None


def _allowed(url, hosts):
    try:
        if not isinstance(url, str) or len(url) > 65536 or "\\" in url or any(ord(c) <= 32 for c in url):
            raise ValueError()
        target = urlsplit(url)
        if (target.scheme != "https" or target.hostname not in hosts
                or target.port not in (None, 443) or target.username is not None
                or target.password is not None or target.fragment):
            raise ValueError()
    except (TypeError, ValueError):
        raise BrowserChallengeError("captcha_unsafe_destination") from None


def _remaining(deadline):
    value = deadline - time.monotonic()
    if value <= 0:
        raise BrowserChallengeError("captcha_timeout")
    return value


def _observe_task(task):
    if task.done() and not task.cancelled():
        task.exception()


async def _settle(tasks, deadline, *, cancel=False, maximum=0.05):
    """Never wait for cancellation acknowledgement beyond the caller's budget."""
    tasks = set(tasks)
    if cancel:
        for task in tasks:
            task.cancel()
    if not tasks:
        return set()
    # wait_for(gather(...)) waits for cancellation-resistant finalizers. wait()
    # instead returns at the deadline, allowing browser/driver teardown to proceed.
    done, pending = await asyncio.wait(tasks, timeout=max(0, min(maximum, deadline - time.monotonic())))
    for task in done:
        _observe_task(task)
    for task in pending:
        task.cancel()
        task.add_done_callback(_observe_task)
    return pending


async def _cleanup_call(operation, deadline, *, maximum=0.08):
    task = asyncio.create_task(operation())
    pending = await _settle({task}, deadline, maximum=maximum)
    return not pending and not task.cancelled() and task.exception() is None


async def _browser_process_group(browser, deadline):
    """Capture ownership from this launched browser, never enumerate processes."""
    if os.name != "posix":
        return None
    session = await browser.new_browser_cdp_session()
    try:
        processes = await session.send("SystemInfo.getProcessInfo")
    finally:
        await _cleanup_call(session.detach, deadline, maximum=0.02)
    for process in processes.get("processInfo", []):
        pid = process.get("id")
        if process.get("type") == "browser" and isinstance(pid, int) and pid > 1:
            with suppress(ProcessLookupError):
                # Playwright launches Chromium as a separate POSIX process group.
                if os.getpgid(pid) == pid and pid != os.getpgrp():
                    return pid
    return None


async def _stop_owned_driver(manager, browser, browser_group, deadline):
    # Playwright 1.63 exposes no public driver process handle. This is the exact
    # subprocess created by this manager, and is used only after bounded closure.
    connection = getattr(manager, "_connection", None)
    transport = getattr(connection, "_transport", None)
    process = getattr(transport, "_proc", None)
    if browser_group and browser and browser.is_connected():
        with suppress(ProcessLookupError):
            if os.getpgid(browser_group) == browser_group and browser_group != os.getpgrp():
                os.killpg(browser_group, signal.SIGKILL)
    if process is None or process.returncode is not None:
        return
    with suppress(Exception):
        transport.request_stop()
    with suppress(ProcessLookupError):
        process.kill()
    await _cleanup_call(process.wait, deadline, maximum=0.05)
    with suppress(Exception):
        connection.cleanup()


class _ProxyHTTP:
    """Async streaming is cancellable even during slow-drip response headers."""

    def __init__(self, gateway, hosts, deadline, *, image_host=None, api_host=None):
        self.gateway, self.deadline = gateway, deadline
        self.image_host, self.api_host = image_host, api_host
        self.hosts = set(hosts) | ({image_host} if image_host else set())
        self.requests, self.transferred, self.pending, self.completed = 0, 0, 0, 0
        self.image_digests = {}
        self.last_failure_code = None
        proxy = getattr(gateway, "proxy", None)
        self.proxy_url = getattr(proxy, "url", None)
        self.direct = self.proxy_url is None and getattr(gateway, "captcha_direct_allowed", False) is True
        try:
            if self.direct:
                region = re.fullmatch(r'([a-z]{2}(?:-[a-z]+)+-\d)\.threat-mitigation\.aws\.amazon\.com', api_host or '')
                expected_image = ('amcs-captcha-prod-' + region[1] + '.s3.dualstack.' + region[1] + '.amazonaws.com') if region else None
                if not region or image_host != expected_image or self.hosts != {api_host, 'cdn.' + api_host, expected_image}:
                    raise ValueError()
            else:
                target = urlsplit(self.proxy_url or "")
                if target.scheme != "socks5h" or not target.hostname or not target.port:
                    raise ValueError()
        except ValueError:
            raise BrowserChallengeError("captcha_unsafe_destination") from None
        self.client = None

    async def __aenter__(self):
        async def image_credentials(request):
            if self.image_host and request.url.host == self.image_host:
                # Run after HTTPX merges its cookie jar into the request. The
                # official signed image URL needs no browser/session credentials.
                for name in ("cookie", "authorization", "referer"):
                    request.headers.pop(name, None)

        transport = {"transport": PublicEndpointTransport()} if self.direct else {}
        self.client = httpx.AsyncClient(
            proxy=self.proxy_url, verify=True, trust_env=False,
            follow_redirects=False, max_redirects=0,
            timeout=httpx.Timeout(min(10, _remaining(self.deadline))),
            limits=httpx.Limits(max_connections=6, max_keepalive_connections=3),
            event_hooks={"request": [image_credentials]},
            **transport,
        )
        await self.client.__aenter__()
        return self

    async def __aexit__(self, *args):
        await self.client.__aexit__(*args)

    async def fetch(self, method, url, headers, body, resource_type=None):
        _allowed(url, self.hosts)
        target = urlsplit(url)
        is_image = self.image_host is not None and target.hostname == self.image_host
        if is_image and (method not in {"GET", "HEAD"} or resource_type != "image" or body):
            raise BrowserChallengeError("captcha_unsafe_destination")
        if method not in {"GET", "HEAD", "POST", "OPTIONS"}:
            raise BrowserChallengeError("captcha_unsafe_destination")
        if (len(body or b"") > MAX_REQUEST or len(headers) > 100
                or sum(len(k) + len(v) for k, v in headers.items()) > 65536):
            raise BrowserChallengeError("captcha_invalid_response")
        self.requests += 1
        if self.requests > MAX_REQUESTS:
            raise BrowserChallengeError("captcha_invalid_response")
        omitted = {"host", "connection", "proxy-authorization", "proxy-connection",
                   "content-length", "transfer-encoding", "accept-encoding"}
        headers = {k: v for k, v in headers.items() if k.lower() not in omitted}
        headers["accept-encoding"] = "identity"
        token = _private_wire.set(True)
        self.pending += 1
        try:
            async with asyncio.timeout(_remaining(self.deadline)):
                # Account binding and cancellation guards execute immediately
                # before each wire request, including images and preflights.
                self.gateway._check_proxy()
                async with self.client.stream(method, url, headers=headers, content=body) as response:
                    # Never forward redirects to Chromium: browser routing may
                    # skip subsequent redirect hops. There are no implicit retries.
                    if 300 <= response.status_code < 400:
                        raise BrowserChallengeError("captcha_unsafe_destination")
                    # AMCS returns 400 for an incorrect guess. Preserve that
                    # response for the official SDK's error/refresh handling;
                    # it is never itself evidence of challenge completion.
                    guess_rejection = (response.status_code == 400 and method == "POST"
                        and self.api_host is not None and target.hostname == self.api_host
                        and target.path == "/amcs/verify" and not target.query)
                    if not 200 <= response.status_code < 300 and not guess_rejection:
                        raise BrowserChallengeError("captcha_browser_failed")
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise BrowserChallengeError("captcha_invalid_response")
                    if is_image and response.headers.get("content-type", "").split(";", 1)[0].strip().lower() not in {
                        "image/png", "image/jpeg", "image/gif", "image/webp",
                    }:
                        raise BrowserChallengeError("captcha_invalid_response")
                    response_limit = MAX_IMAGE if is_image else MAX_RESPONSE
                    size = response.headers.get("content-length")
                    if size is not None:
                        try:
                            if not 0 <= int(size) <= response_limit:
                                raise ValueError()
                        except ValueError:
                            raise BrowserChallengeError("captcha_invalid_response") from None
                    content = bytearray()
                    next_guard = time.monotonic() + GUARD_INTERVAL
                    async for chunk in response.aiter_bytes(chunk_size=16384):
                        # Rechecking the full durable account/group scope for
                        # every 16 KiB turns one SDK download into hundreds of
                        # database reads. Keep the same bounded cancellation
                        # interval as the monitor, plus unconditional checks
                        # before the request and before returning its body.
                        if time.monotonic() >= next_guard:
                            self.gateway._check_proxy()
                            next_guard = time.monotonic() + GUARD_INTERVAL
                        _remaining(self.deadline)
                        self.transferred += len(chunk)
                        if len(content) + len(chunk) > response_limit or self.transferred > MAX_TRANSFER:
                            raise BrowserChallengeError("captcha_invalid_response")
                        content.extend(chunk)
                    self.gateway._check_proxy()
                    result_headers = {
                        name: value for name, value in response.headers.items()
                        if name.lower() not in {"content-length", "content-encoding", "transfer-encoding", "connection", "set-cookie"}
                    }
                    # Playwright accepts separate cookie headers joined by newline.
                    if not is_image and response.headers.get_list("set-cookie"):
                        result_headers["set-cookie"] = "\n".join(response.headers.get_list("set-cookie"))
                    content = bytes(content)
                    if method == "GET" and resource_type == "image":
                        # Only the bounded original image body identifies content;
                        # a crop can change when error text moves the same image.
                        self.image_digests[url] = hashlib.sha256(content).digest()
                    self.completed += 1
                    return response.status_code, result_headers, content
        except (TimeoutError, httpx.TimeoutException):
            raise BrowserChallengeError("captcha_timeout") from None
        except UnsafeEndpointError:
            raise BrowserChallengeError("captcha_unsafe_destination") from None
        except httpx.HTTPError:
            raise BrowserChallengeError("captcha_browser_failed") from None
        finally:
            self.pending -= 1
            _private_wire.reset(token)


def _html(challenge):
    config = json.dumps(challenge, separators=(",", ":")).replace("<", "\\u003c")
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
    <title>Verification</title></head><body><div id="captcha" data-callback="initAMS"></div>
    <script>'use strict';
    const config = __CONFIG__;
    window.__kiroAMS = {accessCode:null,error:null};
    addEventListener('securitypolicyviolation', () => {
      window.__kiroAMS.error='captcha_unsafe_destination';
    });
    window.initAMS = sdk => {
      if (!sdk || typeof sdk.init !== 'function') {window.__kiroAMS.error='captcha_browser_failed'; return;}
      sdk.init({redemptionToken:config.redemption_token,locale:'en-US',showChallengeOnLoad:false,
        onChallengeComplete: answer => {
          if (Date.now()/1000 >= config.expires_at) {window.__kiroAMS.error='captcha_timeout'; return;}
          const code = answer && answer.accessCode;
          if (typeof code !== 'string' || !code.length || code.length > 8192 || /[\\x00-\\x1f\\x7f]/.test(code)) {
            window.__kiroAMS.error='captcha_invalid_response'; return;
          }
          window.__kiroAMS.accessCode=code;
        },onError:()=>{window.__kiroAMS.error='captcha_browser_failed';}});
    };
    const script=document.createElement('script'); script.src=config.script_url;
    script.onerror=()=>{window.__kiroAMS.error='captcha_browser_failed';};
    document.head.appendChild(script);
    </script></body></html>""".replace("__CONFIG__", config)


@dataclass
class _Characters:
    image: object
    field: object
    button: object
    scope: object
    frame: object


class _WidgetFrameDetached(Exception):
    """Restart inspection after an operation's own iframe was removed."""


@dataclass
class _Opener:
    button: object
    frame: object


async def _in_frame(frame, operation):
    from playwright.async_api import Error as PlaywrightError

    try:
        return await operation
    except PlaywrightError:
        if frame.is_detached():
            raise _WidgetFrameDetached() from None
        raise


@dataclass(frozen=True)
class _ImageVersion:
    source: str
    identity: str
    loads: int
    ready: bool
    digest: bytes | None


async def _image_version(image, http):
    state = await image.evaluate("""el => {
        if (!el.__kiroAMSImage) {
            const state = {identity:crypto.randomUUID(),loads:0};
            el.__kiroAMSImage = state;
            el.addEventListener('load', event => {if (event.isTrusted) state.loads++;});
        }
        return {source:el.currentSrc || el.src, ...el.__kiroAMSImage,
            ready:el.isConnected && el.complete && el.naturalWidth > 0 && el.naturalHeight > 0};
    }""")
    return _ImageVersion(**state, digest=http.image_digests.get(state["source"]))


async def _visible(locator, limit=30):
    found = []
    for index in range(min(await locator.count(), limit)):
        value = locator.nth(index)
        if await value.is_visible():
            found.append(value)
    return found


async def _inspect(page):
    from playwright.async_api import Error as PlaywrightError

    matches, openers = [], []
    for frame in page.frames:
        try:
            scope = frame.locator("#captcha" if frame == page.main_frame else "body")
            if not await scope.count():
                continue
            text = (await scope.inner_text())[:12000]
            if (re.search(r"select (?:all|the|each)|drag|slide|rotate|jigsaw|puzzle|"
                          r"one.time (?:code|password)|multi.factor|authenticator|security key|"
                          r"(?:sent|send).{0,60}(?:email|phone|text message)|"
                          r"(?:email|sms).{0,40}(?:verification )?code", text, re.I)
                    or await _visible(scope.locator('canvas, [role="slider"], .g-recaptcha, .h-captcha'))):
                raise BrowserChallengeError("captcha_unsupported_challenge")
            inputs = await _visible(scope.locator("input"))
            fields = []
            for field in inputs:
                metadata = await field.evaluate("""el => [el.type,el.name,el.id,el.autocomplete,
                    el.getAttribute('aria-label'),el.placeholder,...Array.from(el.labels||[], x=>x.innerText)].join(' ')""")
                if re.search(r"password|one-time-code|\botp\b|\bmfa\b|username|\bemail\b|telephone", metadata, re.I):
                    raise BrowserChallengeError("captcha_unsupported_challenge")
                if re.search(r"captcha|characters|letters|security.?code|verification.?code|\bcode\b", metadata, re.I):
                    fields.append(field)
            if len(fields) > 1:
                raise BrowserChallengeError("captcha_unsupported_challenge")
            if fields:
                field = fields[0]
                form = field.locator("xpath=ancestor::form[1]")
                container = form if await form.count() else scope
                images, image_elements = [], container.locator("img")
                for index in range(min(await image_elements.count(), 30)):
                    image = image_elements.nth(index)
                    # Official AMCS puts audio/refresh <img> icons inside buttons.
                    # Exclude them even while only one of those icons has loaded.
                    if await image.evaluate("""el => {
                        if (el.closest('button') || !el.getClientRects().length
                            || ['hidden','collapse'].includes(getComputedStyle(el).visibility)) return false;
                        const bounds = el.getBoundingClientRect();
                        return (bounds.width > 0 && bounds.height > 0)
                            || (el.alt.toLowerCase() === 'captcha' && !!el.src);
                    }"""):
                        # pg has no fixed image dimensions: retain its explicit
                        # 0x0 loading candidate for _drive's bounded readiness wait.
                        images.append(image)
                if len(images) > 1:
                    candidates = []
                    for image in images:
                        metadata = await image.evaluate("el => [el.alt,el.id,el.className,el.src].join(' ')")
                        if re.search(r"captcha|characters|challenge|security.?code|verification.?code", metadata, re.I):
                            candidates.append(image)
                    images = candidates
                if len(images) != 1:
                    raise BrowserChallengeError("captcha_unsupported_challenge")
                image = images[0]
                info = await image.evaluate("el => [el.alt,el.id,el.className,el.src].join(' ')")
                if not re.search(r"captcha|characters|challenge|security.?code|verification.?code", info + " " + text, re.I):
                    raise BrowserChallengeError("captcha_unsupported_challenge")
                buttons = await _visible(container.get_by_role("button", name=re.compile(r"^(?:verify|submit|continue|confirm|check)(?: captcha| answer)?$", re.I)))
                if len(buttons) == 1 and await field.is_enabled() and await buttons[0].is_enabled():
                    matches.append(_Characters(image, field, buttons[0], scope, frame))
            elif inputs:
                raise BrowserChallengeError("captcha_unsupported_challenge")
            else:
                openers.extend(_Opener(button, frame) for button in await _visible(
                    scope.get_by_role("button", name=re.compile(r"^(?:begin|start|verify)(?: verification| challenge)?$", re.I))))
        except PlaywrightError:
            if frame.is_detached():
                raise _WidgetFrameDetached() from None
            raise
    if len(matches) > 1:
        raise BrowserChallengeError("captcha_unsupported_challenge")
    return matches[0] if matches else None, openers[0] if len(openers) == 1 else None


async def _drive(page, http, provider, before_recognition, deadline, failure):
    attempts, opened, submitted, rejected = 0, False, None, None
    # The durable hook may stop sooner after restart; direct calls remain bounded too.
    max_attempts = settings.captcha_max_attempts
    while True:
        _remaining(deadline)
        # The monitor checks cancellation while inspecting local DOM. Fresh
        # guards still precede every wire request and OCR submission below.
        if failure.done():
            raise failure.result()
        state = await page.evaluate("window.__kiroAMS")
        if state and state.get("error"):
            raise BrowserChallengeError(state["error"])
        # Detect OTPs and graphical challenges before accepting any page result.
        try:
            current, opener = await _inspect(page)
        except _WidgetFrameDetached:
            await asyncio.sleep(min(DOM_POLL_SECONDS, _remaining(deadline)))
            continue
        # Only accept a callback observed before this full scan. A callback that
        # arrives during inspection gets another scan for replacement OTP/MFA UI.
        if state and state.get("accessCode"):
            http.gateway._check_proxy()
            _remaining(deadline)
            return state["accessCode"]
        if current:
            try:
                version = await _in_frame(current.frame, _image_version(current.image, http))
                if not version.ready:
                    await asyncio.sleep(min(DOM_POLL_SECONDS, _remaining(deadline)))
                    continue
                if submitted and version.source == submitted.source:
                    # Error text/input resets do not prove a refreshed challenge.
                    # The same URL requires both this element's new load (or a new
                    # element) and changed bytes received by the guarded transport.
                    reloaded = (version.identity, version.loads) != (submitted.identity, submitted.loads)
                    if not reloaded or version.digest is None or version.digest == submitted.digest:
                        await asyncio.sleep(min(DOM_POLL_SECONDS, _remaining(deadline)))
                        continue
                if submitted and rejected is not submitted:
                    http.last_failure_code = "captcha_answer_rejected"
                    rejected = submitted
                bounds = await _in_frame(current.frame, current.image.bounding_box())
                if not bounds or not 4 <= bounds["width"] <= 2000 or not 4 <= bounds["height"] <= 1000:
                    raise BrowserChallengeError("captcha_unsupported_challenge")
                image = await _in_frame(current.frame, current.image.element_handle())
                field = await _in_frame(current.frame, current.field.element_handle())
                button = await _in_frame(current.frame, current.button.element_handle())
                cropped = await _in_frame(current.frame, image.screenshot(
                    type="png", timeout=min(3000, _remaining(deadline) * 1000)))
                if not cropped or len(cropped) > MAX_IMAGE:
                    raise BrowserChallengeError("captcha_invalid_response")
                if await _in_frame(current.frame, _image_version(image, http)) != version:
                    await asyncio.sleep(min(DOM_POLL_SECONDS, _remaining(deadline)))
                    continue
                if attempts >= max_attempts:
                    raise BrowserChallengeError("captcha_attempt_limit",
                        last_failure_code="captcha_answer_rejected" if submitted else None)
                http.gateway._check_proxy()
                _remaining(deadline)
                before_recognition()
                attempts += 1
                try:
                    answer = await provider.arecognize(cropped, mime_type="image/png")
                except VisionError as error:
                    http.last_failure_code = safe_captcha_code(error.code)
                    if error.code not in {"captcha_provider_failed", "captcha_timeout", "captcha_invalid_response"}:
                        raise
                    http.gateway._check_proxy()
                    _remaining(deadline)
                    if attempts >= max_attempts:
                        raise BrowserChallengeError("captcha_attempt_limit", last_failure_code=error.code) from None
                    # Retry within this live AMS session. Reopening the widget would
                    # consume its one-use redemption token again. Rescan before OCR.
                    await asyncio.sleep(min(DOM_POLL_SECONDS, _remaining(deadline)))
                    continue
                http.gateway._check_proxy()
                _remaining(deadline)
                if not isinstance(answer, str) or not re.fullmatch(r"[A-Za-z0-9]{4,10}", answer):
                    raise BrowserChallengeError("captcha_invalid_response")
                # OCR can take seconds; rescan before filling in case OTP/MFA or a
                # different challenge appeared during the provider request.
                fresh, _ = await _inspect(page)
                if (fresh is None or not await _in_frame(current.frame, image.evaluate("el => el.isConnected"))
                        or not await _in_frame(current.frame, field.evaluate("el => el.isConnected"))
                        or not await _in_frame(current.frame, button.evaluate("el => el.isConnected"))
                        or await _in_frame(fresh.frame, _image_version(fresh.image, http)) != version):
                    raise BrowserChallengeError("captcha_unsupported_challenge")
                await _in_frame(current.frame, field.fill(answer))
                submitted = version
                await _in_frame(current.frame, button.click(no_wait_after=True))
            except _WidgetFrameDetached:
                await asyncio.sleep(min(DOM_POLL_SECONDS, _remaining(deadline)))
                continue
        elif opener and not opened and submitted is None:
            opened = True
            try:
                await _in_frame(opener.frame, opener.button.click(no_wait_after=True))
            except _WidgetFrameDetached:
                await asyncio.sleep(min(DOM_POLL_SECONDS, _remaining(deadline)))
                continue
        await asyncio.sleep(min(DOM_POLL_SECONDS, _remaining(deadline)))


async def _launch_browser(deadline):
    from playwright.async_api import async_playwright
    manager = async_playwright()
    browser = group = None
    try:
        playwright = await manager.__aenter__()
        browser = await playwright.chromium.launch(
            headless=True, executable_path=os.getenv("CAPTCHA_CHROMIUM_EXECUTABLE") or None,
            proxy={"server": "http://127.0.0.1:9"},
            args=["--proxy-bypass-list=<-loopback>", "--disable-quic",
                  "--disable-background-networking", "--disable-dev-shm-usage",
                  "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                  "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"],
            timeout=min(15000, _remaining(deadline) * 1000),
        )
        group = await _browser_process_group(browser, deadline)
        return manager, browser, group
    except BaseException:
        await _dispose_browser((manager, browser, group))
        raise


async def _dispose_browser(resources):
    manager, browser, group = resources
    # A shared browser can have just closed twenty renderer processes. Allow
    # its graceful close handshake to finish before falling back to owned-PID
    # cleanup; the caller's deadline still bounds its own wait independently.
    deadline = time.monotonic() + 2
    if browser:
        await _cleanup_call(browser.close, deadline, maximum=1.5)
    await _cleanup_call(lambda: manager.__aexit__(None, None, None), deadline, maximum=0.3)
    await _stop_owned_driver(manager, browser, group, deadline)


async def _solve(challenge, gateway, provider, deadline, before_recognition, runtime=None):
    try:
        from playwright.async_api import Error as PlaywrightError, TimeoutError as PlaywrightTimeout
    except ImportError:
        raise BrowserChallengeError("captcha_browser_unavailable") from None
    hard_deadline = deadline
    # Reserve a small portion of the caller's budget to close the browser after
    # cancelling a stalled provider or network stream.
    deadline -= min(0.5, _remaining(deadline) / 4)
    root = challenge["region"] + ".threat-mitigation.aws.amazon.com"
    hosts = {root, "cdn." + root}
    image_host = "amcs-captcha-prod-" + challenge["region"] + ".s3.dualstack." + challenge["region"] + ".amazonaws.com"
    # This document is fulfilled locally once, without loading a login page or
    # any credential. Preserve the SDK's real embedding origin for AWS CORS.
    bootstrap_url = "https://" + challenge["region"] + ".signin.aws/platform/kiro-captcha"
    context, browser, http, manager, browser_group, tasks = None, None, None, None, None, []
    shared_lease = None
    failure = asyncio.get_running_loop().create_future()
    handlers = set()
    active_timeout = asyncio.timeout(_remaining(deadline))
    try:
        async with active_timeout:
            http = _ProxyHTTP(gateway, hosts, deadline, image_host=image_host, api_host=root)
            await http.__aenter__()
            gateway._check_proxy()
            try:
                if runtime:
                    shared_lease = await runtime.acquire(_launch_browser, _dispose_browser, deadline)
                    browser = shared_lease.resources[1]
                else:
                    manager, browser, browser_group = await _launch_browser(deadline)
            except PlaywrightError:
                raise BrowserChallengeError("captcha_browser_unavailable") from None
            context = await browser.new_context(
                viewport={"width": 960, "height": 720}, locale="en-US",
                service_workers="block", accept_downloads=False,
            )
            context.set_default_timeout(min(3000, _remaining(deadline) * 1000))
            bootstrap_loaded = False

            async def route(route):
                nonlocal bootstrap_loaded
                task = asyncio.current_task()
                handlers.add(task)
                try:
                    request = route.request
                    if not bootstrap_loaded and request.url == bootstrap_url and request.is_navigation_request():
                        bootstrap_loaded = True
                        await route.fulfill(status=200, content_type="text/html", body=_html(challenge), headers={
                            "cache-control": "no-store", "referrer-policy": "no-referrer",
                            "content-security-policy": (
                                "default-src 'none'; script-src 'unsafe-inline' https://" + "cdn." + root
                                + "; style-src 'unsafe-inline' https://" + "cdn." + root
                                + "; img-src data: blob: https://" + root + " https://cdn." + root
                                + " https://" + image_host
                                + "; connect-src https://" + root + " https://cdn." + root
                                + "; frame-src https://" + root + " https://cdn." + root
                                + "; base-uri 'none'; form-action 'none'; worker-src 'none'"
                            ),
                        })
                        return
                    status, headers, body = await http.fetch(request.method, request.url,
                        await request.all_headers(), request.post_data_buffer, request.resource_type)
                    await route.fulfill(status=status, headers=headers, body=body)
                except asyncio.CancelledError:
                    with suppress(PlaywrightError):
                        await route.abort()
                    raise
                except Exception as error:
                    if not failure.done():
                        failure.set_result(error)
                    with suppress(PlaywrightError):
                        await route.abort()
                finally:
                    handlers.discard(task)

            async def websocket(socket):
                if not failure.done():
                    failure.set_result(BrowserChallengeError("captcha_unsafe_destination"))
                await socket.close()

            await context.route("**/*", route)
            await context.route_web_socket("**/*", websocket)
            page = await context.new_page()

            async def drive():
                await page.goto(bootstrap_url, wait_until="domcontentloaded", timeout=_remaining(deadline) * 1000)
                return await _drive(page, http, provider, before_recognition, deadline, failure)

            async def monitor():
                while True:
                    if failure.done():
                        raise failure.result()
                    _remaining(deadline)
                    gateway._check_proxy()
                    await asyncio.sleep(GUARD_INTERVAL)

            tasks = [asyncio.create_task(drive()), asyncio.create_task(monitor())]
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if failure.done():
                raise failure.result()
            if tasks[1] in done:
                await tasks[1]
            return await tasks[0]
    except ActionRequired as error:
        if http is not None and http.last_failure_code:
            error.last_failure_code = http.last_failure_code
        raise
    except (TimeoutError, PlaywrightTimeout):
        raise BrowserChallengeError("captcha_timeout",
            last_failure_code=http.last_failure_code if http is not None else None) from None
    except BrowserChallengeError as error:
        if error.last_failure_code is None and http is not None:
            error.last_failure_code = http.last_failure_code
        raise
    except PlaywrightError:
        raise BrowserChallengeError("captcha_browser_failed") from None
    finally:
        failure.cancel()

        async def cleanup():
            dirty = True
            try:
                pending = await _settle(tasks + list(handlers), hard_deadline, cancel=True)
                context_closed = context is None
                for resource in (context, None if shared_lease else browser):
                    if resource is not None:
                        # Closing several contexts on a busy shared driver can
                        # take more than 80 ms. Allow a bounded graceful close
                        # before retiring the browser and stalling new leases.
                        maximum = 0.4 if shared_lease and resource is context else 0.08
                        closed = await _cleanup_call(resource.close, hard_deadline, maximum=maximum)
                        if resource is context:
                            context_closed = closed
                if http is not None and getattr(http, "client", None) is not None:
                    await _cleanup_call(lambda: http.__aexit__(None, None, None), hard_deadline, maximum=0.05)
                if manager is not None:
                    await _cleanup_call(lambda: manager.__aexit__(None, None, None), hard_deadline)
                    await _stop_owned_driver(manager, browser, browser_group, hard_deadline)
                dirty = bool(pending) or not context_closed
            finally:
                if shared_lease:
                    await runtime.release(shared_lease, dirty=dirty)

        if runtime:
            # The caller's hard timeout can cancel _solve again while several
            # contexts finish together on a throttled CPU. Cleanup must outlive
            # that cancellation, otherwise the runtime retains an active lease
            # forever and every subsequent challenge waits for its own timeout.
            cleanup_task = asyncio.create_task(cleanup())
            cleanup_task.add_done_callback(_observe_task)
            await asyncio.shield(cleanup_task)
        else:
            await cleanup()


def solve_ams(challenge, gateway, provider, *, deadline, before_recognition):
    """Return the SDK access code; ``deadline`` is absolute monotonic time.

    Guard and recognition-hook exceptions deliberately propagate unchanged so
    cancellation, lease loss and account proxy revocation cannot become retries.
    """
    checked = _challenge(challenge)
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
        raise BrowserChallengeError("captcha_timeout")
    deadline = min(deadline, time.monotonic() + 60, time.monotonic() + checked["expires_at"] - time.time())
    _remaining(deadline)
    gateway._check_proxy()
    if settings.captcha_browser_reuse:
        from .captcha_runtime import shared_runtime
        try:
            return shared_runtime().run(lambda runtime: _solve(
                checked, gateway, provider, deadline, before_recognition, runtime), deadline)
        except TimeoutError:
            raise BrowserChallengeError("captcha_timeout") from None
    # Do not let asyncio.run's executor shutdown extend a timed-out DNS lookup.
    # SOCKS target DNS is remote; this also bounds a proxy-host DNS failure.
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(_solve(checked, gateway, provider, deadline, before_recognition))
    finally:
        try:
            loop.run_until_complete(_settle(asyncio.all_tasks(loop), deadline, cancel=True))
            loop.run_until_complete(_cleanup_call(loop.shutdown_asyncgens, deadline, maximum=0.05))
            loop.run_until_complete(_settle(asyncio.all_tasks(loop), deadline, cancel=True, maximum=0))
        finally:
            # The private loop cannot retain arbitrary finalizers past the hard
            # deadline. Its owned driver/Chromium have already been stopped.
            for task in asyncio.all_tasks(loop):
                task.cancel()
                task._log_destroy_pending = False
            loop.close()
