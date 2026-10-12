"""Exercise the image provider through an in-memory HTTP transport only."""

import asyncio
import base64
import importlib
import importlib.util
import json
import time
import traceback

import httpx
import pytest


PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+aQ1cAAAAASUVORK5CYII="
)
API_KEY = "synthetic-vision-key-never-log"
ENDPOINT = "https://vision.example.invalid/claude/v1/messages"


def module():
    assert importlib.util.find_spec("app.vision_captcha"), (
        "The independent CAPTCHA vision provider is missing"
    )
    return importlib.import_module("app.vision_captcha")


def message(text="aB34Zq", **overrides):
    return {
        "id": "synthetic-message",
        "type": "message",
        "role": "assistant",
        "model": "configured-model",
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 12, "output_tokens": 6},
    } | overrides


def provider(handler, **overrides):
    options = {
        "api_key": API_KEY,
        "endpoint": ENDPOINT,
        "model": "configured-model",
        "transport": httpx.MockTransport(handler),
    } | overrides
    return module().ClaudeVisionProvider(**options)


def assert_safe_error(caught, code):
    error = caught.value
    assert error.code == code
    rendered = "".join(traceback.format_exception(error))
    for secret in (API_KEY, "private-response", "private-password", "private-token"):
        assert secret not in str(error)
        assert secret not in repr(error)
        assert secret not in rendered


def test_sync_worker_sends_only_image_and_fixed_instructions():
    seen = []

    def handler(request):
        seen.append(request)
        body = json.loads(request.content)
        assert request.method == "POST"
        assert str(request.url) == ENDPOINT
        assert request.headers["x-api-key"] == API_KEY
        assert request.headers["anthropic-version"] == "2023-06-01"
        assert body["model"] == "configured-model"
        assert body["max_tokens"] <= 64
        assert "untrusted" in body["system"]
        content = body["messages"]
        assert len(content) == 1 and content[0]["role"] == "user"
        blocks = content[0]["content"]
        assert len(blocks) == 2
        assert blocks[0] == {
            "type": "image",
            "source": {
                "type": "base64",
                "media_type": "image/png",
                "data": base64.b64encode(PNG).decode("ascii"),
            },
        }
        assert blocks[1]["type"] == "text"
        assert API_KEY not in request.content.decode()
        return httpx.Response(200, json=message(" aB34Zq\n"))

    recognizer = provider(handler)
    assert recognizer.recognize(PNG) == "aB34Zq"
    assert len(seen) == 1
    assert API_KEY not in repr(recognizer)


def test_async_browser_uses_same_validated_answer():
    recognizer = provider(lambda request: httpx.Response(200, json=message("9aZ3")))
    assert asyncio.run(recognizer.arecognize(PNG)) == "9aZ3"


def test_missing_key_is_distinct_and_never_sends():
    def denied(request):
        pytest.fail("Missing provider configuration must never send a request")

    recognizer = module().ClaudeVisionProvider(
        "", transport=httpx.MockTransport(denied)
    )
    with pytest.raises(module().VisionError) as caught:
        recognizer.recognize(PNG)
    assert_safe_error(caught, "captcha_unavailable")


@pytest.mark.parametrize("status", [301, 307, 400, 401, 403, 429, 500])
def test_http_failures_never_redirect_retry_or_expose_provider_data(status, caplog):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            status,
            text="private-response " + API_KEY + " private-password private-token",
            headers={"location": "https://other.example.invalid/private-token"},
        )

    with pytest.raises(module().VisionError) as caught:
        provider(handler).recognize(PNG)
    assert_safe_error(caught, "captcha_provider_failed")
    assert len(calls) == 1
    assert API_KEY not in caplog.text and "private-response" not in caplog.text


@pytest.mark.parametrize(
    "body",
    [
        [],
        {},
        {"content": None},
        {"content": []},
        {"content": ["private-response"]},
        {"content": [{"type": "text", "text": "ABCD"}, {"type": "text", "text": "1234"}]},
        {"content": [{"type": "tool_use", "text": "ABCD"}]},
        {"content": [{"type": "text", "text": 1234}]},
        message("abc"),
        message("abcdefghijk"),
        message("AB CD"),
        message("验证码ABCD"),
        message("ＡＢＣＤ"),
        message("ABCD\x00"),
        message("private-response " + API_KEY),
        message("Answer: ABCD"),
        message("ABCD", stop_reason="max_tokens"),
    ],
)
def test_malformed_or_unbounded_answers_are_rejected(body):
    with pytest.raises(module().VisionError) as caught:
        provider(lambda request: httpx.Response(200, json=body)).recognize(PNG)
    assert_safe_error(caught, "captcha_invalid_response")


def test_invalid_json_is_not_reported_as_response_text():
    with pytest.raises(module().VisionError) as caught:
        provider(
            lambda request: httpx.Response(200, text="private-response " + API_KEY)
        ).recognize(PNG)
    assert_safe_error(caught, "captcha_invalid_response")


@pytest.mark.parametrize(
    ("image", "mime_type"),
    [(b"", "image/png"), (b"x" * 2_000_001, "image/png"), (PNG, "text/html"), ("not-bytes", "image/png")],
    ids=["empty", "oversized", "unsupported-mime", "not-bytes"],
)
def test_invalid_images_are_rejected_before_any_request(image, mime_type):
    def denied(request):
        pytest.fail("Invalid images must never be sent")

    with pytest.raises(module().VisionError) as caught:
        provider(denied).recognize(image, mime_type)
    assert_safe_error(caught, "captcha_invalid_image")


def test_timeout_exception_is_safe_and_not_retried():
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("private-response " + API_KEY, request=request)

    with pytest.raises(module().VisionError) as caught:
        provider(handler).recognize(PNG)
    assert_safe_error(caught, "captcha_timeout")
    assert len(calls) == 1


def test_total_deadline_cancels_slow_provider():
    async def handler(request):
        await asyncio.sleep(2)
        return httpx.Response(200, json=message())

    started = time.monotonic()
    with pytest.raises(module().VisionError) as caught:
        provider(handler, timeout_seconds=0.05).recognize(PNG)
    assert_safe_error(caught, "captcha_timeout")
    assert time.monotonic() - started < 1


def test_sync_deadline_does_not_wait_for_cancelled_dns_thread():
    async def handler(request):
        # asyncio's resolver uses this same executor bridge. Cancellation must
        # return to the auth worker without waiting for the OS resolver to finish.
        await asyncio.to_thread(time.sleep, 1.2)
        return httpx.Response(200, json=message())

    started = time.monotonic()
    with pytest.raises(module().VisionError) as caught:
        provider(handler, timeout_seconds=0.05).recognize(PNG)
    assert_safe_error(caught, "captcha_timeout")
    assert time.monotonic() - started < 0.8


def test_transport_failure_does_not_expose_exception_text():
    def handler(request):
        raise httpx.ConnectError(
            "private-response private-password private-token " + API_KEY,
            request=request,
        )

    with pytest.raises(module().VisionError) as caught:
        provider(handler).recognize(PNG)
    assert_safe_error(caught, "captcha_provider_failed")


class StreamingBody(httpx.AsyncByteStream):
    def __init__(self, *, delay=0):
        self.chunks_read = 0
        self.closed = False
        self.delay = delay

    async def __aiter__(self):
        for _ in range(20):
            if self.delay:
                await asyncio.sleep(self.delay)
            self.chunks_read += 1
            yield b"x" * 4096

    async def aclose(self):
        self.closed = True


def test_oversized_stream_is_aborted_without_reading_entire_body():
    stream = StreamingBody()
    with pytest.raises(module().VisionError) as caught:
        provider(lambda request: httpx.Response(200, stream=stream)).recognize(PNG)
    assert_safe_error(caught, "captcha_invalid_response")
    assert stream.closed
    assert stream.chunks_read <= 5


def test_response_body_is_also_covered_by_total_deadline():
    stream = StreamingBody(delay=0.1)
    started = time.monotonic()
    with pytest.raises(module().VisionError) as caught:
        provider(
            lambda request: httpx.Response(200, stream=stream), timeout_seconds=0.05
        ).recognize(PNG)
    assert_safe_error(caught, "captcha_timeout")
    assert stream.closed
    assert time.monotonic() - started < 1


@pytest.mark.parametrize("entrypoint", ["recognize", "arecognize"])
def test_remaining_budget_clamps_the_provider_deadline(entrypoint):
    async def handler(request):
        await asyncio.sleep(2)
        return httpx.Response(200, json=message())

    recognizer = provider(handler)
    started = time.monotonic()
    with pytest.raises(module().VisionError) as caught:
        if entrypoint == "recognize":
            recognizer.recognize(PNG, timeout_seconds=0.05)
        else:
            asyncio.run(recognizer.arecognize(PNG, timeout_seconds=0.05))
    assert_safe_error(caught, "captcha_timeout")
    assert time.monotonic() - started < 1


@pytest.mark.parametrize("remaining", [0, -1])
def test_expired_remaining_budget_does_not_send(remaining):
    def denied(request):
        pytest.fail("Expired work must never send a request")

    with pytest.raises(module().VisionError) as caught:
        provider(denied).recognize(PNG, timeout_seconds=remaining)
    assert_safe_error(caught, "captcha_timeout")


@pytest.mark.parametrize("headers", [{"content-length": "16385"}, {"content-encoding": "gzip"}])
def test_unsafe_body_metadata_stops_before_reading(headers):
    stream = StreamingBody()
    with pytest.raises(module().VisionError) as caught:
        provider(
            lambda request: httpx.Response(200, stream=stream, headers=headers)
        ).recognize(PNG)
    assert_safe_error(caught, "captcha_invalid_response")
    assert stream.closed and stream.chunks_read == 0


@pytest.mark.parametrize(
    "options",
    [
        {"api_key": "private-token\n"},
        {"endpoint": "http://vision.example.invalid/messages"},
        {"endpoint": "https://user:private-password@vision.example.invalid/messages"},
        {"endpoint": "https://vision.example.invalid/messages?key=private-token"},
        {"endpoint": "https://vision.example.invalid/messages#private-token"},
        {"endpoint": "https://vision.example.invalid:invalid/messages"},
        {"endpoint": "https://private-token..example.invalid/messages"},
        {"endpoint": "https://vision.example.invalid/messages\n"},
        {"model": ""},
        {"model": "private-token\n"},
        {"timeout_seconds": 0},
        {"timeout_seconds": 61},
        {"timeout_seconds": float("nan")},
        {"timeout_seconds": float("inf")},
    ],
)
def test_invalid_configuration_never_sends_or_exposes_values(options):
    def denied(request):
        pytest.fail("Invalid configuration must never send a request")

    with pytest.raises(module().VisionError) as caught:
        provider(denied, **options).recognize(PNG)
    assert_safe_error(caught, "captcha_invalid_configuration")


def test_environment_configuration_keeps_key_private(monkeypatch):
    from app.config import Settings

    assert "captcha_vision_api_key" in Settings.model_fields
    monkeypatch.setenv("CAPTCHA_VISION_API_KEY", API_KEY)
    monkeypatch.setenv("CAPTCHA_VISION_ENDPOINT", ENDPOINT)
    monkeypatch.setenv("CAPTCHA_VISION_MODEL", "configured-model")
    monkeypatch.setenv("CAPTCHA_VISION_TIMEOUT_SECONDS", "1.5")
    configuration = Settings(_env_file=None)
    assert API_KEY not in repr(configuration)
    assert API_KEY not in configuration.model_dump_json()
    assert configuration.captcha_vision_timeout_seconds == 1.5
    seen = []

    def handler(request):
        seen.append(request)
        assert str(request.url) == ENDPOINT
        assert request.headers["x-api-key"] == API_KEY
        assert json.loads(request.content)["model"] == "configured-model"
        return httpx.Response(200, json=message())

    recognizer = module().ClaudeVisionProvider.from_settings(
        configuration, transport=httpx.MockTransport(handler)
    )
    assert recognizer.recognize(PNG) == "aB34Zq"
    assert len(seen) == 1


def test_vision_settings_default_to_disabled_and_bounded(monkeypatch):
    from app.config import Settings

    assert "captcha_vision_api_key" in Settings.model_fields
    for name in Settings.model_fields:
        if name.startswith("captcha_"):
            monkeypatch.delenv(name.upper(), raising=False)
    configuration = Settings(_env_file=None)
    assert configuration.captcha_vision_api_key.get_secret_value() == ""
    assert configuration.captcha_vision_endpoint == "https://api.anthropic.com/v1/messages"
    assert configuration.captcha_vision_model == "claude-opus-4.6"
    assert configuration.captcha_vision_timeout_seconds == 20
    assert configuration.captcha_max_attempts == 6
    assert configuration.captcha_total_timeout_seconds == 60
    assert configuration.captcha_browser_concurrency == 2
    assert configuration.captcha_chromium_executable is None


@pytest.mark.parametrize(
    "options",
    [
        {"captcha_vision_timeout_seconds": 0},
        {"captcha_vision_timeout_seconds": 61},
        {"captcha_max_attempts": 0},
        {"captcha_max_attempts": 7},
        {"captcha_total_timeout_seconds": 4},
        {"captcha_total_timeout_seconds": 61},
        {"captcha_browser_concurrency": 0},
        {"captcha_browser_concurrency": 5},
    ],
)
def test_settings_reject_unbounded_automation(options):
    from app.config import Settings
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Settings(_env_file=None, **options)


@pytest.mark.parametrize("limit", [1, 3, 6])
def test_recognition_attempt_limit_can_be_lowered_within_six(limit):
    from app.config import Settings

    configuration = Settings(_env_file=None, captcha_max_attempts=limit)
    assert configuration.captcha_max_attempts == limit
