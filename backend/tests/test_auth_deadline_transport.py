import asyncio
import time

import httpx
import pytest
import requests

from app.auth_deadline_transport import send


def invoke(monkeypatch, handler, *, budget=.2, guard=lambda: None, limit=1000):
    original = httpx.AsyncClient
    def client(**kwargs):
        assert kwargs["proxy"] == "socks5h://opaque:secret@proxy.invalid:1080"
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        kwargs.pop("proxy")
        return original(transport=httpx.MockTransport(handler), **kwargs)
    monkeypatch.setattr(httpx, "AsyncClient", client)
    with requests.Session() as session:
        prepared = session.prepare_request(requests.Request("POST", "https://us-east-1.signin.aws/platform/test", json={"captchaGuess": "AB3DE"}))
        response = send(prepared, session, proxy="socks5h://opaque:secret@proxy.invalid:1080",
                        guard=guard, deadline=time.monotonic() + budget, limit=limit)
        return response, session.cookies.get_dict()


def test_preserves_prepared_body_response_cookies_and_no_redirect(monkeypatch):
    def handler(request):
        assert b'"captchaGuess": "AB3DE"' in request.content
        assert request.headers["Accept-Encoding"] == "identity"
        return httpx.Response(200, json={"accepted": True}, headers={"Set-Cookie": "aws-session=test; Path=/; Secure"})
    response, cookies = invoke(monkeypatch, handler)
    assert response.json() == {"accepted": True} and cookies == {"aws-session": "test"}
    assert b"".join(response.iter_content(4)) == response.content


def test_absolute_timeout_cancels_slow_response_before_return(monkeypatch):
    events = []
    async def handler(request):
        try:
            await asyncio.sleep(5)
        finally:
            events.append("cancelled")
    started = time.monotonic()
    with pytest.raises(requests.Timeout):
        invoke(monkeypatch, handler, budget=.05)
    assert time.monotonic() - started < .4 and events == ["cancelled"]


def test_guard_revocation_cancels_pending_wire(monkeypatch):
    started = time.monotonic()
    def guard():
        if time.monotonic() - started > .05:
            raise RuntimeError("revoked")
    async def handler(request):
        await asyncio.sleep(5)
    with pytest.raises(RuntimeError, match="revoked"):
        invoke(monkeypatch, handler, budget=1, guard=guard)
    assert time.monotonic() - started < .5


def test_rejects_oversized_body(monkeypatch):
    with pytest.raises(requests.RequestException):
        invoke(monkeypatch, lambda r: httpx.Response(200, content=b"x" * 101), limit=100)
