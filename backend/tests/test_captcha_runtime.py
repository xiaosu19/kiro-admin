"""Shared real Chromium, with independent transports and account contexts."""
import asyncio
import json
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from test_captcha_browser import (
    Gateway, Vision, Widget, browser_fixture, browser_module, chromium, run,
)


@pytest.fixture
def shared_browser(browser_fixture, monkeypatch):
    from app import captcha_runtime
    module = browser_module()
    captcha_runtime.shutdown()
    monkeypatch.setattr(module.settings, "captcha_browser_reuse", True)
    yield browser_fixture
    captcha_runtime.shutdown()


def test_sequential_contexts_do_not_share_storage_or_cookies(shared_browser):
    install, contexts, launches = shared_browser
    install()
    seen = []

    class StorageVision(Vision):
        async def arecognize(self, *args, **kwargs):
            page = contexts[-1][1].pages[0]
            seen.append(await page.evaluate("[document.cookie, localStorage.getItem('account')]"))
            await page.evaluate("document.cookie='account=private'; localStorage.setItem('account','private')")
            return await super().arecognize(*args, **kwargs)

    for _ in range(2):
        assert run(browser_module(), Gateway(), StorageVision(), lambda: None) == "official-fixture-access-code"
    assert seen == [["", None], ["", None]]
    assert len(launches) == 1 and len(contexts) == 2
    assert contexts[0][1] is not contexts[1][1]
    assert all(not context.pages for _, context, _ in contexts)


def test_ten_parallel_challenges_have_distinct_results_and_one_browser(shared_browser):
    install, contexts, launches = shared_browser

    class DistinctWidget(Widget):
        async def response(self, request):
            if request.url.path == "/verify":
                answer = json.loads(request.content)["answer"]
                return httpx.Response(200, json={"accessCode": "official-" + answer},
                                      headers={"access-control-allow-origin": "*"})
            return await super().response(request)

    install(widget=DistinctWidget())
    entered, simultaneous = [], []

    class OverlappingVision(Vision):
        async def arecognize(self, *args, **kwargs):
            entered.append(self.answer)
            deadline = time.monotonic() + 5
            while len(entered) < 10 and time.monotonic() < deadline:
                await asyncio.sleep(0.01)
            simultaneous.append(sum(bool(context.pages) for _, context, _ in contexts))
            return await super().arecognize(*args, **kwargs)

    def solve(index):
        answer = f"A7b{index:02}"
        return run(browser_module(), Gateway(), OverlappingVision(answer), lambda: None, seconds=15)

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(solve, range(10)))
    assert results == [f"official-A7b{index:02}" for index in range(10)]
    assert len(launches) == 1 and len(contexts) == 10 and max(simultaneous) == 10
    assert all(not context.pages for _, context, _ in contexts)


def test_revoked_account_does_not_close_other_accounts_browser(shared_browser):
    install, contexts, launches = shared_browser
    install()
    error = RuntimeError("fixture account revoked")

    def revoked():
        raise error

    def solve(index):
        try:
            return run(browser_module(), Gateway(), Vision(), revoked if index == 0 else lambda: None)
        except RuntimeError as caught:
            return caught

    with ThreadPoolExecutor(max_workers=3) as pool:
        result = list(pool.map(solve, range(3)))
    assert result == [error, "official-fixture-access-code", "official-fixture-access-code"]
    assert len(launches) == 1 and contexts[-1][0].is_connected()


@pytest.mark.parametrize("mode,code", [
    ("otp", "captcha_unsupported_challenge"),
    ("unsafe", "captcha_unsafe_destination"),
    ("websocket", "captcha_unsafe_destination"),
    ("password", "captcha_unsupported_challenge"),
])
def test_shared_context_keeps_network_and_challenge_guards(shared_browser, mode, code):
    install, _, _ = shared_browser
    install(mode)
    module = browser_module()
    with pytest.raises(module.BrowserChallengeError, match=f"^{code}$"):
        run(module, Gateway(), Vision(), lambda: pytest.fail("Unexpected OCR"))
    install()
    assert run(module, Gateway(), Vision(), lambda: None) == "official-fixture-access-code"


def test_idle_browser_is_released_and_next_job_can_restart(shared_browser, monkeypatch):
    from app import captcha_runtime
    install, contexts, launches = shared_browser
    install()
    monkeypatch.setattr(captcha_runtime, "IDLE_SECONDS", 0.1)
    run(browser_module(), Gateway(), Vision(), lambda: None)
    deadline = time.monotonic() + 2
    while contexts[0][0].is_connected() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not contexts[0][0].is_connected()
    run(browser_module(), Gateway(), Vision(), lambda: None)
    assert len(launches) == 2


def test_browser_rotates_after_bounded_use(shared_browser, monkeypatch):
    from app import captcha_runtime
    install, contexts, launches = shared_browser
    install()
    monkeypatch.setattr(captcha_runtime, "MAX_USES", 2)
    for _ in range(3):
        run(browser_module(), Gateway(), Vision(), lambda: None)
    assert len(launches) == 2
    assert not contexts[0][0].is_connected() and contexts[-1][0].is_connected()


def test_provider_timeout_closes_only_its_context(shared_browser):
    install, contexts, launches = shared_browser
    install()
    module = browser_module()

    class StalledVision(Vision):
        async def arecognize(self, *args, **kwargs):
            await asyncio.sleep(60)

    start = time.monotonic()
    with pytest.raises(module.BrowserChallengeError, match="^captcha_timeout$"):
        run(module, Gateway(), StalledVision(), lambda: None, seconds=2)
    assert time.monotonic() - start < 3
    assert not contexts[0][1].pages
    assert run(module, Gateway(), Vision(), lambda: None) == "official-fixture-access-code"
    assert len(launches) == 1


def test_retiring_browser_waits_for_its_last_live_context(monkeypatch):
    from types import SimpleNamespace
    from app import captcha_runtime
    monkeypatch.setattr(captcha_runtime, "MAX_USES", 1)
    runtime = captcha_runtime.BrowserRuntime()
    launches, closed = [], []

    async def launch(deadline):
        browser = SimpleNamespace(is_connected=lambda: True)
        launches.append(browser)
        return None, browser, None

    async def dispose(resources):
        closed.append(resources[1])

    async def scenario(runtime):
        deadline = time.monotonic() + 2
        first = await runtime.acquire(launch, dispose, deadline)
        second = await runtime.acquire(launch, dispose, deadline)
        assert first is second
        await runtime.release(first, dirty=True)
        waiting = asyncio.create_task(runtime.acquire(launch, dispose, deadline))
        await asyncio.sleep(0.02)
        assert not waiting.done() and not closed
        await runtime.release(second)
        third = await waiting
        assert len(launches) == 2 and closed == [launches[0]]
        await runtime.release(third)

    try:
        runtime.run(scenario, time.monotonic() + 3)
    finally:
        runtime.close()
