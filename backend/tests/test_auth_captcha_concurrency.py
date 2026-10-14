"""Two recognition requests overlap; further challenges wait without a new budget."""
import concurrent.futures
import threading

import pytest

from app.auth_automation import automate_challenge
from app.config import settings
from app.security import decrypt
from test_auth_automation import CaptchaLogin


@pytest.mark.parametrize('limit', [2, 10])
def test_captcha_recognition_runs_in_parallel_with_global_cap(monkeypatch, limit):
    monkeypatch.setattr(settings, 'captcha_browser_concurrency', limit)
    entered, release, mutex = [threading.Event() for _ in range(limit)], threading.Event(), threading.Lock()
    active, maximum, visits = 0, 0, 0

    class Vision:
        def recognize(self, *args, **kwargs):
            nonlocal active, maximum, visits
            with mutex:
                index = visits
                visits += 1
                active += 1
                maximum = max(maximum, active)
                entered[index].set()
            try:
                assert release.wait(5)
                return 'AB3DE'
            finally:
                with mutex:
                    active -= 1

    adapters = [CaptchaLogin() for _ in range(limit + 1)]
    progresses = [adapter.start() for adapter in adapters]
    assert len({decrypt(p.sealed_state)['operation_id'] for p in progresses}) == limit + 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=limit + 1) as pool:
        futures = [pool.submit(automate_challenge, adapters[i], progresses[i], provider=Vision()) for i in range(limit)]
        try:
            assert all(event.wait(3) for event in entered)
            waiting = pool.submit(automate_challenge, adapters[limit], progresses[limit], provider=Vision()).result(timeout=2)
            assert waiting.status == 'polling' and waiting.stage == 'captcha_waiting'
            assert not adapters[limit].answers
            assert maximum == limit and visits == limit
        finally:
            release.set()
        assert all(f.result(timeout=3).status == 'ready' for f in futures)
    for adapter in adapters[:limit]:
        assert [cp.event for cp in adapter.events].count('captcha_verified') == 1
