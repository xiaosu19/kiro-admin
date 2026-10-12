"""Two recognition requests overlap; further challenges wait without a new budget."""
import concurrent.futures
import threading

from app.auth_automation import automate_challenge
from app.config import settings
from app.security import decrypt
from test_auth_automation import CaptchaLogin


def test_captcha_recognition_runs_in_parallel_with_global_cap(monkeypatch):
    monkeypatch.setattr(settings, 'captcha_browser_concurrency', 2)
    entered, release, mutex = [threading.Event(), threading.Event()], threading.Event(), threading.Lock()
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

    adapters = [CaptchaLogin() for _ in range(3)]
    progresses = [adapter.start() for adapter in adapters]
    assert len({decrypt(p.sealed_state)['operation_id'] for p in progresses}) == 3
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(automate_challenge, adapters[i], progresses[i], provider=Vision()) for i in range(2)]
        try:
            assert all(event.wait(3) for event in entered)
            waiting = pool.submit(automate_challenge, adapters[2], progresses[2], provider=Vision()).result(timeout=2)
            assert waiting.status == 'polling' and waiting.stage == 'captcha_waiting'
            assert not adapters[2].answers
            assert maximum == 2 and visits == 2
        finally:
            release.set()
        assert all(f.result(timeout=3).status == 'ready' for f in futures)
    for adapter in adapters[:2]:
        assert [cp.event for cp in adapter.events].count('captcha_verified') == 1
