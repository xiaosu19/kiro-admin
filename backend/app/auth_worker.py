"""Dispatch bounded native authentication steps across independent accounts."""

import logging
import signal
import time
from contextlib import nullcontext

from . import auth_jobs, external_auth_worker
from .auth_session_dispatcher import AuthSessionDispatcher
from .config import settings


def make_dispatcher(*, gateway_factory=None, auth_factory=None,
                    identity_factory=None, max_workers=None):
    next_maintenance = 0

    def maintenance():
        nonlocal next_maintenance
        current = time.monotonic()
        if current >= next_maintenance:
            from .auth_connections import prune
            prune()
            auth_jobs.expire_batches()
            external_auth_worker.expire_batches()
            next_maintenance = current + 5

    return AuthSessionDispatcher(
        lambda: auth_jobs.session_candidates() + external_auth_worker.session_candidates(),
        lambda task: (external_auth_worker.run_one(lane_id=task[2]) if task[1] == 'external' else
                     auth_jobs.run_one(gateway_factory, auth_factory, identity_factory,
                                       account_id=task[0], record_id=task[2], maintenance=False)),
        max_workers=max_workers or settings.auth_worker_concurrency,
        account_key=lambda task: task[0],
        max_per_account=settings.auth_per_account_concurrency or settings.per_account_concurrency,
        fence=lambda task: nullcontext(True),
        maintenance=maintenance,
    )


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    # HTTPX's INFO request URLs can carry opaque AWS challenge query values.
    # Public auth progress is emitted through our fixed, redacted job stages.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    dispatcher = make_dispatcher()

    def stop(*_):
        dispatcher.stop()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not dispatcher.stopped.is_set():
            try:
                dispatcher.tick()
            except Exception as error:
                logging.error("Auth worker stopped a step: %s", type(error).__name__)
            dispatcher.stopped.wait(0.2)
    finally:
        dispatcher.close(wait=True)
        from .captcha_runtime import shutdown
        shutdown()


if __name__ == "__main__":
    main()
