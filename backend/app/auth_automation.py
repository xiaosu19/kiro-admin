"""Bounded automatic CAPTCHA answers within the existing durable auth workflow.

Only the challenge image leaves for the configured vision provider. Native AWS
responses decide acceptance; passwords, identity checks and OIDC remain under the
existing adapter checkpoints and account fence. No browser survives a worker step.
"""
import fcntl
import os
import time
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path

from .config import settings
from .database import engine
from .vision_captcha import VisionError


class ActionRequired(Exception):
    pass


@contextmanager
def browser_slot():
    """A configured cap shared by threads and duplicate worker processes."""
    base = settings.auth_worker_lock_path or Path(str(engine.url.database))
    for index in range(settings.captcha_browser_concurrency):
        path = Path(str(base) + f".captcha-{index}.lock").resolve()
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            continue
        try:
            yield True
        finally:
            os.close(fd)
        return
    yield False


def automate_challenge(adapter, progress, *, actor_id=None, provider=None, browser_solver=None):
    if progress.status != "challenge":
        return progress
    if provider is None:
        if actor_id is None:
            return progress
        from .ai_settings import provider_for_actor
        provider = provider_for_actor(actor_id)
        if provider is None:
            return progress
    with browser_slot() as acquired:
        if not acquired:
            # Keep the encrypted native challenge intact; the normal worker queue
            # retries later without creating another browser or waiting on a lock.
            return replace(progress, status="polling", next_poll_at=adapter.clock() + 2,
                           stage="captcha_waiting")
        previous_deadline = getattr(adapter, "request_deadline", None)
        try:
            return _solve(adapter, progress, provider, browser_solver)
        finally:
            adapter.request_deadline = previous_deadline


def _solve(adapter, progress, provider, browser_solver):
    state = adapter._load(progress.sealed_state)
    initial = "captcha_automation" not in state
    automation = state.setdefault("captcha_automation", {
        "attempts": 0,
        "submissions": 0,
        "deadline": min(state["expires_at"], adapter.clock() + settings.captcha_total_timeout_seconds),
        "status": "pending",
    })
    automation.setdefault("submissions", 0)
    # Never reset counters/deadlines on restart or on a replacement challenge.
    budget = min(settings.captcha_total_timeout_seconds, automation["deadline"] - adapter.clock())
    end = time.monotonic() + max(0, budget)
    adapter.request_deadline = end

    def remaining():
        return min(end - time.monotonic(), automation["deadline"] - adapter.clock(),
                   state["challenge"]["expires_at"] - adapter.clock())

    def publish(event="state"):
        nonlocal progress
        state["captcha_automation"] = automation
        sealed = adapter._emit(state, event)
        progress = replace(progress, sealed_state=sealed, revision=state["revision"])

    def pause(reason):
        automation.update(status="requires_action", reason=reason)
        publish()
        return progress

    def before_recognition():
        adapter._guard()
        if remaining() <= 0 or max(automation["attempts"], automation["submissions"]) >= settings.captcha_max_attempts:
            raise ActionRequired()
        automation.update(status="recognizing", attempts=automation["attempts"] + 1)
        automation.pop("reason", None)
        publish("captcha_recognizing")

    if automation["status"] == "requires_action":
        return progress
    if initial:
        # A crash while fetching an image or loading the official widget must
        # not create another full budget when the worker restarts.
        publish()
    # The time limit also bounds official SDK completions that need no OCR.
    for _ in range(settings.captcha_max_attempts + 1):
        if remaining() <= 0 or max(automation["attempts"], automation["submissions"]) >= settings.captcha_max_attempts:
            return pause("captcha_limit")
        adapter._guard()
        challenge = state.get("automation_challenge") if state["challenge"]["kind"] == "aws_authorization" else state["challenge"]
        if not challenge or challenge["kind"] not in {"image", "ams"}:
            return pause("captcha_unsupported")
        try:
            if challenge["kind"] == "image":
                image = adapter.challenge_image(progress.sealed_state, challenge["revision"])
                before_recognition()
                value = provider.recognize(image.content, mime_type=image.content_type,
                                           timeout_seconds=remaining())
                answer = {"guess": value}
            else:
                from .captcha_browser import BrowserChallengeError, solve_ams
                try:
                    value = (browser_solver or solve_ams)(challenge, adapter.gateway, provider,
                        deadline=time.monotonic() + remaining(), before_recognition=before_recognition)
                except BrowserChallengeError as error:
                    return pause(error.code)
                answer = {"access_code": value}
            adapter._guard()
            if remaining() <= 0:
                return pause("captcha_limit")
            automation["submissions"] += 1
            # Official SDKs may complete without an image. Bound those native
            # submissions too, including after a worker restart.
            publish()
            # AWS consumes a revision-bound answer. Filling a field or obtaining
            # an OCR guess alone cannot emit the verified event.
            progress = adapter.advance(progress.sealed_state, answer={
                "challenge_id": challenge["id"], "revision": challenge["revision"], **answer})
            state = adapter._load(progress.sealed_state)
            state["captcha_automation"] = automation
            if progress.status != "challenge":
                # Native parsing also has to finish inside the same budget.
                if time.monotonic() > end:
                    automation.update(status="submitted", reason="captcha_limit")
                    publish()
                    return progress
                automation.update(status="verified")
                publish("captcha_verified")
                return progress
        except ActionRequired:
            return pause("captcha_limit")
        except VisionError as error:
            if error.code in {"captcha_unavailable", "captcha_invalid_configuration", "captcha_invalid_image"}:
                return pause(error.code)
            # Recognition retries never resubmit a password or an unaccepted
            # captcha answer. Attempts were committed before calling the model.
            automation["reason"] = error.code
    return pause("captcha_limit")
