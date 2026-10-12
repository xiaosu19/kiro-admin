"""Automatic answers still require the native AWS workflow to accept them."""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from app.identity_login import NativeIdentityLogin
from app.security import decrypt, encrypt
from test_identity_login import Gateway, NOW, ams_token, CDN


class CaptchaLogin(NativeIdentityLogin):
    def __init__(self, *, accepts=True, enterprise=False):
        self.events, self.answers = [], []
        self.accepts = accepts
        super().__init__(Gateway(), checkpoint=self.events.append, clock=lambda: NOW)

    def challenge_image(self, sealed_state, revision):
        return SimpleNamespace(content=b"captcha-image-only", content_type="image/png")

    def _advance(self, state, answer):
        self.answers.append(answer)
        if self.accepts:
            state.update(stage="exchange", status="ready")
        else:
            self._challenge(state, {"captchaURL": "https://us-east-1.signin.aws/platform/captcha/test", "captchaCES": "opaque-ces"})

    def start(self, *, ams=False):
        state = decrypt(self.begin("alice", "password-secret", expected_user_id="expected-user").sealed_state)
        state["stage"] = "workflow"
        response = {"captchaToken": ams_token(), "captchaCDN": CDN} if ams else {"captchaURL": "https://us-east-1.signin.aws/platform/captcha/test", "captchaCES": "opaque-ces"}
        self._challenge(state, response)
        return self._publish(state)


class Vision:
    def __init__(self, error=None):
        self.calls, self.error = [], error

    def recognize(self, image, mime_type="image/png", *, timeout_seconds=None):
        self.calls.append((image, mime_type, timeout_seconds))
        if self.error:
            raise self.error
        return "AB3DE"


def solve(adapter, progress, provider, **kwargs):
    from app.auth_automation import automate_challenge
    return automate_challenge(adapter, progress, provider=provider, **kwargs)


def test_image_answer_is_submitted_before_verified_event():
    adapter, vision = CaptchaLogin(), Vision()
    progress = solve(adapter, adapter.start(), vision)
    assert progress.status == "ready"
    assert adapter.answers == [{"captchaGuess": "AB3DE", "captchaCES": "opaque-ces"}]
    assert len(vision.calls) == 1
    assert vision.calls[0][:2] == (b"captcha-image-only", "image/png")
    assert 0 < vision.calls[0][2] <= 60
    events = [event.event for event in adapter.events]
    assert events.index("captcha_recognizing") < events.index("captcha_verified")
    assert decrypt(progress.sealed_state)["captcha_automation"]["status"] == "verified"


def test_rejected_answers_stop_at_three_and_preserve_manual_challenge():
    adapter, vision = CaptchaLogin(accepts=False), Vision()
    progress = solve(adapter, adapter.start(), vision)
    assert progress.status == "challenge" and len(adapter.answers) == len(vision.calls) == 3
    assert "captcha_verified" not in [event.event for event in adapter.events]
    state = decrypt(progress.sealed_state)
    assert state["captcha_automation"]["status"] == "requires_action"
    assert state["challenge"]["kind"] == "image"
    # A worker restart must not silently reset the attempt count.
    again = solve(adapter, progress, vision)
    assert again.status == "challenge" and len(vision.calls) == 3


def test_missing_provider_does_not_report_recognizing(monkeypatch):
    from app.config import settings
    from pydantic import SecretStr
    monkeypatch.setattr(settings, "captcha_vision_api_key", SecretStr(""))
    adapter = CaptchaLogin()
    progress = solve(adapter, adapter.start(), None)
    assert progress.status == "challenge" and not adapter.answers
    assert "captcha_recognizing" not in [event.event for event in adapter.events]


def test_provider_failures_never_submit_a_guess():
    from app.vision_captcha import VisionError
    adapter, vision = CaptchaLogin(), Vision(VisionError("captcha_provider_failed"))
    progress = solve(adapter, adapter.start(), vision)
    assert progress.status == "challenge" and not adapter.answers
    assert len(vision.calls) == 3
    assert "captcha_verified" not in [event.event for event in adapter.events]


def test_expired_overall_budget_does_not_repeat_provider_after_restart():
    adapter, vision = CaptchaLogin(), Vision()
    progress = adapter.start()
    state = decrypt(progress.sealed_state)
    state["captcha_automation"] = {"attempts": 1, "deadline": NOW - 1, "status": "recognizing"}
    progress = replace(progress, sealed_state=encrypt(state))
    result = solve(adapter, progress, vision)
    assert result.status == "challenge" and not vision.calls and not adapter.answers


def test_ams_requires_actual_official_completion_and_native_acceptance():
    adapter, vision = CaptchaLogin(), Vision()
    def browser(challenge, gateway, provider, *, deadline, before_recognition):
        assert challenge["kind"] == "ams" and deadline > 0
        before_recognition()
        return "real-official-access-code"
    result = solve(adapter, adapter.start(ams=True), vision, browser_solver=browser)
    assert result.status == "ready"
    assert adapter.answers == [{"captchaAccessCode": "real-official-access-code"}]


def test_revoked_proxy_stops_before_provider_or_submission():
    adapter, vision = CaptchaLogin(), Vision()
    progress = adapter.start()
    adapter.gateway.denied = True
    with pytest.raises(Exception):
        solve(adapter, progress, vision)
    assert not vision.calls and not adapter.answers


def test_busy_browser_slots_queue_without_recognition(monkeypatch):
    from app.auth_automation import browser_slot
    from app.config import settings
    monkeypatch.setattr(settings, "captcha_browser_concurrency", 1)
    adapter, vision = CaptchaLogin(), Vision()
    start = adapter.start()
    with browser_slot() as acquired:
        assert acquired
        queued = solve(adapter, start, vision)
    assert queued.status == "polling" and queued.stage == "captcha_waiting"
    assert not vision.calls and decrypt(queued.sealed_state)["status"] == "challenge"
    assert solve(adapter, queued, vision).status == "polling"
    # Native advance republishes the held challenge on the scheduled queue turn.
    assert solve(adapter, adapter.advance(queued.sealed_state), vision).status == "ready"


def test_deadline_is_durable_before_image_fetch_or_browser_start():
    adapter, vision = CaptchaLogin(), Vision()
    def crashed_fetch(sealed_state, revision):
        state = decrypt(sealed_state)
        assert state["captcha_automation"]["deadline"] == NOW + 60
        assert state["captcha_automation"]["attempts"] == 0
        assert decrypt(adapter.events[-1].sealed_state) == state
        raise RuntimeError("worker interrupted before image response")
    adapter.challenge_image = crashed_fetch
    with pytest.raises(RuntimeError):
        solve(adapter, adapter.start(), vision)
    assert not vision.calls and not adapter.answers


def test_no_ocr_widget_rejections_are_still_limited_to_three_submissions():
    class SilentWidgetLogin(CaptchaLogin):
        def _advance(self, state, answer):
            self.answers.append(answer)
            self._challenge(state, {"captchaToken": ams_token(), "captchaCDN": CDN})
    adapter, vision, calls = SilentWidgetLogin(), Vision(), []
    def widget(challenge, gateway, provider, **kwargs):
        calls.append(1)
        return "official-code"
    result = solve(adapter, adapter.start(ams=True), vision, browser_solver=widget)
    assert result.status == "challenge" and len(calls) == len(adapter.answers) == 3
    state = decrypt(result.sealed_state)
    assert state["captcha_automation"]["submissions"] == 3
    assert state["captcha_automation"]["attempts"] == 0
    assert "captcha_recognizing" not in [event.event for event in adapter.events]
