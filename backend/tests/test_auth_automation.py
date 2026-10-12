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


class RefreshingCaptchaLogin(CaptchaLogin):
    def challenge_image(self, sealed_state, revision):
        challenge = decrypt(sealed_state)["challenge"]
        return SimpleNamespace(content=b"refreshed-image-" + challenge["id"].encode(),
                               content_type="image/png")


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


def test_unchanged_native_image_is_not_recognized_or_submitted_again():
    adapter, vision = CaptchaLogin(accepts=False), Vision()
    result = solve(adapter, adapter.start(), vision)
    automatic = decrypt(result.sealed_state)["captcha_automation"]
    assert len(vision.calls) == len(adapter.answers) == 1
    assert result.status == "challenge" and automatic["status"] == "requires_action"
    assert automatic["reason"] == "captcha_answer_rejected"
    assert automatic["attempts"] == automatic["submissions"] == 1
    assert "captcha_verified" not in [event.event for event in adapter.events]


def test_new_native_challenge_url_and_ces_do_not_prove_a_new_image():
    class NewChallengeSameImage(CaptchaLogin):
        def _advance(self, state, answer):
            super()._advance(state, answer)
            self._challenge(state, {"captchaURL": "https://us-east-1.signin.aws/platform/captcha/replacement",
                                    "captchaCES": "replacement-ces"})

    adapter, vision = NewChallengeSameImage(accepts=False), Vision()
    result = solve(adapter, adapter.start(), vision)
    state = decrypt(result.sealed_state)
    assert state["challenge"]["image_url"].endswith("/replacement")
    assert len(vision.calls) == len(adapter.answers) == 1
    assert state["captcha_automation"]["reason"] == "captcha_answer_rejected"


def test_pre_upgrade_native_submission_without_image_history_requires_action():
    adapter, vision = CaptchaLogin(accepts=False), Vision()
    original = adapter.start()
    state = decrypt(original.sealed_state)
    state["captcha_automation"] = {"attempts": 1, "submissions": 1, "status": "recognizing",
                                   "deadline": NOW + 60}
    result = solve(adapter, replace(original, sealed_state=encrypt(state)), vision)
    automatic = decrypt(result.sealed_state)["captcha_automation"]
    assert not vision.calls and not adapter.answers
    assert automatic["attempts"] == automatic["submissions"] == 1
    assert automatic["reason"] == "captcha_answer_rejected"


def test_native_image_submission_intent_survives_a_worker_restart():
    class InterruptedLogin(CaptchaLogin):
        def advance(self, *args, **kwargs):
            raise RuntimeError("interrupted after submission intent")

    first, vision = InterruptedLogin(accepts=False), Vision()
    original = first.start()
    with pytest.raises(RuntimeError, match="interrupted after submission intent"):
        solve(first, original, vision)
    checkpoint = first.events[-1]
    stored = decrypt(checkpoint.sealed_state)
    assert stored["captcha_automation"]["submissions"] == 1
    restarted, new_provider = CaptchaLogin(accepts=False), Vision()
    result = solve(restarted, replace(original, sealed_state=checkpoint.sealed_state,
                                     revision=stored["revision"]), new_provider)
    assert not new_provider.calls and not restarted.answers
    automatic = decrypt(result.sealed_state)["captcha_automation"]
    assert automatic["reason"] == "captcha_answer_rejected"
    assert automatic["attempts"] == automatic["submissions"] == 1
    assert automatic["deadline"] == stored["captcha_automation"]["deadline"]


def test_previously_submitted_native_image_is_not_reused_after_another_image():
    class CyclingImages(CaptchaLogin):
        def challenge_image(self, sealed_state, revision):
            return SimpleNamespace(content=b"first" if len(self.answers) % 2 == 0 else b"second",
                                   content_type="image/png")

    adapter, vision = CyclingImages(accepts=False), Vision()
    result = solve(adapter, adapter.start(), vision)
    assert len(vision.calls) == len(adapter.answers) == 2
    assert decrypt(result.sealed_state)["captcha_automation"]["reason"] == "captcha_answer_rejected"


@pytest.mark.parametrize("limit", [1, 3, 6])
def test_rejected_answers_stop_at_configured_limit_and_preserve_manual_challenge(monkeypatch, limit):
    from app.config import settings

    monkeypatch.setattr(settings, "captcha_max_attempts", limit)
    adapter, vision = RefreshingCaptchaLogin(accepts=False), Vision()
    progress = solve(adapter, adapter.start(), vision)
    assert progress.status == "challenge" and len(adapter.answers) == len(vision.calls) == limit
    assert "captcha_verified" not in [event.event for event in adapter.events]
    state = decrypt(progress.sealed_state)
    assert state["captcha_automation"]["status"] == "requires_action"
    assert state["challenge"]["kind"] == "image"
    # A worker restart must not silently reset the attempt count.
    again = solve(adapter, progress, vision)
    assert again.status == "challenge" and len(vision.calls) == limit


def test_native_image_can_succeed_on_first_attempt_plus_five_retries():
    class SixthAnswerLogin(RefreshingCaptchaLogin):
        def _advance(self, state, answer):
            self.accepts = len(self.answers) == 5
            return super()._advance(state, answer)

    adapter, vision = SixthAnswerLogin(), Vision()
    progress = solve(adapter, adapter.start(), vision)
    automatic = decrypt(progress.sealed_state)["captcha_automation"]
    assert progress.status == "ready" and automatic["status"] == "verified"
    assert automatic["attempts"] == automatic["submissions"] == len(vision.calls) == 6
    verified = [event for event in adapter.events if event.event == "captcha_verified"]
    assert len(verified) == 1
    assert decrypt(verified[0].sealed_state)["captcha_automation"]["submissions"] == 6


def test_restart_replacement_image_and_new_provider_share_original_six_attempt_budget():
    class InterruptedVision(Vision):
        def recognize(self, *args, **kwargs):
            answer = super().recognize(*args, **kwargs)
            if len(self.calls) == 3:
                raise RuntimeError("worker interrupted after recognition checkpoint")
            return answer

    first, first_vision = RefreshingCaptchaLogin(accepts=False), InterruptedVision()
    original = first.start()
    with pytest.raises(RuntimeError, match="worker interrupted"):
        solve(first, original, first_vision)
    checkpoint = first.events[-1]
    stored = decrypt(checkpoint.sealed_state)
    assert stored["captcha_automation"]["attempts"] == 3
    original_deadline = stored["captcha_automation"]["deadline"]

    restarted, new_provider = RefreshingCaptchaLogin(accepts=False), Vision()
    restarted.clock = lambda: NOW + 20
    previous_challenge = stored["challenge"]["id"]
    restarted._challenge(stored, {"captchaURL": "https://us-east-1.signin.aws/platform/captcha/replacement", "captchaCES": "replacement-ces"})
    assert stored["challenge"]["id"] != previous_challenge
    restored = restarted._publish(stored)
    result = solve(restarted, restored, new_provider)
    automatic = decrypt(result.sealed_state)["captcha_automation"]
    assert automatic["status"] == "requires_action" and automatic["reason"] == "captcha_attempt_limit"
    assert automatic["last_failure_code"] == "captcha_answer_rejected"
    assert automatic["deadline"] == original_deadline == NOW + 60
    assert automatic["attempts"] == len(first_vision.calls) + len(new_provider.calls) == 6
    assert len(new_provider.calls) == 3
    assert "captcha_verified" not in [event.event for event in restarted.events]

    another_provider = Vision()
    assert solve(CaptchaLogin(), result, another_provider).status == "challenge"
    assert not another_provider.calls


def test_six_attempt_budget_cannot_extend_original_sixty_second_deadline():
    clock = [NOW]
    adapter = RefreshingCaptchaLogin(accepts=False)
    adapter.clock = lambda: clock[0]

    class SlowVision(Vision):
        def recognize(self, *args, **kwargs):
            answer = super().recognize(*args, **kwargs)
            clock[0] += 30
            return answer

    vision = SlowVision()
    result = solve(adapter, adapter.start(), vision)
    automatic = decrypt(result.sealed_state)["captcha_automation"]
    assert automatic["deadline"] == NOW + 60
    assert automatic["status"] == "requires_action" and automatic["reason"] == "captcha_timeout"
    assert automatic["attempts"] == len(vision.calls) == 2
    assert len(adapter.answers) == 1 and "captcha_verified" not in [event.event for event in adapter.events]
    restarted, new_provider = CaptchaLogin(), Vision()
    restarted.clock = lambda: NOW + 61
    assert solve(restarted, result, new_provider).status == "challenge"
    assert not new_provider.calls


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
    assert len(vision.calls) == 6
    assert "captcha_verified" not in [event.event for event in adapter.events]
    automatic = decrypt(progress.sealed_state)["captcha_automation"]
    assert automatic["reason"] == "captcha_attempt_limit"
    assert automatic["last_failure_code"] == "captcha_provider_failed"


def test_expired_overall_budget_does_not_repeat_provider_after_restart():
    adapter, vision = CaptchaLogin(), Vision()
    progress = adapter.start()
    state = decrypt(progress.sealed_state)
    state["captcha_automation"] = {"attempts": 1, "deadline": NOW - 1, "status": "recognizing"}
    progress = replace(progress, sealed_state=encrypt(state))
    result = solve(adapter, progress, vision)
    assert result.status == "challenge" and not vision.calls and not adapter.answers
    assert decrypt(result.sealed_state)["captcha_automation"]["reason"] == "captcha_timeout"


def test_missing_personal_provider_has_safe_configuration_reason(monkeypatch):
    from app.auth_automation import automate_challenge
    monkeypatch.setattr("app.ai_settings.provider_for_actor", lambda actor: None)
    adapter = CaptchaLogin()
    progress = automate_challenge(adapter, adapter.start(), actor_id=2)
    automatic = decrypt(progress.sealed_state).get("captcha_automation", {})
    assert automatic.get("reason") == "captcha_unavailable"
    assert automatic["attempts"] == automatic["submissions"] == 0
    assert not adapter.answers


def test_rejected_native_answers_keep_safe_rejection_code_at_limit():
    adapter = RefreshingCaptchaLogin(accepts=False)
    progress = solve(adapter, adapter.start(), Vision())
    automatic = decrypt(progress.sealed_state)["captcha_automation"]
    assert automatic["reason"] == "captcha_attempt_limit"
    assert automatic["last_failure_code"] == "captcha_answer_rejected"
    assert automatic["attempts"] == automatic["submissions"] == 6


def test_ams_limit_preserves_safe_provider_reason_without_raw_exception():
    from app.captcha_browser import BrowserChallengeError
    adapter = CaptchaLogin()
    def browser(challenge, gateway, provider, *, deadline, before_recognition):
        for _ in range(3):
            before_recognition()
        error = BrowserChallengeError("captcha_attempt_limit")
        error.last_failure_code = "captcha_provider_failed"
        raise error
    progress = solve(adapter, adapter.start(ams=True), Vision(), browser_solver=browser)
    automatic = decrypt(progress.sealed_state)["captcha_automation"]
    assert automatic["reason"] == "captcha_attempt_limit"
    assert automatic["last_failure_code"] == "captcha_provider_failed"
    assert automatic["attempts"] == 3 and automatic["submissions"] == 0


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


def test_no_ocr_widget_rejections_are_still_limited_to_six_submissions():
    class SilentWidgetLogin(CaptchaLogin):
        def _advance(self, state, answer):
            self.answers.append(answer)
            self._challenge(state, {"captchaToken": ams_token(), "captchaCDN": CDN})
    adapter, vision, calls = SilentWidgetLogin(), Vision(), []
    def widget(challenge, gateway, provider, **kwargs):
        calls.append(1)
        return "official-code"
    result = solve(adapter, adapter.start(ams=True), vision, browser_solver=widget)
    assert result.status == "challenge" and len(calls) == len(adapter.answers) == 6
    state = decrypt(result.sealed_state)
    assert state["captcha_automation"]["submissions"] == 6
    assert state["captcha_automation"]["attempts"] == 0
    assert "captcha_recognizing" not in [event.event for event in adapter.events]
