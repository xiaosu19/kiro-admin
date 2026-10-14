"""Explicitly abandon a settled image challenge without replaying a password write."""

from cryptography.fernet import InvalidToken

from .security import decrypt

RESTARTABLE_CAPTCHA_ERRORS = frozenset({
    "captcha_timeout", "captcha_attempt_limit", "captcha_limit", "captcha_answer_rejected",
    "captcha_browser_failed", "captcha_provider_failed", "captcha_invalid_response",
    "captcha_unavailable", "captcha_invalid_configuration",
    "captcha_invalid_image", "captcha_browser_unavailable", "captcha_failed",
})


def restartable_challenge(sealed):
    if not sealed:
        return False
    try:
        state = decrypt(sealed)
        automation, challenge = state.get("captcha_automation", {}), state.get("challenge", {})
        if challenge.get("kind") == "aws_authorization":
            native = state.get("automation_challenge") or {}
            if (native.get("id"), native.get("revision")) != (challenge.get("id"), challenge.get("revision")):
                return False
            challenge = native
        credential = state.get("credential", {})
        return bool(
            automation.get("status") == "requires_action"
            and automation.get("reason") in RESTARTABLE_CAPTCHA_ERRORS
            and challenge.get("kind") in ("image", "ams")
            and not state.get("password_write_pending")
            and not state.get("inflight")
            and credential.get("status") not in ("unknown", "candidate")
        )
    except (InvalidToken, ValueError, TypeError, AttributeError):
        return False
