"""Explicitly abandon a settled image challenge without replaying a password write."""

from cryptography.fernet import InvalidToken

from .security import decrypt

RESTARTABLE_CAPTCHA_ERRORS = frozenset({
    "captcha_timeout", "captcha_attempt_limit", "captcha_limit", "captcha_answer_rejected",
    "captcha_browser_failed", "captcha_provider_failed", "captcha_invalid_response",
    "captcha_unavailable", "captcha_invalid_configuration",
    "captcha_invalid_image", "captcha_browser_unavailable", "captcha_failed",
    "captcha_provider_auth", "captcha_provider_balance", "captcha_provider_rate_limit",
})

# A new isolated login may replace a settled challenge, but must never replay a
# password write or retry permanent provider/configuration failures automatically.
AUTOMATIC_CAPTCHA_ERRORS = frozenset({
    "captcha_timeout", "captcha_attempt_limit", "captcha_limit", "captcha_answer_rejected",
    "captcha_browser_failed", "captcha_provider_failed", "captcha_provider_rate_limit",
    "captcha_invalid_response", "captcha_invalid_image",
})


def automatic_challenge_reason(sealed):
    if not restartable_challenge(sealed):
        return None
    state = decrypt(sealed)
    automatic = state.get("captcha_automation", {})
    reason = automatic.get("reason")
    last = automatic.get("last_failure_code")
    if (reason not in AUTOMATIC_CAPTCHA_ERRORS
            or last and last not in AUTOMATIC_CAPTCHA_ERRORS
            or state.get("external_authorization") or state.get("refresh_only")):
        return None
    return last or reason


def record_captcha_outcome(db, actor, family, job_id, sealed):
    """Keep small diagnostic facts after secret checkpoints have expired."""
    import json
    from .security import audit, encrypt
    from .captcha_errors import safe_captcha_code
    state = decrypt(sealed)
    automatic = state.get("captcha_automation", {})
    status = automatic.get("status")
    if status not in ("requires_action", "verified") or automatic.get("reported"):
        return sealed
    facts = {"family": family, "job_id": job_id, "status": status}
    for key in ("attempts", "submissions"):
        value = automatic.get(key)
        if isinstance(value, int) and 0 <= value <= 1000:
            facts[key] = value
    for key in ("reason", "last_failure_code"):
        if automatic.get(key):
            facts[key] = safe_captcha_code(automatic[key])
    audit(db, actor, "auth_captcha_result", json.dumps(facts))
    automatic["reported"] = True
    return encrypt(state)


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


def can_resume(job, operation, record, secret):
    """Display-only capability; the retry endpoint rechecks current authority."""
    if (not all((job, operation, record, secret)) or job.cancel_requested
            or job.reset_state == 'pending' or record.credential_state == 'unknown'
            or record.active_operation_id not in (None, job.id)):
        return False
    if operation.state == 'challenge':
        return (record.credential_revision == job.credential_revision
                and restartable_challenge(secret.workflow_encrypted))
    if operation.state not in ('failed', 'needs_review'):
        return False
    if record.credential_revision != job.credential_revision:
        return (record.credential_state == 'permanent' and bool(record.password_encrypted)
                and not record.credential_recovery_encrypted)
    try:
        state = decrypt(secret.workflow_encrypted) if secret.workflow_encrypted else {}
        return job.error_code == 'token_expired' or not (job.stage == 'refresh_requested' or state.get('refresh_only'))
    except (InvalidToken, ValueError, TypeError, AttributeError):
        return False
