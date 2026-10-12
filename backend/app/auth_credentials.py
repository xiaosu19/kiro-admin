"""Record credentials outlive short-lived exports, including uncertain candidates."""

import hashlib
import hmac
import json
import secrets
import string

from sqlalchemy import select

from .config import settings
from .models import AuthJob, AuthSecret, RecordOperation, now
from .security import decrypt, encrypt

AUTH_KINDS = (
    "auth_json_export",
    "auth_reset_password",
    "auth_random_password",
    "auth_custom_password",
)


def fingerprint(value):
    # A plain digest of a shared password is an offline dictionary oracle.
    return hmac.new(
        settings.secret_key.encode(),
        b"kiro-auth-v1\0"
        + json.dumps(value, sort_keys=True, separators=(",", ":")).encode(),
        hashlib.sha256,
    ).hexdigest()


def account_fingerprint(a):
    return fingerprint(
        {
            key: getattr(a, key)
            for key in (
                "id",
                "aws_account_id",
                "region",
                "subscription_region",
                "identity_store_id",
                "instance_arn",
                "profile_arn",
                "portal_url",
                "proxy_id",
                "credentials_encrypted",
            )
        }
    )


def password_valid(value):
    return (
        isinstance(value, str)
        and 8 <= len(value) <= 64
        and all(32 < ord(c) < 127 for c in value)
        and any(c.isupper() for c in value)
        and any(c.islower() for c in value)
        and any(c.isdigit() for c in value)
        and any(c in string.punctuation for c in value)
    )


def random_password():
    chars = string.ascii_letters + string.digits + "!@#$%_-+"
    while True:
        value = "".join(secrets.choice(chars) for _ in range(24))
        if password_valid(value):
            return value


def clear_secret(secret):
    if secret:
        secret.payload_encrypted = secret.workflow_encrypted = None
        secret.answer_encrypted = secret.result_encrypted = None


def invalidate_credentials(db, r, *, except_job=None, clear_password=True):
    """Fence old results; retain unresolved recovery until AWS confirms a write."""
    r.credential_revision += 1
    if clear_password:
        r.credential_state = "unknown"
        r.password_encrypted = r.password_generated_at = None
    for job in db.scalars(select(AuthJob).where(AuthJob.record_id == r.id)):
        if job.id == except_job:
            job.credential_revision = r.credential_revision
            continue
        clear_secret(db.get(AuthSecret, job.id))
        job.error_code = "credential_changed"
        op = db.get(RecordOperation, job.id)
        if op.state == "completed":
            op.state = "expired"
            op.error = "登录凭据已更新，旧结果已失效"


def apply_credential(r, encrypted):
    """Only adapter-confirmed current credentials are ever exposed by the console."""
    value = decrypt(encrypted)
    if not isinstance(value, dict) or value.get("status") not in (
        "current",
        "candidate",
        "unknown",
        "confirmed",
    ):
        raise ValueError("invalid credential checkpoint")
    if value.get("candidate"):
        r.credential_recovery_encrypted = encrypted
    if value["status"] == "unknown":
        r.credential_state = "unknown"
    elif value["status"] == "confirmed":
        current = value.get("current")
        if not isinstance(current, str) or not current:
            raise ValueError("invalid confirmed credential")
        r.password_encrypted = encrypt(current)
        r.credential_state = "permanent"
        r.password_generated_at = now()
        r.credential_recovery_encrypted = None
    return value["status"]


def known_password(r):
    return (
        decrypt(r.password_encrypted)
        if (
            r.password_encrypted
            and r.credential_state in ("one_time", "permanent")
            and not r.sso_deleted_at
        )
        else None
    )


def reset_one_time_password(gateway, record, before_send):
    """The existing Identity Center OTP reset, with a durable caller-owned intent."""
    from .aws import AwsFailure

    if gateway.user_info(record) is None:
        raise AwsFailure("AWS 中已找不到该 SSO 用户，请同步状态")
    before_send()
    return gateway.password(record)
