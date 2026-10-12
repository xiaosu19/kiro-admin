"""Bounded auth steps with durable pre-wire checkpoints and same-server fencing.

The OS lock covers exactly one adapter step, so duplicate worker processes never
issue overlapping writes, even after an expired DB lease. API cancellation never
releases a running operation. A dead process releases the OS lock; its successor
inspects the persisted pending intent and refuses to replay password/OTP writes.
Every network call runs outside a SQLAlchemy session/transaction.
"""

import logging
import time
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy import and_, or_, select, update

from .account_dispatcher import account_fence, record_scope, resource_fence
from .auth_batches import (
    check_expiry,
    expire_challenge,
    finish_batch,
    jobs,
    require_access,
)
from .auth_credentials import (
    apply_credential,
    clear_secret,
    invalidate_credentials,
    random_password,
    reset_one_time_password,
)
from .aws import AwsGateway
from .config import settings
from .database import SessionLocal
from .enterprise_auth import EnterpriseAuth
from .identity_login import AuthError, NativeIdentityLogin
from .models import (
    AuthBatch,
    AuthJob,
    AuthSecret,
    AwsAccount,
    RecordOperation,
    Subscription,
    User,
    now,
)
from .security import audit, decrypt, encrypt
from .automatic_retries import ready_clause, schedule_retry, settle_retry
from .captcha_errors import captcha_failure

logger = logging.getLogger("kiro.auth")


class LeaseLost(Exception):
    pass


class Revoked(Exception):
    pass


# Compatibility name; authentication and provisioning use the same account fence.
worker_lock = account_fence


_expiry_cursor = None


def expire_batches(*, limit=25):
    global _expiry_cursor
    if limit < 1:
        return
    with SessionLocal() as db:
        query = select(AuthBatch.id).where(AuthBatch.state == "active").order_by(AuthBatch.id)
        ids = list(db.scalars(query.where(AuthBatch.id > _expiry_cursor).limit(limit))) if _expiry_cursor else []
        if not ids:
            ids = list(db.scalars(query.limit(limit)))
        if not ids:
            _expiry_cursor = None
            return
        _expiry_cursor = ids[-1]
        db.execute(
            update(AuthBatch)
            .where(AuthBatch.id.in_(ids), AuthBatch.state == "active")
            .values(state=AuthBatch.state)
        )
        for batch in db.scalars(select(AuthBatch).where(AuthBatch.id.in_(ids), AuthBatch.state == "active")):
            if not check_expiry(db, batch):
                continue
            for job in jobs(db, batch):
                op, secret = db.get(RecordOperation, job.id), db.get(AuthSecret, job.id)
                if op.state == "challenge" and secret.workflow_encrypted:
                    state = decrypt(secret.workflow_encrypted)
                    if time.time() >= state.get("challenge", {}).get("expires_at", 0):
                        expire_challenge(db, job, op, secret)
            finish_batch(db, batch)
        db.commit()


def eligible_jobs(*, account_id=None, record_id=None):
    eligible = or_(
            RecordOperation.state == "queued",
            and_(RecordOperation.state == "polling", RecordOperation.id.in_(
                select(AuthJob.id).where(AuthJob.next_poll_at <= now()))),
            and_(
                RecordOperation.state == "running", RecordOperation.lease_until < now()
            ),
        )
    eligible = and_(eligible, record_scope(account_id), ready_clause("auth", RecordOperation.id))
    if record_id is not None:
        eligible = and_(eligible, RecordOperation.record_id == record_id)
    return eligible


def candidate_tasks(*, account_id=None, record_id=None):
    with SessionLocal() as db:
        query = (select(Subscription.aws_account_id, Subscription.id)
                 .join(RecordOperation, RecordOperation.record_id == Subscription.id)
                 .join(AuthJob, AuthJob.id == RecordOperation.id)
                 .where(eligible_jobs(account_id=account_id, record_id=record_id))
                 .order_by(RecordOperation.created_at, AuthJob.position))
        return [(aid, 'auth', rid) for aid, rid in db.execute(query)]


def claim_job(*, account_id=None, record_id=None):
    with SessionLocal() as db:
        eligible = eligible_jobs(account_id=account_id, record_id=record_id)
        job = db.scalar(
            select(AuthJob)
            .join(RecordOperation, RecordOperation.id == AuthJob.id)
            .where(eligible)
            .order_by(RecordOperation.created_at, AuthJob.position)
            .limit(1)
        )
        if not job:
            return None
        op = db.get(RecordOperation, job.id)
        token = str(uuid.uuid4())
        changed = db.execute(
            update(RecordOperation)
            .where(
                RecordOperation.id == job.id,
                eligible,
                RecordOperation.state == op.state,
                RecordOperation.lease_token == op.lease_token,
            )
            .values(
                state="running",
                lease_token=token,
                lease_until=now()
                + timedelta(seconds=settings.auth_worker_lease_seconds),
                attempts=RecordOperation.attempts + 1,
            )
        )
        db.commit()
        return (job.id, token) if changed.rowcount else None


def load(db, job_id, token):
    op, job = db.get(RecordOperation, job_id), db.get(AuthJob, job_id)
    if not op or not job or op.state != "running" or op.lease_token != token:
        raise LeaseLost()
    r = db.get(Subscription, job.record_id)
    if (
        r.active_operation_id != job.id
        or r.credential_revision != job.credential_revision
    ):
        raise LeaseLost()
    return job, op, r, db.get(AuthBatch, job.batch_id), db.get(AuthSecret, job.id)


def authorize(job_id, token):
    with SessionLocal() as db:
        job, op, r, batch, secret = load(db, job_id, token)
        if job.cancel_requested or batch.state != "active" or now() >= batch.expires_at:
            raise Revoked()
        try:
            require_access(db, batch, r, job=job)
        except HTTPException:
            raise Revoked() from None


def lease(db, job_id, token):
    changed = db.execute(
        update(RecordOperation)
        .where(
            RecordOperation.id == job_id,
            RecordOperation.lease_token == token,
            RecordOperation.state == "running",
        )
        .values(
            lease_until=now() + timedelta(seconds=settings.auth_worker_lease_seconds)
        )
    )
    if not changed.rowcount:
        raise LeaseLost()


def checkpoint(job_id, token, value):
    state = decrypt(value.sealed_state)
    with SessionLocal() as db:
        lease(db, job_id, token)
        job, op, r, batch, secret = load(db, job_id, token)
        # Persist confirmed passwords even after session revocation/cancellation.
        if value.credential:
            credential = decrypt(value.credential)
            if (
                credential.get("username") != r.username
                or credential.get("expected_user_id") != r.sso_user_id
            ):
                raise LeaseLost()
            if value.event == "password_pending" and r.credential_state != "unknown":
                recovery = value.credential
                invalidate_credentials(db, r, except_job=job.id)
                r.credential_recovery_encrypted = recovery
            apply_credential(r, value.credential)
            if value.event == "external_authorization":
                # An official browser may have replaced either saved password.
                # Preserve this outcome even if cancellation raced the checkpoint.
                r.credential_recovery_encrypted = None
        if not job.cancel_requested and batch.state == "active":
            secret.workflow_encrypted = value.sealed_state
            if value.event == "external_authorization":
                # The adapter has validated and consumed this revision-bound
                # continuation. Commit its consumption with the poll transition
                # so a restarted worker cannot replay it against no challenge.
                secret.answer_encrypted = None
        job.revision = state["revision"]
        job.stage = value.event if value.event in {"captcha_recognizing", "captcha_verified"} else state["stage"]
        op.phase = "pending" if state.get("inflight") else "ready"
        db.commit()
    # Callback returns only after commit; no request proceeds under revoked rights.
    authorize(job_id, token)


def finish_step(job_id, token, progress):
    with SessionLocal() as db:
        lease(db, job_id, token)
        job, op, r, batch, secret = load(db, job_id, token)
        settle_retry(db, "auth", job_id)
        try:
            require_access(db, batch, r, job=job)
            permitted = True
        except HTTPException:
            permitted = False
        if (
            job.cancel_requested
            or batch.state != "active"
            or not permitted
            or now() >= batch.expires_at
        ):
            clear_secret(secret)
            op.state = "cancelled"
            job.error_code = "revoked"
            op.error = "批次已取消或操作者权限已失效"
            r.active_operation_id = None
        else:
            secret.workflow_encrypted = progress.sealed_state
            secret.answer_encrypted = None
            job.revision, job.stage = progress.revision, progress.stage
            automatic = decrypt(progress.sealed_state).get("captcha_automation", {})
            if progress.status == "challenge" and automatic.get("status") == "requires_action":
                job.error_code, op.error = captcha_failure(automatic)
            else:
                job.error_code = op.error = None
            job.next_poll_at = (
                datetime.fromtimestamp(progress.next_poll_at, timezone.utc).replace(
                    tzinfo=None
                )
                if progress.next_poll_at is not None
                else None
            )
            op.state = {
                "ready": "queued",
                "done": "completed",
                "challenge": "challenge",
                "polling": "polling",
            }[progress.status]
            op.phase = "done" if op.state == "completed" else "ready"
            if op.state == "completed":
                if batch.kind == "json_export":
                    # Validate once before storing; a failed profile cannot be exported.
                    from .auth_export import account_json

                    account_json(r, progress.result)
                    secret.result_encrypted = encrypt(progress.result)
                else:
                    secret.workflow_encrypted = None
                secret.payload_encrypted = None
                r.active_operation_id = None
                audit(
                    db,
                    db.get(User, batch.actor_id),
                    "auth_item_completed",
                    f"认证任务 {job.id}；类型 {batch.kind}；凭据状态 {r.credential_state}",
                    subject=r.owner_id,
                )
        op.lease_token = op.lease_until = None
        if op.state in ("completed", "cancelled"):
            op.finished_at = now()
        finish_batch(db, batch)
        db.commit()


def retry_state(error, secret):
    """Resume only a confirmed read step; never clear an uncertain send intent."""
    if not isinstance(error, AuthError) or error.uncertain:
        return None
    sealed = error.sealed_state or secret.workflow_encrypted
    if not sealed:
        return None
    state = decrypt(sealed)
    if (not isinstance(state, dict) or state.get("inflight")
            or state.get("password_write_pending") or state.get("challenge")
            or state.get("credential", {}).get("status") == "unknown"
            or state.get("expires_at", 0) <= time.time()):
        return None
    if state.get("status") not in ("ready", "failed"):
        return None
    state["status"] = "ready"
    return encrypt(state)


def fail_job(job_id, token, error, *, revoked=False):
    with SessionLocal() as db:
        lease(db, job_id, token)
        job, op, r, batch, secret = load(db, job_id, token)
        if isinstance(error, AuthError) and error.credential:
            apply_credential(r, error.credential)
        try:
            require_access(db, batch, r, job=job)
        except HTTPException:
            revoked = True
        cancelled = revoked or job.cancel_requested or batch.state != "active" or now() >= batch.expires_at
        if cancelled:
            clear_secret(secret)
            op.state, op.error, job.error_code = (
                "cancelled",
                "批次已取消或操作者权限已失效",
                "revoked",
            )
        else:
            if isinstance(error, AuthError) and error.sealed_state:
                secret.workflow_encrypted = error.sealed_state
            uncertain = r.credential_state == "unknown" or job.reset_state == "pending"
            resumed = retry_state(error, secret) if not uncertain else None
            if resumed and schedule_retry(db, "auth", job_id, error):
                secret.workflow_encrypted = resumed
                secret.answer_encrypted = secret.result_encrypted = None
                op.state, op.phase, op.error = "queued", "ready", str(error)
                job.error_code = error.code
                op.lease_token = op.lease_until = op.finished_at = None
                db.commit()
                return
            op.state = "needs_review" if uncertain else "failed"
            job.error_code = (
                "reset_unconfirmed"
                if job.reset_state == "pending"
                else error.code
                if isinstance(error, AuthError)
                else "authentication_failed"
            )
            op.error = (
                "一次性密码重置结果未保存；请明确选择再次重置以生成新密码"
                if job.reset_state == "pending"
                else str(error)
                if isinstance(error, AuthError)
                else "认证处理失败，请检查账号与代理后重试"
            )
        secret.answer_encrypted = secret.result_encrypted = None
        settle_retry(db, "auth", job_id)
        if op.state != "needs_review":
            r.active_operation_id = None
        op.lease_token = op.lease_until = None
        op.finished_at = now()
        finish_batch(db, batch)
        audit(
            db,
            db.get(User, batch.actor_id),
            "auth_item_" + op.state,
            f"认证任务 {job.id}；错误代码 {job.error_code}；凭据状态 {r.credential_state}",
            subject=r.owner_id,
        )
        db.commit()


def _run_claimed(job_id, token, gateway_factory, auth_factory, identity_factory):
    adapter, gateway = None, None
    try:
        authorize(job_id, token)
        with SessionLocal() as db:
            job, op, r, batch, secret = load(db, job_id, token)
            _, account = require_access(db, batch, r, job=job)
            reset_state, kind = job.reset_state, batch.kind
            actor_id = batch.actor_id
            stage = job.stage
            sealed, answer = (
                secret.workflow_encrypted,
                decrypt(secret.answer_encrypted) if secret.answer_encrypted else None,
            )
            password = decrypt(r.password_encrypted) if r.password_encrypted else None
            recovery = (
                r.credential_recovery_encrypted
                if r.credential_state == "unknown"
                else None
            )
            target = (
                decrypt(secret.payload_encrypted).get("password")
                if secret.payload_encrypted
                else None
            )
            db.expunge(account)
            db.expunge(r)
        gateway = gateway_factory(account)
        original_guard = gateway._check_proxy

        def guard():
            authorize(job_id, token)
            original_guard()

        gateway._check_proxy = guard
        guard()
        if reset_state == "pending":
            raise AuthError("interrupted", uncertain=True)
        if reset_state == "required":

            def before_reset():
                authorize(job_id, token)
                with SessionLocal() as db:
                    lease(db, job_id, token)
                    j, o, record, b, s = load(db, job_id, token)
                    invalidate_credentials(db, record, except_job=j.id)
                    j.reset_state, o.phase = "pending", "pending"
                    db.commit()
                guard()

            password = reset_one_time_password(gateway, r, before_reset)
            with SessionLocal() as db:
                lease(db, job_id, token)
                j, o, record, b, s = load(db, job_id, token)
                record.password_encrypted, record.password_generated_at = (
                    encrypt(password),
                    now(),
                )
                record.credential_state, j.reset_state, o.phase = (
                    "one_time",
                    "done",
                    "ready",
                )
                record.credential_recovery_encrypted = None
                db.commit()
            authorize(job_id, token)
            reset_state = "done"
            recovery, sealed = None, None
        if kind == "reset_password" and reset_state == "done":
            from .identity_login import AuthProgress

            finish_step(job_id, token, AuthProgress("done", encrypt({}), stage="done"))
            return
        if not sealed and not password:
            if recovery:
                password = decrypt(recovery)["current"]
            else:
                raise AuthError("invalid_state")
        factory = auth_factory if kind == "json_export" else identity_factory
        adapter = factory(gateway, checkpoint=lambda cp: checkpoint(job_id, token, cp))
        if sealed and stage == "refresh_requested":
            progress = adapter.begin_refresh(sealed)
        elif not sealed:
            if kind in ("random_password", "custom_password") and not recovery:
                target = target or random_password()
                with SessionLocal() as db:
                    lease(db, job_id, token)
                    j, o, record, b, s = load(db, job_id, token)
                    s.payload_encrypted = encrypt({"password": target})
                    db.commit()
            kwargs = {
                "expected_user_id": r.sso_user_id,
                "target_password": target,
                "recovery": recovery,
            }
            if kind != "json_export":
                kwargs["password_only"] = True
            progress = adapter.begin(r.username, password, **kwargs)
        else:
            progress = adapter.advance(sealed, answer=answer)
        from .auth_automation import automate_challenge

        progress = automate_challenge(adapter, progress, actor_id=actor_id)
        finish_step(job_id, token, progress)
    except LeaseLost:
        # Another revision is authoritative; never overwrite its credentials/results.
        return
    except Revoked as error:
        fail_job(job_id, token, error, revoked=True)
    except Exception as error:
        # Unknown exceptions are always fixed public messages; never log token data.
        try:
            fail_job(job_id, token, error)
        except LeaseLost:
            pass
    finally:
        if adapter and hasattr(adapter, "close"):
            adapter.close()
        if gateway and hasattr(gateway, "identity"):
            gateway.identity.close()


def run_one(
    gateway_factory=None,
    auth_factory=None,
    identity_factory=None,
    *,
    account_id=None,
    record_id=None,
    maintenance=True,
):
    if maintenance:
        expire_batches()

    from .auth_principals import login_key
    for aid, _, rid in candidate_tasks(account_id=account_id, record_id=record_id):
        with account_fence(aid, shared=True) as account_acquired:
            if not account_acquired:
                continue
            with resource_fence('record', rid) as record_acquired:
                if not record_acquired:
                    continue
                with SessionLocal() as db:
                    record = db.get(Subscription, rid)
                    account = db.get(AwsAccount, aid)
                    if not record or not account:
                        continue
                    key = login_key(account.identity_store_id, record.username)
                with resource_fence('login', key) as login_acquired:
                    if not login_acquired:
                        continue
                    claimed = claim_job(account_id=aid, record_id=rid)
                    if not claimed:
                        continue
                    _run_claimed(*claimed, gateway_factory or AwsGateway,
                                 auth_factory or EnterpriseAuth, identity_factory or NativeIdentityLogin)
                    return True
    return False
