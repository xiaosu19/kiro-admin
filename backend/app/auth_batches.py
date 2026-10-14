"""Actor-private authentication batches over explicitly frozen SSO record IDs."""

import json
import time
import uuid
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .auth_credentials import (
    account_fingerprint,
    clear_secret,
    fingerprint,
    invalidate_credentials,
    password_valid,
)
from .config import settings
from .auth_retry import restartable_challenge
from .database import get_db
from .lifecycle import allowed, owned, validate_operation
from .models import (
    AuthBatch,
    AuthJob,
    AuthSecret,
    AwsAccount,
    ManagedGroup,
    RecordOperation,
    Subscription,
    User,
    now,
)
from .security import audit, encrypt, get_user
from .subscription_eligibility import SUBSCRIPTION_REQUIRED, has_confirmed_subscription_access

router = APIRouter(prefix="/api/auth-batches")
KINDS = Literal["json_export", "reset_password", "random_password", "custom_password"]
TERMINAL = ("completed", "failed", "needs_review", "cancelled", "expired")
STATES = ("queued", "running", "challenge", "polling") + TERMINAL


class BatchInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: KINDS
    record_ids: list[str] = Field(min_length=1, max_length=100)
    request_key: str = Field(min_length=16, max_length=80)
    group_id: str | None = Field(default=None, max_length=36)
    password: str | None = Field(default=None, repr=False)

    @model_validator(mode="after")
    def validate_intent(self):
        if len(set(self.record_ids)) != len(self.record_ids):
            raise ValueError("不能重复选择用户")
        if self.kind == "custom_password":
            if not password_valid(self.password):
                raise ValueError(
                    "密码必须为 8–64 个字符，并包含大写、小写、数字和特殊字符"
                )
        elif self.password is not None:
            raise ValueError("此操作不接受共享密码")
        return self


def jobs(db, batch):
    return list(
        db.scalars(
            select(AuthJob)
            .where(AuthJob.batch_id == batch.id)
            .order_by(AuthJob.position)
        )
    )


def batch_owned(db, batch_id, actor):
    batch = db.get(AuthBatch, batch_id)
    if not batch or batch.actor_id != actor.id:
        raise HTTPException(404, "认证批次不存在")
    return batch


def require_access(db, batch, r, *, job=None):
    actor, a = db.get(User, batch.actor_id), db.get(AwsAccount, r.aws_account_id)
    if (
        not actor
        or not a
        or actor.session_version != batch.session_version
        or actor.must_change_password
        or not allowed(db, actor, a)
        or (actor.role != "admin" and r.owner_id != actor.id)
    ):
        raise HTTPException(403, "操作者登录、记录权限或 AWS 绑定已失效")
    if job:
        from .models import ProvisioningItem
        from .provisioning_coordinator import guard
        from .models import ProvisioningAccountBatch
        item = db.get(ProvisioningItem, r.id)
        if item and item.auth_job_id == job.id:
            guard(db, db.get(ProvisioningAccountBatch, item.account_batch_id))
    if r.sso_deleted_at or not r.sso_user_id:
        raise HTTPException(409, "SSO 用户已删除或尚未就绪")
    if batch.kind == "json_export" and not has_confirmed_subscription_access(r, now()):
        raise HTTPException(409, SUBSCRIPTION_REQUIRED)
    if job and (
        r.credential_revision != job.credential_revision
        or account_fingerprint(a) != job.account_fingerprint
    ):
        raise HTTPException(409, "账号配置或登录凭据已更新，本次结果已失效")
    from .group_json_exports import require_scope
    require_scope(db, batch, r)
    return actor, a


def finish_batch(db, batch):
    if batch.state != "active":
        return
    # A batch may contain thousands of users. SQL checks unfinished operations
    # without loading every job and issuing one SELECT per completed sibling.
    unfinished = db.scalar(select(AuthJob.id).outerjoin(
        RecordOperation, RecordOperation.id == AuthJob.id
    ).where(AuthJob.batch_id == batch.id,
            (RecordOperation.id.is_(None) | RecordOperation.state.not_in(TERMINAL))).limit(1))
    if unfinished is None:
        if batch.completed_at is None:
            batch.completed_at = now()
        from .provisioning_auth_window import parent_download_window
        if not parent_download_window(db, batch, now()) and batch.download_expires_at is None:
            batch.download_expires_at = min(
                batch.expires_at,
                now() + timedelta(seconds=settings.auth_download_ttl_seconds),
            )


def close_batch(db, batch, state):
    from .automatic_retries import settle_retry
    batch.state = state
    for job in jobs(db, batch):
        job.cancel_requested = True
        settle_retry(db, 'auth', job.id)
        secret, op = db.get(AuthSecret, job.id), db.get(RecordOperation, job.id)
        clear_secret(secret)
        # A live wire write retains its lock until its worker records the outcome.
        if op.state == "running":
            continue
        if op.state not in TERMINAL:
            op.state = "expired" if state == "expired" else "cancelled"
            op.finished_at = now()
        r = db.get(Subscription, job.record_id)
        if r.active_operation_id == job.id:
            r.active_operation_id = None


def check_expiry(db, batch):
    instant = now()
    if (batch.state == 'active' and instant < batch.expires_at
            and batch.download_expires_at and instant >= batch.download_expires_at):
        # A linked user may have been retried or resumed since the deadline was
        # established. Recheck the full range before clearing successful siblings.
        from .provisioning_auth_window import parent_download_window
        parent_download_window(db, batch, instant)
    if batch.state == "active" and (
        instant >= batch.expires_at
        or (batch.download_expires_at and instant >= batch.download_expires_at)
    ):
        close_batch(db, batch, "expired")
        db.flush()
    return batch.state == "active"


def require_live(db, batch):
    if not check_expiry(db, batch):
        db.commit()
        raise HTTPException(410, "认证批次已取消、下载或过期，请创建新批次")


def item_owned(db, batch_id, record_id, actor):
    batch = batch_owned(db, batch_id, actor)
    job = db.scalar(
        select(AuthJob).where(
            AuthJob.batch_id == batch.id, AuthJob.record_id == record_id
        )
    )
    if not job:
        raise HTTPException(404, "认证任务不存在")
    r = owned(db, record_id, actor)
    require_access(db, batch, r, job=job)
    return batch, job, r, db.get(RecordOperation, job.id)


def batch_view(db, batch, details=True):
    from .automatic_retries import retry_view
    from .retry_models import AutomaticRetry
    rows = jobs(db, batch)
    op_rows = {op.id: op for op in db.scalars(select(RecordOperation).where(RecordOperation.id.in_([j.id for j in rows])))}
    ops = [op_rows[j.id] for j in rows]
    counts = {state: sum(op.state == state for op in ops) for state in STATES}
    result = {
        k: getattr(batch, k)
        for k in (
            "id",
            "actor_id",
            "kind",
            "group_id",
            "state",
            "created_at",
            "expires_at",
            "completed_at",
            "download_expires_at",
        )
    }
    result.update(
        total=len(rows),
        states=counts,
        success_count=counts["completed"],
        failure_count=sum(
            counts[k] for k in ("failed", "needs_review", "cancelled", "expired")
        ),
        download_ready=batch.kind == "json_export"
        and batch.state == "active"
        and batch.completed_at is not None
        and counts["completed"] > 0,
    )
    from .group_json_exports import batch_scope_view
    grouped_scope = batch_scope_view(db, batch, rows, ops)
    if grouped_scope:
        result['group_scope'] = grouped_scope
    if details:
        records = {r.id: r for r in db.scalars(select(Subscription).where(Subscription.id.in_([j.record_id for j in rows])))}
        retry_rows = {(r.family, r.job_id): r for r in db.scalars(select(AutomaticRetry).join(
            AuthJob, AuthJob.id == AutomaticRetry.job_id).where(AutomaticRetry.family == 'auth', AuthJob.batch_id == batch.id))}
        result["items"] = [
            {
                "record_id": j.record_id,
                "operation_id": j.id,
                "state": op.state,
                "stage": j.stage,
                "revision": j.revision,
                "next_poll_at": j.next_poll_at,
                "error": op.error,
                "error_code": j.error_code,
                "cancel_requested": j.cancel_requested,
                "can_retry_challenge": op.state == "challenge"
                and not j.cancel_requested and j.reset_state != "pending"
                and records[j.record_id].credential_state != "unknown"
                and restartable_challenge(db.get(AuthSecret, j.id).workflow_encrypted),
                **retry_view(db, 'auth', j.id, active=op.state in ('queued', 'running', 'polling'), rows=retry_rows, state=op.state),
                "username": records[j.record_id].username,
                "owner_id": records[j.record_id].owner_id,
                "credential_state": records[j.record_id].credential_state,
                "has_password": bool(records[j.record_id].password_encrypted)
                and records[j.record_id].credential_state != "unknown"
                and not records[j.record_id].sso_deleted_at,
                "requires_new_reset": j.reset_state == "pending"
                or (
                    records[j.record_id].credential_state == "unknown"
                    and not records[j.record_id].credential_recovery_encrypted
                    and not (
                        batch.kind == "json_export"
                        and j.error_code == "token_expired"
                        and db.get(AuthSecret, j.id).workflow_encrypted
                    )
                ),
            }
            for j, op in zip(rows, ops)
        ]
    return result


def validate_record(db, r, actor, kind, group=None):
    validate_operation(db, r, actor, "reset_password")
    if kind == "json_export" and not has_confirmed_subscription_access(r, now()):
        raise HTTPException(409, SUBSCRIPTION_REQUIRED)
    if r.active_operation_id:
        raise HTTPException(409, "该用户已有操作正在处理")
    if group and (
        r.group_id != group.id
        or r.owner_id != group.owner_id
        or r.aws_account_id != group.aws_account_id
    ):
        raise HTTPException(409, "用户已不属于所选分组")
    if kind == "json_export" and not (
        r.credential_recovery_encrypted
        if r.credential_state == "unknown"
        else r.password_encrypted
    ):
        raise HTTPException(409, "没有可恢复的登录凭据，请先明确重置密码")


@router.get("/preview")
def preview(
    group_id: str,
    kind: KINDS = "json_export",
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    from .groups import owned_group

    group = owned_group(db, group_id, actor)
    eligible, skipped = [], []
    rows = db.scalars(
        select(Subscription)
        .where(Subscription.group_id == group.id)
        .order_by(Subscription.id)
    )
    for r in rows:
        try:
            validate_record(db, r, actor, kind, group)
            if len(eligible) >= 100:
                raise HTTPException(409, "每批最多 100 名用户")
            eligible.append(r.id)
        except HTTPException as e:
            skipped.append(
                {"record_id": r.id, "username": r.username, "reason": e.detail}
            )
    return {
        "group_id": group.id,
        "kind": kind,
        "record_ids": eligible,
        "skipped": skipped,
    }


@router.post("", status_code=202)
def create(
    body: BatchInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    batch = admit_auth_batch(db, actor, body, request)
    db.commit()
    return batch_view(db, batch)


def admit_auth_batch(db, actor, body, request=None):
    """Caller owns the auth child/link transaction; regular HTTP behavior is unchanged."""
    from .groups import owned_group

    digest = fingerprint(body.model_dump(exclude={"request_key"}))
    old = db.scalar(
        select(AuthBatch).where(
            AuthBatch.actor_id == actor.id, AuthBatch.request_key == body.request_key
        )
    )
    if old:
        if old.fingerprint != digest:
            raise HTTPException(409, "重复请求标识与原批次内容不同")
        return old
    from .security import lock_user_write
    lock_user_write(db, actor, actor.session_version)
    group = owned_group(db, body.group_id, actor) if body.group_id else None
    records = [owned(db, rid, actor) for rid in body.record_ids]
    for r in records:
        validate_record(db, r, actor, body.kind, group)
    batch = AuthBatch(
        id=str(uuid.uuid4()),
        actor_id=actor.id,
        session_version=actor.session_version,
        request_key=body.request_key,
        fingerprint=digest,
        kind=body.kind,
        group_id=body.group_id,
        expires_at=now() + timedelta(hours=settings.auth_batch_ttl_hours),
    )
    db.add(batch)
    db.flush()
    for position, r in enumerate(records):
        oid = str(uuid.uuid4())
        changed = db.execute(
            update(Subscription)
            .where(
                Subscription.id == r.id,
                Subscription.active_operation_id.is_(None),
                Subscription.credential_revision == r.credential_revision,
            )
            .values(active_operation_id=oid, updated_at=now())
        )
        if not changed.rowcount:
            raise HTTPException(409, "该用户已有操作正在处理")
        db.add(
            RecordOperation(
                id=oid,
                record_id=r.id,
                actor_id=actor.id,
                kind="auth_" + body.kind,
                request_key=oid,
                payload=json.dumps({"batch_id": batch.id}),
            )
        )
        db.flush()
        db.add(
            AuthJob(
                id=oid,
                batch_id=batch.id,
                record_id=r.id,
                position=position,
                credential_revision=r.credential_revision,
                account_fingerprint=account_fingerprint(
                    db.get(AwsAccount, r.aws_account_id)
                ),
                reset_state="required" if body.kind != "json_export" else "none",
            )
        )
        db.flush()
        db.add(
            AuthSecret(
                job_id=oid,
                payload_encrypted=encrypt({"password": body.password})
                if body.password
                else None,
            )
        )
    audit(
        db,
        actor,
        "auth_batch_created",
        f"认证批次 {batch.id}；类型 {batch.kind}；{len(records)} 名用户",
        request=request,
    )
    return batch


@router.get("")
def listing(
    page: int = Query(1, ge=1),
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    batches = list(
        db.scalars(
            select(AuthBatch)
            .where(AuthBatch.actor_id == actor.id)
            .order_by(AuthBatch.created_at.desc())
            .offset((page - 1) * 30)
            .limit(30)
        )
    )
    for batch in batches:
        check_expiry(db, batch)
    db.commit()
    return {"items": [batch_view(db, b, False) for b in batches], "page": page}


@router.get("/{batch_id}")
def detail(
    batch_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)
):
    batch = batch_owned(db, batch_id, actor)
    check_expiry(db, batch)
    finish_batch(db, batch)
    db.commit()
    return batch_view(db, batch)


@router.post("/{batch_id}/cancel")
def cancel(
    batch_id: str,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    batch = batch_owned(db, batch_id, actor)
    close_batch(db, batch, "cancelled")
    audit(
        db, actor, "auth_batch_cancelled", f"取消认证批次 {batch.id}", request=request
    )
    db.commit()
    return batch_view(db, batch)


def zip_results(db, batch, *, refresh_expired=False):
    """Validate a terminal live batch and collect results without consuming it."""
    from .security import decrypt

    finish_batch(db, batch)
    if batch.kind != "json_export" or batch.completed_at is None:
        raise HTTPException(409, "请等待 JSON 批次处理完成后下载")
    from .group_export_models import AuthExportScope
    if refresh_expired or db.get(AuthExportScope, batch.id):
        from .auth_result_refresh import refresh_expired_results
        refresh_expired_results(db, batch)
    included, excluded = [], 0
    for job in jobs(db, batch):
        r = db.get(Subscription, job.record_id)
        require_access(db, batch, r, job=job)
        op, secret = db.get(RecordOperation, job.id), db.get(AuthSecret, job.id)
        if op.state == "completed" and secret.result_encrypted:
            if decrypt(secret.result_encrypted)["expiresAt"] <= time.time():
                secret.result_encrypted = None
                op.state, op.error, job.error_code = (
                    "failed",
                    "认证令牌已过期，请重试此用户以刷新令牌",
                    "token_expired",
                )
        if op.state == "completed" and secret.result_encrypted:
            included.append((r, secret.result_encrypted))
        else:
            excluded += 1
    return included, excluded


@router.post("/{batch_id}/download")
def download(
    batch_id: str,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    from .auth_export import build_zip

    batch = batch_owned(db, batch_id, actor)
    require_live(db, batch)
    included, excluded = zip_results(db, batch)
    if not included:
        db.commit()
        raise HTTPException(409, "没有成功的 JSON 结果可导出")
    from .group_export_models import AuthExportScope
    grouped = db.get(AuthExportScope, batch.id)
    from .provisioning_exports import archive_filename
    filename = archive_filename(batch.id)
    if grouped:
        from .group_json_exports import grouped_zip
        content = grouped_zip(db, batch, included)
        # Serialization is memory-only; revalidate authority before consumption.
        original = [(record.id, encrypted) for record, encrypted in included]
        db.expire_all()
        require_live(db, batch)
        current, current_excluded = zip_results(db, batch)
        if original != [(record.id, encrypted) for record, encrypted in current] or excluded != current_excluded:
            raise HTTPException(409, 'JSON 结果在打包期间已变化，请刷新原批次')
    elif batch.group_id:
        from .provisioning_exports import build_zip as grouped_content, safe_component
        group = db.get(ManagedGroup, batch.group_id)
        account = db.get(AwsAccount, group.aws_account_id)
        path = safe_component(account.account_number or account.aws_account_id, 'account-' + str(account.id)) + '/' + safe_component(group.name, 'group-' + group.id) + '.json'
        content = grouped_content(included, {record.id: path for record, _ in included})
    else:
        content = build_zip(included, folder=filename[:-4])
    close_batch(db, batch, "downloaded")
    audit(
        db,
        actor,
        "auth_zip_downloaded",
        f"认证批次 {batch.id}；成功 {len(included)}；排除 {excluded}",
        request=request,
    )
    db.commit()
    return Response(
        content,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Export-Count": str(len(included)),
            "X-Excluded-Count": str(excluded),
        },
    )


class AnswerInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str = Field(min_length=1, max_length=100)
    revision: int = Field(ge=1)
    guess: str | None = Field(default=None, min_length=1, max_length=128, repr=False)
    access_code: str | None = Field(
        default=None, min_length=1, max_length=8192, repr=False
    )
    continue_authorization: StrictBool | None = None

    @model_validator(mode="after")
    def one_answer(self):
        if (
            sum(
                value is not None
                for value in (self.guess, self.access_code, self.continue_authorization)
            )
            != 1
            or self.continue_authorization is False
        ):
            raise ValueError("请回答当前验证码")
        if any(
            ord(c) < 32 or ord(c) == 127 for c in (self.guess or self.access_code or "")
        ):
            raise ValueError("验证码格式无效")
        return self


class RetryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["resume", "new_reset"] = "resume"


def current_challenge(db, batch, job, op):
    from .security import decrypt

    require_live(db, batch)
    secret = db.get(AuthSecret, job.id)
    if op.state != "challenge" or not secret.workflow_encrypted or job.cancel_requested:
        raise HTTPException(409, "任务当前没有待回答验证码，请刷新任务")
    state = decrypt(secret.workflow_encrypted)
    challenge = state.get("challenge")
    if (
        challenge
        and batch.kind == "json_export"
        and challenge["kind"] in {"ams", "aws_authorization"}
    ):
        from .enterprise_auth import official_authorization_challenge
        from .identity_login import AuthError

        try:
            challenge = official_authorization_challenge(state)
        except AuthError as error:
            raise HTTPException(409, str(error)) from None
    if not challenge or time.time() >= challenge["expires_at"]:
        expire_challenge(db, job, op, secret)
        finish_batch(db, batch)
        db.commit()
        raise HTTPException(410, "验证码已过期，请重试此用户")
    return challenge, state, secret


def expire_challenge(db, job, op, secret):
    changed = db.execute(
        update(RecordOperation)
        .where(
            RecordOperation.id == op.id,
            RecordOperation.state == "challenge",
        )
        .values(state="failed", error="验证码已过期，请重试此用户", finished_at=now())
    )
    if not changed.rowcount:
        return
    secret.workflow_encrypted = secret.answer_encrypted = None
    job.error_code = "expired"
    r = db.get(Subscription, job.record_id)
    if r.credential_state != "unknown":
        r.active_operation_id = None
    else:
        op.state = "needs_review"


@router.get("/{batch_id}/items/{record_id}/challenge")
def challenge_metadata(
    batch_id: str,
    record_id: str,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    from .auth_widget import public_challenge

    batch, job, r, op = item_owned(db, batch_id, record_id, actor)
    challenge, state, secret = current_challenge(db, batch, job, op)
    if challenge["kind"] == "aws_authorization":
        public = challenge
    elif challenge["kind"] == "ams":
        public = {key: challenge[key] for key in ("id", "revision", "expires_at")}
        public.update(
            kind="manual_action",
            username=r.username,
            portal_url=state["binding"]["portal"],
        )
    else:
        public = public_challenge(challenge)
    return {"operation_id": job.id, **public}


@router.post("/{batch_id}/items/{record_id}/resume", status_code=202)
def resume(
    batch_id: str,
    record_id: str,
    body: AnswerInput,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    batch, job, r, op = item_owned(db, batch_id, record_id, actor)
    challenge, state, secret = current_challenge(db, batch, job, op)
    expected = {"image": "guess", "aws_authorization": "continue_authorization"}.get(
        challenge["kind"]
    )
    answer = body.model_dump(exclude_none=True)
    if (
        expected is None
        or (body.challenge_id, body.revision)
        != (
            challenge["id"],
            challenge["revision"],
        )
        or set(answer) != {"challenge_id", "revision", expected}
    ):
        raise HTTPException(409, "验证码版本已变化，请刷新当前任务")
    # Only one answer may win. Persist invalidation before a worker can use the
    # continuation, including when the browser loses this response or reloads.
    changed = db.execute(
        update(RecordOperation)
        .where(RecordOperation.id == op.id, RecordOperation.state == "challenge")
        .values(state="queued")
    )
    if not changed.rowcount:
        raise HTTPException(409, "验证码版本已变化，请刷新当前任务")
    if expected == "continue_authorization":
        from .enterprise_auth import forget_external_password

        invalidate_credentials(db, r, except_job=job.id)
        r.credential_recovery_encrypted = None
        forget_external_password(state)
        secret.workflow_encrypted = encrypt(state)
        secret.payload_encrypted = secret.result_encrypted = None
    secret.answer_encrypted = encrypt(answer)
    op.state = "queued"
    job.next_poll_at = None
    db.commit()
    return {"operation_id": job.id, "state": op.state}


@router.post("/{batch_id}/items/{record_id}/retry", status_code=202)
def retry_item(
    batch_id: str,
    record_id: str,
    body: RetryInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    from .account_dispatcher import resource_fence

    item_owned(db, batch_id, record_id, actor)
    # A challenge checkpoint can become visible before its browser closes.
    # Never restart that login while the old worker still owns the record.
    with resource_fence("record", record_id) as acquired:
        if not acquired:
            raise HTTPException(409, "当前登录步骤正在结束，请稍后重试")
        return retry_item_locked(batch_id, record_id, body, request, actor, db)


def retry_item_locked(batch_id, record_id, body, request, actor, db):
    from .security import decrypt

    batch, job, r, op = item_owned(db, batch_id, record_id, actor)
    require_live(db, batch)
    secret = db.get(AuthSecret, job.id)
    challenge_retry = op.state == "challenge" and restartable_challenge(secret.workflow_encrypted)
    if (op.state not in ("failed", "needs_review") and not challenge_retry) or job.cancel_requested:
        raise HTTPException(409, "仅失败、待核对或自动验证已结束的用户可以重试")
    if challenge_retry and (body.mode != "resume" or job.reset_state == "pending" or r.credential_state == "unknown"):
        raise HTTPException(409, "密码变更结果待核对，不能直接重试验证")
    if r.active_operation_id not in (None, job.id):
        raise HTTPException(409, "该用户已有其他操作正在处理")
    if job.reset_state == "pending" and body.mode != "new_reset":
        raise HTTPException(409, "一次性密码结果未知，请明确选择再次重置")
    saved = decrypt(secret.workflow_encrypted) if secret.workflow_encrypted else {}
    if (body.mode == 'resume' and job.error_code != 'token_expired'
            and (job.stage == 'refresh_requested' or saved.get('refresh_only'))):
        raise HTTPException(409, '原授权刷新失败，请新建授权批次；普通重试不会重新登录或重置密码')
    refresh = (
        batch.kind == "json_export"
        and body.mode == "resume"
        and job.error_code == "token_expired"
        and secret.workflow_encrypted
    )
    if (
        r.credential_state == "unknown"
        and not r.credential_recovery_encrypted
        and body.mode != "new_reset"
        and not refresh
    ):
        raise HTTPException(409, "没有可恢复凭据，请明确选择再次重置")
    if refresh:
        job.stage = "refresh_requested"
    else:
        secret.workflow_encrypted = None
    secret.answer_encrypted = secret.result_encrypted = None
    if body.mode == "new_reset":
        job.reset_state = "required"
    # No native request or OTP reset is replayed by a plain retry. Unknown
    # credential recovery is bounded by the separately retained tried[] budget.
    if batch.kind == "custom_password" and not secret.payload_encrypted:
        recovery = (
            decrypt(r.credential_recovery_encrypted)
            if r.credential_recovery_encrypted
            else None
        )
        if not recovery or not recovery.get("candidate"):
            raise HTTPException(409, "共享密码已清除，请创建新批次")
        secret.payload_encrypted = encrypt({"password": recovery["candidate"]})
    r.active_operation_id = job.id
    op.state, op.phase, op.error = "queued", "ready", None
    op.finished_at = op.lease_token = op.lease_until = None
    job.error_code = job.next_poll_at = None
    batch.completed_at = batch.download_expires_at = None
    from .provisioning_auth_window import parent_download_window
    parent_download_window(db, batch, now())
    audit(
        db,
        actor,
        "auth_item_retry",
        f"重试认证任务 {job.id}；模式 {body.mode}",
        subject=r.owner_id,
        request=request,
    )
    db.commit()
    return {"operation_id": job.id, "state": op.state}


@router.post("/{batch_id}/items/{record_id}/cancel")
def cancel_item(
    batch_id: str,
    record_id: str,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    batch, job, r, op = item_owned(db, batch_id, record_id, actor)
    job.cancel_requested = True
    clear_secret(db.get(AuthSecret, job.id))
    if op.state != "running":
        op.state, op.finished_at = "cancelled", now()
        if r.active_operation_id == job.id:
            r.active_operation_id = None
    finish_batch(db, batch)
    db.commit()
    return {"operation_id": job.id, "state": op.state, "cancel_requested": True}


@router.get("/{batch_id}/items/{record_id}/image")
def challenge_image(
    batch_id: str,
    record_id: str,
    revision: int = Query(ge=1),
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    from .aws import AwsGateway
    from .enterprise_auth import EnterpriseAuth
    from .identity_login import AuthError, NativeIdentityLogin
    from .database import SessionLocal

    batch, job, r, op = item_owned(db, batch_id, record_id, actor)
    challenge, state, secret = current_challenge(db, batch, job, op)
    if challenge["kind"] != "image" or challenge["revision"] != revision:
        raise HTTPException(409, "验证码版本已变化，请刷新任务")
    _, account = require_access(db, batch, r, job=job)
    sealed, kind = secret.workflow_encrypted, batch.kind
    db.expunge(account)
    db.commit()

    def guard():
        with SessionLocal() as check:
            b, j, record, operation = item_owned(check, batch_id, record_id, actor)
            current, _, _ = current_challenge(check, b, j, operation)
            if current["id"] != challenge["id"] or current["revision"] != revision:
                raise AuthError("stale_challenge")

    gateway = AwsGateway(account)
    proxy_guard = gateway._check_proxy

    def checked_proxy():
        guard()
        proxy_guard()

    gateway._check_proxy = checked_proxy
    adapter = (EnterpriseAuth if kind == "json_export" else NativeIdentityLogin)(
        gateway, checkpoint=lambda _: None
    )
    try:
        result = adapter.challenge_image(sealed, revision)
        guard()
        return Response(
            result.content,
            media_type=result.content_type,
            headers={"Cache-Control": "no-store"},
        )
    except AuthError as error:
        raise HTTPException(409, str(error)) from None
    finally:
        if hasattr(adapter, "close"):
            adapter.close()
        gateway.identity.close()
