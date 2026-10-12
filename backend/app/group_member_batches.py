"""Frozen membership envelopes sequence existing leased GroupJob operations."""

import json
import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import DateTime, func, or_, select
from sqlalchemy.orm import Session

from .aws import AwsFailure
from .batches import require_account
from .database import get_db
from .group_members import admit_member, member_context, validate_member
from .group_subscription_state import config_hash, digest, member_activation, quota_finish, reserve_join
from .models import (
    AwsAccount, GroupJob, GroupMemberActivation, GroupMemberBatch, GroupMemberBatchItem,
    ManagedGroup, StopSchedule, Subscription, User, now,
)
from .security import audit, get_user

router = APIRouter(prefix="/api/groups/{group_id}")
LIVE_STATES = ("queued", "running", "failed", "needs_review")


class MemberBatchInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    kind: Literal["attach", "detach"]
    record_ids: list[str]
    expected_revision: int = Field(ge=1)
    request_key: str = Field(min_length=16, max_length=80)

    @field_validator("record_ids")
    @classmethod
    def canonical_ids(cls, ids):
        ids = sorted(set(ids))
        if not 1 <= len(ids) <= 100 or any(not rid or len(rid) > 36 for rid in ids):
            raise ValueError("每批需要 1 至 100 个不同的本地 SSO 记录 ID")
        return ids


def batch_for_job(db, job_id):
    item = db.scalar(select(GroupMemberBatchItem).where(GroupMemberBatchItem.job_id == job_id))
    return db.get(GroupMemberBatch, item.batch_id) if item else None


def batch_rows(db, batch):
    return list(db.execute(select(GroupMemberBatchItem, GroupJob).join(
        GroupJob, GroupJob.id == GroupMemberBatchItem.job_id,
    ).where(GroupMemberBatchItem.batch_id == batch.id).order_by(GroupMemberBatchItem.position)))


def require_viewer_scope(db, group, actor):
    # Admin history and local unsent cleanup remain available without a usable AWS account.
    if actor.role != "admin":
        require_account(db, actor, db.get(AwsAccount, group.aws_account_id))


def visible_batch_ids(db, group, actor):
    """Shared history scope; callers can filter legacy children before pagination."""
    query = select(GroupMemberBatch.id).where(GroupMemberBatch.group_id == group.id)
    if not actor or actor.role != "admin" and group.owner_id != actor.id:
        return query.where(False)
    if actor.role != "admin":
        try:
            require_viewer_scope(db, group, actor)
        except HTTPException as exc:
            if exc.status_code != 403:
                raise
            return query.where(False)
        query = query.where(GroupMemberBatch.actor_id == actor.id)
    return query


def batch_visible(db, batch, actor):
    group = db.get(ManagedGroup, batch.group_id)
    return bool(group and db.scalar(visible_batch_ids(db, group, actor).where(GroupMemberBatch.id == batch.id)))


def owned_batch(db, group_id, batch_id, actor):
    from .groups import owned_group
    group = owned_group(db, group_id, actor)
    batch = db.get(GroupMemberBatch, batch_id)
    if (not batch or batch.group_id != group.id
            or actor.role != "admin" and batch.actor_id != actor.id):
        raise HTTPException(404, "成员批次不存在")
    if not batch_visible(db, batch, actor):
        raise HTTPException(403, "无权使用该 AWS 账号")
    return group, batch


def batch_view(db, batch, *, detail=True):
    group = db.get(ManagedGroup, batch.group_id)
    rows = batch_rows(db, batch)
    counts = {state: sum(job.state == state for _, job in rows) for state in (
        "waiting", "queued", "running", "completed", "failed", "needs_review", "stopped",
    )}
    active = next((j for _, j in rows if j.id == group.active_job_id), None)
    result = {key: getattr(batch, key) for key in (
        "id", "group_id", "owner_id", "actor_id", "request_key", "kind",
        "expected_revision", "state", "stop_requested_at", "error", "created_at",
        "updated_at", "finished_at",
    )} | {
        "record_ids": json.loads(batch.record_ids),
        "active_job_id": active.id if active else None,
        "counts": {"total": len(rows), **counts},
        "actions": {
            "recheck": bool(active and active.state == "needs_review" and active.phase == "pending"),
            "retry": bool(active and active.state == "failed" and active.phase == "ready" and not batch.stop_requested_at),
            "stop": any(j.state not in ("completed", "stopped") and j.phase == "ready" for _, j in rows),
        },
    }
    if detail:
        labels = {record.id: {"username": record.username, "email": record.email, "sso_user_id": record.sso_user_id}
                  for record in db.execute(select(Subscription.id, Subscription.username, Subscription.email, Subscription.sso_user_id).where(
                      Subscription.id.in_(result["record_ids"]), Subscription.owner_id == batch.owner_id,
                      Subscription.aws_account_id == batch.aws_account_id,
                  ))}
        result["items"] = [{"position": item.position, "job_id": job.id, **{
            key: getattr(job, key) for key in (
                "record_id", "kind", "state", "phase", "attempts", "error", "created_at", "finished_at",
            )
        }, **labels.get(job.record_id, {"username": None, "email": None, "sso_user_id": None})} for item, job in rows]
    return result


def sync_batch(db, batch, group):
    rows = batch_rows(db, batch)
    active = next((j for _, j in rows if j.id == group.active_job_id), None)
    if active:
        batch.state, batch.error = active.state, active.error
    else:
        batch.state = "completed" if all(j.state == "completed" for _, j in rows) else "stopped"
        batch.error, batch.finished_at = None, now()
    batch.updated_at = now()


def advance_batch(db, job, group):
    """Called inside completion's transaction, before releasing the group fence."""
    batch = batch_for_job(db, job.id)
    if not batch:
        return
    following = next((j for _, j in batch_rows(db, batch) if j.state == "waiting"), None)
    if following and not batch.stop_requested_at:
        following.state = "queued"
        group.active_job_id, group.state = following.id, "updating"
    sync_batch(db, batch, group)


def snapshot_before(db, record):
    schedule = db.get(StopSchedule, record.id)
    return json.dumps({
        "group_id": record.group_id, "group_membership_id": record.group_membership_id,
        "updated_at": record.updated_at,
        "schedule": {c.name: getattr(schedule, c.name) for c in StopSchedule.__table__.columns} if schedule else None,
    }, default=lambda value: value.isoformat(), sort_keys=True)


def restore_unsent(db, item, job):
    record = db.get(Subscription, job.record_id)
    if not record or record.active_operation_id != job.id:
        raise HTTPException(409, "未发送成员的锁已变化，停止操作未执行")
    # Match this job's ledger explicitly: failed joins may already have released it.
    activations = db.scalars(select(GroupMemberActivation).where(
        GroupMemberActivation.operation_id == job.id,
        GroupMemberActivation.record_id == record.id,
    ))
    for activation in activations:
        if activation.counted or activation.write_requested_at:
            raise HTTPException(409, "成员已存在发送意图或确认授权，不能作为未发送项停止")
        quota_finish(db, activation, False)
    before = json.loads(item.before_snapshot)
    record.group_id, record.group_membership_id = before["group_id"], before["group_membership_id"]
    record.active_operation_id = None
    record.updated_at = datetime.fromisoformat(before["updated_at"])
    schedule = db.get(StopSchedule, record.id)
    if before["schedule"] is None:
        if schedule:
            db.delete(schedule)
    else:
        if not schedule:
            schedule = StopSchedule(record_id=record.id)
            db.add(schedule)
        for column in StopSchedule.__table__.columns:
            value = before["schedule"][column.name]
            if value is not None and isinstance(column.type, DateTime):
                value = datetime.fromisoformat(value)
            setattr(schedule, column.name, value)
    job.state, job.finished_at = "stopped", now()
    job.error = job.lease_token = job.lease_until = None


@router.post("/member-batches", status_code=202)
def submit_batch(group_id: str, body: MemberBatchInput, request: Request,
                 actor: User = Depends(get_user), db: Session = Depends(get_db)):
    from .groups import owned_group
    group = owned_group(db, group_id, actor)
    require_viewer_scope(db, group, actor)
    payload_hash = digest(body.model_dump(exclude={"request_key"}) | {"group_id": group.id})
    old = db.scalar(select(GroupMemberBatch).where(
        GroupMemberBatch.actor_id == actor.id, GroupMemberBatch.request_key == body.request_key,
    ))
    if old:
        if old.payload_hash != payload_hash:
            raise HTTPException(409, "重复请求标识与原成员批次内容不同")
        return batch_view(db, old)
    if (group.deleted_at or not group.remote_id or group.state != "ready" or group.active_job_id
            or group.revision != body.expected_revision):
        raise HTTPException(409, "分组已变化或有未完成任务，请刷新后重试")
    if db.scalar(select(Subscription.id).where(
        Subscription.group_id == group.id,
        or_(Subscription.active_operation_id.is_not(None), Subscription.reserved.is_(True),
            Subscription.state.in_(("queued", "running", "needs_review"))),
    ).limit(1)):
        raise HTTPException(409, "分组成员仍有未完成任务")
    records = [validate_member(db, group, rid, actor, body.kind) for rid in body.record_ids]
    batch = GroupMemberBatch(
        id=str(uuid.uuid4()), group_id=group.id, owner_id=group.owner_id, actor_id=actor.id,
        aws_account_id=group.aws_account_id, request_key=body.request_key, payload_hash=payload_hash,
        kind=body.kind, expected_revision=body.expected_revision,
        record_ids=json.dumps(body.record_ids), config_hash=config_hash(db, db.get(AwsAccount, group.aws_account_id)),
    )
    db.add(batch)
    db.flush()
    for position, record in enumerate(records):
        before = snapshot_before(db, record)
        payload = {"kind": body.kind, "expected_revision": body.expected_revision, "record_id": record.id, "name": None}
        job = admit_member(db, group, record, actor, body.kind, f"member-batch:{batch.id}:{position}", payload,
                           state="queued" if position == 0 else "waiting", request=request)
        db.flush()
        db.add(GroupMemberBatchItem(batch_id=batch.id, record_id=record.id,
                                   job_id=job.id, position=position, before_snapshot=before))
        if position == 0:
            group.active_job_id = job.id
    group.state, group.updated_at = "updating", now()
    audit(db, actor, "group_member_batch", f"分组成员批次：{group.name}；{body.kind} {len(records)} 项",
          subject=group.owner_id, request=request)
    db.commit()
    return batch_view(db, batch)


@router.get("/member-batches")
def list_batches(group_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    from .groups import owned_group
    group = owned_group(db, group_id, actor)
    require_viewer_scope(db, group, actor)
    query = select(GroupMemberBatch).where(GroupMemberBatch.group_id == group_id)
    if actor.role != "admin":
        query = query.where(GroupMemberBatch.actor_id == actor.id)
    return [batch_view(db, b, detail=False) for b in db.scalars(query.order_by(GroupMemberBatch.created_at.desc()).limit(100))]


@router.get("/member-batches/{batch_id}")
def get_batch(group_id: str, batch_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    _, batch = owned_batch(db, group_id, batch_id, actor)
    return batch_view(db, batch)


def recover_batch(db, group, batch, actor, request, *, recheck):
    active = db.get(GroupJob, group.active_job_id) if group.active_job_id else None
    rows = batch_rows(db, batch)
    if not active or active.id not in {j.id for _, j in rows}:
        raise HTTPException(409, "批次没有可恢复的活动项")
    if recheck:
        if active.state != "needs_review" or active.phase != "pending":
            raise HTTPException(409, "批次没有等待核对的发送结果")
    elif batch.stop_requested_at or active.state != "failed" or active.phase != "ready":
        raise HTTPException(409, "只能重试已确认未发送的失败项；未知结果请核对")
    account = db.get(AwsAccount, group.aws_account_id)
    require_account(db, actor, account)
    if (group.owner_id != batch.owner_id or group.aws_account_id != batch.aws_account_id
            or config_hash(db, account) != batch.config_hash):
        raise HTTPException(409, "批次冻结的归属或 AWS 配置已变化，请停止未发送项后重新提交")
    # Only the original actor can renew authorization for the rest of their frozen request.
    # An admin recovering someone else's batch authorizes just the current child.
    selected = ([j for _, j in rows if j.state in ("failed", "waiting")]
                if not recheck and actor.id == batch.actor_id else [active])
    for job in selected:
        job.actor_id = actor.id
        payload = json.loads(job.payload)
        payload["member_context"]["actor_session_version"] = actor.session_version
        job.payload = json.dumps(payload, sort_keys=True)
        try:
            record = member_context(db, job, group, recovering=recheck, require_group_lock=job.id == active.id)
        except AwsFailure as exc:
            raise HTTPException(409, str(exc)) from None
        if not recheck and job.kind == "attach" and not member_activation(db, record.id):
            reserve_join(db, group, record, actor, job.id)
        if not recheck and job.kind == "attach":
            activation = member_activation(db, record.id)
            if activation:
                activation.actor_id = actor.id
    active.state, active.error = "queued", None
    group.state, group.error = "updating", None
    sync_batch(db, batch, group)
    audit(db, actor, "recheck_member_batch" if recheck else "retry_member_batch",
          f"恢复分组成员批次：{group.name}", subject=group.owner_id, request=request)
    db.commit()
    return batch_view(db, batch)


@router.post("/member-batches/{batch_id}/recheck", status_code=202)
def recheck_batch(group_id: str, batch_id: str, request: Request,
                  actor: User = Depends(get_user), db: Session = Depends(get_db)):
    group, batch = owned_batch(db, group_id, batch_id, actor)
    return recover_batch(db, group, batch, actor, request, recheck=True)


@router.post("/member-batches/{batch_id}/retry", status_code=202)
def retry_batch(group_id: str, batch_id: str, request: Request,
                actor: User = Depends(get_user), db: Session = Depends(get_db)):
    group, batch = owned_batch(db, group_id, batch_id, actor)
    return recover_batch(db, group, batch, actor, request, recheck=False)


@router.post("/member-batches/{batch_id}/stop")
def stop_batch(group_id: str, batch_id: str, request: Request,
               actor: User = Depends(get_user), db: Session = Depends(get_db)):
    group, batch = owned_batch(db, group_id, batch_id, actor)
    if batch.state in ("completed", "stopped") or batch.stop_requested_at:
        return batch_view(db, batch)
    rows = batch_rows(db, batch)
    for item, job in rows:
        if job.state not in ("completed", "stopped") and job.phase == "ready":
            restore_unsent(db, item, job)
            if group.active_job_id == job.id:
                group.active_job_id, group.state, group.error = None, "ready", None
    batch.stop_requested_at = now()
    sync_batch(db, batch, group)
    audit(db, actor, "stop_member_batch", f"停止分组成员批次的未发送项：{group.name}",
          subject=group.owner_id, request=request)
    db.commit()
    return batch_view(db, batch)


@router.get("/member-candidates")
def candidates(group_id: str, kind: Literal["attach", "detach"] = "attach", q: str = "",
               page: int = Query(1, ge=1), page_size: int = Query(100, ge=1, le=100),
               actor: User = Depends(get_user), db: Session = Depends(get_db)):
    from .groups import owned_group
    from .main import subscription_view
    group = owned_group(db, group_id, actor)
    require_viewer_scope(db, group, actor)
    query = select(Subscription).where(
        Subscription.owner_id == group.owner_id, Subscription.aws_account_id == group.aws_account_id,
        Subscription.state == "completed", Subscription.sso_user_id.is_not(None),
        Subscription.sso_deleted_at.is_(None), Subscription.active_operation_id.is_(None),
        Subscription.reserved.is_(False),
    )
    query = query.where(Subscription.group_id.is_(None)) if kind == "attach" else query.where(
        Subscription.group_id == group.id, Subscription.group_membership_id.is_not(None),
    )
    if q:
        query = query.where(or_(*(column.icontains(q, autoescape=True) for column in (
            Subscription.username, Subscription.email, Subscription.sso_display_name, Subscription.sso_user_id,
        ))))
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(query.order_by(Subscription.created_at.desc(), Subscription.id).offset((page - 1) * page_size).limit(page_size))
    rows = list(rows)
    from .provisioning_exports import mappings
    numbered = mappings(db, [r.id for r in rows])
    return {"group_id": group.id, "kind": kind, "items": [subscription_view(r, db, actor, numbered) for r in rows],
            "total": total, "page": page, "page_size": page_size}
