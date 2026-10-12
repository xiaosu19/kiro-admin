"""Owned, tracked IAM Identity Center groups and durable operation admission."""

import hashlib
import json
import uuid
from collections import defaultdict
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session, load_only

from .batches import require_account
from .aws import AwsFailure, AwsGateway
from .group_jobs import job_view
from .database import get_db
from .models import (
    AwsAccount,
    GroupJob,
    GroupMemberBatchItem,
    ManagedGroup,
    RecordOperation,
    StopSchedule,
    Subscription,
    User,
    now,
)
from .security import admin, audit, get_user

router = APIRouter(prefix="/api")


class CreateGroupInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    aws_account_id: int
    owner_id: int | None = None
    name: str = Field(min_length=1, max_length=1024)
    request_key: str = Field(min_length=16, max_length=80)


class LinkGroupInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aws_account_id: int
    owner_id: int
    remote_id: str = Field(min_length=1, max_length=100)
    request_key: str = Field(min_length=16, max_length=80)


class GroupJobInput(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    kind: Literal["rename", "delete", "attach", "detach"]
    request_key: str = Field(min_length=16, max_length=80)
    expected_revision: int = Field(ge=1)
    name: str | None = Field(default=None, min_length=1, max_length=1024)
    record_id: str | None = None

    @model_validator(mode="after")
    def valid_name(self):
        if (self.kind == "rename") != (self.name is not None):
            raise ValueError("重命名需要新的分组名称")
        if (self.kind in ("attach", "detach")) != (self.record_id is not None):
            raise ValueError("成员操作需要本地 SSO 记录 ID")
        return self


def scope(account):
    return f"{account.aws_account_id}:{account.identity_store_id}"


def owned_group(db, group_id, actor):
    group = db.get(ManagedGroup, group_id)
    if not group or (actor.role != "admin" and group.owner_id != actor.id):
        raise HTTPException(404, "分组不存在")
    return group


def require_group(db, group_id, actor, account_id, owner_id=None):
    group = owned_group(db, group_id, actor)
    if group.aws_account_id != account_id or (
        owner_id is not None and group.owner_id != owner_id
    ):
        raise HTTPException(409, "分组与 SSO 的所有者和 AWS 配置必须一致")
    if group.deleted_at or group.state not in ("ready", "creating") or (group.state == "ready" and group.active_job_id):
        raise HTTPException(409, "分组尚未就绪或存在待处理任务")
    return group


def subscription_skip_reason(record):
    if record.sso_deleted_at:
        return "sso_deleted"
    if record.plan_id is not None:
        return "plan_already_bound"
    if record.active_operation_id or record.reserved or record.state != "completed":
        return "operation_pending"
    if not record.sso_user_id:
        return "sso_not_ready"
    if record.group_id and not record.group_membership_id:
        return "membership_not_confirmed"
    if (
        not record.provision_only
        or record.subscription_status != "not_subscribed"
        or record.observed_subscription_type
    ):
        return "existing_subscription"
    return None


def local_members(db, group):
    return list(
        db.scalars(
            select(Subscription)
            .where(
                Subscription.group_id == group.id,
                Subscription.owner_id == group.owner_id,
                Subscription.aws_account_id == group.aws_account_id,
            )
            .order_by(Subscription.created_at, Subscription.id)
        )
    )


_SCHEDULE_UNLOADED = object()


def preview_skip_reason(db, record, group, *, schedule=_SCHEDULE_UNLOADED, current=None):
    reason = subscription_skip_reason(record)
    if reason:
        return reason
    if group.state != "ready" or group.active_job_id:
        return "group_not_ready"
    if schedule is _SCHEDULE_UNLOADED:
        schedule = db.get(StopSchedule, record.id)
    if schedule and schedule.mode == "at" and schedule.stop_at <= (current or now()):
        return (
            "group_deadline_expired" if schedule.source_group_id else "deadline_expired"
        )
    return None


def member_counts(db, group, members, schedules=None):
    current = now()
    return {
        "total": len(members),
        "eligible": sum(
            preview_skip_reason(
                db, record, group,
                schedule=schedules.get(record.id) if schedules is not None else _SCHEDULE_UNLOADED,
                current=current,
            ) is None
            for record in members
        ),
        "active": sum(bool(r.sso_user_id) and not r.sso_deleted_at for r in members),
        "subscribed": sum(r.counted for r in members),
        "deleted": sum(bool(r.sso_deleted_at) for r in members),
        "cancelled": sum(bool(r.cancelled_at) for r in members),
    }


def group_view(group, db=None):
    result = {
        key: getattr(group, key)
        for key in (
            "id",
            "owner_id",
            "aws_account_id",
            "name",
            "remote_id",
            "state",
            "error",
            "revision",
            "active_job_id",
            "created_at",
            "deleted_at",
        )
    }
    if db is not None:
        from .group_subscription_state import group_projection
        result["native_subscription"] = group_projection(db, group.id)
        result["supports_scheduled_cancellation"] = db.get(AwsAccount, group.aws_account_id).control_plane == "kiro"
    result["policy"] = {
        "mode": group.policy_mode,
        "days": group.policy_days,
        "stop_at": group.policy_stop_at,
        "revision": group.policy_revision,
    }
    return result


@router.get("/admin/aws/{account_id}/groups")
def remote_groups(
    account_id: int, actor: User = Depends(admin), db: Session = Depends(get_db)
):
    account = db.get(AwsAccount, account_id)
    require_account(db, actor, account)
    linked = set(
        db.scalars(
            select(ManagedGroup.remote_id).where(
                ManagedGroup.aws_scope == scope(account),
                ManagedGroup.remote_id.is_not(None),
            )
        )
    )
    markers = set(
        db.scalars(
            select(ManagedGroup.marker).where(ManagedGroup.aws_scope == scope(account))
        )
    )
    return [
        g
        for g in AwsGateway(account).list_groups()
        if g["id"] not in linked and g["description"] not in markers
    ]


@router.post("/groups/link", status_code=202)
def link_group(
    body: LinkGroupInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    owner = db.get(User, body.owner_id)
    if not owner or owner.deleted_at or not owner.active:
        raise HTTPException(404, "分组所有者不存在或已停用")
    digest = hashlib.sha256(
        json.dumps(body.model_dump(exclude={"request_key"}), sort_keys=True).encode()
    ).hexdigest()
    old = db.scalar(
        select(ManagedGroup).where(
            ManagedGroup.owner_id == owner.id,
            ManagedGroup.request_key == body.request_key,
        )
    )
    if old:
        if old.payload_hash != digest:
            raise HTTPException(409, "重复请求标识与原分组内容不同")
        return group_view(old)
    account = db.get(AwsAccount, body.aws_account_id)
    require_account(db, actor, account)
    require_account(db, owner, account)
    if db.scalar(
        select(ManagedGroup.id).where(
            ManagedGroup.aws_scope == scope(account),
            ManagedGroup.remote_id == body.remote_id,
        )
    ):
        raise HTTPException(409, "该 AWS 分组已被平台管理")
    gid, jid = str(uuid.uuid4()), str(uuid.uuid4())
    group = ManagedGroup(
        id=gid,
        owner_id=owner.id,
        aws_account_id=account.id,
        aws_scope=scope(account),
        name=body.remote_id,
        marker=f"Kiro Console Group {gid}",
        remote_id=body.remote_id,
        request_key=body.request_key,
        payload_hash=digest,
        active_job_id=jid,
        state="linking",
    )
    db.add(group)
    db.flush()
    db.add(
        GroupJob(
            id=jid,
            group_id=gid,
            actor_id=actor.id,
            kind="link",
            request_key=body.request_key,
            payload=json.dumps({"remote_id": body.remote_id}),
        )
    )
    audit(
        db,
        actor,
        "link_group",
        f"关联 AWS 分组：{body.remote_id}",
        subject=owner.id,
        request=request,
    )
    db.commit()
    return group_view(group)


@router.post("/groups", status_code=202)
def create_group(
    body: CreateGroupInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    group = admit_create_group(db, actor, body, request)
    db.commit()
    return group_view(group)


def admit_create_group(db, actor, body, request=None):
    owner_id = body.owner_id if body.owner_id is not None else actor.id
    if actor.role != "admin" and owner_id != actor.id:
        raise HTTPException(403, "只能为自己创建分组")
    owner = db.get(User, owner_id)
    if not owner or owner.deleted_at or not owner.active:
        raise HTTPException(404, "分组所有者不存在或已停用")
    digest = hashlib.sha256(
        json.dumps(
            {
                "aws_account_id": body.aws_account_id,
                "owner_id": owner_id,
                "name": body.name,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    old = db.scalar(
        select(ManagedGroup).where(
            ManagedGroup.owner_id == owner_id,
            ManagedGroup.request_key == body.request_key,
        )
    )
    if old:
        if old.payload_hash != digest:
            raise HTTPException(409, "重复请求标识与原分组内容不同")
        return old
    account = db.get(AwsAccount, body.aws_account_id)
    require_account(db, actor, account)
    require_account(db, owner, account)
    if db.scalar(
        select(ManagedGroup.id).where(
            ManagedGroup.aws_scope == scope(account),
            ManagedGroup.name == body.name,
            ManagedGroup.deleted_at.is_(None),
        )
    ):
        raise HTTPException(409, "该 AWS 身份中心的分组名称已被使用")
    gid, jid = str(uuid.uuid4()), str(uuid.uuid4())
    group = ManagedGroup(
        id=gid,
        owner_id=owner_id,
        aws_account_id=account.id,
        aws_scope=scope(account),
        name=body.name,
        marker=f"Kiro Console Group {gid}",
        request_key=body.request_key,
        payload_hash=digest,
        active_job_id=jid,
    )
    db.add(group)
    db.flush()
    db.add(
        GroupJob(
            id=jid,
            group_id=gid,
            actor_id=actor.id,
            kind="create",
            request_key=body.request_key,
            payload=json.dumps({"name": body.name}),
        )
    )
    audit(
        db,
        actor,
        "create_group",
        f"创建 AWS 分组：{body.name}",
        subject=owner_id,
        request=request,
    )
    return group


@router.get("/groups")
def list_groups(q: str = "", member_q: str = "", aws_account_id: int | None = None,
                actor: User = Depends(get_user), db: Session = Depends(get_db)):
    query = select(ManagedGroup)
    if actor.role != "admin":
        query = query.where(ManagedGroup.owner_id == actor.id)
    if aws_account_id is not None:
        query = query.where(ManagedGroup.aws_account_id == aws_account_id)
    if q:
        query = query.where(ManagedGroup.name.icontains(q, autoescape=True))
    if member_q:
        query = query.where(select(Subscription.id).where(
            Subscription.group_id == ManagedGroup.id,
            Subscription.owner_id == ManagedGroup.owner_id,
            Subscription.aws_account_id == ManagedGroup.aws_account_id,
            Subscription.username.icontains(member_q, autoescape=True),
        ).exists())
    group_rows = list(db.execute(query.add_columns(AwsAccount.control_plane).join(
        AwsAccount, AwsAccount.id == ManagedGroup.aws_account_id
    ).order_by(ManagedGroup.created_at.desc())))
    groups = [row[0] for row in group_rows]
    planes = {row[0].id: row[1] for row in group_rows}
    if not groups:
        return []
    members, schedules = defaultdict(list), {}
    # Read only scoped count inputs, without loading credentials or operation data.
    rows = db.execute(
        select(Subscription, StopSchedule)
        .select_from(Subscription)
        .join(
            ManagedGroup,
            and_(
                Subscription.group_id == ManagedGroup.id,
                Subscription.owner_id == ManagedGroup.owner_id,
                Subscription.aws_account_id == ManagedGroup.aws_account_id,
            ),
        )
        .outerjoin(StopSchedule, StopSchedule.record_id == Subscription.id)
        .where(ManagedGroup.id.in_(query.with_only_columns(ManagedGroup.id)))
        .options(
            load_only(
                Subscription.id, Subscription.group_id, Subscription.plan_id,
                Subscription.active_operation_id, Subscription.reserved,
                Subscription.state, Subscription.sso_user_id,
                Subscription.sso_deleted_at, Subscription.group_membership_id,
                Subscription.provision_only, Subscription.subscription_status,
                Subscription.observed_subscription_type, Subscription.counted,
                Subscription.cancelled_at,
            ),
            load_only(
                StopSchedule.record_id, StopSchedule.mode, StopSchedule.stop_at,
                StopSchedule.source_group_id,
            ),
        )
    )
    for record, schedule in rows:
        members[record.group_id].append(record)
        schedules[record.id] = schedule
    from .models import NativeGroupGrant
    from .group_subscription_state import grant_view
    native = {}
    for grant in db.scalars(select(NativeGroupGrant).where(
        NativeGroupGrant.group_id.in_([g.id for g in groups])
    ).order_by(NativeGroupGrant.created_at.desc())):
        native.setdefault(grant.group_id, grant_view(grant))
    return [
        group_view(group) | {"native_subscription": native.get(group.id), "supports_scheduled_cancellation": planes[group.id] == "kiro", "counts": member_counts(db, group, members[group.id], schedules)}
        for group in groups
    ]


@router.get("/groups/{group_id}")
def get_group(
    group_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)
):
    from .main import subscription_view

    group = owned_group(db, group_id, actor)
    members = local_members(db, group)
    from .provisioning_exports import mappings
    numbered = mappings(db, [r.id for r in members])
    return group_view(group, db) | {
        "members": [subscription_view(r, db, actor, numbered) for r in members],
        "counts": member_counts(db, group, members),
    }


@router.get("/groups/{group_id}/subscription-preview")
def subscription_preview(
    group_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)
):
    group = owned_group(db, group_id, actor)
    members = local_members(db, group)
    eligible, skipped = [], []
    for r in members:
        reason = preview_skip_reason(db, r, group)
        if reason:
            skipped.append({"id": r.id, "reason": reason})
        else:
            eligible.append(r.id)
    return {
        "group_id": group.id,
        "eligible_ids": eligible,
        "eligible_count": len(eligible),
        "skipped": skipped,
    }


@router.get("/groups/{group_id}/jobs")
def group_jobs(
    group_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)
):
    group = owned_group(db, group_id, actor)
    query = select(GroupJob).where(GroupJob.group_id == group_id)
    if actor.role != "admin":
        from .group_member_batches import visible_batch_ids
        member_jobs = select(GroupMemberBatchItem.job_id)
        visible_members = member_jobs.where(
            GroupMemberBatchItem.batch_id.in_(visible_batch_ids(db, group, actor)),
        )
        query = query.where(or_(
            and_(GroupJob.actor_id == actor.id, GroupJob.id.not_in(member_jobs)),
            GroupJob.id.in_(visible_members),
        ))
    jobs = list(db.scalars(query.order_by(GroupJob.created_at.desc()).limit(100)))
    batch_ids = dict(db.execute(select(GroupMemberBatchItem.job_id, GroupMemberBatchItem.batch_id).where(
        GroupMemberBatchItem.job_id.in_([job.id for job in jobs]),
    )).all()) if jobs else {}
    return [job_view(job) | {"member_batch_id": batch_ids.get(job.id)} for job in jobs]


@router.post("/groups/{group_id}/jobs", status_code=202)
def enqueue_group_job(
    group_id: str,
    body: GroupJobInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    group = owned_group(db, group_id, actor)
    payload = json.dumps(body.model_dump(exclude={"request_key"}), sort_keys=True)
    old = db.scalar(
        select(GroupJob).where(
            GroupJob.group_id == group.id, GroupJob.request_key == body.request_key
        )
    )
    if old:
        from .group_member_batches import batch_for_job
        member_batch = batch_for_job(db, old.id)
        if member_batch:
            if actor.role != "admin" and member_batch.actor_id != actor.id:
                raise HTTPException(404, "分组任务不存在")
            raise HTTPException(409, "该任务属于成员批次，请使用批次详情与恢复操作")
        if actor.role != "admin" and old.actor_id != actor.id:
            raise HTTPException(404, "分组任务不存在")
        old_input = {k: v for k, v in json.loads(old.payload).items() if not k.startswith("native_") and k not in ("member_context", "worker_config_hash")}
        if old_input != json.loads(payload):
            raise HTTPException(409, "重复请求标识与原分组操作不同")
        return job_view(old)
    require_account(db, actor, db.get(AwsAccount, group.aws_account_id))
    failed_job = db.get(GroupJob, group.active_job_id) if group.active_job_id else None
    recover_create = (
        body.kind == "rename"
        and group.remote_id is None
        and failed_job
        and failed_job.kind in ("create", "rename")
    )
    discard_failed = (
        (body.kind == "delete" or recover_create)
        and group.state == "failed"
        and failed_job
        and failed_job.state == "failed"
        and failed_job.phase == "ready"
        and not failed_job.record_id
    )
    discard_cancelled_create = (
        body.kind == 'delete' and group.state == 'failed'
        and group.remote_id is None and not group.active_job_id
        and db.scalar(select(GroupJob.id).where(
            GroupJob.group_id == group.id, GroupJob.kind == 'create',
            GroupJob.state == 'cancelled', GroupJob.phase == 'ready',
            GroupJob.record_id.is_(None),
        ).limit(1)) is not None
    )
    if group.revision != body.expected_revision or (
        not (discard_failed or discard_cancelled_create) and (group.active_job_id or group.state != "ready")
    ):
        raise HTTPException(409, "分组已变化或有未完成任务，请刷新后重试")
    if recover_create:
        owner = db.get(User, group.owner_id)
        if not owner.active or owner.deleted_at:
            raise HTTPException(409, "分组所有者已停用")
        require_account(db, owner, db.get(AwsAccount, group.aws_account_id))
    if body.kind == "rename" and db.scalar(
        select(ManagedGroup.id).where(
            ManagedGroup.aws_scope == group.aws_scope,
            ManagedGroup.id != group.id,
            ManagedGroup.name == body.name,
            ManagedGroup.deleted_at.is_(None),
        )
    ):
        raise HTTPException(409, "该 AWS 身份中心的分组名称已被使用")
    from .group_subscription_state import live_grant
    if body.kind == "delete" and live_grant(db, group.id):
        raise HTTPException(409, "分组仍有原生订阅或待核对授权，请先取消订阅")
    if not recover_create and db.scalar(select(Subscription.id).where(
        Subscription.group_id == group.id,
        or_(Subscription.active_operation_id.is_not(None), Subscription.reserved.is_(True),
            Subscription.state.in_(("queued", "running", "needs_review"))),
    ).limit(1)):
        raise HTTPException(409, "分组成员仍有未完成任务")
    if body.kind == "delete":
        from .provisioning_batches import live_intent
        if live_intent(db, group_id=group.id):
            raise HTTPException(409, "分组仍有批次开通意图，请先处理完成")
        pending_states = ("queued", "running", "needs_review")
        member = db.scalar(
            select(Subscription.id)
            .where(
                Subscription.group_id == group.id,
                or_(
                    Subscription.sso_deleted_at.is_(None),
                    Subscription.active_operation_id.is_not(None),
                    Subscription.reserved.is_(True),
                    Subscription.state.in_(pending_states),
                    select(RecordOperation.id)
                    .where(
                        RecordOperation.record_id == Subscription.id,
                        RecordOperation.state.in_(pending_states),
                    )
                    .exists(),
                ),
            )
            .limit(1)
        )
        pending_job = db.scalar(
            select(GroupJob.id)
            .where(GroupJob.group_id == group.id, GroupJob.state.in_(pending_states))
            .limit(1)
        )
        if member or pending_job:
            raise HTTPException(409, "分组仍有未删除的本地成员或未完成任务")
    record = None
    if body.record_id:
        from .group_members import admit_member, validate_member
        record = validate_member(db, group, body.record_id, actor, body.kind)
        job = admit_member(db, group, record, actor, body.kind, body.request_key, json.loads(payload), request=request)
    else:
        job = GroupJob(
            id=str(uuid.uuid4()), group_id=group.id, actor_id=actor.id,
            kind=body.kind, request_key=body.request_key, payload=payload,
        )
        db.add(job)
    group.active_job_id, group.state = (
        job.id,
        "deleting" if body.kind == "delete" else "updating",
    )
    audit(
        db,
        actor,
        f"group_{body.kind}",
        f"AWS 分组操作：{group.name}",
        subject=group.owner_id,
        request=request,
    )
    db.commit()
    return job_view(job)


@router.post("/groups/{group_id}/retry", status_code=202)
def retry_group(
    group_id: str,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    group = owned_group(db, group_id, actor)
    job = db.get(GroupJob, group.active_job_id) if group.active_job_id else None
    if not job or job.state not in ("failed", "needs_review"):
        raise HTTPException(409, "当前没有可重试的分组任务")
    from .group_member_batches import batch_for_job
    member_batch = batch_for_job(db, job.id)
    if member_batch:
        if actor.role != "admin" and member_batch.actor_id != actor.id:
            raise HTTPException(404, "分组任务不存在")
        raise HTTPException(409, "该任务属于成员批次，请使用批次的核对或重试操作")
    if actor.role != "admin" and job.actor_id != actor.id:
        raise HTTPException(404, "分组任务不存在")
    require_account(db, actor, db.get(AwsAccount, group.aws_account_id))
    from .provisioning_coordinator import job_guard
    try:
        job_guard(db, job, recovering=job.phase == "pending")
    except AwsFailure as exc:
        raise HTTPException(409, str(exc)) from None
    if job.record_id and job.phase == "ready":
        from .group_members import refresh_single_retry
        refresh_single_retry(db, job, group, actor)
    if job.kind == "detach" and job.state == "failed" and job.phase == "ready":
        from .group_subscription_state import detach_context, detach_signature
        payload = json.loads(job.payload)
        if payload.get("native_activation_id"):
            record = db.get(Subscription, job.record_id)
            if not record or record.group_id != group.id or payload["native_group_id"] != group.id:
                raise HTTPException(409, "移出原生订阅成员的分组归属已变化")
            refreshed = payload | {"native_detach_signature": detach_signature(db, record, group)}
            try:
                detach_context(db, record, refreshed, job.id, actor.id)
            except AwsFailure as exc:
                raise HTTPException(409, str(exc)) from None
            # This explicit retry authorizes a new unsent attempt. Pending
            # recovery always keeps its original snapshot and never resends.
            job.payload = json.dumps(refreshed, sort_keys=True)
    if job.kind == "attach" and job.phase == "ready":
        from .group_subscription_state import member_activation, reserve_join
        record = db.get(Subscription, job.record_id)
        if not member_activation(db, record.id):
            reserve_join(db, group, record, actor, job.id)
    job.state, job.error = "queued", None
    # A retry uses its current authorizer; original admission remains in audit.
    # Keep phase and attempt history so unknown writes still reconcile safely.
    job.actor_id = actor.id
    group.state, group.error = "updating", None
    audit(
        db,
        actor,
        "retry_group",
        f"重试 AWS 分组任务：{group.name}",
        subject=group.owner_id,
        request=request,
    )
    db.commit()
    return job_view(job)
