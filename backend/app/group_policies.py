"""Versioned group policy inheritance; validate the complete change before writes."""

from datetime import timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from .batches import require_account
from .database import get_db
from .models import AwsAccount, ManagedGroup, StopSchedule, User, now
from .schemas import StopPolicy
from .schedules import configure, deadline, schedule_view, unclaimed_automatic
from .security import audit, get_user

router = APIRouter(prefix="/api")


class GroupPolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    policy: StopPolicy
    expected_revision: int = Field(ge=0)
    overwrite_individual: bool = False


class ResetGroupPolicyInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_revision: int = Field(ge=0)
    expected_group_revision: int = Field(ge=0)


def group_policy(group):
    return StopPolicy(
        mode=group.policy_mode,
        days=group.policy_days,
        stop_at=group.policy_stop_at.replace(tzinfo=timezone.utc)
        if group.policy_stop_at
        else None,
    )


def historical(record):
    return bool(
        record.sso_deleted_at
        or record.cancelled_at
        or record.subscription_status in ("cancelled", "cancel_scheduled")
    )


def busy(db, record):
    return bool(
        (record.active_operation_id and not unclaimed_automatic(db, record))
        or record.reserved
        or record.state in ("queued", "running", "needs_review")
        or record.subscription_status in ("unknown", "pending")
        or (record.counted and record.subscription_status != "active")
    )


def individual(schedule):
    # Schedules made before the SSO joined a group are individual settings too.
    return schedule is not None and (
        schedule.individual_override or not schedule.source_group_id
    )


def inherit(db, record, actor, request=None):
    if not record.group_id or historical(record):
        return
    group = db.get(ManagedGroup, record.group_id)
    schedule = db.get(StopSchedule, record.id)
    if individual(schedule):
        schedule.individual_override = True
        return
    if (
        schedule
        and schedule.source_group_id == group.id
        and schedule.source_group_revision == group.policy_revision
    ):
        return
    configure(
        db,
        record,
        actor,
        group_policy(group),
        request,
        source_group=group,
        allow_expired=record.provision_only and not record.counted,
    )


def ensure_paid_deadline(db, record):
    schedule = db.get(StopSchedule, record.id)
    if schedule and schedule.mode == "at" and schedule.stop_at <= now():
        raise HTTPException(422, "指定的停止订阅时间已过，请延长或关闭后再开通")


def preview_change(db, group, body):
    from .groups import local_members

    if group.policy_revision != body.expected_revision:
        raise HTTPException(409, "分组停止规则已变化，请刷新后重试")
    from .group_subscription_state import live_grant
    from .group_subscription_worker import unclaimed_automatic
    native = live_grant(db, group.id)
    automatic = unclaimed_automatic(db, group)
    if native and native.state != "active":
        raise HTTPException(409, "原生分组订阅正在处理或等待取消生效")
    if group.state != "ready" or (group.active_job_id and not automatic):
        raise HTTPException(409, "分组存在未完成任务")
    deadline(body.policy, native.activated_at if native else None)
    affected, skipped, conflicts = [], [], []
    for record in local_members(db, group):
        if historical(record):
            skipped.append({"id": record.id, "reason": "historical"})
        elif (
            individual(db.get(StopSchedule, record.id))
            and not body.overwrite_individual
        ):
            skipped.append({"id": record.id, "reason": "individual_override"})
        elif busy(db, record) and not (automatic and record.active_operation_id == automatic.id):
            conflicts.append({"id": record.id, "reason": "operation_pending"})
        else:
            deadline(body.policy, native.activated_at if native else record.subscribed_at)
            affected.append(record)
    result = {
        "group_id": group.id,
        "revision": group.policy_revision,
        "affected_ids": [r.id for r in affected],
        "affected_count": len(affected),
        "skipped": skipped,
        "skipped_count": len(skipped),
        "conflicts": conflicts,
        "conflict_count": len(conflicts),
    }
    return affected, result


@router.post("/groups/{group_id}/policy/preview")
def policy_preview(
    group_id: str,
    body: GroupPolicyInput,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    from .groups import owned_group

    group = owned_group(db, group_id, actor)
    return preview_change(db, group, body)[1]


@router.put("/groups/{group_id}/policy")
def set_group_policy(
    group_id: str,
    body: GroupPolicyInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    from .groups import owned_group, group_view

    group = owned_group(db, group_id, actor)
    result = apply_group_policy(db, group, body, actor, request)
    db.commit()
    return result


def apply_group_policy(db, group, body, actor, request=None):
    from .groups import group_view

    if body.policy.mode != "none":
        require_account(db, actor, db.get(AwsAccount, group.aws_account_id))
    records, result = preview_change(db, group, body)
    if result["conflict_count"]:
        raise HTTPException(409, "部分分组成员存在处理中或待核对任务，规则未修改")
    from .group_subscription_worker import supersede_automatic
    from .group_subscription_state import live_grant, group_deadline
    supersede_automatic(db, group)
    group.policy_mode, group.policy_days = body.policy.mode, body.policy.days
    group.policy_stop_at = (
        body.policy.stop_at.replace(tzinfo=None) if body.policy.stop_at else None
    )
    group.policy_revision += 1
    group.updated_at = now()
    native = live_grant(db, group.id)
    if native:
        native.stop_at = group_deadline(group, native.activated_at)
        native.policy_revision = group.policy_revision
    for record in records:
        configure(db, record, actor, body.policy, request, source_group=group)
    audit(
        db,
        actor,
        "set_group_policy",
        f"修改分组停止规则：{group.name}；影响 {len(records)} 名成员",
        subject=group.owner_id,
        request=request,
    )
    return result | {
        "revision": group.policy_revision,
        "policy": group_view(group)["policy"],
    }


@router.post("/subscriptions/{record_id}/stop-schedule/reset-to-group")
def reset_to_group(
    record_id: str,
    body: ResetGroupPolicyInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    from .lifecycle import owned
    from .groups import owned_group

    record = owned(db, record_id, actor)
    if not record.group_id:
        raise HTTPException(409, "该用户没有管理分组")
    group = owned_group(db, record.group_id, actor)
    schedule = db.get(StopSchedule, record.id)
    if (
        body.expected_revision != (schedule.revision if schedule else 0)
        or body.expected_group_revision != group.policy_revision
    ):
        raise HTTPException(409, "停止规则已变化，请刷新后重试")
    if (
        busy(db, record)
        or historical(record)
        or group.state != "ready"
        or group.active_job_id
    ):
        raise HTTPException(409, "该用户或分组存在未完成任务，或已取消、删除")
    require_account(db, actor, db.get(AwsAccount, group.aws_account_id))
    schedule = configure(
        db,
        record,
        actor,
        group_policy(group),
        request,
        source_group=group,
        allow_expired=record.provision_only,
    )
    db.commit()
    return schedule_view(schedule)
