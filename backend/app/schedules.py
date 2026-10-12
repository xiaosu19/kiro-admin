"""Persisted, per-subscription cancellation deadlines serviced by the worker."""

import json
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from .database import SessionLocal, get_db
from .models import AwsAccount, RecordOperation, StopSchedule, Subscription, User, now
from .schemas import StopPolicy, StopScheduleInput
from .security import audit, get_user

router = APIRouter(prefix="/api")
LIVE_STATES = ("waiting", "scheduled", "blocked", "queued", "needs_review", "failed")


def schedule_view(schedule):
    if not schedule:
        return None
    return {
        key: getattr(schedule, key)
        for key in (
            "mode",
            "days",
            "stop_at",
            "revision",
            "source_group_id",
            "source_group_revision",
            "individual_override",
            "principal_type",
            "state",
            "operation_id",
            "error",
            "completed_at",
            "updated_at",
        )
    }


def policy_text(schedule):
    if not schedule or schedule.mode == "none":
        return "不定时停止"
    value = f"开通后 {schedule.days} 天" if schedule.mode == "days" else "指定截止时间"
    return value + (
        f"（{schedule.stop_at.isoformat()} UTC）"
        if schedule.stop_at
        else "（等待开通成功）"
    )


def deadline(policy, subscribed_at=None, allow_expired=False):
    due = None
    if policy.mode == "days" and subscribed_at:
        due = subscribed_at + timedelta(days=policy.days)
    elif policy.mode == "at":
        due = policy.stop_at.replace(tzinfo=None)
    if due and (
        (due <= now() and not allow_expired) or due > now() + timedelta(days=3650)
    ):
        raise HTTPException(
            422, "截止时间必须在未来 10 年内；按天计算已过期时请改选指定时间"
        )
    return due


def schedule_principal(db, record, schedule):
    """Recover only an unambiguous legacy target; never redirect a saved deadline."""
    if schedule.principal_type is not None:
        return schedule.principal_type if schedule.principal_type in ("USER", "GROUP") else None
    from .models import GroupMemberActivation
    from .subscription_sources import direct_source
    history = list(db.scalars(select(GroupMemberActivation).where(
        GroupMemberActivation.record_id == record.id,
        GroupMemberActivation.counted.is_(True),
    )))
    if schedule.source_group_id and not schedule.individual_override:
        return "GROUP" if history else "USER"
    if not history:
        return "USER" if record.counted or record.plan_id else None
    if any(a.first_opening for a in history) and not direct_source(record):
        return "GROUP"
    return None


def configure(
    db,
    record,
    actor,
    policy: StopPolicy,
    request=None,
    *,
    source_group=None,
    allow_expired=False,
    preserve_none=False,
):
    schedule = db.get(StopSchedule, record.id)
    old_text = policy_text(schedule)
    from .group_subscription_state import live_grant, member_activation
    native = live_grant(db, record.group_id) if record.group_id else None
    activation = member_activation(db, record.id)
    from .subscription_sources import direct_source
    direct = direct_source(record)
    principal = (
        ("GROUP" if native else "USER") if source_group else
        schedule.principal_type if schedule and schedule.principal_type in ("USER", "GROUP") else
        "USER" if direct and direct["status"] == "active" else
        "GROUP" if activation else "USER" if record.plan_id else None
    )
    personal_user = not source_group and principal == "USER"
    anchor = native.activated_at if source_group and native else record.subscribed_at if personal_user else activation.activated_at if activation else record.subscribed_at
    due = deadline(policy, anchor, allow_expired)
    if native and not source_group and not personal_user and native.stop_at and due and due > native.stop_at:
        raise HTTPException(409, "个人停止时间不能晚于原生分组的共同截止时间")
    if (
        not schedule
        and policy.mode == "none"
        and not record.group_id
        and not preserve_none
    ):
        return None
    supersede_unclaimed_automatic(db, record, actor, request)
    if not schedule:
        schedule = StopSchedule(record_id=record.id, actor_id=actor.id, revision=0)
        db.add(schedule)
    schedule.revision += 1
    schedule.actor_id = actor.id
    schedule.source_group_id = source_group.id if source_group else None
    schedule.source_group_revision = (
        source_group.policy_revision if source_group else None
    )
    schedule.individual_override = source_group is None
    schedule.principal_type = principal
    schedule.mode, schedule.days, schedule.stop_at = policy.mode, policy.days, due
    schedule.state = (
        "disabled"
        if policy.mode == "none"
        else "scheduled"
        if record.counted
        else "waiting"
    )
    schedule.operation_id = None
    schedule.error = schedule.next_check_at = schedule.completed_at = None
    schedule.updated_at = now()
    audit(
        db,
        actor,
        "set_stop_schedule",
        f"设置定时停止：{record.username}；{old_text} → {policy_text(schedule)}",
        subject=record.owner_id,
        request=request,
    )
    return schedule


@router.put("/subscriptions/{record_id}/stop-schedule")
def set_schedule(
    record_id: str,
    body: StopScheduleInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    from .lifecycle import allowed, owned

    record = owned(db, record_id, actor)
    schedule = db.get(StopSchedule, record.id)
    if body.expected_revision != (schedule.revision if schedule else 0):
        raise HTTPException(409, "定时停止设置已变化，请刷新后重新设置")
    if (
        record.active_operation_id
        or record.state in ("queued", "running", "needs_review")
        or record.reserved
    ):
        raise HTTPException(409, "该用户有处理中或待核对任务，完成后才能修改定时停止")
    if body.policy.mode != "none":
        if not allowed(db, actor, db.get(AwsAccount, record.aws_account_id)):
            raise HTTPException(403, "AWS 账号已停用、删除或未绑定，无法设置定时停止")
        if (
            ((record.provision_only or not record.plan_id) and not record.group_id)
            or record.cancelled_at
            or record.subscription_status in ("cancelled", "cancel_scheduled")
        ):
            raise HTTPException(409, "请为待开通或已生效且尚未取消的 Kiro 订阅设置")
        if record.counted and record.subscription_status != "active":
            raise HTTPException(409, "请先同步 AWS 订阅状态，再设置定时停止")
    schedule = configure(db, record, actor, body.policy, request, preserve_none=True)
    db.commit()
    return schedule_view(schedule)


def activate_after_subscription(db, record, subscribed_at, principal_type="USER"):
    schedule = db.get(StopSchedule, record.id)
    if schedule and schedule.state == "waiting":
        schedule.principal_type = schedule.principal_type or principal_type
        if schedule.mode == "days":
            schedule.stop_at = subscribed_at + timedelta(days=schedule.days)
        schedule.state = "scheduled"
        schedule.updated_at = now()


def ensure_not_expired(db, record):
    # Use an independent read session so provisioning holds no transaction
    # across remote operations and never flushes its in-memory record.
    with SessionLocal() as current_db:
        schedule = current_db.get(StopSchedule, record.id)
        if schedule and schedule.mode == "at" and schedule.stop_at <= now():
            from .aws import AwsFailure
            raise AwsFailure("指定的停止订阅时间已过，请修改定时停止设置后再开通")


def automatic_schedule(db, op):
    payload = json.loads(op.payload)
    schedule = db.get(StopSchedule, op.record_id)
    if (
        op.kind == "cancel_subscription"
        and schedule
        and schedule.mode != "none"
        and schedule.operation_id == op.id
        and schedule.revision == payload.get("schedule_revision")
        and schedule.stop_at
        and schedule.stop_at <= now()
        and payload.get("cancellation_mode") == "IMMEDIATE"
    ):
        return schedule
    return None


def unclaimed_automatic(db, record):
    """Only a current automatic job that no worker has ever claimed is editable."""
    op = (
        db.get(RecordOperation, record.active_operation_id)
        if record.active_operation_id
        else None
    )
    if (
        op
        and op.record_id == record.id
        and op.state == "queued"
        and op.phase == "ready"
        and op.attempts == 0
        and op.lease_token is None
        and op.lease_until is None
    ):
        schedule = automatic_schedule(db, op)
        if schedule and op.request_key == f"auto-stop:{schedule.revision}":
            return op
    return None


def supersede_unclaimed_automatic(db, record, actor, request=None):
    op = unclaimed_automatic(db, record)
    if not op:
        return
    changed = db.execute(
        update(RecordOperation)
        .where(
            RecordOperation.id == op.id,
            RecordOperation.state == "queued",
            RecordOperation.phase == "ready",
            RecordOperation.attempts == 0,
            RecordOperation.lease_token.is_(None),
            RecordOperation.lease_until.is_(None),
        )
        .values(
            state="superseded",
            phase="done",
            finished_at=now(),
            result=json.dumps({"reason": "stop_schedule_changed"}),
        )
    )
    if not changed.rowcount:
        raise HTTPException(409, "定时停止任务已开始处理，规则未修改")
    changed = db.execute(
        update(Subscription)
        .where(Subscription.id == record.id, Subscription.active_operation_id == op.id)
        .values(active_operation_id=None, updated_at=now())
    )
    if not changed.rowcount:
        raise HTTPException(409, "用户操作已变化，规则未修改")
    audit(
        db,
        actor,
        "supersede_stop_schedule",
        f"更新规则，撤销未执行的定时停止：{record.username}；任务 {op.id}",
        subject=record.owner_id,
        request=request,
    )


def sync_schedule_result(db, record, op, error=None):
    schedule = db.get(StopSchedule, record.id)
    if not schedule or schedule.state in ("disabled", "completed"):
        return
    if schedule.operation_id == op.id:
        schedule.state = op.state
        schedule.error = error
        schedule.completed_at = op.finished_at if op.state == "completed" else None
        schedule.updated_at = now()
    elif op.state == "completed":
        from .subscription_sources import direct_source
        from .group_subscription_state import member_activation
        payload = json.loads(op.payload)
        direct = direct_source(record)
        principal = schedule_principal(db, record, schedule)
        user_stopped = (principal == "USER" and op.kind == "cancel_subscription"
                        and not payload.get("native_activation_id")
                        and (not direct or direct["status"] != "active"))
        # GROUP removal cannot complete a USER deadline while its independent
        # claim is still within its cancellation period (or remains active).
        group_stopped = (principal == "GROUP" and payload.get("native_activation_id")
                         and not member_activation(db, record.id))
        no_access = record.subscription_status == "cancelled"
        if user_stopped or group_stopped or no_access:
            schedule.state = "completed"
            schedule.completed_at = record.cancelled_at or now()
            schedule.error = None
            schedule.updated_at = now()


def enqueue_due(limit=100, *, account_id=None):
    scope = True if account_id is None else StopSchedule.record_id.in_(
        select(Subscription.id).where(Subscription.aws_account_id == account_id))
    current = now()
    with SessionLocal() as db:
        ids = list(
            db.scalars(
                select(StopSchedule.record_id)
                .where(
                    StopSchedule.state.in_(("scheduled", "blocked")),
                    scope,
                    StopSchedule.stop_at <= current,
                    or_(
                        StopSchedule.next_check_at.is_(None),
                        StopSchedule.next_check_at <= current,
                    ),
                )
                .order_by(StopSchedule.stop_at)
                .limit(limit)
            )
        )
    queued = 0
    for rid in ids:
        with SessionLocal() as db:
            # Atomic admission serializes with user edits, deletion and other workers.
            changed = db.execute(
                update(StopSchedule)
                .where(
                    StopSchedule.record_id == rid,
                    scope,
                    StopSchedule.state.in_(("scheduled", "blocked")),
                    StopSchedule.stop_at <= current,
                    or_(
                        StopSchedule.next_check_at.is_(None),
                        StopSchedule.next_check_at <= current,
                    ),
                )
                .values(next_check_at=current + timedelta(seconds=30))
            )
            if not changed.rowcount:
                db.rollback()
                continue
            schedule = db.get(StopSchedule, rid)
            record = db.get(Subscription, rid)
            from .group_subscription_state import member_activation, live_grant
            native = live_grant(db, record.group_id) if record.group_id else None
            principal = schedule_principal(db, record, schedule)
            if principal is None:
                schedule.state, schedule.error = "blocked", "停止规则的授权主体待核对，请重新保存个人规则或恢复分组规则"
                schedule.updated_at = current
                db.commit()
                continue
            schedule.principal_type = principal
            if member_activation(db, rid) and native and principal == "GROUP" and (
                not schedule.individual_override or (native.stop_at and schedule.stop_at >= native.stop_at)
            ):
                # The common native deadline is one GROUP cancellation.
                db.commit()
                continue
            if record.subscription_status == "cancelled":
                schedule.state, schedule.completed_at, schedule.error = (
                    "completed",
                    record.cancelled_at or current,
                    None,
                )
            elif (
                record.active_operation_id
                or record.state in ("queued", "running", "needs_review")
                or record.reserved
            ):
                pass  # A running operation owns the record; inspect again after it finishes.
            elif not record.counted or not record.sso_user_id:
                schedule.state, schedule.error = (
                    "blocked",
                    "订阅尚未核实开通成功，请管理员核对",
                )
            else:
                account = db.get(AwsAccount, record.aws_account_id)
                if not account.active or account.deleted_at:
                    message = "AWS 账号已停用或删除；恢复并启用后将继续执行定时停止"
                    if schedule.error != message:
                        audit(
                            db,
                            db.get(User, schedule.actor_id),
                            "stop_schedule_blocked",
                            f"定时停止受阻：{record.username}；{message}",
                            subject=record.owner_id,
                        )
                    schedule.state, schedule.error = "blocked", message
                else:
                    from .lifecycle import native_cancel_payload
                    from .aws import AwsFailure
                    try:
                        target_payload = native_cancel_payload(db, record, schedule=schedule)
                    except AwsFailure as exc:
                        schedule.state, schedule.error = "blocked", str(exc)
                        schedule.updated_at = current
                        db.commit()
                        continue
                    op = RecordOperation(
                        id=str(uuid.uuid4()),
                        record_id=rid,
                        actor_id=schedule.actor_id,
                        kind="cancel_subscription",
                        request_key=f"auto-stop:{schedule.revision}",
                        payload=json.dumps(
                            {
                                "cancellation_mode": "IMMEDIATE",
                                "schedule_revision": schedule.revision,
                                "principal_type": principal,
                                **target_payload,
                            }
                        ),
                    )
                    db.add(op)
                    db.flush()
                    record.active_operation_id, record.updated_at = op.id, current
                    schedule.operation_id, schedule.state, schedule.error = (
                        op.id,
                        "queued",
                        None,
                    )
                    audit(
                        db,
                        db.get(User, schedule.actor_id),
                        "run_stop_schedule",
                        f"到期定时停止：{record.username}；{policy_text(schedule)}",
                        subject=record.owner_id,
                    )
                    queued += 1
            schedule.updated_at = current
            db.commit()
    return queued
