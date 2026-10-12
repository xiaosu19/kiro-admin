"""Owner-filtered admission and recovery APIs for the independent change ledger."""

import hashlib
import json
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from .batches import require_account, require_plan
from .catalog import BY_SUBSCRIPTION_TYPE, PLAN_ORDER
from .config import settings
from .database import get_db
from .lifecycle import owned
from .models import (
    AwsAccount,
    ManagedGroup,
    Plan,
    PlanChange,
    PlanCounter,
    RecordOperation,
    StopSchedule,
    Subscription,
    User,
    now,
)
from .plan_change_state import change_view, current_plan, direct_user_plan, scheduled_change
from .security import audit, get_user


def require_plan_changes(_: User = Depends(get_user)):
    if not settings.plan_changes_enabled:
        raise HTTPException(403, "此站点未启用套餐变更")


router = APIRouter(
    prefix="/api/subscriptions", dependencies=[Depends(require_plan_changes)]
)


class ChangeInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_plan_id: int
    expected_current_type: str = Field(min_length=1, max_length=100)
    confirm_username: str
    request_key: str = Field(min_length=16, max_length=80)


class WithdrawInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_current_type: str = Field(min_length=1, max_length=100)
    confirm_username: str
    request_key: str = Field(min_length=16, max_length=80)


class RecheckInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm_username: str


class ReleaseInput(RecheckInput):
    reason: str = Field(min_length=5, max_length=500)
    acknowledge_not_applied: bool


def admission_owner(db, record, actor):
    from .auth_principals import active_external_login
    if active_external_login(db, record):
        raise HTTPException(409, "该用户已有粘贴账号认证任务，请先处理或取消原任务")
    from .group_subscription_state import member_activation
    from .subscription_sources import direct_source, saved_observation
    direct = direct_source(record)
    if ((saved_observation(record) and (not direct or direct["status"] != "active"))
            or (member_activation(db, record.id) and not direct)):
        raise HTTPException(409, "没有已确认且有效的独立 USER 授权，请管理分组订阅或同步状态")
    account = db.get(AwsAccount, record.aws_account_id)
    owner = db.get(User, record.owner_id)
    if (
        not owner
        or not owner.active
        or owner.deleted_at
        or not actor
        or not actor.active
        or actor.deleted_at
    ):
        raise HTTPException(409, "SSO 所有者或操作者已停用、删除")
    require_account(db, actor, account)
    require_account(db, owner, account)
    if (
        not record.sso_user_id
        or record.sso_deleted_at
        or record.state != "completed"
        or record.reserved
        or not record.counted
        or record.cancelled_at
        or record.subscription_status != "active"
    ):
        raise HTTPException(409, "仅可变更已生效且未取消的 Kiro 订阅，请先同步状态")
    if record.group_id:
        group = db.get(ManagedGroup, record.group_id)
        if not group or group.state != "ready" or group.active_job_id:
            raise HTTPException(409, "分组有处理中任务，请完成后变更")
    return owner


def reserve_target(db, owner, plan_id):
    if owner.role == "admin":
        return None, None
    row = db.execute(
        update(PlanCounter)
        .where(
            PlanCounter.user_id == owner.id,
            PlanCounter.plan_id == plan_id,
            PlanCounter.used_count + PlanCounter.pending_count
            < PlanCounter.limit_count,
        )
        .values(pending_count=PlanCounter.pending_count + 1)
        .returning(PlanCounter.id, PlanCounter.cycle_number)
    ).first()
    if not row:
        raise HTTPException(409, "SSO 所有者的目标套餐次数已用完或未设置，请联系管理员")
    return row


def ensure_change_deadline(db, record):
    schedule = db.get(StopSchedule, record.id)
    if (
        schedule
        and schedule.mode != "none"
        and schedule.stop_at
        and schedule.stop_at <= now()
    ):
        raise HTTPException(
            409, "保存的停止订阅时间已到，本次套餐变更未提交；请先处理定时停止"
        )


def admit(db, record, actor, body, request, predecessor=None, withdraw=False):
    digest = hashlib.sha256(
        json.dumps(
            body.model_dump()
            | {
                "record_id": record.id,
                "withdraw": withdraw,
                "predecessor": predecessor.id if withdraw else None,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    old = db.scalar(
        select(PlanChange).where(
            or_(PlanChange.record_id == record.id, PlanChange.actor_id == actor.id),
            PlanChange.request_key == body.request_key,
        )
    )
    if old:
        if old.actor_id != actor.id or old.payload_hash != digest:
            raise HTTPException(409, "重复请求标识与原操作者或内容不符")
        return old
    if body.confirm_username != record.username:
        raise HTTPException(409, "确认用户名不匹配")
    owner = admission_owner(db, record, actor)
    current = direct_user_plan(db, record)
    if (
        current["subscription_type"] != body.expected_current_type
        or current["subscription_type"] not in PLAN_ORDER
    ):
        raise HTTPException(409, "当前套餐已变化或不受支持，请刷新后重新选择")
    pending = scheduled_change(db, record.id)
    if withdraw:
        if not predecessor or predecessor.id != (pending.id if pending else None):
            raise HTTPException(409, "该待生效变更已变化，请刷新")
        plan = db.get(Plan, current["plan_id"])
        direction = "withdraw"
    else:
        ensure_change_deadline(db, record)
        plan = require_plan(db, body.target_plan_id)
        if plan.subscription_type not in PLAN_ORDER:
            raise HTTPException(409, "该套餐不支持变更")
        if plan.subscription_type == current["subscription_type"] or (
            pending and plan.subscription_type == pending.to_type
        ):
            raise HTTPException(409, "目标与当前或待生效套餐相同")
        direction = (
            "upgrade"
            if PLAN_ORDER[plan.subscription_type]
            > PLAN_ORDER[current["subscription_type"]]
            else "downgrade"
        )
        predecessor = pending
    op_id = str(uuid.uuid4())
    changed = db.execute(
        update(Subscription)
        .where(
            Subscription.id == record.id,
            Subscription.active_operation_id.is_(None),
            Subscription.updated_at == record.updated_at,
            Subscription.state == "completed",
            Subscription.sso_deleted_at.is_(None),
        )
        .values(active_operation_id=op_id, updated_at=now())
    )
    if not changed.rowcount:
        raise HTTPException(409, "该 SSO 用户已有操作正在处理")
    counter_id, cycle = (None, None) if withdraw else reserve_target(db, owner, plan.id)
    c = PlanChange(
        id=str(uuid.uuid4()),
        record_id=record.id,
        operation_id=op_id,
        actor_id=actor.id,
        owner_id=owner.id,
        request_key=body.request_key,
        payload_hash=digest,
        direction=direction,
        from_plan_id=current["plan_id"],
        from_plan_name=current["name"] or db.get(Plan, current["plan_id"]).name,
        from_type=current["subscription_type"],
        to_plan_id=plan.id,
        to_plan_name=plan.name,
        to_type=plan.subscription_type,
        predecessor_id=predecessor.id if predecessor else None,
        counter_id=counter_id,
        cycle_number=cycle,
        reserved=counter_id is not None,
    )
    db.add(
        RecordOperation(
            id=op_id,
            record_id=record.id,
            actor_id=actor.id,
            kind="withdraw_plan_change" if withdraw else "change_plan",
            request_key=f"plan-change:{c.id}",
            payload=json.dumps({"change_id": c.id}),
        )
    )
    db.flush()
    db.add(c)
    audit(
        db,
        actor,
        "request_plan_change",
        f"{record.username}：{c.from_plan_name} → {c.to_plan_name}（{direction}）",
        subject=record.owner_id,
        request=request,
    )
    db.commit()
    return c


@router.get("/{record_id}/plan-options")
def options(
    record_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)
):
    record = owned(db, record_id, actor)
    current, pending = direct_user_plan(db, record), scheduled_change(db, record.id)
    reason = None
    try:
        owner = admission_owner(db, record, actor)
        if record.active_operation_id:
            reason = "该 SSO 用户已有操作正在处理"
    except HTTPException as exc:
        owner, reason = db.get(User, record.owner_id), exc.detail
    targets = []
    for p in db.scalars(
        select(Plan).where(Plan.active.is_(True), Plan.deleted_at.is_(None))
    ):
        if p.subscription_type not in PLAN_ORDER:
            continue
        c = db.scalar(
            select(PlanCounter).where(
                PlanCounter.user_id == record.owner_id, PlanCounter.plan_id == p.id
            )
        )
        unlimited = bool(owner and owner.role == "admin")
        remaining = (
            None
            if unlimited
            else max(0, c.limit_count - c.used_count - c.pending_count)
            if c
            else 0
        )
        same = p.subscription_type == current["subscription_type"] or (
            pending and p.subscription_type == pending.to_type
        )
        disabled = (
            reason
            or ("与当前或待生效套餐相同" if same else None)
            or ("目标套餐次数不足" if not unlimited and not remaining else None)
        )
        targets.append(
            dict(
                plan_id=p.id,
                name=p.name,
                subscription_type=p.subscription_type,
                reference=BY_SUBSCRIPTION_TYPE[p.subscription_type],
                unlimited=unlimited,
                remaining_count=remaining,
                used_count=c.used_count if c else 0,
                pending_count=c.pending_count if c else 0,
                available=not bool(disabled),
                unavailable_reason=disabled,
                direction="upgrade"
                if PLAN_ORDER[p.subscription_type]
                > PLAN_ORDER.get(current["subscription_type"], -1)
                else "downgrade",
            )
        )
    return dict(
        current_plan=current,
        effective_plan=current_plan(db, record),
        pending_change=change_view(pending, actor) if pending else None,
        targets=targets,
        unavailable_reason=reason,
        owner_id=record.owner_id,
    )


@router.get("/{record_id}/plan-changes")
def history(
    record_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)
):
    owned(db, record_id, actor)
    return [
        change_view(c, actor)
        for c in db.scalars(
            select(PlanChange)
            .where(PlanChange.record_id == record_id)
            .order_by(PlanChange.requested_at.desc())
            .limit(100)
        )
    ]


@router.post("/{record_id}/plan-changes", status_code=202)
def enqueue(
    record_id: str,
    body: ChangeInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    return change_view(
        admit(db, owned(db, record_id, actor), actor, body, request), actor
    )


def selected_change(db, record_id, change_id, actor):
    record = owned(db, record_id, actor)
    c = db.get(PlanChange, change_id)
    if not c or c.record_id != record.id:
        raise HTTPException(404, "套餐变更不存在")
    return record, c


@router.post("/{record_id}/plan-changes/{change_id}/withdraw", status_code=202)
def withdraw(
    record_id: str,
    change_id: str,
    body: WithdrawInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    record, c = selected_change(db, record_id, change_id, actor)
    return change_view(
        admit(db, record, actor, body, request, predecessor=c, withdraw=True), actor
    )


def queue_recheck(db, record, c, actor, body, request, release=False):
    if body.confirm_username != record.username:
        raise HTTPException(409, "确认用户名不匹配")
    op = db.get(RecordOperation, c.operation_id)
    if release and (
        not body.acknowledge_not_applied
        or not c.write_requested_at
        or now() - c.write_requested_at < timedelta(minutes=10)
    ):
        raise HTTPException(
            409, "写入后至少等待 10 分钟，并确认核对未生效；将再次只读查询 AWS"
        )
    if c.state == "scheduled" and not release:
        c.next_check_at = now()
    else:
        if c.state == "scheduled" and release:
            changed = db.execute(
                update(Subscription)
                .where(
                    Subscription.id == record.id,
                    Subscription.active_operation_id.is_(None),
                )
                .values(active_operation_id=op.id, updated_at=now())
            )
            if not changed.rowcount:
                raise HTTPException(409, "该 SSO 用户已有操作正在处理")
        elif (
            c.state != "needs_review"
            or record.active_operation_id != op.id
            or op.state != "needs_review"
        ):
            raise HTTPException(409, "该变更无需核对或正在处理")
        payload = json.loads(op.payload)
        payload.pop("confirm_not_applied", None)
        if release:
            payload["confirm_not_applied"] = {
                "actor_id": actor.id,
                "reason": body.reason,
            }
        op.payload = json.dumps(payload)
        op.state, op.error = "queued", None
        # A pending operation is NEVER reset to ready by a recheck or safe release.
        op.phase = "pending"
    audit(
        db,
        actor,
        "confirm_plan_change_not_applied" if release else "recheck_plan_change",
        f"核对 {record.username} 的变更 {c.id}"
        + (f"；{body.reason}" if release else ""),
        subject=record.owner_id,
        request=request,
    )
    db.commit()
    return change_view(c, actor)


@router.post("/{record_id}/plan-changes/{change_id}/recheck", status_code=202)
def recheck(
    record_id: str,
    change_id: str,
    body: RecheckInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    record, c = selected_change(db, record_id, change_id, actor)
    return queue_recheck(db, record, c, actor, body, request)


@router.post(
    "/{record_id}/plan-changes/{change_id}/confirm-not-applied", status_code=202
)
def confirm_not_applied(
    record_id: str,
    change_id: str,
    body: ReleaseInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    record, c = selected_change(db, record_id, change_id, actor)
    return queue_recheck(db, record, c, actor, body, request, release=True)
