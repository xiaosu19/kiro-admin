"""Independent SSO / subscription operations with durable intent and per-record locks."""

import json
import logging
import uuid
from datetime import timedelta

from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict
from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.orm import Session

from .account_dispatcher import (
    record_scope,
    run_fenced,
)
from .auth_credentials import (
    AUTH_KINDS,
    invalidate_credentials,
    reset_one_time_password,
)
from .aws import AwsFailure, AwsGateway
from .config import settings
from .database import SessionLocal, get_db
from .models import (
    AwsAccount,
    Binding,
    ManagedGroup,
    RecordOperation,
    Subscription,
    User,
    now,
)
from .schedules import automatic_schedule, sync_schedule_result
from .schemas import OperationInput
from .security import audit, encrypt, get_user
from .worker_guards import attempt_config, check_config, check_provisioning

router = APIRouter(prefix="/api")
logger = logging.getLogger("kiro.lifecycle")
ACTION_NAMES = {
    "cancel_subscription": "取消 Kiro 订阅",
    "delete_sso": "删除 SSO 用户",
    "reset_password": "重置一次性密码",
    "update_sso": "更新 SSO 姓名和邮箱",
    "sync_status": "同步 AWS 状态",
}


def owned(db, record_id, actor):
    r = db.get(Subscription, record_id)
    if not r or (actor.role != "admin" and r.owner_id != actor.id):
        raise HTTPException(404, "SSO 用户记录不存在")
    return r


def allowed(db, actor, account):
    return (
        actor.active
        and not actor.deleted_at
        and account.active
        and not account.deleted_at
        and (
            actor.role == "admin" or db.get(Binding, (actor.id, account.id)) is not None
        )
    )


def initial_password_recovery(r, kind):
    return kind == "reset_password" and r.state == "needs_review" and r.step == "password_pending"


def operation_view(op):
    return {
        k: getattr(op, k)
        for k in (
            "id",
            "kind",
            "state",
            "attempts",
            "error",
            "created_at",
            "finished_at",
        )
    } | {
        "result": json.loads(op.result) if op.result else None,
        "automatic": bool(json.loads(op.payload).get("schedule_revision")),
    }


def native_cancel_payload(db, record, *, schedule=None):
    from .group_subscription_state import detach_payload
    if schedule and schedule.principal_type == "USER":
        return {"principal_type": "USER"}
    if schedule and schedule.principal_type != "GROUP":
        raise AwsFailure("停止规则的授权主体待核对")
    payload = detach_payload(db, record)
    if schedule and not payload:
        raise AwsFailure("停止规则的 GROUP 授权已不存在，请恢复分组规则或核对原主体")
    return payload | {"principal_type": "GROUP" if payload else "USER"}


def validate_operation(db, r, actor, kind, mode=None):
    from .auth_principals import active_external_login

    if active_external_login(db, r):
        raise HTTPException(409, "该用户已有粘贴账号认证任务，请先处理或取消原任务")
    a = db.get(AwsAccount, r.aws_account_id)
    if not allowed(db, actor, a):
        raise HTTPException(
            403, "AWS 账号已停用、删除或未绑定；请管理员恢复、启用并绑定后再操作"
        )
    recovering_password = initial_password_recovery(r, kind)
    if not r.sso_user_id or (not recovering_password and (r.state not in ("completed", "failed") or r.reserved)):
        raise HTTPException(409, "请先完成或核对开通任务，再管理 SSO 用户")
    if r.sso_deleted_at and kind not in ("cancel_subscription", "sync_status"):
        raise HTTPException(409, "SSO 用户已删除")
    if r.group_id:
        group = db.get(ManagedGroup, r.group_id)
        locks = (None, r.active_operation_id, r.id) if recovering_password else (None, r.active_operation_id)
        if group and (group.state != "ready" or group.active_job_id not in locks):
            raise HTTPException(409, "分组存在未完成任务，请先核对")
    if kind == "cancel_subscription":
        from .group_subscription_state import member_activation
        if member_activation(db, r.id) and mode == "END_OF_PERIOD":
            raise HTTPException(409, "原生分组授权仅支持立即移出成员；整组取消可选择月末")
        if r.cancelled_at:
            raise HTTPException(409, "该记录已完成取消操作，请同步 AWS 状态")
        if not r.counted and r.subscription_status not in (
            "active",
            "cancel_scheduled",
        ):
            raise HTTPException(409, "没有可取消的已开通订阅")
        if mode == "END_OF_PERIOD" and a.control_plane != "kiro":
            raise HTTPException(409, "该 AWS 账号的旧控制面仅支持立即停止访问")


@router.get("/subscriptions/{record_id}/operations")
def operations(
    record_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)
):
    owned(db, record_id, actor)
    query = select(RecordOperation).where(
        RecordOperation.record_id == record_id,
        or_(
            RecordOperation.kind.not_in(AUTH_KINDS),
            RecordOperation.actor_id == actor.id,
        ),
    )
    if actor.role != "admin":
        query = query.where(RecordOperation.actor_id == actor.id)
    return [
        operation_view(op) | {"actor_name": db.get(User, op.actor_id).display_name}
        for op in db.scalars(
            query.order_by(RecordOperation.created_at.desc()).limit(100)
        )
    ]


@router.post("/subscriptions/{record_id}/operations", status_code=202)
def enqueue(
    record_id: str,
    body: OperationInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    r = owned(db, record_id, actor)
    if body.kind == "delete_sso":
        raise HTTPException(409, "删除 SSO 必须先取消订阅；请使用级联删除预览，确认完整范围后提交")
    if (
        body.kind not in ("sync_status", "update_sso")
        and body.confirm_username != r.username
    ):
        raise HTTPException(409, "确认用户名不匹配")
    payload = {}
    if body.kind == "cancel_subscription":
        payload["cancellation_mode"] = body.cancellation_mode
    if body.kind == "update_sso":
        payload.update(display_name=body.display_name, email=str(body.email))
    encoded = json.dumps(payload, sort_keys=True)
    old = db.scalar(
        select(RecordOperation).where(
            RecordOperation.record_id == r.id,
            RecordOperation.request_key == body.request_key,
        )
    )
    if old:
        old_input = {k: v for k, v in json.loads(old.payload).items()
                     if not k.startswith("native_") and k not in ("principal_type", "worker_config_hash")}
        if old.kind != body.kind or old_input != payload:
            raise HTTPException(409, "重复请求标识与原操作不符")
        return operation_view(old)
    validate_operation(db, r, actor, body.kind, body.cancellation_mode)
    recovering_password = initial_password_recovery(r, body.kind)
    if body.kind == "delete_sso" and not body.acknowledge_subscription:
        raise HTTPException(
            409, "请确认删除 SSO 不会代替取消 Kiro 订阅，也不会返还开通次数"
        )
    operation_id = str(uuid.uuid4())
    changed = db.execute(
        update(Subscription)
        .where(
            Subscription.id == r.id,
            Subscription.active_operation_id.is_(None),
            Subscription.updated_at == r.updated_at,
            or_(Subscription.state.in_(("completed", "failed")),
                and_(Subscription.state == "needs_review", Subscription.step == "password_pending")
                if recovering_password else False),
        )
        .values(active_operation_id=operation_id, updated_at=now())
    )
    if not changed.rowcount:
        raise HTTPException(409, "该用户已有操作正在处理，请查看操作进度")
    if body.kind == "cancel_subscription":
        payload.update(native_cancel_payload(db, r))
        encoded = json.dumps(payload, sort_keys=True)
    if recovering_password:
        payload["worker_config_hash"] = r.worker_config_hash
        encoded = json.dumps(payload, sort_keys=True)
    op = RecordOperation(
        id=operation_id,
        record_id=r.id,
        actor_id=actor.id,
        kind=body.kind,
        request_key=body.request_key,
        payload=encoded,
        phase="reset_authorized" if recovering_password else "ready",
    )
    db.add(op)
    audit(
        db,
        actor,
        "request_" + body.kind,
        f"{ACTION_NAMES[body.kind]}：{r.username}",
        subject=r.owner_id,
        request=request,
    )
    db.commit()
    return operation_view(op)


class RetryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm_username: str


@router.post(
    "/subscriptions/{record_id}/operations/{operation_id}/retry", status_code=202
)
def retry_operation(
    record_id: str,
    operation_id: str,
    body: RetryInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    r = owned(db, record_id, actor)
    op = db.get(RecordOperation, operation_id)
    if not op or op.record_id != r.id or op.kind not in ACTION_NAMES:
        raise HTTPException(404, "操作不存在")
    if body.confirm_username != r.username:
        raise HTTPException(409, "确认用户名不匹配")
    validate_operation(
        db, r, actor, op.kind, json.loads(op.payload).get("cancellation_mode")
    )
    if op.state in ("queued", "running"):
        return operation_view(op)
    if op.state != "needs_review" or r.active_operation_id != op.id:
        raise HTTPException(409, "该操作不需要核对，请刷新记录")
    # The existing confirmed password retry explicitly authorizes one new OTP.
    # Keep its original uncertain intent/configuration until the pre-wire commit;
    # other pending operations only reconcile their saved remote result.
    phase = "reset_authorized" if op.kind == "reset_password" else op.phase
    changed = db.execute(
        update(RecordOperation)
        .where(RecordOperation.id == op.id, RecordOperation.state == "needs_review")
        .values(state="queued", phase=phase, error=None, actor_id=actor.id)
    )
    if not changed.rowcount:
        raise HTTPException(409, "操作已经在处理")
    sync_schedule_result(db, r, op)
    audit(
        db,
        actor,
        "retry_" + op.kind,
        f"确认再次处理 {ACTION_NAMES[op.kind]}：{r.username}",
        subject=r.owner_id,
        request=request,
    )
    db.commit()
    return operation_view(op)


def claim_operation(kinds=ACTION_NAMES, *, account_id=None):
    with SessionLocal() as db:
        native_group_id = func.json_extract(RecordOperation.payload, "$.native_group_id")
        eligible = or_(
            RecordOperation.state == "queued",
            and_(
                RecordOperation.state == "running", RecordOperation.lease_until < now()
            ),
        )
        eligible = and_(eligible, or_(
            native_group_id.is_(None),
            select(ManagedGroup.id).where(
                ManagedGroup.id == native_group_id,
                or_(ManagedGroup.active_job_id.is_(None),
                    ManagedGroup.active_job_id == RecordOperation.id),
            ).exists(),
        ))
        eligible = and_(eligible, record_scope(account_id))
        op_id = db.scalar(
            select(RecordOperation.id)
            .where(eligible, RecordOperation.kind.in_(kinds))
            .order_by(RecordOperation.created_at)
            .limit(1)
        )
        if not op_id:
            return None
        candidate = db.get(RecordOperation, op_id)
        payload = json.loads(candidate.payload)
        token = str(uuid.uuid4())
        changed = db.execute(
            update(RecordOperation)
            .where(RecordOperation.id == op_id, eligible)
            .values(
                state="running",
                lease_token=token,
                lease_until=now() + timedelta(seconds=settings.worker_lease_seconds),
                attempts=RecordOperation.attempts + 1,
            )
        )
        if changed.rowcount and payload.get("native_group_id"):
            group_lock = db.execute(update(ManagedGroup).where(
                ManagedGroup.id == payload["native_group_id"],
                or_(ManagedGroup.active_job_id.is_(None), ManagedGroup.active_job_id == op_id),
            ).values(active_job_id=op_id))
            if not group_lock.rowcount:
                db.rollback()
                return None
        db.commit()
        return (op_id, token) if changed.rowcount else None


def load(db, op_id, token):
    op = db.get(RecordOperation, op_id)
    if not op or op.state != "running" or op.lease_token != token:
        raise RuntimeError("操作租约失效")
    r = db.get(Subscription, op.record_id)
    if r.active_operation_id != op.id:
        raise RuntimeError("用户操作锁失效")
    return op, r


def lock_lease(db, op_id, token):
    changed = db.execute(
        update(RecordOperation)
        .where(
            RecordOperation.id == op_id,
            RecordOperation.state == "running",
            RecordOperation.lease_token == token,
        )
        .values(lease_until=now() + timedelta(seconds=settings.worker_lease_seconds))
    )
    if not changed.rowcount:
        raise RuntimeError("操作租约失效")


def mark_pending(op_id, token, clear_password=False, *, frozen_config=None):
    with SessionLocal() as db:
        lock_lease(db, op_id, token)
        op, r = load(db, op_id, token)
        payload = json.loads(op.payload)
        if frozen_config is not None:
            account = db.get(AwsAccount, r.aws_account_id)
            schedule = automatic_schedule(db, op)
            if payload.get("schedule_revision") and not schedule:
                raise AwsFailure("定时停止规则已变更，本次旧版本任务已失效")
            permitted = account.active and not account.deleted_at if schedule else allowed(db, db.get(User, op.actor_id), account)
            if not permitted:
                raise AwsFailure("操作者或 AWS 绑定已停用")
            check_config(db, account, frozen_config)
            if initial_password_recovery(r, op.kind):
                check_provisioning(db, r, account, frozen_config, allow_stopped=True)
                if r.group_id:
                    from .group_subscription_state import checkpoint_join
                    checkpoint_join(db, r.id, mark_intent=False, creation_reset=True)
            payload["worker_config_hash"] = frozen_config
            op.payload = json.dumps(payload)
        if payload.get("native_activation_id"):
            from .group_subscription_state import detach_context
            schedule = automatic_schedule(db, op)
            if payload.get("schedule_revision") and not schedule:
                raise AwsFailure("定时停止规则已变更，本次旧版本任务已失效")
            detach_context(db, r, payload, op.id, op.actor_id, automatic=bool(schedule))
        op.phase = "pending"
        op.lease_until = now() + timedelta(seconds=settings.worker_lease_seconds)
        if clear_password or op.kind == "delete_sso":
            invalidate_credentials(db, r, clear_password=clear_password)
        db.commit()


def complete(op_id, token, values, request_id=None):
    with SessionLocal() as db:
        lock_lease(db, op_id, token)
        op, r = load(db, op_id, token)
        # The immutable opening plan, time and counters are never lifecycle fields.
        writable = {
            "subscription_status",
            "observed_subscription_type",
            "subscription_observation",
            "cancelled_at",
            "cancellation_mode",
            "access_ends_at",
            "sso_display_name",
            "email",
            "sso_deleted_at",
            "password_encrypted",
            "password_generated_at",
            "last_synced_at",
        }
        if not set(values).issubset(writable):
            raise RuntimeError("禁止修改订阅历史字段")
        if (
            values.get("sso_deleted_at")
            and not r.sso_deleted_at
            and (op.kind != "delete_sso" or op.phase != "pending")
        ):
            invalidate_credentials(db, r)
        payload = json.loads(op.payload)
        if payload.get("native_activation_id"):
            from .group_subscription_state import detach_member
            detach_member(db, r)
            r.group_id = r.group_membership_id = None
            group = db.get(ManagedGroup, payload["native_group_id"])
            if group.active_job_id == op.id:
                group.active_job_id = None
        for key, value in values.items():
            setattr(r, key, value)
        if op.kind == "reset_password" and values.get("password_encrypted"):
            r.credential_state = "one_time"
            r.credential_recovery_encrypted = None
            if initial_password_recovery(r, op.kind):
                # Only a confirmed, explicitly requested reset resolves the
                # initial unknown OTP. Keep quota/activation for the SSO worker.
                r.state, r.step = "queued", "subscribe"
                r.worker_config_hash = None
                r.error = None
        if values.get("sso_deleted_at"):
            r.credential_state = "unknown"
            r.credential_recovery_encrypted = None
        r.active_operation_id = None
        r.updated_at = now()
        op.state, op.phase, op.error = "completed", "done", None
        op.lease_token = op.lease_until = None
        op.finished_at, op.aws_request_id = now(), request_id
        op.result = json.dumps(
            {
                k: (v.isoformat() if hasattr(v, "isoformat") else v)
                for k, v in values.items()
                if k != "password_encrypted"
            },
            ensure_ascii=False,
        )
        sync_schedule_result(db, r, op)
        audit(
            db,
            db.get(User, op.actor_id),
            op.kind + "_completed",
            f"{ACTION_NAMES[op.kind]}成功：{r.username}",
            subject=r.owner_id,
        )
        db.commit()


def fail(op_id, token, message, uncertain):
    with SessionLocal() as db:
        lock_lease(db, op_id, token)
        op, r = load(db, op_id, token)
        op.state = "needs_review" if uncertain else "failed"
        op.error = message
        op.lease_token = op.lease_until = None
        if not uncertain:
            payload = json.loads(op.payload)
            payload.pop("worker_config_hash", None)
            op.payload = json.dumps(payload)
            if payload.get("native_group_id"):
                group = db.get(ManagedGroup, payload["native_group_id"])
                if group.active_job_id == op.id:
                    group.active_job_id = None
            r.active_operation_id = None
            op.finished_at = now()
        r.updated_at = now()
        sync_schedule_result(db, r, op, message)
        audit(
            db,
            db.get(User, op.actor_id),
            op.kind + "_" + op.state,
            f"{ACTION_NAMES[op.kind]}：{r.username}；{message}",
            subject=r.owner_id,
        )
        db.commit()


def subscription_values(r, info, mode=None):
    status = info["status"]
    mode = mode or r.cancellation_mode
    expiry = info["expires_at"]
    if status == "not_subscribed" and r.counted:
        status = "cancelled"
    if status == "cancelled" and mode == "END_OF_PERIOD" and expiry and expiry > now():
        status = "cancel_scheduled"
    return {
        "subscription_status": status,
        "observed_subscription_type": info["subscription_type"],
        "access_ends_at": expiry if mode == "END_OF_PERIOD" else None,
        "last_synced_at": now(),
    }


def verify_user_cancellation_sources(gateway, record, *, allow_absent=False):
    from .subscription_sources import confirmed_sources
    sources = confirmed_sources(gateway, record)
    direct = next((c for c in sources if c["source"] == "USER"), None)
    if not allow_absent and direct is None and any(c["source"] == "GROUP" for c in sources):
        raise AwsFailure("没有已确认的 USER 授权，不能按 USER 取消，请核对", uncertain=True)
    return direct


def run_operation(gateway_factory=None, *, account_id=None):
    return run_fenced(account_id, ("lifecycle",),
                      lambda aid: _run_one(gateway_factory or AwsGateway, aid))


def _run_one(gateway_factory, account_id):
    from .cascade_deletions import run_one as run_cascade
    if run_cascade(gateway_factory, account_id=account_id):
        return True
    job = claim_operation(account_id=account_id)
    if not job:
        return False
    op_id, token = job
    pending = False
    recovering_intent = False
    detach_accepted = False
    try:
        with SessionLocal() as db:
            op, r = load(db, op_id, token)
            payload = json.loads(op.payload)
            # Old public retries could reset phase to ready while leaving the
            # original pending fingerprint. Its presence still means recovery.
            pending = recovering_intent = op.phase in ("pending", "reset_authorized") or bool(payload.get("worker_config_hash"))
            a = db.get(AwsAccount, r.aws_account_id)
            frozen_config = attempt_config(db, a, payload.get("worker_config_hash") if pending else None)
            actor = db.get(User, op.actor_id)
            permitted = allowed(db, actor, a)
            # A saved deadline remains authorized if its creator is later disabled
            # or unbound. Only the exact server-created cancellation is eligible.
            schedule = automatic_schedule(db, op)
            if payload.get("schedule_revision") and not schedule and not pending:
                raise AwsFailure("定时停止规则已变更，本次旧版本任务已失效")
            if schedule:
                permitted = a.active and not a.deleted_at
            from .group_subscription_state import detach_context, member_activation
            from .plan_change_state import direct_user_plan, has_plan_history
            changed_plan = has_plan_history(db, r.id)
            managed_type = direct_user_plan(db, r, observed=False)["subscription_type"] or direct_user_plan(db, r)["subscription_type"]
            native = member_activation(db, r.id) if op.kind == "sync_status" else None
            group = db.get(ManagedGroup, r.group_id) if native else None
            if payload.get("native_activation_id"):
                group, activation = detach_context(
                    db, r, payload, op.id, op.actor_id,
                    recovering=pending, automatic=bool(schedule),
                )
            db.expunge_all()
        gateway = gateway_factory(a)
        request_id = None
        if op.kind == "cancel_subscription":
            mode = payload["cancellation_mode"]
            target = "GROUP" if payload.get("native_activation_id") else "USER"
            if (payload.get("principal_type", target) != target or
                    schedule and schedule.principal_type not in (None, target)):
                raise AwsFailure("取消任务的授权主体与保存的目标不一致，请核对", uncertain=pending)
            if payload.get("native_activation_id"):
                # Membership removal is the only individual GROUP cancellation.
                from .group_subscription_state import (
                    detach_context,
                    verify_member_sources,
                )
                membership_id = gateway.get_group_membership(group.remote_id, r.sso_user_id)
                if membership_id:
                    verify_member_sources(gateway, r, group, activation.subscription_type)
                    if pending:
                        raise AwsFailure("移出成员结果尚未确认；仅只读核对，不重复发送", uncertain=True)
                    if not permitted:
                        raise AwsFailure("操作者或 AWS 绑定已停用")
                    mark_pending(op_id, token, frozen_config=frozen_config)
                    pending = True
                    gateway.delete_group_membership(membership_id)
                    detach_accepted = True
                    if gateway.get_group_membership(group.remote_id, r.sso_user_id):
                        raise AwsFailure("AWS 成员移出尚未确认", uncertain=True)
                verify_member_sources(gateway, r, group, present=False)
                from .subscription_sources import (
                    cancellation_values,
                    observe_subscription,
                )
                values = cancellation_values(r, observe_subscription(gateway, r), "GROUP", "IMMEDIATE", group_id=group.remote_id)
                complete(op_id, token, values)
                return True
            fixed_user_schedule = bool(schedule and schedule.principal_type == "USER")
            verify_user_cancellation_sources(gateway, r, allow_absent=pending or fixed_user_schedule)
            info = gateway.subscription_info(r)
            from .plan_change_state import has_plan_history, lifecycle_observation

            if changed_plan:
                managed_type = lifecycle_observation(
                    r.id, op_id, token, gateway.plan_change_info(r)
                )
            # A fixed USER cutoff still applies while a previously cancelled
            # renewal grants access until its future period boundary.
            scheduled_user_access = (fixed_user_schedule and not pending and info["status"] == "cancelled"
                                     and info.get("expires_at") and info["expires_at"] > now())
            # A recovered in-flight write can only reconcile, never blindly replay.
            if (info["status"] in ("active", "not_subscribed") or scheduled_user_access) and not (
                (pending or fixed_user_schedule) and info["status"] == "not_subscribed"
            ):
                if pending:
                    raise AwsFailure(
                        "AWS 仍显示订阅有效；请核对后确认再次取消", uncertain=True
                    )
                if not permitted:
                    raise AwsFailure("操作者或 AWS 绑定已停用")
                if (
                    info["subscription_type"]
                    and info["subscription_type"] != managed_type
                ):
                    raise AwsFailure(
                        "AWS 当前套餐与原绑定套餐不一致，请到 AWS 核对后处理"
                    )
                mark_pending(op_id, token, frozen_config=frozen_config)
                pending = True
                request_id = gateway.cancel_subscription(r, mode)
                verify_user_cancellation_sources(gateway, r, allow_absent=True)
                if changed_plan:
                    lifecycle_observation(
                        r.id, op_id, token, gateway.plan_change_info(r)
                    )
                info = gateway.subscription_info(r)
                if info["status"] == "active":
                    raise AwsFailure("AWS USER 取消尚未确认，等待只读核对", uncertain=True)
            else:
                if (
                    pending
                    and info["status"] == "not_subscribed"
                    and now() - op.created_at < timedelta(minutes=10)
                ):
                    raise AwsFailure(
                        "AWS 尚未返回订阅记录，请等待同步后再次核对", uncertain=True
                    )
            from .subscription_sources import cancellation_values, observe_subscription
            values = cancellation_values(r, observe_subscription(gateway, r), "USER", mode,
                                         user_subscription_type=managed_type)
        elif op.kind == "reset_password":
            if pending and op.phase != "reset_authorized":
                raise AwsFailure(
                    "密码重置结果未保存，旧密码已隐藏；确认再次重置会生成新密码",
                    uncertain=True,
                )
            if not permitted:
                raise AwsFailure("操作者或 AWS 绑定已停用")

            def before_reset():
                nonlocal pending
                mark_pending(op_id, token, clear_password=True, frozen_config=frozen_config)
                pending = True

            values = {
                "password_encrypted": encrypt(
                    reset_one_time_password(gateway, r, before_reset)
                ),
                "password_generated_at": now(),
            }
        elif op.kind in ("delete_sso", "update_sso", "sync_status"):
            remote = gateway.user_info(r)
            if op.kind == "delete_sso":
                if remote is not None:
                    raise AwsFailure(
                        "旧删除任务仅可只读核对 AWS 是否已不存在；请先核对原订阅与删除结果",
                        uncertain=True,
                    )
                values = {
                    "sso_deleted_at": r.sso_deleted_at or now(),
                    "password_encrypted": None,
                    "password_generated_at": None,
                }
            elif op.kind == "update_sso":
                if remote is None:
                    raise AwsFailure("AWS 中已找不到该 SSO 用户，请同步状态")
                matches = remote.get("DisplayName") == payload[
                    "display_name"
                ] and any(
                    e.get("Value") == payload["email"] and e.get("Primary")
                    for e in remote.get("Emails", [])
                )
                if not matches:
                    if pending:
                        raise AwsFailure(
                            "AWS 姓名邮箱尚未与更新内容一致；请核对后再次更新",
                            uncertain=True,
                        )
                    if not permitted:
                        raise AwsFailure("操作者或 AWS 绑定已停用")
                    mark_pending(op_id, token, frozen_config=frozen_config)
                    pending = True
                    request_id = gateway.update_user(
                        r, payload["display_name"], payload["email"]
                    )
                values = {
                    "sso_display_name": payload["display_name"],
                    "email": payload["email"],
                }
            else:
                if not permitted:
                    raise AwsFailure("操作者或 AWS 绑定已停用")
                from .plan_change_state import (
                    has_plan_history,
                    lifecycle_observation,
                )

                if changed_plan:
                    lifecycle_observation(
                        r.id, op_id, token, gateway.plan_change_info(r)
                    )
                from .group_subscription_state import verify_member_sources
                if native:
                    verify_member_sources(gateway, r, group, native.subscription_type)
                from .subscription_sources import (
                    observation_values,
                    observe_subscription,
                )
                values = observation_values(r, observe_subscription(gateway, r))
                if remote is None:
                    values.update(
                        sso_deleted_at=r.sso_deleted_at or now(),
                        password_encrypted=None,
                        password_generated_at=None,
                    )
                else:
                    values["sso_display_name"] = remote.get(
                        "DisplayName", r.sso_display_name
                    )
                    email = next(
                        (
                            e.get("Value")
                            for e in remote.get("Emails", [])
                            if e.get("Primary")
                        ),
                        None,
                    )
                    if email:
                        values["email"] = email
        else:
            raise AwsFailure("未知用户操作")
        complete(op_id, token, values, request_id)
    except AwsFailure as exc:
        fail(
            op_id,
            token,
            str(exc),
            # An uncertain read before the write cannot make this operation's
            # outcome unknown. Preserve pending-write recovery semantics only.
            uncertain=pending and (detach_accepted or exc.uncertain or recovering_intent),
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        uncertain = pending and (
            detach_accepted or recovering_intent
            or code
            in ("InternalServerException", "ConflictException", "RequestTimeout")
        )
        fail(op_id, token, f"AWS 操作失败：{code}", uncertain)
    except Exception as exc:
        logger.error("Operation %s failed: %s", op_id, type(exc).__name__)
        try:
            fail(
                op_id,
                token,
                f"操作中断（{type(exc).__name__}），请核对处理",
                uncertain=pending,
            )
        except Exception:
            logger.error("Operation %s remains leased for recovery", op_id)
    return True
