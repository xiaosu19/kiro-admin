"""Reversible removal of console configuration; AWS resources and history remain."""

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from .catalog import BY_SUBSCRIPTION_TYPE
from .database import get_db
from .models import (
    AwsAccount,
    Binding,
    GroupMemberActivation,
    ManagedGroup,
    Plan,
    PlanCounter,
    PlanChange,
    Proxy,
    RecordOperation,
    StopSchedule,
    Subscription,
    User,
    now,
)
from .security import admin, audit
from .schedules import LIVE_STATES

router = APIRouter(prefix="/api/admin")


class RemovalInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm_name: str = Field(min_length=1, max_length=100)


class StatusInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    active: bool


def resource_usage(db, resource):
    condition = (
        (Subscription.aws_account_id == resource.id)
        if isinstance(resource, AwsAccount)
        else (Subscription.plan_id == resource.id)
    )
    effective_plan = select(GroupMemberActivation.plan_id).where(
        GroupMemberActivation.record_id == Subscription.id,
        GroupMemberActivation.counted.is_(True),
        GroupMemberActivation.state.in_(("active", "cancel_scheduled", "needs_review")),
    ).order_by(GroupMemberActivation.created_at.desc()).limit(1).scalar_subquery()
    active_condition = condition if isinstance(resource, AwsAccount) else (
        func.coalesce(effective_plan, Subscription.plan_id) == resource.id
    )
    rows = db.execute(
        select(
            func.count().filter(condition),
            func.count().filter(
                condition,
                Subscription.sso_user_id.is_not(None),
                Subscription.sso_deleted_at.is_(None),
            ),
            func.count().filter(
                active_condition,
                Subscription.subscription_status.in_(
                    ("active", "cancel_scheduled", "unknown", "pending")
                )
            ),
        )
        .select_from(Subscription)
    ).one()
    return {"records": rows[0], "sso_active": rows[1], "subscriptions_active": rows[2]}


def account_view(a, is_admin=False, db=None):
    fields = ["id", "name", "account_number", "aws_account_id", "region", "active", "portal_url"]
    if is_admin:
        fields += [
            "subscription_region",
            "control_plane",
            "identity_store_id",
            "instance_arn",
            "application_arn",
            "profile_arn",
            "created_at",
            "deleted_at",
            "proxy_id",
        ]
    result = {key: getattr(a, key) for key in fields}
    if db is not None:
        proxy = db.get(Proxy, a.proxy_id) if a.proxy_id is not None else None
        result["proxy_name"] = proxy.name if proxy else None
        result["proxy_status"] = (
            "direct"
            if a.proxy_id is None
            else "missing"
            if proxy is None
            else "enabled"
            if proxy.enabled
            else "disabled"
        )
    if is_admin and db is not None:
        result["usage"] = resource_usage(db, a)
        result["bound_users"] = db.scalar(
            select(func.count())
            .select_from(Binding)
            .where(Binding.aws_account_id == a.id)
        )
    return result


def plan_view(p, db=None):
    result = {
        key: getattr(p, key)
        for key in ("id", "name", "code", "subscription_type", "active", "deleted_at")
    }
    result["reference"] = BY_SUBSCRIPTION_TYPE.get(p.subscription_type)
    if db is not None:
        result["usage"] = resource_usage(db, p)
    return result


def get_resource(db, model, resource_id, include_deleted=True):
    resource = db.get(model, resource_id)
    if not resource or (resource.deleted_at and not include_deleted):
        raise HTTPException(404, "配置不存在或已删除")
    return resource


def ensure_no_tasks(db, resource):
    from .provisioning_batches import live_intent
    selection = {"account_id" if isinstance(resource, AwsAccount) else "plan_id": resource.id}
    if live_intent(db, **selection):
        raise HTTPException(409, "此配置仍有批次开通意图，请先处理完成")
    from .group_member_batches import LIVE_STATES as MEMBER_BATCH_STATES
    from .models import GroupMemberBatch
    if isinstance(resource, AwsAccount) and db.scalar(select(GroupMemberBatch.id).where(
        GroupMemberBatch.aws_account_id == resource.id,
        GroupMemberBatch.state.in_(MEMBER_BATCH_STATES),
    ).limit(1)):
        raise HTTPException(409, "此 AWS 账号仍有未完成成员批次，请先处理完成")
    from .models import NativeGroupGrant
    from .group_subscription_state import LIVE_STATES as NATIVE_STATES
    condition = NativeGroupGrant.aws_account_id == resource.id if isinstance(resource, AwsAccount) else NativeGroupGrant.plan_id == resource.id
    if db.scalar(select(NativeGroupGrant.id).where(
        condition, NativeGroupGrant.state.in_(NATIVE_STATES),
    ).limit(1)):
        raise HTTPException(409, "此配置仍有原生分组订阅或未完成授权，请先取消并核对")
    from .plan_change_state import LIVE_STATES as CHANGE_STATES, referenced_plan

    if isinstance(resource, Plan) and referenced_plan(db, resource.id):
        raise HTTPException(409, "该套餐已被套餐变更历史引用，请停用而不要删除")
    if isinstance(resource, AwsAccount) and db.scalar(
        select(PlanChange.id)
        .join(Subscription, Subscription.id == PlanChange.record_id)
        .where(
            Subscription.aws_account_id == resource.id,
            PlanChange.state.in_(CHANGE_STATES),
        )
        .limit(1)
    ):
        raise HTTPException(409, "此 AWS 账号仍有待生效或待核对套餐变更，请先处理完成")
    if isinstance(resource, AwsAccount) and db.scalar(
        select(ManagedGroup.id)
        .where(
            ManagedGroup.aws_account_id == resource.id,
            ManagedGroup.deleted_at.is_(None),
        )
        .limit(1)
    ):
        raise HTTPException(409, "此 AWS 账号仍有管理分组或分组任务，请先处理完成")
    condition = (
        (Subscription.aws_account_id == resource.id)
        if isinstance(resource, AwsAccount)
        else (Subscription.plan_id == resource.id)
    )
    records = select(Subscription.id).where(condition)
    pending = db.scalar(
        select(Subscription.id)
        .where(
            condition,
            or_(
                Subscription.state.in_(("queued", "running", "needs_review")),
                Subscription.reserved.is_(True),
                Subscription.active_operation_id.is_not(None),
            ),
        )
        .limit(1)
    )
    operation = db.scalar(
        select(RecordOperation.id)
        .where(
            RecordOperation.record_id.in_(records),
            RecordOperation.state.in_(("queued", "running", "needs_review")),
        )
        .limit(1)
    )
    reserved = isinstance(resource, Plan) and db.scalar(
        select(PlanCounter.id)
        .where(PlanCounter.plan_id == resource.id, PlanCounter.pending_count > 0)
        .limit(1)
    )
    if pending or operation or reserved:
        raise HTTPException(409, "此配置还有处理中或待核对任务，请先处理完成再删除")
    if isinstance(resource, AwsAccount) and db.scalar(
        select(StopSchedule.record_id)
        .where(StopSchedule.record_id.in_(records), StopSchedule.state.in_(LIVE_STATES))
        .limit(1)
    ):
        raise HTTPException(
            409, "此 AWS 账号仍有定时停止计划，请先关闭或处理完成再删除"
        )


def remove_resource(db, resource, body, actor, request):
    if body.confirm_name != resource.name:
        raise HTTPException(409, "确认名称不匹配，请输入完整名称")
    if resource.deleted_at:
        return {"ok": True}
    # get_user holds the SQLite write lock, serializing deletion with admission.
    ensure_no_tasks(db, resource)
    resource.active = False
    resource.deleted_at = now()
    is_account = isinstance(resource, AwsAccount)
    if is_account:
        db.execute(delete(Binding).where(Binding.aws_account_id == resource.id))
    audit(
        db,
        actor,
        "delete_aws" if is_account else "delete_plan",
        f"删除{'AWS 账号配置' if is_account else '套餐配置'} {resource.name}；保留 SSO、订阅、次数与审计历史",
        request=request,
    )
    db.commit()
    return {"ok": True}


def restore_resource(db, resource, actor, request):
    if resource.deleted_at:
        resource.deleted_at = None
        resource.active = False
        audit(
            db,
            actor,
            "restore_aws" if isinstance(resource, AwsAccount) else "restore_plan",
            f"恢复配置 {resource.name}，保持停用，待管理员启用",
            request=request,
        )
        db.commit()
    return {"ok": True}


def resource_status(db, resource, body, actor, request):
    if resource.active != body.active:
        resource.active = body.active
        audit(
            db,
            actor,
            "update_aws" if isinstance(resource, AwsAccount) else "update_plan",
            f"{'启用' if body.active else '停用'}配置 {resource.name}",
            request=request,
        )
        db.commit()
    return {"ok": True}


@router.get("/aws/{account_id}")
def account_detail(
    account_id: int, _: User = Depends(admin), db: Session = Depends(get_db)
):
    return account_view(get_resource(db, AwsAccount, account_id), True, db)


@router.delete("/aws/{account_id}")
def remove_account(
    account_id: int,
    body: RemovalInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    return remove_resource(
        db, get_resource(db, AwsAccount, account_id), body, actor, request
    )


@router.post("/aws/{account_id}/restore")
def restore_account(
    account_id: int,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    return restore_resource(
        db, get_resource(db, AwsAccount, account_id), actor, request
    )


@router.patch("/aws/{account_id}/status")
def account_status(
    account_id: int,
    body: StatusInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    return resource_status(
        db, get_resource(db, AwsAccount, account_id, False), body, actor, request
    )


@router.get("/plans/{plan_id}")
def plan_detail(plan_id: int, _: User = Depends(admin), db: Session = Depends(get_db)):
    return plan_view(get_resource(db, Plan, plan_id), db)


@router.delete("/plans/{plan_id}")
def remove_plan(
    plan_id: int,
    body: RemovalInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    return remove_resource(db, get_resource(db, Plan, plan_id), body, actor, request)


@router.post("/plans/{plan_id}/restore")
def restore_plan(
    plan_id: int,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    return restore_resource(db, get_resource(db, Plan, plan_id), actor, request)


@router.patch("/plans/{plan_id}/status")
def plan_status(
    plan_id: int,
    body: StatusInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    return resource_status(
        db, get_resource(db, Plan, plan_id, False), body, actor, request
    )
