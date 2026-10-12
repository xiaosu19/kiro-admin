"""Queue an existing SSO recovery inside the caller's transaction."""
from fastapi import HTTPException
from sqlalchemy import update

from . import aws
from .models import AwsAccount, Binding, ManagedGroup, Plan, Subscription, User, now


def queue_retry(db, r, user):
    from .main import reserve
    if r.state not in ("failed", "needs_review"):
        raise HTTPException(409, "仅失败或待核对记录可以继续处理")
    if r.sso_deleted_at or r.active_operation_id:
        raise HTTPException(409, "SSO 已删除或有其他操作正在处理")
    a = db.get(AwsAccount, r.aws_account_id)
    owner = db.get(User, r.owner_id)
    if r.step not in ("create_user_pending", "password_pending", "subscribe_pending") and not (
        r.step in ("group_membership_pending", "group_entitlement_pending") and r.provision_only
    ) and (
        not owner.active
        or owner.deleted_at
        or not a.active
        or a.deleted_at
        or (
            r.plan_id is not None
            and (
                not db.get(Plan, r.plan_id).active or db.get(Plan, r.plan_id).deleted_at
            )
        )
        or (owner.role != "admin" and not db.get(Binding, (owner.id, a.id)))
    ):
        raise HTTPException(403, "创建者、AWS 绑定或套餐已停用")
    from .provisioning_coordinator import record_guard
    from .worker import CREDENTIAL_STEPS, PENDING_STEPS
    try:
        record_guard(db, r, recovering=r.state == 'needs_review' and r.step in PENDING_STEPS)
    except aws.AwsFailure as exc:
        raise HTTPException(409, str(exc)) from None
    # A definite membership rejection releases its reservation but older jobs
    # retain the send-step label. A new guarded attempt must not inherit the
    # read-only recovery path used by genuinely uncertain writes.
    retry_step = ('group_membership' if r.state == 'failed' and r.step == 'group_membership_pending'
                  else r.step)
    # Acquire the record before reserving to prevent double-click races.
    changed = db.execute(
        update(Subscription)
        .where(
            Subscription.id == r.id,
            Subscription.state.in_(["failed", "needs_review"]),
            Subscription.active_operation_id.is_(None),
            Subscription.sso_deleted_at.is_(None),
        )
        .values(state="queued", step=retry_step, error=None, updated_at=now())
    )
    if not changed.rowcount:
        raise HTTPException(409, "任务已在处理")
    if r.group_id:
        from .group_subscription_state import entitlement_context, join_context, live_grant, member_activation, reserve_join
        group = db.get(ManagedGroup, r.group_id)
        grant = live_grant(db, group.id)
        if retry_step == "group_entitlement_pending":
            try:
                entitlement_context(db, r)
            except aws.AwsFailure as exc:
                raise HTTPException(409, str(exc)) from None
            return
        if grant and not member_activation(db, r.id):
            reserve_join(db, group, r, user, r.id)
        if group.active_job_id not in (None, r.id):
            if not grant or retry_step not in CREDENTIAL_STEPS:
                raise HTTPException(409, "分组存在未完成任务")
            try:
                join_context(db, r, group, recovering=retry_step in PENDING_STEPS,
                             preparing_credentials=True)
            except aws.AwsFailure as exc:
                raise HTTPException(409, str(exc)) from None
    if not r.reserved and not r.counted and not r.provision_only:
        r.counter_id, r.cycle_number = reserve(db, owner, r.plan_id)
        r.reserved = r.counter_id is not None
