"""Native assignment history, quota settlement and shared membership guards."""

import hashlib
import json
import uuid
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import select, update

from .aws import AwsFailure, assignment_read_scope
from .models import (
    AwsAccount,
    GroupMemberActivation,
    ManagedGroup,
    NativeGroupGrant,
    PlanCounter,
    Proxy,
    StopSchedule,
    Subscription,
    now,
)

LIVE_STATES = ("pending", "active", "cancel_scheduled", "needs_review")
OP_STATES = ("queued", "running", "needs_review")


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, default=str).encode()
    ).hexdigest()


def config_hash(db, account):
    proxy = db.get(Proxy, account.proxy_id) if account.proxy_id else None
    return digest(
        {
            k: getattr(account, k)
            for k in (
                "id",
                "aws_account_id",
                "region",
                "subscription_region",
                "control_plane",
                "identity_store_id",
                "instance_arn",
                "application_arn",
                "profile_arn",
                "credentials_encrypted",
                "proxy_id",
            )
        }
        | {
            "proxy_revision": proxy.revision if proxy else None,
            "proxy_enabled": proxy.enabled if proxy else None,
        }
    )


def live_grant(db, group_id):
    return db.scalar(
        select(NativeGroupGrant)
        .where(
            NativeGroupGrant.group_id == group_id,
            NativeGroupGrant.state.in_(LIVE_STATES),
        )
        .order_by(NativeGroupGrant.created_at.desc())
        .limit(1)
    )


def member_activation(db, record_id):
    return db.scalar(
        select(GroupMemberActivation)
        .where(
            GroupMemberActivation.record_id == record_id,
            GroupMemberActivation.state.in_(LIVE_STATES),
        )
        .order_by(GroupMemberActivation.created_at.desc())
        .limit(1)
    )


def detach_signature(db, record, group):
    return digest({
        "config": config_hash(db, db.get(AwsAccount, group.aws_account_id)),
        "group": [group.id, group.remote_id, group.owner_id, group.aws_account_id],
        "record": [record.id, record.owner_id, record.aws_account_id,
                   record.sso_user_id, record.group_id, record.group_membership_id],
    })


def detach_payload(db, record):
    activation = member_activation(db, record.id)
    if not activation:
        return {}
    group = db.get(ManagedGroup, record.group_id)
    return {
        "native_activation_id": activation.id,
        "native_group_id": group.id,
        "native_detach_signature": detach_signature(db, record, group),
    }


def detach_context(db, record, payload, operation_id, actor_id, *, recovering=False, automatic=False):
    """Recheck the exact native detach scope under the caller's intent lock."""
    from .lifecycle import allowed
    from .models import User

    group = db.get(ManagedGroup, payload["native_group_id"])
    activation = db.get(GroupMemberActivation, payload["native_activation_id"])
    grant = db.get(NativeGroupGrant, activation.grant_id) if activation else None
    if (
        not group or group.deleted_at or not group.remote_id
        or not activation or not activation.counted or activation.state not in LIVE_STATES
        or activation.record_id != record.id or not grant or grant.group_id != group.id
        or record.owner_id != group.owner_id or record.aws_account_id != group.aws_account_id
        or grant.owner_id != group.owner_id or grant.aws_account_id != group.aws_account_id
        or record.active_operation_id != operation_id or group.active_job_id != operation_id
        or payload.get("native_detach_signature") != detach_signature(db, record, group)
    ):
        raise AwsFailure("移出原生订阅成员的归属、授权、锁或 AWS 配置已变化")
    if not recovering:
        account = db.get(AwsAccount, group.aws_account_id)
        actor, owner = db.get(User, actor_id), db.get(User, group.owner_id)
        permitted = account.active and not account.deleted_at if automatic else (
            allowed(db, actor, account)
            and (actor.role == "admin" or (actor.id == owner.id and allowed(db, owner, account)))
        )
        if not permitted:
            raise AwsFailure("移出原生分组成员的所有者、操作者或 AWS 绑定已停用")
    return group, activation


def initial_user_activation():
    """Exclude the first GROUP opening projected onto the legacy SSO record."""
    return (
        ~select(GroupMemberActivation.id)
        .where(
            GroupMemberActivation.record_id == Subscription.id,
            GroupMemberActivation.first_opening.is_(True),
            GroupMemberActivation.counted.is_(True),
        )
        .exists()
    )


def grant_view(grant):
    return (
        {
            k: getattr(grant, k)
            for k in (
                "id",
                "group_id",
                "plan_id",
                "plan_name",
                "subscription_type",
                "state",
                "activated_at",
                "cancelled_at",
                "cancellation_mode",
                "access_ends_at",
                "stop_at",
                "policy_revision",
                "created_at",
            )
        }
        | {"source": "GROUP", "future_members_inherit": True}
        if grant
        else None
    )


def group_projection(db, group_id):
    latest = db.scalar(
        select(NativeGroupGrant)
        .where(NativeGroupGrant.group_id == group_id)
        .order_by(NativeGroupGrant.created_at.desc())
        .limit(1)
    )
    return grant_view(latest)


def record_projection(db, record):
    from .subscription_sources import direct_source, saved_observation
    from .plan_change_state import direct_user_plan

    activation = member_activation(db, record.id)
    latest = activation or db.scalar(select(GroupMemberActivation).where(
        GroupMemberActivation.record_id == record.id,
        GroupMemberActivation.counted.is_(True),
    ).order_by(GroupMemberActivation.activated_at.desc()).limit(1))
    grant = db.get(NativeGroupGrant, latest.grant_id) if latest else None
    saved = saved_observation(record)
    direct = direct_source(record)
    first_group = db.scalar(select(GroupMemberActivation.id).where(
        GroupMemberActivation.record_id == record.id,
        GroupMemberActivation.counted.is_(True), GroupMemberActivation.first_opening.is_(True),
    ).limit(1))
    has_access = record.subscription_status in ("active", "cancel_scheduled")
    effective = saved["effective"].get("source") if saved and has_access else None
    if not saved and has_access:
        effective = "GROUP" if activation and activation.counted else "USER" if record.counted and not latest else None
    return {
        "subscription_source": "GROUP" if first_group else "USER" if record.counted else None,
        "effective_subscription_source": effective,
        "subscription_sources": saved["sources"] if saved else [],
        "aws_subscription_status": saved["effective"].get("aws_status") if saved else None,
        "direct_user_plan": direct_user_plan(db, record),
        "direct_user_status": direct.get("status") if direct else None,
        "cancellation_source": "GROUP" if activation and activation.counted else
            "USER" if (direct and direct["status"] == "active")
            or (not saved and not latest and record.counted) else None,
        "native_group_subscription": grant_view(grant),
        "group_activation_id": latest.id if latest else None,
        "controlling_group_stop_at": grant.stop_at if activation and grant else None,
    }


def group_deadline(group, activated_at=None):
    if group.policy_mode == "at":
        return group.policy_stop_at
    if group.policy_mode == "days" and activated_at:
        return activated_at + timedelta(days=group.policy_days)
    return None


def reserve_member(db, grant, record, actor_id, operation_id, request_key):
    from .models import User
    from .plan_changes import reserve_target

    owner = db.get(User, grant.owner_id)
    counter_id, cycle = reserve_target(db, owner, grant.plan_id)
    activation = GroupMemberActivation(
        id=str(uuid.uuid4()),
        grant_id=grant.id,
        record_id=record.id,
        owner_id=record.owner_id,
        actor_id=actor_id,
        plan_id=grant.plan_id,
        plan_name=grant.plan_name,
        subscription_type=grant.subscription_type,
        request_key=request_key,
        operation_id=operation_id,
        counter_id=counter_id,
        cycle_number=cycle,
        reserved=counter_id is not None,
        config_hash=config_hash(db, db.get(AwsAccount, grant.aws_account_id)),
    )
    db.add(activation)
    return activation


def quota_finish(db, activation, counted):
    if activation.counted or activation.state == "failed":
        return
    if activation.reserved:
        values = {"pending_count": PlanCounter.pending_count - 1}
        if counted:
            values.update(
                used_count=PlanCounter.used_count + 1,
                lifetime_count=PlanCounter.lifetime_count + 1,
            )
        changed = db.execute(
            update(PlanCounter)
            .where(
                PlanCounter.id == activation.counter_id,
                PlanCounter.cycle_number == activation.cycle_number,
                PlanCounter.pending_count > 0,
            )
            .values(**values)
        )
        if not changed.rowcount:
            raise RuntimeError("分组开通预占次数不一致，请核对")
    activation.reserved, activation.counted = False, counted
    if not counted:
        activation.state = "failed"


def settle_member(db, activation, at=None, observation=None):
    if activation.counted:
        return
    quota_finish(db, activation, True)
    activation.state, activation.activated_at, activation.error = (
        "active",
        at or now(),
        None,
    )
    record = db.get(Subscription, activation.record_id)
    if not record.counted:
        activation.first_opening = True
        record.counted = True
        # Only the first successful opening sets the immutable SSO history.
        record.plan_id = record.plan_id or activation.plan_id
        record.plan_name_snapshot = record.plan_name_snapshot or activation.plan_name
        record.subscription_type = (
            record.subscription_type or activation.subscription_type
        )
        record.subscribed_at = record.subscribed_at or activation.activated_at
    if observation is None:
        raise RuntimeError("原生分组结算缺少 AWS 整体订阅观测")
    from .subscription_sources import apply_observation
    apply_observation(record, observation)
    group = db.get(ManagedGroup, db.get(NativeGroupGrant, activation.grant_id).group_id)
    schedule = db.get(StopSchedule, record.id)
    if schedule and schedule.source_group_id == group.id and not schedule.individual_override:
        schedule.principal_type = "GROUP"
        schedule.stop_at = group_deadline(
            group, db.get(NativeGroupGrant, activation.grant_id).activated_at
        )
        schedule.source_group_revision = group.policy_revision
        schedule.state = "scheduled" if schedule.mode != "none" else "disabled"
    elif schedule:
        # This opening is a known boundary at which the existing rule's target
        # can be pinned before any later external USER removal changes sources.
        if schedule.principal_type is None:
            first_group = db.scalar(select(GroupMemberActivation.id).where(
                GroupMemberActivation.record_id == record.id,
                GroupMemberActivation.counted.is_(True), GroupMemberActivation.first_opening.is_(True),
            ).limit(1))
            if activation.first_opening:
                schedule.principal_type = "GROUP"
            elif not first_group:
                schedule.principal_type = "USER"
        if schedule.state == "waiting":
            from .schedules import activate_after_subscription
            activate_after_subscription(db, record, activation.activated_at, "GROUP")


def complete_group_schedule(db, record, group_id, at=None):
    schedule = db.get(StopSchedule, record.id)
    from .schedules import schedule_principal
    if schedule and (schedule.source_group_id == group_id and not schedule.individual_override
                     or schedule_principal(db, record, schedule) == "GROUP" and record.group_id == group_id):
        schedule.state, schedule.completed_at, schedule.error = "completed", at or now(), None


def detach_member(db, record, mode="IMMEDIATE", at=None):
    activation = member_activation(db, record.id)
    if activation and activation.counted:
        activation.state, activation.cancelled_at = "cancelled", at or now()
        grant = db.get(NativeGroupGrant, activation.grant_id)
        complete_group_schedule(db, record, grant.group_id, at)


def active_info(info):
    from .subscription_sources import active_source
    return active_source(info)


def verify_member_sources(gateway, record, group=None, subscription_type=None, *, present=True):
    from .subscription_sources import confirmed_sources
    claims = confirmed_sources(gateway, record)
    if group is None:
        return None
    matches = [c for c in claims if c["source"] == "GROUP" and c["group_id"] == group.remote_id and active_info(c)]
    if present:
        if len(matches) != 1 or matches[0]["subscription_type"] != subscription_type:
            raise AwsFailure("目标 GROUP 授权缺失或套餐不一致，需要核对", uncertain=True)
        return matches[0]
    if matches:
        raise AwsFailure("目标 GROUP 授权仍有效，需要核对", uncertain=True)
    return None


def reserve_join(db, group, record, actor, operation_id):
    grant = live_grant(db, group.id)
    if not grant:
        return None
    if grant.state != "active" or (grant.stop_at and grant.stop_at <= now()):
        raise HTTPException(409, "原生分组订阅未就绪、待核对或已到停止时间")
    if member_activation(db, record.id):
        raise HTTPException(409, "该 SSO 已有原生分组开通任务或授权")
    if record.subscription_status in (
        "unknown",
        "pending",
    ):
        raise HTTPException(409, "该 SSO 订阅状态待确认，不能叠加原生分组授权")
    return reserve_member(db, grant, record, actor.id, operation_id, str(uuid.uuid4()))


def join_context(db, record, group, *, recovering=False, creation_reset=False,
                 preparing_credentials=False):
    """Validate the reserved native join under the caller's database lock."""
    from .lifecycle import allowed
    from .models import User, Plan

    grant, activation = live_grant(db, group.id), member_activation(db, record.id)
    if not grant:
        if activation:
            raise AwsFailure("原生分组授权已变化，不能继续加入")
        return grant, activation
    account = db.get(AwsAccount, group.aws_account_id)
    lock_valid = bool(activation and group.active_job_id == activation.operation_id)
    if activation and not activation.write_requested_at and (preparing_credentials or creation_reset):
        if group.active_job_id is None:
            lock_valid = True
        elif preparing_credentials:
            sibling = db.get(Subscription, group.active_job_id)
            sibling_activation = member_activation(db, sibling.id) if sibling else None
            lock_valid = lock_valid or bool(
                sibling and sibling.group_id == group.id
                and sibling.state in ("queued", "running", "needs_review") and sibling_activation
                and sibling_activation.operation_id == sibling.id
                and sibling_activation.grant_id == grant.id
            )
    if (
        not activation
        or activation.grant_id != grant.id
        or activation.counted
        or activation.config_hash != config_hash(db, account)
        or record.owner_id != group.owner_id
        or grant.owner_id != group.owner_id
        or record.aws_account_id != group.aws_account_id
        or grant.aws_account_id != group.aws_account_id
        or group.deleted_at
        or (group.state != "ready" and (preparing_credentials or creation_reset))
        or not group.remote_id
        or record.sso_deleted_at
        or (record.id if creation_reset else (record.active_operation_id or record.id)) != activation.operation_id
    ):
        raise AwsFailure("加入原生订阅分组的预占、归属、锁或配置已变化")
    if not lock_valid:
        raise AwsFailure("分组有未完成或待核对的成员授权，请先核对该成员后继续加入")
    if not recovering:
        owner, actor = db.get(User, grant.owner_id), db.get(User, activation.actor_id)
        plan = db.get(Plan, grant.plan_id)
        schedule = db.get(StopSchedule, record.id)
        if (
            grant.state != "active"
            or not plan.active
            or plan.deleted_at
            or plan.subscription_type != grant.subscription_type
            or not allowed(db, actor, account)
            or not allowed(db, owner, account)
            or (grant.stop_at and grant.stop_at <= now())
            or (schedule and schedule.mode != "none" and schedule.stop_at and schedule.stop_at <= now())
        ):
            raise AwsFailure("加入原生分组的权限、套餐或截止时间已变化")
        counter = db.get(PlanCounter, activation.counter_id) if activation.counter_id else None
        if activation.reserved:
            if not counter or counter.cycle_number != activation.cycle_number or counter.pending_count <= 0:
                raise AwsFailure("原生分组开通预占次数已变化")
        elif owner.role != "admin":
            raise AwsFailure("原生分组开通缺少套餐次数预占")
    return grant, activation


def check_join(record_id, group_id, gateway, *, recovering=False,
               preparing_credentials=False):
    """Local authorization is snapshotted and closed before remote inspection."""
    from .database import SessionLocal

    with SessionLocal() as db:
        record, group = db.get(Subscription, record_id), db.get(ManagedGroup, group_id)
        grant, activation = join_context(db, record, group, recovering=recovering,
                                         preparing_credentials=preparing_credentials)
        expected = {
            (r.sso_user_id, r.group_membership_id)
            for r in db.scalars(
                select(Subscription).where(
                    Subscription.group_id == group.id,
                    Subscription.sso_deleted_at.is_(None),
                )
            )
            if r.sso_user_id and r.group_membership_id
        }
        mixed = db.scalar(
            select(Subscription.id)
            .where(
                Subscription.group_id == group.id,
                Subscription.sso_deleted_at.is_(None),
                (Subscription.owner_id != group.owner_id)
                | (Subscription.aws_account_id != group.aws_account_id),
            )
            .limit(1)
        )
        if mixed:
            raise AwsFailure("本地分组成员归属不一致")
        from .models import ProvisioningItem
        numbered = db.get(ProvisioningItem, record.id) is not None
        db.expunge_all()
    with assignment_read_scope(gateway):
        info = gateway.group_subscription_info(group)
        if numbered and info.get("pending_type"):
            raise AwsFailure("AWS GROUP 正在变更套餐，停止新的成员开通；请先核对分组订阅")
        if grant:
            if (
                info["status"] != "active"
                or info["subscription_type"] != grant.subscription_type
            ):
                raise AwsFailure("AWS 原生分组授权与本地记录不一致，请核对")
            # Independent credentials may be prepared together. Membership
            # snapshots require the exclusive group intent, acquired later.
            if preparing_credentials:
                return activation
            actual = gateway.list_group_memberships(group.remote_id)
            actual_pairs = {(m["user_id"], m["id"]) for m in actual}
            # The current pending join may already be visible remotely while its
            # membership ID was lost with the response. Only that exact user is allowed.
            own = {(uid, mid) for uid, mid in actual_pairs if uid == record.sso_user_id}
            if actual_pairs - own != {
                p for p in expected if p[0] != record.sso_user_id
            } or len(actual) != len(actual_pairs):
                raise AwsFailure("原生分组出现未管理成员或成员漂移，停止加入并等待核对")
            if record.sso_user_id:
                joined = gateway.get_group_membership(
                    group.remote_id, record.sso_user_id
                )
                verify_member_sources(
                    gateway,
                    record,
                    group,
                    grant.subscription_type,
                    present=bool(joined),
                )
        elif active_info(info):
            raise AwsFailure("AWS 分组已有未受管理的原生订阅，禁止自动加入")
        return activation


def checkpoint_join(db, record_id, *, mark_intent=True, creation_reset=False,
                    preparing_credentials=False):
    record = db.get(Subscription, record_id)
    group = db.get(ManagedGroup, record.group_id)
    # An explicit initial OTP reset owns a separate record operation while the
    # original SSO creation keeps its group lock and native quota reservation.
    _, activation = join_context(db, record, group, creation_reset=creation_reset,
                                 preparing_credentials=preparing_credentials)
    if activation and mark_intent:
        activation.write_requested_at = activation.write_requested_at or now()


def finish_join(db, record, observation=None):
    activation = member_activation(db, record.id)
    if activation and not activation.counted:
        settle_member(db, activation, observation=observation)


def fail_join(db, record, uncertain):
    activation = member_activation(db, record.id)
    if activation and not activation.counted:
        if uncertain:
            activation.state = "needs_review"
        else:
            quota_finish(db, activation, False)
