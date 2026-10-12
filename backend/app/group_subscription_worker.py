"""One GROUP write per durable operation; pending writes only reconcile."""

import json
import logging
import uuid
from datetime import timedelta

from fastapi import HTTPException
from sqlalchemy import String, and_, cast, literal, or_, select, update

from .account_dispatcher import (
    account_fence,
    candidate_accounts,
    group_scope,
    run_fenced,
)
from .aws import AwsFailure, AwsGateway, assignment_read_scope
from .config import settings
from .database import SessionLocal
from .group_subscription_state import (
    active_info,
    config_hash,
    group_deadline,
    quota_finish,
    settle_member,
    verify_member_sources,
)
from .group_subscriptions import local_check, members, remote_check, snapshot
from .models import (
    AwsAccount,
    GroupMemberActivation,
    ManagedGroup,
    NativeGroupGrant,
    NativeGroupOperation,
    Plan,
    Subscription,
    User,
    now,
)
from .security import audit
from .automatic_retries import (
    provisioning_stopped, ready_clause, schedule_retry, settle_retry,
)
from .retry_policy import classify_failure

logger = logging.getLogger("kiro.native_groups")
_due_cursors = {}
_expiry_cursors = {}


def claim(*, account_id=None):
    with SessionLocal() as db:
        eligible = or_(
            NativeGroupOperation.state == "queued",
            and_(
                NativeGroupOperation.state == "running",
                NativeGroupOperation.lease_until < now(),
            ),
        )
        eligible = and_(eligible, ready_clause("native", NativeGroupOperation.id))
        if account_id is not None:
            eligible = and_(eligible, group_scope(NativeGroupOperation.group_id, account_id))
        oid = db.scalar(
            select(NativeGroupOperation.id)
            .where(eligible)
            .order_by(NativeGroupOperation.created_at)
            .limit(1)
        )
        if not oid:
            return None
        token = str(uuid.uuid4())
        changed = db.execute(
            update(NativeGroupOperation)
            .where(NativeGroupOperation.id == oid, eligible)
            .values(
                state="running",
                lease_token=token,
                attempts=NativeGroupOperation.attempts + 1,
                lease_until=now() + timedelta(seconds=settings.worker_lease_seconds),
            )
        )
        db.commit()
        return (oid, token) if changed.rowcount else None


def locked(db, oid, token):
    changed = db.execute(
        update(NativeGroupOperation)
        .where(
            NativeGroupOperation.id == oid,
            NativeGroupOperation.lease_token == token,
            NativeGroupOperation.state == "running",
        )
        .values(lease_until=now() + timedelta(seconds=settings.worker_lease_seconds))
    )
    if not changed.rowcount:
        raise RuntimeError("原生分组操作租约失效")
    op = db.get(NativeGroupOperation, oid)
    group = db.get(ManagedGroup, op.group_id)
    if group.active_job_id != op.id:
        raise RuntimeError("原生分组锁已变化")
    for item in json.loads(op.member_snapshot):
        r = db.get(Subscription, item["id"])
        if not r or r.active_operation_id != op.id:
            raise RuntimeError("原生分组成员锁已变化")
    return op, group, db.get(NativeGroupGrant, op.grant_id)


def before_write(oid, token):
    with SessionLocal() as db:
        op, group, grant = locked(db, oid, token)
        from .provisioning_coordinator import job_guard
        job_guard(db, op)
        actor = db.get(User, op.actor_id)
        payload = json.loads(op.payload)
        automatic = bool(payload.get("policy_revision"))
        if not automatic and (
            not actor.active
            or actor.deleted_at
            or actor.session_version != payload["actor_session_version"]
        ):
            raise AwsFailure("操作者权限已变化")
        account, records, _ = local_check(
            db,
            actor,
            group,
            op.kind,
            payload["cancellation_mode"],
            lock_id=op.id,
            automatic=automatic,
        )
        if (
            config_hash(db, account) != op.config_hash
            or snapshot(records) != json.loads(op.member_snapshot)
            or group.policy_revision != payload["policy_revision_expected"]
        ):
            raise AwsFailure("AWS 配置、成员或截止规则已变化，任务未发送")
        if automatic and (grant.stop_at is None or grant.stop_at > now()):
            raise AwsFailure("分组定时停止已失效")
        if op.kind == "subscribe":
            plan = db.get(Plan, grant.plan_id)
            if (
                not plan.active
                or plan.deleted_at
                or plan.subscription_type != grant.subscription_type
            ):
                raise AwsFailure("目标套餐配置已变化")
        if op.phase != "ready":
            raise AwsFailure("操作已有写入意图，只可只读核对", uncertain=True)
        op.phase, op.write_requested_at = "pending", now()
        db.commit()


def release_locks(db, op, group):
    group.active_job_id = None
    group.updated_at = now()
    for item in json.loads(op.member_snapshot):
        r = db.get(Subscription, item["id"])
        if r.active_operation_id == op.id:
            r.active_operation_id = None
            r.updated_at = now()


def complete(oid, token, info, request_id=None):
    with SessionLocal() as db:
        op, group, grant = locked(db, oid, token)
        settle_retry(db, "native", oid)
        at = now()
        if op.kind == "subscribe":
            grant.state, grant.activated_at = (
                "active",
                grant.activated_at or op.write_requested_at or at,
            )
            grant.stop_at = group_deadline(group, grant.activated_at)
            grant.policy_revision = group.policy_revision
            for activation in db.scalars(
                select(GroupMemberActivation).where(
                    GroupMemberActivation.operation_id == op.id
                )
            ):
                settle_member(db, activation, grant.activated_at, info["member_observations"][activation.record_id])
        else:
            mode = json.loads(op.payload)["cancellation_mode"]
            scheduled = mode == "END_OF_PERIOD" and bool(
                info.get("expires_at") and info["expires_at"] > at
            )
            grant.state = "cancel_scheduled" if scheduled else "cancelled"
            grant.cancelled_at, grant.cancellation_mode = grant.cancelled_at or at, mode
            grant.access_ends_at = info.get("expires_at") if scheduled else None
            for activation in db.scalars(
                select(GroupMemberActivation).where(
                    GroupMemberActivation.grant_id == grant.id,
                    GroupMemberActivation.state.in_(("active", "cancel_scheduled")),
                )
            ):
                activation.state, activation.cancelled_at = (
                    grant.state,
                    grant.cancelled_at,
                )
                r = db.get(Subscription, activation.record_id)
                from .group_subscription_state import complete_group_schedule
                from .subscription_sources import cancellation_values
                for key, value in cancellation_values(r, info["member_observations"][r.id], "GROUP", mode,
                                                       group_id=group.remote_id, at=grant.cancelled_at).items():
                    setattr(r, key, value)
                r.updated_at = at
                if not scheduled:
                    complete_group_schedule(db, r, group.id, at)
        op.state, op.phase, op.finished_at = "completed", "done", at
        op.aws_request_id, op.error = request_id or op.aws_request_id, None
        op.lease_token = op.lease_until = None
        release_locks(db, op, group)
        audit(
            db,
            db.get(User, op.actor_id),
            f"native_group_{op.kind}_completed",
            f"原生 GROUP {op.kind} 完成：{group.name}",
            subject=group.owner_id,
        )
        db.commit()


def fail(oid, token, message, uncertain, *, error=None, frozen_config=None):
    with SessionLocal() as db:
        op, group, grant = locked(db, oid, token)
        if (error is not None and frozen_config is not None
                and schedule_retry(db, "native", oid, error,
                                   mode="reconcile" if uncertain else "retry",
                                   config_hash=frozen_config,
                                   stopped=provisioning_stopped(db, "native", op))):
            op.state, op.error = "queued", message
            op.lease_token = op.lease_until = None
            if not uncertain:
                op.phase, op.write_requested_at, op.aws_request_id = "ready", None, None
            db.commit()
            return
        settle_retry(db, "native", oid)
        op.state, op.error = "needs_review" if uncertain else "failed", message
        op.lease_token = op.lease_until = None
        if op.kind == "subscribe":
            grant.state = "needs_review" if uncertain else "failed"
            for activation in db.scalars(
                select(GroupMemberActivation).where(
                    GroupMemberActivation.operation_id == op.id
                )
            ):
                activation.error = message
                if uncertain:
                    activation.state = "needs_review"
                else:
                    quota_finish(db, activation, False)
        if not uncertain:
            op.finished_at = now()
            release_locks(db, op, group)
        audit(
            db,
            db.get(User, op.actor_id),
            f"native_group_{op.state}",
            f"原生 GROUP 操作：{group.name}；{message}",
            subject=group.owner_id,
        )
        db.commit()


def confirm_remote(gateway, group, rows, grant, kind, mode):
    with assignment_read_scope(gateway):
        return _confirm_remote(gateway, group, rows, grant, kind, mode)


def _confirm_remote(gateway, group, rows, grant, kind, mode):
    actual = gateway.list_group_memberships(group.remote_id)
    if {(m["user_id"], m["id"]) for m in actual} != {
        (r.sso_user_id, r.group_membership_id) for r in rows
    } or len(actual) != len(rows):
        raise AwsFailure("写入后成员快照已漂移，保留预占等待核对", uncertain=True)
    info = gateway.group_subscription_info(group)
    if kind == "subscribe":
        if (
            info["status"] != "active"
            or info["subscription_type"] != grant.subscription_type
        ):
            raise AwsFailure("AWS 原生分组开通尚未确认", uncertain=True)
        for r in rows:
            verify_member_sources(gateway, r, group, grant.subscription_type)
    elif info["status"] not in ("cancelled", "not_subscribed") or (
        mode == "IMMEDIATE" and active_info(info)
    ):
        raise AwsFailure("AWS 原生分组取消尚未确认", uncertain=True)
    elif info.get("subscription_type") not in (None, grant.subscription_type):
        raise AwsFailure("AWS 原生分组套餐已漂移，取消结果待核对", uncertain=True)
    from .subscription_sources import observe_subscription
    aggregate_rows = gateway.report_subscriptions() if rows else []
    observations = {}
    for r in rows:
        if kind == "cancel":
            verify_member_sources(gateway, r, group, grant.subscription_type, present=active_info(info))
        observations[r.id] = observe_subscription(gateway, r, rows=aggregate_rows)
    return info | {"member_observations": observations}


def run_one(gateway_factory=None, *, account_id=None):
    return run_fenced(account_id, ("native",),
                      lambda aid: _run_one(gateway_factory or AwsGateway, aid))


def _run_one(gateway_factory, account_id):
    claimed = claim(account_id=account_id)
    if not claimed:
        return False
    oid, token = claimed
    pending = False
    recovering_write = False
    frozen_config = None
    try:
        with SessionLocal() as db:
            op, group, grant = locked(db, oid, token)
            pending = op.phase == "pending"
            recovering_write = pending
            payload = json.loads(op.payload)
            account = db.get(AwsAccount, group.aws_account_id)
            from .provisioning_coordinator import job_guard
            job_guard(db, op, recovering=pending)
            if config_hash(db, account) != op.config_hash:
                raise AwsFailure("AWS 账号或代理配置已变化，请核对原操作")
            frozen_config = op.config_hash
            rows = [
                db.get(Subscription, m["id"]) for m in json.loads(op.member_snapshot)
            ]
            if snapshot(rows) != json.loads(op.member_snapshot):
                raise AwsFailure("本地成员快照已变化")
            db.commit()
            db.expunge_all()
        gateway = gateway_factory(account)
        mode = payload["cancellation_mode"]
        request_id = None
        if not pending:
            gateway.verify()
            info = remote_check(gateway, group, rows, op.kind, grant.subscription_type)
            if payload.get("provisioning_account_id") and op.kind == "subscribe" and (
                info.get("status") not in ("not_subscribed", "cancelled")
                or info.get("pending_subscription_type")
                or info.get("pending_type")
            ):
                raise AwsFailure("AWS GROUP 授权未知或正在变更，请从分组订阅历史核对后恢复")
            if op.kind == "cancel" and not active_info(info):
                # The scheduled expiry may have passed while this stop waited.
                # Confirm and settle it without another DeleteAssignment.
                info = confirm_remote(gateway, group, rows, grant, op.kind, mode)
                complete(oid, token, info)
                return True
            before_write(oid, token)
            pending = True
            try:
                request_id = (
                    gateway.subscribe_group(group, grant.subscription_type)
                    if op.kind == "subscribe"
                    else gateway.cancel_group_subscription(group, mode)
                )
            except AwsFailure as exc:
                # A fresh explicit refusal is a confirmed failure; a recovery
                # read failure can never erase an earlier write intent.
                if not exc.uncertain:
                    pending = False
                raise
            with SessionLocal() as db:
                accepted, _, _ = locked(db, oid, token)
                accepted.aws_request_id = request_id
                db.commit()
        info = confirm_remote(gateway, group, rows, grant, op.kind, mode)
        complete(oid, token, info, request_id)
    except (AwsFailure, HTTPException) as exc:
        if not recovering_write and classify_failure(exc).proven_unsent:
            pending = False
        fail(
            oid,
            token,
            exc.detail if isinstance(exc, HTTPException) else str(exc),
            pending,
            error=exc, frozen_config=frozen_config,
        )
    except Exception as exc:
        logger.error("Native GROUP operation %s failed: %s", oid, type(exc).__name__)
        try:
            fail(
                oid, token, f"原生分组操作中断（{type(exc).__name__}），请核对",
                pending and (recovering_write or not classify_failure(exc).proven_unsent),
                error=exc, frozen_config=frozen_config,
            )
        except Exception:
            logger.error("Native GROUP operation %s remains leased for recovery", oid)
    return True


def unclaimed_automatic(db, group):
    op = (
        db.get(NativeGroupOperation, group.active_job_id)
        if group.active_job_id
        else None
    )
    if (
        op
        and op.kind == "cancel"
        and op.state == "queued"
        and op.phase == "ready"
        and op.attempts == 0
        and json.loads(op.payload).get("policy_revision")
    ):
        return op
    return None


def supersede_automatic(db, group):
    op = unclaimed_automatic(db, group)
    if op:
        op.state, op.error, op.finished_at = (
            "failed",
            "停止规则已修改，旧版本任务已撤销",
            now(),
        )
        release_locks(db, op, group)


def enqueue_due(limit=100, *, account_id=None):
    from .group_subscriptions import enqueue_native

    queued = 0
    cancellable = or_(
        NativeGroupGrant.state == "active",
        and_(NativeGroupGrant.state == "cancel_scheduled", NativeGroupGrant.access_ends_at > now()),
    )
    request_key = literal("auto-native:") + NativeGroupGrant.id + literal(":") + cast(NativeGroupGrant.policy_revision, String)
    eligible = and_(
        cancellable,
        group_scope(NativeGroupGrant.group_id, account_id),
        NativeGroupGrant.stop_at <= now(),
        select(ManagedGroup.id).where(
            ManagedGroup.id == NativeGroupGrant.group_id,
            ManagedGroup.active_job_id.is_(None),
            ManagedGroup.state == "ready",
            ManagedGroup.deleted_at.is_(None),
            ManagedGroup.remote_id.is_not(None),
        ).exists(),
        ~select(NativeGroupOperation.id).where(
            NativeGroupOperation.group_id == NativeGroupGrant.group_id,
            NativeGroupOperation.request_key == request_key,
        ).exists(),
    )
    with SessionLocal() as db:
        query = select(NativeGroupGrant.id).where(eligible).order_by(NativeGroupGrant.stop_at, NativeGroupGrant.id)
        cursor_id = _due_cursors.get(account_id)
        cursor = db.get(NativeGroupGrant, cursor_id) if cursor_id else None
        after = or_(NativeGroupGrant.stop_at > cursor.stop_at,
                    and_(NativeGroupGrant.stop_at == cursor.stop_at, NativeGroupGrant.id > cursor.id)) if cursor and cursor.stop_at else None
        ids = list(db.scalars(query.where(after).limit(limit))) if after is not None else []
        if len(ids) < limit:
            before = query.where(~after) if after is not None else query
            ids += list(db.scalars(before.limit(limit - len(ids))))
        if ids:
            # At most limit local validations per pass. Even a member or policy
            # validation failure advances the cursor for the next account turn.
            _due_cursors[account_id] = ids[-1]
    for gid in ids:
        with SessionLocal() as db:
            # Serialize against policy edits before constructing the snapshot.
            touched = db.execute(
                update(NativeGroupGrant)
                .where(
                    NativeGroupGrant.id == gid,
                    eligible,
                )
                .values(policy_revision=NativeGroupGrant.policy_revision)
            )
            if not touched.rowcount:
                continue
            grant = db.get(NativeGroupGrant, gid)
            group = db.get(ManagedGroup, grant.group_id)
            request_key = f"auto-native:{grant.id}:{grant.policy_revision}"
            if group.active_job_id or db.scalar(
                select(NativeGroupOperation.id).where(
                    NativeGroupOperation.group_id == group.id,
                    NativeGroupOperation.request_key == request_key,
                )
            ):
                continue
            opening = db.scalar(
                select(NativeGroupOperation).where(
                    NativeGroupOperation.grant_id == grant.id,
                    NativeGroupOperation.kind == "subscribe",
                )
            )
            actor = db.get(User, opening.actor_id)
            try:
                _, rows, _ = local_check(db, actor, group, "cancel", automatic=True)
                payload = {
                    "cancellation_mode": "IMMEDIATE",
                    "actor_session_version": actor.session_version,
                    "policy_revision": grant.policy_revision,
                    "policy_revision_expected": group.policy_revision,
                }
                enqueue_native(
                    db,
                    group,
                    grant,
                    actor,
                    rows,
                    "cancel",
                    request_key,
                    payload,
                    request_key,
                )
                db.commit()
                queued += 1
            except HTTPException:
                db.rollback()
    return queued


def reconcile_due(gateway_factory=None, limit=100, *, account_id=None):
    accounts = [account_id] if account_id is not None else candidate_accounts("native_due")
    queued = 0
    for aid in accounts:
        if queued >= limit:
            break
        with account_fence(aid) as acquired:
            if acquired:
                queued += _reconcile_due(gateway_factory or AwsGateway, limit - queued, aid)
    return queued


def _reconcile_due(gateway_factory, limit, account_id):
    """Expired END_OF_PERIOD assignments receive a durable read-only operation."""
    from .group_subscriptions import enqueue_native

    queued = 0
    with SessionLocal() as db:
        query = (
            select(NativeGroupGrant.id)
            .where(
                NativeGroupGrant.state == "cancel_scheduled",
                group_scope(NativeGroupGrant.group_id, account_id),
                NativeGroupGrant.access_ends_at <= now(),
            )
            .order_by(NativeGroupGrant.created_at, NativeGroupGrant.id)
        )
        cursor_id = _expiry_cursors.get(account_id)
        cursor = db.get(NativeGroupGrant, cursor_id) if cursor_id else None
        after = or_(
            NativeGroupGrant.created_at > cursor.created_at,
            and_(NativeGroupGrant.created_at == cursor.created_at,
                 NativeGroupGrant.id > cursor.id),
        ) if cursor else None
        ids = list(db.scalars(query.where(after).limit(limit))) if after is not None else []
        if len(ids) < limit:
            before = query.where(~after) if after is not None else query
            ids += list(db.scalars(before.limit(limit - len(ids))))
        if ids:
            # Advance over every selected grant, including group/member locks
            # and existing expiry intents, without expanding this pass's budget.
            _expiry_cursors[account_id] = ids[-1]
    for gid in ids:
        with SessionLocal() as db:
            touched = db.execute(
                update(NativeGroupGrant)
                .where(
                    NativeGroupGrant.id == gid,
                    NativeGroupGrant.state == "cancel_scheduled",
                    group_scope(NativeGroupGrant.group_id, account_id),
                )
                .values(policy_revision=NativeGroupGrant.policy_revision)
            )
            if not touched.rowcount:
                continue
            grant = db.get(NativeGroupGrant, gid)
            group = db.get(ManagedGroup, grant.group_id)
            if group.active_job_id:
                continue
            previous = db.scalar(
                select(NativeGroupOperation)
                .where(
                    NativeGroupOperation.grant_id == gid,
                    NativeGroupOperation.kind == "cancel",
                    NativeGroupOperation.state == "completed",
                )
                .order_by(NativeGroupOperation.created_at.desc())
                .limit(1)
            )
            rows = members(db, group)
            if any(
                r.active_operation_id or r.state != "completed" or r.reserved
                for r in rows
            ):
                continue
            actor = db.get(User, previous.actor_id)
            key = f"native-expiry:{grant.id}"
            if db.scalar(
                select(NativeGroupOperation.id).where(
                    NativeGroupOperation.group_id == group.id,
                    NativeGroupOperation.request_key == key,
                )
            ):
                continue
            op = enqueue_native(
                db,
                group,
                grant,
                actor,
                rows,
                "cancel",
                key,
                {"cancellation_mode": "END_OF_PERIOD", "reconcile_expiry": True},
                key,
            )
            op.phase, op.write_requested_at, op.config_hash = (
                "pending",
                previous.write_requested_at,
                previous.config_hash,
            )
            db.commit()
            queued += 1
    # The queue worker performs the exact same reconciliation and never writes.
    for _ in range(queued):
        run_one(gateway_factory, account_id=account_id)
    return queued
