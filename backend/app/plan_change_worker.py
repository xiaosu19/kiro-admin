"""Durable UpdateAssignment worker: every uncertain retry is strictly read-only."""

import json
import logging
from datetime import timedelta

from botocore.exceptions import ClientError
from fastapi import HTTPException
from sqlalchemy import or_, select, update

from .account_dispatcher import (
    account_fence,
    run_fenced,
)
from .aws import AwsFailure, AwsGateway
from .config import settings
from .database import SessionLocal
from .lifecycle import claim_operation, load, lock_lease
from .models import (
    AwsAccount,
    Plan,
    PlanChange,
    RecordOperation,
    Subscription,
    User,
    now,
)
from .plan_change_state import (
    KINDS,
    direct_user_plan,
    effective_source,
    reconcile_scheduled,
    release,
    settle,
    validate_info,
)
from .plan_changes import admission_owner, ensure_change_deadline
from .security import audit
from .worker_guards import attempt_config, check_config

logger = logging.getLogger("kiro.plan_changes")


def load_change(db, op_id, token):
    op, record = load(db, op_id, token)
    c = db.scalar(select(PlanChange).where(PlanChange.operation_id == op_id))
    if not c:
        raise RuntimeError("套餐变更记录不存在")
    return op, record, c


def finish_operation(op, record, c):
    op.state, op.phase, op.error = "completed", "done", None
    op.lease_token = op.lease_until = None
    op.finished_at = now()
    op.result = json.dumps({"change_id": c.id, "state": c.state})
    payload = json.loads(op.payload)
    payload.pop("confirm_not_applied", None)
    op.payload = json.dumps(payload)
    record.active_operation_id = None
    record.updated_at = now()


def mark_pending(op_id, token, *, frozen_config=None):
    with SessionLocal() as db:
        lock_lease(db, op_id, token)
        op, record, c = load_change(db, op_id, token)
        if frozen_config is not None:
            check_config(db, db.get(AwsAccount, record.aws_account_id), frozen_config)
            admission_owner(db, record, db.get(User, c.actor_id))
            target = db.get(Plan, c.to_plan_id)
            if c.direction != "withdraw":
                if not target or not target.active or target.deleted_at or target.subscription_type != c.to_type:
                    raise AwsFailure("目标套餐已停用、删除或变更")
                ensure_change_deadline(db, record)
            payload = json.loads(op.payload)
            payload["worker_config_hash"] = frozen_config
            op.payload = json.dumps(payload)
        if op.phase != "ready":
            raise RuntimeError("套餐变更已尝试写入，禁止重放")
        op.phase, c.state = "pending", "applying"
        c.write_requested_at = now()
        db.commit()


def mark_accepted(op_id, token, request_id):
    with SessionLocal() as db:
        lock_lease(db, op_id, token)
        op, _, c = load_change(db, op_id, token)
        op.aws_request_id = request_id
        c.accepted_at = now()
        db.commit()


def preflight(op_id, token, info):
    """Fresh remote source and pending intent must both match before a paid write."""
    with SessionLocal() as db:
        lock_lease(db, op_id, token)
        op, record, c = load_change(db, op_id, token)
        admission_owner(db, record, db.get(User, c.actor_id))
        target = db.get(Plan, c.to_plan_id)
        if c.direction != "withdraw" and (
            not target
            or not target.active
            or target.deleted_at
            or target.subscription_type != c.to_type
        ):
            raise AwsFailure("目标套餐已停用、删除或变更")
        predecessor = db.get(PlanChange, c.predecessor_id) if c.predecessor_id else None
        if (
            predecessor
            and predecessor.scheduled_record_id
            and info["current_type"] == predecessor.to_type
            and not info["pending_type"]
        ):
            settle(db, predecessor)
            db.commit()  # Its already-effective change is owed even if this source is stale.
        if c.direction != "withdraw":
            ensure_change_deadline(db, record)
        if (
            info["status"] != "active"
            or info["current_type"] != c.from_type
            or direct_user_plan(db, record)["subscription_type"] != c.from_type
        ):
            raise AwsFailure("AWS 当前套餐已变化，本次变更未提交，请同步后重新选择")
        expected_pending = (
            predecessor.to_type
            if predecessor and predecessor.scheduled_record_id
            else None
        )
        if info["pending_type"] != expected_pending:
            raise AwsFailure("AWS 待生效套餐与记录不一致，请核对", uncertain=True)
        if c.direction == "withdraw" and not expected_pending:
            raise AwsFailure("原待生效套餐已不存在，本次撤回未提交")
        db.commit()


def apply_observation(op_id, token, info, request_id=None, access_observation=None):
    with SessionLocal() as db:
        lock_lease(db, op_id, token)
        op, record, c = load_change(db, op_id, token)
        validate_info(info)
        c.checked_at = now()
        if access_observation is None:
            raise AwsFailure("缺少 AWS 整体订阅观测，保留变更等待核对", uncertain=True)
        from .subscription_sources import apply_observation as apply_access
        apply_access(record, access_observation)
        if request_id:
            op.aws_request_id = request_id
        payload = json.loads(op.payload)
        predecessor = db.get(PlanChange, c.predecessor_id) if c.predecessor_id else None
        if (
            predecessor
            and predecessor.scheduled_record_id
            and info["current_type"] == predecessor.to_type
        ):
            # This already-effective change is owed even if the newer write still
            # cannot be resolved. Commit it before that later observation fails.
            settle(db, predecessor)
            db.commit()
            lock_lease(db, op_id, token)
            op, record, c = load_change(db, op_id, token)
        source = effective_source(c, predecessor)
        if c.scheduled_record_id:
            if (
                payload.get("confirm_not_applied")
                and info["status"] == "active"
                and info["current_type"] == source
                and info["pending_type"] is None
            ):
                return release_or_review(db, op, record, c, predecessor, info, payload)
            reconcile_scheduled(db, c, info)
            finish_operation(op, record, c)
            db.commit()
            return
        current, pending = info["current_type"], info["pending_type"]
        if c.write_requested_at:
            if (
                c.direction != "withdraw"
                and current == c.to_type
                and pending is None
                and info["status"] in ("active", "cancelled")
            ):
                # A target-tier cancellation still proves the paid change took
                # effect, just as in reconciliation of an accepted schedule.
                if predecessor and predecessor.scheduled_record_id:
                    release(db, predecessor, "superseded")
                settle(db, c)
            elif (
                info["status"] == "cancelled"
                and c.direction == "withdraw"
                and current == source
                and pending is None
            ):
                # Cancellation removes the pending downgrade. An already-effective
                # predecessor was settled above; otherwise its reservation is free.
                if predecessor and predecessor.scheduled_record_id:
                    release(db, predecessor, "cancelled")
                release(db, c, "cancelled")
            elif (
                info["status"] == "active"
                and c.direction == "withdraw"
                and current == c.from_type
                and pending is None
            ):
                if predecessor and predecessor.scheduled_record_id:
                    release(db, predecessor, "withdrawn")
                release(db, c, "withdrawn")
            elif (
                info["status"] == "active"
                and c.direction == "downgrade"
                and current == source
                and pending == c.to_type
            ):
                if predecessor and predecessor.scheduled_record_id:
                    release(db, predecessor, "superseded")
                c.state, c.scheduled_record_id = "scheduled", record.id
                c.accepted_at = c.accepted_at or now()
                c.confirmed_at = now()
                c.expected_effective_at = info.get("expected_effective_at")
                c.next_check_at = now() + timedelta(minutes=10)
                c.error = None
            else:
                return release_or_review(db, op, record, c, predecessor, info, payload)
        else:
            return release_or_review(db, op, record, c, predecessor, info, payload)
        finish_operation(op, record, c)
        db.commit()


def release_or_review(db, op, record, c, predecessor, info, payload):
    expected_pending = (
        predecessor.to_type if predecessor and predecessor.scheduled_record_id else None
    )
    safe_source = (
        info["status"] == "active"
        and info["current_type"] == effective_source(c, predecessor)
        and info["pending_type"] == expected_pending
    )
    confirmed = payload.get("confirm_not_applied")
    waited = c.write_requested_at and now() - c.write_requested_at >= timedelta(
        minutes=10
    )
    if safe_source and (not c.write_requested_at or (confirmed and waited)):
        release(db, c, "not_applied")
        finish_operation(op, record, c)
        audit(
            db,
            None,
            "plan_change_not_applied",
            f"AWS 只读核对未生效，释放本次预占：{c.id}",
            subject=c.owner_id,
        )
        db.commit()
        return
    raise AwsFailure(
        "AWS 尚未确认本次变更结果；保留次数和用户锁，仅可只读核对", uncertain=True
    )


def fail_change(op_id, token, message, uncertain):
    with SessionLocal() as db:
        lock_lease(db, op_id, token)
        op, record, c = load_change(db, op_id, token)
        if c.scheduled_record_id:
            # An accepted schedule cannot monopolize SSO management for a month.
            c.error = message
            c.checked_at, c.next_check_at = now(), now() + timedelta(minutes=10)
            finish_operation(op, record, c)
            op.error = message
        elif uncertain:
            op.state, c.state = "needs_review", "needs_review"
            op.error = c.error = message
            op.lease_token = op.lease_until = None
        else:
            release(db, c, "failed")
            payload = json.loads(op.payload)
            payload.pop("worker_config_hash", None)
            op.payload = json.dumps(payload)
            c.error = op.error = message
            op.state, op.phase = "failed", "done"
            op.lease_token = op.lease_until = None
            op.finished_at, record.active_operation_id = now(), None
        record.updated_at = now()
        audit(
            db,
            None,
            "plan_change_" + c.state,
            f"套餐变更 {c.id}：{message}",
            subject=c.owner_id,
        )
        db.commit()


def run_plan_change(gateway_factory=None, *, account_id=None):
    if not settings.plan_changes_enabled:
        return False
    return run_fenced(account_id, ("plan",),
                      lambda aid: _run_one(gateway_factory or AwsGateway, aid))


def _run_one(gateway_factory, account_id):
    if not settings.plan_changes_enabled:
        return False
    job = claim_operation(KINDS, account_id=account_id)
    if not job:
        return False
    op_id, token = job
    pending, definite_rejection = False, False
    try:
        with SessionLocal() as db:
            op, record, c = load_change(db, op_id, token)
            pending = op.phase == "pending"
            account = db.get(AwsAccount, record.aws_account_id)
            frozen_config = attempt_config(db, account, json.loads(op.payload).get("worker_config_hash")
                                           if pending or c.accepted_at else None)
            if not account or ((not account.active or account.deleted_at) and not (pending or c.accepted_at)):
                raise AwsFailure(
                    "AWS 账号不可用；恢复后继续只读核对", uncertain=pending
                )
            db.expunge_all()
        gateway = gateway_factory(account)
        from .subscription_sources import observe_subscription
        info = validate_info(gateway.plan_change_info(record))
        if pending or c.accepted_at:
            apply_observation(op_id, token, info, access_observation=observe_subscription(gateway, record))
            return True
        preflight(op_id, token, info)
        mark_pending(op_id, token, frozen_config=frozen_config)
        pending = True
        try:
            request_id = gateway.update_assignment(record, c.to_type)
        except AwsFailure as exc:
            definite_rejection = not exc.uncertain
            raise
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "ClientError")
            status = exc.response.get("ResponseMetadata", {}).get(
                "HTTPStatusCode", 0
            )
            definite_rejection = 400 <= status < 500 and code not in (
                "RequestTimeout",
                "ConflictException",
            )
            raise
        mark_accepted(op_id, token, request_id)
        info = validate_info(gateway.plan_change_info(record))
        apply_observation(op_id, token, info, request_id, observe_subscription(gateway, record))
    except HTTPException as exc:
        fail_change(op_id, token, exc.detail, pending)
    except AwsFailure as exc:
        fail_change(
            op_id,
            token,
            str(exc),
            # A failed read cannot make a write that never started uncertain.
            # Once pending was durably checkpointed, only a definite rejection
            # from UpdateAssignment itself can release this reservation.
            pending and not definite_rejection,
        )
    except Exception as exc:
        logger.error("Plan change %s failed: %s", op_id, type(exc).__name__)
        try:
            fail_change(
                op_id,
                token,
                f"套餐变更中断（{type(exc).__name__}），请核对",
                pending and not definite_rejection,
            )
        except Exception:
            logger.error("Plan change %s retains lease for read-only recovery", op_id)
    return True


def reconcile_due(gateway_factory=None, *, limit=20, force=False, account_id=None):
    if not settings.plan_changes_enabled:
        return 0
    if account_id is None:
        # Force is an administrative/test reconciliation request, including future checks.
        with SessionLocal() as db:
            accounts = sorted(set(db.scalars(select(Subscription.aws_account_id).join(
                PlanChange, PlanChange.record_id == Subscription.id).where(
                    PlanChange.scheduled_record_id.is_not(None)))))
    else:
        accounts = [account_id]
    queued = 0
    for aid in accounts:
        if queued >= limit:
            break
        with account_fence(aid) as acquired:
            if acquired:
                queued += _reconcile_due(gateway_factory or AwsGateway, limit=limit - queued,
                                         force=force, account_id=aid)
    return queued


def _reconcile_due(gateway_factory, *, limit, force, account_id):
    """Lease due accepted schedules using their original durable operation."""
    if not settings.plan_changes_enabled:
        return 0
    with SessionLocal() as db:
        query = (
            select(PlanChange.id)
            .join(Subscription, Subscription.id == PlanChange.record_id)
            .where(
                PlanChange.scheduled_record_id.is_not(None),
                Subscription.aws_account_id == account_id,
                Subscription.active_operation_id.is_(None),
            )
        )
        if not force:
            query = query.where(
                or_(
                    PlanChange.next_check_at.is_(None),
                    PlanChange.next_check_at <= now(),
                )
            )
        ids = list(db.scalars(query.order_by(PlanChange.next_check_at).limit(limit)))
    queued = 0
    for change_id in ids:
        with SessionLocal() as db:
            c = db.get(PlanChange, change_id)
            due = or_(
                PlanChange.next_check_at.is_(None), PlanChange.next_check_at <= now()
            )
            changed = db.execute(
                update(PlanChange)
                .where(
                    PlanChange.id == change_id,
                    PlanChange.record_id.in_(select(Subscription.id).where(Subscription.aws_account_id == account_id)),
                    PlanChange.scheduled_record_id.is_not(None),
                    True if force else due,
                )
                .values(next_check_at=now() + timedelta(minutes=10))
            )
            if not changed.rowcount:
                continue
            locked = db.execute(
                update(Subscription)
                .where(
                    Subscription.id == c.record_id,
                    Subscription.active_operation_id.is_(None),
                )
                .values(active_operation_id=c.operation_id, updated_at=now())
            )
            if not locked.rowcount:
                db.rollback()
                continue
            op = db.get(RecordOperation, c.operation_id)
            op.state, op.phase = "queued", "pending"
            op.lease_token = op.lease_until = None
            db.commit()
            queued += 1
        run_plan_change(gateway_factory, account_id=account_id)
    return queued
