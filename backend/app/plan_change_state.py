"""Plan-change projections and quota settlement shared by workers and lifecycle."""

from datetime import timedelta

from sqlalchemy import or_, select, update

from .aws import AwsFailure
from .catalog import PLAN_ORDER
from .models import PlanChange, PlanCounter, now
from .security import audit

KINDS = ("change_plan", "withdraw_plan_change")
LIVE_STATES = ("queued", "applying", "needs_review", "scheduled")


def direct_user_plan(db, record, *, observed=True):
    """The individual operation ledger describes USER assignments only."""
    from .models import GroupMemberActivation
    from .subscription_sources import saved_observation, direct_source, plan_for_type

    saved = saved_observation(record) if observed else None
    latest = db.scalar(select(PlanChange).where(
        PlanChange.record_id == record.id, PlanChange.counted.is_(True),
    ).order_by(PlanChange.applied_at.desc(), PlanChange.requested_at.desc()).limit(1))
    from .aws import aws_datetime
    if latest and (not saved or latest.applied_at > aws_datetime(saved["observed_at"])):
        return dict(plan_id=latest.to_plan_id, name=latest.to_plan_name, subscription_type=latest.to_type)
    if saved:
        direct = direct_source(record)
        return plan_for_type(db, direct.get("subscription_type") if direct else None)
    native_first = db.scalar(select(GroupMemberActivation.id).where(
        GroupMemberActivation.record_id == record.id,
        GroupMemberActivation.first_opening.is_(True), GroupMemberActivation.counted.is_(True),
    ).limit(1))
    if native_first:
        return plan_for_type(db, None)
    return dict(plan_id=record.plan_id, name=record.plan_name_snapshot, subscription_type=record.subscription_type)


def current_plan(db, record):
    from .subscription_sources import saved_observation, plan_for_type
    saved = saved_observation(record)
    if saved:
        return plan_for_type(db, saved["effective"]["subscription_type"])
    # Legacy rows have no source snapshot. Their last AWS observation remains
    # useful; a historical GROUP activation must never override it.
    if record.observed_subscription_type:
        return plan_for_type(db, record.observed_subscription_type)
    return direct_user_plan(db, record)


def scheduled_change(db, record_id):
    return db.scalar(
        select(PlanChange).where(PlanChange.scheduled_record_id == record_id)
    )


def projections(db, record):
    pending = scheduled_change(db, record.id)
    return {
        "current_plan": current_plan(db, record),
        "pending_plan": (
            {
                "change_id": pending.id,
                "plan_id": pending.to_plan_id,
                "name": pending.to_plan_name,
                "subscription_type": pending.to_type,
                "expected_effective_at": pending.expected_effective_at,
                "state": pending.state,
                "error": pending.error,
            }
            if pending
            else None
        ),
    }


def referenced_plan(db, plan_id):
    return db.scalar(
        select(PlanChange.id)
        .where(
            or_(PlanChange.from_plan_id == plan_id, PlanChange.to_plan_id == plan_id)
        )
        .limit(1)
    )


def change_view(c, actor):
    fields = (
        "id",
        "record_id",
        "operation_id",
        "direction",
        "from_plan_id",
        "from_plan_name",
        "from_type",
        "to_plan_id",
        "to_plan_name",
        "to_type",
        "predecessor_id",
        "counter_id",
        "cycle_number",
        "reserved",
        "counted",
        "state",
        "requested_at",
        "write_requested_at",
        "accepted_at",
        "expected_effective_at",
        "confirmed_at",
        "applied_at",
        "checked_at",
        "next_check_at",
        "error",
    )
    result = {k: getattr(c, k) for k in fields}
    if actor.role == "admin":
        result.update(actor_id=c.actor_id, owner_id=c.owner_id)
    return result


def quota_finish(db, c, *, counted):
    if c.counted:
        return
    if c.reserved:
        values = dict(pending_count=PlanCounter.pending_count - 1)
        if counted:
            values.update(
                used_count=PlanCounter.used_count + 1,
                lifetime_count=PlanCounter.lifetime_count + 1,
            )
        changed = db.execute(
            update(PlanCounter)
            .where(
                PlanCounter.id == c.counter_id,
                PlanCounter.cycle_number == c.cycle_number,
                PlanCounter.pending_count > 0,
            )
            .values(**values)
        )
        if not changed.rowcount:
            raise RuntimeError("套餐变更预占次数不一致，需要核对；预占未释放")
        c.reserved = False
    c.counted = counted


def release(db, c, state):
    quota_finish(db, c, counted=False)
    c.state, c.scheduled_record_id, c.next_check_at = state, None, None
    c.confirmed_at, c.error = now(), None
    db.flush()


def settle(db, c):
    if c.counted:
        return
    quota_finish(db, c, counted=True)
    c.state, c.scheduled_record_id, c.next_check_at = "applied", None, None
    c.applied_at = c.confirmed_at = c.checked_at = now()
    c.accepted_at = c.accepted_at or now()
    c.error = None
    audit(
        db,
        None,
        "plan_change_applied",
        f"套餐变更已生效：{c.from_plan_name} → {c.to_plan_name}",
        subject=c.owner_id,
    )
    db.flush()


def validate_info(info):
    if not isinstance(info, dict) or info.get("status") not in (
        "active",
        "cancelled",
        "not_subscribed",
    ):
        raise AwsFailure("AWS 套餐状态无法识别，请核对", uncertain=True)
    current, pending = info.get("current_type"), info.get("pending_type")
    if (
        (info["status"] == "active" and current not in PLAN_ORDER)
        or (current is not None and current not in PLAN_ORDER)
        or (pending is not None and pending not in PLAN_ORDER)
    ):
        raise AwsFailure("AWS 返回未支持的套餐，保留预占等待核对", uncertain=True)
    if pending and (
        info["status"] != "active" or PLAN_ORDER[pending] >= PLAN_ORDER[current]
    ):
        raise AwsFailure(
            "AWS 当前和待生效套餐存在歧义，保留预占等待核对", uncertain=True
        )
    return info


def effective_source(change, predecessor):
    """A confirmed predecessor may apply while a replacement write is unknown.

    Keep the original request snapshots immutable; use its independently verified
    predecessor to describe the source that AWS now actually bills.
    """
    return (
        predecessor.to_type if predecessor and predecessor.counted else change.from_type
    )


def reconcile_scheduled(db, c, info):
    """Must run under the record's operation lock, or the caller's write lock."""
    validate_info(info)
    c.checked_at = now()
    current, pending = info["current_type"], info["pending_type"]
    predecessor = db.get(PlanChange, c.predecessor_id) if c.predecessor_id else None
    source = effective_source(c, predecessor)
    if current == c.to_type and pending is None:
        # Even a cancellation observation can prove that the target took effect.
        settle(db, c)
        return
    if info["status"] == "cancelled" and pending is None:
        if current not in (None, source):
            raise AwsFailure("取消前套餐存在漂移，变更次数待核对", uncertain=True)
        release(db, c, "cancelled")
        return
    if current == source and pending == c.to_type:
        c.error = None
        c.next_check_at = now() + timedelta(minutes=10)
        if info.get("expected_effective_at"):
            c.expected_effective_at = info["expected_effective_at"]
        return
    raise AwsFailure("AWS 套餐与已接受的变更不一致，保留预占等待核对", uncertain=True)


def lifecycle_observation(record_id, operation_id, token, info):
    """Reconcile before/after cancellation and on explicit status synchronization."""
    from .database import SessionLocal
    from .lifecycle import lock_lease, load

    with SessionLocal() as db:
        lock_lease(db, operation_id, token)
        _, record = load(db, operation_id, token)
        c = scheduled_change(db, record_id)
        if c:
            try:
                reconcile_scheduled(db, c, info)
            except AwsFailure as exc:
                c.error = str(exc)
                c.checked_at = now()
                c.next_check_at = now() + timedelta(minutes=10)
                db.commit()
                raise
        managed = direct_user_plan(db, record, observed=False)["subscription_type"]
        db.commit()
        return managed


def has_plan_history(db, record_id):
    return bool(
        db.scalar(
            select(PlanChange.id).where(PlanChange.record_id == record_id).limit(1)
        )
    )
