"""One row per platform user, with independently paginated plan history."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import case, func, literal, or_, select, union_all
from sqlalchemy.orm import Session

from .catalog import PLAN_ORDER
from .database import get_db
from .models import CounterReset, GroupMemberActivation, Plan, PlanChange, PlanCounter, Subscription, User
from .group_subscription_state import initial_user_activation
from .plan_change_state import LIVE_STATES as CHANGE_STATES
from .security import admin
from .statistics import cancelled_record

router = APIRouter(prefix="/api/admin")


def user_summary(db):
    users = list(
        db.scalars(select(User).where(User.deleted_at.is_(None)).order_by(User.id))
    )
    plans = sorted(
        db.scalars(select(Plan)), key=lambda p: PLAN_ORDER.get(p.subscription_type, 999)
    )
    plan_names = {p.id: p.name for p in plans}
    counters = {}
    for c in db.scalars(select(PlanCounter)):
        counters.setdefault(c.user_id, []).append(
            {
                **{
                    k: getattr(c, k)
                    for k in (
                        "id",
                        "user_id",
                        "plan_id",
                        "limit_count",
                        "used_count",
                        "pending_count",
                        "lifetime_count",
                        "cycle_number",
                    )
                },
                "plan_name": plan_names[c.plan_id],
            }
        )
    activations = {
        (uid, pid): n
        for uid, pid, n in db.execute(
            select(Subscription.owner_id, Subscription.plan_id, func.count())
            .where(Subscription.counted.is_(True), initial_user_activation())
            .group_by(Subscription.owner_id, Subscription.plan_id)
        )
    }
    pending = {
        (uid, pid): n
        for uid, pid, n in db.execute(
            select(Subscription.owner_id, Subscription.plan_id, func.count())
            .where(
                Subscription.state.in_(("queued", "running", "needs_review")),
                Subscription.plan_id.is_not(None),
            )
            .group_by(Subscription.owner_id, Subscription.plan_id)
        )
    }
    for uid, pid, count in db.execute(
        select(PlanChange.owner_id, PlanChange.to_plan_id, func.count())
        .where(PlanChange.counted.is_(True))
        .group_by(PlanChange.owner_id, PlanChange.to_plan_id)
    ):
        activations[(uid, pid)] = activations.get((uid, pid), 0) + count
    for uid, pid, count in db.execute(
        select(PlanChange.owner_id, PlanChange.to_plan_id, func.count())
        .where(PlanChange.state.in_(CHANGE_STATES), PlanChange.direction != "withdraw")
        .group_by(PlanChange.owner_id, PlanChange.to_plan_id)
    ):
        pending[(uid, pid)] = pending.get((uid, pid), 0) + count
    for uid, pid, count in db.execute(
        select(GroupMemberActivation.owner_id, GroupMemberActivation.plan_id, func.count())
        .where(GroupMemberActivation.counted.is_(True))
        .group_by(GroupMemberActivation.owner_id, GroupMemberActivation.plan_id)
    ):
        activations[(uid, pid)] = activations.get((uid, pid), 0) + count
    for uid, pid, count in db.execute(
        select(GroupMemberActivation.owner_id, GroupMemberActivation.plan_id, func.count())
        .where(GroupMemberActivation.state.in_(("pending", "needs_review")))
        .group_by(GroupMemberActivation.owner_id, GroupMemberActivation.plan_id)
    ):
        pending[(uid, pid)] = pending.get((uid, pid), 0) + count
    for u in users:
        if u.role == "admin":
            previous = {c["plan_id"]: c for c in counters.get(u.id, [])}
            counters[u.id] = [
                {
                    "id": previous.get(p.id, {}).get("id", 0),
                    "user_id": u.id,
                    "plan_id": p.id,
                    "plan_name": p.name,
                    "limit_count": 0,
                    "used_count": 0,
                    "pending_count": pending.get((u.id, p.id), 0),
                    "lifetime_count": max(
                        activations.get((u.id, p.id), 0),
                        previous.get(p.id, {}).get("lifetime_count", 0),
                    ),
                    "cycle_number": previous.get(p.id, {}).get("cycle_number", 1),
                }
                for p in plans
            ]
    sso = {
        owner: (total, active, pending, cancelled, deleted)
        for owner, total, active, pending, cancelled, deleted in db.execute(
            select(
                Subscription.owner_id,
                func.sum(case((Subscription.sso_user_id.is_not(None), 1), else_=0)),
                func.sum(
                    case(
                        (
                            Subscription.sso_user_id.is_not(None)
                            & Subscription.sso_deleted_at.is_(None),
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.sum(
                    case(
                        (
                            or_(
                                Subscription.state.in_(
                                    ("queued", "running", "needs_review")
                                ),
                                Subscription.active_operation_id.is_not(None),
                            ),
                            1,
                        ),
                        else_=0,
                    )
                ),
                func.count().filter(cancelled_record()),
                func.count().filter(Subscription.sso_deleted_at.is_not(None)),
            ).group_by(Subscription.owner_id)
        )
    }
    return {
        "plans": [
            {"id": p.id, "name": p.name + ("（已删除）" if p.deleted_at else "")}
            for p in plans
        ],
        "users": [
            {
                "id": u.id,
                "username": u.username,
                "display_name": u.display_name,
                "active": u.active,
                "role": u.role,
                "sso_total": sso.get(u.id, (0, 0, 0))[0],
                "sso_active": sso.get(u.id, (0, 0, 0))[1],
                "pending_tasks": sso.get(u.id, (0, 0, 0))[2],
                "counters": counters.get(u.id, []),
                "cancelled_subscriptions": sso.get(u.id, (0, 0, 0, 0, 0))[3],
                "deleted_sso": sso.get(u.id, (0, 0, 0, 0, 0))[4],
            }
            for u in users
        ],
    }


@router.get("/users/{user_id}/plan-history")
def plan_history(
    user_id: int,
    plan_id: int,
    kind: Literal["subscriptions", "resets"] = "subscriptions",
    page: int = Query(1, ge=1),
    _: User = Depends(admin),
    db: Session = Depends(get_db),
):
    u, plan = db.get(User, user_id), db.get(Plan, plan_id)
    if not u or not plan:
        raise HTTPException(404, "用户或套餐不存在")
    if kind == "subscriptions":
        events = union_all(
            select(
                literal("subscription").label("event_kind"),
                Subscription.id.label("id"),
                Subscription.id.label("record_id"),
                Subscription.subscribed_at.label("occurred_at"),
            ).where(
                Subscription.owner_id == user_id,
                Subscription.plan_id == plan_id,
                Subscription.counted.is_(True),
                initial_user_activation(),
            ),
            select(
                literal("plan_change"),
                PlanChange.id,
                PlanChange.record_id,
                PlanChange.applied_at,
            ).where(
                PlanChange.owner_id == user_id,
                PlanChange.to_plan_id == plan_id,
                PlanChange.counted.is_(True),
            ),
            select(literal("group_activation"), GroupMemberActivation.id,
                   GroupMemberActivation.record_id, GroupMemberActivation.activated_at).where(
                GroupMemberActivation.owner_id == user_id,
                GroupMemberActivation.plan_id == plan_id,
                GroupMemberActivation.counted.is_(True),
            ),
        ).subquery()
        total = db.scalar(select(func.count()).select_from(events))
        items = []
        for event in db.execute(
            select(events)
            .order_by(events.c.occurred_at.desc(), events.c.id)
            .offset((page - 1) * 20)
            .limit(20)
        ):
            r = db.get(Subscription, event.record_id)
            c = (
                db.get(PlanChange, event.id)
                if event.event_kind == "plan_change"
                else None
            )
            g = db.get(GroupMemberActivation, event.id) if event.event_kind == "group_activation" else None
            items.append(
                {
                    **{
                        k: getattr(r, k)
                        for k in (
                            "username",
                            "subscribed_at",
                            "subscription_status",
                            "cancelled_at",
                            "sso_deleted_at",
                        )
                    },
                    "id": event.id,
                    "record_id": r.id,
                    "event_kind": event.event_kind,
                    "occurred_at": event.occurred_at,
                    "cycle_number": c.cycle_number if c else g.cycle_number if g else r.cycle_number,
                    "plan_name": c.to_plan_name
                    if c
                    else g.plan_name if g else r.plan_name_snapshot or plan.name,
                    **({"source": "GROUP", "grant_id": g.grant_id, "cancelled_at": g.cancelled_at} if g else {}),
                    **(
                        {
                            "direction": c.direction,
                            "applied_at": c.applied_at,
                            "from_plan_name": c.from_plan_name,
                        }
                        if c
                        else {}
                    ),
                }
            )
    else:
        query = (
            select(CounterReset)
            .join(PlanCounter)
            .where(PlanCounter.user_id == user_id, PlanCounter.plan_id == plan_id)
        )
        total = db.scalar(select(func.count()).select_from(query.subquery()))
        items = [
            {
                **{
                    k: getattr(r, k)
                    for k in (
                        "id",
                        "cycle_number",
                        "used_count",
                        "previous_limit",
                        "new_limit",
                        "reason",
                        "created_at",
                    )
                },
                "actor_name": db.get(User, r.actor_id).username,
                "plan_name": plan.name,
            }
            for r in db.scalars(
                query.order_by(CounterReset.id.desc()).offset((page - 1) * 20).limit(20)
            )
        ]
    return {"items": items, "total": total, "page": page, "page_size": 20}
