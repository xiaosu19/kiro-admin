"""Exact assignment sources and AWS-observed effective subscriptions.

Claims authorize principal-specific writes. ListUserSubscriptions supplies the
effective tier; neither ledger chronology nor tier prices can choose that tier.
"""

import json
from datetime import datetime

from sqlalchemy import select

from .aws import ALIASES, AwsFailure, aws_datetime
from .catalog import BY_SUBSCRIPTION_TYPE, PLAN_ORDER
from .models import GroupJob, GroupMemberActivation, NativeGroupOperation, Plan, PlanChange, RecordOperation, now


def observation_error(message, *, code="subscription_observation_invalid", retryable=False):
    return AwsFailure(message, uncertain=True, code=code, retryable=retryable)


def active_source(info):
    return info["status"] == "active" or bool(
        info.get("expires_at") and info["expires_at"] > now()
    )


def confirmed_sources(gateway, record):
    sources = gateway.user_subscription_sources(record)
    if not isinstance(sources, list):
        raise observation_error("AWS 订阅来源格式不明确，请核对")
    seen = set()
    for c in sources:
        if not isinstance(c, dict):
            raise observation_error("AWS 订阅声明格式不明确，请核对")
        source, gid = c.get("source"), c.get("group_id")
        key = (source, gid)
        kind, pending = c.get("subscription_type"), c.get("pending_type")
        if (
            source not in ("USER", "GROUP")
            or (source == "GROUP" and (not isinstance(gid, str) or not gid))
            or (source == "USER" and gid is not None)
            or key in seen
            or c.get("status") not in ("active", "cancelled", "not_subscribed")
            or (c.get("status") != "not_subscribed" and (
                not isinstance(kind, str) or kind not in PLAN_ORDER
            ))
            or (pending is not None and (
                not isinstance(pending, str) or not isinstance(kind, str)
                or pending not in PLAN_ORDER or kind not in PLAN_ORDER
                or PLAN_ORDER[pending] >= PLAN_ORDER[kind]
                or c.get("status") != "active" or c.get("expires_at") is not None
            ))
            or (c.get("expires_at") is not None and not isinstance(c["expires_at"], datetime))
        ):
            raise observation_error("AWS 订阅来源重复、未知或待确认，请核对")
        seen.add(key)
    return sources


def first_user_opened_at(db, record):
    if not record.counted or not record.subscribed_at:
        return None
    native_first = db.scalar(select(GroupMemberActivation.id).where(
        GroupMemberActivation.record_id == record.id,
        GroupMemberActivation.first_opening.is_(True), GroupMemberActivation.counted.is_(True),
    ).limit(1))
    return None if native_first else record.subscribed_at


def managed_user_type_at(db, record, at):
    change = db.scalar(select(PlanChange).where(
        PlanChange.record_id == record.id, PlanChange.counted.is_(True),
        PlanChange.applied_at <= at,
    ).order_by(PlanChange.applied_at.desc(), PlanChange.requested_at.desc()).limit(1))
    if change:
        return change.to_type
    opened_at = first_user_opened_at(db, record)
    if opened_at and opened_at <= at:
        return record.subscription_type
    return None


def legacy_sync_observed_user(db, record, observed_op):
    """Prove v11's USER branch using completed ends of exact native activations."""
    activations = list(db.scalars(select(GroupMemberActivation).where(
        GroupMemberActivation.record_id == record.id,
        GroupMemberActivation.created_at <= observed_op.finished_at,
    )))
    if not activations:
        return True
    detached = set()
    for model, kind in ((RecordOperation, "cancel_subscription"), (GroupJob, "detach")):
        for event in db.scalars(select(model).where(
            model.record_id == record.id, model.kind == kind,
            model.state == "completed", model.finished_at <= observed_op.created_at,
        )):
            activation_id = json.loads(event.payload).get("native_activation_id")
            if activation_id:
                detached.add(activation_id)
    ended_grants = {}
    for event in db.scalars(select(NativeGroupOperation).where(
        NativeGroupOperation.grant_id.in_({a.grant_id for a in activations}),
        NativeGroupOperation.kind == "cancel", NativeGroupOperation.state == "completed",
        NativeGroupOperation.finished_at <= observed_op.created_at,
    )):
        if (json.loads(event.payload).get("cancellation_mode") == "IMMEDIATE"
                and any(member["id"] == record.id for member in json.loads(event.member_snapshot))):
            ended_grants[event.grant_id] = max(event.finished_at, ended_grants.get(event.grant_id, event.finished_at))
    # EOP cancelled_at and today's native state cannot prove that the GROUP
    # branch had ended when the older sync ran. Each activation needs an end.
    return all(a.id in detached or (a.grant_id in ended_grants and ended_grants[a.grant_id] >= a.created_at)
               for a in activations)


def legacy_user_cancellation_receipt(record):
    """Replay confirmed USER events newest first until a stop or a new grant."""
    from .database import SessionLocal

    with SessionLocal() as db:
        operations = db.scalars(select(RecordOperation).where(
            RecordOperation.record_id == record.id,
            RecordOperation.state == "completed",
        ).order_by(RecordOperation.finished_at.desc(), RecordOperation.created_at.desc()))
        for op in operations:
            result = json.loads(op.result or "{}")
            snapshot = json.loads(result["subscription_observation"]) if result.get("subscription_observation") else None
            if snapshot is not None:
                if any(c["source"] == "USER" and c["status"] == "active" for c in snapshot["sources"]):
                    return None
            elif (op.kind == "sync_status" and result.get("subscription_status") == "active"
                  and result.get("observed_subscription_type") in PLAN_ORDER and op.finished_at):
                if legacy_sync_observed_user(db, record, op):
                    return None
            if op.kind != "cancel_subscription":
                continue
            payload = json.loads(op.payload)
            # Before principal_type was persisted, native_activation_id selected
            # the GROUP worker path. Ordinary group membership selected USER.
            if payload.get("native_activation_id") or payload.get("principal_type", "USER") != "USER":
                continue
            if payload.get("cancellation_mode") != "IMMEDIATE" or not op.finished_at:
                return None
            opened_at = first_user_opened_at(db, record)
            if opened_at and opened_at > op.finished_at:
                return None
            if db.scalar(select(PlanChange.id).where(
                PlanChange.record_id == record.id,
                PlanChange.applied_at > op.finished_at,
            ).limit(1)):
                return None
            if snapshot is not None:
                if "user_cancellation" in snapshot:
                    return snapshot["user_cancellation"]
                direct = next((c for c in snapshot["sources"] if c["source"] == "USER"), None)
                if not direct or direct["status"] != "cancelled":
                    return None
                return {"subscription_type": direct["subscription_type"],
                        "expires_at": direct.get("expires_at"),
                        "confirmed_at": op.finished_at.isoformat()}
            # v11 readback results observed the exact USER assignment. A newly
            # accepted write saved no type, so recover its managed USER tier at
            # completion. Never substitute the first GROUP tier or a later plan.
            # A missing access deadline says nothing about billing expiry.
            kind = result.get("observed_subscription_type") or managed_user_type_at(db, record, op.finished_at)
            if kind in PLAN_ORDER:
                return {"subscription_type": kind, "confirmed_at": op.finished_at.isoformat()}
            return None
    return None


def user_cancellation_receipt(record, sources):
    """Keep a confirmed USER stop only while its cancelled claim still matches.

    Legacy services can retain a billing expiry after IMMEDIATE cancellation.
    A missing claim is also consistent with that cancellation; a newly active
    claim, new tier, or different known expiry supersedes the old confirmation.
    """
    saved = saved_observation(record) or {}
    direct = next((c for c in sources if c["source"] == "USER"), None)
    if direct and direct["status"] == "active":
        return None
    # Explicit null means an observation already superseded the old receipt.
    receipt = saved["user_cancellation"] if "user_cancellation" in saved else legacy_user_cancellation_receipt(record)
    if not receipt:
        return None
    if direct and direct["status"] != "not_subscribed":
        if (direct["subscription_type"] != receipt["subscription_type"] or
                "expires_at" in receipt and aws_datetime(receipt["expires_at"]) != direct.get("expires_at")):
            return None
        # If the claim had disappeared at confirmation, remember the first
        # cancelled claim's boundary when it becomes visible again.
        receipt = receipt | {"expires_at": direct.get("expires_at")}
    return receipt


def access_sources(observation):
    return [c for c in observation["sources"] if active_source(c)
            and not (c["source"] == "USER" and observation.get("user_cancellation"))]


def aggregate_fields(row):
    raw_type, raw_pending = row.get("type"), row.get("newType")
    if not isinstance(raw_type, dict) or (raw_pending is not None and not isinstance(raw_pending, dict)):
        raise observation_error("AWS 整体订阅套餐格式不明确")
    kind, pending = raw_type.get("amazonQ"), (raw_pending or {}).get("amazonQ")
    if not isinstance(kind, str) or (pending is not None and not isinstance(pending, str)):
        raise observation_error("AWS 整体订阅套餐格式不明确")
    kind, pending = ALIASES.get(kind, kind), ALIASES.get(pending, pending)
    raw_status, raw_source = row.get("status"), row.get("aggregatedSubscriptionType")
    source = {"INDIVIDUAL": "USER", "GROUP": "GROUP",
              "INDIVIDUAL_AND_GROUP": "USER_AND_GROUP"}.get(raw_source) if isinstance(raw_source, str) else None
    if (kind not in PLAN_ORDER or source is None or raw_status not in
            ("ACTIVE", "PENDING", "PENDING_REMOVAL", "CANCELLED", "CANCELED")
            or (pending is not None and pending not in PLAN_ORDER)):
        raise observation_error("AWS 整体订阅状态、套餐或来源未支持，请核对")
    try:
        boundary = aws_datetime(row.get("expirationDate"))
    except AwsFailure:
        raise observation_error("AWS 订阅时间格式无法识别") from None
    return kind, pending, raw_status, source, boundary


def confirm_aggregate_shape(rows):
    """A missing user is propagation only when the aggregate itself is sound."""
    seen = set()
    for row in rows:
        principal = row.get("principal")
        uid = principal.get("user") if isinstance(principal, dict) else None
        if not isinstance(uid, str) or not uid:
            raise observation_error("AWS 整体订阅用户格式不明确")
        if uid in seen:
            raise observation_error("AWS 整体订阅重复，等待核对", code="subscription_observation_duplicate")
        seen.add(uid)
        aggregate_fields(row)


def observe_subscription(gateway, record, *, rows=None, sources=None):
    sources = confirmed_sources(gateway, record) if sources is None else sources
    receipt = user_cancellation_receipt(record, sources)
    rows = gateway.report_subscriptions() if rows is None else rows
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise observation_error("AWS 整体订阅响应格式不明确")
    matches = [r for r in rows if isinstance(r.get("principal"), dict)
               and r["principal"].get("user") == record.sso_user_id]
    live = access_sources({"sources": sources, "user_cancellation": receipt})
    if len(matches) > 1:
        raise observation_error("AWS 整体订阅重复，等待核对", code="subscription_observation_duplicate")
    if not matches and live:
        confirm_aggregate_shape(rows)
        # Claims/membership have confirmed access, but no aggregate row can
        # confirm the effective tier yet. Keep the original pending write and
        # let its fenced worker reconcile reads within the existing budget.
        raise observation_error("AWS 授权已确认，整体订阅尚未同步，等待只读核对",
                                code="subscription_observation_propagating", retryable=True)
    effective = dict(status="not_subscribed", subscription_type=None, expires_at=None,
                     pending_type=None, expected_effective_at=None, source=None, aws_status=None)
    if matches:
        row = matches[0]
        kind, pending, raw_status, source, boundary = aggregate_fields(row)
        # AWS PENDING is a usage/billing status, not an unconfirmed assignment.
        # Exact claims still must independently confirm the granted access.
        status = "active" if raw_status in ("ACTIVE", "PENDING") else "cancelled"
        if status == "active" and not live:
            raise observation_error("AWS 整体订阅与授权来源尚未一致，等待核对")
        expires = None if pending else boundary
        if not expires and status == "cancelled" and live:
            # Some aggregate rows omit expirationDate. Only unanimous source
            # cancellation boundaries prove an effective end-of-period deadline.
            boundaries = {c.get("expires_at") for c in live}
            if None in boundaries or len(boundaries) != 1:
                raise observation_error("AWS 整体取消状态与独立授权不一致，等待核对")
            expires = boundaries.pop()
        effective.update(status=status, subscription_type=kind, expires_at=expires,
                         pending_type=pending, expected_effective_at=boundary if pending else None,
                         source=source, aws_status=raw_status)
    return {"effective": effective, "sources": sources, "observed_at": now(), "user_cancellation": receipt}


def observation_values(record, observation):
    if "user_cancellation" not in observation:
        observation = observation | {"user_cancellation": user_cancellation_receipt(record, observation["sources"])}
    effective = observation["effective"]
    status, expires = effective["status"], effective.get("expires_at")
    if status == "not_subscribed" and record.counted:
        status = "cancelled"
    billing_tail_only = observation.get("user_cancellation") and not access_sources(observation)
    if status == "cancelled" and expires and expires > now() and not billing_tail_only:
        status = "cancel_scheduled"
    cancelled = status in ("cancelled", "cancel_scheduled")
    return {
        "subscription_observation": json.dumps(observation, default=lambda v: v.isoformat()),
        "subscription_status": status,
        "observed_subscription_type": effective["subscription_type"],
        "access_ends_at": expires if status == "cancel_scheduled" else None,
        "cancelled_at": record.cancelled_at if cancelled else None,
        "cancellation_mode": ("END_OF_PERIOD" if status == "cancel_scheduled" else
                              record.cancellation_mode) if cancelled else None,
        "last_synced_at": now(),
    }


def apply_observation(record, observation):
    for key, value in observation_values(record, observation).items():
        setattr(record, key, value)
    record.updated_at = now()


def cancellation_values(record, observation, principal_type, mode, *, group_id=None, user_subscription_type=None, at=None):
    """Project remaining access without attaching another principal's stop action."""
    if principal_type == "USER" and mode == "IMMEDIATE":
        direct = next((c for c in observation["sources"] if c["source"] == "USER"), None)
        if direct and direct["status"] == "active":
            raise AwsFailure("AWS USER 立即取消与来源观测尚未一致，等待只读核对", uncertain=True)
        kind = (direct or {}).get("subscription_type") or user_subscription_type or (direct_source(record) or {}).get("subscription_type")
        if kind not in PLAN_ORDER:
            raise AwsFailure("USER 取消前的套餐尚未确认，等待只读核对", uncertain=True)
        receipt = {"subscription_type": kind,
                   "confirmed_at": (at or now()).isoformat()}
        if direct:
            receipt["expires_at"] = direct.get("expires_at")
        elif observation["effective"].get("source") == "USER":
            receipt["expires_at"] = observation["effective"].get("expires_at")
        observation = observation | {"user_cancellation": receipt}
    values = observation_values(record, observation)
    other_live = any((c["source"] != principal_type or
                     principal_type == "GROUP" and c["group_id"] != group_id)
                     for c in access_sources(observation))
    if not other_live and values["subscription_status"] in ("cancelled", "cancel_scheduled"):
        values.update(cancelled_at=record.cancelled_at or at or now(), cancellation_mode=mode)
        if principal_type == "USER" and mode == "IMMEDIATE":
            # Legacy USER immediate cancellation can retain a billing boundary.
            values.update(subscription_status="cancelled", access_ends_at=None)
    return values


def saved_observation(record):
    return json.loads(record.subscription_observation) if record.subscription_observation else None


def direct_source(record):
    saved = saved_observation(record)
    return next((c for c in saved["sources"] if c["source"] == "USER"), None) if saved else None


def plan_for_type(db, kind):
    plan = db.scalar(select(Plan).where(Plan.subscription_type == kind).order_by(Plan.id).limit(1)) if kind else None
    return {"plan_id": plan.id if plan else None,
            "name": plan.name if plan else BY_SUBSCRIPTION_TYPE.get(kind, {}).get("name"),
            "subscription_type": kind}
