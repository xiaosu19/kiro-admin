"""Native GROUP admission and durable selected-principal lifecycle batches."""

import json
import uuid
from collections import Counter
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session

from .aws import AwsFailure, AwsGateway, assignment_read_scope
from .batches import require_account, require_plan
from .database import get_db
from .group_subscription_state import (
    LIVE_STATES,
    active_info,
    config_hash,
    digest,
    grant_view,
    group_deadline,
    live_grant,
    reserve_member,
    verify_member_sources,
)
from .groups import owned_group
from .models import (
    AwsAccount,
    GroupMemberActivation,
    LifecycleBatch,
    LifecycleBatchItem,
    ManagedGroup,
    NativeGroupGrant,
    NativeGroupOperation,
    RecordOperation,
    StopSchedule,
    Subscription,
    User,
    now,
)
from .security import audit, get_user, lock_user_write

router = APIRouter(prefix="/api")


class GroupSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    group_ids: list[str] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def unique(self):
        if len(self.group_ids) != len(set(self.group_ids)):
            raise ValueError("不能重复选择同一分组")
        return self


class SubscribeGroupsInput(GroupSelection):
    plan_id: int
    request_key: str = Field(min_length=16, max_length=80)


class CancelGroupsInput(GroupSelection):
    cancellation_mode: Literal["IMMEDIATE", "END_OF_PERIOD"] = "IMMEDIATE"
    request_key: str = Field(min_length=16, max_length=80)


class CancelUsersInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_ids: list[str] = Field(min_length=1, max_length=100)
    cancellation_mode: Literal["IMMEDIATE", "END_OF_PERIOD"] = "IMMEDIATE"
    request_key: str = Field(min_length=16, max_length=80)

    @model_validator(mode="after")
    def unique(self):
        if len(self.record_ids) != len(set(self.record_ids)):
            raise ValueError("不能重复选择同一 SSO")
        return self


def operation_view(op):
    from .automatic_retries import retry_view
    from sqlalchemy.orm import object_session
    db = object_session(op)
    return {
        k: getattr(op, k)
        for k in (
            "id",
            "group_id",
            "grant_id",
            "kind",
            "state",
            "phase",
            "attempts",
            "error",
            "write_requested_at",
            "aws_request_id",
            "created_at",
            "finished_at",
        )
    } | {
        "principal_type": "GROUP",
        "member_count": len(json.loads(op.member_snapshot)),
        "automatic": bool(json.loads(op.payload).get("policy_revision")),
        **(retry_view(db, 'native', op.id, active=op.state in ('queued', 'running'), state=op.state) if db else {}),
    }


def batch_view(db, batch):
    items = []
    for item in db.scalars(
        select(LifecycleBatchItem)
        .where(LifecycleBatchItem.batch_id == batch.id)
        .order_by(LifecycleBatchItem.id)
    ):
        op = db.get(
            NativeGroupOperation if item.principal_type == "GROUP" else RecordOperation,
            item.operation_id,
        )
        principal = db.get(
            ManagedGroup if item.principal_type == "GROUP" else Subscription,
            item.principal_id,
        )
        items.append(
            {
                "id": item.principal_id,
                "principal_type": item.principal_type,
                "name": principal.name
                if item.principal_type == "GROUP"
                else principal.username,
                "operation_id": item.operation_id,
                "state": op.state,
                "error": op.error,
                "phase": op.phase,
            }
        )
    states = Counter(i["state"] for i in items)
    return {
        "id": batch.id,
        "kind": batch.kind,
        "created_at": batch.created_at,
        "total": len(items),
        "states": {
            s: states[s]
            for s in ("queued", "running", "completed", "failed", "needs_review")
        },
        "items": items,
    }


def batch_replay(db, actor, body, kind):
    payload_hash = digest(body.model_dump(mode="json") | {"kind": kind})
    old = db.scalar(
        select(LifecycleBatch).where(
            LifecycleBatch.actor_id == actor.id,
            LifecycleBatch.request_key == body.request_key,
        )
    )
    if old and (old.payload_hash != payload_hash or old.kind != kind):
        raise HTTPException(409, "重复请求标识与原批次内容不符")
    return old, payload_hash


def members(db, group):
    # Failed provisioning may keep its intended group for history/retry without
    # ever joining AWS. Pending intents/activations remain in the safety snapshot;
    # the complete remote comparison still rejects any unexpected actual member.
    failed_nonmember = and_(
        Subscription.state == "failed",
        Subscription.group_membership_id.is_(None),
        Subscription.active_operation_id.is_(None),
        Subscription.reserved.is_(False),
        ~select(GroupMemberActivation.id).where(
            GroupMemberActivation.record_id == Subscription.id,
            or_(GroupMemberActivation.state.in_(LIVE_STATES), GroupMemberActivation.reserved.is_(True)),
        ).exists(),
    )
    return list(
        db.scalars(
            select(Subscription)
            .where(
                Subscription.group_id == group.id, Subscription.sso_deleted_at.is_(None),
                ~failed_nonmember,
            )
            .order_by(Subscription.id)
        )
    )


def snapshot(records):
    return [
        {
            "id": r.id,
            "sso_user_id": r.sso_user_id,
            "membership_id": r.group_membership_id,
        }
        for r in records
    ]


def local_check(
    db, actor, group, kind, mode="IMMEDIATE", *, lock_id=None, automatic=False
):
    account, owner = (
        db.get(AwsAccount, group.aws_account_id),
        db.get(User, group.owner_id),
    )
    if not automatic:
        require_account(db, actor, account)
    elif not account.active or account.deleted_at:
        raise HTTPException(409, "AWS 账号已停用或删除")
    if kind == "subscribe" or (actor.role != "admin" and not automatic):
        if not owner or not owner.active or owner.deleted_at:
            raise HTTPException(409, "分组所有者已停用")
        require_account(db, owner, account)
    if (
        group.deleted_at
        or not group.remote_id
        or group.state != "ready"
        or group.active_job_id not in (None, lock_id)
    ):
        raise HTTPException(409, "分组未就绪或存在未完成任务")
    if mode == "END_OF_PERIOD" and account.control_plane != "kiro":
        raise HTTPException(409, "该 AWS 账号的旧控制面仅支持立即停止访问")
    rows = members(db, group)
    for r in rows:
        if lock_id is None and not automatic:
            from .auth_principals import active_external_login
            if active_external_login(db, r):
                raise HTTPException(409, "成员已有粘贴账号认证任务，请先处理或取消原任务")
        if (
            r.owner_id != group.owner_id
            or r.aws_account_id != group.aws_account_id
            or not r.sso_user_id
            or not r.group_membership_id
            or r.reserved
            or r.state != "completed"
            or r.active_operation_id not in (None, lock_id)
        ):
            raise HTTPException(409, "分组成员归属、AWS 配置、会员身份或处理状态不一致")
        if kind == "subscribe" and r.subscription_status in ("unknown", "pending"):
            raise HTTPException(409, "成员订阅状态待确认，请先同步核对")
        schedule = db.get(StopSchedule, r.id)
        if (
            kind == "subscribe"
            and schedule
            and schedule.mode != "none"
            # A completed USER stop belongs to that independent source's
            # history; it does not forbid a later native GROUP activation.
            and not (schedule.principal_type == "USER" and schedule.state == "completed")
            and schedule.stop_at
            and schedule.stop_at <= now()
            and not (
                schedule.source_group_id == group.id
                and not schedule.individual_override
                and group.policy_mode == "days"
            )
        ):
            raise HTTPException(409, "成员停止订阅时间已到，请先修改规则")
    if kind == "subscribe" and len(rows) > 100:
        raise HTTPException(409, "原生分组每次最多处理 100 名受管理成员")
    if kind == "subscribe" and group_deadline(group) and group_deadline(group) <= now():
        raise HTTPException(409, "分组停止订阅时间已到，请先修改规则")
    grant = live_grant(db, group.id)
    if kind == "subscribe" and grant and (not lock_id or grant.state != "pending"):
        raise HTTPException(409, "分组已有原生订阅或待核对任务")
    deadline_shortening = bool(
        automatic and mode == "IMMEDIATE" and grant
        and grant.state == "cancel_scheduled"
        and grant.access_ends_at and grant.access_ends_at > now()
    )
    if kind == "cancel" and (not grant or (grant.state != "active" and not deadline_shortening)) and not lock_id:
        raise HTTPException(409, "分组没有可取消的已生效原生订阅")
    return account, rows, grant


def remote_check(gateway, group, rows, kind, plan_type=None):
    with assignment_read_scope(gateway):
        return _remote_check(gateway, group, rows, kind, plan_type)


def _remote_check(gateway, group, rows, kind, plan_type=None):
    actual = gateway.list_group_memberships(group.remote_id)
    expected = {(r.sso_user_id, r.group_membership_id) for r in rows}
    if {(m["user_id"], m["id"]) for m in actual} != expected or len(actual) != len(
        expected
    ):
        raise AwsFailure("AWS 分组成员与本地完整快照不一致，包含未管理成员或成员已变化")
    info = gateway.group_subscription_info(group)
    if kind == "subscribe":
        if active_info(info):
            raise AwsFailure("AWS 分组已有订阅，必须先核对原生授权")
        for r in rows:
            verify_member_sources(gateway, r, group, present=False)
    elif active_info(info):
        if info["subscription_type"] != plan_type:
            raise AwsFailure("AWS 分组套餐已变化，请核对")
        for r in rows:
            verify_member_sources(gateway, r, group, plan_type)
    return info


def prepare(db, actor, ids, kind, mode):
    result = []
    for gid in ids:
        group = owned_group(db, gid, actor)
        account, rows, grant = local_check(db, actor, group, kind, mode)
        signature = digest(
            {
                "members": snapshot(rows),
                "config": config_hash(db, account),
                "revision": group.revision,
                "policy_revision": group.policy_revision,
                "grant": grant.id if grant else None,
            }
        )
        result.append((group, account, rows, grant, signature))
    if kind == "subscribe" and sum(len(item[2]) for item in result) > 100:
        raise HTTPException(409, "一次最多处理 100 名分组成员，请分批操作")
    return result


def preflight(db, actor, ids, kind, mode):
    prepared = prepare(db, actor, ids, kind, mode)
    actor_version = actor.session_version
    # Authentication starts a write transaction. Release it before remote reads,
    # then reacquire it and compare every captured input before reserving counts.
    db.commit()
    try:
        for group, account, rows, grant, _ in prepared:
            remote_check(
                AwsGateway(account),
                group,
                rows,
                kind,
                grant.subscription_type if grant else None,
            )
    except AwsFailure as exc:
        raise HTTPException(409, str(exc)) from None
    lock_user_write(db, actor, actor_version)
    db.expire_all()
    refreshed = prepare(db, actor, ids, kind, mode)
    if [x[4] for x in refreshed] != [x[4] for x in prepared]:
        raise HTTPException(409, "验证期间分组成员、配置或规则已变化，请刷新")
    return refreshed


@router.post("/group-subscriptions/preview")
def preview(
    body: GroupSelection, actor: User = Depends(get_user), db: Session = Depends(get_db)
):
    groups = preflight(db, actor, body.group_ids, "subscribe", "IMMEDIATE")
    return {
        "principal_type": "GROUP",
        "future_members_inherit": True,
        "member_count": sum(len(x[2]) for x in groups),
        "groups": [
            {
                "id": g.id,
                "name": g.name,
                "owner_id": g.owner_id,
                "aws_account_id": g.aws_account_id,
                "member_ids": [r.id for r in rows],
                "member_count": len(rows),
                "policy_revision": g.policy_revision,
            }
            for g, _, rows, _, _ in groups
        ],
    }


def enqueue_native(
    db, group, grant, actor, rows, kind, request_key, payload, payload_hash
):
    op = NativeGroupOperation(
        id=str(uuid.uuid4()),
        group_id=group.id,
        grant_id=grant.id,
        actor_id=actor.id,
        owner_id=group.owner_id,
        kind=kind,
        request_key=request_key,
        payload_hash=payload_hash,
        payload=json.dumps(payload),
        config_hash=config_hash(db, db.get(AwsAccount, group.aws_account_id)),
        member_snapshot=json.dumps(snapshot(rows)),
    )
    changed = db.execute(
        update(ManagedGroup)
        .where(
            ManagedGroup.id == group.id,
            ManagedGroup.active_job_id.is_(None),
            ManagedGroup.state == "ready",
        )
        .values(active_job_id=op.id)
    )
    if not changed.rowcount:
        raise HTTPException(409, "分组已有未完成任务")
    for r in rows:
        changed = db.execute(
            update(Subscription)
            .where(
                Subscription.id == r.id,
                Subscription.active_operation_id.is_(None),
                Subscription.state == "completed",
                Subscription.reserved.is_(False),
            )
            .values(active_operation_id=op.id, updated_at=now())
        )
        if not changed.rowcount:
            raise HTTPException(409, "分组成员已有未完成任务")
        if kind == "subscribe":
            reserve_member(db, grant, r, actor.id, op.id, op.id)
    db.add(op)
    return op


def admit_groups(db, actor, body, request, kind):
    batch_kind = "group_subscribe" if kind == "subscribe" else "group_cancel"
    old, payload_hash = batch_replay(db, actor, body, batch_kind)
    if old:
        return batch_view(db, old)
    mode = getattr(body, "cancellation_mode", "IMMEDIATE")
    prepared = preflight(db, actor, body.group_ids, kind, mode)
    old, _ = batch_replay(db, actor, body, batch_kind)
    if old:
        return batch_view(db, old)
    batch = admit_prepared_groups(db, actor, body, prepared, payload_hash, kind, request)
    db.commit()
    return batch_view(db, batch)


def admit_prepared_groups(db, actor, body, prepared, payload_hash, kind, request=None):
    """Admit validated local scope; the worker repeats remote checks before sending."""
    batch_kind = "group_subscribe" if kind == "subscribe" else "group_cancel"
    mode = getattr(body, "cancellation_mode", "IMMEDIATE")
    plan = require_plan(db, body.plan_id) if kind == "subscribe" else None
    batch = LifecycleBatch(
        id=str(uuid.uuid4()),
        actor_id=actor.id,
        request_key=body.request_key,
        payload_hash=payload_hash,
        kind=batch_kind,
    )
    db.add(batch)
    db.flush()
    for group, _, rows, grant, _ in prepared:
        if kind == "subscribe":
            grant = NativeGroupGrant(
                id=str(uuid.uuid4()),
                group_id=group.id,
                owner_id=group.owner_id,
                aws_account_id=group.aws_account_id,
                plan_id=plan.id,
                plan_name=plan.name,
                subscription_type=plan.subscription_type,
                policy_revision=group.policy_revision,
            )
            db.add(grant)
            db.flush()
        payload = {
            "cancellation_mode": mode,
            "actor_session_version": actor.session_version,
            "policy_revision_expected": group.policy_revision,
        }
        op = enqueue_native(
            db,
            group,
            grant,
            actor,
            rows,
            kind,
            f"{batch.id}:{group.id}",
            payload,
            payload_hash,
        )
        db.add(
            LifecycleBatchItem(
                batch_id=batch.id,
                principal_id=group.id,
                principal_type="GROUP",
                operation_id=op.id,
            )
        )
    audit(
        db,
        actor,
        batch_kind,
        f"原生 GROUP 批次：{len(prepared)} 个分组",
        request=request,
    )
    return batch


@router.post("/group-subscriptions", status_code=202)
def subscribe_groups(
    body: SubscribeGroupsInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    return admit_groups(db, actor, body, request, "subscribe")


@router.post("/group-subscriptions/cancel", status_code=202)
def cancel_groups(
    body: CancelGroupsInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    return admit_groups(db, actor, body, request, "cancel")


@router.get("/groups/{group_id}/native-subscriptions")
def history(
    group_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)
):
    owned_group(db, group_id, actor)
    return {
        "grants": [
            grant_view(g)
            for g in db.scalars(
                select(NativeGroupGrant)
                .where(NativeGroupGrant.group_id == group_id)
                .order_by(NativeGroupGrant.created_at.desc())
            )
        ],
        "operations": [
            operation_view(op)
            for op in db.scalars(
                select(NativeGroupOperation)
                .where(NativeGroupOperation.group_id == group_id)
                .order_by(NativeGroupOperation.created_at.desc())
            )
        ],
    }


@router.post("/group-subscriptions/{operation_id}/recheck", status_code=202)
def recheck(
    operation_id: str,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    op = db.get(NativeGroupOperation, operation_id)
    if not op:
        raise HTTPException(404, "原生分组操作不存在")
    group = owned_group(db, op.group_id, actor)
    require_account(db, actor, db.get(AwsAccount, group.aws_account_id))
    if op.state == "needs_review" and group.active_job_id == op.id:
        op.state, op.error = "queued", None
        # The original write phase is immutable: recheck never resends a write.
        audit(
            db,
            actor,
            "recheck_native_group",
            f"只读核对原生分组任务：{op.id}",
            request=request,
        )
        db.commit()
    elif op.state not in ("queued", "running", "completed"):
        raise HTTPException(409, "操作已经结束，重新操作需使用新的请求标识")
    return operation_view(op)


@router.get("/lifecycle-batches")
def listing(actor: User = Depends(get_user), db: Session = Depends(get_db)):
    query = select(LifecycleBatch)
    if actor.role != "admin":
        query = query.where(LifecycleBatch.actor_id == actor.id)
    return [
        batch_view(db, b)
        for b in db.scalars(query.order_by(LifecycleBatch.created_at.desc()).limit(100))
    ]


@router.get("/lifecycle-batches/{batch_id}")
def detail(
    batch_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)
):
    batch = db.get(LifecycleBatch, batch_id)
    if not batch or (actor.role != "admin" and batch.actor_id != actor.id):
        raise HTTPException(404, "批次不存在")
    return batch_view(db, batch)


@router.post("/subscription-cancellations", status_code=202)
def cancel_users(
    body: CancelUsersInput,
    request: Request,
    actor: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    from .lifecycle import owned, validate_operation, native_cancel_payload

    old, payload_hash = batch_replay(db, actor, body, "user_cancel")
    if old:
        return batch_view(db, old)
    batch = LifecycleBatch(
        id=str(uuid.uuid4()),
        actor_id=actor.id,
        kind="user_cancel",
        request_key=body.request_key,
        payload_hash=payload_hash,
    )
    db.add(batch)
    db.flush()
    for rid in body.record_ids:
        record = owned(db, rid, actor)
        validate_operation(
            db, record, actor, "cancel_subscription", body.cancellation_mode
        )
        oid = str(uuid.uuid4())
        changed = db.execute(
            update(Subscription)
            .where(
                Subscription.id == rid,
                Subscription.active_operation_id.is_(None),
            )
            .values(active_operation_id=oid, updated_at=now())
        )
        if not changed.rowcount:
            raise HTTPException(409, "选择的用户已有未完成操作，批次未提交")
        payload = {
            "cancellation_mode": body.cancellation_mode,
            "lifecycle_batch_id": batch.id,
            **native_cancel_payload(db, record),
        }
        db.add(
            RecordOperation(
                id=oid,
                record_id=rid,
                actor_id=actor.id,
                kind="cancel_subscription",
                request_key=f"bulk-cancel:{batch.id}",
                payload=json.dumps(payload, sort_keys=True),
            )
        )
        db.add(
            LifecycleBatchItem(
                batch_id=batch.id,
                principal_id=rid,
                principal_type="USER",
                operation_id=oid,
            )
        )
    audit(
        db,
        actor,
        "bulk_cancel_subscriptions",
        f"批量停止订阅：{len(body.record_ids)} 个 SSO",
        request=request,
    )
    db.commit()
    return batch_view(db, batch)


@router.get("/subscriptions/{record_id}/group-activations")
def member_history(
    record_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)
):
    from .lifecycle import owned

    owned(db, record_id, actor)
    fields = (
        "id",
        "grant_id",
        "record_id",
        "plan_id",
        "plan_name",
        "subscription_type",
        "counter_id",
        "cycle_number",
        "reserved",
        "counted",
        "first_opening",
        "state",
        "write_requested_at",
        "activated_at",
        "cancelled_at",
        "error",
        "created_at",
    )
    return [
        {k: getattr(a, k) for k in fields}
        for a in db.scalars(
            select(GroupMemberActivation)
            .where(GroupMemberActivation.record_id == record_id)
            .order_by(GroupMemberActivation.created_at.desc())
        )
    ]
