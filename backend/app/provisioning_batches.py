"""Immutable numbered intent admission and read-only progress projections."""

import json
import uuid
from collections import Counter
from datetime import datetime
from types import SimpleNamespace
from typing import Annotated, Literal

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from . import aws, aws_reports, group_observations
from .account_numbers import claim_number
from .batches import require_account, require_plan
from .catalog import BY_SUBSCRIPTION_TYPE
from .database import get_db
from .email_addresses import generated_email
from .group_policies import GroupPolicyInput, group_policy, preview_change
from .group_subscription_state import LIVE_STATES as GRANT_STATES, config_hash, digest
from .group_subscriptions import members as group_members
from .groups import scope as directory_scope
from .models import (
    AwsAccount, AwsAccountNumber, Binding, GroupMemberActivation, ManagedGroup,
    NativeGroupGrant, NativeGroupOperation, PlanCounter, ProvisioningAccountBatch, ProvisioningBatch,
    ProvisioningCounter, ProvisioningItem, Proxy, StopSchedule, Subscription, User, now,
)
from .proxies import ProxyUnavailable, proxy_selection
from .schemas import StopPolicy
from .schedules import LIVE_STATES as SCHEDULE_STATES, deadline
from .security import audit, get_user

router = APIRouter(prefix="/api/provisioning-batches")
# Failed unsent intents can be terminal. Uncertain remote work must retain fences.
LIVE_STATES = ("queued", "running", "needs_review", "uncertain", "stopping", "paused")


class NewGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["new"]


class ExistingGroup(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["existing"]
    group_id: str = Field(min_length=1, max_length=36)
    expected_revision: int = Field(ge=1, strict=True)
    expected_policy_revision: int = Field(ge=0, strict=True)


class ExportFormats(BaseModel):
    model_config = ConfigDict(extra="forbid")
    csv: bool = Field(strict=True)
    txt: bool = Field(strict=True)
    json_export: bool = Field(alias="json", strict=True)


class AccountIntent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    aws_account_id: int = Field(ge=1, strict=True)
    quantity: int = Field(ge=1, le=100, strict=True)
    plan_id: int = Field(ge=1, strict=True)
    group: Annotated[NewGroup | ExistingGroup, Field(discriminator="mode")]
    stop_policy: StopPolicy | None = None
    exports: ExportFormats
    overwrite_individual: bool = Field(default=False, strict=True)

    @model_validator(mode="after")
    def policy_intent(self):
        if "stop_policy" in self.model_fields_set and self.stop_policy is None:
            raise ValueError("省略停止规则表示继承；清除规则请明确选择 none")
        if self.overwrite_individual and (self.group.mode != "existing" or self.stop_policy is None):
            raise ValueError("覆盖个人规则仅适用于明确修改已有分组规则")
        return self


class PreviewInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    accounts: list[AccountIntent] = Field(min_length=1, max_length=100)

    @model_validator(mode="after")
    def unique_accounts(self):
        if len({row.aws_account_id for row in self.accounts}) != len(self.accounts):
            raise ValueError("每个 AWS 账号只能选择一次")
        return self


class AdmissionInput(PreviewInput):
    request_key: str = Field(min_length=16, max_length=80)
    preview_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


def dumps(value):
    return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))


def normalized_intent(body):
    rows = []
    for row in body.accounts:
        value = row.model_dump(mode="json", by_alias=True)
        # New groups have one canonical default. Existing omissions are retained
        # as inheritance, distinct from an explicit clear of an existing rule.
        if row.group.mode == "new" and row.stop_policy is None:
            value["stop_policy"] = StopPolicy().model_dump(mode="json")
        rows.append(value)
    return {"accounts": rows}


def fields(row):
    return {column.name: getattr(row, column.name) for column in row.__table__.columns} if row else None


def actor_identity(actor):
    return {key: getattr(actor, key) for key in ("id", "role", "session_version", "active", "deleted_at", "must_change_password")}


def require_actor(db, actor_id, expected=None):
    actor = db.get(User, actor_id, populate_existing=True)
    if not actor or not actor.active or actor.deleted_at or actor.must_change_password:
        raise HTTPException(401, "登录权限已变更，请重新登录")
    if expected is not None and actor_identity(actor) != expected:
        raise HTTPException(409, "用户角色或登录会话已变化，请重新预览")
    return actor


def configuration_signature(db, account):
    """Transport-only fencing, independent of display names and account codes."""
    proxy = db.get(Proxy, account.proxy_id, populate_existing=True) if account.proxy_id else None
    return digest({"configuration": config_hash(db, account), "portal_url": account.portal_url,
                   "proxy": {key: getattr(proxy, key) for key in (
                       "id", "revision", "enabled", "host", "port", "auth_encrypted",
                   )} if proxy else None})


def compatible_group(db, actor, account, row, plan):
    """Joining a settled active grant is valid; the native opening guard is not."""
    group = db.get(ManagedGroup, row.group.group_id)
    if not group or group.owner_id != actor.id:
        raise HTTPException(404, "分组不存在或不属于当前用户")
    if (group.aws_account_id != account.id or group.aws_scope != directory_scope(account)
            or group.deleted_at or group.state != "ready" or not group.remote_id or group.active_job_id):
        raise HTTPException(409, "分组的账号、归属或状态不可用于批次开通")
    if (group.revision != row.group.expected_revision or group.policy_revision != row.group.expected_policy_revision):
        raise HTTPException(409, "分组或停止规则版本已变化，请重新预览")
    grants = list(db.scalars(select(NativeGroupGrant).where(
        NativeGroupGrant.group_id == group.id, NativeGroupGrant.state.in_(GRANT_STATES))))
    if len(grants) > 1:
        raise HTTPException(409, "分组存在重复原生 GROUP 授权，请先核对")
    grant = grants[0] if grants else None
    if grant and (grant.state != "active" or grant.plan_id != plan.id
                  or grant.subscription_type != plan.subscription_type
                  or grant.owner_id != actor.id or grant.aws_account_id != account.id
                  or not grant.activated_at
                  or (grant.stop_at and grant.stop_at <= now())):
        raise HTTPException(409, "原生 GROUP 订阅的套餐、归属或状态不兼容，或已到停止时间")
    operations = list(db.scalars(select(NativeGroupOperation).where(
        NativeGroupOperation.group_id == group.id, NativeGroupOperation.state.in_(("queued", "running", "needs_review")),
    )))
    if operations:
        raise HTTPException(409, "原生分组仍有未完成或待核对任务")
    records = group_members(db, group)
    if not grant and len(records) + row.quantity > 100:
        raise HTTPException(409, "未订阅分组的已有成员与新增人数合计最多 100 人，请调整人数或使用新分组")
    policy = row.stop_policy or group_policy(group)
    deadline(policy, grant.activated_at if grant else None)
    policy_change, changed_member_ids = None, set()
    if row.stop_policy is not None:
        affected, policy_change = preview_change(db, group, GroupPolicyInput(policy=row.stop_policy,
            expected_revision=row.group.expected_policy_revision, overwrite_individual=row.overwrite_individual))
        if policy_change["conflict_count"]:
            raise HTTPException(409, "分组停止规则存在冲突，请先核对")
        changed_member_ids = {record.id for record in affected}
    member_snapshots = []
    for record in records:
        if (record.owner_id != actor.id or record.aws_account_id != account.id or not record.sso_user_id
                or not record.group_membership_id or record.state != "completed" or record.reserved
                or record.active_operation_id or record.subscription_status in ("unknown", "pending")
                or (grant and record.subscription_status != "active")):
            raise HTTPException(409, "分组成员归属、会员身份或处理状态尚未核对")
        activations = list(db.scalars(select(GroupMemberActivation).where(
            GroupMemberActivation.record_id == record.id,
            or_(GroupMemberActivation.state.in_(("pending", "active", "cancel_scheduled", "needs_review")),
                GroupMemberActivation.reserved.is_(True)),
        ).order_by(GroupMemberActivation.id)))
        if any(a.reserved or not a.counted or a.state != "active" or not a.activated_at
               or not grant or a.grant_id != grant.id or a.owner_id != actor.id
               or a.plan_id != plan.id or a.subscription_type != plan.subscription_type for a in activations):
            raise HTTPException(409, "成员的原生 GROUP 开通尚未结算或等待核对")
        if grant and len(activations) != 1:
            raise HTTPException(409, "有效原生 GROUP 成员缺少已结算授权，请先核对")
        schedule = db.get(StopSchedule, record.id)
        # Shared policy preview validates replacement deadlines and preserves
        # individual/historical skips. Only retained live rules can be overdue;
        # a completed USER deadline does not end independent GROUP access.
        if (schedule and schedule.state in SCHEDULE_STATES and record.id not in changed_member_ids
                and schedule.mode != "none" and schedule.stop_at and schedule.stop_at <= now()):
            inherited_days = schedule.source_group_id == group.id and not schedule.individual_override and group.policy_mode == "days"
            if not inherited_days:
                raise HTTPException(409, "分组成员停止时间已到，请先修改规则")
        # Include a digest of all source fields for drift detection without
        # persisting existing credentials into this new intent envelope.
        member_snapshots.append({"id": record.id, "sso_user_id": record.sso_user_id,
            "username": record.username, "email": record.email, "membership_id": record.group_membership_id,
            "record_hash": digest(fields(record)), "schedule": fields(schedule),
            "activations": [fields(a) for a in activations]})
    return group, grant, member_snapshots, policy, policy_change


def prepare(db, actor, body):
    snapshots, remote_inputs = [], []
    for position, row in enumerate(body.accounts, 1):
        account = db.get(AwsAccount, row.aws_account_id, populate_existing=True)
        require_account(db, actor, account)
        if not account.account_number:
            raise HTTPException(409, "请管理员先设置 AWS 编号")
        number = db.get(AwsAccountNumber, account.account_number)
        if number and number.aws_account_id != account.id:
            raise HTTPException(409, "AWS 编号与永久登记归属不一致")
        if db.scalar(select(AwsAccount.id).where(AwsAccount.account_number == account.account_number, AwsAccount.id != account.id).limit(1)):
            raise HTTPException(409, "AWS 编号存在重复配置")
        try:
            selection = proxy_selection(db, account.proxy_id)
        except ProxyUnavailable:
            raise HTTPException(409, "请先绑定可用代理") from None
        if selection is None:
            raise HTTPException(409, "请先绑定可用代理")
        plan = require_plan(db, row.plan_id)
        if plan.subscription_type not in BY_SUBSCRIPTION_TYPE:
            raise HTTPException(409, "该套餐不支持批次开通")
        group, grant, members, policy_change = None, None, [], None
        policy = row.stop_policy or StopPolicy()
        if row.group.mode == "existing":
            group, grant, members, policy, policy_change = compatible_group(db, actor, account, row, plan)
        else:
            deadline(policy)
        snapshot = {"position": position, "aws_account_id": account.id,
            "account_number": account.account_number, "account_name": account.name,
            "real_aws_account_id": account.aws_account_id,
            "config_hash": configuration_signature(db, account), "active": account.active,
            "deleted_at": account.deleted_at, "bound": bool(db.get(Binding, (actor.id, account.id))),
            "quantity": row.quantity, "plan": fields(plan), "group": fields(group),
            "grant": fields(grant), "members": members,
            "stop_policy": policy.model_dump(mode="json"), "policy_change": policy_change,
            "needed_count": row.quantity + (len(members) if not grant else 0),
            "exports": row.exports.model_dump(by_alias=True), "group_mode": row.group.mode,
            "subscription_order": "grant_first" if grant else "members_first"}
        snapshots.append(snapshot)
        frozen = SimpleNamespace(**{key: getattr(account, key) for key in aws_reports.ACCOUNT_FIELDS},
                                 _proxy_selection=selection)
        remote_inputs.append((frozen, snapshot))
    counts = Counter()
    for row in snapshots:
        counts[row["plan"]["id"]] += row["needed_count"]
    totals, counters = [], []
    for plan_id, needed in sorted(counts.items()):
        counter = db.scalar(select(PlanCounter).where(PlanCounter.user_id == actor.id, PlanCounter.plan_id == plan_id))
        available = counter.limit_count - counter.used_count - counter.pending_count if counter else 0
        if actor.role != "admin" and available < needed:
            raise HTTPException(409, "所选账号合计需要的套餐开通次数不足")
        plan = next(row["plan"] for row in snapshots if row["plan"]["id"] == plan_id)
        price = BY_SUBSCRIPTION_TYPE[plan["subscription_type"]]["monthly_price_usd"]
        totals.append({"plan_id": plan_id, "plan_name": plan["name"], "needed_count": needed,
                       "available_count": available if actor.role != "admin" else None,
                       "reference_monthly_usd": price * needed})
        counters.append(fields(counter))
    return {"actor": actor_identity(actor), "accounts": snapshots, "counters": counters, "totals": totals}, remote_inputs


def remote_preflight(account, snapshot):
    if snapshot["group_mode"] == "new":
        identity = aws.AwsGateway(account).verify()
        if identity != account.aws_account_id:
            raise HTTPException(409, "AWS 密钥所属账号与配置不一致")
        return {"aws_account_id": identity}
    group = snapshot["group"]
    mapped = {member["sso_user_id"]: {"id": member["id"], **member} for member in snapshot["members"]}
    result = group_observations.observe(account, group, mapped)
    directory, subscription = result["directory"], result["subscription"]
    expected = {(m["id"], m["sso_user_id"], m["membership_id"]) for m in snapshot["members"]}
    observed = {(m["record_id"], m["sso_user_id"], m["membership_id"]) for m in directory["owned_members"]}
    if not directory["exists"] or directory["member_count"] != len(expected) or observed != expected:
        raise HTTPException(409, "AWS 分组成员与本地快照不一致，或包含未管理成员")
    canonical_type = aws.ALIASES.get(subscription["subscription_type"], subscription["subscription_type"])
    if subscription["status"] != "Not subscribed" and canonical_type not in BY_SUBSCRIPTION_TYPE:
        raise HTTPException(409, "AWS GROUP 订阅套餐未知，请先核对")
    if subscription["pending_subscription_type"] or (subscription["status"] == "Canceled" and subscription["access_active"]):
        raise HTTPException(409, "AWS 分组正在变更或取消订阅，请先核对")
    if snapshot["grant"]:
        if subscription["status"] != "Subscribed" or not subscription["access_active"] or canonical_type != snapshot["plan"]["subscription_type"]:
            raise HTTPException(409, "AWS GROUP 订阅未知、缺失或套餐不兼容，请先核对")
    elif subscription["status"] not in ("Not subscribed", "Canceled") or subscription["access_active"]:
        raise HTTPException(409, "AWS 分组已有未受管理的 GROUP 订阅，请先核对")
    return {"directory": {"exists": True, "name": directory["name"], "members": sorted(observed)},
            "subscription": {**subscription, "subscription_type": canonical_type}}


def replay(db, actor, body, payload_hash):
    old = db.scalar(select(ProvisioningBatch).where(ProvisioningBatch.actor_id == actor.id,
                                                  ProvisioningBatch.request_key == body.request_key))
    if old:
        if old.payload_hash != payload_hash:
            raise HTTPException(409, "重复请求标识与原批次内容不符")
        require_view_scope(db, old, actor)
    return old


def preflight(db, actor, body, payload_hash=None):
    expected = actor_identity(actor)
    actor = require_actor(db, actor.id, expected)
    before, inputs = prepare(db, actor, body)
    # get_user may already hold SQLite's writer. Nothing from the read-only
    # preparation needs committing. Detached inputs survive rollback unchanged.
    db.rollback()
    remote, failure = [], None
    try:
        remote = [remote_preflight(account, snapshot) for account, snapshot in inputs]
    except (aws.AwsFailure, BotoCoreError, ClientError, HTTPException, ProxyUnavailable) as exc:
        failure = exc
    # Refresh every identity-map row only after acquiring the short write lock.
    db.rollback()
    db.execute(text("BEGIN IMMEDIATE"))
    db.expire_all()
    current = require_actor(db, expected["id"], expected)
    if payload_hash is not None:
        old = replay(db, current, body, payload_hash)
        if old:
            return current, None, None, old
    after, _ = prepare(db, current, body)
    if digest(before) != digest(after):
        raise HTTPException(409, "预检期间账号、代理、成员、权限或规则已变化，请重新预览")
    if failure:
        if isinstance(failure, HTTPException):
            raise failure
        if isinstance(failure, ProxyUnavailable):
            raise HTTPException(409, "请先绑定可用代理") from None
        raise aws_reports.remote_failure(failure)
    fingerprint = digest({"intent": normalized_intent(body), "local": after, "remote": remote})
    for row, observation in zip(after["accounts"], remote):
        row["remote"] = observation
    return current, after, fingerprint, None


def preview_row(row, next_number):
    group = row["group"]
    return {"position": row["position"], "aws_account_id": row["aws_account_id"],
        "account_number": row["account_number"], "account_name": row["account_name"],
        "real_aws_account_id": row["real_aws_account_id"], "next_batch_number": next_number,
        "quantity": row["quantity"], "plan_id": row["plan"]["id"], "plan_name": row["plan"]["name"],
        "group": {"mode": row["group_mode"], "id": group["id"] if group else None,
                  "name": group["name"] if group else next_number,
                  "revision": group["revision"] if group else None,
                  "policy_revision": group["policy_revision"] if group else 0},
        "stop_policy": row["stop_policy"], "policy_change": row["policy_change"],
        "existing_member_count": len(row["members"]), "needed_count": row["needed_count"],
        "exports": row["exports"]}


@router.post("/preview")
def preview(body: PreviewInput, response: Response, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    _, snapshot, fingerprint, _ = preflight(db, actor, body)
    rows = []
    for row in snapshot["accounts"]:
        counter = db.get(ProvisioningCounter, row["aws_account_id"])
        next_number = f'{row["account_number"]}-{(counter.last_sequence if counter else 0) + 1:02d}'
        rows.append(preview_row(row, next_number))
    db.rollback()
    return {"preview_fingerprint": fingerprint, "accounts": rows, "totals": snapshot["totals"],
            "number_is_estimate": True}


@router.post("", status_code=202)
def admit(body: AdmissionInput, request: Request, response: Response,
          actor: User = Depends(get_user), db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    intent = normalized_intent(body)
    payload_hash = digest(intent)
    old = replay(db, actor, body, payload_hash)
    if old:
        return batch_view(db, old, actor=actor)
    actor, snapshot, fingerprint, old = preflight(db, actor, body, payload_hash)
    if old:
        return batch_view(db, old, actor=actor)
    if fingerprint != body.preview_fingerprint:
        raise HTTPException(409, "预览已失效，请重新预览后提交")
    batch = ProvisioningBatch(id=str(uuid.uuid4()), actor_id=actor.id, actor_role=actor.role,
        session_version=actor.session_version, request_key=body.request_key,
        payload_hash=payload_hash, intent=dumps(intent), preview_fingerprint=fingerprint,
        totals=dumps(snapshot["totals"]))
    db.add(batch)
    db.flush()
    for row in snapshot["accounts"]:
        account = db.get(AwsAccount, row["aws_account_id"])
        claim_number(db, account, row["account_number"])
        counter = db.get(ProvisioningCounter, account.id)
        if not counter:
            counter = ProvisioningCounter(aws_account_id=account.id, last_sequence=0)
            db.add(counter)
        counter.last_sequence += 1
        number = f'{row["account_number"]}-{counter.last_sequence:02d}'
        group = row["group"]
        child = ProvisioningAccountBatch(id=str(uuid.uuid4()), batch_id=batch.id, position=row["position"],
            aws_account_id=account.id, account_number=row["account_number"], sequence=counter.last_sequence,
            batch_number=number, config_hash=row["config_hash"], quantity=row["quantity"],
            plan_id=row["plan"]["id"], plan_name=row["plan"]["name"], subscription_type=row["plan"]["subscription_type"],
            group_mode=row["group_mode"], group_id=group["id"] if group else None,
            group_name=group["name"] if group else number, stop_policy=dumps(row["stop_policy"]),
            exports=dumps(row["exports"]), snapshot=dumps(row), needed_count=row["needed_count"])
        db.add(child)
        db.flush()
        usernames = [f"{number}-{position:02d}" for position in range(1, row["quantity"] + 1)]
        if db.scalar(select(Subscription.id).where(
                Subscription.aws_account_id == account.id,
                Subscription.username.in_(usernames)).limit(1)):
            raise HTTPException(409, "批次编号包含已使用的用户名，请核对现有用户并调整 AWS 编号")
        for position in range(1, row["quantity"] + 1):
            username = f"{number}-{position:02d}"
            db.add(ProvisioningItem(record_id=str(uuid.uuid4()), account_batch_id=child.id, position=position,
                internal_id=username, username=username, email=generated_email(username)))
    audit(db, actor, "admit_provisioning_batch", f"受理批次开通意图 {batch.id}，{len(snapshot['accounts'])} 个 AWS 账号", request=request)
    db.commit()
    return batch_view(db, batch, actor=actor)


def child_rows(db, batch):
    return list(db.scalars(select(ProvisioningAccountBatch).where(
        ProvisioningAccountBatch.batch_id == batch.id).order_by(ProvisioningAccountBatch.position)))


def require_view_scope(db, batch, actor):
    if actor.role != "admin":
        if batch.actor_id != actor.id:
            raise HTTPException(404, "批次不存在")
        for row in child_rows(db, batch):
            require_account(db, actor, db.get(AwsAccount, row.aws_account_id))


def batch_view(db, batch, detail=True, actor=None):
    from .provisioning_coordinator import allowed_actions
    from .models import Subscription, RecordOperation, AuthBatch, AuthJob, AuthSecret, GroupJob
    from .auth_retry import can_resume
    from .automatic_retries import retry_view
    from .retry_models import AutomaticRetry
    from sqlalchemy import and_, or_

    result = {key: getattr(batch, key) for key in (
        "id", "actor_id", "request_key", "state", "phase", "error", "created_at", "updated_at", "finished_at",
    )} | {"totals": json.loads(batch.totals), "accounts": []}
    children = child_rows(db, batch)
    item_rows = list(db.scalars(select(ProvisioningItem).where(
        ProvisioningItem.account_batch_id.in_([c.id for c in children])).order_by(ProvisioningItem.position)))
    # Subqueries keep even 100 x 100 record parents below SQLite bind limits.
    record_ids = select(ProvisioningItem.record_id).join(ProvisioningAccountBatch).where(
        ProvisioningAccountBatch.batch_id == batch.id)
    records = {r.id: r for r in db.scalars(select(Subscription).where(Subscription.id.in_(record_ids)))} if detail else {}
    auth_ids = select(ProvisioningItem.auth_job_id).join(ProvisioningAccountBatch).where(
        ProvisioningAccountBatch.batch_id == batch.id)
    auth_ops = {o.id: o for o in db.scalars(select(RecordOperation).where(RecordOperation.id.in_(auth_ids)))}
    auth_jobs = {j.id: j for j in db.scalars(select(AuthJob).where(AuthJob.id.in_(auth_ids)))}
    auth_secrets = {s.job_id: s for s in db.scalars(select(AuthSecret).join(
        RecordOperation, RecordOperation.id == AuthSecret.job_id).where(
        AuthSecret.job_id.in_(auth_ids), RecordOperation.state.in_(('challenge', 'failed', 'needs_review'))))
    } if detail and actor and batch.actor_id == actor.id else {}
    auth_batch_ids = select(ProvisioningItem.auth_batch_id).join(ProvisioningAccountBatch).where(
        ProvisioningAccountBatch.batch_id == batch.id)
    auth_batches = {b.id: b for b in db.scalars(select(AuthBatch).where(AuthBatch.id.in_(auth_batch_ids)))}
    groups = {g.id: g for g in db.scalars(select(ManagedGroup).where(
        ManagedGroup.id.in_([c.group_id for c in children if c.group_id])))}
    group_jobs = {j.id: j for j in db.scalars(select(GroupJob).where(
        GroupJob.id.in_([c.group_job_id for c in children if c.group_job_id])))}
    native_ops = {o.id: o for o in db.scalars(select(NativeGroupOperation).where(
        NativeGroupOperation.id.in_([c.native_operation_id for c in children if c.native_operation_id])))}
    grants = {g.id: g for g in db.scalars(select(NativeGroupGrant).where(
        NativeGroupGrant.id.in_([c.native_grant_id for c in children if c.native_grant_id])))}
    retry_rows = {(r.family, r.job_id): r for r in db.scalars(select(AutomaticRetry).where(or_(
        and_(AutomaticRetry.family == 'sso', AutomaticRetry.job_id.in_(record_ids)),
        and_(AutomaticRetry.family == 'auth', AutomaticRetry.job_id.in_(auth_ids)),
        and_(AutomaticRetry.family == 'group', AutomaticRetry.job_id.in_(select(
            ProvisioningAccountBatch.group_job_id).where(ProvisioningAccountBatch.batch_id == batch.id))),
        and_(AutomaticRetry.family == 'native', AutomaticRetry.job_id.in_(select(
            ProvisioningAccountBatch.native_operation_id).where(ProvisioningAccountBatch.batch_id == batch.id))),
    )))}
    grouped_items = {}
    for item in item_rows:
        grouped_items.setdefault(item.account_batch_id, []).append(item)
    private_auth = actor is not None and actor.id == batch.actor_id
    for child in children:
        snapshot = json.loads(child.snapshot)
        row = preview_row(snapshot, child.batch_number)
        row["account_deleted_at"] = db.get(AwsAccount, child.aws_account_id).deleted_at
        row.pop("next_batch_number")
        row["group"].update(id=child.group_id, name=child.group_name)
        row.update({key: getattr(child, key) for key in (
            "id", "batch_number", "sequence", "state", "phase", "error", "group_job_id",
            "native_operation_id", "native_grant_id", "policy_applied_revision", "stop_requested_at",
            "created_at", "updated_at", "finished_at",
        )})
        from .provisioning_resume import resume_needed
        row['allowed_actions'] = allowed_actions(child, export_retry=private_auth and any(
            i.export_error for i in grouped_items.get(child.id, [])),
            resumable=resume_needed(child, grouped_items.get(child.id, [])),
            failed_items=any(i.state == 'failed' for i in grouped_items.get(child.id, [])))
        grant = grants.get(child.native_grant_id)
        row['group_subscription_state'] = grant.state if grant else None
        row['activated_at'] = grant.activated_at if grant else None
        row['effective_stop_at'] = grant.stop_at if grant else None
        group = groups.get(child.group_id)
        row['effective_policy'] = ({'mode': group.policy_mode, 'days': group.policy_days,
            'stop_at': group.policy_stop_at, 'revision': group.policy_revision} if group else None)
        row['group_job_state'] = group_jobs[child.group_job_id].state if child.group_job_id in group_jobs else None
        row['native_operation_state'] = native_ops[child.native_operation_id].state if child.native_operation_id in native_ops else None
        if child.native_operation_id:
            row.update(retry_view(db, 'native', child.native_operation_id, active=row['native_operation_state'] in ('queued', 'running'), rows=retry_rows, state=row['native_operation_state']))
        elif child.group_job_id:
            row.update(retry_view(db, 'group', child.group_job_id, active=row['group_job_state'] in ('queued', 'running'), rows=retry_rows, state=row['group_job_state']))
        row['recovery'] = None
        if row['group_job_state'] in ('failed', 'needs_review'):
            row['recovery'] = {'kind': 'group_retry', 'method': 'POST',
                'path': f'/api/groups/{child.group_id}/retry',
                'read_only': group_jobs[child.group_job_id].phase == 'pending'}
        elif row['native_operation_state'] == 'needs_review':
            row['recovery'] = {'kind': 'native_recheck', 'method': 'POST',
                'path': f'/api/group-subscriptions/{child.native_operation_id}/recheck', 'read_only': True}
        export_states = Counter()
        for item in grouped_items.get(child.id, []):
            auth, auth_batch = auth_ops.get(item.auth_job_id), auth_batches.get(item.auth_batch_id)
            state = (auth_batch.state if auth_batch and auth_batch.state != 'active' else
                auth.state if auth else 'blocked' if item.export_error else
                'waiting' if snapshot['exports']['json'] else 'not_requested')
            export_states[state] += 1
        row['export_states'] = dict(export_states)
        row['export_state'] = (next(iter(export_states)) if len(export_states) == 1 else 'partial')
        if detail:
            row['items'] = []
            for item in grouped_items.get(child.id, []):
                view = {key: getattr(item, key) for key in (
                    'record_id', 'position', 'internal_id', 'username', 'email', 'state', 'phase', 'error',
                    'sso_batch_id', 'created_at', 'updated_at', 'finished_at')}
                record, auth = records.get(item.record_id), auth_ops.get(item.auth_job_id)
                view.update(retry_view(db, 'sso', item.record_id, active=bool(record and record.state in ('queued', 'running')), rows=retry_rows, state=record.state if record else None))
                auth_batch, auth_job = auth_batches.get(item.auth_batch_id), auth_jobs.get(item.auth_job_id)
                recovery = None
                if record and record.state in ('failed', 'needs_review'):
                    if record.step == 'password_pending':
                        recovery = {'kind': 'reset_password', 'method': 'POST',
                            'path': f'/api/subscriptions/{record.id}/operations',
                            'body': {'kind': 'reset_password', 'confirm_username': record.username},
                            'requires_request_key': True, 'read_only': False}
                    elif not child.stop_requested_at or (record.state == 'needs_review' and record.step.endswith('_pending')):
                        recovery = {'kind': 'sso_retry', 'method': 'POST',
                            'path': f'/api/subscriptions/{record.id}/retry',
                            'read_only': record.state == 'needs_review' and record.step.endswith('_pending')}
                    if recovery and row['recovery'] is None:
                        row['recovery'] = recovery
                view['recovery'] = recovery
                view.update(record_state=record.state if record else None, record_step=record.step if record else None,
                    credentials_ready=bool(record and record.password_encrypted and record.credential_state != 'unknown'),
                    subscribed_at=record.subscribed_at if record else None,
                    auth_batch_id=item.auth_batch_id if private_auth else None,
                    auth_job_id=item.auth_job_id if private_auth else None,
                    export_stage=auth_job.stage if private_auth and auth_job else None,
                    export_state=auth_batch.state if auth_batch and auth_batch.state != 'active' else auth.state if auth else ('blocked' if item.export_error else
                        ('waiting' if snapshot['exports']['json'] else 'not_requested')),
                    export_error=(item.export_error or (auth.error if auth else None)) if private_auth else None)
                if private_auth and auth_job:
                    view['export_retry'] = retry_view(db, 'auth', auth_job.id, active=bool(auth and auth.state in ('queued', 'running', 'polling')), rows=retry_rows, state=auth.state if auth else None)
                    if (auth_batch and auth_batch.state == 'active' and auth_batch.expires_at > now()
                            and (not auth_batch.download_expires_at or auth_batch.download_expires_at > now())
                            and can_resume(auth_job, auth, record, auth_secrets.get(auth_job.id))):
                        view['export_recovery'] = {'kind': 'auth_retry', 'method': 'POST',
                            'path': f'/api/auth-batches/{auth_batch.id}/items/{item.record_id}/retry',
                            'body': {'mode': 'resume'}, 'read_only': False}
                row['items'].append(view)
        if private_auth:
            from .provisioning_exports import download_summary
            row['json_download'] = download_summary([child], grouped_items.get(child.id, []), auth_batches, auth_ops)
        result['accounts'].append(row)
    if private_auth:
        from .provisioning_exports import download_summary
        result['json_download'] = download_summary(children, item_rows, auth_batches, auth_ops)
    return result


def matching_account_query(aws_account_id=None, q=""):
    """Match account and fuzzy search together within one account batch."""
    query = (select(ProvisioningAccountBatch.id)
             .join(ProvisioningBatch, ProvisioningBatch.id == ProvisioningAccountBatch.batch_id)
             .correlate(None))
    if aws_account_id is not None:
        query = query.where(ProvisioningAccountBatch.aws_account_id == aws_account_id)
    if q.strip():
        match = "%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        item_match = select(ProvisioningItem.record_id).where(
            ProvisioningItem.account_batch_id == ProvisioningAccountBatch.id,
            or_(ProvisioningItem.internal_id.ilike(match, escape="\\"),
                ProvisioningItem.username.ilike(match, escape="\\"),
                ProvisioningItem.email.ilike(match, escape="\\"))).correlate(ProvisioningAccountBatch).exists()
        query = query.where(or_(ProvisioningBatch.id.contains(q.strip(), autoescape=True),
            ProvisioningAccountBatch.batch_number.ilike(match, escape="\\"),
            ProvisioningAccountBatch.group_name.ilike(match, escape="\\"), item_match))
    return query


def visible_query(actor, aws_account_id=None, q="", state=None, created_from=None, created_to=None):
    query = select(ProvisioningBatch)
    if actor.role != "admin":
        allowed = select(AwsAccount.id).join(Binding).where(Binding.user_id == actor.id,
            AwsAccount.active.is_(True), AwsAccount.deleted_at.is_(None))
        forbidden = select(ProvisioningAccountBatch.id).where(
            ProvisioningAccountBatch.batch_id == ProvisioningBatch.id,
            ~ProvisioningAccountBatch.aws_account_id.in_(allowed)).exists()
        query = query.where(ProvisioningBatch.actor_id == actor.id, ~forbidden)
    if aws_account_id is not None or q.strip():
        query = query.where(ProvisioningBatch.id.in_(
            matching_account_query(aws_account_id, q).with_only_columns(ProvisioningAccountBatch.batch_id)))
    if state:
        query = query.where(ProvisioningBatch.state == state)
    if created_from:
        query = query.where(ProvisioningBatch.created_at >= created_from)
    if created_to:
        query = query.where(ProvisioningBatch.created_at <= created_to)
    return query


@router.get("")
def listing(response: Response, aws_account_id: int | None = None, q: str = "", state: str | None = None,
            created_from: datetime | None = None, created_to: datetime | None = None,
            page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
            actor: User = Depends(get_user), db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    query = visible_query(actor, aws_account_id, q, state, created_from, created_to)
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    batches = db.scalars(query.order_by(ProvisioningBatch.created_at.desc(), ProvisioningBatch.id)
                         .offset((page - 1) * page_size).limit(page_size))
    return {"items": [batch_view(db, batch, detail=False, actor=actor) for batch in batches], "total": total,
            "page": page, "page_size": page_size}


@router.get("/{batch_id}")
def detail(batch_id: str, response: Response, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    batch = db.get(ProvisioningBatch, batch_id)
    if not batch:
        raise HTTPException(404, "批次不存在")
    require_view_scope(db, batch, actor)
    return batch_view(db, batch, actor=actor)


def live_intent(db, *, actor_id=None, account_id=None, group_id=None, plan_id=None, account_ids=None):
    """Shared fence for real deletion/ownership boundaries, under their write lock."""
    live = ProvisioningAccountBatch.state.in_(LIVE_STATES)
    # Resource fences follow the matching child; a live sibling cannot hold a
    # terminal child's resources. Actor-wide fences also retain the parent.
    if account_id is None and account_ids is None and group_id is None and plan_id is None:
        live = or_(ProvisioningBatch.state.in_(LIVE_STATES), live)
    query = select(ProvisioningBatch.id).join(ProvisioningAccountBatch).where(live)
    if actor_id is not None:
        query = query.where(ProvisioningBatch.actor_id == actor_id)
    if account_id is not None:
        query = query.where(ProvisioningAccountBatch.aws_account_id == account_id)
    if account_ids is not None:
        query = query.where(ProvisioningAccountBatch.aws_account_id.in_(account_ids))
    if group_id is not None:
        query = query.where(ProvisioningAccountBatch.group_id == group_id)
    if plan_id is not None:
        query = query.where(ProvisioningAccountBatch.plan_id == plan_id)
    return db.scalar(query.limit(1))


class ActionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    request_key: str = Field(min_length=16, max_length=80)


@router.post("/{batch_id}/accounts/{account_batch_id}/{action}", status_code=202)
def account_action(batch_id: str, account_batch_id: str, action: Literal['stop', 'retry', 'retry_failed', 'recheck', 'retry_export', 'resume'],
                   body: ActionInput, request: Request, response: Response,
                   actor: User = Depends(get_user), db: Session = Depends(get_db)):
    from .models import ProvisioningAction
    from .provisioning_coordinator import allowed_actions, aggregate, guard, stop_unsent, sync_items, transition, items
    from .provisioning_resume import resume_needed, resume_stopped

    response.headers['Cache-Control'] = 'no-store'
    batch = db.get(ProvisioningBatch, batch_id)
    row = db.get(ProvisioningAccountBatch, account_batch_id)
    if not batch or not row or row.batch_id != batch.id:
        raise HTTPException(404, '批次不存在')
    require_view_scope(db, batch, actor)
    old = db.scalar(select(ProvisioningAction).where(ProvisioningAction.account_batch_id == row.id,
        ProvisioningAction.actor_id == actor.id, ProvisioningAction.request_key == body.request_key))
    if old:
        if old.kind != action:
            raise HTTPException(409, '重复请求标识与原恢复操作不同')
        return batch_view(db, batch, actor=actor)
    export_retry = actor.id == batch.actor_id and any(i.export_error for i in items(db, row))
    if action == 'retry_export' and actor.id != batch.actor_id:
        raise HTTPException(404, '认证批次不存在')
    if action not in allowed_actions(row, export_retry=export_retry,
                                    resumable=resume_needed(row, items(db, row)),
                                    failed_items=any(i.state == 'failed' for i in items(db, row))):
        raise HTTPException(409, '当前状态不允许此操作，请刷新批次')
    if action == 'stop':
        row.stop_requested_at = now()
        sync_items(db, row)
        stop_unsent(db, row)
    elif action == 'resume':
        resume_stopped(db, row)
    elif action == 'retry_failed':
        from .subscription_recovery import queue_retry
        from .batches import update_batch_item
        guard(db, row)
        for item in items(db, row):
            record = db.get(Subscription, item.record_id)
            if item.state == 'failed' and record:
                queue_retry(db, record, actor)
                update_batch_item(db, record, 'queued')
                item.state, item.error, item.updated_at, item.finished_at = 'queued', None, now(), None
        transition(row, row.phase)
    elif action == 'retry_export':
        guard(db, row)
        for item in items(db, row):
            item.export_error = None
        transition(row, 'sso')
    else:
        if action == 'recheck':
            # Only pending child writes are reawakened, preserving their phase.
            # A native worker with a pending intent performs read-only queries.
            guard(db, row, recovering=True)
            from .subscription_recovery import queue_retry
            from .worker import PENDING_STEPS
            from .batches import update_batch_item
            from .models import GroupJob
            op = db.get(NativeGroupOperation, row.native_operation_id) if row.native_operation_id else None
            group = db.get(ManagedGroup, row.group_id) if row.group_id else None
            job = db.get(GroupJob, row.group_job_id) if row.group_job_id else None
            if job and job.state == 'needs_review' and job.phase == 'pending' and group.active_job_id == job.id:
                job.state, job.error = 'queued', None
                group.state, group.error = 'updating', None
            if op and op.state == 'needs_review' and op.phase == 'pending' and group.active_job_id == op.id:
                op.state, op.error = 'queued', None
            for item in items(db, row):
                record = db.get(Subscription, item.record_id)
                if (record and record.state == 'needs_review' and record.step in PENDING_STEPS
                        and record.step != 'password_pending'):
                    queue_retry(db, record, actor)
                    update_batch_item(db, record, 'queued')
                    item.state, item.error = 'queued', None
        if action == 'retry':
            guard(db, row)
            if row.native_operation_id:
                op = db.get(NativeGroupOperation, row.native_operation_id)
                if row.phase == 'group_open' and op.state == 'failed':
                    row.native_request_key = f'numbered:{row.id}:retry:{op.id[:8]}'
                    row.native_operation_id = row.native_grant_id = None
        transition(row, row.phase)
    db.add(ProvisioningAction(id=str(uuid.uuid4()), account_batch_id=row.id, actor_id=actor.id,
        kind=action, request_key=body.request_key))
    aggregate(db, batch)
    audit(db, actor, 'provisioning_' + action, f'编号批次 {row.batch_number}：{action}', request=request)
    db.commit()
    return batch_view(db, batch, actor=actor)
