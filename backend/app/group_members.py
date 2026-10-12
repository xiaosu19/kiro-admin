"""Shared admission and fresh pre-write guards for owned group members."""

import json
import uuid

from fastapi import HTTPException

from .aws import AwsFailure
from .batches import require_account
from .group_subscription_state import config_hash, detach_payload, live_grant, reserve_join
from .lifecycle import allowed, owned
from .models import AwsAccount, GroupJob, Plan, StopSchedule, Subscription, User, now
from .proxies import ProxyUnavailable, proxy_selection, select_proxy


def group_authorized(db, actor, group, kind):
    account, owner = db.get(AwsAccount, group.aws_account_id), db.get(User, group.owner_id)
    cleanup = actor and actor.role == "admin" and (
        kind in ("detach", "delete") or kind == "rename" and group.remote_id is not None
    )
    return bool(actor and account and allowed(db, actor, account) and (
        cleanup or owner and allowed(db, owner, account)
    ) and (actor.role == "admin" or actor.id == group.owner_id))


def validate_member(db, group, record_id, actor, kind):
    record = owned(db, record_id, actor)
    from .auth_principals import active_external_login
    if active_external_login(db, record):
        raise HTTPException(409, "该用户已有粘贴账号认证任务，请先处理或取消原任务")
    if record.aws_account_id != group.aws_account_id or record.owner_id != group.owner_id:
        raise HTTPException(409, "分组与 SSO 的所有者和 AWS 配置必须一致")
    if (record.active_operation_id or record.reserved or record.state != "completed"
            or not record.sso_user_id or record.sso_deleted_at):
        raise HTTPException(409, "SSO 用户尚未就绪或存在未完成操作")
    if kind == "attach" and record.group_id:
        raise HTTPException(409, "该用户已有管理分组")
    if kind == "detach" and (record.group_id != group.id or not record.group_membership_id):
        raise HTTPException(409, "该用户不是此分组的已确认成员")
    account = db.get(AwsAccount, group.aws_account_id)
    require_account(db, actor, account)
    if not group_authorized(db, actor, group, kind):
        raise HTTPException(409, "分组所有者、操作者或 AWS 绑定已停用")
    select_proxy(db, account.proxy_id)
    grant = live_grant(db, group.id)
    if kind == "attach" and grant:
        plan = db.get(Plan, grant.plan_id)
        schedule = db.get(StopSchedule, record.id)
        if (not plan or not plan.active or plan.deleted_at
                or plan.subscription_type != grant.subscription_type
                or schedule and schedule.mode != "none" and schedule.stop_at and schedule.stop_at <= now()):
            raise HTTPException(409, "原生分组套餐或成员截止时间已变化")
    return record


def frozen_context(db, group, record, actor):
    return {
        "config_hash": config_hash(db, db.get(AwsAccount, group.aws_account_id)),
        "group": [group.id, group.owner_id, group.aws_account_id, group.aws_scope,
                  group.remote_id, group.revision, group.policy_revision],
        "record": [record.id, record.owner_id, record.aws_account_id,
                   record.sso_user_id, group.id, record.group_membership_id],
        "actor_session_version": actor.session_version,
    }


def admit_member(db, group, record, actor, kind, request_key, payload, *, state="queued", request=None):
    """Caller validates the complete selection and owns the admission transaction."""
    job = GroupJob(id=str(uuid.uuid4()), group_id=group.id, actor_id=actor.id,
                   kind=kind, request_key=request_key, record_id=record.id,
                   payload="{}", state=state, phase="ready")
    if kind == "attach":
        reserve_join(db, group, record, actor, job.id)
    extra = detach_payload(db, record) if kind == "detach" else {}
    job.payload = json.dumps(payload | extra | {"member_context": frozen_context(db, group, record, actor)}, sort_keys=True)
    db.add(job)
    record.active_operation_id, record.updated_at = job.id, now()
    if kind == "attach":
        record.group_id = group.id
        from .group_policies import inherit
        inherit(db, record, actor, request)
    return job


def member_context(db, job, group, *, recovering=False, require_group_lock=True):
    """Check persisted scope before dispatch and again immediately before a write."""
    record = db.get(Subscription, job.record_id)
    actor = db.get(User, job.actor_id)
    account = db.get(AwsAccount, group.aws_account_id)
    payload = json.loads(job.payload)
    context = payload.get("member_context")
    if (not record or not account or group.deleted_at or not group.remote_id
            or record.sso_deleted_at or not record.sso_user_id
            or record.active_operation_id != job.id or record.group_id != group.id
            or record.owner_id != group.owner_id or record.aws_account_id != group.aws_account_id
            or require_group_lock and group.active_job_id != job.id):
        raise AwsFailure("成员任务的归属、身份或锁已变化")
    if context:
        current = frozen_context(db, group, record, actor) if actor else None
        if (not current or any(current[k] != context[k] for k in ("config_hash", "group", "record"))):
            raise AwsFailure("分组、成员或冻结的 AWS 配置已变化，请停止未发送项后重新提交")
    try:
        proxy_selection(db, account.proxy_id)
    except ProxyUnavailable as exc:
        raise AwsFailure(str(exc)) from None
    if not recovering and (not group_authorized(db, actor, group, job.kind)
            or context and actor.session_version != context["actor_session_version"]):
        raise AwsFailure("分组所有者、操作者会话或 AWS 绑定已停用或变化")
    return record


def refresh_single_retry(db, job, group, actor):
    """Explicit legacy retry can refresh config, but never change record/group identity."""
    payload = json.loads(job.payload)
    context = payload.get("member_context")
    record = db.get(Subscription, job.record_id)
    if context:
        if not record or record.active_operation_id != job.id or record.group_id != group.id:
            raise HTTPException(409, "成员归属或任务锁已变化")
        current = frozen_context(db, group, record, actor)
        if any(current[k] != context[k] for k in ("group", "record")):
            raise HTTPException(409, "成员归属或分组已变化")
        payload["member_context"] = current
        job.payload = json.dumps(payload, sort_keys=True)
