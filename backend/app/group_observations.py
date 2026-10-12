"""Scoped AWS group observations, independent of local grants and job history."""

from datetime import datetime, timezone
from types import SimpleNamespace

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import aws, aws_reports
from .database import get_db
from .groups import owned_group, scope as directory_scope
from .models import ManagedGroup, Subscription, User
from .proxies import ProxyUnavailable, proxy_selection
from .security import get_user

router = APIRouter(prefix="/api/groups")
GROUP_FIELDS = ("id", "owner_id", "aws_account_id", "aws_scope", "remote_id", "name",
                "revision", "state", "active_job_id", "deleted_at")
MEMBER_FIELDS = ("id", "owner_id", "aws_account_id", "sso_user_id", "username", "email",
                 "group_id", "group_membership_id", "sso_deleted_at")


def local_scope(db, actor, group_id, account):
    group = db.get(ManagedGroup, group_id, populate_existing=True)
    if not group or (actor.role != "admin" and group.owner_id != actor.id):
        raise HTTPException(404, "分组不存在")
    if group.aws_account_id != account.id or group.aws_scope != directory_scope(account) or not group.remote_id:
        raise HTTPException(409, "分组的 AWS 身份目录已变化或尚未就绪，请刷新后重试")
    records = list(db.scalars(select(Subscription).where(
        Subscription.owner_id == group.owner_id, Subscription.aws_account_id == account.id,
        Subscription.sso_user_id.is_not(None), Subscription.sso_deleted_at.is_(None),
    ).order_by(Subscription.id).execution_options(populate_existing=True)))
    members = {r.sso_user_id: {key: getattr(r, key) for key in MEMBER_FIELDS} for r in records}
    if len(members) != len(records):
        raise HTTPException(409, "本地 SSO 映射不唯一，请管理员核对后重试")
    identity = {key: getattr(group, key) for key in GROUP_FIELDS}
    return aws_reports.digest((identity, members)), identity, members


def claim_observation(gateway, account, remote_id):
    matches = []
    for row in gateway.report_claims():
        if aws_reports.principal(row) != ("group", remote_id):
            continue
        if not row.get("applicationArn") or not row.get("createdBy"):
            raise aws.AwsFailure("AWS claims 缺少账号范围信息，请重试")
        if row["applicationArn"] == account.application_arn and row["createdBy"] == account.aws_account_id:
            matches.append(row)
    if len(matches) > 1:
        raise aws.AwsFailure("AWS 分组订阅出现重复记录，请核对后重试")
    result = {"status": "Not subscribed", "subscription_type": None, "plan_label": None,
              "pending_subscription_type": None, "pending_plan_label": None, "effective_at": None,
              "cancellation_expires_at": None, "access_active": False}
    if not matches:
        return result
    claim = matches[0]
    kind, pending = aws_reports.subscription_type(claim), aws_reports.subscription_type(claim, "newType")
    raw_boundary = claim.get("expirationDate")
    if isinstance(raw_boundary, bool):
        raise aws.AwsFailure("AWS 订阅时间格式无法识别，请重试")
    boundary = aws.aws_datetime(raw_boundary)
    canceled = boundary is not None and pending is None
    return {
        "status": "Canceled" if canceled else "Subscribed",
        "subscription_type": kind, "plan_label": aws_reports.plan_label(kind),
        "pending_subscription_type": pending,
        "pending_plan_label": aws_reports.plan_label(pending) if pending else None,
        "effective_at": boundary.isoformat() + "Z" if boundary and pending else None,
        "cancellation_expires_at": boundary.isoformat() + "Z" if canceled else None,
        "access_active": not canceled or boundary > datetime.now(timezone.utc).replace(tzinfo=None),
    }


def observe(account, group, owned_members):
    gateway = aws.AwsGateway(account)
    identity = gateway.get_group(group["remote_id"])
    directory = {"exists": identity is not None, "name": None, "member_count": None, "owned_members": []}
    if identity is not None:
        if (not isinstance(identity, dict) or identity.get("id") != group["remote_id"]
                or not isinstance(identity.get("name"), str) or not identity["name"]):
            raise aws.AwsFailure("AWS 分组身份目录响应异常，请重试")
        members = gateway.list_group_memberships(group["remote_id"])
        if not isinstance(members, list):
            raise aws.AwsFailure("AWS 分组成员响应异常，请重试")
        seen_users, seen_memberships, matched = set(), set(), []
        for member in members:
            if (not isinstance(member, dict) or not isinstance(member.get("id"), str) or not member["id"]
                    or not isinstance(member.get("user_id"), str) or not member["user_id"]
                    or member["id"] in seen_memberships or member["user_id"] in seen_users):
                raise aws.AwsFailure("AWS 分组成员响应不完整或重复，请重试")
            seen_memberships.add(member["id"])
            seen_users.add(member["user_id"])
            local = owned_members.get(member["user_id"])
            if local:
                matched.append({"record_id": local["id"], "sso_user_id": local["sso_user_id"],
                                "username": local["username"], "email": local["email"], "membership_id": member["id"]})
        directory.update(name=identity["name"], member_count=len(members), owned_members=matched)
    return {"group_id": group["id"], "aws_account_id": account.id, "remote_id": group["remote_id"],
            "directory": directory, "subscription": claim_observation(gateway, account, group["remote_id"]),
            "queried_at": aws_reports.utc_now()}


@router.post("/{group_id}/aws-refresh")
def refresh_group(group_id: str, response: Response, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    try:
        group = owned_group(db, group_id, actor)
        scope = aws_reports.begin_scope(db, actor, [group.aws_account_id])
        account = scope.accounts[0]
        signature, identity, members = local_scope(db, actor, group_id, account)
        # Freeze credentials/configuration and proxy selection before releasing the read transaction.
        frozen = SimpleNamespace(**{key: getattr(account, key) for key in aws_reports.ACCOUNT_FIELDS},
                                 _proxy_selection=proxy_selection(db, account.proxy_id))
        db.rollback()
        failure = None
        try:
            result = observe(frozen, identity, members)
        except (aws.AwsFailure, BotoCoreError, ClientError) as exc:
            failure = exc
        current_actor = aws_reports.finish_scope(db, scope)
        current_signature, _, _ = local_scope(db, current_actor, group_id, scope.accounts[0])
        if current_signature != signature:
            raise HTTPException(409, "分组身份、归属或本地 SSO 映射已变化，请重新查询")
        if failure:
            raise aws_reports.remote_failure(failure)
        return result
    except ProxyUnavailable:
        raise HTTPException(409, "账号代理不可用，请管理员检查后重试", headers={"Cache-Control": "no-store"}) from None
    except HTTPException as exc:
        exc.headers = {**(exc.headers or {}), "Cache-Control": "no-store"}
        raise
