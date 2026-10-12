"""Authenticated login downloads; credentials decrypt only on explicit export."""

import csv
import io
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .database import get_db
from .models import AwsAccount, Batch, BatchItem, StopSchedule, Subscription, User, now, ProvisioningItem, ProvisioningAccountBatch
from .provisioning_exports import mappings, owned_scope
from .schedules import LIVE_STATES
from .security import audit, get_user
from .statistics import cancelled_record
from .auth_credentials import known_password
from .lifecycle import allowed

router = APIRouter(prefix="/api")


def record_query(user, q="", owner_id=None, group_id=None, aws_account_id=None):
    query = select(Subscription)
    if user.role != "admin":
        query = query.where(Subscription.owner_id == user.id)
    elif owner_id is not None:
        query = query.where(Subscription.owner_id == owner_id)
    if group_id:
        query = query.where(Subscription.group_id == group_id)
    if aws_account_id is not None:
        query = query.where(Subscription.aws_account_id == aws_account_id)
    if q:
        query = query.where(
            Subscription.username.icontains(q, autoescape=True)
            | Subscription.email.icontains(q, autoescape=True)
            | Subscription.sso_display_name.icontains(q, autoescape=True)
            | Subscription.id.in_(select(ProvisioningItem.record_id).where(ProvisioningItem.internal_id.icontains(q, autoescape=True)))
        )
    return query


def sso_query(user, status="", q="", owner_id=None, group_id=None, aws_account_id=None):
    query = record_query(user, q, owner_id, group_id, aws_account_id).where(
        Subscription.sso_user_id.is_not(None)
    )
    if status == "active":
        query = query.where(Subscription.sso_deleted_at.is_(None))
    elif status == "deleted":
        query = query.where(Subscription.sso_deleted_at.is_not(None))
    elif status == "cancelled":
        query = query.where(cancelled_record())
    elif status in ("scheduled", "schedule_attention"):
        states = (
            LIVE_STATES
            if status == "scheduled"
            else ("blocked", "failed", "needs_review")
        )
        query = query.where(
            Subscription.id.in_(
                select(StopSchedule.record_id).where(StopSchedule.state.in_(states))
            )
        )
    elif status == "unsubscribed":
        query = query.where(
            Subscription.sso_deleted_at.is_(None),
            Subscription.plan_id.is_(None),
            Subscription.provision_only.is_(True),
            Subscription.state == "completed",
            Subscription.active_operation_id.is_(None),
            Subscription.subscription_status == "not_subscribed",
            Subscription.observed_subscription_type.is_(None),
        )
    return query


class ExportInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_ids: list[str] | None = Field(default=None, min_length=1, max_length=1000)
    batch_id: str | None = None
    provisioning_batch_id: str | None = Field(default=None, min_length=1, max_length=36)
    provisioning_account_batch_id: str | None = Field(default=None, min_length=1, max_length=36)
    q: str = Field(default="", max_length=254)
    status: Literal[
        "",
        "all",
        "active",
        "deleted",
        "unsubscribed",
        "cancelled",
        "scheduled",
        "schedule_attention",
    ] = ""
    owner_id: int | None = None
    group_id: str | None = None
    aws_account_id: int | None = None
    format: Literal["csv", "txt"] = "csv"

    @model_validator(mode="after")
    def one_scope(self):
        if sum(value is not None for value in (self.record_ids, self.batch_id, self.provisioning_batch_id, self.provisioning_account_batch_id)) > 1:
            raise ValueError("一次只能选择一个导出范围")
        if self.record_ids and len(set(self.record_ids)) != len(self.record_ids):
            raise ValueError("不能重复选择 SSO 用户")
        return self


def csv_text(value):
    value = "" if value is None else str(value)
    # CSV quoting alone does not prevent spreadsheet formula evaluation.
    if value.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")) or value.startswith(
        ("\t", "\r", "\n")
    ):
        return "'" + value
    return value


def timestamp(value):
    return value.isoformat(timespec="seconds") + "Z" if value else ""


def login_text(record, account, internal_id=None):
    """Keep the same labels and ordering as the UI's credentialText copy action."""
    password_line = "密码状态待核对，请先核对结果"
    if record.credential_state in ("one_time", "permanent"):
        label = "一次性密码" if record.credential_state == "one_time" else "永久密码"
        password_line = f"{label}：{known_password(record)}"
    return (
        (f"内部 ID：{internal_id}\n" if internal_id else "")
        + f"AWS 登录地址：{record.portal_url}\n区域：{account.region}\n"
        f"用户名：{record.username}\n{password_line}"
    )


def csv_content(db, rows, accounts, numbered=None):
    numbered = numbered if numbered is not None else mappings(db, [r.id for r in rows])
    schedules = {
        s.record_id: s
        for s in db.scalars(
            select(StopSchedule).where(StopSchedule.record_id.in_([r.id for r in rows]))
        )
    }
    output = io.StringIO(newline="")
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    writer.writerow(
        [
            "内部 ID",
            "AWS 编号",
            "批次编号",
            "用户名",
            "密码",
            "登录地址",
            "邮箱",
            "姓名",
            "身份中心区域",
            "订阅区域",
            "AWS账号",
            "SSO用户ID",
            "密码生成时间(UTC)",
            "原绑定套餐",
            "订阅状态",
            "订阅时间(UTC)",
            "定时停止时间(UTC)",
            "定时停止状态",
            "密码类型",
        ]
    )
    status_names = {
        "active": "已订阅",
        "not_subscribed": "未订阅",
        "cancelled": "已取消",
        "cancel_scheduled": "已取消续订",
    }
    for r in rows:
        a = accounts[r.aws_account_id]
        number = numbered.get(r.id, {})
        values = [
            number.get("internal_id"), number.get("account_number"), number.get("provisioning_batch_number"),
            r.username,
            known_password(r),
            r.portal_url,
            r.email,
            r.sso_display_name,
            a.region,
            a.subscription_region,
            a.name,
            r.sso_user_id,
            timestamp(r.password_generated_at),
            r.plan_name_snapshot or "未绑定套餐",
            status_names.get(r.subscription_status, "待核对"),
            timestamp(r.subscribed_at),
            timestamp(schedules[r.id].stop_at) if r.id in schedules else "",
            schedules[r.id].state if r.id in schedules else "",
            {"one_time": "一次性密码", "permanent": "永久密码", "unknown": "待核对"}[
                r.credential_state
            ],
        ]
        writer.writerow([csv_text(v) for v in values])
    return "\ufeff" + output.getvalue()


@router.post("/sso-users/export")
def export_sso(
    body: ExportInput,
    request: Request,
    user: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    if body.group_id:
        from .groups import owned_group

        owned_group(db, body.group_id, user)
    if body.record_ids:
        query = select(Subscription).where(Subscription.id.in_(body.record_ids))
        if user.role != "admin":
            query = query.where(Subscription.owner_id == user.id)
        rows = list(
            db.scalars(query.order_by(Subscription.created_at, Subscription.id))
        )
        if len(rows) != len(body.record_ids):
            raise HTTPException(404, "选择的 SSO 用户不存在")
        scoped_ids = set(
            db.scalars(
                sso_query(
                    user,
                    body.status,
                    body.q,
                    body.owner_id,
                    body.group_id,
                    body.aws_account_id,
                )
                .with_only_columns(Subscription.id)
                .where(Subscription.id.in_(body.record_ids))
            )
        )
        if scoped_ids != set(body.record_ids):
            raise HTTPException(
                409, "选择的 SSO 用户已不符合筛选条件，请刷新后重新选择"
            )
        if any(
            not r.sso_user_id
            or r.sso_deleted_at
            or (
                r.credential_state != "unknown"
                and (not r.password_encrypted or r.active_operation_id)
            )
            for r in rows
        ):
            raise HTTPException(
                409, "部分用户已删除、登录信息未就绪或正在更新，请刷新后重新选择"
            )
    else:
        query = sso_query(
            user, body.status, body.q, body.owner_id, body.group_id, body.aws_account_id
        )
        numbered_scope = body.provisioning_batch_id or body.provisioning_account_batch_id
        if numbered_scope:
            parent, child = owned_scope(db, user, body.provisioning_batch_id, body.provisioning_account_batch_id)
            query = query.join(ProvisioningItem, ProvisioningItem.record_id == Subscription.id).join(ProvisioningAccountBatch).where(ProvisioningAccountBatch.batch_id == parent.id)
            if child:
                query = query.where(ProvisioningAccountBatch.id == child.id)
        if body.batch_id:
            batch = db.get(Batch, body.batch_id)
            if not batch or (user.role != "admin" and batch.owner_id != user.id):
                raise HTTPException(404, "批次不存在")
            query = query.where(
                Subscription.id.in_(
                    select(BatchItem.record_id).where(BatchItem.batch_id == batch.id)
                )
            )
        query = query.where(
            Subscription.sso_deleted_at.is_(None),
            or_(
                Subscription.credential_state == "unknown",
                Subscription.password_encrypted.is_not(None),
            ),
            or_(
                Subscription.credential_state == "unknown",
                Subscription.active_operation_id.is_(None),
            ),
        )
        rows = list(
            db.scalars(
                query.order_by(*(
                    (ProvisioningAccountBatch.position, ProvisioningItem.position) if numbered_scope
                    else (Subscription.created_at, Subscription.id))).limit(10001)
            )
        )
        if len(rows) > 10000:
            raise HTTPException(409, "一次最多导出 10000 名用户，请缩小筛选范围")
    if not rows:
        raise HTTPException(
            409, "当前范围没有可导出的登录信息，请等待创建完成或调整筛选条件"
        )
    account_ids = {r.aws_account_id for r in rows}
    accounts = {
        a.id: a
        for a in db.scalars(select(AwsAccount).where(AwsAccount.id.in_(account_ids)))
    }
    if any(not allowed(db, user, accounts[r.aws_account_id]) for r in rows):
        raise HTTPException(403, "AWS 账号或绑定已停用，不能导出登录凭据")
    numbered = mappings(db, [r.id for r in rows])
    content = (
        "\n\n---\n\n".join(login_text(r, accounts[r.aws_account_id], numbered.get(r.id, {}).get("internal_id")) for r in rows)
        if body.format == "txt"
        else csv_content(db, rows, accounts, numbered)
    )
    audit(
        db,
        user,
        "export_credentials",
        f"导出 SSO 登录信息 {body.format.upper()}：{len(rows)} 名用户"
        + (f"；批次 {body.batch_id}" if body.batch_id else ""),
        subject=user.id,
        request=request,
    )
    db.commit()
    filename = f"sso-logins-{now():%Y%m%d-%H%M%S}.{body.format}"
    return Response(
        content=content.encode("utf-8"),
        media_type="text/plain" if body.format == "txt" else "text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Cache-Control": "no-store",
            "X-Export-Count": str(len(rows)),
        },
    )
