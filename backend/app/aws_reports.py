"""Read-only AWS console reports and administrator account cost totals."""

import csv
import hashlib
import io
import json
import re
import threading
import time
import unicodedata
import zipfile
from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Literal

from botocore.exceptions import BotoCoreError, ClientError
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import aws
from .aws_bills import current_period, validate_payer
from .catalog import BY_SUBSCRIPTION_TYPE
from .database import get_db
from .models import AwsAccount, Binding, ManagedGroup, Proxy, Subscription, User
from .security import admin, audit, get_user, lock_user_write

router = APIRouter(prefix="/api")
HEADERS = {
    "users": ["Name", "Email", "Kiro plan", "Downgraded to"],
    "groups": ["Group name", "Subscription status", "Kiro plan", "Downgraded to"],
    "subscriptions": ["Name", "Email", "Subscription status", "Kiro plan", "Plan source", "Activation date"],
}
ACCOUNT_FIELDS = (
    "id", "name", "aws_account_id", "region", "subscription_region", "control_plane",
    "identity_store_id", "instance_arn", "application_arn", "profile_arn", "portal_url",
    "credentials_encrypted", "proxy_id", "active", "deleted_at",
)


class ReportInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    view: Literal["users", "groups", "subscriptions"]
    account_ids: list[int] = Field(min_length=1, max_length=100)
    q: str = Field(default="", max_length=254)
    row_ids: list[str] | None = Field(default=None, min_length=1, max_length=100_000)

    @model_validator(mode="after")
    def unique_ids(self):
        if any(i <= 0 for i in self.account_ids) or len(set(self.account_ids)) != len(self.account_ids):
            raise ValueError("请选择不重复的有效 AWS 账号")
        if self.row_ids is not None and (len(set(self.row_ids)) != len(self.row_ids)
                                         or any(len(i) > 100 for i in self.row_ids)):
            raise ValueError("报表行选择无效")
        return self


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()


@dataclass
class Scope:
    actor_id: int
    session_version: int
    role: str
    accounts: list
    fingerprints: dict
    users: dict
    groups: dict

    def signature(self):
        return digest((self.actor_id, self.session_version, self.role, self.fingerprints,
                       {k: sorted(v) for k, v in self.users.items()},
                       {k: sorted(v) for k, v in self.groups.items()}))


def read_scope(db, actor_id, account_ids, billing=False):
    actor = db.get(User, actor_id, populate_existing=True)
    if not actor or not actor.active or actor.deleted_at or actor.must_change_password:
        raise HTTPException(401, "登录权限已变更，请重新登录")
    if billing and actor.role != "admin":
        raise HTTPException(403, "需要管理员权限")
    accounts, fingerprints, users, groups = [], {}, {}, {}
    for account_id in sorted(account_ids):
        account = db.get(AwsAccount, account_id, populate_existing=True)
        if not account or account.deleted_at or (actor.role != "admin" and not account.active):
            raise HTTPException(403, "所选 AWS 账号不可用，请刷新账号范围")
        if actor.role != "admin" and not db.get(Binding, (actor_id, account_id), populate_existing=True):
            raise HTTPException(403, "所选 AWS 账号未绑定当前用户")
        proxy_data = None
        if account.proxy_id is not None:
            proxy = db.get(Proxy, account.proxy_id, populate_existing=True)
            if not proxy or not proxy.enabled:
                raise HTTPException(409, "账号代理不可用，请管理员检查代理后重试")
            proxy_data = tuple(getattr(proxy, k) for k in
                               ("id", "revision", "enabled", "host", "port", "auth_encrypted"))
        fingerprints[account_id] = digest((tuple(getattr(account, k) for k in ACCOUNT_FIELDS), proxy_data))
        accounts.append(account)
        if actor.role != "admin":
            users[account_id] = set(db.scalars(select(Subscription.sso_user_id).where(
                Subscription.aws_account_id == account_id, Subscription.owner_id == actor_id,
                Subscription.sso_user_id.is_not(None),
            )))
            groups[account_id] = set(db.scalars(select(ManagedGroup.remote_id).where(
                ManagedGroup.aws_account_id == account_id, ManagedGroup.owner_id == actor_id,
                ManagedGroup.aws_scope == f"{account.aws_account_id}:{account.identity_store_id}",
                ManagedGroup.remote_id.is_not(None),
            )))
    return Scope(actor.id, actor.session_version, actor.role, accounts, fingerprints, users, groups)


def begin_scope(db, actor, account_ids, billing=False):
    expected_session, expected_role = actor.session_version, actor.role
    scope = read_scope(db, actor.id, account_ids, billing)
    if (scope.session_version, scope.role) != (expected_session, expected_role):
        raise HTTPException(409, "用户权限已变化，请刷新后重试")
    # POST authentication takes a short admission lock. Never hold it over AWS IO.
    db.commit()
    return scope


def finish_scope(db, scope, billing=False):
    db.rollback()
    db.expire_all()
    actor = db.get(User, scope.actor_id)
    if not actor:
        raise HTTPException(401, "登录权限已变更，请重新登录")
    # Serialize final disclosure with role, binding and configuration mutations.
    lock_user_write(db, actor, scope.session_version)
    current = read_scope(db, scope.actor_id, [a.id for a in scope.accounts], billing)
    if current.signature() != scope.signature():
        raise HTTPException(409, "权限、账号或代理配置已变化，请重新查询")
    return actor


def text_value(value, fallback="-"):
    if value is None or value == "":
        return fallback
    if not isinstance(value, str):
        raise aws.AwsFailure("AWS 报表字段格式异常，请重试")
    return value


def plan_label(kind):
    kind = text_value(kind)
    normalized = aws.ALIASES.get(kind, kind)
    if normalized in BY_SUBSCRIPTION_TYPE:
        return BY_SUBSCRIPTION_TYPE[normalized]["name"]
    return {"Q_DEVELOPER_STANDALONE_FREE": "Kiro Free", "KIRO_ENTERPRISE_FREE": "Kiro Free",
            "Q_DEVELOPER_STANDALONE": "Amazon Q Developer Pro", "KIRO_POOLING_SEAT": "Kiro Credit Sharing",
            "KIRO_POOLING_SEAT_PREPAID": "Kiro Credit Sharing"}.get(kind, kind)


def principal(row):
    value = row.get("principal")
    if not isinstance(value, dict):
        raise aws.AwsFailure("AWS 报表主体格式异常，请重试")
    found = [(key, value[key]) for key in ("user", "group") if value.get(key)]
    if len(found) != 1 or not isinstance(found[0][1], str):
        raise aws.AwsFailure("AWS 报表主体格式异常，请重试")
    return found[0]


def subscription_type(row, key="type"):
    value = row.get(key)
    if key == "newType" and (value is None or (isinstance(value, dict) and not value.get("amazonQ"))):
        return None
    if not isinstance(value, dict) or not isinstance(value.get("amazonQ"), str):
        raise aws.AwsFailure("AWS 报表套餐格式异常，请重试")
    return value["amazonQ"]


def activation_date(value):
    if value is None:
        return "-"
    if isinstance(value, bool):
        raise aws.AwsFailure("AWS 激活日期格式异常，请重试")
    return aws.aws_datetime(value).strftime("%Y-%m-%d %H:%M:%S UTC")


def account_rows(account, scope, view):
    gateway = aws.AwsGateway(account)
    try:
        return _account_rows(gateway, account, scope, view)
    finally:
        close = getattr(gateway, "close", None)
        if close:
            close()


def _account_rows(gateway, account, scope, view):
    is_group = view == "groups"
    allowed = None if scope.role == "admin" else (scope.groups if is_group else scope.users)[account.id]
    raw = gateway.report_subscriptions() if view == "subscriptions" else gateway.report_claims()
    relevant = []
    for row in raw:
        kind, remote_id = principal(row)
        if kind != ("group" if is_group else "user") or (allowed is not None and remote_id not in allowed):
            continue
        if view != "subscriptions":
            if not row.get("applicationArn") or not row.get("createdBy"):
                raise aws.AwsFailure("AWS claims 缺少账号范围信息，请重试")
            if row["applicationArn"] != account.application_arn or row["createdBy"] != account.aws_account_id:
                continue
        # The console's Users view excludes canceled claims; a scheduled
        # downgrade retains newType.amazonQ and remains visible.
        if view == "users" and row.get("expirationDate") and not subscription_type(row, "newType"):
            continue
        relevant.append((remote_id, row))
    # Apply exact authorized IDs before accessing directory names or emails.
    ids = {rid for rid, _ in relevant}
    directory = gateway.report_groups() if is_group else gateway.report_users()
    current = {}
    for entry in directory:
        rid = entry.get("GroupId" if is_group else "UserId")
        if not isinstance(rid, str) or not rid:
            raise aws.AwsFailure("AWS 身份目录格式异常，请重试")
        if rid not in ids:
            continue
        if rid in current:
            raise aws.AwsFailure("AWS 身份目录出现重复主体，请重试")
        current[rid] = entry
    rows, seen = [], set()
    for remote_id, raw_row in relevant:
        identity = current.get(remote_id, {})
        name = text_value(identity.get("DisplayName" if is_group else "UserName"), remote_id)
        plan = plan_label(subscription_type(raw_row))
        if is_group:
            new_type = subscription_type(raw_row, "newType")
            status = "Canceled" if raw_row.get("expirationDate") and not new_type else "Subscribed"
            values = [name, status, plan, plan_label(new_type)]
        else:
            emails = identity.get("Emails", [])
            if not isinstance(emails, list) or any(not isinstance(e, dict) for e in emails):
                raise aws.AwsFailure("AWS 身份目录邮箱格式异常，请重试")
            email = text_value(emails[0].get("Value") if emails else None)
            if view == "users":
                values = [name, email, plan, plan_label(subscription_type(raw_row, "newType"))]
            else:
                status = text_value(raw_row.get("status"))
                status = {"ACTIVE": "Active", "PENDING": "Pending", "CANCELED": "Canceled",
                          "CANCELLED": "Canceled", "PENDING_REMOVAL": "Pending removal",
                          "FREE_TRIAL": "Free trial", "UNAVAILABLE": "Unavailable"}.get(status.upper(), status)
                source = text_value(raw_row.get("aggregatedSubscriptionType"))
                source = {"INDIVIDUAL": "Individual", "GROUP": "Group",
                          "INDIVIDUAL_AND_GROUP": "Individual + Group"}.get(source, source)
                values = [name, email, status, plan, source, activation_date(raw_row.get("activationDate"))]
        # Selection identifies a principal, not its mutable plan/status. A live
        # AWS update between preview and download must not invalidate that row.
        row_id = f"{account.id}-{digest((view, remote_id))}"
        if row_id in seen:
            raise aws.AwsFailure("AWS 报表出现重复行，请重新查询")
        seen.add(row_id)
        rows.append({"id": row_id, "account_id": account.id, "account_name": account.name, "values": values})
    return rows


def remote_failure(exc, billing=False):
    # AWS error messages may echo request data; expose only known error classes.
    if isinstance(exc, aws.AwsFailure):
        message = str(exc)
    else:
        message = "AWS 读取失败，请检查账号、区域、代理和服务权限后重试"
    if billing:
        message = "费用暂不可用：" + message + "；请检查 sts:GetFederationToken、账单读取权限及 Billing IAM 访问设置"
    return HTTPException(502, message, headers={"Cache-Control": "no-store"})


def collect(db, actor, body):
    scope = begin_scope(db, actor, body.account_ids)
    try:
        # Only immutable account snapshots enter threads. Never share the request
        # DB session; final disclosure still revalidates every scoped permission.
        from types import SimpleNamespace
        accounts = [SimpleNamespace(**{key: getattr(a, key) for key in ACCOUNT_FIELDS}) for a in scope.accounts]
        def read(account):
            try:
                return account_rows(account, scope, body.view)
            except (aws.AwsFailure, ClientError, BotoCoreError) as exc:
                failure = remote_failure(exc)
                raise HTTPException(failure.status_code, f"AWS 账号 #{account.id}：{failure.detail}", headers=failure.headers) from None
        with ThreadPoolExecutor(max_workers=min(4, len(accounts)), thread_name_prefix="aws-report") as pool:
            rows = [row for result in pool.map(read, accounts) for row in result]
    except (aws.AwsFailure, ClientError, BotoCoreError) as exc:
        raise remote_failure(exc) from None
    q = body.q.strip().casefold()
    if q:
        rows = [r for r in rows if any(q in value.casefold() for value in r["values"][:1 if body.view == "groups" else 2])]
    rows.sort(key=lambda r: (r["account_id"], r["values"][0].casefold(), r["id"]))
    if body.row_ids is not None:
        selected = set(body.row_ids)
        if not selected <= {r["id"] for r in rows}:
            raise HTTPException(409, "选择的报表行已不在当前账号、搜索或权限范围，请重新查询")
        rows = [r for r in rows if r["id"] in selected]
    return scope, rows


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@router.post("/aws-reports/query")
def report_query(body: ReportInput, response: Response, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    scope, rows = collect(db, actor, body)
    payload = {"view": body.view, "columns": HEADERS[body.view], "rows": rows, "total": len(rows),
               "account_ids": sorted(body.account_ids), "generated_at": utc_now()}
    finish_scope(db, scope)
    response.headers["Cache-Control"] = "no-store"
    return payload


def csv_cell(value):
    if value == "-":
        return value
    stripped = value
    while stripped and (stripped[0].isspace() or unicodedata.category(stripped[0]).startswith("C")):
        stripped = stripped[1:]
    if stripped.startswith(("=", "+", "-", "@")) or (value and value[0] in "\t\r\n"):
        return "'" + value
    return value


def csv_bytes(view, rows):
    output = io.StringIO(newline="")
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    writer.writerow(HEADERS[view])
    writer.writerows([[csv_cell(v) for v in row["values"]] for row in rows])
    return ("\ufeff" + output.getvalue()).encode("utf-8")


def report_filename(account, view):
    name = re.sub(r"[^A-Za-z0-9_-]+", "-", account.name).strip("-")[:50] or "account"
    return f"aws-{account.id}-{name}-{account.aws_account_id}-{view}.csv"


@router.post("/aws-reports/download")
def report_download(body: ReportInput, request: Request, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    scope, rows = collect(db, actor, body)
    if len(scope.accounts) == 1:
        content = csv_bytes(body.view, rows)
        filename, media_type = report_filename(scope.accounts[0], body.view), "text/csv; charset=utf-8"
    else:
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
            for account in scope.accounts:
                archive.writestr(report_filename(account, body.view),
                                 csv_bytes(body.view, [r for r in rows if r["account_id"] == account.id]))
        content, filename, media_type = output.getvalue(), f"aws-{body.view}.zip", "application/zip"
    actor = finish_scope(db, scope)
    audit(db, actor, "aws_report_download", json.dumps({"view": body.view, "account_ids": sorted(body.account_ids),
                                                       "count": len(rows)}), request=request)
    db.commit()
    return Response(content, media_type=media_type, headers={"Cache-Control": "no-store",
                    "Content-Disposition": f'attachment; filename="{filename}"', "X-Export-Count": str(len(rows))})


@dataclass
class CostFlight:
    future: Future
    refresh_requested: bool = False


class CostReads:
    """Coalesce in-flight reads; retain only bounded manual-refresh timestamps."""
    def __init__(self, capacity=128, max_inflight=8):
        self.capacity, self.max_inflight = capacity, max_inflight
        self.refreshed, self.pending = OrderedDict(), {}
        self.lock = threading.Lock()

    def get(self, key, load, refresh=False):
        with self.lock:
            flight = self.pending.get(key)
            leader = flight is None
            if leader:
                refreshed = self.refreshed.get(key)
                if refresh and refreshed is not None and time.monotonic() - refreshed < 30:
                    raise HTTPException(429, "账单刚刚刷新，请等待 30 秒后再刷新")
                if len(self.pending) >= self.max_inflight:
                    raise HTTPException(429, "账单查询繁忙，请稍后重试")
                flight = self.pending[key] = CostFlight(Future())
            flight.refresh_requested = flight.refresh_requested or refresh
            future = flight.future
        if not leader:
            return dict(future.result(timeout=120))
        try:
            value = load()
            with self.lock:
                if flight.refresh_requested:
                    self.refreshed[key] = time.monotonic()
                    self.refreshed.move_to_end(key)
                    while len(self.refreshed) > self.capacity:
                        self.refreshed.popitem(last=False)
                # No amount survives the end of this in-flight join window.
                self.pending.pop(key, None)
            future.set_result(value)
            return dict(value)
        except BaseException as exc:
            future.set_exception(exc)
            raise
        finally:
            with self.lock:
                if self.pending.get(key) is flight:
                    self.pending.pop(key, None)


cost_reads = CostReads()


@router.get("/admin/aws/{account_id}/cost")
def account_cost(account_id: int, response: Response, month: str | None = Query(default=None, max_length=7),
                 payer_id: str | None = Query(default=None, max_length=12),
                 refresh: bool = False, actor: User = Depends(admin), db: Session = Depends(get_db)):
    try:
        start, _ = current_period(month)
        validate_payer(payer_id)
    except ValueError:
        raise HTTPException(422, "仅支持当前 UTC 月份，付款账号须为有效的 12 位 AWS 账号 ID") from None
    month = start[:7]
    scope = begin_scope(db, actor, [account_id], billing=True)
    key = (account_id, scope.fingerprints[account_id], month, payer_id)

    def load():
        value = aws.AwsGateway(scope.accounts[0]).monthly_cost(month, payer_id)
        finish_scope(db, scope, billing=True)
        db.commit()
        return {"account_id": account_id, "month": month, **value}

    try:
        payload = cost_reads.get(key, load, refresh)
    except (aws.AwsFailure, ClientError, BotoCoreError) as exc:
        raise remote_failure(exc, billing=True) from None
    except ValueError:
        raise HTTPException(422, "付款账号不在当前账单可选范围内或 UTC 账单月份已变化，请重新查询") from None
    except TimeoutError:
        raise HTTPException(504, "账单查询仍在进行，请稍后重试") from None
    finish_scope(db, scope, billing=True)
    response.headers["Cache-Control"] = "no-store"
    return payload
