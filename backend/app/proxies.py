"""Admin proxy inventory. Authentication is encrypted and never returned or logged."""

from ipaddress import ip_address
from dataclasses import dataclass, field
import ssl
from urllib.parse import quote

import requests
import socks
from urllib3.exceptions import (
    NewConnectionError,
    SSLError as UrllibSSLError,
    TimeoutError as UrllibTimeout,
)

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .database import SessionLocal, get_db
from .models import AwsAccount, Proxy, User, now
from .security import admin, audit, decrypt, encrypt, lock_user_write
from .aws_transport import request_session

router = APIRouter(prefix="/api/admin/proxies")
MAX_IMPORT = 100


class ProxyUnavailable(Exception):
    def __init__(self):
        super().__init__("绑定的代理不可用或配置已变更，请管理员检查代理后重试")


@dataclass(frozen=True)
class ProxySelection:
    proxy_id: int
    revision: int
    url: str = field(repr=False)


def proxy_selection(db, proxy_id, *, require_enabled=True):
    if proxy_id is None:
        return None
    proxy = db.get(Proxy, proxy_id, populate_existing=True)
    if proxy is None or (require_enabled and not proxy.enabled):
        raise ProxyUnavailable()
    try:
        auth = decrypt(proxy.auth_encrypted)
        username, password = auth["username"], auth["password"]
        validate_auth(username, password)
        host = validate_host(proxy.host)
        if ":" in host:
            host = f"[{host}]"
        if not 1 <= proxy.port <= 65535:
            raise ValueError()
        prefix = (
            f"{quote(username, safe='')}:{quote(password, safe='')}@"
            if username
            else ""
        )
    except Exception:
        raise ProxyUnavailable() from None
    return ProxySelection(
        proxy.id, proxy.revision, f"socks5h://{prefix}{host}:{proxy.port}"
    )


def select_proxy(db, proxy_id):
    try:
        return proxy_selection(db, proxy_id)
    except ProxyUnavailable:
        raise HTTPException(
            409, "所选代理不存在、已停用或认证不可用，请刷新后选择"
        ) from None


def check_selection(db, selection, *, require_enabled=True):
    if selection is None:
        return
    proxy = db.get(Proxy, selection.proxy_id, populate_existing=True)
    if (
        proxy is None
        or proxy.revision != selection.revision
        or (require_enabled and not proxy.enabled)
    ):
        raise ProxyUnavailable()


def recheck_proxy(db, selection, *, require_enabled=True):
    try:
        check_selection(db, selection, require_enabled=require_enabled)
    except ProxyUnavailable:
        raise HTTPException(
            409, "代理在验证期间已修改、停用或删除，请刷新后重试"
        ) from None


def account_proxy(account):
    with SessionLocal() as db:
        return proxy_selection(db, account.proxy_id)


def check_account_proxy(account, selection):
    with SessionLocal() as db:
        check_selection(db, selection)
        if account.id is not None:
            selected_id = db.scalar(
                select(AwsAccount.proxy_id).where(AwsAccount.id == account.id)
            )
            if selected_id != (selection.proxy_id if selection else None):
                raise ProxyUnavailable()


def validate_host(value):
    try:
        return str(ip_address(value))
    except ValueError:
        raise ValueError("代理地址需要有效的 IP") from None


def validate_auth(username, password):
    if bool(username) != bool(password) or any(
        len(value.encode()) > 255 or any(ord(c) < 32 or ord(c) == 127 for c in value)
        for value in (username, password)
    ):
        raise ValueError("代理认证需要同时填写用户名和密码，且各不超过 255 字节")
    return {"username": username, "password": password}


def parse_address(value):
    try:
        # Brackets disambiguate IPv6; passwords may themselves contain colons.
        if value.startswith("["):
            host, remainder = value[1:].split("]:", 1)
            port, username, password = remainder.split(":", 2)
        else:
            host, port, username, password = value.split(":", 3)
        host = validate_host(host)
        if not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError()
        auth = validate_auth(username, password)
    except (ValueError, TypeError):
        raise ValueError("代理格式应为 IP:端口:用户名:密码，端口为 1–65535") from None
    return host, int(port), auth


class ProxyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    name: str = Field(min_length=1, max_length=100)
    address: SecretStr = Field(min_length=1, max_length=1100)
    enabled: bool = True

    @field_validator("address")
    @classmethod
    def valid_address(cls, value):
        parse_address(value.get_secret_value())
        return value


class ProxyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    name: str | None = Field(default=None, min_length=1, max_length=100)
    host: str | None = Field(default=None, max_length=45)
    port: int | None = Field(default=None, ge=1, le=65535)
    username: SecretStr | None = Field(default=None, max_length=255)
    password: SecretStr | None = Field(default=None, max_length=255)
    clear_auth: bool = False
    enabled: bool | None = None

    @field_validator("host")
    @classmethod
    def valid_host(cls, value):
        return validate_host(value) if value is not None else value


class ProxyImport(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    addresses: SecretStr = Field(min_length=1, max_length=110000)
    name_prefix: str = Field(default="导入代理", min_length=1, max_length=80)


def binding_count(db, proxy, *, deleted_only=False):
    query = (
        select(func.count())
        .select_from(AwsAccount)
        .where(AwsAccount.proxy_id == proxy.id)
    )
    if deleted_only:
        query = query.where(AwsAccount.deleted_at.is_not(None))
    return db.scalar(query)


def proxy_view(db, proxy):
    return {
        key: getattr(proxy, key)
        for key in (
            "id",
            "name",
            "host",
            "port",
            "enabled",
            "revision",
            "last_probe_status",
            "last_probe_at",
            "egress_ip",
            "created_at",
        )
    } | {
        "status": "enabled" if proxy.enabled else "disabled",
        "auth_configured": bool(decrypt(proxy.auth_encrypted).get("username")),
        "binding_count": binding_count(db, proxy),
        "deleted_binding_count": binding_count(db, proxy, deleted_only=True),
    }


def get_proxy(db, proxy_id):
    proxy = db.get(Proxy, proxy_id)
    if proxy is None:
        raise HTTPException(404, "代理不存在或已删除")
    return proxy


@router.get("")
def list_proxies(_: User = Depends(admin), db: Session = Depends(get_db)):
    return [proxy_view(db, p) for p in db.scalars(select(Proxy).order_by(Proxy.id))]


@router.post("", status_code=201)
def add_proxy(
    body: ProxyCreate,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    host, port, auth = parse_address(body.address.get_secret_value())
    proxy = Proxy(
        name=body.name,
        host=host,
        port=port,
        auth_encrypted=encrypt(auth),
        enabled=body.enabled,
    )
    db.add(proxy)
    db.flush()
    audit(db, actor, "add_proxy", f"添加代理 #{proxy.id}", request=request)
    db.commit()
    return proxy_view(db, proxy)


@router.post("/import", status_code=201)
def import_proxies(
    body: ProxyImport,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    lines = [
        line for line in body.addresses.get_secret_value().splitlines() if line.strip()
    ]
    if not 1 <= len(lines) <= MAX_IMPORT:
        raise HTTPException(422, f"每次需导入 1–{MAX_IMPORT} 行代理")
    parsed = []
    for index, line in enumerate(lines, 1):
        try:
            parsed.append(parse_address(line))
        except ValueError:
            raise HTTPException(
                422, f"第 {index} 行代理格式不正确，未导入任何代理"
            ) from None
    rows = []
    for index, (host, port, auth) in enumerate(parsed, 1):
        proxy = Proxy(
            name=f"{body.name_prefix} {index}",
            host=host,
            port=port,
            auth_encrypted=encrypt(auth),
        )
        db.add(proxy)
        rows.append(proxy)
    # One transaction: validation or uniqueness errors roll back the entire import.
    db.flush()
    audit(
        db,
        actor,
        "import_proxies",
        f"导入 {len(rows)} 个代理；编号 {','.join(str(p.id) for p in rows)}",
        request=request,
    )
    db.commit()
    return {"items": [proxy_view(db, proxy) for proxy in rows]}


@router.get("/{proxy_id}")
def proxy_detail(
    proxy_id: int, _: User = Depends(admin), db: Session = Depends(get_db)
):
    return proxy_view(db, get_proxy(db, proxy_id))


@router.patch("/{proxy_id}")
def edit_proxy(
    proxy_id: int,
    body: ProxyUpdate,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    proxy = get_proxy(db, proxy_id)
    username = body.username.get_secret_value() if body.username else ""
    password = body.password.get_secret_value() if body.password else ""
    try:
        auth = validate_auth(username, password)
    except ValueError:
        raise HTTPException(
            422, "替换代理认证时需同时填写用户名和密码，各不超过 255 字节"
        ) from None
    if body.clear_auth and (username or password):
        raise HTTPException(422, "清除认证时不能同时填写新认证")
    changed = False
    for key in ("name", "host", "port", "enabled"):
        value = getattr(body, key)
        if value is not None and value != getattr(proxy, key):
            setattr(proxy, key, value)
            changed = True
    if username or body.clear_auth:
        proxy.auth_encrypted = encrypt(auth)
        changed = True
    if changed:
        proxy.revision += 1
        proxy.last_probe_status = None
        proxy.last_probe_at = None
        proxy.egress_ip = None
        audit(
            db,
            actor,
            "update_proxy",
            f"修改代理 #{proxy.id}；启用={proxy.enabled}；绑定账号数={binding_count(db, proxy)}",
            request=request,
        )
        db.commit()
    return proxy_view(db, proxy)


@router.delete("/{proxy_id}")
def delete_proxy(
    proxy_id: int,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    proxy = get_proxy(db, proxy_id)
    if binding_count(db, proxy):
        raise HTTPException(409, "此代理仍绑定 AWS 账号，请先修改账号的代理设置")
    db.delete(proxy)
    audit(db, actor, "delete_proxy", f"删除代理 #{proxy_id}", request=request)
    db.commit()
    return {"ok": True}


@router.post("/{proxy_id}/release-deleted-bindings")
def release_deleted_bindings(
    proxy_id: int,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    from .resources import ensure_no_tasks

    proxy = get_proxy(db, proxy_id)
    accounts = db.scalars(
        select(AwsAccount).where(
            AwsAccount.proxy_id == proxy.id,
            AwsAccount.deleted_at.is_not(None),
        ).order_by(AwsAccount.id)
    ).all()
    if not accounts:
        raise HTTPException(409, "没有可解除的已删除配置绑定，请刷新代理列表")
    # get_user holds the writer lock. Recheck all old configurations before
    # changing any selection; current configurations never enter this set.
    for account in accounts:
        ensure_no_tasks(db, account)
    for account in accounts:
        account.proxy_id = None
    audit(
        db,
        actor,
        "release_deleted_proxy_bindings",
        f"解除代理 #{proxy.id} 的已删除 AWS 配置绑定："
        + ", ".join(f"#{account.id}" for account in accounts),
        request=request,
    )
    db.commit()
    return proxy_view(db, proxy)


def probe_error_category(error):
    """Inspect exception types through requests/urllib3 wrappers, never their text."""
    pending, seen, errors = [error], set(), []
    while pending:
        current = pending.pop()
        if not isinstance(current, BaseException) or id(current) in seen:
            continue
        seen.add(id(current))
        errors.append(current)
        pending.extend((current.__cause__, current.__context__, *current.args))
        pending.extend(
            getattr(current, name, None)
            for name in ("reason", "original_error", "socket_err")
        )
    if any(isinstance(e, socks.SOCKS5AuthError) for e in errors):
        return "auth_failed"
    if any(
        isinstance(e, (requests.Timeout, TimeoutError, UrllibTimeout))
        and not isinstance(e, NewConnectionError)
        for e in errors
    ):
        return "timeout"
    if any(
        isinstance(e, (requests.exceptions.SSLError, ssl.SSLError, UrllibSSLError))
        for e in errors
    ):
        return "tls"
    return "connect"


@router.post("/{proxy_id}/probe")
def probe_proxy(
    proxy_id: int,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    get_proxy(db, proxy_id)
    try:
        selection = proxy_selection(db, proxy_id, require_enabled=False)
    except ProxyUnavailable:
        raise HTTPException(409, "代理认证不可用，请重新保存认证后探测") from None
    # get_user deliberately leaves the writer lock free during this bounded call.
    session_version = actor.session_version
    status, egress_ip = "invalid_response", None
    try:
        with request_session(selection.url) as session:
            response = session.get(
                "https://checkip.amazonaws.com/",
                timeout=(5, 10),
                allow_redirects=False,
                verify=True,
            )
            try:
                if response.status_code == 200 and len(response.text) <= 80:
                    egress_ip = str(ip_address(response.text.strip()))
                    status = "ok"
            finally:
                response.close()
    except requests.RequestException as exc:
        status = probe_error_category(exc)
    except ValueError:
        pass
    lock_user_write(db, actor, session_version)
    admin(actor)
    recheck_proxy(db, selection, require_enabled=False)
    proxy = get_proxy(db, proxy_id)
    proxy.last_probe_status, proxy.egress_ip, proxy.last_probe_at = (
        status,
        egress_ip,
        now(),
    )
    audit(
        db,
        actor,
        "probe_proxy",
        f"探测代理 #{proxy_id}；结果={status}",
        request=request,
    )
    db.commit()
    return proxy_view(db, proxy)
