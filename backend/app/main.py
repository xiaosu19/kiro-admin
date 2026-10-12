import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import case, delete, func, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import aws
from .catalog import (
    BILLING_URL,
    BY_SUBSCRIPTION_TYPE,
    CATALOG_CHECKED_AT,
    PAID_PLANS,
    PLAN_ORDER,
    PRICING_URL,
)
from .config import settings
from .database import get_db
from .models import (
    AuditEvent,
    AwsAccount,
    Binding,
    CounterReset,
    LoginAttempt,
    Plan,
    PlanCounter,
    PlanChange,
    RecordOperation,
    GroupJob,
    ManagedGroup,
    StopSchedule,
    Subscription,
    User,
    now,
)
from .schemas import (
    AwsDiscoverInput,
    AwsInput,
    BindingInput,
    ChangePassword,
    CounterInput,
    CounterResetInput,
    ConfiguredResetInput,
    Login,
    PlanInput,
    ResolveUnsubscribedInput,
    SubscriptionInput,
    UserCreate,
    UserUpdate,
)
from .security import (
    admin,
    audit,
    check_password,
    decrypt,
    encrypt,
    get_user,
    hash_password,
    make_token,
    lock_user_write,
    user_view,
)
from .lifecycle import operation_view, router as lifecycle_router
from .exports import router as export_router, record_query, sso_query
from .admin_reports import router as reports_router, user_summary
from .aws_reports import router as aws_reports_router
from .statistics import lifecycle_totals
from .resources import account_view, plan_view, router as resources_router
from .batches import register_batch_routes, update_batch_item
from .schedules import configure, schedule_view, router as schedules_router
from .proxies import router as proxies_router, select_proxy, recheck_proxy
from .groups import router as groups_router
from .group_policies import router as group_policies_router
from .auth_batches import router as auth_batches_router
from .plan_changes import router as plan_changes_router
from .plan_change_state import (
    projections,
    referenced_plan,
    LIVE_STATES as PLAN_CHANGE_LIVE_STATES,
)
from .auth_credentials import AUTH_KINDS
from .auth_widget import router as auth_widget_router, verification_host, request_origin
from .cascade_deletions import router as cascade_deletions_router
from .group_json_exports import router as group_json_exports_router
from .external_auth import router as external_auth_router
from .ai_settings import router as ai_settings_router

app = FastAPI(
    title="Kiro Console", version="2.0", docs_url=None, redoc_url=None, openapi_url=None
)
app.include_router(lifecycle_router)
app.include_router(cascade_deletions_router)
app.include_router(group_json_exports_router)
app.include_router(external_auth_router)
app.include_router(ai_settings_router)
app.include_router(plan_changes_router)
app.include_router(export_router)
app.include_router(reports_router)
app.include_router(aws_reports_router)
app.include_router(resources_router)
app.include_router(schedules_router)
app.include_router(proxies_router)
from .group_subscriptions import router as native_groups_router
app.include_router(native_groups_router)
app.include_router(groups_router)
from .group_member_batches import router as group_member_batches_router
app.include_router(group_member_batches_router)
from .group_observations import router as group_observations_router
app.include_router(group_observations_router)
from .provisioning_batches import router as provisioning_batches_router
from .provisioning_exports import router as provisioning_exports_router, mappings as provisioning_mappings
app.include_router(provisioning_exports_router)
app.include_router(provisioning_batches_router)
app.include_router(group_policies_router)
app.include_router(auth_batches_router)
app.include_router(auth_widget_router)


@app.middleware("http")
async def headers(request, call_next):
    isolated = verification_host(request)
    if (
        isolated and (request.url.path != "/auth-widget" or request.method != "GET")
    ) or (
        request.url.path == "/auth-widget"
        and request_origin(request) != settings.verify_origin
    ):
        response = JSONResponse(status_code=404, content={"detail": "Not Found"})
    else:
        response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    if getattr(request.state, "auth_widget", False):
        return response
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; "
        f"frame-src {settings.verify_origin}"
    )
    if request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.exception_handler(RequestValidationError)
async def invalid_input(request, exc):
    return JSONResponse(
        status_code=422,
        content={
            "detail": "输入格式不正确",
            "fields": [".".join(map(str, e["loc"][1:])) for e in exc.errors()],
        },
    )


@app.exception_handler(IntegrityError)
async def duplicate(request, exc):
    return JSONResponse(
        status_code=409,
        content={"detail": "记录已存在，或刚被其他操作更新，请刷新后重试"},
    )


@app.exception_handler(aws.AwsFailure)
async def aws_error(request, exc):
    return JSONResponse(status_code=502, content={"detail": str(exc)})


@app.get("/health")
def health(db: Session = Depends(get_db)):
    db.execute(select(1))
    return {"status": "ok", "version": "2.0"}


@app.post("/api/auth/login")
def login(
    body: Login, request: Request, response: Response, db: Session = Depends(get_db)
):
    # JSON and same-site cookies prevent cross-site form login; no token in localStorage.
    if request.headers.get("Sec-Fetch-Site") == "cross-site":
        raise HTTPException(403, "请从本站登录")
    key = hashlib.sha256(
        f"{request.client.host}:{body.username.lower()}".encode()
    ).hexdigest()
    cutoff = now() - timedelta(minutes=15)
    db.execute(delete(LoginAttempt).where(LoginAttempt.created_at < cutoff))
    failures = db.scalar(
        select(func.count()).select_from(LoginAttempt).where(LoginAttempt.key == key)
    )
    if failures >= 8:
        db.commit()
        raise HTTPException(429, "登录尝试过多，请 15 分钟后重试")
    user = db.scalar(select(User).where(User.username == body.username))
    if (
        not user
        or not user.active
        or user.deleted_at
        or not check_password(body.password, user.password_hash)
    ):
        db.add(LoginAttempt(key=key))
        db.commit()
        raise HTTPException(401, "用户名或密码不正确")
    db.execute(delete(LoginAttempt).where(LoginAttempt.key == key))
    csrf = secrets.token_urlsafe(32)
    response.set_cookie(
        "kiro_session",
        make_token(user, csrf),
        httponly=True,
        secure=settings.secure_cookie,
        samesite="strict",
        max_age=settings.session_hours * 3600,
        path="/",
    )
    audit(db, user, "login", "登录后台", subject=user.id, request=request)
    db.commit()
    return {"user": user_view(user), "csrf": csrf}


@app.get("/api/auth/me")
def me(request: Request, user: User = Depends(get_user)):
    return {
        "user": user_view(user),
        "csrf": request.state.csrf,
        "capabilities": {"plan_changes_enabled": settings.plan_changes_enabled},
    }


@app.post("/api/auth/logout")
def logout(response: Response, user: User = Depends(get_user)):
    response.delete_cookie("kiro_session", path="/")
    return {"ok": True}


@app.post("/api/auth/change-password")
def change_password(
    body: ChangePassword,
    response: Response,
    request: Request,
    user: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    if not check_password(body.old_password, user.password_hash):
        raise HTTPException(400, "原密码不正确")
    if body.old_password == body.new_password:
        raise HTTPException(400, "新密码需要与原密码不同")
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    user.session_version += 1
    audit(db, user, "change_password", "修改登录密码", subject=user.id, request=request)
    db.commit()
    csrf = secrets.token_urlsafe(32)
    response.set_cookie(
        "kiro_session",
        make_token(user, csrf),
        httponly=True,
        secure=settings.secure_cookie,
        samesite="strict",
        max_age=settings.session_hours * 3600,
        path="/",
    )
    return {"user": user_view(user), "csrf": csrf}


def member(db, user_id):
    u = db.get(User, user_id)
    if not u or u.deleted_at:
        raise HTTPException(404, "用户不存在")
    return u


@app.get("/api/admin/users")
def users(_: User = Depends(admin), db: Session = Depends(get_db)):
    return [
        user_view(u)
        | {
            "account_ids": list(
                db.scalars(
                    select(Binding.aws_account_id).where(Binding.user_id == u.id)
                )
            )
        }
        for u in db.scalars(
            select(User).where(User.deleted_at.is_(None)).order_by(User.id.desc())
        )
    ]


@app.post("/api/admin/users", status_code=201)
def create_user(
    body: UserCreate,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    u = User(
        username=body.username,
        display_name=body.display_name,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(u)
    db.flush()
    audit(
        db,
        actor,
        "create_member",
        f"创建{'管理员' if u.role == 'admin' else '普通用户'} {u.username}",
        subject=u.id,
        request=request,
    )
    db.commit()
    return user_view(u)


@app.patch("/api/admin/users/{user_id}")
def update_user(
    user_id: int,
    body: UserUpdate,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    u = member(db, user_id)
    role_changed = body.role is not None and body.role != u.role
    if u.id == actor.id and (
        body.active is False or (body.role is not None and body.role != u.role)
    ):
        raise HTTPException(409, "不能停用或降低当前登录账号的权限")
    values = {}
    for key in ("display_name", "active", "role"):
        if getattr(body, key) is not None:
            values[key] = getattr(body, key)
    if body.password:
        values["password_hash"] = hash_password(body.password)
        values["must_change_password"] = True
    revoke_session = (
        body.password
        or role_changed
        or (body.active is not None and body.active != u.active)
    )
    values["session_version"] = User.session_version + (1 if revoke_session else 0)
    changed = db.execute(
        update(User)
        .where(
            User.id == u.id,
            User.deleted_at.is_(None),
            User.session_version == u.session_version,
        )
        .values(**values)
    )
    if not changed.rowcount:
        raise HTTPException(409, "用户状态已变化，请刷新后重试")
    if role_changed:
        if unfinished_user_tasks(db, u.id):
            raise HTTPException(409, "该用户还有处理中或待核对任务，完成后才能修改角色")
        if body.role == "member":
            from .models import GroupMemberActivation
            from .group_subscription_state import initial_user_activation
            # Administrator activations are unlimited but remain in lifetime history.
            totals = dict(
                db.execute(
                    select(Subscription.plan_id, func.count())
                    .where(
                        Subscription.owner_id == u.id, Subscription.counted.is_(True), initial_user_activation()
                    )
                    .group_by(Subscription.plan_id)
                ).all()
            )
            for plan_id, count in db.execute(
                select(PlanChange.to_plan_id, func.count())
                .where(PlanChange.owner_id == u.id, PlanChange.counted.is_(True))
                .group_by(PlanChange.to_plan_id)
            ):
                totals[plan_id] = totals.get(plan_id, 0) + count
            for plan_id, count in db.execute(
                select(GroupMemberActivation.plan_id, func.count())
                .where(GroupMemberActivation.owner_id == u.id, GroupMemberActivation.counted.is_(True))
                .group_by(GroupMemberActivation.plan_id)
            ):
                totals[plan_id] = totals.get(plan_id, 0) + count
            for plan_id, total in totals.items():
                c = db.scalar(
                    select(PlanCounter).where(
                        PlanCounter.user_id == u.id, PlanCounter.plan_id == plan_id
                    )
                )
                if c:
                    c.lifetime_count = max(c.lifetime_count, total)
                else:
                    db.add(
                        PlanCounter(
                            user_id=u.id,
                            plan_id=plan_id,
                            limit_count=0,
                            lifetime_count=total,
                        )
                    )
    if not db.scalar(
        select(User.id)
        .where(User.role == "admin", User.active.is_(True), User.deleted_at.is_(None))
        .limit(1)
    ):
        raise HTTPException(409, "至少需要保留一个可用管理员")
    audit(
        db,
        actor,
        "update_member",
        f"修改用户 {u.username}，字段：{', '.join(body.model_fields_set)}"
        + (f"；角色为 {u.role}" if body.role is not None else ""),
        subject=u.id,
        request=request,
    )
    db.commit()
    return user_view(u)


def unfinished_user_tasks(db, user_id):
    owned_ids = select(Subscription.id).where(Subscription.owner_id == user_id)
    pending = db.scalar(
        select(Subscription.id)
        .where(
            Subscription.owner_id == user_id,
            or_(
                Subscription.state.in_(("queued", "running", "needs_review")),
                Subscription.reserved.is_(True),
                Subscription.active_operation_id.is_not(None),
            ),
        )
        .limit(1)
    )
    active_op = db.scalar(
        select(RecordOperation.id)
        .where(
            or_(
                RecordOperation.record_id.in_(owned_ids),
                RecordOperation.actor_id == user_id,
            ),
            RecordOperation.state.in_(("queued", "running", "needs_review")),
        )
        .limit(1)
    )
    group_job = db.scalar(
        select(GroupJob.id)
        .join(ManagedGroup, ManagedGroup.id == GroupJob.group_id)
        .where(
            or_(ManagedGroup.owner_id == user_id, GroupJob.actor_id == user_id),
            or_(
                GroupJob.state.in_(("queued", "running", "needs_review")),
                ManagedGroup.active_job_id == GroupJob.id,
            ),
        )
        .limit(1)
    )
    plan_change = db.scalar(
        select(PlanChange.id)
        .where(
            or_(PlanChange.owner_id == user_id, PlanChange.actor_id == user_id),
            PlanChange.state.in_(PLAN_CHANGE_LIVE_STATES),
        )
        .limit(1)
    )
    from .models import NativeGroupOperation, GroupMemberActivation, GroupMemberBatch
    from .group_member_batches import LIVE_STATES as MEMBER_BATCH_STATES
    member_batch = db.scalar(select(GroupMemberBatch.id).where(
        or_(GroupMemberBatch.owner_id == user_id, GroupMemberBatch.actor_id == user_id),
        GroupMemberBatch.state.in_(MEMBER_BATCH_STATES),
    ).limit(1))
    native = db.scalar(select(NativeGroupOperation.id).where(
        or_(NativeGroupOperation.owner_id == user_id, NativeGroupOperation.actor_id == user_id),
        NativeGroupOperation.state.in_(("queued", "running", "needs_review")),
    ).limit(1))
    joining = db.scalar(select(GroupMemberActivation.id).where(
        or_(GroupMemberActivation.owner_id == user_id, GroupMemberActivation.actor_id == user_id),
        GroupMemberActivation.state.in_(("pending", "needs_review")),
    ).limit(1))
    from .provisioning_batches import live_intent
    return pending or active_op or group_job or plan_change or native or joining or member_batch or live_intent(db, actor_id=user_id)


@app.delete("/api/admin/users/{user_id}")
def delete_member(
    user_id: int,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    u = db.get(User, user_id)
    if not u:
        raise HTTPException(404, "用户不存在")
    if u.deleted_at:
        return {"ok": True}
    if u.active:
        raise HTTPException(409, "请先停用用户，再删除")
    # Obtain the write lock before checking jobs, so deletion cannot race admission.
    changed = db.execute(
        update(User)
        .where(User.id == u.id, User.active.is_(False), User.deleted_at.is_(None))
        .values(deleted_at=now(), session_version=User.session_version + 1)
    )
    if not changed.rowcount:
        raise HTTPException(409, "用户状态已变化，请刷新后重试")
    if unfinished_user_tasks(db, u.id):
        raise HTTPException(409, "该用户还有处理中或待核对任务，请先处理完成")
    db.execute(delete(Binding).where(Binding.user_id == u.id))
    audit(
        db,
        actor,
        "delete_member",
        f"删除已停用用户 {u.username}；保留 SSO、订阅、次数与审计历史",
        subject=u.id,
        request=request,
    )
    db.commit()
    return {"ok": True}


@app.put("/api/admin/users/{user_id}/bindings")
def set_bindings(
    user_id: int,
    body: BindingInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    member(db, user_id)
    ids = set(body.account_ids)
    if len(
        list(
            db.scalars(
                select(AwsAccount.id).where(
                    AwsAccount.id.in_(ids), AwsAccount.deleted_at.is_(None)
                )
            )
        )
    ) != len(ids):
        raise HTTPException(404, "部分 AWS 账号不存在")
    current = set(
        db.scalars(select(Binding.aws_account_id).where(Binding.user_id == user_id))
    )
    # New requests and permission changes are both serialized by SQLite writes.
    db.execute(delete(Binding).where(Binding.user_id == user_id))
    from .provisioning_batches import live_intent
    if current - ids and live_intent(db, actor_id=user_id, account_ids=current - ids):
        raise HTTPException(409, "该用户仍有批次开通意图，处理完成后才能解除相关 AWS 绑定")
    db.add_all([Binding(user_id=user_id, aws_account_id=i) for i in ids])
    audit(
        db,
        actor,
        "bind_aws",
        f"AWS 绑定从 {sorted(current)} 修改为 {sorted(ids)}",
        subject=user_id,
        request=request,
    )
    db.commit()
    return {"ok": True}


@app.get("/api/accounts")
def accounts(
    include_deleted: bool = False,
    user: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    q = select(AwsAccount)
    if not include_deleted or user.role != "admin":
        q = q.where(AwsAccount.deleted_at.is_(None))
    if user.role != "admin":
        q = q.join(Binding).where(
            Binding.user_id == user.id, AwsAccount.active.is_(True)
        )
    return [
        account_view(a, user.role == "admin", db)
        for a in db.scalars(q.order_by(AwsAccount.id))
    ]


@app.post("/api/admin/aws/discover")
def discover_aws(
    body: AwsDiscoverInput, actor: User = Depends(admin), db: Session = Depends(get_db)
):
    selection = select_proxy(db, body.proxy_id)
    session_version = actor.session_version
    try:
        result = aws.discover(body, selection=selection)
    except aws.AwsFailure:
        raise
    except Exception as exc:
        raise HTTPException(
            502, f"AWS 配置读取失败：{type(exc).__name__}；请检查密钥、区域及 IAM 权限"
        )
    lock_user_write(db, actor, session_version)
    admin(actor)
    recheck_proxy(db, selection)
    db.commit()
    return result


@app.post("/api/admin/aws", status_code=201)
def add_account(
    body: AwsInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    if not body.access_key_id or not body.secret_access_key:
        raise HTTPException(422, "需要填写 AK 和 SK")
    if db.scalar(
        select(AwsAccount.id).where(
            AwsAccount.name == body.name, AwsAccount.deleted_at.is_not(None)
        )
    ):
        raise HTTPException(409, "同名 AWS 配置已删除，请在已删除列表恢复后编辑")
    data = body.model_dump(exclude={"access_key_id", "secret_access_key"})
    selection = select_proxy(db, body.proxy_id)
    a = AwsAccount(
        **data,
        aws_account_id="",
        credentials_encrypted=encrypt(
            {
                "access_key_id": body.access_key_id,
                "secret_access_key": body.secret_access_key,
            }
        ),
    )
    a._proxy_selection = selection
    try:
        a.aws_account_id = aws.AwsGateway(a).verify()
    except aws.AwsFailure:
        raise
    except Exception as exc:
        raise HTTPException(502, f"AWS 验证失败：{type(exc).__name__}")
    lock_user_write(db, actor, actor.session_version)
    admin(actor)
    recheck_proxy(db, selection)
    db.add(a)
    db.flush()
    from .account_numbers import claim_number
    claim_number(db, a, body.account_number)
    audit(
        db,
        actor,
        "add_aws",
        f"添加 AWS 账号 {a.name}（{a.aws_account_id}）",
        request=request,
    )
    db.commit()
    return account_view(a, True, db)


@app.put("/api/admin/aws/{account_id}")
def edit_account(
    account_id: int,
    body: AwsInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    a = db.get(AwsAccount, account_id)
    if not a or a.deleted_at:
        raise HTTPException(404, "AWS 账号不存在")
    immutable = (
        "region",
        "subscription_region",
        "control_plane",
        "identity_store_id",
        "instance_arn",
        "application_arn",
        "profile_arn",
    )
    if (
        db.scalar(
            select(Subscription.id).where(Subscription.aws_account_id == a.id).limit(1)
        )
        or db.scalar(
            select(ManagedGroup.id).where(ManagedGroup.aws_account_id == a.id).limit(1)
        )
    ) and any(getattr(a, k) != getattr(body, k) for k in immutable):
        raise HTTPException(
            409, "此 AWS 资源已有创建记录；更换实例或订阅配置请添加新账号"
        )
    if bool(body.access_key_id) != bool(body.secret_access_key):
        raise HTTPException(422, "轮换密钥需要同时填写 AK 和 SK")
    data = body.model_dump(exclude={"access_key_id", "secret_access_key"})
    if "account_number" not in body.model_fields_set:
        data["account_number"] = a.account_number
    if "proxy_id" not in body.model_fields_set:
        data["proxy_id"] = a.proxy_id
    if ("account_number" in body.model_fields_set and not body.access_key_id
            and all(getattr(a, key) == value for key, value in data.items() if key != "account_number")):
        # Display numbering remains editable when the transport is unavailable.
        # It cannot rotate credentials or change the accepted transport signature.
        before = {key: getattr(a, key) for key in (*data.keys(), "credentials_encrypted", "deleted_at")}
        lock_user_write(db, actor, actor.session_version)
        admin(actor)
        db.refresh(a)
        if any(getattr(a, key) != value for key, value in before.items()):
            raise HTTPException(409, "AWS 配置已变化，请刷新后重试")
        from .account_numbers import claim_number
        claim_number(db, a, data["account_number"])
        audit(db, actor, "update_aws_number", f"修改 AWS 编号：{a.name}", request=request)
        db.commit()
        return account_view(a, True, db)
    selection = select_proxy(db, data["proxy_id"])
    before = {
        k: getattr(a, k) for k in (*data.keys(), "credentials_encrypted", "deleted_at")
    }
    encrypted_credentials = a.credentials_encrypted
    if body.access_key_id:
        encrypted_credentials = encrypt(
            {
                "access_key_id": body.access_key_id,
                "secret_access_key": body.secret_access_key,
            }
        )
    candidate = AwsAccount(
        **data,
        aws_account_id=a.aws_account_id,
        credentials_encrypted=encrypted_credentials,
    )
    candidate._proxy_selection = selection
    try:
        identity = aws.AwsGateway(candidate).verify()
        if identity != a.aws_account_id:
            raise HTTPException(409, "新密钥属于其他 AWS 账号，请另行添加")
    except (aws.AwsFailure, HTTPException):
        raise
    except Exception as exc:
        raise HTTPException(502, f"AWS 验证失败：{type(exc).__name__}")
    lock_user_write(db, actor, actor.session_version)
    admin(actor)
    recheck_proxy(db, selection)
    db.refresh(a)
    if any(getattr(a, k) != value for k, value in before.items()):
        raise HTTPException(409, "AWS 配置已被其他操作修改或删除，请刷新后重试")
    if (
        db.scalar(
            select(Subscription.id).where(Subscription.aws_account_id == a.id).limit(1)
        )
        or db.scalar(
            select(ManagedGroup.id).where(ManagedGroup.aws_account_id == a.id).limit(1)
        )
    ) and any(getattr(a, k) != data[k] for k in immutable):
        raise HTTPException(
            409, "此 AWS 资源已有创建记录；更换实例或订阅配置请添加新账号"
        )
    for key, value in data.items():
        setattr(a, key, value)
    from .account_numbers import claim_number
    claim_number(db, a, data["account_number"])
    a.credentials_encrypted = encrypted_credentials
    audit(db, actor, "update_aws", f"修改 AWS 账号 {a.name}", request=request)
    db.commit()
    return account_view(a, True, db)


@app.get("/api/plans")
def plans(
    include_deleted: bool = False,
    user: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    q = select(Plan).order_by(
        case(PLAN_ORDER, value=Plan.subscription_type, else_=99), Plan.id
    )
    if user.role != "admin":
        q = q.where(Plan.active.is_(True))
    if not include_deleted or user.role != "admin":
        q = q.where(Plan.deleted_at.is_(None))
    return [plan_view(p, db if user.role == "admin" else None) for p in db.scalars(q)]


@app.get("/api/plan-catalog")
def plan_catalog(_: User = Depends(get_user)):
    return {
        "items": PAID_PLANS,
        "checked_at": CATALOG_CHECKED_AT,
        "pricing_url": PRICING_URL,
        "billing_url": BILLING_URL,
    }


@app.post("/api/admin/plans", status_code=201)
def add_plan(
    body: PlanInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    if db.scalar(
        select(Plan.id).where(
            or_(
                Plan.code == body.code, Plan.subscription_type == body.subscription_type
            ),
            Plan.deleted_at.is_not(None),
        )
    ):
        raise HTTPException(
            409, "相同代码或订阅类型的套餐已删除，请在已删除列表恢复后编辑"
        )
    p = Plan(**body.model_dump())
    db.add(p)
    audit(db, actor, "add_plan", f"添加套餐 {p.name}", request=request)
    db.commit()
    return {"id": p.id}


@app.put("/api/admin/plans/{plan_id}")
def edit_plan(
    plan_id: int,
    body: PlanInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    p = db.get(Plan, plan_id)
    if not p or p.deleted_at:
        raise HTTPException(404, "套餐不存在")
    if p.subscription_type != body.subscription_type and (
        referenced_plan(db, p.id)
        or db.scalar(
            select(Subscription.id).where(Subscription.plan_id == p.id).limit(1)
        )
    ):
        raise HTTPException(409, "已使用套餐不能改变订阅类型，请添加新套餐")
    for k, v in body.model_dump().items():
        setattr(p, k, v)
    audit(db, actor, "update_plan", f"修改套餐 {p.name}", request=request)
    db.commit()
    return {"ok": True}


def counter_view(c, db):
    return {
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
            "cycle_started_at",
        )
    } | {
        "plan_name": db.get(Plan, c.plan_id).name,
        "username": db.get(User, c.user_id).username,
    }


@app.get("/api/counters")
def counters(
    user_id: int | None = None,
    user: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    q = (
        select(PlanCounter)
        .join(User, User.id == PlanCounter.user_id)
        .where(User.deleted_at.is_(None))
        .order_by(PlanCounter.user_id, PlanCounter.plan_id)
    )
    if user.role != "admin":
        q = q.where(PlanCounter.user_id == user.id)
    elif user_id:
        q = q.where(PlanCounter.user_id == user_id)
    return [counter_view(c, db) for c in db.scalars(q)]


@app.put("/api/admin/users/{user_id}/counters/{plan_id}")
def set_counter(
    user_id: int,
    plan_id: int,
    body: CounterInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    member(db, user_id)
    plan = db.get(Plan, plan_id)
    if not plan or plan.deleted_at:
        raise HTTPException(404, "套餐不存在")
    c = db.scalar(
        select(PlanCounter).where(
            PlanCounter.user_id == user_id, PlanCounter.plan_id == plan_id
        )
    )
    if not c:
        c = PlanCounter(user_id=user_id, plan_id=plan_id, limit_count=body.limit_count)
        db.add(c)
    else:
        changed = db.execute(
            update(PlanCounter)
            .where(
                PlanCounter.id == c.id,
                PlanCounter.used_count + PlanCounter.pending_count <= body.limit_count,
            )
            .values(limit_count=body.limit_count)
        )
        if not changed.rowcount:
            raise HTTPException(409, "上限不能小于本轮已用次数与处理中次数之和")
    audit(
        db,
        actor,
        "set_count_limit",
        f"{db.get(Plan, plan_id).name} 本轮次数上限设为 {body.limit_count}",
        subject=user_id,
        request=request,
    )
    db.commit()
    return {"ok": True}


@app.post("/api/admin/counters/{counter_id}/reset")
def reset_counter(
    counter_id: int,
    body: CounterResetInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    c = db.get(PlanCounter, counter_id)
    if not c:
        raise HTTPException(404, "计数记录不存在")
    if db.get(Plan, c.plan_id).deleted_at:
        raise HTTPException(409, "套餐已删除，请先恢复套餐再重置次数")
    member(db, c.user_id)
    snapshot = {
        k: getattr(c, k)
        for k in ("cycle_number", "used_count", "limit_count", "cycle_started_at")
    }
    result = db.execute(
        update(PlanCounter)
        .where(
            PlanCounter.id == c.id,
            PlanCounter.pending_count == 0,
            PlanCounter.cycle_number == c.cycle_number,
            PlanCounter.used_count == c.used_count,
            PlanCounter.limit_count == c.limit_count,
        )
        .values(
            used_count=0,
            limit_count=body.limit_count,
            cycle_number=PlanCounter.cycle_number + 1,
            cycle_started_at=now(),
        )
    )
    if not result.rowcount:
        raise HTTPException(
            409,
            "存在处理中、待核对订阅或跨月待生效套餐变更，或计数刚发生变更，请处理后再重置",
        )
    db.add(
        CounterReset(
            counter_id=c.id,
            actor_id=actor.id,
            cycle_number=snapshot["cycle_number"],
            used_count=snapshot["used_count"],
            previous_limit=snapshot["limit_count"],
            new_limit=body.limit_count,
            cycle_started_at=snapshot["cycle_started_at"],
            reason=body.reason,
        )
    )
    audit(
        db,
        actor,
        "reset_count",
        f"{db.get(Plan, c.plan_id).name} 第 {snapshot['cycle_number']} 轮已开通 {snapshot['used_count']} 次，重置后上限 {body.limit_count}；{body.reason}",
        subject=c.user_id,
        request=request,
    )
    db.commit()
    return {"ok": True}


@app.get("/api/counter-resets")
def resets(user: User = Depends(get_user), db: Session = Depends(get_db)):
    q = (
        select(CounterReset, PlanCounter)
        .join(PlanCounter, CounterReset.counter_id == PlanCounter.id)
        .order_by(CounterReset.id.desc())
        .limit(200)
    )
    if user.role != "admin":
        q = q.where(PlanCounter.user_id == user.id)
    return [
        {
            k: getattr(r, k)
            for k in (
                "id",
                "cycle_number",
                "used_count",
                "previous_limit",
                "new_limit",
                "reason",
                "created_at",
                "cycle_started_at",
            )
        }
        | {
            "username": db.get(User, c.user_id).username,
            "plan_name": db.get(Plan, c.plan_id).name,
            "actor_name": db.get(User, r.actor_id).username,
        }
        for r, c in db.execute(q)
    ]


@app.post("/api/admin/users/{user_id}/counters/{plan_id}/reset")
def reset_configured_counter(
    user_id: int,
    plan_id: int,
    body: ConfiguredResetInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    c = db.scalar(
        select(PlanCounter).where(
            PlanCounter.user_id == user_id, PlanCounter.plan_id == plan_id
        )
    )
    if not c:
        raise HTTPException(404, "请先为该套餐设置次数")
    if c.cycle_number != body.expected_cycle:
        raise HTTPException(409, "该套餐已重置，请刷新后查看最新次数")
    return reset_counter(
        c.id,
        CounterResetInput(
            limit_count=c.limit_count, reason="子用户页面按已设置次数一键重置"
        ),
        request,
        actor,
        db,
    )


def reserve(db, user, plan_id):
    if user.role == "admin":
        return None, None
    row = db.execute(
        update(PlanCounter)
        .where(
            PlanCounter.user_id == user.id,
            PlanCounter.plan_id == plan_id,
            PlanCounter.used_count + PlanCounter.pending_count
            < PlanCounter.limit_count,
        )
        .values(pending_count=PlanCounter.pending_count + 1)
        .returning(PlanCounter.id, PlanCounter.cycle_number)
    ).first()
    if not row:
        raise HTTPException(409, "该套餐开通次数已用完或尚未设置，请联系管理员")
    return row


def owned(db, record_id, user):
    r = db.get(Subscription, record_id)
    if not r or (user.role != "admin" and r.owner_id != user.id):
        raise HTTPException(404, "创建记录不存在")
    return r


def subscription_view(r, db, actor=None, numbered=None):
    from .group_subscription_state import record_projection
    from .automatic_retries import retry_view
    return {
        k: getattr(r, k)
        for k in (
            "id",
            "owner_id",
            "aws_account_id",
            "plan_id",
            "cycle_number",
            "username",
            "email",
            "state",
            "step",
            "sso_user_id",
            "portal_url",
            "error",
            "counted",
            "attempts",
            "created_at",
            "updated_at",
            "subscribed_at",
            "subscription_type",
            "subscription_status",
            "observed_subscription_type",
            "cancelled_at",
            "cancellation_mode",
            "access_ends_at",
            "sso_display_name",
            "sso_deleted_at",
            "password_generated_at",
            "credential_state",
            "credential_revision",
            "last_synced_at",
            "provision_only",
            "batch_id",
            "group_id",
            "group_membership_id",
        )
    } | {
        **(numbered if numbered is not None else provisioning_mappings(db, [r.id])).get(r.id, {}),
        **projections(db, r),
        **record_projection(db, r),
        **retry_view(db, 'sso', r.id, active=r.state in ('queued', 'running')),
        "subscription_status": r.subscription_status
        if r.provision_only
        else "unknown"
        if r.state == "needs_review"
        else "pending"
        if r.state in ("queued", "running")
        else r.subscription_status,
        "has_password": bool(r.password_encrypted)
        and r.credential_state != "unknown"
        and not r.sso_deleted_at,
        "stop_schedule": schedule_view(db.get(StopSchedule, r.id)),
        "owner_name": db.get(User, r.owner_id).display_name,
        "account_name": db.get(AwsAccount, r.aws_account_id).name,
        "plan_name": r.plan_name_snapshot
        or (db.get(Plan, r.plan_id).name if r.plan_id else "未绑定套餐"),
        "observed_plan_name": BY_SUBSCRIPTION_TYPE.get(
            r.observed_subscription_type, {}
        ).get("name"),
        "supports_scheduled_cancellation": db.get(
            AwsAccount, r.aws_account_id
        ).control_plane
        == "kiro",
        "operation_pending": bool(r.active_operation_id),
        "operation": active_operation_view(db, r.active_operation_id, actor)
        if r.active_operation_id
        else None,
    }


def active_operation_view(db, operation_id, actor):
    from .group_jobs import job_view

    op = db.get(RecordOperation, operation_id)
    if op:
        if op.kind in AUTH_KINDS and (not actor or op.actor_id != actor.id):
            return None
        return (
            operation_view(op)
            if not actor or actor.role == "admin" or op.actor_id == actor.id
            else None
        )
    from .cascade_models import CascadeBatch, CascadeTask
    cascade = db.get(CascadeTask, operation_id)
    if cascade:
        batch = db.get(CascadeBatch, cascade.batch_id)
        if actor and actor.role != "admin" and batch.actor_id != actor.id:
            return None
        return {"id": cascade.id, "kind": "cascade_delete", "state": cascade.state,
                "error": cascade.error, "created_at": cascade.created_at,
                "finished_at": cascade.finished_at, "cascade_batch_id": cascade.batch_id}
    from .models import NativeGroupOperation
    from .group_subscriptions import operation_view as native_operation_view
    native = db.get(NativeGroupOperation, operation_id)
    if native and (not actor or actor.role == "admin" or native.owner_id == actor.id):
        return native_operation_view(native)
    job = db.get(GroupJob, operation_id)
    if job:
        from .group_member_batches import batch_for_job, batch_visible
        member_batch = batch_for_job(db, job.id)
        if member_batch:
            return job_view(job) if batch_visible(db, member_batch, actor) else None
    return (
        job_view(job)
        if job and (not actor or actor.role == "admin" or job.actor_id == actor.id)
        else None
    )


def subscription_request_hash(body: SubscriptionInput):
    exclude = {"request_key"}
    if not body.group_id:
        exclude.add("group_id")
    if body.stop_schedule is None or (
        not body.group_id and body.stop_schedule.mode == "none"
    ):
        exclude.add("stop_schedule")
    return hashlib.sha256(
        json.dumps(
            body.model_dump(mode="json", exclude=exclude), sort_keys=True
        ).encode()
    ).hexdigest()


@app.post("/api/subscriptions", status_code=202)
def create_subscription(
    body: SubscriptionInput,
    request: Request,
    user: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    from .groups import owned_group, require_group

    group = owned_group(db, body.group_id, user) if body.group_id else None
    owner = db.get(User, group.owner_id) if group else user
    payload_hash = subscription_request_hash(body)
    old = db.scalar(
        select(Subscription).where(
            Subscription.owner_id == owner.id,
            Subscription.request_key == body.request_key,
        )
    )
    if old:
        if old.request_payload_hash:
            if old.request_payload_hash != payload_hash:
                raise HTTPException(409, "重复请求标识与原请求内容不同")
            return subscription_view(old, db, user)
        # Legacy admissions have no immutable intent. Keep the conservative
        # field checks without backfilling a guess from mutable current state.
        schedule = db.get(StopSchedule, old.id)
        policy = body.stop_schedule
        if group:
            inherited = bool(
                schedule
                and schedule.source_group_id == group.id
                and not schedule.individual_override
            )
            # Equal rule values still have different future behavior when one
            # request inherits the group and the other sets an individual rule.
            if (policy is None) != inherited:
                raise HTTPException(409, "重复请求标识与原定时停止设置来源不同")
        if (not group or policy) and (
            (policy.mode if policy else "none")
            != (schedule.mode if schedule else "none")
            or (
                policy
                and schedule
                and (
                    policy.days != schedule.days
                    or (
                        policy.mode == "at"
                        and policy.stop_at.replace(tzinfo=None) != schedule.stop_at
                    )
                )
            )
        ):
            raise HTTPException(409, "重复请求标识与原定时停止设置不同")
        if (
            old.aws_account_id != body.aws_account_id
            or old.group_id != body.group_id
            or old.plan_id != body.plan_id
            or old.email != str(body.email)
            or old.username.rsplit("-", 1)[0] != body.username
        ):
            raise HTTPException(409, "重复请求标识与原请求内容不同")
        return subscription_view(old, db, user)
    a = db.get(AwsAccount, body.aws_account_id)
    p = db.get(Plan, body.plan_id)
    if (
        not a
        or a.deleted_at
        or not a.active
        or (user.role != "admin" and not db.get(Binding, (user.id, a.id)))
    ):
        raise HTTPException(403, "无权使用该 AWS 账号")
    if not p or p.deleted_at or not p.active:
        raise HTTPException(404, "套餐不存在或已停用")
    if group:
        require_group(db, group.id, user, a.id, owner.id)
        from .batches import require_account

        require_account(db, owner, a)
        if not owner.active or owner.deleted_at:
            raise HTTPException(409, "分组所有者已停用")
    if group:
        from .group_subscription_state import live_grant
        if live_grant(db, group.id):
            raise HTTPException(409, "原生订阅分组会自动授权，请通过仅创建 SSO 加入分组")
    counter_id, cycle = reserve(db, owner, p.id)
    record_id = str(uuid.uuid4())
    r = Subscription(
        id=record_id,
        owner_id=owner.id,
        group_id=body.group_id,
        aws_account_id=a.id,
        plan_id=p.id,
        counter_id=counter_id,
        cycle_number=cycle,
        request_key=body.request_key,
        request_payload_hash=payload_hash,
        username=f"{body.username}-{record_id[:8]}",
        email=str(body.email),
        portal_url=a.portal_url,
        subscription_type=p.subscription_type,
        plan_name_snapshot=p.name,
        reserved=counter_id is not None,
    )
    db.add(r)
    db.flush()
    if body.stop_schedule:
        configure(db, r, user, body.stop_schedule, request, preserve_none=True)
    elif group:
        from .group_policies import inherit

        inherit(db, r, user, request)
    from .group_policies import ensure_paid_deadline

    ensure_paid_deadline(db, r)
    audit(
        db,
        user,
        "request_subscription",
        f"创建 {p.name}：{r.username}",
        subject=user.id,
        request=request,
    )
    db.commit()
    return subscription_view(r, db, user)


@app.get("/api/subscriptions")
def subscriptions(
    state: str | None = None,
    q: str = "",
    owner_id: int | None = None,
    group_id: str | None = None,
    aws_account_id: int | None = None,
    page: int = Query(1, ge=1),
    user: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    if group_id:
        from .groups import owned_group

        owned_group(db, group_id, user)
    query = record_query(user, q, owner_id, group_id, aws_account_id)
    if state:
        query = query.where(Subscription.state == state)
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(
        query.order_by(Subscription.created_at.desc(), Subscription.id.desc())
        .offset((page - 1) * 30)
        .limit(30)
    )
    rows = list(rows)
    numbered = provisioning_mappings(db, [r.id for r in rows])
    return {
        "items": [subscription_view(r, db, user, numbered) for r in rows],
        "total": total,
        "page": page,
        "page_size": 30,
    }


@app.get("/api/sso-users")
def sso_users(
    q: str = "",
    status: str = "all",
    owner_id: int | None = None,
    group_id: str | None = None,
    aws_account_id: int | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(30, ge=1, le=100),
    user: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    if group_id:
        from .groups import owned_group

        owned_group(db, group_id, user)
    query = sso_query(user, status, q, owner_id, group_id, aws_account_id)
    total = db.scalar(select(func.count()).select_from(query.subquery()))
    rows = db.scalars(
        query.order_by(Subscription.created_at.desc(), Subscription.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = list(rows)
    numbered = provisioning_mappings(db, [r.id for r in rows])
    return {
        "items": [subscription_view(r, db, user, numbered) for r in rows],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


@app.get("/api/subscriptions/{record_id}")
def detail(
    record_id: str, user: User = Depends(get_user), db: Session = Depends(get_db)
):
    return subscription_view(owned(db, record_id, user), db, user)


@app.post("/api/subscriptions/{record_id}/credentials")
def credentials(
    record_id: str,
    request: Request,
    user: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    from .lifecycle import allowed

    r = owned(db, record_id, user)
    if not allowed(db, user, db.get(AwsAccount, r.aws_account_id)):
        raise HTTPException(403, "AWS 账号或绑定已停用，不能查看登录凭据")
    if r.sso_deleted_at:
        raise HTTPException(409, "SSO 用户已删除，登录信息已失效")
    if r.credential_state == "unknown":
        raise HTTPException(409, "密码状态未知，请先明确重置或恢复密码")
    if not r.password_encrypted:
        raise HTTPException(409, "一次性密码尚未生成")
    audit(
        db,
        user,
        "view_credentials",
        f"查看登录信息：{r.username}",
        subject=r.owner_id,
        request=request,
    )
    db.commit()
    return {
        **provisioning_mappings(db, [r.id]).get(r.id, {}),
        "username": r.username,
        "password": decrypt(r.password_encrypted),
        "portal_url": r.portal_url,
        "region": db.get(AwsAccount, r.aws_account_id).region,
        "generated_at": r.password_generated_at,
        "credential_state": r.credential_state,
        "credential_revision": r.credential_revision,
    }


@app.post("/api/subscriptions/{record_id}/retry", status_code=202)
def retry(
    record_id: str,
    request: Request,
    user: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    r = owned(db, record_id, user)
    from .subscription_recovery import queue_retry
    queue_retry(db, r, user)
    audit(
        db,
        user,
        "retry_subscription",
        f"继续处理：{r.username}",
        subject=r.owner_id,
        request=request,
    )
    update_batch_item(db, r, "queued")
    db.commit()
    return {"ok": True}


@app.get("/api/overview")
def overview(user: User = Depends(get_user), db: Session = Depends(get_db)):
    summary = {}
    for state, count in db.execute(
        select(Subscription.state, func.count())
        .where(True if user.role == "admin" else Subscription.owner_id == user.id)
        .group_by(Subscription.state)
    ):
        summary[state] = count
    result = {
        "states": summary,
        "total": sum(summary.values()),
        "subscribed": db.scalar(
            select(func.count())
            .select_from(Subscription)
            .where(
                Subscription.counted.is_(True),
                True if user.role == "admin" else Subscription.owner_id == user.id,
            )
        ),
        "counters": counters(None, user, db),
        **lifecycle_totals(db, None if user.role == "admin" else user.id),
    }
    if user.role == "admin":
        result["member_summary"] = user_summary(db)
        result["members"] = len(result["member_summary"]["users"])
        result["aws_accounts"] = db.scalar(
            select(func.count())
            .select_from(AwsAccount)
            .where(AwsAccount.deleted_at.is_(None))
        )
        try:
            result["backup"] = json.loads(settings.backup_status_path.read_text())
            if result["backup"].get("status") == "ok":
                completed = datetime.fromisoformat(
                    result["backup"]["completed_at"].replace("Z", "+00:00")
                )
                if datetime.now(timezone.utc) - completed > timedelta(minutes=90):
                    result["backup"]["status"] = "stale"
        except (OSError, ValueError, KeyError, TypeError):
            result["backup"] = {"status": "not_configured"}
    return result


@app.post("/api/admin/subscriptions/{record_id}/resolve-unsubscribed")
def resolve_unsubscribed(
    record_id: str,
    body: ResolveUnsubscribedInput,
    request: Request,
    actor: User = Depends(admin),
    db: Session = Depends(get_db),
):
    r = owned(db, record_id, actor)
    if r.state != "needs_review" or r.step != "subscribe_pending":
        raise HTTPException(409, "仅待核对订阅可以进行此操作")
    if now() - r.updated_at < timedelta(minutes=10):
        raise HTTPException(409, "请等待至少 10 分钟，让 AWS 完成同步后再核实")
    if aws.AwsGateway(db.get(AwsAccount, r.aws_account_id)).is_subscribed(r):
        raise HTTPException(409, "AWS 已存在该订阅，请使用“核对结果”记录成功次数")
    # Require both an administrator's explicit AWS check and a fresh API read.
    changed = db.execute(
        update(Subscription)
        .where(
            Subscription.id == r.id,
            Subscription.state == "needs_review",
            Subscription.updated_at == r.updated_at,
        )
        .values(
            state="failed",
            step="subscribe",
            reserved=False,
            updated_at=now(),
            error="管理员已核实 AWS 尚未开通，可按需继续处理",
        )
    )
    if not changed.rowcount:
        raise HTTPException(409, "记录刚发生变更，请刷新后重试")
    if r.counter_id:
        released = db.execute(
            update(PlanCounter)
            .where(
                PlanCounter.id == r.counter_id,
                PlanCounter.cycle_number == r.cycle_number,
                PlanCounter.pending_count > 0,
            )
            .values(pending_count=PlanCounter.pending_count - 1)
        )
        if not released.rowcount:
            raise HTTPException(409, "次数记录不一致，请检查任务")
    audit(
        db,
        actor,
        "resolve_unsubscribed",
        f"核实未开通并释放预占：{r.username}；{body.reason}",
        subject=r.owner_id,
        request=request,
    )
    update_batch_item(db, r, "failed", "管理员已核实 AWS 尚未开通，可按需继续处理")
    db.commit()
    return {"ok": True}


@app.get("/api/audit")
def audit_logs(
    page: int = Query(1, ge=1),
    user: User = Depends(get_user),
    db: Session = Depends(get_db),
):
    q = select(AuditEvent)
    if user.role != "admin":
        q = q.where(AuditEvent.actor_id == user.id)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    return {
        "items": [
            {
                k: getattr(e, k)
                for k in ("id", "actor_name", "action", "detail", "created_at")
            }
            for e in db.scalars(
                q.order_by(AuditEvent.id.desc()).offset((page - 1) * 30).limit(30)
            )
        ],
        "total": total,
        "page": page,
    }


register_batch_routes(app, reserve)

if settings.frontend_dir.exists():
    app.mount(
        "/assets",
        StaticFiles(directory=settings.frontend_dir / "assets"),
        name="assets",
    )

    @app.get("/{path:path}")
    def frontend(path: str):
        if path.startswith(("api/", "health")):
            raise HTTPException(404)
        return FileResponse(settings.frontend_dir / "index.html")
