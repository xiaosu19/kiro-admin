import hmac
import json
from datetime import timedelta

import bcrypt
import jwt
from cryptography.fernet import Fernet
from fastapi import Depends, HTTPException, Request
from sqlalchemy import update
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import AuditEvent, User, now

fernet = Fernet(settings.fernet_key.encode())
if len(settings.secret_key) < 32:
    raise RuntimeError("SECRET_KEY 至少需要 32 个字符")


def encrypt(value):
    return fernet.encrypt(json.dumps(value).encode()).decode()


def decrypt(value):
    return json.loads(fernet.decrypt(value.encode()))


def hash_password(password):
    if not 12 <= len(password) or len(password.encode()) > 72:
        raise HTTPException(422, "密码至少 12 个字符，UTF-8 长度最多 72 字节")
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password, hashed):
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False


def make_token(user, csrf):
    return jwt.encode(
        {
            "sub": str(user.id),
            "sv": user.session_version,
            "csrf": csrf,
            "exp": now() + timedelta(hours=settings.session_hours),
        },
        settings.secret_key,
        algorithm="HS256",
    )


def lock_user_write(db, user, session_version):
    valid = db.execute(
        update(User)
        .where(
            User.id == user.id,
            User.session_version == session_version,
            User.active.is_(True),
            User.deleted_at.is_(None),
        )
        .values(session_version=User.session_version)
        .execution_options(synchronize_session=False, autoflush=False)
    )
    if not valid.rowcount:
        raise HTTPException(401, "登录已过期，请重新登录")
    db.refresh(user)


def get_user(request: Request, db: Session = Depends(get_db)):
    try:
        claims = jwt.decode(
            request.cookies.get("kiro_session", ""),
            settings.secret_key,
            algorithms=["HS256"],
        )
        user = db.get(User, int(claims["sub"]))
        if (
            not user
            or not user.active
            or user.deleted_at
            or user.session_version != claims["sv"]
        ):
            raise ValueError()
    except (jwt.PyJWTError, ValueError, KeyError):
        raise HTTPException(401, "登录已过期，请重新登录")
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if not hmac.compare_digest(
            request.headers.get("X-CSRF-Token", ""), claims["csrf"]
        ):
            raise HTTPException(403, "请求校验失败，请刷新页面")
        # Serialize admission with role changes/deletion. A request that read an
        # old session before another admin revoked it must not mutate afterward.
        # AWS configuration endpoints verify remotely before acquiring this lock.
        remote_validation = (
            (
                request.method == "POST"
                and request.url.path in ("/api/admin/aws", "/api/admin/aws/discover")
            )
            or (
                request.method == "PUT"
                and request.url.path.startswith("/api/admin/aws/")
            )
            or (
                request.method == "POST"
                and request.url.path.startswith("/api/admin/proxies/")
                and request.url.path.endswith("/probe")
            )
        )
        if not remote_validation:
            lock_user_write(db, user, claims["sv"])
    if user.must_change_password and request.url.path not in (
        "/api/auth/me",
        "/api/auth/change-password",
        "/api/auth/logout",
    ):
        raise HTTPException(403, "请先修改初始密码")
    request.state.csrf = claims["csrf"]
    return user


def admin(user: User = Depends(get_user)):
    if user.role != "admin":
        raise HTTPException(403, "需要管理员权限")
    return user


def audit(db, actor, action, detail, subject=None, request=None):
    db.add(
        AuditEvent(
            actor_id=actor.id if actor else None,
            actor_name=actor.username if actor else "系统",
            action=action,
            detail=detail,
            subject_user_id=subject,
            ip=request.client.host if request and request.client else None,
        )
    )


def user_view(user):
    return {
        k: getattr(user, k)
        for k in (
            "id",
            "username",
            "display_name",
            "role",
            "active",
            "must_change_password",
            "created_at",
        )
    }
