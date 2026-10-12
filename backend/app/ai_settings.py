"""Tenant-owned vision settings. Secrets never appear in API views or audits."""
import re
import struct
from typing import Literal
import zlib

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator, model_validator
from sqlalchemy.orm import Session

from .database import SessionLocal, get_db
from .models import AiProviderSettings, User, now
from .security import audit, decrypt, encrypt, get_user
from .vision_captcha import DEFAULT_ENDPOINT, DEFAULT_MODEL, VisionError, VisionProvider, normalize_endpoint

router = APIRouter(prefix="/api/ai-settings")
Protocol = Literal["claude_messages", "openai_chat", "openai_responses"]


class SaveSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    revision: int = Field(ge=0, strict=True)
    protocol: Protocol
    endpoint: str = Field(min_length=1, max_length=2048)
    model: str = Field(min_length=1, max_length=200)
    api_key: SecretStr | None = None
    clear_key: bool = False
    enabled: bool = False
    timeout_seconds: int = Field(default=20, ge=1, le=60, strict=True)

    @field_validator("api_key")
    @classmethod
    def valid_key(cls, value):
        if value is not None:
            key = value.get_secret_value()
            if len(key) > 4096 or any(not 33 <= ord(c) <= 126 for c in key):
                raise ValueError("密钥格式不正确")
        return value

    @field_validator("model")
    @classmethod
    def valid_model(cls, value):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}", value):
            raise ValueError("模型名称格式不正确")
        return value

    @model_validator(mode="after")
    def valid_configuration(self):
        try:
            self.endpoint = normalize_endpoint(self.endpoint, self.protocol)
        except VisionError:
            raise ValueError("请填写与协议匹配的公网 HTTPS 接口地址") from None
        if self.clear_key and self.api_key and self.api_key.get_secret_value():
            raise ValueError("更换密钥和清除密钥不能同时选择")
        return self


class TestSettings(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    revision: int = Field(ge=1, strict=True)


def view(row):
    return {
        "revision": row.revision if row else 0,
        "protocol": row.protocol if row else "claude_messages",
        "endpoint": row.endpoint if row else DEFAULT_ENDPOINT,
        "model": row.model if row else DEFAULT_MODEL,
        "enabled": row.enabled if row else False,
        "timeout_seconds": row.timeout_seconds if row else 20,
        "key_configured": bool(row and row.key_encrypted),
        "updated_at": row.updated_at if row else None,
    }


def provider_for_actor(actor_id, *, expected_revision=None, transport=None):
    """Select by task initiator, never account owner/admin/global environment."""
    with SessionLocal() as db:
        actor = db.get(User, actor_id)
        row = db.get(AiProviderSettings, actor_id)
        if (not actor or not actor.active or actor.deleted_at or actor.must_change_password
            or not row or not row.enabled or not row.key_encrypted
            or expected_revision is not None and row.revision != expected_revision):
            return None
        try:
            provider = VisionProvider(
                decrypt(row.key_encrypted), protocol=row.protocol,
                endpoint=row.endpoint, model=row.model,
                timeout_seconds=row.timeout_seconds, transport=transport,
            )
            provider._validate_configuration()
        except Exception:
            # Unreadable/replaced encryption keys require explicit configuration.
            return None
        revision, session_version = row.revision, actor.session_version
        def check_current():
            with SessionLocal() as current_db:
                current_actor = current_db.get(User, actor_id)
                current = current_db.get(AiProviderSettings, actor_id)
                if (not current_actor or not current_actor.active or current_actor.deleted_at
                    or current_actor.must_change_password or current_actor.session_version != session_version
                    or not current or not current.enabled or current.revision != revision):
                    raise VisionError("captcha_unavailable")
        provider.configuration_guard = check_current
        return provider


@router.get("")
def read(actor: User = Depends(get_user), db: Session = Depends(get_db)):
    return view(db.get(AiProviderSettings, actor.id))


@router.put("")
def save(body: SaveSettings, request: Request, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    row = db.get(AiProviderSettings, actor.id)
    if body.revision != (row.revision if row else 0):
        raise HTTPException(409, "设置已在其他窗口更新，请刷新后重新填写")
    key = body.api_key.get_secret_value() if body.api_key else ""
    encrypted = encrypt(key) if key else row.key_encrypted if row else None
    if body.clear_key:
        encrypted = None
    if body.enabled and not encrypted:
        raise HTTPException(422, "启用自动识别前请先保存自己的 API 密钥")
    if row is None:
        row = AiProviderSettings(user_id=actor.id, revision=0)
        db.add(row)
    row.protocol, row.endpoint, row.model = body.protocol, body.endpoint, body.model
    row.enabled, row.timeout_seconds = body.enabled, body.timeout_seconds
    row.key_encrypted, row.updated_at = encrypted, now()
    row.revision += 1
    audit(db, actor, "ai_settings_updated", "更新个人 AI 识别设置", subject=actor.id, request=request)
    db.commit()
    return view(row)


def synthetic_image():
    """Small, fixed TEST42 PNG; the test endpoint never accepts account images."""
    font = {
        "T": (31, 4, 4, 4, 4, 4, 4), "E": (31, 16, 16, 30, 16, 16, 31),
        "S": (15, 16, 16, 14, 1, 1, 30), "4": (2, 6, 10, 18, 31, 2, 2),
        "2": (14, 17, 1, 2, 4, 8, 31),
    }
    scale, margin = 5, 10
    width, height = 6 * 6 * scale + margin * 2, 7 * scale + margin * 2
    pixels = bytearray()
    for y in range(height):
        pixels.append(0)
        for x in range(width):
            gx, gy = x - margin, y - margin
            dark = False
            if 0 <= gy < 7 * scale and 0 <= gx < 6 * 6 * scale:
                index, column = divmod(gx // scale, 6)
                dark = column < 5 and bool(font["TEST42"[index]][gy // scale] & (1 << (4 - column)))
            pixels.append(0 if dark else 255)
    def chunk(kind, data):
        return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack("!IIBBBBB", width, height, 8, 0, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b""))


@router.post("/test")
def test_saved(body: TestSettings, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    row = db.get(AiProviderSettings, actor.id)
    if not row or row.revision != body.revision:
        raise HTTPException(409, "设置已更改，请刷新后测试已保存配置")
    actor_id, session_version = actor.id, actor.session_version
    db.commit()  # A remote request must never hold the SQLite write lock.
    provider = provider_for_actor(actor_id, expected_revision=body.revision)
    if provider is None:
        raise HTTPException(409, "请先保存并启用自己的 AI 识别配置")
    try:
        answer = provider.recognize(synthetic_image())
        result = {"ok": answer == "TEST42", "code": "ok" if answer == "TEST42" else "recognition_mismatch"}
    except VisionError as error:
        result = {"ok": False, "code": error.code}
    db.expire_all()
    current, row = db.get(User, actor_id), db.get(AiProviderSettings, actor_id)
    if not current or not current.active or current.deleted_at or current.session_version != session_version:
        raise HTTPException(401, "登录已过期，请重新登录")
    if not row or row.revision != body.revision:
        raise HTTPException(409, "测试期间配置已更改，请使用最新配置重新测试")
    return result
