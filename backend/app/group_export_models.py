"""Frozen, secret-free scopes for existing native JSON authentication batches."""

from datetime import datetime
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base
from .models import now


class GroupExportPreview(Base):
    __tablename__ = 'console_group_export_previews'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey('console_users.id'), index=True)
    actor_role: Mapped[str] = mapped_column(String(20))
    session_version: Mapped[int]
    group_ids: Mapped[str] = mapped_column(Text)
    snapshot: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=now)
    expires_at: Mapped[datetime]


class AuthExportScope(Base):
    __tablename__ = 'console_auth_export_scopes'
    batch_id: Mapped[str] = mapped_column(ForeignKey('console_auth_batches.id'), primary_key=True)
    preview_id: Mapped[str] = mapped_column(ForeignKey('console_group_export_previews.id'))
    actor_role: Mapped[str] = mapped_column(String(20))
    payload_hash: Mapped[str] = mapped_column(String(64))
    snapshot: Mapped[str] = mapped_column(Text)


class AuthExportMember(Base):
    __tablename__ = 'console_auth_export_members'
    batch_id: Mapped[str] = mapped_column(ForeignKey('console_auth_batches.id'), primary_key=True)
    record_id: Mapped[str] = mapped_column(ForeignKey('console_subscriptions.id'), primary_key=True)
    group_id: Mapped[str] = mapped_column(ForeignKey('console_groups.id'), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey('console_users.id'))
    aws_account_id: Mapped[int] = mapped_column(ForeignKey('console_aws_accounts.id'))
    username: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(254))
    sso_user_id: Mapped[str] = mapped_column(String(100))
    membership_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    config_hash: Mapped[str] = mapped_column(String(64))
    member_path: Mapped[str] = mapped_column(Text)
