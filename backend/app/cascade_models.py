"""Durable, secret-free previews and cancel-first deletion checkpoints."""

from datetime import datetime

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base
from .models import now


class CascadePreview(Base):
    __tablename__ = 'console_cascade_previews'
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey('console_users.id'), index=True)
    actor_role: Mapped[str] = mapped_column(String(20))
    session_version: Mapped[int]
    intent: Mapped[str] = mapped_column(Text)
    snapshot: Mapped[str] = mapped_column(Text)
    fingerprint: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=now)
    expires_at: Mapped[datetime]


class CascadeBatch(Base):
    __tablename__ = 'console_cascade_batches'
    __table_args__ = (UniqueConstraint('actor_id', 'request_key'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey('console_users.id'), index=True)
    authorized_actor_id: Mapped[int] = mapped_column(ForeignKey('console_users.id'))
    actor_role: Mapped[str] = mapped_column(String(20))
    session_version: Mapped[int]
    preview_id: Mapped[str] = mapped_column(ForeignKey('console_cascade_previews.id'))
    request_key: Mapped[str] = mapped_column(String(80))
    payload_hash: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(10))
    confirm_text: Mapped[str] = mapped_column(String(160))
    created_at: Mapped[datetime] = mapped_column(default=now, index=True)
    updated_at: Mapped[datetime] = mapped_column(default=now)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)


class CascadeTask(Base):
    __tablename__ = 'console_cascade_tasks'
    __table_args__ = (UniqueConstraint('batch_id', 'position'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey('console_cascade_batches.id'), index=True)
    position: Mapped[int]
    owner_id: Mapped[int] = mapped_column(ForeignKey('console_users.id'))
    aws_account_id: Mapped[int] = mapped_column(ForeignKey('console_aws_accounts.id'), index=True)
    target_id: Mapped[str] = mapped_column(String(36))
    group_id: Mapped[str | None] = mapped_column(ForeignKey('console_groups.id'), nullable=True, index=True)
    snapshot: Mapped[str] = mapped_column(Text)
    actions: Mapped[str] = mapped_column(Text)
    cursor: Mapped[int] = mapped_column(default=0)
    state: Mapped[str] = mapped_column(String(30), default='queued', index=True)
    phase: Mapped[str] = mapped_column(String(40), default='ready')
    attempts: Mapped[int] = mapped_column(default=0)
    lease_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)
    updated_at: Mapped[datetime] = mapped_column(default=now)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)


class CascadeAction(Base):
    __tablename__ = 'console_cascade_actions'
    __table_args__ = (UniqueConstraint('batch_id', 'actor_id', 'request_key'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey('console_cascade_batches.id'), index=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey('console_users.id'))
    request_key: Mapped[str] = mapped_column(String(80))
    kind: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(default=now)
