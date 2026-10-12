"""Actor-private, short lived credentials and results for pasted SSO exports."""
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base
from .models import now


class ExternalExportBatch(Base):
    __tablename__ = 'console_external_export_batches'
    __table_args__ = (UniqueConstraint('actor_id', 'request_key'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey('console_users.id'), index=True)
    actor_role: Mapped[str] = mapped_column(String(20))
    session_version: Mapped[int] = mapped_column(Integer)
    request_key: Mapped[str] = mapped_column(String(80))
    payload_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(20), default='active')
    created_at: Mapped[datetime] = mapped_column(default=now)
    expires_at: Mapped[datetime] = mapped_column()
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    download_expires_at: Mapped[datetime | None] = mapped_column(nullable=True)


class ExternalExportItem(Base):
    __tablename__ = 'console_external_export_items'
    __table_args__ = (UniqueConstraint('batch_id', 'position'),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey('console_external_export_batches.id'), index=True)
    position: Mapped[int] = mapped_column(Integer)
    principal_key: Mapped[str] = mapped_column(String(64), index=True)
    lane_id: Mapped[int] = mapped_column(Integer, index=True)
    username: Mapped[str] = mapped_column(String(256))
    portal_url: Mapped[str] = mapped_column(Text)
    region: Mapped[str | None] = mapped_column(String(40), nullable=True)
    configuration: Mapped[str] = mapped_column(Text)
    input_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    workflow_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    answer_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    credential_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str] = mapped_column(String(20), default='queued')
    stage: Mapped[str] = mapped_column(String(50), default='admitted')
    error_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    revision: Mapped[int] = mapped_column(Integer, default=0)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    next_poll_at: Mapped[datetime | None] = mapped_column(nullable=True)
    lease_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
