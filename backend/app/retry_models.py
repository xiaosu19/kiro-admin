"""Independent durable recovery metadata; never stores request or credential data."""

from datetime import datetime

from sqlalchemy import Boolean, CheckConstraint, String
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base
from .models import now


class AutomaticRetry(Base):
    __tablename__ = "console_automatic_retries"
    __table_args__ = (CheckConstraint("retry_count BETWEEN 0 AND 5"),)

    family: Mapped[str] = mapped_column(String(20), primary_key=True)
    job_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    retry_count: Mapped[int] = mapped_column(default=0)
    next_retry_at: Mapped[datetime | None] = mapped_column(nullable=True, index=True)
    error_code: Mapped[str | None] = mapped_column(String(60), nullable=True)
    mode: Mapped[str] = mapped_column(String(20), default="retry")
    config_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    exhausted: Mapped[bool] = mapped_column(Boolean, default=False)
    propagation_started_at: Mapped[datetime | None] = mapped_column(nullable=True)
    propagation_last_checked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    propagation_check_count: Mapped[int] = mapped_column(default=0)
    updated_at: Mapped[datetime] = mapped_column(default=now)
