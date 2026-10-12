from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "console_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True)
    display_name: Mapped[str] = mapped_column(String(100))
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(20), default="member")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=True)
    session_version: Mapped[int] = mapped_column(default=1)
    created_at: Mapped[datetime] = mapped_column(default=now)
    deleted_at: Mapped[datetime | None] = mapped_column(nullable=True)


class AiProviderSettings(Base):
    __tablename__ = "console_ai_provider_settings"
    __table_args__ = (
        CheckConstraint("protocol IN ('claude_messages', 'openai_chat', 'openai_responses')"),
        CheckConstraint("timeout_seconds BETWEEN 1 AND 60 AND revision >= 1"),
    )
    user_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), primary_key=True)
    protocol: Mapped[str] = mapped_column(String(30))
    endpoint: Mapped[str] = mapped_column(String(2048))
    model: Mapped[str] = mapped_column(String(200))
    key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    timeout_seconds: Mapped[int] = mapped_column(default=20)
    revision: Mapped[int] = mapped_column(default=1)
    updated_at: Mapped[datetime] = mapped_column(default=now)


class Proxy(Base):
    __tablename__ = "console_proxies"
    # An in-flight validation must never mistake a replacement row for its
    # deleted selection, even if it was the highest/last proxy in the pool.
    __table_args__ = {"sqlite_autoincrement": True}
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    host: Mapped[str] = mapped_column(String(45))
    port: Mapped[int] = mapped_column(Integer)
    auth_encrypted: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    revision: Mapped[int] = mapped_column(Integer, default=1)
    last_probe_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    last_probe_at: Mapped[datetime | None] = mapped_column(nullable=True)
    egress_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)


class AwsAccount(Base):
    __tablename__ = "console_aws_accounts"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    account_number: Mapped[str | None] = mapped_column(String(24), nullable=True)
    aws_account_id: Mapped[str] = mapped_column(String(12))
    region: Mapped[str] = mapped_column(String(40))
    subscription_region: Mapped[str] = mapped_column(String(40), default="us-east-1")
    control_plane: Mapped[str] = mapped_column(String(20), default="legacy")
    identity_store_id: Mapped[str] = mapped_column(String(100))
    instance_arn: Mapped[str] = mapped_column(String(200))
    application_arn: Mapped[str] = mapped_column(String(200))
    profile_arn: Mapped[str] = mapped_column(String(200))
    portal_url: Mapped[str] = mapped_column(Text)
    credentials_encrypted: Mapped[str] = mapped_column(Text)
    proxy_id: Mapped[int | None] = mapped_column(
        ForeignKey("console_proxies.id"), nullable=True, index=True
    )
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    deleted_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)


class AwsAccountNumber(Base):
    """An issued code belongs to its configuration forever, including deletion."""
    __tablename__ = "console_aws_account_numbers"
    number: Mapped[str] = mapped_column(String(24), primary_key=True)
    aws_account_id: Mapped[int] = mapped_column(ForeignKey("console_aws_accounts.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(default=now)


class ProvisioningCounter(Base):
    __tablename__ = "console_provisioning_counters"
    __table_args__ = (CheckConstraint("last_sequence >= 0"),)
    aws_account_id: Mapped[int] = mapped_column(ForeignKey("console_aws_accounts.id"), primary_key=True)
    last_sequence: Mapped[int] = mapped_column(default=0)


class ProvisioningBatch(Base):
    __tablename__ = "console_provisioning_batches"
    __table_args__ = (UniqueConstraint("actor_id", "request_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), index=True)
    actor_role: Mapped[str] = mapped_column(String(20))
    session_version: Mapped[int]
    request_key: Mapped[str] = mapped_column(String(80))
    payload_hash: Mapped[str] = mapped_column(String(64))
    intent: Mapped[str] = mapped_column(Text)
    preview_fingerprint: Mapped[str] = mapped_column(String(64))
    totals: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    phase: Mapped[str] = mapped_column(String(30), default="admitted")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now, index=True)
    updated_at: Mapped[datetime] = mapped_column(default=now)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)


class ProvisioningAccountBatch(Base):
    __tablename__ = "console_provisioning_account_batches"
    __table_args__ = (
        UniqueConstraint("batch_id", "aws_account_id"),
        UniqueConstraint("batch_id", "position"),
        UniqueConstraint("aws_account_id", "sequence"),
        UniqueConstraint("batch_number"),
        CheckConstraint("quantity BETWEEN 1 AND 100 AND sequence >= 1 AND position >= 1"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("console_provisioning_batches.id"), index=True)
    position: Mapped[int]
    aws_account_id: Mapped[int] = mapped_column(ForeignKey("console_aws_accounts.id"), index=True)
    account_number: Mapped[str] = mapped_column(String(24))
    sequence: Mapped[int]
    batch_number: Mapped[str] = mapped_column(String(50))
    config_hash: Mapped[str] = mapped_column(String(64))
    quantity: Mapped[int]
    plan_id: Mapped[int] = mapped_column(ForeignKey("console_plans.id"))
    plan_name: Mapped[str] = mapped_column(String(100))
    subscription_type: Mapped[str] = mapped_column(String(100))
    group_mode: Mapped[str] = mapped_column(String(10))
    group_id: Mapped[str | None] = mapped_column(ForeignKey("console_groups.id"), nullable=True, index=True)
    group_name: Mapped[str] = mapped_column(String(1024))
    stop_policy: Mapped[str] = mapped_column(Text)
    exports: Mapped[str] = mapped_column(Text)
    snapshot: Mapped[str] = mapped_column(Text)
    needed_count: Mapped[int]
    group_job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    native_operation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    native_request_key: Mapped[str | None] = mapped_column(String(80), nullable=True)
    native_grant_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    policy_applied_revision: Mapped[int | None] = mapped_column(nullable=True)
    stop_requested_at: Mapped[datetime | None] = mapped_column(nullable=True)
    state: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    phase: Mapped[str] = mapped_column(String(30), default="admitted")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)
    updated_at: Mapped[datetime] = mapped_column(default=now)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)


class ProvisioningItem(Base):
    __tablename__ = "console_provisioning_items"
    __table_args__ = (
        UniqueConstraint("account_batch_id", "position"),
        UniqueConstraint("internal_id"),
        UniqueConstraint("username"),
        CheckConstraint("position BETWEEN 1 AND 100"),
    )
    # Admission precedes the ordinary Subscription row with this exact UUID.
    record_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    account_batch_id: Mapped[str] = mapped_column(ForeignKey("console_provisioning_account_batches.id"), index=True)
    position: Mapped[int]
    internal_id: Mapped[str] = mapped_column(String(60))
    username: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(254))
    sso_batch_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    auth_batch_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    auth_job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    export_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime | None] = mapped_column(nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)
    state: Mapped[str] = mapped_column(String(30), default="queued")
    phase: Mapped[str] = mapped_column(String(30), default="admitted")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)


class ProvisioningAction(Base):
    __tablename__ = "console_provisioning_actions"
    __table_args__ = (UniqueConstraint("account_batch_id", "actor_id", "request_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    account_batch_id: Mapped[str] = mapped_column(ForeignKey("console_provisioning_account_batches.id"))
    actor_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"))
    request_key: Mapped[str] = mapped_column(String(80))
    kind: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(default=now)


class Binding(Base):
    __tablename__ = "console_bindings"
    user_id: Mapped[int] = mapped_column(
        ForeignKey("console_users.id"), primary_key=True
    )
    aws_account_id: Mapped[int] = mapped_column(
        ForeignKey("console_aws_accounts.id"), primary_key=True
    )
    created_at: Mapped[datetime] = mapped_column(default=now)


class Plan(Base):
    __tablename__ = "console_plans"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    code: Mapped[str] = mapped_column(String(50), unique=True)
    subscription_type: Mapped[str] = mapped_column(String(100), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    deleted_at: Mapped[datetime | None] = mapped_column(nullable=True)


class PlanCounter(Base):
    __tablename__ = "console_plan_counters"
    __table_args__ = (
        UniqueConstraint("user_id", "plan_id"),
        CheckConstraint("used_count >= 0 AND pending_count >= 0 AND limit_count >= 0"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), index=True)
    plan_id: Mapped[int] = mapped_column(ForeignKey("console_plans.id"))
    limit_count: Mapped[int] = mapped_column(default=0)
    used_count: Mapped[int] = mapped_column(default=0)
    pending_count: Mapped[int] = mapped_column(default=0)
    lifetime_count: Mapped[int] = mapped_column(default=0)
    cycle_number: Mapped[int] = mapped_column(default=1)
    cycle_started_at: Mapped[datetime] = mapped_column(default=now)


class CounterReset(Base):
    __tablename__ = "console_counter_resets"
    id: Mapped[int] = mapped_column(primary_key=True)
    counter_id: Mapped[int] = mapped_column(
        ForeignKey("console_plan_counters.id"), index=True
    )
    actor_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"))
    cycle_number: Mapped[int]
    used_count: Mapped[int]
    previous_limit: Mapped[int]
    new_limit: Mapped[int]
    reason: Mapped[str] = mapped_column(String(500))
    cycle_started_at: Mapped[datetime]
    created_at: Mapped[datetime] = mapped_column(default=now)


class ManagedGroup(Base):
    __tablename__ = "console_groups"
    __table_args__ = (
        UniqueConstraint("owner_id", "request_key"),
        UniqueConstraint("aws_scope", "remote_id"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), index=True)
    aws_account_id: Mapped[int] = mapped_column(ForeignKey("console_aws_accounts.id"))
    # Canonical remote namespace: configuration aliases cannot split ownership.
    aws_scope: Mapped[str] = mapped_column(String(160), index=True)
    request_key: Mapped[str] = mapped_column(String(80))
    payload_hash: Mapped[str] = mapped_column(String(64))
    name: Mapped[str] = mapped_column(String(1024))
    marker: Mapped[str] = mapped_column(String(100))
    remote_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    state: Mapped[str] = mapped_column(String(30), default="creating", index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    revision: Mapped[int] = mapped_column(default=1)
    active_job_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    policy_mode: Mapped[str] = mapped_column(String(20), default="none")
    policy_days: Mapped[int | None] = mapped_column(nullable=True)
    policy_stop_at: Mapped[datetime | None] = mapped_column(nullable=True)
    policy_revision: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(default=now)
    updated_at: Mapped[datetime] = mapped_column(default=now)
    deleted_at: Mapped[datetime | None] = mapped_column(nullable=True)


class GroupJob(Base):
    __tablename__ = "console_group_jobs"
    __table_args__ = (UniqueConstraint("group_id", "request_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    group_id: Mapped[str] = mapped_column(ForeignKey("console_groups.id"), index=True)
    record_id: Mapped[str | None] = mapped_column(
        ForeignKey("console_subscriptions.id"), nullable=True
    )
    actor_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"))
    kind: Mapped[str] = mapped_column(String(30))
    request_key: Mapped[str] = mapped_column(String(80))
    payload: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    phase: Mapped[str] = mapped_column(String(30), default="ready")
    attempts: Mapped[int] = mapped_column(default=0)
    lease_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)


class GroupMemberBatch(Base):
    __tablename__ = "console_group_member_batches"
    __table_args__ = (UniqueConstraint("actor_id", "request_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    group_id: Mapped[str] = mapped_column(ForeignKey("console_groups.id"), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), index=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), index=True)
    aws_account_id: Mapped[int] = mapped_column(ForeignKey("console_aws_accounts.id"))
    request_key: Mapped[str] = mapped_column(String(80))
    payload_hash: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(10))
    expected_revision: Mapped[int]
    record_ids: Mapped[str] = mapped_column(Text)
    config_hash: Mapped[str] = mapped_column(String(64))
    state: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    stop_requested_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)
    updated_at: Mapped[datetime] = mapped_column(default=now)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)


class GroupMemberBatchItem(Base):
    __tablename__ = "console_group_member_batch_items"
    __table_args__ = (
        UniqueConstraint("batch_id", "record_id"),
        UniqueConstraint("batch_id", "position"),
    )
    id: Mapped[int] = mapped_column(primary_key=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("console_group_member_batches.id"), index=True)
    record_id: Mapped[str] = mapped_column(ForeignKey("console_subscriptions.id"))
    job_id: Mapped[str] = mapped_column(ForeignKey("console_group_jobs.id"), unique=True)
    position: Mapped[int]
    # All schedule columns and pre-admission membership survive an unsent stop.
    before_snapshot: Mapped[str] = mapped_column(Text)


class Subscription(Base):
    __tablename__ = "console_subscriptions"
    __table_args__ = (
        UniqueConstraint("owner_id", "request_key"),
        UniqueConstraint("aws_account_id", "username"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), index=True)
    aws_account_id: Mapped[int] = mapped_column(ForeignKey("console_aws_accounts.id"))
    plan_id: Mapped[int | None] = mapped_column(
        ForeignKey("console_plans.id"), nullable=True
    )
    counter_id: Mapped[int | None] = mapped_column(
        ForeignKey("console_plan_counters.id"), nullable=True
    )
    cycle_number: Mapped[int | None] = mapped_column(nullable=True)
    request_key: Mapped[str] = mapped_column(String(80))
    # Immutable single-route admission intent; legacy/batch records remain null.
    request_payload_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # Worker attempt only: pending writes retain their original transport scope.
    # Legacy NULL rows can reconcile; this is not numbered admission authorization.
    worker_config_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    username: Mapped[str] = mapped_column(String(120))
    email: Mapped[str] = mapped_column(String(254))
    state: Mapped[str] = mapped_column(String(40), default="queued", index=True)
    step: Mapped[str] = mapped_column(String(40), default="create_user")
    sso_user_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    password_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    credential_state: Mapped[str] = mapped_column(String(20), default="one_time")
    credential_revision: Mapped[int] = mapped_column(default=1)
    # Independently retained recovery material; never a downloadable candidate.
    credential_recovery_encrypted: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    portal_url: Mapped[str] = mapped_column(Text)
    subscription_type: Mapped[str | None] = mapped_column(String(100), nullable=True)
    aws_request_id: Mapped[str | None] = mapped_column(String(150), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    counted: Mapped[bool] = mapped_column(Boolean, default=False)
    reserved: Mapped[bool] = mapped_column(Boolean, default=True)
    attempts: Mapped[int] = mapped_column(default=0)
    lease_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now, index=True)
    updated_at: Mapped[datetime] = mapped_column(default=now)
    subscribed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    plan_name_snapshot: Mapped[str | None] = mapped_column(String(100), nullable=True)
    subscription_status: Mapped[str] = mapped_column(
        String(40), default="not_subscribed"
    )
    observed_subscription_type: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )
    subscription_observation: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(nullable=True)
    cancellation_mode: Mapped[str | None] = mapped_column(String(30), nullable=True)
    access_ends_at: Mapped[datetime | None] = mapped_column(nullable=True)
    sso_display_name: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    sso_deleted_at: Mapped[datetime | None] = mapped_column(nullable=True)
    password_generated_at: Mapped[datetime | None] = mapped_column(nullable=True)
    last_synced_at: Mapped[datetime | None] = mapped_column(nullable=True)
    active_operation_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    provision_only: Mapped[bool] = mapped_column(Boolean, default=False)
    batch_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    group_id: Mapped[str | None] = mapped_column(
        ForeignKey("console_groups.id"), nullable=True, index=True
    )
    group_membership_id: Mapped[str | None] = mapped_column(String(100), nullable=True)


class Batch(Base):
    __tablename__ = "console_batches"
    __table_args__ = (UniqueConstraint("owner_id", "request_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), index=True)
    export_credentials: Mapped[bool] = mapped_column(Boolean, default=False)
    request_key: Mapped[str] = mapped_column(String(80))
    payload_hash: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(40))
    group_id: Mapped[str | None] = mapped_column(
        ForeignKey("console_groups.id"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(default=now)


class BatchItem(Base):
    __tablename__ = "console_batch_items"
    __table_args__ = (UniqueConstraint("batch_id", "record_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("console_batches.id"), index=True)
    record_id: Mapped[str] = mapped_column(ForeignKey("console_subscriptions.id"))
    state: Mapped[str] = mapped_column(String(40), default="queued")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class RecordOperation(Base):
    __tablename__ = "console_record_operations"
    __table_args__ = (UniqueConstraint("record_id", "request_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    record_id: Mapped[str] = mapped_column(
        ForeignKey("console_subscriptions.id"), index=True
    )
    actor_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"))
    kind: Mapped[str] = mapped_column(String(40))
    request_key: Mapped[str] = mapped_column(String(80))
    payload: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    phase: Mapped[str] = mapped_column(String(30), default="ready")
    attempts: Mapped[int] = mapped_column(default=0)
    lease_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    aws_request_id: Mapped[str | None] = mapped_column(String(150), nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)


class StopSchedule(Base):
    __tablename__ = "console_stop_schedules"
    record_id: Mapped[str] = mapped_column(
        ForeignKey("console_subscriptions.id"), primary_key=True
    )
    actor_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"))
    revision: Mapped[int] = mapped_column(default=1)
    source_group_id: Mapped[str | None] = mapped_column(
        ForeignKey("console_groups.id"), nullable=True
    )
    source_group_revision: Mapped[int | None] = mapped_column(nullable=True)
    individual_override: Mapped[bool] = mapped_column(Boolean, default=False)
    principal_type: Mapped[str | None] = mapped_column(String(10), nullable=True)
    mode: Mapped[str] = mapped_column(String(20))
    days: Mapped[int | None] = mapped_column(nullable=True)
    stop_at: Mapped[datetime | None] = mapped_column(nullable=True, index=True)
    state: Mapped[str] = mapped_column(String(30), index=True)
    operation_id: Mapped[str | None] = mapped_column(
        ForeignKey("console_record_operations.id"), nullable=True
    )
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    next_check_at: Mapped[datetime | None] = mapped_column(nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)
    updated_at: Mapped[datetime] = mapped_column(default=now)


class AuditEvent(Base):
    __tablename__ = "console_audit_events"
    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(
        ForeignKey("console_users.id"), nullable=True
    )
    actor_name: Mapped[str] = mapped_column(String(100))
    subject_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("console_users.id"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(80))
    detail: Mapped[str] = mapped_column(Text)
    ip: Mapped[str | None] = mapped_column(String(100), nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now, index=True)


class LoginAttempt(Base):
    __tablename__ = "console_login_attempts"
    id: Mapped[int] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(160), index=True)
    created_at: Mapped[datetime] = mapped_column(default=now, index=True)


class SchemaVersion(Base):
    __tablename__ = "console_schema_version"
    version: Mapped[int] = mapped_column(Integer, primary_key=True)


class AuthBatch(Base):
    __tablename__ = "console_auth_batches"
    __table_args__ = (UniqueConstraint("actor_id", "request_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), index=True)
    session_version: Mapped[int]
    request_key: Mapped[str] = mapped_column(String(80))
    fingerprint: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(30))
    group_id: Mapped[str | None] = mapped_column(
        ForeignKey("console_groups.id"), nullable=True
    )
    state: Mapped[str] = mapped_column(String(30), default="active")
    created_at: Mapped[datetime] = mapped_column(default=now)
    expires_at: Mapped[datetime]
    completed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    download_expires_at: Mapped[datetime | None] = mapped_column(nullable=True)


class AuthJob(Base):
    __tablename__ = "console_auth_jobs"
    __table_args__ = (UniqueConstraint("batch_id", "record_id"),)
    id: Mapped[str] = mapped_column(
        ForeignKey("console_record_operations.id"), primary_key=True
    )
    batch_id: Mapped[str] = mapped_column(
        ForeignKey("console_auth_batches.id"), index=True
    )
    record_id: Mapped[str] = mapped_column(ForeignKey("console_subscriptions.id"))
    position: Mapped[int]
    credential_revision: Mapped[int]
    account_fingerprint: Mapped[str] = mapped_column(String(64))
    revision: Mapped[int] = mapped_column(default=0)
    stage: Mapped[str] = mapped_column(String(40), default="ready")
    reset_state: Mapped[str] = mapped_column(String(20), default="none")
    next_poll_at: Mapped[datetime | None] = mapped_column(nullable=True)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    error_code: Mapped[str | None] = mapped_column(String(60), nullable=True)


class AuthSecret(Base):
    __tablename__ = "console_auth_secrets"
    # No secret is written to operation payload/result or public job metadata.
    job_id: Mapped[str] = mapped_column(
        ForeignKey("console_auth_jobs.id"), primary_key=True
    )
    payload_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    workflow_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    answer_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    result_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)


class PlanChange(Base):
    """Independent intent and quota ledger; opening Subscription history is immutable."""

    __tablename__ = "console_plan_changes"
    __table_args__ = (
        UniqueConstraint("record_id", "request_key"),
        UniqueConstraint("actor_id", "request_key"),
        CheckConstraint("NOT (counted AND reserved)"),
        CheckConstraint("NOT reserved OR counter_id IS NOT NULL"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    record_id: Mapped[str] = mapped_column(
        ForeignKey("console_subscriptions.id"), index=True
    )
    operation_id: Mapped[str] = mapped_column(
        ForeignKey("console_record_operations.id"), unique=True
    )
    actor_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"))
    owner_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), index=True)
    request_key: Mapped[str] = mapped_column(String(80))
    payload_hash: Mapped[str] = mapped_column(String(64))
    direction: Mapped[str] = mapped_column(String(20))
    from_plan_id: Mapped[int] = mapped_column(ForeignKey("console_plans.id"))
    from_plan_name: Mapped[str] = mapped_column(String(100))
    from_type: Mapped[str] = mapped_column(String(100))
    to_plan_id: Mapped[int] = mapped_column(ForeignKey("console_plans.id"))
    to_plan_name: Mapped[str] = mapped_column(String(100))
    to_type: Mapped[str] = mapped_column(String(100))
    predecessor_id: Mapped[str | None] = mapped_column(
        ForeignKey("console_plan_changes.id"), nullable=True
    )
    counter_id: Mapped[int | None] = mapped_column(
        ForeignKey("console_plan_counters.id"), nullable=True
    )
    cycle_number: Mapped[int | None] = mapped_column(nullable=True)
    reserved: Mapped[bool] = mapped_column(Boolean, default=False)
    counted: Mapped[bool] = mapped_column(Boolean, default=False)
    # A database-enforced single accepted schedule per SSO. Released on settlement.
    scheduled_record_id: Mapped[str | None] = mapped_column(
        ForeignKey("console_subscriptions.id"), nullable=True, unique=True
    )
    state: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    requested_at: Mapped[datetime] = mapped_column(default=now)
    write_requested_at: Mapped[datetime | None] = mapped_column(nullable=True)
    accepted_at: Mapped[datetime | None] = mapped_column(nullable=True)
    expected_effective_at: Mapped[datetime | None] = mapped_column(nullable=True)
    confirmed_at: Mapped[datetime | None] = mapped_column(nullable=True)
    applied_at: Mapped[datetime | None] = mapped_column(nullable=True)
    checked_at: Mapped[datetime | None] = mapped_column(nullable=True)
    next_check_at: Mapped[datetime | None] = mapped_column(nullable=True, index=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class NativeGroupGrant(Base):
    """An immutable opening of an AWS GROUP assignment, including empty groups."""
    __tablename__ = "console_native_group_grants"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    group_id: Mapped[str] = mapped_column(ForeignKey("console_groups.id"), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), index=True)
    aws_account_id: Mapped[int] = mapped_column(ForeignKey("console_aws_accounts.id"))
    plan_id: Mapped[int] = mapped_column(ForeignKey("console_plans.id"))
    plan_name: Mapped[str] = mapped_column(String(100))
    subscription_type: Mapped[str] = mapped_column(String(100))
    state: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    activated_at: Mapped[datetime | None] = mapped_column(nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(nullable=True)
    cancellation_mode: Mapped[str | None] = mapped_column(String(30), nullable=True)
    access_ends_at: Mapped[datetime | None] = mapped_column(nullable=True)
    stop_at: Mapped[datetime | None] = mapped_column(nullable=True, index=True)
    policy_revision: Mapped[int] = mapped_column(default=0)
    created_at: Mapped[datetime] = mapped_column(default=now)


class NativeGroupOperation(Base):
    __tablename__ = "console_native_group_operations"
    __table_args__ = (UniqueConstraint("actor_id", "request_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    group_id: Mapped[str] = mapped_column(ForeignKey("console_groups.id"), index=True)
    grant_id: Mapped[str] = mapped_column(ForeignKey("console_native_group_grants.id"))
    actor_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"))
    kind: Mapped[str] = mapped_column(String(30))
    request_key: Mapped[str] = mapped_column(String(100))
    payload_hash: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str] = mapped_column(Text)
    config_hash: Mapped[str] = mapped_column(String(64))
    member_snapshot: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(30), default="queued", index=True)
    phase: Mapped[str] = mapped_column(String(30), default="ready")
    attempts: Mapped[int] = mapped_column(default=0)
    lease_token: Mapped[str | None] = mapped_column(String(36), nullable=True)
    lease_until: Mapped[datetime | None] = mapped_column(nullable=True)
    write_requested_at: Mapped[datetime | None] = mapped_column(nullable=True)
    aws_request_id: Mapped[str | None] = mapped_column(String(150), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)
    finished_at: Mapped[datetime | None] = mapped_column(nullable=True)


class GroupMemberActivation(Base):
    __tablename__ = "console_group_member_activations"
    __table_args__ = (UniqueConstraint("grant_id", "record_id", "request_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    grant_id: Mapped[str] = mapped_column(ForeignKey("console_native_group_grants.id"), index=True)
    record_id: Mapped[str] = mapped_column(ForeignKey("console_subscriptions.id"), index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), index=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"))
    plan_id: Mapped[int] = mapped_column(ForeignKey("console_plans.id"))
    plan_name: Mapped[str] = mapped_column(String(100))
    subscription_type: Mapped[str] = mapped_column(String(100))
    request_key: Mapped[str] = mapped_column(String(100))
    operation_id: Mapped[str] = mapped_column(String(36), index=True)
    counter_id: Mapped[int | None] = mapped_column(ForeignKey("console_plan_counters.id"), nullable=True)
    cycle_number: Mapped[int | None] = mapped_column(nullable=True)
    reserved: Mapped[bool] = mapped_column(Boolean, default=False)
    counted: Mapped[bool] = mapped_column(Boolean, default=False)
    first_opening: Mapped[bool] = mapped_column(Boolean, default=False)
    state: Mapped[str] = mapped_column(String(30), default="pending", index=True)
    config_hash: Mapped[str] = mapped_column(String(64))
    write_requested_at: Mapped[datetime | None] = mapped_column(nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(nullable=True)
    cancelled_at: Mapped[datetime | None] = mapped_column(nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(default=now)


class LifecycleBatch(Base):
    __tablename__ = "console_lifecycle_batches"
    __table_args__ = (UniqueConstraint("actor_id", "request_key"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("console_users.id"), index=True)
    request_key: Mapped[str] = mapped_column(String(80))
    payload_hash: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(30))
    created_at: Mapped[datetime] = mapped_column(default=now)


class LifecycleBatchItem(Base):
    __tablename__ = "console_lifecycle_batch_items"
    __table_args__ = (UniqueConstraint("batch_id", "principal_id"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("console_lifecycle_batches.id"), index=True)
    principal_id: Mapped[str] = mapped_column(String(36))
    principal_type: Mapped[str] = mapped_column(String(10))
    operation_id: Mapped[str] = mapped_column(String(36))
