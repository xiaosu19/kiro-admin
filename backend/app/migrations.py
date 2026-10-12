"""Transactional, additive SQLite migrations; stop API/worker and back up first."""

from sqlalchemy import inspect, text
from sqlalchemy.schema import CreateIndex, CreateTable

VERSION = 18
AUTH_COLUMNS = {
    "credential_state": "VARCHAR(20) NOT NULL DEFAULT 'one_time'",
    "credential_revision": "INTEGER NOT NULL DEFAULT 1",
    "credential_recovery_encrypted": "TEXT",
}
COLUMNS = {
    "plan_name_snapshot": "VARCHAR(100)",
    "subscription_status": "VARCHAR(40) NOT NULL DEFAULT 'not_subscribed'",
    "observed_subscription_type": "VARCHAR(100)",
    "cancelled_at": "DATETIME",
    "cancellation_mode": "VARCHAR(30)",
    "access_ends_at": "DATETIME",
    "sso_display_name": "VARCHAR(1024)",
    "sso_deleted_at": "DATETIME",
    "password_generated_at": "DATETIME",
    "last_synced_at": "DATETIME",
    "active_operation_id": "VARCHAR(36)",
    "provision_only": "BOOLEAN NOT NULL DEFAULT 0",
    "batch_id": "VARCHAR(36)",
}
GROUP_COLUMNS = {
    "group_id": "VARCHAR(36) REFERENCES console_groups(id)",
    "group_membership_id": "VARCHAR(100)",
    "request_payload_hash": "VARCHAR(64)",
    "worker_config_hash": "VARCHAR(64)",
}


def migrate(engine):
    from .cascade_models import CascadeAction, CascadeBatch, CascadePreview, CascadeTask
    from .retry_models import AutomaticRetry
    from .external_auth_models import ExternalExportBatch, ExternalExportItem
    from .group_export_models import AuthExportMember, AuthExportScope, GroupExportPreview
    from .models import (
        Subscription, AiProviderSettings,
        Proxy,
        ManagedGroup,
        GroupJob,
        AuthBatch,
        AuthJob,
        AuthSecret,
        PlanChange,
        NativeGroupGrant, NativeGroupOperation, GroupMemberActivation,
        LifecycleBatch, LifecycleBatchItem,
        GroupMemberBatch, GroupMemberBatchItem,
        AwsAccountNumber, ProvisioningCounter, ProvisioningBatch,
        ProvisioningAccountBatch, ProvisioningItem, ProvisioningAction,
    )

    # SQLite's documented table-rebuild procedure: FK checking is disabled only
    # on this migration connection, outside the transaction, then verified again.
    with engine.connect() as conn:
        sqlite = engine.dialect.name == "sqlite"
        if sqlite:
            conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
            conn.commit()
        try:
            if sqlite:
                conn.exec_driver_sql("BEGIN IMMEDIATE")
            inspector = inspect(conn)
            tables = inspector.get_table_names()
            version = None
            if "console_schema_version" in tables:
                version = conn.scalar(
                    text("SELECT MAX(version) FROM console_schema_version")
                )
                if version and version > VERSION:
                    raise RuntimeError("数据库版本高于应用版本，不能回退代码")
            Proxy.__table__.create(conn, checkfirst=True)
            ManagedGroup.__table__.create(conn, checkfirst=True)
            GroupJob.__table__.create(conn, checkfirst=True)
            for table, additions in {
                "console_provisioning_account_batches": {
                    "group_job_id": "VARCHAR(36)", "native_operation_id": "VARCHAR(36)",
                    "native_grant_id": "VARCHAR(36)", "native_request_key": "VARCHAR(80)", "policy_applied_revision": "INTEGER",
                    "stop_requested_at": "DATETIME",
                },
                "console_provisioning_items": {
                    "sso_batch_id": "VARCHAR(36)", "auth_batch_id": "VARCHAR(36)",
                    "auth_job_id": "VARCHAR(36)", "export_error": "TEXT",
                    "updated_at": "DATETIME", "finished_at": "DATETIME",
                },
                "console_subscriptions": GROUP_COLUMNS | AUTH_COLUMNS | {"subscription_observation": "TEXT"},
                "console_batches": {
                    "group_id": "VARCHAR(36) REFERENCES console_groups(id)"
                },
                "console_stop_schedules": {
                    "source_group_id": "VARCHAR(36) REFERENCES console_groups(id)",
                    "source_group_revision": "INTEGER",
                    "individual_override": "BOOLEAN NOT NULL DEFAULT 0",
                    "principal_type": "VARCHAR(10)",
                },
            }.items():
                if table in tables:
                    existing = {c["name"] for c in inspector.get_columns(table)}
                    for name, ddl in additions.items():
                        if name not in existing:
                            conn.execute(
                                text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                            )
            if "console_subscriptions" in tables:
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_console_subscriptions_group_id ON console_subscriptions(group_id)"
                    )
                )
            inspector = inspect(conn)
            for model in (AiProviderSettings, AuthBatch, AuthJob, AuthSecret, PlanChange, NativeGroupGrant,
                          NativeGroupOperation, GroupMemberActivation, LifecycleBatch,
                          LifecycleBatchItem, GroupMemberBatch, GroupMemberBatchItem,
                          AwsAccountNumber, ProvisioningCounter, ProvisioningBatch,
                          ProvisioningAccountBatch, ProvisioningItem, ProvisioningAction,
                          CascadePreview, CascadeBatch, CascadeTask, CascadeAction,
                          AutomaticRetry, ExternalExportBatch, ExternalExportItem,
                          GroupExportPreview, AuthExportScope, AuthExportMember):
                model.__table__.create(conn, checkfirst=True)
            if "console_aws_accounts" in tables:
                account_columns = {
                    c["name"] for c in inspector.get_columns("console_aws_accounts")
                }
                if "proxy_id" not in account_columns:
                    conn.execute(
                        text(
                            "ALTER TABLE console_aws_accounts ADD COLUMN proxy_id INTEGER REFERENCES console_proxies(id)"
                        )
                    )
                if "account_number" not in account_columns:
                    conn.execute(text("ALTER TABLE console_aws_accounts ADD COLUMN account_number VARCHAR(24)"))
                conn.execute(
                    text(
                        "CREATE INDEX IF NOT EXISTS ix_console_aws_accounts_proxy_id ON console_aws_accounts(proxy_id)"
                    )
                )
            # Versions 6+ completed the legacy backfills. Proxy and group
            # migrations only add nullable fields and independent tables.
            if version and version >= 6:
                conn.execute(
                    text("UPDATE console_schema_version SET version=:v"), {"v": VERSION}
                )
                if (
                    sqlite
                    and conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall()
                ):
                    raise RuntimeError("数据库迁移外键校验失败")
                conn.commit()
                return
            for table, additions in {
                "console_users": {"deleted_at": "DATETIME"},
                "console_aws_accounts": {"deleted_at": "DATETIME"},
                "console_plans": {"deleted_at": "DATETIME"},
                "console_batches": {"export_credentials": "BOOLEAN NOT NULL DEFAULT 0"},
            }.items():
                if table in tables:
                    existing = {c["name"] for c in inspector.get_columns(table)}
                    for name, ddl in additions.items():
                        if name not in existing:
                            conn.execute(
                                text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
                            )
            if "console_subscriptions" not in tables:
                conn.commit()
                return
            original_columns = inspector.get_columns("console_subscriptions")
            columns = {c["name"] for c in original_columns}
            for name, ddl in COLUMNS.items():
                if name not in columns:
                    conn.execute(
                        text(
                            f"ALTER TABLE console_subscriptions ADD COLUMN {name} {ddl}"
                        )
                    )
            if any(
                not c["nullable"] and c["name"] in ("plan_id", "subscription_type")
                for c in original_columns
            ):
                if not sqlite:
                    raise RuntimeError("本版迁移仅支持 SQLite")
                table = Subscription.__table__
                ddl = str(CreateTable(table).compile(dialect=engine.dialect)).replace(
                    "CREATE TABLE console_subscriptions",
                    "CREATE TABLE console_subscriptions_v3",
                    1,
                )
                conn.exec_driver_sql(ddl)
                names = ",".join('"' + c.name + '"' for c in table.columns)
                conn.exec_driver_sql(
                    f"INSERT INTO console_subscriptions_v3 ({names}) SELECT {names} FROM console_subscriptions"
                )
                conn.exec_driver_sql("DROP TABLE console_subscriptions")
                conn.exec_driver_sql(
                    "ALTER TABLE console_subscriptions_v3 RENAME TO console_subscriptions"
                )
                for index in table.indexes:
                    conn.execute(CreateIndex(index))
            if "subscription_status" not in columns:
                conn.execute(
                    text(
                        "UPDATE console_subscriptions SET subscription_status='active', observed_subscription_type=subscription_type WHERE counted=1"
                    )
                )
            conn.execute(
                text(
                    "UPDATE console_subscriptions SET plan_name_snapshot=(SELECT name FROM console_plans WHERE id=plan_id) WHERE plan_name_snapshot IS NULL AND plan_id IS NOT NULL"
                )
            )
            conn.execute(
                text(
                    "UPDATE console_subscriptions SET sso_display_name='Kiro Console ' || id WHERE sso_user_id IS NOT NULL AND sso_display_name IS NULL"
                )
            )
            if "console_schema_version" in tables:
                conn.execute(
                    text("UPDATE console_schema_version SET version=:v"), {"v": VERSION}
                )
            if sqlite and conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall():
                raise RuntimeError("数据库迁移外键校验失败")
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            if sqlite:
                conn.exec_driver_sql("PRAGMA foreign_keys=ON")
                conn.commit()
