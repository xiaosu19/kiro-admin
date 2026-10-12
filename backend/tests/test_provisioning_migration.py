"""Schema 13 to numbered intents is additive, transactional and repeatable."""

import pytest
from sqlalchemy import create_engine, inspect

from app import models
from app.database import Base, engine
from app.migrations import VERSION, migrate


NEW_TABLES = {
    "console_aws_account_numbers", "console_provisioning_counters", "console_provisioning_batches",
    "console_provisioning_account_batches", "console_provisioning_items",
}

SCHEMA17_TABLES = {
    'console_cascade_previews', 'console_cascade_batches', 'console_cascade_tasks', 'console_cascade_actions',
    'console_automatic_retries', 'console_external_export_batches', 'console_external_export_items',
    'console_group_export_previews', 'console_auth_export_scopes', 'console_auth_export_members',
}


def schema16_database(tmp_path):
    import sqlite3
    path = tmp_path / 'prior16.db'
    with engine.connect() as src, sqlite3.connect(path) as dest:
        src.connection.driver_connection.backup(dest)
    target = create_engine(f'sqlite:///{path}')
    with target.begin() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            if table.name in SCHEMA17_TABLES:
                conn.exec_driver_sql(f'DROP TABLE "{table.name}"')
        conn.exec_driver_sql('DELETE FROM console_schema_version')
        conn.exec_driver_sql('INSERT INTO console_schema_version (version) VALUES (16)')
        old = {name: conn.exec_driver_sql(f'SELECT * FROM "{name}"').fetchall()
               for name in inspect(conn).get_table_names() if name != 'console_schema_version'}
    return target, old


def test_schema17_adds_cascade_group_external_and_retry_tables_without_changing_existing_rows(tmp_path):
    target, old = schema16_database(tmp_path)
    migrate(target)
    migrate(target)
    with target.connect() as conn:
        assert conn.exec_driver_sql('SELECT version FROM console_schema_version').scalar() == 18
        assert SCHEMA17_TABLES <= set(inspect(conn).get_table_names())
        assert conn.exec_driver_sql('PRAGMA foreign_key_check').fetchall() == []
        for name, rows in old.items():
            assert conn.exec_driver_sql(f'SELECT * FROM "{name}"').fetchall() == rows
        for name in SCHEMA17_TABLES:
            assert conn.exec_driver_sql(f'SELECT count(*) FROM "{name}"').scalar() == 0


def test_schema17_group_scope_creation_interruption_rolls_back_all_new_tables(tmp_path, monkeypatch):
    from app.group_export_models import AuthExportScope
    target, old = schema16_database(tmp_path)
    def interrupted(*args, **kwargs):
        raise RuntimeError('interrupted group scope migration')
    monkeypatch.setattr(AuthExportScope.__table__, 'create', interrupted)
    with pytest.raises(RuntimeError, match='interrupted group scope'):
        migrate(target)
    with target.connect() as conn:
        assert conn.exec_driver_sql('SELECT version FROM console_schema_version').scalar() == 16
        assert not SCHEMA17_TABLES & set(inspect(conn).get_table_names())
        for name, rows in old.items():
            assert conn.exec_driver_sql(f'SELECT * FROM "{name}"').fetchall() == rows


def prior_database(tmp_path):
    target = create_engine(f"sqlite:///{tmp_path / 'prior13.db'}")
    old_tables = [t for t in Base.metadata.sorted_tables if t.name not in NEW_TABLES]
    Base.metadata.create_all(target, tables=old_tables)
    with engine.connect() as source, target.begin() as dest:
        for table in old_tables:
            rows = [dict(row) for row in source.execute(table.select()).mappings()]
            if rows:
                dest.execute(table.insert(), rows)
        dest.execute(models.SchemaVersion.__table__.insert(), {"version": 13})
        dest.exec_driver_sql("ALTER TABLE console_aws_accounts DROP COLUMN account_number")
        # Historical SSO identity is retained exactly and is never numbered.
        dest.exec_driver_sql("INSERT INTO console_subscriptions (id, owner_id, aws_account_id, request_key, username, email, state, step, credential_state, credential_revision, portal_url, counted, reserved, attempts, created_at, updated_at, subscription_status, provision_only) VALUES ('historical', 2, 1, 'historical-key', 'real-sso-name', 'old@example.com', 'completed', 'done', 'one_time', 1, 'https://example.com', 0, 0, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'not_subscribed', 1)")
    with target.connect() as conn:
        columns = {t.name: [c["name"] for c in inspect(conn).get_columns(t.name)] for t in old_tables}
        rows = {t.name: conn.exec_driver_sql(f'SELECT * FROM "{t.name}"').fetchall() for t in old_tables}
    return target, columns, rows


def test_schema14_preserves_every_old_column_and_row_and_allocates_nothing(tmp_path):
    target, columns, rows = prior_database(tmp_path)
    migrate(target)
    migrate(target)
    with target.connect() as conn:
        assert VERSION >= 14
        assert conn.exec_driver_sql("SELECT version FROM console_schema_version").scalar() == VERSION
        assert NEW_TABLES <= set(inspect(conn).get_table_names())
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
        for name, names in columns.items():
            if name == "console_schema_version":
                continue
            projection = ",".join(f'"{column}"' for column in names)
            assert conn.exec_driver_sql(f'SELECT {projection} FROM "{name}"').fetchall() == rows[name]
        assert conn.exec_driver_sql("SELECT account_number FROM console_aws_accounts").fetchall() == [(None,)]
        for table in NEW_TABLES:
            assert conn.exec_driver_sql(f'SELECT count(*) FROM "{table}"').scalar() == 0


def test_schema14_interruption_rolls_back_ddl_and_version(tmp_path, monkeypatch):
    target, columns, rows = prior_database(tmp_path)
    def interrupt(*args, **kwargs):
        raise RuntimeError("interrupted numbered migration")
    monkeypatch.setattr(models.ProvisioningItem.__table__, "create", interrupt)
    with pytest.raises(RuntimeError, match="interrupted numbered"):
        migrate(target)
    with target.connect() as conn:
        assert conn.exec_driver_sql("SELECT version FROM console_schema_version").scalar() == 13
        assert not NEW_TABLES & set(inspect(conn).get_table_names())
        for name, names in columns.items():
            assert [c["name"] for c in inspect(conn).get_columns(name)] == names
            assert conn.exec_driver_sql(f'SELECT * FROM "{name}"').fetchall() == rows[name]


def test_schema17_preserves_schema15_rows_and_original_columns(tmp_path):
    """Every old table/column value survives the additive progress migration."""
    from app.database import SessionLocal
    import sqlite3

    with SessionLocal() as db:
        parent = models.ProvisioningBatch(id='old-parent', actor_id=2, actor_role='member', session_version=1,
            request_key='old-request-key-01', payload_hash='frozen', intent='{"accounts":[]}',
            preview_fingerprint='frozen-preview', totals='[]')
        db.add(parent)
        db.flush()
        db.add(models.ProvisioningAccountBatch(id='old-account-batch', batch_id=parent.id,
            position=1, aws_account_id=1, account_number='a', sequence=1, batch_number='a-01',
            config_hash='frozen-config', quantity=1, plan_id=1, plan_name='Kiro Pro',
            subscription_type='Q_DEVELOPER_STANDALONE_PRO', group_mode='new', group_name='a-01',
            stop_policy='{"mode":"none"}', exports='{"json":false}', snapshot='{"frozen":true}', needed_count=1))
        db.flush()
        db.add(models.ProvisioningItem(record_id='frozen-record', account_batch_id='old-account-batch',
            position=1, internal_id='a-01-01', username='random-real-name', email='same@example.com'))
        db.commit()
    path = tmp_path / 'prior15.db'
    with engine.connect() as src, sqlite3.connect(path) as dest:
        src.connection.driver_connection.backup(dest)
    target = create_engine(f'sqlite:///{path}')
    additions = {
        'console_provisioning_account_batches': ('group_job_id', 'native_operation_id', 'native_request_key',
            'native_grant_id', 'policy_applied_revision', 'stop_requested_at'),
        'console_provisioning_items': ('sso_batch_id', 'auth_batch_id', 'auth_job_id', 'export_error',
            'updated_at', 'finished_at'),
    }
    with target.begin() as db:
        db.exec_driver_sql('DROP TABLE console_provisioning_actions')
        db.exec_driver_sql('INSERT INTO console_schema_version (version) VALUES (15)')
        for table, names in additions.items():
            for name in names:
                db.exec_driver_sql(f'ALTER TABLE {table} DROP COLUMN {name}')
        inspector = inspect(db)
        originals = {name: [c['name'] for c in inspector.get_columns(name)] for name in inspector.get_table_names()}
        before = {name: db.exec_driver_sql(f'SELECT * FROM "{name}"').fetchall() for name in originals}
    migrate(target)
    migrate(target)
    with target.connect() as db:
        assert db.exec_driver_sql('SELECT version FROM console_schema_version').scalar() == VERSION == 18
        assert db.exec_driver_sql('PRAGMA foreign_key_check').fetchall() == []
        for table, columns in originals.items():
            if table == 'console_schema_version': continue
            names = ','.join(f'"{c}"' for c in columns)
            assert db.exec_driver_sql(f'SELECT {names} FROM "{table}"').fetchall() == before[table]
        assert db.exec_driver_sql('SELECT group_job_id, native_grant_id FROM console_provisioning_account_batches').fetchall() == [(None, None)]
        assert db.exec_driver_sql('SELECT count(*) FROM console_provisioning_actions').scalar() == 0
