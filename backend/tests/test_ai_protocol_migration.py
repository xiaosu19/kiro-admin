"""Upgrade an actual legacy CHECK constraint, preserving encrypted tenant keys."""
import sqlite3

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError

from app.database import engine
from app.migrations import VERSION, migrate


def test_legacy_ai_protocol_upgrade_preserves_rows_and_constraints(tmp_path):
    path = tmp_path / 'legacy.db'
    with engine.connect() as source, sqlite3.connect(path) as target:
        source.connection.driver_connection.backup(target)
    target = create_engine(f'sqlite:///{path}')
    with target.begin() as conn:
        ddl = conn.exec_driver_sql("SELECT sql FROM sqlite_master WHERE name='console_ai_provider_settings'").scalar()
        ddl = ddl.replace("'claude_messages_bearer', ", '')
        conn.exec_driver_sql('DROP TABLE console_ai_provider_settings')
        conn.exec_driver_sql(ddl)
        conn.exec_driver_sql("INSERT INTO console_ai_provider_settings VALUES (2, 'claude_messages', 'https://example.com/v1/messages', 'own-model', 'opaque-encrypted-key', 1, 20, 7, CURRENT_TIMESTAMP)")
        conn.exec_driver_sql('DELETE FROM console_schema_version')
        conn.exec_driver_sql('INSERT INTO console_schema_version (version) VALUES (19)')
        before = conn.exec_driver_sql('SELECT * FROM console_ai_provider_settings').fetchall()
    migrate(target)
    migrate(target)
    with target.begin() as conn:
        assert conn.exec_driver_sql('SELECT * FROM console_ai_provider_settings').fetchall() == before
        assert conn.exec_driver_sql('PRAGMA foreign_key_check').fetchall() == []
        assert conn.exec_driver_sql('SELECT version FROM console_schema_version').scalar() == VERSION
        conn.exec_driver_sql("UPDATE console_ai_provider_settings SET protocol='claude_messages_bearer'")
        with pytest.raises(IntegrityError):
            conn.exec_driver_sql("UPDATE console_ai_provider_settings SET protocol='unknown'")
        with pytest.raises(IntegrityError):
            conn.exec_driver_sql('UPDATE console_ai_provider_settings SET timeout_seconds=0')
