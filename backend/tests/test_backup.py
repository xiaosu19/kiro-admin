import base64
import json
import os
from pathlib import Path
import sqlite3

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.fernet import InvalidToken

from app import backup
from app.config import settings
from app.database import engine


@pytest.fixture(autouse=True)
def forbid_cloud_client(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Backup tests must inject MemoryS3; no cloud clients")

    monkeypatch.setattr(backup.boto3, "client", denied)


class MemoryS3:
    def __init__(self):
        self.objects = {}

    def put_object(self, **kw):
        content = kw["Body"].read()
        assert kw["ServerSideEncryption"] == "AES256"
        self.objects[(kw["Bucket"], kw["Key"])] = (content, kw["Metadata"])

    def head_object(self, Bucket, Key):
        data, meta = self.objects[(Bucket, Key)]
        return {"ContentLength": len(data), "Metadata": meta}

    def download_file(self, bucket, key, filename):
        Path(filename).write_bytes(self.objects[(bucket, key)][0])


@pytest.fixture
def backup_env(tmp_path, monkeypatch):
    config = tmp_path / "app.env"
    config.write_text(
        f"FERNET_KEY={settings.fernet_key}\nSECRET_KEY={settings.secret_key}\n"
    )
    values = {
        "BACKUP_ENCRYPTION_KEY": base64.urlsafe_b64encode(os.urandom(32)).decode(),
        "BACKUP_BUCKET": "test-private",
        "BACKUP_REGION": "ap-northeast-1",
        "BACKUP_DATABASE_PATH": str(engine.url.database),
        "BACKUP_APP_ENV": str(config),
        "BACKUP_STATUS_PATH": str(tmp_path / "status.json"),
    }
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    return tmp_path


def test_encrypted_s3_backup_downloads_and_restores_with_keys(backup_env):
    s3 = MemoryS3()
    result = backup.run_backup(s3)
    assert result["restore_verified"] and result["status"] == "ok"
    data = next(iter(s3.objects.values()))[0]
    assert b"SECRET_KEY" not in data and b"TEST_SECRET_KEY" not in data
    src, archive = backup_env / "download", backup_env / "restore.tar.gz"
    src.write_bytes(data)
    backup.decrypt_archive(src, archive, backup.master_key())
    manifest = backup.check_archive(archive, backup_env / "restored")
    assert manifest["tables"]["console_users"] == 3
    with sqlite3.connect(backup_env / "restored" / "console.db") as db:
        assert (
            db.execute("select count(*) from console_plan_counters").fetchone()[0] == 3
        )
    assert (backup_env / "restored" / "app.env").stat().st_mode & 0o777 == 0o600


def test_tampered_backup_rejected_before_extraction(backup_env):
    source, enc, restored = [backup_env / x for x in ("source", "enc", "restored")]
    source.write_bytes(os.urandom(backup.CHUNK + 250))
    backup.encrypt_archive(source, enc, backup.master_key())
    content = bytearray(enc.read_bytes())
    content[50] ^= 1
    enc.write_bytes(content)
    with pytest.raises(InvalidTag):
        backup.decrypt_archive(enc, restored, backup.master_key())
    assert not restored.exists()


def test_failed_upload_preserves_last_success_status(backup_env):
    backup.run_backup(MemoryS3())
    previous = json.loads((backup_env / "status.json").read_text())

    class BrokenS3:
        def put_object(self, **kw):
            raise RuntimeError("secret details should not be logged")

    with pytest.raises(RuntimeError):
        backup.run_backup(BrokenS3())
    status = json.loads((backup_env / "status.json").read_text())
    assert status["status"] == "failed"
    assert status["completed_at"] == previous["completed_at"]
    assert status["error"] == "RuntimeError"


def test_backup_with_wrong_application_key_cannot_pass_restore(backup_env, monkeypatch):
    from cryptography.fernet import Fernet

    config = backup_env / "app.env"
    config.write_text(
        f"FERNET_KEY={Fernet.generate_key().decode()}\nSECRET_KEY={settings.secret_key}\n"
    )
    with pytest.raises(InvalidToken):
        backup.run_backup(MemoryS3())
    assert json.loads((backup_env / "status.json").read_text())["status"] == "failed"


def test_backup_rejects_unreadable_proxy_auth(backup_env):
    from app.database import SessionLocal
    from app.models import Proxy

    with SessionLocal() as db:
        db.add(
            Proxy(
                name="broken-test",
                host="127.0.0.1",
                port=1080,
                auth_encrypted="invalid-test-ciphertext",
            )
        )
        db.commit()
    with pytest.raises(InvalidToken):
        backup.run_backup(MemoryS3())


def test_local_backup_without_aws_creates_verified_encrypted_archive_and_retains_seven_days(
    backup_env, monkeypatch
):
    from datetime import datetime, timedelta, timezone
    import uuid

    local = backup_env / "local"
    local.mkdir()

    def name(days):
        return f"kiro-console-{datetime.now(timezone.utc) - timedelta(days=days):%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex}.kirobk"

    old, recent = local / name(8), local / name(6)
    old.write_bytes(b"old owned backup")
    recent.write_bytes(b"recent owned backup")
    unrelated = local / "unrelated.kirobk"
    unrelated.write_bytes(b"keep")
    monkeypatch.setenv("BACKUP_DESTINATION", "local")
    monkeypatch.setenv("BACKUP_LOCAL_DIR", str(local))
    monkeypatch.setenv("BACKUP_RETENTION_DAYS", "7")
    monkeypatch.delenv("BACKUP_REGION")
    monkeypatch.delenv("BACKUP_BUCKET")

    def no_cloud(*args, **kwargs):
        raise AssertionError("local backup attempted cloud access")

    monkeypatch.setattr(backup.boto3, "client", no_cloud)
    result = backup.run_backup()
    assert (
        result["status"] == "ok"
        and result["destination"] == "local"
        and result["restore_verified"]
    )
    assert not old.exists() and recent.exists() and unrelated.exists()
    archive = local / result["object_key"]
    assert archive.exists() and archive.read_bytes().startswith(backup.MAGIC)
    assert archive.stat().st_mode & 0o777 == 0o600
    assert b"SECRET_KEY" not in archive.read_bytes()
    assert result["retention_days"] == 7


def test_local_restore_verification_failure_does_not_publish_or_prune(
    backup_env, monkeypatch
):
    import uuid

    local = backup_env / "local"
    local.mkdir()
    old = local / f"kiro-console-20000101T000000Z-{uuid.uuid4().hex}.kirobk"
    old.write_bytes(b"keep until successful verified replacement")
    monkeypatch.setenv("BACKUP_DESTINATION", "local")
    monkeypatch.setenv("BACKUP_LOCAL_DIR", str(local))

    def fail(*args, **kwargs):
        raise ValueError("synthetic restore failure")

    monkeypatch.setattr(backup, "check_archive", fail)
    with pytest.raises(ValueError):
        backup.run_backup()
    assert list(local.iterdir()) == [old]
    result = json.loads((backup_env / "status.json").read_text())
    assert result["status"] == "failed"
    assert not result.get("restore_verified")


def test_backup_checks_new_encrypted_sidecars(backup_env):
    from app.database import SessionLocal
    from app.models import Subscription
    from test_auth_batches import record

    r = record()
    with SessionLocal() as db:
        db.get(
            Subscription, r.id
        ).credential_recovery_encrypted = "invalid-recovery-ciphertext"
        db.commit()
    with pytest.raises(InvalidToken):
        backup.run_backup(MemoryS3())


@pytest.mark.parametrize("schema", [6, 7, 8])
def test_pre_auth_archives_remain_restorable(backup_env, schema):
    from sqlalchemy import text

    with engine.connect() as db:
        db.exec_driver_sql("PRAGMA foreign_keys=OFF")
        db.commit()
        for table in (
            "console_auth_secrets",
            "console_auth_jobs",
            "console_auth_batches",
        ):
            db.exec_driver_sql("DROP TABLE " + table)
        for column in (
            "credential_recovery_encrypted",
            "credential_state",
            "credential_revision",
        ):
            db.exec_driver_sql(
                "ALTER TABLE console_subscriptions DROP COLUMN " + column
            )
        if schema == 6:
            from app.models import AwsAccount

            columns = [c for c in AwsAccount.__table__.columns if c.name != "proxy_id"]
            ddl = ",".join(
                f"{c.name} {c.type.compile(dialect=engine.dialect)}"
                + (" PRIMARY KEY" if c.primary_key else "")
                for c in columns
            )
            names = ",".join(c.name for c in columns)
            db.exec_driver_sql(f"CREATE TABLE legacy_accounts ({ddl})")
            db.exec_driver_sql(
                f"INSERT INTO legacy_accounts SELECT {names} FROM console_aws_accounts"
            )
            db.exec_driver_sql("DROP TABLE console_aws_accounts")
            db.exec_driver_sql(
                "ALTER TABLE legacy_accounts RENAME TO console_aws_accounts"
            )
            db.exec_driver_sql("DROP TABLE console_proxies")
        db.execute(
            text("INSERT INTO console_schema_version(version) VALUES (:version)"),
            {"version": schema},
        )
        db.commit()
        db.exec_driver_sql("PRAGMA foreign_keys=ON")
    result = backup.run_backup(MemoryS3())
    assert result["restore_verified"] and result["status"] == "ok"


def test_restore_still_rejects_missing_required_legacy_credential_column(backup_env):
    with engine.begin() as db:
        db.exec_driver_sql(
            "ALTER TABLE console_aws_accounts DROP COLUMN credentials_encrypted"
        )
    with pytest.raises(ValueError):
        backup.run_backup(MemoryS3())


@pytest.mark.parametrize("valid", [True, False])
def test_restore_verifies_personal_ai_keys(backup_env, valid):
    from app.database import SessionLocal
    from app.models import AiProviderSettings
    from app.security import decrypt, encrypt

    secret = "synthetic-personal-vision-key"
    with SessionLocal() as db:
        db.add(AiProviderSettings(
            user_id=2, protocol="openai_responses",
            endpoint="https://vision.example.com/v1/responses", model="vision-test",
            key_encrypted=encrypt(secret) if valid else "invalid-ai-ciphertext", enabled=True,
        ))
        db.commit()
    s3 = MemoryS3()
    if not valid:
        with pytest.raises(InvalidToken):
            backup.run_backup(s3)
        assert json.loads((backup_env / "status.json").read_text())["status"] == "failed"
        return
    result = backup.run_backup(s3)
    assert result["restore_verified"]
    encrypted, archive = backup_env / "download", backup_env / "restore.tar.gz"
    encrypted.write_bytes(next(iter(s3.objects.values()))[0])
    backup.decrypt_archive(encrypted, archive, backup.master_key())
    manifest = backup.check_archive(archive, backup_env / "restored")
    assert manifest["tables"]["console_ai_provider_settings"] == 1
    with sqlite3.connect(backup_env / "restored" / "console.db") as db:
        row = db.execute("SELECT user_id, key_encrypted FROM console_ai_provider_settings").fetchone()
    assert row[0] == 2 and row[1] != secret and decrypt(row[1]) == secret
