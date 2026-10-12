"""Consistent SQLite backups, authenticated encryption, S3 upload and restore checks.

Runs independently of the web app. The backup master key must also be retained
offline; it is intentionally not stored inside the archive it encrypts.
"""

import argparse
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import boto3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import dotenv_values

MAGIC = b"KIROBK1\0"
CHUNK = 1024 * 1024
FILES = {"console.db", "app.env", "manifest.json"}


def timestamp():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def master_key():
    key = base64.urlsafe_b64decode(os.environ["BACKUP_ENCRYPTION_KEY"])
    if len(key) != 32:
        raise ValueError("Backup encryption key must contain 32 bytes")
    return key


def encrypt_archive(source, target, key):
    nonce = os.urandom(12)
    header = MAGIC + nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(header)
    with Path(source).open("rb") as src, Path(target).open("wb") as dst:
        os.chmod(target, 0o600)
        dst.write(header)
        while chunk := src.read(CHUNK):
            dst.write(cipher.update(chunk))
        dst.write(cipher.finalize())
        dst.write(cipher.tag)


def decrypt_archive(source, target, key):
    try:
        with Path(source).open("rb") as src, Path(target).open("wb") as dst:
            os.chmod(target, 0o600)
            header = src.read(len(MAGIC) + 12)
            if len(header) != len(MAGIC) + 12 or not header.startswith(MAGIC):
                raise ValueError("Invalid backup format")
            src.seek(-16, 2)
            tag = src.read(16)
            remaining = src.tell() - len(header) - 16
            src.seek(len(header))
            cipher = Cipher(
                algorithms.AES(key), modes.GCM(header[len(MAGIC) :], tag)
            ).decryptor()
            cipher.authenticate_additional_data(header)
            while remaining > 0:
                chunk = src.read(min(CHUNK, remaining))
                remaining -= len(chunk)
                dst.write(cipher.update(chunk))
            dst.write(cipher.finalize())
    except Exception:
        Path(target).unlink(missing_ok=True)
        raise


def database_summary(path):
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        if db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("SQLite integrity check failed")
        if db.execute("PRAGMA foreign_key_check").fetchall():
            raise ValueError("SQLite foreign key check failed")
        tables = [
            r[0]
            for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'console_%' ORDER BY name"
            )
        ]
        if "console_users" not in tables or "console_subscriptions" not in tables:
            raise ValueError("This is not a Kiro Console database")
        return {
            name: db.execute(
                'SELECT count(*) FROM "' + name.replace('"', '""') + '"'
            ).fetchone()[0]
            for name in tables
        }


def snapshot(database_path, app_env, workdir):
    target = Path(workdir) / "console.db"
    with (
        sqlite3.connect(f"file:{database_path}?mode=ro", uri=True) as src,
        sqlite3.connect(target) as dst,
    ):
        src.backup(dst, pages=256)
    os.chmod(target, 0o600)
    config = dotenv_values(app_env)
    if not config.get("FERNET_KEY") or not config.get("SECRET_KEY"):
        raise ValueError("Application recovery keys are missing")
    # The app environment must never contain the independent backup master key.
    if any(k.startswith("BACKUP_ENCRYPTION_") for k in config):
        raise ValueError("Backup master key must be stored in a separate file")
    shutil.copyfile(app_env, Path(workdir) / "app.env")
    os.chmod(Path(workdir) / "app.env", 0o600)
    manifest = {
        "format_version": 1,
        "application_version": "2.0",
        "created_at": timestamp(),
        "tables": database_summary(target),
        "sha256": {
            name: digest(Path(workdir) / name) for name in ("console.db", "app.env")
        },
    }
    (Path(workdir) / "manifest.json").write_text(json.dumps(manifest, indent=2))
    archive = Path(workdir) / "backup.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name in sorted(FILES):
            tar.add(Path(workdir) / name, arcname=name)
    return archive, manifest


def check_archive(archive, output):
    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if list(output.iterdir()):
        raise ValueError("Restore directory must be empty")
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        if (
            len(members) != len(FILES)
            or {m.name for m in members} != FILES
            or any(not m.isfile() for m in members)
        ):
            raise ValueError("Unexpected archive contents")
        for member in members:
            with (
                tar.extractfile(member) as src,
                (output / member.name).open("wb") as dst,
            ):
                os.chmod(output / member.name, 0o600)
                shutil.copyfileobj(src, dst)
    manifest = json.loads((output / "manifest.json").read_text())
    if manifest.get("format_version") != 1:
        raise ValueError("Unsupported archive version")
    for name in ("console.db", "app.env"):
        if digest(output / name) != manifest["sha256"][name]:
            raise ValueError("Backup checksum mismatch")
    if database_summary(output / "console.db") != manifest["tables"]:
        raise ValueError("Restored database record counts mismatch")
    # Validate that the saved app key decrypts all stored AWS/OTP/proxy data.
    from cryptography.fernet import Fernet

    fernet = Fernet(dotenv_values(output / "app.env")["FERNET_KEY"].encode())
    with sqlite3.connect(output / "console.db") as db:
        for table, column in [
            ("console_aws_accounts", "credentials_encrypted"),
            ("console_subscriptions", "password_encrypted"),
            ("console_proxies", "auth_encrypted"),
            ("console_subscriptions", "credential_recovery_encrypted"),
            ("console_auth_secrets", "payload_encrypted"),
            ("console_auth_secrets", "workflow_encrypted"),
            ("console_auth_secrets", "answer_encrypted"),
            ("console_auth_secrets", "result_encrypted"),
            ("console_ai_provider_settings", "key_encrypted"),
        ]:
            # Schemas 6/7/8 predate some optional encrypted columns/tables.
            columns = {row[1] for row in db.execute(f'PRAGMA table_info("{table}")')}
            if column not in columns:
                if (table, column) in {
                    ("console_aws_accounts", "credentials_encrypted"),
                    ("console_subscriptions", "password_encrypted"),
                } or (columns and table in {"console_proxies", "console_auth_secrets", "console_ai_provider_settings"}):
                    raise ValueError("Backup credential schema is incomplete")
                continue
            for (encrypted,) in db.execute(
                f"SELECT {column} FROM {table} WHERE {column} IS NOT NULL"
            ):
                fernet.decrypt(encrypted.encode())
    return manifest


def status_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + ".new")
    temp.write_text(json.dumps(data, indent=2))
    os.chmod(temp, 0o644)
    temp.replace(path)


def run_backup(s3=None):
    status_path = Path(
        os.environ.get("BACKUP_STATUS_PATH", "/var/lib/kiro-console/backup-status.json")
    )
    try:
        previous = json.loads(status_path.read_text())
    except (OSError, ValueError):
        previous = {}
    try:
        destination = os.environ.get("BACKUP_DESTINATION", "s3")
        if destination == "local":
            result = local_backup()
            status_write(status_path, result)
            return result
        if destination != "s3":
            raise ValueError("Unsupported backup destination")
        s3 = s3 or boto3.client("s3", region_name=os.environ["BACKUP_REGION"])
        bucket = os.environ["BACKUP_BUCKET"]
        prefix = os.environ.get("BACKUP_PREFIX", "kiro-console").strip("/")
        key = f"{prefix}/{datetime.now(timezone.utc):%Y/%m/%d/%H%M%S}-{uuid4().hex[:8]}.kirobk"
        with tempfile.TemporaryDirectory(
            prefix="kiro-backup-", dir=os.environ.get("BACKUP_WORK_DIR")
        ) as temp:
            work = Path(temp)
            archive, manifest = snapshot(
                os.environ["BACKUP_DATABASE_PATH"], os.environ["BACKUP_APP_ENV"], work
            )
            encrypted = work / "backup.kirobk"
            encrypt_archive(archive, encrypted, master_key())
            checksum = digest(encrypted)
            with encrypted.open("rb") as body:
                s3.put_object(
                    Bucket=bucket,
                    Key=key,
                    Body=body,
                    ContentLength=encrypted.stat().st_size,
                    ContentType="application/octet-stream",
                    ServerSideEncryption="AES256",
                    ChecksumSHA256=base64.b64encode(bytes.fromhex(checksum)).decode(),
                    Metadata={"sha256": checksum, "format": "kiro-backup-v1"},
                )
            head = s3.head_object(Bucket=bucket, Key=key)
            if (
                head["ContentLength"] != encrypted.stat().st_size
                or head["Metadata"].get("sha256") != checksum
            ):
                raise ValueError("Uploaded backup metadata mismatch")
            # Every successful backup includes an actual S3 download and restore.
            downloaded = work / "downloaded.kirobk"
            s3.download_file(bucket, key, str(downloaded))
            if digest(downloaded) != checksum:
                raise ValueError("Downloaded backup checksum mismatch")
            decrypted = work / "verified.tar.gz"
            decrypt_archive(downloaded, decrypted, master_key())
            check_archive(decrypted, work / "restore-check")
            result = {
                "status": "ok",
                "destination": "s3",
                "completed_at": timestamp(),
                "object_key": key,
                "bucket": bucket,
                "sha256": checksum,
                "bytes": encrypted.stat().st_size,
                "restore_verified": True,
                "tables": manifest["tables"],
            }
        status_write(status_path, result)
        return result
    except Exception as exc:
        status_write(
            status_path,
            {
                "status": "failed",
                "destination": os.environ.get("BACKUP_DESTINATION", "s3"),
                "failed_at": timestamp(),
                "completed_at": previous.get("completed_at"),
                "object_key": previous.get("object_key"),
                "error": type(exc).__name__,
            },
        )
        raise


def local_backup():
    """Publish only verified encrypted archives; prune only our dated filenames."""
    retention = int(os.environ.get("BACKUP_RETENTION_DAYS", "7"))
    if not 1 <= retention <= 3650:
        raise ValueError("Invalid local backup retention")
    directory = Path(
        os.environ.get("BACKUP_LOCAL_DIR", "/var/lib/kiro-console/backups")
    )
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    stamp = datetime.now(timezone.utc)
    filename = f"kiro-console-{stamp:%Y%m%dT%H%M%SZ}-{uuid4().hex}.kirobk"
    target = directory / filename
    # Same filesystem rename is atomic. The private scratch directory is removed
    # on verification failure, without touching previous recovery archives.
    with tempfile.TemporaryDirectory(prefix=".kiro-backup-", dir=directory) as temp:
        work = Path(temp)
        archive, manifest = snapshot(
            os.environ["BACKUP_DATABASE_PATH"], os.environ["BACKUP_APP_ENV"], work
        )
        encrypted = work / "backup.kirobk"
        encrypt_archive(archive, encrypted, master_key())
        checksum = digest(encrypted)
        decrypted = work / "verified.tar.gz"
        decrypt_archive(encrypted, decrypted, master_key())
        check_archive(decrypted, work / "restore-check")
        with encrypted.open("rb") as stream:
            os.fsync(stream.fileno())
        size = encrypted.stat().st_size
        encrypted.replace(target)
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    cutoff = stamp - timedelta(days=retention)
    pattern = re.compile(r"kiro-console-(\d{8}T\d{6}Z)-[0-9a-f]{32}\.kirobk")
    for item in directory.iterdir():
        match = pattern.fullmatch(item.name)
        if match and item != target and item.is_file() and not item.is_symlink():
            try:
                created = datetime.strptime(match[1], "%Y%m%dT%H%M%SZ").replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                continue
            if created < cutoff:
                item.unlink()
    return {
        "status": "ok",
        "destination": "local",
        "completed_at": timestamp(),
        "object_key": filename,
        "directory": str(directory),
        "retention_days": retention,
        "sha256": checksum,
        "bytes": size,
        "restore_verified": True,
        "tables": manifest["tables"],
    }


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["create", "verify"])
    parser.add_argument("--object-key")
    parser.add_argument("--output-dir")
    args = parser.parse_args()
    try:
        if args.command == "create":
            result = run_backup()
            print(
                json.dumps(
                    {
                        k: result[k]
                        for k in (
                            "status",
                            "completed_at",
                            "object_key",
                            "restore_verified",
                        )
                    }
                )
            )
        else:
            if not args.object_key or not args.output_dir:
                parser.error("verify requires --object-key and --output-dir")
            with tempfile.TemporaryDirectory(prefix="kiro-restore-") as temp:
                source, archive = (
                    Path(temp) / "backup.kirobk",
                    Path(temp) / "backup.tar.gz",
                )
                if os.environ.get("BACKUP_DESTINATION", "s3") == "local":
                    if Path(args.object_key).name != args.object_key:
                        raise ValueError("Invalid local backup name")
                    shutil.copyfile(
                        Path(
                            os.environ.get(
                                "BACKUP_LOCAL_DIR", "/var/lib/kiro-console/backups"
                            )
                        )
                        / args.object_key,
                        source,
                    )
                else:
                    boto3.client(
                        "s3", region_name=os.environ["BACKUP_REGION"]
                    ).download_file(
                        os.environ["BACKUP_BUCKET"], args.object_key, str(source)
                    )
                decrypt_archive(source, archive, master_key())
                manifest = check_archive(archive, args.output_dir)
            print(
                json.dumps(
                    {
                        "status": "verified",
                        "created_at": manifest["created_at"],
                        "tables": manifest["tables"],
                    }
                )
            )
    except Exception as exc:
        # Provider exception strings can contain credential or request details.
        print(f"Backup operation failed: {type(exc).__name__}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
