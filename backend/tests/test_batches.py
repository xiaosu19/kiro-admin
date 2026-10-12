import concurrent.futures
import re
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.schema import CreateIndex, CreateTable

from app.aws import AwsFailure
from app.database import SessionLocal, engine
from app.init_db import initialize
from app.migrations import VERSION
from app.models import Binding, RecordOperation, SchemaVersion, Subscription
from app.worker import run_one
from conftest import login
from test_workflows import Gateway, count


@pytest.fixture(autouse=True)
def gateway():
    Gateway.mode = "ok"
    Gateway.calls = 0


def create_batch(client, n=2, kind="sso", plan=1, key=None):
    return client.post(
        "/api/batches/create",
        json={
            "kind": kind,
            "aws_account_id": 1,
            "plan_id": plan if kind == "subscribed" else None,
            "items": [
                {"username": f"person{i}", "email": f"person{i}@example.com"}
                for i in range(n)
            ],
            "request_key": key or str(uuid.uuid4()),
        },
    )


def subscribe(client, ids, plan=1, key=None):
    return client.post(
        "/api/batches/subscribe",
        json={
            "record_ids": ids,
            "plan_id": plan,
            "request_key": key or str(uuid.uuid4()),
        },
    )


def complete_sso(client, n=2):
    response = create_batch(client, n)
    assert response.status_code == 202, response.text
    batch = response.json()
    for _ in range(n):
        assert run_one(Gateway)
    return batch, [i["id"] for i in batch["items"]]


def test_sso_only_without_quota_is_private_and_has_password(alice, bob, admin):
    batch, ids = complete_sso(alice, 3)  # Exceeds Pro quota, but no subscription.
    assert count() == (0, 0, 0, 1)
    assert Gateway.calls == 0
    assert alice.get("/api/overview").json()["subscribed"] == 0
    assert alice.get(f"/api/batches/{batch['id']}").json()["states"]["completed"] == 3
    assert bob.get("/api/batches").json() == []
    assert bob.get(f"/api/batches/{batch['id']}").status_code == 404
    assert admin.get(f"/api/batches/{batch['id']}").status_code == 200
    for rid in ids:
        r = alice.get(f"/api/subscriptions/{rid}").json()
        assert r["plan_id"] is None and r["subscription_type"] is None
        assert r["provision_only"] and not r["counted"]
        assert (
            r["subscribed_at"] is None and r["subscription_status"] == "not_subscribed"
        )
        assert alice.post(f"/api/subscriptions/{rid}/credentials").status_code == 200
        assert bob.post(f"/api/subscriptions/{rid}/credentials").status_code == 404


def test_sso_later_subscribed_once_without_recreation(alice):
    original, ids = complete_sso(alice)
    before = [alice.get(f"/api/subscriptions/{rid}").json() for rid in ids]
    response = subscribe(alice, ids)
    assert response.status_code == 202, response.text
    assert count() == (0, 2, 0, 1)

    class Existing(Gateway):
        def create_user(self, r):
            raise AssertionError("must reuse existing SSO")

        def password(self, r):
            raise AssertionError("must retain password")

    for _ in ids:
        run_one(Existing)
    assert count() == (2, 0, 2, 1)
    for old in before:
        new = alice.get(f"/api/subscriptions/{old['id']}").json()
        assert new["state"] == "completed" and new["subscribed_at"]
        assert new["sso_user_id"] == old["sso_user_id"]
        assert new["password_generated_at"] == old["password_generated_at"]
        assert not new["provision_only"] and new["plan_id"] == 1
    assert (
        alice.get(f"/api/batches/{original['id']}").json()["states"]["completed"] == 2
    )
    assert subscribe(alice, ids, plan=2).status_code == 409
    assert count(2) == (0, 0, 0, 1)


def test_quota_rejection_rolls_back_entire_batch(alice):
    assert create_batch(alice, 3, "subscribed").status_code == 409
    assert count() == (0, 0, 0, 1)
    assert alice.get("/api/batches").json() == []
    assert alice.get("/api/subscriptions").json()["total"] == 0
    _, ids = complete_sso(alice, 3)
    assert subscribe(alice, ids).status_code == 409
    assert count() == (0, 0, 0, 1)
    assert all(
        alice.get(f"/api/subscriptions/{rid}").json()["plan_id"] is None for rid in ids
    )


def test_idempotency_and_payload_conflict(alice):
    key = str(uuid.uuid4())
    a = create_batch(alice, key=key).json()
    assert create_batch(alice, key=key).json()["id"] == a["id"]
    assert create_batch(alice, 1, key=key).status_code == 409
    for _ in range(2):
        run_one(Gateway)
    ids = [i["id"] for i in a["items"]]
    key = str(uuid.uuid4())
    b = subscribe(alice, ids, key=key).json()
    assert subscribe(alice, ids, key=key).json()["id"] == b["id"]
    assert count() == (0, 2, 0, 1)


def test_mixed_success_failure_retries_independently(alice):
    response = create_batch(alice, kind="subscribed")
    assert response.status_code == 202, response.text
    batch = response.json()

    class Mixed(Gateway):
        def subscribe(self, r):
            if r.username.startswith("person1-"):
                raise AwsFailure("test denied")
            return "ok"

    run_one(Mixed)
    run_one(Mixed)
    state = alice.get(f"/api/batches/{batch['id']}").json()
    assert state["states"]["completed"] == state["states"]["failed"] == 1
    assert count() == (1, 0, 1, 1)
    failed = next(i for i in state["items"] if i["state"] == "failed")
    assert alice.post(f"/api/subscriptions/{failed['id']}/retry").status_code == 202
    run_one(Gateway)
    assert count() == (2, 0, 2, 1)
    assert alice.get(f"/api/batches/{batch['id']}").json()["states"]["completed"] == 2


def test_uncertain_batch_does_not_replay_subscription(alice):
    b = create_batch(alice, 1, "subscribed").json()
    rid = b["items"][0]["id"]
    Gateway.mode = "unknown"
    run_one(Gateway)
    assert count() == (0, 1, 0, 1)
    assert alice.get(f"/api/batches/{b['id']}").json()["states"]["needs_review"] == 1
    Gateway.mode = "reconciled"
    alice.post(f"/api/subscriptions/{rid}/retry")
    run_one(Gateway)
    assert Gateway.calls == 1 and count() == (1, 0, 1, 1)


def test_members_cannot_subscribe_other_owners_and_admin_uses_owner_quota(
    alice, bob, admin
):
    _, ids = complete_sso(alice)
    assert subscribe(bob, ids).status_code == 404
    assert subscribe(admin, ids).status_code == 202
    assert count() == (0, 2, 0, 1)
    assert count(3) == (0, 0, 0, 1)
    for _ in ids:
        run_one(Gateway)
    assert count() == (2, 0, 2, 1)
    assert all(
        i["actor_name"] != "管理员" for i in alice.get("/api/audit").json()["items"]
    )


def test_unbound_account_and_selection_validation(alice):
    _, ids = complete_sso(alice)
    assert subscribe(alice, [ids[0], ids[0]]).status_code == 422
    assert create_batch(alice, 101).status_code == 422
    with SessionLocal() as db:
        db.delete(db.get(Binding, (2, 1)))
        db.commit()
    assert create_batch(alice).status_code == 403
    assert subscribe(alice, ids).status_code == 403
    assert count() == (0, 0, 0, 1)


def test_busy_sso_rejects_whole_selection(alice):
    _, ids = complete_sso(alice)
    op = alice.post(
        f"/api/subscriptions/{ids[1]}/operations",
        json={
            "kind": "update_sso",
            "request_key": str(uuid.uuid4()),
            "display_name": "New Name",
            "email": "new@example.com",
        },
    )
    assert op.status_code == 202, op.text
    assert subscribe(alice, ids).status_code == 409
    assert alice.get(f"/api/subscriptions/{ids[0]}").json()["plan_id"] is None
    assert count() == (0, 0, 0, 1)


def test_concurrent_batches_cannot_over_allocate(alice):
    clients = [login("alice") for _ in range(3)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        statuses = list(
            pool.map(lambda c: create_batch(c, 2, "subscribed").status_code, clients)
        )
    assert statuses.count(202) == 1 and statuses.count(409) == 2
    assert count() == (0, 2, 0, 1)
    assert alice.get("/api/subscriptions").json()["total"] == 2


def test_sso_failure_retries_without_requiring_a_plan(alice):
    b = create_batch(alice, 1).json()
    rid = b["items"][0]["id"]

    class Unavailable(Gateway):
        def verify(self):
            raise AwsFailure("temporary failure")

    run_one(Unavailable)
    assert alice.post(f"/api/subscriptions/{rid}/retry").status_code == 202
    run_one(Gateway)
    assert count() == (0, 0, 0, 1)
    assert alice.get(f"/api/batches/{b['id']}").json()["states"]["completed"] == 1


def test_sso_only_does_not_check_subscription_service(alice):
    class IdentityOnly(Gateway):
        def verify(self):
            raise AssertionError("SSO creation must not depend on Kiro availability")

        def verify_identity(self):
            return "123456789012"

    b = create_batch(alice, 1).json()
    run_one(IdentityOnly)
    assert alice.get(f"/api/batches/{b['id']}").json()["states"]["completed"] == 1
    assert count() == (0, 0, 0, 1)


def sequence_batch(client, pattern="member-01-10", key=None):
    return client.post(
        "/api/batches/create",
        json={
            "kind": "sso",
            "aws_account_id": 1,
            "sequence": {"pattern": pattern, "email_template": "team+{n}@example.com"},
            "request_key": key or str(uuid.uuid4()),
        },
    )


def test_sequence_generates_exact_names_emails_and_is_idempotent(alice):
    key = str(uuid.uuid4())
    response = sequence_batch(alice, key=key)
    assert response.status_code == 202, response.text
    b = response.json()
    assert [i["username"] for i in b["items"]] == [f"member-{n}" for n in range(1, 11)]
    assert [i["email"] for i in b["items"]] == [
        f"team+{n}@example.com" for n in range(1, 11)
    ]
    assert sequence_batch(alice, key=key).json()["id"] == b["id"]
    assert sequence_batch(alice).status_code == 409
    assert alice.get("/api/subscriptions").json()["total"] == 10
    assert count() == (0, 0, 0, 1)
    for _ in range(10):
        run_one(Gateway)
    assert alice.get("/api/sso-users?status=unsubscribed").json()["total"] == 10
    ids = [i["id"] for i in b["items"][:2]]
    assert subscribe(alice, ids).status_code == 202
    assert alice.get("/api/sso-users?status=unsubscribed").json()["total"] == 8


@pytest.mark.parametrize(
    "pattern",
    [
        "member-0-10",
        "member-10-1",
        "member-1-101",
        "member-1-10000000",
        "member-1",
        "a b-1-3",
    ],
)
def test_invalid_sequence_has_no_side_effects(alice, pattern):
    assert sequence_batch(alice, pattern).status_code == 422
    assert alice.get("/api/subscriptions").json()["total"] == 0


def test_sequence_collision_does_not_expose_other_owner(alice, bob):
    assert sequence_batch(bob, "team-1-1").status_code == 202
    response = sequence_batch(alice, "team-1-2")
    assert response.status_code == 409
    assert "bob" not in response.text
    assert alice.get("/api/subscriptions").json()["total"] == 0


@pytest.mark.parametrize("mode", ["list", "sequence"])
def test_blank_emails_generate_unique_addresses_once_per_request(alice, mode):
    body = {
        "kind": "sso",
        "aws_account_id": 1,
        "request_key": str(uuid.uuid4()),
    }
    if mode == "sequence":
        body["sequence"] = {"pattern": "autouser-01-10", "email_template": ""}
    else:
        body["items"] = [
            {"username": "autouser1"},
            {"username": "autouser2", "email": " "},
            {"username": "autouser3", "email": None},
            {"username": "autouser4", "email": "explicit@example.com"},
        ]
    response = alice.post("/api/batches/create", json=body)
    assert response.status_code == 202, response.text
    batch = response.json()
    assert alice.post("/api/batches/create", json=body).json() == batch
    emails = [r["email"] for r in batch["items"]]
    assert len(emails) == len(set(emails))
    for row in batch["items"]:
        if row["email"] == "explicit@example.com":
            continue
        assert re.fullmatch(
            re.escape(row["username"]) + r"@[a-z]{8,12}\.com", row["email"]
        )
        assert run_one(Gateway)
        assert (
            alice.get(f"/api/subscriptions/{row['id']}").json()["email"] == row["email"]
        )
    assert count() == (0, 0, 0, 1)


def test_generated_email_is_valid_for_long_or_punctuation_usernames():
    from pydantic import EmailStr, TypeAdapter
    from app.email_addresses import generated_email

    for name in ["x" * 78, "..", "-_.a..b-_"]:
        address = generated_email(name)
        assert TypeAdapter(EmailStr).validate_python(address) == address
        assert len(address.split("@")[0]) <= 64


@pytest.mark.parametrize("mode", ["list", "sequence"])
def test_duplicate_explicit_batch_emails_rejected_before_creating_jobs(alice, mode):
    body = {"kind": "sso", "aws_account_id": 1, "request_key": str(uuid.uuid4())}
    if mode == "list":
        body["items"] = [
            {"username": "one", "email": "same@example.com"},
            {"username": "two", "email": "same@example.com"},
        ]
    else:
        body["sequence"] = {
            "pattern": "same-01-02",
            "email_template": "same@example.com",
        }
    assert alice.post("/api/batches/create", json=body).status_code == 422
    assert alice.get("/api/subscriptions").json()["total"] == 0


@pytest.mark.parametrize(
    "field,value", [("sso_deleted_at", "deleted"), ("subscription_status", "active")]
)
def test_deleted_or_externally_subscribed_sso_cannot_be_bulk_subscribed(
    alice, field, value
):
    from app.models import now

    _, ids = complete_sso(alice, 1)
    with SessionLocal() as db:
        r = db.get(Subscription, ids[0])
        setattr(r, field, now() if field == "sso_deleted_at" else value)
        db.commit()
    assert subscribe(alice, ids).status_code == 409
    assert count() == (0, 0, 0, 1)
    if field == "subscription_status":
        assert alice.get(f"/api/subscriptions/{ids[0]}").json()[field] == "active"


def test_backup_contains_separate_creation_and_subscription_batch_history(
    alice, tmp_path
):
    from app import backup
    from app.config import settings
    import sqlite3

    _, ids = complete_sso(alice)
    assert subscribe(alice, ids).status_code == 202
    run_one(Gateway)
    run_one(Gateway)
    config = tmp_path / "source.env"
    config.write_text(
        f"FERNET_KEY={settings.fernet_key}\nSECRET_KEY={settings.secret_key}\n"
    )
    archive, _ = backup.snapshot(engine.url.database, config, tmp_path)
    manifest = backup.check_archive(archive, tmp_path / "restored")
    assert manifest["tables"]["console_batches"] == 2
    assert manifest["tables"]["console_batch_items"] == 4
    with sqlite3.connect(tmp_path / "restored" / "console.db") as db:
        assert (
            db.execute(
                "SELECT count(*) FROM console_batch_items WHERE state='completed'"
            ).fetchone()[0]
            == 4
        )
        assert (
            db.execute(
                "SELECT used_count FROM console_plan_counters WHERE id=1"
            ).fetchone()[0]
            == 2
        )


def test_v2_not_null_rebuild_preserves_rows_indexes_and_operation_foreign_key(alice):
    b = create_batch(alice, 1, "subscribed").json()
    run_one(Gateway)
    rid = b["items"][0]["id"]
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        # Remove new batch metadata to emulate a real v2 database.
        r.batch_id = None
        db.add(
            RecordOperation(
                id=str(uuid.uuid4()),
                record_id=rid,
                actor_id=2,
                kind="sync_status",
                request_key=str(uuid.uuid4()),
                payload="{}",
            )
        )
        db.add(SchemaVersion(version=2))
        db.commit()
    table = Subscription.__table__
    legacy_columns = [
        c.name for c in table.columns if c.name not in {"provision_only", "batch_id"}
    ]
    names = ",".join('"' + c + '"' for c in legacy_columns)
    ddl = str(CreateTable(table).compile(dialect=engine.dialect))
    ddl = "\n".join(
        line
        for line in ddl.splitlines()
        if not line.lstrip().startswith(("provision_only ", "batch_id "))
    )
    ddl = ddl.replace(
        "CREATE TABLE console_subscriptions", "CREATE TABLE legacy_subscriptions", 1
    )
    ddl = ddl.replace("plan_id INTEGER,", "plan_id INTEGER NOT NULL,")
    ddl = ddl.replace(
        "subscription_type VARCHAR(100),", "subscription_type VARCHAR(100) NOT NULL,"
    )
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
        conn.commit()
        conn.exec_driver_sql("BEGIN IMMEDIATE")
        before = conn.exec_driver_sql(
            f"SELECT {names} FROM console_subscriptions"
        ).fetchall()
        conn.exec_driver_sql(ddl)
        conn.exec_driver_sql(
            f"INSERT INTO legacy_subscriptions ({names}) SELECT {names} FROM console_subscriptions"
        )
        conn.exec_driver_sql("DROP TABLE console_subscriptions")
        conn.exec_driver_sql(
            "ALTER TABLE legacy_subscriptions RENAME TO console_subscriptions"
        )
        for index in table.indexes:
            conn.execute(CreateIndex(index))
        conn.commit()
        conn.exec_driver_sql("PRAGMA foreign_keys=ON")
        conn.commit()
    initialize()
    initialize()
    with engine.connect() as conn:
        assert (
            conn.exec_driver_sql(
                f"SELECT {names} FROM console_subscriptions"
            ).fetchall()
            == before
        )
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
        assert conn.exec_driver_sql("PRAGMA integrity_check").scalar() == "ok"
        assert (
            conn.execute(text("SELECT version FROM console_schema_version")).scalar()
            == VERSION
        )
    assert count() == (1, 0, 1, 1)
    assert create_batch(alice, 1).status_code == 202  # Null plan now allowed.
