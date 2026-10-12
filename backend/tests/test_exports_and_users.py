import csv
import io
import json
import re
import uuid

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient
from sqlalchemy import func, select, text, update

from app.database import SessionLocal, engine
from app.init_db import initialize
from app.main import app
from app.migrations import VERSION
from app.models import (
    AuditEvent,
    Batch,
    Binding,
    SchemaVersion,
    Subscription,
    User,
    now,
)
from app.security import encrypt, get_user, make_token
from app.worker import run_one
from conftest import PASSWORD, login
from test_batches import complete_sso
from test_workflows import Gateway, count, create


def csv_rows(response):
    assert response.status_code == 200, response.text
    assert response.content.startswith(b"\xef\xbb\xbf")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-type"].startswith("text/csv")
    assert ".csv" in response.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(response.content.decode("utf-8-sig"))))
    assert int(response.headers["x-export-count"]) == len(rows)
    return rows


def test_export_own_only_filters_and_no_secret_in_audit(alice, bob, admin):
    batch, ids = complete_sso(alice)
    own = csv_rows(alice.post("/api/sso-users/export", json={"owner_id": 3}))
    assert len(own) == 2  # owner_id cannot override member scope.
    assert all(r["密码"] == "AWS-once-password-test" for r in own)
    assert all(r["登录地址"].startswith("https://") for r in own)
    assert all(r["订阅状态"] == "未订阅" and not r["订阅时间(UTC)"] for r in own)
    assert (
        len(csv_rows(alice.post("/api/sso-users/export", json={"q": "person0"}))) == 1
    )
    assert (
        bob.post("/api/sso-users/export", json={"record_ids": ids}).status_code == 404
    )
    assert (
        bob.post("/api/sso-users/export", json={"batch_id": batch["id"]}).status_code
        == 404
    )
    assert bob.post("/api/sso-users/export", json={}).status_code == 409
    assert len(csv_rows(admin.post("/api/sso-users/export", json={"owner_id": 2}))) == 2
    assert admin.post("/api/sso-users/export", json={"owner_id": 3}).status_code == 409
    assert TestClient(app).post("/api/sso-users/export", json={}).status_code == 401
    assert (
        alice.post(
            "/api/sso-users/export", json={}, headers={"X-CSRF-Token": "wrong"}
        ).status_code
        == 403
    )
    assert count() == (0, 0, 0, 1)
    audit = admin.get("/api/audit").text
    assert "export_credentials" in audit and "AWS-once-password-test" not in audit
    assert "AWS-once-password-test" not in alice.get(f"/api/batches/{batch['id']}").text


def test_export_selection_is_all_or_nothing_and_matches_latest_password(alice, bob):
    _, ids = complete_sso(alice)
    _, foreign = complete_sso(bob, 1)
    assert (
        alice.post(
            "/api/sso-users/export", json={"record_ids": [ids[0], foreign[0]]}
        ).status_code
        == 404
    )
    with SessionLocal() as db:
        r = db.get(Subscription, ids[0])
        r.password_encrypted = encrypt("updated-one-time-password")
        r.sso_display_name = ' =HYPERLINK("https://example.invalid"),\n张三'
        r.subscription_status = "cancelled"
        r.plan_name_snapshot = "Kiro Pro"
        r.subscribed_at = now()
        db.get(Subscription, ids[1]).sso_deleted_at = now()
        db.commit()
    assert (
        alice.post("/api/sso-users/export", json={"record_ids": ids}).status_code == 409
    )
    rows = csv_rows(alice.post("/api/sso-users/export", json={}))
    assert len(rows) == 1 and rows[0]["密码"] == "updated-one-time-password"
    assert rows[0]["姓名"].startswith("' =HYPERLINK") and "\n张三" in rows[0]["姓名"]
    assert rows[0]["原绑定套餐"] == "Kiro Pro" and rows[0]["订阅状态"] == "已取消"
    assert rows[0]["订阅时间(UTC)"].endswith("Z")
    with SessionLocal() as db:
        db.get(Subscription, ids[0]).active_operation_id = str(uuid.uuid4())
        db.commit()
    assert alice.post("/api/sso-users/export", json={}).status_code == 409
    assert (
        alice.post("/api/sso-users/export", json={"record_ids": [ids[0]]}).status_code
        == 409
    )


def test_export_flag_persists_partial_batch_and_idempotency(alice):
    body = {
        "kind": "sso",
        "aws_account_id": 1,
        "sequence": {"pattern": "export-01-03"},
        "export_credentials": True,
        "request_key": str(uuid.uuid4()),
    }
    response = alice.post("/api/batches/create", json=body)
    assert response.status_code == 202, response.text
    batch = response.json()
    assert batch["export_credentials"] and batch["owner_id"] == 2
    assert not any(i["has_credentials"] for i in batch["items"])
    assert (
        alice.post("/api/sso-users/export", json={"batch_id": batch["id"]}).status_code
        == 409
    )
    run_one(Gateway)
    assert (
        len(
            csv_rows(
                alice.post("/api/sso-users/export", json={"batch_id": batch["id"]})
            )
        )
        == 1
    )
    repeated = alice.post("/api/batches/create", json=body).json()
    assert repeated["id"] == batch["id"]
    assert [i["email"] for i in repeated["items"]] == [
        i["email"] for i in batch["items"]
    ]
    assert (
        alice.post(
            "/api/batches/create", json={**body, "export_credentials": False}
        ).status_code
        == 409
    )
    run_one(Gateway)
    run_one(Gateway)
    rows = csv_rows(alice.post("/api/sso-users/export", json={"batch_id": batch["id"]}))
    assert len(rows) == 3 and all(
        re.fullmatch(r"export-\d@[a-z]{8,12}\.com", r["邮箱"]) for r in rows
    )
    assert count() == (0, 0, 0, 1)


@pytest.mark.parametrize(
    "body",
    [
        {"record_ids": []},
        {"record_ids": ["a", "a"]},
        {"record_ids": ["a"], "batch_id": "b"},
        {"status": "invalid"},
        {"role": "admin"},
    ],
)
def test_invalid_export_scope(alice, body):
    assert alice.post("/api/sso-users/export", json=body).status_code == 422


def test_delete_disabled_user_retains_aws_records_and_history(alice, bob, admin):
    Gateway.mode = "ok"
    record = create(alice).json()
    run_one(Gateway)
    assert admin.delete("/api/admin/users/2").status_code == 409
    assert bob.delete("/api/admin/users/2").status_code == 403
    assert admin.patch("/api/admin/users/2", json={"active": False}).status_code == 200
    assert admin.delete("/api/admin/users/2").status_code == 200
    assert admin.delete("/api/admin/users/2").status_code == 200
    assert alice.get("/api/auth/me").status_code == 401
    assert (
        TestClient(app)
        .post("/api/auth/login", json={"username": "alice", "password": PASSWORD})
        .status_code
        == 401
    )
    assert admin.patch("/api/admin/users/2", json={"active": True}).status_code == 404
    assert (
        admin.put("/api/admin/users/2/bindings", json={"account_ids": [1]}).status_code
        == 404
    )
    assert (
        admin.post(
            "/api/admin/users/2/counters/1/reset", json={"expected_cycle": 1}
        ).status_code
        == 404
    )
    assert 2 not in [u["id"] for u in admin.get("/api/admin/users").json()]
    assert 2 not in [c["user_id"] for c in admin.get("/api/counters").json()]
    summary = admin.get("/api/overview").json()["member_summary"]
    assert 2 not in [u["id"] for u in summary["users"]]
    assert count() == (1, 0, 1, 1)
    assert admin.get(f"/api/subscriptions/{record['id']}").status_code == 200
    assert admin.get("/api/sso-users?owner_id=2").json()["total"] == 1
    assert len(csv_rows(admin.post("/api/sso-users/export", json={"owner_id": 2}))) == 1
    assert admin.get("/api/admin/users/2/plan-history?plan_id=1").json()["total"] == 1
    with SessionLocal() as db:
        assert db.get(User, 2).deleted_at and not db.get(Binding, (2, 1))
        r = db.get(Subscription, record["id"])
        assert r.subscription_status == "active" and r.sso_deleted_at is None
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "delete_member")
            )
            == 1
        )


def test_delete_and_role_change_block_unfinished_jobs_and_rollback(alice, admin):
    create(alice)
    assert admin.patch("/api/admin/users/2", json={"role": "admin"}).status_code == 409
    assert (
        alice.get("/api/auth/me").status_code == 200
    )  # Failed update did not invalidate token.
    assert admin.patch("/api/admin/users/2", json={"active": False}).status_code == 200
    assert admin.delete("/api/admin/users/2").status_code == 409
    with SessionLocal() as db:
        assert db.get(User, 2).deleted_at is None
        assert db.get(User, 2).role == "member" and db.get(Binding, (2, 1))


def test_create_admin_and_default_member_and_role_validation(admin, alice):
    body = {
        "username": "second-admin",
        "display_name": "第二管理员",
        "password": PASSWORD,
        "role": "admin",
    }
    assert alice.post("/api/admin/users", json=body).status_code == 403
    assert (
        admin.post("/api/admin/users", json={**body, "role": "superuser"}).status_code
        == 422
    )
    result = admin.post("/api/admin/users", json=body)
    assert result.status_code == 201 and result.json()["role"] == "admin"
    c = login("second-admin")
    assert (
        c.get("/api/admin/users").status_code == 403
    )  # First password change is mandatory.
    changed = c.post(
        "/api/auth/change-password",
        json={"old_password": PASSWORD, "new_password": "new-admin-password-123"},
    )
    assert changed.status_code == 200
    c.headers["X-CSRF-Token"] = changed.json()["csrf"]
    assert c.get("/api/admin/users").status_code == 200
    assert len(c.get("/api/accounts").json()) == 1  # Admin needs no binding.
    result = admin.post(
        "/api/admin/users",
        json={
            k: v for k, v in {**body, "username": "new-member"}.items() if k != "role"
        },
    )
    assert result.status_code == 201 and result.json()["role"] == "member"


def test_role_changes_invalidate_sessions_preserve_counts_and_restore_isolation(
    admin, alice, bob
):
    Gateway.mode = "ok"
    create(alice)
    run_one(Gateway)
    assert bob.patch("/api/admin/users/2", json={"role": "admin"}).status_code == 403
    assert (
        admin.patch("/api/admin/users/2", json={"role": "admin"}).json()["role"]
        == "admin"
    )
    assert alice.get("/api/admin/users").status_code == 401
    upgraded = login("alice")
    assert upgraded.get("/api/admin/users").status_code == 200
    create(upgraded)
    run_one(Gateway)
    admin_summary = next(
        u
        for u in admin.get("/api/overview").json()["member_summary"]["users"]
        if u["id"] == 2
    )
    assert (
        next(c for c in admin_summary["counters"] if c["plan_id"] == 1)[
            "lifetime_count"
        ]
        == 2
    )
    assert (
        admin.patch("/api/admin/users/2", json={"role": "member"}).json()["role"]
        == "member"
    )
    assert upgraded.get("/api/admin/users").status_code == 401
    downgraded = login("alice")
    assert downgraded.get("/api/admin/users").status_code == 403
    assert count() == (
        1,
        0,
        2,
        1,
    )  # Unlimited admin activation is historical, not current-round usage.
    assert "member_summary" not in downgraded.get("/api/overview").json()
    assert all(c["user_id"] == 2 for c in downgraded.get("/api/counters").json())


@pytest.mark.parametrize(
    "body", [{"active": False}, {"role": "member"}, {"role": "member", "active": False}]
)
def test_current_admin_cannot_disable_or_demote_itself(admin, body):
    assert admin.patch("/api/admin/users/1", json=body).status_code == 409
    assert admin.delete("/api/admin/users/1").status_code == 409
    assert admin.get("/api/admin/users").status_code == 200
    with SessionLocal() as db:
        assert db.get(User, 1).active and db.get(User, 1).role == "admin"


def test_summary_one_row_per_user_and_history_filters(admin, alice, bob):
    Gateway.mode = "ok"
    create(alice)
    run_one(Gateway)
    assert (
        admin.post(
            "/api/admin/users/2/counters/1/reset", json={"expected_cycle": 1}
        ).status_code
        == 200
    )
    summary = admin.get("/api/overview").json()["member_summary"]
    assert [u["id"] for u in summary["users"]] == [1, 2, 3]
    u = summary["users"][1]
    assert u["sso_total"] == u["sso_active"] == 1 and u["pending_tasks"] == 0
    c = next(c for c in u["counters"] if c["plan_id"] == 1)
    assert (c["lifetime_count"], c["used_count"], c["cycle_number"]) == (1, 0, 2)
    base = "/api/admin/users/2/plan-history?plan_id=1"
    assert alice.get(base).status_code == 403 and bob.get(base).status_code == 403
    assert admin.get(base).json()["total"] == 1
    assert admin.get(base + "&kind=resets").json()["items"][0]["used_count"] == 1
    assert admin.get(base + "&page=2").json()["items"] == []
    assert admin.get("/api/admin/users/2/plan-history?plan_id=2").json()["total"] == 0
    assert admin.get("/api/admin/users/3/plan-history?plan_id=1").json()["total"] == 0
    assert admin.get("/api/sso-users?owner_id=2").json()["total"] == 1
    assert admin.get("/api/sso-users?owner_id=3").json()["total"] == 0
    assert alice.get("/api/sso-users?owner_id=3").json()["total"] == 1


def test_schema_three_migration_preserves_users_batches_and_credentials(alice):
    batch, ids = complete_sso(alice)
    with engine.begin() as conn:
        user_before = conn.execute(
            text(
                "SELECT id, username, password_hash, role, session_version FROM console_users ORDER BY id"
            )
        ).fetchall()
        batch_before = conn.execute(
            text("SELECT id, owner_id, payload_hash FROM console_batches")
        ).fetchall()
        conn.exec_driver_sql("ALTER TABLE console_users DROP COLUMN deleted_at")
        conn.exec_driver_sql(
            "ALTER TABLE console_batches DROP COLUMN export_credentials"
        )
        conn.execute(text("INSERT INTO console_schema_version (version) VALUES (3)"))
    initialize()
    initialize()
    with engine.connect() as conn:
        assert (
            conn.execute(
                text(
                    "SELECT id, username, password_hash, role, session_version FROM console_users ORDER BY id"
                )
            ).fetchall()
            == user_before
        )
        assert (
            conn.execute(
                text("SELECT id, owner_id, payload_hash FROM console_batches")
            ).fetchall()
            == batch_before
        )
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
    with SessionLocal() as db:
        assert db.scalar(select(SchemaVersion.version)) == VERSION
        assert (
            db.get(User, 2).deleted_at is None
            and not db.get(Batch, batch["id"]).export_credentials
        )
    assert (
        len(csv_rows(alice.post("/api/sso-users/export", json={"record_ids": ids})))
        == 2
    )


def test_old_batch_idempotency_hash_unchanged_without_export_flag(alice):
    # Existing hash format is sha256(JSON of all fields other than request_key).
    from app.batches import CreateBatchInput
    import hashlib

    body = {
        "kind": "sso",
        "aws_account_id": 1,
        "items": [{"username": "legacy", "email": "legacy@example.com"}],
        "request_key": str(uuid.uuid4()),
    }
    response = alice.post("/api/batches/create", json=body)
    assert response.status_code == 202
    expected = hashlib.sha256(
        json.dumps(
            CreateBatchInput(**body).model_dump(
                mode="json",
                exclude={
                    "request_key",
                    "export_credentials",
                    "stop_schedule",
                    "group_id",
                },
            ),
            sort_keys=True,
        ).encode()
    ).hexdigest()
    with SessionLocal() as db:
        assert db.get(Batch, response.json()["id"]).payload_hash == expected
    assert (
        alice.post(
            "/api/batches/create", json={**body, "export_credentials": False}
        ).json()["id"]
        == response.json()["id"]
    )


def test_revocation_between_auth_read_and_write_is_rejected():
    with SessionLocal() as db:
        stale_user = db.get(User, 1)
        token = make_token(stale_user, "test-csrf")
        with SessionLocal() as other:
            other.execute(
                update(User)
                .where(User.id == 1)
                .values(session_version=User.session_version + 1)
            )
            other.commit()
        request = Request(
            {
                "type": "http",
                "method": "POST",
                "path": "/api/admin/users",
                "headers": [
                    (b"cookie", f"kiro_session={token}".encode()),
                    (b"x-csrf-token", b"test-csrf"),
                ],
            }
        )
        with pytest.raises(HTTPException) as exc:
            get_user(request, db)
        assert exc.value.status_code == 401
