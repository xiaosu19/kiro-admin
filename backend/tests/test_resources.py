import uuid

import pytest
from sqlalchemy import func, select, text

from app.database import SessionLocal, engine
from app.init_db import initialize
from app.migrations import VERSION
from app.models import (
    AuditEvent,
    AwsAccount,
    Binding,
    Plan,
    RecordOperation,
    SchemaVersion,
    Subscription,
    User,
)
from app.security import decrypt
from app.worker import run_one
from test_workflows import Gateway, count, create


def remove(client, kind, name, resource_id=1):
    return client.request(
        "DELETE", f"/api/admin/{kind}/{resource_id}", json={"confirm_name": name}
    )


def aws_body(admin, **changes):
    result = admin.get("/api/admin/aws/1").json()
    body = {
        key: result[key]
        for key in (
            "name",
            "region",
            "subscription_region",
            "control_plane",
            "identity_store_id",
            "instance_arn",
            "application_arn",
            "profile_arn",
            "portal_url",
            "active",
        )
    }
    return body | changes


def test_aws_crud_keeps_credentials_private_and_status_works_offline(
    admin, monkeypatch
):
    monkeypatch.setattr("app.main.aws.AwsGateway", Gateway)
    body = aws_body(
        admin,
        name="另一个 AWS",
        access_key_id="TEST_ACCESS_KEY_16",
        secret_access_key="TEST_SECRET_KEY_16",
    )
    added = admin.post("/api/admin/aws", json=body)
    assert added.status_code == 201
    aid = added.json()["id"]
    body["name"] = "修改后的 AWS"
    assert admin.put(f"/api/admin/aws/{aid}", json=body).status_code == 200
    detail = admin.get(f"/api/admin/aws/{aid}")
    assert detail.json()["name"] == body["name"]
    assert (
        "TEST_SECRET_KEY" not in detail.text
        and "credentials_encrypted" not in detail.text
    )
    monkeypatch.setattr(
        Gateway,
        "verify",
        lambda self: pytest.fail("Status and removal must not call AWS"),
    )
    assert (
        admin.patch(f"/api/admin/aws/{aid}/status", json={"active": False}).status_code
        == 200
    )
    assert (
        admin.patch(f"/api/admin/aws/{aid}/status", json={"active": True}).status_code
        == 200
    )
    assert remove(admin, "aws", body["name"], aid).status_code == 200
    assert remove(admin, "aws", body["name"], aid).status_code == 200
    assert admin.post(f"/api/admin/aws/{aid}/restore").status_code == 200
    assert not admin.get(f"/api/admin/aws/{aid}").json()["active"]
    with SessionLocal() as db:
        assert (
            db.scalar(
                select(func.count())
                .select_from(AuditEvent)
                .where(AuditEvent.action == "delete_aws")
            )
            == 1
        )


def test_aws_removal_retains_records_counters_and_can_be_restored(admin, alice):
    Gateway.mode = "ok"
    rid = create(alice).json()["id"]
    run_one(Gateway)
    before = alice.get(f"/api/subscriptions/{rid}").json()
    assert admin.get("/api/admin/aws/1").json()["usage"]["sso_active"] == 1
    assert remove(admin, "aws", "错误名称").status_code == 409
    assert remove(admin, "aws", "测试 AWS").status_code == 200
    assert admin.get("/api/accounts").json() == []
    deleted = admin.get("/api/accounts?include_deleted=true").json()[0]
    assert (
        deleted["deleted_at"] and not deleted["active"] and deleted["bound_users"] == 0
    )
    assert alice.get("/api/accounts?include_deleted=true").json() == []
    assert admin.get("/api/overview").json()["aws_accounts"] == 0
    after = alice.get(f"/api/subscriptions/{rid}").json()
    for key in (
        "sso_user_id",
        "subscribed_at",
        "subscription_status",
        "plan_name",
        "sso_deleted_at",
    ):
        assert after[key] == before[key]
    assert count() == (1, 0, 1, 1)
    assert (
        admin.put("/api/admin/users/2/bindings", json={"account_ids": [1]}).status_code
        == 404
    )
    assert (
        admin.patch("/api/admin/aws/1/status", json={"active": True}).status_code == 404
    )
    assert create(admin).status_code == 403
    assert admin.post("/api/admin/aws/1/restore").status_code == 200
    assert create(admin).status_code == 403
    assert (
        admin.patch("/api/admin/aws/1/status", json={"active": True}).status_code == 200
    )
    assert alice.get("/api/accounts").json() == []
    assert (
        admin.put("/api/admin/users/2/bindings", json={"account_ids": [1]}).status_code
        == 200
    )
    assert alice.get("/api/accounts").json()[0]["id"] == 1
    with SessionLocal() as db:
        assert (
            decrypt(db.get(AwsAccount, 1).credentials_encrypted)["secret_access_key"]
            == "TEST_SECRET_KEY"
        )


def test_plan_crud_preserves_history_counts_and_catalog_deletion(admin, alice):
    Gateway.mode = "ok"
    rid = create(alice).json()["id"]
    run_one(Gateway)
    plan = admin.get("/api/admin/plans/1").json()
    assert plan["usage"]["records"] == 1
    assert remove(admin, "plans", plan["name"]).status_code == 200
    assert len(admin.get("/api/plans").json()) == 1
    assert len(alice.get("/api/plans?include_deleted=true").json()) == 1
    assert count() == (1, 0, 1, 1)
    assert alice.get(f"/api/subscriptions/{rid}").json()["plan_name"] == "Kiro Pro"
    assert admin.get("/api/admin/users/2/plan-history?plan_id=1").json()["total"] == 1
    assert create(alice).status_code == 404
    body = {key: plan[key] for key in ("name", "code", "subscription_type", "active")}
    assert admin.post("/api/admin/plans", json=body).status_code == 409
    assert admin.put("/api/admin/plans/1", json=body).status_code == 404
    assert (
        admin.put("/api/admin/users/2/counters/1", json={"limit_count": 10}).status_code
        == 404
    )
    assert (
        admin.post(
            "/api/admin/users/2/counters/1/reset", json={"expected_cycle": 1}
        ).status_code
        == 409
    )
    initialize()
    with SessionLocal() as db:
        assert db.get(Plan, 1).deleted_at
    # Removing a catalog entry does not block cancellation of existing subscriptions.
    response = alice.post(
        f"/api/subscriptions/{rid}/operations",
        json={
            "kind": "cancel_subscription",
            "request_key": str(uuid.uuid4()),
            "confirm_username": alice.get(f"/api/subscriptions/{rid}").json()[
                "username"
            ],
        },
    )
    assert response.status_code == 202
    assert admin.post("/api/admin/plans/1/restore").status_code == 200
    assert not admin.get("/api/admin/plans/1").json()["active"]
    assert (
        admin.patch("/api/admin/plans/1/status", json={"active": True}).status_code
        == 200
    )
    body["name"] = "自定义 Pro 名称"
    assert admin.put("/api/admin/plans/1", json=body).status_code == 200
    assert alice.get(f"/api/subscriptions/{rid}").json()["plan_name"] == "Kiro Pro"


@pytest.mark.parametrize("kind,name", [("plans", "Kiro Pro")])
@pytest.mark.parametrize("state", ["queued", "running", "needs_review"])
def test_removal_blocks_pending_tasks_and_rolls_back(admin, alice, kind, name, state):
    rid = create(alice).json()["id"]
    with SessionLocal() as db:
        db.get(Subscription, rid).state = state
        db.commit()
    assert remove(admin, kind, name).status_code == 409
    with SessionLocal() as db:
        resource = db.get(AwsAccount if kind == "aws" else Plan, 1)
        assert not resource.deleted_at and resource.active
        assert db.get(Binding, (2, 1))
    assert count() == (0, 1, 0, 1)


@pytest.mark.parametrize("kind,name", [("plans", "Kiro Pro")])
def test_removal_blocks_lifecycle_operations(admin, alice, kind, name):
    Gateway.mode = "ok"
    rid = create(alice).json()["id"]
    run_one(Gateway)
    with SessionLocal() as db:
        db.add(
            RecordOperation(
                id=str(uuid.uuid4()),
                record_id=rid,
                actor_id=2,
                kind="sync_status",
                payload="{}",
                state="needs_review",
                request_key=str(uuid.uuid4()),
            )
        )
        db.commit()
    assert remove(admin, kind, name).status_code == 409


@pytest.mark.parametrize("kind,name", [("aws", "测试 AWS"), ("plans", "Kiro Pro")])
def test_resource_admin_only_csrf_and_confirmation(admin, alice, kind, name):
    url = f"/api/admin/{kind}/1"
    assert alice.get(url).status_code == 403
    assert remove(alice, kind, name).status_code == 403
    assert alice.patch(url + "/status", json={"active": False}).status_code == 403
    assert alice.post(url + "/restore").status_code == 403
    assert (
        admin.request(
            "DELETE",
            url,
            json={"confirm_name": name},
            headers={"X-CSRF-Token": "wrong"},
        ).status_code
        == 403
    )
    assert admin.request("DELETE", url).status_code == 422
    assert remove(admin, kind, name, 999).status_code == 404


def test_aws_edit_cannot_overwrite_removal_during_remote_validation(admin, monkeypatch):
    body = aws_body(admin, name="不能覆盖删除")

    class InterleavedGateway(Gateway):
        def verify(self):
            assert remove(admin, "aws", "测试 AWS").status_code == 200
            return "123456789012"

    monkeypatch.setattr("app.main.aws.AwsGateway", InterleavedGateway)
    assert admin.put("/api/admin/aws/1", json=body).status_code == 409
    with SessionLocal() as db:
        assert (
            db.get(AwsAccount, 1).deleted_at
            and db.get(AwsAccount, 1).name == "测试 AWS"
        )
    assert admin.put("/api/admin/aws/1", json=body).status_code == 404


def test_edit_display_name_keeps_own_session_valid(admin):
    with SessionLocal() as db:
        version = db.get(User, 1).session_version
    assert (
        admin.patch(
            "/api/admin/users/1", json={"display_name": "新的管理名称", "role": "admin"}
        ).status_code
        == 200
    )
    assert admin.get("/api/auth/me").json()["user"]["display_name"] == "新的管理名称"
    with SessionLocal() as db:
        assert db.get(User, 1).session_version == version


def test_schema_four_migration_preserves_configuration_and_history(admin, alice):
    Gateway.mode = "ok"
    rid = create(alice).json()["id"]
    run_one(Gateway)
    with SessionLocal() as db:
        credentials = db.get(AwsAccount, 1).credentials_encrypted
    with engine.begin() as connection:
        connection.exec_driver_sql(
            "ALTER TABLE console_aws_accounts DROP COLUMN deleted_at"
        )
        connection.exec_driver_sql("ALTER TABLE console_plans DROP COLUMN deleted_at")
        connection.execute(
            text("INSERT INTO console_schema_version (version) VALUES (4)")
        )
    initialize()
    initialize()
    with SessionLocal() as db:
        assert db.scalar(select(SchemaVersion.version)) == VERSION
        assert db.get(AwsAccount, 1).credentials_encrypted == credentials
        assert db.get(AwsAccount, 1).deleted_at is None
        assert db.get(Plan, 1).deleted_at is None
        assert db.get(Subscription, rid).counted
    assert count() == (1, 0, 1, 1)
    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
