"""Account-scoped directory and credential downloads never widen ownership."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.database import SessionLocal
from app.main import app
from app.models import AuditEvent, AwsAccount, Binding, ManagedGroup, Subscription, now
from app.security import encrypt


@pytest.fixture
def records():
    with SessionLocal() as db:
        account = db.get(AwsAccount, 1)
        db.add(
            AwsAccount(
                **{
                    column.name: getattr(account, column.name)
                    for column in AwsAccount.__table__.columns
                    if column.name not in ("id", "name")
                },
                id=2,
                name="Second AWS",
            )
        )
        db.add(Binding(user_id=2, aws_account_id=2))
        for gid, aid in (("group-a", 1), ("group-b", 2)):
            db.add(
                ManagedGroup(
                    id=gid,
                    owner_id=2,
                    aws_account_id=aid,
                    aws_scope=f"scope-{aid}",
                    request_key=gid,
                    payload_hash=gid,
                    name=gid,
                    marker=gid,
                    remote_id=gid,
                    state="ready",
                )
            )
        db.flush()
        rows = [
            ("alice", 1, 2, "group-a", "ALICE", "First person", "first@example.com"),
            ("name", 1, 2, "group-a", "name-match", "Alice Name", "name@example.com"),
            ("email", 1, 2, None, "email-match", "Email person", "aLiCe@example.com"),
            (
                "second",
                2,
                2,
                "group-b",
                "alice-other",
                "Second person",
                "second@example.com",
            ),
            (
                "foreign",
                1,
                3,
                None,
                "alice-foreign",
                "Foreign person",
                "foreign@example.com",
            ),
            ("literal", 1, 2, None, "literal%_user", "Literal", "literal@example.com"),
            (
                "deleted",
                1,
                2,
                "group-a",
                "alice-deleted",
                "Deleted",
                "deleted@example.com",
            ),
        ]
        for rid, aid, owner, gid, username, display, email in rows:
            db.add(
                Subscription(
                    id=rid,
                    request_key=rid,
                    owner_id=owner,
                    aws_account_id=aid,
                    group_id=gid,
                    username=username,
                    email=email,
                    sso_display_name=display,
                    sso_user_id=f"sso-{rid}",
                    state="completed",
                    provision_only=True,
                    reserved=False,
                    subscription_status="not_subscribed",
                    portal_url="https://example.awsapps.com/start",
                    credential_state="one_time",
                    password_encrypted=encrypt(f"secret-{rid}"),
                    sso_deleted_at=now() if rid == "deleted" else None,
                )
            )
        db.commit()


@pytest.mark.parametrize("path", ["sso-users", "subscriptions"])
def test_account_and_literal_search_intersect_with_owner_and_group(
    alice, admin, records, path
):
    params = {"aws_account_id": 1, "q": "aLiCe", "owner_id": 3}
    rows = alice.get(f"/api/{path}", params=params).json()
    assert {r["id"] for r in rows["items"]} == {"alice", "name", "email", "deleted"}
    assert rows["total"] == 4
    params["group_id"] = "group-a"
    params["status" if path == "sso-users" else "state"] = (
        "active" if path == "sso-users" else "completed"
    )
    rows = alice.get(f"/api/{path}", params=params).json()
    assert {r["id"] for r in rows["items"]} == (
        {"alice", "name"} if path == "sso-users" else {"alice", "name", "deleted"}
    )
    assert (
        admin.get(
            f"/api/{path}", params={"aws_account_id": 1, "owner_id": 3, "q": "alice"}
        ).json()["total"]
        == 1
    )
    literal = alice.get(f"/api/{path}", params={"aws_account_id": 1, "q": "%_"}).json()
    assert [r["id"] for r in literal["items"]] == ["literal"]
    assert (
        alice.get(
            f"/api/{path}", params={"aws_account_id": 2, "group_id": "group-a"}
        ).json()["total"]
        == 0
    )


def test_account_filtered_directory_pagination_uses_same_total(alice, records):
    query = {"aws_account_id": 1, "q": "alice", "status": "active", "page_size": 2}
    first = alice.get("/api/sso-users", params=query).json()
    second = alice.get("/api/sso-users", params={**query, "page": 2}).json()
    assert first["total"] == second["total"] == 3
    assert len(first["items"]) == 2 and len(second["items"]) == 1
    assert {r["id"] for r in first["items"] + second["items"]} == {
        "alice",
        "name",
        "email",
    }


@pytest.mark.parametrize("format", ["csv", "txt"])
def test_export_uses_exact_account_search_and_group_filters(
    alice, admin, records, format
):
    response = alice.post(
        "/api/sso-users/export",
        json={
            "format": format,
            "aws_account_id": 1,
            "q": "alice",
            "group_id": "group-a",
            "status": "active",
            "owner_id": 3,
        },
    )
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-disposition"].endswith(f'.{format}"')
    assert response.headers["x-export-count"] == "2"
    assert "secret-alice" in response.text and "secret-name" in response.text
    assert all(
        f"secret-{rid}" not in response.text
        for rid in ("second", "foreign", "email", "deleted")
    )
    with SessionLocal() as db:
        details = " ".join(db.scalars(select(AuditEvent.detail)))
        assert "secret-" not in details
        assert format.upper() in details


def test_txt_matches_copy_login_labels_order_and_password_state(alice, records):
    with SessionLocal() as db:
        db.get(Subscription, "name").credential_state = "permanent"
        db.get(Subscription, "email").credential_state = "unknown"
        db.commit()
    response = alice.post(
        "/api/sso-users/export",
        json={"record_ids": ["alice", "name", "email"], "format": "txt"},
    )
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/plain")
    blocks = response.text.split("\n\n---\n\n")
    assert len(blocks) == 3
    assert (
        blocks[0]
        == "AWS 登录地址：https://example.awsapps.com/start\n区域：us-east-1\n用户名：ALICE\n一次性密码：secret-alice"
    )
    assert "永久密码：secret-name" in response.text
    assert "密码状态待核对，请先核对结果" in response.text
    assert "secret-email" not in response.text


@pytest.mark.parametrize("format", ["csv", "txt"])
@pytest.mark.parametrize(
    "scope",
    [
        {"aws_account_id": 2},
        {"group_id": "group-b"},
        {"q": "no-match"},
        {"status": "deleted"},
    ],
)
def test_explicit_export_ids_must_match_applied_filters(alice, records, format, scope):
    response = alice.post(
        "/api/sso-users/export",
        json={"record_ids": ["alice"], "format": format, **scope},
    )
    assert response.status_code == 409
    assert "secret-" not in response.text


def test_txt_export_retains_authentication_and_ownership_checks(alice, bob, records):
    body = {"record_ids": ["alice"], "format": "txt"}
    assert TestClient(app).post("/api/sso-users/export", json=body).status_code == 401
    assert (
        alice.post(
            "/api/sso-users/export", json=body, headers={"X-CSRF-Token": "wrong"}
        ).status_code
        == 403
    )
    assert bob.post("/api/sso-users/export", json=body).status_code == 404
    assert (
        alice.post("/api/sso-users/export", json={**body, "format": "json"}).status_code
        == 422
    )
    with SessionLocal() as db:
        db.get(AwsAccount, 1).active = False
        db.commit()
    assert alice.post("/api/sso-users/export", json=body).status_code == 403


def test_capabilities_default_disabled_and_require_authentication(alice):
    from app.config import Settings

    assert Settings.model_fields["plan_changes_enabled"].default is False
    assert alice.get("/api/auth/me").json()["capabilities"] == {
        "plan_changes_enabled": False
    }
    assert TestClient(app).get("/api/auth/me").status_code == 401


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("GET", "plan-options", None),
        ("GET", "plan-changes", None),
        ("POST", "plan-changes", {}),
        ("POST", "plan-changes/missing/withdraw", {}),
        ("POST", "plan-changes/missing/recheck", {}),
        ("POST", "plan-changes/missing/confirm-not-applied", {}),
    ],
)
def test_disabled_plan_routes_reject_before_lookup_or_writes(alice, method, path, body):
    response = alice.request(method, f"/api/subscriptions/missing/{path}", json=body)
    assert response.status_code == 403, response.text
    assert "未启用" in response.json()["detail"]


def test_disabled_plan_worker_never_claims_or_reconciles(monkeypatch):
    from app import plan_change_worker as worker

    def unexpected(*args, **kwargs):
        pytest.fail("Disabled worker must not claim or load plan changes")

    monkeypatch.setattr(worker, "claim_operation", unexpected)
    monkeypatch.setattr(worker, "SessionLocal", unexpected)
    assert worker.run_plan_change(unexpected) is False
    assert worker.reconcile_due(unexpected, force=True) == 0
