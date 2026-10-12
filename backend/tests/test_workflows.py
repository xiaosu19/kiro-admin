import concurrent.futures
import uuid
from datetime import timedelta

import pytest
from botocore.exceptions import ClientError

from app.aws import AwsFailure, AwsGateway
from app.database import SessionLocal
from app.models import AwsAccount, PlanCounter, Subscription, now
from app.security import decrypt
from app.worker import run_one
from conftest import login


class Gateway:
    def group_subscription_info(self, group):
        return {"status": "not_subscribed", "subscription_type": None, "expires_at": None}

    mode = "ok"
    calls = 0

    def __init__(self, account):
        pass

    def verify(self):
        return "123456789012"

    def verify_identity(self):
        return self.verify()

    def create_user(self, r):
        return f"sso-{r.id}"

    def password(self, r):
        return "AWS-once-password-test"

    def subscribe(self, r):
        type(self).calls += 1
        if self.mode == "reject":
            raise AwsFailure("订阅权限不足")
        if self.mode == "unknown":
            raise AwsFailure("AWS 超时", uncertain=True)
        return "aws-request-123"

    def is_subscribed(self, r):
        return self.mode == "reconciled"


def create(client, plan=1, key=None):
    return client.post(
        "/api/subscriptions",
        json={
            "aws_account_id": 1,
            "plan_id": plan,
            "username": "member",
            "email": f"{uuid.uuid4().hex}@example.com",
            "request_key": key or str(uuid.uuid4()),
        },
    )


def count(counter_id=1):
    with SessionLocal() as db:
        c = db.get(PlanCounter, counter_id)
        return c.used_count, c.pending_count, c.lifetime_count, c.cycle_number


def test_isolation_every_route(alice, bob):
    Gateway.mode = "ok"
    r = create(alice)
    assert r.status_code == 202, r.text
    rid = r.json()["id"]
    run_one(Gateway)
    assert bob.get("/api/subscriptions").json()["total"] == 0
    assert bob.get("/api/subscriptions/" + rid).status_code == 404
    assert bob.post(f"/api/subscriptions/{rid}/credentials").status_code == 404
    assert bob.post(f"/api/subscriptions/{rid}/retry").status_code == 404
    assert bob.get("/api/overview").json()["total"] == 0
    assert all(c["user_id"] == 3 for c in bob.get("/api/counters?user_id=2").json())
    assert not any(
        "member-" in r["detail"] for r in bob.get("/api/audit").json()["items"]
    )
    result = alice.post(f"/api/subscriptions/{rid}/credentials")
    assert result.json()["password"] == "AWS-once-password-test"
    listed = alice.get("/api/subscriptions").json()["items"][0]
    assert "password" not in listed and "password_encrypted" not in listed


def test_member_cannot_admin_or_leak_keys(alice):
    assert alice.get("/api/admin/users").status_code == 403
    assert (
        alice.post(
            "/api/admin/users",
            json={
                "username": "mallory",
                "display_name": "M",
                "password": 'test-password-12345',
            },
        ).status_code
        == 403
    )
    assert (
        alice.post(
            "/api/admin/counters/1/reset", json={"limit_count": 100, "reason": "test"}
        ).status_code
        == 403
    )
    a = alice.get("/api/accounts").json()[0]
    assert set(a) == {"id", "name", "region", "active", "portal_url",
                      "account_number", "aws_account_id", "proxy_name", "proxy_status"}
    assert "TEST_SECRET_KEY" not in alice.get("/api/accounts").text


def test_success_counts_only_once_per_plan(alice):
    Gateway.mode = "ok"
    for _ in range(2):
        assert create(alice).status_code == 202
    assert count() == (0, 2, 0, 1)
    assert create(alice).status_code == 409
    assert create(alice, plan=2).status_code == 202
    for _ in range(3):
        assert run_one(Gateway)
    assert count() == (2, 0, 2, 1)
    assert count(2) == (1, 0, 1, 1)
    assert not run_one(Gateway)
    assert count() == (2, 0, 2, 1)


def test_definite_failure_releases_pending_and_retry_uses_same_user(alice):
    Gateway.mode = "reject"
    r = create(alice).json()
    run_one(Gateway)
    assert count() == (0, 0, 0, 1)
    detail = alice.get("/api/subscriptions/" + r["id"]).json()
    assert detail["state"] == "failed" and detail["has_password"]
    original_user = detail["sso_user_id"]
    Gateway.mode = "ok"
    assert alice.post(f"/api/subscriptions/{r['id']}/retry").status_code == 202
    run_one(Gateway)
    assert count() == (1, 0, 1, 1)
    assert (
        alice.get("/api/subscriptions/" + r["id"]).json()["sso_user_id"]
        == original_user
    )


def test_unknown_result_reconciles_without_reopening_or_double_count(alice, admin):
    Gateway.mode = "unknown"
    Gateway.calls = 0
    r = create(alice).json()
    run_one(Gateway)
    assert count() == (0, 1, 0, 1)
    assert (
        admin.post(
            "/api/admin/counters/1/reset", json={"limit_count": 2, "reason": "新一轮"}
        ).status_code
        == 409
    )
    assert alice.post(f"/api/subscriptions/{r['id']}/retry").status_code == 202
    run_one(Gateway)
    assert Gateway.calls == 1
    assert count() == (0, 1, 0, 1)
    Gateway.mode = "reconciled"
    alice.post(f"/api/subscriptions/{r['id']}/retry")
    run_one(Gateway)
    assert Gateway.calls == 1
    assert count() == (1, 0, 1, 1)


def test_reconciliation_permission_error_does_not_allow_reopening(alice):
    Gateway.mode = "unknown"
    Gateway.calls = 0
    r = create(alice).json()
    run_one(Gateway)

    class Unreadable(Gateway):
        def is_subscribed(self, r):
            raise AwsFailure("AWS AccessDenied")

    alice.post(f"/api/subscriptions/{r['id']}/retry")
    run_one(Unreadable)
    assert count() == (0, 1, 0, 1)
    detail = alice.get("/api/subscriptions/" + r["id"]).json()
    assert detail["state"] == "needs_review" and detail["step"] == "subscribe_pending"
    assert Gateway.calls == 1


@pytest.mark.parametrize(
    "failure", ["disabled_proxy", "aws_error", "sdk_error", "unexpected"]
)
def test_pending_subscription_constructor_failure_never_releases_or_replays(
    alice, admin, monkeypatch, failure
):
    Gateway.mode, Gateway.calls = "unknown", 0
    record_id = create(alice).json()["id"]
    assert run_one(Gateway)
    assert count() == (0, 1, 0, 1) and Gateway.calls == 1
    proxy_id = None
    if failure == "disabled_proxy":
        proxy = admin.post(
            "/api/admin/proxies",
            json={
                "name": "待核对代理",
                "address": "127.0.0.1:1080:dummy-user:dummy-password",
            },
        )
        assert proxy.status_code == 201
        proxy_id = proxy.json()["id"]
        with SessionLocal() as db:
            db.get(AwsAccount, 1).proxy_id = proxy_id
            db.commit()
        assert (
            admin.patch(
                f"/api/admin/proxies/{proxy_id}", json={"enabled": False}
            ).status_code
            == 200
        )
        monkeypatch.setattr(
            "app.aws.make_session",
            lambda *a, **kw: pytest.fail(
                "Unavailable proxy must fail before any AWS session"
            ),
        )
        constructor = AwsGateway
    else:
        error = {
            "aws_error": AwsFailure("代理认证不可用"),
            "sdk_error": ClientError(
                {"Error": {"Code": "AccessDenied"}}, "TestConstructor"
            ),
            "unexpected": RuntimeError("constructor interrupted"),
        }[failure]

        def constructor(account):
            raise error

    assert alice.post(f"/api/subscriptions/{record_id}/retry").status_code == 202
    assert run_one(constructor)
    saved = alice.get(f"/api/subscriptions/{record_id}").json()
    assert saved["state"] == "needs_review" and saved["step"] == "subscribe_pending"
    assert count() == (0, 1, 0, 1) and Gateway.calls == 1
    with SessionLocal() as db:
        assert db.get(Subscription, record_id).reserved
    if proxy_id is not None:
        assert (
            admin.patch(
                f"/api/admin/proxies/{proxy_id}", json={"enabled": True}
            ).status_code
            == 200
        )
    Gateway.mode = "reconciled"
    assert alice.post(f"/api/subscriptions/{record_id}/retry").status_code == 202
    if proxy_id is not None:
        # Enabling a replacement proxy does not restore the pending attempt's
        # original configuration. Do not even construct a gateway on that route.
        def changed_route(account):
            pytest.fail("Pending writes must not move to a replacement proxy")
        assert run_one(changed_route)
        assert count() == (0, 1, 0, 1) and Gateway.calls == 1
        with SessionLocal() as db:
            db.get(AwsAccount, 1).proxy_id = None  # Explicitly restore original config.
            db.commit()
        assert alice.post(f"/api/subscriptions/{record_id}/retry").status_code == 202
    assert run_one(Gateway)
    assert Gateway.calls == 1 and count() == (1, 0, 1, 1)


def test_admin_resolve_requires_wait_and_verified_absence(alice, admin, monkeypatch):
    import app.main as main

    Gateway.mode = "unknown"
    r = create(alice).json()
    run_one(Gateway)
    monkeypatch.setattr(main.aws, "AwsGateway", Gateway)
    url = f"/api/admin/subscriptions/{r['id']}/resolve-unsubscribed"
    body = {"confirmed_in_aws": True, "reason": "已在 AWS 控制台逐项核实"}
    assert alice.post(url, json=body).status_code == 403
    assert admin.post(url, json=body).status_code == 409
    with SessionLocal() as db:
        db.get(Subscription, r["id"]).updated_at = now() - timedelta(minutes=11)
        db.commit()
    Gateway.mode = "reconciled"
    assert admin.post(url, json=body).status_code == 409
    Gateway.mode = "unknown"
    assert admin.post(url, json=body).status_code == 200
    assert count() == (0, 0, 0, 1)
    assert admin.post(url, json=body).status_code == 409
    assert "resolve_unsubscribed" in admin.get("/api/audit").text


def test_reset_keeps_old_records_and_lifetime(alice, admin, bob):
    Gateway.mode = "ok"
    r = create(alice).json()
    run_one(Gateway)
    result = admin.post(
        "/api/admin/counters/1/reset", json={"limit_count": 5, "reason": "第二批订阅"}
    )
    assert result.status_code == 200, result.text
    assert count() == (0, 0, 1, 2)
    assert alice.get("/api/subscriptions/" + r["id"]).json()["cycle_number"] == 1
    history = alice.get("/api/counter-resets").json()
    assert (
        len(history) == 1
        and history[0]["used_count"] == 1
        and history[0]["new_limit"] == 5
    )
    assert bob.get("/api/counter-resets").json() == []
    create(alice)
    run_one(Gateway)
    assert count() == (1, 0, 2, 2)


def test_concurrent_requests_cannot_exceed_limit():
    clients = [login("alice") for _ in range(5)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(create, clients))
    assert sorted(r.status_code for r in results) == [202, 202, 409, 409, 409]
    assert count() == (0, 2, 0, 1)


def test_idempotent_request_and_csrf(alice):
    body = {
        "aws_account_id": 1,
        "plan_id": 1,
        "username": "myuser",
        "email": "test@example.com",
        "request_key": str(uuid.uuid4()),
    }
    r = alice.post("/api/subscriptions", json=body)
    again = alice.post("/api/subscriptions", json=body)
    assert r.status_code == again.status_code == 202
    assert r.json()["id"] == again.json()["id"]
    assert count() == (0, 1, 0, 1)
    body["email"] = "another@example.com"
    assert alice.post("/api/subscriptions", json=body).status_code == 409
    alice.headers["X-CSRF-Token"] = "wrong"
    assert create(alice).status_code == 403


def test_disable_revokes_login_and_queued_permissions(alice, admin):
    create(alice)
    assert admin.patch("/api/admin/users/2", json={"active": False}).status_code == 200
    assert alice.get("/api/subscriptions").status_code == 401
    Gateway.mode = "ok"
    Gateway.calls = 0
    run_one(Gateway)
    assert count() == (0, 0, 0, 1)
    assert Gateway.calls == 0


def test_unbind_prevents_new_jobs_and_queued_work(alice, admin):
    create(alice)
    admin.put("/api/admin/users/2/bindings", json={"account_ids": []})
    assert create(alice).status_code == 403
    Gateway.calls = 0
    run_one(Gateway)
    assert Gateway.calls == 0
    assert count() == (0, 0, 0, 1)


def test_restart_reconciles_inflight_remote_operation(alice):
    r = create(alice).json()
    with SessionLocal() as db:
        record = db.get(Subscription, r["id"])
        record.state = "running"
        record.step = "subscribe_pending"
        record.lease_until = now() - timedelta(seconds=2)
        record.sso_user_id = "existing"
        db.commit()
    Gateway.mode = "reconciled"
    Gateway.calls = 0
    run_one(Gateway)
    assert count() == (1, 0, 1, 1) and Gateway.calls == 0


def test_password_change_enforced_in_backend_and_old_sessions_revoked(admin):
    admin.post(
        "/api/admin/users",
        json={
            "username": "fresh",
            "display_name": "新成员",
            "password": "test-password-12345",
        },
    )
    client = login("fresh")
    assert client.get("/api/overview").status_code == 403
    result = client.post(
        "/api/auth/change-password",
        json={
            "old_password": "test-password-12345",
            "new_password": "new-password-98765",
        },
    )
    assert result.status_code == 200
    client.headers["X-CSRF-Token"] = result.json()["csrf"]
    assert client.get("/api/overview").status_code == 200


def test_counters_cannot_lower_below_pending(alice, admin):
    create(alice)
    assert (
        admin.put("/api/admin/users/2/counters/1", json={"limit_count": 0}).status_code
        == 409
    )
    assert count() == (0, 1, 0, 1)


def test_no_secrets_in_audit_or_storage_plaintext(alice):
    Gateway.mode = "ok"
    r = create(alice).json()
    run_one(Gateway)
    alice.post(f"/api/subscriptions/{r['id']}/credentials")
    audit = alice.get("/api/audit").text
    assert "AWS-once-password-test" not in audit and "TEST_SECRET_KEY" not in audit
    with SessionLocal() as db:
        s = db.get(Subscription, r["id"])
        assert s.password_encrypted != "AWS-once-password-test"
        assert decrypt(s.password_encrypted) == "AWS-once-password-test"
