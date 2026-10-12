import concurrent.futures
import json
import uuid
from datetime import timedelta

import pytest
from botocore.exceptions import ClientError
from sqlalchemy import select, text

from app.aws import AwsFailure, AwsGateway
from app.database import SessionLocal, engine
from app.init_db import initialize
from app.lifecycle import run_operation
from app.migrations import COLUMNS, VERSION
from app.models import (
    AwsAccount,
    Binding,
    Plan,
    RecordOperation,
    SchemaVersion,
    Subscription,
    now,
)
from app.security import decrypt
from app.worker import run_one
from conftest import login
from test_workflows import Gateway, count, create


class LifecycleGateway:
    calls = []
    exists = True
    info = {}
    profile = {}
    failure = None

    def __init__(self, account):
        pass

    def verify(self):
        pass

    def list_user_memberships(self, uid):
        return {}

    def subscription_info(self, r):
        return dict(self.info)

    def user_subscription_sources(self, r):
        self.observed_record = r
        return [{"source": "USER", "group_id": None, **self.subscription_info(r)}]

    def report_subscriptions(self):
        if self.info["status"] == "not_subscribed":
            return []
        return [{"principal": {"user": self.observed_record.sso_user_id},
                 "type": {"amazonQ": self.info["subscription_type"]},
                 "status": self.info["status"].upper(), "aggregatedSubscriptionType": "INDIVIDUAL",
                 "expirationDate": self.info.get("expires_at").isoformat() if self.info.get("expires_at") else None}]

    def user_info(self, r):
        return dict(self.profile, UserName=r.username, UserId=r.sso_user_id) if self.exists else None

    def cancel_subscription(self, r, mode):
        self.calls.append("cancel")
        if self.failure == "denied":
            raise AwsFailure("AWS AccessDenied")
        self.info.update(status="cancelled", expires_at=now() + timedelta(days=5))
        if self.failure == "timeout":
            raise AwsFailure("AWS 连接中断", uncertain=True)
        return "cancel-request"

    def delete_user(self, r):
        self.calls.append("delete")
        type(self).exists = False
        if self.failure == "timeout":
            raise AwsFailure("AWS 连接中断", uncertain=True)
        return "delete-request"

    def password(self, r):
        self.calls.append("password")
        if self.failure == "timeout":
            raise AwsFailure("AWS 连接中断", uncertain=True)
        return "new-one-time-password"

    def update_user(self, r, display_name, email):
        self.calls.append("update")
        self.profile.update(
            DisplayName=display_name, Emails=[{"Value": email, "Primary": True}]
        )
        return "update-request"


@pytest.fixture
def record(alice):
    Gateway.mode = "ok"
    r = create(alice).json()
    run_one(Gateway)
    LifecycleGateway.calls = []
    LifecycleGateway.exists = True
    LifecycleGateway.failure = None
    LifecycleGateway.info = {
        "status": "active",
        "subscription_type": "Q_DEVELOPER_STANDALONE_PRO",
        "expires_at": None,
    }
    LifecycleGateway.profile = {
        "DisplayName": "Old Name",
        "Emails": [{"Value": r["email"], "Primary": True}],
    }
    return alice.get(f"/api/subscriptions/{r['id']}").json()


def operation(client, r, kind, **extra):
    return client.post(
        f"/api/subscriptions/{r['id']}/operations",
        json={
            "kind": kind,
            "request_key": str(uuid.uuid4()),
            "confirm_username": r["username"],
            **extra,
        },
    )


def cascade(client, r, gateway=LifecycleGateway):
    from app import aws
    from test_cascade_deletions import admit, preview
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(aws, 'AwsGateway', gateway)
        value = preview(client, records=[r['id']])
        assert value.status_code == 200, value.text
        return admit(client, value.json())


def drain_lifecycle(gateway=LifecycleGateway):
    for _ in range(10):
        if not run_operation(gateway):
            return
    raise AssertionError('lifecycle failed to settle')


def legacy_delete(r):
    """Historical pending intent; new HTTP admissions must never create it."""
    op_id = str(uuid.uuid4())
    with SessionLocal() as db:
        db.add(RecordOperation(id=op_id, record_id=r['id'], actor_id=2, kind='delete_sso',
            request_key=str(uuid.uuid4()), payload=json.dumps({'acknowledge_subscription': True}), phase='pending'))
        db.get(Subscription, r['id']).active_operation_id = op_id
        db.commit()
    return {'id': op_id}


def get(client, r):
    return client.get(f"/api/subscriptions/{r['id']}").json()


def retry(client, r, op):
    return client.post(
        f"/api/subscriptions/{r['id']}/operations/{op['id']}/retry",
        json={"confirm_username": r["username"]},
    )


def test_cancellation_and_deletion_statistics_are_retained_and_private(
    record, alice, bob, admin
):
    assert alice.get("/api/overview").json()["cancelled_subscriptions"] == 0
    assert alice.get("/api/overview").json()["deleted_sso"] == 0
    assert (
        operation(
            alice, record, "cancel_subscription", cancellation_mode="IMMEDIATE"
        ).status_code
        == 202
    )
    run_operation(LifecycleGateway)
    assert cascade(alice, record).status_code == 202
    drain_lifecycle()
    for client in (alice, admin):
        result = client.get("/api/overview").json()
        assert result["cancelled_subscriptions"] == result["deleted_sso"] == 1
        assert result["subscribed"] == 1
        for status in ("cancelled", "deleted"):
            records = client.get(f"/api/sso-users?status={status}").json()
            assert records["total"] == 1
            saved = records["items"][0]
            assert saved["cancelled_at"] and saved["sso_deleted_at"]
            assert saved["subscribed_at"] == record["subscribed_at"]
    assert bob.get("/api/overview").json()["cancelled_subscriptions"] == 0
    assert bob.get("/api/overview").json()["deleted_sso"] == 0
    assert bob.get("/api/sso-users?status=cancelled&owner_id=2").json()["total"] == 0
    summary = next(
        u
        for u in admin.get("/api/overview").json()["member_summary"]["users"]
        if u["id"] == 2
    )
    assert summary["cancelled_subscriptions"] == summary["deleted_sso"] == 1
    assert count() == (1, 0, 1, 1)
    assert admin.patch("/api/admin/users/2", json={"active": False}).status_code == 200
    assert admin.delete("/api/admin/users/2").status_code == 200
    # Hiding the platform account never subtracts retained lifecycle history.
    result = admin.get("/api/overview").json()
    assert result["cancelled_subscriptions"] == result["deleted_sso"] == 1
    assert admin.get("/api/sso-users?status=deleted&owner_id=2").json()["total"] == 1
    history = admin.get("/api/admin/users/2/plan-history?plan_id=1").json()["items"][0]
    assert history["cancelled_at"] and history["sso_deleted_at"]


def test_scheduled_cancellation_and_sync_do_not_double_count(record, alice):
    with SessionLocal() as db:
        db.get(AwsAccount, 1).control_plane = "kiro"
        db.commit()
    assert (
        operation(
            alice, record, "cancel_subscription", cancellation_mode="END_OF_PERIOD"
        ).status_code
        == 202
    )
    run_operation(LifecycleGateway)
    assert operation(alice, record, "sync_status").status_code == 202
    run_operation(LifecycleGateway)
    result = alice.get("/api/overview").json()
    assert result["cancelled_subscriptions"] == 1 and result["deleted_sso"] == 0
    records = alice.get("/api/sso-users?status=cancelled").json()
    assert (
        records["total"] == 1
        and records["items"][0]["subscription_status"] == "cancel_scheduled"
    )


def test_failed_delete_not_in_deletion_total(record, alice):
    class DeniedDelete(LifecycleGateway):
        def delete_user(self, r):
            raise AwsFailure("delete denied")

    assert cascade(alice, record, DeniedDelete).status_code == 202
    drain_lifecycle(DeniedDelete)
    assert alice.get("/api/overview").json()["deleted_sso"] == 0
    assert alice.get("/api/sso-users?status=deleted").json()["total"] == 0


def assert_immutable(before, after):
    for key in [
        "username",
        "sso_user_id",
        "plan_id",
        "plan_name",
        "subscription_type",
        "subscribed_at",
        "counted",
        "cycle_number",
        "created_at",
    ]:
        assert after[key] == before[key], key


def test_cancel_keeps_sso_password_history_and_count(alice, record):
    assert operation(alice, record, "cancel_subscription").status_code == 202
    run_operation(LifecycleGateway)
    after = get(alice, record)
    assert after["subscription_status"] == "cancelled"
    assert after["sso_deleted_at"] is None and after["has_password"]
    assert LifecycleGateway.calls == ["cancel"] and count() == (1, 0, 1, 1)
    assert_immutable(record, after)


def test_delete_requires_preview_and_cancels_before_removing_sso(alice, record):
    assert operation(alice, record, "delete_sso").status_code == 409
    assert (
        operation(
            alice, record, "delete_sso", acknowledge_subscription=True
        ).status_code
        == 409
    )
    assert cascade(alice, record).status_code == 202
    drain_lifecycle()
    after = get(alice, record)
    assert after["sso_deleted_at"] and not after["has_password"]
    assert after["subscription_status"] == "cancelled"
    assert LifecycleGateway.calls == ["cancel", "delete"]
    assert (
        alice.post(f"/api/subscriptions/{record['id']}/credentials").status_code == 409
    )
    assert operation(alice, record, "reset_password").status_code == 409
    assert (
        operation(
            alice, record, "update_sso", display_name="Name", email="new@example.com"
        ).status_code
        == 409
    )
    assert alice.get("/api/sso-users?status=deleted").json()["total"] == 1
    assert alice.get("/api/sso-users?status=active").json()["total"] == 0
    assert operation(alice, record, "cancel_subscription").status_code == 409
    assert get(alice, record)["subscription_status"] == "cancelled"
    assert LifecycleGateway.calls == ["cancel", "delete"]
    assert count() == (1, 0, 1, 1)
    assert_immutable(record, after)


def test_update_only_name_and_email_preserves_original_plan_and_date(
    alice, admin, record
):
    result = operation(
        alice, record, "update_sso", display_name="张三", email="new@example.com"
    )
    assert result.status_code == 202
    run_operation(LifecycleGateway)
    with SessionLocal() as db:
        db.get(Plan, 1).name = "Renamed catalog plan"
        db.commit()
    after = get(alice, record)
    assert (after["sso_display_name"], after["email"]) == ("张三", "new@example.com")
    assert_immutable(record, after)
    assert alice.get("/api/sso-users?q=new%40example.com").json()["total"] == 1
    for field, value in [
        ("plan_id", 2),
        ("subscription_type", "Q_DEVELOPER_STANDALONE_POWER"),
        ("subscribed_at", "2020-01-01"),
        ("username", "changed"),
    ]:
        assert (
            operation(
                admin,
                record,
                "update_sso",
                display_name="Name",
                email="n@example.com",
                **{field: value},
            ).status_code
            == 422
        )
    assert count() == (1, 0, 1, 1)


def test_reset_replaces_encrypted_password_and_never_exposes_it_in_history(
    alice, record
):
    assert operation(alice, record, "reset_password").status_code == 202
    run_operation(LifecycleGateway)
    after = get(alice, record)
    assert after["password_generated_at"] > record["password_generated_at"]
    password = alice.post(f"/api/subscriptions/{record['id']}/credentials").json()[
        "password"
    ]
    assert password == "new-one-time-password"
    with SessionLocal() as db:
        encrypted = db.get(Subscription, record["id"]).password_encrypted
        assert encrypted != password and decrypt(encrypted) == password
    for url in [
        "/api/sso-users",
        "/api/audit",
        f"/api/subscriptions/{record['id']}/operations",
    ]:
        assert password not in alice.get(url).text
    assert_immutable(record, after)


@pytest.mark.parametrize(
    "kind",
    [
        "cancel_subscription",
        "delete_sso",
        "reset_password",
        "update_sso",
        "sync_status",
    ],
)
def test_all_new_routes_enforce_ownership_and_csrf(alice, bob, record, kind):
    body = {
        "acknowledge_subscription": True,
        "display_name": "Name",
        "email": "x@example.com",
    }
    assert operation(bob, record, kind, **body).status_code == 404
    assert bob.get("/api/sso-users").json()["total"] == 0
    assert bob.get(f"/api/subscriptions/{record['id']}/operations").status_code == 404
    alice.headers["X-CSRF-Token"] = "wrong"
    assert operation(alice, record, kind, **body).status_code == 403


def test_one_operation_per_user_and_idempotent_http_retries(alice, bob, record):
    key = str(uuid.uuid4())
    first = operation(alice, record, "reset_password", request_key=key)
    again = operation(alice, record, "reset_password", request_key=key)
    assert first.status_code == again.status_code == 202
    assert first.json()["id"] == again.json()["id"]
    assert retry(bob, record, first.json()).status_code == 404
    assert (
        operation(
            alice, record, "delete_sso", acknowledge_subscription=True
        ).status_code
        == 409
    )
    assert operation(alice, record, "sync_status", request_key=key).status_code == 409
    run_operation(LifecycleGateway)
    assert not run_operation(LifecycleGateway)
    assert LifecycleGateway.calls == ["password"]


def test_concurrent_operations_have_single_winner(record):
    clients = [login("alice") for _ in range(4)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(
            pool.map(lambda c: operation(c, record, "reset_password"), clients)
        )
    assert sorted(r.status_code for r in responses) == [202, 409, 409, 409]


def test_revocation_prevents_new_mutations_but_admin_can_clean_up(alice, admin, record):
    operation(alice, record, "reset_password")
    with SessionLocal() as db:
        db.delete(db.get(Binding, (2, 1)))
        db.commit()
    run_operation(LifecycleGateway)
    assert LifecycleGateway.calls == []
    assert operation(alice, record, "sync_status").status_code == 403
    assert cascade(admin, record).status_code == 202
    drain_lifecycle()
    assert LifecycleGateway.calls == ["cancel", "delete"]


@pytest.mark.parametrize(
    "kind,expected", [("cancel_subscription", "cancel"), ("delete_sso", "delete")]
)
def test_ambiguous_mutations_reconcile_without_duplicate_write(
    alice, record, kind, expected
):
    if kind == 'delete_sso':
        batch = cascade(alice, record).json()
        assert run_operation(LifecycleGateway)  # cancel-first checkpoint
        LifecycleGateway.failure = 'timeout'
        assert run_operation(LifecycleGateway)
        assert get(alice, record)['operation']['state'] == 'needs_review'
        result = alice.post('/api/cascade-deletions/' + batch['id'] + '/recheck', json={
            'request_key': str(uuid.uuid4()), 'confirm_text': batch['confirm_text']})
        assert result.status_code == 202, result.text
        drain_lifecycle()
        assert get(alice, record)['operation'] is None
        assert LifecycleGateway.calls == ['cancel', expected]
        assert count() == (1, 0, 1, 1)
        return
    LifecycleGateway.failure = "timeout"
    op = operation(alice, record, kind, acknowledge_subscription=True).json()
    run_operation(LifecycleGateway)
    assert get(alice, record)["operation"]["state"] == "needs_review"
    assert retry(alice, record, op).status_code == 202
    run_operation(LifecycleGateway)
    assert get(alice, record)["operation"] is None
    assert LifecycleGateway.calls == [expected]
    assert count() == (1, 0, 1, 1)


def test_lost_password_requires_explicit_regeneration(alice, record):
    LifecycleGateway.failure = "timeout"
    op = operation(alice, record, "reset_password").json()
    run_operation(LifecycleGateway)
    assert not get(alice, record)["has_password"]
    assert get(alice, record)["operation"]["state"] == "needs_review"
    assert not run_operation(LifecycleGateway)
    LifecycleGateway.failure = None
    retry(alice, record, op)
    run_operation(LifecycleGateway)
    assert LifecycleGateway.calls == ["password", "password"]
    assert get(alice, record)["has_password"]


def test_restart_does_not_blindly_replay_reset(alice, record):
    op = operation(alice, record, "reset_password").json()
    with SessionLocal() as db:
        row = db.get(RecordOperation, op["id"])
        row.state, row.phase = "running", "pending"
        row.lease_until = now() - timedelta(seconds=1)
        db.get(Subscription, record["id"]).password_encrypted = None
        db.commit()
    run_operation(LifecycleGateway)
    assert LifecycleGateway.calls == []
    assert get(alice, record)["operation"]["state"] == "needs_review"


@pytest.mark.parametrize("kind", ["cancel_subscription", "delete_sso", "update_sso"])
@pytest.mark.parametrize(
    "failure", ["disabled_proxy", "aws_error", "sdk_error", "unexpected"]
)
def test_pending_lifecycle_constructor_failure_retains_unknown_result(
    alice, admin, record, monkeypatch, kind, failure
):
    if kind == 'delete_sso':
        assert operation(alice, record, kind, acknowledge_subscription=True).status_code == 409
        op_id = legacy_delete(record)['id']
    else:
        result = operation(alice, record, kind, display_name='New Name', email='new@example.com')
        assert result.status_code == 202
        op_id = result.json()['id']
    with SessionLocal() as db:
        op = db.get(RecordOperation, op_id)
        op.state, op.phase = "running", "pending"
        op.lease_until = now() - timedelta(seconds=1)
        db.commit()
    if failure == "disabled_proxy":
        proxy = admin.post(
            "/api/admin/proxies",
            json={
                "name": "待核对代理",
                "address": "127.0.0.1:1080:dummy-user:dummy-password",
                "enabled": False,
            },
        )
        assert proxy.status_code == 201
        with SessionLocal() as db:
            db.get(AwsAccount, 1).proxy_id = proxy.json()["id"]
            db.commit()
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

    assert run_operation(constructor)
    with SessionLocal() as db:
        op = db.get(RecordOperation, op_id)
        assert op.state == "needs_review" and op.phase == "pending"
        assert db.get(Subscription, record["id"]).active_operation_id == op_id
        assert op.finished_at is None
    assert count() == (1, 0, 1, 1)
    assert LifecycleGateway.calls == []


def test_scheduled_cancel_and_sync_do_not_change_opening_history(alice, record):
    assert (
        operation(
            alice, record, "cancel_subscription", cancellation_mode="END_OF_PERIOD"
        ).status_code
        == 409
    )
    with SessionLocal() as db:
        db.get(AwsAccount, 1).control_plane = "kiro"
        db.commit()
    assert (
        operation(
            alice, record, "cancel_subscription", cancellation_mode="END_OF_PERIOD"
        ).status_code
        == 202
    )
    run_operation(LifecycleGateway)
    assert get(alice, record)["subscription_status"] == "cancel_scheduled"
    operation(alice, record, "sync_status")
    run_operation(LifecycleGateway)
    after = get(alice, record)
    assert (
        after["access_ends_at"] and after["subscription_status"] == "cancel_scheduled"
    )
    assert_immutable(record, after)


def test_sync_observes_external_tier_without_rewriting_bound_plan(alice, record):
    LifecycleGateway.info["subscription_type"] = "Q_DEVELOPER_STANDALONE_PRO_MAX"
    operation(alice, record, "sync_status")
    run_operation(LifecycleGateway)
    after = get(alice, record)
    assert after["observed_plan_name"] == "Kiro Pro Max"
    assert_immutable(record, after)
    operation(alice, record, "cancel_subscription")
    run_operation(LifecycleGateway)
    assert LifecycleGateway.calls == []
    assert "不一致" in alice.get(f"/api/subscriptions/{record['id']}/operations").text


def test_delete_failed_opening_blocks_provisioning_retry(alice):
    Gateway.mode = "reject"
    r = create(alice).json()
    run_one(Gateway)
    LifecycleGateway.exists = True
    LifecycleGateway.failure = None
    LifecycleGateway.info = dict(status='not_subscribed', subscription_type=None, expires_at=None)
    assert cascade(alice, r).status_code == 202
    assert alice.post(f"/api/subscriptions/{r['id']}/retry").status_code == 409
    drain_lifecycle()
    assert alice.post(f"/api/subscriptions/{r['id']}/retry").status_code == 409
    assert count() == (0, 0, 0, 1)


def test_additive_v1_migration_preserves_subscriptions_and_counts(alice, record):
    with SessionLocal() as db:
        db.add(SchemaVersion(version=1))
        db.commit()
    with engine.begin() as conn:
        for column in COLUMNS:
            conn.execute(
                text(f"ALTER TABLE console_subscriptions DROP COLUMN {column}")
            )
    initialize()
    initialize()
    after = get(alice, record)
    assert_immutable(record, after)
    assert after["subscription_status"] == "active"
    assert count() == (1, 0, 1, 1)
    with SessionLocal() as db:
        assert db.scalar(select(SchemaVersion.version)) == VERSION


def test_missing_claim_does_not_skip_initial_cancel_write(alice, record):
    LifecycleGateway.info.update(status="not_subscribed", subscription_type=None)
    operation(alice, record, "cancel_subscription")
    run_operation(LifecycleGateway)
    assert LifecycleGateway.calls == ["cancel"]


def test_backup_preserves_sso_changes_and_operation_history(alice, record, tmp_path):
    from app import backup
    from app.config import settings
    import sqlite3

    operation(
        alice,
        record,
        "update_sso",
        display_name="Backup Name",
        email="backup@example.com",
    )
    run_operation(LifecycleGateway)
    operation(alice, record, "cancel_subscription")
    run_operation(LifecycleGateway)
    config = tmp_path / "source.env"
    config.write_text(
        f"FERNET_KEY={settings.fernet_key}\nSECRET_KEY={settings.secret_key}\n"
    )
    archive, _ = backup.snapshot(engine.url.database, config, tmp_path)
    manifest = backup.check_archive(archive, tmp_path / "restored")
    assert manifest["tables"]["console_record_operations"] == 2
    with sqlite3.connect(tmp_path / "restored" / "console.db") as db:
        name, status, original_plan, when = db.execute(
            "SELECT sso_display_name, subscription_status, plan_name_snapshot, subscribed_at FROM console_subscriptions"
        ).fetchone()
        assert (name, status, original_plan) == ("Backup Name", "cancelled", "Kiro Pro")
        assert when.replace(" ", "T") == record["subscribed_at"]


@pytest.mark.parametrize("legacy_snapshot", [False, True, "absent"])
@pytest.mark.parametrize("claim_missing", [False, "before_sync", "during_cancel"])
def test_immediate_user_cancellation_billing_boundary_does_not_restore_access_on_sync(
    alice, record, monkeypatch, legacy_snapshot, claim_missing
):
    if claim_missing == "during_cancel":
        def removed_on_cancel(self, row):
            self.observed_record = row
            return [] if self.info["status"] == "cancelled" else [{"source": "USER", "group_id": None, **self.subscription_info(row)}]
        monkeypatch.setattr(LifecycleGateway, "user_subscription_sources", removed_on_cancel)
    assert operation(alice, record, "cancel_subscription", cancellation_mode="IMMEDIATE").status_code == 202
    run_operation(LifecycleGateway)
    cancelled = get(alice, record)
    assert cancelled["subscription_status"] == "cancelled"
    assert cancelled["cancellation_mode"] == "IMMEDIATE"
    if legacy_snapshot:
        # Previously saved USER observations do not contain a cancellation receipt.
        import json
        with SessionLocal() as db:
            row = db.get(Subscription, record["id"])
            saved = json.loads(row.subscription_observation)
            saved.pop("user_cancellation", None)
            row.subscription_observation = None if legacy_snapshot == "absent" else json.dumps(saved)
            db.commit()
    if claim_missing == "before_sync":
        def missing(self, row):
            self.observed_record = row
            return []
        monkeypatch.setattr(LifecycleGateway, "user_subscription_sources", missing)
    for _ in range(2):
        assert operation(alice, record, "sync_status").status_code == 202
        run_operation(LifecycleGateway)
        synced = get(alice, record)
        assert synced["subscription_status"] == "cancelled"
        assert synced["cancellation_mode"] == "IMMEDIATE"
        assert synced["access_ends_at"] is None
        assert synced["effective_subscription_source"] is None
        assert synced["cancelled_at"] == cancelled["cancelled_at"]
    assert LifecycleGateway.calls == ["cancel"]
    assert_immutable(record, synced)


@pytest.mark.parametrize("new_status", ["active", "cancelled"])
def test_new_external_user_claim_supersedes_previous_immediate_cancellation(alice, record, new_status):
    assert operation(alice, record, "cancel_subscription", cancellation_mode="IMMEDIATE").status_code == 202
    run_operation(LifecycleGateway)
    LifecycleGateway.info.update(status=new_status, expires_at=None if new_status == "active" else now() + timedelta(days=20))
    assert operation(alice, record, "sync_status").status_code == 202
    run_operation(LifecycleGateway)
    synced = get(alice, record)
    assert synced["subscription_status"] == ("active" if new_status == "active" else "cancel_scheduled")
    assert synced["cancellation_mode"] == (None if new_status == "active" else "END_OF_PERIOD")
    assert synced["effective_subscription_source"] == "USER"
    assert LifecycleGateway.calls == ["cancel"]


@pytest.mark.parametrize("legacy_result", ["accepted", "readback"])
def test_legacy_grouped_user_cancellation_uses_user_operation_evidence(alice, record, legacy_result):
    import json
    from test_native_groups import seed_group
    seed_group(0)
    with SessionLocal() as db:
        row = db.get(Subscription, record["id"])
        row.group_id, row.group_membership_id = "group-1", "membership"
        db.commit()
    response = operation(alice, record, "cancel_subscription", cancellation_mode="IMMEDIATE")
    assert response.status_code == 202
    run_operation(LifecycleGateway)
    with SessionLocal() as db:
        db.get(Subscription, record["id"]).subscription_observation = None
        op = db.get(RecordOperation, response.json()["id"])
        payload, result = json.loads(op.payload), json.loads(op.result)
        payload.pop("principal_type", None)
        result.pop("subscription_observation", None)
        if legacy_result == "accepted":
            result = {k: result[k] for k in ("subscription_status", "access_ends_at", "cancelled_at", "cancellation_mode")}
        op.payload, op.result = json.dumps(payload), json.dumps(result)
        db.commit()
    assert operation(alice, record, "sync_status").status_code == 202
    run_operation(LifecycleGateway)
    view = get(alice, record)
    assert view["subscription_status"] == "cancelled"
    assert view["cancellation_mode"] == "IMMEDIATE"
    assert view["access_ends_at"] is None
    assert LifecycleGateway.calls == ["cancel"]


@pytest.mark.parametrize("later_evidence", ["legacy_sync", "source_snapshot", "period_cancel"])
def test_legacy_receipt_yields_to_later_confirmed_user_access(alice, record, later_evidence):
    import json
    stopped = operation(alice, record, "cancel_subscription", cancellation_mode="IMMEDIATE")
    assert stopped.status_code == 202
    run_operation(LifecycleGateway)
    with SessionLocal() as db:
        op = db.get(RecordOperation, stopped.json()["id"])
        result = json.loads(op.result)
        op.payload = json.dumps({"cancellation_mode": "IMMEDIATE"})
        op.result = json.dumps({k: result[k] for k in ("subscription_status", "access_ends_at", "cancelled_at", "cancellation_mode")})
        old_cancelled_at = db.get(Subscription, record["id"]).cancelled_at
        db.commit()
    LifecycleGateway.info.update(status="active", expires_at=None)
    active = operation(alice, record, "sync_status")
    assert active.status_code == 202
    run_operation(LifecycleGateway)
    with SessionLocal() as db:
        row = db.get(Subscription, record["id"])
        row.subscription_observation = None
        op = db.get(RecordOperation, active.json()["id"])
        result = json.loads(op.result)
        if later_evidence != "source_snapshot":
            op.result = json.dumps({k: result[k] for k in ("subscription_status", "observed_subscription_type", "access_ends_at", "last_synced_at")})
        if later_evidence == "period_cancel":
            # The later EOP cancellation must independently supersede the old
            # immediate stop even without a retained active observation.
            op.result = "{}"
            db.get(AwsAccount, 1).control_plane = "kiro"
        else:
            row.cancelled_at, row.cancellation_mode = old_cancelled_at, "IMMEDIATE"
        db.commit()
    if later_evidence == "period_cancel":
        end = operation(alice, record, "cancel_subscription", cancellation_mode="END_OF_PERIOD")
        assert end.status_code == 202
        run_operation(LifecycleGateway)
        with SessionLocal() as db:
            db.get(Subscription, record["id"]).subscription_observation = None
            op = db.get(RecordOperation, end.json()["id"])
            result = json.loads(op.result)
            op.payload = json.dumps({"cancellation_mode": "END_OF_PERIOD"})
            op.result = json.dumps({k: result[k] for k in ("subscription_status", "access_ends_at", "cancelled_at", "cancellation_mode")})
            db.commit()
    boundary = now() + timedelta(days=20)
    LifecycleGateway.info.update(status="cancelled", expires_at=boundary)
    assert operation(alice, record, "sync_status").status_code == 202
    run_operation(LifecycleGateway)
    view = get(alice, record)
    assert view["subscription_status"] == "cancel_scheduled"
    assert view["cancellation_mode"] == "END_OF_PERIOD"
    assert view["access_ends_at"] == boundary.isoformat()
    assert view["effective_subscription_source"] == "USER"
    assert LifecycleGateway.calls == (["cancel", "cancel"] if later_evidence == "period_cancel" else ["cancel"])


def test_later_first_user_opening_invalidates_legacy_readback_cancellation(alice, record):
    import json
    with SessionLocal() as db:
        row = db.get(Subscription, record["id"])
        row.state, row.step, row.counted, row.reserved = "failed", "subscribe", False, False
        row.subscribed_at = row.subscription_observation = None
        db.commit()
    LifecycleGateway.info.update(status="cancelled", expires_at=now() + timedelta(days=5))
    stopped = operation(alice, record, "cancel_subscription", cancellation_mode="IMMEDIATE")
    assert stopped.status_code == 202
    run_operation(LifecycleGateway)
    with SessionLocal() as db:
        op = db.get(RecordOperation, stopped.json()["id"])
        assert op.state == "completed"
        result = json.loads(op.result)
        op.payload = json.dumps({"cancellation_mode": "IMMEDIATE"})
        op.result = json.dumps({k: result[k] for k in ("subscription_status", "access_ends_at", "cancelled_at", "cancellation_mode", "observed_subscription_type", "last_synced_at")})
        old_cancelled_at = db.get(Subscription, record["id"]).cancelled_at
        db.commit()
    assert alice.post(f"/api/subscriptions/{record['id']}/retry").status_code == 202
    Gateway.mode = "ok"
    assert run_one(Gateway)
    with SessionLocal() as db:
        row = db.get(Subscription, record["id"])
        assert row.counted and row.subscribed_at > db.get(RecordOperation, stopped.json()["id"]).finished_at
        row.subscription_observation = None
        row.cancelled_at, row.cancellation_mode = old_cancelled_at, "IMMEDIATE"
        db.commit()
    boundary = now() + timedelta(days=20)
    LifecycleGateway.info.update(status="cancelled", expires_at=boundary)
    assert operation(alice, record, "sync_status").status_code == 202
    run_operation(LifecycleGateway)
    view = get(alice, record)
    assert view["subscription_status"] == "cancel_scheduled"
    assert view["access_ends_at"] == boundary.isoformat()
    assert view["effective_subscription_source"] == "USER"
