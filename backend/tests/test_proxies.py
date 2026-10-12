"""Proxy credentials are dummy values; tests never contact external services."""

from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.models import AuditEvent
from app.security import decrypt
from test_resources import aws_body
from test_workflows import Gateway


ADDRESS = "127.0.0.1:1080:dummy-user:dummy-password"


def create_proxy(admin, **changes):
    return admin.post(
        "/api/admin/proxies",
        json={"name": "测试代理", "address": ADDRESS} | changes,
    )


def test_proxy_pool_admin_only_and_csrf(admin, alice):
    assert create_proxy(alice).status_code == 403
    assert alice.get("/api/admin/proxies").status_code == 403
    assert (
        alice.patch("/api/admin/proxies/1", json={"enabled": False}).status_code == 403
    )
    assert alice.post("/api/admin/proxies/1/probe").status_code == 403
    assert alice.delete("/api/admin/proxies/1").status_code == 403
    assert (
        admin.post(
            "/api/admin/proxies",
            json={"name": "x", "address": ADDRESS},
            headers={"X-CSRF-Token": "wrong"},
        ).status_code
        == 403
    )


def test_proxy_crud_encrypts_and_never_returns_credentials(admin):
    result = create_proxy(admin)
    assert result.status_code == 201, result.text
    row = result.json()
    assert row["host"] == "127.0.0.1" and row["port"] == 1080
    assert row["enabled"] and row["binding_count"] == 0
    assert row["auth_configured"] and row["last_probe_status"] is None
    assert admin.get(f"/api/admin/proxies/{row['id']}").json() == row
    listing = admin.get("/api/admin/proxies")
    assert len(listing.json()) == 1
    for response in (result, listing):
        assert (
            "dummy-user" not in response.text and "dummy-password" not in response.text
        )
        assert "auth_encrypted" not in response.text and "socks5" not in response.text
    from app.models import Proxy

    with SessionLocal() as db:
        ciphertext = db.get(Proxy, row["id"]).auth_encrypted
        assert "dummy-password" not in ciphertext
        assert decrypt(ciphertext) == {
            "username": "dummy-user",
            "password": "dummy-password",
        }
    edited = admin.patch(
        f"/api/admin/proxies/{row['id']}",
        json={
            "name": "改名",
            "host": "127.0.0.2",
            "port": 1081,
            "username": "",
            "password": "",
        },
    )
    assert edited.status_code == 200, edited.text
    with SessionLocal() as db:
        assert db.get(Proxy, row["id"]).auth_encrypted == ciphertext
    assert (
        admin.patch(
            f"/api/admin/proxies/{row['id']}",
            json={"username": "new-user", "password": "new-password", "enabled": False},
        ).status_code
        == 200
    )
    with SessionLocal() as db:
        p = db.get(Proxy, row["id"])
        assert not p.enabled and p.revision == 3
        assert decrypt(p.auth_encrypted)["password"] == "new-password"
        details = " ".join(db.scalars(select(AuditEvent.detail)))
        assert not any(
            x in details
            for x in ("dummy-user", "dummy-password", "new-password", ADDRESS)
        )
    assert admin.delete(f"/api/admin/proxies/{row['id']}").status_code == 200
    assert admin.get("/api/admin/proxies").json() == []


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1:0:dummy-user:dummy-password",
        "127.0.0.1:65536:dummy-user:dummy-password",
        "https://dummy-user:dummy-password@example.com",
        "example.com:1080:dummy-user:dummy-password",
        "127.0.0.1:1080:dummy-user",
        "127.0.0.1:1080:dummy-user:dummy-password\n127.0.0.2:1:u:p",
    ],
)
def test_proxy_validation_hides_submitted_credentials(admin, address):
    result = create_proxy(admin, address=address)
    assert result.status_code == 422
    assert "dummy-user" not in result.text and "dummy-password" not in result.text
    assert admin.get("/api/admin/proxies").json() == []


def test_proxy_multiline_import_is_atomic_and_bounded(admin):
    result = admin.post(
        "/api/admin/proxies/import",
        json={
            "addresses": ADDRESS + "\ninvalid:dummy-password",
            "name_prefix": "导入",
        },
    )
    assert result.status_code == 422
    assert "dummy-password" not in result.text
    assert admin.get("/api/admin/proxies").json() == []
    result = admin.post(
        "/api/admin/proxies/import",
        json={
            "addresses": ADDRESS + "\n127.0.0.2:1081:dummy-user:dummy-password",
            "name_prefix": "导入",
        },
    )
    assert result.status_code == 201, result.text
    assert len(result.json()["items"]) == 2
    assert "dummy-password" not in result.text
    too_many = admin.post(
        "/api/admin/proxies/import", json={"addresses": "\n".join([ADDRESS] * 101)}
    )
    assert too_many.status_code == 422
    assert len(admin.get("/api/admin/proxies").json()) == 2


def test_proxy_bound_disable_allowed_but_delete_blocked(admin):
    result = create_proxy(admin)
    assert result.status_code == 201, result.text
    pid = result.json()["id"]
    from app.models import AwsAccount

    with SessionLocal() as db:
        db.get(AwsAccount, 1).proxy_id = pid
        db.commit()
    disabled = admin.patch(f"/api/admin/proxies/{pid}", json={"enabled": False})
    assert disabled.status_code == 200 and disabled.json()["binding_count"] == 1
    assert disabled.json()["status"] == "disabled"
    assert admin.delete(f"/api/admin/proxies/{pid}").status_code == 409
    with SessionLocal() as db:
        # Deleted console accounts still retain their proxy selection for restore.
        from app.models import now

        db.get(AwsAccount, 1).deleted_at = now()
        db.commit()
    assert admin.delete(f"/api/admin/proxies/{pid}").status_code == 409


def archived_proxy_account(db, pid, *, duplicate=False):
    from app.models import AwsAccount, now

    account = db.get(AwsAccount, 1)
    if duplicate:
        values = {
            column.name: getattr(account, column.name)
            for column in AwsAccount.__table__.columns
            if column.name not in ("id", "name", "account_number")
        }
        account = AwsAccount(id=2, name="历史 AWS", **values)
        db.add(account)
    account.proxy_id = pid
    account.active = False
    account.deleted_at = now()
    return account


def test_proxy_inventory_distinguishes_deleted_configuration_bindings(admin):
    from app.models import AwsAccount

    pid = create_proxy(admin).json()["id"]
    with SessionLocal() as db:
        archived_proxy_account(db, pid, duplicate=True)
        db.get(AwsAccount, 1).proxy_id = pid
        db.commit()
    row = admin.get(f"/api/admin/proxies/{pid}").json()
    assert row["binding_count"] == 2
    assert row["deleted_binding_count"] == 1


def test_release_deleted_proxy_bindings_preserves_current_account_and_history(admin):
    from app.models import AwsAccount

    pid = create_proxy(admin).json()["id"]
    with SessionLocal() as db:
        archived = archived_proxy_account(db, pid, duplicate=True)
        before = archived.credentials_encrypted
        deleted_at = archived.deleted_at
        db.get(AwsAccount, 1).proxy_id = pid
        db.commit()
    released = admin.post(f"/api/admin/proxies/{pid}/release-deleted-bindings")
    assert released.status_code == 200, released.text
    assert released.json()["binding_count"] == 1
    assert released.json()["deleted_binding_count"] == 0
    with SessionLocal() as db:
        current, archived = db.get(AwsAccount, 1), db.get(AwsAccount, 2)
        assert current.proxy_id == pid and current.active and not current.deleted_at
        assert archived.proxy_id is None and not archived.active
        assert archived.deleted_at == deleted_at and archived.credentials_encrypted == before
        events = db.scalars(select(AuditEvent).where(AuditEvent.action == "release_deleted_proxy_bindings")).all()
        assert len(events) == 1 and "2" in events[0].detail
        assert "dummy-password" not in events[0].detail
    assert admin.delete(f"/api/admin/proxies/{pid}").status_code == 409
    assert admin.post("/api/admin/aws/2/restore").status_code == 200
    archived = admin.get("/api/admin/aws/2").json()
    assert not archived["active"] and archived["proxy_id"] is None


def test_deleted_proxy_binding_can_be_released_then_proxy_deleted(admin):
    from app.models import AwsAccount, Proxy

    pid = create_proxy(admin).json()["id"]
    with SessionLocal() as db:
        archived_proxy_account(db, pid)
        db.commit()
    released = admin.post(f"/api/admin/proxies/{pid}/release-deleted-bindings")
    assert released.status_code == 200, released.text
    assert released.json()["binding_count"] == released.json()["deleted_binding_count"] == 0
    assert admin.delete(f"/api/admin/proxies/{pid}").status_code == 200
    with SessionLocal() as db:
        assert db.get(Proxy, pid) is None
        assert db.get(AwsAccount, 1).deleted_at
        assert db.get(AwsAccount, 1).proxy_id is None
    assert admin.post("/api/admin/aws/1/restore").status_code == 200
    assert not admin.get("/api/admin/aws/1").json()["active"]


def test_release_deleted_proxy_bindings_rejects_pending_work_atomically(admin, alice):
    from app.models import AwsAccount
    from test_workflows import create

    pending = create(alice)
    assert pending.status_code == 202, pending.text
    pid = create_proxy(admin).json()["id"]
    with SessionLocal() as db:
        archived_proxy_account(db, pid, duplicate=True)
        archived_proxy_account(db, pid)
        db.commit()
    rejected = admin.post(f"/api/admin/proxies/{pid}/release-deleted-bindings")
    assert rejected.status_code == 409, rejected.text
    assert "任务" in rejected.json()["detail"]
    with SessionLocal() as db:
        assert db.get(AwsAccount, 1).proxy_id == db.get(AwsAccount, 2).proxy_id == pid
        assert db.scalar(select(AuditEvent.id).where(AuditEvent.action == "release_deleted_proxy_bindings")) is None


def test_release_deleted_proxy_bindings_requires_admin_csrf_and_deleted_reference(admin, alice):
    from app.models import AwsAccount

    pid = create_proxy(admin).json()["id"]
    with SessionLocal() as db:
        db.get(AwsAccount, 1).proxy_id = pid
        db.commit()
    url = f"/api/admin/proxies/{pid}/release-deleted-bindings"
    assert alice.post(url).status_code == 403
    assert admin.post(url, headers={"X-CSRF-Token": "wrong"}).status_code == 403
    assert admin.post(url).status_code == 409
    with SessionLocal() as db:
        assert db.get(AwsAccount, 1).proxy_id == pid


def test_proxy_credentials_can_be_explicitly_cleared(admin):
    result = create_proxy(admin)
    assert result.status_code == 201, result.text
    pid = result.json()["id"]
    assert (
        admin.patch(
            f"/api/admin/proxies/{pid}", json={"username": "only-one"}
        ).status_code
        == 422
    )
    result = admin.patch(f"/api/admin/proxies/{pid}", json={"clear_auth": True})
    assert result.status_code == 200 and not result.json()["auth_configured"]
    from app.models import Proxy

    with SessionLocal() as db:
        assert decrypt(db.get(Proxy, pid).auth_encrypted) == {
            "username": "",
            "password": "",
        }


@pytest.mark.parametrize("failure", [None, "redirect", "invalid_ip", "network"])
def test_probe_is_bounded_fixed_https_and_never_echoes_errors(
    admin, monkeypatch, failure
):
    import requests
    from app import proxies

    result = create_proxy(admin)
    pid = result.json()["id"]
    seen = []

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def get(self, url, **kw):
            assert url == "https://checkip.amazonaws.com/"
            assert kw["timeout"] == (5, 10) and kw["allow_redirects"] is False
            assert kw["verify"] is True
            if failure == "network":
                raise requests.ConnectionError(
                    "socks5h://dummy-user:dummy-password@127.0.0.1:1080"
                )
            return SimpleNamespace(
                status_code=302 if failure == "redirect" else 200,
                text="dummy-password" if failure == "invalid_ip" else "203.0.113.42\n",
                close=lambda: None,
            )

    def session(proxy_url):
        seen.append(proxy_url)
        return FakeSession()

    monkeypatch.setattr(proxies, "request_session", session, raising=False)
    result = admin.post(f"/api/admin/proxies/{pid}/probe")
    assert result.status_code == 200, result.text
    assert result.json()["last_probe_status"] == (
        "ok" if failure is None else "connect" if failure == "network" else "invalid_response"
    )
    assert result.json()["last_probe_at"]
    assert result.json()["egress_ip"] == ("203.0.113.42" if failure is None else None)
    assert seen == ["socks5h://dummy-user:dummy-password@127.0.0.1:1080"]
    assert "dummy-password" not in result.text


@pytest.mark.parametrize("failure,category", [("timeout", "timeout"), ("tls", "tls"), ("auth", "auth_failed")])
def test_probe_classifies_nested_errors_without_exposing_credentials(admin, monkeypatch, failure, category):
    import requests
    import socks
    from app import proxies

    pid = create_proxy(admin).json()["id"]
    secret_url = "socks5h://dummy-user:dummy-password@127.0.0.1:1080"
    error = {"timeout": requests.Timeout, "tls": requests.exceptions.SSLError, "auth": socks.SOCKS5AuthError}[failure](secret_url)
    if failure == "auth":
        wrapped = requests.ConnectionError(secret_url)
        wrapped.__cause__ = error
        error = wrapped

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, *args, **kwargs):
            raise error

    monkeypatch.setattr(proxies, "request_session", lambda url: Session())
    response = admin.post(f"/api/admin/proxies/{pid}/probe")
    assert response.status_code == 200
    assert response.json()["last_probe_status"] == category
    assert "dummy-password" not in response.text and secret_url not in response.text
    with SessionLocal() as db:
        assert "dummy-password" not in " ".join(db.scalars(select(AuditEvent.detail)))


def test_real_socks_auth_rejection_has_safe_category_and_no_direct_fallback(admin):
    import socketserver
    import threading
    from test_aws_transport import read_exact

    attempts = []

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(2)
            version, count = read_exact(self.request, 2)
            assert version == 5 and 2 in read_exact(self.request, count)
            self.request.sendall(b"\x05\x02")
            _, count = read_exact(self.request, 2)
            username = read_exact(self.request, count)
            password = read_exact(self.request, read_exact(self.request, 1)[0])
            attempts.append((username, password))
            self.request.sendall(b"\x01\x01")

    with socketserver.TCPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            pid = create_proxy(admin, address=f"127.0.0.1:{server.server_address[1]}:dummy-user:dummy-password").json()["id"]
            response = admin.post(f"/api/admin/proxies/{pid}/probe")
            assert response.status_code == 200
            assert response.json()["last_probe_status"] == "auth_failed"
            assert "dummy-password" not in response.text
        finally:
            server.shutdown()
            thread.join(timeout=3)
    assert attempts == [(b"dummy-user", b"dummy-password")]


def test_proxy_metadata_update_preserves_saved_auth_when_fields_omitted(admin):
    from app.models import Proxy

    pid = create_proxy(admin).json()["id"]
    with SessionLocal() as db:
        before = db.get(Proxy, pid).auth_encrypted
    response = admin.patch(f"/api/admin/proxies/{pid}", json={"name": "Metadata only", "enabled": False})
    assert response.status_code == 200 and response.json()["auth_configured"]
    with SessionLocal() as db:
        assert db.get(Proxy, pid).auth_encrypted == before


def test_probe_connection_refusal_is_not_a_timeout(admin, monkeypatch):
    import requests
    from urllib3.exceptions import MaxRetryError, NewConnectionError
    from app import proxies

    pid = create_proxy(admin).json()["id"]

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def get(self, *args, **kwargs):
            # urllib3's NewConnectionError also inherits ConnectTimeoutError.
            raise requests.ConnectionError(MaxRetryError(None, "synthetic", NewConnectionError(None, "connection refused")))

    monkeypatch.setattr(proxies, "request_session", lambda url: Session())
    assert admin.post(f"/api/admin/proxies/{pid}/probe").json()["last_probe_status"] == "connect"


@pytest.mark.parametrize("path", ["create", "edit", "discover"])
def test_aws_proxy_selection_rejected_before_network(admin, monkeypatch, path):
    called = []
    monkeypatch.setattr(
        Gateway, "verify", lambda self: called.append(True) or "123456789012"
    )
    monkeypatch.setattr("app.main.aws.AwsGateway", Gateway)
    monkeypatch.setattr(
        "app.main.aws.discover", lambda *a, **kw: called.append(True) or {}
    )
    body = aws_body(
        admin,
        name="新 AWS",
        access_key_id="TEST_ACCESS_KEY_16",
        secret_access_key="TEST_SECRET_KEY_16",
        proxy_id=999,
    )
    if path == "discover":
        body = {
            k: body[k]
            for k in (
                "region",
                "subscription_region",
                "access_key_id",
                "secret_access_key",
                "proxy_id",
            )
        }
        result = admin.post("/api/admin/aws/discover", json=body)
    elif path == "edit":
        result = admin.put("/api/admin/aws/1", json=body)
    else:
        result = admin.post("/api/admin/aws", json=body)
    assert result.status_code == 409, result.text
    assert not called


@pytest.mark.parametrize("path", ["create", "edit", "discover"])
@pytest.mark.parametrize("change", ["disable", "edit", "delete"])
def test_aws_rechecks_proxy_revision_after_network(admin, monkeypatch, path, change):
    pid = create_proxy(admin).json()["id"]
    called = []

    def mutate():
        if change == "delete":
            result = admin.delete(f"/api/admin/proxies/{pid}")
        else:
            result = admin.patch(
                f"/api/admin/proxies/{pid}",
                json={"enabled": False} if change == "disable" else {"port": 1081},
            )
        assert result.status_code == 200
        called.append(True)

    class InterleavedGateway(Gateway):
        def verify(self):
            mutate()
            return "123456789012"

    monkeypatch.setattr("app.main.aws.AwsGateway", InterleavedGateway)
    monkeypatch.setattr(
        "app.main.aws.discover", lambda *a, **kw: mutate() or {"profiles": []}
    )
    body = aws_body(
        admin,
        name="新 AWS",
        access_key_id="TEST_ACCESS_KEY_16",
        secret_access_key="TEST_SECRET_KEY_16",
        proxy_id=pid,
    )
    if path == "discover":
        body = {
            k: body[k]
            for k in (
                "region",
                "subscription_region",
                "access_key_id",
                "secret_access_key",
                "proxy_id",
            )
        }
        result = admin.post("/api/admin/aws/discover", json=body)
    elif path == "edit":
        result = admin.put("/api/admin/aws/1", json=body)
    else:
        result = admin.post("/api/admin/aws", json=body)
    assert called
    assert result.status_code == 409, result.text
    assert len(admin.get("/api/accounts").json()) == 1
    assert admin.get("/api/admin/aws/1").json()["proxy_id"] is None


def test_aws_bind_edit_unbind_and_member_privacy(admin, alice, monkeypatch):
    monkeypatch.setattr("app.main.aws.AwsGateway", Gateway)
    pid = create_proxy(admin).json()["id"]
    result = admin.put("/api/admin/aws/1", json=aws_body(admin, proxy_id=pid))
    assert result.status_code == 200, result.text
    account = admin.get("/api/admin/aws/1").json()
    assert account["proxy_id"] == pid and account["proxy_name"] == "测试代理"
    assert account["proxy_status"] == "enabled"
    public = alice.get("/api/accounts")
    assert "proxy_id" not in public.text
    assert public.json()[0]["proxy_name"] == "测试代理"
    assert public.json()[0]["proxy_status"] == "enabled"
    assert "127.0.0.1" not in public.text and "dummy-password" not in public.text
    result = admin.put("/api/admin/aws/1", json=aws_body(admin, proxy_id=None))
    assert result.status_code == 200 and result.json()["proxy_id"] is None


def test_schema_six_proxy_migration_is_additive_and_preserves_all_rows(admin, alice):
    from sqlalchemy import text
    from app.database import engine
    from app.init_db import initialize
    from app.migrations import VERSION
    from app.models import SchemaVersion, StopSchedule
    from test_workflows import create

    rid = create(alice).json()["id"]
    with SessionLocal() as db:
        db.add(
            StopSchedule(
                record_id=rid,
                actor_id=2,
                mode="days",
                days=12,
                state="waiting_start",
                revision=8,
            )
        )
        db.commit()
    from app.models import AwsAccount

    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
        conn.commit()
        columns_v6 = [c for c in AwsAccount.__table__.columns if c.name != "proxy_id"]
        ddl = ",".join(
            f"{c.name} {c.type.compile(dialect=engine.dialect)}"
            + (" PRIMARY KEY" if c.primary_key else "")
            for c in columns_v6
        )
        names_v6 = ",".join(c.name for c in columns_v6)
        conn.exec_driver_sql(f"CREATE TABLE console_aws_accounts_v6 ({ddl})")
        conn.exec_driver_sql(
            f"INSERT INTO console_aws_accounts_v6 SELECT {names_v6} FROM console_aws_accounts"
        )
        conn.exec_driver_sql("DROP TABLE console_aws_accounts")
        conn.exec_driver_sql(
            "ALTER TABLE console_aws_accounts_v6 RENAME TO console_aws_accounts"
        )
        conn.exec_driver_sql("DROP TABLE console_proxies")
        conn.execute(text("INSERT INTO console_schema_version (version) VALUES (6)"))
        names = [
            row[0]
            for row in conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'console_%' AND name NOT IN ('console_schema_version', 'console_plans', 'console_audit_events')"
            )
        ]
        before = {
            name: conn.exec_driver_sql(f"SELECT * FROM {name}").fetchall()
            for name in names
        }
        columns = {
            name: [row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({name})")]
            for name in names
        }
        conn.commit()
        conn.exec_driver_sql("PRAGMA foreign_keys=ON")
        conn.commit()
    initialize()
    initialize()
    with engine.connect() as conn:
        for name in names:
            column_sql = ",".join(columns[name])
            assert (
                conn.exec_driver_sql(f"SELECT {column_sql} FROM {name}").fetchall()
                == before[name]
            )
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
    with SessionLocal() as db:
        assert db.scalar(select(SchemaVersion.version)) == VERSION


def test_probe_rechecks_revision_without_holding_writer_lock(admin, monkeypatch):
    from app import proxies

    pid = create_proxy(admin).json()["id"]

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def get(self, *a, **kw):
            changed = admin.patch(f"/api/admin/proxies/{pid}", json={"port": 1081})
            assert changed.status_code == 200
            return SimpleNamespace(
                status_code=200, text="203.0.113.42", close=lambda: None
            )

    monkeypatch.setattr(
        proxies, "request_session", lambda url: FakeSession(), raising=False
    )
    response = admin.post(f"/api/admin/proxies/{pid}/probe")
    assert response.status_code == 409
    assert admin.get(f"/api/admin/proxies/{pid}").json()["last_probe_status"] is None


@pytest.mark.parametrize("kind", ["missing", "disabled"])
def test_gateway_bound_unavailable_proxy_fails_closed(admin, monkeypatch, kind):
    from app import aws
    from app.models import AwsAccount

    pid = create_proxy(admin).json()["id"]
    if kind == "disabled":
        assert (
            admin.patch(
                f"/api/admin/proxies/{pid}", json={"enabled": False}
            ).status_code
            == 200
        )
    monkeypatch.setattr(
        aws,
        "make_session",
        lambda *a, **kw: pytest.fail(
            "AWS session must not be created for unavailable proxy"
        ),
    )
    with SessionLocal() as db:
        account = db.get(AwsAccount, 1)
        account.proxy_id = pid if kind == "disabled" else 999
        with pytest.raises(aws.AwsFailure, match="代理"):
            aws.AwsGateway(account)


@pytest.mark.parametrize("change", ["disable", "edit", "unbind"])
@pytest.mark.parametrize("operation", ["sdk", "http"])
def test_existing_gateway_rechecks_proxy_on_every_send(
    admin, monkeypatch, change, operation
):
    from app import aws
    from app.models import AwsAccount

    pid = create_proxy(admin).json()["id"]
    with SessionLocal() as db:
        account = db.get(AwsAccount, 1)
        account.proxy_id = pid
        db.commit()
        gateway = aws.AwsGateway(account)
    if change == "unbind":
        with SessionLocal() as db:
            db.get(AwsAccount, 1).proxy_id = None
            db.commit()
    else:
        admin.patch(
            f"/api/admin/proxies/{pid}",
            json={"enabled": False} if change == "disable" else {"port": 1081},
        )
    monkeypatch.setattr(
        "requests.adapters.HTTPAdapter.send",
        lambda *a, **kw: pytest.fail("No network after proxy changes"),
    )
    with pytest.raises(aws.AwsFailure, match="代理"):
        if operation == "sdk":
            gateway.user_info(
                SimpleNamespace(sso_user_id="12345678-1234-1234-1234-123456789012")
            )
        else:
            gateway.password(SimpleNamespace(sso_user_id="test-user"))


def test_gateway_and_discovery_route_every_service_through_selected_proxy(
    admin, monkeypatch
):
    from app import aws
    from app.models import AwsAccount

    pid = create_proxy(admin).json()["id"]
    expected_url = "socks5h://dummy-user:dummy-password@127.0.0.1:1080"
    sdk, http = [], []
    instance = "arn:aws:sso:::instance/ssoins-1234567890123456"
    profile = {
        "arn": "arn:aws:codewhisperer:us-east-1:123456789012:profile/TEST",
        "profileName": "test",
        "identityDetails": {
            "ssoIdentityDetails": {
                "instanceArn": instance,
                "oidcClientId": "arn:aws:sso::123456789012:application/ssoins-1234567890123456/apl-1234567890123456",
            }
        },
    }
    app_arn = profile["identityDetails"]["ssoIdentityDetails"]["oidcClientId"]

    class Sdk:
        def get_caller_identity(self):
            return {"Account": "123456789012"}

        def list_users(self, **kw):
            return {"Users": []}

        def list_instances(self):
            return {
                "Instances": [
                    {"InstanceArn": instance, "IdentityStoreId": "d-1234567890"}
                ]
            }

        def list_applications(self, **kw):
            return {"Applications": [{"ApplicationArn": app_arn, "Status": "ENABLED"}]}

    def configure(client, url, guard):
        assert url == expected_url
        guard()
        sdk.append(client.meta.service_model.service_name)
        return Sdk()

    def signed(session, region, host, service, target, body, **kw):
        assert kw["proxy_url"] == expected_url
        kw["proxy_check"]()
        http.append(target.split(".")[-1])
        return {
            "profiles": [profile],
            "claims": [],
            "Password": "dummy-otp",
        }, "test-request"

    monkeypatch.setattr(aws, "configure_client_proxy", configure)
    monkeypatch.setattr(aws, "signed_call", signed)
    with SessionLocal() as db:
        account = db.get(AwsAccount, 1)
        account.proxy_id = pid
        db.commit()
        gateway = aws.AwsGateway(account)
    assert gateway.verify() == "123456789012"
    record = SimpleNamespace(
        sso_user_id="test-user", subscription_type="Q_DEVELOPER_STANDALONE_PRO"
    )
    gateway.password(record)
    gateway.subscribe(record)
    gateway.cancel_subscription(record, "IMMEDIATE")
    aws.discover(
        SimpleNamespace(
            access_key_id="TEST_ACCESS_KEY",
            secret_access_key="TEST_SECRET_KEY",
            region="us-east-1",
            subscription_region="us-east-1",
            proxy_id=pid,
        )
    )
    assert sdk == ["identitystore", "sts", "sts", "sso-admin"]
    assert set(http) == {
        "ListProfiles",
        "ListApplicationClaims",
        "UpdatePassword",
        "CreateAssignment",
        "DeleteAssignment",
    }


def test_deleted_proxy_id_is_never_reused_during_aws_validation(admin, monkeypatch):
    pid = create_proxy(admin).json()["id"]

    class ReplacingGateway(Gateway):
        def verify(self):
            assert admin.delete(f"/api/admin/proxies/{pid}").status_code == 200
            assert (
                create_proxy(
                    admin,
                    name="替代代理",
                    address="127.0.0.2:1082:new-user:new-password",
                ).status_code
                == 201
            )
            return "123456789012"

    monkeypatch.setattr("app.main.aws.AwsGateway", ReplacingGateway)
    result = admin.put("/api/admin/aws/1", json=aws_body(admin, proxy_id=pid))
    assert result.status_code == 409, result.text
    assert admin.get("/api/admin/proxies").json()[0]["id"] != pid


def test_multiline_import_preserves_password_spaces(admin):
    result = admin.post(
        "/api/admin/proxies/import",
        json={"addresses": "127.0.0.1:1080:dummy-user:dummy password  \n"},
    )
    assert result.status_code == 201
    from app.models import Proxy

    with SessionLocal() as db:
        assert (
            decrypt(db.get(Proxy, result.json()["items"][0]["id"]).auth_encrypted)[
                "password"
            ]
            == "dummy password  "
        )
