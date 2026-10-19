import csv
import io
import json
import zipfile
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app import aws
from app.database import SessionLocal
from app.models import AuditEvent, AwsAccount, Binding, ManagedGroup, Proxy, Subscription, User
from app.security import encrypt


HEADERS = {
    "users": ["Name", "Email", "Kiro plan", "Downgraded to"],
    "groups": ["Group name", "Subscription status", "Kiro plan", "Downgraded to"],
    "subscriptions": ["Name", "Email", "Subscription status", "Kiro plan", "Plan source", "Activation date"],
}


def claim(principal, kind="KIRO_ENTERPRISE_PRO", **kw):
    return {"principal": principal, "type": {"amazonQ": kind},
            "applicationArn": "arn:aws:sso::123456789012:application/ssoins-1234567890123456/apl-1234567890123456",
            "createdBy": "123456789012", **kw}


class ReportsGateway:
    calls = []
    change = None
    users = [{"UserId": "own", "UserName": 'Current, "Alice"\nName', "DisplayName": "Not the console name",
              "Emails": [{"Value": "alice@current.example", "Primary": True}]},
             {"UserId": "foreign", "UserName": "Bob secret", "Emails": [{"Value": "bob@secret.example"}]}]
    groups = [{"GroupId": "own-group", "DisplayName": "Empty group"},
              {"GroupId": "foreign-group", "DisplayName": "Other group"}]
    claims = [claim({"user": "own"}, expirationDate=1893456000, newType={"amazonQ": "KIRO_ENTERPRISE_FREE"}),
              claim({"user": "foreign"}), claim({"user": "deleted"}, "FUTURE_PLAN"),
              claim({"group": "own-group"}, expirationDate=1893456000, newType={"amazonQ": "KIRO_ENTERPRISE_PRO_PLUS"}),
              claim({"group": "foreign-group"})]
    subscriptions = [{"principal": {"user": "own"}, "type": {"amazonQ": "KIRO_ENTERPRISE_PRO"},
                      "status": "PENDING", "aggregatedSubscriptionType": "GROUP"},
                     {"principal": {"user": "foreign"}, "type": {"amazonQ": "KIRO_ENTERPRISE_POWER"},
                      "status": "ACTIVE", "aggregatedSubscriptionType": "INDIVIDUAL", "activationDate": 1790812800},
                     {"principal": {"user": "deleted"}, "type": {"amazonQ": "FUTURE_PLAN"},
                      "status": "FUTURE_STATUS", "aggregatedSubscriptionType": "FUTURE_SOURCE"}]

    def __init__(self, account):
        self.account = account

    def report_users(self):
        if type(self).change:
            type(self).change()
        return type(self).users

    def report_groups(self):
        if type(self).change:
            type(self).change()
        return type(self).groups

    def report_claims(self):
        return type(self).claims

    def report_subscriptions(self):
        return type(self).subscriptions

    def monthly_cost(self, month, payer_id=None):
        type(self).calls.append((self.account.id, month, payer_id))
        if type(self).change:
            type(self).change()
        from app.aws_report_gateway import month_period
        start, end = month_period(month)
        return {"amount": "123.4500", "currency": "USD", "estimated": True,
                "period_start": start, "period_end": end, "source": "aws_bills_console",
                "billing_kind": "proforma", "payer_id": payer_id or "999999999999",
                "available_payers": ["999999999999", "888888888888"], "retrieved_at": "2026-10-11T00:00:00Z"}


@pytest.fixture
def report_remote(monkeypatch):
    from app import aws_bills, aws_reports
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2026, 10, 11, tzinfo=timezone.utc)
    monkeypatch.setattr(aws_bills, "datetime", Clock)
    monkeypatch.setattr(aws_reports, "datetime", Clock)
    monkeypatch.setattr(aws_reports, "cost_reads", aws_reports.CostReads())
    monkeypatch.setattr(aws, "AwsGateway", ReportsGateway)
    monkeypatch.setattr(ReportsGateway, "calls", [])
    monkeypatch.setattr(ReportsGateway, "change", None)
    with SessionLocal() as db:
        for owner, remote in [(2, "own"), (3, "foreign")]:
            db.add(Subscription(id=remote, owner_id=owner, aws_account_id=1, request_key=remote,
                                username="old-" + remote, email=remote + "@old.example", sso_user_id=remote,
                                portal_url="https://example.com", state="completed", reserved=False))
            db.add(ManagedGroup(id=remote + "-group", owner_id=owner, aws_account_id=1,
                                aws_scope="123456789012:d-1234567890", request_key=remote, payload_hash="hash",
                                name="old-group", marker=remote, remote_id=remote + "-group", state="active"))
        db.commit()
    yield ReportsGateway


def query(client, view="subscriptions", **kw):
    return client.post("/api/aws-reports/query", json={"view": view, "account_ids": [1], **kw})


def download(client, view="subscriptions", **kw):
    return client.post("/api/aws-reports/download", json={"view": view, "account_ids": [1], **kw})


@pytest.mark.parametrize("view", HEADERS)
def test_console_csv_contract_current_directory_and_no_secrets(admin, report_remote, view):
    result = query(admin, view)
    assert result.status_code == 200, result.text
    assert result.headers["Cache-Control"] == "no-store"
    assert result.json()["columns"] == HEADERS[view]
    exported = download(admin, view)
    assert exported.status_code == 200, exported.text
    assert exported.content.startswith(b"\xef\xbb\xbf\"")
    assert exported.headers["Cache-Control"] == "no-store"
    assert exported.headers["Content-Disposition"].endswith('.csv"')
    parsed = list(csv.reader(io.StringIO(exported.content.decode("utf-8-sig"))))
    assert parsed[0] == HEADERS[view]
    assert len(parsed) - 1 == result.json()["total"]
    assert int(exported.headers["X-Export-Count"]) == result.json()["total"]
    if view == "groups":
        assert ["Empty group", "Subscribed", "Kiro Pro", "Kiro Pro+"] in parsed
    elif view == "users":
        assert ['Current, "Alice"\nName', "alice@current.example", "Kiro Pro", "Kiro Free"] in parsed
        assert ["deleted", "-", "FUTURE_PLAN", "-"] in parsed
    else:
        assert ['Current, "Alice"\nName', "alice@current.example", "Pending", "Kiro Pro", "Group", "-"] in parsed
        assert any(r[-1].endswith(" UTC") for r in parsed[1:] if r[0] == "Bob secret")
        assert ["deleted", "-", "FUTURE_STATUS", "FUTURE_PLAN", "FUTURE_SOURCE", "-"] in parsed
    assert "old.example" not in exported.text and "password" not in exported.text.lower()
    with SessionLocal() as db:
        events = list(db.scalars(select(AuditEvent).where(AuditEvent.action == "aws_report_download")))
        assert len(events) == 1
        detail = json.loads(events[0].detail)
        assert detail["view"] == view and detail["count"] == len(parsed) - 1
        assert "alice" not in events[0].detail.lower() and "secret" not in events[0].detail.lower()


@pytest.mark.parametrize("view", HEADERS)
def test_member_only_exact_owned_principals_and_bound_accounts(alice, report_remote, view):
    result = query(alice, view)
    assert result.status_code == 200, result.text
    assert result.json()["total"] == 1
    assert "Bob secret" not in result.text and "Other group" not in result.text and "deleted" not in result.text
    with SessionLocal() as db:
        db.delete(db.get(Binding, (2, 1)))
        db.commit()
    assert download(alice, view).status_code == 403


def test_group_inherited_subscription_does_not_need_direct_user_claim(alice, report_remote, monkeypatch):
    monkeypatch.setattr(report_remote, "claims", [c for c in report_remote.claims if c["principal"] != {"user": "own"}])
    result = query(alice)
    assert result.status_code == 200
    assert result.json()["rows"][0]["values"][4:] == ["Group", "-"]


def test_server_revalidates_selected_rows_against_search_and_owner(admin, alice, report_remote):
    all_rows = query(admin).json()["rows"]
    foreign = next(r["id"] for r in all_rows if r["values"][0] == "Bob secret")
    own = next(r["id"] for r in all_rows if r["values"][4] == "Group")
    assert download(alice, row_ids=[foreign]).status_code == 409
    assert download(admin, q="alice@current", row_ids=[foreign]).status_code == 409
    selected = download(admin, q="alice@current", row_ids=[own])
    assert selected.status_code == 200 and selected.headers["X-Export-Count"] == "1"


@pytest.mark.parametrize("change", ["role", "disabled", "session", "binding", "ownership", "account", "credentials", "profile", "proxy"])
@pytest.mark.parametrize("endpoint", ["query", "download"])
def test_report_rechecks_scope_after_remote_reads(alice, report_remote, monkeypatch, change, endpoint):
    def mutate():
        with SessionLocal() as db:
            if change in ("role", "disabled", "session"):
                u = db.get(User, 2)
                if change == "role":
                    u.role = "admin"
                elif change == "disabled":
                    u.active = False
                else:
                    u.session_version += 1
            elif change == "binding":
                db.delete(db.get(Binding, (2, 1)))
            elif change == "ownership":
                db.get(Subscription, "own").owner_id = 3
            else:
                a = db.get(AwsAccount, 1)
                if change == "account":
                    a.active = False
                elif change == "credentials":
                    a.credentials_encrypted = encrypt({"access_key_id": "new", "secret_access_key": "new"})
                elif change == "profile":
                    a.profile_arn += "changed"
                else:
                    db.add(Proxy(id=1, name="changed", host="127.0.0.1", port=9999,
                                 auth_encrypted=encrypt({"username": "", "password": ""})))
                    db.flush()
                    a.proxy_id = 1
            db.commit()
    monkeypatch.setattr(report_remote, "change", mutate)
    result = (query if endpoint == "query" else download)(alice)
    assert result.status_code in (401, 403, 409), result.text
    assert "Current" not in result.text


def second_account():
    with SessionLocal() as db:
        original = db.get(AwsAccount, 1)
        data = {col.name: getattr(original, col.name) for col in AwsAccount.__table__.columns if col.name not in ("id", "name")}
        db.add(AwsAccount(id=2, name='../../quoted, account', **data))
        db.commit()


def test_multi_account_zip_unique_safe_names_and_intersected_search(admin, report_remote):
    second_account()
    response = download(admin, account_ids=[1, 2], q="alice@current")
    assert response.status_code == 200, response.text
    assert response.headers["Content-Type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(response.content)) as z:
        assert len(z.namelist()) == len(set(z.namelist())) == 2
        for name in z.namelist():
            assert name.endswith("-subscriptions.csv") and "/" not in name and ".." not in name
            rows = list(csv.reader(io.StringIO(z.read(name).decode("utf-8-sig"))))
            assert len(rows) == 2 and rows[1][1] == "alice@current.example"


def test_any_account_failure_fails_entire_export(admin, report_remote, monkeypatch):
    second_account()
    original = report_remote.report_users
    def failed(self):
        if self.account.id == 2:
            raise aws.AwsFailure("synthetic failed page")
        return original(self)
    monkeypatch.setattr(report_remote, "report_users", failed)
    response = download(admin, account_ids=[1, 2])
    assert response.status_code == 502, response.text
    assert "Content-Disposition" not in response.headers
    assert "账号 #2" in response.json()['detail']


def test_download_selection_survives_live_plan_update(admin, report_remote, monkeypatch):
    preview = query(admin, 'users').json()
    chosen = next(row['id'] for row in preview['rows'] if row['values'][0].startswith('Current'))
    claims = [dict(row) for row in report_remote.claims]
    claims[0]['newType'] = {'amazonQ': 'KIRO_ENTERPRISE_PRO_PLUS'}
    monkeypatch.setattr(report_remote, 'claims', claims)
    response = download(admin, 'users', row_ids=[chosen])
    assert response.status_code == 200, response.text
    rows = list(csv.reader(io.StringIO(response.content.decode('utf-8-sig'))))
    assert len(rows) == 2 and rows[1][-1] == 'Kiro Pro+'


def test_report_reads_accounts_concurrently_without_sharing_database_session(admin, report_remote, monkeypatch):
    import threading
    second_account()
    rendezvous = threading.Barrier(2, timeout=3)
    original = report_remote.report_subscriptions
    def synchronized(self):
        rendezvous.wait()
        return original(self)
    monkeypatch.setattr(report_remote, 'report_subscriptions', synchronized)
    response = download(admin, account_ids=[1, 2])
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("name", ["=SUM(1,2)", "+1", "-2", "@SUM(A1)", " \t=cmd", "\x00\x1f=cmd", "\u200b=cmd", "\r\n@cmd"])
def test_csv_formula_protection_preserves_missing_hyphen(admin, report_remote, monkeypatch, name):
    monkeypatch.setattr(report_remote, "users", [{"UserId": "own", "UserName": name}])
    response = download(admin, q=name.strip())
    assert response.status_code == 200
    rows = list(csv.reader(io.StringIO(response.content.decode("utf-8-sig"))))
    assert rows[1][0] == "'" + name and rows[1][1] == rows[1][-1] == "-"


def test_cost_admin_only_sequential_fresh_reads_and_config_invalidation(admin, alice, report_remote):
    path = "/api/admin/aws/1/cost?month=2026-10"
    assert alice.get(path).status_code == 403
    first = admin.get(path)
    assert first.status_code == 200, first.text
    assert first.json() == {"account_id": 1, "month": "2026-10", "amount": "123.4500", "currency": "USD",
                            "estimated": True, "period_start": "2026-10-01", "period_end": "2026-11-01",
                            "source": "aws_bills_console", "billing_kind": "proforma", "payer_id": "999999999999",
                            "available_payers": ["999999999999", "888888888888"], "retrieved_at": "2026-10-11T00:00:00Z"}
    assert first.headers["Cache-Control"] == "no-store"
    assert admin.get(path).json() == first.json()
    assert len(report_remote.calls) == 2
    assert admin.get(path + "&refresh=true").status_code == 200
    assert len(report_remote.calls) == 3
    with SessionLocal() as db:
        db.get(AwsAccount, 1).credentials_encrypted = encrypt({"access_key_id": "new", "secret_access_key": "new"})
        db.commit()
    assert admin.get(path).status_code == 200
    assert len(report_remote.calls) == 4


def test_cost_current_utc_month_default_and_invalid_month(admin, report_remote):
    response = admin.get("/api/admin/aws/1/cost")
    assert response.status_code == 200, response.text
    assert report_remote.calls[-1][1] == "2026-10"
    for month in ["2026-09", "2026-11", "2026-13", "../2026-10", "2026-1", "0000-01", "9999-12"]:
        assert admin.get("/api/admin/aws/1/cost", params={"month": month}).status_code == 422


@pytest.mark.parametrize("change", ["role", "active", "profile", "proxy"])
def test_cost_rechecks_access_and_configuration_after_read(admin, report_remote, monkeypatch, change):
    def mutate():
        with SessionLocal() as db:
            if change == "role":
                db.get(User, 1).role = "member"
            elif change == "active":
                db.get(User, 1).active = False
            elif change == "profile":
                db.get(AwsAccount, 1).profile_arn += "other"
            else:
                db.add(Proxy(id=1, name="proxy", host="127.0.0.1", port=9999,
                             auth_encrypted=encrypt({"username": "", "password": ""})))
                db.flush()
                db.get(AwsAccount, 1).proxy_id = 1
            db.commit()
    monkeypatch.setattr(report_remote, "change", mutate)
    response = admin.get("/api/admin/aws/1/cost?month=2026-10")
    assert response.status_code in (401, 403, 409), response.text
    assert "123.4500" not in response.text


def test_cost_failed_refresh_is_not_cached_and_successful_refresh_has_cooldown(admin, report_remote, monkeypatch):
    path = "/api/admin/aws/1/cost?month=2026-10"
    assert admin.get(path).status_code == 200
    original = report_remote.monthly_cost
    def failure(self, month, payer_id=None):
        raise aws.AwsFailure("读取不可用")
    monkeypatch.setattr(report_remote, "monthly_cost", failure)
    failed = admin.get(path + "&refresh=true")
    assert failed.status_code == 502 and "Billing IAM" in failed.text and "ce:GetCostAndUsage" not in failed.text
    monkeypatch.setattr(report_remote, "monthly_cost", original)
    assert admin.get(path + "&refresh=true").status_code == 200
    assert admin.get(path + "&refresh=true").status_code == 429
    assert admin.get(path).status_code == 200
    assert len(report_remote.calls) == 3


@pytest.mark.parametrize("change", ["role", "proxy_auth", "profile"])
def test_cost_each_caller_rechecks_current_scope_after_shared_read(admin, report_remote, monkeypatch, change):
    from app import aws_reports
    with SessionLocal() as db:
        db.add(Proxy(id=1, name="test", host="127.0.0.1", port=9999,
                     auth_encrypted=encrypt({"username": "", "password": ""})))
        db.flush()
        db.get(AwsAccount, 1).proxy_id = 1
        db.commit()
    path = "/api/admin/aws/1/cost?month=2026-10"
    assert admin.get(path).status_code == 200
    original = aws_reports.cost_reads.get
    def get(*args, **kwargs):
        value = original(*args, **kwargs)
        with SessionLocal() as db:
            if change == "role":
                db.get(User, 1).role = "member"
            elif change == "proxy_auth":
                db.get(Proxy, 1).auth_encrypted = encrypt({"username": "changed", "password": "changed"})
            else:
                db.get(AwsAccount, 1).profile_arn += "change"
            db.commit()
        return value
    monkeypatch.setattr(aws_reports.cost_reads, "get", get)
    result = admin.get(path)
    assert result.status_code in (403, 409) and "123.4500" not in result.text
    assert len(report_remote.calls) == 2


def test_claims_other_application_or_account_are_excluded(admin, report_remote, monkeypatch):
    monkeypatch.setattr(report_remote, "claims", [
        claim({"user": "own"}, applicationArn="other-app"),
        claim({"user": "foreign"}, createdBy="222222222222"),
    ])
    assert query(admin, "users").json()["total"] == 0


def test_empty_new_type_is_cancelled_not_malformed_and_unknown_source_visible(admin, report_remote, monkeypatch):
    monkeypatch.setattr(report_remote, "claims", [claim({"group": "own-group"}, expirationDate=1893456000, newType={})])
    result = query(admin, "groups")
    assert result.status_code == 200, result.text
    assert result.json()["rows"][0]["values"] == ["Empty group", "Canceled", "Kiro Pro", "-"]


@pytest.mark.parametrize("kind,label", [
    ("KIRO_ENTERPRISE_PRO_PLUS", "Kiro Pro+"), ("KIRO_ENTERPRISE_PRO_MAX", "Kiro Pro Max"),
    ("KIRO_ENTERPRISE_POWER", "Kiro Power"), ("Q_DEVELOPER_STANDALONE_FREE", "Kiro Free"),
    ("KIRO_POOLING_SEAT", "Kiro Credit Sharing"), ("KIRO_POOLING_SEAT_PREPAID", "Kiro Credit Sharing"),
    ("Q_DEVELOPER_STANDALONE", "Amazon Q Developer Pro"),
])
def test_official_plan_aliases_and_combined_subscription_source(admin, report_remote, monkeypatch, kind, label):
    monkeypatch.setattr(report_remote, "subscriptions", [{"principal": {"user": "own"},
        "type": {"amazonQ": kind}, "status": "ACTIVE", "aggregatedSubscriptionType": "INDIVIDUAL_AND_GROUP",
        "activationDate": "2026-10-01T02:00:00+02:00"}])
    values = query(admin).json()["rows"][0]["values"]
    assert values[3:] == [label, "Individual + Group", "2026-10-01 00:00:00 UTC"]


def test_download_final_check_occurs_after_csv_assembly(admin, report_remote, monkeypatch):
    from app import aws_reports
    original = aws_reports.csv_bytes
    def csv_bytes(*args):
        result = original(*args)
        with SessionLocal() as db:
            db.get(User, 1).role = "member"
            db.commit()
        return result
    monkeypatch.setattr(aws_reports, "csv_bytes", csv_bytes)
    assert download(admin).status_code in (403, 409)


@pytest.mark.parametrize("status,label", [("CANCELLED", "Canceled"), ("CANCELED", "Canceled"),
                                         ("PENDING_REMOVAL", "Pending removal"), ("FREE_TRIAL", "Free trial")])
def test_subscription_status_uses_exact_official_labels(admin, report_remote, monkeypatch, status, label):
    monkeypatch.setattr(report_remote, "subscriptions", [{"principal": {"user": "own"},
        "type": {"amazonQ": "KIRO_ENTERPRISE_PRO"}, "status": status, "aggregatedSubscriptionType": "GROUP"}])
    assert query(admin).json()["rows"][0]["values"][2] == label


def test_admin_can_read_configured_inactive_account_but_member_cannot(admin, alice, report_remote):
    with SessionLocal() as db:
        db.get(AwsAccount, 1).active = False
        db.commit()
    assert query(admin).status_code == 200
    assert admin.get("/api/admin/aws/1/cost?month=2026-10").status_code == 200
    assert query(alice).status_code == 403
    with SessionLocal() as db:
        db.get(AwsAccount, 1).deleted_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.commit()
    assert query(admin).status_code == 403
    assert admin.get("/api/admin/aws/1/cost?month=2026-10").status_code == 403


@pytest.mark.parametrize("pending", [None, {}, {"amazonQ": ""}])
def test_users_report_excludes_cancelled_only_claims_from_preview_and_csv(admin, report_remote, monkeypatch, pending):
    monkeypatch.setattr(report_remote, "claims", [claim({"user": "own"}, expirationDate=1893456000,
        **({"newType": pending} if pending is not None else {}))])
    response = query(admin, "users")
    assert response.status_code == 200, response.text
    assert response.json()["rows"] == []
    response = download(admin, "users")
    assert response.status_code == 200, response.text
    assert list(csv.reader(io.StringIO(response.content.decode("utf-8-sig")))) == [HEADERS["users"]]


def test_users_report_keeps_live_and_scheduled_downgrade_claims_while_groups_keep_canceled(admin, report_remote, monkeypatch):
    monkeypatch.setattr(report_remote, "claims", [
        claim({"user": "own"}, "KIRO_ENTERPRISE_POWER", expirationDate=1893456000),
        claim({"user": "own"}, "KIRO_ENTERPRISE_PRO"),
        claim({"user": "foreign"}, "KIRO_ENTERPRISE_PRO_PLUS", expirationDate=1893456000,
              newType={"amazonQ": "KIRO_ENTERPRISE_PRO"}),
        claim({"group": "own-group"}, expirationDate=1893456000),
    ])
    response = query(admin, "users")
    assert response.status_code == 200, response.text
    assert sorted(row["values"][2:] for row in response.json()["rows"]) == [
        ["Kiro Pro", "-"], ["Kiro Pro+", "Kiro Pro"],
    ]
    exported = list(csv.reader(io.StringIO(download(admin, "users").content.decode("utf-8-sig"))))
    assert len(exported) == 3 and "Kiro Power" not in str(exported)
    assert query(admin, "groups").json()["rows"][0]["values"][1] == "Canceled"


def test_cost_validates_optional_payer_and_forwards_only_valid_selection(admin, report_remote, monkeypatch):
    for payer in ["", "bad", "12345678901", "1234567890123", "../billing"]:
        assert admin.get("/api/admin/aws/1/cost", params={"payer_id": payer}).status_code == 422
    assert not report_remote.calls
    response = admin.get("/api/admin/aws/1/cost", params={"payer_id": "888888888888"})
    assert response.status_code == 200 and response.json()["payer_id"] == "888888888888"
    assert report_remote.calls[-1] == (1, "2026-10", "888888888888")
    def unavailable(self, month, payer_id=None):
        raise ValueError("付款账号不在当前 AWS Bills 返回的可选范围内")
    monkeypatch.setattr(report_remote, "monthly_cost", unavailable)
    assert admin.get("/api/admin/aws/1/cost", params={"payer_id": "777777777777"}).status_code == 422


@pytest.mark.parametrize("change", ["role", "session", "configuration"])
def test_concurrent_bill_read_checks_each_caller_after_shared_wire(admin, report_remote, monkeypatch, change):
    from concurrent.futures import Future, ThreadPoolExecutor
    from threading import Event
    from app import aws_reports
    from conftest import login
    with SessionLocal() as db:
        db.get(User, 2).role = "admin"
        db.commit()
    second = login("alice")
    entered, joined, release = Event(), Event(), Event()
    original = report_remote.monthly_cost
    def read(self, month, payer_id=None):
        entered.set()
        assert release.wait(5)
        return original(self, month, payer_id)
    class JoinedFuture(Future):
        def result(self, *args, **kw):
            joined.set()
            return super().result(*args, **kw)
    monkeypatch.setattr(report_remote, "monthly_cost", read)
    monkeypatch.setattr(aws_reports, "Future", JoinedFuture)
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(admin.get, "/api/admin/aws/1/cost")
        assert entered.wait(5)
        follower = pool.submit(second.get, "/api/admin/aws/1/cost")
        try:
            assert joined.wait(5)
            with SessionLocal() as db:
                if change == "role":
                    db.get(User, 2).role = "member"
                elif change == "session":
                    db.get(User, 2).session_version += 1
                else:
                    db.get(AwsAccount, 1).profile_arn += "changed"
                db.commit()
        finally:
            release.set()
        primary, following = first.result(), follower.result()
    assert len(report_remote.calls) == 1
    assert following.status_code in (401, 403, 409) and "123.4500" not in following.text
    if change == "configuration":
        assert primary.status_code == 409 and "123.4500" not in primary.text
    else:
        assert primary.status_code == 200
    second.close()
