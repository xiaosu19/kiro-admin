from types import SimpleNamespace

import pytest

from app import aws
from app.database import SessionLocal
from app.models import AwsAccount


def gateway():
    with SessionLocal() as db:
        return aws.AwsGateway(db.get(AwsAccount, 1))


def test_subscription_report_protocol_identity_region_and_complete_pages(monkeypatch):
    g = gateway()
    g.account.region = "eu-west-1"
    g.account.subscription_region = "eu-central-1"
    calls = []

    def call(region, host, service, target, body):
        calls.append(body)
        assert (region, host, service, target) == (
            "eu-west-1", "service.user-subscriptions.eu-west-1.amazonaws.com",
            "user-subscriptions", "AWSZornControlPlaneService.ListUserSubscriptions",
        )
        assert body == {"instanceArn": g.account.instance_arn,
                        "subscriptionRegion": "eu-central-1", "maxResults": 1000,
                        **({"nextToken": "second"} if len(calls) == 2 else {})}
        return ({"subscriptions": [{"principal": {"user": str(len(calls))}}],
                 **({"nextToken": "second"} if len(calls) == 1 else {})}, "")

    monkeypatch.setattr(g, "_call", call)
    assert g.report_subscriptions() == [{"principal": {"user": "1"}}, {"principal": {"user": "2"}}]


@pytest.mark.parametrize("method,key,token_key", [
    ("report_subscriptions", "subscriptions", "nextToken"),
    ("report_claims", "claims", "nextToken"),
    ("report_users", "Users", "NextToken"),
    ("report_groups", "Groups", "NextToken"),
])
@pytest.mark.parametrize("bad", ["missing", "not_list", "bad_row", "bad_token", "repeat", "error"])
def test_report_pagination_rejects_incomplete_data(monkeypatch, method, key, token_key, bad):
    g = gateway()
    calls = []

    def page(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            return {key: [], token_key: "next"}
        if bad == "error":
            raise aws.AwsFailure("second page failed")
        return {
            "missing": {}, "not_list": {key: {}}, "bad_row": {key: [None]},
            "bad_token": {key: [], token_key: 42}, "repeat": {key: [], token_key: "next"},
        }[bad]

    monkeypatch.setattr(g, "_call", lambda *args: (page(), ""))
    monkeypatch.setattr(g, "_claims", page)
    g.identity = SimpleNamespace(list_users=page, list_groups=page)
    with pytest.raises(aws.AwsFailure):
        getattr(g, method)()
    assert len(calls) == 2


@pytest.mark.parametrize("method,key", [("report_users", "Users"), ("report_groups", "Groups")])
def test_directory_report_reads_all_pages_through_existing_identity_client(method, key):
    g = gateway()
    calls = []

    def page(**kw):
        calls.append(kw)
        assert kw == {"IdentityStoreId": g.account.identity_store_id, "MaxResults": 100,
                      **({"NextToken": "next"} if len(calls) == 2 else {})}
        return {key: [{"UserId" if key == "Users" else "GroupId": str(len(calls))}],
                **({"NextToken": "next"} if len(calls) == 1 else {})}

    g.identity = SimpleNamespace(list_users=page, list_groups=page)
    assert len(getattr(g, method)()) == 2










@pytest.mark.parametrize("method,key,token_key", [
    ("report_subscriptions", "subscriptions", "nextToken"),
    ("report_claims", "claims", "nextToken"),
    ("report_users", "Users", "NextToken"),
    ("report_groups", "Groups", "NextToken"),
])
def test_report_pagination_has_finite_page_and_row_limits(monkeypatch, method, key, token_key):
    from app import aws_report_gateway
    g = gateway()
    calls = []
    def page(*a, **kw):
        calls.append(1)
        return {key: [], token_key: str(len(calls))}
    monkeypatch.setattr(aws_report_gateway, "MAX_PAGES", 2)
    monkeypatch.setattr(g, "_call", lambda *a: (page(), ""))
    monkeypatch.setattr(g, "_claims", page)
    g.identity = SimpleNamespace(list_users=page, list_groups=page)
    with pytest.raises(aws.AwsFailure):
        getattr(g, method)()
    assert len(calls) == 2
    monkeypatch.setattr(aws_report_gateway, "MAX_ROWS", 1)
    monkeypatch.setattr(g, "_call", lambda *a: ({key: [{}, {}]}, ""))
    monkeypatch.setattr(g, "_claims", lambda *a: {key: [{}, {}]})
    g.identity = SimpleNamespace(list_users=lambda **kw: {key: [{}, {}]}, list_groups=lambda **kw: {key: [{}, {}]})
    with pytest.raises(aws.AwsFailure):
        getattr(g, method)()


def test_real_claims_reader_malformed_response_is_an_actionable_failure(monkeypatch):
    g = gateway()
    monkeypatch.setattr(g, "_call", lambda *a: (None, ""))
    with pytest.raises(aws.AwsFailure):
        g.report_claims()
