"""Read-only group observations use synthetic AWS and never reconcile ledgers."""

from datetime import datetime, timedelta, timezone

import pytest
from botocore.exceptions import ClientError
from sqlalchemy import select

from app import aws, aws_reports, group_observations
from app.database import SessionLocal
from app.models import AwsAccount, Binding, ManagedGroup, PlanCounter, Subscription, User, now

real_membership_read = aws.AwsGateway.list_group_memberships


class ObservationGateway:
    change = None
    group = {"id": "remote-group", "name": "AWS renamed team"}
    members = [{"id": "m-owned", "user_id": "sso-owned"}, {"id": "m-foreign", "user_id": "sso-foreign"}]
    claims = []
    calls = []

    def __init__(self, account):
        self.account = account

    def get_group(self, group_id):
        type(self).calls.append(("group", group_id))
        if type(self).change:
            type(self).change()
        return type(self).group

    def list_group_memberships(self, group_id):
        type(self).calls.append(("members", group_id))
        return type(self).members

    def report_claims(self):
        type(self).calls.append(("claims", self.account.application_arn))
        return type(self).claims


def claim(**extra):
    return {"principal": {"group": "remote-group"}, "type": {"amazonQ": "KIRO_ENTERPRISE_PRO"},
            "applicationArn": "arn:aws:sso::123456789012:application/ssoins-1234567890123456/apl-1234567890123456",
            "createdBy": "123456789012", **extra}


def membership(**extra):
    return {"IdentityStoreId": "d-1234567890", "GroupId": "remote-group",
            "MembershipId": "m", "MemberId": {"UserId": "u"}, **extra}


@pytest.fixture
def remote(monkeypatch):
    monkeypatch.setattr(aws, "AwsGateway", ObservationGateway)
    monkeypatch.setattr(ObservationGateway, "change", None)
    monkeypatch.setattr(ObservationGateway, "group", {"id": "remote-group", "name": "AWS renamed team"})
    monkeypatch.setattr(ObservationGateway, "members", [{"id": "m-owned", "user_id": "sso-owned"}, {"id": "m-foreign", "user_id": "sso-foreign"}])
    monkeypatch.setattr(ObservationGateway, "claims", [claim()])
    monkeypatch.setattr(ObservationGateway, "calls", [])
    with SessionLocal() as db:
        db.add(ManagedGroup(id="group", owner_id=2, aws_account_id=1,
                            aws_scope="123456789012:d-1234567890", name="Immutable local name",
                            remote_id="remote-group", marker="marker", request_key="seed-group", payload_hash="hash", state="ready"))
        for rid, owner in [("owned", 2), ("foreign", 3)]:
            db.add(Subscription(id=rid, owner_id=owner, aws_account_id=1, request_key=rid,
                                username=rid, email=rid + "@example.com", sso_user_id="sso-" + rid,
                                portal_url="https://example.com", state="completed", reserved=False,
                                provision_only=True, subscription_status="not_subscribed"))
        db.commit()
    return ObservationGateway


def refresh(client):
    return client.post("/api/groups/group/aws-refresh")


def ledger():
    with SessionLocal() as db:
        return [[{column.name: getattr(row, column.name) for column in model.__table__.columns}
                 for row in db.scalars(select(model))]
                for model in (ManagedGroup, Subscription, PlanCounter)]


def test_current_directory_exact_claim_and_owned_mapping_are_read_only(alice, remote):
    remote.claims += [claim(createdBy="other"), claim(applicationArn="other"), claim(principal={"user": "remote-group"})]
    before = ledger()
    result = refresh(alice)
    assert result.status_code == 200, result.text
    assert result.headers["Cache-Control"] == "no-store"
    data = result.json()
    assert data["queried_at"] and data["group_id"] == "group"
    assert data["directory"]["exists"] is True
    assert data["directory"]["name"] == "AWS renamed team"
    assert data["directory"]["member_count"] == 2
    assert [item["record_id"] for item in data["directory"]["owned_members"]] == ["owned"]
    assert "foreign@example.com" not in result.text and "sso-foreign" not in result.text
    assert data["subscription"] == {"status": "Subscribed", "subscription_type": "KIRO_ENTERPRISE_PRO",
        "plan_label": "Kiro Pro", "pending_subscription_type": None, "pending_plan_label": None,
        "effective_at": None, "cancellation_expires_at": None, "access_active": True}
    assert ledger() == before


def test_query_time_uses_canonical_utc_for_the_rendered_observation(alice, remote, monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 11, 12, 34, 56, 123456, tzinfo=timezone.utc)

    monkeypatch.setattr(group_observations, "datetime", Clock)
    monkeypatch.setattr(aws_reports, "datetime", Clock)
    result = refresh(alice)
    assert result.status_code == 200, result.text
    assert result.json()["queried_at"] == "2026-10-11T12:34:56Z"


@pytest.mark.parametrize("pages", [
    [{}], [None], [{"GroupMemberships": None}], [{"GroupMemberships": {}}],
    [{"GroupMemberships": [{}]}], [{"GroupMemberships": ["invalid"]}],
    [{"GroupMemberships": [{"MembershipId": "m", "MemberId": {}}]}],
    [{"GroupMemberships": [{"MembershipId": None, "MemberId": {"UserId": "u"}}]}],
    [{"GroupMemberships": [{"MembershipId": "m", "MemberId": None}]}],
    [{"GroupMemberships": [membership(IdentityStoreId=None)]}],
    [{"GroupMemberships": [membership(IdentityStoreId="foreign")]}],
    [{"GroupMemberships": [membership(GroupId="foreign")]}],
    *[[{"GroupMemberships": [], "NextToken": token}] for token in [None, "", False, 1, []]],
    [{"GroupMemberships": [], "NextToken": "same"}, {"GroupMemberships": [], "NextToken": "same"}],
    [{"GroupMemberships": [membership()], "NextToken": "next"}, {}],
])
def test_malformed_real_membership_adapter_response_is_unavailable(alice, remote, monkeypatch, pages):
    class Identity:
        def list_group_memberships(self, **kwargs):
            return pages.pop(0)

    class Gateway(remote):
        list_group_memberships = real_membership_read

        def __init__(self, account):
            super().__init__(account)
            self.identity = Identity()

    monkeypatch.setattr(aws, "AwsGateway", Gateway)
    result = refresh(alice)
    assert result.status_code == 502, result.text
    assert result.headers["Cache-Control"] == "no-store"
    assert "member_count" not in result.text


@pytest.mark.parametrize("pages,count", [
    ([{"GroupMemberships": []}], 0),
    ([{"GroupMemberships": [membership(MembershipId="m1", MemberId={"UserId": "u1"})], "NextToken": "next"},
      {"GroupMemberships": [membership(MembershipId="m2", MemberId={"UserId": "u2"})]}], 2),
])
def test_real_membership_adapter_preserves_valid_empty_and_paginated_reads(alice, remote, monkeypatch, pages, count):
    class Identity:
        def list_group_memberships(self, **kwargs):
            return pages.pop(0)

    class Gateway(remote):
        list_group_memberships = real_membership_read

        def __init__(self, account):
            super().__init__(account)
            self.identity = Identity()

    monkeypatch.setattr(aws, "AwsGateway", Gateway)
    result = refresh(alice)
    assert result.status_code == 200, result.text
    assert result.json()["directory"]["member_count"] == count


@pytest.mark.parametrize("pending,label", [("KIRO_ENTERPRISE_FREE", "Kiro Free"), ("FUTURE_PLAN", "FUTURE_PLAN")])
def test_unknown_and_free_pending_plans_preserve_exact_values(alice, remote, pending, label):
    boundary = (now() + timedelta(days=2)).isoformat()
    remote.claims = [claim(newType={"amazonQ": pending}, expirationDate=boundary)]
    result = refresh(alice).json()["subscription"]
    assert result["status"] == "Subscribed"
    assert result["pending_subscription_type"] == pending and result["pending_plan_label"] == label
    assert result["effective_at"].startswith(boundary)
    assert result["cancellation_expires_at"] is None and result["access_active"] is True


@pytest.mark.parametrize("days,active", [(2, True), (-2, False)])
def test_canceled_claim_retains_access_until_expiration(alice, remote, days, active):
    boundary = (now() + timedelta(days=days)).isoformat()
    remote.claims = [claim(expirationDate=boundary)]
    result = refresh(alice).json()["subscription"]
    assert result["status"] == "Canceled" and result["access_active"] is active
    assert result["cancellation_expires_at"].startswith(boundary)
    assert result["pending_plan_label"] is None and result["effective_at"] is None


def test_empty_subscribed_group_and_missing_directory_are_distinct(alice, remote):
    remote.members = []
    result = refresh(alice).json()
    assert result["directory"]["member_count"] == 0 and result["subscription"]["status"] == "Subscribed"
    remote.group = None
    result = refresh(alice).json()
    assert result["directory"] == {"exists": False, "name": None, "member_count": None, "owned_members": []}
    assert result["subscription"]["status"] == "Subscribed"
    assert [call[0] for call in remote.calls].count("members") == 1


def test_no_claim_is_explicitly_unsubscribed(alice, remote):
    remote.claims = []
    result = refresh(alice).json()["subscription"]
    assert result["status"] == "Not subscribed" and result["plan_label"] is None
    assert result["access_active"] is False


@pytest.mark.parametrize("broken", ["read", "duplicate", "missing_scope", "bad_member"])
def test_failed_or_incomplete_reads_are_unavailable_never_local_fallback(alice, remote, monkeypatch, broken):
    if broken == "read":
        def denied(*_):
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "secret remote detail"}}, "ListGroupMemberships")
        monkeypatch.setattr(remote, "list_group_memberships", denied)
    elif broken == "duplicate":
        remote.claims = [claim(), claim()]
    elif broken == "missing_scope":
        remote.claims = [claim(createdBy=None)]
    else:
        remote.members = [{"id": "bad", "user_id": None}]
    result = refresh(alice)
    assert result.status_code == 502, result.text
    assert result.headers["Cache-Control"] == "no-store"
    assert "member_count" not in result.text and "Immutable local name" not in result.text
    assert "secret remote detail" not in result.text


@pytest.mark.parametrize("field", ["binding", "role", "session", "account", "group_owner", "group_remote", "group_scope", "mapping"])
def test_fences_change_during_reads_and_release_database_writer(alice, remote, field):
    def change():
        # This independent write can commit only if the POST admission writer was released.
        with SessionLocal() as db:
            if field == "binding":
                db.delete(db.get(Binding, (2, 1)))
            elif field == "role":
                db.get(User, 2).role = "admin"
            elif field == "session":
                db.get(User, 2).session_version += 1
            elif field == "account":
                db.get(AwsAccount, 1).application_arn = "changed"
            elif field == "group_owner":
                db.get(ManagedGroup, "group").owner_id = 3
            elif field == "group_remote":
                db.get(ManagedGroup, "group").remote_id = "changed"
            elif field == "group_scope":
                db.get(ManagedGroup, "group").aws_scope = "different-directory"
            else:
                db.get(Subscription, "owned").sso_user_id = "changed"
            db.commit()
    remote.change = change
    result = refresh(alice)
    assert result.status_code in (401, 403, 404, 409), result.text
    assert "AWS renamed team" not in result.text and "owned@example.com" not in result.text


def test_unowned_group_and_wrong_directory_do_not_read_aws(bob, alice, remote):
    assert refresh(bob).status_code == 404 and remote.calls == []
    with SessionLocal() as db:
        db.get(ManagedGroup, "group").aws_scope = "different-directory"
        db.commit()
    assert refresh(alice).status_code == 409 and remote.calls == []
