import concurrent.futures
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.aws import AwsFailure
from app.database import SessionLocal
from app.models import (
    AwsAccount,
    Batch,
    Binding,
    GroupJob,
    ManagedGroup,
    SchemaVersion,
    StopSchedule,
    Subscription,
    now,
)
from app.worker import run_one
from conftest import login
from test_workflows import Gateway, count


class GroupGateway(Gateway):
    groups = {}
    memberships = {}
    group_writes = 0
    member_writes = 0
    user_writes = 0
    password_writes = 0
    lose_group = False
    lose_member = False

    def get_group_id(self, name):
        return next((k for k, g in self.groups.items() if g["name"] == name), None)

    def get_group(self, gid):
        return self.groups.get(gid)

    def list_groups(self):
        return list(self.groups.values())

    def create_group(self, name, marker):
        GroupGateway.group_writes += 1
        gid = str(uuid.uuid4())
        self.groups[gid] = {"id": gid, "name": name, "description": marker}
        if self.lose_group:
            raise AwsFailure("unknown group create", uncertain=True)
        return gid

    def update_group(self, gid, name):
        self.groups[gid]["name"] = name

    def delete_group(self, gid):
        self.groups.pop(gid, None)

    def list_group_memberships(self, gid):
        return [
            {"id": value, "user_id": uid}
            for (group, uid), value in self.memberships.items()
            if group == gid
        ]

    def get_group_membership(self, gid, uid):
        return self.memberships.get((gid, uid))

    def create_group_membership(self, gid, uid):
        GroupGateway.member_writes += 1
        mid = str(uuid.uuid4())
        self.memberships[(gid, uid)] = mid
        if self.lose_member:
            raise AwsFailure("unknown membership", uncertain=True)
        return mid

    def delete_group_membership(self, mid):
        for pair, value in list(self.memberships.items()):
            if value == mid:
                del self.memberships[pair]

    def create_user(self, r):
        GroupGateway.user_writes += 1
        return super().create_user(r)

    def password(self, r):
        GroupGateway.password_writes += 1
        return super().password(r)


@pytest.fixture(autouse=True)
def fake_groups():
    GroupGateway.groups, GroupGateway.memberships = {}, {}
    GroupGateway.group_writes = GroupGateway.member_writes = 0
    GroupGateway.user_writes = GroupGateway.password_writes = 0
    GroupGateway.lose_group = GroupGateway.lose_member = False
    Gateway.mode, Gateway.calls = "ok", 0


def create_group(client, name="alice-team", **kwargs):
    return client.post(
        "/api/groups",
        json={
            "aws_account_id": 1,
            "name": name,
            "request_key": str(uuid.uuid4()),
            **kwargs,
        },
    )


def run_group():
    from app.group_jobs import run_group_job

    return run_group_job(GroupGateway)


def ready_group(client, **kwargs):
    response = create_group(client, **kwargs)
    assert response.status_code == 202, response.text
    assert run_group()
    group = client.get(f"/api/groups/{response.json()['id']}").json()
    assert group["state"] == "ready", group
    return group


def operation(client, gid, kind, **kwargs):
    return client.post(
        f"/api/groups/{gid}/jobs",
        json={
            "kind": kind,
            "request_key": str(uuid.uuid4()),
            **kwargs,
        },
    )


def test_group_ownership(alice, bob):
    response = alice.post(
        "/api/groups",
        json={
            "aws_account_id": 1,
            "name": "alice-team",
            "request_key": "group-create-test-0001",
        },
    )
    assert response.status_code == 202, response.text
    assert bob.get(f"/api/groups/{response.json()['id']}").status_code == 404


def test_create_recovers_exact_marker_after_unknown_result(alice):
    GroupGateway.lose_group = True
    group = create_group(alice).json()
    assert run_group()
    result = alice.get(f"/api/groups/{group['id']}").json()
    assert result["state"] == "needs_review"
    assert alice.post(f"/api/groups/{group['id']}/retry").status_code == 202
    assert run_group()
    result = alice.get(f"/api/groups/{group['id']}").json()
    assert result["state"] == "ready" and result["remote_id"]
    assert GroupGateway.group_writes == 1


def test_legacy_member_recovery_has_no_batch_and_rechecks_the_same_remote_write(alice):
    from test_batches import complete_sso

    group = ready_group(alice)
    _, ids = complete_sso(alice, 1)
    admitted = operation(alice, group["id"], "attach", record_id=ids[0], expected_revision=1)
    assert admitted.status_code == 202, admitted.text
    GroupGateway.lose_member = True
    assert run_group()
    current = alice.get(f"/api/groups/{group['id']}").json()
    jobs = alice.get(f"/api/groups/{group['id']}/jobs").json()
    job = next(item for item in jobs if item["id"] == current["active_job_id"])
    assert job["record_id"] == ids[0] and job["state"] == "needs_review"
    assert job["member_batch_id"] is None
    assert alice.get(f"/api/groups/{group['id']}/member-batches").json() == []
    retry = alice.post(f"/api/groups/{group['id']}/retry")
    assert retry.status_code == 202 and retry.json()["id"] == job["id"]
    assert run_group()
    assert alice.get(f"/api/groups/{group['id']}").json()["state"] == "ready"
    assert GroupGateway.member_writes == 1


def test_create_never_adopts_foreign_same_name(alice):
    GroupGateway.groups["foreign"] = {
        "id": "foreign",
        "name": "alice-team",
        "description": "unmanaged",
    }
    group = create_group(alice).json()
    assert run_group()
    result = alice.get(f"/api/groups/{group['id']}").json()
    assert result["state"] == "failed" and result["remote_id"] is None
    assert GroupGateway.group_writes == 0


def test_group_request_idempotency_csrf_and_designated_owner(alice, bob, admin):
    key = str(uuid.uuid4())
    first = create_group(alice, request_key=key)
    assert create_group(alice, request_key=key).json()["id"] == first.json()["id"]
    assert create_group(alice, name="different", request_key=key).status_code == 409
    assert create_group(alice, owner_id=3).status_code == 403
    group = create_group(admin, name="bob-team", owner_id=3).json()
    assert bob.get(f"/api/groups/{group['id']}").status_code == 200
    assert alice.get(f"/api/groups/{group['id']}").status_code == 404
    assert len(admin.get("/api/groups").json()) == 2
    del alice.headers["X-CSRF-Token"]
    assert create_group(alice, name="csrf").status_code == 403


def test_link_enumeration_is_admin_only_and_aliases_cannot_split_owners(
    alice, admin, monkeypatch
):
    from app import groups

    monkeypatch.setattr(groups, "AwsGateway", GroupGateway)
    GroupGateway.groups["existing"] = {
        "id": "existing",
        "name": "real-group",
        "description": "unmanaged",
    }
    assert alice.get("/api/admin/aws/1/groups").status_code == 403
    assert admin.get("/api/admin/aws/1/groups").json()[0]["id"] == "existing"
    response = admin.post(
        "/api/groups/link",
        json={
            "aws_account_id": 1,
            "remote_id": "existing",
            "owner_id": 2,
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 202, response.text
    assert run_group()
    group = alice.get(f"/api/groups/{response.json()['id']}").json()
    assert group["state"] == "ready" and group["members"] == []
    with SessionLocal() as db:
        account = db.get(AwsAccount, 1)
        fields = {
            c.name: getattr(account, c.name)
            for c in AwsAccount.__table__.columns
            if c.name not in ("id", "name")
        }
        db.add(AwsAccount(id=2, name="alias", **fields))
        db.commit()
        db.add(Binding(user_id=3, aws_account_id=2))
        db.commit()
    assert (
        admin.post(
            "/api/groups/link",
            json={
                "aws_account_id": 2,
                "remote_id": "existing",
                "owner_id": 3,
                "request_key": str(uuid.uuid4()),
            },
        ).status_code
        == 409
    )
    assert admin.get("/api/admin/aws/2/groups").json() == []


def test_group_rename_delete_empty_and_remote_member_guard(alice):
    group = ready_group(alice)
    gid, remote = group["id"], group["remote_id"]
    assert (
        operation(alice, gid, "rename", name="renamed", expected_revision=1).status_code
        == 202
    )
    assert run_group()
    assert GroupGateway.groups[remote]["name"] == "renamed"
    GroupGateway.memberships[(remote, "foreign-user")] = "foreign-member"
    assert operation(alice, gid, "delete", expected_revision=2).status_code == 202
    assert run_group()
    assert remote in GroupGateway.groups
    GroupGateway.memberships.clear()
    assert alice.post(f"/api/groups/{gid}/retry").status_code == 202
    assert run_group()
    assert remote not in GroupGateway.groups
    assert alice.get(f"/api/groups/{gid}").json()["deleted_at"]


def test_concurrent_group_workers_only_one_remote_create(alice):
    create_group(alice)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda _: run_group(), range(2)))
    assert GroupGateway.group_writes == 1


def group_batch(client, gid, n=1, kind="sso", **kwargs):
    return client.post(
        "/api/batches/create",
        json={
            "kind": kind,
            "aws_account_id": 1,
            "group_id": gid,
            "plan_id": 1 if kind == "subscribed" else None,
            "items": [{"username": f"member{i}"} for i in range(n)],
            "request_key": str(uuid.uuid4()),
            **kwargs,
        },
    )


def test_group_membership_unknown_reuses_sso_and_password(alice):
    group = ready_group(alice)
    response = group_batch(alice, group["id"])
    assert response.status_code == 202, response.text
    rid = response.json()["items"][0]["id"]
    GroupGateway.lose_member = True
    assert run_one(GroupGateway)
    before = alice.get(f"/api/subscriptions/{rid}").json()
    assert before["state"] == "needs_review"
    assert before["sso_user_id"] and before["has_password"]
    assert alice.post(f"/api/subscriptions/{rid}/retry").status_code == 202
    assert run_one(GroupGateway)
    after = alice.get(f"/api/subscriptions/{rid}").json()
    assert after["state"] == "completed" and after["group_membership_id"]
    assert after["sso_user_id"] == before["sso_user_id"]
    assert after["password_generated_at"] == before["password_generated_at"]
    assert (
        GroupGateway.user_writes,
        GroupGateway.password_writes,
        GroupGateway.member_writes,
    ) == (1, 1, 1)
    assert count() == (0, 0, 0, 1)


def test_creating_group_wait_does_not_starve_unrelated_sso(alice):
    from test_batches import create_batch

    group = create_group(alice).json()
    grouped = group_batch(alice, group["id"])
    assert grouped.status_code == 202, grouped.text
    other = create_batch(alice, 1).json()["items"][0]["id"]
    assert run_one(GroupGateway)
    assert alice.get(f"/api/subscriptions/{other}").json()["state"] == "completed"
    assert not run_one(GroupGateway)
    assert run_group()
    assert run_one(GroupGateway)
    detail = alice.get(f"/api/groups/{group['id']}").json()
    assert detail["counts"]["eligible"] == 1


def test_group_scope_batch_and_durable_attach_detach(alice, bob):
    from test_batches import complete_sso

    group = ready_group(alice)
    gid, remote = group["id"], group["remote_id"]
    assert group_batch(bob, gid).status_code == 404
    _, ids = complete_sso(alice, 1)
    rid = ids[0]
    response = operation(alice, gid, "attach", record_id=rid, expected_revision=1)
    assert response.status_code == 202, response.text
    assert (
        alice.post(
            f"/api/subscriptions/{rid}/operations",
            json={
                "kind": "sync_status",
                "request_key": str(uuid.uuid4()),
            },
        ).status_code
        == 409
    )
    assert (
        alice.get(f"/api/subscriptions/{rid}").json()["operation"]["kind"] == "attach"
    )
    GroupGateway.lose_member = True
    assert run_group()
    assert operation(alice, gid, "delete", expected_revision=1).status_code == 409
    assert alice.post(f"/api/groups/{gid}/retry").status_code == 202
    assert run_group()
    member = alice.get(f"/api/groups/{gid}").json()["members"][0]
    GroupGateway.memberships[("unrelated", member["sso_user_id"])] = "unrelated-member"
    assert operation(alice, gid, "delete", expected_revision=1).status_code == 409
    assert (
        operation(alice, gid, "detach", record_id=rid, expected_revision=1).status_code
        == 202
    )
    assert run_group()
    assert alice.get(f"/api/subscriptions/{rid}").json()["group_id"] is None
    assert ("unrelated", member["sso_user_id"]) in GroupGateway.memberships
    assert operation(alice, gid, "delete", expected_revision=1).status_code == 202
    assert run_group()
    assert remote not in GroupGateway.groups


def test_group_selection_freezes_ids_and_uses_owner_quota(alice, bob, admin):
    group = ready_group(alice)
    gid = group["id"]
    batch = group_batch(alice, gid, n=2).json()
    for _ in range(2):
        run_one(GroupGateway)
    preview = alice.get(f"/api/groups/{gid}/subscription-preview").json()
    ids = [r["id"] for r in batch["items"]]
    assert set(preview["eligible_ids"]) == set(ids)
    assert bob.get(f"/api/groups/{gid}/subscription-preview").status_code == 404
    body = {
        "group_id": gid,
        "record_ids": ids,
        "plan_id": 1,
        "request_key": str(uuid.uuid4()),
    }
    response = admin.post("/api/batches/subscribe", json=body)
    assert response.status_code == 202, response.text
    assert (
        admin.post("/api/batches/subscribe", json=body).json()["id"]
        == response.json()["id"]
    )
    assert count() == (0, 2, 0, 1)
    extra = group_batch(alice, gid).json()["items"][0]["id"]
    for _ in range(3):
        run_one(GroupGateway)
    assert count() == (2, 0, 2, 1)
    assert alice.get(f"/api/subscriptions/{extra}").json()["plan_id"] is None
    assert len(admin.get(f"/api/batches/{response.json()['id']}").json()["items"]) == 2
    assert (
        admin.post(
            "/api/batches/subscribe",
            json={**body, "record_ids": [extra], "request_key": str(uuid.uuid4())},
        ).status_code
        == 409
    )
    assert alice.get(f"/api/groups/{gid}/subscription-preview").json()[
        "eligible_ids"
    ] == [extra]
    assert (
        len(alice.get(f"/api/groups/{gid}/subscription-preview").json()["skipped"]) == 2
    )


def test_group_gateway_uses_identitystore_protocol():
    from botocore.stub import Stubber
    from test_aws_adapter import gateway

    g = gateway()
    store = g.account.identity_store_id
    gid = "12345678-1234-1234-1234-123456789012"
    uid = "22345678-1234-1234-1234-123456789012"
    mid = "32345678-1234-1234-1234-123456789012"
    with Stubber(g.identity) as stub:
        stub.add_response(
            "list_groups",
            {
                "Groups": [
                    {
                        "GroupId": gid,
                        "DisplayName": "team",
                        "Description": "marker",
                        "IdentityStoreId": store,
                    }
                ],
                "NextToken": "next",
            },
            {"IdentityStoreId": store},
        )
        stub.add_response(
            "list_groups",
            {"Groups": []},
            {"IdentityStoreId": store, "NextToken": "next"},
        )
        stub.add_response(
            "get_group_id",
            {"GroupId": gid, "IdentityStoreId": store},
            {
                "IdentityStoreId": store,
                "AlternateIdentifier": {
                    "UniqueAttribute": {
                        "AttributePath": "displayName",
                        "AttributeValue": "team",
                    }
                },
            },
        )
        stub.add_response(
            "describe_group",
            {
                "GroupId": gid,
                "IdentityStoreId": store,
                "DisplayName": "team",
                "Description": "marker",
            },
            {"IdentityStoreId": store, "GroupId": gid},
        )
        stub.add_response(
            "create_group",
            {"GroupId": gid, "IdentityStoreId": store},
            {"IdentityStoreId": store, "DisplayName": "team", "Description": "marker"},
        )
        stub.add_response(
            "update_group",
            {},
            {
                "IdentityStoreId": store,
                "GroupId": gid,
                "Operations": [
                    {"AttributePath": "displayName", "AttributeValue": "new"}
                ],
            },
        )
        stub.add_response(
            "list_group_memberships",
            {
                "GroupMemberships": [
                    {
                        "MembershipId": mid,
                        "GroupId": gid,
                        "IdentityStoreId": store,
                        "MemberId": {"UserId": uid},
                    }
                ]
            },
            {"IdentityStoreId": store, "GroupId": gid},
        )
        stub.add_response(
            "get_group_membership_id",
            {"MembershipId": mid, "IdentityStoreId": store},
            {"IdentityStoreId": store, "GroupId": gid, "MemberId": {"UserId": uid}},
        )
        stub.add_response(
            "create_group_membership",
            {"MembershipId": mid, "IdentityStoreId": store},
            {"IdentityStoreId": store, "GroupId": gid, "MemberId": {"UserId": uid}},
        )
        stub.add_response(
            "delete_group_membership",
            {},
            {"IdentityStoreId": store, "MembershipId": mid},
        )
        stub.add_response(
            "delete_group", {}, {"IdentityStoreId": store, "GroupId": gid}
        )
        assert g.list_groups() == [{"id": gid, "name": "team", "description": "marker"}]
        assert g.get_group_id("team") == gid
        assert g.get_group(gid)["description"] == "marker"
        assert g.create_group("team", "marker") == gid
        g.update_group(gid, "new")
        assert g.list_group_memberships(gid) == [{"id": mid, "user_id": uid}]
        assert g.get_group_membership(gid, uid) == mid
        assert g.create_group_membership(gid, uid) == mid
        g.delete_group_membership(mid)
        g.delete_group(gid)
        stub.assert_no_pending_responses()


def policy(client, gid, body=None, revision=0, overwrite=False, preview=False):
    data = {
        "policy": body or {"mode": "days", "days": 7},
        "expected_revision": revision,
        "overwrite_individual": overwrite,
    }
    path = f"/api/groups/{gid}/policy"
    return (
        client.post(path + "/preview", json=data)
        if preview
        else client.put(path, json=data)
    )


def detail(client, rid):
    return client.get(f"/api/subscriptions/{rid}").json()


def test_group_policy_new_members_inherit_and_subscription_anchors_days(alice):
    group = ready_group(alice)
    gid = group["id"]
    result = policy(alice, gid)
    assert result.status_code == 200, result.text
    batch = group_batch(alice, gid).json()
    rid = batch["items"][0]["id"]
    assert run_one(GroupGateway)
    first = detail(alice, rid)
    schedule = first["stop_schedule"]
    assert first["plan_id"] is None and count() == (0, 0, 0, 1)
    assert schedule["source_group_id"] == gid and schedule["source_group_revision"] == 1
    assert schedule["mode"] == "days" and schedule["stop_at"] is None
    response = alice.post(
        "/api/batches/subscribe",
        json={
            "record_ids": [rid],
            "group_id": gid,
            "plan_id": 1,
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 202, response.text
    assert run_one(GroupGateway)
    after = detail(alice, rid)
    assert datetime.fromisoformat(
        after["stop_schedule"]["stop_at"]
    ) == datetime.fromisoformat(after["subscribed_at"]) + timedelta(days=7)


def test_individual_none_override_reset_and_overwrite(alice):
    gid = ready_group(alice)["id"]
    rid = group_batch(alice, gid).json()["items"][0]["id"]
    run_one(GroupGateway)
    # Explicit none is retained even when the group's default is already none.
    schedule = detail(alice, rid)["stop_schedule"]
    response = alice.put(
        f"/api/subscriptions/{rid}/stop-schedule",
        json={
            "policy": {"mode": "none"},
            "expected_revision": schedule["revision"] if schedule else 0,
        },
    )
    assert response.status_code == 200 and response.json(), response.text
    assert response.json()["individual_override"]
    assert policy(alice, gid).json()["skipped_count"] == 1
    assert detail(alice, rid)["stop_schedule"]["mode"] == "none"
    schedule = detail(alice, rid)["stop_schedule"]
    reset = alice.post(
        f"/api/subscriptions/{rid}/stop-schedule/reset-to-group",
        json={
            "expected_revision": schedule["revision"],
            "expected_group_revision": 1,
        },
    )
    assert reset.status_code == 200, reset.text
    assert reset.json()["mode"] == "days" and reset.json()["source_group_id"] == gid
    assert not reset.json()["individual_override"]
    individual = alice.put(
        f"/api/subscriptions/{rid}/stop-schedule",
        json={
            "policy": {"mode": "days", "days": 20},
            "expected_revision": reset.json()["revision"],
        },
    )
    assert individual.status_code == 200, individual.text
    assert (
        policy(alice, gid, {"mode": "days", "days": 30}, 1, overwrite=True).json()[
            "affected_count"
        ]
        == 1
    )
    assert detail(alice, rid)["stop_schedule"]["days"] == 30


def test_policy_atomic_conflicts_and_historical_records_unchanged(alice):
    gid = ready_group(alice)["id"]
    ids = [i["id"] for i in group_batch(alice, gid, 2).json()["items"]]
    run_one(GroupGateway)
    response = policy(alice, gid)
    assert response.status_code == 409, response.text
    assert alice.get(f"/api/groups/{gid}").json()["policy"]["revision"] == 0
    assert detail(alice, ids[0])["stop_schedule"]["mode"] == "none"
    assert policy(alice, gid, preview=True).json()["conflict_count"] == 1
    run_one(GroupGateway)
    with SessionLocal() as db:
        db.get(Subscription, ids[1]).cancelled_at = now()
        db.get(Subscription, ids[1]).subscription_status = "cancelled"
        old_revision = db.get(StopSchedule, ids[1]).revision
        db.commit()
    result = policy(alice, gid)
    assert result.status_code == 200 and result.json()["affected_count"] == 1
    assert result.json()["skipped_count"] == 1
    assert detail(alice, ids[1])["stop_schedule"]["revision"] == old_revision


def test_policy_extension_disable_invalidate_deadlines_and_original_time(
    alice, monkeypatch
):
    from app.schedules import enqueue_due

    gid = ready_group(alice)["id"]
    policy(alice, gid)
    rid = group_batch(alice, gid, kind="subscribed").json()["items"][0]["id"]
    run_one(GroupGateway)
    original = detail(alice, rid)
    first_due = datetime.fromisoformat(original["stop_schedule"]["stop_at"])
    result = policy(alice, gid, {"mode": "days", "days": 30}, 1)
    assert result.status_code == 200, result.text
    new = detail(alice, rid)
    assert datetime.fromisoformat(
        new["stop_schedule"]["stop_at"]
    ) == datetime.fromisoformat(original["subscribed_at"]) + timedelta(days=30)
    monkeypatch.setattr("app.schedules.now", lambda: first_due + timedelta(seconds=1))
    assert enqueue_due() == 0
    assert policy(alice, gid, {"mode": "none"}, 2).status_code == 200
    monkeypatch.setattr("app.schedules.now", lambda: first_due + timedelta(days=90))
    assert enqueue_due() == 0
    assert detail(alice, rid)["subscribed_at"] == original["subscribed_at"]
    assert count() == (1, 0, 1, 1)


def test_expired_group_deadline_allows_sso_but_blocks_paid_admission(alice):
    gid = ready_group(alice)["id"]
    assert (
        policy(
            alice,
            gid,
            {
                "mode": "at",
                "stop_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            },
        ).status_code
        == 200
    )
    with SessionLocal() as db:
        db.get(ManagedGroup, gid).policy_stop_at = now() - timedelta(seconds=1)
        db.commit()
    response = group_batch(alice, gid)
    assert response.status_code == 202, response.text
    rid = response.json()["items"][0]["id"]
    assert run_one(GroupGateway)
    assert detail(alice, rid)["state"] == "completed"
    assert (
        alice.get(f"/api/groups/{gid}/subscription-preview").json()["skipped"][0][
            "reason"
        ]
        == "group_deadline_expired"
    )
    assert alice.get(f"/api/groups/{gid}").json()["counts"]["eligible"] == 0
    assert (
        alice.post(
            "/api/batches/subscribe",
            json={
                "record_ids": [rid],
                "group_id": gid,
                "plan_id": 1,
                "request_key": str(uuid.uuid4()),
            },
        ).status_code
        == 422
    )
    assert group_batch(alice, gid, kind="subscribed").status_code == 422
    assert count() == (0, 0, 0, 1)


def test_group_policy_audit_and_job_privacy(alice, bob, admin):
    gid = ready_group(alice)["id"]
    assert policy(bob, gid).status_code == 404
    assert policy(admin, gid).status_code == 200
    assert (
        operation(
            admin, gid, "rename", name="admin-rename", expected_revision=1
        ).status_code
        == 202
    )
    assert run_group()
    assert all(
        j["kind"] != "rename" for j in alice.get(f"/api/groups/{gid}/jobs").json()
    )
    assert all(
        e["actor_name"] != "admin" for e in alice.get("/api/audit").json()["items"]
    )


def test_groups_block_resource_reassignment_deletion_and_pending_user_changes(
    alice, admin, monkeypatch
):
    from test_resources import aws_body, remove

    monkeypatch.setattr("app.main.aws.AwsGateway", GroupGateway)
    group = create_group(alice).json()
    assert remove(admin, "aws", "测试 AWS").status_code == 409
    assert (
        admin.put(
            "/api/admin/aws/1", json=aws_body(admin, identity_store_id="d-9876543210")
        ).status_code
        == 409
    )
    assert admin.patch("/api/admin/users/2", json={"role": "admin"}).status_code == 409
    assert admin.patch("/api/admin/users/2", json={"active": False}).status_code == 200
    assert admin.delete("/api/admin/users/2").status_code == 409
    assert admin.patch("/api/admin/users/2", json={"active": True}).status_code == 200
    assert run_group()
    assert remove(admin, "aws", "测试 AWS").status_code == 409
    assert (
        operation(admin, group["id"], "delete", expected_revision=1).status_code == 202
    )
    assert run_group()
    assert remove(admin, "aws", "测试 AWS").status_code == 200


def test_single_creation_and_sso_filter_export_group_scope(alice, bob):
    gid = ready_group(alice)["id"]
    body = {
        "aws_account_id": 1,
        "group_id": gid,
        "plan_id": 1,
        "username": "single",
        "email": "single@example.com",
        "request_key": str(uuid.uuid4()),
    }
    result = alice.post("/api/subscriptions", json=body)
    assert result.status_code == 202 and result.json().get("group_id") == gid, (
        result.text
    )
    assert run_one(GroupGateway)
    assert (
        alice.post("/api/subscriptions", json=body).json()["id"] == result.json()["id"]
    )
    assert alice.get(f"/api/sso-users?group_id={gid}").json()["total"] == 1
    assert bob.get(f"/api/sso-users?group_id={gid}").status_code == 404
    assert (
        alice.post("/api/sso-users/export", json={"group_id": gid}).status_code == 200
    )
    assert bob.post("/api/sso-users/export", json={"group_id": gid}).status_code == 404


def test_schema_seven_upgrade_is_additive_with_null_group_links(alice):
    from app.database import engine
    from app.init_db import initialize
    from app.migrations import VERSION
    from sqlalchemy import select, text
    from sqlalchemy.schema import CreateTable, CreateIndex
    from test_batches import complete_sso

    _, ids = complete_sso(alice, 1)
    rid = ids[0]
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        before = {
            c.name: getattr(record, c.name)
            for c in Subscription.__table__.columns
            if not c.name.startswith("group_")
        }
        db.add(StopSchedule(record_id=rid, actor_id=2, mode="none", state="disabled"))
        db.commit()
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys=OFF")
        conn.commit()
        for model, excluded in (
            (Subscription, {"group_id", "group_membership_id", "request_payload_hash"}),
            (Batch, {"group_id"}),
            (
                StopSchedule,
                {"source_group_id", "source_group_revision", "individual_override"},
            ),
        ):
            table = model.__table__
            ddl = str(CreateTable(table).compile(dialect=engine.dialect))
            ddl = "\n".join(
                line
                for line in ddl.splitlines()
                if not any(
                    line.lstrip().startswith(
                        (column + " ", "FOREIGN KEY(" + column + ")")
                    )
                    for column in excluded
                )
            )
            import re

            ddl = re.sub(r",\s*\)", "\n)", ddl)
            ddl = ddl.replace(
                "CREATE TABLE " + table.name, "CREATE TABLE legacy_" + table.name, 1
            )
            names = ",".join(
                '"' + c.name + '"' for c in table.columns if c.name not in excluded
            )
            conn.exec_driver_sql(ddl)
            conn.exec_driver_sql(
                f"INSERT INTO legacy_{table.name} ({names}) SELECT {names} FROM {table.name}"
            )
            conn.exec_driver_sql(f"DROP TABLE {table.name}")
            conn.exec_driver_sql(
                f"ALTER TABLE legacy_{table.name} RENAME TO {table.name}"
            )
            for index in table.indexes:
                if not any(c.name in excluded for c in index.columns):
                    conn.execute(CreateIndex(index))
        conn.exec_driver_sql("DROP TABLE console_group_jobs")
        conn.exec_driver_sql("DROP TABLE console_groups")
        conn.execute(text("INSERT INTO console_schema_version (version) VALUES (7)"))
        conn.commit()
        conn.exec_driver_sql("PRAGMA foreign_keys=ON")
    initialize()
    initialize()
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        assert {k: getattr(record, k) for k in before} == before
        assert record.group_id is None and record.group_membership_id is None
        schedule = db.get(StopSchedule, rid)
        assert (
            schedule.source_group_id is None and schedule.source_group_revision is None
        )
        assert not schedule.individual_override
        assert db.scalar(select(SchemaVersion.version)) == VERSION
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
        assert conn.exec_driver_sql("PRAGMA integrity_check").scalar() == "ok"


def test_old_subscribe_hash_and_group_policy_none_semantics(alice):
    import hashlib
    import json
    from test_batches import complete_sso

    _, ids = complete_sso(alice, 1)
    body = {"record_ids": ids, "plan_id": 1, "request_key": str(uuid.uuid4())}
    response = alice.post("/api/batches/subscribe", json=body)
    assert response.status_code == 202
    with SessionLocal() as db:
        batch = db.get(Batch, response.json()["id"])
        assert (
            batch.payload_hash
            == hashlib.sha256(
                json.dumps({"record_ids": ids, "plan_id": 1}, sort_keys=True).encode()
            ).hexdigest()
        )
    assert (
        alice.post(
            "/api/batches/subscribe",
            json=body | {"group_id": None, "stop_schedule": {"mode": "none"}},
        ).json()["id"]
        == response.json()["id"]
    )
    gid = ready_group(alice)["id"]
    policy(alice, gid)
    key = str(uuid.uuid4())
    first = group_batch(alice, gid, request_key=key)
    assert first.status_code == 202
    assert (
        group_batch(
            alice, gid, request_key=key, stop_schedule={"mode": "none"}
        ).status_code
        == 409
    )


def test_group_policy_concurrent_revision_is_atomic(alice):
    gid = ready_group(alice)["id"]
    ids = [item["id"] for item in group_batch(alice, gid, 2).json()["items"]]
    run_one(GroupGateway)
    run_one(GroupGateway)
    clients = [login("alice"), login("alice")]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda pair: policy(
                    pair[1], gid, {"mode": "days", "days": 7 + pair[0]}
                ),
                enumerate(clients),
            )
        )
    assert sorted(r.status_code for r in results) == [200, 409]
    schedules = [detail(alice, rid)["stop_schedule"] for rid in ids]
    assert schedules[0]["days"] == schedules[1]["days"]
    assert all(s["source_group_revision"] == 1 for s in schedules)


def test_membership_recovery_keeps_unknown_intent_when_proxy_setup_fails(alice):
    gid = ready_group(alice)["id"]
    rid = group_batch(alice, gid, kind="subscribed").json()["items"][0]["id"]
    GroupGateway.lose_member = True
    run_one(GroupGateway)
    assert count() == (0, 1, 0, 1)
    assert alice.post(f"/api/subscriptions/{rid}/retry").status_code == 202

    class ProxyUnavailable(GroupGateway):
        def __init__(self, account):
            raise AwsFailure("proxy unavailable")

    run_one(ProxyUnavailable)
    assert detail(alice, rid)["state"] == "needs_review"
    assert count() == (0, 1, 0, 1)
    assert alice.post(f"/api/subscriptions/{rid}/retry").status_code == 202
    run_one(GroupGateway)
    assert detail(alice, rid)["state"] == "completed"
    assert (
        GroupGateway.member_writes
        == GroupGateway.user_writes
        == GroupGateway.password_writes
        == 1
    )


def test_pending_group_create_cannot_be_stolen_by_link(alice, admin, monkeypatch):
    from app import groups

    monkeypatch.setattr(groups, "AwsGateway", GroupGateway)
    GroupGateway.lose_group = True
    group = create_group(alice).json()
    run_group()
    remote_id = next(iter(GroupGateway.groups))
    assert admin.get("/api/admin/aws/1/groups").json() == []
    linked = admin.post(
        "/api/groups/link",
        json={
            "aws_account_id": 1,
            "owner_id": 3,
            "remote_id": remote_id,
            "request_key": str(uuid.uuid4()),
        },
    )
    assert linked.status_code == 202, linked.text
    run_group()
    assert admin.get(f"/api/groups/{linked.json()['id']}").json()["state"] == "failed"
    assert alice.post(f"/api/groups/{group['id']}/retry").status_code == 202
    run_group()
    assert alice.get(f"/api/groups/{group['id']}").json()["remote_id"] == remote_id


def test_group_job_recovery_checks_leases_and_retains_intent(alice):
    from app.group_jobs import claim_group_job, complete, run_group_job

    group = create_group(alice).json()
    first = claim_group_job()
    assert first
    with SessionLocal() as db:
        job = db.get(GroupJob, first[0])
        job.phase = "pending"
        job.lease_until = now() - timedelta(seconds=1)
        db.commit()
    second = claim_group_job()
    assert second and second[1] != first[1]
    with pytest.raises(RuntimeError):
        complete(first[0], first[1], remote_id="invalid")
    with SessionLocal() as db:
        db.get(GroupJob, second[0]).lease_until = now() - timedelta(seconds=1)
        db.commit()

    class BadProxy(GroupGateway):
        def __init__(self, account):
            raise AwsFailure("proxy unavailable")

    assert run_group_job(BadProxy)
    assert alice.get(f"/api/groups/{group['id']}").json()["state"] == "needs_review"
    assert alice.post(f"/api/groups/{group['id']}/retry").status_code == 202
    assert run_group()
    assert GroupGateway.group_writes == 0
    assert alice.get(f"/api/groups/{group['id']}").json()["state"] == "needs_review"
    with SessionLocal() as db:
        marker = db.get(ManagedGroup, group["id"]).marker
    GroupGateway.groups["recovered"] = {
        "id": "recovered",
        "name": "alice-team",
        "description": marker,
    }
    assert alice.post(f"/api/groups/{group['id']}/retry").status_code == 202
    assert run_group()
    assert alice.get(f"/api/groups/{group['id']}").json()["remote_id"] == "recovered"
    assert GroupGateway.group_writes == 0


def test_alias_account_and_other_owner_members_cannot_attach(alice, bob, admin):
    from test_batches import complete_sso

    gid = ready_group(alice)["id"]
    _, bob_ids = complete_sso(bob, 1)
    assert (
        operation(
            alice, gid, "attach", record_id=bob_ids[0], expected_revision=1
        ).status_code
        == 404
    )
    assert (
        operation(
            admin, gid, "attach", record_id=bob_ids[0], expected_revision=1
        ).status_code
        == 409
    )
    with SessionLocal() as db:
        account = db.get(AwsAccount, 1)
        fields = {
            c.name: getattr(account, c.name)
            for c in AwsAccount.__table__.columns
            if c.name not in ("id", "name")
        }
        db.add(AwsAccount(id=2, name="alias", **fields))
        db.commit()
        db.add(Binding(user_id=2, aws_account_id=2))
        db.commit()
    assert group_batch(alice, gid, aws_account_id=2).status_code == 409


def test_paid_membership_selection_validation_rolls_back_whole_batch(alice):
    gid = ready_group(alice)["id"]
    other = ready_group(alice, name="other")["id"]
    ids = [group_batch(alice, g).json()["items"][0]["id"] for g in (gid, other)]
    run_one(GroupGateway)
    run_one(GroupGateway)
    result = alice.post(
        "/api/batches/subscribe",
        json={
            "group_id": gid,
            "record_ids": ids,
            "plan_id": 1,
            "request_key": str(uuid.uuid4()),
        },
    )
    assert result.status_code == 409
    assert all(detail(alice, rid)["plan_id"] is None for rid in ids)
    assert count() == (0, 0, 0, 1)


def test_group_member_does_not_expose_admin_operation(alice, admin):
    from test_batches import complete_sso

    gid = ready_group(alice)["id"]
    _, ids = complete_sso(alice, 1)
    response = operation(admin, gid, "attach", record_id=ids[0], expected_revision=1)
    assert response.status_code == 202
    member = detail(alice, ids[0])
    assert member["operation"] is None
    assert member["operation_pending"]
    assert detail(admin, ids[0])["operation"]["id"] == response.json()["id"]


def test_stale_group_deadline_job_cannot_cancel_after_disable(alice):
    import json
    from app.lifecycle import run_operation
    from app.models import RecordOperation
    from test_lifecycle import LifecycleGateway

    gid = ready_group(alice)["id"]
    policy(alice, gid)
    rid = group_batch(alice, gid, kind="subscribed").json()["items"][0]["id"]
    run_one(GroupGateway)
    original_revision = detail(alice, rid)["stop_schedule"]["revision"]
    assert policy(alice, gid, {"mode": "none"}, 1).status_code == 200
    with SessionLocal() as db:
        op = RecordOperation(
            id=str(uuid.uuid4()),
            record_id=rid,
            actor_id=2,
            kind="cancel_subscription",
            request_key=f"auto-stop:{original_revision}",
            payload=json.dumps(
                {
                    "cancellation_mode": "IMMEDIATE",
                    "schedule_revision": original_revision,
                }
            ),
        )
        db.add(op)
        db.get(Subscription, rid).active_operation_id = op.id
        db.commit()
    LifecycleGateway.calls, LifecycleGateway.failure = [], None
    LifecycleGateway.info = {
        "status": "active",
        "subscription_type": "Q_DEVELOPER_STANDALONE_PRO",
        "expires_at": None,
    }
    assert run_operation(LifecycleGateway)
    assert LifecycleGateway.calls == []
    assert detail(alice, rid)["subscription_status"] == "active"


def test_group_auto_cancellation_survives_owner_disable_and_unbinding(alice, admin):
    from app.lifecycle import run_operation
    from app.models import User
    from app.schedules import enqueue_due
    from sqlalchemy import delete
    from test_lifecycle import LifecycleGateway

    gid = ready_group(alice)["id"]
    policy(alice, gid)
    rid = group_batch(alice, gid, kind="subscribed").json()["items"][0]["id"]
    run_one(GroupGateway)
    with SessionLocal() as db:
        db.get(StopSchedule, rid).stop_at = now() - timedelta(seconds=1)
        db.get(User, 2).active = False
        db.execute(delete(Binding).where(Binding.user_id == 2))
        db.commit()
    LifecycleGateway.calls, LifecycleGateway.failure = [], None
    LifecycleGateway.info = {
        "status": "active",
        "subscription_type": "Q_DEVELOPER_STANDALONE_PRO",
        "expires_at": None,
    }
    assert enqueue_due() == 1 and run_operation(LifecycleGateway)
    assert LifecycleGateway.calls == ["cancel"]
    assert detail(admin, rid)["stop_schedule"]["state"] == "completed"


def test_group_policy_rejects_whole_update_when_days_expired(alice):
    gid = ready_group(alice)["id"]
    policy(alice, gid, {"mode": "days", "days": 30})
    ids = [
        item["id"]
        for item in group_batch(alice, gid, 2, kind="subscribed").json()["items"]
    ]
    run_one(GroupGateway)
    run_one(GroupGateway)
    with SessionLocal() as db:
        db.get(Subscription, ids[1]).subscribed_at = now() - timedelta(days=10)
        db.commit()
    assert policy(alice, gid, {"mode": "days", "days": 3}, 1).status_code == 422
    assert all(detail(alice, rid)["stop_schedule"]["days"] == 30 for rid in ids)
    assert alice.get(f"/api/groups/{gid}").json()["policy"]["revision"] == 1


def test_group_sequence_and_admin_create_charge_designated_owner(alice, admin):
    gid = ready_group(alice)["id"]
    response = admin.post(
        "/api/batches/create",
        json={
            "kind": "sso",
            "aws_account_id": 1,
            "group_id": gid,
            "sequence": {"pattern": "groupseq-01-03"},
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 202, response.text
    for _ in range(3):
        run_one(GroupGateway)
    assert alice.get(f"/api/groups/{gid}").json()["counts"]["eligible"] == 3
    assert count() == (0, 0, 0, 1)
    assert all(
        detail(alice, i["id"])["owner_id"] == 2 for i in response.json()["items"]
    )


def test_backup_includes_group_intents_members_and_policy(alice, tmp_path):
    from app import backup
    from app.config import settings
    from app.database import engine

    gid = ready_group(alice)["id"]
    policy(alice, gid)
    group_batch(alice, gid)
    run_one(GroupGateway)
    config = tmp_path / "test.env"
    config.write_text(
        f"FERNET_KEY={settings.fernet_key}\nSECRET_KEY={settings.secret_key}\n"
    )
    archive, _ = backup.snapshot(engine.url.database, config, tmp_path)
    manifest = backup.check_archive(archive, tmp_path / "restore")
    assert manifest["tables"]["console_groups"] == 1
    assert manifest["tables"]["console_group_jobs"] == 1
    assert manifest["tables"]["console_stop_schedules"] == 1


def test_definitely_failed_group_can_be_deleted_without_touching_foreign_group(alice):
    GroupGateway.groups["foreign"] = {
        "id": "foreign",
        "name": "alice-team",
        "description": "unmanaged",
    }
    gid = create_group(alice).json()["id"]
    run_group()
    assert alice.get(f"/api/groups/{gid}").json()["state"] == "failed"
    response = operation(alice, gid, "delete", expected_revision=1)
    assert response.status_code == 202, response.text
    assert run_group()
    assert "foreign" in GroupGateway.groups
    assert alice.get(f"/api/groups/{gid}").json()["state"] == "deleted"
    assert len(alice.get(f"/api/groups/{gid}/jobs").json()) == 2


def test_disabled_group_owner_cannot_receive_new_paid_jobs(admin, alice):
    gid = ready_group(alice)["id"]
    assert admin.patch("/api/admin/users/2", json={"active": False}).status_code == 200
    response = group_batch(admin, gid, kind="subscribed")
    assert response.status_code == 409, response.text
    assert count() == (0, 0, 0, 1)


def test_ungrouped_subscribe_route_still_checks_group_availability(alice):
    gid = ready_group(alice)["id"]
    rid = group_batch(alice, gid).json()["items"][0]["id"]
    run_one(GroupGateway)
    assert (
        operation(alice, gid, "rename", expected_revision=1, name="waiting").status_code
        == 202
    )
    response = alice.post(
        "/api/batches/subscribe",
        json={
            "record_ids": [rid],
            "plan_id": 1,
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 409, response.text
    assert count() == (0, 0, 0, 1)


def test_admin_can_cleanup_disabled_unbound_owner_but_not_assign_new_members(
    alice, admin
):
    from test_batches import complete_sso
    from sqlalchemy import delete

    gid = ready_group(alice)["id"]
    rid = group_batch(alice, gid).json()["items"][0]["id"]
    run_one(GroupGateway)
    _, extra_ids = complete_sso(alice, 1)
    assert admin.patch("/api/admin/users/2", json={"active": False}).status_code == 200
    with SessionLocal() as db:
        db.execute(delete(Binding).where(Binding.user_id == 2))
        db.commit()
    assert admin.get(f"/api/groups/{gid}").status_code == 200
    assert policy(admin, gid).status_code == 200
    assert policy(admin, gid, {"mode": "none"}, 1).status_code == 200
    assert (
        operation(
            admin, gid, "attach", record_id=extra_ids[0], expected_revision=1
        ).status_code
        == 409
    )
    assert (
        operation(admin, gid, "rename", name="cleanup", expected_revision=1).status_code
        == 202
    )
    assert run_group()
    assert admin.get(f"/api/groups/{gid}").json()["name"] == "cleanup"
    assert (
        operation(admin, gid, "detach", record_id=rid, expected_revision=2).status_code
        == 202
    )
    assert run_group()
    assert detail(admin, rid)["group_id"] is None
    assert operation(admin, gid, "delete", expected_revision=2).status_code == 202
    assert run_group()
    assert admin.get(f"/api/groups/{gid}").json()["state"] == "deleted"


def test_rename_definitely_failed_create_recovers_waiting_sso(alice):
    GroupGateway.groups["foreign"] = {
        "id": "foreign",
        "name": "alice-team",
        "description": "unmanaged",
    }
    gid = create_group(alice).json()["id"]
    rid = group_batch(alice, gid).json()["items"][0]["id"]
    assert run_group()
    assert not run_one(GroupGateway)
    response = operation(
        alice, gid, "rename", name="available-name", expected_revision=1
    )
    assert response.status_code == 202, response.text
    assert run_group()
    assert run_one(GroupGateway)
    assert detail(alice, rid)["state"] == "completed"
    assert GroupGateway.user_writes == GroupGateway.group_writes == 1
    assert GroupGateway.groups["foreign"]["name"] == "alice-team"


@pytest.mark.parametrize("replacement", [False, True])
def test_pending_create_never_replays_when_original_name_no_longer_finds_result(
    alice, replacement
):
    GroupGateway.lose_group = True
    group = create_group(alice).json()
    assert run_group()
    original_id = next(iter(GroupGateway.groups))
    GroupGateway.groups[original_id]["name"] = "externally-renamed"
    if replacement:
        GroupGateway.groups["foreign"] = {
            "id": "foreign",
            "name": "alice-team",
            "description": "unmanaged",
        }
    GroupGateway.lose_group = False
    assert alice.post(f"/api/groups/{group['id']}/retry").status_code == 202
    assert run_group()
    current = alice.get(f"/api/groups/{group['id']}").json()
    assert current["state"] == "needs_review"
    assert current["remote_id"] is None
    assert GroupGateway.group_writes == 1
    assert len(GroupGateway.groups) == 1 + int(replacement)
    assert (
        operation(
            alice, group["id"], "rename", name="new-name", expected_revision=1
        ).status_code
        == 409
    )
    # Once the original result becomes discoverable, the same intent reconciles.
    GroupGateway.groups.pop("foreign", None)
    GroupGateway.groups[original_id]["name"] = "alice-team"
    assert alice.post(f"/api/groups/{group['id']}/retry").status_code == 202
    assert run_group()
    assert alice.get(f"/api/groups/{group['id']}").json()["remote_id"] == original_id
    assert GroupGateway.group_writes == 1


def test_definitive_create_rejection_can_correct_name_and_resume_sso(alice):
    from botocore.exceptions import ClientError
    from app.group_jobs import run_group_job

    class RejectedCreate(GroupGateway):
        def create_group(self, name, marker):
            raise ClientError(
                {
                    "Error": {"Code": "ValidationException", "Message": "invalid name"},
                    "ResponseMetadata": {"HTTPStatusCode": 400},
                },
                "CreateGroup",
            )

    gid = create_group(alice).json()["id"]
    rid = group_batch(alice, gid).json()["items"][0]["id"]
    assert run_group_job(RejectedCreate)
    with SessionLocal() as db:
        group = db.get(ManagedGroup, gid)
        assert group.state == "failed"
        assert db.get(GroupJob, group.active_job_id).phase == "ready"
    assert not run_one(GroupGateway)
    response = operation(
        alice, gid, "rename", name="corrected-name", expected_revision=1
    )
    assert response.status_code == 202, response.text
    assert run_group() and run_one(GroupGateway)
    assert detail(alice, rid)["state"] == "completed"
    assert GroupGateway.group_writes == GroupGateway.user_writes == 1


@pytest.mark.parametrize("failure", ["service", "network"])
def test_uncertain_create_and_later_definitive_lookup_failure_reconcile_only(
    alice, failure
):
    from botocore.exceptions import ClientError, EndpointConnectionError
    from app.group_jobs import run_group_job

    class UncertainCreate(GroupGateway):
        def create_group(self, name, marker):
            GroupGateway.group_writes += 1
            if failure == "network":
                raise EndpointConnectionError(endpoint_url="https://test.invalid")
            raise ClientError(
                {
                    "Error": {"Code": "InternalServerException"},
                    "ResponseMetadata": {"HTTPStatusCode": 500},
                },
                "CreateGroup",
            )

    class RejectedLookup(GroupGateway):
        def get_group_id(self, name):
            raise ClientError(
                {
                    "Error": {"Code": "ValidationException"},
                    "ResponseMetadata": {"HTTPStatusCode": 400},
                },
                "GetGroupId",
            )

    gid = create_group(alice).json()["id"]
    assert run_group_job(UncertainCreate)
    from app.retry_models import AutomaticRetry
    from test_automatic_retries import due

    with SessionLocal() as db:
        group = db.get(ManagedGroup, gid)
        job = db.get(GroupJob, group.active_job_id)
        retry = db.get(AutomaticRetry, ("group", job.id))
        jid, original_payload = job.id, job.payload
        assert job.state == "queued" and job.phase == "pending"
        assert retry.mode == "reconcile" and retry.retry_count == 1
        assert retry.next_retry_at > now()
    assert not run_group_job(RejectedLookup)
    due("group", jid)
    assert run_group_job(RejectedLookup)
    with SessionLocal() as db:
        group = db.get(ManagedGroup, gid)
        assert group.state == "needs_review"
        assert db.get(GroupJob, group.active_job_id).phase == "pending"
        assert db.get(GroupJob, group.active_job_id).payload == original_payload
    assert (
        operation(
            alice, gid, "rename", name="unsafe-new-name", expected_revision=1
        ).status_code
        == 409
    )
    assert alice.post(f"/api/groups/{gid}/retry").status_code == 202
    assert run_group()
    assert alice.get(f"/api/groups/{gid}").json()["state"] == "needs_review"
    assert GroupGateway.group_writes == 1


@pytest.mark.parametrize("new_policy", [{"mode": "none"}, {"mode": "days", "days": 30}])
def test_group_policy_supersedes_unclaimed_automatic_cancellation(alice, new_policy):
    from app.lifecycle import run_operation
    from app.models import RecordOperation
    from app.schedules import enqueue_due
    from test_lifecycle import LifecycleGateway

    gid = ready_group(alice)["id"]
    assert policy(alice, gid).status_code == 200
    rid = group_batch(alice, gid, kind="subscribed").json()["items"][0]["id"]
    assert run_one(GroupGateway)
    original = detail(alice, rid)
    with SessionLocal() as db:
        db.get(StopSchedule, rid).stop_at = now() - timedelta(seconds=1)
        db.commit()
    assert enqueue_due() == 1
    with SessionLocal() as db:
        op_id = db.get(Subscription, rid).active_operation_id
        payload = db.get(RecordOperation, op_id).payload
    preview = policy(alice, gid, new_policy, 1, preview=True)
    assert preview.status_code == 200, preview.text
    assert preview.json()["affected_ids"] == [rid]
    assert preview.json()["conflict_count"] == 0
    with SessionLocal() as db:
        assert db.get(RecordOperation, op_id).state == "queued"
        assert db.get(Subscription, rid).active_operation_id == op_id
    result = policy(alice, gid, new_policy, 1)
    assert result.status_code == 200, result.text
    with SessionLocal() as db:
        op = db.get(RecordOperation, op_id)
        assert op.state == "superseded" and op.finished_at
        assert op.payload == payload and op.attempts == 0
        assert db.get(Subscription, rid).active_operation_id is None
        schedule = db.get(StopSchedule, rid)
        assert schedule.operation_id is None and schedule.source_group_revision == 2
        assert schedule.revision == original["stop_schedule"]["revision"] + 1
    LifecycleGateway.calls = []
    assert not run_operation(LifecycleGateway)
    assert LifecycleGateway.calls == []
    current = detail(alice, rid)
    assert current["subscribed_at"] == original["subscribed_at"]
    assert current["subscription_status"] == "active"
    assert enqueue_due() == 0
    assert count() == (1, 0, 1, 1)


@pytest.mark.parametrize(
    "operation_state", ["running", "pending", "needs_review", "retried"]
)
def test_group_policy_never_supersedes_claimed_or_uncertain_cancellation(
    alice, operation_state
):
    from app.lifecycle import claim_operation, mark_pending
    from app.models import RecordOperation
    from app.schedules import enqueue_due

    gid = ready_group(alice)["id"]
    assert policy(alice, gid).status_code == 200
    ids = [
        item["id"]
        for item in group_batch(alice, gid, 2, kind="subscribed").json()["items"]
    ]
    assert run_one(GroupGateway) and run_one(GroupGateway)
    with SessionLocal() as db:
        for rid in ids:
            db.get(StopSchedule, rid).stop_at = now() - timedelta(seconds=1)
        db.commit()
    assert enqueue_due() == 2
    op_id, token = claim_operation()
    if operation_state != "running":
        mark_pending(op_id, token)
    if operation_state in ("needs_review", "retried"):
        with SessionLocal() as db:
            op = db.get(RecordOperation, op_id)
            op.state = "needs_review" if operation_state == "needs_review" else "queued"
            op.lease_token = op.lease_until = None
            if operation_state == "retried":
                op.phase = "ready"
            db.commit()
    preview = policy(alice, gid, {"mode": "none"}, 1, preview=True)
    assert preview.status_code == 200
    assert preview.json()["affected_count"] == preview.json()["conflict_count"] == 1
    result = policy(alice, gid, {"mode": "none"}, 1)
    assert result.status_code == 409
    with SessionLocal() as db:
        assert db.get(ManagedGroup, gid).policy_revision == 1
        for rid in ids:
            schedule = db.get(StopSchedule, rid)
            op = db.get(RecordOperation, schedule.operation_id)
            assert schedule.mode == "days" and schedule.days == 7
            assert db.get(Subscription, rid).active_operation_id == op.id
            if op.id != op_id:
                assert op.state == "queued" and op.attempts == 0


@pytest.mark.parametrize("uncertain", [False, True])
def test_admin_cleanup_retry_uses_current_authority_and_preserves_job_history(
    alice, admin, uncertain
):
    from sqlalchemy import delete, select
    from app.group_jobs import run_group_job
    from app.models import AuditEvent

    class FailingDetach(GroupGateway):
        def __init__(self, account):
            if not uncertain:
                raise AwsFailure("proxy unavailable")
            super().__init__(account)

        def delete_group_membership(self, mid):
            super().delete_group_membership(mid)
            raise AwsFailure("lost detach response", uncertain=True)

    gid = ready_group(alice)["id"]
    rid = group_batch(alice, gid).json()["items"][0]["id"]
    assert run_one(GroupGateway)
    submitted = operation(alice, gid, "detach", record_id=rid, expected_revision=1)
    assert submitted.status_code == 202
    jid = submitted.json()["id"]
    assert run_group_job(FailingDetach)
    with SessionLocal() as db:
        job = db.get(GroupJob, jid)
        assert job.state == ("needs_review" if uncertain else "failed")
        saved = (job.payload, job.request_key, job.created_at, job.phase)
    assert admin.patch("/api/admin/users/2", json={"active": False}).status_code == 200
    with SessionLocal() as db:
        db.execute(delete(Binding).where(Binding.user_id == 2))
        db.commit()
    retry = admin.post(f"/api/groups/{gid}/retry")
    assert retry.status_code == 202 and retry.json()["id"] == jid
    with SessionLocal() as db:
        job = db.get(GroupJob, jid)
        assert job.actor_id == 1
        assert job.attempts == 1 and job.state == "queued"
        assert (job.payload, job.request_key, job.created_at, job.phase) == saved
    assert run_group()
    assert detail(admin, rid)["group_id"] is None
    with SessionLocal() as db:
        job = db.get(GroupJob, jid)
        assert job.state == "completed" and job.attempts == 2
        assert db.get(Subscription, rid).active_operation_id is None
        history = list(db.scalars(select(AuditEvent)))
        assert any(e.action == "group_detach" and e.actor_id == 2 for e in history)
        assert any(e.action == "retry_group" and e.actor_id == 1 for e in history)
        assert any(
            e.action == "group_detach_completed" and e.actor_id == 1 for e in history
        )
    assert operation(admin, gid, "delete", expected_revision=1).status_code == 202
    assert run_group()


def test_manual_none_before_group_attachment_remains_an_individual_override(alice):
    from test_batches import complete_sso

    _, ids = complete_sso(alice, 1)
    rid = ids[0]
    assert detail(alice, rid)["stop_schedule"] is None
    response = alice.put(
        f"/api/subscriptions/{rid}/stop-schedule",
        json={"policy": {"mode": "none"}, "expected_revision": 0},
    )
    assert response.status_code == 200 and response.json(), response.text
    schedule = response.json()
    assert schedule["mode"] == "none" and schedule["state"] == "disabled"
    assert schedule["individual_override"] and schedule["source_group_id"] is None
    gid = ready_group(alice)["id"]
    assert policy(alice, gid).status_code == 200
    assert (
        operation(alice, gid, "attach", record_id=rid, expected_revision=1).status_code
        == 202
    )
    assert run_group()
    assert detail(alice, rid)["stop_schedule"] == schedule
    changed = policy(alice, gid, {"mode": "days", "days": 30}, 1)
    assert changed.status_code == 200 and changed.json()["skipped_count"] == 1
    response = alice.post(
        "/api/batches/subscribe",
        json={
            "record_ids": [rid],
            "group_id": gid,
            "plan_id": 1,
            "request_key": str(uuid.uuid4()),
        },
    )
    assert response.status_code == 202, response.text
    assert run_one(GroupGateway)
    assert detail(alice, rid)["stop_schedule"] == schedule
    reset = alice.post(
        f"/api/subscriptions/{rid}/stop-schedule/reset-to-group",
        json={"expected_revision": schedule["revision"], "expected_group_revision": 2},
    )
    assert reset.status_code == 200
    assert reset.json()["days"] == 30 and reset.json()["source_group_id"] == gid


def test_group_policy_and_automatic_claim_have_one_winner(alice):
    import threading
    from app.lifecycle import claim_operation
    from app.models import RecordOperation
    from app.schedules import enqueue_due

    gid = ready_group(alice)["id"]
    assert policy(alice, gid).status_code == 200
    rid = group_batch(alice, gid, kind="subscribed").json()["items"][0]["id"]
    assert run_one(GroupGateway)
    with SessionLocal() as db:
        db.get(StopSchedule, rid).stop_at = now() - timedelta(seconds=1)
        db.commit()
    assert enqueue_due() == 1
    with SessionLocal() as db:
        op_id = db.get(Subscription, rid).active_operation_id
    start = threading.Barrier(2)

    def claim():
        start.wait(timeout=5)
        return claim_operation()

    def disable():
        start.wait(timeout=5)
        return policy(alice, gid, {"mode": "none"}, 1)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        claim_future, disable_future = pool.submit(claim), pool.submit(disable)
        claimed, response = claim_future.result(), disable_future.result()
    with SessionLocal() as db:
        op = db.get(RecordOperation, op_id)
        record = db.get(Subscription, rid)
        schedule = db.get(StopSchedule, rid)
        if response.status_code == 200:
            assert claimed is None
            assert op.state == "superseded" and op.attempts == 0
            assert record.active_operation_id is None
            assert schedule.mode == "none" and schedule.operation_id is None
        else:
            assert response.status_code == 409, response.text
            assert claimed and claimed[0] == op_id
            assert op.state == "running" and op.attempts == 1
            assert record.active_operation_id == schedule.operation_id == op_id
            assert schedule.mode == "days" and schedule.source_group_revision == 1
        assert record.subscription_status == "active" and not record.cancelled_at


@pytest.mark.parametrize("entrypoint", ["batch_create", "single_create", "subscribe"])
@pytest.mark.parametrize("explicit_none", [False, True])
def test_explicit_none_admission_survives_later_group_attachment(
    alice, entrypoint, explicit_none
):
    from test_batches import complete_sso

    body = {"request_key": str(uuid.uuid4())}
    if entrypoint == "batch_create":
        path = "/api/batches/create"
        body.update(kind="sso", aws_account_id=1, items=[{"username": "individual"}])
    elif entrypoint == "single_create":
        path = "/api/subscriptions"
        body.update(
            aws_account_id=1,
            plan_id=1,
            username="individual",
            email="individual@example.com",
        )
    else:
        _, ids = complete_sso(alice, 1)
        path = "/api/batches/subscribe"
        body.update(record_ids=ids, plan_id=1)
    if explicit_none:
        body["stop_schedule"] = {"mode": "none"}
    response = alice.post(path, json=body)
    assert response.status_code == 202, response.text
    admitted = response.json()
    rid = (
        admitted["id"] if entrypoint == "single_create" else admitted["items"][0]["id"]
    )
    assert run_one(GroupGateway)
    schedule = detail(alice, rid)["stop_schedule"]
    if explicit_none:
        assert schedule and schedule["mode"] == "none"
        assert schedule["state"] == "disabled" and schedule["individual_override"]
        assert schedule["source_group_id"] is None
    else:
        assert schedule is None

    # Omitted and none retain their historical idempotency equivalence. A replay
    # returns the original admission, without changing its saved policy intent.
    replay_body = body.copy()
    if explicit_none:
        replay_body.pop("stop_schedule")
    else:
        replay_body["stop_schedule"] = {"mode": "none"}
    replay = alice.post(path, json=replay_body)
    assert replay.status_code == 202, replay.text
    assert replay.json()["id"] == admitted["id"]
    assert detail(alice, rid)["stop_schedule"] == schedule

    gid = ready_group(alice)["id"]
    assert policy(alice, gid).status_code == 200
    attached = operation(alice, gid, "attach", record_id=rid, expected_revision=1)
    assert attached.status_code == 202, attached.text
    assert run_group()
    inherited = detail(alice, rid)["stop_schedule"]
    if explicit_none:
        assert inherited == schedule
        assert policy(alice, gid, revision=1).json()["skipped_count"] == 1
    else:
        assert inherited["mode"] == "days" and inherited["days"] == 7
        assert inherited["source_group_id"] == gid
        assert not inherited["individual_override"]
    assert count() == ((0, 0, 0, 1) if entrypoint == "batch_create" else (1, 0, 1, 1))


@pytest.mark.parametrize("mode", ["none", "days", "at"])
@pytest.mark.parametrize("explicit_policy", [False, True])
def test_single_grouped_replay_distinguishes_inheritance_from_equal_override(
    alice, mode, explicit_policy
):
    gid = ready_group(alice)["id"]
    stop_policy = {"mode": mode}
    if mode == "days":
        stop_policy["days"] = 7
    elif mode == "at":
        stop_policy["stop_at"] = (
            datetime.now(timezone.utc) + timedelta(days=7)
        ).isoformat()
    assert policy(alice, gid, stop_policy).status_code == 200
    body = {
        "aws_account_id": 1,
        "group_id": gid,
        "plan_id": 1,
        "username": "group-intent",
        "email": "group-intent@example.com",
        "request_key": str(uuid.uuid4()),
    }
    if explicit_policy:
        body["stop_schedule"] = stop_policy
    response = alice.post("/api/subscriptions", json=body)
    assert response.status_code == 202, response.text
    rid = response.json()["id"]
    original_schedule = detail(alice, rid)["stop_schedule"]
    same = alice.post("/api/subscriptions", json=body)
    assert same.status_code == 202 and same.json()["id"] == rid

    changed_intent = body.copy()
    if explicit_policy:
        changed_intent.pop("stop_schedule")
    else:
        changed_intent["stop_schedule"] = stop_policy
    replay = alice.post("/api/subscriptions", json=changed_intent)
    assert replay.status_code == 409, replay.text
    assert detail(alice, rid)["stop_schedule"] == original_schedule
    assert count() == (0, 1, 0, 1)
    assert run_one(GroupGateway)
    assert count() == (1, 0, 1, 1)
    updated = policy(alice, gid, {"mode": "days", "days": 30}, 1)
    assert updated.status_code == 200, updated.text
    schedule = detail(alice, rid)["stop_schedule"]
    if explicit_policy:
        assert updated.json()["skipped_count"] == 1
        assert schedule["mode"] == mode and schedule["individual_override"]
        assert schedule["source_group_id"] is None
    else:
        assert updated.json()["affected_count"] == 1
        assert schedule["mode"] == "days" and schedule["days"] == 30
        assert schedule["source_group_id"] == gid
        assert not schedule["individual_override"]


@pytest.mark.parametrize("entrypoint", ["sso", "subscribed", "single"])
@pytest.mark.parametrize("remote_exists", [False, True])
def test_linking_group_rejects_admission_until_remote_validation(
    alice, admin, entrypoint, remote_exists
):
    from sqlalchemy import func, select

    if remote_exists:
        GroupGateway.groups["existing"] = {
            "id": "existing",
            "name": "existing-team",
            "description": "unmanaged",
        }
    linked = admin.post(
        "/api/groups/link",
        json={
            "aws_account_id": 1,
            "owner_id": 2,
            "remote_id": "existing",
            "request_key": str(uuid.uuid4()),
        },
    )
    assert linked.status_code == 202 and linked.json()["state"] == "linking"
    gid = linked.json()["id"]
    key = str(uuid.uuid4())

    def submit():
        if entrypoint != "single":
            return group_batch(alice, gid, kind=entrypoint, request_key=key)
        return alice.post(
            "/api/subscriptions",
            json={
                "aws_account_id": 1,
                "group_id": gid,
                "plan_id": 1,
                "username": "link-check",
                "email": "link-check@example.com",
                "request_key": key,
            },
        )

    rejected = submit()
    assert rejected.status_code == 409, rejected.text
    assert count() == (0, 0, 0, 1)
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Subscription)) == 0
        assert db.scalar(select(func.count()).select_from(Batch)) == 0
    assert not run_one(GroupGateway)
    assert run_group()
    after = submit()
    if remote_exists:
        assert after.status_code == 202, after.text
        assert run_one(GroupGateway)
        assert count() == ((0, 0, 0, 1) if entrypoint == "sso" else (1, 0, 1, 1))
    else:
        assert after.status_code == 409, after.text
        assert alice.get(f"/api/groups/{gid}").json()["state"] == "failed"
        assert count() == (0, 0, 0, 1)
        with SessionLocal() as db:
            assert db.scalar(select(func.count()).select_from(Subscription)) == 0
            assert db.scalar(select(func.count()).select_from(Batch)) == 0
    assert GroupGateway.user_writes == int(remote_exists)


def test_creating_group_still_accepts_paid_work_while_waiting(alice):
    gid = create_group(alice).json()["id"]
    response = group_batch(alice, gid, kind="subscribed")
    assert response.status_code == 202, response.text
    rid = response.json()["items"][0]["id"]
    assert count() == (0, 1, 0, 1)
    assert not run_one(GroupGateway)
    assert run_group() and run_one(GroupGateway)
    assert detail(alice, rid)["state"] == "completed"
    assert count() == (1, 0, 1, 1)


@pytest.mark.parametrize("kind", ["sso", "subscribed"])
def test_empty_group_deletion_keeps_deleted_member_history(alice, kind):
    from test_lifecycle import cascade, drain_lifecycle

    class DeleteMember(GroupGateway):
        deleted = set()
        cancelled = set()

        def user_info(self, record):
            return None if record.sso_user_id in self.deleted else {"UserId": record.sso_user_id, 'UserName': record.username}

        def list_user_memberships(self, uid):
            return {gid: mid for (gid, user), mid in self.memberships.items() if user == uid}

        def group_subscription_info(self, group):
            return dict(status='not_subscribed', subscription_type=None, expires_at=None)

        def user_subscription_sources(self, record):
            return [] if kind == 'sso' else [dict(source='USER', group_id=None,
                status='cancelled' if record.sso_user_id in self.cancelled else 'active',
                subscription_type='Q_DEVELOPER_STANDALONE_PRO', expires_at=None)]

        def cancel_subscription(self, record, mode):
            assert mode == 'IMMEDIATE'
            self.cancelled.add(record.sso_user_id)
            return 'cancel-member-request'

        def delete_user(self, record):
            self.deleted.add(record.sso_user_id)
            for pair in list(self.memberships):
                if pair[1] == record.sso_user_id:
                    del self.memberships[pair]
            return "delete-member-request"

    group = ready_group(alice)
    gid = group["id"]
    rid = group_batch(alice, gid, kind=kind).json()["items"][0]["id"]
    assert run_one(GroupGateway)
    member = detail(alice, rid)
    assert cascade(alice, member, DeleteMember).status_code == 202
    drain_lifecycle(DeleteMember)
    history = detail(alice, rid)
    assert history["sso_deleted_at"] and history["group_id"] == gid
    assert not history["operation_pending"] and not GroupGateway.memberships
    deleted = operation(alice, gid, "delete", expected_revision=1)
    assert deleted.status_code == 202, deleted.text
    assert run_group()
    tombstone = alice.get(f"/api/groups/{gid}").json()
    assert tombstone["state"] == "deleted" and tombstone["deleted_at"]
    assert tombstone["counts"]["deleted"] == 1
    assert [r["id"] for r in tombstone["members"]] == [rid]
    assert group["remote_id"] not in GroupGateway.groups
    after = detail(alice, rid)
    for field in (
        "group_id",
        "sso_deleted_at",
        "subscribed_at",
        "plan_id",
        "subscription_status",
    ):
        assert after[field] == history[field]
    assert count() == ((0, 0, 0, 1) if kind == "sso" else (1, 0, 1, 1))


@pytest.mark.parametrize(
    "pending",
    [
        "active_operation",
        "reserved",
        "queued",
        "running",
        "needs_review",
        "record_job",
        "group_job",
    ],
)
def test_deleted_member_history_with_unresolved_work_still_blocks_group_delete(
    alice, pending
):
    from app.models import RecordOperation

    gid = ready_group(alice)["id"]
    rid = group_batch(alice, gid).json()["items"][0]["id"]
    assert run_one(GroupGateway)
    GroupGateway.memberships.clear()
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        record.sso_deleted_at = now()
        if pending == "active_operation":
            record.active_operation_id = str(uuid.uuid4())
        elif pending == "reserved":
            record.reserved = True
        elif pending in ("queued", "running", "needs_review"):
            record.state = pending
        elif pending == "record_job":
            db.add(
                RecordOperation(
                    id=str(uuid.uuid4()),
                    record_id=rid,
                    actor_id=2,
                    kind="sync_status",
                    request_key=str(uuid.uuid4()),
                    payload="{}",
                    state="needs_review",
                )
            )
        else:
            db.add(
                GroupJob(
                    id=str(uuid.uuid4()),
                    group_id=gid,
                    record_id=rid,
                    actor_id=2,
                    kind="detach",
                    request_key=str(uuid.uuid4()),
                    payload="{}",
                    state="needs_review",
                )
            )
        db.commit()
    rejected = operation(alice, gid, "delete", expected_revision=1)
    assert rejected.status_code == 409, rejected.text
    assert alice.get(f"/api/groups/{gid}").json()["state"] == "ready"
    assert not run_group()


@pytest.mark.parametrize("mutation", ["manual_policy", "group_policy", "detach"])
@pytest.mark.parametrize("explicit_policy", [False, True])
def test_single_admission_replay_uses_original_intent_after_mutation(
    alice, mutation, explicit_policy
):
    gid = ready_group(alice)["id"]
    body = {
        "aws_account_id": 1,
        "group_id": gid,
        "plan_id": 1,
        "username": "saved-intent",
        "email": "saved-intent@example.com",
        "request_key": str(uuid.uuid4()),
    }
    if explicit_policy:
        body["stop_schedule"] = {"mode": "none"}
    submitted = alice.post("/api/subscriptions", json=body)
    assert submitted.status_code == 202, submitted.text
    rid = submitted.json()["id"]
    assert run_one(GroupGateway)
    if mutation == "manual_policy":
        changed = alice.put(
            f"/api/subscriptions/{rid}/stop-schedule",
            json={"policy": {"mode": "days", "days": 20}, "expected_revision": 1},
        )
        assert changed.status_code == 200, changed.text
    elif mutation == "group_policy":
        changed = policy(alice, gid, {"mode": "days", "days": 30}, overwrite=True)
        assert changed.status_code == 200, changed.text
    else:
        assert (
            operation(
                alice, gid, "detach", record_id=rid, expected_revision=1
            ).status_code
            == 202
        )
        assert run_group()
    current = detail(alice, rid)
    replay = alice.post("/api/subscriptions", json=body)
    assert replay.status_code == 202, replay.text
    assert replay.json() == current
    different = body.copy()
    if explicit_policy:
        different.pop("stop_schedule")
    else:
        different["stop_schedule"] = {"mode": "none"}
    assert alice.post("/api/subscriptions", json=different).status_code == 409
    assert detail(alice, rid) == current
    assert not run_one(GroupGateway)
    assert count() == (1, 0, 1, 1)


@pytest.mark.parametrize("version", [6, 7, 8])
def test_single_admission_hash_migration_is_nullable_and_preserves_history(
    alice, version
):
    from sqlalchemy import inspect, text
    from app.database import engine
    from app.init_db import initialize
    from test_workflows import create

    response = create(alice)
    assert response.status_code == 202
    rid = response.json()["id"]
    assert run_one(GroupGateway)
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        before = {
            c.name: getattr(record, c.name)
            for c in Subscription.__table__.columns
            if c.name != "request_payload_hash"
        }
    with engine.begin() as conn:
        columns = {
            c["name"] for c in inspect(conn).get_columns("console_subscriptions")
        }
        if "request_payload_hash" in columns:
            conn.exec_driver_sql(
                "ALTER TABLE console_subscriptions DROP COLUMN request_payload_hash"
            )
        conn.execute(
            text("INSERT INTO console_schema_version (version) VALUES (:v)"),
            {"v": version},
        )
    initialize()
    initialize()
    columns = {
        c["name"]: c for c in inspect(engine).get_columns("console_subscriptions")
    }
    assert (
        "request_payload_hash" in columns
        and columns["request_payload_hash"]["nullable"]
    )
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        assert record.request_payload_hash is None
        assert {name: getattr(record, name) for name in before} == before
    with engine.connect() as conn:
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
        assert conn.exec_driver_sql("PRAGMA integrity_check").scalar() == "ok"
    assert count() == (1, 0, 1, 1)


@pytest.mark.parametrize("grouped", [False, True])
def test_single_legacy_null_hash_keeps_conservative_replay_without_backfill(
    alice, grouped
):
    body = {
        "aws_account_id": 1,
        "plan_id": 1,
        "username": "legacy-intent",
        "email": "legacy-intent@example.com",
        "request_key": str(uuid.uuid4()),
    }
    if grouped:
        body["group_id"] = ready_group(alice)["id"]
    response = alice.post("/api/subscriptions", json=body)
    assert response.status_code == 202
    rid = response.json()["id"]
    with SessionLocal() as db:
        db.get(Subscription, rid).request_payload_hash = None
        db.commit()
    replay = alice.post("/api/subscriptions", json=body)
    assert replay.status_code == 202 and replay.json()["id"] == rid
    changed = alice.post(
        "/api/subscriptions", json=body | {"stop_schedule": {"mode": "none"}}
    )
    assert changed.status_code == (409 if grouped else 202)
    with SessionLocal() as db:
        assert db.get(Subscription, rid).request_payload_hash is None
    assert count() == (0, 1, 0, 1)


def test_directory_counts_match_detail_preview_and_keep_scoped_members_private(
    alice, bob, admin,
):
    from app.models import RecordOperation

    alice_group = ready_group(alice)
    gid = alice_group["id"]
    batch = group_batch(alice, gid, n=11)
    assert batch.status_code == 202, batch.text
    ids = [item["id"] for item in batch.json()["items"]]
    for _ in ids:
        assert run_one(GroupGateway)
    bob_group = ready_group(bob, name="bob-private-team")
    assert group_batch(bob, bob_group["id"]).status_code == 202
    assert run_one(GroupGateway)
    hidden_operation = str(uuid.uuid4())
    with SessionLocal() as db:
        account = db.get(AwsAccount, 1)
        fields = {c.name: getattr(account, c.name) for c in AwsAccount.__table__.columns if c.name not in ("id", "name")}
        db.add(AwsAccount(id=2, name="other AWS config", **fields))
        db.flush()
        records = [db.get(Subscription, rid) for rid in ids]
        for index in (1, 2):
            schedule = db.get(StopSchedule, ids[index])
            schedule.mode = "at"
            schedule.stop_at = now() - timedelta(days=1)
            schedule.source_group_id = gid if index == 1 else None
            schedule.individual_override = index == 2
        for index in (3, 4, 5):
            records[index].counted = True
            records[index].plan_id = 1
            records[index].provision_only = False
            records[index].subscription_status = "active"
        records[4].cancelled_at = now()
        records[4].subscription_status = "cancelled"
        records[5].sso_deleted_at = now()
        records[6].active_operation_id = hidden_operation
        db.add(RecordOperation(
            id=hidden_operation, record_id=ids[6], actor_id=1,
            kind="auth_json_export", request_key=str(uuid.uuid4()),
            payload='{"private": "admin-private-auth-data"}',
            result='{"secret": "admin-private-auth-data"}',
        ))
        records[7].group_membership_id = None
        records[8].sso_user_id = None
        # Corrupt references must not cross the same-owner/account scope.
        records[9].owner_id = 3
        records[10].aws_account_id = 2
        db.commit()

    expected = {"total": 9, "eligible": 1, "active": 7, "subscribed": 3, "deleted": 1, "cancelled": 1,
                "unconfirmed": 1, "joined": 6}
    alice_rows = alice.get("/api/groups").json()
    assert len(alice_rows) == 1
    assert alice_rows[0]["counts"] == expected
    assert alice.get(f"/api/groups/{gid}").json()["counts"] == expected
    preview = alice.get(f"/api/groups/{gid}/subscription-preview").json()
    assert preview["eligible_count"] == expected["eligible"]
    reasons = {item["reason"] for item in preview["skipped"]}
    assert {"group_deadline_expired", "deadline_expired", "operation_pending", "membership_not_confirmed", "sso_not_ready"} <= reasons
    hidden = detail(alice, ids[6])
    assert hidden["operation_pending"] is True and hidden["operation"] is None
    bob_rows = bob.get("/api/groups").json()
    assert [row["id"] for row in bob_rows] == [bob_group["id"]]
    assert bob_rows[0]["counts"]["eligible"] == 1
    admin_rows = {row["id"]: row for row in admin.get("/api/groups").json()}
    assert admin_rows[gid]["counts"] == expected
    assert set(admin_rows) == {gid, bob_group["id"]}
    for row in [*alice_rows, *bob_rows, *admin_rows.values()]:
        assert "members" not in row
        assert "operations" not in row
        assert hidden_operation not in str(row)
        assert "admin-private-auth-data" not in str(row)


def test_group_directory_counts_use_bounded_scoped_queries(alice):
    from sqlalchemy import event
    from app.database import engine

    groups = [ready_group(alice, name=f"count-team-{index}") for index in range(4)]
    for group in groups:
        assert group_batch(alice, group["id"], n=2).status_code == 202
        assert run_one(GroupGateway)
        assert run_one(GroupGateway)
    statements = []

    def collect(_conn, _cursor, statement, _parameters, _context, _many):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    event.listen(engine, "before_cursor_execute", collect)
    try:
        response = alice.get("/api/groups")
    finally:
        event.remove(engine, "before_cursor_execute", collect)
    assert response.status_code == 200
    assert [g["counts"]["eligible"] for g in response.json()] == [2] * 4
    # One auth lookup, one group query, and a bounded bulk membership/schedule read.
    assert len(statements) <= 4, statements
