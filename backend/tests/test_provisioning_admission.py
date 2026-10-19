"""Admission-only numbered provisioning: real routes/transactions, synthetic AWS."""

import json
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from datetime import timedelta
from threading import Barrier

import pytest
from sqlalchemy import func, select

from app import aws, models
from app.database import SessionLocal
from app.group_subscription_state import config_hash
from app.security import encrypt


def account_input(account_id=1, **extra):
    with SessionLocal() as db:
        account = db.get(models.AwsAccount, account_id)
        return {key: getattr(account, key) for key in (
            "name", "region", "subscription_region", "control_plane", "identity_store_id",
            "instance_arn", "application_arn", "profile_arn", "portal_url", "active", "proxy_id",
        )} | extra


def duplicate_account(number=None, owner=2):
    with SessionLocal() as db:
        source = db.get(models.AwsAccount, 1)
        values = {c.name: getattr(source, c.name) for c in source.__table__.columns if c.name not in ("id", "name", "account_number")}
        account = models.AwsAccount(name="Second AWS", **values)
        account.account_number = number
        db.add(account)
        db.flush()
        db.add(models.Binding(user_id=owner, aws_account_id=account.id))
        db.commit()
        return account.id


class Gateway:
    calls = []
    change = None
    claims = []
    members = []

    def __init__(self, account):
        self.account = account

    def verify(self):
        type(self).calls.append(("verify", self.account.id))
        if type(self).change:
            type(self).change(self.account)
        return self.account.aws_account_id or "123456789012"

    def get_group(self, group_id):
        type(self).calls.append(("group", group_id))
        if type(self).change:
            type(self).change(self.account)
        return {"id": group_id, "name": "Remote group"}

    def list_group_memberships(self, group_id):
        return deepcopy(type(self).members)

    def report_claims(self):
        return deepcopy(type(self).claims)


@pytest.fixture
def remote(monkeypatch):
    for name, value in (("calls", []), ("change", None), ("claims", []), ("members", [])):
        monkeypatch.setattr(Gateway, name, value)
    monkeypatch.setattr(aws, "AwsGateway", Gateway)
    return Gateway


@pytest.fixture
def ready(admin, remote):
    with SessionLocal() as db:
        proxy = models.Proxy(name="Provisioning egress", host="127.0.0.1", port=1080,
                             auth_encrypted=encrypt({"username": "secret-user", "password": "secret-password"}))
        db.add(proxy)
        db.flush()
        db.get(models.AwsAccount, 1).proxy_id = proxy.id
        db.commit()
    result = admin.put("/api/admin/aws/1", json=account_input(account_number="A"))
    assert result.status_code == 200, result.text
    remote.calls.clear()
    return remote


def intent(account_id=1, quantity=1, **extra):
    return {"accounts": [{"aws_account_id": account_id, "quantity": quantity, "plan_id": 1,
                           "group": {"mode": "new"}, "exports": {"csv": True, "txt": False, "json": True}, **extra}]}


def preview(client, body):
    result = client.post("/api/provisioning-batches/preview", json=body)
    assert result.status_code == 200, result.text
    return result.json()


def admit(client, body, key="numbered-request-0001", preflight=None):
    preflight = preflight or preview(client, body)
    return client.post("/api/provisioning-batches", json=body | {
        "request_key": key, "preview_fingerprint": preflight["preview_fingerprint"],
    })


def test_number_administration_normalizes_and_preserves_transport(admin, alice, remote):
    with SessionLocal() as db:
        before = config_hash(db, db.get(models.AwsAccount, 1))
    result = admin.put("/api/admin/aws/1", json=account_input(account_number="  Ab19  "))
    assert result.status_code == 200, result.text
    assert result.json()["account_number"] == "ab19"
    assert admin.put("/api/admin/aws/1", json=account_input(name="Renamed")).json()["account_number"] == "ab19"
    with SessionLocal() as db:
        assert config_hash(db, db.get(models.AwsAccount, 1)) == before
    assert alice.put("/api/admin/aws/1", json=account_input(account_number="member")).status_code == 403
    view = alice.get("/api/accounts").json()[0]
    assert view["account_number"] == "ab19" and view["aws_account_id"] == "123456789012"
    assert view["proxy_name"] is None and view["proxy_status"] == "direct"
    assert not set(view) & {"credentials_encrypted", "proxy_id", "identity_store_id", "application_arn"}


@pytest.mark.parametrize("number", ["abc-def", "a_1", "中文", "Ａ", "a" * 25, "ß", "ab c"])
def test_invalid_numbers_are_rejected(admin, remote, number):
    assert admin.put("/api/admin/aws/1", json=account_input(account_number=number)).status_code == 422


def test_number_registry_never_releases_and_own_reuse(admin, remote):
    second = duplicate_account()
    for value in ("a", "123", "", "a"):
        result = admin.put("/api/admin/aws/1", json=account_input(account_number=value))
        assert result.status_code == 200, result.text
        assert result.json()["account_number"] == (value or None)
    for value in ("a", "123"):
        result = admin.put(f"/api/admin/aws/{second}", json=account_input(second, account_number=value))
        assert result.status_code == 409, result.text
    assert admin.request("DELETE", "/api/admin/aws/1", json={"confirm_name": "测试 AWS"}).status_code == 200
    assert admin.put(f"/api/admin/aws/{second}", json=account_input(second, account_number="a")).status_code == 409


def test_preview_and_admission_freeze_numbered_intent_only(alice, ready):
    body = intent(quantity=2)
    p = preview(alice, body)
    assert p["accounts"][0]["next_batch_number"] == "a-01"
    assert p["totals"][0]["needed_count"] == 2
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(models.ProvisioningBatch)) == 0
        assert db.scalar(select(func.count()).select_from(models.ProvisioningCounter)) == 0
    result = admit(alice, body, preflight=p)
    assert result.status_code == 202, result.text
    parent = result.json()
    assert parent["state"] == "queued" and parent["phase"] == "admitted"
    row = parent["accounts"][0]
    assert row["batch_number"] == "a-01" and row["group"]["name"] == "a-01"
    assert [i["internal_id"] for i in row["items"]] == ["a-01-01", "a-01-02"]
    assert [i["position"] for i in row["items"]] == [1, 2]
    assert len({i["record_id"] for i in row["items"]}) == 2
    assert all(i["username"] == i["internal_id"] and i["email"].startswith(i["username"] + "@") for i in row["items"])
    assert row["exports"] == body["accounts"][0]["exports"]
    assert alice.get("/api/provisioning-batches/" + parent["id"]).json() == parent
    assert alice.get("/api/provisioning-batches").json()["items"][0]["id"] == parent["id"]
    with SessionLocal() as db:
        for model in (models.Subscription, models.GroupJob, models.ManagedGroup, models.NativeGroupOperation, models.NativeGroupGrant):
            assert db.scalar(select(func.count()).select_from(model)) == 0
        assert db.get(models.PlanCounter, 1).pending_count == 0
        batch = db.get(models.ProvisioningBatch, parent["id"])
        assert batch.actor_role == "member" and batch.session_version == 1


def test_replay_conflict_rename_and_failed_sequences(alice, admin, ready):
    body = intent()
    p = preview(alice, body)
    first = admit(alice, body, preflight=p)
    assert first.status_code == 202, first.text
    first = first.json()
    ready.calls.clear()
    again = admit(alice, body, preflight=p)
    assert again.json() == first and ready.calls == []
    conflict = admit(alice, intent(quantity=2), preflight=p)
    assert conflict.status_code == 409 and ready.calls == []
    with SessionLocal() as db:
        db.get(models.ProvisioningBatch, first["id"]).state = "failed"
        db.commit()
    assert admin.put("/api/admin/aws/1", json=account_input(account_number="z")).status_code == 200
    second = admit(alice, body, key="numbered-request-0002")
    assert second.status_code == 202, second.text
    assert second.json()["accounts"][0]["batch_number"] == "z-02"
    assert alice.get("/api/provisioning-batches/" + first["id"]).json()["accounts"][0]["batch_number"] == "a-01"


def test_numbered_username_collision_rolls_back_admission(alice, ready):
    with SessionLocal() as db:
        db.add(models.Subscription(id="manual-number-collision", owner_id=2, aws_account_id=1,
            request_key="manual-existing-user", username="a-01-01", email="a@example.com",
            state="completed", step="sso_ready", reserved=False, provision_only=True,
            portal_url=db.get(models.AwsAccount, 1).portal_url))
        db.commit()
    result = admit(alice, intent())
    assert result.status_code == 409, result.text
    assert "用户名" in result.json()["detail"]
    with SessionLocal() as db:
        for model in (models.ProvisioningBatch, models.ProvisioningAccountBatch,
                      models.ProvisioningItem, models.ProvisioningCounter):
            assert db.scalar(select(func.count()).select_from(model)) == 0


def test_replayed_legacy_numbered_usernames_are_unchanged(alice, ready):
    body = intent()
    first = admit(alice, body).json()
    with SessionLocal() as db:
        db.get(models.ProvisioningItem, first["accounts"][0]["items"][0]["record_id"]).username = "legacy-random-user"
        db.commit()
    replayed = admit(alice, body, preflight={"preview_fingerprint": "0" * 64})
    assert replayed.status_code == 202, replayed.text
    assert replayed.json()["accounts"][0]["items"][0]["username"] == "legacy-random-user"


def test_distinct_actors_can_concurrently_admit_same_preview_counter(alice, bob, ready):
    body = intent()
    pa, pb = preview(alice, body), preview(bob, body)
    barrier = Barrier(2)
    ready.change = lambda account: barrier.wait(timeout=10)
    with ThreadPoolExecutor(max_workers=2) as pool:
        fa = pool.submit(admit, alice, body, "concurrent-alice-01", pa)
        fb = pool.submit(admit, bob, body, "concurrent-bob-0001", pb)
        results = [fa.result(timeout=15), fb.result(timeout=15)]
    assert [r.status_code for r in results] == [202, 202], [r.text for r in results]
    assert {r.json()["accounts"][0]["batch_number"] for r in results} == {"a-01", "a-02"}


def test_all_rows_atomic_independent_counters_and_plan_totals(alice, admin, ready):
    second = duplicate_account()
    assert admin.put(f"/api/admin/aws/{second}", json=account_input(second, account_number="b")).status_code == 200
    body = intent()
    body["accounts"] += intent(second)["accounts"]
    p = preview(alice, body)
    assert p["totals"][0]["needed_count"] == 2
    with SessionLocal() as db:
        db.get(models.PlanCounter, 1).limit_count = 1
        db.commit()
    refused = admit(alice, body, preflight=p)
    assert refused.status_code == 409, refused.text
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(models.ProvisioningCounter)) == 0
        assert db.scalar(select(func.count()).select_from(models.ProvisioningBatch)) == 0
        db.get(models.PlanCounter, 1).limit_count = 2
        db.commit()
    result = admit(alice, body)
    assert result.status_code == 202, result.text
    assert [row["batch_number"] for row in result.json()["accounts"]] == ["a-01", "b-01"]
    over = intent(quantity=2)
    over["accounts"] += intent(second)["accounts"]
    assert alice.post("/api/provisioning-batches/preview", json=over).status_code == 409


@pytest.mark.parametrize("bad", ["zero", "too_many", "duplicate", "account_cap", "extra", "new_overwrite", "group_extra", "bad_fingerprint"])
def test_request_limits_are_enforced(alice, ready, bad):
    body = intent()
    path = "/api/provisioning-batches/preview"
    if bad == "zero":
        body["accounts"][0]["quantity"] = 0
    elif bad == "too_many":
        body["accounts"][0]["quantity"] = 101
    elif bad == "duplicate":
        body["accounts"] *= 2
    elif bad == "account_cap":
        body["accounts"] = [intent(i)["accounts"][0] for i in range(1, 102)]
    elif bad == "extra":
        body["accounts"][0]["role"] = "admin"
    elif bad == "new_overwrite":
        body["accounts"][0]["overwrite_individual"] = True
    elif bad == "group_extra":
        body["accounts"][0]["group"]["group_id"] = "unexpected"
    else:
        path = "/api/provisioning-batches"
        body |= {"request_key": "numbered-request-0001", "preview_fingerprint": "not-sha256"}
    assert alice.post(path, json=body).status_code == 422


@pytest.mark.parametrize("change", ["number", "proxy", "proxy_credentials", "credentials", "region", "binding", "role", "session", "active", "deleted"])
def test_remote_read_releases_writer_and_rechecks_scope(alice, ready, change):
    body = intent()
    p = preview(alice, body)
    def mutate(frozen):
        assert frozen._proxy_selection and frozen._proxy_selection.url.startswith("socks5h://")
        assert not hasattr(frozen, "_sa_instance_state")
        with SessionLocal() as db:
            account = db.get(models.AwsAccount, 1)
            if change == "number": account.account_number = "z"
            elif change == "proxy": db.get(models.Proxy, account.proxy_id).enabled = False
            elif change == "proxy_credentials": db.get(models.Proxy, account.proxy_id).auth_encrypted = encrypt({"username": "changed", "password": "changed"})
            elif change == "credentials": account.credentials_encrypted = encrypt({"access_key_id": "new", "secret_access_key": "new"})
            elif change == "region": account.region = "eu-central-1"
            elif change == "binding": db.delete(db.get(models.Binding, (2, 1)))
            elif change == "role": db.get(models.User, 2).role = "admin"
            elif change == "session": db.get(models.User, 2).session_version += 1
            elif change == "active": account.active = False
            else: account.deleted_at = models.now()
            db.commit()
        # The remote call continues using its original frozen fields.
        assert frozen.region == "us-east-1"
    ready.change = mutate
    refused = admit(alice, body, preflight=p)
    assert refused.status_code in (401, 403, 409), refused.text
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(models.ProvisioningBatch)) == 0


def seed_group(*, owner=2, member_count=1, grant=False):
    with SessionLocal() as db:
        group = models.ManagedGroup(id="target", owner_id=owner, aws_account_id=1,
            aws_scope="123456789012:d-1234567890", remote_id="remote-target", name="Existing name",
            marker="marker", request_key="seed-group", payload_hash="seed", state="ready")
        db.add(group)
        db.flush()
        for i in range(member_count):
            db.add(models.Subscription(id=f"member-{i}", owner_id=owner, aws_account_id=1,
                request_key=f"member-{i}", username=f"member-{i}", email=f"m{i}@example.com",
                portal_url="https://example.com", sso_user_id=f"sso-{i}", group_id=group.id,
                group_membership_id=f"membership-{i}", state="completed", reserved=False,
                provision_only=True, subscription_status="active" if grant else "not_subscribed"))
        if grant:
            db.add(models.NativeGroupGrant(id="grant", group_id="target", owner_id=owner,
                aws_account_id=1, plan_id=1, plan_name="Kiro Pro", subscription_type="Q_DEVELOPER_STANDALONE_PRO",
                state="active", activated_at=models.now()))
            db.flush()
            for i in range(member_count):
                db.add(models.GroupMemberActivation(id=f"activation-{i}", grant_id="grant", record_id=f"member-{i}",
                    owner_id=owner, actor_id=owner, plan_id=1, plan_name="Kiro Pro",
                    subscription_type="Q_DEVELOPER_STANDALONE_PRO", request_key=f"seed-{i}", operation_id="seed",
                    counted=True, reserved=False, state="active", config_hash="seed", activated_at=models.now()))
        db.commit()
    Gateway.members = [{"id": f"membership-{i}", "user_id": f"sso-{i}"} for i in range(member_count)]
    if grant:
        Gateway.claims = [{"principal": {"group": "remote-target"}, "type": {"amazonQ": "KIRO_ENTERPRISE_PRO"},
            "applicationArn": account_input()["application_arn"], "createdBy": "123456789012"}]
    return intent(group={"mode": "existing", "group_id": "target", "expected_revision": 1, "expected_policy_revision": 0})


@pytest.mark.parametrize("grant,needed", [(False, 2), (True, 1)])
def test_existing_group_uses_real_owned_members_and_compatible_active_grant(alice, ready, grant, needed):
    body = seed_group(grant=grant)
    p = preview(alice, body)
    row = p["accounts"][0]
    assert row["needed_count"] == needed and row["existing_member_count"] == 1
    assert row["group"]["name"] == "Existing name"
    result = admit(alice, body, preflight=p)
    assert result.status_code == 202, result.text
    assert result.json()["accounts"][0]["group"]["name"] == "Existing name"


@pytest.mark.parametrize("bad", ["unowned", "other_account", "deleted", "revision", "policy_revision", "unknown", "pending", "different", "unmanaged", "unsettled", "member_drift", "too_many"])
def test_existing_group_rejects_unsafe_states(alice, admin, ready, bad):
    body = seed_group(grant=bad in ("unknown", "pending", "different", "unsettled"), member_count=101 if bad == "too_many" else 1)
    with SessionLocal() as db:
        group = db.get(models.ManagedGroup, "target")
        if bad == "unowned": group.owner_id = 3
        elif bad == "other_account": group.aws_account_id = duplicate_account()
        elif bad == "deleted": group.deleted_at = models.now()
        elif bad == "revision": group.revision += 1
        elif bad == "policy_revision": group.policy_revision += 1
        elif bad == "unknown": ready.claims[0]["type"] = {"amazonQ": "UNKNOWN"}
        elif bad == "pending": ready.claims[0]["newType"] = {"amazonQ": "KIRO_ENTERPRISE_PRO_PLUS"}
        elif bad == "different": ready.claims[0]["type"] = {"amazonQ": "KIRO_ENTERPRISE_PRO_PLUS"}
        elif bad == "unmanaged": ready.claims = [{"principal": {"group": "remote-target"}, "type": {"amazonQ": "KIRO_ENTERPRISE_PRO"}, "applicationArn": account_input()["application_arn"], "createdBy": "123456789012"}]
        elif bad == "unsettled": db.get(models.NativeGroupGrant, "grant").state = "needs_review"
        elif bad == "member_drift": ready.members.append({"id": "foreign", "user_id": "foreign"})
        db.commit()
    result = (admin if bad == "unowned" else alice).post("/api/provisioning-batches/preview", json=body)
    assert result.status_code in (404, 409), result.text


def test_policy_inheritance_explicit_clear_and_overwrite_preview(alice, ready):
    body = seed_group()
    with SessionLocal() as db:
        group = db.get(models.ManagedGroup, "target")
        group.policy_mode, group.policy_days = "days", 30
        db.add(models.StopSchedule(record_id="member-0", actor_id=2, mode="days", days=10,
                                  state="waiting", individual_override=True))
        db.commit()
    p = preview(alice, body)
    assert p["accounts"][0]["stop_policy"]["days"] == 30
    assert p["accounts"][0]["policy_change"] is None
    body["accounts"][0]["stop_policy"] = {"mode": "none"}
    clear = preview(alice, body)
    assert clear["preview_fingerprint"] != p["preview_fingerprint"]
    assert clear["accounts"][0]["policy_change"]["skipped_count"] == 1
    body["accounts"][0]["overwrite_individual"] = True
    overwrite = preview(alice, body)
    assert overwrite["accounts"][0]["policy_change"]["affected_count"] == 1
    with SessionLocal() as db:
        assert db.get(models.ManagedGroup, "target").policy_mode == "days"


@pytest.mark.parametrize("state", ["completed", "scheduled", "needs_review"])
def test_active_group_join_distinguishes_completed_user_deadline_from_live_rule(alice, ready, state):
    body = seed_group(grant=True)
    past = models.now() - timedelta(days=1)
    with SessionLocal() as db:
        db.add(models.StopSchedule(record_id="member-0", actor_id=2, principal_type="USER",
            individual_override=True, mode="at", stop_at=past, state=state,
            completed_at=past if state == "completed" else None))
        db.commit()
    response = alice.post("/api/provisioning-batches/preview", json=body)
    if state == "completed":
        assert response.status_code == 200, response.text
        result = admit(alice, body, preflight=response.json())
        assert result.status_code == 202, result.text
        assert result.json()["accounts"][0]["needed_count"] == 1
    else:
        assert response.status_code == 409, response.text
        assert "停止时间已到" in response.json()["detail"]
        assert ready.calls == []
    with SessionLocal() as db:
        schedule = db.get(models.StopSchedule, "member-0")
        assert (schedule.state, schedule.principal_type, schedule.stop_at) == (state, "USER", past)
        assert db.get(models.NativeGroupGrant, "grant").state == "active"
        assert db.get(models.GroupMemberActivation, "activation-0").state == "active"
        assert db.get(models.Subscription, "member-0").subscription_status == "active"
        assert db.scalar(select(func.count()).select_from(models.ProvisioningBatch)) == (state == "completed")


@pytest.mark.parametrize("source,change,overwrite,accepted", [
    ("inherited", False, False, False),
    ("inherited", True, False, True),
    ("individual", True, False, False),
    ("individual", True, True, True),
    ("legacy_individual", True, False, False),
    ("legacy_individual", True, True, True),
    ("historical", True, True, False),
])
def test_expired_member_deadline_uses_effective_shared_policy_change(alice, ready, source, change, overwrite, accepted):
    body = seed_group()
    past = models.now() - timedelta(days=1)
    with SessionLocal() as db:
        group = db.get(models.ManagedGroup, "target")
        group.policy_mode, group.policy_stop_at = "at", past
        if source == "historical":
            db.get(models.Subscription, "member-0").cancelled_at = past
        db.add(models.StopSchedule(record_id="member-0", actor_id=2, mode="at", state="waiting",
            source_group_id=None if source == "legacy_individual" else "target", source_group_revision=0,
            individual_override=source == "individual", stop_at=past))
        db.commit()
    shared = None
    if change:
        row = body["accounts"][0]
        row["stop_policy"], row["overwrite_individual"] = {"mode": "none"}, overwrite
        response = alice.post("/api/groups/target/policy/preview", json={
            "expected_revision": 0, "policy": row["stop_policy"], "overwrite_individual": overwrite,
        })
        assert response.status_code == 200, response.text
        shared = response.json()
        assert shared["affected_count"] == int(accepted)
        assert shared["skipped_count"] == int(not accepted)
        assert shared["conflict_count"] == 0
    response = alice.post("/api/provisioning-batches/preview", json=body)
    if accepted:
        assert response.status_code == 200, response.text
        row = response.json()["accounts"][0]
        assert row["policy_change"] == shared and row["stop_policy"]["mode"] == "none"
        result = admit(alice, body, preflight=response.json())
        assert result.status_code == 202, result.text
        assert result.json()["accounts"][0]["needed_count"] == 2
    else:
        assert response.status_code in (409, 422), response.text
        assert ready.calls == []
    with SessionLocal() as db:
        # Preview and admission freeze the intended clear without applying it.
        group = db.get(models.ManagedGroup, "target")
        assert (group.policy_mode, group.policy_stop_at, group.policy_revision) == ("at", past, 0)
        schedule = db.get(models.StopSchedule, "member-0")
        assert (schedule.mode, schedule.stop_at, schedule.state) == ("at", past, "waiting")
        assert db.scalar(select(func.count()).select_from(models.ProvisioningBatch)) == accepted
        if accepted:
            snapshot = json.loads(db.scalar(select(models.ProvisioningAccountBatch)).snapshot)
            assert snapshot["members"][0]["schedule"]["mode"] == "at"
            assert snapshot["members"][0]["schedule"]["state"] == "waiting"
            assert snapshot["stop_policy"]["mode"] == "none"


@pytest.mark.parametrize("field", ["group", "policy", "member", "grant", "schedule"])
def test_existing_group_scope_changes_during_remote_reads_reject(alice, ready, field):
    body = seed_group(grant=True)
    p = preview(alice, body)
    def mutate(_):
        with SessionLocal() as db:
            if field == "group": db.get(models.ManagedGroup, "target").revision += 1
            elif field == "policy": db.get(models.ManagedGroup, "target").policy_revision += 1
            elif field == "member": db.get(models.Subscription, "member-0").group_membership_id = "changed"
            elif field == "grant": db.get(models.NativeGroupGrant, "grant").state = "needs_review"
            else: db.add(models.StopSchedule(record_id="member-0", actor_id=2, mode="none", state="disabled"))
            db.commit()
    ready.change = mutate
    assert admit(alice, body, preflight=p).status_code == 409


def test_history_scopes_all_accounts_and_fences_mutations(alice, bob, admin, ready):
    body = seed_group(member_count=0)
    accepted = admit(alice, body)
    assert accepted.status_code == 202, accepted.text
    batch_id = accepted.json()["id"]
    assert bob.get("/api/provisioning-batches/" + batch_id).status_code == 404
    assert bob.get("/api/provisioning-batches").json()["total"] == 0
    assert admin.get("/api/provisioning-batches/" + batch_id).status_code == 200
    assert admin.patch("/api/admin/users/2", json={"role": "admin"}).status_code == 409
    assert admin.put("/api/admin/users/2/bindings", json={"account_ids": []}).status_code == 409
    assert alice.post("/api/groups/target/jobs", json={"kind": "delete", "expected_revision": 1, "request_key": "delete-target-0001"}).status_code == 409
    assert admin.patch("/api/admin/users/2", json={"active": False}).status_code == 200
    assert admin.delete("/api/admin/users/2").status_code == 409
    with SessionLocal() as db:
        db.get(models.User, 2).active = True
        db.get(models.User, 2).session_version = 1
        db.delete(db.get(models.Binding, (2, 1)))
        db.commit()
    assert alice.get("/api/provisioning-batches/" + batch_id).status_code == 403
    assert alice.get("/api/provisioning-batches").json()["total"] == 0
    assert admin.request("DELETE", "/api/admin/aws/1", json={"confirm_name": "测试 AWS"}).status_code == 200
    retained = admin.get("/api/provisioning-batches/" + batch_id).json()
    assert retained["accounts"][0]["account_deleted_at"]


def test_number_only_edit_remains_available_with_disabled_proxy(admin, ready):
    with SessionLocal() as db:
        account = db.get(models.AwsAccount, 1)
        db.get(models.Proxy, account.proxy_id).enabled = False
        db.commit()
    ready.calls.clear()
    result = admin.put("/api/admin/aws/1", json=account_input(account_number="renumbered"))
    assert result.status_code == 200, result.text
    assert result.json()["account_number"] == "renumbered" and ready.calls == []


def test_account_create_accepts_number_and_rejects_historical_conflicts(admin, remote):
    body = account_input(name="Numbered create", account_number="ABC", access_key_id="a" * 20, secret_access_key="s" * 30)
    result = admin.post("/api/admin/aws", json=body)
    assert result.status_code == 201, result.text
    assert result.json()["account_number"] == "abc"
    result = admin.post("/api/admin/aws", json=body | {"name": "Conflicting create", "account_number": "abc"})
    assert result.status_code == 409, result.text
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(models.AwsAccount)) == 2


@pytest.mark.parametrize("bad", ["direct", "disabled", "bad_auth", "missing_number", "inactive_plan", "unknown_plan"])
def test_prerequisites_fail_before_aws(alice, ready, bad):
    with SessionLocal() as db:
        account = db.get(models.AwsAccount, 1)
        if bad == "direct": account.proxy_id = None
        elif bad == "disabled": db.get(models.Proxy, account.proxy_id).enabled = False
        elif bad == "bad_auth": db.get(models.Proxy, account.proxy_id).auth_encrypted = "invalid"
        elif bad == "missing_number": account.account_number = None
        elif bad == "inactive_plan": db.get(models.Plan, 1).active = False
        else: db.get(models.Plan, 1).subscription_type = "UNKNOWN"
        db.commit()
    result = alice.post("/api/provisioning-batches/preview", json=intent())
    assert result.status_code in (404, 409), result.text
    if bad in ("direct", "disabled", "bad_auth"):
        assert result.json()["detail"] == "请先绑定可用代理"
    assert ready.calls == []


def test_failure_during_second_row_allocation_rolls_back_every_intent_and_counter(alice, admin, ready, monkeypatch):
    from fastapi import HTTPException
    from app import provisioning_batches
    second = duplicate_account()
    assert admin.put(f"/api/admin/aws/{second}", json=account_input(second, account_number="b")).status_code == 200
    body = intent()
    body["accounts"] += intent(second)["accounts"]
    p = preview(alice, body)
    original = provisioning_batches.generated_email
    count = 0
    def interrupted(username):
        nonlocal count
        count += 1
        if count == 2:
            raise HTTPException(409, "Simulated local allocation failure")
        return original(username)
    monkeypatch.setattr(provisioning_batches, "generated_email", interrupted)
    result = admit(alice, body, preflight=p)
    assert result.status_code == 409, result.text
    with SessionLocal() as db:
        for model in (models.ProvisioningBatch, models.ProvisioningAccountBatch, models.ProvisioningCounter, models.ProvisioningItem):
            assert db.scalar(select(func.count()).select_from(model)) == 0
        assert db.get(models.PlanCounter, 1).pending_count == 0


def test_concurrent_same_key_replays_one_atomic_intent(alice, ready):
    body = intent()
    p = preview(alice, body)
    barrier = Barrier(2)
    ready.change = lambda _: barrier.wait(timeout=10)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(admit, alice, body, "concurrent-same-001", p) for _ in range(2)]
        results = [f.result(timeout=15) for f in futures]
    assert [r.status_code for r in results] == [202, 202], [r.text for r in results]
    assert results[0].json() == results[1].json()
    with SessionLocal() as db:
        assert db.get(models.ProvisioningCounter, 1).last_sequence == 1
        assert db.scalar(select(func.count()).select_from(models.ProvisioningBatch)) == 1


def test_list_filters_and_full_scope_for_multi_account_history(alice, admin, ready):
    second = duplicate_account()
    assert admin.put(f"/api/admin/aws/{second}", json=account_input(second, account_number="b")).status_code == 200
    body = intent()
    body["accounts"] += intent(second)["accounts"]
    result = admit(alice, body)
    assert result.status_code == 202, result.text
    data = result.json()
    item = data["accounts"][0]["items"][0]
    for params in ({"q": "a-01"}, {"q": item["internal_id"]}, {"q": item["username"]},
                   {"aws_account_id": second}, {"state": "queued"},
                   {"created_from": "2020-01-01T00:00:00Z", "created_to": "2099-01-01T00:00:00Z"}):
        result = alice.get("/api/provisioning-batches", params=params)
        assert result.status_code == 200 and result.json()["total"] == 1, result.text
        assert result.headers["Cache-Control"] == "no-store"
        assert all(secret not in result.text for secret in ("credentials_encrypted", "secret-password", "socks5h", "config_hash"))
    assert alice.get("/api/provisioning-batches", params={"state": "completed"}).json()["total"] == 0
    with SessionLocal() as db:
        db.delete(db.get(models.Binding, (2, second)))
        db.commit()
    assert alice.get("/api/provisioning-batches", params={"aws_account_id": 1}).json()["total"] == 0
    assert alice.get("/api/provisioning-batches/" + data["id"]).status_code == 403
    assert admin.get("/api/provisioning-batches/" + data["id"]).status_code == 200


def test_padding_grows_and_100_new_items_are_frozen_once(admin, ready):
    with SessionLocal() as db:
        db.add(models.ProvisioningCounter(aws_account_id=1, last_sequence=99))
        db.commit()
    body = intent(quantity=100)
    p = preview(admin, body)
    result = admit(admin, body, preflight=p)
    assert result.status_code == 202, result.text
    row = result.json()["accounts"][0]
    assert row["batch_number"] == "a-100" and row["items"][-1]["internal_id"] == "a-100-100"
    assert len({i["username"] for i in row["items"]}) == 100
    assert admit(admin, body, preflight=p).json() == result.json()


def test_new_omitted_policy_is_canonical_none_and_existing_inherit_is_distinct(alice, ready):
    body = intent()
    omitted = preview(alice, body)
    body["accounts"][0]["stop_policy"] = {"mode": "none"}
    explicit = preview(alice, body)
    assert omitted["preview_fingerprint"] == explicit["preview_fingerprint"]
    body = seed_group(member_count=0)
    omitted = preview(alice, body)
    body["accounts"][0]["stop_policy"] = {"mode": "none"}
    assert preview(alice, body)["preview_fingerprint"] != omitted["preview_fingerprint"]


@pytest.mark.parametrize("bad", ["activation_owner", "activation_plan", "inactive_member", "duplicate_grant", "missing_activation_time"])
def test_active_group_requires_consistent_settled_ledger(alice, ready, bad):
    body = seed_group(grant=True)
    with SessionLocal() as db:
        activation = db.get(models.GroupMemberActivation, "activation-0")
        if bad == "activation_owner": activation.owner_id = 3
        elif bad == "activation_plan": activation.plan_id = 2
        elif bad == "inactive_member": db.get(models.Subscription, "member-0").subscription_status = "cancelled"
        elif bad == "missing_activation_time": db.get(models.NativeGroupGrant, "grant").activated_at = None
        else:
            row = db.get(models.NativeGroupGrant, "grant")
            values = {column.name: getattr(row, column.name) for column in row.__table__.columns if column.name != "id"}
            db.add(models.NativeGroupGrant(id="duplicate-grant", **values))
        db.commit()
    result = alice.post("/api/provisioning-batches/preview", json=body)
    assert result.status_code == 409, result.text


def test_remote_order_and_query_time_are_not_stale_preview_inputs(alice, admin, ready):
    body = seed_group(member_count=2)
    p = preview(admin, intent())  # Separate new-group intent never touches the existing group.
    assert p["accounts"][0]["next_batch_number"] == "a-01"
    with SessionLocal() as db:
        db.get(models.PlanCounter, 1).limit_count = 3
        db.commit()
    p = preview(alice, body)
    ready.members.reverse()
    assert preview(alice, body)["preview_fingerprint"] == p["preview_fingerprint"]
    assert admit(alice, body, preflight=p).status_code == 202


@pytest.mark.parametrize("case,allowed", [("expired", True), ("future", False),
    ("unsettled_local", False), ("expired_unknown", False), ("pending_change", False)])
def test_expired_cancellation_is_reopenable_only_after_access_and_ledger_settle(alice, ready, case, allowed):
    body = seed_group(grant=True)
    boundary = models.now() + timedelta(days=1 if case == "future" else -1)
    ready.claims[0]["expirationDate"] = boundary.isoformat() + "Z"
    if case == "expired_unknown": ready.claims[0]["type"] = {"amazonQ": "UNKNOWN"}
    if case == "pending_change": ready.claims[0]["newType"] = {"amazonQ": "KIRO_ENTERPRISE_PRO_PLUS"}
    if case != "unsettled_local":
        with SessionLocal() as db:
            db.get(models.NativeGroupGrant, "grant").state = "cancelled"
            db.get(models.GroupMemberActivation, "activation-0").state = "cancelled"
            db.get(models.Subscription, "member-0").subscription_status = "cancelled"
            db.commit()
    result = alice.post("/api/provisioning-batches/preview", json=body)
    assert result.status_code == (200 if allowed else 409), result.text
    if allowed:
        assert result.json()["totals"][0]["needed_count"] == 2
        accepted = admit(alice, body, preflight=result.json())
        assert accepted.status_code == 202, accepted.text
        with SessionLocal() as db:
            child = db.get(models.ProvisioningAccountBatch, accepted.json()["accounts"][0]["id"])
            observed = json.loads(child.snapshot)["remote"]["subscription"]
            assert observed["status"] == "Canceled" and observed["access_active"] is False
            assert observed["cancellation_expires_at"] == boundary.isoformat() + "Z"
