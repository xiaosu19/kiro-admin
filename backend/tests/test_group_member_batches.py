"""Durable membership coordination, using only synthetic AWS state."""

import concurrent.futures
import json
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import inspect, select

from app.aws import AwsFailure
from app.database import SessionLocal, engine
from app.group_jobs import claim_group_job, run_group_job
from app.models import (
    AwsAccount, Binding, GroupJob, ManagedGroup, PlanCounter, Proxy,
    StopSchedule, Subscription, User, now,
)
from app.security import encrypt
from test_native_groups import NativeGateway, counter, native, run_native, seed_group, subscribe


def standalone(rid, *, owner=2, account=1, subscribed=False):
    with SessionLocal() as db:
        db.add(Subscription(
            id=rid, owner_id=owner, aws_account_id=account, request_key=rid,
            username=rid, email=rid + "@example.com", portal_url="https://example.com",
            state="completed", step="sso_ready", provision_only=True, reserved=False,
            sso_user_id="sso-" + rid, counted=subscribed,
            plan_id=1 if subscribed else None,
            subscription_type="Q_DEVELOPER_STANDALONE_PRO" if subscribed else None,
            subscription_status="active" if subscribed else "not_subscribed",
        ))
        db.commit()


def prepare(alice, *, paid=False, count=3):
    seed_group(0)
    if paid:
        response = subscribe(alice)
        assert response.status_code == 202, response.text
        assert run_native()
    ids = [f"candidate-{i:03}" for i in range(count)]
    for rid in ids:
        standalone(rid)
    return ids


def submit(client, ids, **extra):
    return client.post("/api/groups/group-1/member-batches", json={
        "kind": "attach", "record_ids": ids, "expected_revision": 1,
        "request_key": str(uuid.uuid4()), **extra,
    })


def admitted(client, ids, **extra):
    response = submit(client, ids, **extra)
    assert response.status_code == 202, response.text
    return response.json()


def route(batch, action=""):
    return f"/api/groups/group-1/member-batches/{batch['id']}" + ("/" + action if action else "")


def get_batch(client, batch):
    response = client.get(route(batch))
    assert response.status_code == 200, response.text
    return response.json()


def operation_projections(client, rid):
    for path, field in (
        (f"/api/subscriptions/{rid}", None),
        ("/api/subscriptions", "items"),
        ("/api/sso-users", "items"),
        ("/api/groups/group-1", "members"),
    ):
        response = client.get(path)
        assert response.status_code == 200, response.text
        value = response.json()
        yield next(item for item in value[field] if item["id"] == rid) if field else value


def full_schedule(rid):
    with SessionLocal() as db:
        s = db.get(StopSchedule, rid)
        return {c.name: getattr(s, c.name) for c in StopSchedule.__table__.columns} if s else None


def test_atomic_scope_and_idempotent_canonical_admission(alice, bob, admin, native):
    ids = prepare(alice)
    standalone("foreign", owner=3)
    key = str(uuid.uuid4())
    assert submit(alice, ids[:1] + ["foreign"], request_key=key).status_code == 404
    assert submit(admin, ids[:1] + ["foreign"], request_key=key).status_code == 409
    with SessionLocal() as db:
        assert not list(db.scalars(select(GroupJob)))
        assert db.get(Subscription, ids[0]).group_id is None
    first = admitted(alice, [ids[1], ids[0], ids[0]], request_key=key)
    assert first["record_ids"] == ids[:2]
    assert first["counts"]["total"] == 2
    assert [i["state"] for i in first["items"]] == ["queued", "waiting"]
    assert submit(alice, ids[:2], request_key=key).json()["id"] == first["id"]
    assert submit(alice, ids, request_key=key).status_code == 409
    assert submit(alice, ids[:2], expected_revision=2, request_key=key).status_code == 409
    assert bob.get(route(first)).status_code == 404
    assert bob.post(route(first, "stop")).status_code == 404


def test_all_ids_ready_and_initial_quota_reservations_are_atomic(alice, native):
    ids = prepare(alice, paid=True)
    assert submit(alice, ids).status_code == 409
    assert counter() == (0, 0, 0)
    with SessionLocal() as db:
        assert not list(db.scalars(select(GroupJob)))
        assert all(db.get(Subscription, rid).group_id is None for rid in ids)
        assert not list(db.scalars(select(StopSchedule)))
        db.get(Subscription, ids[1]).active_operation_id = "other-operation"
        db.commit()
    assert submit(alice, ids[:2]).status_code == 409
    assert counter() == (0, 0, 0)


def test_100_distinct_ids_and_restart_claim_serialization(alice, native):
    ids = prepare(alice, count=101)
    assert submit(alice, ids).status_code == 422
    batch = admitted(alice, list(reversed(ids[:100])) + ids[:2])
    assert batch["counts"]["total"] == 100
    first, token = claim_group_job()
    assert first == batch["items"][0]["job_id"]
    assert claim_group_job() is None
    with SessionLocal() as db:
        job = db.get(GroupJob, first)
        job.lease_until = now() - timedelta(seconds=1)
        db.commit()
    assert run_group_job(native)
    refreshed = get_batch(alice, batch)
    assert refreshed["counts"]["completed"] == 1
    assert refreshed["counts"]["queued"] == 1
    assert refreshed["counts"]["waiting"] == 98
    with SessionLocal() as db:
        assert db.get(ManagedGroup, "group-1").active_job_id == batch["items"][1]["job_id"]
    assert alice.post(route(batch, "stop")).status_code == 200


def test_same_transaction_advance_fences_other_group_operations(alice, native):
    ids = prepare(alice)
    batch = admitted(alice, ids)
    assert run_group_job(native)
    assert alice.post("/api/groups/group-1/jobs", json={
        "kind": "rename", "name": "interleave", "expected_revision": 1,
        "request_key": str(uuid.uuid4()),
    }).status_code == 409
    assert alice.put("/api/groups/group-1/policy", json={
        "policy": {"mode": "days", "days": 2}, "expected_revision": 0,
    }).status_code == 409
    assert run_group_job(native)
    assert run_group_job(native)
    assert not run_group_job(native)
    result = get_batch(alice, batch)
    assert result["state"] == "completed"
    assert result["counts"]["completed"] == 3
    with SessionLocal() as db:
        group = db.get(ManagedGroup, "group-1")
        assert (group.state, group.active_job_id) == ("ready", None)


def test_stop_restores_full_independent_user_schedule_and_releases_quota(alice, native):
    ids = prepare(alice, paid=True, count=2)
    with SessionLocal() as db:
        record = db.get(Subscription, ids[0])
        record.counted, record.plan_id, record.subscription_status = True, 1, "active"
        db.add(StopSchedule(
            record_id=ids[0], actor_id=2, revision=7, principal_type="USER",
            individual_override=False, mode="at", state="scheduled",
            stop_at=now() + timedelta(days=5), error="retained history",
            next_check_at=now() + timedelta(minutes=4), completed_at=now() - timedelta(days=1),
            created_at=now() - timedelta(days=8), updated_at=now() - timedelta(days=2),
        ))
        db.commit()
    before = full_schedule(ids[0])
    batch = admitted(alice, ids)
    assert counter() == (0, 2, 0)
    assert full_schedule(ids[0])["individual_override"] is True
    stopped = alice.post(route(batch, "stop"))
    assert stopped.status_code == 200, stopped.text
    assert stopped.json()["state"] == "stopped"
    assert stopped.json()["counts"]["stopped"] == 2
    assert counter() == (0, 0, 0)
    assert full_schedule(ids[0]) == before
    assert full_schedule(ids[1]) is None
    assert not run_group_job(native)
    assert alice.post(route(batch, "stop")).json() == stopped.json()
    assert alice.post(route(batch, "retry")).status_code == 409
    with SessionLocal() as db:
        for rid in ids:
            r = db.get(Subscription, rid)
            assert (r.group_id, r.group_membership_id, r.active_operation_id) == (None, None, None)


def test_stop_partial_preserves_confirmed_membership_and_paid_grant(alice, native):
    ids = prepare(alice, paid=True, count=2)
    batch = admitted(alice, ids)
    assert run_group_job(native)
    stopped = alice.post(route(batch, "stop")).json()
    assert stopped["state"] == "stopped"
    assert (stopped["counts"]["completed"], stopped["counts"]["stopped"]) == (1, 1)
    assert counter() == (1, 0, 1)
    assert native.members == {("remote-group-1", "sso-" + ids[0]): "member-sso-" + ids[0]}
    assert [w[0] for w in native.writes] == ["create", "attach"]


def test_uncertain_stop_preserves_intent_and_rechecks_without_resend(alice, native):
    ids = prepare(alice, paid=True, count=2)
    batch = admitted(alice, ids)
    native.uncertain = True
    assert run_group_job(native)
    assert not run_group_job(native)
    assert get_batch(alice, batch)["state"] == "needs_review"
    assert counter() == (0, 2, 0)
    stopped = alice.post(route(batch, "stop")).json()
    assert stopped["state"] == "needs_review" and stopped["stop_requested_at"]
    assert stopped["actions"] == {"recheck": True, "retry": False, "stop": False}
    assert counter() == (0, 1, 0)
    assert alice.post("/api/groups/group-1/retry").status_code == 409
    native.uncertain = False
    assert alice.post(route(batch, "recheck")).status_code == 202
    assert run_group_job(native)
    result = get_batch(alice, batch)
    assert result["state"] == "stopped"
    assert counter() == (1, 0, 1)
    assert [w[0] for w in native.writes].count("attach") == 1
    assert not run_group_job(native)


def test_unknown_absent_membership_never_blindly_resends(alice, native, monkeypatch):
    ids = prepare(alice, count=2)
    batch = admitted(alice, ids)
    def lost(*args):
        native.writes.append(("lost",))
        raise AwsFailure("response lost", uncertain=True)
    monkeypatch.setattr(native, "create_group_membership", lost)
    assert run_group_job(native)
    assert alice.post(route(batch, "recheck")).status_code == 202
    assert run_group_job(native)
    assert get_batch(alice, batch)["state"] == "needs_review"
    assert len(native.writes) == 1
    assert not run_group_job(native)


def test_expired_pending_lease_rechecks_once_then_resumes_next_child(alice, native):
    from app.group_jobs import checkpoint
    ids = prepare(alice, paid=True, count=2)
    batch = admitted(alice, ids)
    jid, token = claim_group_job()
    checkpoint(jid, token)
    # Remote accepted the write before the worker process died without recording it.
    native.members[("remote-group-1", "sso-" + ids[0])] = "recovered-member"
    with SessionLocal() as db:
        db.get(GroupJob, jid).lease_until = now() - timedelta(seconds=1)
        db.commit()
    assert run_group_job(native)
    assert [w[0] for w in native.writes].count("attach") == 0
    assert counter() == (1, 1, 1)
    assert run_group_job(native)
    assert get_batch(alice, batch)["state"] == "completed"
    assert [w[0] for w in native.writes].count("attach") == 1
    assert counter() == (2, 0, 2)


@pytest.mark.parametrize("paid", [False, True])
@pytest.mark.parametrize("drift", ["binding", "actor", "config", "owner", "record", "proxy"])
def test_dispatch_and_prewrite_revalidate_frozen_scope(alice, admin, native, monkeypatch, paid, drift):
    ids = prepare(alice, paid=paid, count=2)
    batch = admitted(alice, ids)
    original = native.get_group_membership
    changed = []
    def lookup(self, gid, uid):
        result = original(self, gid, uid)
        if not changed:
            changed.append(True)
            with SessionLocal() as db:
                if drift == "binding":
                    db.delete(db.get(Binding, (2, 1)))
                elif drift == "actor":
                    db.get(User, 2).session_version += 1
                elif drift == "config":
                    db.get(AwsAccount, 1).identity_store_id = "d-changed"
                elif drift == "owner":
                    db.get(ManagedGroup, "group-1").owner_id = 3
                elif drift == "record":
                    db.get(Subscription, ids[0]).owner_id = 3
                else:
                    p = Proxy(name="changed", host="127.0.0.1", port=1080, auth_encrypted=encrypt({"username": "", "password": ""}))
                    db.add(p)
                    db.flush()
                    db.get(AwsAccount, 1).proxy_id = p.id
                db.commit()
        return result
    monkeypatch.setattr(native, "get_group_membership", lookup)
    assert run_group_job(native)
    assert not any(w[0] == "attach" for w in native.writes)
    assert not run_group_job(native)
    with SessionLocal() as db:
        job = db.get(GroupJob, batch["items"][0]["job_id"])
        assert (job.state, job.phase) == ("failed", "ready")


def test_failed_join_stop_does_not_double_release_and_retry_restores_reservation(alice, native, monkeypatch):
    ids = prepare(alice, paid=True, count=2)
    batch = admitted(alice, ids)
    original = native.group_subscription_info
    monkeypatch.setattr(native, "group_subscription_info", lambda *args: {"status": "not_subscribed"})
    assert run_group_job(native)
    assert counter() == (0, 1, 0)
    assert get_batch(alice, batch)["actions"]["retry"]
    monkeypatch.setattr(native, "group_subscription_info", original)
    assert alice.post(route(batch, "retry")).status_code == 202
    assert counter() == (0, 2, 0)
    assert run_group_job(native)
    assert counter() == (1, 1, 1)
    assert alice.post(route(batch, "stop")).status_code == 200
    assert counter() == (1, 0, 1)


def test_failed_reservation_can_be_stopped_idempotently(alice, native, monkeypatch):
    ids = prepare(alice, paid=True, count=2)
    batch = admitted(alice, ids)
    monkeypatch.setattr(native, "group_subscription_info", lambda *args: {"status": "not_subscribed"})
    assert run_group_job(native)
    assert counter() == (0, 1, 0)
    assert alice.post(route(batch, "stop")).status_code == 200
    assert alice.post(route(batch, "stop")).status_code == 200
    assert counter() == (0, 0, 0)


def test_revoked_binding_blocks_all_ordinary_batch_access_but_admin_can_stop(alice, admin, native):
    ids = prepare(alice, count=2)
    key = str(uuid.uuid4())
    batch = admitted(alice, ids, request_key=key)
    assert admin.put("/api/admin/users/2/bindings", json={"account_ids": []}).status_code == 200
    for path in ("/api/groups/group-1/member-batches", route(batch),
                 "/api/groups/group-1/member-candidates"):
        assert alice.get(path).status_code == 403
        assert admin.get(path).status_code == 200
    for action in ("stop", "retry", "recheck"):
        assert alice.post(route(batch, action)).status_code == 403
    assert submit(alice, ids, request_key=key).status_code == 403
    assert admin.post(route(batch, "stop")).status_code == 200
    assert get_batch(admin, batch)["state"] == "stopped"
    assert not run_group_job(native)
    assert not native.writes


@pytest.mark.parametrize("scope_change", ["binding", "inactive"])
def test_legacy_batch_views_filter_current_scope_before_history_limit(alice, admin, native, scope_change):
    ids = prepare(alice, count=100)
    with SessionLocal() as db:
        for actor_id in (1, 2):
            db.add(GroupJob(
                id=f"legacy-history-{actor_id}", group_id="group-1", actor_id=actor_id,
                kind="rename", request_key=f"legacy-history-{actor_id}", payload="{}",
                state="completed", phase="done", created_at=now() - timedelta(days=1),
            ))
        db.commit()
    batch = admitted(alice, ids)
    child_ids = {item["job_id"] for item in batch["items"]}
    with SessionLocal() as db:
        if scope_change == "binding":
            db.delete(db.get(Binding, (2, 1)))
        else:
            db.get(AwsAccount, 1).active = False
        db.commit()
    assert alice.get(route(batch)).status_code == 403
    own_history = alice.get("/api/groups/group-1/jobs")
    assert own_history.status_code == 200, own_history.text
    assert [job["id"] for job in own_history.json()] == ["legacy-history-2"]
    admin_history = admin.get("/api/groups/group-1/jobs")
    assert admin_history.status_code == 200, admin_history.text
    assert {job["id"] for job in admin_history.json()} == child_ids
    # The most recently created member is present in every default first page.
    rid, job_id = ids[-1], batch["items"][-1]["job_id"]
    for value in operation_projections(alice, rid):
        assert value["operation"] is None
        assert value["operation_pending"] is True
    for value in operation_projections(admin, rid):
        assert value["operation"]["id"] == job_id


def test_admin_batch_operations_stay_private_in_legacy_and_viewerless_projections(alice, admin, native):
    from app.main import subscription_view
    ids = prepare(alice, count=2)
    batch = admitted(admin, ids)
    assert alice.get("/api/groups/group-1/jobs").json() == []
    assert len(admin.get("/api/groups/group-1/jobs").json()) == 2
    for value in operation_projections(alice, ids[0]):
        assert value["operation"] is None
        assert value["operation_pending"] is True
    for value in operation_projections(admin, ids[0]):
        assert value["operation"]["id"] == batch["items"][0]["job_id"]
    with SessionLocal() as db:
        value = subscription_view(db.get(Subscription, ids[0]), db)
    assert value["operation_pending"] is True
    assert value["operation"] is None


def test_original_batch_actor_sees_legacy_progress_after_admin_reauthorizes_child(alice, admin, native):
    from conftest import login
    ids = prepare(alice, count=2)
    batch = admitted(alice, ids)
    with SessionLocal() as db:
        db.get(User, 2).session_version += 1
        db.commit()
    assert run_group_job(native)
    assert admin.post(route(batch, "retry")).status_code == 202
    refreshed_alice = login("alice")
    assert get_batch(refreshed_alice, batch)["actor_id"] == 2
    with SessionLocal() as db:
        assert db.get(GroupJob, batch["items"][0]["job_id"]).actor_id == 1
    history = refreshed_alice.get("/api/groups/group-1/jobs")
    assert history.status_code == 200, history.text
    assert {job["id"] for job in history.json()} == {item["job_id"] for item in batch["items"]}
    for value in operation_projections(refreshed_alice, ids[0]):
        assert value["operation"]["id"] == batch["items"][0]["job_id"]


@pytest.mark.parametrize("initiator", ["alice", "admin"])
def test_nonbatch_legacy_jobs_keep_actor_visibility_after_binding_withdrawal(alice, admin, native, initiator):
    rid = prepare(alice, count=1)[0]
    client = alice if initiator == "alice" else admin
    response = client.post("/api/groups/group-1/jobs", json={
        "kind": "attach", "record_id": rid, "expected_revision": 1, "request_key": str(uuid.uuid4()),
    })
    assert response.status_code == 202, response.text
    job_id = response.json()["id"]
    assert admin.put("/api/admin/users/2/bindings", json={"account_ids": []}).status_code == 200
    for viewer, visible in ((alice, initiator == "alice"), (admin, True)):
        history = viewer.get("/api/groups/group-1/jobs")
        assert history.status_code == 200, history.text
        assert [job["id"] for job in history.json()] == ([job_id] if visible else [])
        for value in operation_projections(viewer, rid):
            assert value["operation_pending"] is True
            assert (value["operation"]["id"] if value["operation"] else None) == (job_id if visible else None)


@pytest.mark.parametrize("unavailable", ["inactive", "deleted"])
def test_admin_history_and_unsent_stop_allow_unavailable_aws_config(alice, admin, native, unavailable):
    ids = prepare(alice, paid=True, count=2)
    batch = admitted(alice, ids)
    with SessionLocal() as db:
        account = db.get(AwsAccount, 1)
        if unavailable == "inactive":
            account.active = False
        else:
            account.deleted_at = now()
        db.commit()
    assert alice.get(route(batch)).status_code == 403
    assert admin.get("/api/groups/group-1/member-batches").status_code == 200
    assert get_batch(admin, batch)["counts"]["waiting"] == 1
    assert admin.post(route(batch, "stop")).status_code == 200
    assert counter() == (0, 0, 0)
    assert get_batch(admin, batch)["state"] == "stopped"
    assert not run_group_job(native)
    assert [w[0] for w in native.writes] == ["create"]


def test_admin_recheck_with_withdrawn_owner_binding_is_read_only(alice, admin, native):
    ids = prepare(alice, paid=True, count=2)
    batch = admitted(alice, ids)
    native.uncertain = True
    assert run_group_job(native)
    assert admin.put("/api/admin/users/2/bindings", json={"account_ids": []}).status_code == 200
    assert alice.post(route(batch, "recheck")).status_code == 403
    native.uncertain = False
    assert admin.post(route(batch, "recheck")).status_code == 202
    assert run_group_job(native)
    assert run_group_job(native)
    result = get_batch(admin, batch)
    assert [item["state"] for item in result["items"]] == ["completed", "failed"]
    assert admin.post(route(batch, "retry")).status_code == 409
    assert admin.post(route(batch, "stop")).status_code == 200
    assert counter() == (1, 0, 1)
    assert [w[0] for w in native.writes] == ["create", "attach"]


def test_admin_retry_only_reauthorizes_active_failed_child(alice, admin, native):
    ids = prepare(alice, count=3)
    batch = admitted(alice, ids)
    with SessionLocal() as db:
        original_followers = [db.get(GroupJob, item["job_id"]).payload for item in batch["items"][1:]]
    changed = admin.patch("/api/admin/users/2", json={"password": "ChangedBatchPassword1!"})
    assert changed.status_code == 200, changed.text
    assert run_group_job(native)
    assert get_batch(admin, batch)["state"] == "failed"
    assert admin.post(route(batch, "retry")).status_code == 202
    with SessionLocal() as db:
        jobs = [db.get(GroupJob, item["job_id"]) for item in batch["items"]]
        assert [job.actor_id for job in jobs] == [1, 2, 2]
        assert [job.payload for job in jobs[1:]] == original_followers
    assert run_group_job(native)
    assert run_group_job(native)
    assert not run_group_job(native)
    result = get_batch(admin, batch)
    assert result["actor_id"] == 2
    assert [item["state"] for item in result["items"]] == ["completed", "failed", "waiting"]
    assert [w[0] for w in native.writes] == ["attach"]


def test_original_actor_retry_refreshes_all_own_remaining_sessions(alice, admin, native):
    from conftest import login
    ids = prepare(alice, count=3)
    batch = admitted(alice, ids)
    with SessionLocal() as db:
        db.get(User, 2).session_version += 1
        db.commit()
    assert run_group_job(native)
    assert get_batch(admin, batch)["state"] == "failed"
    refreshed_alice = login("alice")
    assert refreshed_alice.post(route(batch, "retry")).status_code == 202
    with SessionLocal() as db:
        jobs = [db.get(GroupJob, item["job_id"]) for item in batch["items"]]
        assert [job.actor_id for job in jobs] == [2, 2, 2]
        assert all(json.loads(job.payload)["member_context"]["actor_session_version"]
                   == db.get(User, 2).session_version for job in jobs)
    for _ in ids:
        assert run_group_job(native)
    assert not run_group_job(native)
    assert get_batch(refreshed_alice, batch)["state"] == "completed"
    assert [w[0] for w in native.writes] == ["attach", "attach", "attach"]


def test_admin_history_is_hidden_and_original_actor_survives_recovery(alice, admin, native, monkeypatch):
    ids = prepare(alice, count=2)
    private = admitted(admin, ids)
    assert alice.get(route(private)).status_code == 404
    assert alice.get("/api/groups/group-1/member-batches").json() == []
    for action in ("retry", "recheck", "stop"):
        assert alice.post(route(private, action)).status_code == 404
    assert admin.post(route(private, "stop")).status_code == 200
    mine = admitted(alice, ids)
    with SessionLocal() as db:
        db.delete(db.get(Binding, (2, 1)))
        db.commit()
    assert run_group_job(native)
    assert alice.get(route(mine)).status_code == 403
    assert get_batch(admin, mine)["state"] == "failed"
    # Restore owner permission, then explicitly authorize the retry as admin.
    with SessionLocal() as db:
        db.add(Binding(user_id=2, aws_account_id=1))
        db.commit()
    assert admin.post(route(mine, "retry")).status_code == 202
    assert run_group_job(native)
    assert run_group_job(native)
    assert get_batch(alice, mine)["actor_id"] == 2
    assert get_batch(alice, mine)["state"] == "completed"
    assert len(alice.get("/api/groups/group-1/member-batches").json()) == 1


def test_legacy_child_replay_cannot_bypass_private_batch_history(alice, admin, native):
    ids = prepare(alice, count=1)
    batch = admitted(admin, ids)
    with SessionLocal() as db:
        child = db.get(GroupJob, batch["items"][0]["job_id"])
        payload = {k: v for k, v in json.loads(child.payload).items()
                   if k != "member_context" and not k.startswith("native_")}
        payload["request_key"] = child.request_key
    assert alice.post("/api/groups/group-1/jobs", json=payload).status_code == 404
    assert admin.post("/api/groups/group-1/jobs", json=payload).status_code == 409
    with SessionLocal() as db:
        db.get(GroupJob, batch["items"][0]["job_id"]).state = "failed"
        db.get(ManagedGroup, "group-1").state = "failed"
        db.commit()
    assert alice.post("/api/groups/group-1/retry").status_code == 404
    assert admin.post("/api/groups/group-1/retry").status_code == 409


@pytest.mark.parametrize("kind", ["attach", "rename"])
def test_legacy_admin_job_replay_and_retry_remain_actor_private(alice, admin, native, kind):
    ids = prepare(alice, count=1)
    payload = {"kind": kind, "expected_revision": 1, "request_key": str(uuid.uuid4())}
    payload.update({"record_id": ids[0]} if kind == "attach" else {"name": "admin-renamed"})
    original = admin.post("/api/groups/group-1/jobs", json=payload)
    assert original.status_code == 202, original.text
    assert alice.post("/api/groups/group-1/jobs", json=payload).status_code == 404
    assert admin.post("/api/groups/group-1/jobs", json=payload).json()["id"] == original.json()["id"]
    with SessionLocal() as db:
        db.get(GroupJob, original.json()["id"]).state = "failed"
        db.get(ManagedGroup, "group-1").state = "failed"
        db.commit()
    assert alice.post("/api/groups/group-1/retry").status_code == 404
    assert admin.post("/api/groups/group-1/retry").status_code == 202


def test_batch_config_drift_never_refreshes_on_legacy_or_batch_retry(alice, native):
    ids = prepare(alice, count=2)
    batch = admitted(alice, ids)
    with SessionLocal() as db:
        db.get(AwsAccount, 1).region = "us-west-2"
        db.commit()
    assert run_group_job(native)
    assert not native.writes
    assert alice.post("/api/groups/group-1/retry").status_code == 409
    assert alice.post(route(batch, "retry")).status_code == 409
    assert alice.post(route(batch, "stop")).status_code == 200
    assert admitted(alice, ids)["id"] != batch["id"]


def test_candidates_scope_search_and_independent_subscription(alice, admin, native):
    ids = prepare(alice, count=1)
    standalone("other-owner", owner=3)
    standalone("independent", subscribed=True)
    with SessionLocal() as db:
        a = db.get(AwsAccount, 1)
        db.add(AwsAccount(**{c.name: getattr(a, c.name) for c in AwsAccount.__table__.columns if c.name not in ("id", "name")}, id=2, name="alias"))
        db.commit()
    standalone("other-account", account=2)
    standalone("not-ready")
    with SessionLocal() as db:
        db.get(Subscription, "not-ready").active_operation_id = "other-op"
        db.commit()
    for client in (alice, admin):
        response = client.get("/api/groups/group-1/member-candidates?page_size=100")
        assert response.status_code == 200, response.text
        assert {r["id"] for r in response.json()["items"]} == {ids[0], "independent"}
        assert response.json()["total"] == 2
        result = client.get("/api/groups/group-1/member-candidates?q=INDEP").json()
        assert [r["id"] for r in result["items"]] == ["independent"]


def test_detach_batches_require_actual_local_members_and_preserve_history(alice, native):
    seed_group(2)
    ids = [f"group-1-record-{i}" for i in range(2)]
    batch = admitted(alice, ids, kind="detach")
    assert run_group_job(native)
    result = alice.post(route(batch, "stop")).json()
    assert result["state"] == "stopped"
    with SessionLocal() as db:
        assert db.get(Subscription, ids[0]).group_id is None
        assert db.get(Subscription, ids[1]).group_id == "group-1"
        assert db.get(Subscription, ids[1]).group_membership_id == "member-" + ids[1]
    assert [w[0] for w in native.writes] == ["detach"]


def test_concurrent_admission_accepts_only_one_envelope(alice, native):
    ids = prepare(alice, count=4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda subset: submit(alice, subset), (ids[:2], ids[2:])))
    assert sorted(r.status_code for r in results) == [202, 409]
    assert len(alice.get("/api/groups/group-1/member-batches").json()) == 1


def test_stop_revokes_running_but_unsent_child_before_wire(alice, native, monkeypatch):
    ids = prepare(alice, count=2)
    batch = admitted(alice, ids)
    original = native.get_group_membership
    stopped = []
    def lookup(self, gid, uid):
        if not stopped:
            response = alice.post(route(batch, "stop"))
            assert response.status_code == 200, response.text
            stopped.append(response.json())
        return original(self, gid, uid)
    monkeypatch.setattr(native, "get_group_membership", lookup)
    assert run_group_job(native)
    assert not native.writes
    assert get_batch(alice, batch)["state"] == "stopped"
    assert not run_group_job(native)


def test_stop_at_wire_boundary_preserves_active_intent_and_stops_followers(alice, native, monkeypatch):
    ids = prepare(alice, paid=True, count=2)
    batch = admitted(alice, ids)
    original = native.create_group_membership
    def send(self, gid, uid):
        response = alice.post(route(batch, "stop"))
        assert response.status_code == 200, response.text
        assert response.json()["counts"]["running"] == 1
        assert response.json()["counts"]["stopped"] == 1
        return original(self, gid, uid)
    monkeypatch.setattr(native, "create_group_membership", send)
    assert run_group_job(native)
    assert get_batch(alice, batch)["state"] == "stopped"
    assert counter() == (1, 0, 1)
    assert not run_group_job(native)


def test_recheck_does_not_silently_reauthorize_revoked_followers(alice, admin, native):
    ids = prepare(alice, count=2)
    batch = admitted(alice, ids)
    native.uncertain = True
    assert run_group_job(native)
    with SessionLocal() as db:
        db.get(User, 2).session_version += 1
        db.commit()
    native.uncertain = False
    assert admin.post(route(batch, "recheck")).status_code == 202
    assert run_group_job(native)
    assert run_group_job(native)
    assert get_batch(admin, batch)["state"] == "failed"
    assert [w[0] for w in native.writes].count("attach") == 1
    assert admin.post(route(batch, "retry")).status_code == 202
    assert run_group_job(native)
    assert get_batch(admin, batch)["state"] == "completed"
    assert get_batch(admin, batch)["actor_id"] == 2


def test_exact_replay_of_failed_or_stopped_batch_never_requeues(alice, admin, native):
    ids = prepare(alice, count=2)
    key = str(uuid.uuid4())
    batch = admitted(alice, ids, request_key=key)
    with SessionLocal() as db:
        db.delete(db.get(Binding, (2, 1)))
        db.commit()
    assert run_group_job(native)
    assert submit(alice, ids, request_key=key).status_code == 403
    assert not run_group_job(native)
    assert alice.post(route(batch, "retry")).status_code == 403
    with SessionLocal() as db:
        db.add(Binding(user_id=2, aws_account_id=1))
        db.commit()
    assert submit(alice, ids, request_key=key).json()["state"] == "failed"
    assert not run_group_job(native)
    assert admin.post(route(batch, "stop")).status_code == 200
    assert submit(alice, ids, request_key=key).json()["state"] == "stopped"
    assert not run_group_job(native)


@pytest.mark.parametrize("kind", ["attach", "detach"])
def test_single_member_prewrite_shares_ordinary_group_authorization(alice, admin, native, monkeypatch, kind):
    if kind == "detach":
        seed_group(1)
        rid = "group-1-record-0"
    else:
        rid = prepare(alice, count=1)[0]
    response = alice.post("/api/groups/group-1/jobs", json={
        "kind": kind, "record_id": rid, "expected_revision": 1, "request_key": str(uuid.uuid4()),
    })
    assert response.status_code == 202, response.text
    original = native.get_group_membership
    def lookup(self, gid, uid):
        result = original(self, gid, uid)
        with SessionLocal() as db:
            binding = db.get(Binding, (2, 1))
            if binding:
                db.delete(binding)
            db.commit()
        return result
    monkeypatch.setattr(native, "get_group_membership", lookup)
    assert run_group_job(native)
    assert not native.writes
    with SessionLocal() as db:
        job = db.get(GroupJob, response.json()["id"])
        assert (job.state, job.phase) == ("failed", "ready")


def test_batch_attach_detach_keeps_independent_user_grant_and_deadline(alice, native):
    from test_independent_sources import PRO, claim
    rid = prepare(alice, paid=True, count=1)[0]
    uid = "sso-" + rid
    native.user_claims[uid] = [claim()]
    native.effective_rows = [{"principal": {"user": uid}, "type": {"amazonQ": PRO},
                              "status": "ACTIVE", "aggregatedSubscriptionType": "INDIVIDUAL_AND_GROUP"}]
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        record.counted, record.plan_id, record.subscription_status = True, 1, "active"
        record.subscription_type, record.subscribed_at = PRO, now() - timedelta(days=2)
        db.add(StopSchedule(record_id=rid, actor_id=2, mode="at", principal_type="USER",
                            individual_override=True, state="scheduled", stop_at=now() + timedelta(days=7)))
        db.commit()
    original = full_schedule(rid)
    batch = admitted(alice, [rid])
    assert run_group_job(native)
    assert get_batch(alice, batch)["state"] == "completed"
    native.effective_rows[0]["aggregatedSubscriptionType"] = "INDIVIDUAL"
    removal = admitted(alice, [rid], kind="detach")
    assert run_group_job(native)
    assert get_batch(alice, removal)["state"] == "completed"
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        assert record.group_id is None and record.subscription_status == "active"
    assert full_schedule(rid) == original
    assert not any(w[0] == "USER_cancel" for w in native.writes)


def test_live_batch_fences_user_deletion_role_change_and_account_delete(alice, admin, native):
    ids = prepare(alice, count=2)
    batch = admitted(alice, ids)
    assert admin.patch("/api/admin/users/2", json={"role": "admin"}).status_code == 409
    assert admin.patch("/api/admin/users/2", json={"active": False}).status_code == 200
    assert admin.delete("/api/admin/users/2").status_code == 409
    assert admin.request("DELETE", "/api/admin/aws/1", json={"confirm_name": "测试 AWS"}).status_code == 200
    assert admin.post(route(batch, "stop")).status_code == 200


def test_schema12_migration_preserves_every_existing_column_and_row(tmp_path, alice, native):
    from sqlalchemy import create_engine
    from app.database import Base
    from app.migrations import migrate, VERSION
    from app.models import SchemaVersion
    prepare(alice, count=2)
    new_tables = {"console_group_member_batches", "console_group_member_batch_items"}
    assert new_tables <= set(Base.metadata.tables)
    target = create_engine(f"sqlite:///{tmp_path / 'before12.db'}")
    old_tables = [t for t in Base.metadata.sorted_tables if t.name not in new_tables]
    Base.metadata.create_all(target, tables=old_tables)
    with engine.connect() as source, target.begin() as dest:
        for table in old_tables:
            rows = [dict(row) for row in source.execute(table.select()).mappings()]
            if rows:
                dest.execute(table.insert(), rows)
        dest.execute(SchemaVersion.__table__.insert(), {"version": 12})
    with target.connect() as conn:
        before = {t.name: conn.exec_driver_sql(f'SELECT * FROM "{t.name}"').fetchall() for t in old_tables if t.name != "console_schema_version"}
        columns = {name: inspect(conn).get_columns(name) for name in before}
    migrate(target)
    migrate(target)
    with target.connect() as conn:
        assert VERSION >= 13
        assert conn.exec_driver_sql("SELECT version FROM console_schema_version").scalar() == VERSION
        assert conn.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
        assert len(inspect(conn).get_table_names()) == len(Base.metadata.tables)
        for name, rows in before.items():
            assert conn.exec_driver_sql(f'SELECT * FROM "{name}"').fetchall() == rows
            assert [c["name"] for c in inspect(conn).get_columns(name)] == [c["name"] for c in columns[name]]


def test_schema13_failed_migration_rolls_back_new_envelope_and_preserves_version(tmp_path, monkeypatch):
    from sqlalchemy import create_engine
    from app.database import Base
    from app.migrations import migrate
    from app.models import GroupMemberBatchItem, SchemaVersion
    target = create_engine(f"sqlite:///{tmp_path / 'rollback.db'}")
    old_tables = [t for t in Base.metadata.sorted_tables if t.name not in {
        "console_group_member_batches", "console_group_member_batch_items",
    }]
    Base.metadata.create_all(target, tables=old_tables)
    with target.begin() as db:
        db.execute(SchemaVersion.__table__.insert(), {"version": 12})
    def interrupted(*args, **kwargs):
        raise RuntimeError("simulated interrupted migration")
    monkeypatch.setattr(GroupMemberBatchItem.__table__, "create", interrupted)
    with pytest.raises(RuntimeError, match="interrupted migration"):
        migrate(target)
    with target.connect() as db:
        assert db.exec_driver_sql("SELECT version FROM console_schema_version").scalar() == 12
        assert "console_group_member_batches" not in inspect(db).get_table_names()
