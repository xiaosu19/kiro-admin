"""Blocking barriers prove real overlap and retain exact-resource exclusion."""
# Imported pytest fixtures deliberately share their parameter names.
# ruff: noqa: F811

import concurrent.futures
import io
import json
import threading
from contextlib import nullcontext
from datetime import timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from app.aws import AwsGateway as RealAwsGateway
from app.database import SessionLocal
from app.models import AwsAccount, Subscription, now
from test_account_dispatcher import eventually
from test_provisioning_admission import ready, remote  # noqa: F401
from test_provisioning_coordinator import gateway as numbered_gateway  # noqa: F401
from test_workflows import Gateway, count, create


def record(key, *, account_id=1, **values):
    with SessionLocal() as db:
        row = Subscription(
            id=key, owner_id=2, aws_account_id=account_id, request_key=key,
            username=key, email=key + "@example.org", reserved=False,
            portal_url=db.get(AwsAccount, account_id).portal_url,
            provision_only=True, **values,
        )
        db.add(row)
        db.commit()
    return key


def test_shared_account_fences_allow_independent_records_and_block_exclusive_work():
    from app.account_dispatcher import account_fence, resource_fence

    entered, release = threading.Event(), threading.Event()

    def first():
        with account_fence(1, shared=True) as account:
            with resource_fence("record", "a") as acquired:
                assert account and acquired
                entered.set()
                assert release.wait(5)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(first)
        try:
            assert entered.wait(2)
            with account_fence(1, shared=True) as acquired:
                assert acquired
                with account_fence(1) as exclusive:
                    assert not exclusive, "A shared holder must never upgrade silently"
                with resource_fence("record", "a") as same:
                    assert not same
                with resource_fence("record", "b") as independent:
                    assert independent
            with account_fence(1) as exclusive:
                assert not exclusive
        finally:
            release.set()
        future.result(timeout=2)
    with account_fence(1) as exclusive:
        assert exclusive


def test_task_dispatcher_respects_global_and_account_caps_without_waiting():
    from app.account_dispatcher import AccountDispatcher

    release = threading.Event()
    active, visits = [], []
    mutex = threading.Lock()
    tasks = [(aid, "sso", str(i)) for aid in (1, 2, 3) for i in range(3)]

    def run(task):
        with mutex:
            active.append(task)
            visits.append(task)
            assert len(active) <= 4
            assert sum(t[0] == task[0] for t in active) <= 2
        assert release.wait(5)
        with mutex:
            active.remove(task)
        return True

    dispatcher = AccountDispatcher(
        lambda: tasks, run, max_workers=4, max_per_account=2,
        account_key=lambda task: task[0], fence=lambda task: nullcontext(True),
    )
    try:
        assert dispatcher.tick() == 4
        eventually(lambda: len(active) == 4)
        assert {t[0] for t in active} == {1, 2, 3}
        assert dispatcher.tick() == 0
        dispatcher.stop()
        assert dispatcher.tick() == 0
        assert len(visits) == 4
    finally:
        release.set()
        dispatcher.close(wait=True)


def test_two_independent_users_on_same_account_create_concurrently():
    from app.worker import run_one

    first, second = record("parallel-a"), record("parallel-b")
    barrier = threading.Barrier(2)
    entered = []

    class Blocking(Gateway):
        def create_user(self, row):
            entered.append(row.id)
            barrier.wait(timeout=3)
            return super().create_user(row)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = [pool.submit(run_one, Blocking, account_id=1) for _ in range(2)]
        assert all(f.result(timeout=5) for f in results)
    assert set(entered) == {first, second}
    with SessionLocal() as db:
        assert all(db.get(Subscription, rid).state == "completed" for rid in (first, second))


def test_independent_paid_user_subscriptions_overlap_and_settle_each_quota_once(alice):
    from app.worker import run_one

    ids = [create(alice).json()["id"] for _ in range(2)]
    barrier = threading.Barrier(2)
    calls = []

    class Blocking(Gateway):
        def subscribe(self, row):
            calls.append(row.id)
            barrier.wait(timeout=3)
            return "request-" + row.id

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = [pool.submit(run_one, Blocking, account_id=1) for _ in ids]
        assert all(f.result(timeout=5) for f in results)
    assert sorted(calls) == sorted(ids)
    assert count()[:3] == (2, 0, 2)


def test_exact_record_fence_survives_lease_expiry_without_blocking_another_user():
    from app.account_dispatcher import account_fence
    from app.worker import run_one

    first, second = record("fenced-a"), record("fenced-b")
    entered, release = threading.Event(), threading.Event()
    calls = []

    class Blocking(Gateway):
        def create_user(self, row):
            calls.append(row.id)
            if row.id == first:
                entered.set()
                assert release.wait(5)
            return super().create_user(row)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(run_one, Blocking, account_id=1, record_id=first)
        try:
            assert entered.wait(2)
            with SessionLocal() as db:
                db.get(Subscription, first).lease_until = now() - timedelta(seconds=1)
                db.commit()
            assert not run_one(Blocking, account_id=1, record_id=first)
            assert pool.submit(run_one, Blocking, account_id=1, record_id=second).result(timeout=2)
            with account_fence(1) as exclusive:
                assert not exclusive, "Cascade/native writes must wait for the live record holder"
            with SessionLocal() as db:
                assert db.get(Subscription, first).attempts == 1
                assert db.get(Subscription, second).state == "completed"
        finally:
            release.set()
        assert future.result(timeout=3)
    assert calls == [first, second]


def test_creation_service_caps_same_account_at_two_running_users():
    from app import worker

    ids = [record("bounded-" + str(i)) for i in range(4)]
    release = threading.Event()
    entered, active = [], []
    mutex = threading.Lock()

    class Blocking(Gateway):
        def create_user(self, row):
            with mutex:
                entered.append(row.id)
                active.append(row.id)
                assert len(active) <= 2
            assert release.wait(5)
            with mutex:
                active.remove(row.id)
            return super().create_user(row)

    dispatcher = worker.make_dispatcher(gateway_factory=Blocking, max_workers=4)
    try:
        eventually(lambda: (dispatcher.tick(), len(entered) == 2)[1])
        for _ in range(3):
            dispatcher.tick()
        assert len(active) == 2 and len(entered) == 2
        dispatcher.stop()
        assert dispatcher.tick() == 0
    finally:
        release.set()
        dispatcher.close(wait=True)
    with SessionLocal() as db:
        assert sum(db.get(Subscription, rid).state == "completed" for rid in ids) == 2
        assert sum(db.get(Subscription, rid).state == "queued" for rid in ids) == 2


def test_native_group_credentials_overlap_but_member_activation_remains_serial(alice, numbered_gateway):
    from app import worker
    from app.models import ManagedGroup, PlanCounter
    from test_provisioning_coordinator import admit, body, coordinator_to_child

    parent = admit(alice, body(quantity=2)).json()
    coordinator_to_child(parent, "sso")
    ids = [item["record_id"] for item in parent["accounts"][0]["items"]]
    barrier = threading.Barrier(2)
    entered, release = threading.Event(), threading.Event()
    creations, joins = [], []

    class Blocking(numbered_gateway):
        def create_user(self, row):
            creations.append(row.id)
            barrier.wait(timeout=3)
            return super().create_user(row)

        def create_group_membership(self, gid, uid):
            joins.append(uid)
            if len(joins) == 1:
                entered.set()
                assert release.wait(5)
            return super().create_group_membership(gid, uid)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker.run_one, Blocking, account_id=1) for _ in ids]
        try:
            assert entered.wait(4)
            eventually(lambda: any(f.done() for f in futures))
            assert sorted(creations) == sorted(ids) and len(joins) == 1
            with SessionLocal() as db:
                rows = [db.get(Subscription, rid) for rid in ids]
                assert {r.state for r in rows} == {"queued", "running"}
                waiting = next(r for r in rows if r.state == "queued")
                assert waiting.step == "subscribe" and waiting.password_encrypted
                assert db.get(ManagedGroup, waiting.group_id).active_job_id != waiting.id
                assert db.get(PlanCounter, 1).pending_count == 2
        finally:
            release.set()
        assert all(f.result(timeout=3) for f in futures)
    assert worker.run_one(Blocking, account_id=1)
    assert len(joins) == 2
    assert sum(event[0] == "GROUP" for event in numbered_gateway.events) == 1
    with SessionLocal() as db:
        assert all(db.get(Subscription, rid).state == "completed" for rid in ids)
        assert db.get(PlanCounter, 1).pending_count == 0


def test_numbered_json_exports_queue_all_users_before_any_browser_runs(alice, numbered_gateway):
    from app import worker
    from app.models import AuthJob, ProvisioningAccountBatch, ProvisioningItem
    from app.provisioning_coordinator import run_one as coordinate
    from test_provisioning_admission import admit, intent
    from test_provisioning_coordinator import coordinator_to_child, drive

    parent = admit(alice, intent(quantity=2)).json()
    cid = coordinator_to_child(parent, "sso")
    assert worker.run_one(numbered_gateway, account_id=1)
    assert worker.run_one(numbered_gateway, account_id=1)
    assert coordinate(account_id=1)
    with SessionLocal() as db:
        assert not list(db.scalars(select(AuthJob))), 'prepared users cannot authenticate before subscription'
    assert drive(parent, alice)['state'] == 'completed'
    with SessionLocal() as db:
        items = [db.get(ProvisioningItem, item["record_id"]) for item in parent["accounts"][0]["items"]]
        assert all(item.auth_job_id and item.auth_batch_id for item in items)
        assert all(db.get(AuthJob, item.auth_job_id) for item in items)
        assert db.get(ProvisioningAccountBatch, cid).state == "completed"


def test_signed_password_wire_rechecks_authority_after_proxy_guard(monkeypatch):
    from types import SimpleNamespace

    import requests
    from app.aws import AwsGateway
    from app.models import User
    from app.worker import run_one

    rid = record("wire-authority", sso_user_id="existing-user", step="password")
    sent = []

    def post(self, *args, **kwargs):
        sent.append("password")
        return SimpleNamespace(status_code=200, headers={}, json=lambda: {"Password": "SyntheticOTP1!"})

    monkeypatch.setattr(requests.Session, "post", post)

    def factory(account):
        gateway = AwsGateway(account)
        gateway.verify_identity = lambda: None
        proxy_guard = gateway._check_proxy

        def revoke_before_wire():
            proxy_guard()
            with SessionLocal() as db:
                db.get(User, 2).active = False
                db.commit()

        gateway._check_proxy = revoke_before_wire
        return gateway

    assert run_one(factory, account_id=1)
    assert sent == []
    with SessionLocal() as db:
        assert db.get(Subscription, rid).state == "failed"


def test_record_fence_is_held_until_transport_cleanup_finishes():
    from app.account_dispatcher import account_fence, resource_fence
    from app.worker import run_one

    rid = record("cleanup-fence")
    entered, release = threading.Event(), threading.Event()

    class Closing(Gateway):
        def close(self):
            entered.set()
            assert release.wait(5)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run_one, Closing, account_id=1)
        try:
            assert entered.wait(2)
            with resource_fence("record", rid) as acquired:
                assert not acquired
            with account_fence(1) as exclusive:
                assert not exclusive
        finally:
            release.set()
        assert future.result(timeout=2)
    with resource_fence("record", rid) as acquired:
        assert acquired


def test_numbered_stop_blocks_both_parallel_users_before_create_wire(alice, numbered_gateway):
    from app import worker
    from app.models import PlanCounter
    from app.provisioning_coordinator import run_one as coordinate
    from test_provisioning_admission import admit
    from test_provisioning_coordinator import body, coordinator_to_child

    parent = admit(alice, body(quantity=2)).json()
    cid = coordinator_to_child(parent, "sso")
    entered, release = threading.Event(), threading.Event()
    visits = []
    mutex = threading.Lock()
    before = list(numbered_gateway.events)

    class Blocking(numbered_gateway):
        def verify_identity(self):
            with mutex:
                visits.append("verify")
                if len(visits) == 2:
                    entered.set()
            assert release.wait(5)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(worker.run_one, Blocking, account_id=1) for _ in range(2)]
        try:
            assert entered.wait(3)
            stopped = alice.post(f"/api/provisioning-batches/{parent['id']}/accounts/{cid}/stop",
                                 json={"request_key": "stop-parallel-users-001"})
            assert stopped.status_code == 202, stopped.text
        finally:
            release.set()
        assert all(f.result(timeout=3) for f in futures)
    coordinate(account_id=1)
    assert numbered_gateway.events == before
    with SessionLocal() as db:
        assert db.get(PlanCounter, 1).pending_count == 0


def test_late_success_updates_confirmed_item_after_sibling_pauses_parent(alice, numbered_gateway):
    from app import worker
    from app.aws import AwsFailure
    from app.models import (
        GroupMemberActivation,
        ProvisioningAccountBatch,
        ProvisioningItem,
    )
    from app.provisioning_coordinator import run_one as coordinate
    from sqlalchemy import select
    from test_provisioning_admission import admit
    from test_provisioning_coordinator import body, coordinator_to_child, fetch

    parent = admit(alice, body(quantity=2)).json()
    cid = coordinator_to_child(parent, "sso")
    failed, late = [item["record_id"] for item in parent["accounts"][0]["items"]]
    entered, release = threading.Event(), threading.Event()

    class Partial(numbered_gateway):
        def create_user(self, row):
            if row.id == failed:
                raise AwsFailure("definitely rejected")
            entered.set()
            assert release.wait(5)
            return super().create_user(row)

    assert worker.run_one(Partial, account_id=1, record_id=failed)
    assert coordinate(account_id=1)
    assert fetch(alice, parent)["state"] == "needs_review"
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(worker.run_one, Partial, account_id=1, record_id=late)
        try:
            assert entered.wait(3)
            assert fetch(alice, parent)["state"] == "needs_review"
        finally:
            release.set()
        assert future.result(timeout=3)
    assert not coordinate(account_id=1), "A late fact must not restart paused admission"
    final = fetch(alice, parent)
    assert final["state"] == "needs_review"
    assert [item["state"] for item in final["accounts"][0]["items"]] == ["failed", "prepared"]
    with SessionLocal() as db:
        item, row = db.get(ProvisioningItem, late), db.get(ProvisioningAccountBatch, cid)
        activation = db.scalar(select(GroupMemberActivation).where(
            GroupMemberActivation.record_id == late,
            GroupMemberActivation.grant_id == row.native_grant_id,
            GroupMemberActivation.counted.is_(True)))
        assert activation is None and item.finished_at is None
        assert not item.auth_job_id and not db.get(Subscription, late).counted
    assert not any(event[0] == "GROUP" for event in numbered_gateway.events)


@pytest.mark.parametrize("stage", ["create_user", "membership"])
@pytest.mark.parametrize("change", ["authority", "stop", "config"])
def test_sdk_new_writes_recheck_at_transport_boundary(alice, numbered_gateway, monkeypatch, stage, change):
    from app.models import ProvisioningAccountBatch, User
    from app.security import encrypt
    from app.worker import run_one
    from requests.adapters import HTTPAdapter
    from test_provisioning_admission import admit
    from test_provisioning_coordinator import body, coordinator_to_child
    from urllib3.response import HTTPResponse

    parent = admit(alice, body()).json()
    cid = coordinator_to_child(parent, "sso")
    rid = parent["accounts"][0]["items"][0]["record_id"]
    if stage == "membership":
        with SessionLocal() as db:
            row = db.get(Subscription, rid)
            row.sso_user_id, row.step = "12345678-1234-1234-1234-123456789abc", "subscribe"
            row.password_encrypted = encrypt("SyntheticPassword123!")
            db.commit()
    sent, guarded = [], []

    def adapter_send(self, request, **kwargs):
        sent.append(json.loads(request.body))
        payload = json.dumps({"IdentityStoreId": "d-1234567890",
            "UserId": "12345678-1234-1234-1234-123456789abc",
            "MembershipId": "12345678-1234-1234-1234-123456789abd"}).encode()
        return SimpleNamespace(status_code=200, headers={"content-type": "application/x-amz-json-1.1"},
            raw=HTTPResponse(body=io.BytesIO(payload), preload_content=False))

    monkeypatch.setattr(HTTPAdapter, "send", adapter_send)

    def factory(account):
        gateway, remote = RealAwsGateway(account), numbered_gateway(account)
        gateway.verify_identity = lambda: None
        gateway.claim_snapshot = lambda: nullcontext()
        gateway.find_created_user = lambda row: None
        gateway.password = lambda row: "SyntheticPassword123!"
        for name in ("group_subscription_info", "list_group_memberships",
                     "get_group_membership", "user_subscription_sources", "report_subscriptions"):
            setattr(gateway, name, getattr(remote, name))
        original_guard = gateway.identity._endpoint.http_session.guard

        def mutate_before_wire():
            original_guard()
            guarded.append(True)
            with SessionLocal() as db:
                if change == "authority":
                    db.get(User, 2).active = False
                elif change == "stop":
                    db.get(ProvisioningAccountBatch, cid).stop_requested_at = now()
                else:
                    db.get(AwsAccount, 1).profile_arn += "/changed"
                db.commit()

        gateway.identity._endpoint.http_session.guard = mutate_before_wire
        return gateway

    assert run_one(factory, account_id=1, record_id=rid)
    assert guarded, "The test must reach the actual SDK transport guard"
    assert sent == [], "No new SDK write may escape revoked authority, stop or frozen configuration"
    with SessionLocal() as db:
        assert db.get(Subscription, rid).state == "failed"


def test_sdk_readonly_recovery_does_not_run_new_write_authority(monkeypatch):
    from requests.adapters import HTTPAdapter
    from urllib3.response import HTTPResponse

    targets = []

    def adapter_send(self, request, **kwargs):
        target = request.headers['X-Amz-Target']
        targets.append(target.decode() if isinstance(target, bytes) else target)
        payload = b'{"MembershipId":"12345678-1234-1234-1234-123456789abd"}'
        return SimpleNamespace(status_code=200, headers={"content-type": "application/x-amz-json-1.1"},
            raw=HTTPResponse(body=io.BytesIO(payload), preload_content=False))

    monkeypatch.setattr(HTTPAdapter, "send", adapter_send)
    with SessionLocal() as db:
        gateway = RealAwsGateway(db.get(AwsAccount, 1))
    gateway.before_provisioning_write = lambda: pytest.fail("Recovery must remain read only")
    try:
        result = gateway.get_group_membership(
            "12345678-1234-1234-1234-123456789abc", "12345678-1234-1234-1234-123456789abe")
        assert result == "12345678-1234-1234-1234-123456789abd"
        assert len(targets) == 1 and targets[0].endswith('GetGroupMembershipId')
    finally:
        gateway.close()
