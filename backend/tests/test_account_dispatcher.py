"""Account lanes must stay independent without weakening same-host fencing."""

import concurrent.futures
import json
import os
import subprocess
import sys
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest
from app.database import SessionLocal, engine
from app.models import AwsAccount, Binding, Subscription, now
from sqlalchemy import select

PRO = "Q_DEVELOPER_STANDALONE_PRO"
PLUS = "Q_DEVELOPER_STANDALONE_PRO_PLUS"


def eventually(predicate, timeout=3):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(0.01)
    assert predicate()


def accounts():
    with SessionLocal() as db:
        source = db.get(AwsAccount, 1)
        values = {c.name: getattr(source, c.name) for c in AwsAccount.__table__.columns}
        values.update(id=2, name="Account B", aws_account_id="222222222222")
        db.add(AwsAccount(**values))
        db.flush()
        db.add(Binding(user_id=2, aws_account_id=2))
        db.commit()


def sso(account_id, **kw):
    rid = f"sso-account-{account_id}"
    with SessionLocal() as db:
        r = Subscription(
            id=rid,
            owner_id=2,
            aws_account_id=account_id,
            request_key=rid,
            username=rid,
            email=rid + "@example.org",
            portal_url=db.get(AwsAccount, account_id).portal_url,
            provision_only=True,
            reserved=False,
            **kw,
        )
        db.add(r)
        db.commit()
    return rid


def state(rid):
    with SessionLocal() as db:
        return db.get(Subscription, rid).state


def test_dispatcher_capacity_rotation_and_stop_keep_running_fence():
    from app.account_dispatcher import AccountDispatcher, account_fence

    entered, release = threading.Event(), threading.Event()
    visits = []
    active = set()
    mutex = threading.Lock()

    def run(account_id):
        with mutex:
            assert account_id not in active
            active.add(account_id)
            assert len(active) <= 2
            visits.append(account_id)
        if account_id == 1:
            entered.set()
            assert release.wait(5)
        with mutex:
            active.remove(account_id)
        return True

    dispatcher = AccountDispatcher(lambda: [1, 2, 3, 4], run, max_workers=2)
    try:
        dispatcher.tick()
        assert entered.wait(2)
        eventually(lambda: (dispatcher.tick(), 4 in visits)[1])
        assert set(visits[:2]) == {1, 2}
        assert visits[2:4] == [3, 4]
        assert visits.count(1) == 1
        dispatcher.stop()
        previous = list(visits)
        dispatcher.tick()
        assert visits == previous
        with account_fence(1) as acquired:
            assert not acquired
    finally:
        release.set()
        dispatcher.close(wait=True)
    with account_fence(1) as acquired:
        assert acquired


def test_nested_fence_is_reentrant_only_on_same_thread():
    from app.account_dispatcher import account_fence

    def try_lock():
        with account_fence(1) as acquired:
            return acquired

    with account_fence(1) as acquired:
        assert acquired
        assert try_lock()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            assert not pool.submit(try_lock).result(timeout=2)


@pytest.mark.parametrize("explicit_first", [False, True])
def test_sso_legacy_and_filtered_runners_skip_blocked_account(explicit_first):
    from app.worker import run_one
    from test_workflows import Gateway

    accounts()
    a, b = sso(1), sso(2)
    entered, release = threading.Event(), threading.Event()

    class Waiting(Gateway):
        def __init__(self, account):
            self.account = account

        def verify_identity(self):
            if self.account.id == 1:
                entered.set()
                assert release.wait(5)

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(
            run_one, Waiting, **({"account_id": 1} if explicit_first else {})
        )
        try:
            assert entered.wait(2)
            with SessionLocal() as db:
                db.get(Subscription, a).lease_until = now() - timedelta(seconds=1)
                db.get(AwsAccount, 2).name = "Database remains writable"
                db.commit()
            assert pool.submit(
                run_one, Waiting, **({} if explicit_first else {"account_id": 2})
            ).result(timeout=2)
            assert state(b) == "completed"
            assert state(a) == "running"
            assert run_one(Waiting, account_id=1) is False
        finally:
            release.set()
        assert future.result(timeout=2)
    assert state(a) == "completed"


def test_sso_process_fence_survives_expired_lease_and_uses_same_database():
    from app.worker import run_one
    from test_workflows import Gateway

    accounts()
    a = sso(1)
    entered, release = threading.Event(), threading.Event()

    class Waiting(Gateway):
        def verify_identity(self):
            entered.set()
            assert release.wait(10)

    code = """
import json
from app.worker import run_one
from app.database import engine
def forbidden(account):
    raise AssertionError('A live account fence must prevent claiming')
print(json.dumps({'db': str(engine.url), 'result': run_one(forbidden, account_id=1)}))
"""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run_one, Waiting)
        try:
            assert entered.wait(2)
            with SessionLocal() as db:
                db.get(Subscription, a).lease_until = now() - timedelta(seconds=1)
                db.commit()
            child = subprocess.run(
                [sys.executable, "-c", code],
                cwd=Path(__file__).resolve().parents[1],
                env=dict(os.environ),
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert child.returncode == 0, child.stderr
            assert json.loads(child.stdout) == {"db": str(engine.url), "result": False}
            with SessionLocal() as db:
                assert db.get(Subscription, a).attempts == 1
        finally:
            release.set()
        assert future.result(timeout=2)


def test_worker_factory_uses_runtime_gateway_and_dispatches_b_while_a_waits():
    from app import worker
    from test_workflows import Gateway

    accounts()
    a, b = sso(1), sso(2)
    entered, release = threading.Event(), threading.Event()

    class Waiting(Gateway):
        def __init__(self, account):
            self.account = account

        def verify_identity(self):
            if self.account.id == 1:
                entered.set()
                assert release.wait(5)

    dispatcher = worker.make_dispatcher(gateway_factory=Waiting, max_workers=2)
    try:
        dispatcher.tick()
        assert entered.wait(2)
        eventually(lambda: state(b) == "completed")
        assert state(a) == "running"
    finally:
        dispatcher.stop()
        release.set()
        dispatcher.close(wait=True)


def family_work(family, account_id, client):
    """Use real admissions for auth; small durable rows for other runner families."""
    from app.group_subscription_state import config_hash
    from app.models import (
        GroupJob,
        ManagedGroup,
        NativeGroupGrant,
        NativeGroupOperation,
        PlanChange,
        RecordOperation,
    )
    from app.security import encrypt

    key = f"{family}-{account_id}"
    with SessionLocal() as db:
        if family in ("group", "native"):
            group = ManagedGroup(
                id=key,
                owner_id=2,
                aws_account_id=account_id,
                aws_scope=str(account_id),
                request_key=key,
                payload_hash=key,
                name=key,
                marker=key,
                active_job_id=key,
                remote_id="remote-" + key if family == "native" else None,
                state="ready" if family == "native" else "creating",
            )
            db.add(group)
            db.flush()
            if family == "group":
                model = GroupJob
                db.add(
                    GroupJob(
                        id=key,
                        group_id=key,
                        actor_id=2,
                        kind="create",
                        request_key=key,
                        payload=json.dumps({"name": key}),
                    )
                )
            else:
                grant = NativeGroupGrant(
                    id=key,
                    group_id=key,
                    owner_id=2,
                    aws_account_id=account_id,
                    plan_id=1,
                    plan_name="Pro",
                    subscription_type=PRO,
                )
                db.add(grant)
                db.flush()
                model = NativeGroupOperation
                db.add(
                    NativeGroupOperation(
                        id=key,
                        group_id=key,
                        grant_id=key,
                        actor_id=2,
                        owner_id=2,
                        kind="subscribe",
                        request_key=key,
                        payload_hash=key,
                        member_snapshot="[]",
                        config_hash=config_hash(db, db.get(AwsAccount, account_id)),
                        payload=json.dumps(
                            {
                                "cancellation_mode": "IMMEDIATE",
                                "actor_session_version": 1,
                                "policy_revision_expected": 0,
                            }
                        ),
                    )
                )
        else:
            model = RecordOperation
            r = Subscription(
                id=key,
                owner_id=2,
                aws_account_id=account_id,
                request_key=key,
                username=key,
                email=key + "@example.org",
                portal_url=db.get(AwsAccount, account_id).portal_url,
                state="completed",
                step="done",
                sso_user_id=key,
                password_encrypted=encrypt("Password1!"),
                counted=True,
                reserved=False,
                subscription_type=PRO,
                observed_subscription_type=PRO,
                subscription_status="active",
                plan_id=1,
                active_operation_id=key if family != "auth" else None,
            )
            db.add(r)
            db.flush()
            if family == "lifecycle":
                db.add(
                    RecordOperation(
                        id=key,
                        record_id=key,
                        actor_id=2,
                        kind="update_sso",
                        request_key=key,
                        payload=json.dumps(
                            {"display_name": "Updated", "email": "new@example.org"}
                        ),
                    )
                )
            elif family == "plan":
                db.add(
                    RecordOperation(
                        id=key,
                        record_id=key,
                        actor_id=2,
                        kind="change_plan",
                        request_key=key,
                        payload="{}",
                    )
                )
                db.flush()
                db.add(
                    PlanChange(
                        id=key,
                        record_id=key,
                        operation_id=key,
                        actor_id=2,
                        owner_id=2,
                        request_key=key,
                        payload_hash=key,
                        direction="upgrade",
                        from_plan_id=1,
                        from_plan_name="Pro",
                        from_type=PRO,
                        to_plan_id=2,
                        to_plan_name="Plus",
                        to_type=PLUS,
                    )
                )
        db.commit()
    if family == "auth":
        from test_auth_batches import admission

        response = admission(client, [r])
        assert response.status_code == 202, response.text
        with SessionLocal() as db:
            key = db.get(Subscription, key).active_operation_id
    return model, key


def family_runner(family, entered, release, routes, *, connection_counts=None):
    from app import (
        auth_jobs,
        group_jobs,
        group_subscription_worker,
        lifecycle,
        plan_change_worker,
    )
    from app.proxies import account_proxy
    from test_auth_batches import DoneAuth
    from test_auth_batches import Gateway as AuthGateway
    from test_groups import GroupGateway
    from test_lifecycle import LifecycleGateway
    from test_native_groups import NativeGateway
    from test_plan_changes import Gateway as PlanGateway

    bases = {
        "group": GroupGateway,
        "native": NativeGateway,
        "plan": PlanGateway,
        "lifecycle": LifecycleGateway,
        "auth": AuthGateway,
    }

    class Waiting(bases[family]):
        groups = {}
        assignments = {}
        members = {}
        current = PRO
        pending = None
        status = "active"
        effective_type = None
        additional_sources = []
        lag = False
        failure = None
        uncertain = False

        def __init__(self, account):
            self.account = account
            self.proxy = account_proxy(account)
            routes.append((account.id, self.proxy.proxy_id if self.proxy else None))

        def block(self):
            if self.account.id == 1:
                if connection_counts is not None:
                    connection_counts.append(engine.pool.checkedout())
                entered.set()
                assert release.wait(8)

        def get_group_id(self, name):
            self.block()
            return super().get_group_id(name)

        def verify(self):
            self.block()

        def user_info(self, record):
            self.block()
            return {"UserId": record.sso_user_id, "DisplayName": "Before", "Emails": []}

        def update_user(self, record, display_name, email):
            return "updated"

        def plan_change_info(self, record):
            self.block()
            return super().plan_change_info(record)

        def update_assignment(self, record, target):
            self.current = target
            return "updated"

    class WaitingAuth(DoneAuth):
        def _advance(self, state, answer):
            self.gateway.block()
            return super()._advance(state, answer)

    runners = {
        "group": group_jobs.run_group_job,
        "native": group_subscription_worker.run_one,
        "plan": plan_change_worker.run_plan_change,
        "lifecycle": lifecycle.run_operation,
        "auth": auth_jobs.run_one,
    }

    def run(**kwargs):
        if family == "auth":
            return runners[family](Waiting, WaitingAuth, **kwargs)
        return runners[family](Waiting, **kwargs)

    return run


@pytest.mark.parametrize("family", ["group", "native", "lifecycle", "plan", "auth"])
@pytest.mark.parametrize("explicit_first", [False, True])
def test_actual_runner_families_allow_b_before_blocked_a(
    alice, monkeypatch, family, explicit_first
):
    from app.config import settings
    from app.models import Proxy
    from app.security import encrypt

    monkeypatch.setattr(settings, "plan_changes_enabled", True)
    accounts()
    with SessionLocal() as db:
        for aid in (1, 2):
            db.add(
                Proxy(
                    id=aid,
                    name=f"proxy-{aid}",
                    host="127.0.0.1",
                    port=9000 + aid,
                    auth_encrypted=encrypt({"username": "u", "password": "p"}),
                )
            )
        db.flush()
        for aid in (1, 2):
            db.get(AwsAccount, aid).proxy_id = aid
        db.commit()
    model, a = family_work(family, 1, alice)
    _, b = family_work(family, 2, alice)
    entered, release, routes = threading.Event(), threading.Event(), []
    run = family_runner(family, entered, release, routes)
    if family == "auth":
        assert run(
            account_id=1
        )  # Auth begin persists its state; advance does the slow step.
        assert run(account_id=2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(run, **({"account_id": 1} if explicit_first else {}))
        try:
            assert entered.wait(2)
            with SessionLocal() as db:
                db.get(model, a).lease_until = now() - timedelta(seconds=1)
                db.get(AwsAccount, 2).name = "B can still write"
                db.commit()
            assert pool.submit(
                run, **({} if explicit_first else {"account_id": 2})
            ).result(timeout=2)
            with SessionLocal() as db:
                assert db.get(model, b).state == "completed", db.get(model, b).error
                assert db.get(model, a).state == "running"
            assert run(account_id=1) is False
        finally:
            release.set()
        assert future.result(timeout=3)
    with SessionLocal() as db:
        assert db.get(model, a).state == "completed", db.get(model, a).error
    assert set(routes) == {(1, 1), (2, 2)}


@pytest.mark.parametrize("family", ["lifecycle", "plan"])
def test_remote_preflight_holds_no_database_connection(alice, monkeypatch, family):
    from app.config import settings

    monkeypatch.setattr(settings, "plan_changes_enabled", True)
    family_work(family, 1, alice)
    entered, release, counts = threading.Event(), threading.Event(), []
    run = family_runner(family, entered, release, [], connection_counts=counts)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run)
        try:
            assert entered.wait(2)
            assert counts == [0]
        finally:
            release.set()
        assert future.result(timeout=2)


def test_auth_factory_maintenance_is_once_per_pass_not_per_lane(alice, monkeypatch):
    from app import auth_jobs, auth_worker
    from test_auth_batches import DoneAuth, Gateway

    accounts()
    family_work("auth", 1, alice)
    family_work("auth", 2, alice)
    calls = []
    monkeypatch.setattr(auth_jobs, "expire_batches", lambda **kw: calls.append(kw))
    dispatcher = auth_worker.make_dispatcher(
        gateway_factory=Gateway, auth_factory=DoneAuth, max_workers=2
    )
    try:
        dispatcher.tick()
    finally:
        dispatcher.close(wait=True)
    assert len(calls) == 1


@pytest.mark.parametrize("family", ["plan", "native"])
def test_due_reconciliation_never_steals_another_account(alice, monkeypatch, family):
    from app import group_subscription_worker as native_worker
    from app import plan_change_worker as plan_worker
    from app.config import settings
    from app.models import (
        NativeGroupGrant,
        NativeGroupOperation,
        PlanChange,
    )

    monkeypatch.setattr(settings, "plan_changes_enabled", True)
    accounts()
    model, a = family_work(family, 1, alice)
    _, b = family_work(family, 2, alice)
    with SessionLocal() as db:
        # A remains queued, while B is an accepted schedule due for read-only confirmation.
        db.get(model, b).state = "completed"
        if family == "plan":
            c = db.get(PlanChange, b)
            c.state, c.scheduled_record_id, c.next_check_at = (
                "scheduled",
                b,
                now() - timedelta(seconds=1),
            )
            c.write_requested_at = c.accepted_at = now() - timedelta(days=1)
            db.get(Subscription, b).active_operation_id = None
        else:
            from app.models import ManagedGroup

            op = db.get(NativeGroupOperation, b)
            op.kind, op.phase, op.write_requested_at = (
                "cancel",
                "done",
                now() - timedelta(days=1),
            )
            db.get(ManagedGroup, b).active_job_id = None
            grant = db.get(NativeGroupGrant, b)
            grant.state, grant.access_ends_at = (
                "cancel_scheduled",
                now() - timedelta(seconds=1),
            )
        db.commit()
    seen = []

    def gateway(account):
        seen.append(account.id)
        raise RuntimeError("Synthetic read failure remains recoverable")

    module = plan_worker if family == "plan" else native_worker
    assert module.reconcile_due(gateway, limit=1, account_id=2) == 1
    assert seen == [2]
    with SessionLocal() as db:
        assert db.get(model, a).state == "queued"


@pytest.mark.parametrize(
    "stage", ["verify", "lookup", "password", "membership", "subscribe"]
)
@pytest.mark.parametrize("revoke", ["binding", "credentials", "proxy"])
def test_sso_rechecks_authority_and_frozen_config_after_blocking_reads(stage, revoke):
    from app.aws import AwsGateway
    from app.models import ManagedGroup
    from app.security import encrypt
    from app.worker import run_one
    from botocore.exceptions import ClientError
    from test_groups import GroupGateway

    rid = sso(1)
    if revoke == "proxy":
        from app.models import Proxy

        with SessionLocal() as db:
            db.add(
                Proxy(
                    id=1,
                    name="bound",
                    host="127.0.0.1",
                    port=9911,
                    auth_encrypted=encrypt({"username": "u", "password": "p"}),
                )
            )
            db.flush()
            db.get(AwsAccount, 1).proxy_id = 1
            db.commit()
    if stage in ("password", "membership", "subscribe"):
        with SessionLocal() as db:
            r = db.get(Subscription, rid)
            r.sso_user_id = "existing-sso"
            if stage != "password":
                r.password_encrypted = encrypt("Saved1!")
            if stage == "membership":
                group = ManagedGroup(
                    id="guard-group",
                    owner_id=2,
                    aws_account_id=1,
                    aws_scope="1",
                    request_key="guard-group",
                    payload_hash="guard-group",
                    name="group",
                    marker="group",
                    remote_id="remote-group",
                    state="ready",
                )
                db.add(group)
                db.flush()
                r.group_id = group.id
            if stage == "subscribe":
                r.provision_only, r.plan_id, r.subscription_type = False, 1, PRO
            db.commit()
    writes = []
    revoked = False

    def change():
        nonlocal revoked
        if revoked:
            return
        revoked = True
        with SessionLocal() as db:
            if revoke == "binding":
                db.delete(db.get(Binding, (2, 1)))
            elif revoke == "credentials":
                db.get(AwsAccount, 1).credentials_encrypted = encrypt(
                    {"access_key_id": "Changed", "secret_access_key": "Changed"}
                )
            else:
                db.get(Proxy, 1).enabled = False
            db.commit()

    class Identity:
        def get_user_id(self, **kwargs):
            change()
            raise ClientError(
                {"Error": {"Code": "ResourceNotFoundException"}}, "GetUserId"
            )

        def create_user(self, **kwargs):
            writes.append("create")
            return {"UserId": "new"}

    class Gateway(GroupGateway):
        def __init__(self, account):
            self.account, self.identity = account, Identity()

        def verify_identity(self):
            if stage in ("verify", "password"):
                change()

        def verify(self):
            if stage == "subscribe":
                change()

        def create_user(self, r):
            writes.append("create")
            return "new"

        def password(self, r):
            writes.append("password")
            return "Password1!"

        def get_group_membership(self, gid, uid):
            change()
            return None

        def create_group_membership(self, gid, uid):
            writes.append("membership")

        def subscribe(self, r):
            writes.append("subscribe")

    def factory(account):
        if stage != "lookup":
            return Gateway(account)
        # A real AwsGateway instance with only its SDK boundary stubbed. Its
        # internal GetUserId -> CreateUser sequence exercises the actual hook.
        gateway = object.__new__(AwsGateway)
        gateway.account, gateway.identity = account, Identity()
        gateway.verify_identity = lambda: None
        gateway.password = lambda r: writes.append("password") or "Password1!"
        return gateway

    assert run_one(factory)
    assert revoked
    assert writes == []
    assert state(rid) == "failed"


@pytest.mark.parametrize("family", ["group", "lifecycle", "plan"])
def test_configuration_change_during_family_lookup_prevents_mutation(
    alice, monkeypatch, family
):
    from app.config import settings
    from app.security import encrypt

    monkeypatch.setattr(settings, "plan_changes_enabled", True)
    model, key = family_work(family, 1, alice)
    entered, release = threading.Event(), threading.Event()
    run = family_runner(family, entered, release, [])
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run)
        try:
            assert entered.wait(2)
            with SessionLocal() as db:
                db.get(AwsAccount, 1).credentials_encrypted = encrypt(
                    {"access_key_id": "new", "secret_access_key": "new"}
                )
                db.commit()
        finally:
            release.set()
        assert future.result(timeout=2)
    with SessionLocal() as db:
        assert db.get(model, key).state == "failed"
        assert db.get(model, key).phase != "pending"


def test_auth_expiry_maintenance_has_bounded_fair_pages(alice, monkeypatch):
    from app import auth_jobs
    from app.models import AuthBatch
    from test_auth_batches import admission, record

    ids = [admission(alice, [record()]).json()["id"] for _ in range(3)]
    with SessionLocal() as db:
        for bid in ids:
            db.get(AuthBatch, bid).expires_at = now() - timedelta(seconds=1)
        db.commit()
    auth_jobs.expire_batches(limit=1)
    with SessionLocal() as db:
        assert (
            len(list(db.scalars(select(AuthBatch).where(AuthBatch.state == "active"))))
            == 2
        )
    auth_jobs.expire_batches(limit=1)
    auth_jobs.expire_batches(limit=1)
    with SessionLocal() as db:
        assert all(db.get(AuthBatch, bid).state == "expired" for bid in ids)


def test_pending_sso_keeps_original_config_across_restart():
    from app.aws import AwsFailure
    from app.security import encrypt
    from app.worker import run_one
    from test_workflows import Gateway

    rid = sso(1)
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        r.provision_only, r.plan_id, r.subscription_type = False, 1, PRO
        original = db.get(AwsAccount, 1).credentials_encrypted
        db.commit()
    calls = []

    class Uncertain(Gateway):
        def subscribe(self, r):
            calls.append("subscribe")
            raise AwsFailure("Lost response", uncertain=True)

        def is_subscribed(self, r):
            calls.append("reconcile")
            return True

    assert run_one(Uncertain)
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        assert r.state == "needs_review"
        saved = r.worker_config_hash
        assert saved
        r.state = "queued"
        db.get(AwsAccount, 1).credentials_encrypted = encrypt(
            {"access_key_id": "new", "secret_access_key": "new"}
        )
        db.commit()
    assert run_one(Uncertain)
    assert calls == ["subscribe"]
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        assert r.state == "needs_review" and r.worker_config_hash == saved
        r.state = "queued"
        db.get(AwsAccount, 1).credentials_encrypted = original
        db.get(AwsAccount, 1).active = False
        db.commit()
    assert run_one(Uncertain)
    assert calls == ["subscribe", "reconcile"]
    assert state(rid) == "completed"


def test_definite_sso_rejection_releases_attempt_hash_for_explicit_retry():
    from app.aws import AwsFailure
    from app.security import encrypt
    from app.worker import run_one
    from test_workflows import Gateway

    rid = sso(1)
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        r.provision_only, r.plan_id, r.subscription_type = False, 1, PRO
        db.commit()

    class Rejected(Gateway):
        def subscribe(self, r):
            raise AwsFailure("Definite rejection")

    assert run_one(Rejected)
    with SessionLocal() as db:
        r = db.get(Subscription, rid)
        assert r.state == "failed" and r.worker_config_hash is None
        r.state = "queued"
        db.get(AwsAccount, 1).credentials_encrypted = encrypt(
            {"access_key_id": "new", "secret_access_key": "new"}
        )
        db.commit()
    assert run_one(Gateway)
    assert state(rid) == "completed"


def test_bounded_auth_expiry_rotates_past_long_lived_active_batches(alice):
    from app import auth_jobs
    from app.models import AuthBatch
    from test_auth_batches import admission, record

    ids = sorted(admission(alice, [record()]).json()["id"] for _ in range(4))
    with SessionLocal() as db:
        db.get(AuthBatch, ids[-1]).expires_at = now() - timedelta(seconds=1)
        db.commit()
    for _ in range(4):
        auth_jobs.expire_batches(limit=1)
    with SessionLocal() as db:
        assert db.get(AuthBatch, ids[-1]).state == "expired"
        assert all(db.get(AuthBatch, bid).state == "active" for bid in ids[:-1])


@pytest.mark.parametrize("kind", ["rename", "delete"])
def test_uncertain_group_mutation_only_reconciles_after_restart(alice, kind):
    from app.group_jobs import run_group_job
    from app.models import GroupJob, ManagedGroup
    from test_groups import GroupGateway

    _, key = family_work("group", 1, alice)
    with SessionLocal() as db:
        op = db.get(GroupJob, key)
        op.kind, op.phase = kind, "pending"
        group = db.get(ManagedGroup, key)
        group.remote_id = "original-group"
        db.commit()
    writes = []

    class Reconcile(GroupGateway):
        groups = {
            "original-group": {
                "id": "original-group",
                "name": "unchanged",
                "description": key,
            }
        }

        def update_group(self, *args):
            writes.append("rename")

        def delete_group(self, *args):
            writes.append("delete")

        def list_group_memberships(self, *args):
            return []

    assert run_group_job(Reconcile)
    assert writes == []
    with SessionLocal() as db:
        assert db.get(GroupJob, key).state == "needs_review"


def test_schema15_adds_nullable_attempt_hash_without_rewriting_history(tmp_path):
    from app.database import Base
    from app.migrations import VERSION, migrate
    from app.models import SchemaVersion
    from sqlalchemy import create_engine, inspect

    sso(1)
    target = create_engine(f"sqlite:///{tmp_path / 'version14.db'}")
    Base.metadata.create_all(target)
    with engine.connect() as source, target.begin() as dest:
        for table in Base.metadata.sorted_tables:
            rows = [dict(row) for row in source.execute(table.select()).mappings()]
            if rows:
                dest.execute(table.insert(), rows)
        dest.execute(SchemaVersion.__table__.insert(), {"version": 14})
        if "worker_config_hash" in {
            c["name"] for c in inspect(dest).get_columns("console_subscriptions")
        }:
            dest.exec_driver_sql(
                "ALTER TABLE console_subscriptions DROP COLUMN worker_config_hash"
            )
        names = [c["name"] for c in inspect(dest).get_columns("console_subscriptions")]
        before = dest.exec_driver_sql("SELECT * FROM console_subscriptions").fetchall()
    migrate(target)
    migrate(target)
    with target.connect() as db:
        assert VERSION >= 15
        assert (
            db.exec_driver_sql("SELECT version FROM console_schema_version").scalar()
            == VERSION
        )
        projection = ",".join(f'"{name}"' for name in names)
        assert (
            db.exec_driver_sql(
                f"SELECT {projection} FROM console_subscriptions"
            ).fetchall()
            == before
        )
        assert db.exec_driver_sql(
            "SELECT worker_config_hash FROM console_subscriptions"
        ).fetchall() == [(None,)]
        assert db.exec_driver_sql("PRAGMA foreign_key_check").fetchall() == []
    target.dispose()


def process_command(family, selected="legacy", *options):
    return [
        sys.executable,
        str(Path(__file__).with_name("account_worker_probe.py")),
        family,
        str(selected),
        *options,
    ]


def process_environment():
    return dict(os.environ) | {"PYTHONPATH": str(Path(__file__).resolve().parents[1])}


@pytest.mark.parametrize("family", ["group", "native", "lifecycle", "plan", "auth"])
@pytest.mark.parametrize("explicit_first", [False, True])
def test_all_families_use_same_process_fence_before_claim(
    alice, monkeypatch, family, explicit_first
):
    from app.config import settings

    monkeypatch.setattr(settings, "plan_changes_enabled", True)
    model, key = family_work(family, 1, alice)
    entered, release = threading.Event(), threading.Event()
    run = family_runner(family, entered, release, [])
    if family == "auth":
        assert run(account_id=1)
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run, **({"account_id": 1} if explicit_first else {}))
        try:
            assert entered.wait(2)
            with SessionLocal() as db:
                db.get(model, key).lease_until = now() - timedelta(seconds=1)
                before = db.get(model, key).attempts
                db.commit()
            child = subprocess.run(
                process_command(
                    family, "legacy" if explicit_first else 1, "--forbid-gateway"
                ),
                env=process_environment(),
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert child.returncode == 0, child.stderr
            assert json.loads(child.stdout) == {
                "db": str(engine.url),
                "results": [False],
                "routes": [],
            }
            with SessionLocal() as db:
                assert db.get(model, key).attempts == before
        finally:
            release.set()
        assert future.result(timeout=2)


@pytest.mark.parametrize("holder", ["sso", "auth"])
def test_services_share_process_fence_while_other_account_finishes(alice, holder):
    from app.worker import run_one
    from test_workflows import Gateway

    accounts()
    a, b = sso(1), sso(2)
    auth_model, auth_a = family_work("auth", 1, alice)
    _, auth_b = family_work("auth", 2, alice)
    entered, release = threading.Event(), threading.Event()
    if holder == "sso":

        class Waiting(Gateway):
            def verify_identity(self):
                entered.set()
                assert release.wait(8)

        run = lambda: run_one(Waiting, account_id=1)
        other, model, completed = "auth", auth_model, auth_b
    else:
        run_auth = family_runner("auth", entered, release, [])
        assert run_auth(account_id=1)
        run = lambda: run_auth(account_id=1)
        other, model, completed = "sso", Subscription, b
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(run)
        try:
            assert entered.wait(2)
            child = subprocess.run(
                process_command(other, "legacy", "--drain"),
                env=process_environment(),
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert child.returncode == 0, child.stderr
            observed = json.loads(child.stdout)
            assert observed["db"] == str(engine.url)
            assert observed["results"][0]
            assert {aid for aid, _ in observed["routes"]} == {1, 2}
            with SessionLocal() as db:
                assert db.get(model, completed).state == "completed"
                assert db.get(model, auth_a if other == "auth" else a).state == "completed"
                held_model, held_id = (Subscription, a) if holder == "sso" else (auth_model, auth_a)
                assert db.get(held_model, held_id).state == "running"
                assert db.get(held_model, held_id).attempts == (1 if holder == "sso" else 2)
            fence_code = """
import json, sys
from app.account_dispatcher import account_fence, resource_fence
with account_fence(1, shared=True) as shared:
    with resource_fence('record', sys.argv[1]) as exact:
        with account_fence(1) as exclusive:
            print(json.dumps({'shared': shared, 'exact': exact, 'exclusive': exclusive}))
"""
            held_record = a if holder == "sso" else "auth-1"
            fenced = subprocess.run([sys.executable, "-c", fence_code, held_record],
                env=process_environment(), capture_output=True, text=True, timeout=5)
            assert fenced.returncode == 0, fenced.stderr
            assert json.loads(fenced.stdout) == {"shared": True, "exact": False, "exclusive": False}
        finally:
            release.set()
        assert future.result(timeout=2)


@pytest.mark.parametrize("service", ["sso", "auth"])
def test_service_sigterm_stops_admission_and_keeps_live_lane_fenced(alice, service):
    import signal

    from app.account_dispatcher import account_fence
    from app.auth_jobs import run_one
    from test_auth_batches import DoneAuth, Gateway

    accounts()
    if service == "sso":
        model, a, b = Subscription, sso(1), sso(2)
    else:
        model, a = family_work("auth", 1, alice)
        _, b = family_work("auth", 2, alice)
        assert run_one(Gateway, DoneAuth, account_id=1)
    child = subprocess.Popen(
        process_command(service, "legacy", "--service"),
        env=process_environment(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        # A separate wait prevents a broken service from hanging the test process.
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            line = pool.submit(child.stdout.readline)
            try:
                assert line.result(timeout=5).strip() == "entered"
            except BaseException:
                child.kill()
                raise
        child.send_signal(signal.SIGTERM)
        time.sleep(0.1)
        assert child.poll() is None
        with account_fence(1) as acquired:
            assert not acquired
        child.stdin.write("release\n")
        child.stdin.flush()
        _, errors = child.communicate(timeout=5)
        assert child.returncode == 0, errors
        with SessionLocal() as db:
            assert db.get(model, a).state == "completed"
            assert db.get(model, b).state == "queued"
        with account_fence(1) as acquired:
            assert acquired
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=5)


def test_group_job_exact_http_replay_ignores_internal_worker_attempt_hash(alice):
    import uuid

    from app.group_jobs import run_group_job
    from test_groups import GroupGateway, ready_group

    group = ready_group(alice, name="replay-" + uuid.uuid4().hex)
    body = {
        "kind": "rename",
        "name": "renamed",
        "expected_revision": 1,
        "request_key": str(uuid.uuid4()),
    }
    first = alice.post(f"/api/groups/{group['id']}/jobs", json=body)
    assert first.status_code == 202, first.text
    assert run_group_job(GroupGateway)
    replay = alice.post(f"/api/groups/{group['id']}/jobs", json=body)
    assert replay.status_code == 202, replay.text
    assert replay.json()["id"] == first.json()["id"]
