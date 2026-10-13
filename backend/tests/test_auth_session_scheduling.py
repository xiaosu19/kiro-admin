"""Session admission, using real durable native/OIDC steps and local transports."""

import base64
import io
import json
import threading
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import requests
from botocore.exceptions import ClientError
from sqlalchemy import select
from urllib3.response import HTTPResponse

from app import auth_jobs, auth_worker, external_auth_worker
from app.database import SessionLocal, engine
from app.enterprise_auth import EnterpriseAuth
from app.external_auth_models import ExternalExportItem
from app.external_enterprise import ExternalEnterpriseAuth, ExternalGateway
from app.models import AuthJob, AuthSecret, AwsAccount, Binding, RecordOperation, Subscription, now
from app.retry_models import AutomaticRetry
from app.security import decrypt
from test_auth_batches import Gateway, admission, record
from test_external_auth_batches import TEXT, admit
from test_identity_login import LOGIN, env_html, key_context, success, workflow


def step(dispatcher):
    """Drain this tick's threads without stopping admission or advancing the clock."""
    submitted = dispatcher.tick()
    for future in list(dispatcher._futures.values()):
        future.result(timeout=10)
    return submitted


@pytest.fixture
def protocol(monkeypatch, key_context):
    # All adapter parsing, login/password encryption, checkpoints, guards, OIDC
    # transitions and result validation remain real. Only wire responses/time
    # are synthetic, and each tick consumes part of the real adapter deadline.
    clock = [now().replace(tzinfo=timezone.utc).timestamp()]
    local, mutex = threading.local(), threading.Lock()
    active, starts, finished, stages, polls = {}, [], [], set(), Counter()
    maximum = [0]

    def utcnow():
        return datetime.fromtimestamp(clock[0], timezone.utc).replace(tzinfo=None)

    for module in (auth_jobs, external_auth_worker):
        monkeypatch.setattr(module, "now", utcnow)
    monkeypatch.setattr("app.automatic_retries.now", utcnow)

    class Oidc:
        def register_client(self, **kwargs):
            return {"clientId": "client", "clientSecret": "synthetic-secret",
                    "clientSecretExpiresAt": clock[0] + 3600}

        def start_device_authorization(self, **kwargs):
            return {"deviceCode": "device", "userCode": "OUR-CODE", "interval": 20,
                    "expiresIn": 600, "verificationUri": "https://device.sso.us-east-1.amazonaws.com/"}

        def create_token(self, **kwargs):
            username = local.state["username"]
            polls[username] += 1
            if polls[username] == 1:
                raise ClientError({"Error": {"Code": "AuthorizationPendingException"}}, "CreateToken")
            return {"accessToken": "synthetic-access", "refreshToken": "synthetic-refresh",
                    "expiresIn": 3600, "tokenType": "Bearer"}

        def close(self):
            pass

    class ManagedGateway(Gateway):
        def _client(self, *args, **kwargs):
            return Oidc()

    class PastedGateway(ExternalGateway):
        def _client(self, *args, **kwargs):
            return Oidc()

    class Observed:
        def __init__(self, gateway, *, checkpoint):
            super().__init__(gateway, checkpoint=checkpoint, clock=lambda: clock[0])

        def begin(self, username, *args, **kwargs):
            progress = super().begin(username, *args, **kwargs)
            with mutex:
                active[username] = clock[0]
                starts.append(username)
                maximum[0] = max(maximum[0], len(active))
            return progress

        def _advance(self, state, answer):
            local.state = state
            with mutex:
                stages.add(state["stage"])
            return super()._advance(state, answer)

        def advance(self, sealed, **kwargs):
            progress = super().advance(sealed, **kwargs)
            if progress.status == "done":
                username = decrypt(progress.sealed_state)["username"]
                with mutex:
                    active.pop(username)
                    finished.append(username)
            return progress

        def _request(self, state, *args, **kwargs):
            local.state, local.purpose = state, kwargs["purpose"]
            return super()._request(state, *args, **kwargs)

    class ManagedAuth(Observed, EnterpriseAuth):
        pass

    class PastedAuth(Observed, ExternalEnterpriseAuth):
        pass

    def send(_adapter, prepared, **kwargs):
        state, purpose = local.state, local.purpose
        user_id = state["expected_user_id"] or "user-" + state["username"]
        profile = state["binding"]["profile_arn"] or "arn:aws:codewhisperer:us-east-1:123456789012:profile/TEST"
        data = {
            "portal": env_html(),
            "login": {"redirectUrl": LOGIN, "csrfToken": "login-csrf"},
            "signin": '<meta name="initial-workflow-state" content="' + base64.b64encode(
                json.dumps(workflow("get-password", key_context[1])).encode()).decode() + '">',
            "execute": success(),
            "exchange": {"token": "portal-secret"},
            "whoami": {"userIdentifier": user_id, "directoryId": state["binding"]["directory"]},
            "device_session": {"token": "session-secret"},
            "accept": {"deviceContext": {"deviceContextId": "context", "clientId": "client", "clientType": "public"}},
            "associate": {},
            "profiles": {"profiles": [{"arn": profile, "profileName": "Synthetic profile"}]},
            "usage": {"userInfo": {"userId": state["binding"]["directory"] + "." + user_id},
                      "subscriptionInfo": {"type": "Q_DEVELOPER_STANDALONE_PRO"}},
        }[purpose]
        response = requests.Response()
        response.status_code, response.url, response.request = 200, prepared.url, prepared
        payload = data.encode() if isinstance(data, str) else json.dumps(data).encode()
        response.raw = HTTPResponse(body=io.BytesIO(payload), preload_content=False)
        return response

    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", send)
    monkeypatch.setattr(external_auth_worker, "ExternalEnterpriseAuth", PastedAuth)
    monkeypatch.setattr(external_auth_worker, "ExternalGateway", PastedGateway)

    def dispatcher(**kwargs):
        return auth_worker.make_dispatcher(gateway_factory=ManagedGateway,
                                          auth_factory=ManagedAuth, **kwargs)

    return SimpleNamespace(clock=clock, starts=starts, finished=finished, maximum=maximum,
                           active=active, stages=stages, dispatcher=dispatcher,
                           ManagedAuth=ManagedAuth, ManagedGateway=ManagedGateway)


def enqueue(client, family, count):
    if family == "auth":
        response = admission(client, [record(username=f"managed-{i:02}") for i in range(count)])
    else:
        rows = [json.loads(TEXT) | {"username": f"external-{i:02}"} for i in range(count)]
        response = admit(client, json.dumps(rows))
    assert response.status_code == 202, response.text
    return response.json()


def states(family):
    with SessionLocal() as db:
        model = RecordOperation if family == "auth" else ExternalExportItem
        return Counter(db.scalars(select(model.state)))


@pytest.mark.parametrize("count", [2, 60])
@pytest.mark.parametrize("family", ["auth", "external"])
@pytest.mark.parametrize("session_slots", [2, 4])
def test_logins_finish_with_bounded_session_slots_before_native_deadlines(
        alice, protocol, family, count, session_slots, monkeypatch):
    monkeypatch.setattr(auth_worker.settings, "auth_worker_concurrency", session_slots)
    monkeypatch.setattr(auth_worker.settings, "auth_per_account_concurrency", session_slots)
    # Tuning authentication must not also raise the AWS creation/subscription cap.
    assert auth_worker.settings.per_account_concurrency == 2
    enqueue(alice, family, count)
    dispatcher = protocol.dispatcher()
    try:
        for _ in range(1200):
            step(dispatcher)
            protocol.clock[0] += 5
            current = states(family)
            if not any(current[s] for s in ("queued", "running", "polling")):
                break
        assert states(family) == {"completed": count}
        assert protocol.maximum[0] == min(session_slots, count)
        assert len(protocol.starts) == len(set(protocol.starts)) == count
        assert len(protocol.finished) == count
        assert {"register", "device", "workflow", "whoami", "associate", "poll", "profiles", "usage"} <= protocol.stages
    finally:
        dispatcher.close(wait=True)


@pytest.mark.parametrize("family", ["auth", "external"])
@pytest.mark.parametrize("waiting", ["poll", "retry", "running"])
def test_wait_keeps_session_budget_after_worker_restart(alice, protocol, family, waiting):
    enqueue(alice, family, 5)
    first = protocol.dispatcher()
    step(first)
    first.close(wait=True)
    with SessionLocal() as db:
        if family == "auth":
            selected = list(db.scalars(select(RecordOperation).where(RecordOperation.attempts > 0)))
            for op in selected:
                if waiting == "poll":
                    op.state = "polling"
                    db.get(AuthJob, op.id).next_poll_at = now() + timedelta(minutes=5)
                elif waiting == "retry":
                    db.add(AutomaticRetry(family="auth", job_id=op.id,
                                          next_retry_at=now() + timedelta(minutes=5)))
                else:
                    op.state, op.lease_until = "running", now() + timedelta(minutes=5)
        else:
            selected = list(db.scalars(select(ExternalExportItem).where(ExternalExportItem.workflow_encrypted.is_not(None))))
            for item in selected:
                if waiting == "running":
                    item.state, item.lease_until = "running", now() + timedelta(minutes=5)
                else:
                    item.state, item.next_poll_at = "polling", now() + timedelta(minutes=5)
                    if waiting == "retry":
                        item.workflow_encrypted, item.retry_count = None, 1
        assert len(selected) == 2
        db.commit()
    restarted = protocol.dispatcher()
    try:
        for _ in range(4):
            assert step(restarted) == 0
        assert len(protocol.starts) == 2
        protocol.clock[0] += 301
        assert step(restarted) == 2
        # A transient external restart has no workflow, but must reuse the same
        # two session reservations, even when beginning a replacement attempt.
        assert set(protocol.starts) == set(protocol.active)
        assert len(set(protocol.starts)) == 2
    finally:
        restarted.close(wait=True)


def test_two_sessions_really_overlap_without_starting_a_third(alice, protocol):
    enqueue(alice, "auth", 3)
    entered, release, mutex = [], threading.Event(), threading.Lock()

    class Blocking(protocol.ManagedAuth):
        def begin(self, username, *args, **kwargs):
            with mutex:
                entered.append(username)
            assert release.wait(5)
            return super().begin(username, *args, **kwargs)

    dispatcher = auth_worker.make_dispatcher(gateway_factory=protocol.ManagedGateway, auth_factory=Blocking)
    try:
        assert dispatcher.tick() == 2
        from test_account_dispatcher import eventually
        eventually(lambda: len(entered) == 2)
        assert dispatcher.tick() == 0
        assert len(entered) == 2
        from app.account_dispatcher import account_fence
        with account_fence(1) as acquired:
            assert not acquired
    finally:
        release.set()
        dispatcher.close(wait=True)


def test_five_accounts_rotate_at_session_admission_and_keep_per_account_cap(alice, protocol):
    with SessionLocal() as db:
        source = db.get(AwsAccount, 1)
        values = {column.name: getattr(source, column.name) for column in AwsAccount.__table__.columns}
        for aid in range(2, 6):
            db.add(AwsAccount(**(values | {"id": aid, "name": f"Account {aid}", "aws_account_id": str(aid) * 12})))
            db.flush()
            db.add(Binding(user_id=2, aws_account_id=aid))
        db.commit()
    records, accounts = [], {}
    for aid in range(1, 6):
        for index in range(3):
            item = record(username=f"account-{aid}-{index}")
            records.append(item)
            accounts[item.username] = aid
            with SessionLocal() as db:
                db.get(Subscription, item.id).aws_account_id = aid
                db.commit()
    assert admission(alice, records).status_code == 202
    dispatcher = protocol.dispatcher(max_workers=8)
    try:
        assert step(dispatcher) == 8
        assert set(accounts[name] for name in protocol.starts) == set(range(1, 6))
        for _ in range(150):
            active_accounts = Counter(accounts[name] for name in protocol.active)
            assert max(active_accounts.values(), default=0) <= 2
            assert len(protocol.active) <= 8
            step(dispatcher)
            protocol.clock[0] += 5
            if len(protocol.finished) == 15:
                break
        assert states("auth") == {"completed": 15}
    finally:
        dispatcher.close(wait=True)


@pytest.mark.parametrize("family", ["auth", "external"])
@pytest.mark.parametrize("yielded", ["challenge", "failed", "needs_review", "cancelled", "completed"])
def test_human_action_and_terminal_rows_release_session_slots(alice, protocol, family, yielded):
    enqueue(alice, family, 5)
    dispatcher = protocol.dispatcher()
    try:
        assert step(dispatcher) == 2
        with SessionLocal() as db:
            model = RecordOperation if family == "auth" else ExternalExportItem
            started = (model.attempts > 0) if family == "auth" else model.workflow_encrypted.is_not(None)
            for row in db.scalars(select(model).where(started)):
                row.state = yielded
            db.commit()
        assert step(dispatcher) == 2
        assert len(protocol.starts) == 4
    finally:
        dispatcher.close(wait=True)


def test_mixed_managed_and_pasted_sessions_share_managed_account_budget(alice, protocol):
    managed = [record(username=f"mixed-managed-{i}") for i in range(2)]
    pasted = [record(username=f"mixed-pasted-{i}") for i in range(2)]
    response = admit(alice, json.dumps([json.loads(TEXT) | {"username": r.username} for r in pasted]))
    assert response.status_code == 202, response.text
    assert external_auth_worker.run_one()
    assert admission(alice, managed).status_code == 202
    enqueue(alice, "external", 2)
    dispatcher = protocol.dispatcher(max_workers=4)
    known = {r.username for r in managed + pasted}
    try:
        step(dispatcher)
        assert len(protocol.active) == 4
        assert sum(name in known for name in protocol.active) == 2
        for _ in range(100):
            assert sum(name in known for name in protocol.active) <= 2
            assert len(protocol.active) <= 4
            step(dispatcher)
            protocol.clock[0] += 5
            if len(protocol.finished) == 6:
                break
        assert states("auth") == {"completed": 2}
        assert states("external") == {"completed": 4}
    finally:
        dispatcher.close(wait=True)


@pytest.mark.parametrize("family", ["auth", "external"])
def test_recovery_drains_preexisting_workflows_in_bounded_groups(alice, protocol, family):
    enqueue(alice, family, 8)
    # Reproduce an old worker that already began all eight before restarting.
    if family == "auth":
        for aid, _, rid in auth_jobs.candidate_tasks():
            assert auth_jobs.run_one(protocol.ManagedGateway, protocol.ManagedAuth,
                                     account_id=aid, record_id=rid, maintenance=False)
    else:
        for aid, _, lane in external_auth_worker.candidate_tasks():
            assert external_auth_worker.run_one(lane_id=lane)
    assert len(protocol.starts) == 8
    restarted = protocol.dispatcher()
    try:
        for _ in range(3):
            step(restarted)
        with SessionLocal() as db:
            if family == "auth":
                workflows = db.scalars(select(AuthSecret.workflow_encrypted))
            else:
                workflows = db.scalars(select(ExternalExportItem.workflow_encrypted))
            assert sum(decrypt(value)["stage"] != "register" for value in workflows) == 2
        assert len(protocol.starts) == 8
    finally:
        restarted.close(wait=True)


def test_terminal_commit_keeps_slot_until_transport_cleanup_finishes(alice):
    from test_auth_batches import DoneAuth
    from test_account_dispatcher import eventually
    from app.account_dispatcher import account_fence

    enqueue(alice, "auth", 4)
    started, closing, release, mutex = [], [], threading.Event(), threading.Lock()

    class ClosingAuth(DoneAuth):
        def begin(self, username, *args, **kwargs):
            with mutex:
                started.append(username)
            return super().begin(username, *args, **kwargs)

        def advance(self, *args, **kwargs):
            result = super().advance(*args, **kwargs)
            self.completed = result.status == "done"
            return result

        def close(self):
            if getattr(self, "completed", False):
                with mutex:
                    closing.append(1)
                assert release.wait(5)

    dispatcher = auth_worker.make_dispatcher(gateway_factory=Gateway, auth_factory=ClosingAuth)
    try:
        assert step(dispatcher) == 2
        assert dispatcher.tick() == 2
        eventually(lambda: len(closing) == 2)
        assert states("auth") == {"completed": 2, "queued": 2}
        for _ in range(3):
            assert dispatcher.tick() == 0
        assert len(started) == 2
        with account_fence(1) as acquired:
            assert not acquired
        release.set()
        for future in list(dispatcher._futures.values()):
            future.result(timeout=5)
        assert step(dispatcher) == 2
        assert len(started) == 4
    finally:
        release.set()
        dispatcher.close(wait=True)


def test_blocked_unstarted_records_do_not_keep_session_slots(alice, protocol):
    from app.account_dispatcher import resource_fence

    records = [record(username=f"fenced-{i}") for i in range(3)]
    assert admission(alice, records).status_code == 202
    dispatcher = protocol.dispatcher()
    try:
        with ExitStack() as stack:
            for item in records[:2]:
                assert stack.enter_context(resource_fence("record", item.id))
            assert step(dispatcher) == 2
            assert protocol.starts == []
            assert step(dispatcher) == 2
            assert protocol.starts == [records[2].username]
    finally:
        dispatcher.close(wait=True)


def test_metadata_discovery_uses_two_queries_for_both_sixty_item_queues(alice):
    from sqlalchemy import event

    enqueue(alice, "auth", 60)
    enqueue(alice, "external", 60)
    reads = []

    def observed(_connection, _cursor, statement, _parameters, _context, _many):
        reads.append(statement)

    event.listen(engine, "before_cursor_execute", observed)
    try:
        metadata = auth_jobs.session_candidates() + external_auth_worker.session_candidates()
    finally:
        event.remove(engine, "before_cursor_execute", observed)
    assert len(metadata) == 120
    assert len(reads) == 2
    assert all(row.ready and not row.started for row in metadata)
