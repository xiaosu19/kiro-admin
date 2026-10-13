"""Automatic recovery is bounded, durable, and never replays an uncertain write."""

from datetime import timedelta

import pytest
import requests
from botocore.exceptions import ClientError

from app.database import SessionLocal
from app.models import AwsAccount, Subscription, now
from app.worker import run_one
from test_workflows import Gateway, count, create
from test_native_groups import native as native
from test_provisioning_admission import ready as ready
from test_provisioning_admission import remote as remote
from test_provisioning_coordinator import gateway as numbered_gateway


def seed(**values):
    with SessionLocal() as db:
        record = Subscription(
            id="automatic-retry-record", owner_id=2, aws_account_id=1,
            request_key="automatic-retry-record", username="retry-user",
            email="retry@example.org", provision_only=True, reserved=False,
            portal_url=db.get(AwsAccount, 1).portal_url,
            **values,
        )
        db.add(record)
        db.commit()
        return record.id


def client_error(code="InternalServerException", status=500):
    return ClientError({"Error": {"Code": code},
                        "ResponseMetadata": {"HTTPStatusCode": status}}, "ListUsers")


def due(family, job_id):
    from app.retry_models import AutomaticRetry

    with SessionLocal() as db:
        retry = db.get(AutomaticRetry, (family, job_id))
        retry.next_retry_at = now() - timedelta(seconds=1)
        db.commit()


def test_terminal_retry_projection_hides_schedule_and_keeps_history():
    from app.automatic_retries import retry_view, schedule_retry
    from app.retry_models import AutomaticRetry

    with SessionLocal() as db:
        assert schedule_retry(db, "sso", "terminal-record", client_error())
        db.commit()
        active = retry_view(db, "sso", "terminal-record")
        terminal = retry_view(db, "sso", "terminal-record", active=False)
        assert active["next_retry_at"] and active["retry_mode"] == "retry"
        assert terminal["next_retry_at"] is None and terminal["retry_mode"] is None
        assert terminal["automatic_retry_count"] == 1
        assert not terminal["retry_exhausted"]
        assert db.get(AutomaticRetry, ("sso", "terminal-record")).next_retry_at


def test_transient_preflight_failure_has_five_durable_retries_and_backoff():
    rid = seed()
    attempts = []

    class Unavailable(Gateway):
        def verify_identity(self):
            attempts.append("preflight")
            raise client_error()

    assert run_one(Unavailable, account_id=1)
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        assert record.state == "queued"
        assert record.step == "create_user"
    assert not run_one(Unavailable, account_id=1)
    for _ in range(5):
        due("sso", rid)
        assert run_one(Unavailable, account_id=1)
    from app.retry_models import AutomaticRetry
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        retry = db.get(AutomaticRetry, ("sso", rid))
        assert record.state == "failed" and record.attempts == 6
        assert retry.retry_count == 5 and retry.exhausted
        assert retry.next_retry_at is None
    assert not run_one(Unavailable, account_id=1)
    assert len(attempts) == 6


@pytest.mark.parametrize("code,status", [
    ("AccessDeniedException", 403), ("InvalidPasswordException", 400),
    ("AccountLockedException", 400), ("unsupported_mfa", 400),
])
def test_authentication_refusals_never_automatically_retry(code, status):
    from app.retry_models import AutomaticRetry

    rid = seed()

    class Refused(Gateway):
        def verify_identity(self):
            raise client_error(code, status)

    assert run_one(Refused, account_id=1)
    assert not run_one(Refused, account_id=1)
    with SessionLocal() as db:
        assert db.get(Subscription, rid).state == "failed"
        assert db.get(AutomaticRetry, ("sso", rid)) is None


def test_uncertain_paid_write_rechecks_propagation_without_resending(alice, monkeypatch):
    from app.retry_models import AutomaticRetry

    rid = create(alice).json()["id"]
    calls = []

    class LostReply(Gateway):
        def subscribe(self, record):
            calls.append("write")
            raise requests.ReadTimeout("lost response")

        def is_subscribed(self, record):
            calls.append("read")
            return False

    assert run_one(LostReply, account_id=1)
    for _ in range(5):
        due("sso", rid)
        assert run_one(LostReply, account_id=1)
    from app import automatic_retries
    elapsed = now() + timedelta(hours=25)
    monkeypatch.setattr(automatic_retries, "now", lambda: elapsed)
    due("sso", rid)
    assert run_one(LostReply, account_id=1)
    assert calls == ["write"] + ["read"] * 6
    assert count() == (0, 1, 0, 1)
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        retry = db.get(AutomaticRetry, ("sso", rid))
        assert record.state == "needs_review" and record.step == "subscribe_pending"
        assert retry.retry_count == 1 and retry.exhausted
        assert retry.propagation_check_count == 6


def test_untyped_uncertain_failure_requires_review_without_automatic_guessing(alice):
    from app.aws import AwsFailure
    from app.retry_models import AutomaticRetry

    rid = create(alice).json()["id"]

    class UnknownFailure(Gateway):
        def subscribe(self, record):
            raise AwsFailure("unclassified response", uncertain=True)

    assert run_one(UnknownFailure, account_id=1)
    with SessionLocal() as db:
        assert db.get(Subscription, rid).state == "needs_review"
        assert db.get(AutomaticRetry, ("sso", rid)) is None


def test_password_connect_timeout_is_proven_unsent_and_retries_once():
    rid = seed(sso_user_id="existing-user", step="password")
    calls = []

    class ConnectFailure(Gateway):
        def password(self, record):
            calls.append("password")
            if len(calls) == 1:
                raise requests.ConnectTimeout("before connect")
            return "SavedOTP123!"

    assert run_one(ConnectFailure, account_id=1)
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        assert record.state == "queued" and record.step == "password"
        assert record.credential_state == "one_time"
    due("sso", rid)
    assert run_one(ConnectFailure, account_id=1)
    with SessionLocal() as db:
        assert db.get(Subscription, rid).state == "completed"
    assert calls == ["password", "password"]


@pytest.mark.parametrize("metadata", [
    {"HTTPStatusCode": 429, "RetryAttempts": 1},
    {"RetryAttempts": 0},
])
def test_password_sdk_retries_do_not_prove_the_original_write_was_rejected(metadata):
    from app.retry_models import AutomaticRetry

    rid = seed(sso_user_id="existing-user", step="password")

    class Retried(Gateway):
        def password(self, record):
            raise ClientError({"Error": {"Code": "ThrottlingException"},
                               "ResponseMetadata": metadata}, "UpdatePassword")

    assert run_one(Retried, account_id=1)
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        assert record.state == "needs_review" and record.step == "password_pending"
        assert record.credential_state == "unknown"
        assert db.get(AutomaticRetry, ("sso", rid)) is None


def test_configuration_change_stops_automatic_retry_before_constructing_gateway():
    rid = seed()
    calls = []

    class Unavailable(Gateway):
        def __init__(self, account):
            calls.append(account.region)

        def verify_identity(self):
            raise client_error()

    assert run_one(Unavailable, account_id=1)
    with SessionLocal() as db:
        db.get(AwsAccount, 1).region = "eu-west-1"
        db.commit()
    due("sso", rid)
    assert run_one(Unavailable, account_id=1)
    assert len(calls) == 1
    with SessionLocal() as db:
        assert db.get(Subscription, rid).state == "failed"


def test_record_operation_lock_blocks_retry_before_any_remote_action():
    rid = seed(active_operation_id="cascade-operation")
    constructions = []

    class Locked(Gateway):
        def __init__(self, account):
            constructions.append(account.id)

    assert run_one(Locked, account_id=1)
    assert constructions == []
    with SessionLocal() as db:
        assert db.get(Subscription, rid).state == "failed"


def test_aws_failure_classification_uses_metadata_and_never_message_text():
    from app.aws import AwsFailure
    from app.retry_policy import classify_failure

    assert classify_failure(AwsFailure("looks like a timeout")).transient is False
    assert classify_failure(AwsFailure("fixed public error", code="ThrottlingException",
                                       http_status=429, proven_unsent=True)).transient
    denied = classify_failure(AwsFailure("fixed public error", code="AccessDeniedException",
                                         http_status=500, retryable=True))
    assert denied.stop and not denied.transient


def test_terminal_auth_code_overrides_transient_metadata():
    from app.identity_login import AuthError
    from app.retry_policy import classify_failure

    failure = classify_failure(AuthError("login_refused", aws_code="InternalServerException",
                                         http_status=500, retryable=True))
    assert failure.stop and not failure.transient


def test_botocore_tls_failure_is_not_a_transient_retry():
    from botocore.exceptions import SSLError
    from app.retry_policy import classify_failure

    failure = classify_failure(SSLError(endpoint_url="https://fake.invalid", error="invalid cert"))
    assert failure.stop and not failure.transient


@pytest.mark.parametrize("retry_attempts,uncertain", [(0, False), (1, True)])
def test_oidc_retry_metadata_preserves_uncertainty_from_sdk_retries(retry_attempts, uncertain):
    from app.enterprise_auth import EnterpriseAuth
    from app.identity_login import AuthError
    from app.retry_policy import classify_failure
    from test_identity_login import Gateway as IdentityGateway, NOW

    class Throttled:
        def register_client(self, **kwargs):
            raise ClientError({"Error": {"Code": "ThrottlingException"},
                               "ResponseMetadata": {"HTTPStatusCode": 429,
                                                    "RetryAttempts": retry_attempts}}, "RegisterClient")

    gateway = IdentityGateway()
    gateway.oidc = Throttled()
    adapter = EnterpriseAuth(gateway, checkpoint=lambda cp: None, clock=lambda: NOW)
    progress = adapter.begin("retry-user", "Synthetic123!", expected_user_id="synthetic-user")
    with pytest.raises(AuthError) as error:
        adapter.advance(progress.sealed_state)
    assert error.value.uncertain is uncertain
    failure = classify_failure(error.value)
    assert failure.transient and failure.proven_unsent is not uncertain


def test_group_preflight_transient_retries_with_original_config(alice):
    from app.group_jobs import run_group_job
    from app.models import GroupJob, ManagedGroup
    from sqlalchemy import select
    from test_groups import GroupGateway, create_group

    group = create_group(alice).json()
    with SessionLocal() as db:
        jid = db.scalar(select(GroupJob.id).where(GroupJob.group_id == group["id"]))
    attempts = []

    class Delayed(GroupGateway):
        groups = {}

        def get_group_id(self, name):
            attempts.append("lookup")
            if len(attempts) == 1:
                raise client_error("ThrottlingException", 429)
            return super().get_group_id(name)

    assert run_group_job(Delayed, account_id=1)
    with SessionLocal() as db:
        assert db.get(GroupJob, jid).state == "queued"
        assert db.get(ManagedGroup, group["id"]).active_job_id == jid
    assert not run_group_job(Delayed, account_id=1)
    due("group", jid)
    assert run_group_job(Delayed, account_id=1)
    with SessionLocal() as db:
        assert db.get(GroupJob, jid).state == "completed"
    assert attempts == ["lookup", "lookup"]


def test_auth_read_failure_retries_saved_state_without_restarting_login(alice):
    from app.auth_jobs import run_one as auth_one
    from app.identity_login import AuthError
    from app.models import AuthSecret, RecordOperation
    from app.security import decrypt
    from test_auth_batches import DoneAuth, Gateway as AuthGateway, admission, record

    r = record()
    response = admission(alice, [r]).json()
    jid = response["items"][0]["operation_id"]
    calls = []

    class Delayed(DoneAuth):
        def _advance(self, state, answer):
            calls.append(state["stage"])
            if len(calls) == 1:
                raise AuthError("transport_failed", retryable=True)
            return super()._advance(state, answer)

    assert auth_one(AuthGateway, Delayed, account_id=1)
    assert auth_one(AuthGateway, Delayed, account_id=1)
    with SessionLocal() as db:
        op = db.get(RecordOperation, jid)
        assert op.state == "queued"
        assert db.get(Subscription, r.id).active_operation_id == jid
        state = decrypt(db.get(AuthSecret, jid).workflow_encrypted)
        assert state["status"] == "ready" and not state["inflight"]
    assert not auth_one(AuthGateway, Delayed, account_id=1)
    due("auth", jid)
    assert auth_one(AuthGateway, Delayed, account_id=1)
    with SessionLocal() as db:
        assert db.get(RecordOperation, jid).state == "completed"
    assert len(calls) == 2 and calls[0] == calls[1]


def test_native_preflight_retry_retains_reservation_and_group_lock(alice, native):
    from app.group_subscription_worker import run_one as native_one
    from app.models import ManagedGroup, NativeGroupOperation
    from sqlalchemy import select
    from test_native_groups import counter, seed_group, subscribe

    gid = seed_group(n=1)
    assert subscribe(alice, gid).status_code == 202
    with SessionLocal() as db:
        oid = db.scalar(select(NativeGroupOperation.id))
    checks = []

    class Delayed(native):
        def verify(self):
            checks.append("verify")
            if len(checks) == 1:
                raise client_error("ThrottlingException", 429)
            return super().verify()

    assert native_one(Delayed, account_id=1)
    with SessionLocal() as db:
        assert db.get(NativeGroupOperation, oid).state == "queued"
        assert db.get(ManagedGroup, gid).active_job_id == oid
    assert counter() == (0, 1, 0)
    assert not native_one(Delayed, account_id=1)
    due("native", oid)
    assert native_one(Delayed, account_id=1)
    assert counter() == (1, 0, 1)
    assert len(native.writes) == 1


def test_native_paid_timeout_automatically_reconciles_without_another_write(alice, native):
    from app.group_subscription_worker import run_one as native_one
    from app.models import NativeGroupOperation
    from sqlalchemy import select
    from test_native_groups import counter, seed_group, subscribe

    gid = seed_group(n=1)
    assert subscribe(alice, gid).status_code == 202
    with SessionLocal() as db:
        oid = db.scalar(select(NativeGroupOperation.id))

    class LostReply(native):
        def subscribe_group(self, group, subscription_type):
            super().subscribe_group(group, subscription_type)
            raise requests.ReadTimeout("lost response")

    assert native_one(LostReply, account_id=1)
    due("native", oid)
    assert native_one(LostReply, account_id=1)
    assert len(native.writes) == 1
    assert counter() == (1, 0, 1)
    with SessionLocal() as db:
        assert db.get(NativeGroupOperation, oid).state == "completed"


def test_auth_retry_budget_does_not_count_normal_steps(alice):
    from app.auth_jobs import run_one as auth_one
    from app.identity_login import AuthError
    from app.models import RecordOperation
    from app.retry_models import AutomaticRetry
    from test_auth_batches import DoneAuth, Gateway as AuthGateway, admission, record

    response = admission(alice, [record()]).json()
    jid = response["items"][0]["operation_id"]

    class Unavailable(DoneAuth):
        def _advance(self, state, answer):
            raise AuthError("transport_failed", retryable=True)

    assert auth_one(AuthGateway, Unavailable, account_id=1)  # Normal begin step.
    assert auth_one(AuthGateway, Unavailable, account_id=1)
    for _ in range(5):
        due("auth", jid)
        assert auth_one(AuthGateway, Unavailable, account_id=1)
    with SessionLocal() as db:
        op = db.get(RecordOperation, jid)
        retry = db.get(AutomaticRetry, ("auth", jid))
        assert op.state == "failed" and op.attempts == 7
        assert retry.retry_count == 5 and retry.exhausted


def test_cancellation_wins_over_a_simultaneous_auth_retry(alice):
    from app.auth_jobs import run_one as auth_one
    from app.identity_login import AuthError
    from app.models import RecordOperation
    from app.retry_models import AutomaticRetry
    from test_auth_batches import DoneAuth, Gateway as AuthGateway, admission, record

    response = admission(alice, [record()]).json()
    jid = response["items"][0]["operation_id"]

    class Cancelled(DoneAuth):
        def _advance(self, state, answer):
            assert alice.post(f"/api/auth-batches/{response['id']}/cancel").status_code == 200
            raise AuthError("transport_failed", retryable=True)

    assert auth_one(AuthGateway, Cancelled, account_id=1)
    assert auth_one(AuthGateway, Cancelled, account_id=1)
    with SessionLocal() as db:
        assert db.get(RecordOperation, jid).state == "cancelled"
        assert db.get(AutomaticRetry, ("auth", jid)) is None


def test_uncertain_password_write_does_not_enter_auth_retry_queue(alice):
    from app.auth_jobs import run_one as auth_one
    from app.identity_login import AuthError
    from app.models import RecordOperation
    from app.retry_models import AutomaticRetry
    from test_auth_batches import DoneAuth, Gateway as AuthGateway, admission, record

    r = record()
    response = admission(alice, [r]).json()
    jid = response["items"][0]["operation_id"]

    class UnknownPassword(DoneAuth):
        def _advance(self, state, answer):
            state["password_write_pending"] = True
            state["inflight"] = "password_change"
            raise AuthError("transport_failed", uncertain=True, retryable=True)

    assert auth_one(AuthGateway, UnknownPassword, account_id=1)
    assert auth_one(AuthGateway, UnknownPassword, account_id=1)
    with SessionLocal() as db:
        assert db.get(RecordOperation, jid).state == "needs_review"
        assert db.get(Subscription, r.id).credential_state == "unknown"
        assert db.get(AutomaticRetry, ("auth", jid)) is None


def test_numbered_stop_cancels_a_group_retry_before_another_remote_call(alice, numbered_gateway):
    from app.group_jobs import run_group_job
    from app.models import GroupJob, ProvisioningAccountBatch
    from app.provisioning_coordinator import run_one as coordinate
    from test_provisioning_admission import admit
    from test_provisioning_coordinator import body, coordinator_to_child

    parent = admit(alice, body()).json()
    cid = coordinator_to_child(parent, "group")
    with SessionLocal() as db:
        jid = db.get(ProvisioningAccountBatch, cid).group_job_id
    calls = []

    class Delayed(numbered_gateway):
        def get_group_id(self, name):
            calls.append(name)
            raise client_error()

    assert run_group_job(Delayed, account_id=1)
    with SessionLocal() as db:
        assert db.get(GroupJob, jid).state == "queued"
    url = f"/api/provisioning-batches/{parent['id']}/accounts/{cid}/stop"
    assert alice.post(url, json={"request_key": "stop-during-retry"}).status_code == 202
    coordinate(account_id=1)
    due("group", jid)
    assert not run_group_job(Delayed, account_id=1)
    assert len(calls) == 1 and not numbered_gateway.events
    with SessionLocal() as db:
        assert db.get(GroupJob, jid).state == "cancelled"


def test_auth_session_change_cancels_saved_retry_before_adapter_construction(alice):
    from app.auth_jobs import run_one as auth_one
    from app.identity_login import AuthError
    from app.models import RecordOperation, User
    from test_auth_batches import DoneAuth, Gateway as AuthGateway, admission, record

    response = admission(alice, [record()]).json()
    jid = response["items"][0]["operation_id"]
    calls = []

    class Delayed(DoneAuth):
        def _advance(self, state, answer):
            calls.append("read")
            raise AuthError("transport_failed", retryable=True)

    assert auth_one(AuthGateway, Delayed, account_id=1)
    assert auth_one(AuthGateway, Delayed, account_id=1)
    with SessionLocal() as db:
        db.get(User, 2).session_version += 1
        db.commit()
    due("auth", jid)
    assert auth_one(AuthGateway, Delayed, account_id=1)
    assert calls == ["read"]
    with SessionLocal() as db:
        assert db.get(RecordOperation, jid).state == "cancelled"
