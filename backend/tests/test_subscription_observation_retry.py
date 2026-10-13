"""Confirmed writes wait for aggregate propagation using bounded read-only retries."""

import uuid
from datetime import timedelta

import pytest
import requests
from sqlalchemy import select

from app.aws import AwsFailure, AwsGateway
from app.database import SessionLocal
from app.models import (
    AwsAccount, GroupJob, GroupMemberActivation, ManagedGroup, NativeGroupOperation, Subscription, now,
)
from app.retry_models import AutomaticRetry
from app.retry_policy import classify_failure
from app.subscription_eligibility import has_confirmed_subscription_access
from app.subscription_sources import observe_subscription
from test_automatic_retries import due
from test_native_groups import PRO, activate, counter, seed_group, subscribe
from test_native_groups import native as native


def active_group(native):
    seed_group(1)
    native.assignments['remote-group-1'] = {
        'status': 'active', 'subscription_type': PRO, 'expires_at': None,
    }


def test_confirmed_live_source_with_missing_aggregate_has_typed_retryable_failure(native):
    active_group(native)
    with SessionLocal() as db:
        record = db.get(Subscription, 'group-1-record-0')
        with pytest.raises(AwsFailure) as caught:
            observe_subscription(native(None), record, rows=[])
    failure = classify_failure(caught.value)
    assert failure.code == 'subscription_observation_propagating'
    assert failure.transient and caught.value.uncertain


@pytest.mark.parametrize('rows', [
    [{}, {}], [{'principal': None}],
    [{'principal': {'user': 'unrelated'}, 'type': None}],
    [{'principal': {'user': 'unrelated'}, 'type': {'amazonQ': PRO},
      'status': 'ACTIVE', 'aggregatedSubscriptionType': 'GROUP', 'expirationDate': 'invalid'}],
    [{'principal': {'user': 'unrelated'}, 'type': {'amazonQ': PRO},
      'status': 'ACTIVE', 'aggregatedSubscriptionType': 'GROUP'}] * 2,
    [{'principal': {'user': 'sso-group-1-record-0'}, 'type': {'amazonQ': PRO},
      'status': 'UNSUPPORTED', 'aggregatedSubscriptionType': 'GROUP'}],
    [{'principal': {'user': 'sso-group-1-record-0'}, 'type': {'amazonQ': PRO},
      'status': 'ACTIVE', 'aggregatedSubscriptionType': 'GROUP'}] * 2,
])
def test_duplicate_or_malformed_aggregate_is_never_propagation(native, rows):
    active_group(native)
    with SessionLocal() as db:
        with pytest.raises(AwsFailure) as caught:
            observe_subscription(native(None), db.get(Subscription, 'group-1-record-0'), rows=rows)
    failure = classify_failure(caught.value)
    assert not failure.transient and not failure.unknown


def test_aggregate_and_source_drift_is_never_propagation(native):
    seed_group(1)
    with SessionLocal() as db:
        with pytest.raises(AwsFailure) as caught:
            observe_subscription(native(None), db.get(Subscription, 'group-1-record-0'), rows=[{
                'principal': {'user': 'sso-group-1-record-0'}, 'type': {'amazonQ': PRO},
                'status': 'ACTIVE', 'aggregatedSubscriptionType': 'GROUP',
            }])
    failure = classify_failure(caught.value)
    assert not failure.transient and not failure.unknown


@pytest.mark.parametrize('rows', [
    [{'principal': {'user': 'sso-group-1-record-0'}, 'type': None}],
    [{'principal': {'user': 'sso-group-1-record-0'}, 'type': {'amazonQ': PRO},
      'status': 'ACTIVE', 'aggregatedSubscriptionType': 'GROUP'}] * 2,
])
def test_invalid_readback_stops_an_existing_propagation_retry(alice, native, rows):
    from app.group_subscription_worker import run_one

    seed_group(1)
    native.effective_rows = []
    assert subscribe(alice).status_code == 202
    assert run_one(native, account_id=1)
    with SessionLocal() as db:
        operation = db.scalar(select(NativeGroupOperation))
        assert operation.state == 'queued'
        job_id = operation.id
    writes = list(native.writes)
    native.effective_rows = rows
    due('native', job_id)
    assert run_one(native, account_id=1)
    with SessionLocal() as db:
        operation = db.get(NativeGroupOperation, job_id)
        retry = db.get(AutomaticRetry, ('native', job_id))
        activation = db.scalar(select(GroupMemberActivation))
        assert operation.state == 'needs_review' and operation.phase == 'pending'
        assert retry.retry_count == 0 and retry.next_retry_at is None
        assert activation.reserved and not activation.counted
        assert db.get(ManagedGroup, 'group-1').active_job_id == job_id
    assert counter() == (0, 1, 0) and native.writes == writes


def test_missing_aggregate_without_live_source_remains_unsubscribed(native):
    seed_group(1)
    with SessionLocal() as db:
        observation = observe_subscription(native(None), db.get(Subscription, 'group-1-record-0'), rows=[])
    assert observation['effective']['status'] == 'not_subscribed'


@pytest.mark.parametrize('field', ['subscription_type', 'pending_type'])
def test_malformed_source_tier_is_manual_review(native, monkeypatch, field):
    active_group(native)
    source = {'source': 'GROUP', 'group_id': 'remote-group-1', 'status': 'active',
              'subscription_type': PRO, 'expires_at': None, field: []}
    monkeypatch.setattr(native, 'user_subscription_sources', lambda self, record: [source])
    with SessionLocal() as db:
        with pytest.raises(AwsFailure) as caught:
            observe_subscription(native(None), db.get(Subscription, 'group-1-record-0'), rows=[])
    failure = classify_failure(caught.value)
    assert not failure.transient and not failure.unknown


def test_missing_aggregate_with_expired_source_does_not_retry_or_grant_access(native):
    seed_group(1)
    source = {'source': 'GROUP', 'group_id': 'remote-group-1', 'status': 'cancelled',
              'subscription_type': PRO, 'expires_at': now() - timedelta(seconds=1)}
    with SessionLocal() as db:
        record = db.get(Subscription, 'group-1-record-0')
        observation = observe_subscription(native(None), record, rows=[], sources=[source])
        assert not has_confirmed_subscription_access(record, now())
    assert observation['effective']['status'] == 'not_subscribed'


def native_pending_snapshot(db, job_id):
    operation = db.get(NativeGroupOperation, job_id)
    activation = db.scalar(select(GroupMemberActivation).where(GroupMemberActivation.operation_id == job_id))
    record = db.get(Subscription, activation.record_id)
    retry = db.get(AutomaticRetry, ('native', job_id))
    return (operation.phase, operation.aws_request_id, operation.write_requested_at,
            operation.config_hash, operation.member_snapshot, operation.request_key,
            record.sso_user_id, record.group_membership_id, record.password_encrypted,
            record.credential_state, record.credential_revision, activation.id,
            activation.reserved, activation.counted, retry.config_hash,
            db.get(ManagedGroup, 'group-1').active_job_id, record.active_operation_id)


def pending_native_propagation(alice, native):
    from app.group_subscription_worker import run_one

    seed_group(1)
    native.effective_rows = []
    assert subscribe(alice).status_code == 202
    assert run_one(native, account_id=1)
    with SessionLocal() as db:
        operation = db.scalar(select(NativeGroupOperation))
        assert operation.state == 'queued' and operation.phase == 'pending'
        retry = db.get(AutomaticRetry, ('native', operation.id))
        assert retry.retry_count == 0 and retry.propagation_check_count == 1
        assert retry.error_code == 'subscription_observation_propagating'
        return operation.id, native_pending_snapshot(db, operation.id)


def assert_native_reconciliation_stopped(native, job_id, snapshot, writes, *, retries=0):
    from app.group_subscription_worker import run_one

    with SessionLocal() as db:
        operation = db.get(NativeGroupOperation, job_id)
        retry = db.get(AutomaticRetry, ('native', job_id))
        assert operation.state == 'needs_review' and operation.phase == 'pending'
        assert retry.retry_count == retries and retry.next_retry_at is None
        assert native_pending_snapshot(db, job_id) == snapshot
        assert not has_confirmed_subscription_access(db.get(Subscription, 'group-1-record-0'), now())
    assert native.writes == writes and counter() == (0, 1, 0)
    assert not run_one(native, account_id=1)


@pytest.mark.parametrize('drift', ['unmanaged_member', 'missing_member', 'tier', 'expiry'])
def test_propagation_reconciliation_stops_on_actual_remote_drift(alice, native, drift):
    from app.group_subscription_worker import run_one

    job_id, snapshot = pending_native_propagation(alice, native)
    writes = list(native.writes)
    if drift == 'unmanaged_member':
        native.members[('remote-group-1', 'unmanaged-user')] = 'unmanaged-membership'
    elif drift == 'missing_member':
        native.members.clear()
    elif drift == 'tier':
        native.assignments['remote-group-1']['subscription_type'] = 'Q_DEVELOPER_STANDALONE_PRO_PLUS'
    else:
        native.assignments['remote-group-1'].update(status='cancelled', expires_at=now() - timedelta(seconds=1))
    due('native', job_id)
    assert run_one(native, account_id=1)
    assert_native_reconciliation_stopped(native, job_id, snapshot, writes)


@pytest.mark.parametrize('parser,bad', [
    ('claims', 'shape'), ('claims', 'principal'), ('claims', 'tier'),
    ('claims', 'unhashable_tier'), ('claims', 'duplicate'), ('claims', 'pagination'),
    ('report', 'shape'), ('report', 'row'), ('report', 'pagination'),
])
def test_real_claim_and_report_parser_failures_stop_propagation(alice, native, monkeypatch, parser, bad):
    from app.group_subscription_worker import run_one

    job_id, snapshot = pending_native_propagation(alice, native)
    writes = list(native.writes)
    reader = object.__new__(AwsGateway)
    with SessionLocal() as db:
        reader.account = db.get(AwsAccount, 1)
        db.expunge(reader.account)
    if parser == 'claims':
        claim = {'principal': {'group': 'remote-group-1'}, 'type': {'amazonQ': PRO}}
        response = {
            'shape': {},
            'principal': {'claims': [{'principal': None}]},
            'tier': {'claims': [claim | {'type': None}]},
            'unhashable_tier': {'claims': [claim | {'type': {'amazonQ': []}}]},
            'duplicate': {'claims': [claim, claim]},
            'pagination': {'claims': [claim], 'nextToken': 'repeated-cursor'},
        }[bad]
        reader._call = lambda *args: (response, 'synthetic-read-request')
        monkeypatch.setattr(native, 'group_subscription_info', lambda self, group: reader.group_subscription_info(group))
    else:
        response = {'shape': {}, 'row': {'subscriptions': [None]},
                    'pagination': {'subscriptions': [], 'nextToken': 'repeated-cursor'}}[bad]
        reader._call = lambda *args: (response, 'synthetic-read-request')
        monkeypatch.setattr(native, 'report_subscriptions', lambda self: reader.report_subscriptions())
    due('native', job_id)
    assert run_one(native, account_id=1)
    assert_native_reconciliation_stopped(native, job_id, snapshot, writes)


def test_temporary_network_read_does_not_reenable_unknown_reconciliation(alice, native, monkeypatch):
    from app.group_subscription_worker import run_one

    job_id, snapshot = pending_native_propagation(alice, native)
    writes, reads = list(native.writes), []
    def read(self):
        reads.append(True)
        if len(reads) == 1:
            raise requests.ReadTimeout('synthetic temporary read failure')
        raise AwsFailure('unclassified parser or validation failure', uncertain=True)
    monkeypatch.setattr(native, 'report_subscriptions', read)
    due('native', job_id)
    assert run_one(native, account_id=1)
    with SessionLocal() as db:
        operation = db.get(NativeGroupOperation, job_id)
        retry = db.get(AutomaticRetry, ('native', job_id))
        assert operation.state == 'queued' and retry.retry_count == 1
        assert retry.mode == 'reconcile' and retry.next_retry_at is not None
        assert native_pending_snapshot(db, job_id) == snapshot
    due('native', job_id)
    assert run_one(native, account_id=1)
    assert_native_reconciliation_stopped(native, job_id, snapshot, writes, retries=1)
    assert len(reads) == 2


def test_temporary_network_reads_share_original_five_retry_budget(alice, native, monkeypatch):
    from app.group_subscription_worker import run_one

    job_id, snapshot = pending_native_propagation(alice, native)
    writes, reads = list(native.writes), []
    def read(self):
        reads.append(True)
        raise requests.ReadTimeout('synthetic temporary read failure')
    monkeypatch.setattr(native, 'report_subscriptions', read)
    for index in range(6):
        due('native', job_id)
        assert run_one(native, account_id=1)
        with SessionLocal() as db:
            operation = db.get(NativeGroupOperation, job_id)
            retry = db.get(AutomaticRetry, ('native', job_id))
            assert native_pending_snapshot(db, job_id) == snapshot
            assert retry.retry_count == min(index + 1, 5) and retry.mode == 'reconcile'
            assert operation.state == ('needs_review' if index == 5 else 'queued')
            assert retry.exhausted is (index == 5)
        assert native.writes == writes
    assert_native_reconciliation_stopped(native, job_id, snapshot, writes, retries=5)
    assert len(reads) == 6


@pytest.mark.parametrize('family,phase,mode,allowed', [
    ('sso', 'subscribe', 'reconcile', False),
    ('sso', 'group_membership_pending', 'retry', False),
    ('sso', 'group_membership_pending', 'reconcile', True),
    ('sso', 'group_entitlement_pending', 'retry', False),
    ('sso', 'group_entitlement_pending', 'reconcile', True),
    ('native', 'ready', 'reconcile', False),
    ('native', 'pending', 'retry', False),
    ('native', 'pending', 'reconcile', True),
    ('group', 'ready', 'reconcile', False),
    ('group', 'pending', 'retry', False),
    ('group', 'pending', 'reconcile', True),
])
def test_propagation_retry_requires_original_pending_readonly_step(alice, native, family, phase, mode, allowed):
    from app.automatic_retries import schedule_retry

    seed_group(1)
    assert subscribe(alice).status_code == 202
    with SessionLocal() as db:
        if family == 'sso':
            job = db.get(Subscription, 'group-1-record-0')
            job.step = phase
        elif family == 'native':
            job = db.scalar(select(NativeGroupOperation))
            job.phase = phase
        else:
            job = GroupJob(id='existing-member-join', group_id='group-1', record_id='group-1-record-0',
                           actor_id=2, kind='attach', phase=phase, request_key='existing-member-join', payload='{}')
            db.add(job)
        job.state = 'running'
        db.flush()
        error = AwsFailure('AWS 授权已确认，整体订阅尚未同步，等待只读核对', uncertain=True,
                           code='subscription_observation_propagating', retryable=True)
        assert schedule_retry(db, family, job.id, error, mode=mode) is allowed
        retry = db.get(AutomaticRetry, (family, job.id))
        assert bool(retry and retry.mode == 'reconcile' and retry.propagation_check_count == 1 and retry.retry_count == 0) is allowed


@pytest.mark.parametrize('step,mode,allowed', [
    ('subscribe', 'reconcile', False), ('subscribe_pending', 'retry', False),
    ('subscribe_pending', 'reconcile', True), ('group_entitlement_pending', 'reconcile', False),
])
def test_assignment_visibility_retry_requires_original_pending_readonly_step(native, step, mode, allowed):
    from app.automatic_retries import schedule_retry

    seed_group(1)
    with SessionLocal() as db:
        job = db.get(Subscription, 'group-1-record-0')
        job.step, job.state = step, 'running'
        error = AwsFailure('订阅只读核对尚未确认', uncertain=True,
                           code='subscription_assignment_propagating', retryable=True)
        assert schedule_retry(db, 'sso', job.id, error, mode=mode) is allowed


@pytest.mark.parametrize('route', ['native', 'membership'])
@pytest.mark.parametrize('converges', [True, False])
def test_aggregate_delay_reconciles_original_write_for_up_to_twenty_four_hours(alice, native, route, converges, monkeypatch):
    from app.group_subscription_worker import run_one as native_one
    from app.worker import run_one as sso_one

    if route == 'native':
        seed_group(1)
        response = subscribe(alice)
        assert response.status_code == 202, response.text
        rid = 'group-1-record-0'
        with SessionLocal() as db:
            job_id = db.scalar(select(NativeGroupOperation.id))
        family, run, baseline = 'native', native_one, (0, 1, 0)
        original_writes = []
    else:
        activate(alice)
        response = alice.post('/api/batches/create', json={
            'kind': 'sso', 'aws_account_id': 1, 'group_id': 'group-1',
            'items': [{'username': 'late-propagating'}], 'request_key': str(uuid.uuid4()),
        })
        assert response.status_code == 202, response.text
        rid = job_id = response.json()['items'][0]['id']
        family, run, baseline = 'sso', sso_one, (1, 1, 1)
        original_writes = list(native.writes)
    expected_group_lock = job_id if route == 'native' else None
    reads = []

    class DelayedAggregate(native):
        def verify_identity(self):
            return self.account.aws_account_id

        def create_user(self, record):
            self.writes.append(('SSO', record.id))
            return 'sso-' + record.id

        def password(self, record):
            self.writes.append(('OTP', record.id))
            return 'SyntheticPassword123!'

        def subscribe(self, record):
            pytest.fail('GROUP propagation must never create a USER assignment')

        def report_subscriptions(self):
            rows = super().report_subscriptions()
            reads.append(True)
            if not converges or len(reads) <= 2:
                return [row for row in rows if row['principal']['user'] != 'sso-' + rid]
            return rows

    assert run(DelayedAggregate, account_id=1)
    writes = list(native.writes)
    assert writes[len(original_writes):] == (
        [('create', 'remote-group-1', PRO)] if route == 'native' else
        [('SSO', rid), ('OTP', rid), ('attach', 'remote-group-1', 'sso-' + rid)]
    )
    assert counter() == baseline
    with SessionLocal() as db:
        record = db.get(Subscription, rid)
        activation = db.scalar(select(GroupMemberActivation).where(GroupMemberActivation.record_id == rid))
        retry = db.get(AutomaticRetry, (family, job_id))
        operation = db.get(NativeGroupOperation, job_id) if route == 'native' else record
        assert operation.state == 'queued'
        assert (operation.phase if route == 'native' else record.step) == (
            'pending' if route == 'native' else 'group_entitlement_pending')
        assert retry.mode == 'reconcile' and retry.propagation_check_count == 1 and retry.retry_count == 0
        assert retry.error_code == 'subscription_observation_propagating'
        assert db.get(ManagedGroup, 'group-1').active_job_id == expected_group_lock
        assert activation.reserved and not activation.counted
        assert not has_confirmed_subscription_access(record, now())
        stable = (record.sso_user_id, record.group_membership_id, record.password_encrypted,
                  record.credential_state, record.credential_revision, activation.id,
                  retry.config_hash, operation.aws_request_id)
    assert not run(DelayedAggregate, account_id=1)
    started = now()
    for index in range(8):
        elapsed = timedelta(hours=24, minutes=1) if index == 7 else timedelta(hours=index * 3 + 1)
        monkeypatch.setattr("app.automatic_retries.now", lambda: started + elapsed)
        due(family, job_id)
        assert run(DelayedAggregate, account_id=1)
        assert native.writes == writes
        with SessionLocal() as db:
            record = db.get(Subscription, rid)
            activation = db.scalar(select(GroupMemberActivation).where(GroupMemberActivation.record_id == rid))
            operation = db.get(NativeGroupOperation, job_id) if route == 'native' else record
            retry = db.get(AutomaticRetry, (family, job_id))
            assert stable == (record.sso_user_id, record.group_membership_id, record.password_encrypted,
                              record.credential_state, record.credential_revision, activation.id,
                              retry.config_hash, operation.aws_request_id)
            if converges and index == 1:
                assert operation.state == 'completed'
                assert retry.retry_count == 0 and retry.propagation_check_count == 2 and retry.next_retry_at is None
                assert activation.counted and not activation.reserved
                assert db.get(ManagedGroup, 'group-1').active_job_id is None
                assert has_confirmed_subscription_access(record, now())
                break
            if index == 7:
                assert operation.state == 'needs_review'
                assert retry.retry_count == 0 and retry.exhausted and retry.next_retry_at is None
            else:
                assert operation.state == 'queued' and retry.mode == 'reconcile'
                assert retry.retry_count == 0 and retry.propagation_check_count == index + 2
            assert activation.reserved and not activation.counted
            assert db.get(ManagedGroup, 'group-1').active_job_id == expected_group_lock
            assert not has_confirmed_subscription_access(record, now())
        assert counter() == baseline
    assert len(reads) == (3 if converges else 9)
    expected_counter = ((1, 0, 1) if route == 'native' else (2, 0, 2)) if converges else baseline
    assert counter() == expected_counter
    assert not run(DelayedAggregate, account_id=1)
