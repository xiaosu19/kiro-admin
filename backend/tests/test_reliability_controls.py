"""Recovery controls must preserve credentials, remote resources and write intent."""
import json
import time
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.identity_login import AuthProgress
from app.models import AuthJob, AuthSecret, AuditEvent, ManagedGroup, NativeGroupOperation, RecordOperation, Subscription, now
from app.retry_models import AutomaticRetry
from app.security import decrypt, encrypt
from test_auth_batches import ChallengeAuth, DoneAuth, admission, drain, record
from test_external_auth_batches import admit
from test_native_groups import native, seed_group, subscribe, run_native, counter


def challenge(reason='captcha_timeout', **patch):
    return dict(challenge={'id': 'challenge', 'kind': 'image', 'revision': 1, 'expires_at': time.time() + 300},
                credential={'status': 'current'}, revision=1,
                captcha_automation={'status': 'requires_action', 'reason': reason, 'attempts': 3, 'submissions': 2}, **patch)


@pytest.mark.parametrize('family', ['managed', 'pasted'])
def test_captcha_automatically_retries_five_times_then_preserves_manual_recovery(alice, family):
    from app.auth_jobs import finish_step, claim_job as claim
    from app.external_auth_worker import finish, claim as external_claim
    from app.external_auth_models import ExternalExportItem
    if family == 'managed':
        r = record(credential_state='permanent')
        batch = admission(alice, [r]).json()
        job_id = batch['items'][0]['operation_id']
    else:
        batch = admit(alice).json()
        job_id = batch['items'][0]['id']
    for attempt in range(6):
        if family == 'managed':
            with SessionLocal() as db:
                retry = db.get(AutomaticRetry, ('auth', job_id))
                if retry:
                    retry.next_retry_at = now() - timedelta(seconds=1)
                db.commit()
            claimed = claim()
        else:
            with SessionLocal() as db:
                item = db.get(ExternalExportItem, job_id)
                item.next_poll_at = now() - timedelta(seconds=1)
                lane_id = item.lane_id
                db.commit()
            claimed = external_claim(lane_id)
        assert claimed
        state = challenge()
        progress = AuthProgress('challenge', encrypt(state), challenge=state['challenge'])
        (finish_step if family == 'managed' else finish)(*claimed, progress)
        with SessionLocal() as db:
            item = db.get(RecordOperation if family == 'managed' else ExternalExportItem, job_id)
            retry = db.get(AutomaticRetry, ('auth', job_id)) if family == 'managed' else item
            assert retry.retry_count == min(attempt + 1, 5)
            assert item.state == ('challenge' if attempt == 5 else 'queued' if family == 'managed' else 'polling')
            if attempt < 5:
                secret = db.get(AuthSecret, job_id) if family == 'managed' else item
                assert secret.workflow_encrypted is None
            else:
                assert retry.exhausted if family == 'managed' else True
            assert len(list(db.scalars(select(AuditEvent).where(AuditEvent.action == 'auth_captcha_result')))) == attempt + 1
    if family == 'managed':
        with SessionLocal() as db:
            assert decrypt(db.get(Subscription, r.id).password_encrypted) == 'OldOTP1!'
            assert db.get(AuthJob, job_id).reset_state == 'none'


@pytest.mark.parametrize('patch', [
    {'password_write_pending': True}, {'inflight': 'password'},
    {'credential': {'status': 'unknown'}}, {'credential': {'status': 'candidate'}},
    {'external_authorization': True}, {'refresh_only': True},
    {'challenge': {'kind': 'mfa'}},
])
def test_automatic_captcha_restart_never_replays_uncertain_password_or_mfa(patch):
    from app.auth_retry import automatic_challenge_reason
    assert automatic_challenge_reason(encrypt(challenge() | patch)) is None


@pytest.mark.parametrize('reason', ['captcha_unavailable', 'captcha_invalid_configuration',
    'captcha_provider_auth', 'captcha_provider_balance', 'captcha_unsupported', 'captcha_browser_unavailable'])
def test_permanent_captcha_failures_do_not_retry_configuration_forever(reason):
    from app.auth_retry import automatic_challenge_reason
    assert automatic_challenge_reason(encrypt(challenge(reason))) is None


def test_retry_uses_saved_password_without_reset_and_diagnostics_survive_cleanup(alice):
    from app.auth_jobs import finish_step, claim_job as claim
    r = record(credential_state='permanent')
    batch = admission(alice, [r]).json()
    job_id = batch['items'][0]['operation_id']
    state = challenge('captcha_answer_rejected')
    finish_step(*claim(), AuthProgress('challenge', encrypt(state), challenge=state['challenge']))
    drain(DoneAuth)  # Backoff is durable: no request is eligible yet.
    with SessionLocal() as db:
        assert db.get(RecordOperation, job_id).state == 'queued'
        db.get(AutomaticRetry, ('auth', job_id)).next_retry_at = now() - timedelta(seconds=1)
        db.commit()
    drain(DoneAuth)
    result = alice.post(f"/api/auth-batches/{batch['id']}/download")
    assert result.status_code == 200
    with SessionLocal() as db:
        assert not db.get(AuthSecret, job_id).workflow_encrypted
        event = db.scalar(select(AuditEvent).where(AuditEvent.action == 'auth_captcha_result'))
        facts = json.loads(event.detail)
        assert facts['reason'] == 'captcha_answer_rejected'
        assert 'OldOTP1!' not in event.detail and 'credential' not in event.detail


def cancel_batch(alice, gid):
    response = alice.post('/api/group-subscriptions/cancel', json={
        'group_ids': [gid], 'cancellation_mode': 'IMMEDIATE', 'request_key': str(uuid.uuid4())})
    assert response.status_code == 202, response.text
    return response.json()


@pytest.mark.parametrize('claimed', [False, True])
def test_stop_group_cancel_prevents_unsent_writes_and_preserves_subscription(alice, bob, native, claimed):
    from app.group_subscription_worker import claim, before_write
    gid = seed_group()
    subscribe(alice, gid); run_native()
    before = counter()
    batch = cancel_batch(alice, gid)
    lease = claim() if claimed else None
    url = f"/api/lifecycle-batches/{batch['id']}/stop"
    assert bob.post(url).status_code == 404
    response = alice.post(url)
    assert response.status_code == 200
    assert response.json()['states']['cancelled'] == 1
    assert response.json()['stop_requested'] and not response.json()['can_stop']
    assert alice.post(url).json() == response.json()
    if lease:
        with pytest.raises(RuntimeError):
            before_write(*lease)
    assert not run_native()
    assert counter() == before
    assert native.assignments['remote-' + gid]['status'] == 'active'
    with SessionLocal() as db:
        assert db.get(ManagedGroup, gid).active_job_id is None
        assert all(r.active_operation_id is None for r in db.scalars(select(Subscription)))


def test_stop_preserves_pending_group_write_for_read_only_reconciliation(alice, native):
    from app.group_subscription_worker import claim, before_write, fail
    from app.aws import AwsFailure
    gid = seed_group()
    subscribe(alice, gid); run_native()
    batch = cancel_batch(alice, gid)
    op_id, token = claim()
    before_write(op_id, token)
    result = alice.post(f"/api/lifecycle-batches/{batch['id']}/stop").json()
    assert result['states']['running'] == 1 and result['states']['cancelled'] == 0
    with SessionLocal() as db:
        frozen = db.get(NativeGroupOperation, op_id).config_hash
    fail(op_id, token, 'synthetic timeout', True, error=AwsFailure('timeout', retryable=True), frozen_config=frozen)
    with SessionLocal() as db:
        op = db.get(NativeGroupOperation, op_id)
        assert op.state == 'needs_review' and op.phase == 'pending'
    assert not run_native()


def test_stop_user_cancel_releases_only_unsent_operations(alice, bob):
    from app.lifecycle import claim_operation, mark_pending
    records = [record(credential_state='permanent') for _ in range(2)]
    result = alice.post('/api/subscription-cancellations', json={
        'record_ids': [r.id for r in records], 'cancellation_mode': 'IMMEDIATE', 'request_key': str(uuid.uuid4())})
    assert result.status_code == 202, result.text
    batch = result.json()
    lease = claim_operation()
    assert lease
    assert bob.post(f"/api/lifecycle-batches/{batch['id']}/stop").status_code == 404
    result = alice.post(f"/api/lifecycle-batches/{batch['id']}/stop").json()
    assert result['states']['cancelled'] == 2
    with pytest.raises(RuntimeError):
        mark_pending(*lease)
    assert claim_operation() is None
    with SessionLocal() as db:
        for r in records:
            saved = db.get(Subscription, r.id)
            assert saved.subscription_status == 'active' and not saved.active_operation_id


def test_remove_account_with_active_group_preserves_history_and_stops_new_writes(admin, alice, native):
    from test_resources import remove
    gid = seed_group()
    subscribe(alice, gid); run_native()
    batch = cancel_batch(alice, gid)
    before = counter()
    assert remove(admin, 'aws', '测试 AWS').status_code == 200
    run_native()
    assert not any(w[0] == 'cancel' for w in native.writes)
    assert native.assignments['remote-' + gid]['status'] == 'active'
    assert counter() == before
    detail = alice.get('/api/groups/' + gid).json()
    assert detail['account_deleted_at'] and not detail['deleted_at']
    assert detail['native_subscription']['state'] == 'active'
    assert all(m['account_deleted_at'] and not m['sso_deleted_at'] for m in detail['members'])
    assert alice.get('/api/groups').json()[0]['account_deleted_at']
