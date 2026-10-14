"""A settled CAPTCHA can restart before expiry; never overlap a pending write."""
import time

import pytest

from app.account_dispatcher import resource_fence
from app.database import SessionLocal
from app.external_auth_models import ExternalExportItem
from app.external_auth_worker import login_fences
from app.models import AuthSecret, RecordOperation
from app.security import decrypt, encrypt
from test_auth_batches import ChallengeAuth, admission, drain, record
from test_external_auth_batches import admit


@pytest.fixture(params=['managed', 'pasted'])
def challenge_task(request, alice):
    family = request.param
    if family == 'managed':
        r = record()
        batch = admission(alice, [r]).json()
        drain(ChallengeAuth)
        base = '/api/auth-batches/' + batch['id']
        job_id, item_id = batch['items'][0]['operation_id'], r.id
    else:
        batch = admit(alice).json()
        base = '/api/external-auth-batches/' + batch['id']
        job_id = item_id = batch['items'][0]['id']

    def mutate(**patch):
        with SessionLocal() as db:
            if family == 'managed':
                secret = db.get(AuthSecret, job_id)
                state = decrypt(secret.workflow_encrypted)
            else:
                secret = db.get(ExternalExportItem, job_id)
                state = decrypt(secret.workflow_encrypted) if secret.workflow_encrypted else {
                    'challenge': {'id': 'live-challenge', 'revision': 1, 'kind': 'image', 'expires_at': time.time() + 600},
                    'credential': {'status': 'current'},
                }
                secret.state = 'challenge'
            state['captcha_automation'] = {'status': 'requires_action', 'reason': 'captcha_attempt_limit'}
            state.update(patch)
            secret.workflow_encrypted = encrypt(state)
            db.commit()
    mutate()
    return family, base, job_id, item_id, mutate


def test_retry_available_before_challenge_expiry_survives_get_and_clears_old_grant(alice, bob, challenge_task):
    family, base, job_id, item_id, mutate = challenge_task
    for _ in range(2):
        response = alice.get(base)
        assert response.json()['items'][0]['can_retry_challenge'] is True
        assert 'live-challenge' not in response.text and 'secret-ces' not in response.text
    kwargs = {'json': {'mode': 'resume'}} if family == 'managed' else {}
    assert bob.post(f'{base}/items/{item_id}/retry', **kwargs).status_code == 404
    response = alice.post(f'{base}/items/{item_id}/retry', **kwargs)
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        secret = db.get(AuthSecret if family == 'managed' else ExternalExportItem, job_id)
        op = db.get(RecordOperation, job_id) if family == 'managed' else secret
        assert op.state == 'queued' and secret.workflow_encrypted is None
    assert alice.get(base).json()['items'][0]['can_retry_challenge'] is False


@pytest.mark.parametrize('patch', [
    {'password_write_pending': True}, {'inflight': 'password_change'},
    {'credential': {'status': 'unknown'}}, {'credential': {'status': 'candidate'}},
    {'captcha_automation': {'status': 'recognizing'}},
    {'challenge': {'kind': 'mfa'}}, {'challenge': {'kind': 'aws_authorization'}},
])
def test_uncertain_password_or_live_recognition_or_mfa_never_restarted(alice, challenge_task, patch):
    family, base, job_id, item_id, mutate = challenge_task
    mutate(**patch)
    assert alice.get(base).json()['items'][0]['can_retry_challenge'] is False
    response = alice.post(f'{base}/items/{item_id}/retry', **({'json': {'mode': 'resume'}} if family == 'managed' else {}))
    assert response.status_code == 409


def test_browser_cleanup_fence_prevents_overlapping_retry(alice, challenge_task):
    family, base, job_id, item_id, mutate = challenge_task
    with SessionLocal() as db:
        fence = resource_fence('record', item_id) if family == 'managed' else login_fences(db.get(ExternalExportItem, job_id))
        with fence as acquired:
            assert acquired
            response = alice.post(f'{base}/items/{item_id}/retry', **({'json': {'mode': 'resume'}} if family == 'managed' else {}))
            assert response.status_code == 409
    assert alice.get(base).json()['items'][0]['can_retry_challenge'] is True


def test_wrapped_official_widget_is_retryable_but_external_handoff_is_not(alice, challenge_task):
    family, base, job_id, item_id, mutate = challenge_task
    identity = {'id': 'same-live-challenge', 'revision': 2}
    mutate(challenge=identity | {'kind': 'aws_authorization'}, automation_challenge=identity | {'kind': 'ams'})
    assert alice.get(base).json()['items'][0]['can_retry_challenge'] is True
    mutate(automation_challenge=identity | {'kind': 'ams', 'revision': 1})
    assert alice.get(base).json()['items'][0]['can_retry_challenge'] is False
