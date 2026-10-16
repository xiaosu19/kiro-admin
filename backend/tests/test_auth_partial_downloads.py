"""A download consumes successes only; unsettled and failed siblings can continue."""
import io
import json
import time
import zipfile

import pytest

from app.database import SessionLocal
from app.models import AuthBatch, AuthSecret, RecordOperation, Subscription
from app.security import encrypt, decrypt
from test_auth_batches import DoneAuth, Gateway, admission, drain, record
from test_external_auth_batches import TEXT, admit as paste, completed
from test_group_json_exports import seed_groups, preview, admit as groups_admit
from test_provisioning_admission import ready, remote


@pytest.mark.parametrize('state', ['challenge', 'failed', 'needs_review', 'queued', 'running', 'polling'])
@pytest.mark.parametrize('grouped', [False, True])
def test_partial_managed_download_preserves_other_jobs_and_original_deadline(alice, bob, state, grouped):
    if grouped:
        groups, ids = seed_groups(quantity=2)
        batch = groups_admit(alice, preview(alice, groups).json()).json()
    else:
        users = [record(), record()]
        ids = [r.id for r in users]
        batch = admission(alice, users).json()
    drain(DoneAuth, Gateway)
    first, second = batch['items']
    with SessionLocal() as db:
        auth = db.get(AuthBatch, batch['id'])
        auth.completed_at = auth.download_expires_at = None
        op = db.get(RecordOperation, second['operation_id'])
        op.state = state
        secret = db.get(AuthSecret, second['operation_id'])
        secret.result_encrypted = None
        saved = secret.workflow_encrypted
        db.commit()
    base = '/api/auth-batches/' + batch['id']
    view = alice.get(base).json()
    assert view['download_ready'] is True
    assert bob.post(base + '/download').status_code == 404
    response = alice.post(base + '/download')
    assert response.status_code == 200, response.text
    assert response.headers['x-export-count'] == '1'
    assert response.headers['cache-control'] == 'no-store'
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        entries = [v for name in archive.namelist() for v in json.loads(archive.read(name))]
        assert [v['label'] for v in entries] == [first['username']]
    with SessionLocal() as db:
        assert db.get(RecordOperation, first['operation_id']).state == 'downloaded'
        assert db.get(AuthSecret, first['operation_id']).result_encrypted is None
        assert db.get(RecordOperation, second['operation_id']).state == state
        assert db.get(AuthSecret, second['operation_id']).workflow_encrypted == saved
        auth = db.get(AuthBatch, batch['id'])
        assert auth.state == 'active'
        if state in ('challenge', 'queued', 'running', 'polling'):
            assert auth.completed_at is None and auth.download_expires_at is None
    view = alice.get(base).json()
    assert view['states']['downloaded'] == 1
    assert view['success_count'] == 1 and view['download_ready'] is False
    assert alice.post(base + '/download').status_code == 409
    if state in ('failed', 'needs_review'):
        assert alice.post(base + '/items/' + second['record_id'] + '/retry', json={'mode': 'resume'}).status_code == 202
        drain(DoneAuth, Gateway)
        assert alice.get(base).json()['download_ready'] is True
        response = alice.post(base + '/download')
        assert response.status_code == 200 and response.headers['x-export-count'] == '1'
        assert alice.get(base).json()['state'] == 'downloaded'


@pytest.mark.parametrize('state', ['challenge', 'failed', 'queued', 'running', 'polling'])
def test_pasted_partial_download_keeps_original_input_and_retry(alice, state):
    from app.external_auth_models import ExternalExportBatch, ExternalExportItem
    batch = paste(alice, json.dumps([json.loads(TEXT) | {'username': name} for name in ('one', 'two')])).json()
    completed(batch, 0)
    remaining = batch['items'][1]['id']
    with SessionLocal() as db:
        db.get(ExternalExportBatch, batch['id']).completed_at = None
        db.get(ExternalExportBatch, batch['id']).download_expires_at = None
        item = db.get(ExternalExportItem, remaining)
        item.state = state
        original_input = item.input_encrypted
        db.commit()
    base = '/api/external-auth-batches/' + batch['id']
    assert alice.get(base).json()['download_ready'] is True
    result = alice.post(base + '/download')
    assert result.status_code == 200 and result.headers['x-export-count'] == '1'
    with SessionLocal() as db:
        assert db.get(ExternalExportBatch, batch['id']).state == 'active'
        item = db.get(ExternalExportItem, remaining)
        assert item.state == state and not item.cancel_requested
        assert item.input_encrypted == original_input
    if state == 'failed':
        assert alice.post(base + '/items/' + remaining + '/retry').status_code == 202
    completed(batch, 1)
    assert alice.post(base + '/download').status_code == 200
    assert alice.post(base + '/download').status_code == 410


def test_provisioning_exposes_safe_conversion_retry_on_every_reload(alice, admin, gateway):
    from app.models import AuthJob
    from test_provisioning_admission import admit, intent
    from test_provisioning_coordinator import drive
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    drain(DoneAuth, Gateway)
    first, item = parent['accounts'][0]['items']
    with SessionLocal() as db:
        op = db.get(RecordOperation, item['auth_job_id'])
        op.state = 'challenge'
        secret = db.get(AuthSecret, op.id)
        saved = decrypt(secret.workflow_encrypted)
        saved.update(challenge={'id': 'synthetic', 'revision': 1, 'kind': 'image', 'expires_at': time.time() + 600},
                     captcha_automation={'status': 'requires_action', 'reason': 'captcha_timeout'}, inflight=None)
        secret.workflow_encrypted = encrypt(saved)
        secret.result_encrypted = None
        db.get(AuthBatch, item['auth_batch_id']).completed_at = None
        db.commit()
    base = '/api/provisioning-batches/' + parent['id']
    for _ in range(2):
        view = alice.get(base).json()
        assert view['json_download']['ready'] is True
        recovery = view['accounts'][0]['items'][1]['export_recovery']
        assert recovery['kind'] == 'auth_retry'
        assert recovery['body'] == {'mode': 'resume'}
        assert recovery['path'] == f"/api/auth-batches/{item['auth_batch_id']}/items/{item['record_id']}/retry"
    assert admin.get(base).json()['accounts'][0]['items'][1].get('export_recovery') is None
    assert alice.post(base + '/download').status_code == 200
    with SessionLocal() as db:
        assert db.get(RecordOperation, item['auth_job_id']).state == 'challenge'
        db.get(Subscription, item['record_id']).credential_state = 'unknown'
        db.commit()
    assert alice.get(base).json()['accounts'][0]['items'][1].get('export_recovery') is None
    with SessionLocal() as db:
        db.get(Subscription, item['record_id']).credential_state = 'permanent'
        db.get(AuthJob, item['auth_job_id']).reset_state = 'pending'
        db.commit()
    assert alice.get(base).json()['accounts'][0]['items'][1].get('export_recovery') is None


@pytest.mark.parametrize('old_reset_state', ['none', 'required'])
def test_explicit_retry_can_use_a_newer_confirmed_password_without_reset(alice, old_reset_state):
    from app.models import AuthJob
    user = record(credential_state='permanent')
    batch = admission(alice, [user]).json()
    drain(DoneAuth, Gateway)
    item = batch['items'][0]
    with SessionLocal() as db:
        saved = db.get(Subscription, user.id)
        saved.password_encrypted = encrypt('NewConfirmed9!')
        saved.credential_state = 'permanent'
        saved.credential_revision += 1
        revision = saved.credential_revision
        job = db.get(AuthJob, item['operation_id'])
        job.error_code = 'credential_changed'
        job.reset_state = old_reset_state
        db.get(RecordOperation, job.id).state = 'failed'
        db.get(AuthSecret, job.id).result_encrypted = None
        db.commit()
    base = '/api/auth-batches/' + batch['id']
    response = alice.post(base + '/items/' + user.id + '/retry', json={'mode': 'resume'})
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        assert db.get(AuthJob, item['operation_id']).credential_revision == revision
        assert db.get(AuthJob, item['operation_id']).reset_state == 'none'
        assert decrypt(db.get(Subscription, user.id).password_encrypted) == 'NewConfirmed9!'
        assert db.get(AuthSecret, item['operation_id']).workflow_encrypted is None
    drain(DoneAuth, Gateway)
    with SessionLocal() as db:
        saved = db.get(Subscription, user.id)
        assert saved.credential_revision == revision
        assert decrypt(saved.password_encrypted) == 'NewConfirmed9!'
        assert db.get(RecordOperation, item['operation_id']).state == 'completed'


def test_unexported_failed_credential_drift_cannot_block_a_valid_sibling_download(alice):
    users = [record(), record()]
    batch = admission(alice, users).json()
    drain(DoneAuth, Gateway)
    with SessionLocal() as db:
        failed = batch['items'][1]
        db.get(RecordOperation, failed['operation_id']).state = 'failed'
        db.get(AuthSecret, failed['operation_id']).result_encrypted = None
        db.get(Subscription, users[1].id).credential_revision += 1
        db.commit()
    response = alice.post('/api/auth-batches/' + batch['id'] + '/download')
    assert response.status_code == 200, response.text
    assert response.headers['x-export-count'] == '1'


# Reuse the real provisioning fixtures without constructing a second service.
from test_provisioning_coordinator import gateway
