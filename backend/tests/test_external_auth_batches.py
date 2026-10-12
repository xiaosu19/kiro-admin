import json
import io
import time
import uuid
import zipfile
from datetime import timedelta

from sqlalchemy import select

from app.database import SessionLocal
from app.external_auth_models import ExternalExportBatch, ExternalExportItem
from app.models import AuditEvent, User, now
from app.security import decrypt, encrypt
from app.external_enterprise import ExternalEnterpriseAuth
from app.identity_login import AuthError


TEXT = json.dumps({'start_url': 'https://d-1234567890.awsapps.com/start',
                   'region': 'us-east-1', 'username': 'alice', 'password': 'Synthetic8!'})


def admit(client, text=TEXT, key=None):
    preview = client.post('/api/external-auth-batches/preview', json={'text': text})
    assert preview.status_code == 200
    return client.post('/api/external-auth-batches', json={'text': text, 'request_key': key or str(uuid.uuid4()),
                                                        'preview_fingerprint': preview.json()['preview_fingerprint']})


def test_admission_private_encrypted_owned_and_idempotent(alice, bob):
    key = str(uuid.uuid4())
    first = admit(alice, key=key)
    assert first.status_code == 202
    view = first.json()
    assert 'Synthetic8!' not in first.text
    assert len(view['items']) == 1 and view['items'][0]['username'] == 'alice'
    assert admit(alice, key=key).json()['id'] == view['id']
    assert bob.get('/api/external-auth-batches/' + view['id']).status_code == 404
    assert bob.post('/api/external-auth-batches/' + view['id'] + '/cancel').status_code == 404
    with SessionLocal() as db:
        item = db.scalar(select(ExternalExportItem))
        assert decrypt(item.input_encrypted)['password'] == 'Synthetic8!'
        assert 'Synthetic8!' not in item.input_encrypted
        assert len(list(db.scalars(select(ExternalExportBatch)))) == 1
        assert all('Synthetic8!' not in event.detail for event in db.scalars(select(AuditEvent)))


def test_duplicate_live_login_and_invalid_preview_rejected(alice, bob):
    assert admit(alice).status_code == 202
    assert admit(bob).status_code == 409
    response = alice.post('/api/external-auth-batches', json={'text': TEXT, 'request_key': str(uuid.uuid4()),
                                                           'preview_fingerprint': '0' * 64})
    assert response.status_code == 409 and 'Synthetic8!' not in response.text


def test_cancel_releases_unsent_login_and_purges_input_but_preserves_password_recovery(alice, bob):
    batch = admit(alice).json()
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch['items'][0]['id'])
        item.credential_encrypted = encrypt({'status': 'unknown', 'current': 'Old9!', 'candidate': 'Candidate9!'})
        db.commit()
    assert alice.post('/api/external-auth-batches/' + batch['id'] + '/cancel').status_code == 200
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch['items'][0]['id'])
        assert item.state == 'cancelled' and item.input_encrypted is None
        assert decrypt(item.credential_encrypted)['candidate'] == 'Candidate9!'
    assert admit(bob).status_code == 202


def test_worker_revocation_prevents_any_wire_call(alice):
    from app.external_auth_worker import run_one
    batch = admit(alice).json()
    with SessionLocal() as db:
        db.get(User, 2).session_version += 1
        db.commit()
    assert run_one(gateway_factory=lambda *args: (_ for _ in ()).throw(AssertionError('wire reached')))
    with SessionLocal() as db:
        assert db.get(ExternalExportItem, batch['items'][0]['id']).state == 'cancelled'


def test_expiry_purges_token_result(alice):
    from app.external_auth_worker import expire_batches
    batch = admit(alice).json()
    with SessionLocal() as db:
        db.get(ExternalExportBatch, batch['id']).expires_at = now() - timedelta(seconds=1)
        item = db.get(ExternalExportItem, batch['items'][0]['id'])
        item.result_encrypted = encrypt({'accessToken': 'TokenPrivate'})
        db.commit()
    expire_batches()
    with SessionLocal() as db:
        assert db.get(ExternalExportBatch, batch['id']).state == 'expired'
        assert db.get(ExternalExportItem, batch['items'][0]['id']).result_encrypted is None


def result_for(item, *, expires=None):
    return {'accessToken': 'private-access', 'refreshToken': 'private-refresh', 'clientId': 'real-client',
            'clientSecret': 'private-client', 'expiresAt': expires or time.time() + 3600,
            'authRegion': item.region, 'apiRegion': 'us-east-1', 'startUrl': item.portal_url,
            'userId': 'actual-user', 'username': item.username, 'password': 'Permanent9!',
            'identityStoreId': 'd-1234567890', 'profile': {
                'arn': 'arn:aws:codewhisperer:us-east-1:123456789012:profile/real', 'profileName': 'Real'},
            'usage': {'userInfo': {'userId': 'd-1234567890.actual-user', 'email': 'real@example.test'},
                      'subscriptionInfo': {'type': 'Q_DEVELOPER_STANDALONE_PRO'}}}


def completed(batch, index=0, **changes):
    with SessionLocal() as db:
        owner = db.get(ExternalExportBatch, batch['id'])
        item = db.get(ExternalExportItem, batch['items'][index]['id'])
        item.state = 'completed'
        item.result_encrypted = encrypt(result_for(item) | changes)
        owner.completed_at, owner.download_expires_at = now(), now() + timedelta(minutes=15)
        db.commit()


def test_single_then_zip_download_partial_results_are_real_private_and_single_use(alice):
    rows = [json.loads(TEXT) | {'username': name} for name in ('one', 'two', 'failed')]
    batch = admit(alice, json.dumps(rows)).json()
    completed(batch, 0)
    completed(batch, 1)
    with SessionLocal() as db:
        db.get(ExternalExportItem, batch['items'][2]['id']).state = 'failed'
        db.commit()
    assert 'private-access' not in alice.get('/api/external-auth-batches/' + batch['id']).text
    single = alice.post(f"/api/external-auth-batches/{batch['id']}/download?format=json&item_id={batch['items'][0]['id']}")
    assert single.status_code == 200
    assert single.json()[0]['label'] == 'one' and single.json()[0]['accessToken'] == 'private-access'
    archive = alice.post(f"/api/external-auth-batches/{batch['id']}/download")
    assert archive.status_code == 200 and archive.headers['cache-control'] == 'no-store'
    with zipfile.ZipFile(io.BytesIO(archive.content)) as file:
        assert file.namelist() == ['two.json']
        assert json.loads(file.read('two.json'))[0]['userId'] == 'actual-user'
    assert alice.post(f"/api/external-auth-batches/{batch['id']}/download").status_code == 410
    with SessionLocal() as db:
        assert all(not i.result_encrypted for i in db.scalars(select(ExternalExportItem)))


def test_old_login_cannot_download_or_retry_after_session_revocation(alice):
    from conftest import login
    batch = admit(alice).json()
    completed(batch)
    with SessionLocal() as db:
        db.get(User, 2).session_version += 1
        db.commit()
    fresh = login('alice')
    assert fresh.post(f"/api/external-auth-batches/{batch['id']}/download").status_code == 403


def test_download_rejects_cross_portal_or_corrupted_identity_results(alice):
    batch = admit(alice).json()
    completed(batch, startUrl='https://d-9999999999.awsapps.com/start')
    response = alice.post(f"/api/external-auth-batches/{batch['id']}/download")
    assert response.status_code == 409 and 'private-access' not in response.text
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch['items'][0]['id'])
        assert item.state == 'needs_review' and item.result_encrypted is None


def test_expired_real_token_is_excluded_from_download(alice):
    batch = admit(alice).json()
    completed(batch, expiresAt=time.time() - 1)
    response = alice.post(f"/api/external-auth-batches/{batch['id']}/download")
    assert response.status_code == 409
    assert alice.get('/api/external-auth-batches/' + batch['id']).json()['success_count'] == 0


def test_manual_retry_uses_confirmed_permanent_password_and_checks_global_login_lock(alice, bob):
    batch = admit(alice).json()
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch['items'][0]['id'])
        item.state = 'failed'
        item.credential_encrypted = encrypt({'username': item.username, 'status': 'confirmed', 'current': 'NewPermanent9!'})
        db.commit()
    competing = admit(bob).json()
    url = f"/api/external-auth-batches/{batch['id']}/items/{batch['items'][0]['id']}/retry"
    assert alice.post(url).status_code == 409
    bob.post('/api/external-auth-batches/' + competing['id'] + '/cancel')
    assert alice.post(url).status_code == 202
    with SessionLocal() as db:
        assert decrypt(db.get(ExternalExportItem, batch['items'][0]['id']).input_encrypted)['password'] == 'NewPermanent9!'


class CompletedAuth(ExternalEnterpriseAuth):
    def _advance(self, state, answer):
        from types import SimpleNamespace
        state['expected_user_id'] = 'actual-user'
        state.update(stage='done', status='done', result=result_for(SimpleNamespace(
            region=state['binding']['region'], portal_url=state['binding']['portal'], username=state['username'])))


def test_worker_completes_only_verified_real_result_and_isolated_binding(alice):
    from app.external_auth_worker import run_one
    batch = admit(alice).json()
    assert run_one(auth_factory=CompletedAuth)
    assert run_one(auth_factory=CompletedAuth)
    assert not run_one(auth_factory=CompletedAuth)
    view = alice.get('/api/external-auth-batches/' + batch['id']).json()
    assert view['items'][0]['state'] == 'completed' and view['download_ready']
    assert 'Permanent9!' not in json.dumps(view) and 'private-access' not in json.dumps(view)


def test_worker_transient_attempts_are_bounded_and_cancellation_never_replays_password(alice):
    from app.external_auth_worker import run_one
    calls = []
    class Unavailable(ExternalEnterpriseAuth):
        def begin(self, *args, **kwargs):
            calls.append(1)
            raise AuthError('http_failed', http_status=503, retryable=True)
    batch = admit(alice).json()
    for index in range(6):
        assert run_one(auth_factory=Unavailable)
        assert not run_one(auth_factory=Unavailable)
        with SessionLocal() as db:
            item = db.get(ExternalExportItem, batch['items'][0]['id'])
            if index < 5:
                assert item.retry_count == index + 1 and item.state == 'polling'
                item.next_poll_at = now() - timedelta(seconds=1)
                db.commit()
            else:
                assert item.retry_count == 5 and item.state == 'failed'
    assert len(calls) == 6
