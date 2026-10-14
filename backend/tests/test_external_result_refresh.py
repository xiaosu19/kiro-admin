"""Large pasted batches refresh original grants without another login or reset."""
import io
import json
import time
import zipfile
from types import SimpleNamespace

import pytest

from app.database import SessionLocal
from app.external_auth_models import ExternalExportItem
from app.external_auth_worker import run_one
from app.external_enterprise import ExternalEnterpriseAuth, ExternalGateway
from app.identity_login import AuthError
from app.models import Subscription, User, now
from app.security import decrypt, encrypt
from test_external_auth_batches import TEXT, admit, completed, result_for
from test_external_managed_login import managed_record


def expire(batch, index=0, **changes):
    completed(batch, index, expiresAt=time.time() - 1,
              clientSecretExpiresAt=time.time() + 86400, **changes)
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch['items'][index]['id'])
        item.input_encrypted = item.workflow_encrypted = None  # legacy completed job
        db.commit()


class RefreshTransport(ExternalEnterpriseAuth):
    calls = []

    def begin(self, *args, **kwargs):
        raise AssertionError('refresh must never log in')

    def _sdk_call(self, state, operation, **kwargs):
        assert operation == 'create_token' and kwargs['grantType'] == 'refresh_token'
        assert kwargs['clientId'] == 'real-client' and kwargs['clientSecret'] == 'private-client'
        assert kwargs['refreshToken'] == 'private-refresh'
        type(self).calls.append(operation)
        return {'accessToken': 'fresh-access', 'refreshToken': 'fresh-refresh', 'expiresIn': 3600}

    def _request(self, state, method, url, *, purpose, **kwargs):
        assert purpose in ('profiles', 'usage')
        type(self).calls.append(purpose)
        source = result_for(SimpleNamespace(region=state['binding']['region'],
            portal_url=state['binding']['portal'], username=state['username']))
        if purpose == 'profiles':
            return {'profiles': [source['profile']]}
        return source['usage']


def fake_gateway(item, configuration, guard):
    return SimpleNamespace(account=ExternalGateway.account_for(item, configuration),
        _check_proxy=guard, proxy=None, close=lambda: None)


def test_download_refreshes_legacy_result_and_preserves_other_successes(alice):
    batch = admit(alice, json.dumps([json.loads(TEXT) | {'username': n} for n in ('one', 'two')])).json()
    expire(batch)
    completed(batch, 1)
    path = f"/api/external-auth-batches/{batch['id']}/download"
    reply = alice.post(path)
    assert reply.status_code == 409 and '原授权刷新' in reply.json()['detail']
    progress = alice.get(f"/api/external-auth-batches/{batch['id']}").json()
    assert progress['items'][0]['stage'] == 'refresh_requested'
    assert progress['items'][1]['state'] == 'completed' and not progress['download_ready']
    assert all(secret not in reply.text for secret in ('private-access', 'private-refresh', 'Permanent9!'))
    RefreshTransport.calls = []
    for _ in range(4):
        assert run_one(gateway_factory=fake_gateway, auth_factory=RefreshTransport)
    assert not run_one(gateway_factory=fake_gateway, auth_factory=RefreshTransport)
    assert RefreshTransport.calls == ['create_token', 'profiles', 'usage']
    response = alice.post(path)
    assert response.status_code == 200 and response.headers['x-export-count'] == '2'
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        paths = {name.split('/')[-1]: name for name in archive.namelist()}
        assert set(paths) == {'one.json', 'two.json'}
        assert all(len(name.split('/')) == 2 for name in paths.values())
        assert len({name.split('/')[0] for name in paths.values()}) == 1
        first = json.loads(archive.read(paths['one.json']))[0]
        assert first['accessToken'] == 'fresh-access' and first['password'] == 'Permanent9!'
        assert json.loads(archive.read(paths['two.json']))[0]['accessToken'] == 'private-access'


@pytest.mark.parametrize('changes', [
    {'userId': 'another-user'}, {'authRegion': 'eu-central-1'},
    {'clientSecretExpiresAt': 1}, {'clientSecretExpiresAt': None},
    {'refreshToken': ''}, {'password': None},
])
def test_invalid_results_do_not_start_a_refresh_or_login(alice, changes):
    batch = admit(alice).json()
    expire(batch)
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch['items'][0]['id'])
        item.result_encrypted = encrypt(decrypt(item.result_encrypted) | changes)
        db.commit()
    assert alice.post(f"/api/external-auth-batches/{batch['id']}/download").status_code == 409
    assert not run_one(gateway_factory=lambda *a: pytest.fail('invalid refresh reached wire'))


def test_other_live_login_blocks_refresh_without_consuming_original_result(alice, bob):
    batch = admit(alice).json()
    expire(batch)
    assert admit(bob).status_code == 202
    assert alice.post(f"/api/external-auth-batches/{batch['id']}/download").status_code == 409
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch['items'][0]['id'])
        assert item.state == 'completed' and item.result_encrypted


@pytest.mark.parametrize('change', ['cancel', 'session'])
def test_revocation_after_refresh_admission_prevents_wire(alice, change):
    batch = admit(alice).json()
    expire(batch)
    assert alice.post(f"/api/external-auth-batches/{batch['id']}/download").status_code == 409
    if change == 'cancel':
        alice.post(f"/api/external-auth-batches/{batch['id']}/cancel")
    else:
        with SessionLocal() as db:
            db.get(User, 2).session_version += 1
            db.commit()
    run_one(gateway_factory=lambda *a: pytest.fail('revoked refresh reached wire'))


def test_refresh_error_never_falls_back_to_password_login(alice):
    batch = admit(alice).json()
    expire(batch)
    alice.post(f"/api/external-auth-batches/{batch['id']}/download")

    class Unavailable(RefreshTransport):
        def _sdk_call(self, *args, **kwargs):
            raise AuthError('transport_failed', retryable=True, proven_unsent=True)

    assert run_one(gateway_factory=fake_gateway, auth_factory=Unavailable)
    for attempt in range(6):
        assert run_one(gateway_factory=fake_gateway, auth_factory=Unavailable)
        with SessionLocal() as db:
            item = db.get(ExternalExportItem, batch['items'][0]['id'])
            if attempt < 5:
                assert item.state == 'polling' and item.retry_count == attempt + 1
                assert decrypt(item.workflow_encrypted)['refresh_only']
                item.next_poll_at = now()
                db.commit()
    assert not run_one(gateway_factory=fake_gateway, auth_factory=Unavailable)
    with SessionLocal() as db:
        item = db.get(ExternalExportItem, batch['items'][0]['id'])
        assert item.state == 'failed' and item.input_encrypted is None
    assert alice.post(f"/api/external-auth-batches/{batch['id']}/items/{batch['items'][0]['id']}/retry").status_code == 409


def test_managed_credential_change_rejects_saved_grant_before_refresh(alice):
    record = managed_record()
    batch = admit(alice).json()
    expire(batch, profile={'arn': 'arn:aws:codewhisperer:us-east-1:123456789012:profile/TEST', 'profileName': 'Real'})
    with SessionLocal() as db:
        db.get(Subscription, record.id).credential_revision += 1
        db.commit()
    assert alice.post(f"/api/external-auth-batches/{batch['id']}/download").status_code == 409
    assert not run_one(gateway_factory=lambda *a: pytest.fail('stale managed credential reached wire'))
