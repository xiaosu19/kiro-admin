"""User-owned credentials, protocol wiring and revocation, without paid API calls."""
from dataclasses import replace

from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select

from app.ai_settings import provider_for_actor
from app.database import SessionLocal
from app.main import app
from app.models import AiProviderSettings, AuditEvent, User
from app.security import decrypt

KEY_A = 'synthetic-alice-ai-key'
KEY_B = 'synthetic-bob-ai-key'


def save(client, key=KEY_A, **changes):
    return client.put('/api/ai-settings', json={
        'revision': 0, 'protocol': 'claude_messages', 'endpoint': 'https://vision.example.com',
        'model': 'claude-opus-4.6', 'api_key': key, 'enabled': True, 'timeout_seconds': 20,
    } | changes)


def test_every_role_has_separate_encrypted_settings(alice, bob, admin):
    assert TestClient(app).get('/api/ai-settings').status_code == 401
    for client in (alice, bob, admin):
        assert client.get('/api/ai-settings').json()['key_configured'] is False
    assert save(alice).status_code == 200
    assert save(bob, KEY_B, protocol='openai_responses', model='own-vision-model').status_code == 200
    assert save(admin, 'synthetic-admin-key', protocol='openai_chat').status_code == 200
    for actor_id, client, key in ((2, alice, KEY_A), (3, bob, KEY_B), (1, admin, 'synthetic-admin-key')):
        response = client.get('/api/ai-settings?user_id=1')
        assert response.status_code == 200
        assert response.json()['key_configured'] is True
        assert 'api_key' not in response.json() and 'key_encrypted' not in response.json()
        assert key not in response.text
        selected = provider_for_actor(actor_id)
        assert selected._api_key == key
        with SessionLocal() as db:
            row = db.get(AiProviderSettings, actor_id)
            assert key not in row.key_encrypted and decrypt(row.key_encrypted) == key
            for event in db.scalars(select(AuditEvent)):
                assert all(secret not in event.detail for secret in (KEY_A, KEY_B, 'synthetic-admin-key'))
    assert provider_for_actor(3).protocol == 'openai_responses'
    assert provider_for_actor(1).protocol == 'openai_chat'
    assert alice.get('/api/ai-settings/3').status_code == 404
    assert save(alice, user_id=3, revision=1).status_code == 422


def test_key_preservation_removal_and_optimistic_conflict(alice):
    first = save(alice).json()
    assert first['revision'] == 1
    assert save(alice, revision=0).status_code == 409
    assert save(alice, '', revision=1, model='replacement-model').json()['revision'] == 2
    assert provider_for_actor(2)._api_key == KEY_A
    assert save(alice, None, revision=2, clear_key=True).status_code == 422
    assert save(alice, None, revision=2, clear_key=True, enabled=False).status_code == 200
    assert provider_for_actor(2) is None
    assert alice.get('/api/ai-settings').json()['key_configured'] is False
    assert save(alice, '', revision=3).status_code == 422
    assert save(alice, KEY_B, revision=3).status_code == 200
    assert provider_for_actor(2)._api_key == KEY_B


def test_bearer_protocol_can_be_saved_without_replacing_tenant_key(alice):
    assert save(alice).status_code == 200
    response = save(alice, None, revision=1, protocol='claude_messages_bearer')
    assert response.status_code == 200, response.text
    provider = provider_for_actor(2)
    assert provider.protocol == 'claude_messages_bearer'
    assert provider._api_key == KEY_A


def test_csrf_and_no_global_admin_fallback(alice, bob, admin, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, 'captcha_vision_api_key', SecretStr('synthetic-global-key'))
    save(admin)
    assert provider_for_actor(2) is None and provider_for_actor(3) is None
    alice.headers['X-CSRF-Token'] = 'invalid'
    assert save(alice).status_code == 403
    assert alice.post('/api/ai-settings/test', json={'revision': 1}).status_code == 403


def test_disabled_deleted_and_unreadable_settings_never_supply_credentials(alice):
    assert save(alice).status_code == 200
    with SessionLocal() as db:
        db.get(User, 2).active = False
        db.commit()
    assert provider_for_actor(2) is None
    with SessionLocal() as db:
        db.get(User, 2).active = True
        db.get(AiProviderSettings, 2).key_encrypted = 'not-a-valid-encrypted-secret'
        db.commit()
    assert provider_for_actor(2) is None


def test_saved_configuration_test_is_synthetic_and_returns_no_key(alice, monkeypatch):
    from app import ai_settings
    seen = []
    class Vision:
        def recognize(self, image):
            assert image.startswith(b'\x89PNG')
            assert image == ai_settings.synthetic_image()
            seen.append(image)
            return 'TEST42'
    monkeypatch.setattr(ai_settings, 'provider_for_actor', lambda actor_id, **kwargs: Vision() if actor_id == 2 else None)
    assert save(alice).status_code == 200
    response = alice.post('/api/ai-settings/test', json={'revision': 1})
    assert response.status_code == 200 and response.json() == {'ok': True, 'code': 'ok'}
    assert len(seen) == 1
    assert alice.post('/api/ai-settings/test', json={'revision': 2}).status_code == 409
    assert alice.post('/api/ai-settings/test', json={'revision': 1, 'image': 'private-image'}).status_code == 422


def test_test_failures_are_redacted_and_configuration_changes_invalidate_result(alice, monkeypatch):
    from app import ai_settings
    from app.vision_captcha import VisionError
    assert save(alice).status_code == 200
    class Vision:
        def recognize(self, image):
            raise VisionError('captcha_provider_failed')
    monkeypatch.setattr(ai_settings, 'provider_for_actor', lambda actor_id, **kwargs: Vision())
    response = alice.post('/api/ai-settings/test', json={'revision': 1})
    assert response.json() == {'ok': False, 'code': 'captcha_provider_failed'}
    def changed(image):
        with SessionLocal() as db:
            db.get(AiProviderSettings, 2).revision += 1
            db.commit()
        return 'TEST42'
    monkeypatch.setattr(Vision, 'recognize', lambda self, image: changed(image))
    assert alice.post('/api/ai-settings/test', json={'revision': 1}).status_code == 409


def test_auth_automation_selects_initiator_and_does_not_share_environment(alice, bob, monkeypatch):
    from app import ai_settings
    from app.auth_automation import automate_challenge
    from test_auth_automation import CaptchaLogin, Vision
    used = []
    def select(actor_id):
        used.append(actor_id)
        return Vision() if actor_id == 2 else None
    monkeypatch.setattr(ai_settings, 'provider_for_actor', select)
    adapter = CaptchaLogin()
    assert automate_challenge(adapter, adapter.start(), actor_id=2).status == 'ready'
    assert adapter.answers
    other = CaptchaLogin()
    assert automate_challenge(other, other.start(), actor_id=3).status == 'challenge'
    assert other.answers == [] and used == [2, 3]
    missing = CaptchaLogin()
    assert automate_challenge(missing, missing.start()).status == 'challenge'
    assert used == [2, 3]


def test_inflight_provider_is_revoked_after_user_configuration_changes(alice):
    import httpx
    from app.vision_captcha import VisionError
    from test_vision_captcha import PNG
    assert save(alice).status_code == 200
    sent = []
    selected = provider_for_actor(2, transport=httpx.MockTransport(lambda request: sent.append(request)))
    assert selected is not None
    assert save(alice, '', revision=1, enabled=False).status_code == 200
    import pytest
    with pytest.raises(VisionError, match='captcha_unavailable'):
        selected.recognize(PNG)
    assert sent == []


def test_managed_worker_uses_initiator_even_for_admin_operating_member_record(admin, monkeypatch):
    from app import auth_automation
    from app.auth_jobs import run_one
    from test_auth_batches import admission, record, DoneAuth, Gateway
    seen = []
    def automated(adapter, progress, *, actor_id=None, **kwargs):
        seen.append(actor_id)
        return progress
    monkeypatch.setattr(auth_automation, 'automate_challenge', automated)
    assert admission(admin, [record(owner=3)]).status_code == 202
    assert run_one(gateway_factory=Gateway, auth_factory=DoneAuth, identity_factory=DoneAuth)
    assert seen == [1]


def test_pasted_worker_uses_own_initiator(alice, monkeypatch):
    from app import external_auth_worker
    from test_external_auth_batches import admit, CompletedAuth
    seen = []
    def automated(adapter, progress, *, actor_id=None, **kwargs):
        seen.append(actor_id)
        return progress
    monkeypatch.setattr(external_auth_worker, 'automate_challenge', automated)
    assert admit(alice).status_code == 202
    assert external_auth_worker.run_one(auth_factory=CompletedAuth)
    assert seen == [2]


def test_schema18_adds_only_user_provider_table_and_preserves_existing_records(tmp_path):
    import sqlite3
    from sqlalchemy import create_engine, inspect
    from app.database import engine
    from app.migrations import VERSION, migrate
    path = tmp_path / 'schema17.db'
    with engine.connect() as source, sqlite3.connect(path) as dest:
        source.connection.driver_connection.backup(dest)
    target = create_engine(f'sqlite:///{path}')
    with target.begin() as db:
        db.exec_driver_sql('DROP TABLE console_ai_provider_settings')
        db.exec_driver_sql('INSERT INTO console_schema_version(version) VALUES (17)')
        before = {name: db.exec_driver_sql(f'SELECT * FROM "{name}"').fetchall()
                  for name in inspect(db).get_table_names() if name != 'console_schema_version'}
    migrate(target)
    migrate(target)
    with target.connect() as db:
        assert db.exec_driver_sql('SELECT version FROM console_schema_version').scalar() == VERSION
        assert db.exec_driver_sql('SELECT count(*) FROM console_ai_provider_settings').scalar() == 0
        assert db.exec_driver_sql('PRAGMA foreign_key_check').fetchall() == []
        for name, rows in before.items():
            assert db.exec_driver_sql(f'SELECT * FROM "{name}"').fetchall() == rows
    target.dispose()
