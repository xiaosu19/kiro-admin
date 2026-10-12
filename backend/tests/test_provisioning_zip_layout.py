"""Real numbered admission and auth validation; only token acquisition is synthetic."""
import io
import json
import re
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import PurePosixPath
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app import models, provisioning_exports
from app.database import SessionLocal
from app.security import decrypt, encrypt
from test_provisioning_admission import admit, duplicate_account, intent, ready, remote
from test_provisioning_exports import materialize


def completed_parent(client, *, accounts=5, quantity=100):
    ids = [1]
    for position in range(2, accounts + 1):
        account_id = duplicate_account(f'a{position}', owner=1)
        with SessionLocal() as db:
            db.get(models.AwsAccount, account_id).name = f'ZIP AWS {position}'
            db.commit()
        ids.append(account_id)
    parent_response = admit(client, {'accounts': [intent(account_id=account_id, quantity=quantity)['accounts'][0] for account_id in ids]})
    assert parent_response.status_code == 202, parent_response.text
    parent = parent_response.json()
    materialize(parent)
    with SessionLocal() as db:
        for child in parent['accounts']:
            for item in child['items']:
                db.get(models.Subscription, item['record_id']).subscription_status = 'active'
        db.commit()
    for child in parent['accounts']:
        response = client.post('/api/auth-batches', json={'kind': 'json_export', 'record_ids': [item['record_id'] for item in child['items']], 'request_key': str(uuid.uuid4())})
        assert response.status_code == 202, response.text
        auth = response.json()
        assert auth['total'] == quantity <= 100
        with SessionLocal() as db:
            for entry in auth['items']:
                item = db.get(models.ProvisioningItem, entry['record_id'])
                item.auth_batch_id, item.auth_job_id = auth['id'], entry['operation_id']
                item.state, item.phase = 'completed', 'done'
                record = db.get(models.Subscription, item.record_id)
                op = db.get(models.RecordOperation, item.auth_job_id)
                op.state, op.phase, op.finished_at = 'completed', 'done', models.now()
                record.active_operation_id = None
                db.get(models.AuthSecret, op.id).result_encrypted = encrypt({
                    'accessToken': f'synthetic-access-{record.id}', 'refreshToken': f'synthetic-refresh-{record.id}',
                    'expiresAt': time.time() + 3600, 'clientId': f'synthetic-client-{record.id}', 'clientSecret': f'synthetic-secret-{record.id}',
                    'authRegion': 'us-east-1', 'apiRegion': 'us-east-1', 'startUrl': record.portal_url,
                    'userId': record.sso_user_id, 'username': record.username,
                    'profile': {'arn': f'arn:aws:codewhisperer:us-east-1:123456789012:profile/{record.id}'},
                    'usage': {'usageBreakdownList': [], 'userInfo': {'userId': record.sso_user_id}},
                })
                item_data = next(row for row in child['items'] if row['record_id'] == item.record_id)
                item_data.update(auth_job_id=item.auth_job_id, auth_batch_id=item.auth_batch_id)
            db.commit()
    return parent


def download(client, parent, child=None):
    path = f"/api/provisioning-batches/{parent['id']}"
    if child:
        path += f"/accounts/{child['id']}"
    return client.post(path + '/download')


def assert_members(response, parent, *, excluded=()):
    assert response.status_code == 200, response.text
    expected = {f"{child['account_number']}/{item['username']}.json": item for child in parent['accounts'] for item in child['items'] if item['record_id'] not in excluded}
    assert int(response.headers['x-export-count']) == len(expected)
    assert int(response.headers['x-excluded-count']) == len(excluded)
    assert response.headers['cache-control'] == 'no-store'
    header = response.headers['content-disposition']
    assert header.isascii() and re.fullmatch(r'attachment; filename="\d{4}-\d{2}-\d{2}-batch-[a-f0-9]{8}\.zip"', header)
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert archive.namelist() == list(expected), 'account and numeric item order remain stable'
        assert len({PurePosixPath(name).parts[0] for name in archive.namelist()}) == len(parent['accounts'])
        for name, item in expected.items():
            value = json.loads(archive.read(name))
            assert isinstance(value, list) and len(value) == 1
            row = value[0]
            assert row['id'] == item['record_id'] and row['label'] == item['username']
            assert row['userId'] == 'sso-' + item['record_id']
            assert row['accessToken'] == 'synthetic-access-' + item['record_id']
            assert row['refreshToken'] == 'synthetic-refresh-' + item['record_id']
            assert row['clientSecret'] == 'synthetic-secret-' + item['record_id']
            assert row['authMethod'] == 'IdC' and row['provider'] == 'Enterprise'
            assert row['kiro_profile_raw']['profiles'][0]['arn'] == row['profileArn']


@pytest.mark.parametrize('failures', [0, 2])
def test_five_accounts_of_100_export_500_or_498_real_json_members(admin, ready, failures):
    parent = completed_parent(admin)
    assert len(parent['accounts']) == 5 and sum(child['quantity'] for child in parent['accounts']) == 500
    excluded = [parent['accounts'][position]['items'][0]['record_id'] for position in range(failures)]
    with SessionLocal() as db:
        for record_id in excluded:
            item = db.get(models.ProvisioningItem, record_id)
            db.get(models.RecordOperation, item.auth_job_id).state = 'failed'
            db.get(models.AuthSecret, item.auth_job_id).result_encrypted = None
        db.commit()
    assert_members(download(admin, parent), parent, excluded=excluded)
    with SessionLocal() as db:
        assert all(secret.result_encrypted is None for secret in db.scalars(select(models.AuthSecret)))
        assert all(auth.state == 'downloaded' for auth in db.scalars(select(models.AuthBatch)))


def test_parent_waits_for_last_account_challenge_before_any_result_is_consumed(admin, ready):
    parent = completed_parent(admin, accounts=2, quantity=2)
    item = parent['accounts'][-1]['items'][-1]
    with SessionLocal() as db:
        db.get(models.RecordOperation, item['auth_job_id']).state = 'challenge'
        db.commit()
    result = download(admin, parent)
    assert result.status_code == 409 and '等待' in result.text
    with SessionLocal() as db:
        assert all(secret.result_encrypted for secret in db.scalars(select(models.AuthSecret)))
        assert all(auth.state == 'active' for auth in db.scalars(select(models.AuthBatch)))


def test_account_zip_uses_frozen_account_number_and_same_folder_layout(admin, ready):
    parent = completed_parent(admin, accounts=2, quantity=2)
    child = parent['accounts'][0]
    with SessionLocal() as db:
        db.get(models.AwsAccount, child['aws_account_id']).account_number = 'renamed-display-code'
        db.commit()
    assert_members(download(admin, parent, child), {**parent, 'accounts': [child]})


@pytest.mark.parametrize('mutation', ['record_username', 'record_account', 'auth_link', 'token_identity'])
def test_identity_mismatch_rejects_entire_archive_and_preserves_successful_secrets(admin, ready, mutation):
    parent = completed_parent(admin, accounts=2, quantity=2)
    first, second = parent['accounts'][0]['items']
    with SessionLocal() as db:
        item = db.get(models.ProvisioningItem, second['record_id'])
        record = db.get(models.Subscription, second['record_id'])
        if mutation == 'record_username':
            record.username = 'replacement-username'
        elif mutation == 'record_account':
            record.aws_account_id = parent['accounts'][1]['aws_account_id']
        elif mutation == 'auth_link':
            item.auth_job_id = first['auth_job_id']
        else:
            secret = db.get(models.AuthSecret, item.auth_job_id)
            value = decrypt(secret.result_encrypted)
            value['username'] = 'different-person'
            secret.result_encrypted = encrypt(value)
        db.commit()
    result = download(admin, parent)
    assert result.status_code == 409, result.text
    with SessionLocal() as db:
        assert all(secret.result_encrypted for secret in db.scalars(select(models.AuthSecret)))
        assert all(auth.state == 'active' for auth in db.scalars(select(models.AuthBatch)))


@pytest.mark.parametrize('instant,expected', [(datetime(2026, 10, 10, 15, 59, 59, tzinfo=timezone.utc), '2026-10-10'),
    (datetime(2026, 10, 10, 16, 0, 0, tzinfo=timezone.utc), '2026-10-11'), (datetime(2026, 10, 10, 16, 0, 0), '2026-10-11')])
def test_archive_date_uses_singapore_today_including_utc_boundary(monkeypatch, instant, expected):
    assert hasattr(provisioning_exports, 'archive_filename')
    monkeypatch.setattr(provisioning_exports, 'now', lambda: instant)
    assert provisioning_exports.archive_filename('12345678-1234-4321-4321-123456789abc') == f'{expected}-batch-12345678.zip'


def test_unicode_and_malicious_names_are_safe_unique_and_keep_each_json_identity(admin, ready):
    parent = completed_parent(admin, accounts=2, quantity=2)
    names = ['../同名\\用户', '..\\同名/用户', '.', '..']
    with SessionLocal() as db:
        for child in parent['accounts']:
            row = db.get(models.ProvisioningAccountBatch, child['id'])
            snapshot = json.loads(row.snapshot)
            snapshot['account_number'] = '../母号\\编号' if row.position == 1 else '..\\母号/编号'
            row.snapshot = json.dumps(snapshot)
            for item_data in child['items']:
                item = db.get(models.ProvisioningItem, item_data['record_id'])
                record = db.get(models.Subscription, item.record_id)
                item.username = record.username = names.pop(0)
                secret = db.get(models.AuthSecret, item.auth_job_id)
                result = decrypt(secret.result_encrypted); result['username'] = record.username
                secret.result_encrypted = encrypt(result)
        db.commit()
    response = download(admin, parent)
    assert response.status_code == 200, response.text
    assert response.headers['content-disposition'].isascii()
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        names = archive.namelist()
        assert len(names) == len({name.casefold() for name in names}) == 4
        assert len({PurePosixPath(name).parts[0] for name in names}) == 2
        assert any('母号' in name for name in names), 'ZIP members preserve readable UTF-8 names'
        for name in names:
            path = PurePosixPath(name)
            assert len(path.parts) == 2 and not path.is_absolute()
            assert all(part not in ('.', '..', '') for part in path.parts)
            assert not re.search(r'[\\\x00-\x1f\x7f]', name)
            row = json.loads(archive.read(name))[0]
            assert row['accessToken'] == 'synthetic-access-' + row['id']


def test_missing_account_number_falls_back_to_frozen_real_id_and_header_stays_ascii(monkeypatch):
    children = [SimpleNamespace(id='child-one', aws_account_id=17, account_number='',
        snapshot=json.dumps({'real_aws_account_id': '123456789012'}))]
    items = [SimpleNamespace(record_id='record-one', account_batch_id='child-one', username='..', internal_id='a-01-01')]
    assert provisioning_exports.zip_member_paths(children, items) == {'record-one': '123456789012/a-01-01.json'}
    monkeypatch.setattr(provisioning_exports, 'now', lambda: datetime(2026, 10, 11))
    filename = provisioning_exports.archive_filename('../中文\r\nInjected: header')
    assert filename.isascii() and re.fullmatch(r'2026-10-11-batch-[a-f0-9]{8}\.zip', filename)


def test_auth_batch_cannot_include_a_record_outside_the_selected_account_scope(admin, ready):
    parent = completed_parent(admin, accounts=2, quantity=2)
    first, second = parent['accounts']
    with SessionLocal() as db:
        unrelated = db.get(models.AuthJob, second['items'][0]['auth_job_id'])
        unrelated.batch_id = first['items'][0]['auth_batch_id']
        unrelated.position = 3
        db.commit()
    response = download(admin, parent, first)
    assert response.status_code == 409, response.text
    with SessionLocal() as db:
        assert all(secret.result_encrypted for secret in db.scalars(select(models.AuthSecret)))
        assert all(auth.state == 'active' for auth in db.scalars(select(models.AuthBatch)))

