"""Numbered downloads exercise real admission, authorization and in-memory output."""
import csv
import io
import json
import zipfile
from datetime import timedelta

import pytest
from sqlalchemy import select

from app import models
from app.database import SessionLocal
from app.security import encrypt
from test_provisioning_admission import admit, intent, ready, remote, duplicate_account
from test_provisioning_coordinator import gateway, drive, Gateway
from test_auth_batches import drain, DoneAuth, Gateway as AuthGateway


def materialize(parent):
    with SessionLocal() as db:
        for child in parent['accounts']:
            for item in child['items']:
                db.add(models.Subscription(id=item['record_id'], owner_id=parent['actor_id'],
                    aws_account_id=child['aws_account_id'], request_key=item['record_id'],
                    username=item['username'], email=item['email'], state='completed', step='done',
                    reserved=False, provision_only=True, sso_user_id='sso-' + item['record_id'],
                    portal_url='https://example.awsapps.com/start', password_encrypted=encrypt('SyntheticOTP123!')))
        db.commit()


def rows(response):
    assert response.status_code == 200, response.text
    assert response.headers['cache-control'] == 'no-store'
    return list(csv.DictReader(io.StringIO(response.content.decode('utf-8-sig'))))


def test_numbered_credentials_mapping_fuzzy_scope_and_numeric_order(alice, bob, ready):
    with SessionLocal() as db:
        db.get(models.PlanCounter, 1).limit_count = 100
        db.commit()
    parent = admit(alice, intent(quantity=100)).json()
    materialize(parent)
    child = parent['accounts'][0]
    result = rows(alice.post('/api/sso-users/export', json={'provisioning_batch_id': parent['id']}))
    assert [r['内部 ID'] for r in result] == [f'a-01-{i:02}' for i in range(1, 101)]
    assert result[0]['AWS 编号'] == 'a' and result[0]['批次编号'] == 'a-01'
    assert result[0]['用户名'] == child['items'][0]['username']
    txt = alice.post('/api/sso-users/export', json={'provisioning_account_batch_id': child['id'], 'format': 'txt'})
    assert txt.status_code == 200 and txt.text.startswith('内部 ID：a-01-01\nAWS 登录地址：')
    assert '用户名：' + child['items'][0]['username'] in txt.text
    assert bob.post('/api/sso-users/export', json={'provisioning_batch_id': parent['id']}).status_code == 404
    assert alice.post('/api/sso-users/export', json={'provisioning_batch_id': parent['id'], 'record_ids': [child['items'][0]['record_id']]}).status_code == 422
    assert len(rows(alice.post('/api/sso-users/export', json={'provisioning_batch_id': parent['id'], 'q': 'a-01-100', 'aws_account_id': 1}))) == 1
    assert alice.post('/api/sso-users/export', json={'provisioning_batch_id': parent['id'], 'q': 'a-01-100', 'aws_account_id': 999}).status_code == 409
    directory = alice.get('/api/sso-users?q=a-01-100&aws_account_id=1').json()
    assert directory['total'] == 1 and directory['items'][0]['internal_id'] == 'a-01-100'
    assert alice.get('/api/subscriptions?q=a-01-100&aws_account_id=999').json()['total'] == 0
    credential = alice.post('/api/subscriptions/' + child['items'][0]['record_id'] + '/credentials').json()
    assert credential['internal_id'] == 'a-01-01'


def test_report_contains_uncreated_intents_and_no_secrets_with_and_filters(alice, bob, ready):
    parent = admit(alice, intent()).json()
    child = parent['accounts'][0]
    response = alice.get('/api/provisioning-batches/report', params={'account_batch_id': child['id']})
    report = rows(response)
    assert len(report) == 1 and report[0]['内部 ID'] == 'a-01-01'
    assert report[0]['真实用户名'] == child['items'][0]['username']
    assert '密码' not in response.text and 'token' not in response.text.lower()
    assert rows(alice.get('/api/provisioning-batches/report', params={'q': 'a-01', 'aws_account_id': 1})) == report
    assert alice.get('/api/provisioning-batches/report?q=a-01&aws_account_id=999').status_code == 409
    assert bob.get('/api/provisioning-batches/report', params={'account_batch_id': child['id']}).status_code == 404


def test_history_and_report_match_aws_and_search_in_the_same_account_batch(alice, ready):
    second = duplicate_account('b')
    with SessionLocal() as db:
        db.get(models.PlanCounter, 1).limit_count = 10
        db.commit()
    parent = admit(alice, {'accounts': [intent(quantity=2)['accounts'][0],
        intent(account_id=second, quantity=3)['accounts'][0]]}).json()
    first, child = parent['accounts']
    expected = [i['internal_id'] for i in child['items']]
    for q in ('b-01', child['items'][1]['internal_id'], child['items'][1]['username']):
        selected = {'aws_account_id': second, 'q': q}
        listing = alice.get('/api/provisioning-batches', params=selected).json()
        assert listing['total'] == 1 and len(listing['items'][0]['accounts']) == 2
        report = rows(alice.get('/api/provisioning-batches/report', params=selected))
        assert [r['内部 ID'] for r in report] == expected
        mismatch = {'aws_account_id': first['aws_account_id'], 'q': q}
        assert alice.get('/api/provisioning-batches', params=mismatch).json()['total'] == 0
        assert alice.get('/api/provisioning-batches/report', params=mismatch).status_code == 409
    for selected in ({'q': 'b-01'}, {'aws_account_id': second}, {'aws_account_id': second, 'q': parent['id']}):
        assert [r['内部 ID'] for r in rows(alice.get('/api/provisioning-batches/report', params=selected))] == expected
    assert len(rows(alice.get('/api/provisioning-batches/report'))) == 5


@pytest.mark.parametrize('scope', ['provisioning_batch_id', 'provisioning_account_batch_id'])
def test_empty_numbered_export_scope_does_not_expand_to_all_records(alice, scope):
    assert alice.post('/api/sso-users/export', json={scope: ''}).status_code == 422


@pytest.mark.parametrize('scope', ['batch_id', 'account_batch_id'])
def test_empty_report_scope_does_not_expand_to_all_batches(alice, scope):
    assert alice.get('/api/provisioning-batches/report', params={scope: ''}).status_code == 422


def test_aggregate_json_zip_private_single_use_and_no_provisioning_writes(alice, admin, gateway):
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    child = parent['accounts'][0]
    path = f"/api/provisioning-batches/{parent['id']}/accounts/{child['id']}/download"
    assert alice.post(path).status_code == 409
    assert admin.post(path).status_code == 404
    drain(DoneAuth, AuthGateway)
    writes = list(gateway.events)
    response = alice.post(path)
    assert response.status_code == 200, response.text
    assert response.headers['cache-control'] == 'no-store'
    assert response.headers['x-export-count'] == '2'
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert archive.namelist() == [child['account_number'] + '/' + i['username'] + '.json' for i in child['items']]
    with SessionLocal() as db:
        assert all(s.result_encrypted is None and s.workflow_encrypted is None for s in db.scalars(select(models.AuthSecret)))
        assert db.get(models.PlanCounter, 1).used_count == 2
    assert alice.post(path).status_code == 410
    assert gateway.events == writes


def test_aggregate_json_waits_for_challenge_and_excludes_expired_terminal_result(alice, gateway):
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    path = f"/api/provisioning-batches/{parent['id']}/download"
    drain(DoneAuth, AuthGateway)
    first, second = parent['accounts'][0]['items']
    with SessionLocal() as db:
        db.get(models.RecordOperation, second['auth_job_id']).state = 'challenge'
        db.get(models.AuthBatch, second['auth_batch_id']).completed_at = None
        db.commit()
    assert alice.post(path).status_code == 409
    with SessionLocal() as db:
        assert db.get(models.AuthSecret, first['auth_job_id']).result_encrypted
        db.get(models.RecordOperation, second['auth_job_id']).state = 'failed'
        db.get(models.AuthBatch, second['auth_batch_id']).expires_at = models.now() - timedelta(seconds=1)
        db.commit()
    response = alice.post(path)
    assert response.status_code == 200, response.text
    assert response.headers['x-export-count'] == '1' and response.headers['x-excluded-count'] == '1'


def test_parent_export_exceeds_1000_without_truncating_and_unknown_password_is_not_leaked(admin, ready):
    ids = [1]
    for n in range(2, 12):
        aid = duplicate_account('a' + str(n), owner=1)
        with SessionLocal() as db:
            db.get(models.AwsAccount, aid).name = 'AWS ' + str(n)
            db.commit()
        ids.append(aid)
    body = {'accounts': [intent(account_id=aid, quantity=100)['accounts'][0] for aid in ids]}
    parent = admit(admin, body).json()
    materialize(parent)
    with SessionLocal() as db:
        first = db.get(models.Subscription, parent['accounts'][0]['items'][0]['record_id'])
        first.credential_state = 'unknown'
        first.password_encrypted = encrypt('DoNotLeakOldCandidate!')
        first.sso_display_name = '=HYPERLINK("https://example.invalid")'
        db.commit()
    response = admin.post('/api/sso-users/export', json={'provisioning_batch_id': parent['id']})
    result = rows(response)
    assert len(result) == 1100
    assert [r['内部 ID'] for r in result] == [item['internal_id'] for a in parent['accounts'] for item in a['items']]
    assert result[0]['密码'] == '' and 'DoNotLeakOldCandidate!' not in response.text
    assert result[0]['姓名'].startswith("'=HYPERLINK")
    assert len(rows(admin.get('/api/provisioning-batches/report', params={'batch_id': parent['id']}))) == 1100


def two_accounts(alice):
    second = duplicate_account('b')
    body = {'accounts': [intent()['accounts'][0], intent(account_id=second)['accounts'][0]]}
    return drive(admit(alice, body).json(), alice)


def test_parent_zip_aggregates_accounts_and_refuses_a_partly_consumed_scope(alice, gateway):
    parent = two_accounts(alice)
    drain(DoneAuth, AuthGateway)
    first, second = parent['accounts']
    own_path = f"/api/provisioning-batches/{parent['id']}/accounts/{first['id']}/download"
    assert alice.post(own_path).status_code == 200
    response = alice.post(f"/api/provisioning-batches/{parent['id']}/download")
    assert response.status_code == 410 and '已下载' in response.text
    with SessionLocal() as db:
        assert db.get(models.AuthSecret, second['items'][0]['auth_job_id']).result_encrypted
    assert alice.post(f"/api/provisioning-batches/{parent['id']}/accounts/{second['id']}/download").status_code == 200


def test_consumed_parent_zip_returns_gone_even_while_another_account_waits(alice, gateway):
    parent = two_accounts(alice)
    drain(DoneAuth, AuthGateway)
    first, second = parent['accounts']
    assert alice.post(f"/api/provisioning-batches/{parent['id']}/accounts/{first['id']}/download").status_code == 200
    item = second['items'][0]
    with SessionLocal() as db:
        db.get(models.RecordOperation, item['auth_job_id']).state = 'challenge'
        db.get(models.AuthBatch, item['auth_batch_id']).completed_at = None
        db.commit()
    response = alice.post(f"/api/provisioning-batches/{parent['id']}/download")
    assert response.status_code == 410 and '已下载' in response.text
    with SessionLocal() as db:
        assert db.get(models.AuthSecret, item['auth_job_id']).result_encrypted
        assert db.get(models.RecordOperation, item['auth_job_id']).state == 'challenge'
        db.get(models.RecordOperation, item['auth_job_id']).state = 'completed'
        db.commit()
    assert alice.post(f"/api/provisioning-batches/{parent['id']}/accounts/{second['id']}/download").status_code == 200


def test_parent_zip_ready_two_accounts_and_current_credentials_validation(alice, gateway):
    parent = two_accounts(alice)
    drain(DoneAuth, AuthGateway)
    rid = parent['accounts'][1]['items'][0]['record_id']
    with SessionLocal() as db:
        db.get(models.Subscription, rid).credential_revision += 1
        db.commit()
    path = f"/api/provisioning-batches/{parent['id']}/download"
    assert alice.post(path).status_code == 409
    with SessionLocal() as db:
        assert all(s.result_encrypted for s in db.scalars(select(models.AuthSecret)))
        db.get(models.Subscription, rid).credential_revision -= 1
        db.commit()
    result = alice.post(path)
    assert result.status_code == 200 and result.headers['x-export-count'] == '2'
    with zipfile.ZipFile(io.BytesIO(result.content)) as archive:
        assert archive.namelist() == [a['account_number'] + '/' + a['items'][0]['username'] + '.json' for a in parent['accounts']]


def test_waiting_auth_admission_cannot_be_silently_excluded(alice, gateway):
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    drain(DoneAuth, AuthGateway)
    with SessionLocal() as db:
        item = db.get(models.ProvisioningItem, parent['accounts'][0]['items'][1]['record_id'])
        item.auth_batch_id = item.auth_job_id = None
        db.commit()
    response = alice.post(f"/api/provisioning-batches/{parent['id']}/download")
    assert response.status_code == 409
    with SessionLocal() as db:
        assert db.get(models.AuthSecret, parent['accounts'][0]['items'][0]['auth_job_id']).result_encrypted


def test_concurrent_aggregate_and_ordinary_download_consume_a_result_once(alice, gateway, monkeypatch):
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor
    from app import provisioning_exports
    parent = drive(admit(alice, intent()).json(), alice)
    drain(DoneAuth, AuthGateway)
    assert alice.get('/api/auth-batches/' + parent['accounts'][0]['items'][0]['auth_batch_id']).json()['download_ready']
    started, release = threading.Event(), threading.Event()
    original = provisioning_exports.build_zip
    def slow(rows, paths):
        started.set()
        assert release.wait(3)
        return original(rows, paths)
    monkeypatch.setattr(provisioning_exports, 'build_zip', slow)
    with ThreadPoolExecutor(max_workers=2) as pool:
        aggregate = pool.submit(alice.post, f"/api/provisioning-batches/{parent['id']}/download")
        assert started.wait(3)
        ordinary = pool.submit(alice.post, f"/api/auth-batches/{parent['accounts'][0]['items'][0]['auth_batch_id']}/download")
        time.sleep(.05)
        release.set()
        assert sorted([aggregate.result().status_code, ordinary.result().status_code]) == [200, 410]


def test_numbered_mapping_queries_are_batched_for_directory_and_group_projection(alice, gateway):
    from sqlalchemy import event
    from app.database import engine
    parent = drive(admit(alice, intent(quantity=3, exports={'csv': True, 'txt': True, 'json': False})).json(), alice)
    statements = []
    def capture(_conn, _cursor, statement, _parameters, _context, _many):
        if 'console_provisioning_items.internal_id' in statement:
            statements.append(statement)
    event.listen(engine, 'before_cursor_execute', capture)
    try:
        assert alice.get('/api/sso-users').status_code == 200
        assert len(statements) == 1
        statements.clear()
        result = alice.get('/api/groups/' + parent['accounts'][0]['group']['id'])
        assert result.status_code == 200
        assert len(statements) == 1
        assert all(row['internal_id'] for row in result.json()['members'])
    finally:
        event.remove(engine, 'before_cursor_execute', capture)


def test_filtered_report_has_explicit_10000_bound_and_never_silently_truncates(admin, ready):
    from sqlalchemy import insert
    import uuid
    parent = admit(admin, intent(quantity=100)).json()
    with SessionLocal() as db:
        original = db.get(models.ProvisioningBatch, parent['id'])
        child = db.get(models.ProvisioningAccountBatch, parent['accounts'][0]['id'])
        parent_values = {c.name: getattr(original, c.name) for c in original.__table__.columns}
        child_values = {c.name: getattr(child, c.name) for c in child.__table__.columns}
        for n in range(2, 102):
            pid, cid = str(uuid.uuid4()), str(uuid.uuid4())
            db.execute(insert(models.ProvisioningBatch), [parent_values | {'id': pid, 'request_key': pid}])
            db.execute(insert(models.ProvisioningAccountBatch), [child_values | {'id': cid, 'batch_id': pid, 'sequence': n, 'batch_number': f'a-{n:02}'}])
            db.execute(insert(models.ProvisioningItem), [{'record_id': str(uuid.uuid4()), 'account_batch_id': cid,
                'position': i, 'internal_id': f'a-{n:02}-{i:02}', 'username': f'report-{n}-{i}', 'email': 'synthetic@example.invalid'} for i in range(1, 101)])
        db.commit()
    response = admin.get('/api/provisioning-batches/report')
    assert response.status_code == 409 and '10000' in response.text
