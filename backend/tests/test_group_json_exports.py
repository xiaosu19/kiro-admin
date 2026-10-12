"""Whole/multiple group exports use the existing fake native auth worker."""

import io
import json
import uuid
import zipfile

import pytest
from sqlalchemy import select

from app.database import SessionLocal
from app.models import AuthBatch, AuthJob, AuthSecret, AwsAccount, Binding, ManagedGroup, RecordOperation, Subscription, User
from app.security import encrypt
from test_auth_batches import DoneAuth, Gateway, drain


def seed_groups(count=1, quantity=2, *, owner=2):
    groups, records = [], []
    with SessionLocal() as db:
        db.get(AwsAccount, 1).account_number = 'a'
        for index in range(count):
            group = ManagedGroup(id=str(uuid.uuid4()), owner_id=owner, aws_account_id=1,
                aws_scope='123456789012:d-1234567890', name=f'group-{index}', marker='fake',
                remote_id='remote-' + str(index), request_key=str(uuid.uuid4()), payload_hash='old', state='ready')
            db.add(group)
            groups.append(group.id)
            for position in range(quantity):
                rid = str(uuid.uuid4())
                record = Subscription(id=rid, owner_id=owner, aws_account_id=1,
                    group_id=group.id, group_membership_id='membership-' + rid,
                    request_key=rid, username=f'actual-{index}-{position}', email=f'user-{index}-{position}@example.com',
                    state='completed', step='done', reserved=False, provision_only=True,
                    sso_user_id='sso-' + rid, portal_url='https://d-1234567890.awsapps.com/start',
                    password_encrypted=encrypt('FakeOTP9!'))
                db.add(record)
                records.append(rid)
        db.commit()
    return groups, records


def preview(client, groups):
    return client.post('/api/group-json-exports/preview', json={'group_ids': groups})


def admit(client, value, *, key=None):
    return client.post('/api/group-json-exports', json={
        'preview_id': value['id'], 'fingerprint': value['fingerprint'],
        'request_key': key or str(uuid.uuid4()), 'acknowledge_password_changes': True,
    })


def test_five_groups_of_one_hundred_admit_exactly_five_hundred_existing_auth_jobs(alice):
    groups, records = seed_groups(5, 100)
    value = preview(alice, groups)
    assert value.status_code == 200, value.text
    assert value.json()['total'] == value.json()['eligible_count'] == 500
    assert [group['eligible_count'] for group in value.json()['groups']] == [100] * 5
    assert 'FakeOTP' not in value.text
    key = str(uuid.uuid4())
    response = admit(alice, value.json(), key=key)
    assert response.status_code == 202, response.text
    assert response.json()['total'] == 500
    assert admit(alice, value.json(), key=key).json()['id'] == response.json()['id']
    with SessionLocal() as db:
        assert {job.record_id for job in db.scalars(select(AuthJob))} == set(records)
        assert len(list(db.scalars(select(AuthBatch)))) == 1
        assert all(db.get(Subscription, rid).active_operation_id for rid in records)
    # Password/manual routes keep their original admission bound.
    assert alice.post('/api/auth-batches', json={
        'kind': 'reset_password', 'record_ids': records, 'request_key': str(uuid.uuid4())}).status_code == 422


@pytest.mark.parametrize('drift', ['members', 'new_member', 'group_revision', 'owner', 'config', 'session', 'role'])
def test_preview_freezes_group_identity_members_authority_and_config(alice, drift):
    groups, records = seed_groups()
    value = preview(alice, groups)
    assert value.status_code == 200, value.text
    with SessionLocal() as db:
        if drift == 'members':
            db.get(Subscription, records[0]).group_membership_id = 'replacement-membership'
        elif drift == 'new_member':
            db.add(Subscription(id='new-member', owner_id=2, aws_account_id=1, group_id=groups[0],
                request_key='new-member-request', username='new-member', email='new@example.com',
                portal_url='https://d-1234567890.awsapps.com/start', state='completed', step='done',
                reserved=False, provision_only=True, sso_user_id='new-sso'))
        elif drift == 'group_revision':
            db.get(ManagedGroup, groups[0]).revision += 1
        elif drift == 'owner':
            db.get(ManagedGroup, groups[0]).owner_id = 3
        elif drift == 'config':
            db.get(AwsAccount, 1).profile_arn += '-changed'
        elif drift == 'session':
            db.get(User, 2).session_version += 1
        else:
            db.get(User, 2).role = 'admin'
        db.commit()
    result = admit(alice, value.json())
    assert result.status_code in (401, 404, 409), result.text
    with SessionLocal() as db:
        assert not list(db.scalars(select(AuthJob)))


def test_partial_group_export_frozen_number_paths_real_schema_and_single_use(alice):
    groups, records = seed_groups(2, 2)
    with SessionLocal() as db:
        db.get(Subscription, records[1]).password_encrypted = None
        db.commit()
    value = preview(alice, groups)
    assert value.status_code == 200, value.text
    assert value.json()['eligible_count'] == 3 and value.json()['skipped_count'] == 1
    response = admit(alice, value.json())
    assert response.status_code == 202, response.text
    batch = response.json()
    drain(DoneAuth, Gateway, limit=20)
    with SessionLocal() as db:
        db.get(AwsAccount, 1).account_number = 'renamed-after-admission'
        failed = db.scalar(select(AuthJob).where(AuthJob.record_id == records[-1]))
        db.get(RecordOperation, failed.id).state = 'failed'
        db.get(AuthSecret, failed.id).result_encrypted = None
        db.commit()
    result = alice.post(f"/api/auth-batches/{batch['id']}/download")
    assert result.status_code == 200, result.text
    assert '-batch-' in result.headers['content-disposition']
    assert result.headers['x-export-count'] == '2' and result.headers['x-excluded-count'] == '1'
    with zipfile.ZipFile(io.BytesIO(result.content)) as archive:
        assert set(archive.namelist()) == {'a/actual-0-0.json', 'a/actual-1-0.json'}
        for name in archive.namelist():
            value = json.loads(archive.read(name))
            assert isinstance(value, list) and len(value) == 1
            assert value[0]['authMethod'] == 'IdC' and value[0]['profileArn']
            assert value[0]['usageData']['daysUntilReset'] == 7
            assert value[0]['label'] == name.removeprefix('a/').removesuffix('.json')
    with SessionLocal() as db:
        assert all(secret.result_encrypted is None for secret in db.scalars(select(AuthSecret)))
        assert all(not db.get(Subscription, rid).counted for rid in records)
    assert alice.post(f"/api/auth-batches/{batch['id']}/download").status_code == 410


def test_foreign_groups_and_csrf_cannot_preview_or_admit(alice, bob):
    groups, _ = seed_groups()
    assert preview(bob, groups).status_code == 404
    value = preview(alice, groups).json()
    assert admit(bob, value).status_code == 404
    alice.headers['X-CSRF-Token'] = 'wrong'
    assert preview(alice, groups).status_code == 403
    assert admit(alice, value).status_code == 403


def test_worker_refuses_member_or_proxy_drift_before_constructing_auth(alice):
    groups, records = seed_groups(quantity=1)
    response = admit(alice, preview(alice, groups).json())
    assert response.status_code == 202, response.text
    with SessionLocal() as db:
        db.get(Subscription, records[0]).group_membership_id = 'foreign'
        db.commit()
    class Forbidden(Gateway):
        def __init__(self, account):
            pytest.fail('scope drift must stop before native AWS transport')
    drain(DoneAuth, Forbidden)
    with SessionLocal() as db:
        assert db.scalar(select(RecordOperation)).state == 'cancelled'
        assert db.scalar(select(AuthSecret)).result_encrypted is None


def test_group_export_refuses_more_than_five_thousand_members_without_partial_jobs(alice):
    groups, _ = seed_groups(quantity=5001)
    result = preview(alice, groups)
    assert result.status_code == 409 and '5000' in result.text
    with SessionLocal() as db:
        assert not list(db.scalars(select(AuthJob)))


@pytest.mark.parametrize('tamper', ['path', 'missing_member', 'extra_job'])
def test_group_zip_refuses_tampered_frozen_mapping_and_keeps_results(alice, tamper):
    from app.group_export_models import AuthExportMember
    groups, _ = seed_groups(quantity=1)
    batch = admit(alice, preview(alice, groups).json()).json()
    drain(DoneAuth, Gateway)
    with SessionLocal() as db:
        member = db.scalar(select(AuthExportMember))
        if tamper == 'path':
            member.member_path = '../foreign.json'
        elif tamper == 'missing_member':
            db.delete(member)
        else:
            original = db.scalar(select(AuthJob))
            db.add(Subscription(id='foreign-record', owner_id=2, aws_account_id=1, group_id=member.group_id,
                group_membership_id='foreign-member', request_key='foreign-record-request', username='foreign',
                email='foreign@example.com', state='completed', step='done', reserved=False, provision_only=True,
                portal_url='https://d-1234567890.awsapps.com/start', sso_user_id='foreign-sso'))
            db.flush()
            db.add(RecordOperation(id='extra-op', record_id='foreign-record', actor_id=2,
                kind='auth_json_export', request_key='extra-job-request', payload='{}', state='completed'))
            db.flush()
            db.add(AuthJob(id='extra-op', batch_id=batch['id'], record_id='foreign-record', position=5,
                credential_revision=original.credential_revision, account_fingerprint=original.account_fingerprint))
            db.add(AuthSecret(job_id='extra-op', result_encrypted=db.scalar(select(AuthSecret)).result_encrypted))
        db.commit()
    result = alice.post(f"/api/auth-batches/{batch['id']}/download")
    assert result.status_code == 409, result.text
    with SessionLocal() as db:
        assert db.get(AuthBatch, batch['id']).state == 'active'
        assert db.scalar(select(AuthSecret)).result_encrypted


def test_group_download_rechecks_revocation_during_memory_serialization(alice, monkeypatch):
    from sqlalchemy import delete
    from app import group_json_exports
    groups, _ = seed_groups(quantity=1)
    batch = admit(alice, preview(alice, groups).json()).json()
    drain(DoneAuth, Gateway)
    original = group_json_exports.grouped_zip
    def revoke(db, batch, rows):
        content = original(db, batch, rows)
        # Real POSTs hold the user write lock throughout serialization. Inject
        # drift in that transaction to also exercise the final access check.
        db.execute(delete(Binding).where(Binding.user_id == 2, Binding.aws_account_id == 1))
        return content
    monkeypatch.setattr(group_json_exports, 'grouped_zip', revoke)
    assert alice.post(f"/api/auth-batches/{batch['id']}/download").status_code == 403
    with SessionLocal() as db:
        assert db.get(AuthBatch, batch['id']).state == 'active'
        assert db.scalar(select(AuthSecret)).result_encrypted


def test_group_progress_loads_retry_metadata_in_one_bounded_query(alice):
    from sqlalchemy import event
    from app.database import engine
    groups, _ = seed_groups(quantity=12)
    batch = admit(alice, preview(alice, groups).json()).json()
    queries = []
    def observe(conn, cursor, statement, parameters, context, many):
        if statement.lstrip().upper().startswith('SELECT') and 'console_automatic_retries' in statement:
            queries.append(statement)
    event.listen(engine, 'before_cursor_execute', observe)
    try:
        response = alice.get('/api/auth-batches/' + batch['id'])
        assert response.status_code == 200, response.text
        assert len(queries) == 1
    finally:
        event.remove(engine, 'before_cursor_execute', observe)
