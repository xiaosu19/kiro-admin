"""Cancel-first deletion uses fake AWS state and never contacts live services."""

import uuid
from datetime import timedelta

import pytest
from botocore.exceptions import ClientError
from sqlalchemy import select

from app import aws
from app.database import SessionLocal
from app.models import (
    AwsAccount, Binding, GroupJob, GroupMemberActivation, ManagedGroup,
    NativeGroupGrant, PlanCounter, ProvisioningAccountBatch, ProvisioningBatch,
    RecordOperation, Subscription, User, now,
)
from app.security import encrypt


class Directory:
    def __init__(self):
        self.users, self.groups, self.members, self.direct, self.native = {}, {}, {}, {}, {}
        self.calls = []
        self.keep_user = self.keep_group = self.keep_cancel = False
        self.on_cancel = None

    def __call__(self, account):
        self.account = account
        return self

    def verify(self):
        return None

    def user_info(self, record):
        return self.users.get(record.sso_user_id)

    def get_group(self, gid):
        return self.groups.get(gid)

    def get_group_id(self, name):
        return next((gid for gid, group in self.groups.items() if group['name'] == name), None)

    def list_group_memberships(self, gid):
        return [dict(id=mid, user_id=uid) for (group, uid), mid in self.members.items() if group == gid]

    def list_user_memberships(self, uid):
        return {gid: mid for (gid, user), mid in self.members.items() if user == uid}

    def get_group_membership(self, gid, uid):
        return self.members.get((gid, uid))

    def group_subscription_info(self, group):
        return self.native.get(group.remote_id, self.absent())

    @staticmethod
    def absent():
        return dict(status='not_subscribed', subscription_type=None, expires_at=None, pending_type=None)

    def user_subscription_sources(self, record):
        result = []
        if record.sso_user_id in self.direct:
            result.append(dict(source='USER', group_id=None, **self.direct[record.sso_user_id]))
        for gid in self.list_user_memberships(record.sso_user_id):
            if gid in self.native:
                result.append(dict(source='GROUP', group_id=gid, **self.native[gid]))
        return result

    def cancel_subscription(self, record, mode):
        assert mode == 'IMMEDIATE'
        self.calls.append(('cancel_user', record.sso_user_id))
        if not self.keep_cancel:
            self.direct[record.sso_user_id] = dict(self.direct[record.sso_user_id], status='cancelled', expires_at=None)
        if self.on_cancel:
            self.on_cancel()
        return 'cancel-request'

    def cancel_group_subscription(self, group, mode):
        assert mode == 'IMMEDIATE'
        self.calls.append(('cancel_group', group.remote_id))
        self.native[group.remote_id] = dict(self.native[group.remote_id], status='cancelled', expires_at=None)
        return 'group-cancel-request'

    def delete_group_membership(self, mid):
        self.calls.append(('detach', mid))
        self.members = {key: value for key, value in self.members.items() if value != mid}

    def delete_user(self, record):
        self.calls.append(('delete_sso', record.sso_user_id))
        if not self.keep_user:
            self.users.pop(record.sso_user_id, None)
            self.members = {key: mid for key, mid in self.members.items() if key[1] != record.sso_user_id}
        return 'delete-request'

    def delete_group(self, gid):
        self.calls.append(('delete_group', gid))
        if not self.keep_group:
            self.groups.pop(gid, None)


def seed(directory, *, grouped=False, paid=True, user_id='r-one'):
    with SessionLocal() as db:
        if grouped and not db.get(ManagedGroup, 'g-one'):
            db.add(ManagedGroup(id='g-one', owner_id=2, aws_account_id=1,
                aws_scope='123456789012:d-1234567890', name='delete-test', marker='managed-test',
                remote_id='remote-group', request_key='group-request-key', payload_hash='hash', state='ready'))
            db.flush()
        row = Subscription(id=user_id, owner_id=2, aws_account_id=1, plan_id=1 if paid else None,
            counter_id=1 if paid else None, cycle_number=1 if paid else None,
            request_key='request-' + user_id, username=user_id, email=user_id + '@example.com',
            state='completed', step='done', sso_user_id='sso-' + user_id, reserved=False,
            counted=paid, subscribed_at=now() if paid else None,
            subscription_type='Q_DEVELOPER_STANDALONE_PRO' if paid else None,
            subscription_status='active' if paid else 'not_subscribed',
            plan_name_snapshot='Kiro Pro' if paid else None, provision_only=not paid,
            portal_url='https://example.com', password_encrypted=encrypt('one-time-password'),
            group_id='g-one' if grouped else None,
            group_membership_id='m-' + user_id if grouped else None)
        db.add(row)
        if paid:
            counter = db.get(PlanCounter, 1)
            counter.used_count += 1
            counter.lifetime_count += 1
        db.commit()
        directory.users[row.sso_user_id] = dict(UserId=row.sso_user_id, UserName=row.username)
        if paid:
            directory.direct[row.sso_user_id] = dict(status='active', subscription_type=row.subscription_type, expires_at=None, pending_type=None)
        if grouped:
            directory.groups['remote-group'] = dict(id='remote-group', name='delete-test', description='managed-test')
            directory.members[('remote-group', row.sso_user_id)] = row.group_membership_id
        return row.id


def preview(client, *, records=None, groups=None):
    return client.post('/api/cascade-deletions/preview', json={
        'kind': 'group' if groups else 'sso',
        **({'group_ids': groups} if groups else {'record_ids': records}),
    })


def admit(client, value, *, key=None):
    return client.post('/api/cascade-deletions', json={
        'preview_id': value['id'], 'fingerprint': value['fingerprint'],
        'confirm_text': value['confirm_text'], 'acknowledge_fees': True,
        'request_key': key or str(uuid.uuid4()),
    })


def drain(directory, limit=40):
    from app.lifecycle import run_operation
    for _ in range(limit):
        if not run_operation(directory):
            return
    raise AssertionError('cascade did not settle in bounded steps')


def test_preview_names_exact_targets_and_bulk_cancels_before_deleting(alice, bob, monkeypatch):
    directory = Directory()
    one, two = seed(directory), seed(directory, paid=False, user_id='r-two')
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    result = preview(alice, records=[one, two])
    assert result.status_code == 200, result.text
    value = result.json()
    assert value['counts']['sso_users'] == 2
    assert {r['username'] for item in value['items'] for r in item['members']} == {'r-one', 'r-two'}
    assert not directory.calls
    key = str(uuid.uuid4())
    response = admit(alice, value, key=key)
    assert response.status_code == 202, response.text
    batch = response.json()
    assert admit(alice, value, key=key).json()['id'] == batch['id']
    assert bob.get('/api/cascade-deletions/' + batch['id']).status_code == 404
    drain(directory)
    result = alice.get('/api/cascade-deletions/' + batch['id']).json()
    assert result['state'] == 'completed', result
    assert directory.calls.index(('cancel_user', 'sso-r-one')) < directory.calls.index(('delete_sso', 'sso-r-one'))
    assert ('cancel_user', 'sso-r-two') not in directory.calls
    with SessionLocal() as db:
        one = db.get(Subscription, one)
        assert one.sso_deleted_at and one.cancelled_at and one.counted and one.subscribed_at
        assert one.password_encrypted is None
        counter = db.get(PlanCounter, 1)
        assert (counter.used_count, counter.lifetime_count, counter.pending_count) == (1, 1, 0)


def test_individual_group_member_detaches_without_cancelling_group(alice, monkeypatch):
    directory = Directory()
    record = seed(directory, grouped=True)
    directory.native['remote-group'] = dict(status='active', subscription_type='Q_DEVELOPER_STANDALONE_PRO', expires_at=None, pending_type=None)
    with SessionLocal() as db:
        grant = NativeGroupGrant(id='grant', group_id='g-one', owner_id=2, aws_account_id=1,
            plan_id=1, plan_name='Kiro Pro', subscription_type='Q_DEVELOPER_STANDALONE_PRO', state='active')
        db.add(grant)
        db.flush()
        db.add(GroupMemberActivation(id='activation', grant_id='grant', record_id=record, owner_id=2, actor_id=2,
            plan_id=1, plan_name='Kiro Pro', subscription_type=grant.subscription_type,
            request_key='activation-key', operation_id='original', state='active', counted=True, config_hash='old'))
        db.commit()
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    value = preview(alice, records=[record])
    assert value.status_code == 200, value.text
    assert admit(alice, value.json()).status_code == 202
    drain(directory)
    assert ('cancel_group', 'remote-group') not in directory.calls
    assert directory.calls[0] == ('detach', 'm-r-one')
    assert directory.calls[-1] == ('delete_sso', 'sso-r-one')
    with SessionLocal() as db:
        assert db.get(NativeGroupGrant, 'grant').state == 'active'
        assert db.get(GroupMemberActivation, 'activation').state == 'cancelled'


def test_group_cascade_cancels_native_and_user_sources_then_members_then_group(alice, monkeypatch):
    directory = Directory()
    seed(directory, grouped=True)
    seed(directory, grouped=True, paid=False, user_id='r-two')
    directory.native['remote-group'] = dict(status='active', subscription_type='Q_DEVELOPER_STANDALONE_PRO', expires_at=None, pending_type=None)
    with SessionLocal() as db:
        db.add(NativeGroupGrant(id='grant', group_id='g-one', owner_id=2, aws_account_id=1,
            plan_id=1, plan_name='Kiro Pro', subscription_type='Q_DEVELOPER_STANDALONE_PRO', state='active'))
        db.commit()
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    value = preview(alice, groups=['g-one'])
    assert value.status_code == 200, value.text
    assert value.json()['counts']['groups'] == 1
    response = admit(alice, value.json())
    assert response.status_code == 202, response.text
    drain(directory)
    assert directory.calls[0] == ('cancel_group', 'remote-group')
    assert directory.calls[-1] == ('delete_group', 'remote-group')
    assert sum(kind == 'delete_sso' for kind, _ in directory.calls) == 2
    with SessionLocal() as db:
        assert db.get(ManagedGroup, 'g-one').deleted_at
        assert db.get(NativeGroupGrant, 'grant').state == 'cancelled'
        assert db.get(Subscription, 'r-one').counted


def test_unknown_delete_result_is_read_only_until_aws_confirms_absence(alice, monkeypatch):
    directory = Directory()
    record = seed(directory, paid=False)
    directory.keep_user = True
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    response = admit(alice, preview(alice, records=[record]).json())
    assert response.status_code == 202, response.text
    batch = response.json()
    drain(directory)
    assert alice.get('/api/cascade-deletions/' + batch['id']).json()['state'] == 'needs_review'
    with SessionLocal() as db:
        assert db.get(Subscription, record).sso_deleted_at is None
    for _ in range(2):
        assert alice.post('/api/cascade-deletions/' + batch['id'] + '/recheck', json={
            'request_key': str(uuid.uuid4()), 'confirm_text': batch['confirm_text']}).status_code == 202
        drain(directory)
    assert directory.calls == [('delete_sso', 'sso-r-one')]
    directory.users.clear()
    alice.post('/api/cascade-deletions/' + batch['id'] + '/recheck', json={
        'request_key': str(uuid.uuid4()), 'confirm_text': batch['confirm_text']})
    drain(directory)
    assert alice.get('/api/cascade-deletions/' + batch['id']).json()['state'] == 'completed'


def test_group_delete_requires_actual_aws_absence(alice, monkeypatch):
    directory = Directory()
    seed(directory, grouped=True, paid=False)
    directory.keep_group = True
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    result = admit(alice, preview(alice, groups=['g-one']).json())
    assert result.status_code == 202, result.text
    drain(directory)
    assert alice.get('/api/cascade-deletions/' + result.json()['id']).json()['state'] == 'needs_review'
    with SessionLocal() as db:
        assert db.get(ManagedGroup, 'g-one').deleted_at is None


def test_preview_rejects_unmanaged_or_foreign_members_and_extra_groups(alice, bob, monkeypatch):
    directory = Directory()
    record = seed(directory, grouped=True)
    directory.members[('remote-group', 'foreign-user')] = 'foreign-membership'
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    assert preview(alice, groups=['g-one']).status_code == 409
    assert preview(bob, records=[record]).status_code == 404
    directory.members.pop(('remote-group', 'foreign-user'))
    directory.members[('unmanaged-group', 'sso-r-one')] = 'unmanaged-membership'
    assert preview(alice, records=[record]).status_code == 409
    assert not directory.calls


def test_preview_and_worker_refuse_permission_configuration_and_identity_drift(alice, monkeypatch):
    directory = Directory()
    record = seed(directory)
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    value = preview(alice, records=[record]).json()
    with SessionLocal() as db:
        db.get(Subscription, record).email = 'changed@example.com'
        db.commit()
    assert admit(alice, value).status_code == 409
    fresh = preview(alice, records=[record]).json()
    response = admit(alice, fresh)
    assert response.status_code == 202
    with SessionLocal() as db:
        db.get(User, 2).session_version += 1
        db.commit()
    drain(directory)
    assert not directory.calls
    with SessionLocal() as db:
        assert db.get(Subscription, record).sso_deleted_at is None


def test_unknown_provisioning_intents_block_even_empty_group(alice, monkeypatch):
    directory = Directory()
    with SessionLocal() as db:
        db.add(ManagedGroup(id='empty', owner_id=2, aws_account_id=1, aws_scope='123456789012:d-1234567890',
            name='empty', marker='empty-marker', request_key='empty-request-key', payload_hash='hash',
            state='failed', remote_id=None))
        db.add(ProvisioningBatch(id='p', actor_id=2, actor_role='member', session_version=1,
            request_key='provision-request-key', payload_hash='hash', intent='{}', preview_fingerprint='hash', totals='{}'))
        db.flush()
        db.add(ProvisioningAccountBatch(id='pa', batch_id='p', position=1, aws_account_id=1, account_number='1',
            sequence=1, batch_number='1', config_hash='hash', quantity=1, plan_id=1, plan_name='Kiro Pro',
            subscription_type='Q_DEVELOPER_STANDALONE_PRO', group_mode='new', group_id='empty', group_name='empty',
            stop_policy='{}', exports='{}', snapshot='{}', needed_count=0, state='paused'))
        db.commit()
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    assert preview(alice, groups=['empty']).status_code == 409
    with SessionLocal() as db:
        row = db.get(ProvisioningAccountBatch, 'pa')
        assert row.stop_requested_at is None and row.state == 'paused'
        row.state, row.stop_requested_at = 'stopped', now()
        db.get(ProvisioningBatch, 'p').state = 'stopped'
        db.commit()
    result = preview(alice, groups=['empty'])
    assert result.status_code == 200, result.text
    response = admit(alice, result.json())
    assert response.status_code == 202, response.text
    drain(directory)
    with SessionLocal() as db:
        assert db.get(ManagedGroup, 'empty').deleted_at
        assert db.get(ProvisioningAccountBatch, 'pa').stop_requested_at
    assert not directory.calls


def test_new_raw_sso_deletion_cannot_bypass_cancel_first_preview(alice):
    directory = Directory()
    record = seed(directory)
    result = alice.post('/api/subscriptions/' + record + '/operations', json={
        'kind': 'delete_sso', 'request_key': str(uuid.uuid4()), 'confirm_username': record,
        'acknowledge_subscription': True,
    })
    assert result.status_code == 409
    assert '预览' in result.json()['detail']


def test_unknown_cancel_cannot_delete_or_resend_and_recovery_keeps_original_target(alice, monkeypatch):
    directory = Directory()
    record = seed(directory)
    directory.keep_cancel = True
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    response = admit(alice, preview(alice, records=[record]).json())
    assert response.status_code == 202, response.text
    batch = response.json()
    drain(directory)
    assert directory.calls == [('cancel_user', 'sso-r-one')]
    current = alice.get('/api/cascade-deletions/' + batch['id']).json()
    assert current['state'] == 'needs_review' and current['actions']['recheck']
    assert alice.post('/api/cascade-deletions/' + batch['id'] + '/recheck', json={
        'request_key': str(uuid.uuid4()), 'confirm_text': batch['confirm_text']}).status_code == 202
    drain(directory)
    assert directory.calls == [('cancel_user', 'sso-r-one')]
    with SessionLocal() as db:
        assert db.get(Subscription, record).sso_deleted_at is None
        assert db.get(Subscription, record).active_operation_id


def test_unknown_user_cancellation_does_not_gain_false_proof_from_an_old_eop_claim(alice, monkeypatch):
    class UncertainCancel(Directory):
        def cancel_subscription(self, record, mode):
            self.calls.append(('cancel_user', record.sso_user_id))
            raise aws.AwsFailure('timeout after send', uncertain=True)
    directory = UncertainCancel()
    record = seed(directory)
    directory.direct['sso-r-one'].update(status='cancelled', expires_at=now() + timedelta(days=20))
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    batch = admit(alice, preview(alice, records=[record]).json()).json()
    drain(directory)
    assert directory.calls == [('cancel_user', 'sso-r-one')]
    alice.post('/api/cascade-deletions/' + batch['id'] + '/recheck', json={
        'request_key': str(uuid.uuid4()), 'confirm_text': batch['confirm_text']})
    drain(directory)
    assert alice.get('/api/cascade-deletions/' + batch['id']).json()['state'] == 'needs_review'
    assert directory.calls == [('cancel_user', 'sso-r-one')]


def test_members_added_after_admission_block_every_group_write(alice, monkeypatch):
    directory = Directory()
    seed(directory, grouped=True)
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    batch = admit(alice, preview(alice, groups=['g-one']).json()).json()
    directory.members[('remote-group', 'foreign-after-preview')] = 'foreign-membership'
    drain(directory)
    assert not directory.calls
    current = alice.get('/api/cascade-deletions/' + batch['id']).json()
    assert current['state'] == 'failed'
    with SessionLocal() as db:
        assert db.get(ManagedGroup, 'g-one').deleted_at is None


def test_configuration_drift_after_cancellation_prevents_sso_delete(alice, monkeypatch):
    directory = Directory()
    record = seed(directory)
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    batch = admit(alice, preview(alice, records=[record]).json()).json()
    def drift():
        with SessionLocal() as db:
            db.get(AwsAccount, 1).application_arn += '-changed'
            db.commit()
    directory.on_cancel = drift
    drain(directory)
    assert directory.calls == [('cancel_user', 'sso-r-one')]
    with SessionLocal() as db:
        assert db.get(Subscription, record).sso_deleted_at is None
    # The cancellation was sent; configuration drift prevents its readback.
    assert alice.get('/api/cascade-deletions/' + batch['id']).json()['state'] == 'needs_review'


def test_empty_failed_create_history_is_retained_and_same_name_foreign_group_is_not_deleted(alice, monkeypatch):
    directory = Directory()
    with SessionLocal() as db:
        db.add(ManagedGroup(id='empty', owner_id=2, aws_account_id=1, aws_scope='123456789012:d-1234567890',
            name='empty', marker='empty-marker', request_key='empty-request-key', payload_hash='hash',
            state='failed', remote_id=None, active_job_id='failed-create'))
        db.flush()
        db.add(GroupJob(id='failed-create', group_id='empty', actor_id=2, kind='create',
            request_key='failed-create-key', payload='{}', state='failed', phase='ready', error='rejected'))
        db.commit()
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    directory.groups['foreign'] = dict(id='foreign', name='empty', description='not-our-marker')
    assert preview(alice, groups=['empty']).status_code == 409
    directory.groups.clear()
    response = admit(alice, preview(alice, groups=['empty']).json())
    assert response.status_code == 202, response.text
    drain(directory)
    with SessionLocal() as db:
        assert db.get(ManagedGroup, 'empty').deleted_at
        assert db.get(GroupJob, 'failed-create').state == 'failed'
        assert db.get(GroupJob, 'failed-create').error == 'rejected'
    assert not directory.calls


def test_legacy_pending_delete_only_reconciles_absence_without_writing(alice):
    from app.lifecycle import run_operation
    directory = Directory()
    record_id = seed(directory)
    with SessionLocal() as db:
        record = db.get(Subscription, record_id)
        record.active_operation_id = 'old-delete'
        db.add(RecordOperation(id='old-delete', record_id=record.id, actor_id=2, kind='delete_sso',
            request_key='old-delete-request', payload='{}', phase='pending'))
        db.commit()
    assert run_operation(directory)
    assert not directory.calls
    with SessionLocal() as db:
        assert db.get(RecordOperation, 'old-delete').state == 'needs_review'
        assert db.get(RecordOperation, 'old-delete').phase == 'pending'
        assert db.get(Subscription, record_id).sso_deleted_at is None


def test_missing_user_claim_does_not_skip_cancelling_a_managed_user_assignment(alice, monkeypatch):
    class MissingClaim(Directory):
        def cancel_subscription(self, record, mode):
            self.calls.append(('cancel_user', record.sso_user_id))
            return 'definite-cancellation'
    directory = MissingClaim()
    record = seed(directory)
    directory.direct.clear()
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    result = admit(alice, preview(alice, records=[record]).json())
    assert result.status_code == 202, result.text
    drain(directory)
    assert directory.calls == [('cancel_user', 'sso-r-one'), ('delete_sso', 'sso-r-one')]


def test_changed_billing_boundary_invalidates_user_stop_receipt_before_deletion(alice, monkeypatch):
    class BillingTail(Directory):
        def cancel_subscription(self, record, mode):
            self.calls.append(('cancel_user', record.sso_user_id))
            self.direct[record.sso_user_id].update(status='cancelled', expires_at=now() + timedelta(days=5))
            return 'confirmed-immediate-cancel'
    from app.lifecycle import run_operation
    directory = BillingTail()
    record = seed(directory)
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    result = admit(alice, preview(alice, records=[record]).json())
    assert result.status_code == 202, result.text
    assert run_operation(directory)  # cancellation is confirmed and receipt saved
    directory.direct['sso-r-one']['expires_at'] += timedelta(days=10)
    drain(directory)
    assert directory.calls == [('cancel_user', 'sso-r-one')]
    with SessionLocal() as db:
        assert db.get(Subscription, record).sso_deleted_at is None


def add_native(directory):
    directory.native['remote-group'] = dict(status='active', subscription_type='Q_DEVELOPER_STANDALONE_PRO', expires_at=None, pending_type=None)
    with SessionLocal() as db:
        db.add(NativeGroupGrant(id='grant', group_id='g-one', owner_id=2, aws_account_id=1,
            plan_id=1, plan_name='Kiro Pro', subscription_type='Q_DEVELOPER_STANDALONE_PRO', state='active'))
        db.commit()


def test_unknown_group_readback_cannot_authorize_member_or_group_deletion(alice, monkeypatch):
    class UnknownReadback(Directory):
        def cancel_group_subscription(self, group, mode):
            result = super().cancel_group_subscription(group, mode)
            self.native[group.remote_id]['status'] = 'unknown'
            return result
    directory = UnknownReadback()
    seed(directory, grouped=True, paid=False)
    add_native(directory)
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    response = admit(alice, preview(alice, groups=['g-one']).json())
    assert response.status_code == 202, response.text
    drain(directory)
    assert directory.calls == [('cancel_group', 'remote-group')]
    assert alice.get('/api/cascade-deletions/' + response.json()['id']).json()['state'] == 'needs_review'


@pytest.mark.parametrize('drift', ['changed_grant_state', 'new_grant'])
def test_native_grant_drift_stops_all_further_writes(alice, monkeypatch, drift):
    from app.lifecycle import run_operation
    directory = Directory()
    seed(directory, grouped=True, paid=False)
    add_native(directory)
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    response = admit(alice, preview(alice, groups=['g-one']).json())
    assert response.status_code == 202, response.text
    assert run_operation(directory)
    with SessionLocal() as db:
        if drift == 'changed_grant_state':
            db.get(NativeGroupGrant, 'grant').state = 'needs_review'
        else:
            db.add(NativeGroupGrant(id='new-grant', group_id='g-one', owner_id=2, aws_account_id=1,
                plan_id=1, plan_name='Kiro Pro', subscription_type='Q_DEVELOPER_STANDALONE_PRO', state='active'))
        db.commit()
    drain(directory)
    assert directory.calls == [('cancel_group', 'remote-group')]
    with SessionLocal() as db:
        assert db.get(Subscription, 'r-one').sso_deleted_at is None


def test_foreign_native_activation_blocks_group_preview_without_touching_outside_records(alice, monkeypatch):
    directory = Directory()
    seed(directory, grouped=True, paid=False)
    outside = seed(directory, paid=False, user_id='outside')
    add_native(directory)
    with SessionLocal() as db:
        db.add(GroupMemberActivation(id='foreign-activation', grant_id='grant', record_id=outside, owner_id=2, actor_id=2,
            plan_id=1, plan_name='Kiro Pro', subscription_type='Q_DEVELOPER_STANDALONE_PRO',
            request_key='foreign-activation-key', operation_id='original', state='active', counted=True, config_hash='old'))
        db.commit()
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    assert preview(alice, groups=['g-one']).status_code == 409
    assert not directory.calls
    with SessionLocal() as db:
        assert db.get(GroupMemberActivation, 'foreign-activation').state == 'active'
        assert db.get(Subscription, outside).sso_deleted_at is None


def test_missing_group_claim_does_not_skip_initial_managed_group_cancellation(alice, monkeypatch):
    class MissingNative(Directory):
        def cancel_group_subscription(self, group, mode):
            self.calls.append(('cancel_group', group.remote_id))
            assert mode == 'IMMEDIATE'
            return 'definite-native-cancellation'
    directory = MissingNative()
    seed(directory, grouped=True, paid=False)
    add_native(directory)
    directory.native.clear()
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    result = admit(alice, preview(alice, groups=['g-one']).json())
    assert result.status_code == 202, result.text
    drain(directory)
    assert directory.calls[0] == ('cancel_group', 'remote-group')
    assert directory.calls[-1] == ('delete_group', 'remote-group')


@pytest.mark.parametrize('drift', ['record_identity', 'group_owner', 'proxy_revision', 'role', 'binding'])
def test_guard_runs_again_after_remote_reads_before_any_write(alice, monkeypatch, drift):
    from app.models import Proxy
    class ChangesDuringRead(Directory):
        enabled = False

        def verify(self):
            if not self.enabled:
                return
            self.enabled = False
            with SessionLocal() as db:
                if drift == 'record_identity':
                    db.get(Subscription, 'r-one').username = 'foreign-username'
                elif drift == 'group_owner':
                    db.get(ManagedGroup, 'g-one').owner_id = 3
                elif drift == 'proxy_revision':
                    db.get(Proxy, 1).revision += 1
                elif drift == 'role':
                    db.get(User, 2).role = 'admin'
                else:
                    db.delete(db.get(Binding, (2, 1)))
                db.commit()
    directory = ChangesDuringRead()
    record = seed(directory, grouped=True)
    if drift == 'proxy_revision':
        with SessionLocal() as db:
            db.add(Proxy(id=1, name='fake-proxy', host='127.0.0.1', port=1080,
                auth_encrypted=encrypt({'username': 'fake', 'password': 'fake-password'})))
            db.get(AwsAccount, 1).proxy_id = 1
            db.commit()
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    response = admit(alice, preview(alice, records=[record]).json())
    assert response.status_code == 202, response.text
    directory.enabled = True
    drain(directory)
    assert not directory.calls
    with SessionLocal() as db:
        saved = db.get(Subscription, record)
        assert saved.sso_deleted_at is None and saved.active_operation_id


def test_completed_group_cascade_remains_visible_in_member_history(alice, monkeypatch):
    directory = Directory()
    record = seed(directory, grouped=True, paid=False)
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    result = admit(alice, preview(alice, groups=['g-one']).json())
    assert result.status_code == 202, result.text
    drain(directory)
    history = alice.get('/api/cascade-deletions', params={'record_id': record}).json()
    assert [batch['id'] for batch in history] == [result.json()['id']]


@pytest.mark.parametrize('sdk_retries,expected_state', [(0, 'failed'), (1, 'needs_review')])
def test_sdk_retried_rejection_retains_pending_write_and_never_resends(alice, monkeypatch, sdk_retries, expected_state):
    class Denied(Directory):
        def delete_user(self, record):
            self.calls.append(('delete_sso', record.sso_user_id))
            raise ClientError({'Error': {'Code': 'AccessDeniedException'},
                'ResponseMetadata': {'HTTPStatusCode': 403, 'RetryAttempts': sdk_retries}}, 'DeleteUser')
    directory = Denied()
    record = seed(directory, paid=False)
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    batch = admit(alice, preview(alice, records=[record]).json()).json()
    drain(directory)
    saved = alice.get('/api/cascade-deletions/' + batch['id']).json()
    assert saved['state'] == expected_state
    if sdk_retries:
        assert saved['items'][0]['phase'] == 'pending'
        assert alice.post('/api/cascade-deletions/' + batch['id'] + '/recheck', json={
            'request_key': str(uuid.uuid4()), 'confirm_text': batch['confirm_text']}).status_code == 202
        drain(directory)
        assert directory.calls == [('delete_sso', 'sso-r-one')]


def test_revocation_after_pending_commit_stops_write_before_gateway_dispatch(alice, monkeypatch):
    from app import cascade_deletions
    directory = Directory()
    record = seed(directory, paid=False)
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    batch = admit(alice, preview(alice, records=[record]).json()).json()
    original = cascade_deletions.mark_pending
    def revoke_after_checkpoint(*args):
        original(*args)
        with SessionLocal() as db:
            db.delete(db.get(Binding, (2, 1)))
            db.commit()
    monkeypatch.setattr(cascade_deletions, 'mark_pending', revoke_after_checkpoint)
    drain(directory)
    assert not directory.calls
    with SessionLocal() as db:
        assert db.get(Subscription, record).sso_deleted_at is None


def test_inner_gateway_guard_stops_role_drift_immediately_before_wire(alice, monkeypatch):
    class ChangesAtWire(Directory):
        def delete_user(self, record):
            with SessionLocal() as db:
                db.get(User, 2).role = 'admin'
                db.commit()
            self._check_proxy()
            return super().delete_user(record)
    directory = ChangesAtWire()
    record = seed(directory, paid=False)
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    assert admit(alice, preview(alice, records=[record]).json()).status_code == 202
    drain(directory)
    assert not directory.calls


@pytest.mark.parametrize('kind,state', [('sso', 'queued'), ('group', 'challenge')])
def test_existing_pasted_login_blocks_cascade_preview_and_admission(alice, monkeypatch, kind, state):
    from datetime import timedelta
    from app.auth_principals import login_key
    from app.external_auth_models import ExternalExportBatch, ExternalExportItem
    directory = Directory()
    record_id = seed(directory, grouped=True, paid=False)
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    selection = {'records': [record_id]} if kind == 'sso' else {'groups': ['g-one']}
    # Freeze a valid preview first so admission must also recheck the blocker.
    value = preview(alice, **selection).json()
    with SessionLocal() as db:
        db.add(ExternalExportBatch(id='external-batch', actor_id=2, actor_role='member', session_version=1,
            request_key='external-request-key', payload_hash='hash', expires_at=now() + timedelta(hours=1)))
        db.flush()
        db.add(ExternalExportItem(id='external-item', batch_id='external-batch', position=0,
            principal_key=login_key('d-1234567890', 'r-one'), lane_id=-1, username='r-one',
            portal_url='https://d-1234567890.awsapps.com/start', configuration='{}', state=state))
        db.commit()
    assert preview(alice, **selection).status_code == 409
    assert admit(alice, value).status_code == 409
    assert not directory.calls


def test_real_sdk_delete_rechecks_after_transport_guard_before_adapter_send(alice, monkeypatch):
    from app import cascade_deletions
    from app.cascade_models import CascadeTask
    from requests.adapters import HTTPAdapter
    directory = Directory()
    record_id = seed(directory, paid=False)
    class WireGateway(aws.AwsGateway):
        def __init__(self, account):
            super().__init__(account)
            def revoke():
                with SessionLocal() as db:
                    db.delete(db.get(Binding, (2, 1)))
                    db.commit()
            self.identity._endpoint.http_session.guard = revoke
        def verify(self):
            pass
        def user_info(self, record):
            return directory.user_info(record)
        def list_user_memberships(self, uid):
            return {}
        def user_subscription_sources(self, record):
            return []
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    batch = admit(alice, preview(alice, records=[record_id]).json()).json()
    sends = []
    def forbidden_send(*args, **kwargs):
        sends.append('sdk-delete')
        raise aws.AwsFailure('test must stop before SDK send')
    monkeypatch.setattr(HTTPAdapter, 'send', forbidden_send)
    assert cascade_deletions.run_one(WireGateway, account_id=1)
    assert cascade_deletions.run_one(WireGateway, account_id=1)
    with SessionLocal() as db:
        task = db.get(CascadeTask, batch['items'][0]['id'])
        assert task.phase == 'pending', task.error
        assert not sends, task.error
        assert db.get(Subscription, record_id).sso_deleted_at is None


def test_real_sigv4_cancel_rechecks_after_proxy_guard_before_http_send(alice, monkeypatch):
    from app import cascade_deletions
    from app.cascade_models import CascadeTask
    from requests.adapters import HTTPAdapter
    directory = Directory()
    record_id = seed(directory)
    class WireGateway(aws.AwsGateway):
        armed = False
        def _check_proxy(self):
            super()._check_proxy()
            if self.armed:
                self.armed = False
                with SessionLocal() as db:
                    db.delete(db.get(Binding, (2, 1)))
                    db.commit()
        def verify(self):
            pass
        def user_info(self, record):
            return directory.user_info(record)
        def list_user_memberships(self, uid):
            return {}
        def user_subscription_sources(self, record):
            return directory.user_subscription_sources(record)
        def cancel_subscription(self, record, mode):
            self.armed = True
            return super().cancel_subscription(record, mode)
    monkeypatch.setattr(aws, 'AwsGateway', directory)
    batch = admit(alice, preview(alice, records=[record_id]).json()).json()
    sends = []
    def forbidden_send(*args, **kwargs):
        sends.append('sigv4-cancel')
        raise aws.AwsFailure('test must stop before SigV4 send')
    monkeypatch.setattr(HTTPAdapter, 'send', forbidden_send)
    assert cascade_deletions.run_one(WireGateway, account_id=1)
    with SessionLocal() as db:
        task = db.get(CascadeTask, batch['items'][0]['id'])
        assert not sends, task.error
        assert task.phase == 'pending' and task.state == 'needs_review'
        assert not db.get(Subscription, record_id).cancelled_at
