"""Durable coordinator exercises the real dispatcher and child workers, without wire IO."""
import json
import time
from datetime import timedelta

import pytest
from sqlalchemy import func, select

from app import aws, models, worker
from app.database import SessionLocal
from app.security import encrypt
from test_native_groups import NativeGateway
from test_provisioning_admission import admit, intent, ready, remote


class Gateway(NativeGateway):
    groups = {}
    users = {}
    events = []
    hook = None

    def verify_identity(self):
        return self.account.aws_account_id

    def get_group_id(self, name):
        return next((gid for gid, g in self.groups.items() if g['name'] == name), None)

    def get_group(self, gid):
        return self.groups.get(gid)

    def create_group(self, name, marker):
        if type(self).hook:
            type(self).hook('group', self.account.id)
        gid = 'remote-' + name
        self.events.append(('group', self.account.id, name))
        self.groups[gid] = {'id': gid, 'name': name, 'description': marker}
        return gid

    def subscribe_group(self, group, plan):
        self.events.append(('GROUP', self.account.id, group.name))
        return super().subscribe_group(group, plan)

    def report_claims(self):
        return [{'principal': {'group': gid}, 'type': {'amazonQ': info['subscription_type']},
                 'applicationArn': self.account.application_arn, 'createdBy': self.account.aws_account_id}
                for gid, info in self.assignments.items() if info['status'] == 'active']

    def create_user(self, record):
        self.events.append(('sso', self.account.id, record.username))
        self.users[record.id] = 'sso-' + record.id
        return self.users[record.id]

    def find_created_user(self, record):
        return self.users.get(record.id)

    def password(self, record):
        self.events.append(('otp', self.account.id, record.username))
        return 'SyntheticPassword123!'

    def create_group_membership(self, gid, uid):
        self.events.append(('join', self.account.id, uid))
        return super().create_group_membership(gid, uid)

    def subscribe(self, record):
        pytest.fail('Numbered provisioning must not create a USER assignment')


@pytest.fixture
def gateway(ready, monkeypatch):
    for name, value in [('groups', {}), ('users', {}), ('events', []), ('hook', None),
                        ('assignments', {}), ('members', {}), ('user_claims', {}),
                        ('writes', []), ('uncertain', False), ('effective_rows', None)]:
        monkeypatch.setattr(Gateway, name, value)
    monkeypatch.setattr(NativeGateway, "members", {})
    with SessionLocal() as db:
        db.get(models.PlanCounter, 1).limit_count = 20
        db.commit()
    monkeypatch.setattr(aws, "AwsGateway", Gateway)
    return Gateway


def body(quantity=1, **kwargs):
    return intent(quantity=quantity, exports={'csv': True, 'txt': True, 'json': False}, **kwargs)


def fetch(client, parent):
    response = client.get('/api/provisioning-batches/' + parent['id'])
    assert response.status_code == 200, response.text
    return response.json()


def drive(parent, client, factory=Gateway, predicate=None, timeout=10):
    # This bounds a test's asynchronous polling; it is not a provisioning SLA.
    # Shared CI hosts may need several seconds to schedule the durable child work.
    dispatcher = worker.make_dispatcher(gateway_factory=factory, max_workers=2)
    try:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            dispatcher.tick()
            current = fetch(client, parent)
            if (predicate(current) if predicate else current['state'] in ('completed', 'paused', 'needs_review', 'stopped')):
                return current
            time.sleep(.01)
        assert False, current
    finally:
        dispatcher.close(wait=True)


def test_numbered_new_group_exact_identities_order_and_quota(alice, gateway):
    parent = admit(alice, body(quantity=2, stop_policy={'mode': 'days', 'days': 3})).json()
    with SessionLocal() as db:
        frozen = db.get(models.ProvisioningAccountBatch, parent['accounts'][0]['id']).snapshot
    final = drive(parent, alice)
    assert final['state'] == 'completed', final
    assert [x[0] for x in gateway.events[:2]] == ['group', 'GROUP']
    assert len(gateway.events) == 8
    for item in parent['accounts'][0]['items']:
        sso = gateway.events.index(('sso', 1, item['username']))
        otp = gateway.events.index(('otp', 1, item['username']))
        join = gateway.events.index(('join', 1, 'sso-' + item['record_id']))
        assert 1 < sso < otp < join
    row = final['accounts'][0]
    assert row['group']['id'] and row['native_operation_id'] and row['native_grant_id']
    assert row['allowed_actions'] == []
    with SessionLocal() as db:
        assert db.get(models.ProvisioningAccountBatch, row['id']).snapshot == frozen
        for old, item in zip(parent['accounts'][0]['items'], row['items']):
            record = db.get(models.Subscription, old['record_id'])
            assert (record.id, record.username, record.email) == (old['record_id'], old['username'], old['email'])
            assert record.provision_only and record.counted and item['state'] == 'completed'
            assert item['export_state'] == 'not_requested' and item['auth_batch_id'] is None
            schedule = db.get(models.StopSchedule, record.id)
            grant = db.get(models.NativeGroupGrant, row['native_grant_id'])
            assert schedule.stop_at == grant.activated_at + timedelta(days=3)
        counter = db.get(models.PlanCounter, 1)
        assert (counter.pending_count, counter.used_count) == (0, 2)
        assert db.scalar(select(func.count()).select_from(models.AuthBatch)) == 0
    assert admit(alice, body(quantity=2, stop_policy={'mode': 'days', 'days': 3}), preflight={'preview_fingerprint': parent.get('preview_fingerprint', '0'*64)}).json()['id'] == parent['id']
    assert drive(parent, alice)['state'] == 'completed'
    assert len(gateway.events) == 8


def test_stop_before_coordinator_is_durable_idempotent_and_polling_readonly(alice, gateway):
    parent = admit(alice, body()).json()
    row = parent['accounts'][0]
    before = fetch(alice, parent)
    assert fetch(alice, parent) == before and gateway.events == []
    url = f"/api/provisioning-batches/{parent['id']}/accounts/{row['id']}/stop"
    stopped = alice.post(url, json={'request_key': 'stop-numbered-0001'})
    assert stopped.status_code == 202, stopped.text
    assert alice.post(url, json={'request_key': 'stop-numbered-0001'}).json() == stopped.json()
    final = drive(parent, alice)
    assert final['state'] == 'stopped' and not gateway.events
    assert final['accounts'][0]['items'][0]['state'] == 'stopped'


def test_quota_change_after_group_open_pauses_before_sso(alice, gateway):
    parent = admit(alice, body()).json()
    def spend(stage, aid):
        with SessionLocal() as db:
            db.get(models.PlanCounter, 1).limit_count = 0
            db.commit()
    gateway.hook = spend
    final = drive(parent, alice)
    assert final['state'] == 'paused', final
    row = final['accounts'][0]
    assert row['phase'] == 'sso' and row['native_grant_id']
    assert '次数' in row['error']
    assert [event[0] for event in gateway.events] == ['group', 'GROUP']
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(models.Subscription)) == 0
        assert db.get(models.PlanCounter, 1).pending_count == 0
    with SessionLocal() as db:
        db.get(models.PlanCounter, 1).limit_count = 10
        db.commit()
    url = f"/api/provisioning-batches/{parent['id']}/accounts/{row['id']}/retry"
    assert alice.post(url, json={'request_key': 'retry-numbered-001'}).status_code == 202
    assert drive(parent, alice)['state'] == 'completed'
    assert [x[0] for x in gateway.events].count('GROUP') == 1


def coordinator_to_child(parent, phase):
    from app.provisioning_coordinator import run_one
    from app.group_jobs import run_group_job
    from app.group_subscription_worker import run_one as native_one
    cid = parent['accounts'][0]['id']
    for _ in range(16):
        run_one(account_id=1)
        with SessionLocal() as db:
            row = db.get(models.ProvisioningAccountBatch, cid)
            rid = parent['accounts'][0]['items'][0]['record_id']
            reached = {'group': bool(row.group_job_id), 'native': bool(row.native_operation_id),
                       'sso': db.get(models.Subscription, rid) is not None}[phase]
            if reached:
                return cid
        run_group_job(Gateway, account_id=1)
        native_one(Gateway, account_id=1)
    pytest.fail('child not admitted')


def coordinator_to_legacy_first_sso(parent):
    """Legacy only: retain upgrade coverage for batches partially admitted by v16."""
    from app.batches import admit_frozen_sso
    from app.group_subscription_worker import run_one as native_one
    from app.provisioning_coordinator import active_group, guard, items, run_one

    cid = coordinator_to_child(parent, 'native')
    assert native_one(Gateway, account_id=1)
    assert run_one(account_id=1)
    with SessionLocal() as db:
        row = db.get(models.ProvisioningAccountBatch, cid)
        assert row.phase == 'sso'
        actor, _ = guard(db, row)
        active_group(db, row)
        item = items(db, row)[0]
        record = admit_frozen_sso(db, actor, row, item)
        item.sso_batch_id = record.batch_id
        item.phase, item.updated_at = 'create_user', models.now()
        db.commit()
    return cid


@pytest.mark.parametrize('stage', ['group', 'native', 'sso'])
@pytest.mark.parametrize('change', ['stop', 'session', 'role', 'portal', 'proxy'])
def test_child_prewrite_rechecks_frozen_parent(alice, gateway, stage, change):
    parent = admit(alice, body()).json()
    cid = coordinator_to_child(parent, stage)
    before = list(gateway.events)
    called = []
    def mutate():
        if called:
            return
        called.append(True)
        if change == 'stop':
            reply = alice.post(f"/api/provisioning-batches/{parent['id']}/accounts/{cid}/stop",
                               json={'request_key': 'checkpoint-stop-01'})
            assert reply.status_code == 202, reply.text
        else:
            with SessionLocal() as db:
                if change == 'session':
                    db.get(models.User, 2).session_version += 1
                elif change == 'role':
                    db.get(models.User, 2).role = 'admin'
                elif change == 'portal':
                    db.get(models.AwsAccount, 1).portal_url += '/changed'
                elif change == 'proxy':
                    db.get(models.Proxy, db.get(models.AwsAccount, 1).proxy_id).port += 1
                db.commit()
    class Drift(Gateway):
        def get_group_id(self, name):
            if stage == 'group': mutate()
            return super().get_group_id(name)
        def verify(self):
            if stage == 'native': mutate()
            return super().verify()
        def verify_identity(self):
            if stage == 'sso': mutate()
            return super().verify_identity()
    if stage == 'group':
        from app.group_jobs import run_group_job
        run_group_job(Drift, account_id=1)
    elif stage == 'native':
        from app.group_subscription_worker import run_one
        run_one(Drift, account_id=1)
    else:
        worker.run_one(Drift, account_id=1)
    assert called
    assert gateway.events == before, (stage, change, gateway.events)
    with SessionLocal() as db:
        assert db.get(models.PlanCounter, 1).pending_count == 0


def test_config_drift_before_first_stage_pauses_and_number_only_change_does_not(alice, gateway):
    parent = admit(alice, body()).json()
    with SessionLocal() as db:
        db.get(models.AwsAccount, 1).account_number = 'b'
        db.commit()
    assert drive(parent, alice)['state'] == 'completed'
    second = admit(alice, body(), key='new-parent-fence-01').json()
    with SessionLocal() as db:
        db.get(models.AwsAccount, 1).portal_url += '/changed'
        db.commit()
    before = list(gateway.events)
    final = drive(second, alice)
    assert final['state'] == 'paused' and gateway.events == before


def test_json_optin_uses_private_auth_children_and_failure_is_export_only(alice, admin, gateway):
    from app.auth_jobs import run_one as auth_one
    from test_auth_batches import DoneAuth, Gateway as AuthGateway, drain
    from app.identity_login import AuthError
    request = intent(quantity=2)
    parent = admit(alice, request).json()
    final = drive(parent, alice)
    assert final['state'] == 'completed'
    own = final['accounts'][0]['items']
    assert all(i['auth_batch_id'] and i['auth_job_id'] and i['export_state'] == 'queued' for i in own)
    admin_view = fetch(admin, parent)['accounts'][0]['items']
    assert all(i['auth_batch_id'] is None and i['auth_job_id'] is None for i in admin_view)
    assert admin.get('/api/auth-batches/' + own[0]['auth_batch_id']).status_code == 404
    class FailedAuth(DoneAuth):
        def begin(self, *args, **kwargs):
            raise AuthError('interrupted')
    assert auth_one(gateway_factory=AuthGateway, auth_factory=FailedAuth, identity_factory=FailedAuth, account_id=1)
    drain(DoneAuth, AuthGateway)
    after = fetch(alice, parent)
    assert after['state'] == 'completed'
    assert {i['export_state'] for i in after['accounts'][0]['items']} == {'failed', 'completed'}
    failed = next(i for i in after['accounts'][0]['items'] if i['export_state'] == 'failed')
    response = alice.post(f"/api/auth-batches/{failed['auth_batch_id']}/items/{failed['record_id']}/retry", json={'mode': 'resume'})
    assert response.status_code == 202, response.text
    writes = list(gateway.events)
    drain(DoneAuth, AuthGateway)
    assert fetch(alice, parent)['state'] == 'completed' and gateway.events == writes
    with SessionLocal() as db:
        assert (db.get(models.PlanCounter, 1).pending_count, db.get(models.PlanCounter, 1).used_count) == (0, 2)


def test_json_frozen_proxy_change_never_runs_adapter(alice, gateway):
    from app.auth_jobs import run_one as auth_one
    from test_auth_batches import DoneAuth, Gateway as AuthGateway
    parent = admit(alice, intent()).json()
    final = drive(parent, alice)
    assert final['accounts'][0]['items'][0]['auth_job_id']
    with SessionLocal() as db:
        db.get(models.Proxy, db.get(models.AwsAccount, 1).proxy_id).port += 1
        db.commit()
    class Forbidden(DoneAuth):
        def begin(self, *args, **kwargs):
            pytest.fail('Frozen JSON must not run after bound proxy changes')
    assert auth_one(gateway_factory=AuthGateway, auth_factory=Forbidden, identity_factory=Forbidden, account_id=1)
    final = fetch(alice, parent)
    assert final['state'] == 'completed'
    assert final['accounts'][0]['items'][0]['export_state'] != 'completed'


def existing_body(client, gid, quantity=1, **extra):
    group = client.get('/api/groups/' + gid).json()
    return body(quantity, group={'mode': 'existing', 'group_id': gid,
        'expected_revision': group['revision'], 'expected_policy_revision': group['policy']['revision']}, **extra)


@pytest.mark.parametrize('replacement', [None, {'mode': 'none'}, {'mode': 'days', 'days': 5}])
def test_existing_active_group_inherits_or_explicitly_replaces_policy(alice, gateway, replacement):
    first = admit(alice, body(stop_policy={'mode': 'days', 'days': 3})).json()
    first = drive(first, alice)
    gid = first['accounts'][0]['group']['id']
    extra = {'stop_policy': replacement} if replacement else {}
    second = admit(alice, existing_body(alice, gid, **extra), key='existing-group-00001')
    assert second.status_code == 202, second.text
    result = drive(second.json(), alice)
    assert result['state'] == 'completed', result
    assert [e[0] for e in gateway.events].count('GROUP') == 1
    with SessionLocal() as db:
        group = db.get(models.ManagedGroup, gid)
        grant = db.get(models.NativeGroupGrant, first['accounts'][0]['native_grant_id'])
        expected_days = replacement['days'] if replacement and replacement['mode'] == 'days' else 3
        assert grant.stop_at == (None if replacement and replacement['mode'] == 'none' else grant.activated_at + timedelta(days=expected_days))
        assert db.get(models.PlanCounter, 1).used_count == 2


def test_unopened_existing_group_charges_old_owned_members_once(alice, gateway):
    from test_native_groups import seed_group
    gid = seed_group(2)
    gateway.members.update(NativeGateway.members)
    gateway.groups['remote-' + gid] = {'id': 'remote-' + gid, 'name': gid, 'description': gid}
    parent = admit(alice, existing_body(alice, gid, stop_policy={'mode': 'days', 'days': 4}))
    assert parent.status_code == 202, parent.text
    assert parent.json()['accounts'][0]['needed_count'] == 3
    final = drive(parent.json(), alice)
    assert final['state'] == 'completed', final
    assert [e[0] for e in gateway.events] == ['GROUP', 'sso', 'otp', 'join']
    with SessionLocal() as db:
        assert db.get(models.PlanCounter, 1).used_count == 3
        assert db.scalar(select(func.count()).select_from(models.GroupMemberActivation).where(models.GroupMemberActivation.counted.is_(True))) == 3


@pytest.mark.parametrize('drift', ['local_member', 'remote_member', 'unknown_assignment'])
def test_unopened_group_drift_blocks_native_opening(alice, gateway, drift):
    from test_native_groups import seed_group
    gid = seed_group(1)
    gateway.members.update(NativeGateway.members)
    gateway.groups['remote-' + gid] = {'id': 'remote-' + gid, 'name': gid, 'description': gid}
    parent = admit(alice, existing_body(alice, gid)).json()
    if drift == 'local_member':
        with SessionLocal() as db:
            db.get(models.Subscription, gid + '-record-0').email = 'changed@example.org'
            db.commit()
    elif drift == 'remote_member':
        gateway.members[('remote-' + gid, 'foreign')] = 'foreign-membership'
    else:
        gateway.assignments['remote-' + gid] = {'status': 'unknown', 'subscription_type': None, 'expires_at': None}
    final = drive(parent, alice)
    assert final['state'] in ('paused', 'needs_review'), final
    assert not gateway.events


def test_later_group_policy_edit_governs_remaining_members(alice, gateway):
    parent = admit(alice, body(quantity=2, stop_policy={'mode': 'days', 'days': 3})).json()
    coordinator_to_legacy_first_sso(parent)
    worker.run_one(Gateway, account_id=1)
    with SessionLocal() as db:
        group = db.get(models.ManagedGroup, db.get(models.ProvisioningAccountBatch, parent['accounts'][0]['id']).group_id)
        gid, revision = group.id, group.policy_revision
    changed = alice.put('/api/groups/' + gid + '/policy', json={
        'policy': {'mode': 'days', 'days': 7}, 'expected_revision': revision})
    assert changed.status_code == 200, changed.text
    final = drive(parent, alice)
    assert final['state'] == 'completed', final
    with SessionLocal() as db:
        row = db.get(models.ProvisioningAccountBatch, parent['accounts'][0]['id'])
        assert json.loads(row.stop_policy)['days'] == 3
        assert row.policy_applied_revision == revision
        grant = db.get(models.NativeGroupGrant, row.native_grant_id)
        assert grant.stop_at == grant.activated_at + timedelta(days=7)
        for item in final['accounts'][0]['items']:
            assert db.get(models.StopSchedule, item['record_id']).stop_at == grant.stop_at


def action(client, parent, name, key=None):
    row = parent['accounts'][0]
    return client.post(f"/api/provisioning-batches/{parent['id']}/accounts/{row['id']}/{name}",
                       json={'request_key': key or 'action-' + name + '-request01'})


@pytest.mark.parametrize('stage', ['group', 'native', 'sso', 'join'])
def test_uncertain_accepted_child_reconciles_without_duplicate_writes(alice, gateway, stage):
    from app.aws import AwsFailure
    parent = admit(alice, body()).json()
    class Lost(Gateway):
        def create_group(self, *args):
            result = super().create_group(*args)
            if stage == 'group': raise AwsFailure('lost response', uncertain=True)
            return result
        def subscribe_group(self, *args):
            result = super().subscribe_group(*args)
            if stage == 'native': raise AwsFailure('lost response', uncertain=True)
            return result
        def create_user(self, *args):
            result = super().create_user(*args)
            if stage == 'sso': raise AwsFailure('lost response', uncertain=True)
            return result
        def create_group_membership(self, *args):
            result = super().create_group_membership(*args)
            if stage == 'join': raise AwsFailure('lost response', uncertain=True)
            return result
    final = drive(parent, alice, Lost)
    assert final['state'] == 'needs_review', final
    row = final['accounts'][0]
    if stage == 'group':
        retry = alice.post(f"/api/groups/{row['group']['id']}/retry")
    elif stage == 'native':
        retry = alice.post(f"/api/group-subscriptions/{row['native_operation_id']}/recheck")
    else:
        retry = alice.post(f"/api/subscriptions/{row['items'][0]['record_id']}/retry")
    assert retry.status_code == 202, retry.text
    assert action(alice, parent, 'recheck').status_code == 202
    final = drive(parent, alice)
    assert final['state'] == 'completed', final
    assert [e[0] for e in gateway.events] == ['group', 'GROUP', 'sso', 'otp', 'join']
    with SessionLocal() as db:
        assert (db.get(models.PlanCounter, 1).used_count, db.get(models.PlanCounter, 1).pending_count) == (1, 0)


def test_stop_after_paid_group_releases_unsent_sso_only(alice, gateway):
    parent = admit(alice, body(quantity=2)).json()
    coordinator_to_child(parent, 'sso')
    assert action(alice, parent, 'stop').status_code == 202
    final = drive(parent, alice)
    assert final['state'] == 'stopped'
    with SessionLocal() as db:
        assert db.get(models.NativeGroupGrant, final['accounts'][0]['native_grant_id']).state == 'active'
        assert db.get(models.PlanCounter, 1).pending_count == 0
    assert [e[0] for e in gateway.events] == ['group', 'GROUP']


def test_active_remote_pending_plan_blocks_before_sso_creation(alice, gateway):
    parent = admit(alice, body()).json()
    coordinator_to_child(parent, 'sso')
    with SessionLocal() as db:
        gid = db.get(models.ProvisioningAccountBatch, parent['accounts'][0]['id']).group_id
        remote_id = db.get(models.ManagedGroup, gid).remote_id
    gateway.assignments[remote_id]['pending_type'] = 'Q_DEVELOPER_STANDALONE_FREE'
    worker.run_one(Gateway, account_id=1)
    final = drive(parent, alice)
    assert final['state'] == 'needs_review'
    assert [e[0] for e in gateway.events] == ['group', 'GROUP']
    with SessionLocal() as db:
        assert db.get(models.PlanCounter, 1).pending_count == 0


def test_native_proved_unsent_failure_can_retry_without_repeating_paid_work(alice, gateway):
    parent = admit(alice, body()).json()
    cid = coordinator_to_child(parent, 'native')
    class Reject(Gateway):
        def verify(self):
            raise aws.AwsFailure('definitely unsent')
    from app.group_subscription_worker import run_one
    assert run_one(Reject, account_id=1)
    final = drive(parent, alice)
    assert 'retry' in final['accounts'][0]['allowed_actions']
    old = final['accounts'][0]['native_operation_id']
    assert action(alice, parent, 'retry').status_code == 202
    result = drive(parent, alice)
    assert result['state'] == 'completed', result
    assert result['accounts'][0]['native_operation_id'] != old
    assert [e[0] for e in gateway.events].count('GROUP') == 1
    with SessionLocal() as db:
        assert db.get(models.NativeGroupOperation, old).state == 'failed'


def test_json_missing_credentials_is_completed_provisioning_with_export_only_retry(alice, gateway):
    parent = admit(alice, intent()).json()
    coordinator_to_child(parent, 'sso')
    worker.run_one(Gateway, account_id=1)
    rid = parent['accounts'][0]['items'][0]['record_id']
    with SessionLocal() as db:
        db.get(models.Subscription, rid).password_encrypted = None
        db.get(models.Subscription, rid).credential_state = 'unknown'
        db.commit()
    final = drive(parent, alice)
    assert final['state'] == 'completed'
    assert final['accounts'][0]['items'][0]['export_state'] == 'blocked'
    assert final['accounts'][0]['allowed_actions'] == ['retry_export']
    with SessionLocal() as db:
        db.get(models.Subscription, rid).password_encrypted = encrypt('KnownPassword123!')
        db.get(models.Subscription, rid).credential_state = 'one_time'
        db.commit()
    before = list(gateway.events)
    assert action(alice, parent, 'retry_export').status_code == 202
    final = drive(parent, alice)
    assert final['state'] == 'completed'
    assert final['accounts'][0]['items'][0]['auth_batch_id']
    assert gateway.events == before


@pytest.mark.parametrize('stage,module_name,helper', [
    ('group', 'groups', 'admit_create_group'),
    ('native', 'group_subscriptions', 'admit_prepared_groups'),
    ('sso', 'batches', 'admit_frozen_sso'),
    ('auth', 'auth_batches', 'admit_auth_batch'),
])
def test_crash_after_child_admission_before_link_rolls_back_atomically(alice, gateway, monkeypatch, stage, module_name, helper):
    import importlib
    from app.provisioning_coordinator import run_one
    from app.group_jobs import run_group_job
    from app.group_subscription_worker import run_one as native_one
    parent = admit(alice, intent() if stage == 'auth' else body()).json()
    if stage == 'group':
        run_one(account_id=1)
    elif stage == 'native':
        coordinator_to_child(parent, 'group')
        run_group_job(Gateway, account_id=1)
        run_one(account_id=1)
        run_one(account_id=1)
    elif stage == 'sso':
        coordinator_to_child(parent, 'native')
        native_one(Gateway, account_id=1)
        run_one(account_id=1)
    else:
        coordinator_to_child(parent, 'sso')
        worker.run_one(Gateway, account_id=1)
    module = importlib.import_module('app.' + module_name)
    real = getattr(module, helper)
    counts = (models.ManagedGroup, models.NativeGroupOperation, models.Subscription, models.AuthBatch)
    with SessionLocal() as db:
        before = [db.scalar(select(func.count()).select_from(m)) for m in counts]
        pending = db.get(models.PlanCounter, 1).pending_count
    def crash(*args, **kwargs):
        real(*args, **kwargs)
        raise RuntimeError('simulated crash before saving child link')
    monkeypatch.setattr(module, helper, crash)
    with pytest.raises(RuntimeError, match='simulated crash'):
        run_one(account_id=1)
    with SessionLocal() as db:
        assert [db.scalar(select(func.count()).select_from(m)) for m in counts] == before
        assert db.get(models.PlanCounter, 1).pending_count == pending
    monkeypatch.setattr(module, helper, real)
    final = drive(parent, alice)
    assert final['state'] == 'completed', final
    assert [e[0] for e in gateway.events] == ['group', 'GROUP', 'sso', 'otp', 'join']
    with SessionLocal() as db:
        assert db.get(models.PlanCounter, 1).used_count == 1
        assert db.scalar(select(func.count()).select_from(models.AuthBatch)) == (1 if stage == 'auth' else 0)


def test_partial_sso_failure_uses_existing_retry_and_keeps_completed_sibling(alice, gateway):
    parent = admit(alice, body(quantity=3)).json()
    coordinator_to_child(parent, 'sso')
    failed_id = parent['accounts'][0]['items'][1]['record_id']
    class Partial(Gateway):
        def create_user(self, record):
            if record.id == failed_id:
                raise aws.AwsFailure('definitely rejected')
            return super().create_user(record)
    for item in parent['accounts'][0]['items']:
        assert worker.run_one(Partial, account_id=1, record_id=item['record_id'])
    first = drive(parent, alice, Partial)
    assert first['state'] == 'needs_review', first
    assert [i['state'] for i in first['accounts'][0]['items']] == ['completed', 'failed', 'completed']
    with SessionLocal() as db:
        assert (db.get(models.PlanCounter, 1).used_count, db.get(models.PlanCounter, 1).pending_count) == (2, 0)
    assert alice.post('/api/subscriptions/' + failed_id + '/retry').status_code == 202
    assert action(alice, parent, 'recheck').status_code == 202
    final = drive(parent, alice)
    assert final['state'] == 'completed', final
    assert [x[0] for x in gateway.events].count('sso') == 3
    assert [x[0] for x in gateway.events].count('GROUP') == 1
    assert [i['username'] for i in final['accounts'][0]['items']] == [i['username'] for i in parent['accounts'][0]['items']]


def test_stopped_parent_explicit_lost_otp_recovery_never_joins(alice, gateway):
    from app.lifecycle import run_operation
    parent = admit(alice, body()).json()
    class Lost(Gateway):
        def password(self, r):
            super().password(r)
            raise aws.AwsFailure('lost OTP', uncertain=True)
    first = drive(parent, alice, Lost)
    assert first['state'] == 'needs_review'
    rid = first['accounts'][0]['items'][0]['record_id']
    assert action(alice, parent, 'stop').status_code == 202
    operation = alice.post('/api/subscriptions/' + rid + '/operations', json={
        'kind': 'reset_password', 'request_key': 'explicit-stopped-otp-01',
        'confirm_username': first['accounts'][0]['items'][0]['username']})
    assert operation.status_code == 202, operation.text
    assert run_operation(Gateway, account_id=1)
    assert action(alice, parent, 'recheck').status_code == 202
    final = drive(parent, alice)
    assert final['state'] == 'stopped', final
    assert not any(x[0] == 'join' for x in gateway.events)
    with SessionLocal() as db:
        assert db.get(models.Subscription, rid).password_encrypted
        assert db.get(models.PlanCounter, 1).pending_count == 0


def test_disabled_original_actor_readonly_native_recovery_cannot_admit_followers(alice, admin, gateway):
    parent = admit(alice, body()).json()
    class Lost(Gateway):
        def subscribe_group(self, *args):
            super().subscribe_group(*args)
            raise aws.AwsFailure('lost', uncertain=True)
    first = drive(parent, alice, Lost)
    with SessionLocal() as db:
        db.get(models.User, 2).active = False
        db.commit()
    oid = first['accounts'][0]['native_operation_id']
    assert admin.post('/api/group-subscriptions/' + oid + '/recheck').status_code == 202
    assert action(admin, parent, 'recheck').status_code == 202
    from app.group_subscription_worker import run_one
    assert run_one(Gateway, account_id=1)
    final = drive(parent, admin)
    assert final['state'] == 'paused', final
    assert final['accounts'][0]['group_subscription_state'] == 'active'
    assert [x[0] for x in gateway.events] == ['group', 'GROUP']


def test_blocked_account_a_does_not_block_account_b_with_real_dispatcher(alice, gateway):
    import threading
    from test_provisioning_admission import duplicate_account
    second = duplicate_account('b')
    with SessionLocal() as db:
        p = models.Proxy(name='Account B', host='127.0.0.2', port=1081,
            auth_encrypted=encrypt({'username': '', 'password': ''}))
        db.add(p)
        db.flush()
        db.get(models.AwsAccount, second).proxy_id = p.id
        db.commit()
    first = admit(alice, body()).json()
    entered, release = threading.Event(), threading.Event()
    observed = []
    class Waiting(Gateway):
        def __init__(self, account):
            super().__init__(account)
            observed.append((account.id, account._proxy_selection.proxy_id))
        def create_group(self, name, marker):
            if self.account.id == 1:
                entered.set()
                assert release.wait(5)
            return super().create_group(name, marker)
    dispatcher = worker.make_dispatcher(gateway_factory=Waiting, max_workers=2)
    try:
        until = time.monotonic() + 3
        while not entered.is_set() and time.monotonic() < until:
            dispatcher.tick()
            time.sleep(.01)
        assert entered.is_set()
        other = intent(second, exports={'csv': True, 'txt': False, 'json': False})
        second_parent = admit(alice, other, key='concurrent-parent-B1').json()
        until = time.monotonic() + 3
        while time.monotonic() < until:
            dispatcher.tick()
            result = fetch(alice, second_parent)
            if result['state'] == 'completed': break
            time.sleep(.01)
        assert result['state'] == 'completed', result
        assert not any(e[0] == 'sso' and e[1] == 1 for e in gateway.events)
        assert set(observed) == {(1, 1), (second, 2)}
    finally:
        release.set()
        dispatcher.close(wait=True)
    assert drive(first, alice)['state'] == 'completed'


def test_coordinator_uses_same_process_fence_as_all_workers(alice, gateway):
    import os
    import subprocess
    import sys
    from app.account_dispatcher import account_fence
    parent = admit(alice, body()).json()
    with account_fence(1) as locked:
        assert locked
        result = subprocess.run([sys.executable, '-c',
            'from app.provisioning_coordinator import run_one; print(run_one(account_id=1))'],
            env={**os.environ, 'PYTHONPATH': 'backend'}, capture_output=True, text=True, timeout=5)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == 'False'
    assert drive(parent, alice)['state'] == 'completed'


def test_completed_projection_exposes_effective_policy_and_private_export_progress(alice, admin, gateway):
    parent = admit(alice, intent()).json()
    result = drive(parent, alice)
    row = result['accounts'][0]
    assert row['export_state'] == 'queued'
    assert row['export_states'] == {'queued': 1}
    assert row['effective_policy']['mode'] == 'none'
    changed = alice.put('/api/groups/' + row['group']['id'] + '/policy', json={
        'policy': {'mode': 'days', 'days': 8}, 'expected_revision': row['policy_applied_revision']})
    # JSON may hold its own record operation: close the unstarted export first.
    if changed.status_code == 409:
        auth = row['items'][0]['auth_batch_id']
        assert alice.post('/api/auth-batches/' + auth + '/cancel').status_code == 200
        changed = alice.put('/api/groups/' + row['group']['id'] + '/policy', json={
            'policy': {'mode': 'days', 'days': 8}, 'expected_revision': row['policy_applied_revision']})
    assert changed.status_code == 200, changed.text
    refreshed = fetch(alice, parent)['accounts'][0]
    assert refreshed['stop_policy']['mode'] == 'none'
    assert refreshed['effective_policy']['days'] == 8
    assert refreshed['export_state'] in ('queued', 'cancelled')
    public = fetch(admin, parent)['accounts'][0]
    assert public['export_state'] == refreshed['export_state']
    assert public['items'][0]['auth_batch_id'] is None


def test_child_failure_projection_offers_exact_authoritative_recovery_route(alice, gateway):
    parent = admit(alice, body()).json()
    class Rejected(Gateway):
        def create_user(self, record):
            raise aws.AwsFailure('rejected')
    row = drive(parent, alice, Rejected)['accounts'][0]
    recovery = row['recovery']
    assert recovery['kind'] == 'sso_retry'
    assert recovery['path'] == '/api/subscriptions/' + row['items'][0]['record_id'] + '/retry'
    assert recovery['method'] == 'POST'


@pytest.mark.parametrize('phase', ['group', 'native', 'sso'])
def test_scope_binding_disabled_owner_and_proxy_before_child_read_send_nothing(alice, admin, gateway, phase):
    parent = admit(alice, body()).json()
    coordinator_to_child(parent, phase)
    before = list(gateway.events)
    with SessionLocal() as db:
        db.delete(db.get(models.Binding, (2, 1)))
        db.commit()
    if phase == 'group':
        from app.group_jobs import run_group_job
        run_group_job(Gateway, account_id=1)
    elif phase == 'native':
        from app.group_subscription_worker import run_one
        run_one(Gateway, account_id=1)
    else:
        worker.run_one(Gateway, account_id=1)
    assert gateway.events == before
    result = drive(parent, admin)
    assert result['state'] == 'paused', result
    assert alice.get('/api/provisioning-batches/' + parent['id']).status_code == 403


def test_expired_later_policy_prevents_new_paid_members(alice, gateway):
    parent = admit(alice, body(quantity=2)).json()
    coordinator_to_legacy_first_sso(parent)
    worker.run_one(Gateway, account_id=1)
    with SessionLocal() as db:
        row = db.get(models.ProvisioningAccountBatch, parent['accounts'][0]['id'])
        group = db.get(models.ManagedGroup, row.group_id)
        group.policy_mode, group.policy_stop_at = 'at', models.now() - timedelta(seconds=1)
        group.policy_revision += 1
        grant = db.get(models.NativeGroupGrant, row.native_grant_id)
        grant.stop_at, grant.policy_revision = group.policy_stop_at, group.policy_revision
        db.commit()
    result = drive(parent, alice)
    assert result['state'] == 'paused'
    assert [e[0] for e in gateway.events].count('sso') == 1
    with SessionLocal() as db:
        assert db.get(models.PlanCounter, 1).used_count == 1


@pytest.mark.parametrize('reply_phase', ['ready', 'pending'])
def test_native_retry_after_definite_rejection_preserves_history(alice, gateway, reply_phase):
    parent = admit(alice, body()).json()
    coordinator_to_child(parent, 'native')
    class Reject(Gateway):
        def verify(self):
            if reply_phase == 'ready': raise aws.AwsFailure('rejected before send')
            return super().verify()
        def subscribe_group(self, group, plan):
            raise aws.AwsFailure('explicit server refusal', uncertain=False)
    from app.group_subscription_worker import run_one
    run_one(Reject, account_id=1)
    result = drive(parent, alice)
    assert result['state'] == 'paused'
    assert action(alice, parent, 'retry').status_code == 202
    result = drive(parent, alice)
    assert result['state'] == 'completed', result
    assert [e[0] for e in gateway.events].count('GROUP') == 1


def test_large_detail_and_coordinator_step_use_bounded_bulk_reads(alice, gateway):
    from sqlalchemy import event
    from app.database import engine
    from app.provisioning_coordinator import run_one
    with SessionLocal() as db:
        db.get(models.PlanCounter, 1).limit_count = 200
        db.commit()
    parent = admit(alice, body(quantity=100)).json()
    queries = []
    def seen(conn, cursor, statement, parameters, context, many):
        if statement.lstrip().upper().startswith('SELECT'):
            queries.append(statement)
    event.listen(engine, 'before_cursor_execute', seen)
    try:
        detail = fetch(alice, parent)
        assert len(detail['accounts'][0]['items']) == 100
        assert len(queries) <= 20, queries
        queries.clear()
        assert run_one(account_id=1)
        assert len(queries) <= 25, len(queries)
    finally:
        event.remove(engine, 'before_cursor_execute', seen)


def test_completed_user_deadline_does_not_block_independent_group_activation(alice, gateway):
    from test_native_groups import seed_group
    gid = seed_group(1)
    gateway.members.update(NativeGateway.members)
    gateway.groups['remote-' + gid] = {'id': 'remote-' + gid, 'name': gid, 'description': gid}
    rid = gid + '-record-0'
    with SessionLocal() as db:
        record = db.get(models.Subscription, rid)
        record.counted, record.plan_id, record.subscription_type = True, 1, 'Q_DEVELOPER_STANDALONE_PRO'
        record.subscription_status, record.cancelled_at = 'cancelled', models.now() - timedelta(days=2)
        db.add(models.StopSchedule(record_id=rid, actor_id=2, mode='at', state='completed',
            stop_at=models.now() - timedelta(days=1), principal_type='USER', individual_override=True))
        db.commit()
    parent = admit(alice, existing_body(alice, gid)).json()
    final = drive(parent, alice)
    assert final['state'] == 'completed', final
    with SessionLocal() as db:
        schedule = db.get(models.StopSchedule, rid)
        assert schedule.state == 'completed' and schedule.principal_type == 'USER'


def test_stopped_unsent_sso_cannot_reserve_again_through_generic_retry(alice, gateway):
    parent = admit(alice, body()).json()
    coordinator_to_child(parent, 'sso')
    assert action(alice, parent, 'stop').status_code == 202
    rid = parent['accounts'][0]['items'][0]['record_id']
    response = alice.post('/api/subscriptions/' + rid + '/retry')
    assert response.status_code == 409, response.text
    with SessionLocal() as db:
        assert db.get(models.PlanCounter, 1).pending_count == 0


def test_json_official_challenge_retains_success_and_actor_private_task(alice, admin, gateway):
    from test_auth_batches import Gateway as AuthGateway, drain
    from test_official_auth_fallback import ExternalAuth
    parent = admit(alice, intent()).json()
    drive(parent, alice)
    before = list(gateway.events)
    drain(ExternalAuth, AuthGateway)
    final = fetch(alice, parent)
    row = final['accounts'][0]
    item = row['items'][0]
    assert final['state'] == 'completed' and item['state'] == 'completed'
    assert row['export_state'] == item['export_state'] == 'challenge'
    metadata = alice.get(f"/api/auth-batches/{item['auth_batch_id']}/items/{item['record_id']}/challenge")
    assert metadata.status_code == 200 and metadata.json()['kind'] == 'aws_authorization'
    assert fetch(admin, parent)['accounts'][0]['items'][0]['auth_batch_id'] is None
    assert gateway.events == before


@pytest.mark.parametrize('failure_stage', ['create_user', 'membership'])
def test_failed_numbered_retry_cannot_join_reopened_higher_group_tier(alice, gateway, monkeypatch, failure_stage):
    from app import group_subscriptions
    from app.group_subscription_worker import run_one as native_one
    monkeypatch.setattr(group_subscriptions, 'AwsGateway', Gateway)
    parent = admit(alice, body()).json()
    class Reject(Gateway):
        def create_user(self, record):
            if failure_stage == 'create_user':
                raise aws.AwsFailure('definitely rejected')
            return super().create_user(record)
        def create_group_membership(self, gid, uid):
            raise aws.AwsFailure('definitely rejected', uncertain=False)
    result = drive(parent, alice, Reject)
    row, item = result['accounts'][0], result['accounts'][0]['items'][0]
    gid = row['group']['id']
    cancellation = alice.post('/api/group-subscriptions/cancel', json={
        'group_ids': [gid], 'request_key': 'manual-cancel-group01'})
    assert cancellation.status_code == 202, cancellation.text
    assert native_one(Gateway, account_id=1)
    opening = alice.post('/api/group-subscriptions', json={
        'group_ids': [gid], 'plan_id': 2, 'request_key': 'manual-new-tier-group01'})
    assert opening.status_code == 202, opening.text
    assert native_one(Gateway, account_id=1)
    before = list(gateway.events)
    response = alice.post('/api/subscriptions/' + item['record_id'] + '/retry')
    assert response.status_code == 409, response.text
    worker.run_one(Gateway, account_id=1)
    assert gateway.events == before
    with SessionLocal() as db:
        assert not db.scalar(select(models.GroupMemberActivation).where(
            models.GroupMemberActivation.record_id == item['record_id'], models.GroupMemberActivation.reserved.is_(True)))
        assert db.get(models.ProvisioningAccountBatch, row['id']).plan_id == 1


def test_definitely_failed_membership_retry_is_new_guarded_write(alice, gateway):
    parent = admit(alice, body()).json()
    class Reject(Gateway):
        def create_group_membership(self, gid, uid):
            raise aws.AwsFailure('definitely rejected', uncertain=False)
    result = drive(parent, alice, Reject)
    row, item = result['accounts'][0], result['accounts'][0]['items'][0]
    assert item['record_state'] == 'failed' and item['record_step'] == 'group_membership_pending'
    assert item['recovery']['read_only'] is False
    response = alice.post('/api/subscriptions/' + item['record_id'] + '/retry')
    assert response.status_code == 202, response.text
    assert action(alice, parent, 'recheck').status_code == 202
    final = drive(parent, alice)
    assert final['state'] == 'completed'
    with SessionLocal() as db:
        counter = db.get(models.PlanCounter, 1)
        assert (counter.used_count, counter.pending_count, counter.lifetime_count) == (1, 0, 1)
    assert [event[0] for event in gateway.events].count('sso') == 1


def test_stop_definitely_failed_membership_does_not_require_uncertain_recovery(alice, gateway):
    parent = admit(alice, body()).json()
    class Reject(Gateway):
        def create_group_membership(self, gid, uid):
            raise aws.AwsFailure('definitely rejected', uncertain=False)
    assert drive(parent, alice, Reject)['state'] == 'needs_review'
    before = list(gateway.events)
    stopped = action(alice, parent, 'stop')
    assert stopped.status_code == 202, stopped.text
    assert stopped.json()['state'] == 'stopped'
    row = stopped.json()['accounts'][0]
    assert row['allowed_actions'] == ['resume'] and row['items'][0]['recovery'] is None
    assert gateway.events == before
    with SessionLocal() as db:
        assert db.get(models.PlanCounter, 1).pending_count == 0
    assert action(alice, parent, 'resume').status_code == 202
    assert drive(parent, alice)['state'] == 'completed'
    assert [event[0] for event in gateway.events].count('sso') == 1
    assert [event[0] for event in gateway.events].count('GROUP') == 1


def test_remaining_numbered_items_cannot_follow_reopened_same_plan_grant(alice, gateway, monkeypatch):
    from app import group_subscriptions
    from app.group_subscription_worker import run_one as native_one
    monkeypatch.setattr(group_subscriptions, 'AwsGateway', Gateway)
    parent = admit(alice, body(quantity=2)).json()
    coordinator_to_legacy_first_sso(parent)
    assert worker.run_one(Gateway, account_id=1)
    with SessionLocal() as db:
        row = db.get(models.ProvisioningAccountBatch, parent['accounts'][0]['id'])
        gid, original_grant = row.group_id, row.native_grant_id
    cancellation = alice.post('/api/group-subscriptions/cancel', json={
        'group_ids': [gid], 'request_key': 'manual-same-plan-cancel'})
    assert cancellation.status_code == 202, cancellation.text
    assert native_one(Gateway, account_id=1)
    opening = alice.post('/api/group-subscriptions', json={
        'group_ids': [gid], 'plan_id': 1, 'request_key': 'manual-same-plan-reopen'})
    assert opening.status_code == 202, opening.text
    assert native_one(Gateway, account_id=1)
    before = list(gateway.events)
    final = drive(parent, alice)
    row = final['accounts'][0]
    assert row['native_grant_id'] == original_grant
    assert final['state'] == 'paused'
    assert row['items'][0]['state'] == 'completed' and row['items'][0]['finished_at']
    assert gateway.events == before
    with SessionLocal() as db:
        assert db.get(models.Subscription, row['items'][1]['record_id']) is None
        assert db.get(models.PlanCounter, 1).pending_count == 0


def test_existing_group_grant_is_frozen_before_coordinator_links_it(alice, gateway, monkeypatch):
    from app import group_subscriptions
    from app.group_subscription_worker import run_one as native_one
    from app.provisioning_coordinator import run_one as coordinate
    monkeypatch.setattr(group_subscriptions, 'AwsGateway', Gateway)
    first = drive(admit(alice, body()).json(), alice)
    gid = first['accounts'][0]['group']['id']
    parent = admit(alice, existing_body(alice, gid), key='test-idempotency-00000001').json()
    assert coordinate(account_id=1)  # Validate the originally accepted snapshot.
    cancellation = alice.post('/api/group-subscriptions/cancel', json={
        'group_ids': [gid], 'request_key': 'existing-plan-cancel'})
    assert cancellation.status_code == 202, cancellation.text
    assert native_one(Gateway, account_id=1)
    opening = alice.post('/api/group-subscriptions', json={
        'group_ids': [gid], 'plan_id': 1, 'request_key': 'existing-plan-reopen'})
    assert opening.status_code == 202, opening.text
    assert native_one(Gateway, account_id=1)
    before = list(gateway.events)
    final = drive(parent, alice)
    row = final['accounts'][0]
    assert row['native_grant_id'] is None
    assert final['state'] == 'paused'
    assert gateway.events == before


def test_confirmed_item_progress_survives_following_quota_pause(alice, gateway):
    parent = admit(alice, body(quantity=2)).json()
    coordinator_to_legacy_first_sso(parent)
    assert worker.run_one(Gateway, account_id=1)
    with SessionLocal() as db:
        counter = db.get(models.PlanCounter, 1)
        assert (counter.used_count, counter.pending_count) == (1, 0)
        counter.limit_count = 1
        db.commit()
    final = drive(parent, alice)
    assert final['state'] == 'paused'
    first, second = final['accounts'][0]['items']
    assert first['record_state'] == first['state'] == 'completed'
    assert first['finished_at'] and first['sso_batch_id']
    assert second['record_state'] is None
    with SessionLocal() as db:
        item = db.get(models.ProvisioningItem, first['record_id'])
        assert item.state == 'completed' and item.finished_at
        assert db.get(models.Subscription, second['record_id']) is None
        assert db.get(models.PlanCounter, 1).pending_count == 0
    assert fetch(alice, parent)['accounts'][0]['items'][0] == first


@pytest.mark.parametrize('reopen', [False, True])
def test_progress_uses_original_counted_grant_history(alice, gateway, monkeypatch, reopen):
    from app import group_subscriptions
    from app.group_subscription_worker import run_one as native_one
    monkeypatch.setattr(group_subscriptions, 'AwsGateway', Gateway)
    parent = admit(alice, body(quantity=2)).json()
    coordinator_to_legacy_first_sso(parent)
    assert worker.run_one(Gateway, account_id=1)
    first_id = parent['accounts'][0]['items'][0]['record_id']
    with SessionLocal() as db:
        row = db.get(models.ProvisioningAccountBatch, parent['accounts'][0]['id'])
        gid, original_grant = row.group_id, row.native_grant_id
        activation = db.scalar(select(models.GroupMemberActivation).where(
            models.GroupMemberActivation.record_id == first_id,
            models.GroupMemberActivation.grant_id == original_grant))
        assert activation.counted
        activated_at = activation.activated_at.isoformat()
    response = alice.post('/api/group-subscriptions/cancel', json={
        'group_ids': [gid], 'request_key': 'history-original-cancel'})
    assert response.status_code == 202, response.text
    assert native_one(Gateway, account_id=1)
    if reopen:
        response = alice.post('/api/group-subscriptions', json={
            'group_ids': [gid], 'plan_id': 1, 'request_key': 'history-new-grant-open'})
        assert response.status_code == 202, response.text
        assert native_one(Gateway, account_id=1)
    final = drive(parent, alice)
    row = final['accounts'][0]
    assert final['state'] == 'paused' and row['native_grant_id'] == original_grant
    first = row['items'][0]
    assert first['state'] == 'completed'
    assert first['finished_at'] == activated_at
    assert row['items'][1]['record_state'] is None


def test_completed_record_without_original_counted_proof_releases_coordinator_lane(alice, gateway):
    from app.provisioning_coordinator import run_one as coordinate
    parent = admit(alice, body()).json()
    coordinator_to_child(parent, 'sso')
    rid = parent['accounts'][0]['items'][0]['record_id']
    # An inconsistent recovered record is not evidence of confirmed GROUP
    # access. Keep its original reservation and expose explicit review.
    with SessionLocal() as db:
        record = db.get(models.Subscription, rid)
        record.state, record.step = 'completed', 'sso_ready'
        db.commit()
    before = list(gateway.events)
    final = drive(parent, alice)
    row = final['accounts'][0]
    assert final['state'] == row['items'][0]['state'] == 'needs_review'
    assert row['items'][0]['finished_at'] is None
    assert row['allowed_actions'] == ['recheck', 'stop']
    assert not coordinate(account_id=1)
    assert gateway.events == before


def test_stopped_unsent_group_can_be_explicitly_deleted_without_remote_calls(alice, bob, gateway):
    from app.group_jobs import run_group_job
    parent = admit(alice, body()).json()
    coordinator_to_child(parent, 'group')
    stopped = action(alice, parent, 'stop').json()
    row = stopped['accounts'][0]
    gid = row['group']['id']
    request = {'kind': 'delete', 'expected_revision': 1, 'request_key': 'delete-stopped-local-group'}
    path = '/api/groups/' + gid + '/jobs'
    assert alice.post('/api/groups/' + gid + '/retry').status_code == 409
    assert alice.post(path, json=request | {'kind': 'rename', 'name': 'must-not-restart'}).status_code == 409
    assert bob.post(path, json=request).status_code == 404
    assert alice.post(path, json=request | {'expected_revision': 2}).status_code == 409
    admitted = alice.post(path, json=request)
    assert admitted.status_code == 202, admitted.text
    assert alice.post(path, json=request).json() == admitted.json()
    class NoRemote(Gateway):
        def get_group(self, gid):
            pytest.fail('Local unsent deletion must not query AWS')
        def delete_group(self, gid):
            pytest.fail('Local unsent deletion must not mutate AWS')
    assert run_group_job(NoRemote, account_id=1)
    assert gateway.events == []
    with SessionLocal() as db:
        group = db.get(models.ManagedGroup, gid)
        assert group.state == 'deleted' and group.deleted_at and group.revision == 2
        assert db.get(models.GroupJob, row['group_job_id']).state == 'cancelled'
        assert db.get(models.GroupJob, admitted.json()['id']).state == 'completed'
        assert db.get(models.ProvisioningBatch, parent['id']).state == 'stopped'
        assert db.scalar(select(models.AuditEvent.id).where(models.AuditEvent.action == 'group_delete_completed'))
    assert alice.post('/api/groups/' + gid + '/retry').status_code == 409
    assert fetch(alice, parent)['state'] == 'stopped'


@pytest.mark.parametrize('change', ['remote', 'pending'])
def test_stopped_group_cleanup_requires_proved_unsent_creation(alice, gateway, change):
    parent = admit(alice, body()).json()
    coordinator_to_child(parent, 'group')
    row = action(alice, parent, 'stop').json()['accounts'][0]
    with SessionLocal() as db:
        if change == 'remote':
            db.get(models.ManagedGroup, row['group']['id']).remote_id = 'possibly-created'
        else:
            db.get(models.GroupJob, row['group_job_id']).phase = 'pending'
        db.commit()
    response = alice.post('/api/groups/' + row['group']['id'] + '/jobs', json={
        'kind': 'delete', 'expected_revision': 1, 'request_key': 'reject-uncertain-delete'})
    assert response.status_code == 409, response.text
    assert gateway.events == []


def two_account_fence_intent(alice, *, shared_plan=False):
    from test_provisioning_admission import duplicate_account
    second = duplicate_account(number='b')
    request = body()
    request['accounts'] += intent(second, plan_id=1 if shared_plan else 2,
        exports={'csv': True, 'txt': True, 'json': False})['accounts']
    accepted = admit(alice, request)
    assert accepted.status_code == 202, accepted.text
    return accepted.json(), second


@pytest.mark.parametrize('sibling_state', ['queued', 'running', 'paused', 'needs_review', 'uncertain', 'stopping'])
def test_stopped_group_cleanup_is_independent_of_live_sibling(alice, gateway, sibling_state):
    from app.group_jobs import run_group_job
    from app.provisioning_batches import live_intent
    from app.provisioning_coordinator import run_one as coordinate
    parent, second = two_account_fence_intent(alice)
    coordinator_to_child(parent, 'group')
    assert coordinate(account_id=second)
    assert coordinate(account_id=second)
    with SessionLocal() as db:
        sibling = db.get(models.ProvisioningAccountBatch, parent['accounts'][1]['id'])
        sibling.state = sibling_state
        sibling_group = sibling.group_id
        db.commit()
    stopped = action(alice, parent, 'stop')
    assert stopped.status_code == 202, stopped.text
    first, sibling = stopped.json()['accounts']
    gid = first['group']['id']
    assert first['state'] == 'stopped' and sibling['state'] == sibling_state
    with SessionLocal() as db:
        assert live_intent(db, actor_id=2) == parent['id']
        assert live_intent(db, actor_id=3) is None
        assert live_intent(db, group_id=gid) is None
        assert live_intent(db, account_id=1) is None
        assert live_intent(db, actor_id=2, account_ids={1}) is None
        assert live_intent(db, plan_id=1) is None
        assert live_intent(db, group_id=sibling_group) == parent['id']
        assert live_intent(db, account_id=second) == parent['id']
        assert live_intent(db, actor_id=2, account_ids={1, second}) == parent['id']
        assert live_intent(db, plan_id=2) == parent['id']
    deletion = alice.post('/api/groups/' + gid + '/jobs', json={
        'kind': 'delete', 'expected_revision': 1, 'request_key': 'delete-stopped-account-a'})
    assert deletion.status_code == 202, deletion.text
    assert run_group_job(Gateway, account_id=1)
    assert gateway.events == []
    with SessionLocal() as db:
        assert db.get(models.ManagedGroup, gid).deleted_at
        assert db.get(models.GroupJob, first['group_job_id']).state == 'cancelled'
        assert db.get(models.ProvisioningAccountBatch, sibling['id']).state == sibling_state
        assert db.get(models.ManagedGroup, sibling_group).deleted_at is None
        assert live_intent(db, actor_id=2) == parent['id']


def test_live_sibling_preserves_actor_and_resource_mutation_fences(alice, admin, gateway):
    parent, second = two_account_fence_intent(alice)
    assert action(alice, parent, 'stop').status_code == 202
    with SessionLocal() as db:
        first_account = db.get(models.AwsAccount, 1).name
        second_account = db.get(models.AwsAccount, second).name
        first_plan = db.get(models.Plan, 1).name
        second_plan = db.get(models.Plan, 2).name
    assert admin.patch('/api/admin/users/2', json={'role': 'admin'}).status_code == 409
    assert admin.put('/api/admin/users/2/bindings', json={'account_ids': [1]}).status_code == 409
    for kind, key, name in [('aws', second, second_account), ('plans', 2, second_plan)]:
        rejected = admin.request('DELETE', f'/api/admin/{kind}/{key}', json={'confirm_name': name})
        assert rejected.status_code == 409 and '批次开通意图' in rejected.json()['detail']
    assert admin.put('/api/admin/users/2/bindings', json={'account_ids': [second]}).status_code == 200
    for kind, key, name in [('aws', 1, first_account), ('plans', 1, first_plan)]:
        removed = admin.request('DELETE', f'/api/admin/{kind}/{key}', json={'confirm_name': name})
        assert removed.status_code == 200, removed.text
    assert admin.patch('/api/admin/users/2', json={'active': False}).status_code == 200
    assert admin.delete('/api/admin/users/2').status_code == 409
    with SessionLocal() as db:
        assert db.get(models.AwsAccount, second).deleted_at is None
        assert db.get(models.Plan, 2).deleted_at is None
        assert db.get(models.Binding, (2, second))
        assert db.get(models.ProvisioningAccountBatch, parent['accounts'][1]['id']).state == 'queued'
    assert gateway.events == []


def test_shared_resource_and_actor_fences_survive_stale_parent_aggregate(alice, gateway):
    from app.provisioning_batches import live_intent
    parent, second = two_account_fence_intent(alice, shared_plan=True)
    assert action(alice, parent, 'stop').status_code == 202
    with SessionLocal() as db:
        assert live_intent(db, plan_id=1) == parent['id']
        saved = db.get(models.ProvisioningBatch, parent['id'])
        saved.state = 'stopped'
        db.flush()
        assert live_intent(db, actor_id=2) == parent['id']
        assert live_intent(db, account_id=second) == parent['id']
        assert live_intent(db, plan_id=1) == parent['id']
        db.get(models.ProvisioningAccountBatch, parent['accounts'][1]['id']).state = 'stopped'
        saved.state = 'running'
        db.flush()
        # Actor-wide protections remain conservative until parent aggregation.
        assert live_intent(db, actor_id=2) == parent['id']
        assert live_intent(db, account_id=second) is None
        assert live_intent(db, plan_id=1) is None
