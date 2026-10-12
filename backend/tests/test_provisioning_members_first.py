"""Current admission prepares all members before the single paid GROUP write."""
import json

import pytest
from sqlalchemy import select

from app import models, worker
from app.aws import AwsFailure
from app.database import SessionLocal
from test_provisioning_admission import admit, ready, remote  # noqa: F401
from test_provisioning_coordinator import Gateway, body, drive, fetch, gateway  # noqa: F401


def action(client, parent, kind, key):
    row = parent['accounts'][0]
    return client.post(f"/api/provisioning-batches/{parent['id']}/accounts/{row['id']}/{kind}",
                       json={'request_key': key})


def admit_members(parent):
    from app.group_jobs import run_group_job
    from app.provisioning_coordinator import run_one
    for _ in range(20):
        run_one(account_id=1)
        run_group_job(Gateway, account_id=1)
        with SessionLocal() as db:
            if all(db.get(models.Subscription, item['record_id']) for item in parent['accounts'][0]['items']):
                return
    pytest.fail('members were not admitted before subscription')


def test_all_members_join_before_group_subscription_and_json_admission(alice, gateway):
    request = body(quantity=3)
    request['accounts'][0]['exports']['json'] = True
    parent = admit(alice, request).json()
    final = drive(parent, alice)
    assert final['state'] == 'completed', final
    kinds = [e[0] for e in gateway.events]
    assert kinds.count('GROUP') == 1
    assert max(i for i, kind in enumerate(kinds) if kind in ('sso', 'otp', 'join')) < kinds.index('GROUP')
    assert all(i['state'] == 'completed' and i['auth_batch_id'] for i in final['accounts'][0]['items'])
    with SessionLocal() as db:
        row = db.get(models.ProvisioningAccountBatch, parent['accounts'][0]['id'])
        assert json.loads(row.snapshot)['subscription_order'] == 'members_first'
        assert db.get(models.PlanCounter, 1).used_count == 3
        for item in final['accounts'][0]['items']:
            r = db.get(models.Subscription, item['record_id'])
            assert r.subscription_status == 'active' and r.counted


def test_failure_offers_batch_retry_and_preserves_prepared_members(alice, gateway):
    parent = admit(alice, body(quantity=3)).json()
    failed_id = parent['accounts'][0]['items'][1]['record_id']
    class Refusal(Gateway):
        def create_user(self, record):
            if record.id == failed_id:
                raise AwsFailure('creation refused', code='AccessDeniedException')
            return super().create_user(record)
    final = drive(parent, alice, Refusal)
    row = final['accounts'][0]
    assert final['state'] == 'needs_review', final
    assert not any(e[0] == 'GROUP' for e in gateway.events)
    assert 'retry_failed' in row['allowed_actions']
    prior = list(gateway.events)
    reply = action(alice, parent, 'retry_failed', 'retry-members-first-01')
    assert reply.status_code == 202, reply.text
    assert action(alice, parent, 'retry_failed', 'retry-members-first-01').status_code == 202
    final = drive(parent, alice)
    assert final['state'] == 'completed', final
    assert all(gateway.events.count(e) == prior.count(e) for e in prior)
    assert len([e for e in gateway.events if e[0] == 'sso']) == 3
    assert len([e for e in gateway.events if e[0] == 'GROUP']) == 1


@pytest.mark.parametrize('prepared', [1, 3])
def test_stop_resume_before_subscription_keeps_existing_users_and_memberships(alice, gateway, prepared):
    parent = admit(alice, body(quantity=3)).json()
    admit_members(parent)
    for item in parent['accounts'][0]['items'][:prepared]:
        assert worker.run_one(Gateway, record_id=item['record_id'])
    prior = list(gateway.events)
    assert not any(e[0] == 'GROUP' for e in prior)
    response = action(alice, parent, 'stop', 'stop-members-first-01')
    assert response.status_code == 202, response.text
    assert response.json()['state'] == 'stopped', response.text
    assert response.json()['accounts'][0]['allowed_actions'] == ['resume']
    response = action(alice, parent, 'resume', 'resume-members-first-01')
    assert response.status_code == 202, response.text
    final = drive(parent, alice)
    assert final['state'] == 'completed', final
    assert all(gateway.events.count(e) == prior.count(e) for e in prior)
    assert len([e for e in gateway.events if e[0] == 'GROUP']) == 1
    with SessionLocal() as db:
        assert len(list(db.scalars(select(models.Subscription)))) == 3
        assert db.get(models.PlanCounter, 1).used_count == 3


def test_uncertain_group_write_rechecks_without_resubscribing(alice, gateway):
    parent = admit(alice, body(quantity=2)).json()
    gateway.uncertain = True
    # Membership responses stay certain; only the paid GROUP response is lost.
    class LostGroupResponse(Gateway):
        def create_group_membership(self, gid, uid):
            type(self).uncertain = False
            try:
                return super().create_group_membership(gid, uid)
            finally:
                type(self).uncertain = True
    final = drive(parent, alice, LostGroupResponse)
    assert final['state'] == 'needs_review', final
    assert [e[0] for e in gateway.events].count('GROUP') == 1
    reply = action(alice, parent, 'recheck', 'recheck-members-first-01')
    assert reply.status_code == 202, reply.text
    final = drive(parent, alice)
    assert final['state'] == 'completed', final
    assert [e[0] for e in gateway.events].count('GROUP') == 1


def test_group_readback_delay_does_not_fail_prepared_sso_siblings(alice, gateway):
    from test_automatic_retries import due

    parent = admit(alice, body(quantity=3)).json()
    gateway.effective_rows = []
    final = drive(parent, alice, predicate=lambda view: bool(view['accounts'][0].get('next_retry_at')))
    assert final['state'] == 'running', final
    row = final['accounts'][0]
    assert row['phase'] == 'group_open'
    assert row['native_operation_state'] == 'queued'
    assert row['retry_mode'] == 'reconcile' and row['automatic_retry_count'] == 1
    assert all(i['state'] == 'prepared' for i in row['items'])
    assert not any(i['auth_batch_id'] for i in row['items'])
    before = list(gateway.events)
    gateway.effective_rows = None
    due('native', row['native_operation_id'])
    final = drive(parent, alice)
    assert final['state'] == 'completed', final
    assert gateway.events == before


def test_unsubscribed_existing_group_opens_original_and_new_members_once(alice, gateway):
    from test_provisioning_coordinator import existing_body
    first = admit(alice, body()).json()
    admit_members(first)
    assert worker.run_one(Gateway, account_id=1)
    assert action(alice, first, 'stop', 'stop-prepared-existing-01').status_code == 202
    gid = fetch(alice, first)['accounts'][0]['group']['id']
    second = admit(alice, existing_body(alice, gid, quantity=2), key='test-00000000000001').json()
    final = drive(second, alice)
    assert final['state'] == 'completed', final
    assert [e[0] for e in gateway.events].count('GROUP') == 1
    assert len([e for e in gateway.events if e[0] == 'sso']) == 3
    with SessionLocal() as db:
        records = list(db.scalars(select(models.Subscription)))
        assert len(records) == 3 and all(r.counted and r.subscription_status == 'active' for r in records)
        assert db.get(models.PlanCounter, 1).used_count == 3


def test_quota_failure_before_paid_write_can_resume_without_recreating_users(alice, gateway):
    parent = admit(alice, body(quantity=2)).json()
    admit_members(parent)
    for item in parent['accounts'][0]['items']:
        assert worker.run_one(Gateway, record_id=item['record_id'])
    with SessionLocal() as db:
        db.get(models.PlanCounter, 1).limit_count = 0
        db.commit()
    final = drive(parent, alice)
    assert final['state'] == 'paused', final
    assert not any(e[0] == 'GROUP' for e in gateway.events)
    before = list(gateway.events)
    with SessionLocal() as db:
        db.get(models.PlanCounter, 1).limit_count = 20
        db.commit()
    assert action(alice, parent, 'retry', 'retry-quota-members-first').status_code == 202
    assert drive(parent, alice)['state'] == 'completed'
    assert gateway.events[:-1] == before


def test_stop_resume_after_definite_group_refusal_keeps_prepared_members(alice, gateway):
    parent = admit(alice, body(quantity=2)).json()
    class RefusedGroup(Gateway):
        def subscribe_group(self, group, plan):
            raise AwsFailure('group subscription refused', code='AccessDeniedException')
    final = drive(parent, alice, RefusedGroup)
    assert final['state'] == 'paused', final
    assert all(i['state'] == 'prepared' for i in final['accounts'][0]['items'])
    before = list(gateway.events)
    assert action(alice, parent, 'stop', 'stop-refused-group-01').status_code == 202
    reply = action(alice, parent, 'resume', 'resume-refused-group-01')
    assert reply.status_code == 202, reply.text
    final = drive(parent, alice)
    assert final['state'] == 'completed', final
    assert gateway.events[:-1] == before
    assert [e[0] for e in gateway.events].count('GROUP') == 1


def test_legacy_recheck_queues_pending_credentials_behind_uncertain_membership(alice, gateway):
    from app.provisioning_coordinator import run_one
    from test_provisioning_coordinator import admit as admit_legacy, coordinator_to_child
    parent = admit_legacy(alice, body(quantity=2)).json()
    coordinator_to_child(parent, 'sso')
    first, second = [i['record_id'] for i in parent['accounts'][0]['items']]
    class LostMembership(Gateway):
        def create_group_membership(self, gid, uid):
            super().create_group_membership(gid, uid)
            raise AwsFailure('lost membership response', uncertain=True)
    class LostCreate(Gateway):
        def create_user(self, record):
            super().create_user(record)
            raise AwsFailure('lost create response', uncertain=True)
    assert worker.run_one(LostMembership, account_id=1, record_id=first)
    assert worker.run_one(LostCreate, account_id=1, record_id=second)
    assert run_one(account_id=1)
    row = fetch(alice, parent)['accounts'][0]
    assert [i['record_step'] for i in row['items']] == ['group_membership_pending', 'create_user_pending']
    before = list(gateway.events)
    reply = action(alice, parent, 'recheck', 'recover-both-pending-01')
    assert reply.status_code == 202, reply.text
    with SessionLocal() as db:
        records = [db.get(models.Subscription, record_id) for record_id in (first, second)]
        assert [r.state for r in records] == ['queued', 'queued']
        assert [r.step for r in records] == ['group_membership_pending', 'create_user_pending']
    # Uncertain sends are first recovered by readback, never repeated.
    assert worker.run_one(Gateway, record_id=first)
    assert worker.run_one(Gateway, record_id=second)
    assert gateway.events[:len(before)] == before
    assert gateway.events.count(('sso', 1, row['items'][1]['username'])) == 1
    assert [e[0] for e in gateway.events].count('GROUP') == 1


def test_recheck_recovers_uncertain_group_creation_without_recreating(alice, gateway):
    class LostGroup(Gateway):
        def create_group(self, name, marker):
            super().create_group(name, marker)
            raise AwsFailure('lost group creation response', uncertain=True)
    parent = admit(alice, body()).json()
    final = drive(parent, alice, LostGroup)
    assert final['state'] == 'needs_review', final
    row = final['accounts'][0]
    reply = action(alice, parent, 'recheck', 'recover-created-group-01')
    assert reply.status_code == 202, reply.text
    with SessionLocal() as db:
        job = db.get(models.GroupJob, row['group_job_id'])
        assert job.state == 'queued' and job.phase == 'pending'
    assert drive(parent, alice)['state'] == 'completed'
    assert [e[0] for e in gateway.events].count('group') == 1


def test_existing_unsubscribed_group_rejects_combined_size_before_creating_users(alice, gateway):
    from test_provisioning_coordinator import existing_body
    first = admit(alice, body()).json()
    admit_members(first)
    assert worker.run_one(Gateway, account_id=1)
    assert action(alice, first, 'stop', 'stop-prepared-capacity-01').status_code == 202
    gid = fetch(alice, first)['accounts'][0]['group']['id']
    before = list(gateway.events)
    with SessionLocal() as db:
        db.get(models.PlanCounter, 1).limit_count = 200
        db.commit()
    second = alice.post('/api/provisioning-batches/preview', json=existing_body(alice, gid, quantity=100))
    assert second.status_code == 409, second.text
    assert '100' in second.text
    assert gateway.events == before
    with SessionLocal() as db:
        assert len(list(db.scalars(select(models.Subscription)))) == 1


def test_legacy_failed_credentials_retry_can_prepare_behind_uncertain_membership(alice, gateway):
    from app.provisioning_coordinator import run_one
    from test_provisioning_coordinator import admit as admit_legacy, coordinator_to_child
    parent = admit_legacy(alice, body(quantity=2)).json()
    coordinator_to_child(parent, 'sso')
    first, second = [i['record_id'] for i in parent['accounts'][0]['items']]
    class LostMembership(Gateway):
        def create_group_membership(self, gid, uid):
            super().create_group_membership(gid, uid)
            raise AwsFailure('lost membership response', uncertain=True)
    class RefusedCreate(Gateway):
        def create_user(self, record):
            raise AwsFailure('create explicitly refused', code='AccessDeniedException')
    assert worker.run_one(LostMembership, account_id=1, record_id=first)
    assert worker.run_one(RefusedCreate, account_id=1, record_id=second)
    assert run_one(account_id=1)
    before = list(gateway.events)
    reply = action(alice, parent, 'retry_failed', 'retry-credential-sibling-01')
    assert reply.status_code == 202, reply.text
    assert worker.run_one(Gateway, record_id=second)
    with SessionLocal() as db:
        first_record, second_record = [db.get(models.Subscription, i) for i in (first, second)]
        group = db.get(models.ManagedGroup, first_record.group_id)
        assert group.active_job_id == first
        assert first_record.state == 'needs_review'
        assert second_record.state == 'queued' and second_record.step == 'subscribe'
        assert second_record.sso_user_id and second_record.password_encrypted
    assert len([e for e in gateway.events[len(before):] if e[0] == 'sso']) == 1
    assert not any(e[0] in ('join', 'GROUP') for e in gateway.events[len(before):])
