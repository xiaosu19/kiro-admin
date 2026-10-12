from datetime import timedelta

# Pytest fixture imports intentionally share parameter names.
# ruff: noqa: F811

import pytest
from sqlalchemy import select

from app import auth_batches, auth_jobs, models
from app.database import SessionLocal
from app.identity_login import AuthError
from app.security import decrypt, encrypt
from test_auth_batches import DoneAuth, Gateway as AuthGateway, drain, native_result
from test_provisioning_admission import admit, intent, ready, remote  # noqa: F401
from test_provisioning_coordinator import drive, gateway  # noqa: F401


def test_linked_result_survives_while_parent_is_still_waiting(alice, gateway, monkeypatch):
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    first, second = parent["accounts"][0]["items"]
    for _ in range(3):
        assert auth_jobs.run_one(AuthGateway, DoneAuth, record_id=first["record_id"])
        with SessionLocal() as db:
            if db.get(models.RecordOperation, first["auth_job_id"]).state == "completed":
                break
    with SessionLocal() as db:
        assert db.get(models.RecordOperation, second["auth_job_id"]).state == "queued"
        assert db.get(models.AuthSecret, first["auth_job_id"]).result_encrypted
    assert alice.post(f"/api/provisioning-batches/{parent['id']}/download").status_code == 409
    later = models.now() + timedelta(minutes=16)
    monkeypatch.setattr(auth_batches, "now", lambda: later)
    auth_jobs.expire_batches()
    with SessionLocal() as db:
        batch = db.get(models.AuthBatch, first["auth_batch_id"])
        secret = db.get(models.AuthSecret, first["auth_job_id"])
        assert batch.state == "active" and secret.result_encrypted, (
            "An early successful result must remain while its parent is waiting")


def test_expired_early_token_does_not_consume_the_parent_as_partial_success(alice, gateway):
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    drain(DoneAuth, AuthGateway)
    first, second = parent["accounts"][0]["items"]
    with SessionLocal() as db:
        secret = db.get(models.AuthSecret, first["auth_job_id"])
        result = decrypt(secret.result_encrypted)
        result["expiresAt"] = 1
        secret.result_encrypted = encrypt(result)
        db.commit()
    response = alice.post(f"/api/provisioning-batches/{parent['id']}/download")
    assert response.status_code == 409, (
        response.status_code, response.headers.get("x-export-count"),
        response.headers.get("x-excluded-count"))
    with SessionLocal() as db:
        assert db.get(models.AuthSecret, first["auth_job_id"]).workflow_encrypted
        assert db.get(models.AuthSecret, second["auth_job_id"]).result_encrypted


@pytest.mark.parametrize('unadmitted', [False, True])
def test_short_download_window_starts_after_all_frozen_users_finish(alice, gateway, monkeypatch, unadmitted):
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    first, second = parent['accounts'][0]['items']
    for _ in range(3):
        auth_jobs.run_one(AuthGateway, DoneAuth, record_id=first['record_id'])
    instant = models.now() + timedelta(minutes=16)
    monkeypatch.setattr(auth_batches, 'now', lambda: instant)
    with SessionLocal() as db:
        item = db.get(models.ProvisioningItem, second['record_id'])
        original = item.auth_batch_id, item.auth_job_id
        if unadmitted:
            item.auth_batch_id = item.auth_job_id = None
        auth_batches.finish_batch(db, db.get(models.AuthBatch, first['auth_batch_id']))
        db.commit()
        assert db.get(models.AuthBatch, first['auth_batch_id']).download_expires_at is None
        item.auth_batch_id, item.auth_job_id = original
        db.commit()
    for _ in range(3):
        auth_jobs.run_one(AuthGateway, DoneAuth, record_id=second['record_id'])
    with SessionLocal() as db:
        a, b = (db.get(models.AuthBatch, item['auth_batch_id']) for item in (first, second))
        assert a.download_expires_at == b.download_expires_at
        assert a.download_expires_at > instant
        assert a.completed_at < b.completed_at


def test_waiting_parent_does_not_extend_absolute_auth_expiry(alice, gateway, monkeypatch):
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    first = parent['accounts'][0]['items'][0]
    for _ in range(3):
        auth_jobs.run_one(AuthGateway, DoneAuth, record_id=first['record_id'])
    monkeypatch.setattr(auth_batches, 'now', lambda: models.now() + timedelta(hours=73))
    auth_jobs.expire_batches()
    with SessionLocal() as db:
        assert db.get(models.AuthBatch, first['auth_batch_id']).state == 'expired'
        assert db.get(models.AuthSecret, first['auth_job_id']).workflow_encrypted is None


class RefreshableAuth(DoneAuth):
    starts = 0
    refreshes = 0

    def begin(self, *args, **kwargs):
        type(self).starts += 1
        return super().begin(*args, **kwargs)

    def begin_refresh(self, sealed):
        type(self).refreshes += 1
        return super().begin_refresh(sealed)

    def _advance(self, state, answer):
        state['registration'] = {'clientId': 'private-client', 'clientSecret': 'private-secret',
                                 'clientSecretExpiresAt': self.clock() + 86400}
        state.update(status='done', stage='done', result=native_result(state))


def expire_result(item):
    with SessionLocal() as db:
        secret = db.get(models.AuthSecret, item['auth_job_id'])
        result = decrypt(secret.result_encrypted)
        result['expiresAt'] = 1
        secret.result_encrypted = encrypt(result)
        db.commit()


def test_parent_refreshes_original_oidc_job_without_reset_or_relogin(alice, gateway):
    RefreshableAuth.starts = RefreshableAuth.refreshes = 0
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    drain(RefreshableAuth, AuthGateway)
    first, second = parent['accounts'][0]['items']
    writes, resets, starts = list(gateway.events), AuthGateway.resets, RefreshableAuth.starts
    expire_result(first)
    path = f"/api/provisioning-batches/{parent['id']}/download"
    assert alice.post(path).status_code == 409
    with SessionLocal() as db:
        job = db.get(models.AuthJob, first['auth_job_id'])
        assert job.stage == 'refresh_requested'
        assert db.get(models.RecordOperation, job.id).state == 'queued'
        assert db.get(models.Subscription, first['record_id']).active_operation_id == job.id
        assert db.get(models.AuthSecret, job.id).workflow_encrypted
        assert db.get(models.AuthSecret, second['auth_job_id']).result_encrypted
        assert db.get(models.AuthBatch, second['auth_batch_id']).download_expires_at is None
    assert alice.post(path).status_code == 409
    drain(RefreshableAuth, AuthGateway)
    result = alice.post(path)
    assert result.status_code == 200 and result.headers['x-export-count'] == '2'
    assert RefreshableAuth.refreshes == 1 and RefreshableAuth.starts == starts
    assert AuthGateway.resets == resets and gateway.events == writes


def test_failed_refresh_is_terminal_and_does_not_restart_login(alice, gateway):
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    drain(RefreshableAuth, AuthGateway)
    first = parent['accounts'][0]['items'][0]
    expire_result(first)
    path = f"/api/provisioning-batches/{parent['id']}/download"
    assert alice.post(path).status_code == 409

    class FailedRefresh(RefreshableAuth):
        def begin_refresh(self, sealed):
            raise AuthError('expired')

        def begin(self, *args, **kwargs):
            pytest.fail('refresh must never replay a login or password reset')

    drain(FailedRefresh, AuthGateway)
    with SessionLocal() as db:
        assert db.get(models.RecordOperation, first['auth_job_id']).state == 'failed'
        assert db.get(models.AuthSecret, first['auth_job_id']).workflow_encrypted
    retry = alice.post(f"/api/auth-batches/{first['auth_batch_id']}/items/{first['record_id']}/retry", json={'mode': 'resume'})
    assert retry.status_code == 409 and '新建授权批次' in retry.text
    result = alice.post(path)
    assert result.status_code == 200 and result.headers['x-export-count'] == '1'
    assert result.headers['x-excluded-count'] == '1'


@pytest.mark.parametrize('change', ['credential', 'active_operation'])
def test_refresh_rechecks_current_record_authority_before_queue(alice, gateway, change):
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    drain(RefreshableAuth, AuthGateway)
    first, second = parent['accounts'][0]['items']
    expire_result(first)
    with SessionLocal() as db:
        r = db.get(models.Subscription, first['record_id'])
        if change == 'credential':
            r.credential_revision += 1
        else:
            r.active_operation_id = second['auth_job_id']
        db.commit()
    result = alice.post(f"/api/provisioning-batches/{parent['id']}/download")
    assert result.status_code == 409
    with SessionLocal() as db:
        assert db.get(models.RecordOperation, first['auth_job_id']).state == 'completed'
        assert db.get(models.AuthSecret, first['auth_job_id']).result_encrypted
        assert db.get(models.AuthSecret, second['auth_job_id']).result_encrypted


def test_multiple_group_download_refreshes_without_consuming_successful_members(alice):
    from test_group_json_exports import seed_groups, preview, admit as admit_groups

    groups, records = seed_groups(2, 1)
    batch = admit_groups(alice, preview(alice, groups).json()).json()
    drain(RefreshableAuth, AuthGateway)
    with SessionLocal() as db:
        job = db.scalar(select(models.AuthJob).where(models.AuthJob.record_id == records[0]))
        item = {'auth_job_id': job.id}
    expire_result(item)
    path = f"/api/auth-batches/{batch['id']}/download"
    assert alice.post(path).status_code == 409
    with SessionLocal() as db:
        assert db.get(models.AuthSecret, item['auth_job_id']).workflow_encrypted
        assert db.get(models.AuthBatch, batch['id']).state == 'active'
    drain(RefreshableAuth, AuthGateway)
    result = alice.post(path)
    assert result.status_code == 200 and result.headers['x-export-count'] == '2'


def test_manual_retry_retains_successful_sibling_past_its_previous_deadline(alice, gateway, monkeypatch):
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    drain(RefreshableAuth, AuthGateway)
    first, second = parent['accounts'][0]['items']
    with SessionLocal() as db:
        db.get(models.RecordOperation, first['auth_job_id']).state = 'failed'
        db.get(models.AuthJob, first['auth_job_id']).error_code = 'authentication_failed'
        db.commit()
    retry = alice.post(f"/api/auth-batches/{first['auth_batch_id']}/items/{first['record_id']}/retry", json={'mode': 'resume'})
    assert retry.status_code == 202, retry.text
    instant = models.now() + timedelta(minutes=16)
    monkeypatch.setattr(auth_batches, 'now', lambda: instant)
    auth_jobs.expire_batches()
    with SessionLocal() as db:
        assert db.get(models.AuthBatch, second['auth_batch_id']).state == 'active'
        assert db.get(models.AuthSecret, second['auth_job_id']).result_encrypted


def test_expiry_maintenance_rechecks_reopened_range_before_clearing(alice, gateway, monkeypatch):
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    drain(RefreshableAuth, AuthGateway)
    first, second = parent['accounts'][0]['items']
    with SessionLocal() as db:
        db.get(models.RecordOperation, first['auth_job_id']).state = 'queued'
        db.get(models.AuthBatch, first['auth_batch_id']).completed_at = None
        db.commit()
    monkeypatch.setattr(auth_batches, 'now', lambda: models.now() + timedelta(minutes=16))
    auth_jobs.expire_batches()
    with SessionLocal() as db:
        assert db.get(models.AuthBatch, second['auth_batch_id']).state == 'active'
        assert db.get(models.AuthSecret, second['auth_job_id']).result_encrypted


def test_one_parent_download_queues_all_expired_users_together(alice, gateway):
    parent = drive(admit(alice, intent(quantity=2)).json(), alice)
    drain(RefreshableAuth, AuthGateway)
    items = parent['accounts'][0]['items']
    for item in items:
        expire_result(item)
    path = f"/api/provisioning-batches/{parent['id']}/download"
    assert alice.post(path).status_code == 409
    with SessionLocal() as db:
        for item in items:
            assert db.get(models.RecordOperation, item['auth_job_id']).state == 'queued'
            assert db.get(models.AuthJob, item['auth_job_id']).stage == 'refresh_requested'
            assert db.get(models.AuthSecret, item['auth_job_id']).workflow_encrypted
    drain(RefreshableAuth, AuthGateway)
    result = alice.post(path)
    assert result.status_code == 200 and result.headers['x-export-count'] == '2'
