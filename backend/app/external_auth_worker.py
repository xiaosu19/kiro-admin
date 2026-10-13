"""Pasted exports share the existing bounded auth dispatcher and native adapters."""
import json
import uuid
from contextlib import ExitStack, contextmanager
from datetime import datetime, timedelta, timezone
from functools import partial

from fastapi import HTTPException
from sqlalchemy import and_, or_, select

from .account_dispatcher import account_fence, resource_fence
from .auth_automation import automate_challenge
from .auth_session_dispatcher import AuthSession
from .auth_principals import apply_managed_credential, validate_managed
from .config import settings
from .database import SessionLocal
from .external_auth import ACTIVE, clear, close_batch, document, finish_batch
from .external_auth_models import ExternalExportBatch, ExternalExportItem
from .external_enterprise import (
    ExternalEnterpriseAuth,
    ExternalGateway,
    discover_region,
)
from .identity_login import AuthError
from .models import Subscription, User, now
from .retry_policy import MAX_AUTOMATIC_RETRIES, RETRY_DELAYS, classify_failure
from .security import audit, decrypt, encrypt
from .captcha_errors import captcha_failure


class LeaseLost(Exception):
    pass


class Revoked(Exception):
    pass


def eligible():
    return or_(and_(ExternalExportItem.state.in_(('queued', 'polling')),
                   or_(ExternalExportItem.next_poll_at.is_(None), ExternalExportItem.next_poll_at <= now())),
               and_(ExternalExportItem.state == 'running', ExternalExportItem.lease_until <= now()))


def candidate_lanes():
    with SessionLocal() as db:
        return list(set(db.scalars(select(ExternalExportItem.lane_id).where(eligible()))))


def candidate_tasks():
    with SessionLocal() as db:
        rows = db.scalars(select(ExternalExportItem).where(eligible())
                          .order_by(ExternalExportItem.created_at, ExternalExportItem.position))
        lanes = {}
        for item in rows:
            account = json.loads(item.configuration).get('_managed_account_id', item.lane_id)
            lanes.setdefault(item.lane_id, (account, 'external', item.lane_id))
        return list(lanes.values())


def session_candidates():
    """Project scheduling metadata only, including future polls and retry waits."""
    with SessionLocal() as db:
        query = select(
            ExternalExportItem.lane_id, ExternalExportItem.configuration,
            or_(ExternalExportItem.workflow_encrypted.is_not(None), ExternalExportItem.retry_count > 0,
                ExternalExportItem.state.in_(('running', 'polling'))),
            eligible(), ExternalExportItem.state == 'running',
        ).where(ExternalExportItem.state.in_(('queued', 'running', 'polling'))).order_by(
            ExternalExportItem.created_at, ExternalExportItem.position)
        lanes = {}
        for lane, configuration, started, ready, running in db.execute(query):
            account = json.loads(configuration).get('_managed_account_id', lane)
            old = lanes.get(lane)
            lanes[lane] = AuthSession((account, 'external', lane),
                bool(started or old and old.started), bool(ready or old and old.ready),
                bool(running or old and old.running))
        return list(lanes.values())


@contextmanager
def login_fences(item):
    """Use the same account -> record -> login order as managed authentication."""
    configuration = json.loads(item.configuration)
    with ExitStack() as stack:
        fences = []
        if configuration.get('_managed_record_id'):
            fences.extend((account_fence(configuration['_managed_account_id'], shared=True),
                           resource_fence('record', configuration['_managed_record_id'])))
        fences.extend((resource_fence('login', item.principal_key), account_fence(item.lane_id)))
        for fence in fences:
            if not stack.enter_context(fence):
                yield False
                return
        yield True


def expire_batches():
    with SessionLocal() as db:
        rows = list(db.scalars(select(ExternalExportBatch).where(ExternalExportBatch.state == 'active',
            or_(ExternalExportBatch.expires_at <= now(), ExternalExportBatch.download_expires_at <= now())).limit(100)))
        for batch in rows:
            close_batch(db, batch, 'expired')
        db.commit()


def load(db, item_id, token):
    item = db.get(ExternalExportItem, item_id)
    if not item or item.state != 'running' or item.lease_token != token:
        raise LeaseLost()
    return item, db.get(ExternalExportBatch, item.batch_id)


def permitted(db, batch):
    actor = db.get(User, batch.actor_id)
    return (actor and actor.active and not actor.deleted_at and not actor.must_change_password
            and actor.session_version == batch.session_version and actor.role == batch.actor_role)


def scope_permitted(db, item, batch):
    if not permitted(db, batch):
        return False
    try:
        validate_managed(db, item, db.get(User, batch.actor_id))
        return True
    except HTTPException:
        return False


def authorize(item_id, token):
    with SessionLocal() as db:
        item, batch = load(db, item_id, token)
        if item.cancel_requested or batch.state != 'active' or batch.expires_at <= now() or not scope_permitted(db, item, batch):
            raise Revoked()


def checkpoint(item_id, token, value):
    state = decrypt(value.sealed_state)
    with SessionLocal() as db:
        item, batch = load(db, item_id, token)
        if state.get('username') != item.username or state.get('binding', {}).get('account_id') != item.id:
            raise LeaseLost()
        if value.credential:
            credential = decrypt(value.credential)
            if credential.get('username') != item.username:
                raise LeaseLost()
            # Save password outcomes even if cancellation occurred on the wire.
            item.credential_encrypted = value.credential
            apply_managed_credential(db, item, value.credential, value.event)
        if not item.cancel_requested and batch.state == 'active':
            item.workflow_encrypted = value.sealed_state
            if value.event == 'external_authorization':
                item.answer_encrypted = None
        item.revision = state['revision']
        item.stage = value.event if value.event in ('captcha_recognizing', 'captcha_verified') else state['stage']
        item.lease_until = now() + timedelta(seconds=settings.auth_worker_lease_seconds)
        db.commit()
    authorize(item_id, token)


def claim(lane_id, item_id=None):
    with SessionLocal() as db:
        item = db.scalar(select(ExternalExportItem).where(eligible(), ExternalExportItem.lane_id == lane_id,
                         ExternalExportItem.id == item_id if item_id else True)
                         .order_by(ExternalExportItem.created_at, ExternalExportItem.position).limit(1))
        if not item:
            return None
        token = str(uuid.uuid4())
        item.state, item.lease_token = 'running', token
        item.lease_until = now() + timedelta(seconds=settings.auth_worker_lease_seconds)
        db.commit()
        return item.id, token


def finish(item_id, token, progress):
    with SessionLocal() as db:
        item, batch = load(db, item_id, token)
        if item.cancel_requested or batch.state != 'active' or batch.expires_at <= now() or not scope_permitted(db, item, batch):
            item.state, item.error_code, item.error = 'cancelled', 'revoked', '批次已取消或登录权限已失效'
            clear(item)
        else:
            item.workflow_encrypted, item.revision, item.stage = progress.sealed_state, progress.revision, progress.stage
            item.answer_encrypted = None
            item.state = {'ready': 'queued', 'polling': 'polling', 'challenge': 'challenge', 'done': 'completed'}[progress.status]
            item.error_code = item.error = None
            if progress.status == 'done':
                document(item, progress.result, db=db, actor=db.get(User, batch.actor_id))
                item.result_encrypted = encrypt(progress.result)
                item.input_encrypted = item.workflow_encrypted = None
                audit(db, db.get(User, batch.actor_id), 'external_export_completed', f'粘贴转换任务 {item.id}')
            elif progress.status == 'challenge':
                automatic = decrypt(progress.sealed_state).get('captcha_automation', {})
                if automatic.get('status') == 'requires_action':
                    item.error_code, item.error = captcha_failure(automatic)
            item.next_poll_at = (datetime.fromtimestamp(progress.next_poll_at, timezone.utc).replace(tzinfo=None)
                                 if progress.next_poll_at is not None else None)
        item.lease_token = item.lease_until = None
        if item.state not in ACTIVE:
            item.finished_at = now()
        finish_batch(db, batch)
        db.commit()


def fail(item_id, token, error):
    with SessionLocal() as db:
        item, batch = load(db, item_id, token)
        if isinstance(error, AuthError) and error.credential:
            credential = decrypt(error.credential)
            if credential.get('username') == item.username:
                item.credential_encrypted = error.credential
                apply_managed_credential(db, item, error.credential)
        if item.cancel_requested or batch.state != 'active' or batch.expires_at <= now() or not scope_permitted(db, item, batch):
            item.state, item.error_code, item.error = 'cancelled', 'revoked', '批次已取消或登录权限已失效'
            clear(item)
        else:
            credential = decrypt(item.credential_encrypted) if item.credential_encrypted else {}
            uncertain = bool(getattr(error, 'uncertain', False)) or credential.get('status') in ('unknown', 'candidate')
            failure = classify_failure(error)
            if failure.transient and not failure.stop and not uncertain and item.retry_count < MAX_AUTOMATIC_RETRIES:
                item.retry_count += 1
                item.state, item.stage = 'polling', 'retry_wait'
                item.next_poll_at = now() + timedelta(seconds=RETRY_DELAYS[item.retry_count - 1])
                item.workflow_encrypted = None
                if credential.get('current'):
                    item.input_encrypted = encrypt({'password': credential['current']})
                item.error_code, item.error = 'transient_retry', f'连接暂时失败，等待第 {item.retry_count}/5 次自动重试'
            else:
                item.state = 'needs_review' if uncertain else 'failed'
                item.error_code = error.code if isinstance(error, AuthError) else 'authentication_failed'
                item.error = str(error) if isinstance(error, AuthError) else '账号认证失败，请核对账号或网络后重试'
                if isinstance(error, AuthError) and error.sealed_state:
                    item.workflow_encrypted = error.sealed_state
                item.finished_at = now()
            item.answer_encrypted = item.result_encrypted = None
        item.lease_token = item.lease_until = None
        finish_batch(db, batch)
        db.commit()


def run_one(*, lane_id=None, gateway_factory=None, auth_factory=None):
    lanes = [lane_id] if lane_id is not None else candidate_lanes()
    for lane in lanes:
        with SessionLocal() as db:
            selected = db.scalar(select(ExternalExportItem).where(eligible(), ExternalExportItem.lane_id == lane)
                                 .order_by(ExternalExportItem.created_at, ExternalExportItem.position).limit(1))
            if not selected:
                continue
            db.expunge(selected)
        with login_fences(selected) as acquired:
            if not acquired:
                continue
            found = claim(lane, selected.id)
            if not found:
                continue
            item_id, token = found
            adapter = gateway = None
            try:
                authorize(item_id, token)
                with SessionLocal() as db:
                    item, _batch = load(db, item_id, token)
                    actor_id = _batch.actor_id
                    configuration = json.loads(item.configuration)
                    password = decrypt(item.input_encrypted)['password'] if item.input_encrypted else None
                    managed = db.get(Subscription, configuration['_managed_record_id']) if configuration.get('_managed_record_id') else None
                    if managed and managed.credential_state == 'permanent' and managed.password_encrypted:
                        password = decrypt(managed.password_encrypted)
                    sealed = item.workflow_encrypted
                    answer = decrypt(item.answer_encrypted) if item.answer_encrypted else None
                    db.expunge(item)
                guard = partial(authorize, item_id, token)
                if not item.region:
                    region = discover_region(item.portal_url, guard)
                    with SessionLocal() as db:
                        current, _ = load(db, item_id, token)
                        current.region = region
                        db.commit()
                    item.region = region
                gateway = (gateway_factory or ExternalGateway)(item, configuration, guard)
                adapter = (auth_factory or ExternalEnterpriseAuth)(gateway,
                    checkpoint=partial(checkpoint, item_id, token))
                if sealed:
                    progress = adapter.advance(sealed, answer=answer)
                else:
                    progress = adapter.begin(item.username, password,
                        expected_user_id=configuration.get('expected_user_id'))
                progress = automate_challenge(adapter, progress, actor_id=actor_id)
                finish(item_id, token, progress)
            except LeaseLost:
                pass
            except Exception as error:
                try:
                    fail(item_id, token, error)
                except LeaseLost:
                    pass
            finally:
                if adapter:
                    adapter.close()
                if gateway:
                    gateway.close()
            return True
    return False
