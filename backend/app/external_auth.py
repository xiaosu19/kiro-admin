"""Owner scoped admission, progress and sensitive download for pasted accounts."""
import hashlib
import hmac
import io
import json
import time
import uuid
import zipfile
from datetime import timedelta
from types import SimpleNamespace
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth_batches import AnswerInput
from .auth_export import account_json
from .auth_principals import login_key, managed_configuration, validate_managed
from .config import settings
from .database import get_db
from .external_auth_models import ExternalExportBatch, ExternalExportItem
from .external_export_input import InputError, parse_accounts
from .identity_login import AuthError
from .models import User, now
from .security import audit, decrypt, encrypt, get_user, lock_user_write
from .subscription_eligibility import has_observed_paid_entitlement

router = APIRouter(prefix='/api/external-auth-batches')
ACTIVE = ('queued', 'running', 'polling', 'challenge')
TERMINAL = ('completed', 'downloaded', 'failed', 'needs_review', 'cancelled', 'expired')


class PreviewInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    text: str = Field(min_length=1, max_length=512_000, repr=False)


class AdmissionInput(PreviewInput):
    request_key: str = Field(min_length=16, max_length=80)
    preview_fingerprint: str = Field(pattern=r'^[a-f0-9]{64}$')


def parse(text):
    try:
        return parse_accounts(text)
    except InputError as error:
        raise HTTPException(422, str(error)) from None


def digest(accounts):
    rows = [{k: v for k, v in a.public().items() if k != 'credential_state'} |
            {'password': a.password.get_secret_value()} for a in accounts]
    return hmac.new(settings.secret_key.encode(), json.dumps(rows, ensure_ascii=False, sort_keys=True).encode(), hashlib.sha256).hexdigest()


def principal(account):
    return login_key(account.directory, account.username)


def require_session(batch, actor):
    if actor.session_version != batch.session_version or actor.role != batch.actor_role:
        raise HTTPException(403, '原登录会话已失效，请重新提交账号')


def batch_owned(db, batch_id, actor):
    batch = db.get(ExternalExportBatch, batch_id)
    if not batch or batch.actor_id != actor.id:
        raise HTTPException(404, '粘贴转换批次不存在')
    return batch


def item_owned(db, batch, item_id):
    item = db.get(ExternalExportItem, item_id)
    if not item or item.batch_id != batch.id:
        raise HTTPException(404, '粘贴转换任务不存在')
    return item


def items(db, batch):
    return list(db.scalars(select(ExternalExportItem).where(ExternalExportItem.batch_id == batch.id)
                           .order_by(ExternalExportItem.position)))


def clear(item):
    item.input_encrypted = item.workflow_encrypted = item.answer_encrypted = item.result_encrypted = None
    # Keep only the independent credential checkpoint: an in-flight first-login
    # password change may have succeeded. Its owner can download recovery data.


def close_batch(db, batch, state):
    batch.state = state
    for item in items(db, batch):
        item.cancel_requested = True
        if item.state != 'running':
            if item.state in ACTIVE:
                item.state, item.finished_at = state, now()
            clear(item)


def finish_batch(db, batch):
    if batch.state != 'active':
        return
    if all(i.state in TERMINAL for i in items(db, batch)) and batch.completed_at is None:
        batch.completed_at = now()
        batch.download_expires_at = min(batch.expires_at, now() + timedelta(seconds=settings.auth_download_ttl_seconds))


def live(db, batch):
    if batch.state == 'active' and (batch.expires_at <= now() or
                                  batch.download_expires_at and batch.download_expires_at <= now()):
        close_batch(db, batch, 'expired')
        db.commit()
    if batch.state != 'active':
        raise HTTPException(410, '批次已取消、下载或过期，请重新提交')


def can_retry_challenge(item):
    from .auth_retry import restartable_challenge
    if item.state != 'challenge' or item.cancel_requested or not item.input_encrypted:
        return False
    credential = decrypt(item.credential_encrypted) if item.credential_encrypted else {}
    return credential.get('status') not in ('unknown', 'candidate') and restartable_challenge(item.workflow_encrypted)


def view(db, batch, detail=True):
    rows = items(db, batch)
    counts = {state: sum(i.state == state for i in rows) for state in ACTIVE + TERMINAL}
    result = {k: getattr(batch, k) for k in ('id', 'actor_id', 'state', 'created_at', 'expires_at',
                                          'completed_at', 'download_expires_at', 'request_key')}
    result.update(total=len(rows), states=counts, success_count=counts['completed'] + counts['downloaded'],
                  failure_count=sum(counts[s] for s in ('failed', 'needs_review', 'cancelled', 'expired')),
                  download_ready=batch.state == 'active' and counts['completed'] > 0)
    if detail:
        result['items'] = [{k: getattr(i, k) for k in ('id', 'position', 'username', 'portal_url', 'region', 'state',
                           'stage', 'error_code', 'error', 'revision', 'retry_count', 'next_poll_at', 'cancel_requested')}
                           | {'credential_recovery_available': bool(i.credential_encrypted),
                              'can_retry_challenge': can_retry_challenge(i)} for i in rows]
    return result


@router.post('/preview')
def preview(body: PreviewInput, actor: User = Depends(get_user)):
    accounts = parse(body.text)
    return {'total': len(accounts), 'accounts': [a.public() for a in accounts], 'preview_fingerprint': digest(accounts)}


@router.post('', status_code=202)
def admit(body: AdmissionInput, request: Request, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    accounts = parse(body.text)
    fingerprint = digest(accounts)
    if not hmac.compare_digest(fingerprint, body.preview_fingerprint):
        raise HTTPException(409, '输入已变化，请重新预览')
    # The principal lookup and managed binding freeze share one writer lock,
    # including callers outside the HTTP dependency's admission transaction.
    lock_user_write(db, actor, actor.session_version)
    old = db.scalar(select(ExternalExportBatch).where(ExternalExportBatch.actor_id == actor.id,
                                                    ExternalExportBatch.request_key == body.request_key))
    if old:
        if old.payload_hash != fingerprint:
            raise HTTPException(409, '原请求标识已用于不同的输入')
        return view(db, old)
    keys = [principal(a) for a in accounts]
    if db.scalar(select(ExternalExportItem.id).where(ExternalExportItem.principal_key.in_(keys),
                                                    ExternalExportItem.state.in_(ACTIVE)).limit(1)):
        raise HTTPException(409, '所选账号已有认证任务，请等待原任务结束或取消后重试')
    configurations = [managed_configuration(db, account, actor) for account in accounts]
    batch = ExternalExportBatch(id=str(uuid.uuid4()), actor_id=actor.id, actor_role=actor.role,
        session_version=actor.session_version, request_key=body.request_key, payload_hash=fingerprint,
        expires_at=now() + timedelta(hours=settings.auth_batch_ttl_hours))
    db.add(batch)
    db.flush()
    for position, (account, key, configuration) in enumerate(zip(accounts, keys, configurations), 1):
        db.add(ExternalExportItem(id=str(uuid.uuid4()), batch_id=batch.id, position=position,
            principal_key=key, lane_id=-(int(key[:12], 16) + 1), username=configuration['username'],
            portal_url=account.portal_url, region=configuration['region'], configuration=json.dumps(configuration),
            input_encrypted=encrypt({'password': account.password.get_secret_value()})))
    audit(db, actor, 'external_export_admitted', f'粘贴转换批次 {batch.id}；{len(accounts)} 个账号', request=request)
    db.commit()
    return view(db, batch)


@router.get('')
def history(page: int = Query(1, ge=1), request_key: str | None = Query(None, min_length=16, max_length=80),
            actor: User = Depends(get_user), db: Session = Depends(get_db)):
    query = select(ExternalExportBatch).where(ExternalExportBatch.actor_id == actor.id)
    if request_key:
        query = query.where(ExternalExportBatch.request_key == request_key)
    rows = list(db.scalars(query
                          .order_by(ExternalExportBatch.created_at.desc()).offset((page - 1) * 30).limit(30)))
    return {'items': [view(db, row, detail=False) for row in rows], 'page': page}


@router.get('/{batch_id}')
def progress(batch_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    batch = batch_owned(db, batch_id, actor)
    return view(db, batch)


@router.post('/{batch_id}/cancel')
def cancel(batch_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    batch = batch_owned(db, batch_id, actor)
    if batch.state == 'active':
        close_batch(db, batch, 'cancelled')
        audit(db, actor, 'external_export_cancelled', f'粘贴转换批次 {batch.id}')
        db.commit()
    return view(db, batch)


@router.post('/{batch_id}/items/{item_id}/retry', status_code=202)
def retry(batch_id: str, item_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    from .external_auth_worker import login_fences
    batch = batch_owned(db, batch_id, actor)
    item = item_owned(db, batch, item_id)
    with login_fences(item) as acquired:
        if not acquired:
            raise HTTPException(409, '当前登录步骤正在结束，请稍后重试')
        return retry_locked(batch_id, item_id, actor, db)


def retry_locked(batch_id, item_id, actor, db):
    batch = batch_owned(db, batch_id, actor)
    live(db, batch)
    require_session(batch, actor)
    item = item_owned(db, batch, item_id)
    validate_managed(db, item, actor)
    if (item.state not in ('failed', 'needs_review') and not can_retry_challenge(item)) or item.cancel_requested or not item.input_encrypted:
        raise HTTPException(409, '此项不可恢复，请核对后重新粘贴账号')
    credential = decrypt(item.credential_encrypted) if item.credential_encrypted else {}
    if credential.get('status') in ('unknown', 'candidate'):
        raise HTTPException(409, '密码变更结果待核对，请下载凭据恢复信息并在官方入口核对后重新提交')
    if db.scalar(select(ExternalExportItem.id).where(ExternalExportItem.id != item.id,
            ExternalExportItem.principal_key == item.principal_key, ExternalExportItem.state.in_(ACTIVE)).limit(1)):
        raise HTTPException(409, '同一账号已有其他认证任务，请先处理或取消原任务')
    if credential.get('current'):
        item.input_encrypted = encrypt({'password': credential['current']})
    item.state, item.stage, item.error, item.error_code = 'queued', 'admitted', None, None
    item.workflow_encrypted = item.answer_encrypted = None
    item.finished_at = item.next_poll_at = None
    batch.completed_at = batch.download_expires_at = None
    audit(db, actor, 'external_export_retry', f'粘贴转换任务 {item.id}')
    db.commit()
    return view(db, batch)


def exported_record(item, result):
    password = result.get('password')
    identity = json.loads(item.configuration).get('_managed_record_id', item.id)
    return SimpleNamespace(id=identity, username=item.username, email=result.get('usage', {}).get('userInfo', {}).get('email'),
        sso_user_id=result['userId'], created_at=item.created_at, credential_state='permanent' if password else 'unknown',
        password_encrypted=encrypt(password) if password else None, sso_deleted_at=None)


def document(item, result, *, db=None, actor=None):
    from .enterprise_auth import verified_external_identity
    configuration = json.loads(item.configuration)
    if db is not None:
        validate_managed(db, item, actor)
    if (result.get('startUrl') != item.portal_url or result.get('authRegion') != item.region
            or result.get('identityStoreId') != configuration['directory']
            or configuration.get('expected_user_id') not in (None, result.get('userId'))
            or configuration.get('profile_arn') and (result.get('profile') or {}).get('arn') != configuration['profile_arn']
            or configuration.get('api_region') and result.get('apiRegion') != configuration['api_region']
            or not verified_external_identity(result.get('usage'), configuration['directory'], result.get('userId'))):
        raise ValueError('export identity mismatch')
    if not configuration.get('_managed_record_id') and not has_observed_paid_entitlement(result.get('usage')):
        raise AuthError('paid_entitlement_unconfirmed')
    return account_json(exported_record(item, result), result)


@router.post('/{batch_id}/download')
def download(batch_id: str, format: Literal['zip', 'json'] = 'zip', item_id: str | None = None,
             actor: User = Depends(get_user), db: Session = Depends(get_db)):
    lock_user_write(db, actor, actor.session_version)
    batch = batch_owned(db, batch_id, actor)
    live(db, batch)
    require_session(batch, actor)
    rows = [i for i in items(db, batch) if i.state == 'completed' and i.result_encrypted and
            (item_id is None or i.id == item_id)]
    if not rows or format == 'json' and len(rows) != 1:
        raise HTTPException(409, '没有可下载的对应成功结果，单个 JSON 需选择一个成功账号')
    from .external_result_refresh import refresh_expired_results
    refresh_expired_results(db, batch, actor, rows)
    rows = [i for i in rows if i.state == 'completed']
    if not rows:
        db.commit()
        raise HTTPException(409, '部分令牌已过期，正在使用原授权刷新；请等待原批次更新后再下载')
    documents = []
    for item in rows:
        try:
            result = decrypt(item.result_encrypted)
            data = document(item, result, db=db, actor=actor)
            if not isinstance(result.get('expiresAt'), (int, float)) or result['expiresAt'] <= time.time():
                raise ValueError('export expired')
            documents.append((item, data))
        except AuthError as error:
            item.state, item.error_code, item.error = 'failed', error.code, str(error)
            item.result_encrypted = None
        except (ValueError, TypeError, KeyError, HTTPException):
            item.state, item.error_code, item.error = 'needs_review', 'export_invalid', 'Token 已过期或导出身份核对未通过，请重新粘贴账号'
            item.result_encrypted = None
    if not documents:
        db.commit()
        raise HTTPException(409, '没有通过身份和有效期校验的成功结果，请重新粘贴账号')
    if format == 'json':
        content = json.dumps(documents[0][1], ensure_ascii=False, indent=2).encode()
        media, filename = 'application/json', 'kiro-account.json'
    else:
        from .provisioning_exports import archive_filename, safe_component, unique_components
        filename = archive_filename(batch.id)
        folder = filename[:-4]
        names = unique_components([(item.id, safe_component(item.username, 'user-' + item.id)) for item, _ in documents])
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
            for item, data in documents:
                archive.writestr(folder + '/' + names[item.id] + '.json', json.dumps(data, ensure_ascii=False, indent=2).encode())
        content, media = output.getvalue(), 'application/zip'
    for item, _ in documents:
        item.state = 'downloaded'
        clear(item)
        # The confirmed password is now present in the sensitive downloaded JSON.
        if item.credential_encrypted and decrypt(item.credential_encrypted).get('status') == 'confirmed':
            item.credential_encrypted = None
    if all(i.state in ('downloaded', 'cancelled', 'expired') for i in items(db, batch)):
        close_batch(db, batch, 'downloaded')
    else:
        finish_batch(db, batch)
    audit(db, actor, 'external_export_downloaded', f'粘贴转换批次 {batch.id}；{len(documents)} 个结果')
    db.commit()
    return Response(content, media_type=media, headers={'Content-Disposition': f'attachment; filename="{filename}"',
                    'Cache-Control': 'no-store', 'X-Export-Count': str(len(documents)),
                    'X-Excluded-Count': str(len(items(db, batch)) - len(documents))})


@router.post('/{batch_id}/items/{item_id}/credential-recovery')
def credentials(batch_id: str, item_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    batch = batch_owned(db, batch_id, actor)
    item = item_owned(db, batch, item_id)
    validate_managed(db, item, actor, check_revision=False, check_operations=False, check_subscription=False)
    if not item.credential_encrypted:
        raise HTTPException(404, '没有保存的凭据恢复信息')
    credential = decrypt(item.credential_encrypted)
    content = {'username': item.username, 'portal_url': item.portal_url,
               **{k: credential.get(k) for k in ('status', 'current', 'candidate')}}
    audit(db, actor, 'external_credential_recovery_downloaded', f'粘贴转换任务 {item.id}')
    db.commit()
    return Response(json.dumps(content, ensure_ascii=False, indent=2), media_type='application/json',
                    headers={'Content-Disposition': 'attachment; filename="credential-recovery.json"', 'Cache-Control': 'no-store'})


def current_challenge(db, batch, item, actor):
    from .external_enterprise import ExternalEnterpriseAuth, ExternalGateway

    live(db, batch)
    require_session(batch, actor)
    validate_managed(db, item, actor)
    if item.state != 'challenge' or item.cancel_requested or not item.workflow_encrypted:
        raise HTTPException(409, '当前没有待处理验证，请刷新任务')
    state = decrypt(item.workflow_encrypted)
    challenge = state.get('challenge')
    if not challenge or time.time() >= challenge['expires_at']:
        item.state, item.error_code, item.error = 'failed', 'expired', '验证已过期，请重试或重新粘贴账号'
        item.finished_at = now()
        finish_batch(db, batch)
        db.commit()
        raise HTTPException(410, '验证已过期')
    adapter = ExternalEnterpriseAuth(ExternalGateway(item, json.loads(item.configuration), lambda: None), checkpoint=lambda value: None)
    public = adapter._public_challenge(state)
    if public.get('kind') in ('requires_action', 'ams'):
        public = {k: challenge[k] for k in ('id', 'revision', 'expires_at')} | {'kind': 'manual_action', 'username': item.username}
    return state, challenge, public


@router.get('/{batch_id}/items/{item_id}/challenge')
def challenge(batch_id: str, item_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    batch = batch_owned(db, batch_id, actor)
    item = item_owned(db, batch, item_id)
    _, _, public = current_challenge(db, batch, item, actor)
    return {'operation_id': item.id, **public}


@router.post('/{batch_id}/items/{item_id}/resume', status_code=202)
def answer(batch_id: str, item_id: str, body: AnswerInput, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    batch = batch_owned(db, batch_id, actor)
    item = item_owned(db, batch, item_id)
    _, challenge, public = current_challenge(db, batch, item, actor)
    expected = {'image': 'guess', 'aws_authorization': 'continue_authorization'}.get(public['kind'])
    value = body.model_dump(exclude_none=True)
    if (expected is None or (body.challenge_id, body.revision) != (challenge['id'], challenge['revision'])
            or set(value) != {'challenge_id', 'revision', expected}):
        raise HTTPException(409, '验证形式或版本不匹配，请刷新任务')
    item.answer_encrypted = encrypt(value)
    item.state, item.next_poll_at = 'queued', None
    db.commit()
    return view(db, batch)


@router.get('/{batch_id}/items/{item_id}/image')
def image(batch_id: str, item_id: str, revision: int = Query(..., ge=1), actor: User = Depends(get_user), db: Session = Depends(get_db)):
    from .external_auth_worker import login_fences, scope_permitted
    from .external_enterprise import ExternalEnterpriseAuth, ExternalGateway
    from .identity_login import AuthError

    batch = batch_owned(db, batch_id, actor)
    item = item_owned(db, batch, item_id)
    _, challenge, public = current_challenge(db, batch, item, actor)
    if public['kind'] != 'image' or challenge['revision'] != revision:
        raise HTTPException(409, '图片验证版本不匹配')
    configuration, sealed, owner_batch_id = json.loads(item.configuration), item.workflow_encrypted, batch.id
    db.expunge(item)
    db.rollback()
    def guard():
        from .database import SessionLocal
        with SessionLocal() as session:
            current = session.get(ExternalExportItem, item.id)
            owner_batch = session.get(ExternalExportBatch, owner_batch_id)
            if (not current or current.state != 'challenge' or current.cancel_requested
                    or not owner_batch or not scope_permitted(session, current, owner_batch) or owner_batch.state != 'active'
                    or owner_batch.expires_at <= now()):
                raise AuthError('expired')
    with login_fences(item) as acquired:
        if not acquired:
            raise HTTPException(409, '当前验证正在处理，请稍后重试')
        adapter = ExternalEnterpriseAuth(ExternalGateway(item, configuration, guard), checkpoint=lambda value: None)
        try:
            result = adapter.challenge_image(sealed, revision)
            return Response(result.content, media_type=result.content_type, headers={'Cache-Control': 'no-store'})
        except AuthError as error:
            raise HTTPException(409, str(error)) from None
        finally:
            adapter.close()
