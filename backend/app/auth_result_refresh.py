"""Refresh expired aggregate results through the original frozen OIDC job only."""

import time
from types import SimpleNamespace

from fastapi import HTTPException
from sqlalchemy import or_, update

from .models import AuthSecret, RecordOperation, Subscription, now
from .security import decrypt


def refresh_expired_results(db, batch, *, defer_commit=False):
    from .auth_batches import jobs, require_access
    from .auth_principals import active_external_login
    from .enterprise_auth import EnterpriseAuth
    from .identity_login import AuthError

    candidates = []
    for job in jobs(db, batch):
        record = db.get(Subscription, job.record_id)
        _, account = require_access(db, batch, record, job=job)
        operation, secret = db.get(RecordOperation, job.id), db.get(AuthSecret, job.id)
        if (operation.state == 'completed' and secret.result_encrypted
                and decrypt(secret.result_encrypted)['expiresAt'] <= time.time()):
            if (job.cancel_requested or record.active_operation_id not in (None, job.id)
                    or active_external_login(db, record)):
                raise HTTPException(409, '该用户已有其他认证或管理操作，请先核对')
            candidates.append((job, operation, secret, record, account))
    if not candidates:
        return False
    refreshed = 0
    for job, operation, secret, record, account in candidates:
        refreshable = False
        if secret.workflow_encrypted:
            try:
                saved = decrypt(secret.workflow_encrypted)
                adapter = EnterpriseAuth(SimpleNamespace(account=account), checkpoint=lambda _: None)
                registration = saved['registration']
                refreshable = (saved['version'] == 1 and saved['kind'] == 'enterprise'
                    and saved['binding'] == adapter._binding() and saved['status'] == 'done'
                    and not saved['inflight'] and saved['username'] == record.username
                    and saved['expected_user_id'] == record.sso_user_id
                    and registration['clientSecretExpiresAt'] > time.time()
                    and all(isinstance(registration.get(k), str) and registration[k]
                            for k in ('clientId', 'clientSecret'))
                    and bool(saved['result']['refreshToken']))
            except (AuthError, KeyError, TypeError, ValueError):
                refreshable = False
        secret.result_encrypted = secret.answer_encrypted = None
        if refreshable:
            changed = db.execute(update(Subscription).where(
                Subscription.id == record.id,
                Subscription.credential_revision == job.credential_revision,
                or_(Subscription.active_operation_id.is_(None), Subscription.active_operation_id == job.id),
            ).values(active_operation_id=job.id, updated_at=now()))
            if not changed.rowcount:
                raise HTTPException(409, '用户凭据或任务已变化，请刷新原批次')
            operation.state, operation.phase, operation.error = 'queued', 'ready', None
            operation.finished_at = operation.lease_token = operation.lease_until = None
            job.stage, job.error_code, job.next_poll_at = 'refresh_requested', None, None
            refreshed += 1
        else:
            # Keep the sealed evidence. A failed refresh never falls back to a
            # login, password reset or new client/device authorization.
            operation.state, operation.error, job.error_code = (
                'failed', '令牌已过期且原客户端无法刷新，请重新授权此用户', 'token_expired')
    batch.completed_at = batch.download_expires_at = None
    db.flush()
    if defer_commit:
        return True
    from .provisioning_auth_window import parent_download_window
    parent_download_window(db, batch, now())
    db.commit()
    raise HTTPException(409, '部分令牌已过期，正在使用原授权刷新；请等待原批次更新后再下载'
                        if refreshed else '部分令牌已过期且无法刷新，请核对失败用户后再下载成功结果')
