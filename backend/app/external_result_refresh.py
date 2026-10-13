"""Queue expired pasted exports on the existing bounded authentication worker."""
import json
import time
from types import SimpleNamespace

from fastapi import HTTPException
from sqlalchemy import select

from .external_auth_models import ExternalExportItem
from .external_enterprise import ExternalEnterpriseAuth, ExternalGateway
from .identity_login import AuthError
from .security import audit, decrypt


def refresh_expired_results(db, batch, actor, rows):
    from .external_auth import ACTIVE, document

    candidates = []
    for item in rows:
        try:
            result = decrypt(item.result_encrypted)
            document(item, result, db=db, actor=actor)
            if result['expiresAt'] > time.time():
                continue
            configuration = json.loads(item.configuration)
            gateway = SimpleNamespace(account=ExternalGateway.account_for(item, configuration))
            adapter = ExternalEnterpriseAuth(gateway, checkpoint=lambda _: None)
            # Validate the original client expiry and identity before scheduling;
            # this performs no wire call or credential write in the request.
            adapter.result_refresh_state(item.username, result,
                expected_user_id=configuration.get('expected_user_id'))
        except (AuthError, HTTPException, KeyError, ValueError, TypeError):
            # The existing download validator handles invalid/nonrefreshable
            # results. Never turn an identity/config failure into a login retry.
            continue
        if item.cancel_requested or db.scalar(select(ExternalExportItem.id).where(
                ExternalExportItem.id != item.id,
                ExternalExportItem.principal_key == item.principal_key,
                ExternalExportItem.state.in_(ACTIVE)).limit(1)):
            raise HTTPException(409, '该用户已有其他认证任务，请先核对')
        candidates.append(item)
    if not candidates:
        return
    for item in candidates:
        item.state, item.stage = 'queued', 'refresh_requested'
        item.error = item.error_code = None
        item.workflow_encrypted = item.answer_encrypted = None
        item.next_poll_at = item.finished_at = item.lease_token = item.lease_until = None
    batch.completed_at = batch.download_expires_at = None
    audit(db, actor, 'external_export_refresh_requested', f'粘贴转换批次 {batch.id}；{len(candidates)} 个结果')
    db.commit()
    # Do not partially consume this download while another success is refreshing.
    raise HTTPException(409, '部分令牌已过期，正在使用原授权刷新；请等待原批次更新后再下载')
