"""Keep linked results until the whole frozen provisioning range can download."""

import json
from datetime import timedelta

from sqlalchemy import select, update

from .config import settings
from .models import AuthBatch, ProvisioningAccountBatch, ProvisioningItem, RecordOperation


def parent_download_window(db, batch, instant):
    """Return whether this batch belongs to a parent, including unadmitted users.

    Only the short download window is deferred. Every child retains its absolute
    authentication expiry, so waiting cannot keep credentials indefinitely.
    """
    parent_id = db.scalar(select(ProvisioningAccountBatch.batch_id).join(
        ProvisioningItem, ProvisioningItem.account_batch_id == ProvisioningAccountBatch.id
    ).where(ProvisioningItem.auth_batch_id == batch.id).limit(1))
    if not parent_id:
        return False
    children = list(db.scalars(select(ProvisioningAccountBatch).where(
        ProvisioningAccountBatch.batch_id == parent_id)))
    requested = [child.id for child in children if json.loads(child.exports)['json']]
    rows = list(db.execute(select(
        ProvisioningItem.state, ProvisioningItem.export_error,
        ProvisioningItem.auth_batch_id, AuthBatch.state, AuthBatch.expires_at,
        RecordOperation.state,
    ).outerjoin(AuthBatch, AuthBatch.id == ProvisioningItem.auth_batch_id)
      .outerjoin(RecordOperation, RecordOperation.id == ProvisioningItem.auth_job_id)
      .where(ProvisioningItem.account_batch_id.in_(requested))))
    waiting = any(
        (auth_id is None and not error and state not in ('failed', 'stopped'))
        or (auth_id is not None and auth_state == 'active' and expiry > instant
            and operation_state in ('queued', 'running', 'challenge', 'polling'))
        for state, error, auth_id, auth_state, expiry, operation_state in rows
    )
    auth_ids = {row[2] for row in rows if row[2]}
    if waiting:
        # A refresh can reopen a previously terminal range. Retain all of its
        # successful siblings until the refresh finishes, without consuming them.
        db.execute(update(AuthBatch).where(
            AuthBatch.id.in_(auth_ids), AuthBatch.state == 'active'
        ).values(download_expires_at=None))
        return True
    siblings = list(db.scalars(select(AuthBatch).where(
        AuthBatch.id.in_(auth_ids), AuthBatch.state == 'active')))
    deadline = min([instant + timedelta(seconds=settings.auth_download_ttl_seconds)]
                   + [s.download_expires_at for s in siblings if s.download_expires_at])
    for sibling in siblings:
        if sibling.download_expires_at is None:
            sibling.download_expires_at = min(sibling.expires_at, deadline)
    return True
