"""Explicitly resume settled stopped intents without replaying completed writes."""
import json

from fastapi import HTTPException

from .aws import AwsFailure
from .models import GroupJob, ManagedGroup, NativeGroupOperation, Subscription, now


def resume_needed(row, current):
    if row.state != 'stopped' or not row.stop_requested_at:
        return False
    export_json = json.loads(row.exports)['json']
    return any(i.state == 'stopped' or (
        i.state == 'completed' and export_json and not i.auth_batch_id
    ) for i in current)


def resume_stopped(db, row):
    from .batches import update_batch_item
    from .group_subscription_state import member_activation, reserve_join
    from .provisioning_coordinator import active_group, guard, items, record_guard, transition

    current = items(db, row)
    if not resume_needed(row, current):
        raise HTTPException(409, '批次没有可恢复的停止项')
    actor, _ = guard(db, row, allow_stopped=True)
    group = db.get(ManagedGroup, row.group_id) if row.group_id else None
    job = db.get(GroupJob, row.group_job_id) if row.group_job_id else None
    op = db.get(NativeGroupOperation, row.native_operation_id) if row.native_operation_id else None
    if job and job.state != 'completed':
        if (job.state not in ('cancelled', 'failed') or job.phase != 'ready'
                or job.kind != 'create' or not group or group.remote_id
                or group.active_job_id not in (None, job.id)):
            raise HTTPException(409, '分组创建尚未核对完成或已变化，请先核对原任务')
    if op and op.state not in ('completed', 'failed', 'cancelled'):
        raise HTTPException(409, 'GROUP 开通尚未核对完成，请先核对原任务')
    if op and op.state == 'cancelled' and (op.phase == 'pending' or op.write_requested_at):
        raise HTTPException(409, '已发送的 GROUP 开通不能直接恢复，请先核对')
    if row.phase == 'sso' or op and op.state == 'completed':
        active_group(db, row)
    records = []
    for item in current:
        if item.state == 'completed':
            continue
        if item.state != 'stopped':
            raise HTTPException(409, '尚有未完成核对的成员，请先核对原任务')
        record = db.get(Subscription, item.record_id)
        if not record:
            continue
        if record.state != 'failed' or record.active_operation_id or record.sso_deleted_at:
            raise HTTPException(409, '成员仍在处理、待核对或已删除，不能直接恢复')
        try:
            record_guard(db, record, allow_stopped=True)
        except AwsFailure as exc:
            raise HTTPException(409, str(exc)) from None
        records.append((item, record))

    # The caller holds the write lock and commits the action and all resets
    # together. Any quota/guard failure rolls the whole recovery back.
    row.stop_requested_at = None
    if job and job.state != 'completed':
        job.state, job.error, job.finished_at = 'queued', None, None
        job.lease_token = job.lease_until = None
        group.state, group.error, group.active_job_id = 'creating', None, job.id
    if op and op.state in ('failed', 'cancelled'):
        row.native_request_key = f'numbered:{row.id}:resume:{op.id[:8]}'
        row.native_operation_id = row.native_grant_id = None
    for item, record in records:
        if record.step == 'group_membership_pending':
            record.step = 'group_membership'
        if group.active_job_id not in (None, record.id):
            raise HTTPException(409, '分组存在未完成任务')
        if not member_activation(db, record.id):
            reserve_join(db, group, record, actor, record.id)
        record.state, record.error, record.updated_at = 'queued', None, now()
        record.lease_token = record.lease_until = None
        update_batch_item(db, record, 'queued')
    for item in current:
        if item.state == 'stopped':
            item.state, item.phase, item.error = 'queued', 'admitted', None
            item.updated_at, item.finished_at = now(), None
    transition(row, row.phase)
