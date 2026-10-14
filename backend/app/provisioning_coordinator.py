"""Short, transactional transitions linking numbered intent to existing workers.

No remote mutations or second activation ledger live here. Every admitted child
and its link commit together; deterministic keys additionally recover old links.
"""
import json

from fastapi import HTTPException
from sqlalchemy import select, text

from .account_dispatcher import run_fenced
from .aws import AwsFailure
from .database import SessionLocal
from .models import (
    AwsAccount, AuthJob, GroupJob, LifecycleBatchItem,
    ManagedGroup, NativeGroupGrant, NativeGroupOperation, Plan, ProvisioningAccountBatch,
    ProvisioningBatch, ProvisioningItem, Subscription, User, now,
)
from .provisioning_batches import configuration_signature, child_rows
from .batches import require_account
from .proxies import ProxyUnavailable, proxy_selection

RUNNABLE = ('queued', 'running', 'stopping')


def members_first(row):
    """Persisted pre-upgrade batches retain their original paid-write order."""
    return json.loads(row.snapshot).get('subscription_order') == 'members_first'


def items(db, row):
    return list(db.scalars(select(ProvisioningItem).where(
        ProvisioningItem.account_batch_id == row.id).order_by(ProvisioningItem.position)))


def guard(db, row, *, recovering=False, allow_stopped=False):
    """The original authorizer and transport remain authoritative for followers."""
    parent = db.get(ProvisioningBatch, row.batch_id)
    account = db.get(AwsAccount, row.aws_account_id, populate_existing=True)
    if not account or configuration_signature(db, account) != row.config_hash:
        raise HTTPException(409, 'AWS 账号或绑定代理配置已变化，请恢复原配置后核对')
    try:
        account._proxy_selection = proxy_selection(db, account.proxy_id)
        if account._proxy_selection is None:
            raise ProxyUnavailable()
    except ProxyUnavailable:
        raise HTTPException(409, '请先绑定可用代理') from None
    if recovering:
        return db.get(User, parent.actor_id), account
    actor = db.get(User, parent.actor_id, populate_existing=True)
    if (not actor or not actor.active or actor.deleted_at or actor.must_change_password
            or actor.role != parent.actor_role or actor.session_version != parent.session_version):
        raise HTTPException(409, '原操作者角色、登录会话或权限已变化，不能继续批次开通')
    require_account(db, actor, account)
    if row.stop_requested_at and not allow_stopped:
        raise HTTPException(409, '批次已停止；不再提交新的分组、SSO 或成员授权')
    plan = db.get(Plan, row.plan_id)
    if not plan or not plan.active or plan.deleted_at or plan.subscription_type != row.subscription_type:
        raise HTTPException(409, '冻结的目标套餐已停用或变更')
    if row.group_id:
        from .groups import scope
        group = db.get(ManagedGroup, row.group_id)
        if (not group or group.deleted_at or group.owner_id != parent.actor_id
                or group.aws_account_id != row.aws_account_id or group.aws_scope != scope(account)):
            raise HTTPException(409, '分组归属或 AWS 身份中心已变化')
    return actor, account


def record_guard(db, record, *, recovering=False, allow_stopped=False):
    item = db.get(ProvisioningItem, record.id)
    if item and item.state != 'completed':
        row = db.get(ProvisioningAccountBatch, item.account_batch_id)
        try:
            guard(db, row, recovering=recovering, allow_stopped=allow_stopped)
            if not recovering:
                from .group_subscription_state import live_grant
                grant = live_grant(db, row.group_id)
                preparing = members_first(row) and row.native_operation_id is None
                if preparing and grant:
                    raise HTTPException(409, '分组在成员准备完成前出现新的订阅授权，请先核对')
                if not preparing and (not grant or grant.id != row.native_grant_id or grant.state != 'active'
                        or grant.plan_id != row.plan_id or grant.subscription_type != row.subscription_type
                        or (grant.stop_at and grant.stop_at <= now())):
                    raise HTTPException(409, '原编号批次的 GROUP 授权或套餐已变化，不能加入新的授权；请核对原批次')
            if (record.username, record.email, record.owner_id, record.aws_account_id, record.group_id) != (
                    item.username, item.email, db.get(ProvisioningBatch, row.batch_id).actor_id,
                    row.aws_account_id, row.group_id):
                raise HTTPException(409, '编号 SSO 的冻结身份或归属已变化')
        except HTTPException as exc:
            raise AwsFailure(str(exc.detail)) from None


def job_guard(db, job, *, recovering=False):
    key = json.loads(job.payload).get('provisioning_account_id')
    if key:
        row = db.get(ProvisioningAccountBatch, key)
        try:
            if not row:
                raise HTTPException(409, '编号批次已不存在')
            guard(db, row, recovering=recovering)
        except HTTPException as exc:
            raise AwsFailure(str(exc.detail)) from None


def aggregate(db, parent):
    rows = child_rows(db, parent)
    states = {r.state for r in rows}
    if states <= {'completed'}:
        state = 'completed'
    elif states <= {'completed', 'stopped'}:
        state = 'stopped'
    elif states & set(RUNNABLE):
        state = 'running'
    elif 'needs_review' in states:
        state = 'needs_review'
    else:
        state = 'paused'
    parent.state = state
    parent.phase = 'done' if state in ('completed', 'stopped') else 'accounts'
    parent.error = next((r.error for r in rows if r.error), None)
    parent.updated_at = now()
    parent.finished_at = now() if state in ('completed', 'stopped') else None


def transition(row, phase, state='running', error=None):
    row.phase, row.state, row.error, row.updated_at = phase, state, error, now()
    row.finished_at = now() if state in ('completed', 'stopped') else None


def sync_items(db, row):
    from .models import GroupMemberActivation

    current = items(db, row)
    ids = [i.record_id for i in current]
    records = {r.id: r for r in db.scalars(select(Subscription).where(Subscription.id.in_(ids)))}
    activations = {}
    for activation in db.scalars(select(GroupMemberActivation).where(
            GroupMemberActivation.record_id.in_(ids), GroupMemberActivation.grant_id == row.native_grant_id,
            GroupMemberActivation.counted.is_(True)
            ).order_by(GroupMemberActivation.created_at)):
        activations.setdefault(activation.record_id, activation)
    for item in current:
        record = records.get(item.record_id)
        if not record or item.state == 'completed':
            continue
        activation = activations.get(record.id)
        item.sso_batch_id = record.batch_id
        if activation:
            item.state, item.phase, item.error = 'completed', 'group_access', None
            item.finished_at = item.finished_at or activation.activated_at
        elif record.state == 'completed' and members_first(row) and not record.counted:
            item.state, item.phase, item.error = 'prepared', 'group_access', None
        elif record.state == 'completed':
            item.state, item.phase = 'needs_review', 'group_access'
            item.error = '未确认原编号批次的 GROUP 成员授权，请核对原授权历史'
        else:
            item.state, item.phase, item.error = record.state, record.step, record.error
        item.updated_at = record.updated_at


def stop_unsent(db, row):
    """Release only proved-unsent children; active sends retain their leases."""
    from .group_subscription_state import fail_join, quota_finish
    from .group_subscription_worker import release_locks
    from .models import GroupMemberActivation
    from .worker import PENDING_STEPS
    from .automatic_retries import settle_retry
    pending = False
    running = False
    job = db.get(GroupJob, row.group_job_id) if row.group_job_id else None
    if job and job.state in ('queued', 'running', 'needs_review'):
        if job.phase == 'pending' or job.state == 'running':
            pending = True
            running = running or job.state in ('queued', 'running')
        else:
            job.state, job.finished_at = 'cancelled', now()
            settle_retry(db, 'group', job.id)
            group = db.get(ManagedGroup, job.group_id)
            group.state, group.active_job_id = 'failed', None
    op = db.get(NativeGroupOperation, row.native_operation_id) if row.native_operation_id else None
    if op and op.state in ('queued', 'running', 'needs_review'):
        if op.phase == 'pending' or op.state == 'running':
            pending = True
            running = running or op.state in ('queued', 'running')
        else:
            op.state, op.finished_at = 'cancelled', now()
            settle_retry(db, 'native', op.id)
            db.get(NativeGroupGrant, op.grant_id).state = 'failed'
            for activation in db.scalars(select(GroupMemberActivation).where(GroupMemberActivation.operation_id == op.id)):
                quota_finish(db, activation, False)
            release_locks(db, op, db.get(ManagedGroup, op.group_id))
    for item in items(db, row):
        if item.state in ('completed', 'prepared'):
            continue
        record = db.get(Subscription, item.record_id)
        if record and (record.state == 'running' or
                (record.state != 'failed' and record.step in PENDING_STEPS) or record.active_operation_id):
            pending = True
            running = running or record.state in ('queued', 'running') or bool(record.active_operation_id)
            continue
        if record and record.state in ('queued', 'failed', 'needs_review'):
            settle_retry(db, 'sso', record.id)
            fail_join(db, record, False)
            group = db.get(ManagedGroup, record.group_id)
            if group.active_job_id == record.id:
                group.active_job_id = None
            record.state, record.error = 'failed', '批次已停止，尚未发送的成员授权已释放'
            from .batches import update_batch_item
            update_batch_item(db, record, 'failed', record.error)
        item.state, item.phase, item.error = 'stopped', 'unsent', None
        item.updated_at = item.finished_at = now()
    if pending:
        transition(row, row.phase, 'stopping' if running else 'needs_review', '批次已停止后续提交；已发送或结果不明的子任务需只读核对')
    else:
        transition(row, row.phase, 'stopped')


def validate_existing(db, row, actor):
    """Before first use, compare frozen identities and original group revision."""
    from .group_subscription_state import digest, live_grant
    from .group_subscriptions import members
    from .provisioning_batches import fields
    snap = json.loads(row.snapshot)
    group = db.get(ManagedGroup, row.group_id)
    if (group.revision != snap['group']['revision'] or group.state != 'ready'
            or group.active_job_id or group.remote_id != snap['group']['remote_id']):
        raise HTTPException(409, '原分组版本、远端身份或状态已变化，请先核对')
    records = members(db, group)
    if {r.id for r in records} != {m['id'] for m in snap['members']}:
        raise HTTPException(409, '原分组的已有成员已变化，请先核对')
    for record in records:
        saved = next(m for m in snap['members'] if m['id'] == record.id)
        if digest(fields(record)) != saved['record_hash']:
            raise HTTPException(409, '原分组的已有成员快照已变化，请先核对')
    grant = live_grant(db, group.id)
    if (grant.id if grant else None) != (snap['grant']['id'] if snap['grant'] else None):
        raise HTTPException(409, '原分组的 GROUP 授权已变化，请先核对')


def active_group(db, row):
    from .group_subscription_state import live_grant
    grant = live_grant(db, row.group_id)
    original = json.loads(row.snapshot)['grant']
    expected_id = row.native_grant_id or (original['id'] if original else None)
    if expected_id and (not grant or grant.id != expected_id):
        raise HTTPException(409, '原编号批次的 GROUP 授权已变化，不能加入新的授权；请核对原批次')
    if (not grant or grant.state != 'active' or grant.plan_id != row.plan_id
            or grant.subscription_type != row.subscription_type or not grant.activated_at
            or (grant.stop_at and grant.stop_at <= now())):
        raise HTTPException(409, '原生 GROUP 授权未确认、套餐不兼容或已到停止时间；请使用分组订阅历史核对')
    group = db.get(ManagedGroup, row.group_id)
    if group.state != 'ready' or group.active_job_id:
        raise HTTPException(409, '分组存在未完成任务，请先核对')
    row.native_grant_id = grant.id
    return grant


def admit_exports(db, row):
    """Export admission failure never changes confirmed provisioning outcome."""
    from .auth_batches import BatchInput, admit_auth_batch

    if json.loads(row.exports)['json']:
        # At most 100 frozen children are admitted before browsers can start.
        # A separate savepoint retains per-item refusal/skip semantics.
        for item in (i for i in items(db, row) if not i.auth_batch_id and not i.export_error):
            try:
                with db.begin_nested():
                    actor, _ = guard(db, row)
                    active_group(db, row)
                    record = db.get(Subscription, item.record_id)
                    record_guard(db, record)
                    if not record.password_encrypted or record.credential_state == 'unknown':
                        raise HTTPException(409, '没有可用登录凭据，请明确恢复密码后仅重试导出')
                    batch = admit_auth_batch(db, actor, BatchInput(kind='json_export',
                        group_id=row.group_id, record_ids=[item.record_id],
                        request_key=f'numbered:{item.record_id}:json'))
                    db.flush()
                    job = db.scalar(select(AuthJob).where(AuthJob.batch_id == batch.id))
                    item.auth_batch_id, item.auth_job_id = batch.id, job.id
                    item.updated_at = now()
            except (HTTPException, AwsFailure) as exc:
                item.export_error = str(exc.detail) if isinstance(exc, HTTPException) else str(exc)
    transition(row, 'completed', 'completed')


def _advance(db, row):
    if row.stop_requested_at:
        stop_unsent(db, row)
        return
    if row.phase in ('sso', 'group_open') and all(i.state == 'completed' for i in items(db, row)):
        admit_exports(db, row)
        return
    actor, account = guard(db, row)
    if row.phase == 'admitted':
        if row.group_mode == 'existing':
            validate_existing(db, row, actor)
        transition(row, 'group_create' if row.group_mode == 'new' else 'group_policy')
        return
    if row.phase == 'group_create':
        from .groups import CreateGroupInput, admit_create_group
        if not row.group_job_id:
            group = admit_create_group(db, actor, CreateGroupInput(aws_account_id=row.aws_account_id,
                name=row.group_name, request_key=f'numbered:{row.id}:group'))
            row.group_id = group.id
            job = db.scalar(select(GroupJob).where(GroupJob.group_id == group.id, GroupJob.kind == 'create'))
            row.group_job_id = job.id
            job.payload = json.dumps(json.loads(job.payload) | {'provisioning_account_id': row.id})
        job = db.get(GroupJob, row.group_job_id)
        if job.state == 'completed':
            transition(row, 'group_policy')
        elif job.state in ('failed', 'needs_review'):
            transition(row, 'group_create', 'needs_review', job.error)
        return
    if row.phase == 'group_policy':
        from .group_policies import GroupPolicyInput, apply_group_policy
        from .schemas import StopPolicy
        group = db.get(ManagedGroup, row.group_id)
        if row.policy_applied_revision is None:
            intent = json.loads(db.get(ProvisioningBatch, row.batch_id).intent)['accounts'][row.position - 1]
            if row.group_mode == 'new' or intent.get('stop_policy') is not None:
                revision = 0 if row.group_mode == 'new' else intent['group']['expected_policy_revision']
                apply_group_policy(db, group, GroupPolicyInput(policy=StopPolicy.model_validate(json.loads(row.stop_policy)),
                    expected_revision=revision, overwrite_individual=intent['overwrite_individual']), actor)
            row.policy_applied_revision = group.policy_revision
        transition(row, 'sso' if members_first(row) else 'group_open')
        return
    if row.phase == 'group_open':
        from .group_subscriptions import SubscribeGroupsInput, admit_prepared_groups, batch_replay, prepare
        snap = json.loads(row.snapshot)
        if not row.native_operation_id and snap['grant']:
            active_group(db, row)
            transition(row, 'sso')
            return
        if not row.native_operation_id:
            body = SubscribeGroupsInput(group_ids=[row.group_id], plan_id=row.plan_id,
                                        request_key=row.native_request_key or f'numbered:{row.id}:native')
            old, fingerprint = batch_replay(db, actor, body, 'group_subscribe')
            if not old:
                prepared = prepare(db, actor, [row.group_id], 'subscribe', 'IMMEDIATE')
                # Existing member identities must still match immediately before
                # admission; the native worker then checks the full remote set.
                expected = {m['id'] for m in snap['members']}
                if members_first(row):
                    expected.update(i.record_id for i in items(db, row))
                if {r.id for r in prepared[0][2]} != expected:
                    raise HTTPException(409, '原分组已有成员变化，开通未发送')
                old = admit_prepared_groups(db, actor, body, prepared, fingerprint, 'subscribe')
                db.flush()
            link = db.scalar(select(LifecycleBatchItem).where(LifecycleBatchItem.batch_id == old.id))
            op = db.get(NativeGroupOperation, link.operation_id)
            row.native_operation_id, row.native_grant_id = op.id, op.grant_id
            op.payload = json.dumps(json.loads(op.payload) | {'provisioning_account_id': row.id})
        op = db.get(NativeGroupOperation, row.native_operation_id)
        if op.state == 'completed':
            active_group(db, row)
            if members_first(row):
                sync_items(db, row)
                if not all(i.state == 'completed' for i in items(db, row)):
                    raise HTTPException(409, '整组订阅已结束，但仍有成员授权未确认，请核对原任务')
                admit_exports(db, row)
            else:
                transition(row, 'sso')
        elif op.state in ('failed', 'needs_review'):
            transition(row, 'group_open', 'paused' if op.state == 'failed' else 'needs_review', op.error)
        return
    if row.phase == 'sso':
        from .batches import admit_frozen_sso
        current = items(db, row)
        failed = next((i for i in current if i.state in ('failed', 'needs_review')), None)
        if failed:
            transition(row, 'sso', 'needs_review', failed.error)
            return
        if members_first(row) and current and all(i.state == 'prepared' for i in current):
            transition(row, 'group_open')
            return
        unresolved = [i for i in current if i.state != 'completed']
        existing = set(db.scalars(select(Subscription.id).where(
            Subscription.id.in_([i.record_id for i in unresolved])))) if unresolved else set()
        pending = [i for i in unresolved if i.record_id not in existing]
        if pending:
            # The accepted intent bounds this account to at most 100 children.
            # Queue admission stays atomic; only the bounded dispatcher may
            # execute them, independently of a slow sibling's remote calls.
            if members_first(row):
                from .group_subscription_state import live_grant
                group = db.get(ManagedGroup, row.group_id)
                if group.state != 'ready' or group.active_job_id or live_grant(db, group.id):
                    raise HTTPException(409, '分组尚未就绪或出现未确认授权，不能创建本批次成员')
            else:
                active_group(db, row)
            for item in pending:
                record = admit_frozen_sso(db, actor, row, item)
                item.sso_batch_id = record.batch_id
                item.phase, item.updated_at = 'create_user', now()
        return


def run_one(*, account_id=None):
    return run_fenced(account_id, ('provisioning',), _run_one)


def _run_one(account_id):
    with SessionLocal() as db:
        db.execute(text('BEGIN IMMEDIATE'))
        row = db.scalar(select(ProvisioningAccountBatch).where(
            ProvisioningAccountBatch.aws_account_id == account_id,
            ProvisioningAccountBatch.state.in_(RUNNABLE)).order_by(ProvisioningAccountBatch.updated_at,
            ProvisioningAccountBatch.position).limit(1))
        if not row:
            return False
        row_id = row.id
        # Confirmed child facts survive a later admission failure. The nested
        # transaction below still keeps each new child and its link atomic.
        sync_items(db, row)
        try:
            # Admission+links share this savepoint: a quota failure leaves no
            # unreserved record or half-linked child, while the pause persists.
            with db.begin_nested():
                _advance(db, row)
                row.updated_at = now()
                db.flush()
        except HTTPException as exc:
            row = db.get(ProvisioningAccountBatch, row_id)
            transition(row, row.phase, 'paused', str(exc.detail))
        aggregate(db, db.get(ProvisioningBatch, row.batch_id))
        db.commit()
        return True


def allowed_actions(row, *, export_retry=False, resumable=False, failed_items=False):
    if row.stop_requested_at:
        if row.state == 'stopped' and resumable:
            return ['resume']
        return ['recheck'] if row.state == 'needs_review' else []
    if row.state == 'completed' and export_retry:
        return ['retry_export']
    if row.state in ('queued', 'running'):
        return ['stop']
    if row.state == 'paused':
        return ['retry', *(['retry_failed'] if failed_items else []), 'stop']
    if row.state == 'needs_review':
        return ['recheck', *(['retry_failed'] if failed_items else []), 'stop']
    return []
