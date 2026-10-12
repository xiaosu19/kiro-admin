"""Cancel-first, explicitly scoped deletion on the existing account worker lanes.

Every remote write has a committed pending checkpoint. Recovery may observe that
checkpoint, but can never send it again. Rows, opening counters and billing
history are retained; only confirmed AWS absence marks an identity deleted.
"""

import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Literal

from botocore.exceptions import ClientError
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import and_, or_, select, update
from sqlalchemy.orm import Session

from . import aws
from .cascade_models import CascadeAction, CascadeBatch, CascadePreview, CascadeTask
from .catalog import PLAN_ORDER
from .database import SessionLocal, get_db
from .group_subscription_state import config_hash, digest, live_grant
from .models import (
    AwsAccount, GroupJob, GroupMemberActivation, GroupMemberBatch, ManagedGroup,
    NativeGroupGrant, NativeGroupOperation, PlanChange, ProvisioningAccountBatch,
    ProvisioningItem, RecordOperation, StopSchedule, Subscription, User, now,
)
from .security import audit, get_user, lock_user_write
from .subscription_sources import active_source, confirmed_sources, user_cancellation_receipt
from .worker_guards import check_config

router = APIRouter(prefix='/api/cascade-deletions')
logger = logging.getLogger('kiro.cascade')
LIVE = ('queued', 'running', 'needs_review', 'polling', 'paused', 'stopping')
LABELS = {
    'cancel_group': '取消整组 GROUP 订阅', 'detach_member': '移出该成员的 AWS 分组授权',
    'cancel_user': '取消独立 USER 订阅', 'delete_sso': '删除 SSO 并确认 AWS 中已不存在',
    'delete_group': '删除空 AWS 分组并确认已不存在',
}


def dumps(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=lambda v: v.isoformat())


def plain(value):
    return json.loads(dumps(value))


class Selection(BaseModel):
    model_config = ConfigDict(extra='forbid')
    kind: Literal['sso', 'group']
    record_ids: list[str] | None = Field(default=None, min_length=1, max_length=100)
    group_ids: list[str] | None = Field(default=None, min_length=1, max_length=100)

    @model_validator(mode='after')
    def exact_selection(self):
        ids = self.record_ids if self.kind == 'sso' else self.group_ids
        other = self.group_ids if self.kind == 'sso' else self.record_ids
        if not ids or other is not None or len(ids) != len(set(ids)) or any(not x or len(x) > 36 for x in ids):
            raise ValueError('请选择明确且不重复的 SSO 或分组 ID')
        return self


class Admission(BaseModel):
    model_config = ConfigDict(extra='forbid')
    preview_id: str = Field(min_length=1, max_length=36)
    fingerprint: str = Field(min_length=64, max_length=64)
    request_key: str = Field(min_length=16, max_length=80)
    confirm_text: str = Field(min_length=1, max_length=160)
    acknowledge_fees: bool


class Recovery(BaseModel):
    model_config = ConfigDict(extra='forbid')
    request_key: str = Field(min_length=16, max_length=80)
    confirm_text: str = Field(min_length=1, max_length=160)


def actor_identity(actor):
    return [actor.id, actor.role, actor.session_version]


def require_actor(db, actor, account):
    from .lifecycle import allowed
    if not actor or actor.must_change_password or not account or not allowed(db, actor, account):
        raise HTTPException(403, '操作者、AWS 账号或绑定已停用，请恢复权限后再预览')


def owner_snapshot(owner):
    return plain({k: getattr(owner, k) for k in ('id', 'role', 'active', 'deleted_at')})


RECORD_FIELDS = (
    'id', 'owner_id', 'aws_account_id', 'username', 'email', 'sso_user_id',
    'group_id', 'group_membership_id', 'sso_deleted_at', 'plan_id', 'subscription_type',
    'counted', 'subscribed_at', 'state', 'step', 'reserved',
)
GROUP_FIELDS = ('id', 'owner_id', 'aws_account_id', 'remote_id', 'name', 'aws_scope', 'revision', 'policy_revision', 'deleted_at')
ACTIVATION_FIELDS = ('id', 'grant_id', 'record_id', 'owner_id', 'plan_id', 'subscription_type', 'state', 'reserved', 'counted')


def record_snapshot(db, record):
    from .plan_change_state import direct_user_plan
    return plain({k: getattr(record, k) for k in RECORD_FIELDS} | {
        'managed_user_type': direct_user_plan(db, record, observed=False)['subscription_type'],
    })


def provisioning_settled(db, *, group_id=None, record_id=None):
    query = select(ProvisioningAccountBatch)
    if group_id:
        query = query.where(ProvisioningAccountBatch.group_id == group_id)
    else:
        item = db.get(ProvisioningItem, record_id)
        if not item:
            return
        query = query.where(ProvisioningAccountBatch.id == item.account_batch_id)
    for row in db.scalars(query):
        if row.state != 'completed' and not (row.state == 'stopped' and row.stop_requested_at):
            raise HTTPException(409, '仍有批次开通意图；请先明确停止原批次，并核对已发送任务直至停止完成')


def record_ready(db, record, actor):
    if not record or actor.role != 'admin' and record.owner_id != actor.id:
        raise HTTPException(404, 'SSO 用户记录不存在')
    require_actor(db, actor, db.get(AwsAccount, record.aws_account_id))
    from .auth_principals import active_external_login
    if active_external_login(db, record):
        raise HTTPException(409, 'SSO 仍有粘贴账号认证任务，请先处理或取消原任务')
    if (record.reserved or record.active_operation_id or record.state not in ('completed', 'failed')
            or record.step.endswith('_pending') or record.lease_token):
        raise HTTPException(409, 'SSO 仍有开通、预占或待核对操作，请先处理完成')
    if db.scalar(select(RecordOperation.id).where(
        RecordOperation.record_id == record.id, RecordOperation.state.in_(LIVE),
    ).limit(1)) or db.scalar(select(GroupJob.id).where(
        GroupJob.record_id == record.id, GroupJob.state.in_(LIVE),
    ).limit(1)):
        raise HTTPException(409, 'SSO 仍有未完成操作，请先核对原任务')
    from .plan_change_state import LIVE_STATES as PLAN_STATES
    if db.scalar(select(PlanChange.id).where(PlanChange.record_id == record.id,
                                            PlanChange.state.in_(PLAN_STATES)).limit(1)):
        raise HTTPException(409, 'SSO 仍有待生效或待核对套餐变更，请先处理完成')
    if db.scalar(select(GroupMemberActivation.id).where(
        GroupMemberActivation.record_id == record.id,
        or_(GroupMemberActivation.reserved.is_(True), GroupMemberActivation.state.in_(('pending', 'needs_review'))),
    ).limit(1)):
        raise HTTPException(409, 'SSO 仍有未确认的 GROUP 授权，请先核对')
    provisioning_settled(db, record_id=record.id)


def group_ready(db, group, actor, *, deleting=False):
    if not group or actor.role != 'admin' and group.owner_id != actor.id:
        raise HTTPException(404, '分组不存在')
    account = db.get(AwsAccount, group.aws_account_id)
    require_actor(db, actor, account)
    from .groups import scope
    if group.deleted_at or group.aws_scope != scope(account):
        raise HTTPException(409, '分组已删除或 AWS 身份中心已变化')
    old = db.get(GroupJob, group.active_job_id) if group.active_job_id else None
    failed_unsent = deleting and group.state == 'failed' and (
        not group.active_job_id or old and old.state in ('failed', 'cancelled') and old.phase == 'ready' and not old.record_id
    )
    if not failed_unsent and (group.state != 'ready' or group.active_job_id):
        raise HTTPException(409, '分组仍有未完成或待核对任务，请先处理完成')
    if db.scalar(select(GroupJob.id).where(GroupJob.group_id == group.id, GroupJob.state.in_(LIVE)).limit(1)):
        raise HTTPException(409, '分组仍有未完成成员或创建任务')
    if db.scalar(select(NativeGroupOperation.id).where(
        NativeGroupOperation.group_id == group.id, NativeGroupOperation.state.in_(LIVE),
    ).limit(1)) or db.scalar(select(GroupMemberBatch.id).where(
        GroupMemberBatch.group_id == group.id, GroupMemberBatch.state.in_(LIVE),
    ).limit(1)):
        raise HTTPException(409, '分组仍有未完成订阅或成员批次')
    grant = live_grant(db, group.id)
    if grant and grant.state not in ('active', 'cancel_scheduled'):
        raise HTTPException(409, '原生 GROUP 授权尚待确认，请先核对')
    if grant and not group.remote_id:
        raise HTTPException(409, '原生 GROUP 授权缺少已确认的 AWS 分组 ID，请先核对')
    provisioning_settled(db, group_id=group.id)
    return account, grant


def native_activations(db, group, grant):
    live = list(db.scalars(select(NativeGroupGrant).where(
        NativeGroupGrant.group_id == group.id, NativeGroupGrant.state.in_(('pending', 'active', 'cancel_scheduled', 'needs_review')),
    )))
    if {g.id for g in live} != ({grant.id} if grant else set()):
        raise HTTPException(409, '分组包含多个或未确认的 GROUP 授权，请先核对')
    if not grant:
        return []
    if grant.owner_id != group.owner_id or grant.aws_account_id != group.aws_account_id:
        raise HTTPException(409, '原生 GROUP 授权属于其他所有者或 AWS 配置')
    rows = list(db.scalars(select(GroupMemberActivation).where(
        GroupMemberActivation.grant_id == grant.id,
        or_(GroupMemberActivation.state.in_(('pending', 'active', 'cancel_scheduled', 'needs_review')),
            GroupMemberActivation.reserved.is_(True)),
    ).order_by(GroupMemberActivation.id)))
    for row in rows:
        member = db.get(Subscription, row.record_id)
        if (not member or member.group_id != group.id or member.owner_id != group.owner_id
                or member.aws_account_id != group.aws_account_id or row.owner_id != group.owner_id
                or row.subscription_type != grant.subscription_type or row.plan_id != grant.plan_id
                or row.state not in ('active', 'cancel_scheduled') or row.reserved):
            raise HTTPException(409, 'GROUP 授权包含组外、其他所有者或待确认的成员，拒绝影响组外记录')
    return [plain({key: getattr(row, key) for key in ACTIVATION_FIELDS}) for row in rows]


def prepare_local(db, actor, body):
    result = []
    ids = sorted(body.record_ids if body.kind == 'sso' else body.group_ids)
    for target_id in ids:
        if body.kind == 'group':
            group = db.get(ManagedGroup, target_id)
            account, grant = group_ready(db, group, actor, deleting=True)
            records = list(db.scalars(select(Subscription).where(Subscription.group_id == group.id).order_by(Subscription.id)))
            for record in records:
                if record.owner_id != group.owner_id or record.aws_account_id != group.aws_account_id:
                    raise HTTPException(409, '分组包含其他所有者或 AWS 配置的记录，拒绝删除')
                record_ready(db, record, actor)
        else:
            record = db.get(Subscription, target_id)
            record_ready(db, record, actor)
            if not record.sso_user_id or record.sso_deleted_at:
                raise HTTPException(409, '所选 SSO 尚未创建或已删除')
            records, group = [record], db.get(ManagedGroup, record.group_id) if record.group_id else None
            account = db.get(AwsAccount, record.aws_account_id)
            grant = None
            if group:
                if group.owner_id != record.owner_id or group.aws_account_id != record.aws_account_id:
                    raise HTTPException(409, 'SSO 分组归属或 AWS 配置不一致')
                _, grant = group_ready(db, group, actor)
        owner_id = group.owner_id if group else records[0].owner_id
        owner = db.get(User, owner_id)
        if not owner:
            raise HTTPException(409, '原所有者已不存在')
        if actor.role != 'admin':
            require_actor(db, owner, account)
        result.append({
            'kind': body.kind, 'target_id': target_id, 'owner_id': owner_id,
            'aws_account_id': account.id, 'account_name': account.name,
            'config_hash': config_hash(db, account), 'owner': owner_snapshot(owner),
            'group': plain({k: getattr(group, k) for k in GROUP_FIELDS}) if group else None,
            'group_state': group.state if group else None,
            'old_group_job_id': group.active_job_id if group else None,
            'grant': plain({k: getattr(grant, k) for k in ('id', 'group_id', 'subscription_type', 'state')}) if grant else None,
            'activations': native_activations(db, group, grant) if group else [],
            'records': [record_snapshot(db, record) for record in records],
        })
    if sum(len(item['records']) for item in result) > 100:
        raise HTTPException(409, '一次级联删除最多包含 100 条 SSO 记录，请分批预览')
    return result


def validate_user_identity(gateway, record):
    remote = gateway.user_info(record)
    if remote is not None and (not isinstance(remote, dict) or remote.get('UserName') != record.username
                               or remote.get('UserId', record.sso_user_id) != record.sso_user_id):
        raise aws.AwsFailure('AWS SSO 身份与冻结的用户名或 ID 不一致，拒绝删除', uncertain=True)
    return remote


def sources_for(gateway, record, frozen, group, *, preview=False):
    sources = confirmed_sources(gateway, record)
    for source in sources:
        if source.get('pending_type'):
            raise aws.AwsFailure('AWS 订阅仍有待生效变更，先核对原套餐变更', uncertain=True)
        if source['source'] == 'USER':
            expected = frozen.get('managed_user_type') if preview else frozen.get('user_type')
            if source['status'] != 'not_subscribed' and source['subscription_type'] != expected:
                raise aws.AwsFailure('发现未受管理或已变化的独立 USER 订阅，拒绝推断并取消', uncertain=True)
        elif (not group or source['group_id'] != group['remote_id']
              or source['subscription_type'] != frozen.get('group_type')):
            raise aws.AwsFailure('发现其他或未受管理的 GROUP 授权，拒绝影响组外资源', uncertain=True)
    return sources


def group_subscription(gateway, group, grant):
    info = gateway.group_subscription_info(group)
    if (not isinstance(info, dict) or info.get('status') not in ('active', 'cancelled', 'not_subscribed')
            or info.get('pending_type') or info.get('expires_at') is not None and not isinstance(info['expires_at'], datetime)):
        raise aws.AwsFailure('AWS GROUP 订阅未知或正在变更，请先核对', uncertain=True)
    if info['status'] != 'not_subscribed' and (
        not grant or info.get('subscription_type') not in PLAN_ORDER or info['subscription_type'] != grant['subscription_type']
    ):
        raise aws.AwsFailure('发现未受管理或套餐已变化的 GROUP 订阅，拒绝取消', uncertain=True)
    return info


def remote_preview(db, snapshot, gateway):
    gateway.verify()
    group = snapshot['group']
    if group:
        remote = gateway.get_group(group['remote_id']) if group['remote_id'] else None
        if not group['remote_id'] and gateway.get_group_id(group['name']):
            raise aws.AwsFailure('AWS 存在同名分组，但本地未确认其 ID，请先核对原创建任务')
        if remote and (remote.get('id') != group['remote_id'] or remote.get('name') != group['name']):
            raise aws.AwsFailure('AWS 分组 ID 或名称与预览不一致，请先同步核对')
        snapshot['remote_group_exists'] = bool(remote)
        actual = gateway.list_group_memberships(group['remote_id']) if remote else []
        expected = {(r['sso_user_id'], r['group_membership_id']) for r in snapshot['records']
                    if r['sso_user_id'] and not r['sso_deleted_at'] and r['group_membership_id']}
        if snapshot['kind'] == 'group' and (
            len(actual) != len(expected) or {(m['user_id'], m['id']) for m in actual} != expected
        ):
            raise aws.AwsFailure('AWS 分组包含未管理、其他所有者或已变化的成员，拒绝级联删除')
        info = group_subscription(gateway, db.get(ManagedGroup, group['id']), snapshot['grant']) if group['remote_id'] else {
            'status': 'not_subscribed', 'subscription_type': None, 'expires_at': None,
        }
        snapshot['group_subscription'] = plain(info)
    else:
        snapshot['remote_group_exists'], snapshot['group_subscription'] = False, None
    for frozen in snapshot['records']:
        record = db.get(Subscription, frozen['id'])
        frozen['group_type'] = snapshot['grant']['subscription_type'] if snapshot['grant'] else None
        if not record.sso_user_id or record.sso_deleted_at:
            frozen.update(remote_exists=False, sources=[], user_type=None, prior_user_stop=None)
            continue
        frozen['remote_exists'] = validate_user_identity(gateway, record) is not None
        memberships = gateway.list_user_memberships(record.sso_user_id) if frozen['remote_exists'] else {}
        expected = {group['remote_id']: record.group_membership_id} if group and record.group_membership_id else {}
        if memberships != expected:
            raise aws.AwsFailure('SSO 的 AWS 分组归属与本地不一致，包含其他分组或未知成员关系')
        sources = sources_for(gateway, record, frozen, group, preview=True)
        direct = next((s for s in sources if s['source'] == 'USER'), None)
        frozen.update(sources=plain(sources), user_type=(direct or {}).get('subscription_type') or frozen['managed_user_type'],
                      prior_user_stop=plain(user_cancellation_receipt(record, sources)))
    return snapshot


def preflight(db, actor, body):
    local = prepare_local(db, actor, body)
    signature, identity = digest(local), actor_identity(actor)
    db.commit()
    try:
        complete = [remote_preview(db, item, aws.AwsGateway(db.get(AwsAccount, item['aws_account_id']))) for item in plain(local)]
    except aws.AwsFailure as exc:
        raise HTTPException(409, str(exc)) from None
    lock_user_write(db, actor, identity[2])
    db.expire_all()
    if actor_identity(db.get(User, actor.id)) != identity or digest(prepare_local(db, actor, body)) != signature:
        raise HTTPException(409, '预览期间所有者、成员、权限或 AWS 配置已变化，请重新预览')
    return complete


def confirmation(kind, snapshots):
    count = sum(bool(r['sso_user_id']) and not r['sso_deleted_at'] for item in snapshots for r in item['records'])
    return f'删除 {len(snapshots)} 个分组和 {count} 名 SSO' if kind == 'group' else f'删除 {count} 名 SSO'


def public_scope(snapshot):
    return {
        'target_id': snapshot['target_id'], 'owner_id': snapshot['owner_id'],
        'aws_account_id': snapshot['aws_account_id'], 'account_name': snapshot['account_name'],
        'group_id': snapshot['group']['id'] if snapshot['group'] else None,
        'group_name': snapshot['group']['name'] if snapshot['group'] else None,
        'members': [{k: r.get(k) for k in ('id', 'username', 'email', 'sso_user_id', 'sso_deleted_at', 'user_type', 'group_type')}
                    for r in snapshot['records']],
    }


def preview_view(preview):
    items = json.loads(preview.snapshot)
    kind = json.loads(preview.intent)['kind']
    return {
        'id': preview.id, 'fingerprint': preview.fingerprint, 'kind': kind,
        'confirm_text': confirmation(kind, items), 'expires_at': preview.expires_at,
        'counts': {
            'groups': len(items) if kind == 'group' else 0,
            'sso_users': sum(bool(r['sso_user_id']) and not r['sso_deleted_at'] for item in items for r in item['records']),
            'user_subscriptions': sum(bool(r.get('user_type')) for item in items for r in item['records']),
            'group_subscriptions': sum(bool(item['grant']) for item in items) if kind == 'group' else 0,
        },
        'items': [public_scope(item) for item in items],
        'fee_notice': '立即停止授权；当月费用按 AWS 实际账单结算。已用次数、订阅、费用与审计历史保留，不返还次数。',
    }


@router.post('/preview')
def preview(body: Selection, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    items = preflight(db, actor, body)
    row = CascadePreview(id=str(uuid.uuid4()), actor_id=actor.id, actor_role=actor.role,
        session_version=actor.session_version, intent=dumps(body.model_dump(exclude_none=True)),
        snapshot=dumps(items), fingerprint=digest(items), expires_at=now() + timedelta(minutes=10))
    db.add(row)
    db.commit()
    return preview_view(row)


def make_actions(snapshot):
    actions = []
    group = snapshot['group']
    if snapshot['kind'] == 'group' and group and group['remote_id']:
        actions.append({'kind': 'cancel_group'})
    living = [r for r in snapshot['records'] if r['sso_user_id'] and not r['sso_deleted_at']]
    # All independent sources are stopped before the first SSO in this group.
    actions.extend({'kind': 'detach_member', 'record_id': r['id']} for r in living if r['group_membership_id'])
    actions.extend({'kind': 'cancel_user', 'record_id': r['id']} for r in living)
    actions.extend({'kind': 'delete_sso', 'record_id': r['id']} for r in living)
    if snapshot['kind'] == 'group':
        actions.append({'kind': 'delete_group'})
    return [action | {'state': 'ready', 'request_id': None, 'accepted': False} for action in actions]


def lock_task(db, task, *, initial=False):
    snapshot = json.loads(task.snapshot)
    for frozen in snapshot['records']:
        changed = db.execute(update(Subscription).where(
            Subscription.id == frozen['id'],
            or_(Subscription.active_operation_id.is_(None), Subscription.active_operation_id == task.id),
        ).values(active_operation_id=task.id, updated_at=now()))
        if not changed.rowcount:
            raise HTTPException(409, 'SSO 用户刚被其他操作占用，请刷新并重新预览')
    if snapshot['group']:
        old = snapshot['old_group_job_id'] if initial else None
        conditions = or_(ManagedGroup.active_job_id.is_(None), ManagedGroup.active_job_id == task.batch_id)
        if old:
            conditions = or_(conditions, ManagedGroup.active_job_id == old)
        changed = db.execute(update(ManagedGroup).where(
            ManagedGroup.id == task.group_id, conditions,
        ).values(active_job_id=task.batch_id,
                 state='deleting' if snapshot['kind'] == 'group' else 'ready', updated_at=now()))
        if not changed.rowcount:
            raise HTTPException(409, '分组刚被其他任务占用，请刷新并重新预览')


@router.post('', status_code=202)
def admit(body: Admission, request: Request, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    payload_hash = digest(body.model_dump(exclude={'request_key'}))
    old = db.scalar(select(CascadeBatch).where(CascadeBatch.actor_id == actor.id, CascadeBatch.request_key == body.request_key))
    if old:
        if old.payload_hash != payload_hash:
            raise HTTPException(409, '重复请求标识与原级联删除范围不符')
        visible(db, old, actor)
        return batch_view(db, old)
    saved = db.get(CascadePreview, body.preview_id)
    if not saved or saved.actor_id != actor.id:
        raise HTTPException(404, '删除预览不存在')
    if saved.actor_role != actor.role or saved.session_version != actor.session_version:
        raise HTTPException(409, '登录会话或角色已变化，请重新预览删除范围')
    if saved.expires_at <= now() or body.fingerprint != saved.fingerprint:
        raise HTTPException(409, '删除预览已过期或内容不一致，请重新预览')
    if not body.acknowledge_fees or body.confirm_text != preview_view(saved)['confirm_text']:
        raise HTTPException(409, '请确认完整删除范围、费用和次数历史，并输入预览中的确认文字')
    items = preflight(db, actor, Selection.model_validate(json.loads(saved.intent)))
    if digest(items) != saved.fingerprint:
        raise HTTPException(409, 'SSO、订阅来源、成员或 AWS 配置已变化，请重新预览删除范围')
    batch = CascadeBatch(id=str(uuid.uuid4()), actor_id=actor.id, authorized_actor_id=actor.id,
        actor_role=actor.role, session_version=actor.session_version, preview_id=saved.id,
        request_key=body.request_key, payload_hash=payload_hash,
        kind=json.loads(saved.intent)['kind'], confirm_text=body.confirm_text)
    db.add(batch)
    db.flush()
    for position, item in enumerate(items, 1):
        task = CascadeTask(id=str(uuid.uuid4()), batch_id=batch.id, position=position,
            owner_id=item['owner_id'], aws_account_id=item['aws_account_id'], target_id=item['target_id'],
            group_id=item['group']['id'] if item['group'] else None, snapshot=dumps(item), actions=dumps(make_actions(item)))
        db.add(task)
        db.flush()
        lock_task(db, task, initial=True)
    audit(db, actor, 'request_cascade_delete', body.confirm_text + '；范围已冻结；立即取消订阅后删除；费用和次数历史保留', request=request)
    db.commit()
    return batch_view(db, batch)


def visible(db, batch, actor):
    if not batch or actor.role != 'admin' and batch.actor_id != actor.id:
        raise HTTPException(404, '级联删除批次不存在')
    for task in db.scalars(select(CascadeTask).where(CascadeTask.batch_id == batch.id)):
        account = db.get(AwsAccount, task.aws_account_id)
        require_actor(db, actor, account)
        if actor.role != 'admin' and task.owner_id != actor.id:
            raise HTTPException(404, '级联删除批次不存在')


def task_view(task):
    actions = json.loads(task.actions)
    return public_scope(json.loads(task.snapshot)) | {
        'id': task.id, 'position': task.position, 'state': task.state, 'phase': task.phase,
        'error': task.error, 'attempts': task.attempts, 'completed_steps': task.cursor,
        'total_steps': len(actions), 'finished_at': task.finished_at,
        'steps': [{k: a.get(k) for k in ('kind', 'record_id', 'state', 'request_id')}
                  | {'label': LABELS[a['kind']]} for a in actions],
    }


def batch_view(db, batch):
    tasks = list(db.scalars(select(CascadeTask).where(CascadeTask.batch_id == batch.id).order_by(CascadeTask.position)))
    counts = {key: sum(t.state == key for t in tasks) for key in ('queued', 'running', 'needs_review', 'failed', 'completed')}
    counts['total'] = len(tasks)
    state = ('completed' if counts['completed'] == len(tasks) else 'needs_review' if counts['needs_review'] else
             'running' if counts['running'] else 'queued' if counts['queued'] else 'failed')
    return {
        'id': batch.id, 'kind': batch.kind, 'state': state, 'confirm_text': batch.confirm_text,
        'counts': counts, 'created_at': batch.created_at, 'finished_at': batch.finished_at,
        'items': [task_view(task) for task in tasks],
        'actions': {
            'recheck': any(t.state == 'needs_review' and t.phase == 'pending' for t in tasks),
            'retry': any(t.state == 'failed' for t in tasks),
        },
    }


@router.get('')
def listing(group_id: str | None = None, record_id: str | None = None,
            actor: User = Depends(get_user), db: Session = Depends(get_db)):
    query = select(CascadeBatch)
    if actor.role != 'admin':
        query = query.where(CascadeBatch.actor_id == actor.id)
    if group_id:
        from .groups import owned_group
        owned_group(db, group_id, actor)
        query = query.where(select(CascadeTask.id).where(CascadeTask.batch_id == CascadeBatch.id, CascadeTask.group_id == group_id).exists())
    if record_id:
        from .lifecycle import owned
        owned(db, record_id, actor)
        query = query.where(select(CascadeTask.id).where(
            CascadeTask.batch_id == CascadeBatch.id,
            CascadeTask.snapshot.contains('"id": ' + dumps(record_id), autoescape=True),
        ).exists())
    result = []
    for batch in db.scalars(query.order_by(CascadeBatch.created_at.desc()).limit(30)):
        try:
            visible(db, batch, actor)
        except HTTPException:
            continue
        value = batch_view(db, batch)
        if record_id and not any(member['id'] == record_id for task in value['items'] for member in task['members']):
            continue
        result.append(value)
    return result


@router.get('/{batch_id}')
def detail(batch_id: str, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    batch = db.get(CascadeBatch, batch_id)
    visible(db, batch, actor)
    return batch_view(db, batch)


@router.post('/{batch_id}/{action}', status_code=202)
def recover(batch_id: str, action: Literal['recheck', 'retry'], body: Recovery, request: Request,
            actor: User = Depends(get_user), db: Session = Depends(get_db)):
    batch = db.get(CascadeBatch, batch_id)
    visible(db, batch, actor)
    if body.confirm_text != batch.confirm_text:
        raise HTTPException(409, '确认文字与原删除范围不匹配')
    old = db.scalar(select(CascadeAction).where(CascadeAction.batch_id == batch.id,
        CascadeAction.actor_id == actor.id, CascadeAction.request_key == body.request_key))
    if old:
        if old.kind != action:
            raise HTTPException(409, '重复请求标识与原恢复操作不同')
        return batch_view(db, batch)
    tasks = list(db.scalars(select(CascadeTask).where(CascadeTask.batch_id == batch.id)))
    candidates = [t for t in tasks if (t.state == 'needs_review' and t.phase == 'pending' if action == 'recheck' else t.state == 'failed')]
    if not candidates:
        raise HTTPException(409, '当前没有可核对或继续的步骤，请刷新进度')
    for task in candidates:
        # Drifted targets/configuration are never refreshed by recovery.
        validate_task(db, task, batch, fresh=False)
        lock_task(db, task)
        task.state, task.error, task.updated_at = 'queued', None, now()
    if action == 'retry':
        batch.authorized_actor_id, batch.actor_role, batch.session_version = actor.id, actor.role, actor.session_version
    db.add(CascadeAction(id=str(uuid.uuid4()), batch_id=batch.id, actor_id=actor.id, request_key=body.request_key, kind=action))
    audit(db, actor, 'cascade_' + action, batch.confirm_text + ('；只读核对原 AWS 写入，不重复发送' if action == 'recheck' else '；明确继续尚未发送的步骤'), request=request)
    db.commit()
    return batch_view(db, batch)


def claim(account_id):
    from .config import settings
    with SessionLocal() as db:
        eligible = and_(CascadeTask.aws_account_id == account_id, or_(
            CascadeTask.state == 'queued', and_(CascadeTask.state == 'running', CascadeTask.lease_until < now()),
        ))
        task_id = db.scalar(select(CascadeTask.id).where(eligible).order_by(CascadeTask.created_at, CascadeTask.position).limit(1))
        if not task_id:
            return None
        token = str(uuid.uuid4())
        changed = db.execute(update(CascadeTask).where(CascadeTask.id == task_id, eligible).values(
            state='running', attempts=CascadeTask.attempts + 1, lease_token=token,
            lease_until=now() + timedelta(seconds=settings.worker_lease_seconds), updated_at=now(),
        ))
        db.commit()
        return (task_id, token) if changed.rowcount else None


def locked(db, task_id, token):
    from .config import settings
    changed = db.execute(update(CascadeTask).where(
        CascadeTask.id == task_id, CascadeTask.state == 'running', CascadeTask.lease_token == token,
    ).values(lease_until=now() + timedelta(seconds=settings.worker_lease_seconds)))
    if not changed.rowcount:
        raise RuntimeError('级联删除租约失效')
    task = db.get(CascadeTask, task_id)
    return task, db.get(CascadeBatch, task.batch_id)


def validate_task(db, task, batch, *, fresh):
    snapshot, actions = json.loads(task.snapshot), json.loads(task.actions)
    account = db.get(AwsAccount, task.aws_account_id, populate_existing=True)
    check_config(db, account, snapshot['config_hash'])
    owner = db.get(User, task.owner_id, populate_existing=True)
    if not owner or owner_snapshot(owner) != snapshot['owner']:
        raise aws.AwsFailure('原所有者身份或状态已变化，拒绝继续删除')
    if fresh:
        actor = db.get(User, batch.authorized_actor_id, populate_existing=True)
        if not actor or actor_identity(actor) != [batch.authorized_actor_id, batch.actor_role, batch.session_version]:
            raise aws.AwsFailure('操作者角色或登录会话已变化；请重新登录后明确继续未发送步骤')
        require_actor(db, actor, account)
        if actor.role != 'admin' and actor.id != task.owner_id:
            raise aws.AwsFailure('当前操作者已不拥有删除目标')
    if snapshot['group']:
        group = db.get(ManagedGroup, task.group_id, populate_existing=True)
        if (not group or plain({k: getattr(group, k) for k in GROUP_FIELDS}) != snapshot['group']
                or group.active_job_id != task.batch_id
                or group.state != ('deleting' if snapshot['kind'] == 'group' else 'ready')):
            raise aws.AwsFailure('冻结的分组归属、名称、版本或操作锁已变化')
        provisioning_settled(db, group_id=group.id)
        grant = db.get(NativeGroupGrant, snapshot['grant']['id']) if snapshot['grant'] else None
        cancelled = completed_action(actions, 'cancel_group')
        if snapshot['grant'] and (not grant or grant.group_id != group.id or grant.owner_id != task.owner_id
                      or grant.aws_account_id != account.id or grant.subscription_type != snapshot['grant']['subscription_type']
                      or grant.state != ('cancelled' if cancelled else snapshot['grant']['state'])):
            raise aws.AwsFailure('冻结的 GROUP 授权归属或套餐已变化')
        live = list(db.scalars(select(NativeGroupGrant.id).where(
            NativeGroupGrant.group_id == group.id, NativeGroupGrant.state.in_(('pending', 'active', 'cancel_scheduled', 'needs_review')),
        )))
        if set(live) != ({grant.id} if grant and not cancelled else set()):
            raise aws.AwsFailure('分组出现新增或待确认的 GROUP 授权，拒绝继续删除')
        expected_activations = {row['id']: dict(row) for row in snapshot['activations']}
        for row in expected_activations.values():
            if cancelled or completed_action(actions, 'detach_member', row['record_id']):
                row['state'] = 'cancelled'
        actual_activations = list(db.scalars(select(GroupMemberActivation).where(
            or_(GroupMemberActivation.id.in_(expected_activations), and_(
                GroupMemberActivation.grant_id == (grant.id if grant else ''),
                or_(GroupMemberActivation.state.in_(('pending', 'active', 'cancel_scheduled', 'needs_review')),
                    GroupMemberActivation.reserved.is_(True)),
            )),
        )))
        if {row.id: plain({k: getattr(row, k) for k in ACTIVATION_FIELDS}) for row in actual_activations} != expected_activations:
            raise aws.AwsFailure('冻结的 GROUP 成员授权已变化，拒绝影响组外或未知记录')
    for frozen in snapshot['records']:
        record = db.get(Subscription, frozen['id'], populate_existing=True)
        if not record or record.active_operation_id != task.id:
            raise aws.AwsFailure('冻结的 SSO 记录或操作锁已变化')
        from .auth_principals import active_external_login
        if active_external_login(db, record):
            raise aws.AwsFailure('SSO 出现粘贴账号认证任务，保留原删除步骤等待核对')
        expected = {k: frozen[k] for k in RECORD_FIELDS}
        if any(a['kind'] == 'detach_member' and a.get('record_id') == record.id and a['state'] == 'completed' for a in actions):
            expected['group_membership_id'] = None
        actual = plain({k: getattr(record, k) for k in RECORD_FIELDS})
        if actual != expected:
            raise aws.AwsFailure('冻结的 SSO 身份、归属、套餐或开通状态已变化')
        provisioning_settled(db, record_id=record.id)
    return account


def mark_pending(task_id, token):
    from .auth_credentials import invalidate_credentials
    with SessionLocal() as db:
        task, batch = locked(db, task_id, token)
        validate_task(db, task, batch, fresh=True)
        actions = json.loads(task.actions)
        action = actions[task.cursor]
        if action['state'] != 'ready':
            raise aws.AwsFailure('原写入结果未核对，禁止重复发送', uncertain=True)
        if action['kind'] == 'delete_sso':
            invalidate_credentials(db, db.get(Subscription, action['record_id']))
        action['state'] = 'pending'
        task.actions, task.phase, task.updated_at = dumps(actions), 'pending', now()
        db.commit()


def accepted(task_id, token, request_id):
    with SessionLocal() as db:
        task, _ = locked(db, task_id, token)
        actions = json.loads(task.actions)
        actions[task.cursor].update(accepted=True, request_id=request_id if isinstance(request_id, str) else None)
        task.actions = dumps(actions)
        db.commit()


def completed_action(actions, kind, record_id=None):
    return any(a['kind'] == kind and a.get('record_id') == record_id and a['state'] == 'completed' for a in actions)


def remote_group_scope(gateway, snapshot, actions, current):
    group = snapshot['group']
    if not group or snapshot['kind'] != 'group' or not group['remote_id']:
        return
    remote = gateway.get_group(group['remote_id'])
    if remote and (remote.get('id') != group['remote_id'] or remote.get('name') != group['name']):
        raise aws.AwsFailure('AWS 分组身份已变化，拒绝继续删除', uncertain=True)
    expected = {(r['sso_user_id'], r['group_membership_id']) for r in snapshot['records']
                if r['sso_user_id'] and not r['sso_deleted_at'] and r['group_membership_id']
                and not completed_action(actions, 'detach_member', r['id'])
                and not completed_action(actions, 'delete_sso', r['id'])}
    actual = gateway.list_group_memberships(group['remote_id']) if remote else []
    actual_set = {(m['user_id'], m['id']) for m in actual}
    if len(actual_set) != len(actual):
        raise aws.AwsFailure('AWS 分组成员重复或不完整，请核对', uncertain=True)
    if current['state'] == 'pending' and current['kind'] in ('detach_member', 'delete_sso'):
        frozen = next(r for r in snapshot['records'] if r['id'] == current['record_id'])
        expected_without = expected - {(frozen['sso_user_id'], frozen['group_membership_id'])}
        matches = actual_set in (expected, expected_without)
    else:
        matches = actual_set == expected
    if not matches:
        raise aws.AwsFailure('AWS 分组出现未管理或漂移成员，保留原任务等待核对', uncertain=True)


def user_membership_scope(gateway, record, frozen, snapshot, actions, current):
    remote = validate_user_identity(gateway, record)
    memberships = gateway.list_user_memberships(record.sso_user_id) if remote else {}
    expected = {}
    if (snapshot['group'] and frozen['group_membership_id']
            and not completed_action(actions, 'detach_member', record.id)):
        expected = {snapshot['group']['remote_id']: frozen['group_membership_id']}
    allowed = memberships == expected or current['kind'] in ('detach_member', 'delete_sso') and current['state'] == 'pending' and not memberships
    if not allowed:
        raise aws.AwsFailure('AWS SSO 分组关系出现其他分组或已变化，拒绝删除', uncertain=True)
    return remote, memberships


def current_sources(gateway, record, frozen, snapshot):
    return sources_for(gateway, record, frozen, snapshot['group'])


def no_user_access(record, sources, frozen, actions):
    direct = next((s for s in sources if s['source'] == 'USER'), None)
    # A billing tail is safe only while the exact confirmed cancellation still
    # matches. A missing claim alone cannot skip the first managed USER stop.
    receipt = user_cancellation_receipt(record, sources)
    if direct:
        return not active_source(direct) or bool(receipt and direct['status'] == 'cancelled')
    return not frozen.get('user_type') or bool(receipt)


def finish_step(task_id, token, *, direct=None):
    from .auth_credentials import invalidate_credentials
    from .group_subscription_state import complete_group_schedule, detach_member
    with SessionLocal() as db:
        task, batch = locked(db, task_id, token)
        validate_task(db, task, batch, fresh=False)
        actions, snapshot = json.loads(task.actions), json.loads(task.snapshot)
        action, at = actions[task.cursor], now()
        record = db.get(Subscription, action['record_id']) if action.get('record_id') else None
        if action['kind'] == 'cancel_group' and snapshot['grant']:
            grant = db.get(NativeGroupGrant, snapshot['grant']['id'])
            grant.state, grant.cancelled_at, grant.cancellation_mode, grant.access_ends_at = 'cancelled', grant.cancelled_at or at, 'IMMEDIATE', None
            for activation in db.scalars(select(GroupMemberActivation).where(
                GroupMemberActivation.grant_id == grant.id, GroupMemberActivation.state.in_(('active', 'cancel_scheduled')),
            )):
                activation.state, activation.cancelled_at = 'cancelled', grant.cancelled_at
                complete_group_schedule(db, db.get(Subscription, activation.record_id), grant.group_id, at)
        elif action['kind'] == 'detach_member':
            detach_member(db, record, at=at)
            record.group_membership_id = None
        elif action['kind'] == 'cancel_user':
            frozen = next(r for r in snapshot['records'] if r['id'] == record.id)
            kind = frozen.get('user_type')
            if record.counted or kind:
                record.subscription_status, record.cancelled_at = 'cancelled', record.cancelled_at or at
                record.cancellation_mode, record.access_ends_at = 'IMMEDIATE', None
            else:
                record.subscription_status = 'not_subscribed'
            # Preserve a USER cancellation receipt, including any billing tail.
            receipt = {'subscription_type': kind, 'confirmed_at': at.isoformat()} if kind else None
            if receipt and direct:
                receipt['expires_at'] = direct.get('expires_at')
            record.subscription_observation = dumps({
                'effective': {'status': record.subscription_status, 'subscription_type': kind,
                              'expires_at': (direct or {}).get('expires_at'), 'source': 'USER' if kind else None},
                'sources': [dict(direct, source='USER', group_id=None)] if direct else [],
                'observed_at': at, 'user_cancellation': receipt,
            })
            record.last_synced_at = at
            schedule = db.get(StopSchedule, record.id)
            if schedule:
                schedule.state, schedule.completed_at, schedule.error = 'completed', at, None
        elif action['kind'] == 'delete_sso':
            if action['state'] != 'pending':
                invalidate_credentials(db, record)
            record.sso_deleted_at, record.password_encrypted, record.password_generated_at = record.sso_deleted_at or at, None, None
            record.credential_state, record.credential_recovery_encrypted = 'unknown', None
        elif action['kind'] == 'delete_group':
            group = db.get(ManagedGroup, task.group_id)
            group.deleted_at, group.state, group.revision, group.error = at, 'deleted', group.revision + 1, None
        action['state'] = 'completed'
        task.cursor += 1
        task.actions, task.phase, task.error, task.updated_at = dumps(actions), 'ready', None, at
        if record:
            record.updated_at = at
        # Update the frozen postconditions only for changes produced by this task.
        if action['kind'] == 'delete_sso':
            frozen = next(r for r in snapshot['records'] if r['id'] == record.id)
            frozen['sso_deleted_at'] = record.sso_deleted_at.isoformat()
        if action['kind'] == 'delete_group':
            snapshot['group'] = plain({k: getattr(group, k) for k in GROUP_FIELDS})
        task.snapshot = dumps(snapshot)
        task.lease_token = task.lease_until = None
        task.state = 'completed' if task.cursor == len(actions) else 'queued'
        if task.state == 'completed':
            task.finished_at = at
            for frozen in snapshot['records']:
                row = db.get(Subscription, frozen['id'])
                if row.active_operation_id == task.id:
                    row.active_operation_id = None
            if task.group_id and not db.scalar(select(CascadeTask.id).where(
                CascadeTask.batch_id == batch.id, CascadeTask.group_id == task.group_id,
                CascadeTask.id != task.id, CascadeTask.state != 'completed',
            ).limit(1)):
                group = db.get(ManagedGroup, task.group_id)
                if group.active_job_id == batch.id:
                    group.active_job_id = None
            if not db.scalar(select(CascadeTask.id).where(CascadeTask.batch_id == batch.id,
                    CascadeTask.id != task.id, CascadeTask.state != 'completed').limit(1)):
                batch.finished_at = at
        batch.updated_at = at
        audit(db, db.get(User, batch.authorized_actor_id), 'cascade_' + action['kind'] + '_completed',
              LABELS[action['kind']] + '：' + (record.username if record else snapshot['group']['name']), subject=task.owner_id)
        db.commit()


def fail(task_id, token, message, *, definite_refusal=False):
    with SessionLocal() as db:
        task, batch = locked(db, task_id, token)
        actions = json.loads(task.actions)
        action = actions[task.cursor]
        if definite_refusal:
            action['state'], action['accepted'] = 'ready', False
            task.actions, task.phase = dumps(actions), 'ready'
        pending = action['state'] == 'pending'
        task.state, task.error, task.updated_at = 'needs_review' if pending else 'failed', message, now()
        task.lease_token = task.lease_until = None
        batch.updated_at = now()
        audit(db, db.get(User, batch.authorized_actor_id), 'cascade_' + task.state,
              batch.confirm_text + '；' + message, subject=task.owner_id)
        db.commit()


def _write(task_id, token, writer):
    from .retry_policy import classify_failure
    mark_pending(task_id, token)
    try:
        result = writer()
    except Exception as exc:
        # A service code alone does not prove earlier SDK attempts were unsent.
        if classify_failure(exc).proven_unsent:
            exc._cascade_definite_refusal = True
        raise
    accepted(task_id, token, result)


class GuardedGateway:
    """Revalidate at each public call and at both SDK/SigV4 wire transports."""
    def __init__(self, gateway, task_id, token, *, fresh):
        self.gateway = gateway
        self.task_id, self.token, self.fresh = task_id, token, fresh
        self.original_proxy_check = getattr(gateway, '_check_proxy', None)
        self.had_proxy_check = hasattr(gateway, '_check_proxy')
        gateway._check_proxy = self.before_wire
        self.original_cascade_guard = getattr(gateway, 'before_cascade_wire', None)
        self.had_cascade_guard = hasattr(gateway, 'before_cascade_wire')
        gateway.before_cascade_wire = self.check
        self.transport = getattr(getattr(getattr(gateway, 'identity', None), '_endpoint', None), 'http_session', None)
        self.original_transport_guard = getattr(self.transport, 'guard', None)
        if self.transport is not None and hasattr(self.transport, 'guard'):
            self.transport.guard = self.before_sdk_wire

    def check(self):
        with SessionLocal() as db:
            task, batch = locked(db, self.task_id, self.token)
            validate_task(db, task, batch, fresh=self.fresh)
            db.commit()

    def before_wire(self):
        self.check()
        if self.original_proxy_check:
            self.original_proxy_check()

    def before_sdk_wire(self):
        self.check()
        if self.original_transport_guard:
            self.original_transport_guard()

    def __getattr__(self, name):
        value = getattr(self.gateway, name)
        if not callable(value):
            return value
        def guarded(*args, **kwargs):
            self.before_wire()
            return value(*args, **kwargs)
        return guarded

    def close(self):
        # Test adapters may reuse their gateway; never retain a stale task guard.
        if self.had_proxy_check:
            self.gateway._check_proxy = self.original_proxy_check
        else:
            del self.gateway._check_proxy
        if self.had_cascade_guard:
            self.gateway.before_cascade_wire = self.original_cascade_guard
        else:
            del self.gateway.before_cascade_wire
        if self.transport is not None and hasattr(self.transport, 'guard'):
            self.transport.guard = self.original_transport_guard
        close = getattr(self.gateway, 'close', None)
        if callable(close):
            close()


def run_one(gateway_factory=None, *, account_id):
    from .account_dispatcher import run_fenced
    return run_fenced(account_id, ('lifecycle',), lambda aid: _run_one(gateway_factory, account_id=aid))


def _run_one(gateway_factory=None, *, account_id):
    """One checkpoint per tick; the existing dispatcher bounds account lanes."""
    claimed = claim(account_id)
    if not claimed:
        return False
    task_id, token = claimed
    gateway = None
    try:
        with SessionLocal() as db:
            task, batch = locked(db, task_id, token)
            actions, snapshot = json.loads(task.actions), json.loads(task.snapshot)
            current = actions[task.cursor]
            account = validate_task(db, task, batch, fresh=current['state'] != 'pending')
            group = db.get(ManagedGroup, task.group_id) if task.group_id else None
            frozen = next((r for r in snapshot['records'] if r['id'] == current.get('record_id')), None)
            record = db.get(Subscription, current['record_id']) if frozen else None
            db.commit()
            db.expunge_all()
        gateway = GuardedGateway((gateway_factory or aws.AwsGateway)(account), task_id, token,
                                 fresh=current['state'] != 'pending')
        if current['state'] != 'pending':
            gateway.verify()
        remote_group_scope(gateway, snapshot, actions, current)
        kind, pending = current['kind'], current['state'] == 'pending'
        direct = None
        if kind == 'cancel_group':
            info = group_subscription(gateway, group, snapshot['grant'])
            if active_source(info) or snapshot['grant'] and info['status'] == 'not_subscribed' and not pending:
                if pending:
                    raise aws.AwsFailure('AWS GROUP 取消尚未确认；仅只读核对，不重复发送', uncertain=True)
                _write(task_id, token, lambda: gateway.cancel_group_subscription(group, 'IMMEDIATE'))
                info = group_subscription(gateway, group, snapshot['grant'])
                if active_source(info):
                    raise aws.AwsFailure('AWS GROUP 取消尚未确认，等待只读核对', uncertain=True)
        elif kind == 'delete_group':
            remote = gateway.get_group(group.remote_id) if group.remote_id else None
            if not group.remote_id and gateway.get_group_id(group.name):
                raise aws.AwsFailure('发现同名但未确认 ID 的 AWS 分组，请核对原创建任务', uncertain=True)
            if group.remote_id and active_source(group_subscription(gateway, group, snapshot['grant'])):
                raise aws.AwsFailure('AWS GROUP 仍有有效订阅，拒绝删除分组', uncertain=True)
            if remote:
                if gateway.list_group_memberships(group.remote_id):
                    raise aws.AwsFailure('AWS 分组仍有成员，拒绝删除', uncertain=True)
                if pending:
                    raise aws.AwsFailure('AWS 分组仍存在；仅只读核对，不重复发送', uncertain=True)
                _write(task_id, token, lambda: gateway.delete_group(group.remote_id))
                if gateway.get_group(group.remote_id) is not None:
                    raise aws.AwsFailure('AWS 分组删除尚未确认，等待只读核对', uncertain=True)
        else:
            remote, memberships = user_membership_scope(gateway, record, frozen, snapshot, actions, current)
            sources = current_sources(gateway, record, frozen, snapshot)
            direct = next((s for s in sources if s['source'] == 'USER'), None)
            if kind == 'detach_member':
                mid = memberships.get(snapshot['group']['remote_id'])
                if mid:
                    if mid != frozen['group_membership_id']:
                        raise aws.AwsFailure('AWS 成员关系 ID 已变化，拒绝移出', uncertain=True)
                    if pending:
                        raise aws.AwsFailure('AWS 成员移出尚未确认；仅只读核对，不重复发送', uncertain=True)
                    _write(task_id, token, lambda: gateway.delete_group_membership(mid))
                    if gateway.get_group_membership(snapshot['group']['remote_id'], record.sso_user_id):
                        raise aws.AwsFailure('AWS 成员移出尚未确认，等待只读核对', uncertain=True)
                if any(s['source'] == 'GROUP' and active_source(s) for s in current_sources(gateway, record, frozen, snapshot)):
                    raise aws.AwsFailure('AWS GROUP 成员授权尚未消失，等待只读核对', uncertain=True)
            elif kind == 'cancel_user':
                if not no_user_access(record, sources, frozen, actions):
                    if pending:
                        if not current.get('accepted') or not direct or direct['status'] == 'active':
                            raise aws.AwsFailure('AWS USER 取消尚未确认；仅只读核对，不重复发送', uncertain=True)
                    else:
                        _write(task_id, token, lambda: gateway.cancel_subscription(record, 'IMMEDIATE'))
                    sources = current_sources(gateway, record, frozen, snapshot)
                    direct = next((s for s in sources if s['source'] == 'USER'), None)
                    if direct and direct['status'] == 'active':
                        raise aws.AwsFailure('AWS USER 取消尚未确认，等待只读核对', uncertain=True)
                if any(s['source'] == 'GROUP' and active_source(s) for s in sources):
                    raise aws.AwsFailure('AWS GROUP 授权仍有效，拒绝进入 SSO 删除步骤', uncertain=True)
            elif kind == 'delete_sso':
                if not no_user_access(record, sources, frozen, actions) or any(s['source'] == 'GROUP' and active_source(s) for s in sources):
                    raise aws.AwsFailure('AWS 仍有有效订阅来源，拒绝删除 SSO', uncertain=True)
                if remote is not None:
                    if pending:
                        raise aws.AwsFailure('AWS SSO 仍存在；仅只读核对，不重复发送', uncertain=True)
                    _write(task_id, token, lambda: gateway.delete_user(record))
                    if validate_user_identity(gateway, record) is not None:
                        raise aws.AwsFailure('AWS SSO 删除尚未确认，等待只读核对', uncertain=True)
        finish_step(task_id, token, direct=direct)
    except (aws.AwsFailure, HTTPException, ClientError) as exc:
        message = exc.detail if isinstance(exc, HTTPException) else str(exc) if isinstance(exc, aws.AwsFailure) else 'AWS 明确拒绝请求或读取失败，请核对权限及原任务'
        fail(task_id, token, message, definite_refusal=bool(getattr(exc, '_cascade_definite_refusal', False)))
    except Exception as exc:
        logger.error('Cascade task %s interrupted: %s', task_id, type(exc).__name__)
        try:
            fail(task_id, token, '级联删除中断（' + type(exc).__name__ + '），请核对原步骤',
                 definite_refusal=bool(getattr(exc, '_cascade_definite_refusal', False)))
        except Exception:
            logger.error('Cascade task %s remains leased for recovery', task_id)
    finally:
        if gateway is not None and callable(getattr(gateway, 'close', None)):
            gateway.close()
    return True
