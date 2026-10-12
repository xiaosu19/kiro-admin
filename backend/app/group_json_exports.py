"""Whole/multiple group JSON export admission over the existing auth queue."""

import json
import uuid
from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from .aws import AwsFailure
from .database import get_db
from .group_export_models import AuthExportMember, AuthExportScope, GroupExportPreview
from .group_subscription_state import config_hash, digest
from .models import AuthBatch, AwsAccount, ManagedGroup, Subscription, User, now
from .security import audit, get_user, lock_user_write

router = APIRouter(prefix='/api/group-json-exports')
GROUP_FIELDS = ('id', 'owner_id', 'aws_account_id', 'name', 'remote_id', 'aws_scope', 'revision', 'policy_revision', 'deleted_at')
MEMBER_FIELDS = ('id', 'owner_id', 'aws_account_id', 'group_id', 'group_membership_id', 'username', 'email', 'sso_user_id', 'sso_deleted_at', 'state', 'step', 'reserved', 'credential_revision')


def dumps(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=lambda v: v.isoformat())


def plain(value):
    return json.loads(dumps(value))


class GroupSelection(BaseModel):
    model_config = ConfigDict(extra='forbid')
    group_ids: list[str] = Field(min_length=1, max_length=100)

    @model_validator(mode='after')
    def distinct(self):
        if len(set(self.group_ids)) != len(self.group_ids) or any(not x or len(x) > 36 for x in self.group_ids):
            raise ValueError('请选择 1 至 100 个不重复的具体分组')
        return self


class GroupAdmission(BaseModel):
    model_config = ConfigDict(extra='forbid')
    preview_id: str = Field(min_length=1, max_length=36)
    fingerprint: str = Field(min_length=64, max_length=64)
    request_key: str = Field(min_length=16, max_length=80)
    acknowledge_password_changes: bool


def snapshot(db, actor, ids):
    from .auth_batches import validate_record
    from .groups import owned_group, scope
    from .lifecycle import allowed

    result, total = [], 0
    for gid in sorted(ids):
        group = owned_group(db, gid, actor)
        account = db.get(AwsAccount, group.aws_account_id)
        if not account or actor.must_change_password or not allowed(db, actor, account):
            raise HTTPException(403, '分组所属 AWS 账号或操作者权限已失效')
        if (group.deleted_at or group.state != 'ready' or group.active_job_id or not group.remote_id
                or group.aws_scope != scope(account)):
            raise HTTPException(409, '所选分组尚未就绪、正在变更或已删除，请先核对原任务')
        owner = db.get(User, group.owner_id)
        if not owner:
            raise HTTPException(409, '分组所有者已不存在')
        members = list(db.scalars(select(Subscription).where(Subscription.group_id == gid).order_by(Subscription.id).limit(5001)))
        total += len(members)
        if total > 5000:
            raise HTTPException(409, '一次整组 JSON 导出最多预览 5000 名成员，请分批选择分组')
        frozen = []
        for record in members:
            if record.owner_id != group.owner_id or record.aws_account_id != group.aws_account_id:
                raise HTTPException(409, '分组包含其他所有者或 AWS 配置的记录，请先核对成员归属')
            reason = None
            try:
                validate_record(db, record, actor, 'json_export', group)
            except HTTPException as exc:
                reason = str(exc.detail)
            frozen.append(plain({k: getattr(record, k) for k in MEMBER_FIELDS}) | {'skip_reason': reason})
        result.append({
            'group': plain({k: getattr(group, k) for k in GROUP_FIELDS}),
            'owner': plain({k: getattr(owner, k) for k in ('id', 'role', 'active', 'deleted_at')}),
            'account_name': account.name, 'account_number': account.account_number,
            'folder_number': account.account_number or account.aws_account_id,
            'config_hash': config_hash(db, account), 'members': frozen,
        })
    return result


def scope_view(items):
    groups = [{
        'id': item['group']['id'], 'name': item['group']['name'], 'owner_id': item['group']['owner_id'],
        'aws_account_id': item['group']['aws_account_id'], 'account_name': item['account_name'],
        'account_number': item['folder_number'], 'revision': item['group']['revision'],
        'total': len(item['members']), 'eligible_count': sum(m['skip_reason'] is None for m in item['members']),
        'skipped_count': sum(m['skip_reason'] is not None for m in item['members']),
        'members': [{'record_id': m['id'], 'username': m['username'], 'email': m['email'],
                     'sso_user_id': m['sso_user_id'], 'skip_reason': m['skip_reason']} for m in item['members']],
    } for item in items]
    return {'groups': groups, 'total': sum(g['total'] for g in groups),
            'eligible_count': sum(g['eligible_count'] for g in groups), 'skipped_count': sum(g['skipped_count'] for g in groups)}


@router.post('/preview')
def preview(body: GroupSelection, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    lock_user_write(db, actor, actor.session_version)
    items = snapshot(db, actor, body.group_ids)
    row = GroupExportPreview(id=str(uuid.uuid4()), actor_id=actor.id, actor_role=actor.role,
        session_version=actor.session_version, group_ids=dumps(sorted(body.group_ids)), snapshot=dumps(items),
        fingerprint=digest(items), expires_at=now() + timedelta(minutes=10))
    db.add(row)
    db.commit()
    return scope_view(items) | {'id': row.id, 'fingerprint': row.fingerprint, 'expires_at': row.expires_at}


def member_paths(items):
    from .provisioning_exports import safe_component, unique_components
    accounts = {item['group']['aws_account_id']: item['folder_number'] for item in items}
    folders = unique_components([(str(aid), safe_component(number, f'account-{aid}')) for aid, number in sorted(accounts.items())])
    result = {}
    for aid in accounts:
        members = [m for item in items if item['group']['aws_account_id'] == aid for m in item['members'] if m['skip_reason'] is None]
        names = unique_components([(m['id'], safe_component(m['username'], 'user-' + m['id'])) for m in members])
        result.update({rid: folders[str(aid)] + '/' + name + '.json' for rid, name in names.items()})
    return result


@router.post('', status_code=202)
def admit(body: GroupAdmission, request: Request, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    from .auth_batches import BatchInput, admit_auth_batch, batch_view
    payload_hash = digest(body.model_dump(exclude={'request_key'}))
    old = db.scalar(select(AuthBatch).where(AuthBatch.actor_id == actor.id, AuthBatch.request_key == body.request_key))
    if old:
        saved_scope = db.get(AuthExportScope, old.id)
        if not saved_scope or saved_scope.payload_hash != payload_hash:
            raise HTTPException(409, '重复请求标识与原分组 JSON 范围不匹配')
        return batch_view(db, old)
    saved = db.get(GroupExportPreview, body.preview_id)
    if not saved or saved.actor_id != actor.id:
        raise HTTPException(404, '分组 JSON 预览不存在')
    if saved.actor_role != actor.role or saved.session_version != actor.session_version:
        raise HTTPException(409, '登录或角色已变化，请重新预览分组')
    if saved.expires_at <= now() or body.fingerprint != saved.fingerprint or not body.acknowledge_password_changes:
        raise HTTPException(409, '预览已过期、范围不符或尚未确认首次登录改密，请重新预览')
    lock_user_write(db, actor, actor.session_version)
    db.expire_all()
    items = snapshot(db, actor, json.loads(saved.group_ids))
    if digest(items) != saved.fingerprint:
        raise HTTPException(409, '分组成员、归属、权限、凭据或 AWS 配置已变化，请重新预览')
    selected = [m['id'] for item in items for m in item['members'] if m['skip_reason'] is None]
    if not selected:
        raise HTTPException(409, '所选分组没有可转换用户，请先处理预览中的跳过原因')
    # Only this validated, preview-bound path can exceed the public manual cap.
    internal = BatchInput.model_construct(kind='json_export', record_ids=selected,
        request_key=body.request_key, group_id=None, password=None)
    batch = admit_auth_batch(db, actor, internal, request)
    db.add(AuthExportScope(batch_id=batch.id, preview_id=saved.id, actor_role=actor.role,
        payload_hash=payload_hash, snapshot=dumps(items)))
    paths = member_paths(items)
    for item in items:
        for member in item['members']:
            if member['skip_reason'] is None:
                db.add(AuthExportMember(batch_id=batch.id, record_id=member['id'], group_id=item['group']['id'],
                    owner_id=member['owner_id'], aws_account_id=member['aws_account_id'], username=member['username'],
                    email=member['email'], sso_user_id=member['sso_user_id'], membership_id=member['group_membership_id'],
                    config_hash=item['config_hash'], member_path=paths[member['id']]))
    audit(db, actor, 'group_json_export_created', f'分组 JSON 批次 {batch.id}；{len(items)} 组；{len(selected)} 人；成员范围已冻结', request=request)
    db.commit()
    return batch_view(db, batch)


def require_scope(db, batch, record):
    """Existing worker authorization invokes this before every native step."""
    from .worker_guards import check_config
    scope = db.get(AuthExportScope, batch.id)
    if not scope:
        return
    actor = db.get(User, batch.actor_id)
    member = db.get(AuthExportMember, (batch.id, record.id))
    if not actor or actor.role != scope.actor_role:
        raise HTTPException(403, '原分组 JSON 操作者或用户范围已变化')
    if not member:
        raise HTTPException(409, '原分组 JSON 成员映射已变化')
    group = db.get(ManagedGroup, member.group_id)
    item = next((item for item in json.loads(scope.snapshot) if item['group']['id'] == member.group_id), None)
    if (not item or not group or group.state != 'ready' or group.active_job_id
            or plain({k: getattr(group, k) for k in GROUP_FIELDS}) != item['group']):
        raise HTTPException(409, '冻结的分组身份、版本或成员归属已变化，请重新预览')
    original = next((m for m in item['members'] if m['id'] == record.id and m['skip_reason'] is None), None)
    if (not original or member.config_hash != item['config_hash'] or
            (member.owner_id, member.aws_account_id, member.group_id, member.membership_id,
             member.username, member.email, member.sso_user_id) !=
            tuple(original[k] for k in ('owner_id', 'aws_account_id', 'group_id', 'group_membership_id',
                                       'username', 'email', 'sso_user_id'))):
        raise HTTPException(409, '原分组 JSON 成员映射与预览不符')
    owner = db.get(User, member.owner_id)
    if not owner or plain({k: getattr(owner, k) for k in ('id', 'role', 'active', 'deleted_at')}) != item['owner']:
        raise HTTPException(409, '原分组所有者状态已变化')
    if (record.owner_id, record.aws_account_id, record.group_id, record.group_membership_id,
        record.username, record.email, record.sso_user_id) != (
        member.owner_id, member.aws_account_id, member.group_id, member.membership_id,
        member.username, member.email, member.sso_user_id):
        raise HTTPException(409, '冻结的分组成员身份或归属已变化')
    try:
        check_config(db, db.get(AwsAccount, member.aws_account_id), member.config_hash)
    except AwsFailure as exc:
        raise HTTPException(409, str(exc)) from None


def batch_scope_view(db, batch, jobs, ops):
    scope = db.get(AuthExportScope, batch.id)
    if not scope:
        return None
    result = scope_view(json.loads(scope.snapshot))
    by_record = {job.record_id: op.state for job, op in zip(jobs, ops)}
    for group in result['groups']:
        states = {}
        for member in group.pop('members'):
            state = by_record.get(member['record_id'])
            if state:
                states[state] = states.get(state, 0) + 1
        group['states'] = states
    return result


def grouped_zip(db, batch, included):
    from .auth_batches import jobs
    from .provisioning_exports import build_zip
    scope = db.get(AuthExportScope, batch.id)
    expected = member_paths(json.loads(scope.snapshot))
    members = list(db.scalars(select(AuthExportMember).where(AuthExportMember.batch_id == batch.id)))
    paths = {m.record_id: m.member_path for m in members}
    if (paths != expected or {job.record_id for job in jobs(db, batch)} != set(expected)
            or any(record.id not in paths for record, _ in included)
            or len(set(paths.values())) != len(paths)):
        raise HTTPException(409, '原分组 JSON 文件映射已变化，请重新转换')
    return build_zip(included, paths)
