"""Read-only numbered mappings and explicit, memory-only batch downloads."""
import csv
import hashlib
import io
import json
import re
import unicodedata
import zipfile
from collections import Counter
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session, load_only

from .database import get_db
from .models import (AuthBatch, ManagedGroup, ProvisioningBatch,
                     ProvisioningAccountBatch, ProvisioningItem, RecordOperation, Subscription, User, now)
from .security import audit, get_user

router = APIRouter(prefix="/api/provisioning-batches")


def archive_filename(batch_id):
    instant = now()
    if instant.tzinfo is None:
        instant = instant.replace(tzinfo=timezone.utc)
    day = instant.astimezone(ZoneInfo('Asia/Singapore')).date().isoformat()
    short = batch_id[:8] if re.fullmatch(r'[a-fA-F0-9-]{8,36}', batch_id) else hashlib.sha256(batch_id.encode()).hexdigest()[:8]
    return f'{day}-batch-{short}.zip'


def safe_component(value, fallback):
    value = unicodedata.normalize('NFKC', str(value or ''))
    value = re.sub(r'[\\/<>:"|?*\x00-\x1f\x7f-\x9f]', '_', value).strip(' .')
    value = value.encode('utf-8')[:180].decode('utf-8', errors='ignore').rstrip(' .') or fallback
    if re.match(r'^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', value, re.IGNORECASE):
        value = '_' + value
    return value


def unique_components(values):
    counts = Counter(value.casefold() for _, value in values)
    names, used = {}, set()
    for identity, value in values:
        suffix = hashlib.sha256(identity.encode()).hexdigest()[:12]
        candidate = f'{value}--{suffix}' if counts[value.casefold()] > 1 else value
        index = 1
        while candidate.casefold() in used:
            candidate = f'{value}--{suffix}-{index}'
            index += 1
        used.add(candidate.casefold())
        names[identity] = candidate
    return names


def zip_member_paths(children, items):
    """One merged group document per frozen account batch."""
    folders = []
    for child in children:
        snapshot = json.loads(child.snapshot)
        number = snapshot.get('account_number') or child.account_number or snapshot.get('real_aws_account_id')
        folders.append((child.id, safe_component(number, f'account-{child.aws_account_id}')))
    folders = unique_components(folders)
    names = {}
    for child in children:
        selected = [item for item in items if item.account_batch_id == child.id]
        name = safe_component(child.group_name, safe_component(child.batch_number, 'group-' + child.id))
        names.update({item.record_id: f'{folders[child.id]}/{name}.json' for item in selected})
    return names


def build_zip(rows, member_paths):
    """Merge successful account arrays sharing a group path without changing schema."""
    from .auth_export import account_json
    from .security import decrypt
    documents, seen = {}, set()
    for record, encrypted in rows:
        try:
            if record.id in seen:
                raise ValueError('duplicate export identity')
            seen.add(record.id)
            value = account_json(record, decrypt(encrypted))
            documents.setdefault(member_paths[record.id], []).extend(value)
        except (ValueError, KeyError, TypeError):
            raise HTTPException(409, 'JSON 结果与原用户身份不匹配或已失效，请重新转换') from None
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for path, value in documents.items():
            archive.writestr(path, json.dumps(value, ensure_ascii=False, indent=2).encode())
    return output.getvalue()


def validate_result_links(db, parent, selected, children, linked, ops):
    """A linked auth batch may never add or consume a different user's result."""
    from .auth_batches import jobs
    by_record = {item.record_id: item for item in selected}
    by_child = {child.id: child for child in children}
    for auth_id in dict.fromkeys(item.auth_batch_id for item in selected if item.auth_batch_id):
        auth = linked.get(auth_id)
        if not auth or auth.actor_id != parent.actor_id or auth.kind != 'json_export':
            raise HTTPException(404, '认证批次不存在')
        auth_jobs = jobs(db, auth)
        expected = {item.auth_job_id for item in selected if item.auth_batch_id == auth_id}
        if {job.id for job in auth_jobs} != expected:
            raise HTTPException(409, 'JSON 任务与原批次对应关系已变化，请核对后重新转换')
        for job in auth_jobs:
            item = by_record.get(job.record_id)
            op, record = ops.get(job.id), db.get(Subscription, job.record_id)
            child = by_child.get(item.account_batch_id) if item else None
            if (not item or not child or not record or not op or item.auth_job_id != job.id or item.auth_batch_id != auth_id
                    or op.record_id != item.record_id or op.actor_id != parent.actor_id or op.kind != 'auth_json_export'
                    or (record.username, record.email, record.aws_account_id, record.owner_id) !=
                    (item.username, item.email, child.aws_account_id, parent.actor_id)):
                raise HTTPException(409, 'JSON 结果与原批次用户身份不匹配，请核对后重新转换')


def mappings(db, record_ids):
    """One bounded mapping query for a page/export, never read credentials."""
    return {row.record_id: {'internal_id': row.internal_id, 'account_number': row.account_number,
                           'provisioning_batch_number': row.batch_number}
            for row in db.execute(select(ProvisioningItem.record_id, ProvisioningItem.internal_id,
                ProvisioningAccountBatch.account_number, ProvisioningAccountBatch.batch_number)
                .join(ProvisioningAccountBatch).where(ProvisioningItem.record_id.in_(record_ids)))}


def owned_scope(db, actor, batch_id=None, account_batch_id=None, *, private=False):
    from .provisioning_batches import require_view_scope
    child = db.get(ProvisioningAccountBatch, account_batch_id) if account_batch_id else None
    if account_batch_id and (not child or (batch_id and child.batch_id != batch_id)):
        raise HTTPException(404, '批次不存在')
    batch = db.get(ProvisioningBatch, child.batch_id if child else batch_id)
    if not batch or (private and batch.actor_id != actor.id):
        raise HTTPException(404, '批次不存在')
    require_view_scope(db, batch, actor)
    return batch, child


def scope_items(batch, child=None):
    query = select(ProvisioningItem).join(ProvisioningAccountBatch).where(ProvisioningAccountBatch.batch_id == batch.id)
    if child:
        query = query.where(ProvisioningAccountBatch.id == child.id)
    return query.order_by(ProvisioningAccountBatch.position, ProvisioningItem.position)


@router.get('/report')
def report(request: Request, account_batch_id: str | None = Query(None, min_length=1, max_length=36),
           batch_id: str | None = Query(None, min_length=1, max_length=36),
           aws_account_id: int | None = None, q: str = Query('', max_length=254), state: str | None = None,
           created_from: datetime | None = None, created_to: datetime | None = None,
           actor: User = Depends(get_user), db: Session = Depends(get_db)):
    from .exports import csv_text, timestamp
    from .provisioning_batches import matching_account_query, visible_query
    if account_batch_id and batch_id:
        raise HTTPException(422, '一次只能选择一个导出范围')
    if account_batch_id or batch_id:
        batch, child = owned_scope(db, actor, batch_id, account_batch_id)
    else:
        batch = child = None
    visible = visible_query(actor, aws_account_id, q, state, created_from, created_to)
    query = (select(ProvisioningItem, ProvisioningAccountBatch, ProvisioningBatch, Subscription, ManagedGroup)
             .select_from(ProvisioningItem)
             .join(ProvisioningAccountBatch, ProvisioningAccountBatch.id == ProvisioningItem.account_batch_id)
             .join(ProvisioningBatch, ProvisioningBatch.id == ProvisioningAccountBatch.batch_id)
             .outerjoin(Subscription, Subscription.id == ProvisioningItem.record_id)
             .outerjoin(ManagedGroup, ManagedGroup.id == Subscription.group_id)
             .options(load_only(Subscription.id, Subscription.subscribed_at),
                      load_only(ManagedGroup.id, ManagedGroup.name),
                      load_only(ProvisioningBatch.id, ProvisioningBatch.state))
             .where(ProvisioningBatch.id.in_(visible.with_only_columns(ProvisioningBatch.id))))
    if batch:
        query = query.where(ProvisioningBatch.id == batch.id)
    if child:
        query = query.where(ProvisioningAccountBatch.id == child.id)
    if aws_account_id is not None or q.strip():
        query = query.where(ProvisioningAccountBatch.id.in_(matching_account_query(aws_account_id, q)))
    entries = list(db.execute(query.order_by(ProvisioningBatch.created_at, ProvisioningBatch.id,
        ProvisioningAccountBatch.position, ProvisioningItem.position).limit(10001)))
    if len(entries) > 10000:
        raise HTTPException(409, '一次最多导出 10000 项，请缩小筛选范围')
    if not entries:
        raise HTTPException(409, '当前范围没有可导出的批次记录')
    output = io.StringIO(newline='')
    writer = csv.writer(output, quoting=csv.QUOTE_ALL)
    writer.writerow(['批次 ID', '账号批次 ID', '内部 ID', 'AWS 编号', '批次编号', '原账号名称', '真实 AWS ID',
        '真实用户名', '原分组名称', '当前分组名称', '套餐', '批次状态', '账号状态', '开通状态', '开通阶段',
        '导出状态', '创建时间(UTC)', '开通时间(UTC)', '完成时间(UTC)'])
    auth_ids = [i.auth_job_id for i, *_ in entries if i.auth_job_id]
    ops = {op.id: op.state for op in db.scalars(select(RecordOperation).where(RecordOperation.id.in_(auth_ids)))}
    batches = {b.id: b.state for b in db.scalars(select(AuthBatch).where(AuthBatch.id.in_(
        [i.auth_batch_id for i, *_ in entries if i.auth_batch_id])))}
    for item, account, parent, record, group in entries:
        snapshot = json.loads(account.snapshot)
        export = batches.get(item.auth_batch_id)
        if export == 'active':
            export = ops.get(item.auth_job_id, 'waiting')
        export = export or ('blocked' if item.export_error else 'waiting' if snapshot['exports']['json'] else 'not_requested')
        writer.writerow([csv_text(v) for v in [parent.id, account.id, item.internal_id, account.account_number,
            account.batch_number, snapshot['account_name'], snapshot['real_aws_account_id'], item.username,
            account.group_name, group.name if group else '', account.plan_name, parent.state, account.state,
            item.state, item.phase, export, timestamp(item.created_at), timestamp(record.subscribed_at) if record else '',
            timestamp(item.finished_at)]])
    audit(db, actor, 'export_provisioning_report', f'导出批次报告：{len(entries)} 项', request=request)
    db.commit()
    return Response(('\ufeff' + output.getvalue()).encode(), media_type='text/csv', headers={
        'Cache-Control': 'no-store', 'Content-Disposition': 'attachment; filename="provisioning-report.csv"',
        'X-Export-Count': str(len(entries))})


def download_summary(children, items, batches, ops):
    """Metadata only: downloading still authoritatively revalidates every result."""
    requested = {c.id for c in children if json.loads(c.exports)['json']}
    terminal = {'failed', 'stopped'}
    included = excluded = waiting = consumed = 0
    for item in items:
        if item.account_batch_id not in requested:
            continue
        batch, op = batches.get(item.auth_batch_id), ops.get(item.auth_job_id)
        if batch:
            if batch.state == 'downloaded' or op and op.state == 'downloaded':
                consumed += 1
            elif batch.state != 'active' or batch.expires_at <= now() or (batch.download_expires_at and batch.download_expires_at <= now()):
                excluded += 1
            elif op and op.state in ('queued', 'running', 'challenge', 'polling'):
                waiting += 1
            elif op and op.state == 'completed':
                included += 1
            else:
                excluded += 1
        elif item.export_error or item.state in terminal:
            excluded += 1
        else:
            waiting += 1
    deadlines = [batches[i.auth_batch_id].download_expires_at for i in items
                 if i.account_batch_id in requested and i.auth_batch_id in batches
                 and batches[i.auth_batch_id].state == 'active'
                 and batches[i.auth_batch_id].download_expires_at]
    return {'ready': bool(included), 'available_count': included,
            'excluded_count': excluded, 'waiting_count': waiting, 'consumed_count': consumed, 'requested': bool(requested),
            'download_expires_at': min(deadlines) if deadlines and not waiting else None}


def download(db, actor, request, batch_id, account_batch_id=None):
    from . import auth_batches
    from .security import lock_user_write
    lock_user_write(db, actor, actor.session_version)
    batch, child = owned_scope(db, actor, batch_id, account_batch_id, private=True)
    all_children = list(db.scalars(select(ProvisioningAccountBatch).where(ProvisioningAccountBatch.batch_id == batch.id).order_by(ProvisioningAccountBatch.position)))
    children = [child] if child else all_children
    items = list(db.scalars(scope_items(batch, child)))
    requested = {c.id for c in children if json.loads(c.exports)['json']}
    selected = [i for i in items if i.account_batch_id in requested]
    if not selected:
        raise HTTPException(409, '本批次未选择 JSON 转换')
    linked = {b.id: b for b in db.scalars(select(AuthBatch).where(AuthBatch.id.in_([i.auth_batch_id for i in selected if i.auth_batch_id])))}
    ops = {o.id: o for o in db.scalars(select(RecordOperation).where(RecordOperation.id.in_([i.auth_job_id for i in selected if i.auth_job_id])))}
    # Check every live job before touching any successful secret. A challenge is
    # never closed merely because a different user's JSON is ready.
    summary = download_summary(children, selected, linked, ops)
    validate_result_links(db, batch, selected, children, linked, ops)
    # Queue every expired result in this range in one submission. Returning on
    # the first child would make a large export require hundreds of clicks.
    from .auth_result_refresh import refresh_expired_results
    refreshing = False
    for auth in linked.values():
        if auth_batches.check_expiry(db, auth):
            refreshing = refresh_expired_results(db, auth, defer_commit=True) or refreshing
    if refreshing:
        from .provisioning_auth_window import parent_download_window
        parent_download_window(db, next(iter(linked.values())), now())
    included, excluded, consumed = [], len([i for i in selected if not i.auth_batch_id]), []
    for auth_id in dict.fromkeys(i.auth_batch_id for i in selected if i.auth_batch_id):
        auth = linked.get(auth_id)
        if not auth or auth.actor_id != actor.id or auth.kind != 'json_export':
            raise HTTPException(404, '认证批次不存在')
        if not auth_batches.check_expiry(db, auth):
            excluded += len(auth_batches.jobs(db, auth))
            continue
        results, skipped = auth_batches.zip_results(db, auth)
        included.extend(results)
        excluded += skipped
        if results:
            consumed.append((auth, results))
    if not included:
        db.commit()
        closed = all(auth.state != 'active' for auth in linked.values()) and not summary['waiting_count']
        raise HTTPException(410 if closed else 409, '没有可下载的 JSON 结果；结果可能已下载、过期或转换失败')
    # Preserve account position then numeric item position even if an auth batch
    # contains multiple linked jobs in a future coordinator version.
    order = {i.record_id: n for n, i in enumerate(selected)}
    included.sort(key=lambda row: order[row[0].id])
    content = build_zip(included, zip_member_paths(all_children, selected))
    for auth, results in consumed:
        auth_batches.consume_results(db, auth, results)
    audit(db, actor, 'provisioning_zip_downloaded', f'批次 {batch.id}；账号批次 {account_batch_id or "全部"}；成功 {len(included)}；排除 {excluded}', request=request)
    db.commit()
    return Response(content, media_type='application/zip', headers={
        'Cache-Control': 'no-store', 'Content-Disposition': f'attachment; filename="{archive_filename(batch.id)}"',
        'X-Export-Count': str(len(included)), 'X-Excluded-Count': str(excluded)})


@router.post('/{batch_id}/download')
def parent_download(batch_id: str, request: Request, actor: User = Depends(get_user), db: Session = Depends(get_db)):
    return download(db, actor, request, batch_id)


@router.post('/{batch_id}/accounts/{account_batch_id}/download')
def account_download(batch_id: str, account_batch_id: str, request: Request,
                     actor: User = Depends(get_user), db: Session = Depends(get_db)):
    return download(db, actor, request, batch_id, account_batch_id)
