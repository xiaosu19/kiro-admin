import { useEffect, useRef, useState, type FormEvent } from "react";
import { SearchableSelect } from "./SearchableSelect";
import { date, type GroupDetail, type MemberBatch, type MemberBatchKind, type MemberCandidates, type RecordItem, type User } from "./api";
import { useGroupAccess, useRemote, type GroupAccess } from "./groupRequests";
import { memberCandidatePath, memberIntent, memberStates, selectMemberRecords } from "./groupMemberLogic";
import { useMemberAdmission, useMemberBatchAction } from "./groupMemberRequests";
import { GroupJoinNotice } from "./NativeSubscriptions";
import { activeNativeGroup, subscriptionSourceLabel } from "./nativeSubscriptionsLogic";

export function MemberSelection({ records, selected, disabled, onSelection }: {
  records: RecordItem[]; selected: RecordItem[]; disabled: boolean; onSelection: (value: RecordItem[]) => void;
}) {
  const selectedIds = new Set(selected.map(record => record.id)), all = !!records.length && records.every(record => selectedIds.has(record.id));
  return <>
    <div className="selection-toolbar"><span>已选 <strong>{selected.length}</strong> / 100 人</span>
      <button className="secondary" type="button" disabled={disabled || !records.length} onClick={() => onSelection(selectMemberRecords(selected, records, !all))}>{all ? "取消本页选择" : "选择本页成员"}</button>
      <small>每批 1–100 人；搜索和翻页保留已选成员。</small></div>
    <div className="table-wrap group-member-choices"><table><thead><tr><th>选择</th><th>SSO 用户</th><th>现有订阅来源</th></tr></thead><tbody>
      {records.map(record => <tr key={record.id} aria-selected={selectedIds.has(record.id)}>
        <td><input type="checkbox" aria-label={`选择成员 ${record.username}`} checked={selectedIds.has(record.id)} disabled={disabled || selected.length >= 100 && !selectedIds.has(record.id)}
          onChange={event => onSelection(selectMemberRecords(selected, [record], event.target.checked))} /></td>
        <td><strong>{record.username}</strong><small>{record.email}</small></td><td>{subscriptionSourceLabel(record)}</td>
      </tr>)}
    </tbody></table></div>
  </>;
}

export function MemberPickerDialog({ group, user, scope, kind, admission, close, onAccepted, onAccessDenied, access }: {
  group: GroupDetail; user: User; scope: string; kind: MemberBatchKind; admission: ReturnType<typeof useMemberAdmission>;
  close: () => void; onAccepted: (batch: MemberBatch) => void; onAccessDenied: () => void; access?: GroupAccess;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [query, setQuery] = useState(""), [page, setPage] = useState(1), [selected, setSelected] = useState<RecordItem[]>([]), [error, setError] = useState("");
  const permitted = !access || access.canAccess(group.id);
  const candidates = useRemote<MemberCandidates>(permitted ? memberCandidatePath(group.id, kind, query, page) : null, 0, user.id, scope, onAccessDenied);
  const blocked = admission.busy || !!admission.pending;
  useEffect(() => { dialog.current?.showModal(); }, []);
  useEffect(() => { if (candidates.forbidden) { setSelected([]); onAccessDenied(); } }, [candidates.forbidden, onAccessDenied]);
  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (blocked || candidates.forbidden || access && !access.canAccess(group.id)) return;
    setError("");
    try { const batch = await admission.submit(memberIntent(group, kind, selected.map(record => record.id))); if (batch) onAccepted(batch); }
    catch (e) { setError((e as Error).message); }
  }
  if (!permitted || candidates.forbidden) return <p className="error" role="alert">当前范围不可读取成员。</p>;
  const records = candidates.data?.group_id === group.id && candidates.data.kind === kind ? candidates.data.items : [];
  return <dialog ref={dialog} className="modal proxy-dialog group-dialog" aria-label={kind === "attach" ? "批量添加成员" : "批量移出成员"}
    onCancel={event => { event.preventDefault(); if (!admission.busy) close(); }}>
    <div className="modal-title"><h2>{kind === "attach" ? "批量添加成员" : "批量移出成员"}</h2><button type="button" className="icon-button" aria-label="关闭" disabled={admission.busy} onClick={close}>×</button></div>
    <form onSubmit={submit}>
      <p className="info-note">只选择「{group.name}」同一 AWS 账号、同一所有者的 SSO。{kind === "attach" ? "独立 USER 订阅可继续保留；加入后继承分组规则，已有更早的个人截止时间会保留。" : "移出仅停止此 GROUP 授权，保留 SSO 和独立 USER 订阅；当前停止规则转为个人规则。"}</p>
      {(error || admission.error || candidates.error) && <p className="error" role="alert">{error || admission.error || candidates.error}</p>}
      <fieldset className="resource-fields" disabled={blocked || candidates.forbidden}>
        <label className="field"><span>搜索用户名、姓名或邮箱</span><input aria-label="搜索可选成员" value={query} placeholder="输入以搜索同账号、同所有者的成员"
          onChange={event => { setQuery(event.target.value); setPage(1); }} onKeyDown={event => { if (event.key === "Enter") event.preventDefault(); }} /></label>
        <MemberSelection records={records} selected={selected} disabled={blocked || candidates.loading} onSelection={setSelected} />
        {!records.length && <p className="muted">{candidates.loading ? "正在读取可选成员…" : candidates.error ? "成员暂不可用，请重试。" : "没有符合搜索条件的成员。"}</p>}
        <div className="pager"><button type="button" className="secondary" disabled={page <= 1 || candidates.loading} onClick={() => setPage(value => value - 1)}>上一页</button>
          <span>第 {page} 页 · 每页 100 人 · 共 {candidates.data?.total ?? "—"} 人</span>
          <button type="button" className="secondary" disabled={!candidates.data || page * 100 >= candidates.data.total || candidates.loading} onClick={() => setPage(value => value + 1)}>下一页</button></div>
        {!!selected.length && <div className="group-member-selected" aria-label="本批已选成员"><div className="stop-heading"><strong>本批已选 {selected.length} 人（含其他搜索页）</strong>
          <button type="button" className="text-button" onClick={() => setSelected([])}>清空成员选择</button></div><ul>{selected.map(record => <li key={record.id}>
            <span>{record.username}</span><button type="button" className="text-button" aria-label={`取消选择 ${record.username}`} onClick={() => setSelected(current => current.filter(row => row.id !== record.id))}>移除</button></li>)}</ul></div>}
        {kind === "attach" && <><GroupJoinNotice group={group} count={selected.length} />{activeNativeGroup(group) && <label className="check-line"><input type="checkbox" required />我已确认加入分组将自动获得付费套餐并消耗次数</label>}</>}
        <div className="modal-actions"><button type="button" className="secondary" onClick={close}>取消</button>
          <button className={kind === "attach" ? "primary" : "danger"} disabled={!selected.length || !!candidates.error}>{admission.busy ? "正在提交…" : `确认${kind === "attach" ? "添加" : "移出"} ${selected.length} 人`}</button></div>
      </fieldset>
    </form>
  </dialog>;
}

export function MemberBatchProgress({ batch, busy, onAction }: { batch: MemberBatch; busy: boolean; onAction: (action: keyof MemberBatch["actions"]) => void }) {
  return <article className="group-member-progress" aria-label="成员批次进度">
    <div className="stop-heading"><strong>{batch.kind === "attach" ? "添加成员" : "移出成员"} · {memberStates[batch.state] || batch.state}</strong><small>{date(batch.created_at)}</small></div>
    <div className="group-counts"><span>本批 <strong>{batch.counts.total}</strong> 人</span>{Object.entries(memberStates).map(([state, label]) => <span key={state}>{label} <strong>{batch.counts[state as keyof typeof memberStates]}</strong></span>)}</div>
    {batch.error && <p className="error" role="alert">{batch.error}</p>}
    {batch.stop_requested_at && <p className="info-note">已请求停止未发送项。已发送或待核对项继续保留实际结果。</p>}
    <div className="proxy-buttons">
      {batch.actions.recheck && <button className="secondary" disabled={busy} onClick={() => onAction("recheck")}>只读核对</button>}
      {batch.actions.retry && <button className="primary" disabled={busy} onClick={() => onAction("retry")}>明确重试失败成员</button>}
      {batch.actions.stop && <button className="danger" disabled={busy} onClick={() => onAction("stop")}>停止未发送成员</button>}
    </div>
    {!!batch.items?.length && <div className="table-wrap group-member-items"><table><thead><tr><th>顺序</th><th>SSO 用户</th><th>状态</th><th>尝试次数</th><th>结果 / 原因</th></tr></thead><tbody>
      {batch.items.map(item => <tr key={item.position}><td>{item.position + 1}</td><td><strong>{item.username || "成员记录"}</strong>{item.email && <small>{item.email}</small>}
        {item.sso_user_id && <small className="mono">SSO ID：{item.sso_user_id}</small>}<small className="mono">记录 ID：{item.record_id}</small></td><td>{memberStates[item.state]}</td><td>{item.attempts}</td><td>{item.error || "—"}</td></tr>)}
    </tbody></table></div>}
  </article>;
}

export function GroupMemberManager({ group, user, scope, blocked, accessible, onChanged, access: sharedAccess }: {
  group: GroupDetail; user: User; scope: string; blocked: boolean; accessible: boolean; onChanged: () => void; access?: GroupAccess;
}) {
  const localAccess = useGroupAccess(user.id, scope), access = sharedAccess || localAccess;
  const [kind, setKind] = useState<MemberBatchKind | null>(null), [opened, setOpened] = useState<string | null>(null);
  const permitted = accessible && access.canAccess(group.id), denied = () => access.deny(group.id);
  const batches = useRemote<MemberBatch[]>(permitted ? `/groups/${encodeURIComponent(group.id)}/member-batches` : null, 3000, user.id, scope, denied);
  const detail = useRemote<MemberBatch>(permitted && !batches.forbidden && opened ? `/groups/${encodeURIComponent(group.id)}/member-batches/${encodeURIComponent(opened)}` : null, 3000, user.id, scope, denied);
  const allowed = permitted && !batches.forbidden && !detail.forbidden;
  const admission = useMemberAdmission(user.id, group.id, scope, allowed, access);
  const action = useMemberBatchAction(user.id, group.id, scope, allowed, access);
  useEffect(() => { setKind(null); setOpened(null); }, [scope, group.id]);
  useEffect(() => { setKind(null); }, [group.revision]);
  useEffect(() => { if (admission.pending && !admission.busy) setKind(null); }, [admission.pending, admission.busy]);
  useEffect(() => {
    if (!allowed) { setKind(null); setOpened(null); return; }
    const confirmed = admission.confirm(batches.data || []);
    if (confirmed) { setOpened(confirmed.id); setKind(null); }
    else if (!opened && batches.data?.length) setOpened(batches.data[0].id);
  }, [batches.data, allowed, opened]);
  function accepted(batch: MemberBatch) { if (!access.canAccess(group.id)) return; setOpened(batch.id); setKind(null); void batches.refresh(); void detail.refresh(); onChanged(); }
  const current = allowed ? (detail.data?.id === opened ? detail.data : batches.data?.find(batch => batch.id === opened)) : null;
  return <section className="panel group-member-manager" aria-label="成员批次与进度">
    <div className="group-section-heading"><div><h2>成员批次与进度</h2><p className="muted">每批 1–100 人。后台逐项执行，刷新页面可继续查看；重试和停止以当前批次状态为准。</p></div>
      <div className="proxy-buttons"><button className="primary" disabled={blocked || !allowed || admission.busy || !!admission.pending} onClick={() => setKind("attach")}>批量添加成员</button>
        <button className="secondary" disabled={blocked || !allowed || admission.busy || !!admission.pending} onClick={() => setKind("detach")}>批量移出成员</button>
        <button className="text-button" disabled={!allowed} onClick={() => { if (access.canAccess(group.id)) { void batches.refresh(); void detail.refresh(); } }}>刷新成员批次</button></div></div>
    {(batches.error || detail.error || action.error || admission.error) && <p className="error" role="alert">{batches.error || detail.error || action.error || admission.error}</p>}
    {allowed && admission.pending && <div className="info-note group-recovery" role="status"><strong>上次成员批次的提交结果尚未确认。</strong>
      <p>保留原选择、分组版本和请求标识。继续确认同一请求；刷新页面不会自动重新提交。</p>
      <button className="secondary" disabled={admission.busy} onClick={async () => { const result = await admission.submit(); if (result) accepted(result); }}>{admission.busy ? "正在确认…" : "继续确认上次成员批次"}</button></div>}
    {allowed && !!batches.data?.length && <label className="field"><span>最近 100 个成员批次</span><SearchableSelect aria-label="选择成员批次" value={opened || ""} onChange={event => setOpened(event.target.value)}>
      {batches.data.map(batch => <option key={batch.id} value={batch.id}>{batch.kind === "attach" ? "添加" : "移出"} {batch.counts.total} 人 · {memberStates[batch.state]} · {date(batch.created_at)}</option>)}
    </SearchableSelect></label>}
    {current ? <MemberBatchProgress batch={current} busy={action.busy || admission.busy} onAction={async next => {
      const result = await action.submit(current, next); if (result) { void batches.refresh(); void detail.refresh(); onChanged(); }
    }} /> : <p className="muted">{!allowed ? "当前范围不可读取成员批次。" : batches.loading ? "正在读取成员批次…" : "暂无成员批次。"}</p>}
    {kind && allowed && <MemberPickerDialog key={`${scope}:${group.id}:${group.revision}:${kind}`} group={group} user={user} scope={scope} kind={kind} admission={admission} access={access}
      close={() => setKind(null)} onAccepted={accepted} onAccessDenied={denied} />}
  </section>;
}
