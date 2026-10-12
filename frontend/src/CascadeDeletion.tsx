import { useEffect, useRef, useState, type FormEvent } from "react";
import { cascadeSelection, date, stateName, type CascadeBatch, type CascadeKind, type CascadePreview } from "./api";
import { useRemote } from "./groupRequests";
import { useCascadeAdmission, useCascadePreview, useCascadeRecovery } from "./cascadeRequests";

type Admission = ReturnType<typeof useCascadeAdmission>;

export function CascadeScopePreview({ value }: { value: CascadePreview }) {
  return <>
    <p><strong>{value.confirm_text}</strong>。独立 USER 订阅 {value.counts.user_subscriptions} 项
      {value.kind === "group" ? `，整组 GROUP 订阅 ${value.counts.group_subscriptions} 项` : ""}。</p>
    <p>{value.kind === "group"
      ? "先立即取消整组 GROUP 和成员独立 USER 订阅，再删除下列全部 SSO，最后删除 AWS 分组。"
      : "先移出所选成员的 AWS 组授权并立即取消独立 USER 订阅，再删除下列 SSO。其他组成员继续保留授权。"}</p>
    <div className="table-wrap"><table><thead><tr><th>AWS 账号 / 分组</th><th>SSO 用户 / ID</th><th>本次停止的授权</th></tr></thead>
      <tbody>{value.items.flatMap(item => item.members.length ? item.members.map(member => <tr key={`${item.target_id}:${member.id}`}>
        <td>{item.account_name}<small>{item.group_name || "无分组"} · 创建者 ID {item.owner_id}</small></td>
        <td><strong>{member.username}</strong><small>{member.email}</small><small>SSO ID：{member.sso_user_id || "尚未创建"}</small><small>记录 ID：{member.id}</small></td>
        <td>{member.sso_deleted_at ? "SSO 已删除 · 历史保留" : <>{member.user_type ? "独立 USER 订阅" : "无独立 USER 订阅"}
          {member.group_type && <small>{value.kind === "group" ? "取消整组 GROUP 订阅" : "仅移出此成员的 GROUP 授权"}</small>}</>}</td>
      </tr>) : [<tr key={item.target_id}><td>{item.account_name}<small>{item.group_name} · 创建者 ID {item.owner_id}</small></td><td>空分组</td><td>{value.counts.group_subscriptions ? "核对并取消 GROUP 订阅" : "核对 AWS 中为空后删除"}</td></tr>])}</tbody>
    </table></div>
    <p className="info-note">{value.fee_notice}</p>
    <small className="muted">预览有效至 {date(value.expires_at)}。提交时会重新核对完整范围；未管理成员、其他分组授权或未知写入会阻止删除。</small>
  </>;
}

export function CascadeDialog({ actorId, scope, kind, ids, admission, close, onAccepted }: {
  actorId: number; scope: string; kind: CascadeKind; ids: string[]; admission: Admission;
  close: () => void; onAccepted: (batch: CascadeBatch) => void;
}) {
  const selection = cascadeSelection(kind, ids), preview = useCascadePreview(actorId, scope, selection);
  const dialog = useRef<HTMLDialogElement>(null);
  const [confirmation, setConfirmation] = useState(""), [acknowledged, setAcknowledged] = useState(false);
  const value = preview.data;
  const title = kind === "group" ? "预览删除分组与全部 SSO" : "预览取消订阅后删除 SSO";
  useEffect(() => { dialog.current?.showModal?.(); }, []);
  useEffect(() => { setConfirmation(""); setAcknowledged(false); }, [value?.fingerprint]);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!value || confirmation !== value.confirm_text || !acknowledged) return;
    const result = await admission.submit(value);
    if (result) onAccepted(result);
  }
  return <dialog ref={dialog} className="modal group-dialog" aria-label={title} onCancel={event => { event.preventDefault(); if (!admission.busy) close(); }}>
    <div className="modal-title"><h2>{title}</h2><button type="button" className="icon-button" aria-label="关闭删除预览" disabled={admission.busy} onClick={close}>×</button></div>
    {(preview.error || admission.error) && <p role="alert" className="error">{preview.error || admission.error}</p>}
    {preview.busy && <p role="status">正在只读核对 AWS 订阅、完整成员和删除范围…</p>}
    {!value && !preview.busy && <button className="secondary" onClick={() => void preview.refresh()}>重新读取删除预览</button>}
    {value && <form onSubmit={submit}>
      <CascadeScopePreview value={value} />
      <button type="button" className="text-button" disabled={admission.busy || !!admission.pending || preview.busy} onClick={() => void preview.refresh()}>重新核对删除范围</button>
      <fieldset className="resource-fields" disabled={admission.busy || !!admission.pending}>
        <label className="check-label"><input type="checkbox" required checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} />我确认删除以上全部对象，了解当月费用继续按 AWS 账单结算，历史与已用次数保留。</label>
        <label className="field"><span>输入“{value.confirm_text}”确认范围</span><input required autoComplete="off" value={confirmation} onChange={event => setConfirmation(event.target.value)} /></label>
        <div className="modal-actions"><button type="button" className="secondary" onClick={close}>返回</button>
          <button className="danger" disabled={!acknowledged || confirmation !== value.confirm_text}>{admission.busy ? "正在提交…" : "确认取消订阅后删除"}</button></div>
      </fieldset>
    </form>}
    {admission.pending && <CascadeSubmissionRecovery admission={admission} onAccepted={onAccepted} />}
  </dialog>;
}

export function CascadeSubmissionRecovery({ admission, onAccepted }: { admission: Admission; onAccepted: (batch: CascadeBatch) => void }) {
  if (!admission.pending) return null;
  return <section className="info-note group-recovery" role="status"><strong>上次“{admission.pending.body.confirm_text}”的提交结果尚待确认。</strong>
    <p>继续原请求确认是否已受理；原请求未受理时，将提交原确认范围。刷新页面后也可恢复，范围和请求标识保持一致。</p>
    <details><summary>原确认范围：{admission.pending.target_ids.length} 个{admission.pending.kind === 'group' ? '分组' : 'SSO 记录'}</summary>
      <ul>{admission.pending.target_ids.map(id => <li key={id}>ID：{id}</li>)}</ul></details>
    {admission.error && <p role="alert" className="error-text">{admission.error}</p>}
    <button className="secondary" disabled={admission.busy} onClick={async () => { const batch = await admission.submit(); if (batch) onAccepted(batch); }}>
      {admission.busy ? "正在确认…" : "确认上次删除提交结果"}</button>
  </section>;
}

export function CascadeProgress({ batch, busy, onAction }: { batch: CascadeBatch; busy: boolean; onAction: (action: "recheck" | "retry") => void }) {
  return <article className="group-recovery" aria-label={`级联删除 ${batch.confirm_text}`}>
    <div className="group-section-heading"><div><h3>{batch.confirm_text} · {stateName[batch.state] || batch.state}</h3>
      <p>已完成 {batch.counts.completed} / {batch.counts.total} 项；待核对 {batch.counts.needs_review}，未发送步骤失败 {batch.counts.failed}。</p>
      <small>提交：{date(batch.created_at)} · 批次 ID：{batch.id}</small></div>
      <div className="proxy-buttons">{batch.actions.recheck && <button className="secondary" disabled={busy} onClick={() => onAction("recheck")}>只读核对原 AWS 写入</button>}
        {batch.actions.retry && <button className="danger" disabled={busy} onClick={() => onAction("retry")}>明确继续未发送步骤</button>}</div></div>
    <p className="muted">每次 AWS 写入前保存检查点。待核对步骤只读取结果；AWS 确认不存在后才记为删除。费用、已用次数与审计历史保留。</p>
    <div className="table-wrap"><table><thead><tr><th>范围</th><th>后台进度</th><th>步骤 / 结果</th></tr></thead><tbody>
      {batch.items.map(item => <tr key={item.id}><td>{item.group_name || item.members[0]?.username || "空分组"}<small>{item.account_name}</small>
        {item.members.map(member => <small key={member.id}>{member.username} · SSO ID：{member.sso_user_id || "尚未创建"}</small>)}</td>
        <td>{stateName[item.state] || item.state}<small>{item.completed_steps} / {item.total_steps} 步已确认</small></td>
        <td>{item.steps.map((step, index) => <small key={index}>{index + 1}. {step.label}{step.record_id ? ` · ${item.members.find(member => member.id === step.record_id)?.username || step.record_id}` : ""}：
          {step.state === "completed" ? "已确认" : step.state === "pending" ? "写入已发送 · 等待只读核对" : "尚未发送"}</small>)}
          {item.error && <p role="alert" className="error-text">{item.error}</p>}</td></tr>)}
    </tbody></table></div>
  </article>;
}

export function CascadeHistory({ actorId, scope, groupId, recordId, kind, onChanged }: {
  actorId: number; scope: string; groupId?: string; recordId?: string; kind?: CascadeKind; onChanged?: () => void;
}) {
  const query = new URLSearchParams({ ...(groupId ? { group_id: groupId } : {}), ...(recordId ? { record_id: recordId } : {}) });
  const history = useRemote<CascadeBatch[]>(`/cascade-deletions?${query}`, 4000, actorId, scope);
  const recovery = useCascadeRecovery(actorId, scope);
  const [confirmRetry, setConfirmRetry] = useState<CascadeBatch | null>(null), [confirmText, setConfirmText] = useState("");
  useEffect(() => { setConfirmRetry(null); setConfirmText(""); }, [actorId, scope]);
  const batches = (history.data || []).filter(batch => !kind || batch.kind === kind);
  const currentRetry = !history.forbidden && batches.find(batch => batch.id === confirmRetry?.id && batch.actions.retry);
  async function action(batch: CascadeBatch, next: "recheck" | "retry") {
    if (next === "retry" && confirmRetry?.id !== batch.id) { setConfirmRetry(batch); setConfirmText(""); return; }
    if (next === "retry" && confirmText !== batch.confirm_text) return;
    const result = await recovery.submit(batch, next);
    if (result) { setConfirmRetry(null); await history.refresh(); onChanged?.(); }
  }
  if (!batches.length && !history.error) return null;
  return <section className="panel group-jobs" aria-label="级联删除进度与历史"><div className="group-section-heading"><div><h2>级联删除进度与历史</h2>
    <p className="muted">后台逐项处理，刷新或重新登录后仍可查看进度。</p></div><button className="secondary" onClick={() => void history.refresh()}>刷新删除进度</button></div>
    {(history.error || recovery.error) && <p role="alert" className="error-text">{history.error || recovery.error}</p>}
    {currentRetry && <form className="info-note" onSubmit={event => { event.preventDefault(); void action(currentRetry, "retry"); }}>
      <p>继续原范围“{currentRetry.confirm_text}”中尚未发送的步骤，当前权限会再次核对。已完成和结果不明的写入不会重新发送。</p>
      <label className="field"><span>输入“{currentRetry.confirm_text}”确认继续</span><input required autoComplete="off" value={confirmText} onChange={event => setConfirmText(event.target.value)} /></label>
      <button className="danger" disabled={recovery.busy || confirmText !== currentRetry.confirm_text}>确认继续未发送步骤</button>
      <button type="button" className="secondary" disabled={recovery.busy} onClick={() => setConfirmRetry(null)}>返回</button>
    </form>}
    {batches.map(batch => <CascadeProgress key={batch.id} batch={batch} busy={recovery.busy} onAction={next => void action(batch, next)} />)}
  </section>;
}
