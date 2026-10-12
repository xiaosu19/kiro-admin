import { SearchableSelect } from "./SearchableSelect";
import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { date, type CancellationMode, type Counter, type GroupActivation, type GroupItem, type LifecycleBatch, type LifecycleItem, type LifecycleKind, type NativeGrant, type NativeOperation, type NativePreview, type Plan, type RecordItem, type User } from "./api";
import { useRemote } from "./groupRequests";
import { useLifecycleAdmission, useLifecycleRecheck, useNativePreview } from "./nativeSubscriptionRequests";
import { activeNativeGroup, canCancelGroup, canCancelRecord, canSubscribeGroup, intentIds, lifecycleNames, lifecycleStates, nativeAccess, nativeGrantStates, nativeIntent, supportsRecordScheduledCancellation, validLifecycleBatch } from "./nativeSubscriptionsLogic";

type Admission = ReturnType<typeof useLifecycleAdmission>;
function NativeDialog({ title, busy, close, children }: { title: string; busy: boolean; close: () => void; children: ReactNode }) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => { dialog.current?.showModal(); }, []);
  return <dialog ref={dialog} className="modal proxy-dialog group-dialog" aria-label={title} onCancel={event => { event.preventDefault(); if (!busy) close(); }}>
    <div className="modal-title"><h2>{title}</h2><button type="button" className="icon-button" aria-label="关闭" disabled={busy} onClick={close}>×</button></div>{children}
  </dialog>;
}
export function GroupJoinNotice({ group, count }: { group?: GroupItem | null; count?: number }) {
  return activeNativeGroup(group) ? <div className="info-note native-warning">
    <strong>加入「{group!.name}」将自动获得 {group!.native_subscription!.plan_name} 付费套餐。</strong>
    <p>{count === undefined ? "每名新成员确认授权后消耗创建者该套餐 1 次" : `本次 ${count} 人，确认授权后消耗创建者该套餐 ${count} 次`}；剩余次数不足时无法加入。之后的新成员同样按人消耗 1 次。</p>
    <p>分组共同停止：{group!.native_subscription!.stop_at ? date(group!.native_subscription!.stop_at) : "未设置"}。后来加入的成员继承剩余时长，个人更早的截止时间仍有效。</p>
    {group!.native_subscription!.state === "cancel_scheduled" && <p>该组已取消续订，访问最多保留到 {date(group!.native_subscription!.access_ends_at)}。</p>}
  </div> : <p className="info-note">单独创建 SSO 不消耗 Kiro 套餐次数。未开通原生订阅的分组不会自动授予付费套餐；生效中的原生分组会自动授权并按人计次。</p>;
}
export function NativePreviewSummary({ preview }: { preview: NativePreview }) {
  return <div className="native-preview">
    <p><strong>已选 {preview.groups.length} 个完整分组 · 完整成员 {preview.member_count} 人</strong></p>
    <ul className="group-preview-list">{preview.groups.map(group => <li key={group.id}><strong>{group.name}</strong> · {group.member_count} 名完整成员</li>)}</ul>
    <p className="info-note">将为整个 AWS 分组开通付费订阅，用户名筛选不会缩小授权成员范围。每名成员确认授权后消耗创建者目标套餐 1 次。未来加入的成员自动获得同一套餐，并各消耗 1 次。</p>
    <p className="muted">天数规则从本次分组开通时间共同起算，后来加入的成员继承剩余时长。预览不预占次数；提交时会重新核对完整成员。</p>
  </div>;
}
export function CancellationFields({ groups, records, mode, onChange }: { groups?: GroupItem[]; records?: RecordItem[]; mode: CancellationMode; onChange: (mode: CancellationMode) => void }) {
  const supports = groups ? groups.length > 0 && groups.every(group => group.supports_scheduled_cancellation) : supportsRecordScheduledCancellation(records || []);
  const inherited = records?.filter(nativeAccess) || [];
  return <>
    {groups ? <p className="info-note">取消所选完整分组的付费授权，保留 SSO 和 AWS 分组成员关系。独立 USER 和其他 GROUP 授权继续保留。不会删除用户，历史成功次数不返还。</p> : <p>处理明确选中的 {records?.length || 0} 名用户的目标授权；保留 SSO 与历史成功次数。</p>}
    {!!inherited.length && <div className="info-note native-warning"><strong>移出 AWS 组并停止该组授权，保留 SSO</strong><p>{inherited.map(record => record.username).join("、")} 继承原生分组套餐，只支持立即移出成员；独立 USER 和其他 GROUP 授权继续保留，其他组成员继续保留授权。</p></div>}
    <label className="field"><span>取消方式</span><SearchableSelect aria-label="取消方式" value={supports ? mode : "IMMEDIATE"} onChange={event => onChange(event.target.value as CancellationMode)}>
      <option value="IMMEDIATE">立即停止访问</option>{supports && <option value="END_OF_PERIOD">月底停止访问</option>}
    </SearchableSelect></label>
    {!supports && <p className="muted">所选对象仅支持立即停止访问。</p>}
    {supports && mode === "END_OF_PERIOD" && <p className="muted">取消续订后，到 AWS 确认的到期时间前仍有访问权限；更早的分组或个人停止规则继续执行。当月费用按 AWS 规则结算。</p>}
  </>;
}
export function LifecycleRecovery({ admission, onAccepted }: { admission: Admission; onAccepted: (batch: LifecycleBatch) => void }) {
  const pending = admission.pending;
  return <>
    {admission.error && <p className="error" role="alert">{admission.error}</p>}
    {pending && <section className="info-note group-recovery" aria-label="恢复订阅请求" role="status">
      <strong>上次“{lifecycleNames[pending.kind]}”结果尚待确认</strong>
      <p>已冻结 {intentIds(pending).length} 个对象{pending.kind === "group_subscribe" ? `，套餐 #${pending.body.plan_id}` : `，${pending.body.cancellation_mode === "IMMEDIATE" ? "立即停止访问" : "月底停止访问"}`}。继续时使用相同选择、内容和请求标识；刷新页面不会自动提交。</p>
      <details><summary>查看原选择</summary><ul>{intentIds(pending).map(id => <li key={id} className="mono">{id}</li>)}</ul></details>
      <button className="secondary" type="button" disabled={admission.busy} onClick={async () => { const batch = await admission.submit(); if (batch) onAccepted(batch); }}>{admission.busy ? "正在确认…" : "继续原请求确认"}</button>
    </section>}
  </>;
}
export function NativeSubscriptionDialog({ kind, user, groups = [], records = [], admission, close, onAccepted }: {
  kind: LifecycleKind; user: User; groups?: GroupItem[]; records?: RecordItem[]; admission: Admission; close: () => void; onAccepted: (batch: LifecycleBatch) => void;
}) {
  const ids = kind === "user_cancel" ? records.map(record => record.id) : groups.map(group => group.id);
  const preview = useNativePreview(user.id, ids, kind === "group_subscribe" && !admission.pending);
  const plans = useRemote<Plan[]>(kind === "group_subscribe" ? "/plans" : null, 0, user.id);
  const counters = useRemote<Counter[]>(kind === "group_subscribe" ? "/counters" : null, 0, user.id);
  const [planId, setPlanId] = useState(0), [mode, setMode] = useState<CancellationMode>("IMMEDIATE");
  const [ack, setAck] = useState(false), [error, setError] = useState("");
  const frozen = admission.busy || !!admission.pending;
  const valid = ids.length > 0 && ids.length <= 100 && (kind === "group_subscribe" ? groups.every(canSubscribeGroup) && !!preview.data && preview.data.member_count <= 100 && planId > 0 : kind === "group_cancel" ? groups.every(canCancelGroup) : records.every(canCancelRecord));
  const plan = plans.data?.find(item => item.id === planId && item.active);
  const counts = new Map<number, number>();
  preview.data?.groups.forEach(group => counts.set(group.owner_id, (counts.get(group.owner_id) || 0) + group.member_count));
  async function submit(event: FormEvent) {
    event.preventDefault(); if (!valid || !ack || frozen) return;
    setError("");
    try {
      const allowed = kind === "group_cancel" ? groups.every(group => group.supports_scheduled_cancellation) : supportsRecordScheduledCancellation(records);
      const batch = await admission.submit(nativeIntent(kind, ids, kind === "group_subscribe" ? planId : allowed ? mode : "IMMEDIATE"));
      if (batch) onAccepted(batch);
      else if (kind === "group_subscribe") void preview.refresh();
    } catch (e) { setError((e as Error).message); }
  }
  return <NativeDialog title={lifecycleNames[kind]} busy={admission.busy} close={close}>
    {(error || preview.error || plans.error) && <p className="error" role="alert">{error || preview.error || plans.error}</p>}
    <form onSubmit={submit}><fieldset className="resource-fields" disabled={frozen}>
      {kind === "group_subscribe" ? <>
        {preview.loading && <p role="status">正在只读核对完整分组成员…</p>}
        {preview.data && <NativePreviewSummary preview={preview.data} />}
        {preview.error && <button type="button" className="secondary" onClick={() => void preview.refresh()}>重新读取分组预览</button>}
        <label className="field"><span>分组订阅套餐</span><SearchableSelect aria-label="分组订阅套餐" required value={planId || ""} onChange={event => { setPlanId(Number(event.target.value)); setAck(false); }}>
          <option value="">请选择付费套餐</option>{plans.data?.filter(plan => plan.active).map(plan => <option key={plan.id} value={plan.id}>{plan.name}{plan.reference ? ` · $${plan.reference.monthly_price_usd} / 月` : ""}</option>)}
        </SearchableSelect></label>
        {plan && <div className="native-quota"><strong>{plan.name} · 本次需 {preview.data?.member_count || 0} 次</strong>{[...counts].map(([owner, count]) => {
          const counter = counters.data?.find(item => item.user_id === owner && item.plan_id === planId);
          return <p key={owner}>创建者 {owner === user.id ? user.display_name || user.username : counter?.username || `#${owner}`}：本次 {count} 次 · {owner === user.id && user.role === "admin" ? "管理员不限次数" : counter ? `剩余 ${Math.max(0, counter.limit_count - counter.used_count - counter.pending_count)} 次（预占 ${counter.pending_count} 次）` : "剩余次数将在提交时校验"}</p>;
        })}</div>}
        {counters.error && <p className="muted">剩余次数暂不可用；提交时会核对剩余次数。</p>}
        {preview.data && preview.data.member_count > 100 && <p className="error">本次完整成员超过 100 人，请减少所选分组。</p>}
      </> : <>
        <p><strong>确认所选 {ids.length} 个{kind === "group_cancel" ? "分组" : "SSO 用户"}</strong></p>
        <ul className="group-preview-list">{kind === "group_cancel" ? groups.map(group => <li key={group.id}>{group.name} · {group.native_subscription?.plan_name}{group.counts ? ` · 现存成员 ${group.counts.active} 人` : ""}</li>) : records.map(record => <li key={record.id}>{record.username} · {record.current_plan?.name || record.plan_name} · {nativeAccess(record) ? "原生分组 GROUP" : "个人 USER"}</li>)}</ul>
        <CancellationFields {...(kind === "group_cancel" ? { groups } : { records })} mode={mode} onChange={setMode} />
      </>}
      <label className="check-line"><input type="checkbox" required checked={ack} onChange={event => setAck(event.target.checked)} />{kind === "group_subscribe" ? "我已确认完整分组与次数消耗" : "我已确认所选对象与取消方式"}</label>
      {!valid && !preview.loading && <p className="muted">请核对完整选择与当前状态；有任务待处理或已取消的对象不能重复提交。</p>}
      <div className="modal-actions"><button type="button" className="secondary" onClick={close}>返回</button><button className={kind === "group_subscribe" ? "primary" : "danger"} disabled={!valid || !ack || frozen || kind === "group_subscribe" && !plan}>{kind === "group_subscribe" ? "确认开通分组订阅" : kind === "group_cancel" ? "确认取消分组订阅" : "确认取消所选订阅"}</button></div>
    </fieldset></form>
    {admission.pending && <p className="info-note">请求结果尚待确认。关闭此窗口后，在页面顶部继续原请求。</p>}
    {admission.error && <p className="error" role="alert">{admission.error}</p>}
  </NativeDialog>;
}
export function LifecycleBatchView({ batch, busy, onRecheck }: { batch: LifecycleBatch; busy: boolean; onRecheck: (item: LifecycleItem) => void }) {
  return <article className="native-batch" data-batch-id={batch.id}>
    <div className="group-section-heading"><strong>{lifecycleNames[batch.kind]}</strong><small>{date(batch.created_at)}</small></div>
    <p className="native-batch-counts" aria-live="polite">共 {batch.total} 项 · {Object.entries(lifecycleStates).map(([state, name]) => `${name} ${batch.states[state as keyof typeof lifecycleStates] || 0}`).join(" · ")}</p>
    <div className="table-wrap"><table><thead><tr><th>对象</th><th>状态</th><th>结果 / 原因</th><th>恢复</th></tr></thead><tbody>{batch.items.map(item => <tr key={item.id}>
      <td>{item.name}<small>{item.principal_type === "GROUP" ? "完整分组 · GROUP" : "所选 SSO 用户"}</small></td><td><span className={`badge ${item.state === "completed" ? "completed" : ["failed", "needs_review"].includes(item.state) ? "failed" : ""}`}>{lifecycleStates[item.state]}</span></td>
      <td>{item.error || (item.state === "completed" ? "已确认完成" : "等待后台确认")}</td>
      <td>{item.state === "needs_review" ? <button className="secondary" aria-label={`只读核对 AWS ${item.name}`} disabled={busy} onClick={() => onRecheck(item)}>只读核对 AWS</button> : item.state === "failed" ? <span className="muted">确认失败；修正原因后可重新选择提交</span> : "—"}</td>
    </tr>)}</tbody></table></div>
  </article>;
}
export function LifecycleHistory({ actorId, version = 0, groupId, initialBatch }: { actorId: number; version?: number; groupId?: string; initialBatch?: LifecycleBatch | null }) {
  const inScope = (batch: unknown): batch is LifecycleBatch => validLifecycleBatch(batch) && (!groupId || batch.items.some(item => item.principal_type === "GROUP" && item.id === groupId));
  const initial = inScope(initialBatch) ? initialBatch : null;
  const scope = `${actorId}:${groupId || "all"}`;
  const batches = useRemote<LifecycleBatch[]>("/lifecycle-batches", 3000, actorId);
  const [selection, setSelection] = useState({ scope, id: initial?.id || null });
  const opened = selection.scope === scope ? selection.id : initial?.id || null;
  const recovery = useLifecycleRecheck(actorId, groupId || "all");
  const detail = useRemote<LifecycleBatch>(opened ? `/lifecycle-batches/${encodeURIComponent(opened)}` : null, 3000, actorId);
  useEffect(() => { void batches.refresh(); setSelection({ scope, id: initial?.id || null }); }, [version, initial?.id, scope, batches.refresh]);
  const list = (Array.isArray(batches.data) ? batches.data : []).filter(inScope);
  const chosen = inScope(detail.data) && detail.data.id === opened ? detail.data : list.find(batch => batch.id === opened) || (initial?.id === opened ? initial : null);
  async function recheck(item: LifecycleItem) {
    if (await recovery.submit(item)) { void batches.refresh(); void detail.refresh(); }
  }
  return <section className="panel native-history" aria-label="订阅批次与进度"><div className="group-section-heading"><div><h2>订阅批次与进度</h2><p className="muted">最近 100 个批次；已完成、失败和待核对结果逐项保留。待核对只读取 AWS 结果。</p></div><button className="secondary" onClick={() => { void batches.refresh(); void detail.refresh(); }}>刷新批次</button></div>
    {(recovery.error || batches.error || detail.error) && <p className="error" role="alert">{recovery.error || batches.error || detail.error}</p>}
    {!list.length && !initial && <p className="muted">{batches.loading ? "正在读取订阅批次…" : "暂无订阅批次。"}</p>}
    <div className="native-batch-list">{list.map(batch => <button type="button" className={opened === batch.id ? "secondary active" : "text-button"} key={batch.id} onClick={() => setSelection({ scope, id: batch.id })}>{lifecycleNames[batch.kind]} · {date(batch.created_at)} · 完成 {batch.states.completed}/{batch.total}{batch.states.failed ? ` · 失败 ${batch.states.failed}` : ""}{batch.states.needs_review ? ` · 待核对 ${batch.states.needs_review}` : ""}</button>)}</div>
    {chosen && <LifecycleBatchView batch={chosen} busy={recovery.busy} onRecheck={item => void recheck(item)} />}
  </section>;
}
export function NativeGroupHistory({ actorId, group }: { actorId: number; group: GroupItem }) {
  const history = useRemote<{ grants: NativeGrant[]; operations: NativeOperation[] }>(`/groups/${encodeURIComponent(group.id)}/native-subscriptions`, 3000, actorId);
  const recovery = useLifecycleRecheck(actorId, group.id);
  return <section className="panel native-history" aria-label="原生分组订阅历史"><h2>原生分组订阅历史</h2>
    {(history.error || recovery.error) && <p className="error" role="alert">{history.error || recovery.error}</p>}
    {(history.data?.grants || []).map(grant => <article className="native-grant" key={grant.id}><strong>{grant.plan_name} · GROUP</strong><span className="badge">{nativeGrantStates[grant.state]}</span><p>开通：{date(grant.activated_at)} · 共同停止：{date(grant.stop_at)}{grant.cancelled_at && ` · 取消：${date(grant.cancelled_at)}`}{grant.access_ends_at && ` · AWS 到期：${date(grant.access_ends_at)}`}</p>
      {history.data?.operations.filter(operation => operation.grant_id === grant.id).map(operation => <p key={operation.id}>{operation.automatic ? "定时停止 · " : ""}{operation.kind === "subscribe" ? "开通分组" : "取消分组"} · {lifecycleStates[operation.state]} · {operation.member_count} 人{operation.error && <span className="error-text"> · {operation.error}</span>}{operation.state === "needs_review" && <button className="text-button" disabled={recovery.busy} onClick={async () => { if (await recovery.submit({ id: group.id, name: group.name, principal_type: "GROUP", operation_id: operation.id, state: operation.state, phase: operation.phase, error: operation.error })) void history.refresh(); }}>只读核对该分组操作</button>}</p>)}
    </article>)}
    {!history.data?.grants.length && <p className="muted">{history.loading ? "正在读取原生订阅历史…" : "尚未开通原生分组订阅。"}</p>}
  </section>;
}
export function NativeMemberHistory({ actorId, record }: { actorId: number; record: RecordItem }) {
  const history = useRemote<GroupActivation[]>(`/subscriptions/${encodeURIComponent(record.id)}/group-activations`, 3000, actorId);
  return <section className="native-member-history" aria-label="分组授权历史"><h3>分组授权历史</h3>{history.error && <p className="error" role="alert">{history.error}</p>}
    {history.data?.map(item => <article key={item.id}><strong>{item.plan_name} · 原生分组 GROUP</strong><p>{item.counted ? "已消耗 1 次" : item.reserved ? "预占 1 次，等待授权确认" : "未计次"} · {item.first_opening ? "首次开通" : "后续授权"} · {item.state}</p><small>生效：{date(item.activated_at)} · 取消：{date(item.cancelled_at)}</small>{item.error && <p className="error-text">{item.error}</p>}</article>)}
    {!history.data?.length && <p className="muted">{history.loading ? "正在读取授权历史…" : "暂无分组授权历史。"}</p>}
    {record.native_group_subscription && <NavLink to={`/groups?group_id=${encodeURIComponent(record.native_group_subscription.group_id)}`}>查看分组订阅与历史</NavLink>}
  </section>;
}
