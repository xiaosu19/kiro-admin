import { useEffect, useRef, useState, type FormEvent } from "react";
import { NavLink } from "react-router-dom";
import { nativeAccess, independentUserAccess, subscriptionSourceLabel } from "./nativeSubscriptionsLogic";
import { matchesSelection } from "./selectionSearch";
import { date, type CurrentPlan, type PlanChange, type PlanChangeOptions, type RecordItem } from "./api";
import { usePlanChangeAdmission, usePlanChangeData, usePlanChangeRecovery, type PlanChangeIntent } from "./planChangeRequests";
import {
  canConfirmNotApplied, canConfirmPlanChange, canSubmitNotApplied, canWithdrawPlanChange,
  isPlanChangeOperation, needsPlanReview, planChangeDirection, planChangeState, targetUnavailableReason,
} from "./planChangesLogic";

const observationMismatch = "系统记录与 AWS 最近观测不一致，请先核对 AWS 状态。";
function planObservation(record: RecordItem, currentPlan = record.current_plan) {
  const managed = currentPlan?.name || currentPlan?.subscription_type || (record.subscription_status === "active" ? record.plan_name : "未订阅");
  const observed = record.observed_plan_name || record.observed_subscription_type;
  const mismatch = currentPlan?.subscription_type && record.observed_subscription_type
    ? currentPlan.subscription_type !== record.observed_subscription_type
    : !!observed && !!currentPlan?.name && currentPlan.name !== observed;
  return { managed, observed, mismatch };
}

export function CurrentPlanFacts({ record, currentPlan }: { record: RecordItem; currentPlan?: CurrentPlan }) {
  const { managed, observed, mismatch } = planObservation(record, currentPlan);
  return <>
    <div><dt>当前套餐（系统记录）</dt><dd>{managed || "等待核对"}</dd></div>
    <div><dt>当前授权来源</dt><dd>{subscriptionSourceLabel(record)}</dd></div>
    {record.subscription_source === "GROUP" && !nativeAccess(record) && <div><dt>历史授权来源</dt><dd>原生分组 · GROUP（历史保留）</dd></div>}
    {record.native_group_subscription && !nativeAccess(record) && ["pending", "needs_review"].includes(record.native_group_subscription.state) && <div><dt>待确认分组套餐</dt><dd>{record.native_group_subscription.plan_name} · 尚未确认生效</dd></div>}
    {record.direct_user_plan?.subscription_type && <div><dt>独立 USER 套餐</dt><dd>{record.direct_user_plan.name || record.direct_user_plan.subscription_type} · {record.direct_user_status}</dd></div>}
    {record.aws_subscription_status && <div><dt>AWS 订阅状态</dt><dd>{record.aws_subscription_status}</dd></div>}
    <div><dt>AWS 最近观测套餐</dt><dd>{observed || "尚未同步"}{mismatch && <small className="plan-observation-warning error-text">{observationMismatch}</small>}</dd></div>
  </>;
}

export function RecordPlanLabel({ record, directory }: { record: RecordItem; directory: boolean }) {
  if (!directory) return <>{record.plan_name}</>;
  const { managed, observed, mismatch } = planObservation(record);
  return <>
    <span>当前（系统记录）：{managed}</span>
    {record.effective_subscription_source && <small>来源：{subscriptionSourceLabel(record)}</small>}
    {record.subscription_source === "GROUP" && !nativeAccess(record) && <small>历史来源：原生分组 · GROUP</small>}
    {record.native_group_subscription && !nativeAccess(record) && ["pending", "needs_review"].includes(record.native_group_subscription.state) && <small>待确认分组套餐：{record.native_group_subscription.plan_name} · 尚未确认生效</small>}
    {observed && <small>AWS 最近观测：{observed}</small>}
    {mismatch && <small className="plan-observation-warning error-text">{observationMismatch}</small>}
    {record.pending_plan && <small className="plan-change-pending">待生效：{record.pending_plan.name || record.pending_plan.subscription_type} · 预计 {date(record.pending_plan.expected_effective_at)}</small>}
  </>;
}

export function PlanChangeTargets({ record, options, value, disabled, onChange }: {
  record: RecordItem; options: PlanChangeOptions; value: number; disabled: boolean; onChange: (id: number) => void;
}) {
  const [query, setQuery] = useState("");
  const matches = (target: PlanChangeOptions["targets"][number]) => matchesSelection(query, target.name, target.plan_id, target.subscription_type);
  const selected = options.targets.find(target => target.plan_id === value);
  return <fieldset className="plan-change-targets" disabled={disabled}>
    <legend>目标套餐</legend>
    <input className="selection-collection-search" type="search" aria-label="搜索目标套餐" placeholder="搜索套餐名称或 ID" value={query} onChange={event => setQuery(event.target.value)} onKeyDown={event => { if (event.key === "Enter") event.preventDefault(); }} />
    {selected && <p className="selection-current">已选：{selected.name}</p>}
    {[...options.targets].sort((a, b) => a.reference.monthly_price_usd - b.reference.monthly_price_usd).map(target => {
      const reason = targetUnavailableReason(record, options, target);
      return <label key={target.plan_id} hidden={!matches(target)} className={`plan-change-target${value === target.plan_id ? " selected" : ""}${reason ? " unavailable" : ""}`}>
        <input type="radio" name="target_plan_id" value={target.plan_id} checked={value === target.plan_id} disabled={disabled || !!reason}
          onChange={() => onChange(target.plan_id)} />
        <span>
          <strong>{target.name}</strong><span className="plan-change-price">${target.reference.monthly_price_usd} / 月</span>
          <small>{target.reference.monthly_credits.toLocaleString("en-US")} credits · {planChangeDirection[target.direction]}</small>
          <small>{target.unlimited ? "创建者为管理员 · 不限次数" : `创建者剩余 ${target.remaining_count ?? 0} 次 · 已用 ${target.used_count} 次 · 预占 ${target.pending_count} 次`}</small>
          {reason && <small className="error-text">{reason}</small>}
        </span>
      </label>;
    })}
    {!options.targets.length && <p className="muted">暂无可选套餐。</p>}
    {!!options.targets.length && !options.targets.some(matches) && <p className="selection-empty" role="status">没有匹配的套餐，已选套餐会保留。</p>}
  </fieldset>;
}

export function PlanChangeHistory({ history, busy, now, onRecheck, onRelease }: {
  history: PlanChange[]; busy: boolean; now: number;
  onRecheck: (change: PlanChange) => void; onRelease: (change: PlanChange) => void;
}) {
  return <section className="plan-change-history" aria-label="套餐变更历史">
    <h4>套餐变更历史</h4>
    {!history.length && <p className="muted">暂无套餐变更。</p>}
    {history.map(change => <article key={change.id} data-change-id={change.id}>
      <div className="plan-change-heading">
        <strong>{change.from_plan_name || change.from_type || "未知套餐"} → {change.to_plan_name || change.to_type || "未知套餐"}</strong>
        <span className={`badge ${change.state === "applied" ? "completed" : change.state === "needs_review" || change.state === "failed" ? "failed" : "queued"}`}>{planChangeState[change.state]}</span>
      </div>
      <p>{planChangeDirection[change.direction]} · {change.reserved ? "预占 1 次" : "无预占"} · {change.counted ? "已计入 1 次" : "尚未计次"} · {change.direction === "withdraw" ? "撤回不额外计次" : change.cycle_number ? `第 ${change.cycle_number} 轮` : "不限次数"}</p>
      <dl className="plan-change-times">
        <div><dt>申请时间</dt><dd>{date(change.requested_at)}</dd></div>
        <div><dt>实际生效</dt><dd>{change.applied_at ? date(change.applied_at) : "尚未确认"}</dd></div>
        <div><dt>预计生效</dt><dd>{change.expected_effective_at ? date(change.expected_effective_at) : "—"}</dd></div>
        {change.checked_at && <div><dt>最近核对</dt><dd>{date(change.checked_at)}</dd></div>}
      </dl>
      {change.error && <p className="error-text">{change.error}</p>}
      {(change.state === "needs_review" || change.state === "scheduled") && <div className="plan-change-controls">
        <button type="button" className="secondary" disabled={busy} onClick={() => onRecheck(change)}>只读核对 AWS</button>
        {needsPlanReview(change) && <button type="button" className="text-button" disabled={busy || !canConfirmNotApplied(change, now)} onClick={() => onRelease(change)}>确认未生效</button>}
      </div>}
      {needsPlanReview(change) && <small className="muted">写入请求满 10 分钟后可确认未生效；系统会再次只读核实，确认后才释放预占。</small>}
    </article>)}
  </section>;
}

interface PlanChangeProps {
  actorId: number; record: RecordItem; onChanged: () => void;
}
export function PlanChangeManager({ enabled = false, ...props }: PlanChangeProps & { enabled?: boolean }) {
  if (enabled && nativeAccess(props.record) && !independentUserAccess(props.record)) return <section className="plan-change-manager"><p>原生分组授权不能单独变更套餐，请管理分组订阅。</p>{props.record.native_group_subscription && <NavLink to={`/groups?group_id=${encodeURIComponent(props.record.native_group_subscription.group_id)}`}>管理分组订阅</NavLink>}</section>;
  return enabled ? <EnabledPlanChangeManager {...props} /> : null;
}
function EnabledPlanChangeManager({ actorId, record, onChanged }: PlanChangeProps) {
  const data = usePlanChangeData(actorId, record.id);
  const admission = usePlanChangeAdmission(actorId, record.id);
  const recovery = usePlanChangeRecovery(actorId, record.id);
  const [open, setOpen] = useState(!!admission.pending || !!record.pending_plan || isPlanChangeOperation(record.operation?.kind || ""));
  const [targetId, setTargetId] = useState(0), [username, setUsername] = useState(""), [acknowledged, setAcknowledged] = useState(false);
  const [withdrawing, setWithdrawing] = useState(false), [withdrawName, setWithdrawName] = useState(""), [withdrawAck, setWithdrawAck] = useState(false);
  const [releaseId, setReleaseId] = useState(""), [releaseName, setReleaseName] = useState(""), [reason, setReason] = useState(""), [releaseAck, setReleaseAck] = useState(false);
  const [notice, setNotice] = useState("");
  const identity = `${actorId}:${record.id}`, active = useRef(""), generation = useRef(0), inFlight = useRef(false);
  useEffect(() => {
    active.current = identity; generation.current += 1; inFlight.current = false;
    setTargetId(0); setUsername(""); setAcknowledged(false); setWithdrawing(false); setWithdrawName(""); setWithdrawAck(false);
    setReleaseId(""); setReleaseName(""); setReason(""); setReleaseAck(false); setNotice("");
    return () => { active.current = ""; generation.current += 1; };
  }, [identity]);
  const busy = admission.busy || recovery.busy;
  const frozen = busy || !!admission.pending;
  const options = data.options, pending = options?.pending_change;
  const target = options?.targets.find(item => item.plan_id === targetId);
  const release = data.history.find(item => item.id === releaseId);
  const savedTargetId = admission.pending?.kind === "change" ? admission.pending.body.target_plan_id : null;
  const now = Date.now();
  const confirmChange = canConfirmPlanChange(record, options, target, username, acknowledged);
  const confirmWithdrawal = canWithdrawPlanChange(record, options) && withdrawName === record.username && withdrawAck;

  // The shared lock also serializes clicks across paid admission and read-only
  // recovery before React has rendered either hook's busy state.
  async function run(work: () => Promise<PlanChange | null>) {
    if (active.current !== identity || inFlight.current) return;
    const current = generation.current;
    const isCurrent = () => active.current === identity && generation.current === current;
    inFlight.current = true; setNotice("");
    try {
      const result = await work();
      if (!result || !isCurrent()) return;
      setUsername(""); setAcknowledged(false); setTargetId(0); setWithdrawing(false); setWithdrawName(""); setWithdrawAck(false);
      setReleaseId(""); setReleaseName(""); setReason(""); setReleaseAck(false);
      setNotice("请求已受理，页面会自动更新；实际生效及次数以 AWS 核对结果为准。");
      void data.refresh(); onChanged();
    } finally { if (isCurrent()) inFlight.current = false; }
  }
  async function changePlan(event: FormEvent) {
    event.preventDefault();
    if (frozen || !confirmChange || !options || !target) return;
    const intent: PlanChangeIntent = { kind: "change", body: { target_plan_id: target.plan_id, expected_current_type: options.current_plan.subscription_type!, confirm_username: username, request_key: crypto.randomUUID() } };
    await run(() => admission.submit(intent));
  }
  async function withdraw(event: FormEvent) {
    event.preventDefault();
    if (frozen || !confirmWithdrawal || !pending || !options) return;
    const intent: PlanChangeIntent = { kind: "withdraw", change_id: pending.id, body: { expected_current_type: options.current_plan.subscription_type!, confirm_username: withdrawName, request_key: crypto.randomUUID() } };
    await run(() => admission.submit(intent));
  }
  async function recheck(item: PlanChange) {
    if (busy || !["needs_review", "scheduled"].includes(item.state)) return;
    await run(() => recovery.submit(item.id, "recheck", { confirm_username: record.username }));
  }
  async function confirmNotApplied(event: FormEvent) {
    event.preventDefault();
    if (busy || !release || !canSubmitNotApplied(release, record.username, releaseName, reason, releaseAck)) return;
    await run(() => recovery.submit(release.id, "confirm-not-applied", { confirm_username: releaseName, reason: reason.trim(), acknowledge_not_applied: true }));
  }
  return <section className="plan-change-manager">
    <div className="plan-change-heading">
      <h3>套餐变更</h3>
      <button type="button" className="secondary" data-testid="plan-change-toggle" aria-expanded={open} aria-controls={`plan-change-${record.id}`} onClick={() => setOpen(!open)}>{open ? "收起套餐变更" : "更改套餐"}</button>
    </div>
    {!open && <p className="muted">升级立即生效，降级下月生效。可在此查看变更历史和核对处理结果。</p>}
    {open && <div id={`plan-change-${record.id}`}>
      <dl className="record-facts plan-change-facts">
        <div><dt>首次开通套餐 · 只读</dt><dd>{record.plan_name || "—"}</dd></div>
        <div><dt>首次订阅时间 · 只读</dt><dd>{date(record.subscribed_at)}</dd></div>
        <CurrentPlanFacts record={record} />
        {options?.current_plan.subscription_type && <p>本次变更独立 USER 套餐：{options.current_plan.name || options.current_plan.subscription_type}</p>}
        <div><dt>待生效降级</dt><dd>{pending ? `${pending.to_plan_name || pending.to_type} · ${planChangeState[pending.state]}` : data.loading ? "读取中…" : "无"}</dd></div>
        {pending && <div><dt>预计生效时间</dt><dd>{date(pending.expected_effective_at)}（以 AWS 确认实际生效为准）</dd></div>}
      </dl>
      <p className="info-note">AWS 保留并重新核算本月已用 credits，升级不会清零用量。升级按新档计费，可能增加当月费用；参考月价以 AWS 结算规则为准。</p>
      <p className="muted">变更实际生效后计入目标套餐 1 次。降级先预占 1 次，AWS 确认生效后计次；撤回或改选的原预占在 AWS 确认后释放。额度属于这条记录的创建者。</p>
      {data.loading && <p role="status">正在读取套餐及变更历史…</p>}
      {(data.error || admission.error || recovery.error) && <div className="error" role="alert">{admission.error || recovery.error || data.error}</div>}
      {data.error && <button type="button" className="text-button" onClick={() => void data.refresh()}>重新读取套餐信息</button>}
      {notice && <p className="info-note" role="status">{notice}</p>}
      {admission.pending && <div className="plan-change-recovery info-note" role="status">
        <strong>上次{admission.pending.kind === "withdraw" ? "撤回" : "套餐变更"}请求的结果尚待确认</strong>
        <p>用户名：{admission.pending.body.confirm_username}。{savedTargetId ? `目标：${options?.targets.find(item => item.plan_id === savedTargetId)?.name || `套餐 #${savedTargetId}`}。` : "撤回原待生效降级。"}继续原请求会沿用原确认内容，防止重复计次。</p>
        <button type="button" className="secondary" data-testid="plan-change-resume" disabled={busy} onClick={() => run(() => admission.submit())}>{busy ? "正在核对…" : "继续原请求"}</button>
      </div>}
      {options?.unavailable_reason && <p className="error-text">{options.unavailable_reason}</p>}
      {options && <form data-testid="plan-change-form" onSubmit={changePlan} className="plan-change-form">
        {pending && <p className="info-note">改选其他套餐会替换待生效降级。原预占保留到 AWS 确认替换成功。</p>}
        <PlanChangeTargets record={record} options={options} value={targetId} disabled={frozen} onChange={setTargetId} />
        <label className="field"><span>输入完整用户名以确认套餐变更</span><input data-testid="plan-confirm-username" value={username} onChange={event => setUsername(event.target.value)} placeholder={record.username} autoComplete="off" required disabled={frozen} /></label>
        <label className="check"><input data-testid="plan-billing-ack" type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} required disabled={frozen} />我已了解 AWS 计费规则及目标套餐预占、计次规则</label>
        <button className="primary" data-testid="plan-change-submit" disabled={frozen || !confirmChange}>{busy ? "提交中…" : pending ? "确认改选套餐" : "确认更改套餐"}</button>
      </form>}
      {pending && <div className="plan-change-withdraw">
        <p>可在降级生效前撤回，不额外占用套餐次数；确认 AWS 已撤回后释放原预占。</p>
        <button type="button" className="secondary" data-testid="plan-withdraw-open" disabled={frozen || !canWithdrawPlanChange(record, options)} onClick={() => setWithdrawing(!withdrawing)}>{withdrawing ? "收起撤回确认" : "撤回待生效降级"}</button>
        {withdrawing && <form data-testid="plan-withdraw-form" onSubmit={withdraw}>
          <label className="field"><span>输入完整用户名以确认撤回</span><input data-testid="plan-withdraw-username" autoComplete="off" required value={withdrawName} onChange={event => setWithdrawName(event.target.value)} disabled={frozen} placeholder={record.username} /></label>
          <label className="check"><input data-testid="plan-withdraw-ack" type="checkbox" required checked={withdrawAck} onChange={event => setWithdrawAck(event.target.checked)} disabled={frozen} />我确认保留当前套餐，原预占在 AWS 确认撤回后释放</label>
          <button className="secondary" data-testid="plan-withdraw-submit" disabled={frozen || !confirmWithdrawal}>确认撤回降级</button>
        </form>}
      </div>}
      <PlanChangeHistory history={data.history} busy={busy} now={now} onRecheck={recheck} onRelease={item => { setReleaseId(item.id); setReleaseName(""); setReason(""); setReleaseAck(false); }} />
      {release && <form data-testid="plan-release-form" className="plan-change-release" onSubmit={confirmNotApplied}>
        <h4>确认变更未生效 · {release.from_plan_name} → {release.to_plan_name}</h4>
        <p className="muted">写入请求至少满 10 分钟后，提供核实说明。服务端会再次只读查询 AWS；只有确认未生效后才释放预占。</p>
        <label className="field"><span>输入完整用户名以确认未生效</span><input data-testid="plan-release-username" autoComplete="off" required value={releaseName} onChange={event => setReleaseName(event.target.value)} disabled={busy} placeholder={record.username} /></label>
        <label className="field"><span>核实说明（至少 5 字）</span><textarea data-testid="plan-release-reason" minLength={5} maxLength={500} required value={reason} onChange={event => setReason(event.target.value)} disabled={busy} /></label>
        <label className="check"><input data-testid="plan-release-ack" type="checkbox" required checked={releaseAck} onChange={event => setReleaseAck(event.target.checked)} disabled={busy} />我已核实该变更未生效，理解系统将再次核对 AWS</label>
        <div className="plan-change-controls">
          <button type="button" className="secondary" disabled={busy} onClick={() => setReleaseId("")}>返回</button>
          <button className="primary" data-testid="plan-release-submit" disabled={busy || !canSubmitNotApplied(release, record.username, releaseName, reason, releaseAck, now)}>确认未生效并核对</button>
        </div>
      </form>}
    </div>}
  </section>;
}
