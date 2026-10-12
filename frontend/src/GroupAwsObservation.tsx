import { date } from "./api";
import type { ObservationEntry } from "./groupObservationRequests";

export function AwsObservationNote({ entry }: { entry?: ObservationEntry }) {
  return <span className={entry?.error ? "error-text" : "muted"}>
    {entry?.loading ? "正在读取 AWS…" : entry?.stale ? "本地状态已变化，请刷新 AWS" : entry?.error ? "AWS 状态暂不可用" : "尚未读取 AWS"}
    {entry?.error && <small role="alert">{entry.error}</small>}
  </span>;
}
export function AwsGroupValue({ entry, field }: { entry?: ObservationEntry; field: "members" | "subscription" | "pending" }) {
  const data = entry?.data;
  if (!data) return <AwsObservationNote entry={entry} />;
  const subscription = data.subscription;
  if (field === "members") return data.directory.exists ? <>
    <strong>AWS 实际成员 {data.directory.member_count} 人</strong>
    <small>匹配本地所有者的 SSO {data.directory.owned_members.length} 人</small>
  </> : <span className="error-text">AWS 身份目录中不存在</span>;
  if (field === "pending") return subscription.pending_plan_label ? <>
    <strong>{subscription.pending_plan_label}</strong><small>生效：{date(subscription.effective_at)}</small>
  </> : subscription.cancellation_expires_at ? <><strong>取消到期</strong><small>{date(subscription.cancellation_expires_at)}</small></> : <span className="muted">无待生效变更</span>;
  return <>
    <strong>{subscription.plan_label || "未订阅"}</strong>
    <small>{subscription.status} · GROUP</small>
    {subscription.status === "Canceled" && <small>{subscription.access_active ? "到期前仍可访问" : "访问已结束"}</small>}
  </>;
}
export function GroupAwsPanel({ entry, busy, refresh, disabled = false }: { entry?: ObservationEntry; busy: boolean; refresh: () => void; disabled?: boolean }) {
  const data = entry?.data;
  return <section className="panel group-aws-panel" aria-label="AWS 实际状态">
    <div className="group-section-heading"><div><h2>AWS 实际状态</h2>
      <p className="muted">手动读取当前身份目录与 Kiro GROUP 订阅。查询结果与下方本地历史分别展示。</p></div>
      <button className="secondary" disabled={busy || disabled} onClick={refresh}>{busy ? "正在读取 AWS…" : "刷新此分组的 AWS 状态"}</button></div>
    {!data ? <p role="status"><AwsObservationNote entry={entry} /></p> : <>
      <p className="muted">查询时间：{date(data.queried_at)}</p>
      <div className="group-aws-grid">
        <div><h3>Identity Center 成员</h3><p>{data.directory.exists ? <strong>{data.directory.name}</strong> : "AWS 身份目录中不存在"}</p><AwsGroupValue entry={entry} field="members" /></div>
        <div><h3>Kiro GROUP 订阅</h3><AwsGroupValue entry={entry} field="subscription" /></div>
        <div><h3>待生效套餐 / 取消日期</h3><AwsGroupValue entry={entry} field="pending" /></div>
      </div>
      {!!data.directory.owned_members.length && <details className="group-aws-matches"><summary>当前 AWS 成员中匹配的本地 SSO（{data.directory.owned_members.length}）</summary>
        <ul>{data.directory.owned_members.map(member => <li key={member.record_id}><strong>{member.username}</strong> <span>{member.email}</span></li>)}</ul></details>}
    </>}
  </section>;
}
