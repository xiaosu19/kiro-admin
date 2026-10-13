import { date, type RetryProgress } from "./api";

export function RetryStatus({ value }: { value: RetryProgress }) {
  if (value.propagation_state === "waiting") return <small role="status">
    订阅已提交，等待 AWS 同步成员。后台会自动核对，确认后继续改密和导出。
    <br />上次核对：{date(value.propagation_last_checked_at)} · 下次核对：{date(value.next_retry_at)}
    <br />等待截止：{date(value.propagation_deadline)}（最长 24 小时）。无需重复开通订阅。
  </small>;
  if (value.propagation_state === "timed_out") return <small className="error-text">
    AWS 订阅同步超过 24 小时，已停止自动等待。请核对原订阅请求；不会重复开通，也不会导出未确认订阅的账号。
  </small>;
  if (!value.automatic_retry_count) return null;
  return <small>自动重试 {value.automatic_retry_count}/{value.automatic_retry_limit || 5}
    {value.next_retry_at ? ` · ${value.retry_mode === "reconcile" ? "只读核对" : "下次重试"}：${date(value.next_retry_at)}` : value.retry_exhausted ? " · 已达上限，请核对后处理" : ""}</small>;
}
