let csrf = "";
export function setCsrf(value: string) {
  csrf = value;
}
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
  ) {
    super(message);
  }
}
export async function api<T = unknown>(
  path: string,
  method = "GET",
  body?: unknown,
): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method,
    credentials: "same-origin",
    ...(path.startsWith("/auth-batches") ? { cache: "no-store" as const } : {}),
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res
    .json()
    .catch(() => ({ detail: "服务暂时不可用，请稍后重试" }));
  if (!res.ok) {
    if (res.status === 401 && path !== "/auth/login")
      window.dispatchEvent(new Event("session-expired"));
    throw new ApiError(
      `${data.detail || "操作失败"}${data.fields?.length ? `（${data.fields.join("、")}）` : ""}`,
      res.status,
    );
  }
  return data as T;
}
// Scope checks run before interpreting errors, so an older login cannot expire a newer session.
export async function groupRequest<T>(path: string, method = "GET", body?: unknown,
  isCurrent = () => true, signal?: AbortSignal): Promise<T | null> {
  const session = csrf;
  if (!isCurrent()) return null;
  const res = await fetch(`/api${path}`, {
    method, credentials: "same-origin", cache: "no-store", signal,
    headers: { "Content-Type": "application/json", "X-CSRF-Token": session },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({ detail: "服务暂时不可用，请稍后重试" }));
  if (!isCurrent() || session !== csrf) return null;
  if (!res.ok) {
    if (res.status === 401) window.dispatchEvent(new Event("session-expired"));
    throw new ApiError(data.detail || "操作失败", res.status);
  }
  return data as T;
}
export interface RecordScope {
  q?: string;
  status?: string;
  state?: string;
  owner_id?: number;
  group_id?: string;
  aws_account_id?: number;
}
export type LoginExportFormat = "csv" | "txt";
export function recordQuery(scope: RecordScope) {
  return new URLSearchParams(Object.entries(scope).filter(([, value]) => value !== undefined).map(([key, value]) => [key, String(value)])).toString();
}
export function loginExportBody(scope: RecordScope, recordIds?: string[], format: LoginExportFormat = "csv") {
  return { ...scope, ...(recordIds ? { record_ids: recordIds } : {}), format };
}
export async function downloadLogins(body: Record<string, unknown>) {
  const res = await fetch("/api/sso-users/export", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const data = await res.json().catch(() => ({ detail: "导出失败，请重试" }));
    if (res.status === 401) window.dispatchEvent(new Event("session-expired"));
    throw new ApiError(data.detail || "导出失败", res.status);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download =
    res.headers.get("Content-Disposition")?.match(/filename="([^"]+)"/)?.[1] ||
    `sso-logins.${body.format === "txt" ? "txt" : "csv"}`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return Number(res.headers.get("X-Export-Count") || 0);
}
export const downloadCsv = downloadLogins;
// Numbered exports fence both the response and the Blob against scope/session
// changes; an old request cannot download private data into a newer session.
export async function downloadProvisioning(path: string, method: "GET" | "POST", body: unknown, isCurrent = () => true) {
  const session = csrf;
  if (!isCurrent()) return null;
  const res = await fetch(`/api${path}`, { method, credentials: "same-origin", cache: "no-store",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": session }, body: body === undefined ? undefined : JSON.stringify(body) });
  if (!isCurrent() || session !== csrf) return null;
  if (!res.ok) {
    const data = await res.json().catch(() => ({ detail: "下载失败，请刷新批次后重试" }));
    if (!isCurrent() || session !== csrf) return null;
    if (res.status === 401) window.dispatchEvent(new Event("session-expired"));
    throw new ApiError(data.detail || "下载失败", res.status);
  }
  const blob = await res.blob();
  if (!isCurrent() || session !== csrf) return null;
  const url = URL.createObjectURL(blob), link = document.createElement("a");
  try {
    link.href = url; link.download = res.headers.get("Content-Disposition")?.match(/filename="([A-Za-z0-9_.-]+)"/)?.[1] || "provisioning-export";
    document.body.appendChild(link); link.click();
  } finally { link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
  return { count: Number(res.headers.get("X-Export-Count") || 0), excluded: Number(res.headers.get("X-Excluded-Count") || 0) };
}
export interface Capabilities {
  plan_changes_enabled: boolean;
}
export interface User {
  id: number;
  username: string;
  display_name: string;
  role: "admin" | "member";
  active: boolean;
  must_change_password: boolean;
  account_ids?: number[];
}
export async function downloadAuthZip(batchId: string, isCurrent = () => true) {
  const result = await downloadProvisioning(`/auth-batches/${encodeURIComponent(batchId)}/download`, "POST", undefined, isCurrent);
  return result && { included: result.count, excluded: result.excluded };
}
export interface Account {
  account_number?: string | null;
  id: number;
  name: string;
  region: string;
  active: boolean;
  deleted_at?: string | null;
  usage?: ResourceUsage;
  bound_users?: number;
  portal_url: string;
  aws_account_id?: string;
  subscription_region?: string;
  control_plane?: string;
  identity_store_id?: string;
  instance_arn?: string;
  application_arn?: string;
  profile_arn?: string;
  proxy_id?: number | null;
  proxy_name?: string | null;
  proxy_status?: "direct" | "enabled" | "disabled" | "missing";
}
export type AwsReportView = "users" | "groups" | "subscriptions";
export interface AwsReportInput {
  view: AwsReportView;
  account_ids: number[];
  q?: string;
  row_ids?: string[] | null;
}
export interface AwsReportRow {
  id: string;
  account_id: number;
  account_name: string;
  values: string[];
}
export interface AwsReportResult {
  view: AwsReportView;
  columns: string[];
  rows: AwsReportRow[];
  total: number;
  account_ids: number[];
  generated_at: string;
}
export interface AwsCost {
  account_id: number;
  month: string;
  amount: string;
  currency: string;
  estimated: boolean;
  period_start: string;
  period_end: string;
  source: "aws_bills_console";
  billing_kind: "billable" | "proforma";
  payer_id: string;
  available_payers: string[];
  retrieved_at: string;
}
export async function awsReportRequest<T>(path: string, body?: unknown, isCurrent = () => true): Promise<T | null> {
  const res = await fetch(`/api${path}`, {
    method: body === undefined ? "GET" : "POST", credentials: "same-origin", cache: "no-store",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({ detail: "AWS 数据读取失败，请重试" }));
  if (!isCurrent()) return null;
  if (!res.ok) {
    if (res.status === 401) window.dispatchEvent(new Event("session-expired"));
    throw new ApiError(data.detail || "AWS 数据读取失败", res.status);
  }
  return data as T;
}
export async function downloadAwsReport(body: AwsReportInput, isCurrent = () => true): Promise<number | null> {
  const res = await fetch("/api/aws-reports/download", {
    method: "POST", credentials: "same-origin", cache: "no-store",
    headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: JSON.stringify(body),
  });
  if (!isCurrent()) return null;
  if (!res.ok) {
    const data = await res.json().catch(() => ({ detail: "AWS 报表下载失败，请重试" }));
    if (!isCurrent()) return null;
    if (res.status === 401) window.dispatchEvent(new Event("session-expired"));
    throw new ApiError(data.detail || "AWS 报表下载失败", res.status);
  }
  const blob = await res.blob();
  if (!isCurrent()) return null;
  const url = URL.createObjectURL(blob), link = document.createElement("a");
  try {
    link.href = url;
    link.download = res.headers.get("Content-Disposition")?.match(/filename="([A-Za-z0-9_.-]+)"/)?.[1] || `aws-${body.view}.${body.account_ids.length > 1 ? "zip" : "csv"}`;
    document.body.appendChild(link);
    link.click();
  } finally {
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  return Number(res.headers.get("X-Export-Count") || 0);
}
export interface ProxyItem {
  id: number;
  name: string;
  host: string;
  port: number;
  enabled: boolean;
  status: "enabled" | "disabled";
  auth_configured: boolean;
  binding_count: number;
  deleted_binding_count?: number;
  revision: number;
  last_probe_status: "ok" | "failed" | "auth_failed" | "timeout" | "connect" | "tls" | "invalid_response" | null;
  last_probe_at: string | null;
  egress_ip: string | null;
}
export interface Plan {
  id: number;
  name: string;
  code: string;
  subscription_type: string;
  active: boolean;
  deleted_at?: string | null;
  usage?: ResourceUsage;
  reference?: CatalogPlan | null;
}
export interface ResourceUsage {
  records: number;
  sso_active: number;
  subscriptions_active: number;
}
export interface CatalogPlan {
  name: string;
  code: string;
  subscription_type: string;
  monthly_price_usd: number;
  monthly_credits: number;
}
export interface PlanCatalog {
  items: CatalogPlan[];
  checked_at: string;
  pricing_url: string;
  billing_url: string;
}
export interface Counter {
  id: number;
  user_id: number;
  plan_id: number;
  plan_name: string;
  username: string;
  limit_count: number;
  used_count: number;
  pending_count: number;
  lifetime_count: number;
  cycle_number: number;
}
export interface RetryProgress {
  propagation_state?: "waiting" | "timed_out" | null;
  propagation_started_at?: string | null;
  propagation_last_checked_at?: string | null;
  propagation_deadline?: string | null;
  propagation_check_count?: number;
  automatic_retry_count?: number;
  automatic_retry_limit?: number;
  next_retry_at?: string | null;
  retry_mode?: "retry" | "reconcile" | null;
  retry_exhausted?: boolean;
}
export interface RecordItem extends RetryProgress {
  account_deleted_at?: string | null;
  internal_id?: string;
  account_number?: string;
  provisioning_batch_number?: string;
  id: string;
  plan_id: number | null;
  provision_only: boolean;
  batch_id: string | null;
  owner_id: number;
  aws_account_id: number;
  group_id: string | null;
  group_membership_id: string | null;
  operation_pending: boolean;
  subscription_source?: "GROUP" | "USER" | null;
  effective_subscription_source?: "GROUP" | "USER" | "USER_AND_GROUP" | null;
  cancellation_source?: "GROUP" | "USER" | null;
  direct_user_plan?: CurrentPlan;
  direct_user_status?: string | null;
  aws_subscription_status?: string | null;
  subscription_sources?: { source: "USER" | "GROUP"; group_id: string | null; subscription_type: string | null; status: string; pending_type?: string | null; expected_effective_at?: string | null; expires_at?: string | null }[];
  native_group_subscription?: NativeGrant | null;
  group_activation_id?: string | null;
  controlling_group_stop_at?: string | null;
  username: string;
  email: string;
  owner_name: string;
  account_name: string;
  plan_name: string;
  state: string;
  step: string;
  error: string | null;
  has_password: boolean;
  credential_state: CredentialState;
  counted: boolean;
  cycle_number: number | null;
  created_at: string;
  subscribed_at: string | null;
  sso_user_id: string | null;
  sso_display_name: string | null;
  sso_deleted_at: string | null;
  password_generated_at: string | null;
  subscription_status: string;
  subscription_type: string | null;
  current_plan: CurrentPlan;
  pending_plan: PendingPlan | null;
  observed_subscription_type: string | null;
  observed_plan_name: string | null;
  cancelled_at: string | null;
  cancellation_mode: string | null;
  access_ends_at: string | null;
  last_synced_at: string | null;
  supports_scheduled_cancellation: boolean;
  operation: RecordOperation | null;
  stop_schedule: StopSchedule | null;
}
export interface CurrentPlan {
  plan_id: number | null;
  name: string | null;
  subscription_type: string | null;
}
export interface PendingPlan {
  change_id: string;
  plan_id: number | null;
  name: string | null;
  subscription_type: string | null;
  expected_effective_at: string | null;
  state: string;
  error: string | null;
}
export interface PlanChange {
  id: string;
  record_id: string;
  operation_id: string | null;
  direction: "upgrade" | "downgrade" | "withdraw";
  from_plan_id: number | null;
  from_plan_name: string | null;
  from_type: string | null;
  to_plan_id: number | null;
  to_plan_name: string | null;
  to_type: string | null;
  predecessor_id: string | null;
  counter_id: number | null;
  cycle_number: number | null;
  reserved: boolean;
  counted: boolean;
  state: "queued" | "applying" | "needs_review" | "scheduled" | "applied" | "failed" | "withdrawn" | "superseded" | "cancelled" | "not_applied";
  requested_at: string;
  write_requested_at: string | null;
  accepted_at: string | null;
  expected_effective_at: string | null;
  confirmed_at: string | null;
  applied_at: string | null;
  checked_at: string | null;
  next_check_at: string | null;
  error: string | null;
}
export interface PlanChangeTarget {
  plan_id: number;
  name: string;
  subscription_type: string;
  reference: CatalogPlan;
  unlimited: boolean;
  remaining_count: number | null;
  used_count: number;
  pending_count: number;
  available: boolean;
  unavailable_reason: string | null;
  direction: "upgrade" | "downgrade";
}
export interface PlanChangeOptions {
  current_plan: CurrentPlan;
  pending_change: PlanChange | null;
  targets: PlanChangeTarget[];
  unavailable_reason: string | null;
  owner_id: number;
}
export interface StopPolicy {
  mode: "none" | "days" | "at";
  days?: number;
  stop_at?: string;
}
export interface StopSchedule {
  principal_type?: "USER" | "GROUP" | null;
  source_group_id: string | null;
  source_group_revision: number | null;
  individual_override: boolean;
  mode: StopPolicy["mode"];
  days: number | null;
  stop_at: string | null;
  revision: number;
  state: string;
  error: string | null;
  completed_at: string | null;
}
export interface RecordOperation {
  cascade_batch_id?: string;
  principal_type?: "GROUP" | "USER";
  id: string;
  kind: string;
  state: string;
  error: string | null;
  created_at: string;
  finished_at: string | null;
  actor_name?: string;
  automatic?: boolean;
  result?: Record<string, unknown> | null;
}
export const operationName: Record<string, string> = {
  cascade_delete: "取消订阅后级联删除",
  cancel_subscription: "取消 Kiro 订阅",
  delete_sso: "删除 SSO 用户",
  reset_password: "重置一次性密码",
  update_sso: "更新姓名和邮箱",
  sync_status: "同步 AWS 状态",
  attach: "加入 AWS 分组",
  detach: "移出 AWS 分组",
  auth_json_export: "JSON 导出",
  auth_reset_password: "批量重置一次性密码",
  auth_random_password: "设置随机永久密码",
  auth_custom_password: "设置共享永久密码",
  change_plan: "更改套餐",
  withdraw_plan_change: "撤回套餐变更",
};

export type CascadeKind = "sso" | "group";
export type CascadeSelection = { kind: "sso"; record_ids: string[] } | { kind: "group"; group_ids: string[] };
export function cascadeSelection(kind: CascadeKind, ids: string[]): CascadeSelection {
  const selected = [...new Set(ids)].sort();
  if (!selected.length || selected.length > 100 || selected.some(id => !id || id.length > 36))
    throw new Error("请选择 1 至 100 个明确的 SSO 或分组。");
  return kind === "sso" ? { kind, record_ids: selected } : { kind, group_ids: selected };
}
export interface CascadeScope {
  target_id: string;
  owner_id: number;
  aws_account_id: number;
  account_name: string;
  group_id: string | null;
  group_name: string | null;
  members: { id: string; username: string; email: string; sso_user_id: string | null;
    sso_deleted_at: string | null; user_type: string | null; group_type: string | null }[];
}
export interface CascadePreview {
  id: string;
  kind: CascadeKind;
  fingerprint: string;
  confirm_text: string;
  expires_at: string;
  fee_notice: string;
  counts: { groups: number; sso_users: number; user_subscriptions: number; group_subscriptions: number };
  items: CascadeScope[];
}
export interface CascadeAdmissionBody {
  preview_id: string;
  fingerprint: string;
  confirm_text: string;
  acknowledge_fees: boolean;
  request_key: string;
}
export interface CascadeTask extends CascadeScope {
  id: string;
  position: number;
  state: string;
  phase: string;
  error: string | null;
  attempts: number;
  completed_steps: number;
  total_steps: number;
  finished_at: string | null;
  steps: { kind: string; record_id: string | null; state: string; label: string; request_id: string | null }[];
}
export interface CascadeBatch {
  id: string;
  kind: CascadeKind;
  state: string;
  confirm_text: string;
  counts: { total: number; queued: number; running: number; needs_review: number; failed: number; completed: number };
  items: CascadeTask[];
  actions: { recheck: boolean; retry: boolean };
  created_at: string;
  finished_at: string | null;
}
export function subscriptionStatus(r: {
  subscription_status?: string;
  access_ends_at?: string | null;
}) {
  if (
    r.subscription_status === "cancel_scheduled" &&
    r.access_ends_at &&
    new Date(r.access_ends_at + "Z") <= new Date()
  )
    return "已取消";
  return (
    (
      {
        active: "已订阅",
        not_subscribed: "未订阅",
        cancelled: "已取消",
        cancel_scheduled: "已取消续订 · 月底停止访问",
      } as Record<string, string>
    )[r.subscription_status || ""] || "待核对"
  );
}
export interface Page<T> {
  items: T[];
  total: number;
  page: number;
  page_size?: number;
}
export interface Overview {
  total: number;
  subscribed: number;
  cancelled_subscriptions: number;
  deleted_sso: number;
  states: Record<string, number>;
  counters: Counter[];
  members?: number;
  aws_accounts?: number;
  member_summary?: MemberSummary;
  backup?: {
    status: string;
    completed_at?: string;
    object_key?: string;
    error?: string;
  };
}
export interface BatchInfo {
  id: string;
  owner_id: number;
  export_credentials: boolean;
  kind: "sso" | "subscribed" | "subscribe_existing";
  created_at: string;
  total: number;
  states: Record<string, number>;
  items?: {
    id: string;
    username: string;
    email: string;
    state: string;
    error: string | null;
    has_credentials: boolean;
  }[];
}
export interface MemberSummary {
  plans: { id: number; name: string }[];
  users: MemberSummaryRow[];
}
export interface MemberSummaryRow {
  id: number;
  username: string;
  display_name: string;
  active: boolean;
  role: "admin" | "member";
  sso_total: number;
  sso_active: number;
  pending_tasks: number;
  cancelled_subscriptions: number;
  deleted_sso: number;
  counters: Counter[];
}
export interface PlanHistoryItem {
  id: string | number;
  plan_name: string;
  cycle_number: number | null;
  username?: string;
  subscribed_at?: string;
  subscription_status?: string;
  cancelled_at?: string | null;
  sso_deleted_at?: string | null;
  used_count?: number;
  previous_limit?: number;
  new_limit?: number;
  reason?: string;
  created_at?: string;
  actor_name?: string;
  event_kind?: "subscription" | "plan_change" | "group_activation";
  occurred_at?: string | null;
  record_id?: string;
  direction?: "upgrade" | "downgrade" | "withdraw";
  applied_at?: string | null;
  from_plan_name?: string | null;
}
export interface Reset {
  id: number;
  username: string;
  plan_name: string;
  cycle_number: number;
  used_count: number;
  previous_limit: number;
  new_limit: number;
  reason: string;
  actor_name: string;
  created_at: string;
}
export interface Audit {
  id: number;
  actor_name: string;
  action: string;
  detail: string;
  created_at: string;
}
export const stateName: Record<string, string> = {
  queued: "等待处理",
  running: "开通中",
  completed: "已开通",
  failed: "开通失败",
  needs_review: "待核对",
};
export function date(value?: string | null) {
  if (!value) return "—";
  return new Date(value.endsWith("Z") ? value : `${value}Z`).toLocaleString(
    "zh-CN",
    { hour12: false },
  );
}

export interface GroupPolicy {
  mode: StopPolicy["mode"];
  days: number | null;
  stop_at: string | null;
  revision: number;
}
export interface GroupItem {
  account_name?: string;
  account_deleted_at?: string | null;
  id: string;
  owner_id: number;
  aws_account_id: number;
  name: string;
  remote_id: string | null;
  state: string;
  error: string | null;
  revision: number;
  active_job_id: string | null;
  created_at: string;
  deleted_at: string | null;
  policy: GroupPolicy;
  counts?: GroupCounts;
  supports_scheduled_cancellation?: boolean;
  native_subscription?: NativeGrant | null;
}
export type CancellationMode = "IMMEDIATE" | "END_OF_PERIOD";
export interface NativeGrant {
  id: string; group_id: string; plan_id: number; plan_name: string; subscription_type: string;
  state: "pending" | "active" | "cancel_scheduled" | "cancelled" | "needs_review" | "failed";
  activated_at: string | null; cancelled_at: string | null; cancellation_mode: CancellationMode | null;
  access_ends_at: string | null; stop_at: string | null; policy_revision: number; created_at: string;
  source: "GROUP"; future_members_inherit: true;
}
export type LifecycleKind = "group_subscribe" | "group_cancel" | "user_cancel";
export type LifecycleState = "queued" | "running" | "completed" | "failed" | "needs_review" | "cancelled";
export interface LifecycleItem {
  id: string; name: string; principal_type: "GROUP" | "USER"; operation_id: string;
  state: LifecycleState; phase: string; error: string | null;
}
export interface LifecycleBatch {
  can_stop?: boolean;
  stop_requested?: boolean;
  id: string; kind: LifecycleKind; created_at: string; total: number;
  states: Record<LifecycleState, number>; items: LifecycleItem[];
}
export interface NativePreview {
  principal_type: "GROUP"; future_members_inherit: true; member_count: number;
  groups: { id: string; name: string; owner_id: number; aws_account_id: number; member_ids: string[]; member_count: number; policy_revision: number }[];
}
export interface NativeOperation extends RetryProgress {
  id: string; group_id: string; grant_id: string; kind: "subscribe" | "cancel";
  state: LifecycleState; phase: string; attempts: number; error: string | null;
  write_requested_at: string | null; aws_request_id: string | null; created_at: string;
  finished_at: string | null; principal_type: "GROUP"; member_count: number; automatic: boolean;
}
export interface GroupActivation {
  id: string; grant_id: string; record_id: string; plan_id: number; plan_name: string;
  subscription_type: string; counter_id: number | null; cycle_number: number | null;
  reserved: boolean; counted: boolean; first_opening: boolean; state: string;
  write_requested_at: string | null; activated_at: string | null; cancelled_at: string | null;
  error: string | null; created_at: string;
}
export interface GroupCounts { total: number; eligible: number; active: number; subscribed: number; deleted: number; cancelled: number; unconfirmed?: number; joined?: number }
export interface GroupDetail extends GroupItem {
  members: RecordItem[];
  counts: GroupCounts;
}
export interface GroupObservation {
  group_id: string; aws_account_id: number; remote_id: string; queried_at: string;
  directory: { exists: boolean; name: string | null; member_count: number | null;
    owned_members: { record_id: string; sso_user_id: string; username: string; email: string; membership_id: string }[] };
  subscription: { status: "Subscribed" | "Canceled" | "Not subscribed"; subscription_type: string | null;
    plan_label: string | null; pending_subscription_type: string | null; pending_plan_label: string | null;
    effective_at: string | null; cancellation_expires_at: string | null; access_active: boolean };
}
export type MemberBatchKind = "attach" | "detach";
export type MemberBatchState = "waiting" | "queued" | "running" | "completed" | "failed" | "needs_review" | "stopped";
export interface MemberBatchInput { kind: MemberBatchKind; record_ids: string[]; expected_revision: number; request_key: string }
export interface MemberBatch {
  id: string; group_id: string; owner_id: number; actor_id: number; request_key: string; kind: MemberBatchKind;
  expected_revision: number; record_ids: string[]; state: MemberBatchState; active_job_id: string | null;
  stop_requested_at: string | null; error: string | null; counts: Record<MemberBatchState | "total", number>;
  actions: Record<"recheck" | "retry" | "stop", boolean>; created_at: string; updated_at: string; finished_at: string | null;
  items?: { position: number; record_id: string; job_id: string; kind: MemberBatchKind; state: MemberBatchState;
    phase: string; attempts: number; error: string | null; created_at: string; finished_at: string | null;
    username?: string | null; email?: string | null; sso_user_id?: string | null }[];
}
export interface MemberCandidates { group_id: string; kind: MemberBatchKind; items: RecordItem[]; total: number; page: number; page_size: number }
export interface GroupJob {
  id: string;
  group_id: string;
  record_id: string | null;
  member_batch_id?: string | null;
  kind: string;
  state: string;
  phase: string;
  attempts: number;
  error: string | null;
  created_at: string;
  finished_at: string | null;
}
export interface GroupPolicyRequest {
  policy: StopPolicy;
  expected_revision: number;
  overwrite_individual: boolean;
}
export interface GroupPolicyPreview {
  group_id: string;
  revision: number;
  affected_ids: string[];
  affected_count: number;
  skipped: { id: string; reason: string }[];
  skipped_count: number;
  conflicts: { id: string; reason: string }[];
  conflict_count: number;
}
export interface GroupSubscriptionPreview {
  group_id: string;
  eligible_ids: string[];
  eligible_count: number;
  skipped: { id: string; reason: string }[];
}

export type CredentialState = "one_time" | "permanent" | "unknown";
export interface LoginCredential {
  internal_id?: string;
  username: string;
  password: string;
  portal_url: string;
  region: string;
  generated_at: string | null;
  credential_state: CredentialState;
}
export type AuthKind = "json_export" | "reset_password" | "random_password" | "custom_password";
export type PasswordKind = Exclude<AuthKind, "json_export">;
export interface AuthBatchInput {
  kind: AuthKind;
  record_ids: readonly string[];
  request_key: string;
  group_id?: string;
  password?: string;
}
export type AuthItemState = "queued" | "running" | "challenge" | "polling" | "completed" | "downloaded" | "failed" | "needs_review" | "cancelled" | "expired";
export interface AuthItem extends RetryProgress {
  record_id: string;
  operation_id: string;
  username: string;
  owner_id: number;
  state: AuthItemState;
  stage: string;
  revision: number;
  next_poll_at: string | null;
  error: string | null;
  error_code: string | null;
  cancel_requested: boolean;
  credential_state: CredentialState;
  has_password: boolean;
  requires_new_reset: boolean;
  can_retry_challenge?: boolean;
}
export interface AuthBatch {
  id: string;
  actor_id: number;
  kind: AuthKind;
  group_id: string | null;
  state: "active" | "downloaded" | "cancelled" | "expired";
  created_at: string;
  expires_at: string;
  completed_at: string | null;
  download_expires_at: string | null;
  total: number;
  states: Partial<Record<AuthItemState, number>>;
  success_count: number;
  failure_count: number;
  download_ready: boolean;
  items?: AuthItem[];
  group_scope?: GroupJsonScope;
}
export interface GroupJsonMember { record_id: string; username: string; email: string; sso_user_id: string | null; skip_reason: string | null }
export interface GroupJsonGroup {
  id: string; name: string; owner_id: number; aws_account_id: number; account_name: string; account_number: string;
  revision: number; total: number; eligible_count: number; skipped_count: number;
  states?: Partial<Record<AuthItemState, number>>;
}
export interface GroupJsonScope { groups: GroupJsonGroup[]; total: number; eligible_count: number; skipped_count: number }
export interface GroupJsonPreview extends GroupJsonScope {
  id: string; fingerprint: string; expires_at: string;
  groups: (GroupJsonGroup & { members: GroupJsonMember[] })[];
}
export interface GroupJsonAdmissionBody { preview_id: string; fingerprint: string; request_key: string; acknowledge_password_changes: true }
export function groupJsonSelection(ids: readonly string[]) {
  const selected = [...new Set(ids)].sort();
  if (!selected.length || selected.length > 100 || selected.some(id => !id || id.length > 36)) throw new Error("请选择 1 至 100 个具体分组");
  return { group_ids: selected };
}
export function groupJsonUrl(ids: readonly string[]) {
  const params = new URLSearchParams({ source: "group" });
  groupJsonSelection(ids).group_ids.forEach(id => params.append("group_id", id));
  return "/json-export?" + params.toString();
}
export interface AuthPreview {
  group_id: string;
  kind: AuthKind;
  record_ids: string[];
  skipped: { record_id: string; username: string; reason: string }[];
}
export interface AuthChallenge {
  kind: "image" | "ams" | "aws_authorization" | "manual_action";
  id: string;
  operation_id: string;
  revision: number;
  expires_at: number;
  authorization_url?: string;
  user_code?: string;
  username?: string;
  portal_url?: string;
  frame_url?: string;
  frame_origin?: string;
  region?: string;
  stage?: string;
  callback?: string;
  container_id?: string;
  locale?: string;
  show_challenge_on_load?: boolean;
  script_url?: string;
  widget_origin?: string;
  redemption_token?: string;
}
