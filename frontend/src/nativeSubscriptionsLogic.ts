import { ApiError, type CancellationMode, type GroupItem, type LifecycleBatch, type LifecycleItem, type LifecycleKind, type NativePreview, type RecordItem } from "./api";

export type LifecycleIntent =
  | { kind: "group_subscribe"; body: { group_ids: string[]; plan_id: number; request_key: string } }
  | { kind: "group_cancel"; body: { group_ids: string[]; cancellation_mode: CancellationMode; request_key: string } }
  | { kind: "user_cancel"; body: { record_ids: string[]; cancellation_mode: CancellationMode; request_key: string } };
export const lifecycleNames: Record<LifecycleKind, string> = { group_subscribe: "开通原生分组订阅", group_cancel: "取消分组订阅", user_cancel: "批量取消订阅" };
export const lifecycleStates = { queued: "等待处理", running: "正在处理", completed: "已完成", failed: "处理失败", needs_review: "待核对", cancelled: "已停止" };
export const nativeGrantStates = { pending: "等待开通确认", active: "已生效", cancel_scheduled: "已取消续订 · 到期前仍可访问", cancelled: "已取消 · 历史保留", needs_review: "待核对", failed: "处理失败" };
export function groupSearchPath(scope: { account: string; q: string; member: string }) {
  const query = new URLSearchParams();
  if (scope.account) query.set("aws_account_id", scope.account);
  if (scope.q.trim()) query.set("q", scope.q.trim());
  if (scope.member.trim()) query.set("member_q", scope.member.trim());
  return `/groups${query.size ? `?${query}` : ""}`;
}
export function filterGroups(groups: GroupItem[], owner: string, state: string) {
  return groups.filter(group => (!owner || group.owner_id === Number(owner)) && (!state || group.state === state));
}
export function currentGroupSelection(ids: string[], groups: GroupItem[]) {
  const available = new Set(groups.filter(group => !group.deleted_at && !group.account_deleted_at).map(group => group.id));
  return [...new Set(ids)].filter(id => available.has(id)).slice(0, 100);
}
export function nativeAccess(record: RecordItem) {
  if (record.cancellation_source !== undefined) return record.cancellation_source === "GROUP";
  return record.effective_subscription_source === "GROUP" || record.effective_subscription_source === "USER_AND_GROUP";
}
export function independentUserAccess(record: RecordItem) { return record.direct_user_status === "active" && !!record.direct_user_plan?.subscription_type; }
export function subscriptionSourceLabel(record: RecordItem) {
  return record.effective_subscription_source === "USER_AND_GROUP" ? "个人订阅 · USER + 原生分组 · GROUP"
    : record.effective_subscription_source === "GROUP" ? "原生分组 · GROUP"
    : record.effective_subscription_source === "USER" ? "个人订阅 · USER" : "当前无已确认授权";
}
export function activeNativeGroup(group?: GroupItem | null) { return !!group?.native_subscription && ["active", "cancel_scheduled"].includes(group.native_subscription.state); }
export function canCancelRecord(record: RecordItem) {
  return !record.account_deleted_at && record.cancellation_source !== null && !!record.sso_user_id && !record.operation_pending && !record.operation && ["completed", "failed"].includes(record.state) &&
    !record.cancelled_at && ["active", "cancel_scheduled"].includes(record.subscription_status);
}
export function supportsRecordScheduledCancellation(records: RecordItem[]) {
  return records.length > 0 && records.every(record => record.supports_scheduled_cancellation && !nativeAccess(record));
}
export function canSubscribeGroup(group: GroupItem) {
  return group.state === "ready" && !group.deleted_at && !group.account_deleted_at && !group.active_job_id &&
    (!group.native_subscription || ["cancelled", "failed"].includes(group.native_subscription.state));
}
export function canCancelGroup(group: GroupItem) {
  return group.state === "ready" && !group.deleted_at && !group.account_deleted_at && !group.active_job_id && group.native_subscription?.state === "active";
}
export function lifecycleEndpoint(kind: LifecycleKind) {
  return { group_subscribe: "/group-subscriptions", group_cancel: "/group-subscriptions/cancel", user_cancel: "/subscription-cancellations" }[kind];
}
export function intentIds(intent: LifecycleIntent) { return intent.kind === "user_cancel" ? intent.body.record_ids : intent.body.group_ids; }
export function nativeIntent(kind: LifecycleKind, ids: string[], choice: number | CancellationMode): LifecycleIntent {
  if (!Array.isArray(ids) || !ids.length || ids.length > 100 || ids.some(id => typeof id !== "string" || !id) || new Set(ids).size !== ids.length) throw new Error("请选择 1–100 个不同的对象。");
  const request_key = crypto.randomUUID();
  if (kind === "group_subscribe") {
    if (!Number.isInteger(choice) || Number(choice) < 1) throw new Error("请选择分组订阅套餐。");
    return { kind, body: { group_ids: [...ids], plan_id: Number(choice), request_key } };
  }
  if (choice !== "IMMEDIATE" && choice !== "END_OF_PERIOD") throw new Error("请选择取消方式。");
  return kind === "group_cancel" ? { kind, body: { group_ids: [...ids], cancellation_mode: choice, request_key } }
    : { kind, body: { record_ids: [...ids], cancellation_mode: choice, request_key } };
}
export function freezeLifecycleIntent(value: LifecycleIntent): LifecycleIntent {
  const frozen = nativeIntent(value.kind, intentIds(value), value.kind === "group_subscribe" ? value.body.plan_id : value.body.cancellation_mode);
  frozen.body.request_key = value.body.request_key;
  Object.freeze(intentIds(frozen)); Object.freeze(frozen.body); return Object.freeze(frozen);
}
export function validNativePreview(value: unknown, ids: string[]): value is NativePreview {
  const preview = value as NativePreview;
  return !!preview && preview.principal_type === "GROUP" && preview.future_members_inherit === true && Array.isArray(preview.groups) &&
    preview.groups.length === ids.length && preview.groups.every(g => !!g) && new Set(preview.groups.map(g => g.id)).size === ids.length &&
    preview.groups.every(g => ids.includes(g.id) && typeof g.name === "string" && Number.isInteger(g.owner_id) && Number.isInteger(g.aws_account_id) &&
      Number.isInteger(g.policy_revision) && Array.isArray(g.member_ids) && g.member_ids.every(id => typeof id === "string") &&
      new Set(g.member_ids).size === g.member_ids.length && g.member_count === g.member_ids.length) &&
    preview.member_count === preview.groups.reduce((total, g) => total + g.member_count, 0);
}
export function validLifecycleBatch(value: unknown, intent?: LifecycleIntent): value is LifecycleBatch {
  const batch = value as LifecycleBatch;
  if (!batch || typeof batch.id !== "string" || !batch.id || !Object.prototype.hasOwnProperty.call(lifecycleNames, batch.kind) || typeof batch.created_at !== "string" ||
    !Array.isArray(batch.items) || !batch.items.length || batch.total !== batch.items.length || !batch.states) return false;
  if (!batch.items.every(item => !!item && typeof item.id === "string" && !!item.id && typeof item.name === "string" && typeof item.operation_id === "string" && !!item.operation_id &&
    item.principal_type === (batch.kind === "user_cancel" ? "USER" : "GROUP") && Object.prototype.hasOwnProperty.call(lifecycleStates, item.state) &&
    typeof item.phase === "string" && (item.error === null || typeof item.error === "string"))) return false;
  if (!Object.keys(lifecycleStates).every(state => (batch.states[state as keyof typeof lifecycleStates] ?? (state === "cancelled" ? 0 : undefined)) === batch.items.filter(item => item.state === state).length)) return false;
  const ids = batch.items.map(item => item.id);
  return new Set(ids).size === ids.length && (!intent || batch.kind === intent.kind && ids.length === intentIds(intent).length && intentIds(intent).every(id => ids.includes(id)));
}
export function lifecycleRecovery(item: LifecycleItem): { path: string; body?: { confirm_username: string } } {
  return item.principal_type === "GROUP" ? { path: `/group-subscriptions/${encodeURIComponent(item.operation_id)}/recheck` }
    : { path: `/subscriptions/${encodeURIComponent(item.id)}/operations/${encodeURIComponent(item.operation_id)}/retry`, body: { confirm_username: item.name } };
}
// Only known pre-admission rejections unlock changed contents. Unknown responses
// and mismatched keys must retain the original request for reconciliation.
export function definiteLifecycleRejection(error: unknown) {
  if (!(error instanceof ApiError)) return false;
  if ([400, 422].includes(error.status)) return true;
  if (error.status === 404) return ["套餐不存在或已停用", "分组不存在", "SSO 用户记录不存在"].includes(error.message);
  if (error.status === 403) return ["无权使用该 AWS 账号", "AWS 账号已停用、删除或未绑定；请管理员恢复、启用并绑定后再操作"].includes(error.message);
  return error.status === 409 && [
    "SSO 所有者的目标套餐次数已用完或未设置，请联系管理员", "AWS 账号已停用或删除", "分组所有者已停用", "分组未就绪或存在未完成任务", "该 AWS 账号的旧控制面仅支持立即停止访问",
    "成员已有 USER 或其他 GROUP 订阅，不能重复开通", "成员订阅来源或套餐与管理分组不一致，需要核对",
    "分组成员归属、AWS 配置、会员身份或处理状态不一致", "成员停止订阅时间已到，请先修改规则", "原生分组每次最多处理 100 名受管理成员",
    "分组停止订阅时间已到，请先修改规则", "分组已有原生订阅或待核对任务", "分组没有可取消的已生效原生订阅",
    "一次最多处理 100 名分组成员，请分批操作", "验证期间分组成员、配置或规则已变化，请刷新", "分组已有未完成任务", "分组成员已有未完成任务",
    "选择的用户已有未完成操作，批次未提交", "请先完成或核对开通任务，再管理 SSO 用户", "分组存在未完成任务，请先核对",
    "原生分组授权仅支持立即移出成员；整组取消可选择月末", "该记录已完成取消操作，请同步 AWS 状态", "没有可取消的已开通订阅",
    "AWS 分组成员与本地完整快照不一致，包含未管理成员或成员已变化", "AWS 分组已有订阅，必须先核对原生授权", "AWS 分组套餐已变化，请核对",
  ].includes(error.message);
}
