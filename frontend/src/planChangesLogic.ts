
import type { PlanChange, PlanChangeOptions, PlanChangeTarget, PlanHistoryItem, RecordItem } from "./api";
import { nativeAccess, independentUserAccess } from "./nativeSubscriptionsLogic";

export const planChangeState: Record<PlanChange["state"], string> = {
  queued: "等待处理", applying: "正在提交 AWS", needs_review: "待核对", scheduled: "等待下月生效",
  applied: "已生效", failed: "失败", withdrawn: "已撤回", superseded: "已替换", cancelled: "已取消", not_applied: "已确认未生效",
};
export const planChangeDirection = { upgrade: "立即升级", downgrade: "下月降级", withdraw: "撤回降级" };

export function planWritesBlocked(record: RecordItem) {
  return (nativeAccess(record) && !independentUserAccess(record)) || !!record.operation || record.operation_pending || record.state !== "completed" || !!record.sso_deleted_at || record.subscription_status !== "active";
}
export function targetUnavailableReason(record: RecordItem, options: PlanChangeOptions, target: PlanChangeTarget) {
  if (nativeAccess(record) && !independentUserAccess(record)) return "原生分组授权不能单独变更套餐，请管理分组订阅";
  if (target.subscription_type === options.current_plan.subscription_type) return "当前套餐";
  if (target.subscription_type === options.pending_change?.to_type) return "已是待生效套餐";
  if (options.unavailable_reason) return options.unavailable_reason;
  if (!target.available) return target.unavailable_reason || "该套餐当前不可选";
  if (planWritesBlocked(record)) return "该用户有任务待处理或订阅状态不可变更";
  if (!target.unlimited && (target.remaining_count === null || target.remaining_count < 1)) return "创建者该套餐剩余次数不足";
  return "";
}
export function canConfirmPlanChange(record: RecordItem, options: PlanChangeOptions | null, target: PlanChangeTarget | undefined, username: string, acknowledged: boolean) {
  return !!options?.current_plan.subscription_type && !!target && username === record.username && acknowledged && !targetUnavailableReason(record, options, target);
}
export function needsPlanReview(change: PlanChange) {
  return change.state === "needs_review" || (change.state === "scheduled" && !!change.error);
}
export function canConfirmNotApplied(change: PlanChange, now = Date.now()) {
  if (!needsPlanReview(change) || !change.write_requested_at) return false;
  const time = Date.parse(/(?:Z|[+-]\d{2}:\d{2})$/.test(change.write_requested_at) ? change.write_requested_at : `${change.write_requested_at}Z`);
  return Number.isFinite(time) && now - time >= 10 * 60_000;
}
export function canWithdrawPlanChange(record: RecordItem, options: PlanChangeOptions | null) {
  return !!options?.current_plan.subscription_type && options.pending_change?.state === "scheduled" && !options.unavailable_reason && !planWritesBlocked(record);
}
export function canSubmitNotApplied(change: PlanChange, username: string, confirmation: string, reason: string, acknowledged: boolean, now = Date.now()) {
  return canConfirmNotApplied(change, now) && confirmation === username && reason.trim().length >= 5 && reason.length <= 500 && acknowledged;
}
export function planHistoryTime(item: PlanHistoryItem) {
  return item.event_kind === "plan_change" ? item.occurred_at || item.applied_at || null : item.occurred_at || item.subscribed_at || item.created_at || null;
}
export function isPlanChangeOperation(kind: string) {
  return kind === "change_plan" || kind === "withdraw_plan_change";
}

export function isPlanChange(value: unknown, recordId: string): value is PlanChange {
  if (!value || typeof value !== "object") return false;
  const item = value as PlanChange;
  const nullableStrings: (keyof PlanChange)[] = ["operation_id", "from_plan_name", "from_type", "to_plan_name", "to_type", "predecessor_id", "write_requested_at", "accepted_at", "expected_effective_at", "confirmed_at", "applied_at", "checked_at", "next_check_at", "error"];
  const nullableNumbers: (keyof PlanChange)[] = ["from_plan_id", "to_plan_id", "counter_id", "cycle_number"];
  return typeof item.id === "string" && !!item.id && item.record_id === recordId &&
    ["upgrade", "downgrade", "withdraw"].includes(item.direction) && Object.prototype.hasOwnProperty.call(planChangeState, item.state) &&
    typeof item.requested_at === "string" && !!item.requested_at && typeof item.reserved === "boolean" && typeof item.counted === "boolean" &&
    nullableStrings.every(key => item[key] === null || typeof item[key] === "string") &&
    nullableNumbers.every(key => item[key] === null || Number.isInteger(item[key]));
}

export function isPlanChangeOptions(value: unknown, recordId: string): value is PlanChangeOptions {
  if (!value || typeof value !== "object") return false;
  const item = value as PlanChangeOptions;
  const nullableText = (field: unknown) => field === null || typeof field === "string";
  return Number.isInteger(item.owner_id) && !!item.current_plan &&
    (item.current_plan.plan_id === null || Number.isInteger(item.current_plan.plan_id)) &&
    nullableText(item.current_plan.name) && nullableText(item.current_plan.subscription_type) && nullableText(item.unavailable_reason) &&
    (item.pending_change === null || isPlanChange(item.pending_change, recordId)) &&
    Array.isArray(item.targets) && item.targets.every(target => target && Number.isInteger(target.plan_id) &&
      typeof target.name === "string" && typeof target.subscription_type === "string" &&
      !!target.reference && Number.isFinite(target.reference.monthly_price_usd) && Number.isFinite(target.reference.monthly_credits) &&
      typeof target.unlimited === "boolean" && (target.remaining_count === null || Number.isInteger(target.remaining_count)) &&
      Number.isInteger(target.used_count) && Number.isInteger(target.pending_count) && typeof target.available === "boolean" &&
      nullableText(target.unavailable_reason) && ["upgrade", "downgrade"].includes(target.direction));
}
