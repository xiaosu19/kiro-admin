import type {
  BatchInfo,
  GroupItem,
  GroupPolicyRequest,
  RecordItem,
  StopPolicy,
} from "./api";
import { nativeAccess } from "./nativeSubscriptionsLogic";

export function groupMemberStatus(record: RecordItem) {
  if (record.sso_deleted_at) return "已删除 · 历史保留";
  if (!record.sso_user_id) {
    if (record.state === "needs_review" || record.step === "create_user_pending")
      return "SSO 创建结果待核对";
    return record.state === "failed" ? "SSO 创建失败，尚未确认用户" : "SSO 尚未创建";
  }
  if (record.group_membership_id) {
    if (record.state === "needs_review" && record.step === "group_membership_pending")
      return "已记录加组，授权待核对";
    return record.operation_pending || record.operation ? "已确认加组 · 有任务待处理" : "已确认加入 AWS 分组";
  }
  if (record.state === "failed") return "SSO 已创建，加组失败";
  if (record.step === "group_membership_pending") return "SSO 已创建，加组结果待核对";
  return record.state === "needs_review" ? "SSO 已创建，待核对" : "SSO 已创建，等待加组";
}

export function ownedCreationGroups(
  groups: GroupItem[],
  ownerId: number,
  accountId: number,
) {
  return groups.filter(
    (g) =>
      g.owner_id === ownerId &&
      g.aws_account_id === accountId &&
      !g.deleted_at &&
      ["ready", "creating"].includes(g.state),
  );
}
export function canSubscribeRecord(record: RecordItem) {
  return (
    record.plan_id === null &&
    record.provision_only &&
    record.state === "completed" &&
    record.subscription_status === "not_subscribed" &&
    !record.observed_plan_name &&
    !!record.sso_user_id &&
    !record.sso_deleted_at &&
    !record.operation &&
    !record.operation_pending &&
    (!record.group_id || !!record.group_membership_id)
  );
}
export function canEditStopRule(record: RecordItem) {
  const native = nativeAccess(record);
  return (
    !!(record.group_id || (!record.provision_only && record.plan_id)) &&
    !record.sso_deleted_at &&
    (!record.cancelled_at || native) &&
    !["cancelled", ...(!native ? ["cancel_scheduled"] : []), "unknown", "pending"].includes(
      record.subscription_status,
    ) &&
    !record.operation_pending &&
    !record.operation &&
    (!record.counted || record.subscription_status === "active" || native && record.subscription_status === "cancel_scheduled") &&
    !["queued", "running", "needs_review"].includes(record.state)
  );
}
export function subscriptionRequest(
  ids: string[],
  planId: number,
  override?: StopPolicy,
  groupId?: string,
) {
  if (!ids.length || ids.length > 100 || new Set(ids).size !== ids.length)
    throw new Error("请选择 1–100 名不同的 SSO 用户。");
  if (!Number.isInteger(planId) || planId < 1)
    throw new Error("请选择 Kiro 套餐。");
  return {
    record_ids: [...ids],
    plan_id: planId,
    ...(groupId ? { group_id: groupId } : {}),
    ...(override ? { stop_schedule: override } : {}),
  };
}
export function selectionFromPreview(
  selected: string[],
  eligibleIds: string[],
) {
  const eligible = new Set(eligibleIds);
  return [...new Set(selected)].filter((id) => eligible.has(id)).slice(0, 100);
}
export function resetToGroupRequest(record: RecordItem, group: GroupItem) {
  return {
    expected_revision: record.stop_schedule?.revision || 0,
    expected_group_revision: group.policy.revision,
  };
}
export function policyPreviewCurrent(
  reviewed: GroupPolicyRequest | null,
  draft: GroupPolicyRequest,
  revision: number,
) {
  return (
    !!reviewed &&
    reviewed.expected_revision === revision &&
    JSON.stringify(reviewed) === JSON.stringify(draft)
  );
}

export interface SsoCreationBody {
  kind: "sso";
  aws_account_id: number;
  export_credentials: boolean;
  group_id?: string;
  items?: { username: string; email: string | null }[];
  sequence?: { pattern: string; email_template: string };
}
export interface SsoCreationIntent {
  body: SsoCreationBody;
  key: string;
  group?: {
    body: { name: string; aws_account_id: number };
    key: string;
    id?: string;
  };
}
export function validateSsoCreation(body: SsoCreationBody) {
  if (!Number.isInteger(body.aws_account_id) || body.aws_account_id < 1)
    throw new Error("请选择 AWS 账号。");
  let rows = body.items || [];
  if (body.sequence) {
    const match = body.sequence.pattern.match(
      /^([a-zA-Z0-9_.-]{1,60})-(\d{1,7})-(\d{1,7})$/,
    );
    if (!match) throw new Error("编号格式示例：member-01-10。");
    const first = Number(match[2]),
      last = Number(match[3]);
    if (first < 1 || last < first || last > 1000000 || last - first + 1 > 100)
      throw new Error("每批请填写 1–100 个用户，结束编号不超过 1000000。");
    rows = Array.from({ length: last - first + 1 }, (_, index) => ({
      username: `${match[1]}-${first + index}`,
      email:
        body
          .sequence!.email_template.split("{n}")
          .join(String(first + index)) || null,
    }));
  }
  if (!rows.length || rows.length > 100)
    throw new Error("每批请填写 1–100 个用户。");
  for (const [index, row] of rows.entries()) {
    if (
      !/^[a-zA-Z0-9_.-]{2,70}$/.test(row.username) ||
      (row.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(row.email))
    )
      throw new Error(`第 ${index + 1} 名用户的用户名或邮箱格式有误。`);
  }
  const emails = rows.map((r) => r.email?.toLowerCase()).filter(Boolean);
  if (new Set(emails).size !== emails.length)
    throw new Error("AWS 要求邮箱唯一，请调整邮箱或留空自动生成。");
}
export function createSsoIntent(
  body: SsoCreationBody,
  group?: { name: string; aws_account_id: number },
): SsoCreationIntent {
  validateSsoCreation(body);
  if (
    group &&
    (!group.name.trim() ||
      group.name.trim().length > 1024 ||
      group.aws_account_id !== body.aws_account_id)
  )
    throw new Error("请填写同一 AWS 账号下的分组名称。");
  return {
    body: structuredClone(body),
    key: crypto.randomUUID(),
    ...(group
      ? {
          group: {
            body: { ...group, name: group.name.trim() },
            key: crypto.randomUUID(),
          },
        }
      : {}),
  };
}
export async function runSsoCreation(
  saved: SsoCreationIntent,
  post: <T>(path: string, body: unknown) => Promise<T>,
  checkpoint: (intent: SsoCreationIntent) => void,
): Promise<BatchInfo> {
  let intent = saved;
  if (intent.group && !intent.group.id) {
    const group = await post<GroupItem>("/groups", {
      ...intent.group.body,
      request_key: intent.group.key,
    });
    intent = { ...intent, group: { ...intent.group, id: group.id } };
    checkpoint(intent);
  }
  return post<BatchInfo>("/batches/create", {
    ...intent.body,
    ...(intent.group ? { group_id: intent.group.id } : {}),
    request_key: intent.key,
  });
}

export type AdmissionPost = <T>(path: string, body: unknown) => Promise<T>;

function definitivelyRejected(path: string, error: unknown) {
  const { status, message } = error as { status?: number; message?: string };
  const groupJob = /^\/groups\/[^/]+\/jobs$/.test(path);
  const knownAdmission = groupJob || ["/groups", "/groups/link", "/batches/create", "/batches/subscribe"].includes(path);
  if (!knownAdmission) return false;
  if (status === 400 || status === 422) return true;
  if (status !== 409) return false;
  // These checks occur after lookup by request key. Auth/permission errors,
  // key-content mismatches and unknown conflicts do not prove non-admission.
  const conflicts = groupJob ? [
    "分组已变化或有未完成任务，请刷新后重试",
    "该 AWS 身份中心的分组名称已被使用",
    "分组仍有未删除的本地成员或未完成任务",
    "SSO 用户尚未就绪或存在未完成操作",
    "该用户已有管理分组或已删除",
    "该用户不属于此分组",
    "分组与 SSO 的所有者和 AWS 配置必须一致",
    "分组尚未就绪或存在待处理任务",
    "分组所有者已停用",
  ] : path === "/batches/create" ? [
    "编号范围包含已使用的用户名，请调整起始编号后重试",
    "分组与 SSO 的所有者和 AWS 配置必须一致",
    "分组尚未就绪或存在待处理任务",
    "分组所有者已停用",
  ] : path === "/batches/subscribe" ? [
    "分组尚未就绪",
    "选择的 SSO 用户已不属于该分组",
    "SSO 创建者已停用",
    "仅可选择已完成创建、尚未绑定套餐、未发现现有订阅且未删除的 SSO 用户",
    "SSO 用户刚发生变化，请刷新后重新选择",
  ] : path === "/groups/link" ? ["该 AWS 分组已被平台管理"] : ["该 AWS 身份中心的分组名称已被使用"];
  return conflicts.includes(message || "");
}

export async function runRecoverableSubmission<Intent, Result>(
  intent: Intent,
  post: AdmissionPost,
  remember: (intent: Intent | null) => void,
  execute: (send: AdmissionPost, checkpoint: (intent: Intent) => void) => Promise<Result>,
): Promise<
  | { state: "accepted"; result: Result; intent: Intent }
  | { state: "rejected" | "unresolved"; error: Error; intent: Intent }
> {
  let current = intent;
  let failedPath = "";
  const checkpoint = (next: Intent) => { current = next; remember(next); };
  const send: AdmissionPost = async (path, body) => {
    try { return await post(path, body); }
    catch (error) { failedPath = path; throw error; }
  };
  try {
    checkpoint(intent);
    const result = await execute(send, checkpoint);
    remember(null);
    return { state: "accepted", result, intent: current };
  } catch (error) {
    const rejected = definitivelyRejected(failedPath, error);
    if (rejected) remember(null);
    return { state: rejected ? "rejected" : "unresolved", error: error as Error, intent: current };
  }
}
