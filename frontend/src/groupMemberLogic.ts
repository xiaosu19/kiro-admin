import { ApiError, type GroupItem, type MemberBatch, type MemberBatchInput, type MemberBatchKind, type RecordItem } from "./api";

export interface MemberIntent { group_id: string; body: MemberBatchInput }
export const memberStates = { waiting: "等待前项完成", queued: "等待处理", running: "正在处理", completed: "已完成", failed: "处理失败", needs_review: "待核对", stopped: "已停止" };
export function memberCandidatePath(groupId: string, kind: MemberBatchKind, q: string, page: number) {
  return `/groups/${encodeURIComponent(groupId)}/member-candidates?${new URLSearchParams({ kind, q, page: String(page), page_size: "100" })}`;
}
export function selectMemberRecords(selected: RecordItem[], visible: RecordItem[], checked: boolean) {
  const ids = new Set(visible.map(record => record.id));
  if (!checked) return selected.filter(record => !ids.has(record.id));
  return [...new Map([...selected, ...visible].map(record => [record.id, record])).values()].slice(0, 100);
}
export function freezeMemberIntent(value: MemberIntent): MemberIntent {
  const ids = [...new Set(value.body.record_ids)].sort();
  if (!value.group_id || !["attach", "detach"].includes(value.body.kind) || ids.length < 1 || ids.length > 100 ||
    ids.some(id => typeof id !== "string" || !id || id.length > 36) || !Number.isInteger(value.body.expected_revision) || value.body.expected_revision < 1 ||
    typeof value.body.request_key !== "string" || value.body.request_key.length < 16 || value.body.request_key.length > 80) throw new Error("请选择 1–100 个有效成员并重新读取分组。");
  const body = { kind: value.body.kind, record_ids: ids, expected_revision: value.body.expected_revision, request_key: value.body.request_key };
  Object.freeze(ids); Object.freeze(body); return Object.freeze({ group_id: value.group_id, body });
}
export function memberIntent(group: Pick<GroupItem, "id" | "revision">, kind: MemberBatchKind, ids: string[]) {
  return freezeMemberIntent({ group_id: group.id, body: { kind, record_ids: ids, expected_revision: group.revision, request_key: crypto.randomUUID() } });
}
export function validMemberBatch(value: unknown, intent?: MemberIntent, actorId?: number): value is MemberBatch {
  const batch = value as MemberBatch;
  if (!batch || typeof batch.id !== "string" || !batch.id || !["attach", "detach"].includes(batch.kind) || !Array.isArray(batch.record_ids) ||
    typeof batch.group_id !== "string" || !batch.group_id || !Number.isInteger(batch.owner_id) || batch.owner_id < 1 || !Number.isInteger(batch.actor_id) || batch.actor_id < 1 ||
    !Object.keys(memberStates).includes(batch.state) || batch.record_ids.some(id => typeof id !== "string" || !id || id.length > 36) ||
    new Set(batch.record_ids).size !== batch.record_ids.length || !batch.record_ids.length || batch.record_ids.length > 100 ||
    !batch.counts || batch.counts.total !== batch.record_ids.length || !batch.actions ||
    !Object.keys(memberStates).every(key => Number.isInteger(batch.counts[key as keyof typeof memberStates]) && batch.counts[key as keyof typeof memberStates] >= 0) ||
    Object.keys(memberStates).reduce((sum, key) => sum + batch.counts[key as keyof typeof memberStates], 0) !== batch.counts.total ||
    !["recheck", "retry", "stop"].every(key => typeof batch.actions[key as keyof MemberBatch["actions"]] === "boolean")) return false;
  if (batch.items !== undefined && (!Array.isArray(batch.items) || batch.items.length !== batch.counts.total ||
    batch.items.some((item, position) => !item || item.position !== position || item.record_id !== batch.record_ids[position] || !Object.keys(memberStates).includes(item.state)))) return false;
  return (actorId === undefined || batch.actor_id === actorId) && (!intent || batch.group_id === intent.group_id && batch.kind === intent.body.kind &&
    batch.request_key === intent.body.request_key && batch.expected_revision === intent.body.expected_revision &&
    JSON.stringify([...batch.record_ids].sort()) === JSON.stringify(intent.body.record_ids));
}
export function definiteMemberRejection(error: unknown) {
  return error instanceof ApiError && ([400, 422].includes(error.status) || error.status === 409 && [
    "分组已变化或有未完成任务，请刷新后重试", "分组成员仍有未完成任务", "分组与 SSO 的所有者和 AWS 配置必须一致",
    "SSO 用户尚未就绪或存在未完成操作", "该用户已有管理分组", "该用户不是此分组的已确认成员",
    "分组所有者、操作者或 AWS 绑定已停用", "原生分组套餐或成员截止时间已变化",
    "原生分组订阅未就绪、待核对或已到停止时间", "该 SSO 已有原生分组开通任务或授权",
    "该 SSO 订阅状态待确认，不能叠加原生分组授权", "SSO 所有者的目标套餐次数已用完或未设置，请联系管理员",
  ].includes(error.message));
}
