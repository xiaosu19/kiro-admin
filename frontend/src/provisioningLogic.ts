import type { Account, GroupItem, GroupPolicyPreview, RetryProgress, StopPolicy } from "./api";

export interface ProvisioningSettings {
  quantity: number; plan_id: number; policy: StopPolicy;
  exports: { csv: boolean; txt: boolean; json: boolean };
}
export interface AccountDraft extends ProvisioningSettings {
  aws_account_id: number; groupId: string; settingsMode: 'shared' | 'custom';
  groupRevision: number; policyRevision: number; policyMode: 'inherit' | 'change';
  overwrite_individual: boolean;
}
export interface AccountIntent {
  aws_account_id: number; quantity: number; plan_id: number;
  group: { mode: 'new' } | { mode: 'existing'; group_id: string; expected_revision: number; expected_policy_revision: number };
  stop_policy?: StopPolicy; overwrite_individual?: boolean; exports: AccountDraft['exports'];
}
export interface ProvisioningBody { accounts: AccountIntent[] }
export interface ProvisioningIntent extends ProvisioningBody { request_key: string; preview_fingerprint: string }
export interface JsonDownload { ready: boolean; requested: boolean; available_count: number; excluded_count: number; waiting_count: number; consumed_count: number }
export interface Recovery { kind: string; method: string; path: string; body?: Record<string, unknown>; requires_request_key?: boolean; read_only: boolean }
export interface ProvisioningItem extends RetryProgress {
  record_id: string; internal_id: string; position: number; username: string; email: string;
  state: string; phase: string; error: string | null; record_state: string | null; record_step: string | null;
  credentials_ready: boolean; subscribed_at: string | null; export_state: string; export_error: string | null;
  export_stage: string | null; auth_batch_id: string | null; recovery: Recovery | null;
  export_retry?: import("./api").RetryProgress;
}
export interface AccountPreview {
  aws_account_id: number; account_number: string; account_name: string; real_aws_account_id: string;
  quantity: number; next_batch_number: string; plan_id: number; plan_name: string;
  group: { mode: 'new' | 'existing'; id: string | null; name: string; revision: number | null; policy_revision: number };
  stop_policy: StopPolicy; policy_change: GroupPolicyPreview | null; existing_member_count: number; needed_count: number;
  exports: AccountDraft['exports'];
}
export interface PlanTotal { plan_id: number; plan_name: string; needed_count: number; available_count: number | null; reference_monthly_usd: number }
export interface ProvisioningPreview { preview_fingerprint: string; accounts: AccountPreview[]; totals: PlanTotal[]; number_is_estimate: boolean }
export interface ProvisioningAccount extends AccountPreview, RetryProgress {
  id: string; batch_number: string; state: string; phase: string; error: string | null; allowed_actions: string[];
  group_job_state?: string | null;
  effective_policy: StopPolicy | null; effective_stop_at: string | null; activated_at: string | null;
  recovery: Recovery | null; export_state: string; export_states: Record<string, number>; items?: ProvisioningItem[];
  json_download?: JsonDownload;
}
export interface ProvisioningBatch {
  id: string; actor_id: number; request_key: string; state: string; phase: string; error: string | null;
  created_at: string; finished_at: string | null; accounts: ProvisioningAccount[]; totals: PlanTotal[]; json_download?: JsonDownload;
}
export const provisioningStates: Record<string, string> = {
  queued: '等待处理', running: '正在处理', completed: '开通完成', paused: '已暂停', needs_review: '待核对',
  failed: '处理失败', stopped: '已停止', stopping: '正在停止', partial: '部分完成', uncertain: '结果待确认',
};
export const provisioningPhases: Record<string, string> = {
  admitted: '已受理', group_create: '创建分组', group_open: '开通分组', sso: '创建用户与加入分组',
  done: '已完成', group: '准备分组', export: '转换 JSON', password_pending: '核对密码',
  completed: '开通完成', group_access: '确认分组访问', group_policy: '设置分组停止规则', accounts: '处理账号批次',
};
export const exportStates: Record<string, string> = {
  not_requested: '未选择 JSON', waiting: '等待开通', queued: '等待转换', running: '正在转换', polling: '等待授权结果',
  challenge: '等待官方授权', completed: '转换完成', failed: '转换失败', needs_review: '转换待核对',
  downloaded: '已下载并清理', cancelled: '已取消', expired: '已过期', blocked: '转换未受理', partial: '状态见明细',
};
export function accountLabel(account: Account) { return `${account.account_number || '未设置编号'} · ${account.name} · ${account.aws_account_id || 'AWS ID 未设置'}`; }
export function defaultProvisioningSettings(planId = 0): ProvisioningSettings {
  return { quantity: 1, plan_id: planId, policy: { mode: 'none' }, exports: { csv: true, txt: true, json: false } };
}
export function accountDraft(account: Account, planId: number, settings = defaultProvisioningSettings(planId)): AccountDraft {
  return { ...settings, policy: { ...settings.policy }, exports: { ...settings.exports }, aws_account_id: account.id,
    settingsMode: 'shared', groupId: '', groupRevision: 0, policyRevision: 0, policyMode: 'change', overwrite_individual: false };
}
export function inheritProvisioningSettings(row: AccountDraft, settings: ProvisioningSettings): AccountDraft {
  return { ...row, quantity: settings.quantity, plan_id: settings.plan_id, exports: { ...settings.exports }, settingsMode: 'shared',
    policyMode: row.groupId ? 'inherit' : 'change', policy: { ...(row.groupId ? row.policy : settings.policy) }, overwrite_individual: false };
}
export function applySharedProvisioningSettings(rows: AccountDraft[], settings: ProvisioningSettings): AccountDraft[] {
  return rows.map(row => row.settingsMode === 'custom' ? row : inheritProvisioningSettings(row, settings));
}
export function toggleProvisioningAccount(rows: AccountDraft[], account: Account, settings: ProvisioningSettings): AccountDraft[] {
  if (rows.some(row => row.aws_account_id === account.id)) return rows.filter(row => row.aws_account_id !== account.id);
  return rows.length >= 100 ? rows : [...rows, accountDraft(account, settings.plan_id, settings)];
}
export function ownedGroups(groups: GroupItem[], actorId: number, accountId: number) {
  return groups.filter(g => g.owner_id === actorId && g.aws_account_id === accountId && !g.deleted_at);
}
export function withGroup(row: AccountDraft, group: GroupItem | null): AccountDraft {
  return { ...row, groupId: group?.id || '', groupRevision: group?.revision || 0, policyRevision: group?.policy.revision || 0,
    policyMode: group ? 'inherit' : 'change', policy: group ? { mode: group.policy.mode, ...(group.policy.days ? { days: group.policy.days } : {}),
      ...(group.policy.stop_at ? { stop_at: group.policy.stop_at } : {}) } : { mode: 'none' }, overwrite_individual: false };
}
export function provisioningBody(rows: AccountDraft[], accounts: Account[], groups: GroupItem[], actorId: number): ProvisioningBody {
  if (!rows.length || rows.length > 100 || new Set(rows.map(r => r.aws_account_id)).size !== rows.length) throw new Error('请选择 1–100 个不同的 AWS 账号。');
  return { accounts: rows.map(row => {
    const account = accounts.find(a => a.id === row.aws_account_id);
    if (!account?.active || account.deleted_at || !account.account_number || account.proxy_status !== 'enabled') throw new Error(`${account?.name || '所选账号'}：请管理员设置编号并绑定可用代理。`);
    if (!Number.isInteger(row.quantity) || row.quantity < 1 || row.quantity > 100) throw new Error(`${account.account_number}：新增人数须为 1–100。`);
    if (!row.plan_id) throw new Error(`${account.account_number}：请选择套餐。`);
    const group = row.groupId ? ownedGroups(groups, actorId, account.id).find(g => g.id === row.groupId) : null;
    if (row.groupId && (!group || group.state !== 'ready' || !group.remote_id || group.active_job_id || group.revision !== row.groupRevision || group.policy.revision !== row.policyRevision)) throw new Error(`${account.account_number}：分组或规则已变化，请重新选择分组。`);
    const policy = row.policyMode === 'inherit' && group ? undefined : row.policy;
    if (policy?.mode === 'days' && (!Number.isInteger(policy.days) || policy.days! < 1 || policy.days! > 3650)) throw new Error(`${account.account_number}：请填写 1–3650 天。`);
    if (policy?.mode === 'at' && (!policy.stop_at || !Number.isFinite(Date.parse(policy.stop_at)))) throw new Error(`${account.account_number}：请选择截止时间。`);
    return { aws_account_id: row.aws_account_id, quantity: row.quantity, plan_id: row.plan_id,
      group: group ? { mode: 'existing' as const, group_id: group.id, expected_revision: group.revision, expected_policy_revision: group.policy.revision } : { mode: 'new' as const },
      ...(policy ? { stop_policy: { ...policy } } : {}), ...(group && policy ? { overwrite_individual: row.overwrite_individual } : {}), exports: { ...row.exports } };
  }) };
}
export function freezeProvisioning<T>(input: T): T {
  const copy = JSON.parse(JSON.stringify(input));
  const freeze = (value: unknown) => { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } };
  freeze(copy); return copy;
}
export function provisioningIntent(body: ProvisioningBody, fingerprint: string): ProvisioningIntent {
  if (!/^[a-f0-9]{64}$/.test(fingerprint)) throw new Error('请重新预览批次。');
  return freezeProvisioning({ ...body, request_key: crypto.randomUUID(), preview_fingerprint: fingerprint });
}
export function validProvisioningBatch(batch: ProvisioningBatch, intent: ProvisioningIntent) {
  return !!batch?.id && batch.request_key === intent.request_key && Array.isArray(batch.accounts) && batch.accounts.length === intent.accounts.length &&
    intent.accounts.every((row, i) => { const actual = batch.accounts[i]; return actual?.aws_account_id === row.aws_account_id && actual.quantity === row.quantity && actual.plan_id === row.plan_id &&
      (row.group.mode === 'new' || actual.group.id === row.group.group_id); });
}
export function completedLegacyRecovery(batch: ProvisioningBatch, path: string) {
  const offered = batch.accounts.some(account => [account.recovery, ...(account.items || []).map(item => item.recovery)]
    .some(recovery => recovery?.path.replace(/^\/api/, '') === path));
  if (offered) return false;
  const account = batch.accounts.find(row => row.group.id && path === `/groups/${row.group.id}/retry`);
  if (account) return account.group_job_state == null ? account.state === 'completed' : account.group_job_state === 'completed';
  const item = batch.accounts.flatMap(row => row.items || []).find(row => path === `/subscriptions/${row.record_id}/retry`);
  return !!item && (item.record_state == null ? item.state === 'completed' : item.record_state === 'completed');
}
export function historyQuery(scope: Record<string, string | number | undefined>) {
  return new URLSearchParams(Object.entries(scope).filter(([, v]) => v !== undefined && v !== '').map(([k, v]) => [k, String(v)])).toString();
}
