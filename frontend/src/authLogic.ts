import type { AuthBatch, AuthBatchInput, AuthChallenge, AuthKind, CredentialState, LoginCredential, RecordItem, User } from "./api";

export const authKindLabel: Record<AuthKind, string> = {
  json_export: "JSON 导出", reset_password: "重置一次性密码",
  random_password: "随机永久密码", custom_password: "共享永久密码",
};
export const authStateLabel: Record<string, string> = {
  queued: "等待处理", running: "正在处理", challenge: "等待人工验证", polling: "等待授权结果",
  completed: "已完成", downloaded: "已下载并清理", failed: "处理失败", needs_review: "待核对", cancelled: "已取消", expired: "已过期",
};
export const authStageLabel: Record<string, string> = {
  ready: "准备处理", register: "准备授权", device: "准备授权", portal: "连接登录服务",
  identity: "验证用户名", password: "验证登录密码", change_password: "设置永久密码",
  captcha_recognizing: "自动识别中", captcha_waiting: "等待验证码处理资源", captcha_verified: "验证成功",
  device_session: "确认授权", accept: "确认授权", associate: "确认授权", poll: "等待授权结果",
  profiles: "读取 Kiro 配置", usage: "读取用量", refresh: "更新授权", refresh_requested: "准备更新授权", done: "已完成",
  login: "连接登录服务", signin: "准备登录", workflow: "验证登录信息", whoami: "确认登录身份", exchange: "完成登录", native_success: "已确认登录",
};
export function validPermanentPassword(value: string) {
  return /^[\x21-\x7e]{8,64}$/.test(value) && /[A-Z]/.test(value) && /[a-z]/.test(value) && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value);
}
export function authRequest(kind: AuthKind, ids: readonly string[], groupId?: string, password?: string): AuthBatchInput {
  if (!ids.length || ids.length > 100 || new Set(ids).size !== ids.length || ids.some(id => !id))
    throw new Error("请选择 1–100 名不同的 SSO 用户。");
  if (kind === "custom_password" && !validPermanentPassword(password || ""))
    throw new Error("密码须为 8–64 位，包含大写、小写、数字和特殊字符，不含空格。");
  return Object.freeze({ kind, record_ids: Object.freeze([...ids]), request_key: crypto.randomUUID(),
    ...(groupId ? { group_id: groupId } : {}), ...(kind === "custom_password" ? { password } : {}) });
}
export function selectAuthRecords(current: readonly string[], ids: readonly string[], checked: boolean) {
  return checked ? [...new Set([...current, ...ids])].slice(0, 100) : current.filter(id => !ids.includes(id));
}
export function selectPreviewIds(selected: readonly string[], preview: readonly string[]) {
  if (selected.some(id => !preview.includes(id))) throw new Error("分组预览已变化，请重新选择用户。");
  return [...selected];
}
export function hasConfirmedSubscriptionAccess(r: Pick<RecordItem, "subscription_status" | "access_ends_at">, instant = Date.now()) {
  if (!["active", "cancel_scheduled"].includes(r.subscription_status || "")) return false;
  if (!r.access_ends_at) return r.subscription_status === "active";
  const raw = r.access_ends_at;
  const expiry = Date.parse(/(?:Z|[+-]\d{2}:\d{2})$/i.test(raw) ? raw : raw + "Z");
  return Number.isFinite(expiry) && expiry > instant;
}
export function canUseAuthRecord(r: RecordItem, user: User, kind: AuthKind) {
  return (r.owner_id === user.id || user.role === "admin") && !!r.sso_user_id && !r.sso_deleted_at &&
    ["completed", "failed"].includes(r.state) && !r.operation_pending && !r.operation &&
    (kind !== "json_export" || hasConfirmedSubscriptionAccess(r) && (r.has_password || r.credential_state === "unknown"));
}
export function credentialLabel(state?: CredentialState, hasPassword?: boolean) {
  if (hasPassword === false && state !== "unknown") return "未保存登录密码";
  return state === "one_time" ? "一次性密码" : state === "permanent" ? "永久密码" : "密码状态待核对";
}
export function credentialText(c: LoginCredential) {
  return `${c.internal_id ? `内部 ID：${c.internal_id}\n` : ""}AWS 登录地址：${c.portal_url}\n区域：${c.region}\n用户名：${c.username}\n${credentialLabel(c.credential_state)}${c.credential_state === "one_time" || c.credential_state === "permanent" ? `：${c.password}` : "，请先核对结果"}`;
}
export function batchCanDownload(batch: AuthBatch) {
  return batch.kind === "json_export" && batch.state === "active" && batch.download_ready &&
    batch.success_count > 0;
}
export function retryableItems(batch: AuthBatch) {
  return (batch.items || []).filter(item => (["failed", "needs_review"].includes(item.state) || item.state === "challenge" && item.can_retry_challenge) && !item.requires_new_reset && !item.cancel_requested);
}

export function safeAuthorizationUrl(challenge: AuthChallenge) {
  try {
    const raw = challenge.authorization_url || "";
    if (challenge.kind !== "aws_authorization" || !challenge.user_code || /[\\\s\x00-\x1f\x7f]/.test(raw)) return false;
    const url = new URL(raw);
    if (url.protocol !== "https:" || url.username || url.password || url.port) return false;
    const portal = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:awsapps\.com|app\.aws)$/.test(url.hostname);
    let query: string;
    if (portal && url.pathname === "/start/" && !url.search && url.hash.startsWith("#/device?")) query = url.hash.slice("#/device?".length);
    else if (/^device\.sso\.[a-z]{2}(?:-[a-z]+)+-\d\.amazonaws\.com$/.test(url.hostname) && url.pathname === "/" && !url.hash) query = url.search.slice(1);
    else return false;
    const params = [...new URLSearchParams(query).entries()];
    return params.length === 1 && params[0][0] === "user_code" && params[0][1] === challenge.user_code;
  } catch { return false; }
}

const challengeFields = ["kind", "id", "revision", "expires_at", "region", "stage", "callback", "container_id", "locale", "show_challenge_on_load", "script_url", "widget_origin", "redemption_token"] as const;
export function widgetInit(challenge: AuthChallenge) {
  return { type: "kiro-auth-init", operation_id: challenge.operation_id, challenge_id: challenge.id, revision: challenge.revision,
    challenge: Object.fromEntries(challengeFields.map(key => [key, challenge[key]])) };
}
type WidgetMessage = { type: "kiro-auth-ready" | "kiro-auth-complete" | "kiro-auth-error"; operation_id: string; challenge_id: string; revision: number; access_code?: string; code?: string };
export function acceptWidgetMessage(event: Pick<MessageEvent, "data" | "origin" | "source">, frame: Window | null, challenge: AuthChallenge, now = Date.now() / 1000): WidgetMessage | null {
  if (!frame || event.source !== frame || event.origin !== challenge.frame_origin || challenge.kind !== "ams" || !Number.isFinite(challenge.expires_at) || now >= challenge.expires_at) return null;
  const value = event.data;
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const extras = value.type === "kiro-auth-ready" ? [] : value.type === "kiro-auth-complete" ? ["access_code"] : value.type === "kiro-auth-error" ? ["code"] : null;
  if (!extras || Object.keys(value).sort().join(",") !== ["type", "operation_id", "challenge_id", "revision", ...extras].sort().join(",") ||
    value.operation_id !== challenge.operation_id || value.challenge_id !== challenge.id || value.revision !== challenge.revision) return null;
  if (value.type === "kiro-auth-complete" && (typeof value.access_code !== "string" || !value.access_code.length || value.access_code.length > 8192 || /[\x00-\x1f\x7f]/.test(value.access_code))) return null;
  if (value.type === "kiro-auth-error" && value.code !== "widget_failed") return null;
  return value;
}
