export interface PastedPreview {
  total: number; preview_fingerprint: string;
  accounts: { username: string; portal_url: string; region: string | null; email?: string | null }[];
}
export interface ExternalItem {
  id: string; username: string; portal_url: string; region: string | null;
  state: string; stage: string; error: string | null; error_code: string | null;
  revision: number; retry_count: number; next_poll_at: string | null;
  cancel_requested: boolean; credential_recovery_available: boolean;
  can_retry_challenge?: boolean;
}
export interface ExternalBatch {
  id: string; actor_id: number; request_key: string; state: string;
  created_at: string; expires_at: string; completed_at: string | null;
  download_expires_at: string | null; download_ready: boolean;
  total: number; success_count: number; failure_count: number; items?: ExternalItem[];
}
export interface ExternalPending { request_key: string; preview_fingerprint: string }
export function externalPending(raw: string | null): ExternalPending | null {
  try {
    const value = JSON.parse(raw || "null");
    return value && typeof value.request_key === "string" && value.request_key.length >= 16 && value.request_key.length <= 80 && /^[a-f0-9]{64}$/.test(value.preview_fingerprint)
      ? { request_key: value.request_key, preview_fingerprint: value.preview_fingerprint } : null;
  } catch { return null; }
}
export function externalIntent(preview: PastedPreview, pending?: ExternalPending | null): ExternalPending {
  if (!/^[a-f0-9]{64}$/.test(preview.preview_fingerprint) || preview.total < 1 || preview.total > 100)
    throw new Error("请重新预览账号");
  if (pending && pending.preview_fingerprint !== preview.preview_fingerprint)
    throw new Error("当前输入与原请求不同，请粘贴原账号后核对；勿用新内容重复提交原请求");
  return pending || { request_key: crypto.randomUUID(), preview_fingerprint: preview.preview_fingerprint };
}
export const externalStages: Record<string, string> = {
  admitted: "等待登录", register: "注册 OIDC 客户端", device: "创建设备授权", portal: "读取登录入口",
  login: "开始登录", signin: "读取登录步骤", workflow: "登录处理中", whoami: "核对用户身份",
  poll: "等待 Token", profiles: "读取真实 Kiro 配置", usage: "核对实际账号数据", done: "转换完成",
  captcha_recognizing: "自动识别中", captcha_verified: "验证成功", retry_wait: "等待自动重试",
  refresh_requested: "准备更新授权", refresh: "更新授权",
};
