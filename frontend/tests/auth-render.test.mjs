import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
process.env.NODE_ENV = "production";
const { createElement: h } = await import("react");
const { renderToStaticMarkup } = await import("react-dom/server");
const { MemoryRouter } = await import("react-router-dom");
const { PasswordFields, AuthBatchView, AdmissionRecovery, CredentialDetails } = await loadSource("AuthBatches");
const { JsonExport } = await loadSource("JsonExport");
const { PasswordBatches } = await loadSource("PasswordBatches");
const { AuthRecordTable, ManualAuthPicker } = await loadSource("AuthSelection");
const render = component => renderToStaticMarkup(h(MemoryRouter, null, component));

test("password modes remain distinct and custom input is a masked non-autofilled field", () => {
  const html = render(h(PasswordFields, { kind: "custom_password", password: "", disabled: false, onKind() {}, onPassword() {} }));
  assert.match(html, /重置一次性密码/); assert.match(html, /独立随机永久密码/); assert.match(html, /共享永久密码/);
  assert.match(html, /type="password"/); assert.match(html, /autoComplete="new-password"/);
  assert.match(html, /8–64/); assert.match(html, /最近三次/);
  assert.doesNotMatch(html, /JSON|token|OAuth/);
});

const batch = { id: "batch-a", actor_id: 7, kind: "json_export", state: "active", total: 3, success_count: 1, failure_count: 2,
  completed_at: "2026-10-09T08:00:00", created_at: "2026-10-09T07:00:00", expires_at: "2026-10-10T07:00:00", download_expires_at: "2026-10-09T09:00:00", download_ready: true,
  states: { completed: 1, failed: 1, needs_review: 1 }, items: [
    { record_id: "a", username: "success-user", state: "completed", credential_state: "permanent" },
    { record_id: "b", username: "failed-user", state: "failed", error: "请管理员在对应的 AWS IAM Identity Center 关闭 MFA 后重试", credential_state: "one_time" },
    { record_id: "c", username: "unknown-user", state: "needs_review", requires_new_reset: true, credential_state: "unknown" },
  ] };
const actions = { busy: false, onAction() {}, onDownload() {}, onChallenge() {} };
test("settled CAPTCHA exposes retry before failure while ongoing verification does not", () => {
  const waiting = { ...batch, completed_at: null, download_ready: false, items: [
    { record_id: "challenge", username: "waiting", state: "challenge", can_retry_challenge: true },
  ] };
  assert.match(render(h(AuthBatchView, { batch: waiting, ...actions })), /重试验证/);
  waiting.items[0].can_retry_challenge = false;
  assert.doesNotMatch(render(h(AuthBatchView, { batch: waiting, ...actions })), /重试验证/);
});
test("partial batch displays per-account outcomes, excluded count, deadline and explicit unknown reset", () => {
  const html = render(h(AuthBatchView, { batch, ...actions }));
  assert.match(html, /成功 1/); assert.match(html, /未成功 2/);
  assert.match(html, /下载 1 人的 JSON/); assert.match(html, /不包含未成功的 2/);
  for (const label of ["success-user", "failed-user", "unknown-user", "永久密码", "一次性密码", "密码状态待核对", "明确再次重置", "关闭 MFA", "下载截止"])
    assert.ok(html.includes(label), label);
});
test("JSON queue explains current saved password type and subscribed first-login conversion", () => {
  const html = render(h(AuthBatchView, { batch, ...actions }));
  assert.match(html, /当前密码类型.*已保存/);
  assert.match(html, /订阅.*有效/);
  assert.match(html, /AWS 要求.*首次登录.*保存永久密码.*JSON/);
  assert.match(html, /已有永久密码.*保留/);
});
test("purged and expired exports direct regeneration without offering another download", () => {
  for (const state of ["downloaded", "expired", "cancelled"]) {
    const html = render(h(AuthBatchView, { batch: { ...batch, state }, ...actions }));
    assert.match(html, /重新选择用户生成/); assert.doesNotMatch(html, /下载 1 人的 JSON/);
  }
});
test("closed terminal rows do not claim cancellation is still pending, while running cancellation does", () => {
  const closed = { ...batch, state: "downloaded", items: ["completed", "failed", "needs_review", "cancelled", "expired"].map(state => ({
    record_id: state, username: `user-${state}`, state, cancel_requested: true, credential_state: "permanent",
  })) };
  const html = render(h(AuthBatchView, { batch: closed, ...actions }));
  assert.doesNotMatch(html, /已请求取消，等待当前步骤结束/);
  const running = render(h(AuthBatchView, { batch: { ...batch, items: [{ record_id: "running", username: "running-user", state: "running", cancel_requested: true }] }, ...actions }));
  assert.match(running, /已请求取消，等待当前步骤结束/);
});
test("custom reload recovery offers history review and never suggests silent resubmission", () => {
  const html = render(h(AdmissionRecovery, { admission: { pending: { kind: "custom_password", record_ids: ["a"] }, busy: false, canResume: false, error: "", clearAfterReview() {} }, onAccepted() {} }));
  assert.match(html, /核对下方本人历史记录/); assert.match(html, /不能仅凭时间相近/);
  assert.doesNotMatch(html, /继续原请求/);
});

test("dedicated export page selects existing accounts or groups and explains first-login password changes", () => {
  const html = render(h(JsonExport, { user: { id: 7, role: "member" }, notify() {} }));
  assert.match(html, /JSON 导出/); assert.match(html, /手动选择/); assert.match(html, /按分组选择/);
  assert.match(html, /首次登录/); assert.match(html, /最多 100/); assert.match(html, /本人历史记录/);
  assert.match(html, /AWS .*官方页面/); assert.match(html, /不包含.*密码/);
  assert.doesNotMatch(html, /textarea|API Key|一次性密码重置/);
});
test("account table labels hidden jobs and disables their checkboxes", () => {
  const html = render(h(AuthRecordTable, { user: { id: 7, role: "member" }, kind: "json_export", selected: [], disabled: false, onChange() {}, records: [
    { id: "hidden", username: "busy-user", owner_id: 7, sso_user_id: "sso", state: "completed", has_password: true, credential_state: "permanent", operation: null, operation_pending: true },
  ] }));
  assert.match(html, /有任务正在处理或待核对/); assert.match(html, /disabled=""/);
});
test("saved credential labels do not claim a one-time password exists when absent", () => {
  const html = render(h(AuthRecordTable, { user: { id: 7, role: "member" }, kind: "json_export", selected: [], disabled: false, onChange() {}, records: [
    { id: "missing", username: "missing-password", owner_id: 7, sso_user_id: "sso", state: "completed", has_password: false, credential_state: "one_time", subscription_status: "active" },
  ] }));
  assert.match(html, /未保存登录密码/); assert.doesNotMatch(html, /一次性密码/);
  assert.match(html, /disabled=""/);
  const queue = render(h(AuthBatchView, { batch: { ...batch, items: [
    { record_id: "missing", username: "missing-password", state: "queued", has_password: false, credential_state: "one_time" },
  ] }, ...actions }));
  assert.match(queue, /未保存登录密码/); assert.doesNotMatch(queue, /<td>一次性密码<\/td>/);
});

test("login detail shows a confirmed permanent password and never renders an unknown candidate", () => {
  const credential = { username: "test-user", portal_url: "https://example.awsapps.com/start", password: "Synthetic8!", region: "us-east-1", generated_at: "2026-10-09T00:00:00" };
  const html = render(h(CredentialDetails, { credential: { ...credential, credential_state: "permanent" } }));
  assert.match(html, /永久密码/); assert.match(html, /Synthetic8!/); assert.doesNotMatch(html, /历史一次性密码/);
  for (const state of ["unknown", undefined]) {
    const unknown = render(h(CredentialDetails, { credential: { ...credential, credential_state: state } }));
    assert.match(unknown, /密码状态待核对/); assert.doesNotMatch(unknown, /Synthetic8!/);
  }
});
test("SSO existence filter uses the backend's undeleted meaning", () => {
  const html = render(h(ManualAuthPicker, { user: { id: 7, role: "member" }, kind: "json_export", selected: [], disabled: false, onChange() {} }));
  assert.match(html, /value="active">未删除/);
  assert.doesNotMatch(html, /value="active">已订阅/);
});

test("password selector with no incoming selection exposes account and name/email search", () => {
  const html = render(h(PasswordBatches, { user: { id: 7, role: "member" }, notify() {}, onClose() {} }));
  assert.match(html, /按 AWS 账号筛选/);
  assert.match(html, /搜索用户名、姓名或邮箱/);
});
