import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
process.env.NODE_ENV = "production";
const { createElement: h } = await import("react");
const { renderToStaticMarkup } = await import("react-dom/server");
const aws = await loadSource("GroupAwsObservation"), members = await loadSource("GroupMembers");
const text = component => renderToStaticMarkup(component).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
const entry = { loading: false, stale: false, error: "", data: { queried_at: "2026-10-11T00:00:00Z",
  directory: { exists: true, name: "Remote name", member_count: 0, owned_members: [] },
  subscription: { status: "Canceled", plan_label: "Kiro Pro", pending_plan_label: null, effective_at: null, cancellation_expires_at: "2026-11-01T00:00:00Z", access_active: true } } };

test("AWS group UI distinguishes empty, missing, failed and not queried without local fallbacks", () => {
  assert.equal(typeof aws.GroupAwsPanel, "function");
  const render = value => text(h(aws.GroupAwsPanel, { entry: value, busy: false, refresh() {} }));
  assert.match(render(entry), /Remote name.*0 人/);
  assert.match(render(entry), /Canceled.*到期前仍可访问/);
  const missing = render({ ...entry, data: { ...entry.data, directory: { exists: false, name: null, member_count: null, owned_members: [] } } });
  assert.match(missing, /AWS 身份目录中不存在/); assert.doesNotMatch(missing, /实际成员 0/);
  assert.match(render(undefined), /尚未读取 AWS/);
  const failure = render({ data: null, loading: false, error: "AWS unavailable", stale: false });
  assert.match(failure, /AWS 状态暂不可用/); assert.doesNotMatch(failure, /0 人|Not subscribed/);
  assert.match(render({ ...entry, data: null, stale: true }), /已变化，请刷新/);
});

test("AWS group UI renders pending plans and the actual effective boundary", () => {
  assert.equal(typeof aws.GroupAwsPanel, "function");
  const html = text(h(aws.GroupAwsPanel, { entry: { ...entry, data: { ...entry.data, subscription: { ...entry.data.subscription,
    status: "Subscribed", pending_plan_label: "FUTURE_PLAN", effective_at: "2026-11-01T00:00:00Z", cancellation_expires_at: null } } }, busy: false, refresh() {} }));
  assert.match(html, /FUTURE_PLAN/); assert.match(html, /生效/); assert.match(html, /查询时间/);
});

test("AWS observation response query time renders the canonical UTC instant", () => {
  const data = { group_id: "group", aws_account_id: 1, remote_id: "remote-group", queried_at: "2026-10-11T12:34:56Z",
    directory: { exists: true, name: "AWS renamed team", member_count: 2, owned_members: [
      { record_id: "owned", sso_user_id: "sso-owned", username: "owned", email: "owned@example.com", membership_id: "m-owned" } ] },
    subscription: { status: "Subscribed", subscription_type: "KIRO_ENTERPRISE_PRO", plan_label: "Kiro Pro", pending_subscription_type: null,
      pending_plan_label: null, effective_at: null, cancellation_expires_at: null, access_active: true } };
  const html = text(h(aws.GroupAwsPanel, { entry: { ...entry, data }, busy: false, refresh() {} }));
  const expected = new Date(data.queried_at).toLocaleString("zh-CN", { hour12: false });
  assert.ok(html.includes(`查询时间：${expected}`), html);
  assert.doesNotMatch(html, /Invalid Date/);
});

test("batch member checkboxes show USER + GROUP and the 100 selection cap", () => {
  assert.equal(typeof members.MemberSelection, "function");
  const selected = Array.from({ length: 100 }, (_, i) => ({ id: "r" + i, username: "member" + i }));
  const row = { id: "other", username: "independent", effective_subscription_source: "USER_AND_GROUP", direct_user_status: "active" };
  const html = renderToStaticMarkup(h(members.MemberSelection, { records: [row], selected, disabled: false, onSelection() {} }));
  assert.match(html, /个人订阅 · USER \+ 原生分组 · GROUP/); assert.match(html, /100/);
  assert.match(html, /aria-label="选择成员 independent"[^>]*disabled/);
});

test("durable progress keeps partial success and uses only server allowed actions", () => {
  assert.equal(typeof members.MemberBatchProgress, "function");
  const batch = { id: "b", kind: "attach", state: "needs_review", error: "uncertain AWS", counts: { total: 100, completed: 3, needs_review: 1, waiting: 96, queued: 0, running: 0, failed: 0, stopped: 0 },
    actions: { recheck: true, retry: false, stop: true }, items: [{ position: 3, record_id: "r3", username: "actual-member-name", sso_user_id: "sso-id", state: "needs_review", phase: "pending", attempts: 1, error: "uncertain AWS" }] };
  const html = text(h(members.MemberBatchProgress, { batch, busy: false, onAction() {} }));
  assert.match(html, /已完成 3/); assert.match(html, /等待前项完成 96/); assert.match(html, /只读核对/); assert.match(html, /停止未发送成员/);
  assert.doesNotMatch(html, /明确重试/); assert.match(html, /uncertain AWS/);
  assert.match(html, /actual-member-name/); assert.match(html, /SSO ID：sso-id/); assert.match(html, /记录 ID：r3/);
  const stopped = text(h(members.MemberBatchProgress, { batch: { ...batch, state: "stopped", actions: { recheck: false, retry: false, stop: false }, stop_requested_at: "2026-10-11", counts: { ...batch.counts, stopped: 96, waiting: 0 } }, busy: false, onAction() {} }));
  assert.match(stopped, /已停止 96/); assert.doesNotMatch(stopped, /停止未发送成员/);
});
