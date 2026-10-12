import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
import { record } from "./plan-change-fixtures.mjs";
process.env.NODE_ENV = "production";
const { createElement: h } = await import("react");
const { renderToStaticMarkup } = await import("react-dom/server");
const { MemoryRouter } = await import("react-router-dom");
const ui = await loadSource("NativeSubscriptions");
const { Groups, GroupDirectoryTable } = await loadSource("Groups");
const { CurrentPlanFacts, RecordPlanLabel, PlanChangeManager } = await loadSource("PlanChangeManager");
const { StopRuleSource, StopScheduleEditor, StopPolicyFields } = await loadSource("StopSchedule");
const { canConfirmPlanChange } = await loadSource("planChangesLogic");
const { options } = await import("./plan-change-fixtures.mjs");
const render = component => renderToStaticMarkup(h(MemoryRouter, null, component));
const text = component => render(component).replace(/<[^>]+>/g, "");
const grant = { id: "grant1", group_id: "g1", state: "active", plan_name: "Native Pro", activated_at: "2026-10-01T00:00:00", stop_at: "2026-11-01T00:00:00", future_members_inherit: true };
const group = { id: "g1", name: "Native Team", owner_id: 7, aws_account_id: 2, state: "ready", policy: { mode: "days", days: 31, revision: 1 }, native_subscription: grant, counts: { total: 2, active: 2, subscribed: 2, eligible: 0 } };
const native = { ...record, group_id: "g1", effective_subscription_source: "GROUP", subscription_source: "GROUP", native_group_subscription: grant, controlling_group_stop_at: grant.stop_at };
test("mixed-source facts display effective and USER plans and scoped cancellation", () => {
  const mixed = { ...native, effective_subscription_source: "USER_AND_GROUP", cancellation_source: "GROUP",
    direct_user_plan: { plan_id: 1, name: "Direct Pro", subscription_type: "Q_DEVELOPER_STANDALONE_PRO" }, direct_user_status: "active",
    aws_subscription_status: "PENDING" };
  const facts = text(h(CurrentPlanFacts, { record: mixed }));
  assert.match(facts, /USER.*GROUP/);
  assert.match(facts, /Direct Pro/);
  assert.match(facts, /PENDING/);
  const cancellation = text(h(ui.CancellationFields, { records: [mixed], mode: "IMMEDIATE", onChange() {} }));
  assert.match(cancellation, /独立 USER.*其他 GROUP.*保留/);
});
test("personal USER deadline describes only USER cancellation and retained GROUP access", () => {
  const html = text(h(StopPolicyFields, { initial: { mode: "days", days: 30 }, independentUser: true }));
  assert.match(html, /仅取消独立 USER 授权.*GROUP.*保留/);
  assert.doesNotMatch(html, /停止 Kiro 访问/);
});
test("group detail and its asynchronous history have distinct sibling keys so loading DOM is replaced", () => {
  let tree;
  function Capture() { tree = Groups({ user: { id: 7, role: "member" }, notify() {} }); return null; }
  renderToStaticMarkup(h(MemoryRouter, { initialEntries: ["/groups?group_id=g1"] }, h(Capture)));
  const keys = tree.props.children.filter(child => child && child.key !== null).map(child => child.key);
  assert.equal(keys.length, new Set(keys).size, "distinct group detail and history keys prevent orphaned loading nodes");
});
test("group directory offers actual selectable principals and native current plan", () => {
  const html = render(h(GroupDirectoryTable, { groups: [group], selected: ["g1"], onSelection() {}, isAdmin: false, ownerName: () => "Owner", accountName: () => "AWS B" }));
  assert.match(html, /aria-label="选择分组 Native Team"/); assert.match(html, /aria-label="选择当前结果中的分组"/);
  assert.match(html, /Native Pro/); assert.match(html, /GROUP/);
});
test("paid confirmation states full member count and future member activation charges", () => {
  assert.equal(typeof ui.NativePreviewSummary, "function");
  const html = text(h(ui.NativePreviewSummary, { preview: { principal_type: "GROUP", future_members_inherit: true, member_count: 2, groups: [{ ...group, member_ids: ["r1", "r2"], member_count: 2 }] } }));
  assert.match(html, /完整成员 2 人/); assert.match(html, /Native Team/); assert.match(html, /未来加入.*自动.*套餐/); assert.match(html, /消耗.*1 次/);
});
test("SSO join copy distinguishes standalone free creation and paid active-group attachment", () => {
  assert.equal(typeof ui.GroupJoinNotice, "function");
  assert.match(text(h(ui.GroupJoinNotice, { group: null })), /单独创建 SSO.*不消耗/);
  const html = text(h(ui.GroupJoinNotice, { group, count: 2 }));
  assert.match(html, /Native Team/); assert.match(html, /Native Pro/); assert.match(html, /2 次/); assert.match(html, /共同停止/);
  assert.doesNotMatch(html, /不会自动开通|不消耗/);
  const general = text(h(ui.GroupJoinNotice, { group }));
  assert.match(general, /每名新成员.*1 次/); assert.doesNotMatch(general, /本次 1 人/);
});
test("selected inherited cancellation is immediate-only and explicitly removes membership while keeping SSO", () => {
  const html = render(h(ui.CancellationFields, { records: [native], mode: "IMMEDIATE", onChange() {} }));
  assert.match(html, /移出 AWS 组并停止该组授权，保留 SSO/); assert.doesNotMatch(html, /value="END_OF_PERIOD"/);
  const direct = render(h(ui.CancellationFields, { records: [{ ...record, supports_scheduled_cancellation: true }], mode: "IMMEDIATE", onChange() {} }));
  assert.match(direct, /value="END_OF_PERIOD"/);
});
test("group cancellation preserves SSO and membership and honors legacy mode support", () => {
  const html = render(h(ui.CancellationFields, { groups: [group], mode: "IMMEDIATE", onChange() {} }));
  assert.match(html, /保留 SSO.*成员关系/); assert.doesNotMatch(html, /value="END_OF_PERIOD"/);
});
test("batch progress preserves per-item errors and exposes only read reconciliation for uncertain group items", () => {
  const html = render(h(ui.LifecycleBatchView, { batch: { id: "b1", kind: "group_cancel", total: 3, created_at: "2026-10-10", states: { completed: 1, failed: 1, needs_review: 1 }, items: ["completed", "failed", "needs_review"].map((state, i) => ({ id: `g${i}`, name: `Team ${i}`, operation_id: `op${i}`, principal_type: "GROUP", state, phase: state === "needs_review" ? "pending" : "done", error: state === "completed" ? null : `failure ${i}` })) }, busy: false, onRecheck() {} }));
  assert.match(html, /已完成/); assert.match(html, /处理失败/); assert.match(html, /待核对/); assert.match(html, /failure 1/); assert.match(html, /failure 2/);
  assert.equal((html.match(/只读核对 AWS Team 2/g) || []).length, 1); assert.doesNotMatch(html, /只读核对 AWS Team 1/);
});
test("native effective source and pending target remain distinct from current plan and original fields", () => {
  const pending = { ...record, effective_subscription_source: null, subscription_source: "GROUP", native_group_subscription: { ...grant, state: "pending", plan_name: "Pending Power" } };
  const html = text(h(RecordPlanLabel, { record: pending, directory: true }));
  assert.match(html, /当前（系统记录）：Pro\+/); assert.match(html, /待确认分组套餐：Pending Power/);
  assert.doesNotMatch(html, /当前（系统记录）：Pending Power/);
  assert.match(text(h(CurrentPlanFacts, { record: native })), /原生分组.*GROUP/);
});
test("active native plans block individual plan change even with enabled capability", () => {
  assert.equal(canConfirmPlanChange(native, options, options.targets[2], native.username, true), false);
  const html = text(h(PlanChangeManager, { enabled: true, actorId: 7, record: native, onChanged() {} }));
  assert.match(html, /原生分组授权不能单独变更套餐/); assert.doesNotMatch(html, /更改套餐/);
  assert.equal(render(h(PlanChangeManager, { enabled: false, actorId: 7, record: native, onChanged() {} })), "");
});
test("native group stop shows common deadline and allows earlier individual edit while future cancellation still grants access", () => {
  const scheduled = { ...native, subscription_status: "cancel_scheduled", cancelled_at: null, stop_schedule: { mode: "at", stop_at: "2026-10-20T00:00:00", revision: 2, individual_override: true, state: "scheduled" } };
  const html = text(h(StopScheduleEditor, { record: scheduled, group, blocked: false, onChanged() {} }));
  assert.match(html, /分组共同停止/); assert.match(html, /不能.*超过/); assert.match(html, /单独设置停止规则/); assert.match(html, /恢复分组规则/);
  assert.match(text(h(StopRuleSource, { record: native, group })), /后来加入.*剩余/);
});

test("saved deadline principal stays visible after its USER claim ends or a USER claim joins", () => {
  const schedule = { mode: "days", days: 30, stop_at: "2026-10-20T00:00:00", revision: 2, individual_override: true, state: "scheduled" };
  const userDeadline = { ...native, stop_schedule: { ...schedule, principal_type: "USER" }, direct_user_status: "cancelled" };
  const userHtml = text(h(StopScheduleEditor, { record: userDeadline, group, blocked: false, onChanged() {} }));
  assert.match(userHtml, /个人截止时间仅取消独立 USER 授权/);
  assert.doesNotMatch(userHtml, /不能延长到超过分组共同截止时间/);
  const groupDeadline = { ...native, stop_schedule: { ...schedule, principal_type: "GROUP" },
    direct_user_status: "active", direct_user_plan: { subscription_type: "Q_DEVELOPER_STANDALONE_PRO" } };
  const groupHtml = text(h(StopScheduleEditor, { record: groupDeadline, group, blocked: false, onChanged() {} }));
  assert.match(groupHtml, /不能延长到超过分组共同截止时间/);
  assert.doesNotMatch(groupHtml, /个人截止时间仅取消独立 USER 授权/);
});
