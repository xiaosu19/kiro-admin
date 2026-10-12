import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
import { record, options, change, scheduled } from "./plan-change-fixtures.mjs";
const logic = await loadSource("planChangesLogic");
test("paid confirmation requires exact username, acknowledgment and an available target", () => {
  assert.equal(typeof logic.canConfirmPlanChange, "function");
  const target = options.targets.find(t => t.plan_id === 3);
  for (const [name, acknowledged] of [["", true], [` ${record.username}`, true], [record.username, false]])
    assert.equal(logic.canConfirmPlanChange(record, options, target, name, acknowledged), false);
  assert.equal(logic.canConfirmPlanChange(record, options, target, record.username, true), true);
  assert.equal(logic.canConfirmPlanChange({ ...record, operation_pending: true }, options, target, record.username, true), false);
});
test("current, pending, exhausted and server-unavailable targets cannot be chosen", () => {
  assert.equal(typeof logic.targetUnavailableReason, "function");
  const reason = (id, opts = options) => logic.targetUnavailableReason(record, opts, opts.targets.find(t => t.plan_id === id));
  assert.match(reason(2), /当前套餐/);
  assert.match(reason(1, { ...options, pending_change: scheduled }), /待生效/);
  assert.equal(reason(4), "创建者该套餐次数不足");
  assert.equal(reason(3, { ...options, unavailable_reason: "订阅已取消" }), "订阅已取消");
  assert.equal(reason(3), "");
});
test("release eligibility uses naive UTC write time, ten minutes, and scheduled errors", () => {
  assert.equal(typeof logic.canConfirmNotApplied, "function");
  const item = { ...change, state: "needs_review", write_requested_at: "2026-10-10T00:00:00" };
  const now = Date.parse("2026-10-10T00:10:00Z");
  assert.equal(logic.canConfirmNotApplied(item, now - 1), false);
  assert.equal(logic.canConfirmNotApplied(item, now), true);
  assert.equal(logic.canConfirmNotApplied({ ...item, write_requested_at: null }, now), false);
  assert.equal(logic.canConfirmNotApplied({ ...scheduled, write_requested_at: item.write_requested_at, error: "AWS 待核实" }, now), true);
  assert.equal(logic.canConfirmNotApplied({ ...scheduled, write_requested_at: item.write_requested_at }, now), false);
});

test("withdrawal requires a scheduled pending change but never another target quota", () => {
  assert.equal(typeof logic.canWithdrawPlanChange, "function");
  const exhausted = { ...options, pending_change: scheduled, targets: options.targets.map(t => ({ ...t, available: false, remaining_count: 0 })) };
  assert.equal(logic.canWithdrawPlanChange(record, exhausted), true);
  assert.equal(logic.canWithdrawPlanChange({ ...record, operation_pending: true }, exhausted), false);
  assert.equal(logic.canWithdrawPlanChange(record, { ...exhausted, pending_change: { ...scheduled, state: "applied" } }), false);
});

test("safe release needs the exact username, a meaningful reason, acknowledgement and ten minutes", () => {
  assert.equal(typeof logic.canSubmitNotApplied, "function");
  const item = { ...change, state: "needs_review", write_requested_at: "2026-10-10T00:00:00+00:00" };
  const now = Date.parse("2026-10-10T00:10:00Z");
  for (const [username, reason, ack, time] of [["another", "核对 AWS 尚未生效", true, now], [record.username, " 123 ", true, now], [record.username, "核对 AWS 尚未生效", false, now], [record.username, "核对 AWS 尚未生效", true, now - 1]])
    assert.equal(logic.canSubmitNotApplied(item, record.username, username, reason, ack, time), false);
  assert.equal(logic.canSubmitNotApplied(item, record.username, record.username, "核对 AWS 尚未生效", true, now), true);
});

test("admin history timestamps use the actual event and distinguish changes from the initial subscription", () => {
  assert.equal(typeof logic.planHistoryTime, "function");
  assert.equal(logic.planHistoryTime({ event_kind: "plan_change", subscribed_at: "old", occurred_at: "actual", applied_at: "applied" }), "actual");
  assert.equal(logic.planHistoryTime({ event_kind: "plan_change", subscribed_at: "old", applied_at: "applied" }), "applied");
  assert.equal(logic.planHistoryTime({ event_kind: "plan_change", subscribed_at: "old" }), null);
  assert.equal(logic.planHistoryTime({ subscribed_at: "old" }), "old");
  assert.equal(typeof logic.isPlanChangeOperation, "function");
  assert.equal(logic.isPlanChangeOperation("change_plan"), true);
  assert.equal(logic.isPlanChangeOperation("withdraw_plan_change"), true);
  assert.equal(logic.isPlanChangeOperation("reset_password"), false);
});
