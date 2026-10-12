import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
import { mountHook, settle } from "./hooks.mjs";
import { environment, response, record } from "./plan-change-fixtures.mjs";
const logic = await loadSource("nativeSubscriptionsLogic");
const requests = await loadSource("nativeSubscriptionRequests");
const { ApiError } = await loadSource("api");
const group = { id: "g1", name: "Match Team", owner_id: 7, aws_account_id: 2, state: "ready", deleted_at: null, active_job_id: null, supports_scheduled_cancellation: true };
const grant = { id: "grant-1", group_id: "g1", state: "active", plan_name: "Pro", stop_at: "2026-11-01T00:00:00" };
const native = { ...record, effective_subscription_source: "GROUP", native_group_subscription: grant, supports_scheduled_cancellation: true };
test("mixed sources keep managed-group cancellation but permit independent USER plan changes", async () => {
  const mixed = { ...native, effective_subscription_source: "USER_AND_GROUP", cancellation_source: "GROUP",
    direct_user_plan: record.current_plan, direct_user_status: "active" };
  assert.equal(logic.nativeAccess(mixed), true);
  const plans = await loadSource("planChangesLogic");
  assert.equal(plans.planWritesBlocked(mixed), false);
  assert.equal(logic.nativeAccess({ ...mixed, cancellation_source: "USER", native_group_subscription: { ...grant, state: "cancelled" } }), false);
  assert.equal(logic.canCancelRecord({ ...mixed, cancellation_source: null }), false);
});
const intent = () => ({ kind: "group_subscribe", body: { group_ids: ["g1", "g2"], plan_id: 3, request_key: "native-request-key-0001" } });
const batch = { id: "batch-1", kind: "group_subscribe", created_at: "2026-10-10T00:00:00", total: 2, states: { queued: 0, running: 0, completed: 1, failed: 0, needs_review: 1 }, items: [
  { id: "g1", name: "Match Team", principal_type: "GROUP", operation_id: "op1", state: "completed", phase: "done", error: null },
  { id: "g2", name: "Team 2", principal_type: "GROUP", operation_id: "op2", state: "needs_review", phase: "pending", error: "AWS response lost" },
] };
test("group request intersects account, group and member searches without converting members to recipients", () => {
  assert.equal(typeof logic.groupSearchPath, "function");
  const url = new URL(logic.groupSearchPath({ account: "2", q: " MaTcH ", member: " one " }), "https://example.test");
  assert.equal(url.searchParams.get("aws_account_id"), "2");
  assert.equal(url.searchParams.get("q"), "MaTcH");
  assert.equal(url.searchParams.get("member_q"), "one");
  assert.deepEqual(logic.nativeIntent("group_subscribe", ["g1", "g2"], 3).body.group_ids, ["g1", "g2"]);
});
test("group filters retain owner/state scope and selection remains inside current results", () => {
  assert.deepEqual(logic.filterGroups([group, { ...group, id: "g2", owner_id: 8 }, { ...group, id: "g3", state: "failed" }], "7", "ready").map(g => g.id), ["g1"]);
  assert.deepEqual(logic.currentGroupSelection(["g1", "g2", "g1"], [group]), ["g1"]);
});
test("native preview validates complete selected group snapshots and total member count", () => {
  const preview = { principal_type: "GROUP", future_members_inherit: true, member_count: 2, groups: [{ ...group, member_ids: ["r1", "r2"], member_count: 2, policy_revision: 1 }] };
  assert.equal(logic.validNativePreview(preview, ["g1"]), true);
  assert.equal(logic.validNativePreview({ ...preview, member_count: 1 }, ["g1"]), false);
  assert.equal(logic.validNativePreview(preview, ["g2"]), false);
});
test("cancellation guards use public operation_pending and native grants permit immediate only", () => {
  assert.equal(logic.canCancelRecord(native), true);
  assert.equal(logic.canCancelRecord({ ...native, operation_pending: true }), false);
  assert.equal(logic.supportsRecordScheduledCancellation([native]), false);
  assert.equal(logic.supportsRecordScheduledCancellation([{ ...record, supports_scheduled_cancellation: true }]), true);
  assert.equal(logic.supportsRecordScheduledCancellation([{ ...record, supports_scheduled_cancellation: false }]), false);
  assert.equal(logic.canCancelGroup({ ...group, native_subscription: { ...grant, state: "cancel_scheduled" } }), false);
});
test("request builder selects dedicated group/individual routes and preserves exact ordered selection", () => {
  for (const [kind, endpoint, key] of [["group_subscribe", "/group-subscriptions", "group_ids"], ["group_cancel", "/group-subscriptions/cancel", "group_ids"], ["user_cancel", "/subscription-cancellations", "record_ids"]]) {
    const request = logic.nativeIntent(kind, ["b", "a"], kind === "group_subscribe" ? 3 : "END_OF_PERIOD");
    assert.equal(logic.lifecycleEndpoint(request.kind), endpoint);
    assert.deepEqual(request.body[key], ["b", "a"]);
    assert.equal(request.body.request_key.length >= 16, true);
  }
});
test("batch recovery differentiates GROUP recheck from USER operation retry even for inherited members", () => {
  assert.deepEqual(logic.lifecycleRecovery(batch.items[1]), { path: "/group-subscriptions/op2/recheck" });
  assert.deepEqual(logic.lifecycleRecovery({ ...batch.items[1], id: "r1", principal_type: "USER", name: "user-one" }), { path: "/subscriptions/r1/operations/op2/retry", body: { confirm_username: "user-one" } });
});
test("full batch validation rejects incomplete results or the wrong principals before clearing paid intent", () => {
  assert.equal(logic.validLifecycleBatch(batch, intent()), true);
  assert.equal(logic.validLifecycleBatch({ ...batch, items: [batch.items[0]] }, intent()), false);
  assert.equal(logic.validLifecycleBatch({ ...batch, kind: "group_cancel" }, intent()), false);
  assert.equal(logic.validLifecycleBatch({ ...batch, states: {} }, intent()), false);
  assert.equal(logic.validLifecycleBatch({ ...batch, items: [null, batch.items[1]] }, intent()), false);
  assert.equal(logic.validNativePreview({ principal_type: "GROUP", future_members_inherit: true, groups: [null] }, ["g1"]), false);
});
test("grown active groups over 100 members remain cancellable", () => {
  assert.equal(logic.canCancelGroup({ ...group, counts: { active: 120 }, native_subscription: grant }), true);
});
for (const status of [0, 503, 409, 422]) test(`uncertain admission then ${status} retains frozen body and key through actor-scoped reload`, async t => {
  const calls = [];
  const { storage } = environment(t, async (url, options) => {
    calls.push({ url, body: JSON.parse(options.body) });
    assert.equal(storage.size, 1, "saved before first network write");
    if (calls.length === 1) throw new TypeError("network lost");
    if (calls.length === 2) { if (!status) throw new TypeError("lost again"); return response({ detail: "unknown outcome" }, status); }
    return response(batch, 202);
  });
  assert.equal(typeof requests.useLifecycleAdmission, "function");
  let hook = mountHook(requests.useLifecycleAdmission, 7, "groups");
  const original = intent(); await hook.current.submit(original); hook.render(); original.body.group_ids.reverse();
  await hook.current.submit(logic.nativeIntent("user_cancel", ["different"], "IMMEDIATE")); hook.render();
  assert.ok(hook.current.pending); hook.unmount();
  hook = mountHook(requests.useLifecycleAdmission, 7, "sso");
  assert.equal(calls.length, 2, "remount never posts automatically");
  assert.equal((await hook.current.submit()).id, batch.id); hook.render();
  assert.equal(hook.current.pending, null);
  assert.deepEqual(calls, Array(3).fill({ url: "/api/group-subscriptions", body: intent().body })); hook.unmount();
});
for (const [status, message, discarded] of [[422, "invalid", true], [409, "分组已有原生订阅或待核对任务", true], [409, "重复请求标识与原批次内容不符", false], [409, "unknown conflict", false], [503, "unavailable", false]]) test(`initial ${status} ${message} ${discarded ? "permits correction" : "stays frozen"}`, async t => {
  environment(t, async () => response({ detail: message }, status));
  const hook = mountHook(requests.useLifecycleAdmission, 7, "groups");
  await hook.current.submit(intent()); hook.render(); assert.equal(hook.current.pending === null, discarded); hook.unmount();
});
test("paid admission serializes double submit and stale actor/scope responses cannot update the UI", async t => {
  const replies = [];
  environment(t, () => new Promise(resolve => replies.push(resolve)));
  const hook = mountHook(requests.useLifecycleAdmission, 7, "groups");
  const old = hook.current.submit(intent());
  assert.equal(await hook.current.submit(intent()), null);
  hook.render(8, "groups"); assert.equal(hook.current.pending, null);
  replies[0](response(batch, 202)); assert.equal(await old, null); hook.render(); assert.equal(hook.current.busy, false);
  const late = hook.current.submit(intent()); hook.unmount(); replies[1](response(batch, 202)); await late;
  assert.equal(hook.updatesAfterUnmount, 0);
});
test("an old response cannot clear a reopened panel's retry snapshot", async t => {
  const replies = [];
  const { storage } = environment(t, () => new Promise(resolve => replies.push(resolve)));
  const first = mountHook(requests.useLifecycleAdmission, 7, "groups");
  const original = first.current.submit(intent()); first.unmount();
  const next = mountHook(requests.useLifecycleAdmission, 7, "groups");
  const retry = next.current.submit();
  replies[0](response(batch, 202)); await original;
  assert.equal(storage.size, 1);
  replies[1](response(batch, 202)); await retry; assert.equal(storage.size, 0); next.unmount();
});
test("group preview ignores actor/selection changes and is never used by cancellation", async t => {
  const replies = [], calls = [];
  environment(t, (url, options) => { calls.push({ url, options }); return new Promise(resolve => replies.push(resolve)); });
  const hook = mountHook(requests.useNativePreview, 7, ["g1"], false);
  assert.equal(calls.length, 0);
  hook.render(7, ["g1"], true); assert.equal(calls.length, 1);
  hook.render(8, ["g2"], true);
  replies[0](response({ principal_type: "GROUP", future_members_inherit: true, member_count: 0, groups: [{ ...group, member_ids: [], member_count: 0, policy_revision: 1 }] }));
  await settle(); hook.render(); assert.equal(hook.current.data, null);
  hook.unmount(); replies[1](response({})); await settle(); assert.equal(hook.updatesAfterUnmount, 0);
});
test("group directory reads ignore stale filter and actor responses", async t => {
  const { useRemote } = await loadSource("groupRequests");
  const replies = [];
  environment(t, () => new Promise(resolve => replies.push(resolve)));
  const hook = mountHook(useRemote, "/groups?q=first", 0, 7);
  hook.render("/groups?q=second", 0, 7);
  replies[0](response([group])); await settle(); hook.render(); assert.equal(hook.current.data, null);
  replies[1](response([{ ...group, id: "new" }])); await settle(); hook.render(); assert.equal(hook.current.data[0].id, "new");
  hook.render("/groups?q=second", 0, 8); assert.equal(hook.current.data, null);
  hook.unmount(); replies[2](response([group])); await settle(); assert.equal(hook.updatesAfterUnmount, 0);
});
test("native recovery sends no write body, individual recovery keeps username, and stale replies cannot refresh a new scope", async t => {
  const replies = [], calls = [];
  environment(t, (url, options) => { calls.push({ url, body: options.body && JSON.parse(options.body) }); return new Promise(resolve => replies.push(resolve)); });
  assert.equal(typeof requests.useLifecycleRecheck, "function");
  const hook = mountHook(requests.useLifecycleRecheck, 7, "g1");
  const work = hook.current.submit(batch.items[1]);
  assert.equal(await hook.current.submit(batch.items[1]), false);
  assert.deepEqual(calls[0], { url: "/api/group-subscriptions/op2/recheck", body: undefined });
  hook.render(8, "g2"); replies[0](response({ id: "op2" }, 202)); assert.equal(await work, false); hook.render();
  const userWork = hook.current.submit({ ...batch.items[1], id: "r1", name: "user-one", principal_type: "USER" });
  assert.deepEqual(calls[1], { url: "/api/subscriptions/r1/operations/op2/retry", body: { confirm_username: "user-one" } });
  hook.unmount(); replies[1](response({ id: "op2" }, 202)); assert.equal(await userWork, false); assert.equal(hook.updatesAfterUnmount, 0);
});
for (const kind of ["group_cancel", "user_cancel"]) test(`${kind} preserves selected IDs and cancellation mode after lost response`, async t => {
  const calls = [], original = logic.nativeIntent(kind, ["b", "a"], "END_OF_PERIOD");
  const result = { ...batch, kind, items: batch.items.map((item, index) => ({ ...item, id: ["b", "a"][index], principal_type: kind === "user_cancel" ? "USER" : "GROUP" })) };
  environment(t, async (url, options) => { calls.push({ url, body: JSON.parse(options.body) }); if (calls.length === 1) throw new TypeError("lost"); return response(result, 202); });
  const hook = mountHook(requests.useLifecycleAdmission, 7, "cancel");
  await hook.current.submit(original); hook.render();
  assert.equal((await hook.current.submit(logic.nativeIntent(kind, ["other"], "IMMEDIATE"))).id, result.id);
  assert.deepEqual(calls, Array(2).fill({ url: `/api${logic.lifecycleEndpoint(kind)}`, body: original.body })); hook.unmount();
});

const confirmedRejections = [
  [404, "套餐不存在或已停用", "group_subscribe"],
  [404, "分组不存在", "group_subscribe"],
  [404, "SSO 用户记录不存在", "user_cancel"],
  [403, "无权使用该 AWS 账号", "group_subscribe"],
  [403, "AWS 账号已停用、删除或未绑定；请管理员恢复、启用并绑定后再操作", "user_cancel"],
  [409, "成员已有 USER 或其他 GROUP 订阅，不能重复开通", "group_subscribe"],
  [409, "成员订阅来源或套餐与管理分组不一致，需要核对", "group_cancel"],
];
function acceptedBatch(kind, ids) {
  return { ...batch, kind, total: ids.length, states: { queued: 0, running: 0, completed: ids.length, failed: 0, needs_review: 0 },
    items: ids.map(id => ({ ...batch.items[0], id, principal_type: kind === "user_cancel" ? "USER" : "GROUP" })) };
}
for (const [status, message, kind] of confirmedRejections) {
  test(`first confirmed ${status} ${message} permits a corrected request after reload`, async t => {
    const calls = [];
    const { storage } = environment(t, async (_url, options) => {
      const body = JSON.parse(options.body); calls.push(body);
      return calls.length === 1 ? response({ detail: message }, status) : response(acceptedBatch(kind, body.group_ids || body.record_ids), 202);
    });
    let hook = mountHook(requests.useLifecycleAdmission, 7, "initial-scope");
    const original = logic.nativeIntent(kind, ["stale-record"], kind === "group_subscribe" ? 3 : "IMMEDIATE");
    await hook.current.submit(original); hook.render();
    assert.equal(hook.current.pending, null); assert.equal(hook.current.error, message); assert.equal(storage.size, 0); hook.unmount();
    hook = mountHook(requests.useLifecycleAdmission, 7, "corrected-scope");
    assert.equal(calls.length, 1, "remount never posts automatically"); assert.equal(hook.current.pending, null);
    const corrected = logic.nativeIntent(kind, ["valid-record"], kind === "group_subscribe" ? 1 : "END_OF_PERIOD");
    assert.equal((await hook.current.submit(corrected)).id, batch.id);
    assert.deepEqual(calls, [original.body, corrected.body]); assert.notEqual(calls[0].request_key, calls[1].request_key); hook.unmount();
  });
  test(`previously uncertain request stays frozen after ${status} ${message}`, async t => {
    const calls = [];
    const { storage } = environment(t, async (url, options) => {
      const body = JSON.parse(options.body); calls.push({ url, body });
      if (calls.length === 1) throw new TypeError("accepted response was lost");
      if (calls.length === 2) return response({ detail: message }, status);
      return response(acceptedBatch(kind, body.group_ids || body.record_ids), 202);
    });
    const original = logic.nativeIntent(kind, ["original-first", "original-second"], kind === "group_subscribe" ? 3 : "IMMEDIATE");
    let hook = mountHook(requests.useLifecycleAdmission, 7, "first-scope");
    await hook.current.submit(original); hook.unmount();
    hook = mountHook(requests.useLifecycleAdmission, 7, "other-scope");
    await hook.current.submit(logic.nativeIntent(kind, ["different"], kind === "group_subscribe" ? 1 : "END_OF_PERIOD")); hook.render();
    assert.deepEqual(hook.current.pending, original); assert.equal(storage.size, 1); hook.unmount();
    hook = mountHook(requests.useLifecycleAdmission, 7, "last-scope");
    assert.equal(calls.length, 2); await hook.current.submit(); hook.render();
    assert.deepEqual(calls, Array(3).fill({ url: `/api${logic.lifecycleEndpoint(kind)}`, body: original.body }));
    assert.equal(hook.current.pending, null); assert.equal(storage.size, 0); hook.unmount();
  });
}
test("recognized rejection text requires its exact status code", () => {
  for (const [status, message] of confirmedRejections) {
    for (const wrongStatus of [401, 403, 404, 409, 503].filter(value => value !== status))
      assert.equal(logic.definiteLifecycleRejection(new ApiError(message, wrongStatus)), false, `${wrongStatus}: ${message}`);
  }
});
test("unknown, middleware, session, CSRF and body-mismatch responses remain frozen", async t => {
  let rejection;
  environment(t, async () => response({ detail: rejection[1] }, rejection[0]));
  for (const [index, value] of [
    [403, "unknown permission failure"], [404, "Not Found"], [409, "unknown conflict"],
    [401, "登录已过期，请重新登录"], [403, "请求校验失败，请刷新页面"], [403, "请先修改初始密码"],
    [409, "重复请求标识与原批次内容不符"],
  ].entries()) {
    rejection = value;
    const hook = mountHook(requests.useLifecycleAdmission, 70 + index, "groups");
    const original = intent(); await hook.current.submit(original); hook.render();
    assert.deepEqual(hook.current.pending, original, `${value[0]}: ${value[1]}`); hook.unmount();
  }
});
