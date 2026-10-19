import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
import { mountHook, settle } from "./hooks.mjs";
import { environment, response } from "./plan-change-fixtures.mjs";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";

const { useLifecycleStop } = await loadSource("nativeSubscriptionRequests");
const { LifecycleBatchView } = await loadSource("NativeSubscriptions");
const { canCancelGroup, canCancelRecord, canSubscribeGroup, validLifecycleBatch } = await loadSource("nativeSubscriptionsLogic");
const { canUseAuthRecord } = await loadSource("authLogic");
const item = { id: "r1", name: "User 1", principal_type: "USER", operation_id: "op1", state: "queued", phase: "ready", error: null };
const batch = { id: "b1", kind: "user_cancel", created_at: "2026-10-19T00:00:00", total: 1, can_stop: true, stop_requested: false,
  states: { queued: 1, running: 0, completed: 0, failed: 0, needs_review: 0, cancelled: 0 }, items: [item] };
const stopped = { ...batch, can_stop: false, stop_requested: true, states: { ...batch.states, queued: 0, cancelled: 1 },
  items: [{ ...item, state: "cancelled", phase: "done", error: "本项未发送到 AWS" }] };

test("batch stop is explicit, persists terminal items and explains in-flight writes", () => {
  const html = renderToStaticMarkup(h(LifecycleBatchView, { batch, busy: false, onRecheck() {}, onStop() {} }));
  assert.match(html, /关闭批量取消订阅/);
  assert.match(html, /已发送的请求继续核对结果/);
  assert.match(html, /已取消的订阅不会重新开通/);
  const done = renderToStaticMarkup(h(LifecycleBatchView, { batch: stopped, busy: false, onRecheck() {}, onStop() {} }));
  assert.doesNotMatch(done, /<button[^>]*>关闭批量取消订阅/);
  assert.match(done, /已停止/);
  assert.equal(validLifecycleBatch(stopped), true);
});

test("stop sends only the selected batch and cannot double-submit", async t => {
  let resolve; const calls = [];
  environment(t, (url, options) => { calls.push([url, options.method]); return new Promise(r => { resolve = r; }); });
  const host = mountHook(useLifecycleStop, 7, "b1");
  assert.equal(calls.length, 0);
  const pending = host.current.stop(batch); await settle(); host.render();
  assert.equal(await host.current.stop(batch), false);
  assert.deepEqual(calls, [["/api/lifecycle-batches/b1/stop", "POST"]]);
  resolve(response(stopped)); assert.equal(await pending, true);
  host.render(); assert.equal(host.current.busy, false); host.unmount();
});

test("a delayed stop result cannot affect another actor or batch", async t => {
  let resolve;
  environment(t, () => new Promise(r => { resolve = r; }));
  const host = mountHook(useLifecycleStop, 7, "b1");
  const pending = host.current.stop(batch); await settle();
  host.render(8, "b2"); host.render(7, "b1"); resolve(response(stopped));
  assert.equal(await pending, false); host.render();
  assert.equal(host.current.busy, false); assert.equal(host.current.error, ""); host.unmount();
});

test("deleted account history cannot be selected for new paid or auth operations", () => {
  const g = { state: "ready", account_deleted_at: "2026-10-19", native_subscription: { state: "active" } };
  assert.equal(canCancelGroup(g), false);
  assert.equal(canSubscribeGroup({ ...g, native_subscription: null }), false);
  const r = { owner_id: 7, account_deleted_at: "2026-10-19", sso_user_id: "sso", state: "completed", subscription_status: "active", has_password: true };
  assert.equal(canCancelRecord(r), false);
  assert.equal(canUseAuthRecord(r, { id: 7 }, "json_export"), false);
});
