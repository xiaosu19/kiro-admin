import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
import { mountHook, settle } from "./hooks.mjs";
import { environment, response } from "./plan-change-fixtures.mjs";
const { LifecycleHistory, LifecycleBatchView } = await loadSource("NativeSubscriptions");
function find(node, predicate) {
  if (!node || typeof node !== "object") return null;
  if (Array.isArray(node)) { for (const child of node) { const found = find(child, predicate); if (found) return found; } return null; }
  return predicate(node) ? node : find(node.props?.children, predicate);
}
function batch(id, ids, kind = "group_subscribe") {
  return { id, kind, created_at: "2026-10-10T00:00:00", total: ids.length,
    states: { queued: 0, running: 0, completed: 0, failed: 0, needs_review: ids.length },
    items: ids.map(id => ({ id, name: `Team ${id}`, principal_type: kind === "user_cancel" ? "USER" : "GROUP", operation_id: `op-${id}`, state: "needs_review", phase: "pending", error: "AWS response lost" })) };
}
const a = batch("batch-a", ["group-a"]), b = batch("batch-b", ["group-b"]);
const view = host => find(host.current, node => node.type === LifecycleBatchView);
const button = (host, id) => find(host.current, node => node.type === "button" && node.key === id);

for (const initialBatch of [a, batch("user-batch", ["group-b"], "user_cancel")]) test(`group history excludes unrelated initial ${initialBatch.id} and its recovery actions`, async t => {
  const calls = [];
  environment(t, async url => { calls.push(url); return response(url === "/api/lifecycle-batches" ? [initialBatch] : initialBatch); });
  const host = mountHook(LifecycleHistory, { actorId: 7, groupId: "group-b", initialBatch });
  assert.equal(view(host), null);
  await settle(); host.render();
  assert.equal(view(host), null); assert.equal(button(host, initialBatch.id), null);
  assert.ok(find(host.current, node => node.type === "p" && node.props.children === "暂无订阅批次。"));
  assert.ok(calls.every(url => url === "/api/lifecycle-batches"), "unrelated initial batches are never polled");
  host.unmount();
});

test("navigation from group A to B resets the opened batch and ignores a delayed A detail", async t => {
  const details = [];
  environment(t, url => url === "/api/lifecycle-batches" ? Promise.resolve(response([a, b])) : new Promise(resolve => details.push({ url, resolve })));
  const host = mountHook(LifecycleHistory, { actorId: 7, groupId: "group-a", initialBatch: a });
  assert.equal(view(host).props.batch.id, a.id); await settle(); host.render();
  host.render({ actorId: 7, groupId: "group-b", initialBatch: a });
  assert.equal(view(host), null); await settle(); host.render();
  assert.equal(button(host, a.id), null); button(host, b.id).props.onClick(); host.render();
  details.find(item => item.url.endsWith(b.id)).resolve(response(b)); await settle(); host.render();
  assert.equal(view(host).props.batch.id, b.id);
  details.find(item => item.url.endsWith(a.id)).resolve(response(a)); await settle(); host.render();
  assert.equal(view(host).props.batch.id, b.id); assert.deepEqual(view(host).props.batch.items.map(item => item.id), ["group-b"]);
  host.unmount();
});

for (const detail of [a, batch("wrong-batch-id", ["group-b"])]) test(`loaded detail ${detail.id} cannot replace the selected group B batch`, async t => {
  environment(t, async url => response(url === "/api/lifecycle-batches" ? [a, b] : detail));
  const host = mountHook(LifecycleHistory, { actorId: 7, groupId: "group-b", initialBatch: b });
  await settle(); host.render();
  assert.equal(view(host).props.batch.id, b.id); assert.deepEqual(view(host).props.batch.items.map(item => item.id), ["group-b"]);
  host.unmount();
});

test("multi-group batches remain complete for every included group and global history retains USER batches", async t => {
  const multi = batch("multi", ["group-a", "group-b"]), user = batch("user", ["record-one"], "user_cancel");
  environment(t, async url => response(url === "/api/lifecycle-batches" ? [multi, user] : url.endsWith(user.id) ? user : multi));
  const host = mountHook(LifecycleHistory, { actorId: 7, groupId: "group-a", initialBatch: multi });
  await settle(); host.render(); assert.deepEqual(view(host).props.batch.items, multi.items);
  host.render({ actorId: 7, groupId: "group-b", initialBatch: multi });
  await settle(); host.render(); assert.deepEqual(view(host).props.batch.items, multi.items); assert.equal(button(host, user.id), null);
  host.render({ actorId: 7, initialBatch: multi });
  await settle(); host.render(); assert.ok(button(host, multi.id)); assert.ok(button(host, user.id));
  button(host, user.id).props.onClick(); host.render(); await settle(); host.render();
  assert.equal(view(host).props.batch.id, user.id); host.unmount();
});

test("actor change clears an opened batch and delayed detail cannot restore the prior actor's recovery actions", async t => {
  let actor = 7;
  const details = [];
  environment(t, url => url === "/api/lifecycle-batches" ? Promise.resolve(response(actor === 7 ? [a] : [])) : new Promise(resolve => details.push({ url, resolve })));
  const host = mountHook(LifecycleHistory, { actorId: 7, groupId: "group-a" });
  await settle(); host.render(); button(host, a.id).props.onClick(); host.render();
  assert.equal(view(host).props.batch.id, a.id);
  actor = 8; host.render({ actorId: 8, groupId: "group-a" });
  assert.equal(view(host), null); assert.equal(details.length, 1, "the new actor does not poll the old actor's selected batch");
  details[0].resolve(response(a)); await settle(); host.render();
  assert.equal(view(host), null); assert.equal(button(host, a.id), null); host.unmount();
});
