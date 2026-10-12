import test from "node:test";
import assert from "node:assert/strict";
import { mountHook, settle } from "./hooks.mjs";
import { loadSource } from "./load-source.mjs";
import { response, record, change, options, intent, environment } from "./plan-change-fixtures.mjs";
const requests = await loadSource("planChangeRequests");
function admission(...args) { assert.equal(typeof requests.usePlanChangeAdmission, "function", "plan change admission hook exists"); return mountHook(requests.usePlanChangeAdmission, ...args); }

for (const status of [400, 401, 403, 409, 422, 429]) test(`an initial definite ${status} rejection permits editing and a new request`, async t => {
  const calls = [];
  const env = environment(t, async (_url, request) => { calls.push(JSON.parse(request.body)); return calls.length === 1 ? response({ detail: "拒绝原因" }, status) : response(change, 202); });
  const hook = admission(7, record.id);
  assert.equal(await hook.current.submit(intent()), null); hook.render();
  assert.equal(hook.current.pending, null); assert.match(hook.current.error, /拒绝原因/);
  assert.equal(env.storage.size, 0);
  assert.equal((await hook.current.submit(intent("request-key-00000002"))).id, change.id);
  assert.notEqual(calls[0].request_key, calls[1].request_key);
  if (status === 401) assert.deepEqual(env.events, ["session-expired"]);
  hook.unmount();
});

for (const status of [0, 401, 403, 409, 503, 200]) test(`ambiguous first result then ${status} preserves the exact request across retry and reload`, async t => {
  const calls = [];
  const { storage } = environment(t, async (url, request) => {
    calls.push({ url, body: JSON.parse(request.body) });
    assert.equal(storage.size, 1, "intent was saved before fetch");
    if (calls.length === 1) throw new TypeError("网络连接中断");
    if (calls.length === 2) { if (!status) throw new TypeError("仍然断开"); return response({ detail: "结果待确认" }, status); }
    return response(change, 202);
  });
  let hook = admission(7, record.id);
  const original = intent();
  await hook.current.submit(original); hook.render();
  original.body.target_plan_id = 4;
  await hook.current.submit(intent("request-key-different", 4)); hook.render();
  assert.ok(hook.current.pending); assert.equal(hook.current.pending.body.target_plan_id, 3);
  hook.unmount();
  hook = admission(7, record.id);
  assert.equal(calls.length, 2, "reload never submits automatically");
  assert.equal((await hook.current.submit()).id, change.id); hook.render();
  assert.equal(hook.current.pending, null); assert.equal(storage.size, 0);
  assert.deepEqual(calls, Array(3).fill({ url: `/api/subscriptions/${record.id}/plan-changes`, body: intent().body }));
  hook.unmount();
});

for (const body of [{}, { ...change, id: "" }, { ...change, record_id: "another-record" }, { ...change, to_plan_id: 4 }]) test(`malformed success keeps admission frozen: ${JSON.stringify(body).slice(0, 65)}`, async t => {
  environment(t, async () => response(body, 202));
  const hook = admission(7, record.id);
  assert.equal(await hook.current.submit(intent()), null); hook.render();
  assert.ok(hook.current.pending); assert.match(hook.current.error, /结果.*确认/); hook.unmount();
});

test("initial server failure remains frozen and withdrawal retries retain the original endpoint/body", async t => {
  const calls = [];
  environment(t, async (url, request) => { calls.push({ url, body: JSON.parse(request.body) }); return response({ detail: "服务故障" }, 503); });
  const hook = admission(7, record.id);
  const original = { kind: "withdraw", change_id: "scheduled-a", body: { expected_current_type: "PRO_PLUS", confirm_username: record.username, request_key: "request-withdraw-0001" } };
  await hook.current.submit(original); hook.render();
  await hook.current.submit(intent()); hook.render();
  assert.deepEqual(calls, Array(2).fill({ url: `/api/subscriptions/${record.id}/plan-changes/scheduled-a/withdraw`, body: original.body }));
  assert.equal(hook.current.pending.kind, "withdraw"); hook.unmount();
});

test("double clicks are serialized and unmounted completions cannot update or navigate", async t => {
  let finish, calls = 0;
  environment(t, () => { calls++; return new Promise(resolve => { finish = resolve; }); });
  const hook = admission(7, record.id);
  const pending = hook.current.submit(intent());
  assert.equal(await hook.current.submit(intent()), null); assert.equal(calls, 1);
  hook.unmount(); finish(response(change, 202)); assert.equal(await pending, null);
  assert.equal(hook.updatesAfterUnmount, 0);
});

test("actor/record switches isolate saved intents and an old response cannot unlock a newer write", async t => {
  const replies = [];
  environment(t, () => new Promise(resolve => replies.push(resolve)));
  const hook = admission(7, record.id);
  const original = hook.current.submit(intent()); hook.render();
  hook.render(8, "record-b"); assert.equal(hook.current.pending, null);
  const next = hook.current.submit(intent("request-key-00000002")); hook.render();
  replies[0](response(change, 202)); assert.equal(await original, null); hook.render();
  assert.equal(hook.current.busy, true); assert.equal(hook.current.pending.body.request_key, "request-key-00000002");
  replies[1](response({ ...change, record_id: "record-b" }, 202)); await next; hook.render();
  assert.equal(hook.current.pending, null); hook.unmount();
});

test("read polling fences out-of-order, record-switch, actor-switch and unmounted responses", async t => {
  const replies = [];
  environment(t, url => new Promise(resolve => replies.push({ url, resolve })));
  assert.equal(typeof requests.usePlanChangeData, "function", "plan change data hook exists");
  const hook = mountHook(requests.usePlanChangeData, 7, record.id);
  const second = hook.current.refresh();
  replies[2].resolve(response(options)); replies[3].resolve(response([change])); await second; hook.render();
  assert.equal(hook.current.history[0].id, change.id);
  replies[0].resolve(response({ ...options, unavailable_reason: "stale" })); replies[1].resolve(response([])); await settle(); hook.render();
  assert.equal(hook.current.options.unavailable_reason, null);
  hook.render(7, "record-b"); assert.equal(hook.current.options, null); assert.deepEqual(hook.current.history, []);
  hook.render(8, "record-b");
  replies[4].resolve(response(options)); replies[5].resolve(response([change])); await settle(); hook.render();
  assert.equal(hook.current.options, null);
  hook.unmount(); replies[6].resolve(response(options)); replies[7].resolve(response([])); await settle();
  assert.equal(hook.updatesAfterUnmount, 0);
});

test("read failures expose loading/error and propagate 401 session expiry", async t => {
  const { events } = environment(t, async () => response({ detail: "登录已过期" }, 401));
  assert.equal(typeof requests.usePlanChangeData, "function");
  const hook = mountHook(requests.usePlanChangeData, 7, record.id);
  assert.equal(hook.current.loading, true); await settle(); hook.render();
  assert.equal(hook.current.loading, false); assert.match(hook.current.error, /登录已过期/); assert.ok(events.includes("session-expired")); hook.unmount();
});

test("a success with an invalid state or missing settlement fields remains an uncertain write", async t => {
  const bodies = [{ ...change, state: "unexpected" }, { id: change.id, record_id: record.id, to_plan_id: 3, direction: "upgrade" }];
  environment(t, async () => response(bodies.shift(), 202));
  const hook = admission(7, record.id);
  await hook.current.submit(intent()); hook.render();
  assert.ok(hook.current.pending);
  await hook.current.submit(); hook.render();
  assert.ok(hook.current.pending); hook.unmount();
});

test("recovery requests are serialized, validate the matching change, and expire sessions", async t => {
  assert.equal(typeof requests.usePlanChangeRecovery, "function");
  const calls = [], replies = [];
  const { events } = environment(t, (url, options) => { calls.push({ url, body: JSON.parse(options.body) }); return new Promise(resolve => replies.push(resolve)); });
  const hook = mountHook(requests.usePlanChangeRecovery, 7, record.id);
  const work = hook.current.submit(change.id, "recheck", { confirm_username: record.username });
  assert.equal(await hook.current.submit(change.id, "recheck", { confirm_username: record.username }), null);
  assert.equal(calls.length, 1);
  replies[0](response({ ...change, id: "another-change" }, 202));
  assert.equal(await work, null); hook.render(); assert.match(hook.current.error, /结果/);
  const again = hook.current.submit(change.id, "confirm-not-applied", { confirm_username: record.username, reason: "已核对 AWS", acknowledge_not_applied: true });
  replies[1](response({ detail: "请重新登录" }, 401)); await again; hook.render();
  assert.deepEqual(events, ["session-expired"]);
  assert.match(hook.current.error, /请重新登录/);
  assert.deepEqual(calls.map(c => c.url), [`/api/subscriptions/${record.id}/plan-changes/${change.id}/recheck`, `/api/subscriptions/${record.id}/plan-changes/${change.id}/confirm-not-applied`]);
  hook.unmount();
});

test("recovery responses are ignored after actor/record changes and unmount", async t => {
  assert.equal(typeof requests.usePlanChangeRecovery, "function");
  const replies = [];
  environment(t, () => new Promise(resolve => replies.push(resolve)));
  const hook = mountHook(requests.usePlanChangeRecovery, 7, record.id);
  const work = hook.current.submit(change.id, "recheck", { confirm_username: record.username });
  hook.render(8, "record-b");
  replies[0](response(change, 202)); assert.equal(await work, null); hook.render();
  assert.equal(hook.current.busy, false); assert.equal(hook.current.error, "");
  const late = hook.current.submit(change.id, "recheck", { confirm_username: record.username });
  hook.unmount(); replies[1](response({ ...change, record_id: "record-b" }, 202));
  assert.equal(await late, null); assert.equal(hook.updatesAfterUnmount, 0);
});

test("slow polling responses still populate the panel, and an older refresh cannot unlock a newer read", async t => {
  const replies = [];
  const { intervals } = environment(t, url => new Promise(resolve => replies.push({ url, resolve })));
  const hook = mountHook(requests.usePlanChangeData, 7, record.id);
  for (let i = 0; i < 3; i++) intervals[0]();
  assert.equal(replies.length, 2, "a running poll is not superseded by each timer tick");
  const newer = hook.current.refresh();
  replies[0].resolve(response(options)); replies[1].resolve(response([])); await settle();
  intervals[0](); assert.equal(replies.length, 4, "old completion cannot release the newer request guard");
  replies[2].resolve(response(options)); replies[3].resolve(response([change])); await newer; hook.render();
  assert.equal(hook.current.history[0].id, change.id); assert.equal(hook.current.loading, false);
  intervals[0](); assert.equal(replies.length, 6);
  hook.unmount(); replies[4].resolve(response(options)); replies[5].resolve(response([])); await settle();
  assert.equal(hook.updatesAfterUnmount, 0);
});

for (const patch of [{ write_requested_at: 12 }, { applied_at: {} }, { from_plan_name: undefined }]) test(`incomplete success data cannot clear the frozen paid intent: ${JSON.stringify(patch)}`, async t => {
  environment(t, async () => response({ ...change, ...patch }, 202));
  const hook = admission(7, record.id);
  await hook.current.submit(intent()); hook.render();
  assert.ok(hook.current.pending); hook.unmount();
});

test("an initial definite rejection unlocks persisted editing even if session expiry unmounted the panel", async t => {
  let reply;
  const { storage } = environment(t, () => new Promise(resolve => { reply = resolve; }));
  const hook = admission(7, record.id);
  const work = hook.current.submit(intent());
  hook.unmount(); reply(response({ detail: "请重新登录" }, 401)); await work;
  assert.equal(storage.size, 0);
  assert.equal(hook.updatesAfterUnmount, 0);
});

test("invalid plan option responses surface an error instead of creating unusable choices", async t => {
  environment(t, async url => response(url.endsWith("plan-options") ? { ...options, targets: [{ plan_id: 3 }] } : []));
  const hook = mountHook(requests.usePlanChangeData, 7, record.id);
  await settle(); hook.render();
  assert.equal(hook.current.options, null); assert.match(hook.current.error, /信息不完整/); assert.equal(hook.current.loading, false);
  hook.unmount();
});

for (const status of [401, 403, 409]) test(`a delayed initial ${status} cannot erase a reopened panel's ambiguous retry`, async t => {
  const calls = [], replies = [];
  const { storage, events } = environment(t, (url, request) => {
    calls.push({ url, body: JSON.parse(request.body) });
    return new Promise((resolve, reject) => replies.push({ resolve, reject }));
  });
  const first = admission(7, record.id);
  const original = first.current.submit(intent());
  first.unmount();

  const second = admission(7, record.id);
  assert.deepEqual(second.current.pending, intent());
  const retry = second.current.submit();
  replies[0].resolve(response({ detail: "原请求未受理" }, status));
  assert.equal(await original, null);
  assert.equal(storage.size, 1, "the newer retry still owns a durable recovery record");
  replies[1].reject(new TypeError("重试结果未知"));
  assert.equal(await retry, null); second.render();
  assert.deepEqual(second.current.pending, intent());
  second.unmount();

  const third = admission(7, record.id);
  assert.deepEqual(third.current.pending, intent(), "a second reopen must retain the exact frozen body and key");
  assert.deepEqual(calls, Array(2).fill({ url: `/api/subscriptions/${record.id}/plan-changes`, body: intent().body }));
  if (status === 401) assert.deepEqual(events, ["session-expired"]);
  assert.equal(first.updatesAfterUnmount, 0);
  third.unmount();
});
