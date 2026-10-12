import test from "node:test";
import assert from "node:assert/strict";
import { mountHook, settle } from "./hooks.mjs";
import { loadSource } from "./load-source.mjs";

const { useRemote, useGroupSubscription } = await loadSource("groupRequests");
const { subscriptionRequest } = await loadSource("groupsLogic");
const response = (body, status = 200) => new Response(JSON.stringify(body), { status });

function environment(t, fetch) {
  const savedWindow = globalThis.window, savedStorage = globalThis.sessionStorage;
  const storage = new Map();
  globalThis.window = { setInterval() {}, clearInterval() {}, dispatchEvent() {} };
  globalThis.sessionStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
    removeItem: key => storage.delete(key),
  };
  t.mock.method(globalThis, "fetch", fetch);
  t.after(() => {
    if (savedWindow === undefined) delete globalThis.window;
    else globalThis.window = savedWindow;
    if (savedStorage === undefined) delete globalThis.sessionStorage;
    else globalThis.sessionStorage = savedStorage;
  });
  return storage;
}

const body = subscriptionRequest(["member-a", "member-b"], 2, { mode: "none" }, "group-a");
for (const [status, message] of [
  [401, "请重新登录"], [403, "无权使用该 AWS 账号"], [429, "稍后重试"],
  [409, "未知冲突"], [409, "重复请求标识与原批次内容不同"], [503, "服务暂时不可用"],
  [0, "再次断网"], [200, "结果未包含已受理的批次"],
]) {
  test(`paid recovery keeps the exact admitted request through ${status} ${message} and a login remount`, async t => {
    const calls = [], committed = new Map();
    const storage = environment(t, async (url, options) => {
      assert.equal(url, "/api/batches/subscribe");
      const sent = JSON.parse(options.body);
      calls.push(sent);
      if (calls.length === 2) {
        if (!status) throw new TypeError(message);
        return response({ detail: message }, status);
      }
      if (!committed.has(sent.request_key)) committed.set(sent.request_key, { id: "original-batch" });
      if (calls.length === 1) throw new TypeError("success response lost after commit");
      return response(committed.get(sent.request_key));
    });
    let hook = mountHook(useGroupSubscription, 7, "group-a");
    assert.equal((await hook.current.submit(body)).state, "unresolved");
    hook.render();
    assert.deepEqual(hook.current.pending.body, body);
    assert.equal((await hook.current.submit()).state, "unresolved");
    hook.render();
    assert.deepEqual(hook.current.pending.body, body);
    const originalIntent = structuredClone(hook.current.pending);
    hook.unmount();

    const otherActor = mountHook(useGroupSubscription, 8, "group-a");
    const otherGroup = mountHook(useGroupSubscription, 7, "group-b");
    assert.equal(otherActor.current.pending, null);
    assert.equal(otherGroup.current.pending, null);
    otherActor.unmount();
    otherGroup.unmount();
    hook = mountHook(useGroupSubscription, 7, "group-a");
    assert.deepEqual(hook.current.pending, originalIntent);
    assert.equal(calls.length, 2, "remount must not automatically replay a paid request");
    // Even if a stale form supplies another selection, pending recovery wins.
    const result = await hook.current.submit(subscriptionRequest(["other-member"], 3));
    hook.render();
    assert.equal(result.state, "accepted");
    assert.equal(result.result.id, "original-batch");
    assert.equal(hook.current.pending, null);
    assert.equal(storage.size, 0);
    assert.deepEqual(calls, [calls[0], calls[0], calls[0]]);
    assert.equal(committed.size, 1);
    hook.unmount();
  });
}

test("subscription recovery releases only definite non-admission and can submit a revised selection", async t => {
  let attempt = 0, rejection = [422, "停止日期已过"];
  const calls = [];
  const storage = environment(t, async (_url, options) => {
    calls.push(JSON.parse(options.body));
    if (++attempt % 3 === 1) throw new TypeError("request lost before admission");
    if (attempt % 3 === 2) return response({ detail: rejection[1] }, rejection[0]);
    return response({ id: "revised-batch" });
  });
  for (rejection of [[400, "无效的请求"], [422, "停止日期已过"], [409, "选择的 SSO 用户已不属于该分组"], [409, "SSO 用户刚发生变化，请刷新后重新选择"]]) {
    const hook = mountHook(useGroupSubscription, 7, "group-a");
    assert.equal((await hook.current.submit(body)).state, "unresolved");
    hook.render();
    assert.equal((await hook.current.submit()).state, "rejected");
    hook.render();
    assert.equal(hook.current.pending, null);
    assert.equal(storage.size, 0);
    const revised = subscriptionRequest(["different-member"], 3, undefined, "group-a");
    assert.equal((await hook.current.submit(revised)).state, "accepted");
    hook.render();
    assert.equal(hook.current.pending, null);
    assert.equal(storage.size, 0);
    assert.deepEqual(calls.at(-3), calls.at(-2));
    assert.notEqual(calls.at(-1).request_key, calls.at(-2).request_key);
    assert.deepEqual(calls.at(-1).record_ids, revised.record_ids);
    hook.unmount();
  }
});

test("useRemote applies the latest response when real refreshes resolve out of order", async t => {
  const requests = [];
  environment(t, url => new Promise(resolve => requests.push({ url, resolve })));
  const hook = mountHook(useRemote, "/groups/group-a");
  const latest = hook.current.refresh();
  assert.equal(requests.length, 2);
  requests[1].resolve(response({ revision: 2 }));
  await latest;
  hook.render();
  assert.deepEqual(hook.current.data, { revision: 2 });
  requests[0].resolve(response({ revision: 1 }));
  await settle();
  hook.render();
  assert.deepEqual(hook.current.data, { revision: 2 });
  assert.equal(hook.current.error, "");
  hook.unmount();
});

test("useRemote ignores stale errors, path callbacks and responses after unmount", async t => {
  const requests = [];
  environment(t, url => new Promise(resolve => requests.push({ url, resolve })));
  const hook = mountHook(useRemote, "/groups/group-a");
  const oldRefresh = hook.current.refresh;
  const latest = oldRefresh();
  requests[1].resolve(response({ revision: 2 }));
  await latest;
  requests[0].resolve(response({ detail: "old request failed" }, 503));
  await settle();
  hook.render();
  assert.equal(hook.current.error, "");

  const oldInFlight = hook.current.refresh();
  hook.render("/groups/group-b");
  assert.equal(hook.current.data, null);
  const ignored = oldRefresh();
  assert.equal(requests.length, 4, "a callback from the previous path must not start a new request");
  await ignored;
  requests[2].resolve(response({ revision: 3 }));
  await oldInFlight;
  hook.render();
  assert.equal(hook.current.data, null);
  assert.equal(hook.current.loading, true);
  requests[3].resolve(response({ revision: 9 }));
  await settle();
  hook.render();
  assert.deepEqual(hook.current.data, { revision: 9 });

  const finalRefresh = hook.current.refresh;
  const pending = finalRefresh();
  hook.unmount();
  requests[4].resolve(response({ revision: 10 }));
  await pending;
  assert.equal(hook.updatesAfterUnmount, 0);
  const afterUnmount = finalRefresh();
  assert.equal(requests.length, 5);
  await afterUnmount;
});

test("useRemote keeps applying four-second responses with a three-second poll interval", async t => {
  const requests = [], applied = [];
  let now = 0, tick;
  environment(t, () => new Promise(resolve => requests.push({ resolve, readyAt: now + 4000, revision: requests.length + 1 })));
  window.setInterval = (callback, delay) => {
    assert.equal(delay, 3000);
    tick = callback;
    return 1;
  };
  const hook = mountHook(useRemote, "/groups/group-a", 3000);
  for (now = 1000; now <= 28000; now += 1000) {
    if (now % 3000 === 0) tick();
    for (const request of requests.filter(request => request.readyAt === now))
      request.resolve(response({ revision: request.revision }));
    await settle();
    hook.render();
    const revision = hook.current.data?.revision;
    if (revision && revision !== applied.at(-1)) applied.push(revision);
  }
  assert.deepEqual(applied, [1, 2, 3, 4, 5]);
  assert.equal(requests.length, 5);
  assert.equal(hook.current.loading, false);
  assert.equal(hook.current.error, "");
  hook.unmount();
});

test("an older explicit refresh cannot release the polling guard for a newer request", async t => {
  const requests = [];
  let tick;
  environment(t, () => new Promise(resolve => requests.push({ resolve })));
  window.setInterval = callback => { tick = callback; return 1; };
  const hook = mountHook(useRemote, "/groups/group-a", 3000);
  const older = hook.current.refresh();
  const newer = hook.current.refresh();
  assert.equal(requests.length, 3, "manual refresh still supersedes in-flight reads");
  requests[1].resolve(response({ revision: 2 }));
  await older;
  tick();
  assert.equal(requests.length, 3);
  requests[0].resolve(response({ revision: 1 }));
  await settle();
  tick();
  assert.equal(requests.length, 3);
  requests[2].resolve(response({ revision: 3 }));
  await newer;
  hook.render();
  assert.deepEqual(hook.current.data, { revision: 3 });
  tick();
  assert.equal(requests.length, 4, "polling resumes after the current request settles");
  requests[3].resolve(response({ detail: "temporarily unavailable" }, 503));
  await settle();
  tick();
  assert.equal(requests.length, 5, "a failed current read also releases polling");
  hook.unmount();
});
