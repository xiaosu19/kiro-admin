import test from "node:test";
import assert from "node:assert/strict";
import { mountHook, settle } from "./hooks.mjs";
import { loadSource } from "./load-source.mjs";

const { GroupDetails } = await loadSource("GroupDetails-test");
const { useGroupAccess } = await loadSource("groupRequests");
const { GroupMemberManager } = await loadSource("GroupMembers");
const { setCsrf } = await loadSource("api");
const response = (body, status = 200) => new Response(JSON.stringify(body), { status });
const group = { id: "g", owner_id: 2, aws_account_id: 1, name: "Legacy group", remote_id: "remote-g", state: "needs_review", active_job_id: "legacy",
  revision: 1, policy: { mode: "none", revision: 0 }, members: [], counts: { total: 0, active: 0, eligible: 0, subscribed: 0, cancelled: 0, deleted: 0 } };
const job = { id: "legacy", group_id: "g", record_id: "r", member_batch_id: null, kind: "attach", state: "needs_review", phase: "pending",
  attempts: 1, created_at: "2026-10-11T00:00:00Z", error: "uncertain membership", finished_at: null };
const props = { groupId: "g", user: { id: 2, role: "member" }, ownerName: () => "Alice", accountName: () => "AWS", busy: false, hasPending: false,
  mutate: async () => false, notify() {}, refreshVersion: 0, admission: { pending: null, busy: false }, onAccepted() {}, scope: "bound", accountIds: [1], accountsLoaded: true };
function find(node, predicate) {
  if (!node || typeof node !== "object") return null;
  if (predicate(node)) return node;
  for (const child of [node.props?.children].flat(Infinity)) { const result = find(child, predicate); if (result) return result; }
  return null;
}
const recovery = tree => find(tree, node => node.type === "button" && node.props.children === "核对并继续同一任务");
function environment(t, fetch) {
  const original = globalThis.window;
  globalThis.window = { setInterval() {}, clearInterval() {}, dispatchEvent() {} };
  t.mock.method(globalThis, "fetch", fetch); setCsrf("current-session");
  t.after(() => { if (original === undefined) delete globalThis.window; else globalThis.window = original; });
}
function mountDetail(extra = {}) {
  return mountHook((input = extra) => {
    const access = useGroupAccess(input.user?.id || 2, input.scope || "bound");
    return GroupDetails({ ...props, ...input, access });
  });
}
async function loaded(hook) { await settle(); hook.render(); }

for (const kind of ["attach", "detach"]) {
  for (const state of ["failed", "needs_review"]) {
    test(`legacy ${kind} ${state} shows same-job recovery without a MemberBatch`, async t => {
      const current = { ...job, kind, state, phase: state === "failed" ? "ready" : "pending" }, calls = [];
      environment(t, async (url, options) => {
        calls.push({ url, options });
        if (options.method === "POST") { current.state = "queued"; return response(current, 202); }
        return response(url.endsWith("/jobs") ? [current] : url.endsWith("/member-batches") ? [] : { ...group, state: current.state === "queued" ? "updating" : state });
      });
      const hook = mountDetail(); await loaded(hook);
      assert.equal(find(hook.current, node => node.type === GroupMemberManager).props.blocked, true);
      const button = recovery(hook.current); assert.ok(button, "legacy members must not lose their only recovery control");
      const first = button.props.onClick(), duplicate = button.props.onClick();
      await Promise.all([first, duplicate]); hook.render();
      const posts = calls.filter(call => call.options.method === "POST");
      assert.equal(posts.length, 1); assert.equal(posts[0].url, "/api/groups/g/retry");
      assert.equal(posts[0].options.body, undefined); assert.equal(posts[0].options.cache, "no-store");
      assert.equal(recovery(hook.current), null); hook.unmount();
    });
  }
}

test("batch children and actor-hidden jobs keep legacy retry unavailable", async t => {
  let jobs = [{ ...job, member_batch_id: "private-batch" }];
  environment(t, async url => response(url.endsWith("/jobs") ? jobs : group));
  const hook = mountDetail(); await loaded(hook); assert.equal(recovery(hook.current), null);
  jobs = []; hook.render({ scope: "new-scope" }); await loaded(hook); assert.equal(recovery(hook.current), null); hook.unmount();
});

for (const status of [403, 404]) {
  test(`legacy recovery ${status} hides the detail and fences the previously rendered retry`, async t => {
    const calls = [];
    environment(t, async (url, options) => {
      calls.push({ url, options });
      return options.method === "POST" ? response({ detail: "scope withdrawn" }, status) : response(url.endsWith("/jobs") ? [job] : group);
    });
    const hook = mountDetail(); await loaded(hook);
    const button = recovery(hook.current); assert.ok(button);
    await button.props.onClick(); await button.props.onClick();
    assert.equal(calls.filter(call => call.options.method === "POST").length, 1);
    hook.render(); assert.equal(recovery(hook.current), null);
    assert.equal(find(hook.current, node => node.type === GroupMemberManager), null); hook.unmount();
  });
}

for (const changed of ["actor", "session"]) {
  test(`legacy recovery ignores a queued response from the previous ${changed}`, async t => {
    let finish, notified = 0;
    const calls = [];
    environment(t, (url, options) => {
      calls.push({ url, options });
      return options.method === "POST" ? new Promise(resolve => { finish = resolve; }) : Promise.resolve(response(url.endsWith("/jobs") ? [job] : group));
    });
    const hook = mountDetail({ notify() { notified++; } }); await loaded(hook);
    const button = recovery(hook.current), sent = button.props.onClick();
    if (changed === "actor") { hook.render({ user: { id: 3, role: "admin" }, scope: "new-actor", notify() { notified++; } }); await loaded(hook); }
    else setCsrf("new-session");
    const count = calls.length;
    finish(response({ ...job, state: "queued" }, 202)); await sent;
    assert.equal(calls.length, count, "old success must not refresh the new scope"); assert.equal(notified, 0);
    if (changed === "actor") { await button.props.onClick(); assert.equal(calls.length, count); }
    hook.unmount();
  });
}

test("stopped unsent group offers explicit local deletion without creation recovery", async t => {
  const stopped = { ...group, state: "failed", remote_id: null, active_job_id: null };
  const cancelled = { ...job, kind: "create", state: "cancelled", phase: "ready", record_id: null };
  environment(t, async url => response(url.endsWith("/jobs") ? [cancelled] : stopped));
  const hook = mountDetail(); await loaded(hook);
  const deletion = find(hook.current, node => node.type === "button" && node.props.children === "删除空分组");
  assert.equal(deletion.props.disabled, false);
  assert.equal(find(hook.current, node => node.type === "button" && node.props.children === "重命名").props.disabled, true);
  assert.equal(recovery(hook.current), null);
  assert.ok(find(hook.current, node => node.type === "td" && node.props.children === "已停止"));
  deletion.props.onClick(); hook.render();
  assert.ok(find(hook.current, node => node.type === "input" && node.props.name === "confirm_name"));
  hook.unmount();
});

for (const change of ["remote", "pending", "active_job", "hidden_job", "pending_intent"]) {
  test(`local cleanup remains disabled for ${change}`, async t => {
    const stopped = { ...group, state: "failed", remote_id: change === "remote" ? "remote-g" : null,
      active_job_id: change === "active_job" ? "other-job" : null };
    const cancelled = { ...job, kind: "create", state: "cancelled", phase: change === "pending" ? "pending" : "ready", record_id: null };
    environment(t, async url => response(url.endsWith("/jobs") ? (change === "hidden_job" ? [] : [cancelled]) : stopped));
    const hook = mountDetail({ hasPending: change === "pending_intent" }); await loaded(hook);
    assert.equal(find(hook.current, node => node.type === "button" && node.props.children === "删除空分组").props.disabled, true);
    assert.equal(recovery(hook.current), null); hook.unmount();
  });
}
