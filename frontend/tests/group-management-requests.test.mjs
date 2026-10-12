import test from "node:test";
import assert from "node:assert/strict";
import { mountHook, settle } from "./hooks.mjs";
import { loadSource } from "./load-source.mjs";

const observation = await loadSource("groupObservationRequests");
const members = await loadSource("groupMemberRequests");
const logic = await loadSource("groupMemberLogic");
const ui = await loadSource("GroupMembers");
const { useRemote, useGroupAccess } = await loadSource("groupRequests");
const { setCsrf, groupRequest } = await loadSource("api");
const response = (body, status = 200) => new Response(JSON.stringify(body), { status });
const group = (id = "g") => ({ id, owner_id: 2, aws_account_id: 1, revision: 1, state: "ready", remote_id: id });
const live = id => ({ group_id: id, aws_account_id: 1, remote_id: id, queried_at: "2026-10-11T00:00:00Z",
  directory: { exists: true, name: "Actual " + id, member_count: 0, owned_members: [] },
  subscription: { status: "Subscribed", subscription_type: "KIRO_ENTERPRISE_PRO", plan_label: "Kiro Pro", pending_subscription_type: null,
    pending_plan_label: null, effective_at: null, cancellation_expires_at: null, access_active: true } });
const summary = body => ({ id: "batch", group_id: "g", owner_id: 2, actor_id: 2, ...body, state: "queued", active_job_id: "job",
  stop_requested_at: null, error: null, counts: { total: body.record_ids.length, waiting: body.record_ids.length - 1, queued: 1, running: 0, completed: 0, failed: 0, needs_review: 0, stopped: 0 },
  actions: { recheck: false, retry: false, stop: true }, created_at: "2026-10-11", updated_at: "2026-10-11", finished_at: null,
  items: body.record_ids.map((record_id, position) => ({ position, record_id, job_id: "job" + position, kind: body.kind, state: position ? "waiting" : "queued", phase: "ready", attempts: 0, error: null })) });

function environment(t, fetch) {
  const savedWindow = globalThis.window, savedStorage = globalThis.sessionStorage;
  const storage = new Map(), events = [];
  globalThis.window = { setInterval() {}, clearInterval() {}, dispatchEvent: event => events.push(event.type) };
  globalThis.sessionStorage = { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) };
  t.mock.method(globalThis, "fetch", fetch);
  setCsrf("session-a");
  t.after(() => {
    if (savedWindow === undefined) delete globalThis.window; else globalThis.window = savedWindow;
    if (savedStorage === undefined) delete globalThis.sessionStorage; else globalThis.sessionStorage = savedStorage;
  });
  return { storage, events };
}

test("group requests use POST without a body and discard a response from the previous session", async t => {
  assert.equal(typeof groupRequest, "function");
  let finish;
  const { events } = environment(t, (_url, options) => {
    assert.equal(options.method, "POST"); assert.equal(options.body, undefined); assert.equal(options.cache, "no-store");
    return new Promise(resolve => { finish = resolve; });
  });
  const request = groupRequest("/groups/g/aws-refresh", "POST");
  setCsrf("session-b"); finish(response({ detail: "expired previous session" }, 401));
  assert.equal(await request, null); assert.deepEqual(events, []);
});

test("120 explicit AWS refreshes are bounded to three and scope change cancels queued work", async t => {
  assert.equal(typeof observation.useGroupObservations, "function");
  const requests = [];
  environment(t, (url, options) => new Promise(resolve => requests.push({ url, options, resolve })));
  const groups = Array.from({ length: 120 }, (_, i) => group("g" + i));
  const hook = mountHook(observation.useGroupObservations, 2, "scope-a", groups);
  assert.equal(requests.length, 0, "local polling must not trigger AWS reads");
  const running = hook.current.refresh(groups);
  assert.equal(requests.length, 3);
  requests[0].resolve(response(live("g0"))); await settle(); hook.render();
  assert.equal(requests.length, 4); assert.equal(hook.current.entries.g0.data.directory.member_count, 0);
  hook.render(2, "scope-b", groups.slice(0, 1));
  for (const request of requests.slice(1)) request.resolve(response(live("stale")));
  await running; hook.render();
  assert.equal(requests.length, 4); assert.deepEqual(hook.current.entries, {});
  assert.ok(requests.slice(1).every(request => request.options.signal === undefined), "already sent reads retain their global concurrency slots until completion");
  hook.unmount();
});

test("AWS refresh clears failures, fences changed local revisions and ignores old actor callbacks", async t => {
  assert.equal(typeof observation.useGroupObservations, "function");
  let status = 200;
  const calls = [];
  environment(t, async url => { calls.push(url); return response(status === 200 ? live("g") : { detail: "unavailable" }, status); });
  const hook = mountHook(observation.useGroupObservations, 2, "member", [group()]);
  await hook.current.refresh([group()]); hook.render();
  assert.equal(hook.current.entries.g.data.subscription.plan_label, "Kiro Pro");
  hook.render(2, "member", [{ ...group(), revision: 2 }]);
  assert.equal(hook.current.entries.g.stale, true);
  assert.equal(hook.current.entries.g.data, null);
  status = 502; await hook.current.refresh([{ ...group(), revision: 2 }]); hook.render();
  assert.equal(hook.current.entries.g.data, null); assert.equal(hook.current.entries.g.error, "unavailable");
  const old = hook.current.refresh;
  hook.render(3, "member", [group()]);
  await old([group()]); assert.equal(calls.length, 2); assert.deepEqual(hook.current.entries, {});
  hook.unmount();
});

test("actor scoped reads clear private data on forbidden and reject old actor refresh callbacks", async t => {
  let status = 200, calls = 0;
  environment(t, async () => { calls++; return response(status === 200 ? [{ id: "private-batch" }] : { detail: "binding removed" }, status); });
  const hook = mountHook(useRemote, "/groups/g/member-batches", 0, 2, "scope");
  await settle(); hook.render(); assert.equal(hook.current.data.length, 1);
  status = 403; await hook.current.refresh(); hook.render(); assert.equal(hook.current.data, null);
  const old = hook.current.refresh;
  hook.render("/groups/g/member-batches", 0, 3, "scope"); await settle();
  const count = calls; await old(); assert.equal(calls, count);
  hook.unmount();
});

test("membership admission freezes all 100 IDs with one synchronous submit and no reload repost", async t => {
  assert.equal(typeof members.useMemberAdmission, "function");
  let resolveFirst;
  const calls = [];
  const { storage } = environment(t, (_url, options) => {
    calls.push(JSON.parse(options.body));
    return calls.length === 1 ? new Promise(resolve => { resolveFirst = resolve; }) : Promise.resolve(response(summary(calls[0]), 202));
  });
  const input = logic.memberIntent(group(), "attach", Array.from({ length: 100 }, (_, i) => "r" + i));
  let hook = mountHook(members.useMemberAdmission, 2, "g", "scope", true);
  const first = hook.current.submit(input), duplicate = hook.current.submit(input);
  assert.equal(await duplicate, null); assert.equal(calls.length, 1);
  resolveFirst(response({ detail: "lost after admission" }, 503)); assert.equal(await first, null); hook.render();
  assert.deepEqual(hook.current.pending.body, input.body); hook.unmount();
  const other = mountHook(members.useMemberAdmission, 3, "g", "scope", true);
  assert.equal(other.current.pending, null); other.unmount();
  hook = mountHook(members.useMemberAdmission, 2, "g", "scope", true);
  assert.equal(calls.length, 1); assert.deepEqual(hook.current.pending.body.record_ids, input.body.record_ids);
  assert.equal((await hook.current.submit()).id, "batch"); hook.render();
  assert.deepEqual(calls[0], calls[1]); assert.equal(hook.current.pending, null); assert.equal(storage.size, 0);
  hook.unmount();
});

test("accepted membership history restores progress without admission POST and actor change ignores late success", async t => {
  assert.equal(typeof members.useMemberAdmission, "function");
  let finish;
  const { storage } = environment(t, () => new Promise(resolve => { finish = resolve; }));
  const intent = logic.memberIntent(group(), "detach", ["r2", "r1"]);
  const hook = mountHook(members.useMemberAdmission, 2, "g", "scope", true);
  const pending = hook.current.submit(intent); hook.render();
  assert.equal(hook.current.confirm([summary(intent.body)]).id, "batch"); hook.render();
  assert.equal(hook.current.pending, null); assert.equal(storage.size, 0);
  hook.render(3, "g", "other-actor", true);
  finish(response(summary(intent.body), 202)); assert.equal(await pending, null);
  hook.render(); assert.equal(hook.current.pending, null); assert.equal(hook.current.error, "");
  hook.unmount();
});

test("membership recovery retains uncertain payload after errors and scope loss hides it", async t => {
  assert.equal(typeof members.useMemberAdmission, "function");
  let status = 503;
  environment(t, async () => response({ detail: "uncertain" }, status));
  const hook = mountHook(members.useMemberAdmission, 2, "g", "scope", true);
  const intent = logic.memberIntent(group(), "attach", ["r"]);
  await hook.current.submit(intent); hook.render(); status = 422;
  await hook.current.submit(); hook.render(); assert.deepEqual(hook.current.pending.body, intent.body);
  hook.render(2, "g", "unbound", false); assert.equal(hook.current.pending, null);
  assert.equal(await hook.current.submit(), null); hook.unmount();
});

test("AWS invalidation during a read never restores the old observation", async t => {
  let finish;
  environment(t, () => new Promise(resolve => { finish = resolve; }));
  const hook = mountHook(observation.useGroupObservations, 2, "scope", [group()]);
  const request = hook.current.refresh([group()]);
  hook.current.invalidate(["g"]);
  finish(response(live("g"))); await request; hook.render();
  assert.equal(hook.current.entries.g.data, null); assert.equal(hook.current.entries.g.stale, true);
  hook.unmount();
});

test("only server-authorized membership actions submit and late actor responses are discarded", async t => {
  assert.equal(typeof members.useMemberBatchAction, "function");
  const calls = [], pending = [];
  environment(t, (url, options) => { calls.push({ url, options }); return new Promise(resolve => pending.push(resolve)); });
  const intent = logic.memberIntent(group(), "attach", ["r1", "r2"]), batch = summary(intent.body);
  const hook = mountHook(members.useMemberBatchAction, 2, "g", "scope", true);
  assert.equal(await hook.current.submit(batch, "retry"), null); assert.equal(calls.length, 0);
  const stop = hook.current.submit(batch, "stop");
  assert.equal(await hook.current.submit(batch, "stop"), null); assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "/api/groups/g/member-batches/batch/stop"); assert.equal(calls[0].options.body, undefined);
  pending[0](response({ ...batch, state: "stopped", counts: { ...batch.counts, waiting: 0, queued: 0, stopped: 2 }, actions: { recheck: false, retry: false, stop: false } }));
  assert.equal((await stop).counts.stopped, 2);
  const recheck = hook.current.submit({ ...batch, actions: { recheck: true, retry: false, stop: true } }, "recheck");
  hook.render(3, "g", "other", true); pending[1](response({ detail: "old actor forbidden" }, 403));
  assert.equal(await recheck, null); hook.render(); assert.equal(hook.current.error, ""); hook.unmount();
});

test("AWS concurrency stays at three across navigation while previous reads finish", async t => {
  const requests = [];
  environment(t, url => new Promise(resolve => requests.push({ url, resolve })));
  const groups = [group("a"), group("b"), group("c")];
  const first = mountHook(observation.useGroupObservations, 2, "list", groups);
  const previous = first.current.refresh(groups);
  assert.equal(requests.length, 3); first.unmount();
  const detail = mountHook(observation.useGroupObservations, 2, "detail", [group("d")]);
  const next = detail.current.refresh([group("d")]);
  assert.equal(requests.length, 3, "navigation must not start a fourth active AWS read");
  requests[0].resolve(response(live("a"))); await settle(); assert.equal(requests.length, 4);
  requests[1].resolve(response(live("b"))); requests[2].resolve(response(live("c"))); requests[3].resolve(response(live("d")));
  await Promise.all([previous, next]); detail.render(); assert.equal(detail.current.entries.d.data.group_id, "d");
  assert.equal(first.updatesAfterUnmount, 0); detail.unmount();
});

function findNode(node, predicate) {
  if (!node || typeof node !== "object") return null;
  if (predicate(node)) return node;
  for (const child of [node.props?.children].flat(Infinity)) { const found = findNode(child, predicate); if (found) return found; }
  return null;
}

test("member dialog search Enter never admits and hidden choices survive a server search", async t => {
  const calls = [];
  const record = { id: "r1", username: "Independent USER", owner_id: 2, aws_account_id: 1, effective_subscription_source: "USER" };
  environment(t, async (url, options) => {
    calls.push({ url, options }); return response({ group_id: "g", kind: "attach", items: url.includes("q=hidden") ? [] : [record], total: 120, page: 1, page_size: 100 });
  });
  let submits = 0;
  const hook = mountHook(ui.MemberPickerDialog, { group: { ...group(), name: "Group" }, user: { id: 2 }, scope: "owner-account", kind: "attach",
    admission: { pending: null, busy: false, error: "", submit: async () => { submits++; return null; } }, close() {}, onAccepted() {}, onAccessDenied() {} });
  await settle(); hook.render();
  const selection = findNode(hook.current, node => node.type === ui.MemberSelection);
  selection.props.onSelection([record]); hook.render();
  const search = findNode(hook.current, node => node.props?.["aria-label"] === "搜索可选成员");
  let prevented = false; search.props.onKeyDown({ key: "Enter", preventDefault() { prevented = true; } });
  assert.equal(prevented, true); assert.equal(submits, 0);
  search.props.onChange({ target: { value: "hidden" } }); hook.render(); await settle(); hook.render();
  const next = findNode(hook.current, node => node.type === ui.MemberSelection);
  assert.deepEqual(next.props.selected, [record]); assert.deepEqual(next.props.records, []);
  assert.ok(calls.every(call => call.options.method === "GET")); assert.ok(calls.at(-1).url.includes("kind=attach&q=hidden&page=1&page_size=100"));
  hook.unmount();
});

test("member manager reload restores accepted batch detail entirely through GET", async t => {
  const body = logic.memberIntent(group(), "attach", ["r1", "r2"]).body, batch = summary(body), calls = [];
  environment(t, async (url, options) => { calls.push({ url, options }); return response(url.endsWith("/batch") ? batch : [batch]); });
  const props = { group: group(), user: { id: 2 }, scope: "member", blocked: true, accessible: true, onChanged() {} };
  const hook = mountHook(ui.GroupMemberManager, props);
  await settle(); hook.render(); await settle(); hook.render();
  assert.equal(findNode(hook.current, node => node.type === ui.MemberBatchProgress).props.batch.id, "batch");
  assert.ok(calls.every(call => call.options.method === "GET")); assert.equal(calls.length, 2);
  hook.render({ ...props, scope: "binding-lost", accessible: false });
  assert.equal(findNode(hook.current, node => node.type === ui.MemberBatchProgress), null); hook.unmount();
});

test("incomplete AWS plan data is unavailable instead of being labeled unsubscribed", async t => {
  const data = live("g"); delete data.subscription.plan_label;
  environment(t, async () => response(data));
  const hook = mountHook(observation.useGroupObservations, 2, "scope", [group()]);
  await hook.current.refresh([group()]); hook.render();
  assert.equal(hook.current.entries.g.data, null); assert.match(hook.current.entries.g.error, /不完整/); hook.unmount();
});

test("malformed accepted batch state retains the original pending admission", async t => {
  const intent = logic.memberIntent(group(), "attach", ["r"]);
  environment(t, async () => response({ ...summary(intent.body), state: "unrecognized" }, 202));
  const hook = mountHook(members.useMemberAdmission, 2, "g", "scope", true);
  assert.equal(await hook.current.submit(intent), null); hook.render();
  assert.deepEqual(hook.current.pending.body, intent.body); assert.match(hook.current.error, /尚未确认/); hook.unmount();
});

test("a definite first membership eligibility rejection allows a corrected selection", async t => {
  let denied = true;
  environment(t, async (_url, options) => denied ? response({ detail: "该用户已有管理分组" }, 409) : response(summary(JSON.parse(options.body)), 202));
  const hook = mountHook(members.useMemberAdmission, 2, "g", "scope", true);
  assert.equal(await hook.current.submit(logic.memberIntent(group(), "attach", ["r1"])), null); hook.render();
  assert.equal(hook.current.pending, null); denied = false;
  assert.deepEqual((await hook.current.submit(logic.memberIntent(group(), "attach", ["r2"]))).record_ids, ["r2"]); hook.unmount();
});

for (const status of [403, 404]) {
  test(`member action ${status} hides cached private detail and fences the old callback immediately`, async t => {
    const batch = summary(logic.memberIntent(group(), "attach", ["r"]).body), calls = [];
    Object.assign(batch.items[0], { username: "private-name", email: "private@example.test", sso_user_id: "private-sso" });
    environment(t, async (url, options) => {
      calls.push({ url, options });
      return response(options.method === "POST" ? { detail: "scope withdrawn" } : url.endsWith("/batch") ? batch : [batch], options.method === "POST" ? status : 200);
    });
    const hook = mountHook(ui.GroupMemberManager, { group: group(), user: { id: 2 }, scope: "bound", accessible: true, blocked: false, onChanged() {} });
    await settle(); hook.render(); await settle(); hook.render();
    const before = findNode(hook.current, node => node.type === ui.MemberBatchProgress);
    assert.equal(before.props.batch.items[0].email, "private@example.test");
    await before.props.onAction("stop");
    await before.props.onAction("stop");
    assert.equal(calls.filter(call => call.options.method === "POST").length, 1, "old handlers must be fenced before another render");
    hook.render();
    assert.equal(findNode(hook.current, node => node.type === ui.MemberBatchProgress), null);
    assert.equal(findNode(hook.current, node => node.type === ui.MemberPickerDialog), null);
    assert.equal(findNode(hook.current, node => node.props?.children === "批量添加成员").props.disabled, true);
    hook.unmount();
  });

  test(`first admission ${status} closes candidates and hides recovery while retaining its actor-private request`, async t => {
    const intent = logic.memberIntent(group(), "attach", ["r"]), batch = summary(intent.body), calls = [];
    const { storage } = environment(t, async (url, options) => {
      calls.push({ url, options });
      return response(options.method === "POST" ? { detail: "scope withdrawn" } : url.endsWith("/batch") ? batch : [batch], options.method === "POST" ? status : 200);
    });
    const props = { group: group(), user: { id: 2 }, scope: "bound", accessible: true, blocked: false, onChanged() {} };
    const hook = mountHook(ui.GroupMemberManager, props);
    await settle(); hook.render(); await settle(); hook.render();
    findNode(hook.current, node => node.props?.children === "批量添加成员").props.onClick(); hook.render();
    const picker = findNode(hook.current, node => node.type === ui.MemberPickerDialog);
    assert.ok(picker);
    await picker.props.admission.submit(intent);
    await picker.props.admission.submit();
    assert.equal(calls.filter(call => call.options.method === "POST").length, 1);
    hook.render();
    assert.equal(findNode(hook.current, node => node.type === ui.MemberPickerDialog), null);
    assert.equal(findNode(hook.current, node => node.type === ui.MemberBatchProgress), null);
    assert.equal(findNode(hook.current, node => node.props?.className?.includes("group-recovery")), null);
    assert.deepEqual(JSON.parse(storage.get("kiro-group-members:2:g")).body, intent.body);
    const posts = calls.filter(call => call.options.method === "POST").length;
    hook.render({ ...props, scope: "revalidated", accessible: true }); await settle(); hook.render();
    assert.equal(calls.filter(call => call.options.method === "POST").length, posts, "valid scope recovery must not automatically repost");
    hook.unmount();
  });

  test(`AWS ${status} denies the shared group scope and hides sibling batch data without waiting for GET`, async t => {
    assert.equal(typeof useGroupAccess, "function");
    const batch = summary(logic.memberIntent(group(), "attach", ["r"]).body), calls = [];
    let denied = false;
    environment(t, async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith("/aws-refresh")) return response(denied ? { detail: "scope withdrawn" } : live("g"), denied ? status : 200);
      return response(url.endsWith("/batch") ? batch : [batch]);
    });
    const hook = mountHook(() => {
      const access = useGroupAccess(2, "bound");
      const aws = observation.useGroupObservations(2, "bound", [group()], access);
      const manager = ui.GroupMemberManager({ group: group(), user: { id: 2 }, scope: "bound", accessible: true, blocked: false, onChanged() {}, access });
      return { aws, manager, access };
    });
    await settle(); hook.render(); await settle(); hook.render();
    await hook.current.aws.refresh([group()]); hook.render();
    assert.equal(hook.current.aws.entries.g.data.directory.name, "Actual g");
    const oldAction = findNode(hook.current.manager, node => node.type === ui.MemberBatchProgress).props.onAction;
    findNode(hook.current.manager, node => node.props?.children === "批量添加成员").props.onClick(); hook.render();
    const oldAdmission = findNode(hook.current.manager, node => node.type === ui.MemberPickerDialog).props.admission.submit;
    denied = true; await hook.current.aws.refresh([group()]);
    const count = calls.length;
    await oldAction("stop"); await oldAdmission(logic.memberIntent(group(), "attach", ["other"])); await hook.current.aws.refresh([group()]);
    assert.equal(calls.length, count, "cross-component callbacks must stop immediately at the shared denial boundary");
    hook.render();
    assert.equal(hook.current.access.canAccess("g"), false); assert.deepEqual(hook.current.aws.entries, {});
    assert.equal(findNode(hook.current.manager, node => node.type === ui.MemberBatchProgress), null);
    assert.equal(findNode(hook.current.manager, node => node.type === ui.MemberPickerDialog), null);
    hook.unmount();
  });
}

test("member scope denial rejects an already sent sibling AWS response and preserves other groups", async t => {
  assert.equal(typeof useGroupAccess, "function");
  const batch = summary(logic.memberIntent(group(), "attach", ["r"]).body);
  let finish;
  environment(t, (url, options) => {
    if (url.endsWith("/aws-refresh")) return new Promise(resolve => { finish = resolve; });
    return Promise.resolve(response({ detail: "scope withdrawn" }, 403));
  });
  const hook = mountHook(() => {
    const access = useGroupAccess(2, "bound");
    return { access, aws: observation.useGroupObservations(2, "bound", [group()], access), action: members.useMemberBatchAction(2, "g", "bound", true, access) };
  });
  const read = hook.current.aws.refresh([group()]);
  await hook.current.action.submit(batch, "stop");
  assert.equal(hook.current.access.canAccess("g"), false); assert.equal(hook.current.access.canAccess("other"), true);
  finish(response(live("g"))); await read; hook.render();
  assert.deepEqual(hook.current.aws.entries, {}); hook.unmount();
});

test("an open candidate dialog clears selected private names after its admission is denied", async t => {
  const record = { id: "r", username: "private-candidate", email: "private@example.test" }, calls = [];
  const { storage } = environment(t, async (url, options) => {
    calls.push({ url, options });
    return options.method === "POST" ? response({ detail: "scope withdrawn" }, 403)
      : response({ group_id: "g", kind: "attach", items: [record], total: 1, page: 1, page_size: 100 });
  });
  const hook = mountHook(() => {
    const access = useGroupAccess(2, "bound"), admission = members.useMemberAdmission(2, "g", "bound", true, access);
    return ui.MemberPickerDialog({ group: group(), user: { id: 2 }, scope: "bound", kind: "attach", admission, access,
      close() {}, onAccepted() {}, onAccessDenied() { access.deny("g"); } });
  });
  await settle(); hook.render();
  const selection = findNode(hook.current, node => node.type === ui.MemberSelection);
  assert.equal(selection.props.records[0].email, "private@example.test"); selection.props.onSelection([record]); hook.render();
  const form = findNode(hook.current, node => node.type === "form");
  await form.props.onSubmit({ preventDefault() {} });
  await form.props.onSubmit({ preventDefault() {} });
  assert.equal(calls.filter(call => call.options.method === "POST").length, 1);
  hook.render();
  assert.equal(findNode(hook.current, node => node.type === ui.MemberSelection), null);
  assert.equal(findNode(hook.current, node => node.props?.["aria-label"] === "本批已选成员"), null);
  assert.equal(findNode(hook.current, node => node.type === "form"), null);
  assert.equal(storage.size, 1); hook.unmount();
});

test("a previous actor's scope denial callback cannot deny the newly validated actor", () => {
  const hook = mountHook(useGroupAccess, 2, "bound");
  const old = hook.current;
  old.deny("g"); hook.render(); assert.equal(hook.current.canAccess("g"), false);
  hook.render(3, "bound");
  old.deny("other");
  assert.equal(old.canAccess("g"), false);
  assert.equal(hook.current.canAccess("g"), true); assert.equal(hook.current.canAccess("other"), true);
  hook.unmount(); assert.equal(hook.current.canAccess("g"), false);
});
