import test from "node:test";
import assert from "node:assert/strict";
import { mountHook, settle } from "./hooks.mjs";
import { loadSource } from "./load-source.mjs";
const { useAuthAdmission, useAuthGroupPreview } = await loadSource("authRequests");
const { authRequest } = await loadSource("authLogic");
const { downloadAuthZip, setCsrf } = await loadSource("api");
const response = (body, status = 200) => new Response(JSON.stringify(body), { status });
function environment(t, fetch) {
  const originals = { window: globalThis.window, sessionStorage: globalThis.sessionStorage };
  const storage = new Map();
  globalThis.window = { setInterval() {}, clearInterval() {}, dispatchEvent() {} };
  globalThis.sessionStorage = { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) };
  t.mock.method(globalThis, "fetch", fetch);
  t.after(() => { for (const [key, value] of Object.entries(originals)) { if (value === undefined) delete globalThis[key]; else globalThis[key] = value; } });
  return storage;
}

for (const status of [0, 401, 403, 429, 503, 409, 200]) test(`auth admission retains frozen original intent after lost response and ${status}`, async t => {
  const calls = [];
  environment(t, async (_url, options) => {
    calls.push(JSON.parse(options.body));
    if (calls.length === 1) throw new TypeError("response lost after commit");
    if (calls.length === 2) { if (!status) throw new TypeError("offline"); return response({ detail: "尚待确认" }, status); }
    return response({ id: "original", actor_id: 7, kind: "json_export" });
  });
  let hook = mountHook(useAuthAdmission, 7, "json_export");
  const original = authRequest("json_export", ["first", "second"], "group-a");
  assert.equal(await hook.current.submit(original), null);
  hook.render();
  assert.ok(hook.current.pending);
  assert.equal(await hook.current.submit(authRequest("json_export", ["different"])), null);
  hook.render(); hook.unmount();
  const other = mountHook(useAuthAdmission, 8, "json_export");
  assert.equal(other.current.pending, null); other.unmount();
  hook = mountHook(useAuthAdmission, 7, "json_export");
  assert.equal(calls.length, 2, "reload does not automatically submit");
  assert.equal((await hook.current.submit()).id, "original");
  hook.render();
  assert.equal(hook.current.pending, null);
  assert.deepEqual(calls, [original, original, original]);
  hook.unmount();
});

test("custom password is retained only in memory; reload requires history review rather than resubmission", async t => {
  const calls = [];
  const storage = environment(t, async (_url, options) => { calls.push(JSON.parse(options.body)); throw new TypeError("offline"); });
  const body = authRequest("custom_password", ["first"], "group-a", "Synthetic8!");
  let hook = mountHook(useAuthAdmission, 7, "password");
  await hook.current.submit(body); hook.render();
  assert.doesNotMatch(JSON.stringify([...storage.values()]), /Synthetic8!|"password"\s*:/);
  assert.doesNotMatch(JSON.stringify(hook.current.pending), /Synthetic8!/);
  assert.equal(hook.current.canResume, true);
  await hook.current.submit(authRequest("custom_password", ["other"], undefined, "Different8!"));
  assert.deepEqual(calls, [body, body]);
  hook.unmount();
  hook = mountHook(useAuthAdmission, 7, "password");
  assert.equal(hook.current.canResume, false);
  assert.ok(hook.current.pending);
  await hook.current.submit(body);
  assert.equal(calls.length, 2, "no blind replay or key rotation after custom password loss");
  assert.equal(hook.current.clearAfterReview(false), false);
  assert.equal(hook.current.clearAfterReview(true), true);
  hook.render(); assert.equal(hook.current.pending, null);
  hook.unmount();
});

test("admission serializes double clicks and ignores completions after unmount", async t => {
  let finish, calls = 0;
  environment(t, () => { calls++; return new Promise(resolve => { finish = resolve; }); });
  const hook = mountHook(useAuthAdmission, 7, "password");
  const pending = hook.current.submit(authRequest("reset_password", ["one"]));
  assert.equal(await hook.current.submit(authRequest("reset_password", ["two"])), null);
  assert.equal(calls, 1);
  hook.unmount();
  finish(response({ id: "accepted", actor_id: 7, kind: "reset_password" }));
  assert.equal(await pending, null, "an unmounted caller must not navigate to the old actor's batch"); await settle();
  assert.equal(hook.updatesAfterUnmount, 0);
});

test("switching actor clears the visible pending intent and fences the old response", async t => {
  let finish;
  environment(t, () => new Promise(resolve => { finish = resolve; }));
  const hook = mountHook(useAuthAdmission, 7, "password");
  const old = hook.current.submit(authRequest("custom_password", ["private-a"], undefined, "Synthetic8!"));
  hook.render(); assert.ok(hook.current.pending);
  hook.render(8, "password");
  assert.equal(hook.current.pending, null);
  finish(response({ id: "private-batch", actor_id: 7, kind: "custom_password" }));
  assert.equal(await old, null);
  hook.render(); assert.equal(hook.current.pending, null);
  hook.unmount();
});

test("an old accepted response never erases a newer manually reviewed intent", async t => {
  const requests = [];
  const storage = environment(t, () => new Promise(resolve => requests.push(resolve)));
  const old = mountHook(useAuthAdmission, 7, "password");
  const first = old.current.submit(authRequest("reset_password", ["first"]));
  old.unmount();
  const current = mountHook(useAuthAdmission, 7, "password");
  current.current.clearAfterReview(true); current.render();
  const body = authRequest("random_password", ["new"]);
  const next = current.current.submit(body);
  requests[0](response({ id: "old", actor_id: 7, kind: "reset_password" }));
  await first;
  assert.equal(JSON.parse([...storage.values()][0]).request_key, body.request_key);
  requests[1](response({ id: "new", actor_id: 7, kind: "random_password" }));
  await next; current.unmount();
});

test("ZIP download is an authenticated no-store POST blob with a revoked object URL and accurate counts", async t => {
  let request, clicked = false, revoked = false;
  const oldDocument = globalThis.document;
  environment(t, async (url, options) => { request = { url, options }; return new Response("synthetic-zip", { headers: { "Content-Disposition": 'attachment; filename="kiro-batch.zip"', "X-Export-Count": "2", "X-Excluded-Count": "1" } }); });
  globalThis.document = { body: { appendChild() {} }, createElement() { return { click() { clicked = true; assert.equal(this.download, "kiro-batch.zip"); }, remove() {} }; } };
  t.after(() => { if (oldDocument === undefined) delete globalThis.document; else globalThis.document = oldDocument; });
  t.mock.method(URL, "createObjectURL", blob => { assert.ok(blob instanceof Blob); return "blob:synthetic"; });
  t.mock.method(URL, "revokeObjectURL", url => { assert.equal(url, "blob:synthetic"); revoked = true; });
  t.mock.method(globalThis, "setTimeout", callback => { callback(); return 1; });
  setCsrf("synthetic-csrf");
  assert.deepEqual(await downloadAuthZip("batch-a"), { included: 2, excluded: 1 });
  assert.equal(request.url, "/api/auth-batches/batch-a/download");
  assert.equal(request.options.method, "POST"); assert.equal(request.options.cache, "no-store");
  assert.equal(request.options.credentials, "same-origin");
  assert.equal(request.options.headers["X-CSRF-Token"], "synthetic-csrf");
  assert.equal(clicked && revoked, true);
});

test("group preview is explicit, ignores older responses and clears when group or mode changes", async t => {
  const requests = [];
  environment(t, url => new Promise(resolve => requests.push({ url, resolve })));
  const hook = mountHook(useAuthGroupPreview, "group-a", "json_export");
  assert.equal(requests.length, 0, "no automatic all-member selection");
  const first = hook.current.refresh();
  const second = hook.current.refresh();
  requests[2].resolve(response({ group_id: "group-a", kind: "json_export", record_ids: ["new"], skipped: [] }));
  requests[3].resolve(response({ id: "group-a", members: [{ id: "new", username: "new-user" }] }));
  await second; hook.render();
  assert.deepEqual(hook.current.snapshot.preview.record_ids, ["new"]);
  requests[0].resolve(response({ group_id: "group-a", kind: "json_export", record_ids: ["old"], skipped: [] }));
  requests[1].resolve(response({ id: "group-a", members: [{ id: "old", username: "old-user" }] }));
  await first; hook.render();
  assert.deepEqual(hook.current.snapshot.preview.record_ids, ["new"]);
  hook.render("group-b", "custom_password");
  assert.equal(hook.current.snapshot, null);
  assert.equal(requests.length, 4);
  const pending = hook.current.refresh(); hook.unmount();
  requests[4].resolve(response({ group_id: "group-b", kind: "custom_password", record_ids: [], skipped: [] }));
  requests[5].resolve(response({ id: "group-b", members: [] }));
  await pending;
  assert.equal(hook.updatesAfterUnmount, 0);
});
