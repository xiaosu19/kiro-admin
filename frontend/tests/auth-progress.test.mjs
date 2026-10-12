import test from "node:test";
import assert from "node:assert/strict";
import { mountHook, settle } from "./hooks.mjs";
import { loadSource } from "./load-source.mjs";
const { AuthProgress, AuthBatchView, HumanChallenge, safeFrame } = await loadSource("AuthBatches");
const { setCsrf } = await loadSource("api");
const response = (body, status = 200) => new Response(JSON.stringify(body), { status });
function find(node, predicate) {
  if (!node || typeof node !== "object") return null;
  if (Array.isArray(node)) { for (const child of node) { const found = find(child, predicate); if (found) return found; } return null; }
  return predicate(node) ? node : find(node.props?.children, predicate);
}
function environment(t, fetch) {
  const previous = globalThis.window;
  const events = new Map(), timers = [];
  globalThis.window = { location: { origin: "https://console.example.test" }, setInterval() {}, clearInterval() {},
    setTimeout: fn => { timers.push(fn); return timers.length; }, clearTimeout() {}, dispatchEvent() {},
    addEventListener: (name, fn) => events.set(name, fn), removeEventListener: name => events.delete(name) };
  t.mock.method(globalThis, "fetch", fetch);
  t.after(() => { if (previous === undefined) delete globalThis.window; else globalThis.window = previous; });
  return { events, timers };
}
const batch = { id: "batch", actor_id: 7, kind: "json_export", state: "active", total: 2, success_count: 0, failure_count: 2, states: { failed: 1, needs_review: 1 }, created_at: "date", expires_at: "date", items: [
  { record_id: "failed", operation_id: "op-a", username: "retry-user", state: "failed", credential_state: "permanent", requires_new_reset: false },
  { record_id: "unknown", operation_id: "op-b", username: "unknown-user", state: "needs_review", credential_state: "unknown", requires_new_reset: true },
] };

test("HTTP verification frames are allowed only between distinct exact loopback origins", () => {
  const frame = url => ({ frame_url: url, frame_origin: new URL(url).origin });
  for (const parentHost of ["localhost", "127.0.0.1", "[::1]"]) {
    for (const frameHost of ["localhost", "127.0.0.1", "[::1]"])
      assert.equal(safeFrame(frame(`http://${frameHost}:8001/auth-widget`), `http://${parentHost}:8000`), true);
  }
  for (const [parent, url] of [
    ["https://console.example.test", "http://127.0.0.1:8001/auth-widget"],
    ["https://localhost:8000", "http://localhost:8001/auth-widget"],
    ["http://console.example.test", "http://localhost:8001/auth-widget"],
    ["http://localhost:8000", "http://verify.example.test/auth-widget"],
    ["http://localhost:8000", "http://localhost.example.test:8001/auth-widget"],
    ["http://localhost:8000", "http://localhost.:8001/auth-widget"],
    ["http://localhost:8000", "http://127.0.0.2:8001/auth-widget"],
    ["http://localhost:8000", "http://127.1:8001/auth-widget"],
    ["http://localhost:8000", "http://0x7f000001:8001/auth-widget"],
    ["http://127.1:8000", "http://localhost:8001/auth-widget"],
    ["http://localhost:8000", "http://localhost:8000/auth-widget"],
    ["http://localhost:8000", "http://user:pass@localhost:8001/auth-widget"],
    ["http://localhost:8000", "http://localhost:8001/other"],
    ["http://localhost:8000", "http://localhost:8001/auth-widget#unexpected"],
    ["https://console.example.test", "https://console.example.test/auth-widget"],
  ]) assert.equal(safeFrame(frame(url), parent), false, `${parent} -> ${url}`);
  assert.equal(safeFrame(frame("https://verify.example.test/auth-widget"), "https://console.example.test"), true);
  assert.equal(safeFrame({ ...frame("http://localhost:8001/auth-widget"), frame_origin: "http://localhost:8002" }, "http://localhost:8000"), false);
});

test("batch recovery retries only recoverable items and new OTP reset requires an explicit second action", async t => {
  const calls = [];
  environment(t, async (url, options) => {
    if (options.method === "POST") { calls.push({ url, body: JSON.parse(options.body) }); return response({ state: "queued" }); }
    return response(batch);
  });
  const host = mountHook(AuthProgress, { id: "batch", actorId: 7, scope: "json_export", notify() {} });
  await settle(); host.render();
  find(host.current, node => node.type === AuthBatchView).props.onAction("retry_batch");
  await settle(); host.render();
  assert.deepEqual(calls, [{ url: "/api/auth-batches/batch/items/failed/retry", body: { mode: "resume" } }]);
  find(host.current, node => node.type === AuthBatchView).props.onAction("new_reset", batch.items[1]); host.render();
  assert.equal(calls.length, 1);
  const confirmation = find(host.current, node => node.type === "button" && node.props.children === "确认再次重置并继续");
  assert.ok(confirmation); confirmation.props.onClick(); confirmation.props.onClick();
  await settle(); host.render();
  assert.deepEqual(calls[1], { url: "/api/auth-batches/batch/items/unknown/retry", body: { mode: "new_reset" } });
  assert.equal(calls.length, 2, "double-click must not issue two resets");
  host.unmount();
});

test("a foreign actor's batch response is never rendered as accessible progress", async t => {
  environment(t, async () => response({ ...batch, actor_id: 8 }));
  const host = mountHook(AuthProgress, { id: "batch", actorId: 7, scope: "json_export", notify() {} });
  await settle(); host.render();
  assert.equal(find(host.current, node => node.type === AuthBatchView), null);
  assert.doesNotMatch(JSON.stringify(host.current), /retry-user|unknown-user/);
  host.unmount();
});

for (const [change, stage] of [["unmount", "response"], ["unmount", "blob"], ["session", "response"], ["session", "blob"],
  ["actor", "response"], ["scope", "response"], ["id", "response"], ["current", "blob"]])
  test(`auth ZIP download fences ${change} while waiting for ${stage}`, async t => {
    const ready = { ...batch, completed_at: "date", download_ready: true, success_count: 2, failure_count: 0, states: { completed: 2 } };
    let finishResponse, finishBlob, downloads = 0, objects = 0;
    const notices = [], calls = [], previousDocument = globalThis.document;
    globalThis.document = { body: { appendChild() {} }, createElement: () => ({ click() { downloads++; }, remove() {} }) };
    t.after(() => { if (previousDocument === undefined) delete globalThis.document; else globalThis.document = previousDocument; });
    t.mock.method(URL, "createObjectURL", () => { objects++; return "blob:synthetic"; });
    t.mock.method(URL, "revokeObjectURL", () => {});
    environment(t, (url, options) => {
      calls.push({ url, method: options.method });
      return options.method === "POST" ? new Promise(resolve => { finishResponse = resolve; }) : Promise.resolve(response(ready));
    });
    setCsrf("auth-download-session");
    const props = { id: "batch", actorId: 7, scope: "json_export", notify: message => notices.push(message) };
    const host = mountHook(AuthProgress, props);
    await settle(); host.render();
    const download = find(host.current, node => node.type === AuthBatchView).props.onDownload;
    download(); download();
    assert.equal(calls.filter(call => call.method === "POST").length, 1);
    const result = { ok: true, headers: new Headers({ "X-Export-Count": "2", "X-Excluded-Count": "0" }),
      blob: () => new Promise(resolve => { finishBlob = resolve; }) };
    if (stage === "blob") { finishResponse(result); await settle(); }
    if (change === "unmount") host.unmount();
    else if (change === "session") setCsrf("replacement-session");
    else if (change === "actor") host.render({ ...props, actorId: 8 });
    else if (change === "scope") host.render({ ...props, scope: "password" });
    else if (change === "id") host.render({ ...props, id: "another-batch" });
    if (stage === "response") { finishResponse(result); await settle(); }
    finishBlob?.(new Blob(["synthetic-private-json"]));
    await settle(); await settle();
    assert.equal(downloads, change === "current" ? 1 : 0);
    assert.equal(objects, downloads);
    assert.equal(notices.length, downloads);
    assert.equal(host.updatesAfterUnmount, 0);
    if (change !== "unmount") host.unmount();
  });

const officialChallenge = { kind: "aws_authorization", id: "authorization-a", operation_id: "op-a", revision: 2,
  expires_at: Date.now() / 1000 + 120, username: "retry-user", user_code: "HUMAN-CODE",
  authorization_url: "https://example.awsapps.com/start/#/device?user_code=HUMAN-CODE" };
const officialProps = { batchId: "batch", item: { ...batch.items[0], revision: 99, state: "challenge" }, kind: "json_export", onChanged: async () => {}, onClose() {} };

test("official AWS continuation renders a protected link without iframe and posts only an explicit revision-bound answer", async t => {
  const calls = [];
  environment(t, async (url, options) => {
    if (options.method === "POST") { calls.push({ url, body: JSON.parse(options.body) }); return response({ state: "queued" }); }
    return response(officialChallenge);
  });
  const host = mountHook(HumanChallenge, officialProps);
  await settle(); host.render();
  assert.equal(find(host.current, node => node.type === "iframe"), null);
  const link = find(host.current, node => node.type === "a");
  assert.ok(link);
  assert.equal(link.props.href, officialChallenge.authorization_url);
  assert.equal(link.props.target, "_blank");
  assert.equal(link.props.rel, "noopener noreferrer");
  assert.equal(link.props.referrerPolicy, "no-referrer");
  assert.match(JSON.stringify(host.current), /HUMAN-CODE/);
  assert.match(JSON.stringify(host.current), /密码.*待核对/);
  assert.match(JSON.stringify(host.current), /MFA/);
  assert.equal(calls.length, 0, "opening the challenge never resumes or opens a tab automatically");
  const form = find(host.current, node => node.type === "form");
  const event = { preventDefault() {} };
  await Promise.all([form.props.onSubmit(event), form.props.onSubmit(event)]);
  assert.deepEqual(calls, [{ url: "/api/auth-batches/batch/items/failed/resume", body: {
    challenge_id: "authorization-a", revision: 2, continue_authorization: true,
  } }]);
  host.unmount();
});

test("official challenge reload fetches metadata without writes and refresh rejects old handlers", async t => {
  const calls = [], requests = [];
  environment(t, (url, options) => {
    if (options.method === "POST") { calls.push(JSON.parse(options.body)); return Promise.resolve(response({ state: "queued" })); }
    return new Promise(resolve => requests.push(resolve));
  });
  let host = mountHook(HumanChallenge, officialProps);
  requests[0](response(officialChallenge)); await settle(); host.render();
  host.unmount();
  host = mountHook(HumanChallenge, officialProps);
  requests[1](response(officialChallenge)); await settle(); host.render();
  assert.equal(calls.length, 0);
  const staleForm = find(host.current, node => node.type === "form");
  find(host.current, node => node.type === "button" && node.props.children === "刷新验证").props.onClick();
  host.render();
  assert.equal(find(host.current, node => node.type === "a"), null);
  await staleForm.props.onSubmit({ preventDefault() {} });
  assert.equal(calls.length, 0);
  requests[2](response({ ...officialChallenge, revision: 3 })); await settle(); host.render();
  await staleForm.props.onSubmit({ preventDefault() {} });
  assert.equal(calls.length, 0);
  await find(host.current, node => node.type === "form").props.onSubmit({ preventDefault() {} });
  assert.equal(calls[0].revision, 3);
  host.unmount();
});

for (const kind of ["ams", "manual_action"]) test(`password-only ${kind} gives manual/reset guidance without an iframe or OAuth success button`, async t => {
  environment(t, async () => response({ ...officialChallenge, kind, portal_url: "https://example.awsapps.com/start",
    frame_url: "https://verify.example.test/auth-widget", frame_origin: "https://verify.example.test" }));
  const host = mountHook(HumanChallenge, { ...officialProps, kind: "random_password" });
  await settle(); host.render();
  assert.equal(find(host.current, node => node.type === "iframe"), null);
  assert.equal(find(host.current, node => node.type === "form"), null);
  assert.match(JSON.stringify(host.current), /无法确认.*永久密码/);
  assert.match(JSON.stringify(host.current), /取消.*重置/);
  host.unmount();
});

for (const url of ["https://evil.example/", "javascript:alert(1)",
  "https://example.awsapps.com/start/#/device?user_code=OTHER",
  "https://example.awsapps.com/start/#/device?user_code=HUMAN-CODE&redirect_uri=https://evil.example/"])
  test(`official link rejects unexpected destination or code: ${url}`, async t => {
    environment(t, async () => response({ ...officialChallenge, authorization_url: url }));
    const host = mountHook(HumanChallenge, officialProps);
    await settle(); host.render();
    assert.equal(find(host.current, node => node.type === "a"), null);
    const submit = find(host.current, node => node.type === "button" && node.props.className === "primary");
    assert.ok(!submit || submit.props.disabled);
    host.unmount();
  });

test("expired official metadata never exposes a live authorization link or submits", async t => {
  const calls = [];
  const { timers } = environment(t, async (url, options) => {
    if (options.method === "POST") calls.push(url);
    return response({ ...officialChallenge, expires_at: 1 });
  });
  const host = mountHook(HumanChallenge, officialProps);
  await settle(); host.render();
  for (const fn of timers) fn();
  host.render();
  assert.equal(find(host.current, node => node.type === "a"), null);
  assert.equal(find(host.current, node => node.type === "form"), null);
  assert.match(JSON.stringify(host.current), /过期/);
  assert.deepEqual(calls, []);
  host.unmount();
});

const imageChallenge = { kind: "image", id: "image-a", operation_id: "op-a", revision: 2, expires_at: Date.now() / 1000 + 120 };
const imageProps = { batchId: "batch", item: { ...batch.items[0], revision: 99, state: "challenge" }, kind: "json_export", onChanged: async () => {}, onClose() {} };
const png = Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl6fNsAAAAASUVORK5CYII=", "base64");
const imageResponse = (bytes = png) => new Response(bytes, { headers: { "Content-Type": "image/png" } });

test("classical CAPTCHA uses an in-memory data image permitted by console CSP", async t => {
  let imageRequest;
  environment(t, async (url, options) => {
    if (url.includes("/image?")) { imageRequest = { url, options }; return imageResponse(); }
    return response(imageChallenge);
  });
  const host = mountHook(HumanChallenge, imageProps);
  await settle(); host.render(); await settle(); host.render();
  const image = find(host.current, node => node.type === "img");
  assert.equal(image.props.src, `data:image/png;base64,${png.toString("base64")}`);
  assert.equal(imageRequest.url, "/api/auth-batches/batch/items/failed/image?revision=2");
  assert.equal(imageRequest.options.credentials, "same-origin");
  assert.equal(imageRequest.options.cache, "no-store");
  assert.equal(imageRequest.options.signal.aborted, false);
  host.unmount(); assert.equal(imageRequest.options.signal.aborted, true);
});

test("replaced and unmounted CAPTCHA image requests are aborted and cannot replace the latest data image", async t => {
  let revision = 0;
  const images = [];
  environment(t, (url, options) => {
    if (url.includes("/image?")) return new Promise(resolve => images.push({ resolve, signal: options.signal }));
    return Promise.resolve(response({ ...imageChallenge, revision: ++revision }));
  });
  const host = mountHook(HumanChallenge, imageProps);
  await settle(); host.render();
  const refresh = () => find(host.current, node => node.type === "button" && node.props.children === "刷新验证").props.onClick();
  refresh(); await settle(); host.render();
  assert.equal(images[0].signal.aborted, true);
  const currentBytes = Buffer.concat([png, Buffer.from("synthetic-current")]);
  images[1].resolve(imageResponse(currentBytes)); await settle(); host.render();
  const expected = `data:image/png;base64,${currentBytes.toString("base64")}`;
  assert.equal(find(host.current, node => node.type === "img").props.src, expected);
  images[0].resolve(imageResponse()); await settle(); host.render();
  assert.equal(find(host.current, node => node.type === "img").props.src, expected);
  refresh(); await settle(); host.render();
  host.unmount(); assert.equal(images[2].signal.aborted, true);
  images[2].resolve(imageResponse()); await settle();
  assert.equal(host.updatesAfterUnmount, 0);
});

for (const [status, type, content] of [[403, "image/png", png], [200, "text/html", "<html>unavailable</html>"], [200, "image/png", ""]])
  test(`invalid CAPTCHA image fetch is rejected (${status}, ${type}, ${content.length} bytes)`, async t => {
    environment(t, async url => url.includes("/image?") ? new Response(content, { status, headers: { "Content-Type": type } }) : response(imageChallenge));
    const host = mountHook(HumanChallenge, imageProps);
    await settle(); host.render(); await settle(); host.render();
    assert.equal(find(host.current, node => node.type === "img"), null);
    assert.match(JSON.stringify(host.current), /验证码图片无法读取/);
    host.unmount();
  });
