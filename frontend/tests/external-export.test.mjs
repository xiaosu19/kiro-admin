import test from 'node:test';
import assert from 'node:assert/strict';
import { loadSource } from './load-source.mjs';
import { mountHook, settle } from './hooks.mjs';
const api = await loadSource('api');
const requests = await loadSource('externalExportRequests');
const logic = await loadSource('externalExportLogic');
const ui = await loadSource('ExternalJsonExport');
const { JsonExport } = await loadSource('JsonExport');
const { createElement: h } = await import('react');
const { renderToStaticMarkup: render } = await import('react-dom/server');
const { MemoryRouter } = await import('react-router-dom');
const fingerprint = 'b'.repeat(64);

function environment(t, fetch) {
  const oldWindow = globalThis.window, oldStorage = globalThis.sessionStorage, storage = new Map(), events = [];
  globalThis.window = { dispatchEvent: event => events.push(event.type) };
  globalThis.sessionStorage = { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) };
  t.mock.method(globalThis, 'fetch', fetch); api.setCsrf('session-a');
  t.after(() => {
    if (oldWindow === undefined) delete globalThis.window; else globalThis.window = oldWindow;
    if (oldStorage === undefined) delete globalThis.sessionStorage; else globalThis.sessionStorage = oldStorage;
  });
  return { storage, events };
}

test('lost pasted admission retains only original metadata through every error and reload', async t => {
  const calls = [], statuses = [408, 429, 403, 409, 200];
  const { storage } = environment(t, async (url, options) => {
    assert.equal(url, '/api/external-auth-batches'); assert.equal(options.cache, 'no-store');
    const body = JSON.parse(options.body); calls.push(body);
    const status = statuses.shift();
    return new Response(JSON.stringify(status === 200 ? { id: 'batch', actor_id: 7, request_key: body.request_key } : { detail: 'unknown outcome' }), { status });
  });
  let hook = mountHook(requests.useExternalAdmission, 7);
  for (let i = 0; i < 4; i++) {
    assert.equal(await hook.current.submit('Private9!', { total: 1, preview_fingerprint: fingerprint }), null);
    hook.render(); assert.ok(hook.current.pending);
    assert.doesNotMatch([...storage.values()].join(''), /Private9!/);
  }
  hook.unmount(); hook = mountHook(requests.useExternalAdmission, 7);
  assert.equal(calls.length, 4, 'reload does not automatically replay passwords');
  assert.equal((await hook.current.submit('Private9!', { total: 1, preview_fingerprint: fingerprint })).id, 'batch');
  hook.render(); assert.equal(hook.current.pending, null); assert.equal(storage.size, 0);
  assert.ok(calls.every(body => body.request_key === calls[0].request_key)); hook.unmount();
});

test('pasted admission rejects different contents while unresolved and serializes clicks', async t => {
  const calls = []; let finish;
  environment(t, (url, options) => { calls.push(JSON.parse(options.body)); return new Promise(resolve => { finish = resolve; }); });
  const hook = mountHook(requests.useExternalAdmission, 7), preview = { total: 1, preview_fingerprint: fingerprint };
  const send = hook.current.submit('Private9!', preview);
  assert.equal(await hook.current.submit('Private9!', preview), null); assert.equal(calls.length, 1);
  finish(new Response(JSON.stringify({ detail: 'unknown' }), { status: 503 })); await send; hook.render();
  assert.equal(await hook.current.submit('OtherSecret9!', { ...preview, preview_fingerprint: 'a'.repeat(64) }), null);
  hook.render(); assert.equal(calls.length, 1); assert.match(hook.current.error, /原请求不同/); hook.unmount();
});

test('late old-session pasted responses cannot affect a different actor or expire their login', async t => {
  const calls = []; let finish;
  const { events } = environment(t, (url, options) => { calls.push(options); return new Promise(resolve => { finish = resolve; }); });
  const hook = mountHook(requests.useExternalAdmission, 7), original = hook.current.submit;
  const send = original('Private9!', { total: 1, preview_fingerprint: fingerprint });
  hook.render(8); api.setCsrf('session-b');
  finish(new Response(JSON.stringify({ detail: 'expired' }), { status: 401 })); await send; await settle(); hook.render();
  assert.equal(hook.current.error, ''); assert.equal(hook.current.pending, null); assert.deepEqual(events, []);
  assert.equal(await original('Private9!', { total: 1, preview_fingerprint: fingerprint }), null);
  assert.equal(calls.length, 1); hook.unmount(); assert.equal(hook.updatesAfterUnmount, 0);
});

test('pasted export replay metadata never retains supplied credentials', () => {
  const pending = logic.externalPending(JSON.stringify({ request_key: 'a'.repeat(36), preview_fingerprint: fingerprint,
    password: 'Private9!', text: 'Private9!', accounts: [{ password: 'Private9!' }] }));
  assert.deepEqual(pending, { request_key: 'a'.repeat(36), preview_fingerprint: fingerprint });
  assert.equal(logic.externalPending('{bad'), null);
  assert.equal(logic.externalPending(JSON.stringify({ request_key: '', preview_fingerprint: fingerprint })), null);
  assert.deepEqual(logic.externalIntent({ total: 2, preview_fingerprint: fingerprint }, pending), pending);
  assert.throws(() => logic.externalIntent({ total: 101, preview_fingerprint: fingerprint }));
  assert.throws(() => logic.externalIntent({ total: 1, preview_fingerprint: 'c'.repeat(64) }, pending));
});

test('the JSON page opens pasted single/batch accounts from its own source tab and deep link', () => {
  const page = render(h(MemoryRouter, { initialEntries: ['/json-export?source=paste'] },
    h(JsonExport, { user: { id: 7, role: 'member' }, notify() {} })));
  assert.match(page, /粘贴账号转换/); assert.match(page, /粘贴单个或批量账号/);
  assert.match(page, /textarea/); assert.match(page, /解析并预览/);
  assert.match(page, /本人粘贴转换记录/); assert.doesNotMatch(page, /转换选中的 0 人/);
  assert.match(page, /默认 AWS access portal URL/);
  assert.match(page, /双栈 AWS access portal URL/);
});

test('pasted preview displays parsed identity and region with no credential columns', () => {
  const page = render(h(ui.PastedPreviewTable, { preview: { total: 1, preview_fingerprint: fingerprint,
    accounts: [{ username: 'our-user', portal_url: 'https://d-1234567890.awsapps.com/start', region: null, password: 'Private9!' }] } }));
  assert.match(page, /our-user/); assert.match(page, /从 AWS 入口自动读取/);
  assert.doesNotMatch(page, /Private9!|<th>密码/);
});

test('partial pasted conversion exposes actual successful downloads and recoverable password outcomes', () => {
  const batch = { id: 'batch', actor_id: 7, state: 'active', total: 2, success_count: 1, failure_count: 1,
    download_ready: true, created_at: '2026-10-11T00:00:00Z', expires_at: '2026-10-12T00:00:00Z', items: [
      { id: 'success', username: 'success-user', state: 'completed', retry_count: 0 },
      { id: 'failed', username: 'failed-user', state: 'needs_review', retry_count: 5, credential_recovery_available: true, error: '密码待核对' },
    ] };
  const page = render(h(ui.ExternalBatchTable, { batch, busy: false, onAction() {}, onDownload() {}, onChallenge() {} }));
  assert.match(page, /成功 1/); assert.match(page, /未成功 1/); assert.match(page, /下载此用户 JSON/);
  assert.match(page, /下载凭据恢复信息/); assert.match(page, /自动重试 5\/5/);
  const closed = render(h(ui.ExternalBatchTable, { batch: { ...batch, state: 'expired', download_ready: false }, busy: false, onAction() {}, onDownload() {}, onChallenge() {} }));
  assert.doesNotMatch(closed, /下载此用户 JSON|继续处理/); assert.match(closed, /下载凭据恢复信息/);
});
