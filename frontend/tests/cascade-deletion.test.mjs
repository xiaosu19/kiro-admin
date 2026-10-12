import test from 'node:test';
import assert from 'node:assert/strict';
import { loadSource } from './load-source.mjs';
import { mountHook, settle } from './hooks.mjs';
const api = await loadSource('api');
const requests = await loadSource('cascadeRequests');
const ui = await loadSource('CascadeDeletion');
const { createElement: h } = await import('react');
const { renderToStaticMarkup } = await import('react-dom/server');
const response = (body, status = 200) => new Response(JSON.stringify(body), { status });
const preview = (target = 'r-one', kind = 'sso') => ({ id: 'preview-' + target, kind, fingerprint: 'a'.repeat(64),
  confirm_text: kind === 'sso' ? '删除 1 名 SSO' : '删除 1 个分组和 1 名 SSO', expires_at: '2026-10-11T12:00:00Z',
  fee_notice: '费用与次数历史保留', counts: { groups: kind === 'group' ? 1 : 0, sso_users: 1, user_subscriptions: 1, group_subscriptions: kind === 'group' ? 1 : 0 },
  items: [{ target_id: target, owner_id: 2, aws_account_id: 1, account_name: 'AWS test', group_name: 'test group', group_id: 'g',
    members: [{ id: 'r-one', username: 'actual-member', email: 'member@example.com', sso_user_id: 'sso-one', sso_deleted_at: null, user_type: 'PRO', group_type: 'PRO' }] }] });
const batch = (value = preview()) => ({ id: 'admitted-batch', kind: value.kind, confirm_text: value.confirm_text, state: 'needs_review',
  counts: { total: 1, completed: 0, queued: 0, running: 0, needs_review: 1, failed: 0 }, actions: { recheck: true, retry: false }, created_at: '2026-10-11T00:00:00Z',
  items: value.items.map(item => ({ ...item, id: 'task', completed_steps: 1, total_steps: 2, state: 'needs_review', error: 'unknown deletion result',
    steps: [{ kind: 'cancel_user', record_id: 'r-one', label: '取消独立 USER 订阅', state: 'completed' }, { kind: 'delete_sso', record_id: 'r-one', label: '删除 SSO 并确认已不存在', state: 'pending' }] })) });

function environment(t, fetch) {
  const oldWindow = globalThis.window, oldStorage = globalThis.sessionStorage, storage = new Map(), events = [];
  globalThis.window = { setInterval() {}, clearInterval() {}, dispatchEvent: event => events.push(event.type) };
  globalThis.sessionStorage = { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) };
  t.mock.method(globalThis, 'fetch', fetch); api.setCsrf('session-a');
  t.after(() => {
    if (oldWindow === undefined) delete globalThis.window; else globalThis.window = oldWindow;
    if (oldStorage === undefined) delete globalThis.sessionStorage; else globalThis.sessionStorage = oldStorage;
  });
  return { storage, events };
}

test('cascade selection uses exact unique IDs and never a query-wide scope', () => {
  assert.equal(typeof api.cascadeSelection, 'function');
  assert.deepEqual(api.cascadeSelection('sso', ['r-two', 'r-one', 'r-two']), { kind: 'sso', record_ids: ['r-one', 'r-two'] });
  assert.deepEqual(api.cascadeSelection('group', ['g-one']), { kind: 'group', group_ids: ['g-one'] });
  assert.throws(() => api.cascadeSelection('sso', []));
  assert.throws(() => api.cascadeSelection('group', Array.from({ length: 101 }, (_, i) => 'g' + i)));
});

test('lost deletion admission retains the exact preview and key across errors and remounts', async t => {
  const calls = [], value = preview();
  const { storage } = environment(t, async (url, options) => {
    assert.equal(url, '/api/cascade-deletions'); assert.equal(options.cache, 'no-store'); calls.push(JSON.parse(options.body));
    if (calls.length === 1) throw new TypeError('response lost after commit');
    if (calls.length === 2) return response({ detail: '预览已过期' }, 409);
    return response(batch(value));
  });
  let hook = mountHook(requests.useCascadeAdmission, 2, 'scope');
  assert.equal(await hook.current.submit(value), null); hook.render(); const intent = structuredClone(hook.current.pending);
  assert.equal(await hook.current.submit(), null); hook.render(); assert.deepEqual(hook.current.pending, intent);
  hook.unmount(); hook = mountHook(requests.useCascadeAdmission, 2, 'scope');
  assert.equal(calls.length, 2, 'remount never submits a destructive request');
  assert.equal((await hook.current.submit(preview('other-record'))).id, 'admitted-batch'); hook.render();
  assert.deepEqual(calls, [calls[0], calls[0], calls[0]]); assert.equal(hook.current.pending, null); assert.equal(storage.size, 0); hook.unmount();
});

test('deletion submissions serialize clicks and late actor/session results cannot update the new login', async t => {
  const calls = []; let finish;
  const { events } = environment(t, (url, options) => { calls.push([url, options]); return new Promise(resolve => { finish = resolve; }); });
  const hook = mountHook(requests.useCascadeAdmission, 2, 'scope');
  const send = hook.current.submit(preview()); assert.equal(await hook.current.submit(preview()), null); assert.equal(calls.length, 1);
  const old = hook.current.submit; hook.render(3, 'scope'); api.setCsrf('session-b');
  finish(response({ detail: 'old session expired' }, 401)); assert.equal(await send, null); hook.render();
  assert.equal(hook.current.pending, null); assert.equal(hook.current.error, ''); assert.deepEqual(events, []);
  assert.equal(await old(preview()), null); assert.equal(calls.length, 1); hook.unmount();
});

test('a second mounted deletion surface cannot overwrite an unresolved destructive request', async t => {
  const calls = [];
  const { storage } = environment(t, async (_url, options) => { calls.push(JSON.parse(options.body)); throw new TypeError('response lost'); });
  const first = mountHook(requests.useCascadeAdmission, 2, 'directory');
  const second = mountHook(requests.useCascadeAdmission, 2, 'record-detail');
  await first.current.submit(preview('r-one')); first.render(); const original = [...storage.values()][0];
  await second.current.submit(preview('r-two')); second.render();
  assert.equal(calls.length, 1); assert.equal([...storage.values()][0], original);
  assert.equal(second.current.pending.body.preview_id, 'preview-r-one');
  first.unmount(); second.unmount();
});

test('a changed selection discards stale AWS deletion preview and old callbacks', async t => {
  const calls = [];
  environment(t, (url, options) => new Promise(resolve => calls.push({ url, options, resolve })));
  const hook = mountHook(requests.useCascadePreview, 2, 'scope', api.cascadeSelection('sso', ['r-one']));
  const old = hook.current.refresh;
  hook.render(2, 'scope', api.cascadeSelection('sso', ['r-two']));
  assert.equal(calls.length, 2);
  calls[0].resolve(response(preview('r-one'))); await settle(); hook.render(); assert.equal(hook.current.data, null);
  calls[1].resolve(response(preview('r-two'))); await settle(); hook.render(); assert.equal(hook.current.data.id, 'preview-r-two');
  await old(); assert.equal(calls.length, 2); hook.unmount();
});

test('progress exposes only server allowed recovery and shows actual targets and pending fences', () => {
  const html = renderToStaticMarkup(h(ui.CascadeProgress, { batch: batch(), busy: false, onAction() {} }));
  assert.match(html, /actual-member/); assert.match(html, /sso-one/); assert.match(html, /只读核对原 AWS 写入/);
  assert.match(html, /等待只读核对/); assert.match(html, /unknown deletion result/); assert.doesNotMatch(html, /明确继续未发送步骤/);
  const scope = renderToStaticMarkup(h(ui.CascadeScopePreview, { value: preview('g-one', 'group') }));
  assert.match(scope, /先立即取消整组 GROUP 和成员独立 USER 订阅/); assert.match(scope, /actual-member/); assert.match(scope, /创建者 ID 2/);
  assert.match(scope, /费用与次数历史保留/);
});
