import test from 'node:test';
import assert from 'node:assert/strict';
import { loadSource } from './load-source.mjs';
import { mountHook, settle } from './hooks.mjs';
const api = await loadSource('api');
const requests = await loadSource('groupJsonRequests');
const response = (body, status = 200) => new Response(JSON.stringify(body), { status });
const preview = (ids = ['g-one'], quantity = 1) => ({ id: 'frozen-preview', fingerprint: 'a'.repeat(64), expires_at: '2030-10-11T12:00:00Z',
  total: ids.length * quantity, eligible_count: ids.length * quantity, skipped_count: 0,
  groups: ids.map((id, index) => ({ id, name: 'whole-' + id, owner_id: 7, aws_account_id: index + 1, account_name: 'AWS-' + index,
    account_number: 'number-' + index, revision: 1, total: quantity, eligible_count: quantity, skipped_count: 0,
    members: Array.from({ length: quantity }, (_, n) => ({ record_id: 'r-' + id + '-' + n, username: 'actual-' + id + '-' + n,
      email: 'fake@example.com', sso_user_id: 'sso-' + id + '-' + n, skip_reason: null })) })) });
const batch = value => ({ id: 'admitted-group-batch', actor_id: 7, kind: 'json_export', total: value.eligible_count,
  group_id: null, state: 'active', states: { queued: value.eligible_count }, success_count: 0, failure_count: 0, group_scope: {
    total: value.total, eligible_count: value.eligible_count, skipped_count: value.skipped_count,
    groups: value.groups.map(({ members, ...group }) => ({ ...group, states: { queued: group.eligible_count } })),
  } });
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

test('whole and multi-group JSON navigation freezes exact distinct group IDs', () => {
  assert.equal(typeof api.groupJsonSelection, 'function');
  assert.deepEqual(api.groupJsonSelection(['g-two', 'g-one', 'g-two']), { group_ids: ['g-one', 'g-two'] });
  const path = api.groupJsonUrl(['group & first', 'g-two']);
  const params = new URL(path, 'https://local.test').searchParams;
  assert.equal(params.get('source'), 'group');
  assert.deepEqual(params.getAll('group_id'), ['g-two', 'group & first']);
  assert.throws(() => api.groupJsonSelection([]));
  assert.throws(() => api.groupJsonSelection(Array.from({ length: 101 }, (_, i) => 'g-' + i)));
});

test('whole-group picker retains multiple groups through filters and never turns counts into manual selection', async () => {
  const ui = await loadSource('AuthSelection');
  assert.equal(typeof ui.GroupJsonPicker, 'function');
  const { createElement: h } = await import('react');
  const { renderToStaticMarkup } = await import('react-dom/server');
  const groups = [{ id: 'g-one', name: 'whole-first', aws_account_id: 1, counts: { total: 100 } },
    { id: 'g-two', name: 'whole-second', aws_account_id: 2, counts: { total: 100 } }];
  const html = renderToStaticMarkup(h(ui.GroupJsonPicker, { groups, accounts: [], selected: ['g-one', 'g-two'], disabled: false, onChange() {} }));
  assert.match(html, /whole-first/); assert.match(html, /whole-second/); assert.match(html, /筛选不改变已选分组/);
  assert.match(html, /选择整个 whole-first/); assert.doesNotMatch(html, /最多 100 人|选择.*用户/);
});

test('group deep link opens whole and multiple group conversion alongside existing private history', async () => {
  const { JsonExport } = await loadSource('JsonExport');
  const { createElement: h } = await import('react');
  const { renderToStaticMarkup } = await import('react-dom/server');
  const { MemoryRouter } = await import('react-router-dom');
  const html = renderToStaticMarkup(h(MemoryRouter, { initialEntries: ['/json-export?source=group&group_id=g-one&group_id=g-two'] },
    h(JsonExport, { user: { id: 7, role: 'member' }, notify() {} })));
  assert.match(html, /整组 \/ 多组 JSON 导出/); assert.match(html, /已选.*2.*100 个完整分组/);
  assert.match(html, /5000/); assert.match(html, /本人历史记录/); assert.match(html, /粘贴账号转换/);
  assert.doesNotMatch(html, /预览分组用户|转换选中的 0 人/);
});

test('five complete groups keep five hundred members and refuse truncated or duplicate previews', () => {
  const value = preview(['g-one', 'g-two', 'g-three', 'g-four', 'g-five'], 100);
  assert.equal(requests.validGroupJsonPreview(value, value.groups.map(g => g.id)), true);
  assert.equal(requests.validGroupJsonPreview({ ...value, eligible_count: 100 }, value.groups.map(g => g.id)), false);
  const duplicate = structuredClone(value);
  duplicate.groups[1].members[0] = duplicate.groups[0].members[0];
  assert.equal(requests.validGroupJsonPreview(duplicate, value.groups.map(g => g.id)), false);
});

test('group preview waits for explicit action and discards a stale account or group selection response', async t => {
  const calls = [];
  environment(t, (url, options) => new Promise(resolve => calls.push({ url, options, resolve })));
  const hook = mountHook(requests.useGroupJsonPreview, 7, 'account-config-a', ['g-one']);
  assert.equal(calls.length, 0, 'mount only shows selection, never previews or submits');
  const old = hook.current.refresh, first = hook.current.refresh();
  hook.render(7, 'account-config-b', ['g-two']);
  const second = hook.current.refresh();
  calls[0].resolve(response(preview(['g-one']))); await first; hook.render(); assert.equal(hook.current.data, null);
  calls[1].resolve(response(preview(['g-two']))); await second; hook.render(); assert.equal(hook.current.data.groups[0].id, 'g-two');
  await old(); assert.equal(calls.length, 2); hook.unmount();
});

test('ambiguous multi-group submission retains the exact five hundred member preview and key through reload and expiry', async t => {
  const calls = [], value = preview(['g-one', 'g-two', 'g-three', 'g-four', 'g-five'], 100);
  const { storage } = environment(t, async (url, options) => {
    assert.equal(url, '/api/group-json-exports'); assert.equal(options.cache, 'no-store'); calls.push(JSON.parse(options.body));
    if (calls.length === 1) throw new TypeError('response lost after commit');
    if (calls.length === 2) return response({ detail: '预览已过期' }, 409);
    return response(batch(value));
  });
  let hook = mountHook(requests.useGroupJsonAdmission, 7, 'scope');
  assert.equal(await hook.current.submit(value), null); hook.render(); const intent = structuredClone(hook.current.pending);
  assert.equal(intent.eligible_count, 500); assert.equal(intent.group_ids.length, 5);
  await hook.current.submit(); hook.render(); assert.deepEqual(hook.current.pending, intent);
  hook.unmount(); hook = mountHook(requests.useGroupJsonAdmission, 7, 'scope');
  assert.equal(calls.length, 2, 'reload never resubmits any password-affecting operation');
  assert.equal((await hook.current.submit(preview(['replacement']))).id, 'admitted-group-batch'); hook.render();
  assert.deepEqual(calls, [calls[0], calls[0], calls[0]]); assert.equal(storage.size, 0); assert.equal(hook.current.pending, null); hook.unmount();
});

test('late group submission from an old actor or CSRF session cannot change the current login', async t => {
  let finish; const calls = [];
  const { events } = environment(t, (url, options) => { calls.push([url, options]); return new Promise(resolve => { finish = resolve; }); });
  const hook = mountHook(requests.useGroupJsonAdmission, 7, 'member');
  const send = hook.current.submit(preview()); assert.equal(await hook.current.submit(preview()), null);
  const old = hook.current.submit; hook.render(8, 'member'); api.setCsrf('session-b');
  finish(response({ detail: 'expired old login' }, 401)); await send; hook.render();
  assert.equal(hook.current.pending, null); assert.equal(hook.current.error, ''); assert.deepEqual(events, []);
  assert.equal(await old(preview()), null); assert.equal(calls.length, 1); hook.unmount();
});

test('another group composer cannot replace an unresolved original conversion scope', async t => {
  const calls = [];
  environment(t, async (_url, options) => { calls.push(JSON.parse(options.body)); throw new TypeError('lost'); });
  const first = mountHook(requests.useGroupJsonAdmission, 7, 'first'), second = mountHook(requests.useGroupJsonAdmission, 7, 'second');
  await first.current.submit(preview(['g-one'])); await second.current.submit(preview(['g-two'])); second.render();
  assert.equal(calls.length, 1); assert.deepEqual(second.current.pending.group_ids, ['g-one']); first.unmount(); second.unmount();
});

test('group scope preview shows every original group and independent eligible and skipped counts', async () => {
  const { GroupJsonScopePreview } = await loadSource('GroupJsonExport');
  const { createElement: h } = await import('react');
  const { renderToStaticMarkup } = await import('react-dom/server');
  const value = preview(['g-one', 'g-two'], 100);
  value.groups[1].members[0].skip_reason = '没有可恢复的登录凭据'; value.groups[1].eligible_count--; value.groups[1].skipped_count++;
  value.eligible_count--; value.skipped_count++;
  const html = renderToStaticMarkup(h(GroupJsonScopePreview, { value }));
  assert.match(html, /转换 199 人，跳过 1 人/); assert.match(html, /转换 100 \/ 100 人/); assert.match(html, /转换 99 \/ 100 人/);
  assert.match(html, /actual-g-two-0/); assert.match(html, /没有可恢复的登录凭据/); assert.match(html, /账号编号 \/ 用户名.json/);
});

test('group history and progress keep frozen per-group counts alongside current auth job states', async () => {
  const { AuthBatchView } = await loadSource('AuthBatches');
  const { createElement: h } = await import('react');
  const { renderToStaticMarkup } = await import('react-dom/server');
  const value = batch(preview(['g-one', 'g-two'], 100));
  const html = renderToStaticMarkup(h(AuthBatchView, { batch: value, busy: false, onAction() {}, onDownload() {}, onChallenge() {} }));
  assert.match(html, /whole-g-one/); assert.match(html, /whole-g-two/); assert.match(html, /number-0/);
  assert.match(html, /冻结成员范围/); assert.match(html, /等待 100/);
});
