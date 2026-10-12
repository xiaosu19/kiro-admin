import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { loadSource } from './load-source.mjs';
import { mountHook, settle } from './hooks.mjs';

// Existence assertions provide a useful red failure before adding source files.
const logic = existsSync(new URL('../src/provisioningLogic.ts', import.meta.url)) ? await loadSource('provisioningLogic') : {};
const hooks = existsSync(new URL('../src/provisioningRequests.ts', import.meta.url)) ? await loadSource('provisioningRequests') : {};
const { setCsrf } = await loadSource('api');
const { StopPolicyFields } = await loadSource('StopSchedule');
const response = (body, status = 200) => new Response(JSON.stringify(body), { status });
const account = { id: 1, account_number: 'a', name: 'Account A', aws_account_id: '123456789012', active: true, proxy_status: 'enabled' };
const group = { id: 'g', owner_id: 2, aws_account_id: 1, name: 'Owned group', state: 'ready', remote_id: 'aws-g', revision: 4, policy: { mode: 'days', days: 3, revision: 2 } };
const batch = body => ({ id: 'parent', actor_id: 2, request_key: body.request_key, accounts: body.accounts.map(r => ({ ...r, id: 'child', group: { ...r.group, id: r.group.group_id || 'new-group' } })) });
function environment(t, fetch) {
  const savedWindow = globalThis.window, savedStorage = globalThis.sessionStorage, storage = new Map(), events = [], intervals = [];
  globalThis.window = { setInterval(callback) { intervals.push(callback); return intervals.length; }, clearInterval() {}, dispatchEvent: event => events.push(event.type) };
  globalThis.sessionStorage = { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) };
  t.mock.method(globalThis, 'fetch', fetch); setCsrf('session-a');
  t.after(() => { globalThis.window = savedWindow; globalThis.sessionStorage = savedStorage; });
  return { storage, events, intervals };
}

test('independent account rows preserve explicit inheritance versus clearing, own groups and immutable replay', () => {
  assert.equal(typeof logic.accountDraft, 'function');
  const a = logic.accountDraft(account, 1), b = logic.accountDraft({ ...account, id: 2, account_number: 'b' }, 2);
  a.quantity = 5; a.exports.json = true;
  assert.equal(b.quantity, 1); assert.equal(b.exports.json, false);
  const inherited = logic.withGroup(a, group);
  const body = logic.provisioningBody([inherited, b], [account, { ...account, id: 2, account_number: 'b' }], [group], 2);
  assert.equal('stop_policy' in body.accounts[0], false);
  assert.equal(body.accounts[0].group.expected_policy_revision, 2);
  const clear = logic.provisioningBody([{ ...inherited, policyMode: 'change', policy: { mode: 'none' } }], [account], [group], 2);
  assert.deepEqual(clear.accounts[0].stop_policy, { mode: 'none' });
  assert.throws(() => logic.provisioningBody([inherited], [account], [{ ...group, owner_id: 3 }], 2), /分组/);
  const frozen = logic.provisioningIntent(body, 'a'.repeat(64));
  body.accounts[0].quantity = 99;
  assert.equal(frozen.accounts[0].quantity, 5);
  assert.ok(Object.isFrozen(frozen.accounts[0].exports));
  assert.equal(logic.withGroup(inherited, null).policy.mode, 'none');
});

test('search labels contain number/name/real AWS ID and filters combine 100+ groups', () => {
  assert.equal(typeof logic.accountLabel, 'function');
  assert.match(logic.accountLabel(account), /a.*Account A.*123456789012/);
  const groups = Array.from({ length: 125 }, (_, n) => ({ ...group, id: `g${n}`, name: `Team ${n}` }));
  assert.equal(logic.ownedGroups(groups, 2, 1).length, 125);
  assert.equal(logic.ownedGroups([...groups, { ...group, id: 'foreign', owner_id: 3 }], 2, 1).length, 125);
  assert.equal(new URLSearchParams(logic.historyQuery({ aws_account_id: 1, q: 'a-01-100', state: 'completed' })).get('q'), 'a-01-100');
});

test('admission double-click is one POST; uncertain retry freezes intent across GET-only reload; next batch can submit', async t => {
  assert.equal(typeof hooks.useProvisioningAdmission, 'function');
  let finish; const calls = [];
  const { storage } = environment(t, (_url, options) => {
    calls.push(JSON.parse(options.body));
    return calls.length === 1 ? new Promise(resolve => { finish = resolve; }) : Promise.resolve(response(batch(calls.at(-1)), 202));
  });
  const input = logic.provisioningIntent({ accounts: [{ aws_account_id: 1, quantity: 1, plan_id: 1, group: { mode: 'new' }, stop_policy: { mode: 'none' }, exports: { csv: true, txt: true, json: false } }] }, 'a'.repeat(64));
  let host = mountHook(hooks.useProvisioningAdmission, 2, 'scope');
  const sent = host.current.submit(input);
  assert.equal(await host.current.submit(input), null); assert.equal(calls.length, 1);
  finish(response({ detail: 'uncertain' }, 503)); await sent; host.render();
  assert.deepEqual(host.current.pending, input); host.unmount();
  host = mountHook(hooks.useProvisioningAdmission, 2, 'scope');
  assert.equal(calls.length, 1); assert.equal((await host.current.submit()).id, 'parent'); host.render();
  assert.deepEqual(calls[0], calls[1]); assert.equal(storage.size, 0);
  const second = logic.provisioningIntent({ accounts: input.accounts }, 'b'.repeat(64));
  assert.equal((await host.current.submit(second)).id, 'parent'); assert.notEqual(calls[2].request_key, calls[0].request_key);
  host.unmount();
});

test('preview is explicit and discards late private responses after scope or session change', async t => {
  assert.equal(typeof hooks.useProvisioningPreview, 'function');
  let finish; const calls = [];
  const { events } = environment(t, (url, options) => { calls.push({ url, options }); return new Promise(resolve => { finish = resolve; }); });
  const body = { accounts: [] };
  const host = mountHook(hooks.useProvisioningPreview, 2, 'scope-a', body);
  assert.equal(calls.length, 0);
  const pending = host.current.submit();
  host.render(3, 'scope-b', body); setCsrf('session-b');
  finish(response({ detail: 'old login' }, 401)); await pending; host.render();
  assert.equal(host.current.data, null); assert.deepEqual(events, []); host.unmount();
});

function find(node, predicate) {
  if (!node || typeof node !== 'object') return null;
  if (Array.isArray(node)) { for (const child of node) { const value = find(child, predicate); if (value) return value; } return null; }
  return predicate(node) ? node : find(node.props?.children, predicate);
}
test('shared stop fields support scoped controlled days and dates without leaking another account defaults', () => {
  let changed;
  const props = { namePrefix: 'a:', labelPrefix: 'a ', nativeGroup: true, value: { mode: 'days', days: 8 }, onChange: value => { changed = value; } };
  const host = mountHook(StopPolicyFields, props);
  const days = find(host.current, node => node.props?.name === 'a:stop_days');
  assert.ok(days); assert.equal(days.props.value, 8);
  days.props.onChange({ target: { value: '13' } }); assert.deepEqual(changed, { mode: 'days', days: 13 });
  host.render({ ...props, value: { mode: 'none' } });
  assert.equal(find(host.current, node => node.props?.name === 'a:stop_days'), null);
  const select = find(host.current, node => node.props?.name === 'a:stop_mode');
  assert.equal(select.props['aria-label'], 'a 停止方式'); host.unmount();
});

test('provisioning account rows expose scoped fields, owned group choices and explicit downloads', async () => {
  assert.ok(existsSync(new URL('../src/Provisioning.tsx', import.meta.url)));
  const { ProvisioningAccountFields, ProvisioningAccountPicker, ProvisioningDownloads } = await loadSource('Provisioning');
  const row = logic.withGroup(logic.accountDraft(account, 1), group);
  const tree = ProvisioningAccountFields({ account, row, groups: [group, { ...group, id: 'foreign', owner_id: 3 }], plans: [{ id: 1, name: 'Pro', active: true }], actorId: 2, disabled: false, onChange() {}, onRemove() {} });
  assert.ok(find(tree, node => node.props?.['aria-label'] === 'a 新增人数'));
  assert.ok(find(tree, node => node.props?.['aria-label'] === 'a 停止规则'));
  assert.equal(find(tree, node => node.type === 'option' && node.props.value === 'foreign'), null);
  const picker = ProvisioningAccountPicker({ accounts: Array.from({ length: 125 }, (_, i) => ({ ...account, id: i + 1 })), selected: [], search: '', onSearch() {}, onToggle() {}, disabled: false });
  assert.ok(find(picker, node => node.props?.['aria-label'] === '选择 AWS 账号'));
  const downloads = ProvisioningDownloads({ actorId: 2, batch: { id: 'b', actor_id: 2 }, account: { id: 'c', exports: { csv: true, txt: true, json: false }, items: [{ credentials_ready: true }] }, disabled: false, onDownload() {} });
  const menu = find(downloads, node => node.type?.name === 'LoginExportMenu');
  assert.ok(menu, 'login downloads share a format menu');
  assert.deepEqual(menu.props.scopes[0].formats, ['csv', 'txt']);
  assert.equal(find(downloads, node => node.type === 'button' && node.props.children === '下载 JSON ZIP'), null);
});

test('stopped batch resume is explicit, cancellable and submits only the scoped resume action', async () => {
  const { AccountProgress } = await loadSource('Provisioning');
  assert.equal(typeof AccountProgress, 'function');
  const calls = [];
  const row = { id: 'child', batch_number: 'a-01', account_name: 'AWS A', quantity: 2,
    group: { id: 'g', name: 'a-01' }, state: 'stopped', phase: 'sso',
    allowed_actions: ['resume'], exports: { csv: true, txt: true, json: false },
    stop_policy: { mode: 'none' }, items: [{ record_id: 'one', state: 'completed', internal_id: 'a-01-01', username: 'a-01-01' },
      { record_id: 'two', state: 'stopped', internal_id: 'a-01-02', username: 'a-01-02' }] };
  const props = { row, batch: { id: 'parent', actor_id: 2 }, user: { id: 2 }, disabled: false,
    run: (...args) => calls.push(args), download() {}, onAuth() {} };
  const host = mountHook(AccountProgress, props);
  const click = label => { const button = find(host.current, node => node.type === 'button' && node.props.children === label); assert.ok(button, label); button.props.onClick(); host.render(); };
  click('恢复未完成项'); assert.equal(calls.length, 0);
  assert.ok(find(host.current, node => node.props?.['aria-label'] === '确认恢复未完成项'));
  click('取消'); assert.equal(calls.length, 0);
  assert.equal(find(host.current, node => node.props?.['aria-label'] === '确认恢复未完成项'), null);
  click('恢复未完成项'); click('确认恢复');
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], '/provisioning-batches/parent/accounts/child/resume');
  assert.ok(calls[0][1].request_key.length >= 16);
  host.render({ ...props, disabled: true });
  assert.equal(find(host.current, node => node.type === 'button' && node.props.children === '恢复未完成项').props.disabled, true);
  host.render({ ...props, row: { ...row, state: 'completed', allowed_actions: [] } });
  assert.equal(find(host.current, node => node.type === 'button' && node.props.children === '恢复未完成项'), null);
  host.unmount();
});

test('failed-member retry stays scoped to the account and is hidden while running', async () => {
  const { AccountProgress } = await loadSource('Provisioning');
  const calls = [];
  const row = { id: 'failed-child', batch_number: 'a-01', account_name: 'AWS A', quantity: 2,
    group: { id: 'g', name: 'a-01' }, state: 'needs_review', phase: 'sso',
    allowed_actions: ['recheck', 'retry_failed', 'stop'], exports: { csv: true, txt: true, json: false },
    stop_policy: { mode: 'none' }, items: [{ record_id: 'one', state: 'prepared', internal_id: 'a-01-01', username: 'a-01-01' },
      { record_id: 'two', state: 'failed', internal_id: 'a-01-02', username: 'a-01-02' }] };
  const props = { row, batch: { id: 'parent', actor_id: 2 }, user: { id: 2 }, disabled: false,
    run: (...args) => calls.push(args), download() {}, onAuth() {} };
  const host = mountHook(AccountProgress, props);
  const retry = () => find(host.current, node => node.type === 'button' && node.props.children === '重试失败项');
  assert.ok(retry());
  retry().props.onClick();
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], '/provisioning-batches/parent/accounts/failed-child/retry_failed');
  assert.ok(calls[0][1].request_key.length >= 16);
  host.render({ ...props, disabled: true });
  assert.equal(retry().props.disabled, true);
  host.render({ ...props, row: { ...row, state: 'running', allowed_actions: ['stop'] } });
  assert.equal(retry(), null);
  host.unmount();
});

test('provisioning detail clears private rows and actions after authoritative forbidden polling', async t => {
  const ui = await loadSource('Provisioning'), { useGroupAccess } = await loadSource('groupRequests');
  assert.equal(typeof ui.ProvisioningBatchDetail, 'function');
  let status = 200; const calls = [];
  const { intervals } = environment(t, async (url, options) => { calls.push({ url, options }); return response(status === 200 ? { id: 'private', actor_id: 2, state: 'completed', created_at: '2026-10-11', accounts: [], totals: [] } : { detail: 'binding revoked' }, status); });
  function harness() { const access = useGroupAccess(2, 'scope'); return ui.ProvisioningBatchDetail({ id: 'private', user: { id: 2 }, scope: 'scope', access, notify() {} }); }
  const host = mountHook(harness); await settle(); host.render();
  assert.ok(find(host.current, node => node.type === 'h2' && node.props.children === '批次进度'));
  status = 403; intervals.at(-1)(); await settle(); host.render();
  assert.equal(find(host.current, node => node.type === 'h2' && node.props.children === '批次进度'), null);
  assert.ok(calls.every(call => call.options.method === 'GET')); host.unmount();
});

for (const scenario of ['group', 'sso', 'unfinished', 'replacement', 'unreadable', 'foreign', 'keyed'])
  test(`pending recovery reconciles ${scenario} only from the matching completed target`, async t => {
    const { ProvisioningBatchDetail } = await loadSource('Provisioning');
    const keyed = scenario === 'keyed', groupRetry = !['sso', 'replacement'].includes(scenario);
    const path = keyed ? '/provisioning-batches/parent/accounts/child/recheck' : groupRetry ? '/groups/g/retry' : '/subscriptions/r/retry';
    const body = keyed ? { request_key: 'original-recovery-request-key' } : undefined;
    const recovery = { kind: groupRetry ? 'group_retry' : 'sso_retry', method: 'POST', path: '/api' + path, read_only: false };
    const row = { id: 'child', aws_account_id: 1, account_name: 'AWS A', batch_number: 'a-01', quantity: 1,
      plan_id: 1, plan_name: 'Pro', group: { id: 'g', name: 'a-01' }, state: 'needs_review', phase: 'sso',
      group_job_state: 'failed', exports: { csv: true, txt: true, json: false }, allowed_actions: ['recheck'],
      stop_policy: { mode: 'none' }, recovery, items: [{ record_id: 'r', username: 'real-user', internal_id: 'a-01-01',
        state: 'failed', record_state: 'failed', phase: 'sso', credentials_ready: true, recovery: groupRetry ? null : recovery }] };
    let parent = { id: 'parent', actor_id: 2, state: 'needs_review', phase: 'sso', created_at: '2026-10-11', accounts: [row], totals: [] };
    const posts = [], gets = [], notices = [];
    const { storage } = environment(t, async (url, options) => {
      if (options.method === 'GET') {
        gets.push(url);
        if (posts.length > 1 && scenario === 'unreadable') return response({ detail: 'cannot refresh' }, 503);
        return response(posts.length > 1 && scenario === 'foreign' ? { ...parent, actor_id: 8 } : parent);
      }
      posts.push({ url, body: options.body });
      if (posts.length > 1) return response({ detail: 'no retryable operation remains' }, 409);
      if (scenario !== 'unfinished') {
        const nextRecovery = scenario === 'replacement' ? { ...recovery, kind: 'reset_password', path: '/api/subscriptions/r/operations' } : null;
        parent = { ...parent, state: 'completed', accounts: [{ ...row, state: 'completed', group_job_state: 'completed',
          phase: 'done', recovery: nextRecovery, allowed_actions: [], items: [{ ...row.items[0], state: 'completed',
            record_state: scenario === 'replacement' ? 'failed' : 'completed', recovery: nextRecovery }] }] };
      }
      return response({ detail: 'response lost after acceptance' }, 503);
    });
    const props = { id: 'parent', user: { id: 2 }, scope: 'scope', access: { canAccess: () => true, deny() {} }, notify: message => notices.push(message) };
    let host = mountHook(ProvisioningBatchDetail, props);
    await settle(); host.render();
    await find(host.current, node => node.props?.row?.id === 'child').props.run(path, body);
    host.render(); host.unmount();
    host = mountHook(ProvisioningBatchDetail, props);
    await settle(); host.render();
    assert.equal(posts.length, 1, 'reload only reads progress');
    await find(host.current, node => node.type === 'button' && node.props.children === '继续确认原操作').props.onClick();
    await settle(); host.render();
    assert.deepEqual(posts, [{ url: '/api' + path, body: body && JSON.stringify(body) }, { url: '/api' + path, body: body && JSON.stringify(body) }]);
    const resolved = ['group', 'sso'].includes(scenario);
    assert.equal(find(host.current, node => node.props?.row?.id === 'child').props.disabled, !resolved);
    assert.equal(!!storage.get('kiro-provisioning-action:2:parent'), !resolved);
    assert.equal(notices.length, resolved ? 1 : 0);
    if (resolved) { assert.match(notices[0], /最新进度.*完成/); assert.ok(gets.length >= 3); }
    host.unmount();
    host = mountHook(ProvisioningBatchDetail, props);
    await settle(); host.render();
    if (scenario !== 'unreadable') assert.equal(!!find(host.current, node => node.type === 'button' && node.props.children === '继续确认原操作'), !resolved);
    assert.equal(!!storage.get('kiro-provisioning-action:2:parent'), !resolved);
    assert.equal(posts.length, 2); host.unmount();
  });

test('a scoped download whose Blob completes after session replacement cannot save a file', async t => {
  const { downloadProvisioning } = await loadSource('api');
  let completeBlob;
  environment(t, async () => ({ ok: true, blob: () => new Promise(resolve => { completeBlob = resolve; }) }));
  const pending = downloadProvisioning('/provisioning-batches/p/download', 'POST', undefined);
  await settle(); setCsrf('different-session'); completeBlob(new Blob(['private-result']));
  assert.equal(await pending, null);
});

test('filtered report download discards old filter and unmounted completions', async t => {
  assert.equal(typeof hooks.useProvisioningReport, 'function');
  let finish;
  environment(t, () => new Promise(resolve => { finish = resolve; }));
  const host = mountHook(hooks.useProvisioningReport, 2, 'aws=1');
  const first = host.current.download('/provisioning-batches/report?aws_account_id=1');
  host.render(2, 'aws=2'); finish(response({ detail: 'old scope' }, 403));
  assert.equal(await first, null); host.render(); assert.equal(host.current.error, '');
  const second = host.current.download('/provisioning-batches/report?aws_account_id=2');
  host.unmount(); finish(response({ detail: 'unmounted' }, 500));
  assert.equal(await second, null); assert.equal(host.updatesAfterUnmount, 0);
});
