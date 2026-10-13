// Run with KIRO_PLAYWRIGHT_MODULE and, if needed, KIRO_BROWSER_PATH.
// The real application is mounted; every API call is intercepted locally.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const { chromium } = createRequire(import.meta.url)(process.env.KIRO_PLAYWRIGHT_MODULE || 'playwright');
let server, browser, address;
const accounts = Array.from({ length: 20 }, (_, index) => ({ id: index + 1, account_number: `a${index + 1}`,
  name: `AWS ${index + 1}`, aws_account_id: String(123456789000 + index), active: true, proxy_status: 'enabled' }));
const plans = [{ id: 1, name: 'Pro', active: true }, { id: 2, name: 'Power', active: true }];
const group = { id: 'group-a1', owner_id: 7, aws_account_id: 1, name: 'Existing team', state: 'ready', remote_id: 'aws-group-a1',
  revision: 8, policy: { mode: 'days', days: 9, revision: 3 } };
test.before(async () => {
  server = await createServer({ root: fileURLToPath(new URL('..', import.meta.url)), server: { host: '127.0.0.1', port: 0 } });
  await server.listen(); address = `http://127.0.0.1:${server.httpServer.address().port}/provisioning`;
  browser = await chromium.launch({ headless: true, ...(process.env.KIRO_BROWSER_PATH ? { executablePath: process.env.KIRO_BROWSER_PATH } : {}) });
});
test.after(async () => { await browser?.close(); await server?.close(); });
function preview(body) {
  const rows = body.accounts.map(row => ({ ...row, account_number: accounts[row.aws_account_id - 1].account_number,
    account_name: accounts[row.aws_account_id - 1].name, real_aws_account_id: accounts[row.aws_account_id - 1].aws_account_id,
    next_batch_number: `a${row.aws_account_id}-01`, plan_name: plans.find(plan => plan.id === row.plan_id).name,
    group: { mode: row.group.mode, id: row.group.group_id || null, name: row.group.group_id ? group.name : `a${row.aws_account_id}-01`, revision: row.group.expected_revision || null, policy_revision: row.group.expected_policy_revision || 0 },
    stop_policy: row.stop_policy || group.policy, policy_change: null, existing_member_count: row.group.group_id ? 2 : 0, needed_count: row.quantity }));
  return { preview_fingerprint: 'd'.repeat(64), accounts: rows, totals: [], number_is_estimate: true };
}
async function fixture(t, viewport = { width: 1440, height: 1000 }) {
  const page = await browser.newPage({ viewport }), previews = [], admissions = [], errors = [], unexpected = [];
  page.setDefaultTimeout(5000); page.on('pageerror', error => errors.push(error.message));
  await page.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    let body, status = 200;
    if (path === '/api/auth/me') body = { user: { id: 7, role: 'member', display_name: 'Shared settings test', active: true, account_ids: accounts.map(account => account.id), must_change_password: false }, csrf: 'local-test' };
    else if (path === '/api/accounts') body = accounts;
    else if (path === '/api/plans') body = plans;
    else if (path === '/api/groups') body = [group];
    else if (path === '/api/provisioning-batches' && request.method() === 'GET') body = { items: [], total: 0 };
    else if (path === '/api/provisioning-batches/preview') { const input = request.postDataJSON(); previews.push(input); body = preview(input); }
    else if (path === '/api/provisioning-batches' && request.method() === 'POST') { admissions.push(request.postDataJSON()); body = { detail: 'Local fixture: result not confirmed' }; status = 503; }
    else { unexpected.push(`${request.method()} ${path}`); body = { detail: 'Unexpected local API call' }; status = 404; }
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  });
  t.after(async () => { await page.close(); assert.deepEqual(errors, []); assert.deepEqual(unexpected, []); });
  await page.goto(address); await page.getByLabel('公共 新增人数', { exact: true }).waitFor();
  await page.getByRole('button', { name: '预览批次', exact: true }).waitFor();
  return { page, previews, admissions };
}
async function selectTwenty(page) {
  for (const account of accounts) await page.getByRole('checkbox', { name: `${account.account_number} · ${account.name} · ${account.aws_account_id}`, exact: true }).check();
  assert.equal(await page.locator('[data-testid^="provisioning-summary-"]').count(), 20);
}
async function choose(page, label, option) {
  await page.getByRole('combobox', { name: label, exact: true }).click();
  await page.getByRole('option', { name: option, exact: true }).click();
}

test('real page applies shared settings to twenty accounts, preserves overrides and freezes pending replay', async t => {
  const { page, previews, admissions } = await fixture(t);
  assert.match(await page.locator('.page-heading').innerText(), /真实 AWS 用户名与固定的内部 ID 相同/);
  await selectTwenty(page);
  assert.equal(await page.locator('.provisioning-account-fields').count(), 0);
  await page.getByLabel('公共 新增人数', { exact: true }).fill('4');
  await choose(page, '公共 停止方式', '开通后若干天');
  await page.getByLabel('公共 开通后天数', { exact: true }).fill('30');
  await page.getByLabel('公共 转换 JSON', { exact: true }).check();
  await choose(page, 'a1 分组', 'Existing team · 尚未开通 · 可用');
  await page.getByTestId('provisioning-customize-2').click();
  await page.getByLabel('a2 新增人数', { exact: true }).fill('2');
  await choose(page, 'a2 套餐', 'Power');
  await page.getByLabel('公共 新增人数', { exact: true }).fill('8');
  assert.match(await page.getByTestId('provisioning-summary-1').innerText(), /8 人 · Pro.*继承分组：开通后 9 天/s);
  assert.match(await page.getByTestId('provisioning-summary-2').innerText(), /2 人 · Power/s);
  await page.getByRole('button', { name: '预览批次', exact: true }).click();
  await page.getByRole('button', { name: '确认开通', exact: true }).waitFor();
  assert.equal(previews[0].accounts.length, 20); assert.equal(previews[0].accounts[1].quantity, 2); assert.equal(previews[0].accounts[1].plan_id, 2);
  assert.equal('stop_policy' in previews[0].accounts[0], false);
  assert.deepEqual(previews[0].accounts[0].group, { mode: 'existing', group_id: group.id, expected_revision: 8, expected_policy_revision: 3 });
  assert.deepEqual(previews[0].accounts[2].stop_policy, { mode: 'days', days: 30 });
  assert.equal(previews[0].accounts[2].exports.json, true);
  await page.getByLabel('公共 新增人数', { exact: true }).fill('10');
  assert.equal(await page.getByRole('button', { name: '确认开通', exact: true }).count(), 0, 'changing a common setting invalidates the preview');
  await page.getByTestId('provisioning-restore-2').click();
  assert.match(await page.getByTestId('provisioning-summary-2').innerText(), /10 人 · Pro/s);
  await page.getByTestId('provisioning-remove-20').click();
  await page.getByRole('checkbox', { name: 'a20 · AWS 20 · 123456789019', exact: true }).check();
  assert.match(await page.getByTestId('provisioning-summary-20').innerText(), /10 人 · Pro/s);
  if (process.env.KIRO_PROVISIONING_SCREENSHOTS) await page.locator('.provisioning-shared-configuration').screenshot({ path: `${process.env.KIRO_PROVISIONING_SCREENSHOTS}-desktop.png` });
  await page.getByRole('button', { name: '预览批次', exact: true }).click();
  await page.getByRole('button', { name: '确认开通', exact: true }).click();
  await page.getByRole('heading', { name: '继续确认原请求' }).waitFor();
  assert.equal(await page.getByLabel('公共 新增人数', { exact: true }).isDisabled(), true);
  assert.equal(await page.getByRole('combobox', { name: 'a1 分组', exact: true }).isDisabled(), true);
  assert.equal(await page.getByTestId('provisioning-customize-1').isDisabled(), true);
  assert.equal(await page.getByTestId('provisioning-remove-1').isDisabled(), true);
  const first = structuredClone(admissions[0]);
  await page.reload(); await page.getByRole('heading', { name: '继续确认原请求' }).waitFor();
  await page.getByRole('button', { name: '继续确认原请求', exact: true }).click();
  await page.getByText('Local fixture: result not confirmed', { exact: true }).waitFor();
  assert.equal(admissions.length, 2); assert.deepEqual(admissions[1], first, 'reload replays the saved immutable request');
});

test('compact summaries stay inside a scrolling table on narrow screens', async t => {
  const { page } = await fixture(t, { width: 390, height: 844 });
  await selectTwenty(page); await page.getByLabel('公共 新增人数', { exact: true }).fill('5');
  assert.equal(await page.locator('.provisioning-account-fields').count(), 0);
  const layout = await page.evaluate(() => ({ width: document.documentElement.clientWidth, scrollWidth: document.documentElement.scrollWidth,
    tableWidth: document.querySelector('.provisioning-selected-accounts table').getBoundingClientRect().width,
    viewportWidth: document.querySelector('.provisioning-selected-accounts .table-wrap').getBoundingClientRect().width }));
  assert.ok(layout.scrollWidth <= layout.width + 1, JSON.stringify(layout)); assert.ok(layout.tableWidth > layout.viewportWidth);
  if (process.env.KIRO_PROVISIONING_SCREENSHOTS) await page.screenshot({ path: `${process.env.KIRO_PROVISIONING_SCREENSHOTS}-mobile.png`, fullPage: true });
});

test('preview validates effective account settings when unused common settings are incomplete', async t => {
  const { page, previews } = await fixture(t);
  await page.getByRole('checkbox', { name: 'a1 · AWS 1 · 123456789000', exact: true }).check();
  await page.getByTestId('provisioning-customize-1').click();
  await page.getByLabel('公共 新增人数', { exact: true }).fill('');
  await choose(page, '公共 停止方式', '指定日期时间');
  await page.getByRole('button', { name: '预览批次', exact: true }).click();
  await page.getByRole('button', { name: '确认开通', exact: true }).waitFor();
  assert.equal(previews.length, 1); assert.equal(previews[0].accounts[0].quantity, 1);
  assert.deepEqual(previews[0].accounts[0].stop_policy, { mode: 'none' });
  await page.getByTestId('provisioning-restore-1').click();
  await page.getByRole('button', { name: '预览批次', exact: true }).click();
  await page.getByRole('alert').filter({ hasText: '新增人数须为 1–100' }).waitFor();
  assert.equal(previews.length, 1, 'invalid effective settings never reach server preview');
});

test('synchronization step shows real member progress without a failure alert', async t => {
  const { page } = await fixture(t);
  let confirmed = 2;
  await page.route('**/api/provisioning-batches/sync-batch', async route => {
    const items = Array.from({ length: 60 }, (_, index) => ({ record_id: `record-${index}`,
      internal_id: `a1-01-${index + 1}`, username: `a1-01-${index + 1}`,
      state: index < confirmed ? 'completed' : 'queued', phase: 'group_entitlement_pending',
      propagation_state: index < confirmed ? null : 'waiting', export_state: 'waiting',
      error: index < confirmed ? null : 'AWS 授权已确认，整体订阅尚未同步，等待只读核对' }));
    const row = { id: 'child', batch_number: 'a1-01', account_name: 'AWS 1', plan_name: 'Power',
      group: { id: group.id, name: 'a1-01' }, quantity: 60, phase: 'sso', state: 'running',
      error: 'AWS 授权已确认，整体订阅尚未同步，等待只读核对', allowed_actions: ['stop'],
      exports: { csv: true, txt: true, json: true }, stop_policy: { mode: 'none' },
      export_state: 'waiting', items };
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ id: 'sync-batch',
      actor_id: 7, state: 'running', phase: 'accounts', error: row.error, accounts: [row], totals: [] }) });
  });
  await page.goto(address + '?batch_id=sync-batch');
  const panel = page.locator('.provisioning-sync-progress');
  await panel.getByText('已同步 2 / 60 人', { exact: true }).waitFor();
  assert.equal(await panel.locator('progress').getAttribute('value'), '2');
  assert.equal(await panel.locator('progress').getAttribute('max'), '60');
  assert.equal(await page.locator('.provisioning-detail [role="alert"]').count(), 0);
  assert.equal(await page.locator('.provisioning-detail .badge.failed').count(), 0);
  confirmed = 14;
  await panel.getByText('已同步 14 / 60 人', { exact: true }).waitFor();
  if (process.env.KIRO_SYNC_SCREENSHOT) await panel.screenshot({ path: process.env.KIRO_SYNC_SCREENSHOT });
});
