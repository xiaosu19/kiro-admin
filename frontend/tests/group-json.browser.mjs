// Entirely local API fixtures: no AWS requests, live users, or real credentials.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const { chromium } = createRequire(import.meta.url)(process.env.KIRO_PLAYWRIGHT_MODULE || 'playwright');
let server, browser, address;
const ids = Array.from({ length: 5 }, (_, n) => 'fixture-group-' + n);
const groups = ids.map((id, n) => ({ id, name: 'Fixture group ' + n, owner_id: 7, aws_account_id: 1, state: 'ready',
  revision: 1, remote_id: 'remote-' + n, active_job_id: null, policy: { revision: 1, mode: 'none' }, counts: { total: 100 } }));
const preview = { id: 'fixture-preview', fingerprint: 'a'.repeat(64), expires_at: '2030-10-11T12:00:00Z', total: 500,
  eligible_count: 500, skipped_count: 0, groups: groups.map(group => ({ ...group, account_name: 'Fixture AWS', account_number: 'a',
    total: 100, eligible_count: 100, skipped_count: 0, members: Array.from({ length: 100 }, (_, n) => ({
      record_id: group.id + '-member-' + n, username: group.id + '-actual-' + n, email: 'fake@example.com',
      sso_user_id: group.id + '-sso-' + n, skip_reason: null,
    })) })) };
const batch = { id: 'fixture-auth-batch', actor_id: 7, kind: 'json_export', group_id: null, state: 'active', total: 500,
  created_at: '2030-10-11T00:00:00Z', expires_at: '2030-10-12T00:00:00Z', completed_at: '2030-10-11T00:20:00Z',
  download_expires_at: '2030-10-11T00:35:00Z', states: { completed: 499, needs_review: 1 }, success_count: 499,
  failure_count: 1, download_ready: true, group_scope: { total: 500, eligible_count: 500, skipped_count: 0,
    groups: preview.groups.map(({ members, ...group }, n) => ({ ...group, states: n === 4 ? { completed: 99, needs_review: 1 } : { completed: 100 } })) },
  items: preview.groups.flatMap(g => g.members).map((member, n) => ({ record_id: member.record_id, username: member.username,
    operation_id: 'operation-' + n, owner_id: 7, state: n === 499 ? 'needs_review' : 'completed', credential_state: 'permanent',
    error: n === 499 ? 'Fixture member requires review' : null, error_code: null, requires_new_reset: false })) };
test.before(async () => {
  server = await createServer({ root: fileURLToPath(new URL('..', import.meta.url)), server: { host: '127.0.0.1', port: 0 } });
  await server.listen(); address = `http://127.0.0.1:${server.httpServer.address().port}`;
  browser = await chromium.launch({ headless: true, ...(process.env.KIRO_BROWSER_PATH ? { executablePath: process.env.KIRO_BROWSER_PATH } : {}) });
});
test.after(async () => { await browser?.close(); await server?.close(); });

test('five entire groups preview five hundred users, recover exact admission after GET-only reload, and download successful results', async t => {
  const context = await browser.newContext({ acceptDownloads: true }), page = await context.newPage();
  const admissions = [], previews = [], unexpected = [], errors = [], writes = [];
  page.setDefaultTimeout(7000); page.on('pageerror', e => errors.push(e.message));
  await page.route('**/api/**', async route => {
    const req = route.request(), path = new URL(req.url()).pathname;
    let body, status = 200;
    if (req.method() !== 'GET') { writes.push(path); assert.equal(req.headers()['x-csrf-token'], 'fixture-csrf'); }
    if (path === '/api/auth/me') body = { user: { id: 7, role: 'member', display_name: 'Fixture user', active: true,
      account_ids: [1], must_change_password: false }, csrf: 'fixture-csrf' };
    else if (path === '/api/accounts') body = [{ id: 1, name: 'Fixture AWS', active: true, account_number: 'a' }];
    else if (path === '/api/groups') body = groups;
    else if (path === '/api/group-json-exports/preview') { previews.push(req.postDataJSON()); body = preview; }
    else if (path === '/api/group-json-exports') {
      admissions.push(req.postDataJSON()); status = admissions.length === 1 ? 503 : 202;
      body = admissions.length === 1 ? { detail: 'Fixture group outcome unknown' } : batch;
    } else if (path === '/api/auth-batches') body = { items: admissions.length > 1 ? [batch] : [], page: 1 };
    else if (path === '/api/auth-batches/fixture-auth-batch') body = batch;
    else if (path === '/api/auth-batches/fixture-auth-batch/download') {
      assert.equal(req.method(), 'POST');
      await route.fulfill({ status: 200, contentType: 'application/zip', headers: { 'Content-Disposition': 'attachment; filename="2026-10-11-batch-fixture.zip"',
        'Cache-Control': 'no-store', 'X-Export-Count': '499', 'X-Excluded-Count': '1' }, body: 'local-fixture-zip' }); return;
    } else { unexpected.push(`${req.method()} ${path}`); status = 404; body = { detail: 'Unexpected fixture call' }; }
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  });
  t.after(async () => { await context.close(); assert.deepEqual(errors, []); assert.deepEqual(unexpected, []); });
  const query = new URLSearchParams({ source: 'group' }); ids.forEach(id => query.append('group_id', id));
  await page.goto(`${address}/json-export?${query}`);
  await page.getByRole('button', { name: '预览选中 5 个完整分组', exact: true }).click();
  assert.deepEqual(previews, [{ group_ids: ids }]);
  await page.getByText('本次 5 个分组，共 500 名成员；转换 500 人，跳过 0 人。', { exact: false }).waitFor();
  const submit = page.getByRole('button', { name: '转换 5 组的 500 人', exact: true });
  assert.equal(await submit.isDisabled(), true);
  await page.getByLabel('我已核对完整范围，并同意首次登录可能更新所选用户的永久密码').check();
  await submit.click(); await page.getByText('Fixture group outcome unknown', { exact: true }).waitFor();
  const original = structuredClone(admissions[0]);
  await page.reload(); await page.getByRole('button', { name: '继续原整组请求', exact: true }).waitFor();
  assert.equal(admissions.length, 1); assert.equal(previews.length, 1, 'reload never repeats previews or submissions');
  await page.getByRole('button', { name: '继续原整组请求', exact: true }).click();
  await page.getByText('Fixture member requires review', { exact: true }).waitFor();
  assert.deepEqual(admissions, [original, original]);
  await page.getByLabel('冻结成员范围').getByRole('cell', { name: /Fixture group 4/ }).waitFor();
  const download = page.waitForEvent('download');
  await page.getByRole('button', { name: '下载 499 份 JSON（ZIP）', exact: true }).click();
  assert.equal((await download).suggestedFilename(), '2026-10-11-batch-fixture.zip');
  assert.deepEqual(writes, ['/api/group-json-exports/preview', '/api/group-json-exports', '/api/group-json-exports', '/api/auth-batches/fixture-auth-batch/download']);
});
