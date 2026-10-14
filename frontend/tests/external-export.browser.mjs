// Mount the real page with local API fixtures. No credentials leave this browser.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';

const { chromium } = createRequire(import.meta.url)(process.env.KIRO_PLAYWRIGHT_MODULE || 'playwright');
let server, browser, address;
const fingerprint = 'a'.repeat(64);
const pasted = 'https://d-1234567890.awsapps.com/start----us-east-1----fixture-user----FixturePassword9!';
const account = { username: 'fixture-user', portal_url: 'https://d-1234567890.awsapps.com/start', region: 'us-east-1' };
const preview = { total: 1, accounts: [account], preview_fingerprint: fingerprint };
const batch = { id: 'external-fixture', actor_id: 7, state: 'active', total: 2, success_count: 1, failure_count: 1,
  download_ready: true, created_at: '2026-10-11T00:00:00Z', expires_at: '2026-10-12T00:00:00Z', items: [
    { ...account, id: 'success', state: 'completed', retry_count: 0 },
    { ...account, username: 'failed-fixture', id: 'failed', state: 'needs_review', retry_count: 5,
      error: 'Fixture password requires review', credential_recovery_available: true },
  ] };
test.before(async () => {
  server = await createServer({ root: fileURLToPath(new URL('..', import.meta.url)), server: { host: '127.0.0.1', port: 0 } });
  await server.listen(); address = `http://127.0.0.1:${server.httpServer.address().port}`;
  browser = await chromium.launch({ headless: true, ...(process.env.KIRO_BROWSER_PATH ? { executablePath: process.env.KIRO_BROWSER_PATH } : {}) });
});
test.after(async () => { await browser?.close(); await server?.close(); });

async function fixture(t, { admit, download, denied, progress, retry } = {}) {
  const context = await browser.newContext({ acceptDownloads: true }), page = await context.newPage();
  const admissions = [], unexpected = [], errors = [], downloads = [];
  page.setDefaultTimeout(6000); page.on('pageerror', e => errors.push(e.message)); page.on('download', e => downloads.push(e.suggestedFilename()));
  await page.route('**/api/**', async route => {
    const req = route.request(), url = new URL(req.url()), path = url.pathname;
    let body, status = 200;
    if (path === '/api/auth/me') body = { user: { id: 7, role: 'member', display_name: 'Fixture user', active: true,
      account_ids: [1], must_change_password: false }, csrf: 'fixture-csrf' };
    else if (path === '/api/external-auth-batches/preview') {
      assert.equal(req.headers()['x-csrf-token'], 'fixture-csrf'); assert.equal(req.postDataJSON().text, pasted); body = preview;
    } else if (path === '/api/external-auth-batches' && req.method() === 'POST') {
      admissions.push(req.postDataJSON()); assert.equal(req.headers()['x-csrf-token'], 'fixture-csrf');
      ({ body, status } = await admit(admissions.at(-1), admissions.length));
    } else if (path === '/api/external-auth-batches') body = { items: [], page: 1 };
    else if (path === '/api/external-auth-batches/external-fixture/download') {
      assert.equal(req.method(), 'POST'); assert.equal(req.headers()['x-csrf-token'], 'fixture-csrf');
      if (download) await download();
      await route.fulfill({ status: 200, contentType: 'application/json', headers: { 'Content-Disposition': 'attachment; filename="fixture-user.json"', 'Cache-Control': 'no-store' }, body: '{"fixture":true}' }); return;
    } else if (path === '/api/external-auth-batches/external-fixture/items/challenge/retry' && retry) {
      assert.equal(req.headers()['x-csrf-token'], 'fixture-csrf'); body = retry(); status = 202;
    } else if (path === '/api/external-auth-batches/external-fixture') {
      status = denied?.() ? 403 : 200; body = status === 403 ? { detail: 'Fixture access revoked' } : progress ? progress() : batch;
    } else { unexpected.push(`${req.method()} ${path}`); status = 404; body = { detail: 'Unexpected fixture call' }; }
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  });
  t.after(async () => { await context.close(); assert.deepEqual(errors, []); assert.deepEqual(unexpected, []); });
  return { page, admissions, downloads };
}

test('pasted conversion survives an uncertain admission without retaining passwords or automatically reposting', async t => {
  const { page, admissions, downloads } = await fixture(t, { admit: async (body, count) => ({
    status: count === 1 ? 503 : 202, body: count === 1 ? { detail: 'Fixture request outcome unknown' } : { ...batch, request_key: body.request_key },
  }) });
  await page.goto(`${address}/json-export?source=paste`);
  await page.getByLabel('粘贴账号信息').fill(pasted);
  await page.getByRole('button', { name: '解析并预览', exact: true }).click();
  await page.getByRole('button', { name: '开始转换 1 个账号', exact: true }).click();
  await page.getByText('Fixture request outcome unknown', { exact: true }).waitFor();
  const stored = await page.evaluate(() => JSON.stringify({ ...sessionStorage }));
  assert.doesNotMatch(stored, /FixturePassword|awsapps|fixture-user/);
  assert.match(stored, /request_key/);
  await page.reload(); await page.getByLabel('粘贴账号信息').waitFor();
  assert.equal(await page.getByLabel('粘贴账号信息').inputValue(), ''); assert.equal(admissions.length, 1);
  await page.getByLabel('粘贴账号信息').fill(pasted);
  await page.getByRole('button', { name: '解析并预览', exact: true }).click();
  await page.getByRole('button', { name: '继续确认原请求', exact: true }).click();
  await page.getByRole('heading', { name: '粘贴转换进度', exact: true }).waitFor();
  assert.equal(admissions.length, 2); assert.deepEqual(admissions[0], admissions[1]);
  await page.getByText('Fixture password requires review', { exact: true }).waitFor();
  const finished = page.waitForEvent('download');
  await page.getByRole('button', { name: '下载此用户 JSON', exact: true }).click();
  assert.equal((await finished).suggestedFilename(), 'fixture-user.json'); assert.deepEqual(downloads, ['fixture-user.json']);
});

test('settled CAPTCHA retry survives leaving the page and reloading before challenge expiry', async t => {
  let calls = 0;
  let current = { ...batch, completed_at: null, download_ready: false, success_count: 0, failure_count: 0,
    items: [{ ...account, id: 'challenge', state: 'challenge', can_retry_challenge: true, retry_count: 0 }] };
  const { page } = await fixture(t, { progress: () => current, retry: () => {
    calls++; current = { ...current, items: [{ ...current.items[0], state: 'queued', can_retry_challenge: false }] }; return current;
  } });
  await page.goto(`${address}/json-export?source=paste&external_batch_id=external-fixture`);
  await page.getByRole('button', { name: '重试验证', exact: true }).waitFor();
  await page.evaluate(() => sessionStorage.setItem('kiro:json-export:last:8', JSON.stringify({ source: 'paste', id: 'other-user-task' })));
  await page.goto(`${address}/json-export?source=paste`);
  await page.getByLabel('粘贴账号信息').waitFor();
  await page.goto(`${address}/json-export`);
  await page.getByRole('button', { name: '重试验证', exact: true }).waitFor();
  assert.match(page.url(), /external_batch_id=external-fixture/);
  await page.reload();
  await page.getByRole('button', { name: '重试验证', exact: true }).click();
  await page.getByText('等待处理', { exact: true }).waitFor();
  assert.equal(calls, 1);
  assert.equal(await page.getByRole('button', { name: '重试验证', exact: true }).count(), 0);
});

test('a late JSON download is discarded after the next progress check revokes access', async t => {
  let revoke = false, finish, entered;
  const sent = new Promise(resolve => { entered = resolve; });
  const pending = new Promise(resolve => { finish = resolve; });
  const { page, downloads } = await fixture(t, { denied: () => revoke, download: async () => { entered(); await pending; } });
  await page.goto(`${address}/json-export?source=paste&external_batch_id=external-fixture`);
  await page.getByRole('button', { name: '下载此用户 JSON', exact: true }).click(); await sent;
  revoke = true;
  await page.waitForResponse(r => new URL(r.url()).pathname === '/api/external-auth-batches/external-fixture' && r.status() === 403);
  await page.getByText('Fixture access revoked', { exact: true }).waitFor();
  const response = page.waitForResponse(r => new URL(r.url()).pathname.endsWith('/external-fixture/download'));
  finish(); await response;
  await page.getByRole('button', { name: '刷新进度', exact: true }).click();
  assert.deepEqual(downloads, []); assert.equal(await page.getByRole('button', { name: '下载此用户 JSON', exact: true }).count(), 0);
});
