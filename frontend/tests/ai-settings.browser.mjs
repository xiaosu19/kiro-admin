// Real React page, local API fixtures only; no provider or AWS request is sent.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { createServer } from 'vite';
const { chromium } = createRequire(import.meta.url)(process.env.KIRO_PLAYWRIGHT_MODULE || 'playwright');
let server, browser, address;
test.before(async () => {
  server = await createServer({ root: fileURLToPath(new URL('..', import.meta.url)), server: { host: '127.0.0.1', port: 0 } });
  await server.listen(); address = `http://127.0.0.1:${server.httpServer.address().port}`;
  browser = await chromium.launch({ headless: true, ...(process.env.KIRO_BROWSER_PATH ? { executablePath: process.env.KIRO_BROWSER_PATH } : {}) });
});
test.after(async () => { await browser?.close(); await server?.close(); });
async function fixture(t, viewport = { width: 1440, height: 1000 }) {
  const page = await browser.newPage({ viewport }), writes = [], tests = [], errors = [], unexpected = [];
  page.setDefaultTimeout(5000); page.on('pageerror', error => errors.push(error.message));
  let settings = { revision: 0, protocol: 'claude_messages', endpoint: 'https://api.anthropic.com/v1/messages',
    model: 'claude-opus-4.6', enabled: false, timeout_seconds: 20, key_configured: false, updated_at: null };
  await page.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    let body, status = 200;
    if (path === '/api/auth/me') body = { user: { id: 2, role: 'member', display_name: 'User A', active: true, must_change_password: false }, csrf: 'synthetic-csrf' };
    else if (path === '/api/ai-settings' && request.method() === 'GET') body = settings;
    else if (path === '/api/ai-settings' && request.method() === 'PUT') {
      const input = request.postDataJSON(); writes.push(input);
      const { api_key, clear_key, ...fields } = input;
      settings = { ...settings, ...fields, revision: settings.revision + 1, updated_at: new Date().toISOString(),
        key_configured: clear_key ? false : !!api_key || settings.key_configured };
      body = settings;
    } else if (path === '/api/ai-settings/test') { tests.push(request.postDataJSON()); body = { ok: true, code: 'ok' }; }
    else if (path === '/api/sso-users' || path === '/api/auth-batches') body = { items: [], total: 0 };
    else if (path === '/api/accounts' || path === '/api/groups' || path === '/api/plans') body = [];
    else { unexpected.push(`${request.method()} ${path}`); status = 404; body = { detail: 'Unexpected fixture call' }; }
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
  });
  t.after(async () => { await page.close(); assert.deepEqual(errors, []); assert.deepEqual(unexpected, []); });
  await page.goto(address + '/json-export'); await page.getByRole('heading', { name: 'JSON 导出', exact: true }).waitFor();
  return { page, writes, tests };
}

test('AI configuration is inside JSON export, preserves blank keys and clears explicitly', async t => {
  const { page, writes, tests } = await fixture(t);
  assert.equal(await page.locator('nav').getByRole('link', { name: 'AI 识别设置', exact: true }).count(), 0);
  await page.getByRole('button', { name: 'AI 识别设置', exact: true }).click();
  const panel = page.getByRole('region', { name: '我的 AI 识别设置', exact: true });
  await panel.getByRole('combobox', { name: '接口协议', exact: true }).waitFor();
  await panel.getByLabel('接口地址', { exact: true }).fill('https://vision.example.com/v1');
  await panel.getByRole('combobox', { name: '接口协议', exact: true }).click();
  await page.getByRole('option', { name: 'OpenAI Chat Completions', exact: true }).click();
  assert.equal(await panel.getByLabel('接口地址', { exact: true }).inputValue(), 'https://vision.example.com/v1');
  await panel.getByLabel('接口地址', { exact: true }).fill('https://vision.example.com/v1/chat/completions');
  await panel.getByRole('combobox', { name: '接口协议', exact: true }).click();
  await page.getByRole('option', { name: 'OpenAI Responses', exact: true }).click();
  assert.equal(await panel.getByLabel('接口地址', { exact: true }).inputValue(), 'https://vision.example.com/v1/responses');
  await panel.getByLabel('模型名称', { exact: true }).fill('my-vision-model');
  await panel.getByLabel('API 密钥', { exact: true }).fill('synthetic-user-key');
  await panel.getByLabel('为我的任务启用自动图像识别', { exact: true }).check();
  await panel.getByRole('button', { name: '保存设置', exact: true }).click();
  await page.getByRole('status').filter({ hasText: '个人 AI 识别设置已保存' }).waitFor();
  assert.equal(writes.length, 1); assert.equal(writes[0].protocol, 'openai_responses');
  assert.equal(await panel.getByLabel('API 密钥', { exact: true }).inputValue(), '');
  assert.equal(await panel.getByRole('button', { name: '保存设置', exact: true }).isDisabled(), true);
  await panel.getByRole('button', { name: '测试已保存配置', exact: true }).click();
  await panel.getByRole('status').filter({ hasText: '测试图片识别正确' }).waitFor();
  assert.deepEqual(tests, [{ revision: 1 }]);
  await panel.getByLabel('模型名称', { exact: true }).fill('my-second-model');
  assert.equal(await panel.getByRole('button', { name: '测试已保存配置', exact: true }).isDisabled(), true);
  await panel.getByRole('button', { name: '保存设置', exact: true }).click();
  await panel.getByRole('button', { name: '测试已保存配置', exact: true }).waitFor({ state: 'visible' });
  await page.waitForFunction(() => document.querySelector('input[placeholder="已保存，留空保留原密钥"]')?.value === '');
  assert.equal(writes.length, 2); assert.equal('api_key' in writes[1], false);
  await panel.getByLabel('清除已保存的密钥', { exact: true }).check();
  assert.equal(await panel.getByLabel('为我的任务启用自动图像识别', { exact: true }).isChecked(), false);
  await panel.getByRole('button', { name: '保存设置', exact: true }).click();
  await panel.getByPlaceholder('填写你自己的 API 密钥').waitFor();
  assert.equal(writes[2].clear_key, true); assert.equal(writes[2].enabled, false);
  await page.getByRole('button', { name: '收起 AI 设置', exact: true }).click();
  await panel.waitFor({ state: 'hidden' });
});

test('settings stay usable within the mobile JSON export page', async t => {
  const { page } = await fixture(t, { width: 390, height: 844 });
  await page.getByRole('button', { name: 'AI 识别设置', exact: true }).click();
  await page.getByRole('combobox', { name: '接口协议', exact: true }).waitFor();
  const layout = await page.evaluate(() => ({ width: document.documentElement.clientWidth, scroll: document.documentElement.scrollWidth }));
  assert.ok(layout.scroll <= layout.width + 1, JSON.stringify(layout));
  if (process.env.KIRO_AI_SCREENSHOT) await page.screenshot({ path: process.env.KIRO_AI_SCREENSHOT, fullPage: true });
});

test('logout clears entered secrets and a late save failure cannot expire the next user', async t => {
  const { page } = await fixture(t);
  await page.getByRole('button', { name: 'AI 识别设置', exact: true }).click();
  const panel = page.getByRole('region', { name: '我的 AI 识别设置', exact: true });
  await panel.getByLabel('API 密钥', { exact: true }).fill('synthetic-user-a-secret');
  let release, started;
  const held = new Promise(resolve => { release = resolve; });
  t.after(() => release());
  const saving = new Promise(resolve => { started = resolve; });
  await page.route('**/api/ai-settings', async route => {
    if (route.request().method() === 'PUT') {
      started(); await held;
      await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ detail: 'Old session expired' }) });
    } else await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ revision: 1,
      protocol: 'claude_messages', endpoint: 'https://second.example.com/v1/messages', model: 'second-user-model',
      enabled: true, timeout_seconds: 20, key_configured: true, updated_at: null }) });
  });
  for (const [path, body] of [
    ['logout', {}], ['login', { csrf: 'synthetic-second-csrf' }],
    ['me', { user: { id: 3, role: 'member', display_name: 'User B', active: true, must_change_password: false }, csrf: 'synthetic-second-csrf' }],
  ]) await page.route(`**/api/auth/${path}`, route => route.fulfill({ contentType: 'application/json', body: JSON.stringify(body) }));
  await panel.getByRole('button', { name: '保存设置', exact: true }).click();
  await saving;
  await page.getByRole('button', { name: '退出', exact: true }).click();
  await page.locator('input[name="username"]').fill('second-user');
  await page.locator('input[name="password"]').fill('synthetic-password-123');
  await page.getByRole('button', { name: /^登录\s*→$/ }).click();
  await panel.getByLabel('模型名称', { exact: true }).waitFor();
  assert.equal(await panel.getByLabel('模型名称', { exact: true }).inputValue(), 'second-user-model');
  assert.equal(await panel.getByLabel('API 密钥', { exact: true }).inputValue(), '');
  await page.evaluate(() => { window.oldSessionExpirations = 0; window.addEventListener('session-expired', () => { window.oldSessionExpirations += 1; }); });
  const lateResponse = page.waitForResponse(response => response.url().endsWith('/api/ai-settings') && response.request().method() === 'PUT');
  release(); await (await lateResponse).finished();
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await page.evaluate(() => window.oldSessionExpirations), 0);
  assert.equal(await panel.getByLabel('模型名称', { exact: true }).inputValue(), 'second-user-model');
});
