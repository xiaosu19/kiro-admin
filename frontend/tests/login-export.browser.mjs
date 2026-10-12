// Run with KIRO_PLAYWRIGHT_MODULE pointing to an already installed Playwright module.
import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";
const { chromium } = createRequire(import.meta.url)(process.env.KIRO_PLAYWRIGHT_MODULE || "playwright");
let server, browser, address;
const cacheDir = mkdtempSync(join(tmpdir(), "kiro-export-vite-"));
test.before(async () => {
  server = await createServer({ root: fileURLToPath(new URL("..", import.meta.url)), cacheDir, server: { host: "127.0.0.1", port: 0 } });
  await server.listen();
  address = `http://127.0.0.1:${server.httpServer.address().port}/tests/fixtures/login-export.html`;
  browser = await chromium.launch({ headless: true, ...(process.env.KIRO_BROWSER_PATH ? { executablePath: process.env.KIRO_BROWSER_PATH } : {}) });
});
test.after(async () => { await browser?.close(); await server?.close(); rmSync(cacheDir, { recursive: true, force: true }); });
async function fixture(t, viewport = { width: 1000, height: 700 }) {
  const page = await browser.newPage({ viewport });
  page.setDefaultTimeout(5000);
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  t.after(async () => { await page.close(); assert.deepEqual(errors, []); });
  await page.goto(address);
  await page.getByTestId("downloads").waitFor();
  return page;
}
const exports = page => page.getByTestId("list-exports").getByRole("button", { name: "导出登录信息", exact: true });
const dialog = page => page.getByRole("dialog", { name: "导出登录信息", exact: true });

test("one export button opens a scoped format chooser and only the choice initiates a download", async t => {
  const page = await fixture(t);
  assert.equal(await page.getByTestId("list-exports").getByRole("button").count(), 1);
  await exports(page).click();
  assert.equal(await page.getByTestId("downloads").innerText(), "[]");
  await dialog(page).getByRole("group", { name: "选中用户（2）", exact: true }).getByRole("button", { name: "TXT 登录信息", exact: true }).click();
  assert.deepEqual(JSON.parse(await page.getByTestId("downloads").innerText()), [{ ids: ["a", "b"], format: "txt" }]);
  assert.equal(await dialog(page).count(), 0);
  assert.equal(await exports(page).evaluate(node => node === document.activeElement), true);
  await exports(page).click();
  await dialog(page).getByRole("group", { name: "筛选结果", exact: true }).getByRole("button", { name: "CSV 表格", exact: true }).click();
  assert.deepEqual(JSON.parse(await page.getByTestId("downloads").innerText()).at(-1), { format: "csv" });
});

test("keyboard Enter, Tab, Space and Escape keep focus inside the chooser and restore the trigger", async t => {
  const page = await fixture(t);
  const trigger = exports(page);
  await trigger.focus(); await trigger.press("Enter");
  const csv = dialog(page).getByRole("group", { name: "选中用户（2）", exact: true }).getByRole("button", { name: "CSV 表格", exact: true });
  const txt = dialog(page).getByRole("group", { name: "选中用户（2）", exact: true }).getByRole("button", { name: "TXT 登录信息", exact: true });
  assert.equal(await csv.evaluate(node => node === document.activeElement), true);
  await csv.press("Tab");
  assert.equal(await txt.evaluate(node => node === document.activeElement), true);
  await txt.press("Space");
  assert.equal(await trigger.evaluate(node => node === document.activeElement), true);
  await trigger.press("Space");
  await page.keyboard.press("Escape");
  assert.equal(await dialog(page).count(), 0);
  assert.equal(await trigger.evaluate(node => node === document.activeElement), true);
  assert.equal(JSON.parse(await page.getByTestId("downloads").innerText()).length, 1);
});

test("narrow screens, cancellation and unavailable choices preserve the requested scope", async t => {
  const page = await fixture(t, { width: 320, height: 640 });
  await page.getByRole("button", { name: "清空选择", exact: true }).click();
  await exports(page).click();
  const selection = dialog(page).getByRole("group", { name: "选中用户（0）", exact: true });
  assert.equal(await selection.getByRole("button", { name: "CSV 表格", exact: true }).isDisabled(), true);
  const bounds = await dialog(page).boundingBox();
  assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 320);
  assert.ok(bounds.y >= 0 && bounds.y + bounds.height <= 640);
  await dialog(page).getByRole("button", { name: "取消", exact: true }).click();
  assert.equal(await page.getByTestId("downloads").innerText(), "[]");
  const account = page.getByRole("region", { name: "账号批次下载", exact: true });
  await account.getByRole("button", { name: "导出登录信息", exact: true }).click();
  assert.equal(await dialog(page).getByRole("button", { name: "CSV 表格", exact: true }).count(), 0);
  await dialog(page).getByRole("button", { name: "TXT 登录信息", exact: true }).click();
  assert.deepEqual(JSON.parse(await page.getByTestId("downloads").innerText()), [{ path: "/sso-users/export", method: "POST", body: { provisioning_account_batch_id: "child", format: "txt" } }]);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
});

test("busy state disables all export entries and closes an already open chooser", async t => {
  const page = await fixture(t);
  await page.getByRole("button", { name: "延迟忙碌", exact: true }).click();
  await exports(page).click();
  await dialog(page).waitFor({ state: "hidden" });
  assert.equal(await exports(page).isDisabled(), true);
  assert.equal(await page.getByTestId("downloads").innerText(), "[]");
});
