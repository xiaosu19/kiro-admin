// Run with KIRO_PLAYWRIGHT_MODULE pointing to an already installed Playwright module.
// No browser testing dependency is added to the application.
import test from "node:test";
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { createServer } from "vite";
const { chromium } = createRequire(import.meta.url)(process.env.KIRO_PLAYWRIGHT_MODULE || "playwright");
let server, browser, address;
test.before(async () => {
  server = await createServer({ root: fileURLToPath(new URL("..", import.meta.url)), server: { host: "127.0.0.1", port: 0 } });
  await server.listen();
  address = `http://127.0.0.1:${server.httpServer.address().port}/tests/fixtures/searchable-select.html`;
  browser = await chromium.launch({ headless: true, ...(process.env.KIRO_BROWSER_PATH ? { executablePath: process.env.KIRO_BROWSER_PATH } : {}) });
});
test.after(async () => { await browser?.close(); await server?.close(); });
async function fixture(t, viewport = { width: 1000, height: 900 }) {
  const page = await browser.newPage({ viewport });
  page.setDefaultTimeout(5000);
  const errors = [];
  page.on("pageerror", error => errors.push(error.message));
  t.after(async () => { await page.close(); assert.deepEqual(errors, []); });
  await page.goto(address);
  await page.getByRole("combobox", { name: "受控账号", exact: true }).waitFor({ timeout: 5000 });
  return page;
}
const combo = (page, name) => page.getByRole("combobox", { name, exact: true });
async function choose(page, name, query, label) {
  await combo(page, name).click();
  await page.getByRole("combobox", { name: `搜索${name}`, exact: true }).fill(query);
  await page.getByRole("option", { name: label, exact: true }).click();
}

test("120 choices filter by case-insensitive ID, preserve the current choice, and dispatch a native change", async t => {
  const page = await fixture(t);
  await combo(page, "受控账号").click();
  const search = combo(page, "搜索受控账号");
  await search.fill("ACCOUNT-99");
  assert.equal(await page.getByRole("option").count(), 1);
  assert.match(await combo(page, "受控账号").innerText(), /Account 1(?:\n|$)/);
  await search.fill("不存在");
  assert.equal(await page.getByRole("option").count(), 0);
  assert.match(await page.locator(".searchable-select-panel").getByRole("status").innerText(), /没有匹配/);
  await search.fill("account-99");
  await search.press("ArrowDown"); await search.press("Enter");
  assert.match(await combo(page, "受控账号").innerText(), /Account 99(?:\n|$)/);
  assert.deepEqual(JSON.parse(await page.getByTestId("changes").innerText()), ["controlled:account-99:account-99"]);
  assert.equal(await combo(page, "受控账号").evaluate(node => node === document.activeElement), true);
  await page.getByRole("button", { name: "更新受控值" }).click();
  assert.match(await combo(page, "受控账号").innerText(), /Account 42(?:\n|$)/);
});

test("disabled options, disabled fieldsets and declined controlled changes cannot change a choice", async t => {
  const page = await fixture(t);
  await combo(page, "受控账号").click();
  const search = combo(page, "搜索受控账号");
  await search.fill("account-98"); await search.press("ArrowDown"); await search.press("Enter");
  assert.equal(await page.getByRole("option").getAttribute("aria-disabled"), "true");
  await page.getByRole("option").evaluate(node => node.click());
  assert.match(await combo(page, "受控账号").innerText(), /Account 1(?:\n|$)/);
  await search.fill("disabled-group"); await search.press("ArrowDown"); await search.press("Enter");
  assert.match(await combo(page, "受控账号").innerText(), /Account 1(?:\n|$)/);
  await page.getByRole("button", { name: "切换冻结" }).click();
  assert.equal(await combo(page, "受控账号").isDisabled(), true);
  assert.equal(await page.getByRole("listbox").count(), 0);
  await page.getByRole("button", { name: "切换冻结" }).click();
  await choose(page, "固定账号", "account-99", "研发 Account 99");
  assert.match(await combo(page, "固定账号").innerText(), /Account 1(?:\n|$)/);
});

test("required validation focuses the search, FormData is correct and reset restores uncontrolled defaults", async t => {
  const page = await fixture(t);
  await page.getByRole("button", { name: "提交表单" }).click();
  assert.equal(await page.getByTestId("data").innerText(), "");
  assert.equal(await combo(page, "搜索必填账号").evaluate(node => node === document.activeElement), true);
  await combo(page, "搜索必填账号").fill("account-99"); await page.getByRole("option", { name: "研发 Account 99", exact: true }).click();
  await choose(page, "默认账号", "account-119", "研发 Account 119");
  await page.getByRole("button", { name: "提交表单" }).click();
  let data = new Map(JSON.parse(await page.getByTestId("data").innerText()));
  assert.equal(data.get("required"), "account-99"); assert.equal(data.get("default"), "account-119");
  await page.getByRole("button", { name: "更新受控值" }).click();
  await page.getByRole("button", { name: "重置表单" }).click();
  await page.waitForFunction(() => document.querySelector('[aria-label="默认账号"]').textContent.includes("Account 7"));
  assert.match(await combo(page, "默认账号").innerText(), /Account 7(?:\n|$)/);
  assert.match(await combo(page, "受控账号").innerText(), /Account 42(?:\n|$)/);
  assert.match(await combo(page, "必填账号").innerText(), /请选择账号/);
});

test("Escape, Space, Tab, outside click and narrow viewports keep focus and the panel usable", async t => {
  const page = await fixture(t, { width: 320, height: 640 });
  const trigger = combo(page, "固定账号");
  await trigger.focus(); await trigger.press("Space");
  let search = combo(page, "搜索固定账号");
  assert.equal(await search.evaluate(node => node === document.activeElement), true);
  await search.press("End");
  const bounds = await page.locator(".searchable-select-panel").boundingBox();
  assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 320);
  assert.ok(bounds.y >= 0 && bounds.y + bounds.height <= 640);
  await search.press("Escape");
  assert.equal(await trigger.evaluate(node => node === document.activeElement), true);
  await trigger.press("ArrowDown"); await combo(page, "搜索固定账号").press("Tab");
  assert.equal(await page.getByLabel("下一个输入", { exact: true }).evaluate(node => node === document.activeElement), true);
  await trigger.click(); await page.getByRole("button", { name: "外部按钮" }).click();
  assert.equal(await page.getByRole("listbox").count(), 0);
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
});

test("account binding and plan filters preserve hidden selections and form values", async t => {
  const page = await fixture(t);
  await page.getByRole("searchbox", { name: "搜索可绑定 AWS 账号" }).fill("Account 99");
  await page.getByRole("checkbox", { name: /研发 Account 99/ }).check();
  const selected = await page.locator("#selection-form").evaluate(form => new FormData(form).getAll("account"));
  assert.deepEqual(selected, ["1", "99"]);
  await page.getByRole("searchbox", { name: "搜索可绑定 AWS 账号" }).fill("");
  const original = page.locator('#selection-form input[name="account"][value="1"]');
  assert.equal(await original.isVisible(), true);
  assert.equal(await original.isChecked(), true);
  await page.getByRole("searchbox", { name: "搜索目标套餐" }).fill("Pro+");
  assert.equal(await page.getByRole("radio").count(), 1);
  assert.match(await page.locator(".plan-change-targets").innerText(), /已选：Power/);
  assert.equal(await page.locator("#selection-form").evaluate(form => new FormData(form).get("target_plan_id")), "3");
});

test("keyboard navigation scrolls the long list and discovery-style native form updates stay visible", async t => {
  const page = await fixture(t);
  await page.getByRole("button", { name: "填充探测配置" }).click();
  await page.waitForFunction(() => document.querySelector('[aria-label="默认账号"]').textContent.includes("Account 42"));
  assert.match(await combo(page, "默认账号").innerText(), /Account 42(?:\n|$)/);
  const trigger = combo(page, "默认账号");
  await trigger.focus(); await trigger.press("ArrowUp");
  const search = combo(page, "搜索默认账号");
  const activeId = await search.getAttribute("aria-activedescendant");
  const active = page.locator(`[id="${activeId}"]`);
  assert.equal(await active.innerText(), "研发 Account 119");
  const optionBounds = await active.boundingBox(), listBounds = await page.getByRole("listbox").boundingBox();
  assert.ok(optionBounds.y >= listBounds.y && optionBounds.y + optionBounds.height <= listBounds.y + listBounds.height + 1);
  await search.press("Enter");
  assert.match(await trigger.innerText(), /Account 119(?:\n|$)/);
  await page.locator("#selection-form").evaluate(form => form.addEventListener("reset", event => event.preventDefault(), { once: true }));
  await page.getByRole("button", { name: "重置表单" }).click();
  assert.match(await trigger.innerText(), /Account 119(?:\n|$)/);
  assert.equal(await page.locator('select[name="default"]').inputValue(), "account-119");
});

test("native showModal dialogs keep searchable options interactive and focused inside the top layer", async t => {
  const page = await fixture(t, { width: 320, height: 640 });
  await page.getByRole("button", { name: "打开原生弹窗" }).click();
  const dialog = page.getByRole("dialog", { name: "原生弹窗测试" });
  assert.equal(await dialog.evaluate(node => node.matches(":modal")), true);
  await dialog.getByText("弹窗账号", { exact: true }).click();
  const search = page.locator('.searchable-select-panel input[aria-label="搜索弹窗账号"]');
  await page.waitForFunction(() => document.querySelector('input[aria-label="搜索弹窗账号"]') === document.activeElement);
  assert.equal(await search.evaluate(node => node === document.activeElement), true);
  await search.fill("account-99");
  await page.getByRole("option", { name: "研发 Account 99", exact: true }).click();
  assert.match(await combo(page, "弹窗账号").innerText(), /Account 99(?:\n|$)/);
  assert.equal(await combo(page, "弹窗账号").evaluate(node => node === document.activeElement), true);
  await dialog.getByRole("button", { name: "提交弹窗表单" }).click();
  assert.equal(await page.getByTestId("modal-data").innerText(), "account-99");
  await combo(page, "弹窗账号").click();
  await search.press("Escape");
  assert.equal(await dialog.evaluate(node => node.open), true);
  assert.equal(await page.getByRole("listbox").count(), 0);
  await combo(page, "弹窗账号").press("ArrowUp");
  const panelBounds = await page.locator(".searchable-select-panel").boundingBox();
  assert.ok(panelBounds.x >= 0 && panelBounds.x + panelBounds.width <= 320);
  assert.ok(panelBounds.y >= 0 && panelBounds.y + panelBounds.height <= 640);
  await search.press("Enter");
  assert.match(await combo(page, "弹窗账号").innerText(), /Account 119(?:\n|$)/);
  await combo(page, "弹窗账号").click();
  await dialog.getByRole("button", { name: "弹窗内其他按钮" }).click();
  assert.equal(await page.getByRole("listbox").count(), 0);
  assert.ok(await dialog.evaluate(node => node.scrollWidth <= node.clientWidth));
});

for (const [label, query] of [["搜索可绑定 AWS 账号", "Account 99"], ["搜索目标套餐", "Power"]]) {
  test(`${label} filters without Enter submitting an otherwise valid mutation form`, async t => {
    const page = await fixture(t);
    await choose(page, "必填账号", "account-99", "研发 Account 99");
    const search = page.getByRole("searchbox", { name: label, exact: true });
    await search.fill(query);
    await search.press("Enter");
    assert.equal(await page.getByTestId("data").innerText(), "");
    assert.equal(await search.evaluate(node => node === document.activeElement), true);
    await page.getByRole("button", { name: "提交表单", exact: true }).click();
    assert.equal(new Map(JSON.parse(await page.getByTestId("data").innerText())).get("required"), "account-99");
  });
}
