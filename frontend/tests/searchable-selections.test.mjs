import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { loadSource } from "./load-source.mjs";
import { mountHook, settle } from "./hooks.mjs";

const available = name => existsSync(new URL(`../src/${name}.tsx`, import.meta.url));
const control = available("SearchableSelect") ? await loadSource("SearchableSelect") : {};
const search = existsSync(new URL("../src/selectionSearch.ts", import.meta.url)) ? await loadSource("selectionSearch") : {};

test("selection searches find labels and IDs across 120 options regardless of case", () => {
  assert.equal(typeof search.matchesSelection, "function", "shared choice matcher exists");
  const options = Array.from({ length: 120 }, (_, id) => ({ id: `account-${id}`, label: `研发 Account ${id}` }));
  const find = query => options.filter(option => search.matchesSelection(query, option.label, option.id));
  assert.deepEqual(find(" ACCOUNT-99 "), [options[99]]);
  assert.deepEqual(find("研发 account 119"), [options[119]]);
  assert.equal(find("  ").length, 120);
  assert.deepEqual(find("不存在"), []);
});

test("filtered select-all changes only visible choices and retains hidden selections", () => {
  assert.equal(typeof search.toggleVisibleSelection, "function", "visible-only bulk selection exists");
  assert.deepEqual(search.toggleVisibleSelection([1, 7], [2, 7], true), [1, 7, 2]);
  assert.deepEqual(search.toggleVisibleSelection([1, 2, 7], [2, 7], false), [1]);
  assert.deepEqual(search.toggleVisibleSelection([1], [], false), [1]);
});

test("searchable select retains named, required, default and disabled option semantics", () => {
  assert.equal(typeof control.SearchableSelect, "function", "searchable select exists");
  const html = renderToStaticMarkup(h(control.SearchableSelect, { name: "account_id", "aria-label": "AWS 账号", required: true, defaultValue: "99" },
    h("option", { value: "" }, "请选择"), h("option", { value: "99" }, "研发 Account 99"), h("option", { value: "100", disabled: true }, "已停用")));
  assert.match(html, /role="combobox"/);
  assert.match(html, /aria-expanded="false"/);
  assert.match(html, /<select[^>]*name="account_id"[^>]*required/);
  assert.match(html, /<option value="99" selected=""/);
  assert.match(html, /<option value="100" disabled=""/);
  assert.match(html, /aria-label="AWS 账号"/);
});

test("no application choice menu remains a visible native select", () => {
  const files = readdirSync(new URL("../src", import.meta.url)).filter(name => name.endsWith(".tsx") && name !== "SearchableSelect.tsx");
  const remaining = files.filter(name => /<select\b/.test(readFileSync(new URL(`../src/${name}`, import.meta.url), "utf8")));
  assert.deepEqual(remaining, [], `migrate remaining selects: ${remaining.join(", ")}`);
});

test("account binding search keeps every checkbox in the form", async () => {
  assert.ok(available("AccountBindings"), "searchable account binding collection exists");
  const { AccountBindings } = await loadSource("AccountBindings");
  const html = renderToStaticMarkup(h(AccountBindings, { accounts: [{ id: 1, name: "First", region: "us-east-1", active: true }, { id: 99, name: "研发 Account 99", region: "us-east-1", active: true }], selected: [1] }));
  assert.match(html, /搜索可绑定 AWS 账号/);
  assert.equal((html.match(/name="account"/g) || []).length, 2);
  assert.match(html, /<input(?=[^>]*value="1")(?=[^>]*checked="")[^>]*>/);
});

function find(node, predicate) {
  if (!node || typeof node !== "object") return null;
  if (Array.isArray(node)) return node.map(child => find(child, predicate)).find(Boolean);
  return predicate(node) ? node : find(node.props?.children, predicate);
}

test("report account search does not discard hidden choices when selecting or clearing visible results", async t => {
  const { AwsReports } = await loadSource("AwsReports");
  const accounts = Array.from({ length: 120 }, (_, id) => ({ id, name: `Account ${id}`, active: true }));
  t.mock.method(globalThis, "fetch", async () => ({ ok: true, json: async () => accounts }));
  const host = mountHook(AwsReports, { user: { id: 7, role: "admin", active: true }, notify() {} });
  await settle(); host.render();
  const byLabel = name => find(host.current, node => node.props?.["aria-label"] === name);
  byLabel("报表 AWS 账号 Account 1").props.onChange({ target: { checked: true } }); host.render();
  const query = byLabel("搜索报表 AWS 账号");
  assert.ok(query, "report account choice has search");
  query.props.onChange({ target: { value: "ACCOUNT 99" } }); host.render();
  byLabel("选择全部 AWS 账号（当前搜索结果）").props.onChange({ target: { checked: true } }); host.render();
  assert.equal(byLabel("报表 AWS 账号 Account 99").props.checked, true);
  byLabel("选择全部 AWS 账号（当前搜索结果）").props.onChange({ target: { checked: false } }); host.render();
  byLabel("搜索报表 AWS 账号").props.onChange({ target: { value: "" } }); host.render();
  assert.equal(byLabel("报表 AWS 账号 Account 1").props.checked, true);
  assert.equal(byLabel("报表 AWS 账号 Account 99").props.checked, false);
  host.unmount();
});

test("plan choice cards offer a search without changing the paid-plan selection contract", async () => {
  const { PlanChangeTargets } = await loadSource("PlanChangeManager");
  const { record, options } = await import("./plan-change-fixtures.mjs");
  const html = renderToStaticMarkup(h(PlanChangeTargets, { record, options, value: 3, disabled: false, onChange() {} }));
  assert.match(html, /搜索目标套餐/);
  assert.match(html, /已选：Power/);
});
