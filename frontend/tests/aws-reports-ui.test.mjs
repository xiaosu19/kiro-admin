import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
import { mountHook, settle } from "./hooks.mjs";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";

const reports = await loadSource("AwsReports");
const actor = { id: 2, role: "member", active: true, account_ids: [1, 2] };
const account = { id: 1, name: "Team", active: true, aws_account_id: "123456789012", region: "us-east-1", profile_arn: "profile" };
const result = { view: "subscriptions", columns: ["Name", "Email", "Subscription status", "Kiro plan", "Plan source", "Activation date"],
  account_ids: [1], total: 2, generated_at: "2026-10-10T00:00:00Z", rows: [
    { id: "a", account_id: 1, account_name: "Team", values: ["Alice", "alice@example.com", "Pending", "Kiro Pro", "Group", "-"] },
    { id: "b", account_id: 1, account_name: "Team", values: ["Bob", "bob@example.com", "Active", "Kiro Power", "Individual", "2026-10-01 00:00:00 UTC"] },
  ] };
const cost = { account_id: 1, month: "2026-10", amount: "-0.05", currency: "USD", estimated: true,
  period_start: "2026-10-01", period_end: "2026-11-01", retrieved_at: "2026-10-10T02:00:00Z",
  source: "aws_bills_console", billing_kind: "proforma", payer_id: "999999999999", available_payers: ["999999999999", "888888888888"] };

test("report page has distinct console views, explicit query, account selection and search", () => {
  const html = renderToStaticMarkup(h(reports.AwsReports, { user: actor, notify() {} }));
  for (const text of ["AWS 报表", "Users", "Groups", "Subscriptions", "查询 AWS 报表", "搜索报表姓名、邮箱或分组", "下载 CSV", "选择全部 AWS 账号"])
    assert.ok(html.includes(text), text);
});

test("report table renders every official column and real Pending GROUP values", () => {
  const html = renderToStaticMarkup(h(reports.ReportTable, { data: result, selected: ["a"], onSelect() {} }));
  for (const text of [...result.columns, "Alice", "alice@example.com", "Pending", "Group", "选择全部筛选结果", "选择报表行 a"])
    assert.ok(html.includes(text), text);
  assert.match(html, /checked/);
});

test("reports only query explicitly and combine accounts with query", async () => {
  let request;
  global.fetch = async (_path, options) => { request = JSON.parse(options.body); return { ok: true, json: async () => result }; };
  const host = mountHook(reports.useAwsReport, actor, "subscriptions", [1, 2], "alice");
  assert.equal(request, undefined);
  await host.current.load(); host.render();
  assert.deepEqual(request, { view: "subscriptions", account_ids: [1, 2], q: "alice" });
  assert.equal(host.current.data.total, 2);
  host.unmount();
});

test("scope change immediately hides rows and selection before an older response settles", async () => {
  let resolve;
  global.fetch = async () => ({ ok: true, json: () => new Promise(r => { resolve = r; }) });
  const host = mountHook(reports.useAwsReport, actor, "subscriptions", [1], "alice");
  const pending = host.current.load(); await settle();
  host.render(actor, "subscriptions", [2], "bob");
  assert.equal(host.current.data, null);
  assert.deepEqual(host.current.selected, []);
  resolve(result); await pending; host.render();
  assert.equal(host.current.data, null);
  host.unmount();
});

test("same actor role changes invalidate report rows and every row selection", async () => {
  global.fetch = async () => ({ ok: true, json: async () => result });
  const host = mountHook(reports.useAwsReport, actor, "subscriptions", [1], "");
  await host.current.load(); host.render();
  host.current.setSelected(["a"]); host.render();
  assert.deepEqual(host.current.selected, ["a"]);
  host.render({ ...actor, role: "admin" }, "subscriptions", [1], "");
  assert.equal(host.current.data, null);
  assert.deepEqual(host.current.selected, []);
  host.unmount();
});

test("unmounted report requests never write state", async () => {
  let resolve;
  global.fetch = async () => ({ ok: true, json: () => new Promise(r => { resolve = r; }) });
  const host = mountHook(reports.useAwsReport, actor, "subscriptions", [1], "");
  const pending = host.current.load(); await settle(); host.unmount();
  resolve(result); await pending;
  assert.equal(host.updatesAfterUnmount, 0);
});

test("cost displays actual signed amount, estimate, period and freshness; unavailable never becomes zero", () => {
  const html = renderToStaticMarkup(h(reports.CostFacts, { data: cost, loading: false, error: "" }));
  for (const text of ["0.05", "USD", "预估", "形式账单", "2026-10-01", "2026-11-01", "获取于"])
    assert.ok(html.includes(text), text);
  assert.doesNotMatch(html, /更新于|缓存|Cost Explorer|ce:GetCostAndUsage/);
  const failed = renderToStaticMarkup(h(reports.CostFacts, { data: null, loading: false, error: "Billing IAM 权限" }));
  assert.match(failed, /Billing IAM/); assert.doesNotMatch(failed, /0\.00/);
});

test("members cannot render or request billing panels", async () => {
  let called = false;
  global.fetch = async () => { called = true; throw new Error("member billing"); };
  const host = mountHook(reports.useAccountCost, actor, account);
  await settle(); host.render();
  assert.equal(called, false);
  assert.equal(renderToStaticMarkup(h(reports.AccountCost, { user: actor, account })), "");
  host.unmount();
});

test("billing loads per payer/configuration; refresh is explicit", async () => {
  const paths = [];
  global.fetch = async path => { paths.push(path); return { ok: true, json: async () => cost }; };
  const user = { ...actor, role: "admin" };
  const host = mountHook(reports.useAccountCost, user, account);
  await settle(); host.render(); host.render(user, { ...account });
  assert.equal(paths.length, 1);
  await host.current.refresh(); host.render();
  assert.match(paths[1], /refresh=true/);
  host.render(user, account, "888888888888"); await settle(); host.render();
  assert.match(paths[2], /payer_id=888888888888/);
  host.render(user, { ...account, profile_arn: "new-profile" }, "888888888888"); await settle(); host.render();
  assert.equal(paths.length, 4);
  host.unmount();
});

test("slow billing response cannot overwrite a newly selected payer or changed actor", async () => {
  const pending = [];
  global.fetch = async () => ({ ok: true, json: () => new Promise(resolve => pending.push(resolve)) });
  const user = { ...actor, role: "admin" };
  const host = mountHook(reports.useAccountCost, user, account);
  await settle(); host.render(user, account, "888888888888"); await settle();
  pending[1]({ ...cost, payer_id: "888888888888" }); await settle(); host.render();
  pending[0](cost); await settle(); host.render();
  assert.equal(host.current.data.payer_id, "888888888888");
  host.render(actor, account);
  assert.equal(host.current.data, null);
  host.unmount();
});

test("administrators can inspect current Bills for inactive configured accounts", async () => {
  let called = 0;
  global.fetch = async () => { called++; return { ok: true, json: async () => cost }; };
  const user = { ...actor, role: "admin" };
  const host = mountHook(reports.useAccountCost, user, { ...account, active: false });
  await settle(); host.render();
  assert.equal(called, 1);
  assert.equal(host.current.data.amount, "-0.05");
  host.render(user, { ...account, deleted_at: "2026-10-10" });
  assert.equal(host.current.data, null);
  host.unmount();
});

test("returning to an earlier report filter never restores its prior rows or selection", async () => {
  global.fetch = async () => ({ ok: true, json: async () => result });
  const host = mountHook(reports.useAwsReport, actor, "users", [1], "alice");
  await host.current.load(); host.render();
  host.current.setSelected(["a"]); host.render();
  host.render(actor, "users", [2], "bob");
  host.render(actor, "users", [1], "alice");
  assert.equal(host.current.data, null);
  assert.deepEqual(host.current.selected, []);
  host.unmount();
});

test("an old query callback cannot invalidate the active scope's in-flight query", async () => {
  let resolve;
  global.fetch = async () => ({ ok: true, json: () => new Promise(r => { resolve = r; }) });
  const host = mountHook(reports.useAwsReport, actor, "users", [1], "alice");
  const oldLoad = host.current.load;
  host.render(actor, "users", [2], "bob");
  const pending = host.current.load(); await settle();
  await oldLoad();
  resolve(result); await pending; host.render();
  assert.equal(host.current.data.total, 2);
  assert.equal(host.current.busy, false);
  host.unmount();
});


test("Bills panel has current UTC month, exact currency formatting and no historical month field", () => {
  assert.equal(reports.formatBillAmount("90071992547409931.4567", "USD"), "USD 90,071,992,547,409,931.46");
  assert.equal(reports.formatBillAmount("-0.05", "USD"), "-USD 0.05");
  assert.equal(reports.formatBillAmount("1234.5", "JPY"), "JPY 1,235");
  const html = renderToStaticMarkup(h(reports.AccountCost, { user: { ...actor, role: "admin" }, account }));
  assert.match(html, /AWS Bills 本月账单/);
  assert.ok(html.includes(new Date().toISOString().slice(0, 7)));
  assert.doesNotMatch(html, /type="month"|缓存|Cost Explorer/);
});

test("payer uses a searchable selection and only explicit choices change the selected payer", () => {
  const selected = [];
  const element = reports.PayerChoice({ accountName: account.name, payers: cost.available_payers,
    value: cost.payer_id, onChange: value => selected.push(value) });
  const html = renderToStaticMarkup(element);
  assert.match(html, /role="combobox"/);
  for (const payer of cost.available_payers) assert.ok(html.includes(payer));
  assert.deepEqual(selected, []);
  element.props.onChange({ target: { value: "888888888888" } });
  assert.deepEqual(selected, ["888888888888"]);
});

test("account and actor changes immediately discard payer options and ignore unmounted replies", async () => {
  const pending = [];
  global.fetch = async () => ({ ok: true, json: () => new Promise(resolve => pending.push(resolve)) });
  const user = { ...actor, role: "admin" };
  const host = mountHook(reports.useAccountCost, user, account);
  await settle(); pending[0](cost); await settle(); host.render();
  assert.deepEqual(host.current.availablePayers, cost.available_payers);
  host.render(user, { ...account, id: 2 });
  assert.equal(host.current.data, null);
  assert.deepEqual(host.current.availablePayers, []);
  await settle(); host.render(actor, account); host.unmount();
  pending[1](cost); await settle();
  assert.equal(host.updatesAfterUnmount, 0);
});

test("one hundred cards have at most three active reads and obsolete queued cards never fetch", async () => {
  let active = 0, peak = 0, calls = 0;
  const pending = [];
  global.fetch = async () => {
    calls++; active++; peak = Math.max(peak, active);
    return { ok: true, json: () => new Promise(resolve => pending.push(value => { active--; resolve(value); })) };
  };
  const user = { ...actor, role: "admin" };
  const hosts = Array.from({ length: 100 }, (_, i) => mountHook(reports.useAccountCost, user, { ...account, id: i + 1 }));
  await settle();
  assert.equal(calls, 3);
  for (const host of hosts.slice(50)) host.unmount();
  while (pending.length) { pending.shift()(cost); await settle(); }
  assert.equal(calls, 50); assert.equal(peak, 3);
  for (const host of hosts.slice(0, 50)) { host.render(); assert.ok(host.current.data); host.unmount(); }
  assert.ok(hosts.every(host => host.updatesAfterUnmount === 0));
});
