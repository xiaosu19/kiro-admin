import test from "node:test";
import assert from "node:assert/strict";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { mountHook, settle } from "./hooks.mjs";
import { loadSource } from "./load-source.mjs";
import { environment, response, record, intent } from "./plan-change-fixtures.mjs";

const api = await loadSource("api");
const { ManualAuthPicker, GroupAuthPicker, LoginExportActions } = await loadSource("AuthSelection");
const { PlanChangeManager } = await loadSource("PlanChangeManager");
const { Proxies } = await loadSource("Proxies");
function find(node, predicate) {
  if (!node || typeof node !== "object") return null;
  if (Array.isArray(node)) { for (const child of node) { const match = find(child, predicate); if (match) return match; } return null; }
  return predicate(node) ? node : find(node.props?.children, predicate);
}
const input = (host, label) => find(host.current, node => node.props?.["aria-label"] === label);
const button = (host, text) => find(host.current, node => node.type === "button" && node.props.children === text);
const event = { preventDefault() {} };

test("list, all-page selection and exports serialize the same applied account and search scope", () => {
  assert.equal(typeof api.recordQuery, "function");
  assert.equal(typeof api.loginExportBody, "function");
  const scope = { q: "aLi%_ &", status: "active", owner_id: 7, aws_account_id: 2, group_id: "g/a" };
  const params = new URLSearchParams(api.recordQuery(scope));
  assert.deepEqual(Object.fromEntries(params), Object.fromEntries(Object.entries(scope).map(([k, v]) => [k, String(v)])));
  assert.deepEqual(api.loginExportBody(scope, undefined, "txt"), { ...scope, format: "txt" });
  assert.deepEqual(api.loginExportBody(scope, ["record-a"], "txt"), { ...scope, record_ids: ["record-a"], format: "txt" });
  assert.equal(api.loginExportBody(scope).format, "csv");
  assert.equal(new URLSearchParams(api.recordQuery({ q: "email", state: "failed", aws_account_id: 2 })).get("state"), "failed");
});

test("manual selector combines account/search/status and resets page plus reviewed selection", async t => {
  const calls = [], selections = [];
  environment(t, async url => {
    calls.push(url);
    return response(url === "/api/accounts" ? [{ id: 1, name: "AWS A" }, { id: 2, name: "AWS B" }] : { items: [], total: 61 });
  });
  const host = mountHook(ManualAuthPicker, { user: { id: 7 }, kind: "json_export", selected: [record], disabled: false, onChange: rows => selections.push(rows) });
  await settle(); host.render();
  button(host, "下一页").props.onClick(); host.render(); await settle(); host.render();
  assert.equal(new URL(calls.at(-1), "https://console.test").searchParams.get("page"), "2");
  const account = input(host, "按 AWS 账号筛选"); assert.ok(account, "account filter is available");
  account.props.onChange({ target: { value: "2" } }); host.render(); await settle(); host.render();
  assert.deepEqual(selections.at(-1), []);
  let params = new URL(calls.at(-1), "https://console.test").searchParams;
  assert.equal(params.get("page"), "1"); assert.equal(params.get("aws_account_id"), "2");
  input(host, "搜索用户名、姓名或邮箱").props.onChange({ target: { value: "Ali%_" } }); host.render();
  find(host.current, node => node.type === "form").props.onSubmit(event); host.render(); await settle(); host.render();
  params = new URL(calls.at(-1), "https://console.test").searchParams;
  assert.equal(params.get("q"), "Ali%_"); assert.equal(params.get("aws_account_id"), "2"); assert.equal(params.get("owner_id"), "7");
  input(host, "SSO 状态").props.onChange({ target: { value: "unsubscribed" } }); host.render(); await settle(); host.render();
  params = new URL(calls.at(-1), "https://console.test").searchParams;
  assert.equal(params.get("status"), "unsubscribed"); assert.equal(params.get("q"), "Ali%_");
  assert.equal(selections.length, 3); host.unmount();
});

test("group selector intersects account and literal group-name search and clears the old group", async t => {
  environment(t, async url => response(url === "/api/accounts" ? [{ id: 1, name: "A" }, { id: 2, name: "B" }] : [
    { id: "one", owner_id: 7, aws_account_id: 1, name: "ALICE%_", state: "ready" },
    { id: "two", owner_id: 7, aws_account_id: 2, name: "alice%_", state: "ready" },
    { id: "three", owner_id: 7, aws_account_id: 2, name: "other", state: "ready" },
    { id: "foreign", owner_id: 8, aws_account_id: 2, name: "alice%_", state: "ready" },
  ]));
  const changes = [], groups = [];
  const host = mountHook(GroupAuthPicker, { groupId: "one", onGroup: id => groups.push(id), user: { id: 7 }, kind: "json_export", selected: [record], disabled: false, onChange: rows => changes.push(rows) });
  await settle(); host.render();
  const account = input(host, "按 AWS 账号筛选"); assert.ok(account, "group account filter is available");
  account.props.onChange({ target: { value: "2" } }); host.render();
  input(host, "搜索分组名称").props.onChange({ target: { value: "ICE%_" } }); host.render();
  const select = input(host, "我的分组");
  const html = renderToStaticMarkup(select);
  assert.match(html, /value="two"/); assert.doesNotMatch(html, /value="one"|value="three"|value="foreign"/);
  assert.deepEqual(groups, ["", ""]); assert.deepEqual(changes, [[], []]); host.unmount();
});

test("TXT download sends explicit selection and uses attachment filename without caching", async t => {
  assert.equal(typeof api.downloadLogins, "function");
  const calls = [], downloads = [], urls = [];
  environment(t, async (url, request) => { calls.push({ url, request }); return new Response("AWS 登录地址：synthetic", { headers: { "Content-Disposition": 'attachment; filename="selected.txt"', "X-Export-Count": "2" } }); });
  const oldDocument = globalThis.document;
  globalThis.document = { createElement: () => ({ click() { downloads.push(this.download); }, remove() {} }), body: { appendChild() {} } };
  t.after(() => { globalThis.document = oldDocument; });
  t.mock.method(URL, "createObjectURL", () => "blob:synthetic");
  t.mock.method(URL, "revokeObjectURL", value => urls.push(value));
  t.mock.method(globalThis, "setTimeout", fn => { fn(); return 1; });
  api.setCsrf("test-csrf");
  assert.equal(await api.downloadLogins({ record_ids: ["a", "b"], aws_account_id: 2, format: "txt" }), 2);
  assert.deepEqual(JSON.parse(calls[0].request.body), { record_ids: ["a", "b"], aws_account_id: 2, format: "txt" });
  assert.equal(calls[0].request.headers["X-CSRF-Token"], "test-csrf"); assert.equal(calls[0].request.cache, "no-store");
  assert.deepEqual(downloads, ["selected.txt"]); assert.deepEqual(urls, ["blob:synthetic"]);
});

test("export controls use one entry while preserving selected and filtered scopes", () => {
  assert.equal(typeof LoginExportActions, "function");
  const exports = [];
  const host = mountHook(LoginExportActions, { selected: ["a"], canExportSelection: true, hasResults: true, busy: false, onExport: (ids, format) => exports.push({ ids, format }) });
  const menu = find(host.current, node => node.type?.name === "LoginExportMenu");
  assert.ok(menu, "one shared export entry replaces the format selector and separate buttons");
  assert.deepEqual(exports, []);
  assert.equal(menu.props.scopes.length, 2);
  menu.props.scopes[0].onExport("txt");
  menu.props.scopes[1].onExport("txt");
  assert.deepEqual(exports, [{ ids: ["a"], format: "txt" }, { ids: undefined, format: "txt" }]);
  host.unmount();
});

test("disabled plan capability hides every control and makes no plan reads even with pending history", async t => {
  const calls = [];
  const env = environment(t, async url => { calls.push(url); return response({}); });
  env.storage.set(`kiro-plan-change:7:${record.id}`, JSON.stringify(intent()));
  for (const enabled of [false, undefined]) {
    const html = renderToStaticMarkup(h(PlanChangeManager, { enabled, actorId: 7, record: { ...record, pending_plan: { state: "scheduled" } }, onChanged() {} }));
    assert.equal(html, "");
  }
  assert.deepEqual(calls, []);
});

test("proxy inventory names safe diagnostic categories and whether auth was saved", async t => {
  const states = { auth_failed: "认证失败", timeout: "探测超时", connect: "连接失败", tls: "TLS 验证失败", invalid_response: "响应无效" };
  environment(t, async () => response(Object.keys(states).map((status, index) => ({ id: index, name: status, host: "127.0.0.1", port: 1080, enabled: true, auth_configured: index === 0, binding_count: 1, last_probe_status: status }))));
  const host = mountHook(Proxies, { notify() {} }); await settle(); host.render();
  const html = renderToStaticMarkup(host.current);
  for (const label of Object.values(states)) assert.ok(html.includes(label), label);
  assert.match(html, /认证已保存/); assert.match(html, /无认证/); host.unmount();
});
