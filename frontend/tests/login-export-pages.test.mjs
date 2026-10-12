import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
import { mountHook, settle } from "./hooks.mjs";
import { environment, response } from "./plan-change-fixtures.mjs";

const { Records, BatchProgress } = await loadSource("LoginExports-test");
function find(node, predicate) {
  if (!node || typeof node !== "object") return null;
  if (Array.isArray(node)) { for (const child of node) { const result = find(child, predicate); if (result) return result; } return null; }
  return predicate(node) ? node : find(node.props?.children, predicate);
}
function downloadEnvironment(t, read) {
  const requests = [];
  const state = environment(t, async (url, request) => {
    if (request.method !== "POST") return response(read(url));
    requests.push({ url, body: JSON.parse(request.body) });
    return new Response("synthetic-login-file", { headers: { "Content-Disposition": 'attachment; filename="login.txt"', "X-Export-Count": "1" } });
  });
  const savedDocument = globalThis.document;
  globalThis.document = { createElement: () => ({ click() {}, remove() {} }), body: { appendChild() {} } };
  t.after(() => { globalThis.document = savedDocument; });
  t.mock.method(URL, "createObjectURL", () => "blob:synthetic");
  t.mock.method(URL, "revokeObjectURL", () => {});
  t.mock.method(globalThis, "setTimeout", callback => { callback(); return 1; });
  return { ...state, requests };
}
function menuFrom(tree) {
  const component = find(tree, node => node.type?.name === "LoginExportMenu");
  assert.ok(component, "login export uses the format chooser");
  const host = mountHook(component.type, component.props);
  find(host.current, node => node.type === "dialog").ref.current = { open: false, showModal() { this.open = true; }, close() { this.open = false; } };
  return { host, choose: async format => {
    find(host.current, node => node.type === "button" && node.props["aria-haspopup"] === "dialog").props.onClick();
    const option = find(host.current, node => node.type === "button" && String(node.props.children).startsWith(format));
    assert.ok(option); option.props.onClick(); await settle();
  } };
}
const record = { id: "record-a", username: "synthetic-user", owner_id: 7, state: "completed", sso_user_id: "sso-a", has_password: true, credential_state: "permanent" };
const page = items => ({ page: 1, total: items.length, items });

test("single-record TXT and CSV exports keep the current search, owner, account and group filters", async t => {
  const { requests } = downloadEnvironment(t, url => url.startsWith("/api/sso-users?") ? page([record]) : []);
  const host = mountHook(Records, { directory: true }); await settle(); host.render();
  find(host.current, node => node.type === "input" && node.props["aria-label"] === "搜索用户名、姓名或邮箱").props.onChange({ target: { value: "Ali%_" } }); host.render();
  find(host.current, node => node.type === "form").props.onSubmit({ preventDefault() {} }); host.render(); await settle(); host.render();
  for (const format of ["TXT", "CSV"]) {
    const row = find(host.current, node => node.type === "tr" && node.key === record.id);
    const menu = menuFrom(row);
    assert.equal(requests.length, format === "TXT" ? 0 : 1);
    await menu.choose(format); host.render();
    assert.deepEqual(requests.at(-1), { url: "/api/sso-users/export", body: { q: "Ali%_", status: "active", owner_id: 7, aws_account_id: 2, group_id: "g-a", record_ids: [record.id], format: format.toLowerCase() } });
    menu.host.unmount();
  }
  host.unmount();
});

test("row export stays disabled for missing credentials, deleted SSO and pending operations", async t => {
  const rows = [{ ...record, id: "no-password", has_password: false }, { ...record, id: "deleted", sso_deleted_at: "date" }, { ...record, id: "pending", operation_pending: true }, { ...record, id: "operation", operation: { kind: "json_export", state: "running" } }];
  const { requests } = downloadEnvironment(t, url => url.startsWith("/api/sso-users?") ? page(rows) : []);
  const host = mountHook(Records, { directory: true }); await settle(); host.render();
  for (const record of rows) {
    const row = find(host.current, node => node.type === "tr" && node.key === record.id), menu = menuFrom(row);
    assert.equal(find(menu.host.current, node => node.type === "button" && node.props["aria-haspopup"] === "dialog").props.disabled, true);
    await menu.choose("TXT"); menu.host.unmount();
  }
  assert.deepEqual(requests, []); host.unmount();
});

test("ordinary batch exports choose CSV or TXT without changing the batch ID or automatic-export behavior", async t => {
  const batch = { id: "batch-a", kind: "create", owner_id: 7, export_credentials: false, total: 1, states: { completed: 1, queued: 0, running: 0, failed: 0, needs_review: 0 }, items: [{ ...record, has_credentials: true }] };
  const { requests } = downloadEnvironment(t, () => batch);
  const host = mountHook(BatchProgress, { id: batch.id }); await settle(); host.render();
  assert.deepEqual(requests, []);
  for (const format of ["CSV", "TXT"]) {
    const menu = menuFrom(host.current);
    await menu.choose(format); host.render();
    assert.deepEqual(requests.at(-1), { url: "/api/sso-users/export", body: { batch_id: "batch-a", format: format.toLowerCase() } });
    menu.host.unmount();
  }
  host.unmount();
});
