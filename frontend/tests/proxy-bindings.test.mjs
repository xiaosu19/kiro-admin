import test from "node:test";
import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { mountHook, settle } from "./hooks.mjs";
import { loadSource } from "./load-source.mjs";
import { environment, response } from "./plan-change-fixtures.mjs";

const { Proxies } = await loadSource("Proxies");
const api = await loadSource("api");
const archived = { id: 3, name: "旧代理", host: "127.0.0.1", port: 1080, enabled: false, auth_configured: true, binding_count: 1, deleted_binding_count: 1, last_probe_status: null };
function find(node, predicate) {
  if (!node || typeof node !== "object") return null;
  if (Array.isArray(node)) {
    for (const child of node) { const found = find(child, predicate); if (found) return found; }
    return null;
  }
  return predicate(node) ? node : find(node.props?.children, predicate);
}
const button = (host, text) => find(host.current, node => node.type === "button" && node.props.children === text);

test("archived proxy binding is released only after confirmation, enabling later deletion", async t => {
  const calls = [], notices = [];
  let row = { ...archived };
  environment(t, async (url, request) => {
    calls.push({ url, request });
    if (request.method === "POST") row = { ...row, binding_count: 0, deleted_binding_count: 0 };
    return response(request.method === "POST" ? row : [row]);
  });
  api.setCsrf("proxy-csrf");
  const host = mountHook(Proxies, { notify: message => notices.push(message) });
  await settle(); host.render();
  assert.equal(button(host, "删除").props.disabled, true);
  assert.match(renderToStaticMarkup(host.current), /已删除配置：1 个/);
  const release = button(host, "解除旧配置绑定");
  assert.ok(release, "archived configuration has an explicit release entry");
  release.props.onClick(); host.render();
  assert.equal(calls.length, 1, "opening the confirmation does not release a binding");
  assert.match(renderToStaticMarkup(host.current), /恢复.*直接连接/);
  await button(host, "确认解除").props.onClick();
  host.render(); await settle(); host.render();
  const mutation = calls.find(call => call.request.method === "POST");
  assert.equal(mutation.url, "/api/admin/proxies/3/release-deleted-bindings");
  assert.equal(mutation.request.headers["X-CSRF-Token"], "proxy-csrf");
  assert.equal(calls.filter(call => call.request.method === "DELETE").length, 0);
  assert.equal(button(host, "解除旧配置绑定"), null);
  assert.equal(button(host, "删除").props.disabled, false);
  assert.equal(notices.length, 1);
  host.unmount();
});

test("releasing historical references keeps deletion blocked by a current AWS configuration", async t => {
  let row = { ...archived, binding_count: 2 };
  environment(t, async (_url, request) => {
    if (request.method === "POST") row = { ...row, binding_count: 1, deleted_binding_count: 0 };
    return response(request.method === "POST" ? row : [row]);
  });
  const host = mountHook(Proxies, { notify() {} });
  await settle(); host.render();
  assert.match(renderToStaticMarkup(host.current), /当前配置：1 个/);
  button(host, "解除旧配置绑定").props.onClick(); host.render();
  await button(host, "确认解除").props.onClick();
  host.render(); await settle(); host.render();
  assert.equal(button(host, "删除").props.disabled, true);
  assert.equal(button(host, "解除旧配置绑定"), null);
  host.unmount();
});

test("cancelling or rejecting archived unbind leaves the protected proxy unchanged", async t => {
  const calls = [];
  environment(t, async (url, request) => {
    calls.push({ url, request });
    if (request.method === "POST") return response({ detail: "旧配置仍有未完成任务" }, 409);
    return response([{ ...archived }]);
  });
  const host = mountHook(Proxies, { notify() { assert.fail("failed release must not announce success"); } });
  await settle(); host.render();
  assert.ok(button(host, "解除旧配置绑定"));
  button(host, "解除旧配置绑定").props.onClick(); host.render();
  button(host, "取消").props.onClick(); host.render();
  assert.equal(calls.length, 1);
  button(host, "解除旧配置绑定").props.onClick(); host.render();
  await button(host, "确认解除").props.onClick(); host.render();
  assert.match(renderToStaticMarkup(host.current), /旧配置仍有未完成任务/);
  assert.ok(button(host, "确认解除"));
  assert.equal(button(host, "删除").props.disabled, true);
  assert.equal(calls.length, 2);
  host.unmount();
});
