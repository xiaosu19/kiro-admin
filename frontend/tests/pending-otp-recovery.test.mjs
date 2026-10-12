import test from "node:test";
import assert from "node:assert/strict";
import { mountHook, settle } from "./hooks.mjs";
import { loadSource } from "./load-source.mjs";
import { environment, response, record } from "./plan-change-fixtures.mjs";

const { RecordManager } = await loadSource("RecordManager-test");
function find(node, predicate) {
  if (!node || typeof node !== "object") return null;
  if (Array.isArray(node)) {
    for (const child of node) { const found = find(child, predicate); if (found) return found; }
    return null;
  }
  return predicate(node) ? node : find(node.props?.children, predicate);
}
const button = (host, label) => find(host.current, node => node.type === "button" && node.props.children === label);

test("initial pending OTP exposes only the existing confirmed reset action", async t => {
  const r = { ...record, state: "needs_review", step: "password_pending", has_password: false, credential_state: "unknown" };
  environment(t, async url => response(url === `/api/subscriptions/${r.id}` ? r : []));
  const host = mountHook(RecordManager, { initial: r, onClose() {}, onChanged() {}, onCredentials() {} });
  await settle(); host.render();
  assert.equal(button(host, "重置一次性密码").props.disabled, false);
  for (const label of ["同步 AWS 状态", "更新姓名 / 邮箱", "查看登录信息"])
    assert.equal(button(host, label).props.disabled, true, label);
  button(host, "重置一次性密码").props.onClick(); host.render();
  const confirmation = find(host.current, node => node.type === "input" && node.props.name === "confirm_username");
  assert.ok(confirmation?.props.required, "existing username confirmation remains required");
  host.unmount();
});

for (const variant of [
  { step: "subscribe_pending" }, { step: "create_user_pending" }, { state: "queued" },
  { operation_pending: true }, { operation: { kind: "reset_password", state: "needs_review" } },
]) test(`pending OTP exception cannot unlock unrelated or occupied work: ${JSON.stringify(variant)}`, async t => {
  const r = { ...record, state: "needs_review", step: "password_pending", has_password: false, credential_state: "unknown", ...variant };
  environment(t, async url => response(url === `/api/subscriptions/${r.id}` ? r : []));
  const host = mountHook(RecordManager, { initial: r, onClose() {}, onChanged() {}, onCredentials() {} });
  await settle(); host.render();
  assert.equal(button(host, "重置一次性密码").props.disabled, true);
  host.unmount();
});
