import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
import { mountHook } from "./hooks.mjs";

const { LoginExportActions } = await loadSource("AuthSelection");
const { ProvisioningDownloads } = await loadSource("Provisioning");
function find(node, predicate) {
  if (!node || typeof node !== "object") return null;
  if (Array.isArray(node)) { for (const child of node) { const result = find(child, predicate); if (result) return result; } return null; }
  return predicate(node) ? node : find(node.props?.children, predicate);
}
function control(tree) {
  const menu = find(tree, node => node.type?.name === "LoginExportMenu");
  assert.ok(menu, "login information uses the shared export control");
  const host = mountHook(menu.type, menu.props);
  const dialog = find(host.current, node => node.type === "dialog");
  assert.ok(dialog, "a native dialog provides keyboard focus and Escape handling");
  const native = { open: false, showModal() { this.open = true; }, close() { this.open = false; } };
  dialog.ref.current = native;
  return { host, native,
    trigger: () => find(host.current, node => node.type === "button" && node.props["aria-haspopup"] === "dialog"),
    option: (scope, format) => {
      const group = find(host.current, node => node.type === "fieldset" && (!scope || find(node, child => child.type === "legend" && child.props.children === scope)));
      const option = find(group, node => node.type === "button" && String(node.props.children).startsWith(format));
      assert.ok(option, `${scope || "login"} ${format} option`);
      return option;
    },
  };
}
const listProps = { selected: ["a", "b"], canExportSelection: true, hasResults: true, busy: false };
function actions(props) {
  const host = mountHook(LoginExportActions, props), tree = host.current;
  host.unmount();
  return tree;
}

test("one export entry waits for an explicit format and keeps the selected or filtered scope", () => {
  const downloads = [];
  const menu = control(actions({ ...listProps, onExport: (ids, format) => downloads.push({ ids, format }) }));
  for (const [scope, ids, format] of [["选中用户（2）", ["a", "b"], "CSV"], ["选中用户（2）", ["a", "b"], "TXT"], ["筛选结果", undefined, "TXT"]]) {
    const count = downloads.length;
    menu.trigger().props.onClick();
    assert.equal(menu.native.open, true);
    assert.equal(downloads.length, count, "opening the menu never initiates a download");
    menu.option(scope, format).props.onClick();
    assert.equal(menu.native.open, false);
    assert.deepEqual(downloads.at(-1), { ids, format: format.toLowerCase() });
  }
  menu.host.unmount();
});

test("unavailable selection stays disabled while filtered export remains available", () => {
  const downloads = [];
  const menu = control(actions({ ...listProps, canExportSelection: false, onExport: (...args) => downloads.push(args) }));
  assert.equal(menu.trigger().props.disabled, false);
  menu.trigger().props.onClick();
  assert.equal(menu.option("选中用户（2）", "CSV").props.disabled, true);
  menu.option("选中用户（2）", "CSV").props.onClick();
  assert.deepEqual(downloads, []);
  menu.option("筛选结果", "TXT").props.onClick();
  assert.deepEqual(downloads, [[undefined, "txt"]]);
  menu.host.unmount();
});

test("busy or empty controls cannot open or start downloads and busy updates close an open dialog", () => {
  for (const patch of [{ busy: true }, { hasResults: false, canExportSelection: false }]) {
    const downloads = [];
    const menu = control(actions({ ...listProps, ...patch, onExport: (...args) => downloads.push(args) }));
    assert.equal(menu.trigger().props.disabled, true);
    menu.trigger().props.onClick();
    assert.equal(menu.native.open, false);
    menu.option("筛选结果", "TXT").props.onClick();
    assert.deepEqual(downloads, []);
    menu.host.unmount();
  }
  const props = { ...listProps, onExport() {} };
  const tree = actions(props), menu = control(tree);
  menu.trigger().props.onClick();
  menu.host.render({ ...tree.props, disabled: true });
  assert.equal(menu.native.open, false);
  menu.host.unmount();
});

test("provisioning parent and account downloads retain their exact scope and enabled formats", () => {
  const batch = { id: "parent", actor_id: 2 }, downloads = [];
  for (const [account, expected] of [[undefined, { provisioning_batch_id: "parent" }], [{ id: "child", exports: { csv: false, txt: true, json: false }, items: [{ credentials_ready: true }] }, { provisioning_account_batch_id: "child" }]]) {
    const tree = ProvisioningDownloads({ actorId: 2, batch, account, disabled: false, onDownload: value => downloads.push(value) });
    const menu = control(tree);
    menu.trigger().props.onClick();
    menu.option(undefined, "TXT").props.onClick();
    assert.deepEqual(downloads.at(-1), { path: "/sso-users/export", method: "POST", body: { ...expected, format: "txt" } });
    if (account) assert.equal(find(menu.host.current, node => node.type === "button" && node.props.children === "CSV 表格"), null);
    const report = find(tree, node => node.type === "button" && node.props.children === "下载批次报告");
    report.props.onClick();
    assert.deepEqual(downloads.at(-1), { path: `/provisioning-batches/report?${account ? "account_batch_id=child" : "batch_id=parent"}`, method: "GET" });
    menu.host.unmount();
  }
});

test("provisioning keeps credential readiness and JSON ownership gates", () => {
  const props = { actorId: 3, batch: { id: "parent", actor_id: 2, json_download: { requested: true, ready: true } }, account: { id: "child", exports: { csv: true, txt: true, json: true }, items: [{ credentials_ready: false }], json_download: { ready: true } }, disabled: false, onDownload() { assert.fail("unavailable credentials must not download"); } };
  const tree = ProvisioningDownloads(props), menu = control(tree);
  assert.equal(menu.trigger().props.disabled, true);
  menu.option(undefined, "CSV").props.onClick();
  assert.equal(find(tree, node => node.type === "button" && node.props.children === "下载 JSON ZIP"), null);
  const unavailable = ProvisioningDownloads({ ...props, account: { ...props.account, exports: { csv: false, txt: false, json: true } } });
  assert.equal(find(unavailable, node => node.type?.name === "LoginExportMenu"), null);
  menu.host.unmount();
});
