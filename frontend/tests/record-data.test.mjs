import test from "node:test";
import assert from "node:assert/strict";
import { mountHook, settle } from "./hooks.mjs";
import { loadSource } from "./load-source.mjs";
import { environment, response } from "./plan-change-fixtures.mjs";

const { useData } = await loadSource("App");
const { recordQuery } = await loadSource("api");
const { AuthRecordTable } = await loadSource("AuthSelection");
const accountA = `/sso-users?page=1&${recordQuery({ aws_account_id: 1, q: "Ali%_", status: "active" })}`;
const accountB = `/sso-users?page=1&${recordQuery({ aws_account_id: 2, q: "BeTa", status: "active" })}`;
const page = (account, username) => ({ total: 1, page: 1, items: [{
  id: `${account}-${username}`, aws_account_id: account, username, owner_id: 7,
  sso_user_id: `sso-${username}`, state: "completed", subscription_status: "active", credential_state: "permanent", has_password: true,
}] });
function find(node, predicate) {
  if (!node || typeof node !== "object") return null;
  if (Array.isArray(node)) { for (const child of node) { const match = find(child, predicate); if (match) return match; } return null; }
  return predicate(node) ? node : find(node.props?.children, predicate);
}
function requestsFor(t) {
  const requests = [];
  const env = environment(t, url => new Promise(resolve => requests.push({ url, resolve })));
  return { requests, ...env };
}

for (const oldResponse of ["success", "error"]) {
  test(`late account/search ${oldResponse} cannot replace current rows, selection or error`, async t => {
    const { requests, intervals } = requestsFor(t);
    const host = mountHook(useData, accountA, 4000);
    requests[0].resolve(response(page(1, "Alice"))); await settle(); host.render();
    intervals[0](); // The old account's automatic refresh is now in flight.
    host.render(accountB, 4000);
    requests[2].resolve(response(page(2, "Beta"))); await settle(); host.render();
    const current = host.current.data;
    requests[1].resolve(oldResponse === "success" ? response(page(1, "Alice-old")) : response({ detail: "old account failed" }, 503));
    await settle(); host.render();
    assert.deepEqual(host.current.data, current);
    assert.equal(host.current.error, "");
    assert.equal(host.current.loading, false);
    // The displayed page is the only source for a concrete reviewed selection.
    let selected;
    const table = AuthRecordTable({ user: { id: 7 }, kind: "json_export", records: host.current.data.items, selected: [], disabled: false, onChange: rows => { selected = rows; } });
    find(table, node => node.type === "button" && node.props.children === "选中本页可处理用户").props.onClick();
    assert.deepEqual(selected.map(row => row.id), ["2-Beta"]);
    assert.deepEqual(requests.map(request => request.url), [`/api${accountA}`, `/api${accountA}`, `/api${accountB}`]);
    host.unmount();
  });
}

test("old refresh callbacks and completions cannot end the current scope's loading", async t => {
  const { requests } = requestsFor(t);
  const host = mountHook(useData, accountA, 4000);
  requests[0].resolve(response(page(1, "Alice"))); await settle(); host.render();
  const oldRefresh = host.current.refresh;
  const pending = oldRefresh();
  host.render(accountB, 4000);
  requests[1].resolve(response(page(1, "Alice-old"))); await pending; host.render();
  assert.equal(host.current.data, null);
  assert.equal(host.current.loading, true);
  assert.equal(host.current.error, "");
  await oldRefresh();
  assert.equal(requests.length, 3, "a callback from account A cannot start another request while B is current");
  requests[2].resolve(response(page(2, "Beta"))); await settle(); host.render();
  assert.equal(host.current.loading, false);
  host.unmount();
});

test("returning to the same account starts a new scope generation", async t => {
  const { requests, intervals } = requestsFor(t);
  const host = mountHook(useData, accountA, 4000);
  requests[0].resolve(response(page(1, "Alice"))); await settle(); host.render();
  intervals[0]();
  host.render(accountB, 4000);
  host.render(accountA, 4000);
  requests[3].resolve(response(page(1, "Alice-current"))); await settle(); host.render();
  requests[1].resolve(response(page(1, "Alice-old")));
  requests[2].resolve(response(page(2, "Beta"))); await settle(); host.render();
  assert.equal(host.current.data.items[0].username, "Alice-current");
  assert.equal(host.current.loading, false);
  host.unmount();
});

test("a stale success cannot clear a current error and switching scope resets it", async t => {
  const { requests, intervals } = requestsFor(t);
  const host = mountHook(useData, accountA, 4000);
  requests[0].resolve(response(page(1, "Alice"))); await settle(); host.render();
  intervals[0]();
  host.render(accountB, 4000);
  requests[2].resolve(response({ detail: "current account failed" }, 503)); await settle(); host.render();
  requests[1].resolve(response(page(1, "Alice-old"))); await settle(); host.render();
  assert.equal(host.current.data, null);
  assert.equal(host.current.error, "current account failed");
  host.render(accountA, 4000);
  assert.equal(host.current.error, "");
  assert.equal(host.current.loading, true);
  host.unmount();
});

for (const outcome of ["success", "error"]) {
  test(`refresh ${outcome} after unmount cannot update any state`, async t => {
    const { requests } = requestsFor(t);
    const host = mountHook(useData, accountA, 4000);
    requests[0].resolve(response(page(1, "Alice"))); await settle(); host.render();
    const refresh = host.current.refresh;
    const pending = refresh();
    host.unmount();
    requests[1].resolve(outcome === "success" ? response(page(1, "Alice-old")) : response({ detail: "unmounted failure" }, 503));
    await pending;
    assert.equal(host.updatesAfterUnmount, 0);
    await refresh();
    assert.equal(requests.length, 2);
  });
}

test("same-scope manual refresh and periodic refresh still update current records", async t => {
  const { requests, intervals } = requestsFor(t);
  const host = mountHook(useData, accountA, 4000);
  requests[0].resolve(response(page(1, "Alice"))); await settle(); host.render();
  const pending = host.current.refresh();
  requests[1].resolve(response(page(1, "Alice-manual"))); await pending; host.render();
  assert.equal(host.current.data.items[0].username, "Alice-manual");
  intervals[0]();
  requests[2].resolve(response(page(1, "Alice-poll"))); await settle(); host.render();
  assert.equal(host.current.data.items[0].username, "Alice-poll");
  assert.equal(host.current.loading, false);
  assert.equal(host.current.error, "");
  host.unmount();
});
