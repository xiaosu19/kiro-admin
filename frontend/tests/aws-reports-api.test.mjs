import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";

const api = await loadSource("api");
test("AWS report query keeps account selection AND name/email search with no-store", async () => {
  api.setCsrf("report-csrf");
  let request;
  global.fetch = async (path, options) => {
    request = { path, options };
    return { ok: true, json: async () => ({ rows: [] }) };
  };
  const body = { view: "subscriptions", account_ids: [1, 2], q: "alice@example.com" };
  assert.deepEqual(await api.awsReportRequest("/aws-reports/query", body), { rows: [] });
  assert.equal(request.path, "/api/aws-reports/query");
  assert.equal(request.options.cache, "no-store");
  assert.equal(request.options.headers["X-CSRF-Token"], "report-csrf");
  assert.deepEqual(JSON.parse(request.options.body), body);
});

test("a stale actor response cannot expire the new session or disclose a report", async () => {
  let expired = false;
  global.window = { dispatchEvent: () => { expired = true; } };
  global.fetch = async () => ({ ok: false, status: 401, json: async () => ({ detail: "stale" }) });
  assert.equal(await api.awsReportRequest("/aws-reports/query", {}, () => false), null);
  assert.equal(expired, false);
});

test("download validates scope again after blob loading before any browser side effect", async () => {
  let current = true, clicked = false;
  global.fetch = async () => ({ ok: true, headers: new Headers({ "Content-Disposition": 'attachment; filename="aws-users.csv"' }),
    blob: async () => { current = false; return new Blob(["csv"]); } });
  global.document = { createElement: () => { clicked = true; throw new Error("stale download"); } };
  assert.equal(await api.downloadAwsReport({ view: "users", account_ids: [1], row_ids: ["one"] }, () => current), null);
  assert.equal(clicked, false);
});

test("CSV ZIP download sends explicit row IDs and returns included count", async () => {
  let body, clicked = false, removed = false;
  global.fetch = async (_path, options) => { body = JSON.parse(options.body); return {
    ok: true, headers: new Headers({ "Content-Disposition": 'attachment; filename="aws-users.zip"', "X-Export-Count": "2" }),
    blob: async () => new Blob(["zip"]),
  }; };
  const link = { click() { clicked = true; }, remove() { removed = true; } };
  global.document = { createElement: () => link, body: { appendChild() {} } };
  assert.equal(await api.downloadAwsReport({ view: "users", account_ids: [1, 2], row_ids: ["a", "b"], q: "alice" }), 2);
  assert.deepEqual(body.row_ids, ["a", "b"]);
  assert.equal(link.download, "aws-users.zip");
  assert.equal(clicked && removed, true);
});
