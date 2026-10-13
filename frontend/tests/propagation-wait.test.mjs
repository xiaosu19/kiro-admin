import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
process.env.NODE_ENV = "production";
const { createElement: h } = await import("react");
const { renderToStaticMarkup } = await import("react-dom/server");
const { RetryStatus } = await loadSource("RetryStatus");
const render = value => renderToStaticMarkup(h(RetryStatus, { value }));

test("AWS synchronization explains automatic continuation without claiming failed retries", () => {
  const html = render({ propagation_state: "waiting", propagation_check_count: 12, automatic_retry_count: 0,
    propagation_last_checked_at: "2026-01-01T01:00:00", next_retry_at: "2026-01-01T01:15:00", propagation_deadline: "2026-01-02T00:00:00" });
  for (const text of ["等待 AWS 同步成员", "后台会自动核对", "确认后继续改密和导出", "上次核对", "下次核对", "等待截止", "24 小时", "无需重复开通"])
    assert.ok(html.includes(text), text);
  assert.doesNotMatch(html, /自动重试|处理失败|已达上限/);
});

test("deadline stops waiting and asks for reconciliation of the original request", () => {
  const html = render({ propagation_state: "timed_out", automatic_retry_count: 0 });
  assert.match(html, /超过 24 小时/); assert.match(html, /已停止自动等待/);
  assert.match(html, /原订阅请求/); assert.match(html, /不会重复开通/);
});

test("normal failures retain five retries and settled waits are silent", () => {
  assert.match(render({ automatic_retry_count: 5, retry_exhausted: true }), /自动重试 5\/5.*已达上限/);
  assert.equal(render({ propagation_state: null, propagation_check_count: 12, automatic_retry_count: 0 }), "");
});
