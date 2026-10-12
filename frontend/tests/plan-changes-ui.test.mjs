import test from "node:test";
import assert from "node:assert/strict";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { mountHook, settle } from "./hooks.mjs";
import { loadSource } from "./load-source.mjs";
import { record, options, change, scheduled, response, environment, intent } from "./plan-change-fixtures.mjs";
const ui = await loadSource("PlanChangeManager");
function find(node, predicate) {
  if (!node || typeof node !== "object") return null;
  if (Array.isArray(node)) { for (const child of node) { const hit = find(child, predicate); if (hit) return hit; } return null; }
  return predicate(node) ? node : find(node.props?.children, predicate);
}
const byTest = (host, name) => find(host.current, node => node.props?.["data-testid"] === name);
const changeValue = (host, name, value) => { const input = byTest(host, name); assert.ok(input, name); input.props.onChange({ target: { value, checked: value } }); host.render(); };
function manager(props = {}) { assert.equal(typeof ui.PlanChangeManager, "function", "plan change manager exists"); const panel = ui.PlanChangeManager({ enabled: true, actorId: 7, record, onChanged() {}, ...props }); return mountHook(panel.type, panel.props); }
async function open(host) { await settle(); host.render(); const toggle = byTest(host, "plan-change-toggle"); if (!toggle.props["aria-expanded"]) { toggle.props.onClick(); host.render(); } }
const event = { preventDefault() {} };

test("targets show ascending prices, credits, owner quota, timing and unavailable reasons", () => {
  assert.equal(typeof ui.PlanChangeTargets, "function");
  const html = renderToStaticMarkup(h(ui.PlanChangeTargets, { record, options, value: 0, disabled: false, onChange() {} }));
  const prices = [...html.matchAll(/\$(20|40|100|200) \/ 月/g)].map(match => Number(match[1]));
  assert.deepEqual(prices, [20, 40, 100, 200]);
  for (const text of ["1,000 credits", "10,000 credits", "创建者剩余 3 次", "预占 1 次", "立即升级", "下月降级", "当前套餐", "创建者该套餐次数不足"]) assert.ok(html.includes(text), text);
  assert.doesNotMatch(html, /管理员不限次数/);
  const unlimited = renderToStaticMarkup(h(ui.PlanChangeTargets, { record, options: { ...options, targets: options.targets.map(t => ({ ...t, unlimited: true })) }, value: 0, disabled: false, onChange() {} }));
  assert.match(unlimited, /创建者为管理员 · 不限次数/);
});

test("history shows settlement and actual timestamps without actor identity and offers only read rechecks", () => {
  assert.equal(typeof ui.PlanChangeHistory, "function");
  const pending = { ...scheduled, actor_id: 99, actor_name: "private-admin", error: "等待 AWS 核实" };
  const html = renderToStaticMarkup(h(ui.PlanChangeHistory, { history: [pending, change, { ...change, id: "cancelled", state: "cancelled" }], busy: false, now: Date.parse("2026-10-10T00:11:00Z"), onRecheck() {}, onRelease() {} }));
  for (const text of ["Pro+ → Pro", "等待下月生效", "已生效", "已取消", "申请时间", "实际生效", "预计生效", "预占 1 次", "已计入 1 次", "第 2 轮", "只读核对 AWS", "确认未生效"]) assert.ok(html.includes(text), text);
  assert.doesNotMatch(html, /private-admin|actor_id|再次执行/);
});

test("paid form gates exact confirmation, serializes double clicks and keeps entered form during polling", async t => {
  const posts = [], replies = [];
  const { intervals } = environment(t, (url, request) => {
    if (request.method === "POST") { posts.push({ url, body: JSON.parse(request.body) }); return new Promise(resolve => replies.push(resolve)); }
    return Promise.resolve(response(url.endsWith("plan-options") ? options : []));
  });
  let updates = 0;
  const host = manager({ onChanged() { updates++; } }); await open(host);
  const form = () => byTest(host, "plan-change-form");
  await form().props.onSubmit(event); assert.equal(posts.length, 0);
  const targets = find(host.current, node => node.type === ui.PlanChangeTargets);
  targets.props.onChange(3); host.render();
  changeValue(host, "plan-confirm-username", record.username);
  assert.equal(byTest(host, "plan-change-submit").props.disabled, true);
  changeValue(host, "plan-billing-ack", true);
  for (const poll of intervals) poll(); await settle(); host.render();
  assert.equal(byTest(host, "plan-confirm-username").props.value, record.username);
  assert.equal(byTest(host, "plan-billing-ack").props.checked, true);
  const first = form().props.onSubmit(event); const second = form().props.onSubmit(event);
  assert.equal(posts.length, 1);
  assert.equal(posts[0].body.target_plan_id, 3); assert.equal(posts[0].body.expected_current_type, "PRO_PLUS");
  replies[0](response(change, 202)); await Promise.all([first, second]); host.render();
  assert.equal(updates, 1); assert.equal(byTest(host, "plan-confirm-username").props.value, ""); host.unmount();
});

test("a restored uncertain request can resume with its original body even when fresh options disallow it", async t => {
  const posts = [];
  const env = environment(t, async (url, request) => {
    if (request.method === "POST") { posts.push({ url, body: JSON.parse(request.body) }); return response(change, 202); }
    return response(url.endsWith("plan-options") ? { ...options, current_plan: { plan_id: 3, name: "Power", subscription_type: "POWER" }, unavailable_reason: "该用户已有任务" } : [change]);
  });
  env.storage.set(`kiro-plan-change:7:${record.id}`, JSON.stringify(intent()));
  const host = manager({ record: { ...record, operation_pending: true } }); await open(host);
  assert.equal(posts.length, 0);
  assert.equal(byTest(host, "plan-change-resume").props.disabled, false);
  await byTest(host, "plan-change-resume").props.onClick(); host.render();
  assert.deepEqual(posts[0].body, intent().body); assert.equal(posts.length, 1); host.unmount();
});

test("scheduled downgrade offers a quota-free withdrawal and replacement uses the normal target form", async t => {
  const posts = [];
  const scheduledOptions = { ...options, pending_change: scheduled };
  environment(t, async (url, request) => {
    if (request.method === "POST") { posts.push({ url, body: JSON.parse(request.body) }); return response({ ...scheduled, id: "withdraw-a", predecessor_id: scheduled.id, direction: "withdraw", state: "queued" }, 202); }
    return response(url.endsWith("plan-options") ? scheduledOptions : [scheduled]);
  });
  const host = manager(); await open(host);
  byTest(host, "plan-withdraw-open").props.onClick(); host.render();
  const form = () => byTest(host, "plan-withdraw-form");
  await form().props.onSubmit(event); assert.equal(posts.length, 0);
  changeValue(host, "plan-withdraw-username", record.username);
  changeValue(host, "plan-withdraw-ack", true);
  await form().props.onSubmit(event); host.render();
  assert.equal(posts[0].url, `/api/subscriptions/${record.id}/plan-changes/${scheduled.id}/withdraw`);
  assert.equal(posts[0].body.target_plan_id, undefined);
  assert.equal(posts[0].body.confirm_username, record.username);
  assert.ok(byTest(host, "plan-change-form")); host.unmount();
});

test("recovery remains accessible under record locks and delayed release requires explicit confirmation", async t => {
  const posts = [], item = { ...change, state: "needs_review", error: "网络待核实", write_requested_at: "2026-01-01T00:00:00" };
  environment(t, async (url, request) => {
    if (request.method === "POST") { posts.push({ url, body: JSON.parse(request.body) }); return response(item, 202); }
    return response(url.endsWith("plan-options") ? { ...options, unavailable_reason: "有任务待核对" } : [item]);
  });
  const host = manager({ record: { ...record, operation_pending: true, operation: { kind: "change_plan" } } }); await open(host);
  const history = () => find(host.current, node => node.type === ui.PlanChangeHistory);
  await history().props.onRecheck(item); host.render();
  assert.deepEqual(posts[0].body, { confirm_username: record.username });
  history().props.onRelease(item); host.render();
  const form = () => byTest(host, "plan-release-form");
  await form().props.onSubmit(event); assert.equal(posts.length, 1);
  changeValue(host, "plan-release-username", record.username);
  changeValue(host, "plan-release-reason", "已在 AWS 核实未生效");
  changeValue(host, "plan-release-ack", true);
  await form().props.onSubmit(event); host.render();
  assert.match(posts[1].url, /confirm-not-applied$/);
  assert.deepEqual(posts[1].body, { confirm_username: record.username, reason: "已在 AWS 核实未生效", acknowledge_not_applied: true }); host.unmount();
});

test("late component completions do not call onChanged after unmount or reset a switched record", async t => {
  let finish, updates = 0;
  const env = environment(t, (url, request) => request.method === "POST" ? new Promise(resolve => { finish = resolve; }) : Promise.resolve(response(url.endsWith("plan-options") ? options : [])));
  env.storage.set(`kiro-plan-change:7:${record.id}`, JSON.stringify(intent()));
  const host = manager({ onChanged() { updates++; } }); await open(host);
  const pending = byTest(host, "plan-change-resume").props.onClick();
  host.unmount(); finish(response(change, 202)); await pending;
  assert.equal(updates, 0); assert.equal(host.updatesAfterUnmount, 0);
});

test("directory shows current and pending plans while creation records retain the original plan", () => {
  assert.equal(typeof ui.RecordPlanLabel, "function");
  const item = { ...record, pending_plan: { name: "Pro", subscription_type: "PRO", expected_effective_at: "2026-11-01T00:00:00", state: "scheduled" } };
  const directory = renderToStaticMarkup(h(ui.RecordPlanLabel, { record: item, directory: true }));
  assert.match(directory, /当前（系统记录）：Pro\+/); assert.match(directory, /待生效：Pro/); assert.match(directory, /预计/);
  assert.doesNotMatch(directory, /Original Pro/);
  const creation = renderToStaticMarkup(h(ui.RecordPlanLabel, { record: item, directory: false }));
  assert.match(creation, /Original Pro/); assert.doesNotMatch(creation, /待生效：|当前（系统记录）：/);
});

test("a replacement request selects a distinct target and keeps the existing pending downgrade visible", async t => {
  const posts = [], currentOptions = { ...options, pending_change: scheduled };
  environment(t, async (url, request) => {
    if (request.method === "POST") { posts.push(JSON.parse(request.body)); return response({ ...change, predecessor_id: scheduled.id, state: "queued", counted: false, reserved: true }, 202); }
    return response(url.endsWith("plan-options") ? currentOptions : [scheduled]);
  });
  const host = manager(); await open(host);
  const choices = find(host.current, node => node.type === ui.PlanChangeTargets);
  choices.props.onChange(1); host.render();
  changeValue(host, "plan-confirm-username", record.username); changeValue(host, "plan-billing-ack", true);
  assert.equal(byTest(host, "plan-change-submit").props.disabled, true, "same pending plan stays disabled");
  find(host.current, node => node.type === ui.PlanChangeTargets).props.onChange(3); host.render();
  assert.equal(byTest(host, "plan-change-submit").props.children, "确认改选套餐");
  await byTest(host, "plan-change-form").props.onSubmit(event); host.render();
  assert.equal(posts[0].target_plan_id, 3);
  assert.equal(find(host.current, node => node.type === ui.PlanChangeHistory).props.history[0].id, scheduled.id);
  host.unmount();
});

const driftedRecord = { ...record, plan_name: "Original subscription", subscription_type: "KIRO_PRO",
  current_plan: { plan_id: 1, name: "Kiro Pro", subscription_type: "KIRO_PRO" },
  observed_plan_name: "Kiro Pro+", observed_subscription_type: "KIRO_PRO_PLUS" };

test("directory exposes the managed plan and AWS observation mismatch while preserving the creation label", () => {
  const html = renderToStaticMarkup(h(ui.RecordPlanLabel, { record: driftedRecord, directory: true }));
  assert.match(html, /当前（系统记录）：Kiro Pro/);
  assert.match(html, /AWS 最近观测：Kiro Pro\+/);
  assert.match(html, /系统记录与 AWS 最近观测不一致/);
  const creation = renderToStaticMarkup(h(ui.RecordPlanLabel, { record: driftedRecord, directory: false }));
  assert.equal(creation, "Original subscription");
});

test("record detail facts distinguish both plan sources and compare subscription types before display names", () => {
  assert.equal(typeof ui.CurrentPlanFacts, "function");
  const render = item => renderToStaticMarkup(h(ui.CurrentPlanFacts, { record: item }));
  const drift = render(driftedRecord);
  assert.match(drift, /当前套餐（系统记录）/); assert.match(drift, /AWS 最近观测套餐/);
  assert.match(drift, /Kiro Pro\+/); assert.match(drift, /系统记录与 AWS 最近观测不一致/);
  const renamed = render({ ...driftedRecord, current_plan: { ...driftedRecord.current_plan, name: "团队专用套餐", subscription_type: "KIRO_PRO_PLUS" } });
  assert.match(renamed, /团队专用套餐/); assert.match(renamed, /Kiro Pro\+/);
  assert.doesNotMatch(renamed, /不一致/);
  const unknown = render({ ...driftedRecord, observed_plan_name: null, observed_subscription_type: null });
  assert.match(unknown, /尚未同步/); assert.doesNotMatch(unknown, /不一致/);
});

test("plan change panel exposes AWS drift without replacing the managed admission type or original subscription", async t => {
  const posts = [];
  environment(t, async (url, request) => {
    if (request.method === "POST") { posts.push(JSON.parse(request.body)); return response(change, 202); }
    return response(url.endsWith("plan-options") ? { ...options, current_plan: driftedRecord.current_plan } : []);
  });
  const host = manager({ record: driftedRecord }); await open(host);
  const html = renderToStaticMarkup(host.current);
  assert.match(html, /Original subscription/); assert.match(html, /首次订阅时间 · 只读/);
  assert.match(html, /当前套餐（系统记录）/); assert.match(html, /AWS 最近观测套餐/);
  assert.match(html, /Kiro Pro\+/); assert.match(html, /系统记录与 AWS 最近观测不一致/);
  find(host.current, node => node.type === ui.PlanChangeTargets).props.onChange(3); host.render();
  changeValue(host, "plan-confirm-username", record.username); changeValue(host, "plan-billing-ack", true);
  await byTest(host, "plan-change-form").props.onSubmit(event);
  assert.equal(posts[0].expected_current_type, "KIRO_PRO");
  assert.equal(posts[0].target_plan_id, 3);
  host.unmount();
});
