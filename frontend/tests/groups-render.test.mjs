import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";

process.env.NODE_ENV = "production";
const { createElement: h } = await import("react");
const { renderToStaticMarkup } = await import("react-dom/server");
const { MemoryRouter } = await import("react-router-dom");
const {
  StopRuleSource,
  StopScheduleEditor,
  SubscriptionPolicyFields,
  readSubscriptionPolicy,
} = await loadSource("StopSchedule");
const { Groups, GroupDirectoryTable } = await loadSource("Groups");
const render = (component) =>
  renderToStaticMarkup(h(MemoryRouter, null, component));
const group = {
  id: "owned-group",
  name: "研发团队",
  state: "ready",
  policy: { mode: "days", days: 30, revision: 4 },
};
const record = {
  id: "member",
  username: "team-member",
  group_id: group.id,
  provision_only: true,
  plan_id: null,
  state: "completed",
  subscription_status: "not_subscribed",
  stop_schedule: {
    mode: "days",
    days: 30,
    revision: 1,
    source_group_id: group.id,
    individual_override: false,
    state: "waiting",
  },
};

test("unpaid group members see their inherited source and can set a personal rule", () => {
  const html = render(
    h(StopScheduleEditor, { record, group, blocked: false, onChanged() {} }),
  );
  assert.match(html, /分组规则/);
  assert.match(html, /研发团队/);
  assert.match(html, /单独设置停止规则/);
  assert.doesNotMatch(html, /恢复分组规则/);
});

test("individual none offers reset to the current group rule", () => {
  const html = render(
    h(StopScheduleEditor, {
      record: {
        ...record,
        stop_schedule: {
          ...record.stop_schedule,
          mode: "none",
          source_group_id: null,
          individual_override: true,
        },
      },
      group,
      blocked: false,
      onChanged() {},
    }),
  );
  assert.match(html, /个人规则/);
  assert.match(html, /不定时停止/);
  assert.match(html, /恢复分组规则/);
  assert.match(html, /开通后 30 天停止/);
});

test("cancelled and deleted history has no editable rule or reset control", () => {
  for (const patch of [
    { cancelled_at: "2026-10-01" },
    { sso_deleted_at: "2026-10-01" },
  ]) {
    const html = render(
      h(StopScheduleEditor, {
        record: { ...record, ...patch },
        group,
        blocked: false,
        onChanged() {},
      }),
    );
    assert.match(html, /历史记录保留原规则/);
    assert.doesNotMatch(html, /单独设置停止规则|恢复分组规则/);
  }
});

test("a hidden operation prevents record rule actions", () => {
  const html = render(
    h(StopScheduleEditor, {
      record: { ...record, operation_pending: true, operation: null },
      group,
      blocked: false,
      onChanged() {},
    }),
  );
  assert.doesNotMatch(html, /单独设置停止规则|恢复分组规则/);
});

test("subscription UI defaults to existing rules without a hidden none override", () => {
  const html = render(
    h(SubscriptionPolicyFields, { records: [record], groups: [group] }),
  );
  assert.match(html, /value="inherit" selected=""/);
  assert.match(html, /研发团队/);
  assert.doesNotMatch(html, /name="stop_mode"/);
  assert.equal(readSubscriptionPolicy(new FormData()), undefined);
  const form = new FormData();
  form.set("stop_override", "individual");
  form.set("stop_mode", "none");
  assert.deepEqual(readSubscriptionPolicy(form), { mode: "none" });
});

test("AWS association is offered only to administrators in the group directory", () => {
  for (const role of ["member", "admin"]) {
    const html = render(h(Groups, { user: { id: 1, role }, notify() {} }));
    assert.match(html, /创建分组/);
    assert.equal(html.includes("关联已有 AWS 分组"), role === "admin");
  }
});

test("missing group data is shown as loading instead of claiming no stop rule", () => {
  const html = render(
    h(StopRuleSource, { record: { ...record, stop_schedule: null } }),
  );
  assert.match(html, /正在读取分组规则/);
  assert.doesNotMatch(html, /不定时停止/);
});


test("group directory displays membership, eligible and cumulative subscribed counts", () => {
  const html = render(h(GroupDirectoryTable, {
    groups: [{ ...group, owner_id: 2, aws_account_id: 1, counts: { total: 9, active: 7, eligible: 1, subscribed: 3, deleted: 1, cancelled: 1 } }],
    isAdmin: false, ownerName: () => "Alice", accountName: () => "测试 AWS",
  }));
  const text = html.replace(/<[^>]+>/g, "");
  assert.match(text, /成员记录 9 条/);
  assert.match(text, /现存 7 人/);
  assert.match(text, /可订阅 1 人/);
  assert.match(text, /累计已订阅 3 人/);
});

test("empty and deleted group directory rows keep explicit zero counts", () => {
  const html = render(h(GroupDirectoryTable, {
    groups: [{ ...group, deleted_at: "2026-10-01T00:00:00", state: "deleted", counts: { total: 0, active: 0, eligible: 0, subscribed: 0, deleted: 0, cancelled: 0 } }],
    isAdmin: true, ownerName: () => "Alice", accountName: () => "测试 AWS",
  }));
  const text = html.replace(/<[^>]+>/g, "");
  assert.match(text, /成员记录 0 条/);
  assert.match(text, /可订阅 0 人/);
  assert.match(text, /累计已订阅 0 人/);
  assert.match(text, /查看历史/);
});
