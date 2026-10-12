import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
const {
  ownedCreationGroups,
  canSubscribeRecord,
  canEditStopRule,
  subscriptionRequest,
  resetToGroupRequest,
  policyPreviewCurrent,
  validateSsoCreation,
  createSsoIntent,
  runSsoCreation,
  selectionFromPreview,
} = await loadSource("groupsLogic");

const group = {
  id: "group-a",
  owner_id: 7,
  aws_account_id: 3,
  state: "ready",
  active_job_id: null,
  deleted_at: null,
  revision: 24,
  policy: { mode: "days", days: 30, revision: 4 },
};
const record = {
  id: "sso-a",
  plan_id: null,
  provision_only: true,
  state: "completed",
  subscription_status: "not_subscribed",
  sso_user_id: "aws-user",
  sso_deleted_at: null,
  cancelled_at: null,
  observed_plan_name: null,
  group_id: group.id,
  group_membership_id: "membership",
  operation: null,
  operation_pending: false,
  stop_schedule: {
    mode: "days",
    days: 30,
    revision: 9,
    source_group_id: group.id,
    individual_override: false,
  },
};

test("SSO creation offers only current creator and account groups that can admit members", () => {
  assert.deepEqual(
    ownedCreationGroups(
      [
        group,
        { ...group, id: "creating", state: "creating" },
        { ...group, id: "other-owner", owner_id: 8 },
        { ...group, id: "other-account", aws_account_id: 9 },
        { ...group, id: "history", deleted_at: "2026-01-01" },
        { ...group, id: "busy", state: "updating" },
      ],
      7,
      3,
    ).map((g) => g.id),
    ["group-a", "creating"],
  );
});

test("subscription eligibility respects hidden operations and confirmed group membership", () => {
  assert.equal(canSubscribeRecord(record), true);
  assert.equal(
    canSubscribeRecord({ ...record, operation_pending: true }),
    false,
  );
  assert.equal(
    canSubscribeRecord({ ...record, group_membership_id: null }),
    false,
  );
  assert.equal(canSubscribeRecord({ ...record, plan_id: 2 }), false);
});

test("unpaid group members can edit rules, while historical and busy members cannot", () => {
  assert.equal(canEditStopRule(record), true);
  for (const patch of [
    { sso_deleted_at: "2026-01-01" },
    { cancelled_at: "2026-01-01" },
    { subscription_status: "cancel_scheduled" },
    { operation_pending: true },
    { group_id: null },
  ]) {
    assert.equal(canEditStopRule({ ...record, ...patch }), false);
  }
});

test("default subscription omits a rule so each selected user inherits its existing source", () => {
  assert.deepEqual(subscriptionRequest(["one", "two"], 2), {
    record_ids: ["one", "two"],
    plan_id: 2,
  });
  assert.deepEqual(subscriptionRequest(["one"], 2, undefined, group.id), {
    record_ids: ["one"],
    plan_id: 2,
    group_id: group.id,
  });
});

test("explicit none is retained as an independent override", () => {
  assert.deepEqual(
    subscriptionRequest(["one"], 2, { mode: "none" }).stop_schedule,
    { mode: "none" },
  );
});

test("subscription admission freezes distinct explicit IDs and enforces the 100 member cap", () => {
  const ids = ["one", "two"];
  const body = subscriptionRequest(ids, 2);
  ids.push("later");
  assert.deepEqual(body.record_ids, ["one", "two"]);
  assert.throws(() => subscriptionRequest([], 2));
  assert.throws(() => subscriptionRequest(["one", "one"], 2));
  assert.throws(() =>
    subscriptionRequest(
      Array.from({ length: 101 }, (_, i) => String(i)),
      2,
    ),
  );
  assert.deepEqual(
    selectionFromPreview(["one", "stale", "two"], ["one", "two"]),
    ["one", "two"],
  );
});

test("reset uses record schedule and group POLICY revisions, never group CRUD revision", () => {
  assert.deepEqual(resetToGroupRequest(record, group), {
    expected_revision: 9,
    expected_group_revision: 4,
  });
  assert.deepEqual(
    resetToGroupRequest({ ...record, stop_schedule: null }, group),
    { expected_revision: 0, expected_group_revision: 4 },
  );
});

test("editing a reviewed group policy or changing its revision invalidates the preview", () => {
  const body = {
    policy: { mode: "days", days: 30 },
    expected_revision: 4,
    overwrite_individual: false,
  };
  assert.equal(policyPreviewCurrent(body, structuredClone(body), 4), true);
  assert.equal(
    policyPreviewCurrent(
      body,
      { ...body, policy: { mode: "days", days: 31 } },
      4,
    ),
    false,
  );
  assert.equal(
    policyPreviewCurrent(body, { ...body, overwrite_individual: true }, 4),
    false,
  );
  assert.equal(policyPreviewCurrent(body, body, 5), false);
});

const ssoBody = {
  kind: "sso",
  aws_account_id: 3,
  export_credentials: false,
  items: [{ username: "member-a", email: null }],
};
test("invalid SSO data is rejected before a group creation intent can be made", () => {
  assert.throws(() =>
    createSsoIntent(
      { ...ssoBody, items: [{ username: "!", email: null }] },
      { name: "Group", aws_account_id: 3 },
    ),
  );
  assert.throws(() =>
    validateSsoCreation({
      ...ssoBody,
      items: [{ username: "valid", email: "broken" }],
    }),
  );
  assert.throws(() =>
    validateSsoCreation({
      ...ssoBody,
      items: [
        { username: "valid", email: "a@b.com" },
        { username: "other", email: "A@b.com" },
      ],
    }),
  );
  assert.doesNotThrow(() =>
    validateSsoCreation({
      ...ssoBody,
      items: undefined,
      sequence: { pattern: "test-01-02", email_template: "" },
    }),
  );
});

test("a lost group response reuses its key and never creates an extra group or batch", async () => {
  let intent = createSsoIntent(ssoBody, { name: "Group", aws_account_id: 3 });
  const persisted = [],
    groups = new Map(),
    batches = new Map();
  let loseGroupResponse = true;
  const post = async (path, body) => {
    const store = path === "/groups" ? groups : batches;
    if (!store.has(body.request_key))
      store.set(body.request_key, {
        id: path === "/groups" ? "new-group" : "batch",
      });
    if (path === "/groups" && loseGroupResponse) {
      loseGroupResponse = false;
      throw new TypeError("network lost");
    }
    if (path === "/batches/create") {
      assert.equal(body.group_id, "new-group");
      assert.equal("stop_schedule" in body, false);
    }
    return store.get(body.request_key);
  };
  const checkpoint = (next) => {
    intent = structuredClone(next);
    persisted.push(intent);
  };
  await assert.rejects(runSsoCreation(intent, post, checkpoint));
  assert.equal(groups.size, 1);
  const result = await runSsoCreation(
    structuredClone(intent),
    post,
    checkpoint,
  );
  assert.equal(result.id, "batch");
  assert.equal(groups.size, 1);
  assert.equal(batches.size, 1);
  assert.equal(persisted.at(-1).group.id, "new-group");
});

test("a lost batch response reuses saved group and batch keys after a reload", async () => {
  let intent = createSsoIntent(ssoBody, { name: "Group", aws_account_id: 3 });
  let groupCalls = 0,
    loseBatchResponse = true;
  const batches = new Map();
  const post = async (path, body) => {
    if (path === "/groups") {
      groupCalls++;
      return { id: "created-group" };
    }
    if (!batches.has(body.request_key))
      batches.set(body.request_key, { id: "batch" });
    if (loseBatchResponse) {
      loseBatchResponse = false;
      throw new TypeError("network lost");
    }
    return batches.get(body.request_key);
  };
  await assert.rejects(
    runSsoCreation(intent, post, (next) => {
      intent = structuredClone(next);
    }),
  );
  const result = await runSsoCreation(structuredClone(intent), post, () => {});
  assert.equal(result.id, "batch");
  assert.equal(groupCalls, 1);
  assert.equal(batches.size, 1);
});

test("counted subscriptions must be active before their stop rules can be edited", () => {
  assert.equal(
    canEditStopRule({
      ...record,
      counted: true,
      plan_id: 2,
      provision_only: false,
      subscription_status: "not_subscribed",
    }),
    false,
  );
});

const { runRecoverableSubmission } = await loadSource("groupsLogic");
const rejected = (status, message) => Object.assign(new Error(message), { status });
const renameRequest = {
  path: "/groups/group-a/jobs",
  body: { kind: "rename", name: "renamed", expected_revision: 1, request_key: "rename-stable-key" },
};

function recoveryState(post, execute = (intent, send) => send(intent.path, intent.body)) {
  let pending = null;
  return {
    get pending() { return pending; },
    submit(intent) {
      return runRecoverableSubmission(intent, post, next => { pending = structuredClone(next); },
        (send, checkpoint) => execute(intent, send, checkpoint));
    },
  };
}

test("lost rename before admission then revision conflict clears pending and permits a fresh revision", async () => {
  const attempts = [];
  const state = recoveryState(async (path, body) => {
    attempts.push({ path, body: structuredClone(body) });
    if (attempts.length === 1) throw new TypeError("response lost");
    if (body.expected_revision === 1) throw rejected(409, "分组已变化或有未完成任务，请刷新后重试");
    return { id: "accepted-job" };
  });
  assert.equal((await state.submit(renameRequest)).state, "unresolved");
  assert.deepEqual(state.pending, renameRequest);
  assert.equal((await state.submit(state.pending)).state, "rejected");
  assert.equal(state.pending, null);
  const next = { ...renameRequest, body: { ...renameRequest.body, expected_revision: 2, request_key: "fresh-rename-key" } };
  assert.equal((await state.submit(next)).state, "accepted");
  assert.deepEqual(attempts[0], attempts[1]);
});

test("network then validation rejection unlocks group creation without losing uncertain retries", async () => {
  for (const status of [400, 422]) {
    let attempt = 0;
    const state = recoveryState(async () => {
      if (++attempt === 1) throw new TypeError("network error");
      throw rejected(status, "分组名称不符合要求");
    });
    const request = { path: "/groups", body: { name: "invalid", request_key: "group-stable-key" } };
    assert.equal((await state.submit(request)).state, "unresolved");
    assert.equal((await state.submit(state.pending)).state, "rejected");
    assert.equal(state.pending, null);
  }
});

test("network and server failures replay exactly the same request until accepted", async () => {
  const calls = [];
  const state = recoveryState(async (path, body) => {
    calls.push({ path, body: structuredClone(body) });
    if (calls.length === 1) throw new TypeError("network error");
    if (calls.length === 2) throw rejected(503, "服务暂时不可用");
    return { id: "original-job" };
  });
  for (let i = 0; i < 2; i++) {
    assert.equal((await state.submit(state.pending || renameRequest)).state, "unresolved");
    assert.deepEqual(state.pending, renameRequest);
  }
  assert.equal((await state.submit(state.pending)).state, "accepted");
  assert.equal(state.pending, null);
  assert.deepEqual(calls, [renameRequest, renameRequest, renameRequest]);
});

test("authentication, permission and unrecognized conflicts do not discard a possibly admitted request", async () => {
  for (const [status, message] of [[401, "请登录"], [403, "无权使用该 AWS 账号"], [429, "稍后重试"], [409, "重复请求标识与原分组操作不同"], [409, "未知冲突"]]) {
    const state = recoveryState(async () => { throw rejected(status, message); });
    assert.equal((await state.submit(renameRequest)).state, "unresolved");
    assert.deepEqual(state.pending, renameRequest);
  }
});

test("rejected SSO recovery retains the already created group while unlocking the form", async () => {
  for (const [status, message] of [[422, "邮箱格式有误"], [409, "编号范围包含已使用的用户名，请调整起始编号后重试"]]) {
    let groupCalls = 0, batchCalls = 0;
    const state = recoveryState(async (path) => {
      if (path === "/groups") { groupCalls++; return { id: "durable-group" }; }
      if (++batchCalls === 1) throw new TypeError("network lost");
      throw rejected(status, message);
    }, (intent, post, checkpoint) => runSsoCreation(intent, post, checkpoint));
    const intent = createSsoIntent(ssoBody, { name: "Saved group", aws_account_id: 3 });
    assert.equal((await state.submit(intent)).state, "unresolved");
    assert.equal(state.pending.group.id, "durable-group");
    const result = await state.submit(state.pending);
    assert.equal(result.state, "rejected");
    assert.equal(state.pending, null);
    assert.equal(result.intent.group.id, "durable-group");
    assert.equal(groupCalls, 1);
  }
});

test("a committed request with a lost response survives expired login or permissions without a second admission", async () => {
  for (const status of [401, 403]) {
    const admitted = new Map();
    let calls = 0;
    const state = recoveryState(async (_path, body) => {
      calls++;
      if (calls === 2) throw rejected(status, "访问需要恢复");
      if (!admitted.has(body.request_key)) admitted.set(body.request_key, { id: "original-admission" });
      if (calls === 1) throw new TypeError("response lost after commit");
      return admitted.get(body.request_key);
    });
    assert.equal((await state.submit(renameRequest)).state, "unresolved");
    assert.equal((await state.submit(state.pending)).state, "unresolved");
    assert.deepEqual(state.pending, renameRequest);
    const result = await state.submit(state.pending);
    assert.equal(result.state, "accepted");
    assert.equal(result.result.id, "original-admission");
    assert.equal(admitted.size, 1);
    assert.equal(state.pending, null);
  }
});
