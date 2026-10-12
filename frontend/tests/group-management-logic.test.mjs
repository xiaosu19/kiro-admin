import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";
const logic = await loadSource("groupMemberLogic");

test("candidate searches are server scoped and checkbox selection preserves hidden choices up to 100", () => {
  assert.equal(typeof logic.memberCandidatePath, "function");
  assert.equal(logic.memberCandidatePath("group/a", "attach", "user & team", 2), "/groups/group%2Fa/member-candidates?kind=attach&q=user+%26+team&page=2&page_size=100");
  const hidden = [{ id: "hidden", username: "USER subscribed", direct_user_status: "active" }];
  const visible = Array.from({ length: 120 }, (_, i) => ({ id: String(i) }));
  const selected = logic.selectMemberRecords(hidden, visible, true);
  assert.equal(selected.length, 100); assert.equal(selected[0].id, "hidden");
  assert.deepEqual(logic.selectMemberRecords(selected, visible, false), hidden);
});

test("membership intent canonicalizes and freezes body, key and revision", () => {
  assert.equal(typeof logic.memberIntent, "function");
  const group = { id: "g", revision: 4 };
  const value = logic.memberIntent(group, "detach", ["b", "a", "b"]);
  assert.deepEqual(value.body.record_ids, ["a", "b"]);
  assert.equal(value.body.expected_revision, 4); assert.ok(value.body.request_key.length >= 16);
  assert.throws(() => value.body.record_ids.push("c"));
  assert.throws(() => logic.memberIntent(group, "attach", []), /1.*100/);
  assert.throws(() => logic.memberIntent(group, "attach", Array.from({ length: 101 }, (_, i) => String(i))), /1.*100/);
});
