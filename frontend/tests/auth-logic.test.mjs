import test from "node:test";
import assert from "node:assert/strict";
import { loadSource } from "./load-source.mjs";

const { authRequest, selectAuthRecords, selectPreviewIds, canUseAuthRecord,
  validPermanentPassword, credentialLabel, credentialText, widgetInit,
  acceptWidgetMessage, batchCanDownload, retryableItems } = await loadSource("authLogic");

test("selection retains accounts across pages and filters, deduplicates, and stops at 100", () => {
  const old = ["earlier-page", "filtered-out"];
  assert.deepEqual(selectAuthRecords(old, ["next-page", "earlier-page"], true), [...old, "next-page"]);
  assert.deepEqual(selectAuthRecords(old, ["earlier-page"], false), ["filtered-out"]);
  const ids = selectAuthRecords(old, Array.from({ length: 110 }, (_, i) => `id-${i}`), true);
  assert.equal(ids.length, 100);
  assert.deepEqual(old, ["earlier-page", "filtered-out"]);
});

test("group admission freezes only explicitly selected preview IDs", () => {
  const ids = ["first", "second"], preview = [...ids, "not-selected"];
  const frozen = authRequest("json_export", selectPreviewIds(ids, preview), "group-a");
  ids.push("later"); preview.push("new-member");
  assert.deepEqual(frozen.record_ids, ["first", "second"]);
  assert.equal(frozen.group_id, "group-a");
  assert.ok(Object.isFrozen(frozen.record_ids));
  assert.throws(() => selectPreviewIds(["stale"], preview));
  assert.throws(() => authRequest("json_export", []));
  assert.throws(() => authRequest("json_export", ["a", "a"]));
  assert.throws(() => authRequest("json_export", Array.from({ length: 101 }, (_, i) => `${i}`)));
});

test("hidden operations, ownership and unavailable credentials block selection", () => {
  const user = { id: 7, role: "member" };
  const r = { owner_id: 7, sso_user_id: "sso", state: "completed", subscription_status: "active", has_password: true, credential_state: "permanent" };
  assert.equal(canUseAuthRecord(r, user, "json_export"), true);
  for (const patch of [{ operation_pending: true, operation: null }, { owner_id: 8 }, { sso_deleted_at: "date" }, { state: "running" }])
    assert.equal(canUseAuthRecord({ ...r, ...patch }, user, "json_export"), false);
  assert.equal(canUseAuthRecord({ ...r, has_password: false, credential_state: "unknown" }, user, "json_export"), true, "server decides whether unknown credentials have recoverable candidate");
  assert.equal(canUseAuthRecord({ ...r, has_password: false, credential_state: "one_time" }, user, "json_export"), false);
});

test("JSON selection requires confirmed unexpired subscription while password maintenance remains available", () => {
  const user = { id: 7, role: "member" };
  const r = { owner_id: 7, sso_user_id: "sso", state: "completed", has_password: true };
  for (const subscription_status of [undefined, "not_subscribed", "pending", "unknown", "cancelled", "expired"]) {
    const row = { ...r, subscription_status, counted: true };
    assert.equal(canUseAuthRecord(row, user, "json_export"), false, subscription_status);
    assert.equal(canUseAuthRecord(row, user, "reset_password"), true);
  }
  for (const subscription_status of ["active", "cancel_scheduled"]) {
    assert.equal(canUseAuthRecord({ ...r, subscription_status, access_ends_at: "2999-01-01T00:00:00" }, user, "json_export"), true);
    assert.equal(canUseAuthRecord({ ...r, subscription_status, access_ends_at: "2000-01-01T00:00:00" }, user, "json_export"), false);
  }
  assert.equal(canUseAuthRecord({ ...r, subscription_status: "cancel_scheduled" }, user, "json_export"), false);
});

test("custom password validation matches printable AWS native policy and never adds passwords to other modes", () => {
  assert.equal(validPermanentPassword("Sample8!"), true);
  assert.equal(validPermanentPassword("A1!" + "a".repeat(61)), true);
  for (const value of ["short1!", "lowercase8!", "UPPERCASE8!", "NoNumber!", "NoSpecial8", "Sample 8!", "Sample8!\n", "A1!" + "a".repeat(62)])
    assert.equal(validPermanentPassword(value), false);
  assert.throws(() => authRequest("custom_password", ["a"], undefined, "bad"));
  assert.equal(authRequest("custom_password", ["a"], undefined, "Sample8!").password, "Sample8!");
  assert.equal("password" in authRequest("random_password", ["a"], undefined, "Sample8!"), false);
});

test("credential copy distinguishes permanent, OTP and unknown outcomes", () => {
  const base = { username: "test-user", password: "Sample8!", portal_url: "https://test.awsapps.com/start", region: "us-east-1" };
  assert.equal(credentialLabel("one_time"), "一次性密码");
  assert.match(credentialText({ ...base, credential_state: "permanent" }), /永久密码：Sample8!/);
  const unknown = credentialText({ ...base, credential_state: "unknown" });
  assert.match(unknown, /密码状态待核对/);
  assert.doesNotMatch(unknown, /Sample8!/);
});

const frame = {}, otherFrame = {};
const challenge = { kind: "ams", id: "challenge-a", revision: 2, expires_at: 1100,
  operation_id: "operation-a", frame_url: "https://verify.example.test/auth-widget", frame_origin: "https://verify.example.test",
  region: "us-east-1", stage: "prod", callback: "initAMS", container_id: "captcha", locale: "en-US",
  show_challenge_on_load: false, script_url: "https://cdn.us-east-1.threat-mitigation.aws.amazon.com/assets/consumer/consumer.min.js",
  widget_origin: "https://cdn.us-east-1.threat-mitigation.aws.amazon.com", redemption_token: "synthetic-challenge" };
const message = { type: "kiro-auth-complete", operation_id: "operation-a", challenge_id: "challenge-a", revision: 2, access_code: "human-code" };
const event = data => ({ data, origin: challenge.frame_origin, source: frame });

test("widget messages require exact frame, origin, shape, operation and challenge revision before expiry", () => {
  assert.equal(acceptWidgetMessage(event(message), frame, challenge, 1000)?.access_code, "human-code");
  for (const invalid of [
    { ...event(message), source: otherFrame }, { ...event(message), origin: challenge.widget_origin },
    event({ ...message, revision: 3 }), event({ ...message, operation_id: "another" }), event({ ...message, challenge_id: "another" }),
    event({ ...message, password: "forbidden" }), event({ ...message, access_code: "" }), event({ ...message, access_code: "x\ny" }),
    event({ ...message, type: "kiro-auth-ready" }), event([]),
  ]) assert.equal(acceptWidgetMessage(invalid, frame, challenge, 1000), null);
  assert.equal(acceptWidgetMessage(event(message), frame, challenge, 1100), null);
  const ready = { type: "kiro-auth-ready", operation_id: "operation-a", challenge_id: "challenge-a", revision: 2 };
  assert.equal(acceptWidgetMessage(event(ready), frame, challenge, 1000)?.type, "kiro-auth-ready");
  assert.equal(acceptWidgetMessage(event({ ...ready, type: "kiro-auth-error", code: "other" }), frame, challenge, 1000), null);
});

test("widget initialization forwards only thirteen public CAPTCHA fields", () => {
  const init = widgetInit({ ...challenge, password: "forbidden", accessToken: "forbidden", cookies: "forbidden" });
  assert.equal(Object.keys(init.challenge).length, 13);
  assert.equal(init.revision, 2);
  assert.equal(init.operation_id, "operation-a");
  assert.doesNotMatch(JSON.stringify(init), /forbidden|frame_origin|frame_url/);
});

test("partial ZIP is available while siblings are processing and never after purge", () => {
  const batch = { kind: "json_export", state: "active", download_ready: true, completed_at: "date", success_count: 1,
    states: { completed: 1, failed: 1 }, items: [ { record_id: "ok", state: "completed" }, { record_id: "failed", state: "failed" }, { record_id: "unknown", state: "needs_review", requires_new_reset: true } ] };
  assert.equal(batchCanDownload(batch), true);
  assert.equal(batchCanDownload({ ...batch, completed_at: null, states: { completed: 1, running: 1, challenge: 1 } }), true);
  for (const patch of [{ state: "downloaded" }, { state: "expired" }, { download_ready: false }, { success_count: 0 }])
    assert.equal(batchCanDownload({ ...batch, ...patch }), false);
  assert.deepEqual(retryableItems(batch).map(item => item.record_id), ["failed"], "normal retry must never implicitly reset unknown OTP");
});
