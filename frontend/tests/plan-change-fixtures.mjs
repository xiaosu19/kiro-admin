export const response = (body, status = 200) => new Response(JSON.stringify(body), { status });
export const record = {
  id: "record-a", owner_id: 7, owner_name: "member-owner", username: "enterprise-user", plan_name: "Original Pro", subscribed_at: "2026-09-01T00:00:00",
  subscription_status: "active", subscription_type: "PRO", state: "completed", sso_user_id: "sso-a", sso_deleted_at: null,
  current_plan: { plan_id: 2, name: "Pro+", subscription_type: "PRO_PLUS" }, operation: null, operation_pending: false,
};
export const change = {
  id: "change-a", record_id: record.id, operation_id: "operation-a", direction: "upgrade", from_plan_id: 2, from_plan_name: "Pro+", from_type: "PRO_PLUS",
  to_plan_id: 3, to_plan_name: "Power", to_type: "POWER", predecessor_id: null, counter_id: 5, cycle_number: 2,
  reserved: false, counted: true, state: "applied", requested_at: "2026-10-10T00:00:00", write_requested_at: "2026-10-10T00:00:01",
  accepted_at: "2026-10-10T00:00:02", expected_effective_at: null, confirmed_at: "2026-10-10T00:00:03", applied_at: "2026-10-10T00:00:03",
  checked_at: "2026-10-10T00:00:03", next_check_at: null, error: null,
};
export const scheduled = { ...change, id: "scheduled-a", direction: "downgrade", to_plan_id: 1, to_plan_name: "Pro", to_type: "PRO", reserved: true, counted: false, state: "scheduled", applied_at: null, expected_effective_at: "2026-11-01T00:00:00" };
export const options = {
  owner_id: 7, current_plan: record.current_plan, pending_change: null, unavailable_reason: null,
  targets: [
    [4, "Power+", "POWER_PLUS", 200, 10000], [1, "Pro", "PRO", 20, 1000], [3, "Power", "POWER", 100, 5000], [2, "Pro+", "PRO_PLUS", 40, 2000],
  ].map(([plan_id, name, subscription_type, monthly_price_usd, monthly_credits]) => ({
    plan_id, name, subscription_type, reference: { name, code: name, subscription_type, monthly_price_usd, monthly_credits },
    unlimited: false, remaining_count: plan_id === 4 ? 0 : 3, used_count: 2, pending_count: 1,
    available: plan_id !== 4, unavailable_reason: plan_id === 4 ? "创建者该套餐次数不足" : null,
    direction: monthly_price_usd > 40 ? "upgrade" : "downgrade",
  })),
};
export const intent = (key = "request-key-00000001", target = 3) => ({ kind: "change", body: { target_plan_id: target, expected_current_type: "PRO_PLUS", confirm_username: record.username, request_key: key } });
export function environment(t, fetch) {
  const originals = { window: globalThis.window, sessionStorage: globalThis.sessionStorage };
  const storage = new Map(), events = [], intervals = [];
  globalThis.window = { setInterval(fn) { intervals.push(fn); return intervals.length; }, clearInterval() {}, dispatchEvent(event) { events.push(event.type); } };
  globalThis.sessionStorage = { getItem: key => storage.get(key) ?? null, setItem: (key, value) => storage.set(key, value), removeItem: key => storage.delete(key) };
  t.mock.method(globalThis, "fetch", fetch);
  t.after(() => { for (const [key, value] of Object.entries(originals)) { if (value === undefined) delete globalThis[key]; else globalThis[key] = value; } });
  return { storage, events, intervals };
}
