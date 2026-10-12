
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, type PlanChange, type PlanChangeOptions } from "./api";
import { isPlanChange, isPlanChangeOptions } from "./planChangesLogic";

interface Confirmation {
  expected_current_type: string;
  confirm_username: string;
  request_key: string;
}
export type PlanChangeIntent =
  | { kind: "change"; body: Confirmation & { target_plan_id: number } }
  | { kind: "withdraw"; change_id: string; body: Confirmation };

function freezeIntent(value: PlanChangeIntent): PlanChangeIntent {
  const body = { expected_current_type: value.body.expected_current_type, confirm_username: value.body.confirm_username, request_key: value.body.request_key };
  return value.kind === "change"
    ? Object.freeze({ kind: "change", body: Object.freeze({ ...body, target_plan_id: value.body.target_plan_id }) })
    : Object.freeze({ kind: "withdraw", change_id: value.change_id, body: Object.freeze(body) });
}
function readIntent(key: string): PlanChangeIntent | null {
  try {
    const value = JSON.parse(sessionStorage.getItem(key) || "null");
    const body = value?.body;
    if (!body || typeof body.expected_current_type !== "string" || !body.expected_current_type || typeof body.confirm_username !== "string" || !body.confirm_username ||
      typeof body.request_key !== "string" || body.request_key.length < 16 || body.request_key.length > 80 ||
      !(value.kind === "change" && Number.isInteger(body.target_plan_id) && body.target_plan_id > 0 || value.kind === "withdraw" && typeof value.change_id === "string" && !!value.change_id)) return null;
    return freezeIntent(value);
  } catch { return null; }
}

// A stored intent may have reached the server even if the page was closed
// before the response. Only an initially definitive rejection unlocks editing.
export function usePlanChangeAdmission(actorId: number, recordId: string) {
  const storageKey = `kiro-plan-change:${actorId}:${recordId}`;
  const [pending, setPending] = useState<PlanChangeIntent | null>(() => readIntent(storageKey));
  const intent = useRef(pending), uncertain = useRef(!!pending), inFlight = useRef(false);
  const active = useRef(""), generation = useRef(0);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  useEffect(() => {
    active.current = storageKey; generation.current += 1;
    const saved = readIntent(storageKey);
    intent.current = saved; uncertain.current = !!saved; inFlight.current = false;
    setPending(saved); setBusy(false); setError("");
    return () => { active.current = ""; generation.current += 1; };
  }, [storageKey]);
  async function submit(input?: PlanChangeIntent): Promise<PlanChange | null> {
    if (active.current !== storageKey || inFlight.current) return null;
    const request = intent.current || (input ? freezeIntent(input) : null);
    if (!request) return null;
    const current = generation.current, wasUncertain = uncertain.current;
    const isCurrent = () => active.current === storageKey && generation.current === current;
    // The request key/body stay frozen, but each HTTP attempt owns a distinct
    // saved snapshot. A late response from a closed panel cannot erase a
    // reopened panel's retry merely because both used the same request key.
    const savedAttempt = JSON.stringify({ ...request, attempt_id: crypto.randomUUID() });
    const clearSaved = () => {
      try {
        if (sessionStorage.getItem(storageKey) !== savedAttempt) return false;
        sessionStorage.removeItem(storageKey);
        return true;
      } catch { return false; }
    };
    inFlight.current = true; intent.current = request;
    setPending(request); setBusy(true); setError("");
    let sent = false;
    try {
      // Persist only the whitelisted, nonsecret request, before writing remotely.
      sessionStorage.setItem(storageKey, savedAttempt);
      sent = true;
      const endpoint = `/subscriptions/${encodeURIComponent(recordId)}/plan-changes${request.kind === "withdraw" ? `/${encodeURIComponent(request.change_id)}/withdraw` : ""}`;
      const result = await api<PlanChange>(endpoint, "POST", request.body);
      if (!isPlanChange(result, recordId) ||
        (request.kind === "withdraw" ? result.direction !== "withdraw" || result.predecessor_id !== request.change_id : !["upgrade", "downgrade"].includes(result.direction) || result.to_plan_id !== request.body.target_plan_id))
        throw new Error("提交结果尚未确认，请继续原请求核对。");
      clearSaved();
      if (!isCurrent()) return null;
      intent.current = null; uncertain.current = false; setPending(null);
      return result;
    } catch (e) {
      const definiteRejection = e instanceof ApiError && e.status >= 400 && e.status < 500 && e.status !== 408;
      const discard = !wasUncertain && (!sent || definiteRejection && clearSaved());
      if (isCurrent()) {
        if (discard) {
          intent.current = null; uncertain.current = false; setPending(null);
        } else uncertain.current = true;
        setError((e as Error).message || "提交结果尚未确认，请继续原请求核对。");
      }
      return null;
    } finally {
      if (isCurrent()) { inFlight.current = false; setBusy(false); }
    }
  }
  return { pending, busy, error, submit };
}

export function usePlanChangeData(actorId: number, recordId: string) {
  const key = `${actorId}:${recordId}`, active = useRef(""), generation = useRef(0);
  const inFlight = useRef<number | null>(null);
  const [options, setOptions] = useState<PlanChangeOptions | null>(null), [history, setHistory] = useState<PlanChange[]>([]);
  const [loading, setLoading] = useState(true), [error, setError] = useState("");
  const refresh = useCallback(async () => {
    if (active.current !== key) return;
    const current = ++generation.current;
    inFlight.current = current;
    try {
      const path = `/subscriptions/${encodeURIComponent(recordId)}`;
      const [nextOptions, nextHistory] = await Promise.all([api<PlanChangeOptions>(`${path}/plan-options`), api<PlanChange[]>(`${path}/plan-changes`)]);
      if (active.current !== key || current !== generation.current) return;
      if (!isPlanChangeOptions(nextOptions, recordId) || !Array.isArray(nextHistory) || nextHistory.some(item => !isPlanChange(item, recordId))) throw new Error("套餐信息不完整，请重新读取。");
      setOptions(nextOptions); setHistory(nextHistory); setError("");
    } catch (e) { if (active.current === key && current === generation.current) setError((e as Error).message || "套餐信息读取失败"); }
    finally {
      if (active.current === key && current === generation.current) setLoading(false);
      if (inFlight.current === current) inFlight.current = null;
    }
  }, [key, recordId]);
  useEffect(() => {
    active.current = key; generation.current += 1; setOptions(null); setHistory([]); setLoading(true); setError("");
    void refresh();
    const timer = window.setInterval(() => { if (inFlight.current === null) void refresh(); }, 3000);
    return () => { active.current = ""; generation.current += 1; inFlight.current = null; window.clearInterval(timer); };
  }, [key, refresh]);
  return { options, history, loading, error, refresh };
}

type RecoveryBody = { confirm_username: string; reason?: string; acknowledge_not_applied?: boolean };
export function usePlanChangeRecovery(actorId: number, recordId: string) {
  const key = `${actorId}:${recordId}`, active = useRef(""), generation = useRef(0), inFlight = useRef(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  useEffect(() => {
    active.current = key; generation.current += 1; inFlight.current = false; setBusy(false); setError("");
    return () => { active.current = ""; generation.current += 1; };
  }, [key]);
  async function submit(changeId: string, action: "recheck" | "confirm-not-applied", body: RecoveryBody) {
    if (active.current !== key || inFlight.current) return null;
    const current = generation.current;
    const isCurrent = () => active.current === key && current === generation.current;
    inFlight.current = true; setBusy(true); setError("");
    try {
      const result = await api<PlanChange>(`/subscriptions/${encodeURIComponent(recordId)}/plan-changes/${encodeURIComponent(changeId)}/${action}`, "POST", body);
      if (!isPlanChange(result, recordId) || result.id !== changeId) throw new Error("核对结果尚未确认，请重新只读核对 AWS。");
      return isCurrent() ? result : null;
    } catch (e) {
      if (isCurrent()) setError((e as Error).message || "核对失败，请重新读取。");
      return null;
    } finally { if (isCurrent()) { inFlight.current = false; setBusy(false); } }
  }
  return { busy, error, submit };
}
