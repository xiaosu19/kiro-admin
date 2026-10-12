import { useCallback, useEffect, useRef, useState } from "react";
import { api, type LifecycleBatch, type LifecycleItem, type NativePreview } from "./api";
import { definiteLifecycleRejection, freezeLifecycleIntent, lifecycleEndpoint, lifecycleRecovery, validLifecycleBatch, validNativePreview, type LifecycleIntent } from "./nativeSubscriptionsLogic";

function readIntent(key: string): LifecycleIntent | null {
  try {
    const value = JSON.parse(sessionStorage.getItem(key) || "null");
    if (!value || !["group_subscribe", "group_cancel", "user_cancel"].includes(value.kind) ||
      typeof value.body?.request_key !== "string" || value.body.request_key.length < 16 || value.body.request_key.length > 80) return null;
    return freezeLifecycleIntent(value);
  } catch { return null; }
}
export function useLifecycleAdmission(actorId: number, scope: string) {
  const storageKey = `kiro-lifecycle-request:${actorId}`, identity = `${storageKey}:${scope}`;
  const [pending, setPending] = useState<LifecycleIntent | null>(() => readIntent(storageKey));
  const saved = useRef(pending), uncertain = useRef(!!pending), inFlight = useRef(false);
  const active = useRef(""), generation = useRef(0);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  useEffect(() => {
    active.current = identity; generation.current += 1;
    const restored = readIntent(storageKey);
    saved.current = restored; uncertain.current = !!restored; inFlight.current = false;
    setPending(restored); setBusy(false); setError("");
    return () => { active.current = ""; generation.current += 1; };
  }, [identity, storageKey]);
  async function submit(input?: LifecycleIntent): Promise<LifecycleBatch | null> {
    if (active.current !== identity || inFlight.current) return null;
    const request = saved.current || (input ? freezeLifecycleIntent(input) : null);
    if (!request) return null;
    const current = generation.current, wasUncertain = uncertain.current;
    const isCurrent = () => active.current === identity && current === generation.current;
    const attempt = JSON.stringify({ ...request, attempt_id: crypto.randomUUID() });
    const clear = () => {
      try { if (sessionStorage.getItem(storageKey) !== attempt) return false; sessionStorage.removeItem(storageKey); return true; }
      catch { return false; }
    };
    inFlight.current = true; saved.current = request; setPending(request); setBusy(true); setError("");
    let sent = false;
    try {
      sessionStorage.setItem(storageKey, attempt);
      sent = true;
      const result = await api<LifecycleBatch>(lifecycleEndpoint(request.kind), "POST", request.body);
      if (!validLifecycleBatch(result, request)) throw new Error("批次结果尚未确认，请继续原请求确认。");
      clear();
      if (!isCurrent()) return null;
      saved.current = null; uncertain.current = false; setPending(null); return result;
    } catch (e) {
      const discard = !wasUncertain && (!sent || definiteLifecycleRejection(e) && clear());
      if (isCurrent()) {
        if (discard) { saved.current = null; uncertain.current = false; setPending(null); }
        else uncertain.current = true;
        setError((e as Error).message || "提交结果尚未确认，请继续原请求确认。");
      }
      return null;
    } finally { if (isCurrent()) { inFlight.current = false; setBusy(false); } }
  }
  return { pending, busy, error, submit };
}

export function useNativePreview(actorId: number, groupIds: string[], enabled: boolean) {
  const selection = JSON.stringify(groupIds), key = `${actorId}:${enabled}:${selection}`;
  const active = useRef(""), generation = useRef(0);
  const [data, setData] = useState<NativePreview | null>(null), [error, setError] = useState(""), [loading, setLoading] = useState(enabled);
  const refresh = useCallback(async () => {
    if (!enabled || active.current !== key) return;
    const current = ++generation.current;
    setData(null); setLoading(true); setError("");
    try {
      const result = await api<NativePreview>("/group-subscriptions/preview", "POST", { group_ids: JSON.parse(selection) });
      if (active.current !== key || current !== generation.current) return;
      if (!validNativePreview(result, JSON.parse(selection))) throw new Error("分组成员预览不完整，请重新读取。");
      setData(result);
    } catch (e) { if (active.current === key && current === generation.current) setError((e as Error).message); }
    finally { if (active.current === key && current === generation.current) setLoading(false); }
  }, [key, selection, enabled]);
  useEffect(() => {
    active.current = key; generation.current += 1; setData(null); setError(""); setLoading(enabled); void refresh();
    return () => { active.current = ""; generation.current += 1; };
  }, [key, enabled, refresh]);
  return { data, error, loading, refresh };
}

export function useLifecycleRecheck(actorId: number, scope: string) {
  const key = `${actorId}:${scope}`, active = useRef(""), generation = useRef(0), inFlight = useRef(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  useEffect(() => {
    active.current = key; generation.current += 1; inFlight.current = false; setBusy(false); setError("");
    return () => { active.current = ""; generation.current += 1; };
  }, [key]);
  async function submit(item: LifecycleItem) {
    if (active.current !== key || inFlight.current || item.state !== "needs_review") return false;
    const current = generation.current;
    const isCurrent = () => active.current === key && current === generation.current;
    inFlight.current = true; setBusy(true); setError("");
    try {
      const request = lifecycleRecovery(item);
      const result = await api<{ id: string }>(request.path, "POST", request.body);
      if (result?.id !== item.operation_id) throw new Error("核对结果尚未确认，请刷新批次或再次只读核对。");
      return isCurrent();
    } catch (e) { if (isCurrent()) setError((e as Error).message); return false; }
    finally { if (isCurrent()) { inFlight.current = false; setBusy(false); } }
  }
  return { busy, error, submit };
}
