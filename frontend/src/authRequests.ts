import { useCallback, useEffect, useRef, useState } from "react";
import { api, type AuthBatch, type AuthBatchInput, type AuthKind, type AuthPreview, type GroupDetail, type RecordItem } from "./api";

export type AuthIntentSummary = Omit<AuthBatchInput, "password">;
type Scope = "json_export" | "password";
function summaryOf(body: AuthBatchInput): AuthIntentSummary {
  return { kind: body.kind, record_ids: [...body.record_ids], request_key: body.request_key, ...(body.group_id ? { group_id: body.group_id } : {}) };
}
function readIntent(key: string, scope: Scope): AuthIntentSummary | null {
  try {
    const value = JSON.parse(sessionStorage.getItem(key) || "null");
    if (!value || !["json_export", "reset_password", "random_password", "custom_password"].includes(value.kind) ||
      (value.kind === "json_export") !== (scope === "json_export") || typeof value.request_key !== "string" || value.request_key.length < 16 || value.request_key.length > 80 ||
      !Array.isArray(value.record_ids) || !value.record_ids.length || value.record_ids.length > 100 || new Set(value.record_ids).size !== value.record_ids.length ||
      !value.record_ids.every((id: unknown) => typeof id === "string" && !!id) || (value.group_id !== undefined && typeof value.group_id !== "string")) return null;
    return summaryOf(value);
  } catch { return null; }
}

// Custom passwords live only in this mounted hook. The saved nonsecret reminder
// requires manual history review after reload, never blind password replay.
export function useAuthAdmission(actorId: number, scope: Scope) {
  const storageKey = `kiro-auth-intent:${actorId}:${scope}`;
  const [pending, setPending] = useState<AuthIntentSummary | null>(() => readIntent(storageKey, scope));
  const intent = useRef<AuthBatchInput | null>(pending?.kind === "custom_password" ? null : pending);
  const summary = useRef(pending);
  const inFlight = useRef(false);
  const alive = useRef(false);
  const generation = useRef(0);
  const activeKey = useRef(storageKey);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    alive.current = true;
    activeKey.current = storageKey;
    generation.current += 1;
    const saved = readIntent(storageKey, scope);
    summary.current = saved;
    intent.current = saved?.kind === "custom_password" ? null : saved;
    inFlight.current = false;
    setPending(saved); setBusy(false); setError("");
    return () => { alive.current = false; generation.current += 1; intent.current = null; };
  }, [storageKey, scope]);
  function clearAfterReview(confirmed: boolean) {
    if (!confirmed || inFlight.current || activeKey.current !== storageKey || !alive.current) return false;
    sessionStorage.removeItem(storageKey);
    intent.current = null;
    summary.current = null;
    if (alive.current) { setPending(null); setError(""); }
    return true;
  }
  async function submit(body?: AuthBatchInput): Promise<AuthBatch | null> {
    if (inFlight.current || !alive.current || activeKey.current !== storageKey) return null;
    if (summary.current && !intent.current) {
      setError("共享密码未保存在浏览器中。请先核对下方本人历史记录，确认上次结果后再开始新批次。");
      return null;
    }
    const request = intent.current || (body ? Object.freeze({ ...body, record_ids: Object.freeze([...body.record_ids]) }) : null);
    if (!request) return null;
    const current = generation.current;
    inFlight.current = true;
    intent.current = request;
    summary.current = summaryOf(request);
    setPending(summary.current);
    setBusy(true);
    setError("");
    try {
      // Save whitelisted metadata before any write, including when fetch fails.
      sessionStorage.setItem(storageKey, JSON.stringify(summary.current));
      const batch = await api<AuthBatch>("/auth-batches", "POST", request);
      if (!batch?.id || batch.actor_id !== actorId || batch.kind !== request.kind)
        throw new Error("提交结果尚未确认，请继续使用原请求确认。");
      if (readIntent(storageKey, scope)?.request_key === request.request_key) sessionStorage.removeItem(storageKey);
      if (!alive.current || current !== generation.current) return null;
      intent.current = null;
      summary.current = null;
      if (alive.current) setPending(null);
      return batch;
    } catch (e) {
      // An error cannot prove a prior attempt was not admitted. Preserve the
      // exact key/body through network, auth, permission and unknown conflicts.
      if (alive.current && current === generation.current) setError((e as Error).message || "提交结果尚未确认");
      return null;
    } finally {
      if (alive.current && current === generation.current) { inFlight.current = false; setBusy(false); }
    }
  }
  return { pending, busy, error, canResume: !!intent.current, submit, clearAfterReview };
}

export function useAuthGroupPreview(groupId: string, kind: AuthKind) {
  const [snapshot, setSnapshot] = useState<{ preview: AuthPreview; records: RecordItem[] } | null>(null);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const generation = useRef(0), active = useRef("");
  const key = `${groupId}:${kind}`;
  useEffect(() => {
    active.current = key; generation.current += 1; setSnapshot(null); setError(""); setBusy(false);
    return () => { active.current = ""; generation.current += 1; };
  }, [key]);
  const refresh = useCallback(async () => {
    if (!groupId || active.current !== key) return null;
    const current = ++generation.current;
    setBusy(true); setError(""); setSnapshot(null);
    try {
      const [preview, group] = await Promise.all([
        api<AuthPreview>(`/auth-batches/preview?group_id=${encodeURIComponent(groupId)}&kind=${kind}`),
        api<GroupDetail>(`/groups/${encodeURIComponent(groupId)}`),
      ]);
      if (current !== generation.current) return null;
      if (preview.group_id !== groupId || preview.kind !== kind || group.id !== groupId || preview.record_ids.some(id => !group.members.some(record => record.id === id)))
        throw new Error("分组成员已变化，请重新预览。");
      const next = { preview, records: preview.record_ids.map(id => group.members.find(record => record.id === id)!) };
      setSnapshot(next); return next;
    } catch (e) { if (current === generation.current) setError((e as Error).message); return null; }
    finally { if (current === generation.current) setBusy(false); }
  }, [groupId, kind, key]);
  return { snapshot, busy, error, refresh };
}
