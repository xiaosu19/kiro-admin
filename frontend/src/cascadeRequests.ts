import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, groupRequest, type CascadeAdmissionBody, type CascadeBatch, type CascadeKind, type CascadePreview, type CascadeSelection } from "./api";

export interface CascadeIntent { kind: CascadeKind; target_ids: string[]; body: CascadeAdmissionBody }

function readIntent(key: string): CascadeIntent | null {
  try {
    const value = JSON.parse(sessionStorage.getItem(key) || "null");
    if (!value || !["sso", "group"].includes(value.kind) || !Array.isArray(value.target_ids)
      || !value.target_ids.length || value.target_ids.length > 100
      || !value.target_ids.every((id: unknown) => typeof id === "string" && id.length > 0 && id.length <= 36)
      || new Set(value.target_ids).size !== value.target_ids.length
      || typeof value.body?.preview_id !== "string" || typeof value.body.fingerprint !== "string" || value.body.fingerprint.length !== 64
      || typeof value.body.confirm_text !== "string" || value.body.acknowledge_fees !== true
      || typeof value.body.request_key !== "string" || value.body.request_key.length < 16 || value.body.request_key.length > 80) return null;
    return value;
  } catch { return null; }
}

export function validCascadeResult(batch: CascadeBatch, intent: Pick<CascadeIntent, "kind" | "target_ids">) {
  return !!batch && typeof batch.id === "string" && batch.id.length > 0 && batch.kind === intent.kind
    && Array.isArray(batch.items) && JSON.stringify(batch.items.map(item => item.target_id).sort()) === JSON.stringify([...intent.target_ids].sort());
}

export function useCascadeAdmission(actorId: number, scope: string) {
  const storageKey = `kiro-cascade-request:${actorId}`, identity = `${storageKey}:${scope}`;
  const [pending, setPending] = useState<CascadeIntent | null>(() => readIntent(storageKey));
  const saved = useRef(pending), uncertain = useRef(!!pending), inFlight = useRef(false);
  const active = useRef(""), latest = useRef(identity), generation = useRef(0);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  latest.current = identity;
  useEffect(() => {
    active.current = identity; generation.current += 1; inFlight.current = false;
    const restored = readIntent(storageKey);
    saved.current = restored; uncertain.current = !!restored; setPending(restored); setError(""); setBusy(false);
    return () => { active.current = ""; generation.current += 1; };
  }, [identity, storageKey]);
  async function submit(value?: CascadePreview): Promise<CascadeBatch | null> {
    if (active.current !== identity || latest.current !== identity || inFlight.current) return null;
    const elsewhere = readIntent(storageKey);
    if (elsewhere && elsewhere.body.request_key !== saved.current?.body.request_key) {
      saved.current = elsewhere; uncertain.current = true; setPending(elsewhere);
      setError("另一处删除提交的结果尚未确认，请先继续原请求。");
      return null;
    }
    const intent = saved.current || (value ? {
      kind: value.kind, target_ids: value.items.map(item => item.target_id),
      body: { preview_id: value.id, fingerprint: value.fingerprint, confirm_text: value.confirm_text,
        acknowledge_fees: true, request_key: crypto.randomUUID() },
    } : null);
    if (!intent) return null;
    const current = generation.current, wasUncertain = uncertain.current;
    const isCurrent = () => active.current === identity && latest.current === identity && current === generation.current;
    const attempt = JSON.stringify(intent);
    const clear = () => { if (sessionStorage.getItem(storageKey) === attempt) sessionStorage.removeItem(storageKey); };
    inFlight.current = true; saved.current = intent; setPending(intent); setBusy(true); setError("");
    try {
      sessionStorage.setItem(storageKey, attempt);
      const result = await groupRequest<CascadeBatch>("/cascade-deletions", "POST", intent.body, isCurrent);
      if (!result || !isCurrent()) { if (isCurrent()) uncertain.current = true; return null; }
      if (!validCascadeResult(result, intent)) throw new Error("删除批次结果尚未确认，请继续原请求确认。");
      clear(); saved.current = null; uncertain.current = false; setPending(null); return result;
    } catch (e) {
      if (isCurrent()) {
        const definite = !wasUncertain && e instanceof ApiError && (e.status === 400 || e.status === 422 || e.status === 409 && /预览|已变化|确认文字|完整删除范围/.test(e.message));
        if (definite) { clear(); saved.current = null; uncertain.current = false; setPending(null); }
        else uncertain.current = true;
        setError((e as Error).message || "提交结果尚未确认，请继续原请求确认。");
      }
      return null;
    } finally { if (isCurrent()) { inFlight.current = false; setBusy(false); } }
  }
  const currentScope = active.current === identity && latest.current === identity;
  return { pending: currentScope ? pending : null, busy: currentScope && busy, error: currentScope ? error : "", submit };
}

export function useCascadePreview(actorId: number, scope: string, selection: CascadeSelection) {
  const serialized = JSON.stringify(selection), identity = `${actorId}:${scope}:${serialized}`;
  const [data, setData] = useState<CascadePreview | null>(null), [error, setError] = useState(""), [busy, setBusy] = useState(false);
  const active = useRef(""), latest = useRef(identity), generation = useRef(0);
  latest.current = identity;
  const refresh = useCallback(async () => {
    if (active.current !== identity || latest.current !== identity) return;
    const current = ++generation.current;
    const isCurrent = () => active.current === identity && latest.current === identity && current === generation.current;
    setData(null); setError(""); setBusy(true);
    try {
      const result = await groupRequest<CascadePreview>("/cascade-deletions/preview", "POST", JSON.parse(serialized), isCurrent);
      if (!result || !isCurrent()) return;
      const selected = JSON.parse(serialized) as CascadeSelection;
      const ids = selected.kind === "sso" ? selected.record_ids : selected.group_ids;
      if (!validCascadeResult(result as unknown as CascadeBatch, { kind: selected.kind, target_ids: ids })
          || typeof result.fingerprint !== "string" || result.fingerprint.length !== 64 || !result.confirm_text)
        throw new Error("删除范围预览不完整，请重新读取。");
      setData(result);
    } catch (e) { if (isCurrent()) setError((e as Error).message); }
    finally { if (isCurrent()) setBusy(false); }
  }, [identity, serialized]);
  useEffect(() => {
    active.current = identity; generation.current += 1; setData(null); setError(""); void refresh();
    return () => { active.current = ""; generation.current += 1; };
  }, [identity, refresh]);
  const currentScope = active.current === identity && latest.current === identity;
  return { data: currentScope ? data : null, error: currentScope ? error : "", busy: currentScope && busy, refresh };
}

export function useCascadeRecovery(actorId: number, scope: string) {
  const identity = `${actorId}:${scope}`, active = useRef(""), latest = useRef(identity), generation = useRef(0), inFlight = useRef(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  latest.current = identity;
  useEffect(() => {
    active.current = identity; generation.current += 1; inFlight.current = false; setBusy(false); setError("");
    return () => { active.current = ""; generation.current += 1; };
  }, [identity]);
  async function submit(batch: CascadeBatch, action: "recheck" | "retry") {
    if (inFlight.current || !batch.actions[action] || active.current !== identity || latest.current !== identity) return null;
    const current = generation.current, isCurrent = () => active.current === identity && latest.current === identity && current === generation.current;
    inFlight.current = true; setBusy(true); setError("");
    try {
      const result = await groupRequest<CascadeBatch>(`/cascade-deletions/${encodeURIComponent(batch.id)}/${action}`, "POST",
        { request_key: crypto.randomUUID(), confirm_text: batch.confirm_text }, isCurrent);
      if (!result || !isCurrent()) return null;
      if (result.id !== batch.id) throw new Error("恢复结果尚未确认，请刷新原批次。");
      return result;
    } catch (e) { if (isCurrent()) setError((e as Error).message); return null; }
    finally { if (isCurrent()) { inFlight.current = false; setBusy(false); } }
  }
  const currentScope = active.current === identity && latest.current === identity;
  return { busy: currentScope && busy, error: currentScope ? error : "", submit };
}
