import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, groupJsonSelection, groupRequest, type AuthBatch, type GroupJsonAdmissionBody, type GroupJsonPreview } from "./api";

export interface GroupJsonIntent {
  group_ids: string[];
  groups: { id: string; name: string; account_number: string }[];
  eligible_count: number;
  skipped_count: number;
  body: GroupJsonAdmissionBody;
}

function readIntent(key: string): GroupJsonIntent | null {
  try {
    const value = JSON.parse(sessionStorage.getItem(key) || "null");
    if (!value || !Array.isArray(value.group_ids) || value.group_ids.some((id: unknown) => typeof id !== "string")
      || new Set(value.group_ids).size !== value.group_ids.length || !Array.isArray(value.groups)
      || value.groups.length !== value.group_ids.length || value.groups.some((g: GroupJsonIntent["groups"][number]) =>
        !g || !value.group_ids.includes(g.id) || typeof g.name !== "string" || typeof g.account_number !== "string")
      || !Number.isInteger(value.eligible_count) || value.eligible_count < 1 || value.eligible_count > 5000
      || !Number.isInteger(value.skipped_count) || value.skipped_count < 0
      || typeof value.body?.preview_id !== "string" || !value.body.preview_id || value.body.preview_id.length > 36
      || typeof value.body.fingerprint !== "string" || value.body.fingerprint.length !== 64
      || value.body.acknowledge_password_changes !== true || typeof value.body.request_key !== "string"
      || value.body.request_key.length < 16 || value.body.request_key.length > 80) return null;
    groupJsonSelection(value.group_ids);
    return value;
  } catch { return null; }
}

export function validGroupJsonPreview(value: GroupJsonPreview, ids: readonly string[]) {
  if (!value || !value.id || value.fingerprint?.length !== 64 || !Array.isArray(value.groups)
    || JSON.stringify(value.groups.map(g => g.id).sort()) !== JSON.stringify([...ids].sort())) return false;
  const members = value.groups.flatMap(g => g.members || []);
  return members.length <= 5000 && new Set(members.map(m => m.record_id)).size === members.length
    && value.groups.every(g => Array.isArray(g.members) && g.total === g.members.length
      && g.eligible_count === g.members.filter(m => m.skip_reason === null).length
      && g.skipped_count === g.members.filter(m => m.skip_reason !== null).length)
    && value.total === members.length && value.eligible_count === value.groups.reduce((n, g) => n + g.eligible_count, 0)
    && value.skipped_count === value.groups.reduce((n, g) => n + g.skipped_count, 0);
}

export function useGroupJsonPreview(actorId: number, scope: string, ids: readonly string[]) {
  const serialized = JSON.stringify([...ids].sort()), identity = `${actorId}:${scope}:${serialized}`;
  const active = useRef(""), latest = useRef(identity), generation = useRef(0);
  const [data, setData] = useState<GroupJsonPreview | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState("");
  latest.current = identity;
  useEffect(() => {
    active.current = identity; generation.current += 1; setData(null); setBusy(false); setError("");
    return () => { active.current = ""; generation.current += 1; };
  }, [identity]);
  const refresh = useCallback(async () => {
    if (active.current !== identity || latest.current !== identity) return;
    const version = ++generation.current;
    const current = () => active.current === identity && latest.current === identity && generation.current === version;
    setData(null); setBusy(true); setError("");
    try {
      const body = groupJsonSelection(JSON.parse(serialized));
      const result = await groupRequest<GroupJsonPreview>("/group-json-exports/preview", "POST", body, current);
      if (!result || !current()) return;
      if (!validGroupJsonPreview(result, body.group_ids)) throw new Error("分组人数或成员范围不完整，请重新预览。");
      setData(result);
    } catch (e) { if (current()) setError((e as Error).message); }
    finally { if (current()) setBusy(false); }
  }, [identity, serialized]);
  const current = active.current === identity && latest.current === identity;
  return { data: current ? data : null, busy: current && busy, error: current ? error : "", refresh };
}

export function useGroupJsonAdmission(actorId: number, scope: string) {
  const storageKey = `kiro-group-json-request:${actorId}`, identity = `${storageKey}:${scope}`;
  const [pending, setPending] = useState<GroupJsonIntent | null>(() => readIntent(storageKey));
  const saved = useRef(pending), uncertain = useRef(!!pending), inFlight = useRef(false);
  const active = useRef(""), latest = useRef(identity), generation = useRef(0);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  latest.current = identity;
  useEffect(() => {
    active.current = identity; generation.current += 1; inFlight.current = false;
    const restored = readIntent(storageKey);
    saved.current = restored; uncertain.current = !!restored; setPending(restored); setBusy(false); setError("");
    return () => { active.current = ""; generation.current += 1; };
  }, [identity, storageKey]);
  async function submit(value?: GroupJsonPreview): Promise<AuthBatch | null> {
    if (active.current !== identity || latest.current !== identity || inFlight.current) return null;
    const elsewhere = readIntent(storageKey);
    if (elsewhere && elsewhere.body.request_key !== saved.current?.body.request_key) {
      saved.current = elsewhere; uncertain.current = true; setPending(elsewhere);
      setError("另一处整组转换的结果尚未确认，请先继续原请求。"); return null;
    }
    const intent = saved.current || (value && value.eligible_count > 0 && validGroupJsonPreview(value, value.groups.map(g => g.id)) ? {
      group_ids: value.groups.map(g => g.id), groups: value.groups.map(g => ({ id: g.id, name: g.name, account_number: g.account_number })),
      eligible_count: value.eligible_count, skipped_count: value.skipped_count,
      body: { preview_id: value.id, fingerprint: value.fingerprint, acknowledge_password_changes: true as const, request_key: crypto.randomUUID() },
    } : null);
    if (!intent) return null;
    const version = generation.current, wasUncertain = uncertain.current;
    const current = () => active.current === identity && latest.current === identity && generation.current === version;
    const attempt = JSON.stringify(intent);
    const clear = () => { if (sessionStorage.getItem(storageKey) === attempt) sessionStorage.removeItem(storageKey); };
    inFlight.current = true; saved.current = intent; setPending(intent); setBusy(true); setError("");
    try {
      sessionStorage.setItem(storageKey, attempt);
      const batch = await groupRequest<AuthBatch>("/group-json-exports", "POST", intent.body, current);
      if (!batch || !current()) { if (current()) uncertain.current = true; return null; }
      if (!batch.id || batch.actor_id !== actorId || batch.kind !== "json_export" || batch.total !== intent.eligible_count
        || !batch.group_scope || JSON.stringify(batch.group_scope.groups.map(g => g.id).sort()) !== JSON.stringify([...intent.group_ids].sort()))
        throw new Error("整组转换结果尚未确认，请继续原请求。");
      clear(); saved.current = null; uncertain.current = false; setPending(null); return batch;
    } catch (e) {
      if (current()) {
        const definite = !wasUncertain && e instanceof ApiError && (e.status === 400 || e.status === 422
          || e.status === 409 && /预览|已变化|没有可转换|尚未确认/.test(e.message));
        if (definite) { clear(); saved.current = null; uncertain.current = false; setPending(null); }
        else uncertain.current = true;
        setError((e as Error).message || "提交结果尚未确认，请继续原请求。");
      }
      return null;
    } finally { if (current()) { inFlight.current = false; setBusy(false); } }
  }
  function clearAfterReview(reviewed: boolean) {
    if (!reviewed || inFlight.current || active.current !== identity || latest.current !== identity) return false;
    if (saved.current && sessionStorage.getItem(storageKey) === JSON.stringify(saved.current)) sessionStorage.removeItem(storageKey);
    saved.current = null; uncertain.current = false; setPending(null); setError(""); return true;
  }
  const current = active.current === identity && latest.current === identity;
  return { pending: current ? pending : null, busy: current && busy, error: current ? error : "", submit, clearAfterReview };
}
