import { useEffect, useRef, useState } from "react";
import { groupRequest, type MemberBatch } from "./api";
import { definiteMemberRejection, freezeMemberIntent, validMemberBatch, type MemberIntent } from "./groupMemberLogic";
import { groupAccessDenied, useGroupAccess, type GroupAccess } from "./groupRequests";

function readIntent(key: string, groupId: string): MemberIntent | null {
  try { const value = JSON.parse(sessionStorage.getItem(key) || "null"); return value?.group_id === groupId ? freezeMemberIntent(value) : null; }
  catch { return null; }
}
export function useMemberAdmission(actorId: number, groupId: string, scope: string, enabled = true, sharedAccess?: GroupAccess) {
  const localAccess = useGroupAccess(actorId, scope), access = sharedAccess || localAccess;
  const storageKey = `kiro-group-members:${actorId}:${groupId}`, identity = `${storageKey}:${scope}:${enabled}`;
  const [pending, setPending] = useState<MemberIntent | null>(() => enabled ? readIntent(storageKey, groupId) : null);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const saved = useRef(pending), uncertain = useRef(!!pending), inFlight = useRef(false);
  const active = useRef(""), latest = useRef(identity), generation = useRef(0);
  latest.current = identity;
  useEffect(() => {
    active.current = identity; generation.current += 1;
    const value = enabled ? readIntent(storageKey, groupId) : null;
    saved.current = value; uncertain.current = !!value; inFlight.current = false;
    setPending(value); setBusy(false); setError("");
    return () => { active.current = ""; generation.current += 1; };
  }, [identity, enabled, storageKey, groupId]);
  function confirm(batches: MemberBatch[]) {
    if (!enabled || !access.canAccess(groupId) || active.current !== identity || latest.current !== identity || !saved.current) return null;
    const found = batches.find(batch => validMemberBatch(batch, saved.current!, actorId));
    if (!found) return null;
    try { if (readIntent(storageKey, groupId)?.body.request_key === saved.current.body.request_key) sessionStorage.removeItem(storageKey); }
    catch { /* Accepted server history is authoritative even if browser storage is unavailable. */ }
    saved.current = null; uncertain.current = false; setPending(null); setError("");
    return found;
  }
  async function submit(input?: MemberIntent): Promise<MemberBatch | null> {
    if (!enabled || !access.canAccess(groupId) || active.current !== identity || latest.current !== identity || inFlight.current) return null;
    const request = saved.current || (input ? freezeMemberIntent(input) : null);
    if (!request || request.group_id !== groupId) return null;
    const current = generation.current, wasUncertain = uncertain.current;
    const isCurrent = () => access.canAccess(groupId) && latest.current === identity && active.current === identity && current === generation.current;
    const attempt = JSON.stringify({ ...request, attempt_id: crypto.randomUUID() });
    const clear = () => { try { if (sessionStorage.getItem(storageKey) !== attempt) return false; sessionStorage.removeItem(storageKey); return true; } catch { return false; } };
    inFlight.current = true; saved.current = request; setPending(request); setBusy(true); setError("");
    let sent = false;
    try {
      sessionStorage.setItem(storageKey, attempt); sent = true;
      const result = await groupRequest<MemberBatch>(`/groups/${encodeURIComponent(groupId)}/member-batches`, "POST", request.body, isCurrent);
      if (!isCurrent() || result === null) return null;
      if (!validMemberBatch(result, request, actorId)) throw new Error("成员批次结果尚未确认，请继续原请求确认。");
      clear(); saved.current = null; uncertain.current = false; setPending(null); return result;
    } catch (e) {
      if (!isCurrent() || saved.current?.body.request_key !== request.body.request_key) return null;
      if (groupAccessDenied(e)) { uncertain.current = true; access.deny(groupId); return null; }
      if (!wasUncertain && (!sent || definiteMemberRejection(e) && clear())) { saved.current = null; uncertain.current = false; setPending(null); }
      else uncertain.current = true;
      setError((e as Error).message || "成员批次结果尚未确认，请继续原请求确认。"); return null;
    } finally { if (isCurrent()) { inFlight.current = false; setBusy(false); } }
  }
  const currentScope = enabled && access.canAccess(groupId) && active.current === identity && latest.current === identity;
  return { pending: currentScope ? pending : null, busy: currentScope && busy, error: currentScope ? error : "", submit, confirm };
}

export function useMemberBatchAction(actorId: number, groupId: string, scope: string, enabled = true, sharedAccess?: GroupAccess) {
  const localAccess = useGroupAccess(actorId, scope), access = sharedAccess || localAccess;
  const identity = `${actorId}:${groupId}:${scope}:${enabled}`, active = useRef(""), latest = useRef(identity), generation = useRef(0), inFlight = useRef(false);
  latest.current = identity;
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  useEffect(() => {
    active.current = identity; generation.current += 1; inFlight.current = false; setBusy(false); setError("");
    return () => { active.current = ""; generation.current += 1; };
  }, [identity]);
  async function submit(batch: MemberBatch, action: keyof MemberBatch["actions"]) {
    if (!enabled || !access.canAccess(groupId) || latest.current !== identity || active.current !== identity || inFlight.current || batch.group_id !== groupId || !batch.actions[action]) return null;
    const current = generation.current, isCurrent = () => access.canAccess(groupId) && latest.current === identity && active.current === identity && current === generation.current;
    inFlight.current = true; setBusy(true); setError("");
    try {
      const result = await groupRequest<MemberBatch>(`/groups/${encodeURIComponent(groupId)}/member-batches/${encodeURIComponent(batch.id)}/${action}`, "POST", undefined, isCurrent);
      if (!isCurrent() || result === null) return null;
      if (!validMemberBatch(result) || result.id !== batch.id || result.group_id !== groupId || result.actor_id !== batch.actor_id) throw new Error("处理结果尚未确认，请刷新成员批次。");
      return result;
    } catch (e) { if (isCurrent()) { if (groupAccessDenied(e)) access.deny(groupId); else setError((e as Error).message); } return null; }
    finally { if (isCurrent()) { inFlight.current = false; setBusy(false); } }
  }
  const currentScope = enabled && access.canAccess(groupId) && active.current === identity && latest.current === identity;
  return { busy: currentScope && busy, error: currentScope ? error : "", submit };
}
