import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError, groupRequest, type BatchInfo, type GroupJob } from "./api";
import { runRecoverableSubmission, type subscriptionRequest } from "./groupsLogic";

export interface GroupAccess { canAccess: (groupId: string) => boolean; deny: (groupId: string) => void }
export function groupAccessDenied(error: unknown) {
  return error instanceof ApiError && [401, 403, 404].includes(error.status);
}
// Sibling group surfaces share this synchronous fence; a denied POST must not
// leave cached private data or old event handlers usable until the next poll.
export function useGroupAccess(actorId: number, scope: string): GroupAccess {
  const identity = `${actorId}:${scope}`, latest = useRef(identity), active = useRef(identity);
  const denied = useRef({ identity, ids: new Set<string>() });
  const [, render] = useState(0);
  latest.current = identity;
  if (denied.current.identity !== identity) denied.current = { identity, ids: new Set() };
  useEffect(() => { active.current = identity; render(value => value + 1); return () => { active.current = ""; }; }, [identity]);
  const canAccess = useCallback((groupId: string) => latest.current === identity && active.current === identity && !denied.current.ids.has(groupId), [identity]);
  const deny = useCallback((groupId: string) => {
    if (latest.current !== identity || active.current !== identity || denied.current.ids.has(groupId)) return;
    denied.current.ids.add(groupId); render(value => value + 1);
  }, [identity]);
  return { canAccess, deny };
}

export function useGroupJobRecovery(actorId: number, groupId: string, scope: string, access: GroupAccess) {
  const identity = `${actorId}:${groupId}:${scope}`, latest = useRef(identity), active = useRef("");
  const generation = useRef(0), inFlight = useRef(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  latest.current = identity;
  useEffect(() => {
    active.current = identity; generation.current += 1; inFlight.current = false; setBusy(false); setError("");
    return () => { active.current = ""; generation.current += 1; };
  }, [identity]);
  async function submit(job: GroupJob) {
    const current = generation.current;
    const isCurrent = () => access.canAccess(groupId) && latest.current === identity && active.current === identity && current === generation.current;
    if (!isCurrent() || inFlight.current || job.group_id !== groupId || job.member_batch_id || !["failed", "needs_review"].includes(job.state)) return null;
    inFlight.current = true; setBusy(true); setError("");
    try {
      const result = await groupRequest<GroupJob>(`/groups/${encodeURIComponent(groupId)}/retry`, "POST", undefined, isCurrent);
      if (!isCurrent() || result === null) return null;
      if (result.id !== job.id || result.group_id !== groupId || result.state !== "queued") throw new Error("核对请求结果尚未确认，请刷新分组。");
      return result;
    } catch (e) {
      if (isCurrent()) { if (groupAccessDenied(e)) access.deny(groupId); else setError((e as Error).message); }
      return null;
    } finally { if (isCurrent()) { inFlight.current = false; setBusy(false); } }
  }
  const currentScope = access.canAccess(groupId) && latest.current === identity && active.current === identity;
  return { busy: currentScope && busy, error: currentScope ? error : "", submit };
}

export function useRemote<T>(path: string | null, poll = 0, actorId?: number, scope = "", onAccessDenied?: () => void) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [forbidden, setForbidden] = useState(false);
  const generation = useRef(0);
  const inFlight = useRef<number | null>(null);
  const activePath = useRef<string | null>(null);
  const identity = JSON.stringify([path, actorId, scope]);
  const latestIdentity = useRef(identity);
  const deniedCallback = useRef(onAccessDenied);
  latestIdentity.current = identity;
  deniedCallback.current = onAccessDenied;
  const refresh = useCallback(async () => {
    if (!path || activePath.current !== identity || latestIdentity.current !== identity) return;
    const current = ++generation.current;
    const isCurrent = () => current === generation.current && activePath.current === identity && latestIdentity.current === identity;
    inFlight.current = current;
    try {
      const result = await groupRequest<T>(path, "GET", undefined, isCurrent);
      if (result !== null && isCurrent()) {
        setData(result);
        setError("");
        setForbidden(false);
      }
    } catch (e) {
      if (isCurrent()) {
        setError((e as Error).message);
        if (groupAccessDenied(e)) { setData(null); setForbidden(true); deniedCallback.current?.(); }
      }
    } finally {
      if (current === generation.current) setLoading(false);
      if (inFlight.current === current) inFlight.current = null;
    }
  }, [path, actorId, identity]);
  useEffect(() => {
    activePath.current = identity;
    setData(null);
    setError("");
    setForbidden(false);
    setLoading(!!path);
    void refresh();
    const timer = path && poll ? window.setInterval(() => {
      if (inFlight.current === null) void refresh();
    }, poll) : undefined;
    return () => {
      activePath.current = null;
      generation.current += 1;
      inFlight.current = null;
      window.clearInterval(timer);
    };
  }, [path, poll, refresh, actorId, identity]);
  const currentScope = activePath.current === identity && latestIdentity.current === identity;
  return { data: currentScope ? data : null, error: currentScope ? error : "", loading: currentScope ? loading : !!path, forbidden: currentScope && forbidden, refresh };
}

type SubscriptionBody = ReturnType<typeof subscriptionRequest>;
interface SubscriptionIntent {
  body: SubscriptionBody;
  key: string;
}

function savedSubscription(key: string, groupId: string): SubscriptionIntent | null {
  try {
    const saved = JSON.parse(sessionStorage.getItem(key) || "null");
    if (!saved || typeof saved.key !== "string" || saved.body?.group_id !== groupId ||
      !Array.isArray(saved.body.record_ids) || !saved.body.record_ids.every((id: unknown) => typeof id === "string") ||
      !Number.isInteger(saved.body.plan_id)) return null;
    return saved;
  } catch {
    return null;
  }
}

export function useGroupSubscription(actorId: number, groupId: string) {
  const storageKey = `kiro-group-subscription:${actorId}:${groupId}`;
  const [pending, setPending] = useState<SubscriptionIntent | null>(() => savedSubscription(storageKey, groupId));
  const intent = useRef(pending);
  const inFlight = useRef(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function submit(body?: SubscriptionBody) {
    if (inFlight.current) return null;
    const request = intent.current || (body ? { body: structuredClone(body), key: crypto.randomUUID() } : null);
    if (!request) return null;
    inFlight.current = true;
    setBusy(true);
    setError("");
    try {
      const outcome = await runRecoverableSubmission(
        request,
        (path, payload) => api(path, "POST", payload),
        next => {
          // Persist this non-secret intent before admission so login/remount can
          // resume the same explicit selection and key without automatic reposts.
          if (next) sessionStorage.setItem(storageKey, JSON.stringify(next));
          else sessionStorage.removeItem(storageKey);
          intent.current = next;
          setPending(next);
        },
        async send => {
          const batch = await send<BatchInfo>("/batches/subscribe", { ...request.body, request_key: request.key });
          if (!batch || typeof batch.id !== "string" || !batch.id)
            throw new Error("开通结果尚未确认，请继续使用原请求确认。");
          return batch;
        },
      );
      if (outcome.state !== "accepted") setError(outcome.error.message);
      return outcome;
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }
  return { pending, busy, error, submit };
}
