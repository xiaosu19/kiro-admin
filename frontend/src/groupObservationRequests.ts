import { useEffect, useRef, useState } from "react";
import { groupRequest, type GroupItem, type GroupObservation } from "./api";
import { groupAccessDenied, useGroupAccess, type GroupAccess } from "./groupRequests";

// Keep sent reads in their slots across navigation; aborting HTTP would release the
// browser slot while a synchronous AWS read could still be running on the server.
let activeReads = 0;
const readQueue: { current: () => boolean; read: () => Promise<GroupObservation | null>;
  resolve: (value: GroupObservation | null) => void; reject: (error: unknown) => void }[] = [];
function drainReads() {
  while (activeReads < 3 && readQueue.length) {
    const task = readQueue.shift()!;
    if (!task.current()) { task.resolve(null); continue; }
    activeReads += 1;
    void (async () => {
      try { task.resolve(await task.read()); } catch (error) { task.reject(error); }
      finally { activeReads -= 1; drainReads(); }
    })();
  }
}
function queueRead(read: () => Promise<GroupObservation | null>, current: () => boolean) {
  return new Promise<GroupObservation | null>((resolve, reject) => { readQueue.push({ read, current, resolve, reject }); drainReads(); });
}

export interface ObservationEntry { data: GroupObservation | null; loading: boolean; stale: boolean; error: string; stamp: string }
export function groupObservationStamp(group: GroupItem) {
  return JSON.stringify([group.id, group.owner_id, group.aws_account_id, group.remote_id, group.revision,
    group.state, group.active_job_id, group.deleted_at, group.counts, group.native_subscription]);
}
function validObservation(value: unknown, group: GroupItem): value is GroupObservation {
  const data = value as GroupObservation;
  return !!data && data.group_id === group.id && data.aws_account_id === group.aws_account_id && data.remote_id === group.remote_id &&
    typeof data.queried_at === "string" && Number.isFinite(Date.parse(data.queried_at)) && !!data.directory && typeof data.directory.exists === "boolean" && Array.isArray(data.directory.owned_members) &&
    data.directory.owned_members.every(member => member && [member.record_id, member.sso_user_id, member.username, member.email, member.membership_id].every(value => typeof value === "string")) &&
    (data.directory.exists ? typeof data.directory.name === "string" && Number.isInteger(data.directory.member_count) && data.directory.member_count! >= 0
      : data.directory.name === null && data.directory.member_count === null) && !!data.subscription &&
    ["Subscribed", "Canceled", "Not subscribed"].includes(data.subscription.status) && typeof data.subscription.access_active === "boolean" &&
    [data.subscription.subscription_type, data.subscription.plan_label, data.subscription.pending_subscription_type, data.subscription.pending_plan_label,
      data.subscription.effective_at, data.subscription.cancellation_expires_at].every(value => value === null || typeof value === "string") &&
    (data.subscription.status === "Not subscribed" ? data.subscription.subscription_type === null && data.subscription.plan_label === null
      : typeof data.subscription.subscription_type === "string" && !!data.subscription.subscription_type && typeof data.subscription.plan_label === "string" && !!data.subscription.plan_label);
}

export function useGroupObservations(actorId: number, scope: string, groups: GroupItem[], sharedAccess?: GroupAccess) {
  const localAccess = useGroupAccess(actorId, scope), access = sharedAccess || localAccess;
  const identity = `${actorId}:${scope}`, latest = useRef(identity), active = useRef("");
  latest.current = identity;
  const available = useRef(new Map<string, GroupItem>());
  available.current = new Map(groups.map(group => [group.id, group]));
  const [stored, setStored] = useState<Record<string, ObservationEntry>>({});
  const [busy, setBusy] = useState(false), [progress, setProgress] = useState({ done: 0, total: 0 });
  const running = useRef<{ controller: AbortController } | null>(null);
  const invalidations = useRef(new Map<string, number>());
  useEffect(() => {
    active.current = identity; running.current?.controller.abort(); running.current = null;
    invalidations.current.clear();
    setStored({}); setBusy(false); setProgress({ done: 0, total: 0 });
    return () => { active.current = ""; running.current?.controller.abort(); running.current = null; };
  }, [identity]);
  function invalidate(ids: string[]) {
    if (active.current !== identity || latest.current !== identity) return;
    for (const id of ids) invalidations.current.set(id, (invalidations.current.get(id) || 0) + 1);
    setStored(current => Object.fromEntries(Object.entries(current).map(([id, entry]) => [id,
      ids.includes(id) ? { ...entry, data: null, stale: true, loading: false, error: "" } : entry])));
  }
  async function refresh(targets: GroupItem[]) {
    if (active.current !== identity || latest.current !== identity || running.current) return;
    const selected = [...new Map(targets.filter(group => access.canAccess(group.id) && group.remote_id && available.current.has(group.id) &&
      groupObservationStamp(available.current.get(group.id)!) === groupObservationStamp(group)).map(group => [group.id, group])).values()];
    if (!selected.length) return;
    const run = { controller: new AbortController() };
    const versions = new Map(selected.map(group => [group.id, invalidations.current.get(group.id) || 0]));
    running.current = run; setBusy(true); setProgress({ done: 0, total: selected.length });
    const isCurrent = () => active.current === identity && latest.current === identity && running.current === run && !run.controller.signal.aborted;
    setStored(current => ({ ...current, ...Object.fromEntries(selected.map(group => [group.id,
      { data: null, loading: true, stale: false, error: "", stamp: groupObservationStamp(group) }])) }));
    let next = 0, done = 0;
    async function worker() {
      while (isCurrent() && next < selected.length) {
        const group = selected[next++], stamp = groupObservationStamp(group);
        const unchanged = () => access.canAccess(group.id) && available.current.has(group.id) && groupObservationStamp(available.current.get(group.id)!) === stamp &&
          (invalidations.current.get(group.id) || 0) === versions.get(group.id);
        try {
          if (!unchanged()) continue;
          const data = await queueRead(() => groupRequest<GroupObservation>(`/groups/${encodeURIComponent(group.id)}/aws-refresh`, "POST", undefined, () => isCurrent() && access.canAccess(group.id)), () => isCurrent() && unchanged());
          if (!isCurrent()) return;
          if (!access.canAccess(group.id)) continue;
          if (data === null) throw new Error("登录状态已变化，请刷新后重新读取 AWS。");
          if (!validObservation(data, group)) throw new Error("AWS 分组响应不完整，请重新读取。");
          setStored(current => ({ ...current, [group.id]: { data: unchanged() ? data : null, stale: !unchanged(), loading: false, error: "", stamp } }));
        } catch (e) {
          if (isCurrent()) {
            if (groupAccessDenied(e)) access.deny(group.id);
            setStored(current => ({ ...current, [group.id]: { data: null, stale: false, loading: false, error: (e as Error).message, stamp } }));
          }
        } finally { if (isCurrent()) { done += 1; setProgress({ done, total: selected.length }); } }
      }
    }
    try { await Promise.all(Array.from({ length: Math.min(3, selected.length) }, worker)); }
    finally { if (isCurrent()) { running.current = null; setBusy(false); } }
  }
  const currentScope = active.current === identity && latest.current === identity;
  const entries = Object.fromEntries(Object.entries(currentScope ? stored : {}).filter(([id]) => access.canAccess(id) && available.current.has(id)).map(([id, entry]) => [id,
    groupObservationStamp(available.current.get(id)!) === entry.stamp ? entry : { ...entry, data: null, stale: true, loading: false, error: "" }]));
  return { entries, busy: currentScope && busy, progress: currentScope ? progress : { done: 0, total: 0 }, refresh, invalidate };
}
