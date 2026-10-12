import { useEffect, useRef, useState } from "react";
import { ApiError, downloadProvisioning, groupRequest } from "./api";
import { freezeProvisioning, validProvisioningBatch, type ProvisioningBody, type ProvisioningIntent, type ProvisioningPreview, type ProvisioningBatch } from "./provisioningLogic";

function savedIntent(key: string): ProvisioningIntent | null {
  try {
    const value = JSON.parse(sessionStorage.getItem(key) || 'null');
    if (!value || typeof value.request_key !== 'string' || value.request_key.length < 16 || value.request_key.length > 80 ||
      !/^[a-f0-9]{64}$/.test(value.preview_fingerprint) || !Array.isArray(value.accounts) || !value.accounts.length || value.accounts.length > 100) return null;
    return freezeProvisioning({ accounts: value.accounts, request_key: value.request_key, preview_fingerprint: value.preview_fingerprint });
  } catch { return null; }
}
export function useProvisioningAdmission(actorId: number, scope: string) {
  const storageKey = `kiro-provisioning-request:${actorId}`, identity = `${storageKey}:${scope}`;
  const [pending, setPending] = useState(() => savedIntent(storageKey));
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  const saved = useRef(pending), uncertain = useRef(!!pending), flight = useRef(false), generation = useRef(0);
  const active = useRef(''), latest = useRef(identity); latest.current = identity;
  useEffect(() => {
    active.current = identity; generation.current++; saved.current = savedIntent(storageKey); uncertain.current = !!saved.current;
    flight.current = false; setPending(saved.current); setBusy(false); setError('');
    return () => { active.current = ''; generation.current++; };
  }, [identity, storageKey]);
  function confirm(batch: ProvisioningBatch) {
    if (active.current !== identity || latest.current !== identity || !saved.current || batch.actor_id !== actorId || !validProvisioningBatch(batch, saved.current)) return false;
    try { const stored = savedIntent(storageKey); if (stored?.request_key === saved.current.request_key) sessionStorage.removeItem(storageKey); } catch { /* Keep a recoverable in-memory request. */ }
    saved.current = null; uncertain.current = false; setPending(null); setError(''); return true;
  }
  async function submit(input?: ProvisioningIntent): Promise<ProvisioningBatch | null> {
    if (active.current !== identity || latest.current !== identity || flight.current) return null;
    const body = saved.current || (input ? freezeProvisioning(input) : null);
    if (!body) return null;
    const epoch = generation.current, wasUncertain = uncertain.current;
    const isCurrent = () => active.current === identity && latest.current === identity && generation.current === epoch;
    const attempt = JSON.stringify({ ...body, attempt_id: crypto.randomUUID() });
    const clear = () => { try { if (sessionStorage.getItem(storageKey) !== attempt) return false; sessionStorage.removeItem(storageKey); return true; } catch { return false; } };
    flight.current = true; saved.current = body; setPending(body); setBusy(true); setError('');
    let sent = false;
    try {
      sessionStorage.setItem(storageKey, attempt); sent = true;
      const result = await groupRequest<ProvisioningBatch>('/provisioning-batches', 'POST', body, isCurrent);
      if (!result || !isCurrent()) return null;
      if (result.actor_id !== actorId || !validProvisioningBatch(result, body)) throw new Error('受理结果尚未确认，请继续原请求确认。');
      clear(); saved.current = null; uncertain.current = false; setPending(null); return result;
    } catch (e) {
      if (!isCurrent()) return null;
      const definite = e instanceof ApiError && e.status >= 400 && e.status < 500 && ![408, 429].includes(e.status);
      if (!wasUncertain && (!sent || definite && clear())) { saved.current = null; uncertain.current = false; setPending(null); }
      else uncertain.current = true;
      setError((e as Error).message || '受理结果尚未确认，请继续原请求确认。'); return null;
    } finally { if (isCurrent()) { flight.current = false; setBusy(false); } }
  }
  const current = active.current === identity && latest.current === identity;
  return { pending: current ? pending : null, busy: current && busy, error: current ? error : '', submit, confirm };
}

export function useProvisioningPreview(actorId: number, scope: string, body: ProvisioningBody | null) {
  const serialized = JSON.stringify(body), identity = `${actorId}:${scope}:${serialized}`;
  const [data, setData] = useState<ProvisioningPreview | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState('');
  const active = useRef(''), latest = useRef(identity), generation = useRef(0), flight = useRef(false); latest.current = identity;
  useEffect(() => {
    active.current = identity; generation.current++; flight.current = false; setData(null); setBusy(false); setError('');
    return () => { active.current = ''; generation.current++; };
  }, [identity]);
  async function submit() {
    if (!body || active.current !== identity || latest.current !== identity || flight.current) return;
    const epoch = ++generation.current, isCurrent = () => active.current === identity && latest.current === identity && generation.current === epoch;
    flight.current = true; setBusy(true); setData(null); setError('');
    try {
      const result = await groupRequest<ProvisioningPreview>('/provisioning-batches/preview', 'POST', JSON.parse(serialized), isCurrent);
      if (!result || !isCurrent()) return;
      if (!/^[a-f0-9]{64}$/.test(result.preview_fingerprint) || result.accounts.length !== body.accounts.length) throw new Error('批次预览不完整，请重新预览。');
      setData(result);
    } catch (e) { if (isCurrent()) setError((e as Error).message); }
    finally { if (isCurrent()) { flight.current = false; setBusy(false); } }
  }
  const current = active.current === identity && latest.current === identity;
  return { data: current ? data : null, busy: current && busy, error: current ? error : '', submit };
}

export function useProvisioningReport(actorId: number, scope: string) {
  const identity = `${actorId}:${scope}`, latest = useRef(identity), active = useRef(''), epoch = useRef(0), flight = useRef(false);
  const [busy, setBusy] = useState(false), [error, setError] = useState('');
  latest.current = identity;
  useEffect(() => {
    active.current = identity; epoch.current++; flight.current = false; setBusy(false); setError('');
    return () => { active.current = ''; epoch.current++; };
  }, [identity]);
  async function download(path: string) {
    const generation = epoch.current;
    const isCurrent = () => active.current === identity && latest.current === identity && epoch.current === generation;
    if (!isCurrent() || flight.current) return null;
    flight.current = true; setBusy(true); setError('');
    try { return await downloadProvisioning(path, 'GET', undefined, isCurrent); }
    catch (e) { if (isCurrent()) setError((e as Error).message); return null; }
    finally { if (isCurrent()) { flight.current = false; setBusy(false); } }
  }
  const current = active.current === identity && latest.current === identity;
  return { download, busy: current && busy, error: current ? error : '' };
}
