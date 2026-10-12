import { useEffect, useRef, useState } from "react";
import { groupRequest } from "./api";
import { externalIntent, externalPending, type ExternalBatch, type ExternalPending, type PastedPreview } from "./externalExportLogic";

export function useExternalAdmission(actorId: number) {
  const key = `kiro:external-export:${actorId}`;
  const read = () => typeof sessionStorage === "undefined" ? null : externalPending(sessionStorage.getItem(key));
  const [pending, setPending] = useState<ExternalPending | null>(read);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const latest = useRef(key), active = useRef(""), flight = useRef(false), generation = useRef(0);
  latest.current = key;
  useEffect(() => {
    active.current = key; generation.current++; flight.current = false;
    setPending(read()); setBusy(false); setError("");
    return () => { active.current = ""; generation.current++; };
  }, [key]);
  const current = () => latest.current === key && active.current === key;
  function clear(requestKey: string) {
    if (!current()) return false;
    if (read()?.request_key === requestKey) sessionStorage.removeItem(key);
    setPending(null); setError(""); return true;
  }
  function recovered(batch: ExternalBatch) {
    const saved = read();
    return current() && !!saved && batch.actor_id === actorId && batch.request_key === saved.request_key && clear(saved.request_key);
  }
  function clearAfterReview() {
    if (!current() || flight.current) return false;
    const saved = read();
    return !saved || clear(saved.request_key);
  }
  async function submit(text: string, preview: PastedPreview) {
    if (!current() || flight.current) return null;
    const epoch = generation.current, valid = () => current() && generation.current === epoch;
    flight.current = true; setBusy(true); setError("");
    try {
      const saved = read(); setPending(saved);
      const intent = externalIntent(preview, saved);
      sessionStorage.setItem(key, JSON.stringify(intent)); setPending(intent);
      const batch = await groupRequest<ExternalBatch>("/external-auth-batches", "POST", { text, ...intent }, valid);
      if (batch && valid()) {
        if (!batch.id || batch.actor_id !== actorId || batch.request_key !== intent.request_key)
          throw new Error("提交结果尚未确认，请核对本人转换记录并保留原请求");
        clear(intent.request_key); return batch;
      }
    } catch (e) {
      // Every error can follow an already committed admission. Only explicit
      // history review or a matching response clears nonsecret replay metadata.
      if (valid()) setError((e as Error).message || "提交结果尚未确认");
    } finally { if (valid()) { flight.current = false; setBusy(false); } }
    return null;
  }
  return { pending, busy, error, submit, recovered, clearAfterReview };
}
