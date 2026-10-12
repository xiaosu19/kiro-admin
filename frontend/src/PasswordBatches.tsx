import { useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { type AuthBatch, type PasswordKind, type RecordItem, type User } from "./api";
import { authRequest, canUseAuthRecord, validPermanentPassword } from "./authLogic";
import { useAuthAdmission } from "./authRequests";
import { AdmissionRecovery, AuthError, AuthHistory, AuthProgress, PasswordFields } from "./AuthBatches";
import { GroupAuthPicker, ManualAuthPicker, SelectedAuthRecords } from "./AuthSelection";
import { AiRecognitionNotice } from "./AiSettings";

export function PasswordBatches({ user, records = [], groupId, sourceGroupId, notify, onClose, onChanged }: {
  user: User; records?: RecordItem[]; groupId?: string; sourceGroupId?: string; notify: (message: string, error?: boolean) => void; onClose: () => void; onChanged?: () => void;
}) {
  const [params, setParams] = useSearchParams();
  const [kind, setKind] = useState<PasswordKind>("reset_password");
  const [password, setPassword] = useState("");
  const [selected, setSelected] = useState<RecordItem[]>(() => groupId ? [] : records.filter(record => canUseAuthRecord(record, user, "reset_password")).slice(0, 100));
  const [error, setError] = useState(""), [version, setVersion] = useState(0);
  const admission = useAuthAdmission(user.id, "password");
  const locked = admission.busy || !!admission.pending;
  const batchId = params.get("password_batch");
  function selectBatch(id: string) {
    setParams(old => { const next = new URLSearchParams(old); next.set("password_batch", id); return next; });
  }
  function accepted(batch: AuthBatch) {
    setPassword(""); setSelected([]); setError(""); setVersion(v => v + 1); selectBatch(batch.id); onChanged?.();
    notify("改密已提交，请查看每位用户的结果");
  }
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (locked) return;
    setError("");
    try {
      const body = authRequest(kind, selected.map(record => record.id), groupId || sourceGroupId, password);
      // The frozen request in the admission hook is the only retained copy.
      setPassword("");
      const batch = await admission.submit(body);
      if (batch) accepted(batch);
    } catch (e) { setError((e as Error).message); }
  }
  return <section className="auth-password-manager" aria-label="批量改密">
    <div className="page-heading"><div><h2>批量改密</h2><p>重置一次性密码，或设置永久密码。每位用户单独保存处理结果。</p></div><button className="secondary" disabled={admission.busy} onClick={onClose}>收起改密</button></div>
    <AdmissionRecovery admission={admission} onAccepted={accepted} />
    <AiRecognitionNotice />
    <section className="panel">
      <PasswordFields kind={kind} password={password} disabled={locked} onKind={next => { setKind(next); setPassword(""); if (groupId) setSelected([]); }} onPassword={setPassword} />
      {groupId ? <GroupAuthPicker key={`${groupId}:${kind}`} user={user} kind={kind} groupId={groupId} selected={selected} disabled={locked} onChange={setSelected} /> : !records.length && !sourceGroupId && <ManualAuthPicker user={user} kind={kind} selected={selected} disabled={locked} onChange={setSelected} />}
      <SelectedAuthRecords records={selected} disabled={locked} onChange={setSelected} />
      <form onSubmit={submit}><AuthError text={error} /><button className="primary" disabled={locked || !selected.length || (kind === "custom_password" && !validPermanentPassword(password))}>{admission.busy ? "正在提交…" : `确认${kind === "reset_password" ? "重置" : "改密"} ${selected.length} 人`}</button></form>
    </section>
    {batchId && <AuthProgress key={`${user.id}:${batchId}`} id={batchId} actorId={user.id} scope="password" notify={notify} onChanged={() => { setVersion(v => v + 1); onChanged?.(); }} />}
    <AuthHistory actorId={user.id} scope="password" version={version} selectedId={batchId} onSelect={selectBatch} />
  </section>;
}
