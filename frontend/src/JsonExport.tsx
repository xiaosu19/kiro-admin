import { useEffect, useState } from "react";
import { useLocation, useSearchParams } from "react-router-dom";
import { type AuthBatch, type RecordItem, type User } from "./api";
import { authRequest, canUseAuthRecord } from "./authLogic";
import { useAuthAdmission } from "./authRequests";
import { AdmissionRecovery, AuthError, AuthHistory, AuthProgress } from "./AuthBatches";
import { ManualAuthPicker, SelectedAuthRecords } from "./AuthSelection";
import { ExternalJsonExport } from "./ExternalJsonExport";
import { GroupJsonExport } from "./GroupJsonExport";
import { AiRecognitionNotice, AiSettings } from "./AiSettings";
import { exportMode, exportTaskParams, rememberedExport, restoreExport } from "./jsonExportNavigation";

export function JsonExport({ user, notify }: { user: User; notify: (message: string, error?: boolean) => void }) {
  const [params, setParams] = useSearchParams();
  const location = useLocation();
  let currentParams = params;
  if (!params.size && !(location.state as { records?: unknown } | null)?.records) {
    try { currentParams = restoreExport(sessionStorage.getItem(`kiro:json-export:last:${user.id}`)) || params; }
    catch { /* Render the normal picker when storage is unavailable. */ }
  }
  const mode = exportMode(currentParams);
  useEffect(() => {
    try {
      const key = `kiro:json-export:last:${user.id}`, saved = rememberedExport(params);
      if (saved) sessionStorage.setItem(key, saved);
      else if (!params.size && !(location.state as { records?: unknown } | null)?.records) {
        const restored = restoreExport(sessionStorage.getItem(key));
        if (restored) setParams(restored, { replace: true });
      }
    } catch { /* Storage can be unavailable; server history remains accessible. */ }
  }, [user.id, params, setParams, location.state]);
  const [selected, setSelected] = useState<RecordItem[]>(() => {
    const records = (location.state as { records?: RecordItem[] } | null)?.records;
    return Array.isArray(records) ? records.filter(r => r && typeof r.id === "string" && canUseAuthRecord(r, user, "json_export")).slice(0, 100) : [];
  });
  const [error, setError] = useState(""), [version, setVersion] = useState(0);
  const admission = useAuthAdmission(user.id, "json_export");
  const locked = admission.busy || !!admission.pending;
  const batchId = currentParams.get("batch_id");
  function accepted(batch: AuthBatch) {
    setSelected([]); setError(""); setVersion(v => v + 1);
    setParams(exportTaskParams(mode === "group" ? "group" : "manual", batch.id));
    notify("转换已提交，请查看每位用户的进度");
  }
  async function submit() {
    if (locked) return;
    setError("");
    try {
      const body = authRequest("json_export", selected.map(record => record.id));
      const batch = await admission.submit(body);
      if (batch) accepted(batch);
    } catch (e) { setError((e as Error).message); }
  }
  return <>
    <div className="page-heading"><div><p className="eyebrow">企业账号</p><h1>JSON 导出</h1><p>选择已有 SSO 用户，或粘贴单个、批量账号转换。只下载实际成功的 JSON。</p></div>
      <button className="secondary" aria-expanded={params.get("ai_settings") === "1"} onClick={() => setParams(old => {
        const next = new URLSearchParams(old);
        if (next.get("ai_settings") === "1") next.delete("ai_settings"); else next.set("ai_settings", "1");
        return next;
      })}>{params.get("ai_settings") === "1" ? "收起 AI 设置" : "AI 识别设置"}</button></div>
    {params.get("ai_settings") === "1" && <AiSettings key={user.id} notify={notify} />}
    <AiRecognitionNotice />
    <div className="auth-mode" role="group" aria-label="选择来源">{([
      ["manual", "手动选择"], ["group", "按分组选择"], ["paste", "粘贴账号转换"],
    ] as const).map(([value, label]) => <button key={value} className={mode === value ? "primary" : "secondary"} disabled={locked} onClick={() => {
      setSelected([]); setParams({ source: value });
    }}>{label}</button>)}</div>
    {mode === "paste" ? <ExternalJsonExport key={user.id} user={user} notify={notify}
      selectedId={currentParams.get("external_batch_id")} onSelected={id => setParams(exportTaskParams("paste", id))} /> : <>
    <AdmissionRecovery admission={admission} onAccepted={accepted} />
    {mode === "group" ? <GroupJsonExport key={`${user.id}:${params.getAll("group_id").join(":")}`} user={user} notify={notify}
      initialGroupIds={params.getAll("group_id")} onAccepted={accepted} /> :
    <section className="panel auth-composer">
      <h2>选择转换用户</h2>
      <p className="info-note">首次登录可能需要自动设置并保存新的永久密码。图片验证码优先使用你的 AI 配置，需人工处理时在本页填写；AWS 要求官方页面验证时，打开授权链接完成后再回来继续。官方页面登录后的密码标记为待核对，JSON 不包含旧密码。</p>
      <ManualAuthPicker user={user} kind="json_export" selected={selected} disabled={locked} onChange={setSelected} />
      <SelectedAuthRecords records={selected} disabled={locked} onChange={setSelected} />
      <AuthError text={error} />
      <button className="primary" disabled={locked || !selected.length} onClick={() => void submit()}>{admission.busy ? "正在提交…" : `转换选中的 ${selected.length} 人`}</button>
    </section>}
    {batchId && <AuthProgress key={`${user.id}:${batchId}`} id={batchId} actorId={user.id} scope="json_export" notify={notify} onChanged={() => setVersion(v => v + 1)} />}
    <AuthHistory actorId={user.id} scope="json_export" version={version} selectedId={batchId} onSelect={id => setParams(exportTaskParams(mode === "group" ? "group" : "manual", id))} />
    </>}
  </>;
}
