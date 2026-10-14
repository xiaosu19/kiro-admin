import { useEffect, useRef, useState } from "react";
import { date, downloadProvisioning, groupRequest, type AuthItem, type User } from "./api";
import { AuthError, HumanChallenge } from "./AuthBatches";
import { groupAccessDenied, useRemote } from "./groupRequests";
import { authStateLabel } from "./authLogic";
import { externalStages, type ExternalBatch, type ExternalItem, type PastedPreview } from "./externalExportLogic";
import { useExternalAdmission } from "./externalExportRequests";

export function PastedPreviewTable({ preview }: { preview: PastedPreview }) {
  return <div className="table-wrap"><table><thead><tr><th>用户名</th><th>登录地址</th><th>登录区域</th></tr></thead><tbody>
    {preview.accounts.map((row, i) => <tr key={i}><td>{row.username}</td><td>{row.portal_url}</td><td>{row.region || "从 AWS 入口自动读取"}</td></tr>)}
  </tbody></table></div>;
}

export function ExternalBatchTable({ batch, busy, onAction, onDownload, onChallenge }: {
  batch: ExternalBatch; busy: boolean; onAction: (item: ExternalItem, action: "retry" | "credential-recovery") => void;
  onDownload: (item?: ExternalItem) => void; onChallenge: (item: ExternalItem) => void;
}) {
  return <><p role="status">共 {batch.total} 人 · 成功 {batch.success_count} · 未成功 {batch.failure_count}</p>
    <p className="muted">提交：{date(batch.created_at)} · 任务截止：{date(batch.expires_at)}{batch.download_expires_at && <> · 下载截止：{date(batch.download_expires_at)}</>}</p>
    {batch.download_ready && <button className="primary" disabled={busy} onClick={() => onDownload()}>下载成功结果 JSON ZIP</button>}
    <p className="muted">只导出实际成功且通过订阅校验的 Token。外部账号须由 AWS 用量响应确认受支持的付费方案。批量 ZIP 内只有一个文件夹，按用户名分别保存 JSON。整批结束后开始计算下载保留时间，可离开页面稍后回来下载；下载后对应结果会清除，单个结果可直接下载 JSON。</p>
    <div className="table-wrap"><table><thead><tr><th>用户 / 登录入口</th><th>进度</th><th>操作</th></tr></thead><tbody>
      {batch.items?.map(item => <tr key={item.id}><td>{item.username}<small>{item.portal_url}</small></td><td>{item.state === "downloaded" ? "已下载并清理" : authStateLabel[item.state] || item.state}
        {item.state === "running" && <small>{externalStages[item.stage] || "处理账号"}</small>}
        {item.retry_count > 0 && <small>自动重试 {item.retry_count}/5{item.next_poll_at ? ` · 下次：${date(item.next_poll_at)}` : ""}</small>}
        {item.error && <small className="proxy-failed">{item.error}</small>}</td>
        <td><div className="row-actions">
          {batch.download_ready && item.state === "completed" && <button className="text-button" disabled={busy} onClick={() => onDownload(item)}>下载此用户 JSON</button>}
          {batch.state === "active" && item.state === "challenge" && <button className="text-button" disabled={busy} onClick={() => onChallenge(item)}>人工处理</button>}
          {batch.state === "active" && item.state === "challenge" && item.can_retry_challenge && <button className="text-button" disabled={busy || item.cancel_requested} onClick={() => onAction(item, "retry")}>重试验证</button>}
          {batch.state === "active" && ["failed", "needs_review"].includes(item.state) && <button className="text-button" disabled={busy} onClick={() => onAction(item, "retry")}>继续处理</button>}
          {item.credential_recovery_available && ["failed", "needs_review", "cancelled", "expired"].includes(item.state) && <button className="text-button" disabled={busy} onClick={() => onAction(item, "credential-recovery")}>下载凭据恢复信息</button>}
        </div></td></tr>)}
    </tbody></table></div></>;
}

function ExternalProgress({ id, user, notify, onChanged }: { id: string; user: User; notify: (message: string) => void; onChanged: () => void }) {
  const denied = useRef(false);
  const remote = useRemote<ExternalBatch>(`/external-auth-batches/${encodeURIComponent(id)}`, 3000, user.id, `${user.id}:${id}`, () => { denied.current = true; });
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const [confirmCancel, setConfirmCancel] = useState(false), [challengeId, setChallengeId] = useState<string | null>(null);
  const mounted = useRef(true), flight = useRef(false);
  if (remote.forbidden) denied.current = true;
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const batch = remote.data?.actor_id === user.id ? remote.data : null;
  const current = () => mounted.current && !denied.current;
  async function refresh() { await remote.refresh(); if (current()) onChanged(); }
  async function run(path: string, download = false) {
    if (!batch || flight.current || !current()) return;
    flight.current = true; setBusy(true); setError("");
    try {
      if (download) {
        const result = await downloadProvisioning(path, "POST", undefined, current);
        if (result && current()) notify("文件已下载，请妥善保存");
      } else await groupRequest(path, "POST", undefined, current);
    } catch (e) { if (current()) { setError((e as Error).message); if (groupAccessDenied(e)) denied.current = true; } }
    finally { await refresh(); flight.current = false; if (mounted.current) setBusy(false); }
  }
  const challenge = batch?.items?.find(i => i.id === challengeId && i.state === "challenge" && !i.cancel_requested);
  const authItem: AuthItem | null = challenge ? { ...challenge, state: "challenge", record_id: challenge.id,
    operation_id: challenge.id, owner_id: user.id, credential_state: "unknown", has_password: false, requires_new_reset: false } : null;
  return <section className="panel"><div className="section-heading"><h2>粘贴转换进度</h2><button className="secondary" disabled={busy} onClick={() => void refresh()}>刷新进度</button></div>
    <AuthError text={error || remote.error} />
    {batch && !denied.current && <><ExternalBatchTable batch={batch} busy={busy}
      onDownload={item => void run(`/external-auth-batches/${id}/download${item ? `?format=json&item_id=${encodeURIComponent(item.id)}` : ""}`, true)}
      onAction={(item, action) => void run(`/external-auth-batches/${id}/items/${item.id}/${action}`, action === "credential-recovery")}
      onChallenge={item => setChallengeId(item.id)} />
      {batch.state === "active" && <button className="secondary" disabled={busy} onClick={() => setConfirmCancel(true)}>取消转换批次</button>}
      {confirmCancel && <div className="info-note" role="group" aria-label="确认取消粘贴转换"><p>取消会清除 Token 结果。已经完成的首次登录密码修改不会恢复，可下载已保存的凭据恢复信息核对。</p><button className="danger" disabled={busy} onClick={() => { setConfirmCancel(false); void run(`/external-auth-batches/${id}/cancel`); }}>确认取消</button><button className="secondary" onClick={() => setConfirmCancel(false)}>返回</button></div>}
      {authItem && <HumanChallenge key={`${authItem.operation_id}:${authItem.revision}`} batchId={id} item={authItem} kind="json_export" family="external-auth-batches" onChanged={refresh} onClose={() => setChallengeId(null)} />}
    </>}
  </section>;
}

export function ExternalJsonExport({ user, selectedId, onSelected, notify }: {
  user: User; selectedId: string | null; onSelected: (id: string) => void; notify: (message: string) => void;
}) {
  const [text, setText] = useState(""), [preview, setPreview] = useState<PastedPreview | null>(null);
  const [error, setError] = useState(""), [inspecting, setInspecting] = useState(false), [page, setPage] = useState(1);
  const admission = useExternalAdmission(user.id), pending = admission.pending, busy = inspecting || admission.busy;
  const history = useRemote<{ items: ExternalBatch[]; page: number }>(`/external-auth-batches?page=${page}`, 5000, user.id);
  const recovery = useRemote<{ items: ExternalBatch[] }>(pending ? `/external-auth-batches?request_key=${encodeURIComponent(pending.request_key)}` : null, 5000, user.id);
  const mounted = useRef(true), flight = useRef(false), epoch = useRef(0);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; epoch.current++; }; }, []);
  const current = () => mounted.current;
  function accepted(batch: ExternalBatch) {
    setText(""); setPreview(null); setError("");
    onSelected(batch.id); void history.refresh(); notify("粘贴转换已提交，关闭页面后继续执行");
  }
  useEffect(() => {
    if (!pending) return;
    const found = recovery.data?.items.find(b => b.actor_id === user.id && b.request_key === pending.request_key);
    if (found && admission.recovered(found)) accepted(found);
  }, [recovery.data, pending]);
  async function inspect() {
    if (flight.current || !text.trim()) return;
    const generation = epoch.current;
    const valid = () => current() && generation === epoch.current;
    flight.current = true; setInspecting(true); setError("");
    try {
      const result = await groupRequest<PastedPreview>("/external-auth-batches/preview", "POST", { text }, valid);
      if (result && valid()) setPreview(result);
    } catch (e) { if (valid()) setError((e as Error).message); }
    finally { flight.current = false; if (current()) setInspecting(false); }
  }
  async function submit() {
    if (flight.current || !preview || !text.trim()) return;
    const batch = await admission.submit(text, preview);
    if (batch && current()) accepted(batch);
  }
  return <><section className="panel auth-composer"><h2>粘贴单个或批量账号</h2>
    <p className="info-note">支持 AWS 原始登录信息块、本系统复制的登录信息、TXT、CSV 或账号 JSON，每批最多 100 个。可一起粘贴默认 AWS access portal URL 和双栈 AWS access portal URL，两种入口会识别为同一个账号；多个账号可连续粘贴。双栈入口会自动补充登录区域和实例信息。首次登录要求改密时，会自动设置永久密码并保存到成功 JSON；失败或取消后可下载凭据恢复信息。</p>
    <label className="field"><span>账号信息</span><textarea aria-label="粘贴账号信息" rows={9} maxLength={512000} autoComplete="off" spellCheck={false} disabled={busy} value={text}
      placeholder={'https://d-xxxxxxxxxx.awsapps.com/start----us-east-1----用户名----密码'} onChange={e => { epoch.current++; setText(e.target.value); setPreview(null); setError(""); }} /></label>
    <details><summary>支持的 JSON 格式</summary><pre>{'{"start_url":"https://d-xxxxxxxxxx.awsapps.com/start","username":"用户名","password":"密码"}'}</pre>
      <p className="muted">批量使用数组。可补充 region、identity_store_id、instance_arn、profile_arn、api_region、expected_user_id。自定义登录别名须提供 identity_store_id；仅提供双栈入口时也须补充 identity_store_id。未填区域时从 AWS 登录入口读取。多个 Kiro profile 时须提供 profile_arn。</p></details>
    {pending && <div className="info-note"><p>上次请求结果尚待确认。先核对下方本人记录；刷新后需粘贴原账号、预览后继续原请求。页面不会保存明文密码或自动重复提交。</p>
      <button className="secondary" disabled={busy || recovery.loading || !!recovery.error} onClick={() => admission.clearAfterReview()}>已核对记录，开始新请求</button></div>}
    <AuthError text={error || admission.error || recovery.error} /><button className="secondary" disabled={busy || !text.trim()} onClick={() => void inspect()}>{busy ? "处理中…" : "解析并预览"}</button>
    {preview && <><p>识别到 {preview.total} 个账号</p><PastedPreviewTable preview={preview} /><button className="primary" disabled={busy} onClick={() => void submit()}>{pending ? "继续确认原请求" : `开始转换 ${preview.total} 个账号`}</button></>}
  </section>
    {selectedId && <ExternalProgress key={`${user.id}:${selectedId}`} id={selectedId} user={user} notify={notify} onChanged={() => void history.refresh()} />}
    <section className="panel"><div className="section-heading"><h2>本人粘贴转换记录</h2><button className="secondary" onClick={() => void history.refresh()}>刷新记录</button></div><AuthError text={history.error} />
      <div className="table-wrap"><table><thead><tr><th>时间</th><th>结果</th><th>操作</th></tr></thead><tbody>{history.data?.items.map(batch => <tr key={batch.id}><td>{date(batch.created_at)}</td><td>{batch.total} 人 · 成功 {batch.success_count} · 未成功 {batch.failure_count}</td><td><button className="text-button" onClick={() => onSelected(batch.id)}>查看进度</button></td></tr>)}</tbody></table></div>
      {!history.data?.items.length && <p className="muted">暂无粘贴转换记录。</p>}
      <div className="auth-pager"><button className="secondary" disabled={page === 1} onClick={() => setPage(value => value - 1)}>上一页</button><span>第 {page} 页</span><button className="secondary" disabled={(history.data?.items.length || 0) < 30} onClick={() => setPage(value => value + 1)}>下一页</button></div>
    </section></>;
}
