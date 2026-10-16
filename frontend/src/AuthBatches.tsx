import { SearchableSelect } from "./SearchableSelect";
import { RetryStatus } from "./RetryStatus";
export { RetryStatus } from "./RetryStatus";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { NavLink } from "react-router-dom";
import { api, date, downloadAuthZip, type AuthBatch, type AuthChallenge, type AuthItem, type LoginCredential, type PasswordKind } from "./api";
import { useRemote } from "./groupRequests";
import { useAuthAdmission } from "./authRequests";
import { authKindLabel, authStageLabel, authStateLabel, batchCanDownload, credentialLabel, retryableItems, safeAuthorizationUrl } from "./authLogic";

type Notify = (message: string, error?: boolean) => void;
export function AuthError({ text }: { text?: string }) {
  return text ? <div className="error" role="alert">{text}</div> : null;
}
export function CredentialDetails({ credential }: { credential: LoginCredential }) {
  const known = credential.credential_state === "one_time" || credential.credential_state === "permanent";
  return <>
    <div className="credential">
      <div className="field"><span>AWS 登录地址</span><a href={credential.portal_url} target="_blank" rel="noreferrer">{credential.portal_url} ↗</a></div>
      <label className="field"><span>区域</span><input readOnly value={credential.region} /></label>
      <label className="field"><span>用户名</span><input readOnly value={credential.username} /></label>
      <label className="field"><span>{credentialLabel(credential.credential_state)}</span><input readOnly value={known ? credential.password : "密码结果尚待核对"} /></label>
    </div>
    <p className="muted">最新保存时间：{date(credential.generated_at)}。
      {credential.credential_state === "one_time" ? "这是一次性密码，首次登录后需要修改。" : credential.credential_state === "permanent" ? "这是已确认保存的永久密码。" : "密码结果尚待核对，暂不提供未确认的密码。"}
      用户自行修改密码后，已保存密码可能失效。
    </p>
  </>;
}
export function PasswordFields({ kind, password, disabled, onKind, onPassword }: {
  kind: PasswordKind; password: string; disabled: boolean; onKind: (kind: PasswordKind) => void; onPassword: (password: string) => void;
}) {
  return <fieldset className="auth-password-fields" disabled={disabled}>
    <legend>密码方式</legend>
    <label className="field"><span>选择方式</span><SearchableSelect aria-label="选择方式" value={kind} onChange={e => onKind(e.target.value as PasswordKind)}>
      <option value="reset_password">重置一次性密码</option>
      <option value="random_password">独立随机永久密码</option>
      <option value="custom_password">共享永久密码</option>
    </SearchableSelect></label>
    <p className="muted">{kind === "reset_password" ? "每位用户生成新的一次性密码，首次登录需要修改。" : kind === "random_password" ? "先重置一次性密码，再为每位用户分别设置不同的随机永久密码。" : "先重置一次性密码，再为所选用户设置下面的同一个永久密码。"}</p>
    {kind === "custom_password" && <label className="field"><span>共享永久密码</span>
      <input type="password" autoComplete="new-password" minLength={8} maxLength={64} required value={password} onChange={e => onPassword(e.target.value)} />
      <small>8–64 位，包含大写、小写、数字和特殊字符，不含空格；不能重复最近三次密码。</small>
    </label>}
    <p className="muted">原密码可能立即失效。成功后在 SSO 登录信息或导出文件中查看最新密码及类型。</p>
  </fieldset>;
}

export function AdmissionRecovery({ admission, onAccepted }: { admission: ReturnType<typeof useAuthAdmission>; onAccepted: (batch: AuthBatch) => void }) {
  const [reviewed, setReviewed] = useState(false);
  const pending = admission.pending;
  if (!pending) return <AuthError text={admission.error} />;
  return <section className="info-note auth-recovery" aria-label="上次提交确认">
    <strong>上次{authKindLabel[pending.kind]}，共 {pending.record_ids.length} 人，结果尚待确认。</strong>
    <p>已保留原选择。请先核对下方本人历史记录；不能仅凭时间相近就认定是上次提交。</p>
    <AuthError text={admission.error} />
    {admission.canResume ? <button className="primary" disabled={admission.busy} onClick={async () => { const batch = await admission.submit(); if (batch) onAccepted(batch); }}>
      {admission.busy ? "正在确认…" : "继续原请求"}
    </button> : <p>共享密码仅保存在提交页面的内存中，离开或刷新后无法原样继续。请在历史记录中核对用户名、方式、时间和处理结果。</p>}
    {!admission.busy && <details><summary>已核对上次结果</summary>
      <p>只有确认已找到对应批次，或确认上次未受理后，才能清除此提醒。若无法确定，请保留提醒并联系管理员核对。</p>
      <label className="check-line"><input type="checkbox" checked={reviewed} onChange={e => setReviewed(e.target.checked)} />我已核实上次结果，允许重新选择用户</label>
      <button className="secondary" disabled={!reviewed} onClick={() => { if (admission.clearAfterReview(reviewed)) setReviewed(false); }}>清除提醒</button>
    </details>}
  </section>;
}

export function AuthHistory({ actorId, scope, selectedId, onSelect, version = 0 }: {
  actorId: number; scope: "json_export" | "password"; selectedId: string | null; onSelect: (id: string) => void; version?: number;
}) {
  const [page, setPage] = useState(1);
  const history = useRemote<{ items: AuthBatch[]; page: number }>(`/auth-batches?page=${page}`, 5000);
  useEffect(() => { void history.refresh(); }, [version, history.refresh]);
  const items = history.data?.items.filter(batch => batch.actor_id === actorId && (batch.kind === "json_export") === (scope === "json_export")) || [];
  return <section className="panel auth-history">
    <div className="stop-heading"><div><h2>本人历史记录</h2><p className="muted">刷新或重新登录后，可在这里继续查看进度。</p></div><button className="secondary" onClick={() => void history.refresh()}>刷新记录</button></div>
    <AuthError text={history.error} />
    <div className="table-wrap"><table><thead><tr><th>提交时间 / 方式</th><th>结果</th><th>状态</th><th>操作</th></tr></thead><tbody>
      {items.map(batch => <tr key={batch.id} aria-selected={selectedId === batch.id}>
        <td>{date(batch.created_at)}<small>{authKindLabel[batch.kind]} · {batch.total} 人</small>
          {batch.group_scope && <small>{batch.group_scope.groups.length} 个完整分组 · 跳过 {batch.group_scope.skipped_count} 人</small>}</td>
        <td>成功 {batch.success_count} · 未成功 {batch.failure_count}<small>等待人工验证 {batch.states.challenge || 0} 人</small></td>
        <td>{batch.state === "downloaded" ? "已下载 · 结果已清除" : batch.state === "expired" ? "已过期" : batch.state === "cancelled" ? "已取消" : batch.completed_at ? "处理结束" : "正在处理"}</td>
        <td><button className="text-button" onClick={() => onSelect(batch.id)}>查看进度</button></td>
      </tr>)}
    </tbody></table></div>
    {!items.length && <p className="muted">{history.loading ? "正在读取记录…" : "本页没有此类批次。"}</p>}
    <div className="auth-pager"><button className="secondary" disabled={page === 1} onClick={() => setPage(page - 1)}>上一页</button><span>第 {page} 页</span><button className="secondary" disabled={!history.data || history.data.items.length < 30} onClick={() => setPage(page + 1)}>下一页</button></div>
  </section>;
}

type ItemAction = "retry" | "new_reset" | "cancel";
export function AuthBatchView({ batch, busy, onAction, onDownload, onChallenge }: {
  batch: AuthBatch; busy: boolean; onAction: (action: ItemAction | "cancel_batch" | "retry_batch", item?: AuthItem) => void;
  onDownload: () => void; onChallenge: (item: AuthItem) => void;
}) {
  const live = batch.state === "active";
  return <>
    <div className="auth-summary" role="status"><strong>{authKindLabel[batch.kind]} · {batch.total} 人</strong><span>成功 {batch.success_count}</span><span>未成功 {batch.failure_count}</span><span>等待人工验证 {batch.states.challenge || 0}</span></div>
    <p className="muted">提交：{date(batch.created_at)} · 处理截止：{date(batch.expires_at)}{batch.download_expires_at && <> · 下载截止：{date(batch.download_expires_at)}</>}</p>
    {batch.group_scope && <div aria-label="冻结成员范围">
      <p className="muted">冻结成员范围：{batch.group_scope.groups.length} 个分组，纳入 {batch.group_scope.eligible_count} 人，跳过 {batch.group_scope.skipped_count} 人。ZIP 按提交时的账号编号 / 分组名.json 整理，同组成功用户合并在一个文件中。</p>
      <div className="table-wrap"><table><thead><tr><th>原分组 / 账号编号</th><th>预览范围</th><th>当前进度</th></tr></thead><tbody>
        {batch.group_scope.groups.map(group => <tr key={group.id}>
          <td>{group.name}<small>{group.account_name} · {group.account_number}</small></td>
          <td>纳入 {group.eligible_count} / {group.total} 人<small>跳过 {group.skipped_count} 人</small></td>
          <td>成功 {(group.states?.completed || 0) + (group.states?.downloaded || 0)}<small>等待 {["queued", "running", "challenge", "polling"].reduce((n, state) => n + (group.states?.[state as keyof typeof group.states] || 0), 0)} · 未成功 {["failed", "needs_review", "cancelled", "expired"].reduce((n, state) => n + (group.states?.[state as keyof typeof group.states] || 0), 0)}</small></td>
        </tr>)}
      </tbody></table></div>
    </div>}
    {batch.kind === "json_export" && <>
      <p className="muted">当前密码类型显示账号已保存的凭据。仅订阅仍有效的账号可导出；若 AWS 要求首次登录修改密码，会先保存永久密码，再生成 JSON。已有永久密码会保留。</p>
      {live ? <p className="muted">成功项可立即下载；其余用户继续处理或重试。全部处理结束后开始计算下载保留时间，可稍后回来下载；{batch.group_scope || batch.group_id ? "同组用户合并为分组名.json" : "用户名.json 统一放在一个文件夹内"}，打包为 ZIP。不包含未成功的 {batch.failure_count} 人。请在下载截止前保存，每次仅清除已下载的结果。</p> : <p className="info-note">{batch.state === "downloaded" ? "此批次已经下载。" : batch.state === "expired" ? "此批次已过期。" : "此批次已取消。"}结果已清除，无法再次下载；如需文件，请重新选择用户生成。</p>}
      {batchCanDownload(batch) && <button className="primary" disabled={busy} onClick={onDownload}>下载 {batch.states.completed || 0} 人的 JSON（ZIP）</button>}
    </>}
    {batch.kind !== "json_export" && <p className="muted">每位用户单独处理。失败时也可能已生成一次性密码，请以当前密码类型和错误提示为准；已成功的密码修改不会因取消而恢复。</p>}
    {live && <div className="proxy-buttons auth-batch-actions">
      {retryableItems(batch).length > 0 && <button className="secondary" disabled={busy} onClick={() => onAction("retry_batch")}>重试可恢复的 {retryableItems(batch).length} 人</button>}
      <button className="secondary" disabled={busy} onClick={() => onAction("cancel_batch")}>取消批次</button>
    </div>}
    <div className="table-wrap"><table className="auth-progress-table"><thead><tr><th>SSO 用户</th><th>进度 / 结果</th><th>当前密码类型</th><th>操作</th></tr></thead><tbody>
      {(batch.items || []).map(item => <tr key={item.record_id}>
        <td className="mono">{item.username}</td>
        <td><span className={`badge ${item.state === "completed" ? "completed" : ["failed", "needs_review"].includes(item.state) ? "failed" : ""}`}>{item.state === "challenge" && item.can_retry_challenge ? "自动验证未通过，可重试" : authStateLabel[item.state] || "正在处理"}</span>
          {item.state === "running" && <small>{authStageLabel[item.stage] || "正在处理账号"}</small>}
          {item.next_poll_at && ["polling", "queued"].includes(item.state) && <small>下次检查：{date(item.next_poll_at)}</small>}
          <RetryStatus value={item} />
          {item.error && <small className="proxy-failed">{item.error}</small>}
          {item.cancel_requested && ["queued", "running", "challenge", "polling"].includes(item.state) && <small>已请求取消，等待当前步骤结束</small>}
        </td>
        <td>{credentialLabel(item.credential_state, item.has_password)}</td>
        <td><div className="row-actions">
          {live && !item.cancel_requested && <>
            {item.state === "challenge" && <button className="text-button" disabled={busy} onClick={() => onChallenge(item)}>人工验证</button>}
            {item.state === "challenge" && item.can_retry_challenge && <button className="text-button" disabled={busy} onClick={() => onAction("retry", item)}>重试验证</button>}
            {["failed", "needs_review"].includes(item.state) && (item.requires_new_reset
              ? <button className="text-button" disabled={busy} onClick={() => onAction("new_reset", item)}>明确再次重置</button>
              : <button className="text-button" disabled={busy} onClick={() => onAction("retry", item)}>继续处理</button>)}
            {!["downloaded", "cancelled", "expired"].includes(item.state) && <button className="text-button" disabled={busy} onClick={() => onAction("cancel", item)}>取消此人</button>}
          </>}
        </div></td>
      </tr>)}
    </tbody></table></div>
  </>;
}

export function AuthProgress({ id, actorId, scope, notify, onChanged }: {
  id: string; actorId: number; scope: "json_export" | "password"; notify: Notify; onChanged?: () => void;
}) {
  const remote = useRemote<AuthBatch>(`/auth-batches/${encodeURIComponent(id)}`, 3000, actorId, scope);
  const [busy, setBusy] = useState(false), [error, setError] = useState("");
  const locked = useRef(false);
  const mounted = useRef(true);
  const identity = `${actorId}:${scope}:${id}`, latest = useRef(identity), generation = useRef(0);
  latest.current = identity;
  const [challengeId, setChallengeId] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{ action: ItemAction | "cancel_batch"; item?: AuthItem } | null>(null);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { generation.current++; return () => { generation.current++; }; }, [identity]);
  const batch = remote.data;
  const allowed = batch?.actor_id === actorId && (batch.kind === "json_export") === (scope === "json_export");
  const changed = async () => { await remote.refresh(); if (mounted.current) onChanged?.(); };
  async function act(action: ItemAction | "cancel_batch" | "retry_batch", item?: AuthItem) {
    if (locked.current || !allowed || !batch) return;
    locked.current = true; setBusy(true); setError(""); setConfirm(null);
    try {
      if (action === "cancel_batch") await api(`/auth-batches/${id}/cancel`, "POST");
      else {
        const items = action === "retry_batch" ? retryableItems(batch) : item ? [item] : [];
        for (const target of items) await api(`/auth-batches/${id}/items/${target.record_id}/${action === "cancel" ? "cancel" : "retry"}`, "POST",
          action === "cancel" ? undefined : { mode: action === "new_reset" ? "new_reset" : "resume" });
      }
      if (mounted.current) notify("已提交，进度会自动更新");
    } catch (e) {
      if (mounted.current) setError(`${(e as Error).message}。请先刷新进度核对结果，勿重复重置。`);
    } finally {
      await changed(); locked.current = false; if (mounted.current) setBusy(false);
    }
  }
  async function download() {
    const epoch = generation.current;
    const isCurrent = () => mounted.current && latest.current === identity && generation.current === epoch;
    if (!isCurrent() || locked.current || !allowed || !batch || !batchCanDownload(batch)) return;
    locked.current = true; setBusy(true); setError("");
    try {
      const result = await downloadAuthZip(id, isCurrent);
      if (result && isCurrent()) notify(`已下载 ${result.included} 份 JSON，未包含 ${result.excluded} 人`);
    } catch (e) {
      if (isCurrent()) setError(`${(e as Error).message}。下载可能已清除结果，请刷新状态；文件丢失时需重新生成。`);
    } finally { if (isCurrent()) await changed(); locked.current = false; if (mounted.current) setBusy(false); }
  }
  const currentChallenge = allowed && batch?.state === "active" ? batch.items?.find(item => item.record_id === challengeId && item.state === "challenge" && !item.cancel_requested) : null;
  return <section className="panel auth-progress">
    <div className="stop-heading"><h2>批次进度</h2><button className="secondary" disabled={busy} onClick={() => void remote.refresh()}>刷新进度</button></div>
    <AuthError text={error || remote.error} />
    {!batch ? <p className="muted">{remote.loading ? "正在读取批次…" : "无法读取批次，请从本人历史记录重新选择。"}</p> : !allowed ? <p className="error">无法在此页面查看该批次，请从本人历史记录选择。</p> : <>
      <AuthBatchView batch={batch} busy={busy} onDownload={() => void download()} onChallenge={item => setChallengeId(item.record_id)}
        onAction={(action, item) => { if (["new_reset", "cancel", "cancel_batch"].includes(action)) setConfirm({ action: action as ItemAction | "cancel_batch", item }); else void act(action, item); }} />
      {confirm && <div className="auth-confirm" role="group" aria-label="确认操作">
        <p>{confirm.action === "new_reset" ? `将为 ${confirm.item?.username} 明确生成新的一次性密码，并继续本批次处理。旧密码或未确认的新密码可能立即失效。` : "取消会清除对应的导出结果；已成功的密码修改不会恢复。"}</p>
        <div className="proxy-buttons"><button className="danger" disabled={busy} onClick={() => void act(confirm.action, confirm.item)}>{confirm.action === "new_reset" ? "确认再次重置并继续" : "确认取消"}</button><button className="secondary" disabled={busy} onClick={() => setConfirm(null)}>返回</button></div>
      </div>}
      {currentChallenge && <HumanChallenge key={`${currentChallenge.operation_id}:${currentChallenge.revision}`} batchId={id} item={currentChallenge} kind={batch.kind} onChanged={changed} onClose={() => setChallengeId(null)} />}
      {scope === "password" && <NavLink to="/sso">前往 SSO 查看登录信息 →</NavLink>}
    </>}
  </section>;
}

export function safeFrame(challenge: AuthChallenge, parentOrigin = window.location.origin) {
  try {
    const url = new URL(challenge.frame_url || "");
    const parent = new URL(parentOrigin);
    const loopback = new Set(["localhost", "127.0.0.1", "[::1]"]);
    const localHttp = url.protocol === "http:" && parent.protocol === "http:" &&
      loopback.has(url.hostname) && loopback.has(parent.hostname) && parent.origin === parentOrigin &&
      challenge.frame_url?.startsWith(`${url.origin}/`);
    return (url.protocol === "https:" || localHttp) && url.origin === challenge.frame_origin && url.origin !== parentOrigin &&
      !url.username && !url.password && url.pathname === "/auth-widget" && !url.hash;
  } catch { return false; }
}
export function HumanChallenge({ batchId, item, kind, onChanged, onClose, family = "auth-batches" }: {
  batchId: string; item: AuthItem; kind: AuthBatch["kind"]; onChanged: () => Promise<void>; onClose: () => void;
  family?: "auth-batches" | "external-auth-batches";
}) {
  const path = `/${family}/${encodeURIComponent(batchId)}/items/${encodeURIComponent(item.record_id)}`;
  const remote = useRemote<AuthChallenge>(`${path}/challenge`);
  const [refreshing, setRefreshing] = useState(false);
  const challenge = !refreshing && !remote.error && remote.data?.operation_id === item.operation_id ? remote.data : null;
  const activeChallenge = useRef<AuthChallenge | null>(null);
  activeChallenge.current = challenge;
  const [guess, setGuess] = useState("");
  const [error, setError] = useState(""), [busy, setBusy] = useState(false), [expired, setExpired] = useState(false);
  const [image, setImage] = useState("");
  const sending = useRef(false);
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => {
    setGuess(""); setError(""); setImage(""); setExpired(false);
    if (!challenge) return;
    if (!Number.isFinite(challenge.expires_at) || Date.now() / 1000 >= challenge.expires_at) { setExpired(true); return; }
    const expires = window.setTimeout(() => setExpired(true), Math.max(0, challenge.expires_at * 1000 - Date.now()));
    let active = true;
    const controller = new AbortController();
    if (challenge.kind === "image") {
      void fetch(`/api${path}/image?revision=${challenge.revision}`, { credentials: "same-origin", cache: "no-store", signal: controller.signal })
        .then(async response => {
          if (!response.ok) throw new Error("验证码图片无法读取，请刷新验证或核对任务状态。");
          const blob = await response.blob();
          if (!active) return;
          const mime = blob.type.split(";")[0].toLowerCase();
          if (!["image/png", "image/jpeg", "image/gif", "image/webp"].includes(mime) || !blob.size || blob.size > 1024 * 1024)
            throw new Error("验证码图片无法读取，请刷新验证或核对任务状态。");
          const bytes = new Uint8Array(await blob.arrayBuffer());
          if (!active || Date.now() / 1000 >= challenge.expires_at) return;
          let binary = "";
          for (let offset = 0; offset < bytes.length; offset += 32768)
            binary += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
          // The console CSP allows data images, but intentionally excludes blob.
          if (active && Date.now() / 1000 < challenge.expires_at)
            setImage(`data:${mime};base64,${btoa(binary)}`);
        }).catch(e => { if (active && e.name !== "AbortError") setError(e.message); });
    }
    return () => { active = false; controller.abort(); window.clearTimeout(expires); };
  }, [challenge, path]);
  const official = challenge?.kind === "aws_authorization" && kind === "json_export" && challenge.username === item.username && safeAuthorizationUrl(challenge);
  async function resume(e: FormEvent) {
    e.preventDefault();
    if (!challenge || activeChallenge.current !== challenge || sending.current || !mounted.current) return;
    if (Date.now() / 1000 >= challenge.expires_at) { setExpired(true); return; }
    const answer = challenge.kind === "image" && guess.trim() ? { guess: guess.trim() } : official ? { continue_authorization: true } : null;
    if (!answer) return;
    sending.current = true; setBusy(true); setError("");
    try {
      await api(`${path}/resume`, "POST", { challenge_id: challenge.id, revision: challenge.revision, ...answer });
      if (mounted.current) setGuess("");
      await onChanged();
    } catch (e) { if (mounted.current) setError((e as Error).message); await onChanged(); }
    finally { sending.current = false; if (mounted.current) setBusy(false); }
  }
  return <section className="auth-challenge" aria-label="人工验证">
    <div className="stop-heading"><h3>{item.username} · 等待人工验证</h3><button className="text-button" disabled={busy} onClick={onClose}>收起</button></div>
    <AuthError text={error || remote.error} />
    {!challenge ? <p className="muted">{remote.loading ? "正在读取验证…" : "验证码已变化或无法读取，请刷新验证或核对任务状态。"}</p> : <>
      <p className="muted">请本人完成验证，有效期至 {new Date(challenge.expires_at * 1000).toLocaleString("zh-CN", { hour12: false })}。</p>
      {expired ? <p className="error">验证码或设备授权已过期，请刷新进度，再选择此人的“继续处理”。</p> : challenge.kind === "manual_action" || challenge.kind === "ams" ? <div className="info-note">
        <p>AWS 要求在官方页面完成人机验证。当前任务无法确认所请求的永久密码已经设置。</p>
        <p>{family === "external-auth-batches" ? "可先在 AWS 官方登录入口核对账号后重新粘贴。若需使用官方授权页面，请在账号 JSON 中补充真实 expected_user_id，系统会核对授权结果的用户身份。" : "可先取消此任务，再从 SSO 登录信息打开 AWS 官方登录页面手动处理；需要新密码时，明确选择重置一次性密码后重试。"}</p>
        <p>人机验证码与 MFA 是不同的验证步骤，关闭 MFA 不会消除人机验证码。</p>
      </div> : <form onSubmit={resume}>
        {challenge.kind === "image" ? <>
          {image ? <img className="auth-captcha-image" src={image} alt="请读取并输入图片验证码" /> : <p>正在读取验证码图片…</p>}
          <label className="field"><span>图片验证码</span><input autoComplete="off" value={guess} maxLength={128} disabled={busy} onChange={e => setGuess(e.target.value)} required /></label>
        </> : official ? <div className="info-note">
          <p>AWS 要求在官方页面完成人机验证。请使用下方用户名登录，核对授权码并完成授权，再回到这里继续。</p>
          <p>用户名：<strong className="mono">{challenge.username}</strong> · 授权码：<strong className="mono">{challenge.user_code}</strong></p>
          <a href={challenge.authorization_url} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer">打开 AWS 官方授权页面 ↗</a>
          <p>点击继续后，已保存密码会标记为待核对；导出的 JSON 不包含旧密码。如需新的登录密码，可在任务结束后明确重置一次性密码。</p>
          <p>人机验证码与 MFA 是不同的验证步骤，关闭 MFA 不会消除人机验证码。AWS 仍未完成授权时，本页会等待授权结果。</p>
        </div> : <p className="error">官方授权地址不可用，请刷新验证或核对任务状态。</p>}
        <button className="primary" disabled={busy || expired || (challenge.kind === "image" ? !image || !guess.trim() : !official)}>{busy ? "正在提交…" : official ? "已完成 AWS 授权，继续转换" : kind === "json_export" ? "继续转换" : "继续改密"}</button>
      </form>}
    </>}
    <button className="text-button" disabled={busy || refreshing} onClick={async () => {
      if (sending.current) return;
      activeChallenge.current = null; setRefreshing(true); setGuess(""); setError("");
      await remote.refresh();
      if (mounted.current) setRefreshing(false);
      await onChanged();
    }}>刷新验证</button>
  </section>;
}
