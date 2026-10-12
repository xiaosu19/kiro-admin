import { useEffect, useState } from "react";
import { date, groupJsonSelection, type Account, type AuthBatch, type GroupItem, type GroupJsonPreview, type User } from "./api";
import { AuthError } from "./AuthBatches";
import { GroupJsonPicker } from "./AuthSelection";
import { useRemote } from "./groupRequests";
import { useGroupJsonAdmission, useGroupJsonPreview } from "./groupJsonRequests";

export function GroupJsonScopePreview({ value }: { value: GroupJsonPreview }) {
  return <div aria-label="整组 JSON 转换范围">
    <p className="info-note">本次 {value.groups.length} 个分组，共 {value.total} 名成员；转换 {value.eligible_count} 人，跳过 {value.skipped_count} 人。仅处理以下冻结名单，之后新增成员需要另建批次。</p>
    <p className="muted">ZIP 按账号编号 / 用户名.json 整理。只包含成功结果；下载后认证结果会清除。预览有效至 {date(value.expires_at)}。</p>
    {value.groups.map(group => <details key={group.id} className="auth-skipped">
      <summary>{group.name} · {group.account_name}（{group.account_number}）· 转换 {group.eligible_count} / {group.total} 人 · 跳过 {group.skipped_count} 人</summary>
      <div className="table-wrap"><table><thead><tr><th>用户名 / 邮箱</th><th>处理范围</th></tr></thead><tbody>
        {group.members.map(member => <tr key={member.record_id}><td className="mono">{member.username}<small>{member.email}</small></td>
          <td>{member.skip_reason || "纳入本次整组转换"}</td></tr>)}
      </tbody></table></div>
      {!group.members.length && <p className="muted">该组当前没有成员。</p>}
    </details>)}
  </div>;
}

export function GroupJsonExport({ user, initialGroupIds = [], onAccepted }: {
  user: User; notify?: (message: string, error?: boolean) => void; initialGroupIds?: string[]; onAccepted: (batch: AuthBatch) => void;
}) {
  const actorScope = JSON.stringify([user.id, user.role, user.active, user.must_change_password, user.account_ids]);
  const accounts = useRemote<Account[]>("/accounts", 4000, user.id, actorScope);
  const accountScope = JSON.stringify(accounts.data?.map(a => [a.id, a.active, a.deleted_at, a.aws_account_id, a.identity_store_id,
    a.region, a.subscription_region, a.profile_arn, a.application_arn, a.control_plane, a.proxy_id, a.proxy_status, a.account_number]));
  const groups = useRemote<GroupItem[]>("/groups", 4000, user.id, `${actorScope}:${accountScope}:${accounts.forbidden}`);
  const owned = (groups.data || []).filter(group => (user.role === "admin" || group.owner_id === user.id)
    && !group.deleted_at && group.state === "ready" && !group.active_job_id && !!group.remote_id
    && accounts.data?.some(account => account.id === group.aws_account_id && account.active && !account.deleted_at));
  const [selected, setSelected] = useState<string[]>(() => [...new Set(initialGroupIds)].sort());
  const [acknowledged, setAcknowledged] = useState(false), [reviewed, setReviewed] = useState(false);
  const permissionScope = `${actorScope}:${accountScope}:${accounts.forbidden}:${groups.forbidden}:${JSON.stringify(owned.map(g => [g.id, g.owner_id, g.aws_account_id, g.revision, g.policy.revision, g.remote_id]))}`;
  const preview = useGroupJsonPreview(user.id, permissionScope, selected);
  const admission = useGroupJsonAdmission(user.id, permissionScope);
  const locked = admission.busy || !!admission.pending;
  let selectionError = "";
  if (selected.length) {
    try { groupJsonSelection(selected); } catch (e) { selectionError = (e as Error).message; }
    if (!groups.loading && selected.some(id => !owned.some(group => group.id === id))) selectionError ||= "部分已选分组已不可用，请核对并重新选择。";
  }
  useEffect(() => { setAcknowledged(false); }, [preview.data?.id, permissionScope]);
  async function submit() {
    const batch = await admission.submit(preview.data || undefined);
    if (batch) { setSelected([]); setAcknowledged(false); onAccepted(batch); }
  }
  return <section className="panel auth-composer">
    <h2>整组 / 多组 JSON 导出</h2>
    <p className="info-note">选择完整分组，再核对各组的用户名、可转换人数和跳过原因。首次登录可能需要自动设置并保存新的永久密码；验证码及 AWS 官方页面验证沿用下方逐人进度。</p>
    {admission.pending && <div className="info-note auth-recovery" aria-label="上次整组转换确认">
      <strong>上次 {admission.pending.group_ids.length} 组、{admission.pending.eligible_count} 人的转换结果尚未确认。</strong>
      <p>原范围：{admission.pending.groups.map(g => `${g.name}（${g.account_number}）`).join("、")}。继续时使用原预览和原请求；若原请求尚未受理，将提交这份原名单。</p>
      <button type="button" className="primary" disabled={admission.busy} onClick={() => void submit()}>{admission.busy ? "正在确认…" : "继续原整组请求"}</button>
      <details><summary>已核对本人历史记录</summary><p>确认已找到原批次或确认上次未受理后，可清除此提醒。</p>
        <label className="check-line"><input type="checkbox" checked={reviewed} disabled={admission.busy} onChange={e => setReviewed(e.target.checked)} />我已核实上次提交结果</label>
        <button type="button" className="secondary" disabled={!reviewed || admission.busy} onClick={() => { if (admission.clearAfterReview(reviewed)) setReviewed(false); }}>清除提醒</button>
      </details>
    </div>}
    <AuthError text={admission.error || preview.error || selectionError || accounts.error || groups.error} />
    <GroupJsonPicker groups={owned} accounts={accounts.data || []} selected={selected} disabled={locked || preview.busy || accounts.loading || groups.loading}
      onChange={ids => { setSelected(ids); setAcknowledged(false); }} />
    <button type="button" className="secondary" disabled={locked || preview.busy || !selected.length || !!selectionError || accounts.loading || groups.loading}
      onClick={() => void preview.refresh()}>{preview.busy ? "正在预览完整成员…" : `预览选中 ${selected.length} 个完整分组`}</button>
    {preview.data && <>
      <GroupJsonScopePreview value={preview.data} />
      <label className="check-line"><input type="checkbox" checked={acknowledged} disabled={locked} onChange={e => setAcknowledged(e.target.checked)} />我已核对完整范围，并同意首次登录可能更新所选用户的永久密码</label>
      <button type="button" className="primary" disabled={locked || !acknowledged || !preview.data.eligible_count} onClick={() => void submit()}>
        {admission.busy ? "正在提交…" : `转换 ${preview.data.groups.length} 组的 ${preview.data.eligible_count} 人`}
      </button>
    </>}
  </section>;
}
