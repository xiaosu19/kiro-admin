import { useEffect, useRef, useState, type FormEvent } from "react";
import { NavLink, useSearchParams } from "react-router-dom";
import { date, downloadProvisioning, groupRequest, type Account, type GroupItem, type LoginExportFormat, type Page, type Plan, type User } from "./api";
import { SearchableSelect } from "./SearchableSelect";
import { LoginExportMenu } from "./LoginExportMenu";
import { StopPolicyFields, policySummary, stopTime } from "./StopSchedule";
import { AuthProgress, RetryStatus } from "./AuthBatches";
import { groupAccessDenied, useGroupAccess, useRemote, type GroupAccess } from "./groupRequests";
import { matchesSelection } from "./selectionSearch";
import { accountLabel, applySharedProvisioningSettings, completedLegacyRecovery, defaultProvisioningSettings, exportStates, historyQuery,
  inheritProvisioningSettings, ownedGroups, provisioningBody, provisioningIntent, provisioningPhases, provisioningStates, toggleProvisioningAccount,
  withGroup, synchronizationProgress, type AccountDraft, type ProvisioningAccount, type ProvisioningBatch, type ProvisioningSettings,
  type ProvisioningBody, type ProvisioningPreview, type Recovery } from "./provisioningLogic";
import { useProvisioningAdmission, useProvisioningPreview, useProvisioningReport } from "./provisioningRequests";

const actionLabels: Record<string, string> = { stop: '停止后续开通', retry: '继续本账号批次', retry_failed: '重试失败项', recheck: '核对本账号进度', retry_export: '重新受理 JSON 转换', resume: '恢复未完成项' };
const recoveryLabels: Record<string, string> = { group_retry: '恢复分组任务', native_recheck: '核对 GROUP 开通', sso_retry: '恢复此用户', reset_password: '重新生成一次性密码' };
type Download = { path: string; method: 'GET' | 'POST'; body?: unknown };
function ErrorBox({ text }: { text?: string }) { return text ? <p className="error" role="alert">{text}</p> : null; }
function State({ state }: { state: string }) { return <span className={`badge ${state === 'completed' ? 'completed' : ['failed', 'paused', 'needs_review'].includes(state) ? 'failed' : ''}`}><i />{provisioningStates[state] || state}</span>; }

export function ProvisioningAccountPicker({ accounts, selected, search, onSearch, onToggle, disabled }: {
  accounts: Account[]; selected: number[]; search: string; onSearch: (v: string) => void; onToggle: (a: Account) => void; disabled: boolean;
}) {
  const visible = accounts.filter(a => matchesSelection(search, accountLabel(a), a.id));
  return <fieldset className="provisioning-picker" disabled={disabled} aria-label="选择 AWS 账号">
    <legend>选择 AWS 账号</legend>
    <label className="field"><span>搜索 AWS 账号</span><input type="search" aria-label="搜索 AWS 账号" placeholder="编号、名称或 AWS ID" value={search} onChange={e => onSearch(e.target.value)} /></label>
    <p className="muted">已选 {selected.length} / 100 个账号。新选账号自动使用公共设置，也可为个别账号单独配置。</p>
    <div className="provisioning-account-options">{visible.map(a => {
      const checked = selected.includes(a.id), unavailable = !a.active || !!a.deleted_at || !a.account_number || a.proxy_status !== 'enabled';
      return <label className="check-line" key={a.id}><input type="checkbox" aria-label={accountLabel(a)} checked={checked} disabled={!checked && (unavailable || selected.length >= 100)} onChange={() => onToggle(a)} />
        <span>{accountLabel(a)}<small>{!a.account_number ? '请管理员先设置 AWS 编号' : a.proxy_status !== 'enabled' ? '请管理员绑定可用代理' : `代理：${a.proxy_name || '已绑定'} · ${a.active ? '可使用' : '已停用'}`}</small></span></label>;
    })}</div>
    {!visible.length && <p className="muted">没有匹配的 AWS 账号。</p>}
  </fieldset>;
}

export function ProvisioningGroupSelect({ account, row, groups, actorId, disabled, onChange }: {
  account: Account; row: AccountDraft; groups: GroupItem[]; actorId: number; disabled: boolean; onChange: (row: AccountDraft) => void;
}) {
  const number = account.account_number || String(account.id), choices = ownedGroups(groups, actorId, account.id);
  const group = choices.find(g => g.id === row.groupId);
  return <SearchableSelect aria-label={`${number} 分组`} value={row.groupId} disabled={disabled} onChange={e => onChange(withGroup(row, choices.find(g => g.id === e.target.value) || null))}>
    <option value="">创建本批次的新分组（编号自动生成）</option>{row.groupId && !group && <option value={row.groupId} disabled>原分组已不可用，请重新选择</option>}{choices.map(g => <option key={g.id} value={g.id} disabled={g.state !== 'ready' || !g.remote_id || !!g.active_job_id}>{g.name} · {g.native_subscription?.plan_name || '尚未开通'}{g.native_subscription ? `（${({ active: '订阅生效', pending: '开通中', cancel_scheduled: '已取消续订', cancelled: '已取消', needs_review: '待核对', failed: '开通失败' } as Record<string, string>)[g.native_subscription.state] || g.native_subscription.state}）` : ''} · {g.state === 'ready' ? '可用' : provisioningStates[g.state] || g.state}</option>)}
  </SearchableSelect>;
}

function ProvisioningExportFields({ value, labelPrefix, onChange }: {
  value: ProvisioningSettings['exports']; labelPrefix: string; onChange: (value: ProvisioningSettings['exports']) => void;
}) {
  return <div className="provisioning-export-flags">{(['csv', 'txt', 'json'] as const).map(format => <label className="check-line" key={format}><input type="checkbox" aria-label={`${labelPrefix}${format === 'json' ? '转换 JSON' : `导出 ${format.toUpperCase()}`}`} checked={value[format]} onChange={e => onChange({ ...value, [format]: e.target.checked })} />{format === 'json' ? '转换 JSON（可选）' : `登录 ${format.toUpperCase()}`}</label>)}</div>;
}

export function ProvisioningSharedFields({ value, plans, selectedCount, customCount, disabled, onChange }: {
  value: ProvisioningSettings; plans: Plan[]; selectedCount: number; customCount: number; disabled: boolean; onChange: (value: ProvisioningSettings) => void;
}) {
  return <fieldset className="panel provisioning-shared-fields" aria-label="公共设置" disabled={disabled}>
    <legend>公共设置</legend>
    <p className="muted">已选 {selectedCount} 个 AWS 账号，{selectedCount - customCount} 个使用公共设置{customCount > 0 ? `，${customCount} 个已单独配置` : ''}。修改后会同步到使用公共设置的账号。</p>
    <div className="provisioning-shared-grid">
      <label className="field"><span>每个账号新增人数</span><input aria-label="公共 新增人数" type="number" min={1} max={100} step={1} required value={value.quantity} onChange={e => onChange({ ...value, quantity: Number(e.target.value) })} /></label>
      <label className="field"><span>套餐</span><SearchableSelect aria-label="公共 套餐" required value={value.plan_id || ''} onChange={e => onChange({ ...value, plan_id: Number(e.target.value) })}><option value="">请选择套餐</option>{plans.filter(p => p.active && !p.deleted_at).map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</SearchableSelect></label>
      <div className="provisioning-shared-policy"><StopPolicyFields value={value.policy} onChange={policy => onChange({ ...value, policy })} namePrefix="shared:" labelPrefix="公共 " nativeGroup /></div>
    </div>
    <p className="muted">停止规则用于新建分组；选择已有分组时默认继承该分组的规则。套餐与已有分组是否兼容会在预览时核对。</p>
    <ProvisioningExportFields value={value.exports} labelPrefix="公共 " onChange={exports => onChange({ ...value, exports })} />
    <p className="muted">下载需手动点击。JSON 在确认开通后转换，可能需要官方 AWS 授权；转换失败不会重复开通。</p>
  </fieldset>;
}

export function useProvisioningConfiguration(initialPlanId = 0) {
  const [shared, setShared] = useState(() => defaultProvisioningSettings(initialPlanId));
  const [drafts, setDrafts] = useState<AccountDraft[]>([]);
  function changeShared(value: ProvisioningSettings) {
    setShared({ ...value, policy: { ...value.policy }, exports: { ...value.exports } });
    setDrafts(old => applySharedProvisioningSettings(old, value));
  }
  const changeDraft = (value: AccountDraft) => setDrafts(old => old.map(row => row.aws_account_id === value.aws_account_id ? value : row));
  const toggle = (account: Account) => setDrafts(old => toggleProvisioningAccount(old, account, shared));
  const remove = (accountId: number) => setDrafts(old => old.filter(row => row.aws_account_id !== accountId));
  return { shared, drafts, setDrafts, changeShared, changeDraft, toggle, remove };
}

export function ProvisioningConfigurations({ shared, rows, accounts, groups, plans, actorId, disabled, onSharedChange, onChange, onRemove }: {
  shared: ProvisioningSettings; rows: AccountDraft[]; accounts: Account[]; groups: GroupItem[]; plans: Plan[]; actorId: number; disabled: boolean;
  onSharedChange: (value: ProvisioningSettings) => void; onChange: (row: AccountDraft) => void; onRemove: (accountId: number) => void;
}) {
  const [expanded, setExpanded] = useState<number[]>([]);
  const update = (row: AccountDraft) => { if (!disabled) onChange(row); };
  return <div className="provisioning-shared-configuration">
    <ProvisioningSharedFields value={shared} plans={plans} selectedCount={rows.length} customCount={rows.filter(row => row.settingsMode === 'custom').length} disabled={disabled} onChange={value => { if (!disabled) onSharedChange(value); }} />
    {!!rows.length && <section className="panel provisioning-selected-accounts" aria-label="已选账号配置">
      <div className="section-heading"><h2>账号配置</h2><p className="muted">共新增 {rows.reduce((total, row) => total + row.quantity, 0)} 人</p></div>
      <div className="table-wrap"><table><thead><tr><th>AWS 账号</th><th>分组</th><th>本次配置</th><th>操作</th></tr></thead><tbody>{rows.map(row => {
        const account = accounts.find(a => a.id === row.aws_account_id); if (!account) return null;
        const number = account.account_number || String(account.id), custom = row.settingsMode === 'custom', open = custom && expanded.includes(account.id);
        const group = ownedGroups(groups, actorId, account.id).find(g => g.id === row.groupId);
        const formats = [row.exports.csv ? 'CSV' : '', row.exports.txt ? 'TXT' : '', row.exports.json ? 'JSON' : ''].filter(Boolean).join('、');
        return [<tr key={account.id} data-testid={`provisioning-summary-${account.id}`}>
          <td><strong>AWS {number} · {account.name}</strong><small className="mono">{account.aws_account_id}</small><small>{custom ? '单独配置' : '公共设置'}</small></td>
          <td><ProvisioningGroupSelect account={account} row={row} groups={groups} actorId={actorId} disabled={disabled} onChange={value => update(value.settingsMode === 'custom' ? value : inheritProvisioningSettings(value, shared))} /></td>
          <td><strong>{row.quantity} 人 · {plans.find(plan => plan.id === row.plan_id)?.name || '请选择套餐'}</strong><small>{row.groupId && row.policyMode === 'inherit' ? `继承分组：${group ? policySummary(group.policy) : '请重新选择分组'}` : policySummary(row.policy)}</small><small>{formats ? `导出：${formats}` : '未选择导出'}</small></td>
          <td><div className="row-actions provisioning-summary-actions">
            <button type="button" className="text-button" data-testid={`provisioning-customize-${account.id}`} disabled={disabled} onClick={() => {
              if (disabled) return;
              if (open) setExpanded(old => old.filter(id => id !== account.id));
              else { if (!custom) update({ ...row, settingsMode: 'custom' }); setExpanded(old => [...old.filter(id => id !== account.id), account.id]); }
            }}>{open ? '收起配置' : custom ? '编辑单独配置' : '单独配置'}</button>
            {custom && <button type="button" className="text-button" data-testid={`provisioning-restore-${account.id}`} disabled={disabled} onClick={() => {
              if (disabled) return; update(inheritProvisioningSettings(group ? withGroup(row, group) : row, shared)); setExpanded(old => old.filter(id => id !== account.id));
            }}>恢复公共设置</button>}
            <button type="button" className="text-button" aria-label={`移除 ${number}`} data-testid={`provisioning-remove-${account.id}`} disabled={disabled} onClick={() => { if (!disabled) onRemove(account.id); }}>移除</button>
          </div></td>
        </tr>, open && <tr key={`${account.id}-settings`} className="provisioning-custom-settings"><td colSpan={4}>
          <ProvisioningAccountFields account={account} row={row} groups={groups} plans={plans} actorId={actorId} disabled={disabled} showGroup={false} onChange={update} onRemove={() => { if (!disabled) onRemove(account.id); }} />
        </td></tr>];
      })}</tbody></table></div>
    </section>}
  </div>;
}

export function ProvisioningAccountFields({ account, row, groups, plans, actorId, disabled, onChange, onRemove, showGroup = true }: {
  account: Account; row: AccountDraft; groups: GroupItem[]; plans: Plan[]; actorId: number; disabled: boolean;
  onChange: (row: AccountDraft) => void; onRemove: () => void; showGroup?: boolean;
}) {
  const number = account.account_number || String(account.id), choices = ownedGroups(groups, actorId, account.id);
  const group = choices.find(g => g.id === row.groupId);
  return <fieldset className="panel provisioning-account-fields" disabled={disabled}>
    <legend>AWS {number} · {account.name}</legend>
    <div className="section-heading"><p className="mono muted">{account.aws_account_id} · 代理：{account.proxy_name || '已绑定'}</p><button type="button" className="text-button" aria-label={`移除 ${number}`} onClick={onRemove}>移除此账号</button></div>
    <div className="provisioning-fields-grid">
      <label className="field"><span>新增人数</span><input aria-label={`${number} 新增人数`} type="number" min={1} max={100} step={1} required value={row.quantity} onChange={e => onChange({ ...row, quantity: Number(e.target.value) })} /></label>
      <label className="field"><span>套餐</span><SearchableSelect aria-label={`${number} 套餐`} required value={row.plan_id || ''} onChange={e => onChange({ ...row, plan_id: Number(e.target.value) })}><option value="">请选择套餐</option>{plans.filter(p => p.active && !p.deleted_at).map(p => <option key={p.id} value={p.id}>{p.name}</option>)}</SearchableSelect></label>
      {showGroup && <label className="field provisioning-wide"><span>分组</span><ProvisioningGroupSelect account={account} row={row} groups={groups} actorId={actorId} disabled={disabled} onChange={onChange} /></label>}
    </div>
    {group ? <><p className="info-note">当前分组规则：{policySummary(group.policy)}。分组只显示当前用户拥有的实际 AWS 分组，套餐兼容性将在预览时核对。</p>
      <label className="field"><span>停止规则</span><SearchableSelect aria-label={`${number} 停止规则`} value={row.policyMode} onChange={e => onChange({ ...row, policyMode: e.target.value as AccountDraft['policyMode'], overwrite_individual: false })}>
        <option value="inherit">继承当前分组规则（默认）</option><option value="change">修改此分组的共同规则</option></SearchableSelect></label></>
      : <p className="muted">批次编号在受理时确定。真实 AWS 用户名与内部 ID 相同，例如 {number}-01-01。</p>}
    {(!group || row.policyMode === 'change') && <StopPolicyFields value={row.policy} onChange={policy => onChange({ ...row, policy })} namePrefix={`account-${account.id}:`} labelPrefix={`${number} `} nativeGroup subscribedAt={group?.native_subscription?.activated_at} />}
    {group && row.policyMode === 'change' && <label className="check-line"><input type="checkbox" aria-label={`${number} 覆盖个人规则`} checked={row.overwrite_individual} onChange={e => onChange({ ...row, overwrite_individual: e.target.checked })} />覆盖已有成员的个人规则（默认保留）</label>}
    <ProvisioningExportFields value={row.exports} labelPrefix={`${number} `} onChange={exports => onChange({ ...row, exports })} />
    <p className="muted">下载需手动点击。JSON 在确认开通后转换，可能需要官方 AWS 授权；转换失败不会重复开通。</p>
  </fieldset>;
}

function Preview({ preview }: { preview: ProvisioningPreview }) {
  return <section className="panel provisioning-preview" aria-label="批次预览"><h2>批次预览</h2><p className="info-note">以下编号为预估，预览不会占用编号或开通次数。受理后固定内部 ID，并用它作为真实 AWS 用户名。</p>
    <div className="table-wrap"><table><thead><tr><th>AWS 账号 / 预估编号</th><th>分组 / 套餐</th><th>新增 / 原有成员</th><th>预计次数</th><th>停止规则与影响</th></tr></thead><tbody>{preview.accounts.map(a => <tr key={a.aws_account_id}>
      <td>{a.account_name}<small className="mono">{a.next_batch_number}</small></td><td>{a.group.name}<small>{a.plan_name}</small></td><td>{a.quantity} / {a.existing_member_count}</td><td>{a.needed_count}</td>
      <td>{policySummary(a.stop_policy)}<small>{a.policy_change ? `改变 ${a.policy_change.affected_count} 名已有成员；保留 ${a.policy_change.skipped_count} 名成员的个人或历史规则` : '沿用规则'} </small></td>
    </tr>)}</tbody></table></div>
    <div className="provisioning-totals">{preview.totals.map(p => <p key={p.plan_id}><strong>{p.plan_name}</strong>：本批共需 {p.needed_count} 次 · 可用 {p.available_count ?? '不限'} 次 · 参考月费 ${p.reference_monthly_usd}</p>)}</div>
  </section>;
}

export function ProvisioningDownloads({ actorId, batch, account, disabled, onDownload }: {
  actorId: number; batch: Pick<ProvisioningBatch, 'id' | 'actor_id' | 'json_download'>; account?: ProvisioningAccount;
  disabled: boolean; onDownload: (download: Download) => void;
}) {
  const scope = account ? { provisioning_account_batch_id: account.id } : { provisioning_batch_id: batch.id };
  const meta = account?.json_download || batch.json_download;
  const credentials = account ? !!account.items?.some(i => i.credentials_ready) : true;
  const formats = (["csv", "txt"] as LoginExportFormat[]).filter(format => !account || account.exports[format]);
  return <div className="provisioning-downloads"><div className="row-actions">
    {!!formats.length && <LoginExportMenu disabled={disabled || !credentials} scopes={[{ formats,
      onExport: format => onDownload({ path: '/sso-users/export', method: 'POST', body: { ...scope, format } }),
    }]} />}
    <button type="button" className="secondary" disabled={disabled} onClick={() => onDownload({ path: `/provisioning-batches/report?${account ? `account_batch_id=${encodeURIComponent(account.id)}` : `batch_id=${encodeURIComponent(batch.id)}`}`, method: 'GET' })}>下载批次报告</button>
    {actorId === batch.actor_id && (account ? account.exports.json : meta?.requested) && <button type="button" className="secondary" disabled={disabled || !meta?.ready} onClick={() => onDownload({ path: `/provisioning-batches/${encodeURIComponent(batch.id)}${account ? `/accounts/${encodeURIComponent(account.id)}` : ''}/download`, method: 'POST' })}>下载 JSON ZIP</button>}
  </div>{meta?.requested && actorId === batch.actor_id && <p className="muted">JSON：可下载 {meta.available_count} 项；等待 {meta.waiting_count} 项；排除 {meta.excluded_count} 项。{meta.consumed_count > 0 ? '部分结果已下载并清理，完整 ZIP 不可再生成；可分别下载剩余账号批次。' : '全部任务结束后开始计算下载保留时间，可离开页面稍后回来下载；下载后认证结果会清理。'}{meta.download_expires_at && <> 下载截止：{date(meta.download_expires_at)}。</>}</p>}</div>;
}

function RecoveryButton({ recovery, disabled, run }: { recovery: Recovery; disabled: boolean; run: (path: string, body?: unknown) => void }) {
  const [confirmation, setConfirmation] = useState('');
  const username = String(recovery.body?.confirm_username || '');
  return <div className="provisioning-recovery">{recovery.kind === 'reset_password' && <label className="field"><span>确认真实用户名后重新生成密码</span><input aria-label={`确认用户名 ${username}`} value={confirmation} placeholder={username} onChange={e => setConfirmation(e.target.value)} disabled={disabled} /></label>}
    <button type="button" className="text-button" disabled={disabled || recovery.kind === 'reset_password' && confirmation !== username} onClick={() => run(recovery.path.replace(/^\/api/, ''), recovery.requires_request_key ? { ...recovery.body, request_key: crypto.randomUUID() } : recovery.body)}>{recoveryLabels[recovery.kind] || '打开恢复操作'}{recovery.read_only ? '（只读核对）' : ''}</button>
  </div>;
}

export function AccountProgress({ row, batch, user, disabled, run, download, onAuth }: {
  row: ProvisioningAccount; batch: ProvisioningBatch; user: User; disabled: boolean;
  run: (path: string, body?: unknown) => void; download: (request: Download) => void; onAuth: (id: string) => void;
}) {
  const [confirmResume, setConfirmResume] = useState(false);
  const completed = row.items?.filter(i => i.state === 'completed').length || 0;
  const sync = synchronizationProgress(row);
  return <section className="panel provisioning-account-progress" aria-label={`批次 ${row.batch_number}`}>
    <div className="section-heading"><div><h3 className="mono">{row.batch_number} · {row.account_name}</h3><p>{row.plan_name} · {sync ? '等待同步' : provisioningPhases[row.phase] || row.phase}</p></div><State state={sync ? '等待同步' : row.state} /></div>
    {sync ? <div className="provisioning-sync-progress" role="status">
      <p><strong>等待同步</strong><span>已同步 {sync.confirmed} / {sync.total} 人</span></p>
      <progress aria-label={`${row.batch_number} 同步进度`} value={sync.confirmed} max={sync.total} />
      <small>同步完成后自动继续</small>
    </div> : <><p>已确认开通 {completed} / {row.quantity} 人 · JSON：{exportStates[row.export_state] || row.export_state}</p><progress aria-label={`${row.batch_number} 开通进度`} value={completed} max={row.quantity} /></>}
    <p>{row.group.id ? <NavLink to={`/groups?group_id=${encodeURIComponent(row.group.id)}`}>分组：{row.group.name} · 查看或修改停止规则 →</NavLink> : `分组：${row.group.name}（等待创建）`}</p>
    <p className="muted">当前规则：{policySummary(row.effective_policy || row.stop_policy)} · 开通：{row.activated_at ? date(row.activated_at) : '等待确认'} · 共同截止：{row.effective_stop_at ? stopTime(row.effective_stop_at) : '未设置或等待开通'}</p>
    <ErrorBox text={sync || row.propagation_state ? '' : row.error || ''} />
    {!sync && <RetryStatus value={row} />}
    <div className="row-actions">{row.allowed_actions.map(action => <button key={action} type="button" className={action === 'stop' ? 'danger' : 'secondary'} disabled={disabled} onClick={() => action === 'resume' ? setConfirmResume(true) : run(`/provisioning-batches/${batch.id}/accounts/${row.id}/${action}`, { request_key: crypto.randomUUID() })}>{actionLabels[action] || action}</button>)}</div>
    {confirmResume && row.allowed_actions.includes('resume') && <div className="info-note" role="group" aria-label="确认恢复未完成项">
      <p>恢复本批次尚未完成的任务？已完成 {completed} 人会保留。剩余开通将使用当前套餐次数{row.exports.json ? '，完成后继续转换 JSON' : ''}。</p>
      <div className="row-actions"><button type="button" className="secondary" disabled={disabled} onClick={() => setConfirmResume(false)}>取消</button>
        <button type="button" className="primary" disabled={disabled} onClick={() => { setConfirmResume(false); run(`/provisioning-batches/${batch.id}/accounts/${row.id}/resume`, { request_key: crypto.randomUUID() }); }}>确认恢复</button></div>
    </div>}
    {row.allowed_actions.includes('stop') && <p className="muted">停止只阻止后续尚未发出的操作。已经开通的付费资源不会自动取消；需要停止订阅时请在分组页面处理。</p>}
    {row.recovery && !row.items?.some(i => i.recovery?.path === row.recovery?.path) && <RecoveryButton recovery={row.recovery} disabled={disabled} run={run} />}
    <ProvisioningDownloads actorId={user.id} batch={batch} account={row} disabled={disabled} onDownload={download} />
    <div className="table-wrap"><table><thead><tr><th>内部 ID / 真实用户名</th><th>开通状态</th><th>开通时间</th><th>JSON 转换</th><th>恢复</th></tr></thead><tbody>{row.items?.map(item => <tr key={item.record_id}>
      <td><strong className="mono">{item.internal_id}</strong><small className="mono">{item.username}</small></td><td><State state={item.propagation_state === "waiting" ? "等待同步" : item.state} /><small>{item.propagation_state === 'waiting' ? '等待同步' : provisioningPhases[item.phase] || item.phase}</small>{item.propagation_state !== 'waiting' && <RetryStatus value={item} />}{item.error && !item.propagation_state && <small className="error-text">{item.error}</small>}</td><td>{item.subscribed_at ? date(item.subscribed_at) : '等待确认'}</td>
      <td>{exportStates[item.export_state] || item.export_state}{item.export_retry && <RetryStatus value={item.export_retry} />}{item.export_error && <small className="error-text">{item.export_error}</small>}{item.auth_batch_id && <button type="button" className="text-button" onClick={() => onAuth(item.auth_batch_id!)} disabled={disabled}>授权与转换进度</button>}</td>
      <td>{item.recovery && <RecoveryButton recovery={item.recovery} disabled={disabled} run={run} />}</td>
    </tr>)}</tbody></table></div>
  </section>;
}

export function ProvisioningBatchDetail({ id, user, scope, notify, access }: { id: string; user: User; scope: string; notify: (message: string, error?: boolean) => void; access: GroupAccess }) {
  const remote = useRemote<ProvisioningBatch>(access.canAccess(id) ? `/provisioning-batches/${encodeURIComponent(id)}` : null, 2500, user.id, scope, () => access.deny(id));
  const [error, setError] = useState(''), [busy, setBusy] = useState(false), [authId, setAuthId] = useState('');
  const storageKey = `kiro-provisioning-action:${user.id}:${id}`;
  const [pending, setPending] = useState<{ path: string; body?: unknown } | null>(() => { try { return JSON.parse(sessionStorage.getItem(storageKey) || 'null'); } catch { return null; } });
  const saved = useRef(pending), flight = useRef(false), active = useRef(true);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  const current = () => active.current && access.canAccess(id);
  const batch = current() && !remote.forbidden ? remote.data : null;
  const waitingSync = !!batch?.accounts.some(row => synchronizationProgress(row));
  const syncOnly = waitingSync && batch!.accounts.every(row => row.state === 'completed' || synchronizationProgress(row));
  const batchError = batch?.accounts.find(row => row.error && !synchronizationProgress(row))?.error
    || (waitingSync ? '' : batch?.error);
  async function run(path: string, body?: unknown) {
    if (!current() || flight.current) return;
    const request = saved.current || { path, body }, wasPending = !!saved.current;
    saved.current = request; setPending(request); flight.current = true; setBusy(true); setError('');
    try {
      sessionStorage.setItem(storageKey, JSON.stringify(request));
      const result = await groupRequest(request.path, 'POST', request.body, current);
      if (result === null || !current()) return;
      sessionStorage.removeItem(storageKey); saved.current = null; setPending(null); void remote.refresh();
      notify('操作已受理，正在读取最新进度');
    } catch (e) {
      if (current()) {
        if (groupAccessDenied(e)) access.deny(id);
        else setError((e as Error).message);
        if (!wasPending && e instanceof Error && 'status' in e && Number(e.status) < 500 && ![408, 429].includes(Number(e.status))) { sessionStorage.removeItem(storageKey); saved.current = null; setPending(null); }
        // Legacy retries have no replay key: an accepted retry can later return
        // 409. Only a fresh read proving that exact step completed resolves it.
        if (wasPending && e instanceof Error && 'status' in e && Number(e.status) === 409 && /^\/(groups|subscriptions)\/[^/]+\/retry$/.test(request.path)) {
          try {
            const latest = await groupRequest<ProvisioningBatch>(`/provisioning-batches/${encodeURIComponent(id)}`, 'GET', undefined, current);
            if (latest && current() && latest.id === id && latest.actor_id === batch?.actor_id && completedLegacyRecovery(latest, request.path)) {
              sessionStorage.removeItem(storageKey); saved.current = null; setPending(null); setError('');
              notify('已从最新进度确认恢复步骤完成，待确认提醒已清除'); void remote.refresh();
            }
          } catch (refreshError) {
            if (current()) {
              if (groupAccessDenied(refreshError)) access.deny(id);
              else setError('最新进度暂时无法确认，原请求仍保留。请稍后继续确认。');
            }
          }
        }
      }
    } finally { if (current()) { flight.current = false; setBusy(false); } }
  }
  async function download(request: Download) {
    if (!current() || flight.current) return;
    flight.current = true; setBusy(true); setError('');
    try {
      const result = await downloadProvisioning(request.path, request.method, request.body, current);
      if (result && current()) { notify(`已发起下载：${result.count} 项${result.excluded ? `；排除 ${result.excluded} 项` : ''}`); void remote.refresh(); }
    } catch (e) { if (current()) { if (groupAccessDenied(e)) access.deny(id); else setError((e as Error).message); } }
    finally { if (current()) { flight.current = false; setBusy(false); } }
  }
  if (!access.canAccess(id) || remote.forbidden) return <ErrorBox text="当前批次不可访问，请刷新账号权限。" />;
  return <section className="provisioning-detail" aria-label="批次详情"><ErrorBox text={remote.error || error} />{remote.loading && <p>正在读取批次进度…</p>}
    {batch && <><div className="panel"><div className="section-heading"><div><h2>批次进度</h2><p>{date(batch.created_at)} · {batch.accounts.length} 个 AWS 账号</p></div><State state={syncOnly ? '等待同步' : batch.state} /></div>
      <p className="muted">任务已保存，关闭页面后继续在后台执行。可继续提交另一批次。</p><ErrorBox text={batchError || ''} />
      <ProvisioningDownloads actorId={user.id} batch={batch} disabled={busy || !!pending} onDownload={download} />
      {pending && <div className="info-note">上次操作结果尚未确认，请用原请求确认。<button type="button" className="secondary" disabled={busy} onClick={() => run(pending.path, pending.body)}>继续确认原操作</button></div>}
    </div>{batch.accounts.map(row => <AccountProgress key={row.id} row={row} batch={batch} user={user} disabled={busy || !!pending} run={run} download={download} onAuth={setAuthId} />)}
      {authId && batch.actor_id === user.id && batch.accounts.some(a => a.items?.some(i => i.auth_batch_id === authId)) && <AuthProgress key={authId} id={authId} actorId={user.id} scope="json_export" notify={notify} onChanged={() => { void remote.refresh(); }} />}
    </>}
  </section>;
}

export function Provisioning({ user, notify }: { user: User; notify: (message: string, error?: boolean) => void }) {
  const [params, setParams] = useSearchParams(), detailId = params.get('batch_id');
  const actorScope = JSON.stringify([user.id, user.role, user.active, user.must_change_password, user.account_ids]);
  const accounts = useRemote<Account[]>('/accounts', 4000, user.id, actorScope);
  const plans = useRemote<Plan[]>('/plans', 0, user.id, actorScope);
  const accountScope = JSON.stringify(accounts.data?.map(a => [a.id, a.account_number, a.active, a.deleted_at, a.aws_account_id, a.region, a.subscription_region, a.control_plane, a.identity_store_id, a.application_arn, a.profile_arn, a.proxy_id, a.proxy_status, a.proxy_name]));
  const scope = `${actorScope}:${accountScope}:${accounts.forbidden}`;
  const groups = useRemote<GroupItem[]>('/groups', 4000, user.id, scope);
  const access = useGroupAccess(user.id, scope);
  const { drafts, setDrafts, shared, changeShared, changeDraft, toggle, remove } = useProvisioningConfiguration();
  const [search, setSearch] = useState(''), initializedPlan = useRef(false);
  const [filterAccount, setFilterAccount] = useState(''), [query, setQuery] = useState(''), [state, setState] = useState(''), [from, setFrom] = useState(''), [to, setTo] = useState(''), [page, setPage] = useState(1);
  const [validation, setValidation] = useState('');
  const admission = useProvisioningAdmission(user.id, scope);
  useEffect(() => {
    if (initializedPlan.current || !plans.data || admission.pending) return;
    initializedPlan.current = true;
    const firstPlan = plans.data.find(plan => plan.active && !plan.deleted_at);
    if (!shared.plan_id && firstPlan) changeShared({ ...shared, plan_id: firstPlan.id });
  }, [plans.data, admission.pending]);
  // Rule edits and group revision changes invalidate previews and reset the
  // selected group's defaults; no stale inherited policy becomes an override.
  useEffect(() => {
    if (!groups.data || admission.pending) return;
    setDrafts(old => old.map(row => {
      if (!row.groupId) return row;
      const group = ownedGroups(groups.data!, user.id, row.aws_account_id).find(g => g.id === row.groupId);
      return group && (row.groupRevision !== group.revision || row.policyRevision !== group.policy.revision) ? withGroup(row, group) : row;
    }));
  }, [groups.data, user.id, admission.pending]);
  useEffect(() => { if (accounts.data && !admission.pending) setDrafts(old => old.filter(r => accounts.data!.some(a => a.id === r.aws_account_id && a.active && a.account_number))); }, [accounts.data, admission.pending]);
  let body: ProvisioningBody | null = null, formError = '';
  try { body = provisioningBody(drafts, accounts.data || [], groups.data || [], user.id); } catch (e) { formError = (e as Error).message; }
  const preview = useProvisioningPreview(user.id, scope, body);
  const filters = { aws_account_id: filterAccount, q: query, state, created_from: from ? new Date(`${from}T00:00:00+08:00`).toISOString() : '', created_to: to ? new Date(`${to}T23:59:59+08:00`).toISOString() : '' };
  const filterQuery = historyQuery(filters);
  const history = useRemote<Page<ProvisioningBatch>>(`/provisioning-batches?${filterQuery}&page=${page}`, 3000, user.id, scope);
  const accepted = (batch: ProvisioningBatch) => { setParams({ batch_id: batch.id }); setDrafts([]); setValidation(''); void history.refresh(); notify('批次已受理，可继续提交另一批次'); };
  useEffect(() => {
    if (!admission.pending) return;
    const found = history.data?.items.find(b => b.request_key === admission.pending?.request_key && b.actor_id === user.id);
    if (found && admission.confirm(found)) { setParams({ batch_id: found.id }); setDrafts([]); }
  }, [history.data, admission.pending, user.id]);
  const blocked = !!admission.pending || admission.busy || preview.busy || accounts.loading || plans.loading || !!accounts.error || !!plans.error || !!groups.error || !groups.data;
  async function previewForm(event: FormEvent) { event.preventDefault(); if (blocked) return; setValidation(formError); if (body) await preview.submit(); }
  async function submit() {
    if (!admission.pending && (!body || !preview.data)) return;
    const result = await admission.submit(admission.pending || provisioningIntent(body!, preview.data!.preview_fingerprint));
    if (result) accepted(result);
  }
  const reportDownload = useProvisioningReport(user.id, `${scope}:${filterQuery}`);
  async function report() {
    const result = await reportDownload.download(`/provisioning-batches/report?${filterQuery}`);
    if (result) notify(`已发起 ${result.count} 项批次报告下载`);
  }
  return <><div className="page-heading"><div><h1>批次开通</h1><p>选择多个 AWS 账号，统一设置并开通。真实 AWS 用户名与固定的内部 ID 相同。</p></div></div>
    <ErrorBox text={accounts.error || plans.error || groups.error} />
    {detailId && <p><button type="button" className="secondary" onClick={() => { setParams({}); document.getElementById('provisioning-form')?.scrollIntoView({ block: 'start' }); }}>新建另一批次</button></p>}
    <form id="provisioning-form" onSubmit={previewForm} noValidate>
      <div className="panel"><ProvisioningAccountPicker accounts={accounts.data || []} selected={drafts.map(d => d.aws_account_id)} search={search} onSearch={setSearch} disabled={blocked} onToggle={account => {
        if (blocked) return; setValidation(''); toggle(account);
      }} /></div>
      <ProvisioningConfigurations shared={shared} rows={drafts} accounts={accounts.data || []} groups={groups.data || []} plans={plans.data || []} actorId={user.id} disabled={blocked}
        onSharedChange={value => { if (!blocked) { setValidation(''); changeShared(value); } }} onChange={value => { if (!blocked) { setValidation(''); changeDraft(value); } }}
        onRemove={accountId => { if (!blocked) { setValidation(''); remove(accountId); } }} />
      <ErrorBox text={validation || preview.error || admission.error} />
      {!admission.pending && <button type="submit" className="primary" disabled={blocked || !drafts.length}>{preview.busy ? '正在核对账号与分组…' : '预览批次'}</button>}
    </form>
    {preview.data && !admission.pending && <><Preview preview={preview.data} /><button type="button" className="primary" disabled={admission.busy} onClick={submit}>确认开通</button></>}
    {admission.pending && <section className="panel"><h2>继续确认原请求</h2><p>提交结果尚未确认，原账号、数量、规则和请求标识已保存。刷新页面不会自动重新提交。</p><button type="button" className="primary" disabled={admission.busy} onClick={submit}>{admission.busy ? '正在确认…' : '继续确认原请求'}</button></section>}
    {detailId && <ProvisioningBatchDetail key={`${user.id}:${scope}:${detailId}`} id={detailId} user={user} scope={scope} notify={notify} access={access} />}
    <section className="panel batch-history"><div className="section-heading"><h2>批次历史</h2><button type="button" className="secondary" disabled={reportDownload.busy || !!history.error || !history.data?.total} onClick={report}>下载筛选批次报告</button></div>
      <div className="provisioning-history-filters"><label className="field"><span>AWS 账号</span><SearchableSelect aria-label="筛选 AWS 账号" value={filterAccount} onChange={e => { setFilterAccount(e.target.value); setPage(1); }}><option value="">全部 AWS 账号</option>{accounts.data?.map(a => <option key={a.id} value={a.id}>{accountLabel(a)}</option>)}</SearchableSelect></label>
        <label className="field"><span>模糊搜索</span><input type="search" aria-label="搜索批次、内部 ID 或用户名" placeholder="批次、内部 ID 或用户名" value={query} onChange={e => { setQuery(e.target.value); setPage(1); }} /></label>
        <label className="field"><span>状态</span><SearchableSelect aria-label="筛选批次状态" value={state} onChange={e => { setState(e.target.value); setPage(1); }}><option value="">全部状态</option>{Object.entries(provisioningStates).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</SearchableSelect></label>
        <label className="field"><span>创建日期从</span><input aria-label="创建日期从" type="date" value={from} onChange={e => { setFrom(e.target.value); setPage(1); }} /></label><label className="field"><span>创建日期到</span><input aria-label="创建日期到" type="date" value={to} onChange={e => { setTo(e.target.value); setPage(1); }} /></label>
      </div><ErrorBox text={history.error || reportDownload.error} />
      <div className="table-wrap"><table><thead><tr><th>创建时间</th><th>AWS 批次</th><th>状态</th><th>操作</th></tr></thead><tbody>{history.data?.items.map(batch => <tr key={batch.id}><td>{date(batch.created_at)}</td><td>{batch.accounts.map(a => <div key={a.id}><span className="mono">{a.batch_number}</span> · {a.account_name} · {a.quantity} 人 · {a.plan_name}</div>)}</td><td><State state={batch.state} /></td><td><button type="button" className="text-button" onClick={() => setParams({ batch_id: batch.id })}>查看进度</button></td></tr>)}</tbody></table></div>
      {!history.data?.items.length && !history.loading && <p className="muted">没有匹配的批次。</p>}<div className="row-actions"><button type="button" className="secondary" disabled={page <= 1} onClick={() => setPage(page - 1)}>上一页</button><span>第 {page} 页 · 共 {history.data?.total || 0} 批</span><button type="button" className="secondary" disabled={page * 20 >= (history.data?.total || 0)} onClick={() => setPage(page + 1)}>下一页</button></div>
    </section></>;
}
