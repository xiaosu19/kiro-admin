import { accountLabel } from "./provisioningLogic";
import { SearchableSelect } from "./SearchableSelect";
import { useState } from "react";
import { recordQuery, type Account, type AuthKind, type GroupItem, type LoginExportFormat, type Page, type RecordItem, type User } from "./api";
import { useRemote } from "./groupRequests";
import { useAuthGroupPreview } from "./authRequests";
import { canUseAuthRecord, credentialLabel, selectAuthRecords, selectPreviewIds } from "./authLogic";
import { AuthError } from "./AuthBatches";
import { LoginExportMenu } from "./LoginExportMenu";

export interface AuthSelectionValue { records: RecordItem[]; groupId?: string }
export function LoginExportActions({ selected, canExportSelection, hasResults, busy, onExport }: {
  selected: string[]; canExportSelection: boolean; hasResults: boolean; busy: boolean;
  onExport: (ids: string[] | undefined, format: LoginExportFormat) => void;
}) {
  return <LoginExportMenu disabled={busy} label={busy ? "正在处理…" : "导出"} scopes={[
    { label: `选中用户（${selected.length}）`, disabled: !canExportSelection, onExport: format => onExport(selected, format) },
    { label: "筛选结果", disabled: !hasResults, onExport: format => onExport(undefined, format) },
  ]} />;
}

interface PickerProps {
  user: User; kind: AuthKind; selected: RecordItem[]; disabled: boolean;
  onChange: (records: RecordItem[]) => void;
}
export function AuthRecordTable({ user, kind, records, selected, disabled, onChange }: PickerProps & { records: RecordItem[] }) {
  const eligible = records.filter(r => canUseAuthRecord(r, user, kind));
  const ids = selected.map(r => r.id);
  function change(rows: RecordItem[], checked: boolean) {
    const nextIds = selectAuthRecords(ids, rows.map(r => r.id), checked);
    const known = new Map([...selected, ...records].map(r => [r.id, r]));
    onChange(nextIds.map(id => known.get(id)!));
  }
  const all = !!eligible.length && eligible.every(r => ids.includes(r.id));
  return <>
    <div className="selection-toolbar"><span>已选 <strong>{selected.length}</strong> / 100 人</span>
      <button type="button" className="secondary" disabled={disabled || !eligible.length} onClick={() => change(eligible, !all)}>{all ? "取消本页选择" : "选中本页可处理用户"}</button>
      <small>最多 100 人；翻页保留选择，更换筛选条件会清空。</small>
    </div>
    <div className="table-wrap auth-selection-table"><table><thead><tr><th>选择</th><th>SSO 用户</th><th>AWS 账号</th><th>当前状态</th></tr></thead><tbody>
      {records.map(record => <tr key={record.id} aria-selected={ids.includes(record.id)}>
        <td><input type="checkbox" aria-label={`选择 ${record.username}`} checked={ids.includes(record.id)} disabled={disabled || !canUseAuthRecord(record, user, kind) || (ids.length >= 100 && !ids.includes(record.id))} onChange={e => change([record], e.target.checked)} /></td>
        <td className="mono">{record.username}</td><td>{record.account_name || "—"}</td>
        <td>{record.operation_pending || record.operation ? "有任务正在处理或待核对" : record.sso_deleted_at ? "SSO 已删除" : !record.sso_user_id ? "SSO 尚未就绪" : credentialLabel(record.credential_state)}</td>
      </tr>)}
    </tbody></table></div>
  </>;
}

export function SelectedAuthRecords({ records, disabled, onChange }: { records: RecordItem[]; disabled: boolean; onChange: (records: RecordItem[]) => void }) {
  return <div className="auth-selected" aria-label="已选用户预览">
    <div className="stop-heading"><strong>本次选择：{records.length} 人</strong><button type="button" className="text-button" disabled={disabled || !records.length} onClick={() => onChange([])}>清空选择</button></div>
    {records.length ? <ul>{records.map(record => <li key={record.id}><span className="mono">{record.username}</span><small>{record.account_name}</small><button type="button" className="text-button" disabled={disabled} aria-label={`移除 ${record.username}`} onClick={() => onChange(records.filter(r => r.id !== record.id))}>移除</button></li>)}</ul> : <p className="muted">请明确勾选要处理的用户。</p>}
  </div>;
}

export function ManualAuthPicker(props: PickerProps) {
  const [query, setQuery] = useState(""), [search, setSearch] = useState(""), [status, setStatus] = useState("all"), [page, setPage] = useState(1);
  const [account, setAccount] = useState("");
  const accounts = useRemote<Account[]>("/accounts");
  const scope = recordQuery({ owner_id: props.user.id, q: search, status, ...(account ? { aws_account_id: Number(account) } : {}) });
  const remote = useRemote<Page<RecordItem>>(`/sso-users?page=${page}&page_size=30&${scope}`, 5000);
  function reset() { setPage(1); props.onChange([]); }
  return <>
    <form className="auth-filters" onSubmit={e => { e.preventDefault(); const next = query.trim(); if (next !== search) reset(); setSearch(next); }}>
      <label><span className="sr-only">按 AWS 账号筛选</span><SearchableSelect aria-label="按 AWS 账号筛选" value={account} disabled={props.disabled} onChange={e => { setAccount(e.target.value); reset(); }}><option value="">全部 AWS 账号</option>{accounts.data?.map(item => <option key={item.id} value={item.id}>{accountLabel(item)}</option>)}</SearchableSelect></label>
      <label><span className="sr-only">搜索用户名、姓名或邮箱</span><input aria-label="搜索用户名、姓名或邮箱" placeholder="搜索用户名、姓名或邮箱" value={query} disabled={props.disabled} onChange={e => setQuery(e.target.value)} /></label>
      <label><span className="sr-only">SSO 状态</span><SearchableSelect aria-label="SSO 状态" value={status} disabled={props.disabled} onChange={e => { setStatus(e.target.value); reset(); }}><option value="all">全部 SSO</option><option value="unsubscribed">未订阅</option><option value="active">未删除</option><option value="deleted">已删除</option></SearchableSelect></label>
      <button className="secondary" disabled={props.disabled}>搜索</button>
    </form>
    <AuthError text={remote.error || accounts.error} />
    <AuthRecordTable {...props} disabled={props.disabled || remote.loading} records={remote.data?.items || []} />
    {!remote.data?.items.length && <p className="muted">{remote.loading ? "正在读取 SSO…" : "暂无匹配的 SSO 用户。"}</p>}
    <div className="auth-pager"><button className="secondary" disabled={props.disabled || page <= 1} onClick={() => setPage(page - 1)}>上一页</button><span>第 {page} 页 · 共 {remote.data?.total || 0} 人</span><button className="secondary" disabled={props.disabled || !remote.data || page * 30 >= remote.data.total} onClick={() => setPage(page + 1)}>下一页</button></div>
  </>;
}

export function GroupAuthPicker({ groupId, onGroup, ...props }: PickerProps & { groupId: string; onGroup?: (id: string) => void }) {
  const groups = useRemote<GroupItem[]>(onGroup ? "/groups" : null);
  const accounts = useRemote<Account[]>(onGroup ? "/accounts" : null);
  const [account, setAccount] = useState(""), [search, setSearch] = useState("");
  const owned = groups.data?.filter(group => group.owner_id === props.user.id && !group.deleted_at && group.state === "ready" &&
    (!account || group.aws_account_id === Number(account)) && group.name.toLowerCase().includes(search.trim().toLowerCase())) || [];
  const preview = useAuthGroupPreview(groupId, props.kind);
  function reset() { props.onChange([]); onGroup?.(""); }
  return <>
    <div className="auth-filters">
      {onGroup && <>
        <label className="field"><span>AWS 账号</span><SearchableSelect aria-label="按 AWS 账号筛选" value={account} disabled={props.disabled} onChange={e => { setAccount(e.target.value); reset(); }}><option value="">全部 AWS 账号</option>{accounts.data?.map(item => <option key={item.id} value={item.id}>{accountLabel(item)}</option>)}</SearchableSelect></label>
        <label className="field"><span>搜索分组</span><input aria-label="搜索分组名称" placeholder="搜索分组名称" value={search} disabled={props.disabled} onChange={e => { setSearch(e.target.value); reset(); }} /></label>
        <label className="field"><span>我的分组</span><SearchableSelect aria-label="我的分组" value={groupId} disabled={props.disabled} onChange={e => { props.onChange([]); onGroup(e.target.value); }}><option value="">请选择分组</option>{owned.map(group => <option key={group.id} value={group.id}>{group.name}</option>)}</SearchableSelect></label>
      </>}
      <button type="button" className="secondary" disabled={props.disabled || preview.busy || !groupId || (!!onGroup && !owned.some(group => group.id === groupId))} onClick={() => { props.onChange([]); void preview.refresh(); }}>{preview.busy ? "正在预览…" : "预览分组用户"}</button>
    </div>
    <AuthError text={preview.error || groups.error || accounts.error} />
    <p className="muted">先预览，再明确勾选。本次只处理预览中选定的用户；之后加入分组的成员不会自动加入。</p>
    {preview.snapshot && <>
      <AuthRecordTable {...props} records={preview.snapshot.records} onChange={records => {
        selectPreviewIds(records.map(record => record.id), preview.snapshot!.preview.record_ids);
        props.onChange(records);
      }} />
      {!preview.snapshot.records.length && <p className="muted">当前没有可处理的分组用户。</p>}
      {!!preview.snapshot.preview.skipped.length && <details className="auth-skipped"><summary>未纳入预览 {preview.snapshot.preview.skipped.length} 人</summary><ul>{preview.snapshot.preview.skipped.map(item => <li key={item.record_id}>{item.username}：{item.reason}</li>)}</ul></details>}
    </>}
  </>;
}

export function GroupJsonPicker({ groups, accounts, selected, disabled, onChange }: {
  groups: GroupItem[]; accounts: Account[]; selected: string[]; disabled: boolean; onChange: (ids: string[]) => void;
}) {
  const [account, setAccount] = useState(""), [search, setSearch] = useState("");
  const filtered = groups.filter(group => (!account || group.aws_account_id === Number(account))
    && group.name.toLocaleLowerCase().includes(search.trim().toLocaleLowerCase()));
  return <>
    <div className="auth-filters">
      <label className="field"><span>AWS 账号</span><SearchableSelect aria-label="整组导出 AWS 账号筛选" value={account} disabled={disabled} onChange={e => setAccount(e.target.value)}>
        <option value="">全部 AWS 账号</option>{accounts.map(item => <option key={item.id} value={item.id}>{accountLabel(item)}</option>)}
      </SearchableSelect></label>
      <label className="field"><span>搜索分组</span><input aria-label="搜索整组导出分组名称" placeholder="搜索分组名称" disabled={disabled} value={search} onChange={e => setSearch(e.target.value)} /></label>
    </div>
    <div className="selection-toolbar"><span>已选 <strong>{selected.length}</strong> / 100 个完整分组</span>
      <button type="button" className="text-button" disabled={disabled || !selected.length} onClick={() => onChange([])}>清空分组选择</button>
      <small>筛选不改变已选分组；每批最多 5000 名成员，实际可转换人数以预览为准。</small>
    </div>
    <div className="table-wrap"><table><thead><tr><th>选择整组</th><th>分组</th><th>AWS 账号</th><th>本地成员数</th></tr></thead><tbody>
      {filtered.map(group => <tr key={group.id} aria-selected={selected.includes(group.id)}>
        <td><input type="checkbox" aria-label={`选择整个 ${group.name}`} disabled={disabled || selected.length >= 100 && !selected.includes(group.id)}
          checked={selected.includes(group.id)} onChange={e => onChange(e.target.checked ? [...selected, group.id] : selected.filter(id => id !== group.id))} /></td>
        <td>{group.name}</td><td>{accounts.find(a => a.id === group.aws_account_id)?.name || `AWS ${group.aws_account_id}`}</td><td>{group.counts?.total ?? "待预览"}</td>
      </tr>)}
    </tbody></table></div>
    {!filtered.length && <p className="muted">没有匹配且已就绪的分组。</p>}
    {!!selected.length && <p className="muted">本次整组范围：{selected.map(id => groups.find(group => group.id === id)?.name || id).join("、")}</p>}
  </>;
}
