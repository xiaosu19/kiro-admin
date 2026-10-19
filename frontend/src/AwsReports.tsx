import { accountLabel } from "./provisioningLogic";
import { useCallback, useEffect, useRef, useState } from "react";
import { SearchableSelect } from "./SearchableSelect";
import { matchesSelection, toggleVisibleSelection } from "./selectionSearch";
import {
  awsReportRequest, downloadAwsReport, date,
  type Account, type AwsCost, type AwsReportResult, type AwsReportView, type User,
} from "./api";

function actorScope(user: User) {
  return JSON.stringify([user.id, user.role, user.active, user.account_ids?.slice().sort((a, b) => a - b)]);
}

function useScopeGuard(key: string) {
  const scope = useRef({ key, generation: 0 }), mounted = useRef(false), request = useRef(0);
  if (scope.current.key !== key) scope.current = { key, generation: scope.current.generation + 1 };
  const active = scope.current;
  useEffect(() => {
    mounted.current = true;
    request.current += 1;
    return () => { mounted.current = false; request.current += 1; };
  }, [active]);
  const isScopeCurrent = useCallback(() => mounted.current && scope.current === active, [active]);
  const begin = useCallback(() => {
    if (!isScopeCurrent()) return () => false;
    const current = ++request.current;
    return () => isScopeCurrent() && request.current === current;
  }, [isScopeCurrent]);
  return { begin, isScopeCurrent, scopeKey: `${active.generation}:${key}` };
}

export function useAwsReport(user: User, view: AwsReportView, accountIds: number[], q: string) {
  const scope = JSON.stringify([actorScope(user), view, accountIds.slice().sort((a, b) => a - b), q]);
  const { begin, isScopeCurrent, scopeKey: key } = useScopeGuard(scope);
  const [state, setState] = useState<{ key: string; data: AwsReportResult | null; selected: string[]; error: string; busy: boolean }>({
    key, data: null, selected: [], error: "", busy: false,
  });
  const current = state.key === key ? state : { key, data: null, selected: [], error: "", busy: false };
  const load = useCallback(async () => {
    const isCurrent = begin();
    if (!isCurrent()) return;
    setState({ key, data: null, selected: [], error: "", busy: true });
    try {
      if (!accountIds.length) throw new Error("请先选择 AWS 账号");
      const data = await awsReportRequest<AwsReportResult>("/aws-reports/query", {
        view, account_ids: accountIds, q,
      }, isCurrent);
      if (isCurrent()) setState({ key, data, selected: [], error: "", busy: false });
    } catch (e) {
      if (isCurrent()) setState({ key, data: null, selected: [], error: (e as Error).message, busy: false });
    }
  }, [key, begin]);
  const setSelected = (ids: string[]) => {
    if (!isScopeCurrent()) return;
    const available = new Set(current.data?.rows.map(r => r.id));
    setState({ ...current, selected: [...new Set(ids)].filter(id => available.has(id)) });
  };
  const download = async () => {
    if (!current.data || current.busy) return null;
    const isCurrent = begin();
    if (!isCurrent()) return null;
    setState({ ...current, busy: true, error: "" });
    try {
      const count = await downloadAwsReport({ view, account_ids: accountIds, q,
        row_ids: current.selected.length ? current.selected : null }, isCurrent);
      if (isCurrent()) setState({ ...current, busy: false, error: "" });
      return isCurrent() ? count : null;
    } catch (e) {
      if (isCurrent()) setState({ ...current, busy: false, error: (e as Error).message });
      return null;
    }
  };
  return { ...current, load, setSelected, download };
}

export function ReportTable({ data, selected, onSelect, disabled = false }: {
  data: AwsReportResult; selected: string[]; onSelect: (ids: string[]) => void; disabled?: boolean;
}) {
  const [page, setPage] = useState(0);
  const pages = Math.max(1, Math.ceil(data.rows.length / 50));
  const visiblePage = Math.min(page, pages - 1);
  const selectedSet = new Set(selected);
  return <>
    <div className="table-wrap"><table className="report-table">
      <thead><tr>
        <th><input type="checkbox" aria-label="选择全部筛选结果" disabled={disabled || !data.rows.length}
          checked={data.rows.length > 0 && data.rows.every(row => selectedSet.has(row.id))}
          onChange={e => onSelect(e.target.checked ? data.rows.map(row => row.id) : [])} /></th>
        <th>AWS 账号</th>{data.columns.map(column => <th key={column}>{column}</th>)}
      </tr></thead>
      <tbody>{data.rows.slice(visiblePage * 50, (visiblePage + 1) * 50).map(row => <tr key={row.id}>
        <td><input type="checkbox" aria-label={`选择报表行 ${row.id}`} disabled={disabled} checked={selectedSet.has(row.id)}
          onChange={e => onSelect(e.target.checked ? [...selected, row.id] : selected.filter(id => id !== row.id))} /></td>
        <td>{row.account_name}</td>{row.values.map((value, index) => <td key={index}>{value}</td>)}
      </tr>)}</tbody>
    </table></div>
    {pages > 1 && <div className="report-pagination">
      <button className="secondary" disabled={!visiblePage} onClick={() => setPage(visiblePage - 1)}>上一页</button>
      <span>第 {visiblePage + 1} / {pages} 页 · 每页 50 条</span>
      <button className="secondary" disabled={visiblePage === pages - 1} onClick={() => setPage(visiblePage + 1)}>下一页</button>
    </div>}
  </>;
}

export function AwsReports({ user, notify }: { user: User; notify: (message: string, error?: boolean) => void }) {
  const actorKey = actorScope(user), actorRef = useRef(actorKey);
  actorRef.current = actorKey;
  const [options, setOptions] = useState<{ key: string; accounts: Account[]; error: string }>({ key: actorKey, accounts: [], error: "" });
  const [view, setView] = useState<AwsReportView>("users"), [q, setQ] = useState("");
  const [accountQuery, setAccountQuery] = useState("");
  const [selection, setSelection] = useState<{ key: string; ids: number[] }>({ key: actorKey, ids: [] });
  useEffect(() => {
    let alive = true;
    const isCurrent = () => alive && actorRef.current === actorKey;
    void awsReportRequest<Account[]>("/accounts", undefined, isCurrent).then(accounts => {
      if (isCurrent() && accounts) setOptions({ key: actorKey, accounts: accounts.filter(a => !a.deleted_at && (user.role === "admin" || a.active)), error: "" });
    }).catch(e => { if (isCurrent()) setOptions({ key: actorKey, accounts: [], error: (e as Error).message }); });
    return () => { alive = false; };
  }, [actorKey]);
  const accounts = options.key === actorKey ? options.accounts : [];
  const visibleAccounts = accounts.filter(account => matchesSelection(accountQuery, account.account_number, account.name, account.id, account.aws_account_id, account.region));
  const accountIds = selection.key === actorKey ? selection.ids.filter(id => accounts.some(a => a.id === id)) : [];
  const report = useAwsReport(user, view, accountIds, q);
  const setIds = (ids: number[]) => setSelection({ key: actorKey, ids: ids.slice(0, 100) });
  return <>
    <div className="page-heading"><div><h1>AWS 报表</h1><p>读取当前 AWS 身份目录与 Kiro 订阅，按控制台列顺序下载 CSV。</p></div></div>
    <section className="panel report-controls">
      <div role="tablist" aria-label="AWS 报表视图" className="report-tabs">
        {(["users", "groups", "subscriptions"] as const).map(tab => <button key={tab} role="tab" aria-selected={view === tab}
          className={view === tab ? "primary" : "secondary"} onClick={() => setView(tab)}>
          {tab === "users" ? "Users" : tab === "groups" ? "Groups" : "Subscriptions"}
        </button>)}
      </div>
      <fieldset className="report-accounts"><legend>AWS 账号（可多选，每次最多 100 个）</legend>
        <input className="selection-collection-search" type="search" aria-label="搜索报表 AWS 账号" placeholder="搜索账号名称、ID 或区域" value={accountQuery} onChange={event => setAccountQuery(event.target.value)} />
        <label><input type="checkbox" aria-label="选择全部 AWS 账号（当前搜索结果）" checked={visibleAccounts.length > 0 && visibleAccounts.every(account => accountIds.includes(account.id))}
          disabled={!visibleAccounts.length} onChange={e => setIds(toggleVisibleSelection(accountIds, visibleAccounts.map(a => a.id), e.target.checked))} />选择全部 AWS 账号（当前搜索结果）</label>
        {visibleAccounts.map(account => <label key={account.id}><input type="checkbox" aria-label={`报表 AWS 账号 ${account.name}`}
          checked={accountIds.includes(account.id)} onChange={e => setIds(e.target.checked ? [...accountIds, account.id] : accountIds.filter(id => id !== account.id))} />{accountLabel(account)}</label>)}
        {!!accounts.length && !visibleAccounts.length && <p className="selection-empty" role="status">没有匹配的 AWS 账号，已勾选项会保留。</p>}
      </fieldset>
      {options.key === actorKey && options.error && <div className="error" role="alert">{options.error}</div>}
      <form className="report-search" onSubmit={e => { e.preventDefault(); void report.load(); }}>
        <input aria-label="搜索报表姓名、邮箱或分组" placeholder="搜索当前用户名、邮箱或分组" value={q} onChange={e => setQ(e.target.value)} />
        <button className="secondary" disabled={report.busy || !accountIds.length}>{report.busy ? "正在读取…" : "查询 AWS 报表"}</button>
      </form>
      <div className="report-download"><span className="muted">已选 {accountIds.length} 个 AWS 账号 · 未勾选行时导出全部当前筛选结果</span>
        <button className="primary" disabled={report.busy || !report.data} onClick={async () => {
          const count = await report.download();
          if (count !== null) notify(`已下载 ${count} 条 AWS 报表记录`);
        }}>{accountIds.length > 1 ? "下载 ZIP" : "下载 CSV"}</button>
      </div>
    </section>
    {report.error && <div className="error" role="alert">{report.error}</div>}
    {report.busy && <p role="status">正在读取完整 AWS 数据，请稍候…</p>}
    {report.data ? <section className="panel">
      <div className="section-heading"><h2>{report.data.total} 条记录 · 已勾选 {report.selected.length} 条</h2>
        <small>查询时间 {date(report.data.generated_at)}</small></div>
      {report.data.rows.length ? <ReportTable key={report.data.generated_at + view} data={report.data} selected={report.selected} onSelect={report.setSelected} disabled={report.busy} />
        : <p className="empty">当前账号和搜索范围内没有报表记录。</p>}
    </section> : !report.busy && <section className="panel"><p className="empty">选择账号与报表视图，然后查询 AWS 报表。更改筛选条件后需重新查询。</p></section>}
  </>;
}

// All account cards share this queue. Obsolete queued scopes never start IO.
let activeBillsReads = 0;
const billsQueue: { current: () => boolean; run: () => Promise<AwsCost | null>;
  resolve: (data: AwsCost | null) => void; reject: (reason: unknown) => void }[] = [];
function drainBillsQueue() {
  while (activeBillsReads < 3 && billsQueue.length) {
    const job = billsQueue.shift()!;
    if (!job.current()) { job.resolve(null); continue; }
    activeBillsReads++;
    void job.run().then(job.resolve, job.reject).finally(() => { activeBillsReads--; drainBillsQueue(); });
  }
}
function queueBillsRead(run: () => Promise<AwsCost | null>, current: () => boolean, refresh: boolean) {
  return new Promise<AwsCost | null>((resolve, reject) => {
    const job = { run, current, resolve, reject };
    if (refresh) billsQueue.unshift(job); else billsQueue.push(job);
    drainBillsQueue();
  });
}

function billingScope(user: User, account: Account, month: string) {
  return JSON.stringify([actorScope(user), month, account.id, account.active, account.deleted_at,
    account.aws_account_id, account.region, account.subscription_region, account.identity_store_id,
    account.instance_arn, account.application_arn, account.profile_arn, account.proxy_id, account.proxy_status]);
}

export function useAccountCost(user: User, account: Account, payerId?: string) {
  const month = new Date().toISOString().slice(0, 7);
  const { scopeKey: baseKey } = useScopeGuard(billingScope(user, account, month));
  const { begin, scopeKey: key } = useScopeGuard(JSON.stringify([baseKey, payerId]));
  const enabled = user.role === "admin" && user.active && !account.deleted_at;
  const [options, setOptions] = useState<{ key: string; payers: string[]; selected: string }>({ key: baseKey, payers: [], selected: "" });
  const [state, setState] = useState<{ key: string; data: AwsCost | null; error: string; loading: boolean }>({ key, data: null, error: "", loading: false });
  const load = useCallback(async (refresh = false) => {
    const isCurrent = begin();
    if (!enabled || !isCurrent()) return;
    setState({ key, data: null, error: "", loading: true });
    try {
      const params = new URLSearchParams({ month });
      if (payerId) params.set("payer_id", payerId);
      if (refresh) params.set("refresh", "true");
      const data = await queueBillsRead(() => awsReportRequest<AwsCost>(`/admin/aws/${account.id}/cost?${params}`, undefined, isCurrent), isCurrent, refresh);
      if (isCurrent()) {
        if (data) setOptions({ key: baseKey, payers: data.available_payers, selected: data.payer_id });
        setState({ key, data, error: "", loading: false });
      }
    } catch (e) {
      if (isCurrent()) setState({ key, data: null, error: (e as Error).message, loading: false });
    }
  }, [key, begin, enabled]);
  useEffect(() => { void load(); }, [load]);
  return { ...(state.key === key && enabled ? state : { data: null, error: "", loading: false }), month,
    availablePayers: options.key === baseKey && enabled ? options.payers : [],
    selectedPayer: payerId || (options.key === baseKey && enabled ? options.selected : ""), refresh: () => load(true) };
}

/** Round the decimal string to the currency's minor unit without a float conversion. */
export function formatBillAmount(amount: string, currency: string) {
  const formatter = new Intl.NumberFormat("zh-CN", { style: "currency", currency, currencyDisplay: "code" });
  const digits = formatter.resolvedOptions().maximumFractionDigits ?? 2;
  const negative = amount.startsWith("-");
  const [integer, fraction = ""] = amount.replace(/^[+-]/, "").split(".");
  const scale = 10n ** BigInt(digits);
  let minor = BigInt(integer) * scale + BigInt(fraction.padEnd(digits, "0").slice(0, digits) || "0");
  if ((fraction[digits] || "0") >= "5") minor++;
  const whole = minor / scale;
  const signed = negative ? (whole === 0n ? -0 : -whole) : whole;
  return formatter.formatToParts(signed).map(part => part.type === "fraction"
    ? (minor % scale).toString().padStart(digits, "0") : part.value).join("");
}

export function CostFacts({ data, error, loading }: { data: AwsCost | null; error: string; loading: boolean }) {
  if (loading) return <p className="muted" role="status">正在读取 AWS Bills…</p>;
  if (error) return <p className="error" role="alert">{error}</p>;
  if (!data) return <p className="muted">账单暂不可用</p>;
  return <div className="cost-facts"><p className="cost-amount"><strong>{formatBillAmount(data.amount, data.currency)}</strong> <span className="badge">预估</span>
    {data.billing_kind === "proforma" && <span className="badge">形式账单 · Pro forma</span>}</p>
    <p className="muted">{data.period_start} 至 {data.period_end}（UTC，不含结束日）</p>
    <small>获取于 {date(data.retrieved_at)}</small>
    <p className="muted">每次查询读取 AWS 最新已出账金额，尚未入账的用量可能稍后体现。</p>
  </div>;
}

export function PayerChoice({ accountName, payers, value, onChange }: {
  accountName: string; payers: string[]; value: string; onChange: (payer: string) => void;
}) {
  return <SearchableSelect aria-label={`付款账号 ${accountName}`} value={value} onChange={event => onChange(event.target.value)}>
    {payers.map(payer => <option key={payer} value={payer}>{payer}</option>)}
  </SearchableSelect>;
}

export function AccountCost({ user, account }: { user: User; account: Account }) {
  const { scopeKey: key } = useScopeGuard(billingScope(user, account, new Date().toISOString().slice(0, 7)));
  const [selection, setSelection] = useState<{ key: string; payer?: string }>({ key });
  const state = useAccountCost(user, account, selection.key === key ? selection.payer : undefined);
  if (user.role !== "admin") return null;
  return <section className="account-cost" aria-label={`AWS Bills 本月账单 ${account.name}`}>
    <h3>AWS Bills 本月账单</h3>
    <div className="cost-controls"><span className="muted">{state.month}（UTC）</span>
      <button className="secondary" aria-label={`刷新账单 ${account.name}`} disabled={state.loading || !!account.deleted_at}
        onClick={() => void state.refresh()}>刷新账单</button></div>
    {!!state.availablePayers.length && <label className="cost-payer">付款账号
      <PayerChoice accountName={account.name} payers={state.availablePayers} value={state.selectedPayer}
        onChange={payer => setSelection({ key, payer })} /></label>}
    <CostFacts data={state.data} error={state.error} loading={state.loading} />
  </section>;
}
