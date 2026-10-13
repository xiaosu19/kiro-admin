import { SearchableSelect } from "./SearchableSelect";
import { RetryStatus } from "./RetryStatus";
import { AccountBindings } from "./AccountBindings";
import { Provisioning } from "./Provisioning";
import { accountLabel } from "./provisioningLogic";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import {
  NavLink,
  Navigate,
  Route,
  Routes,
  useNavigate,
  useSearchParams,
} from "react-router-dom";
import {
  api,
  downloadCsv,
  downloadLogins,
  loginExportBody,
  recordQuery,
  setCsrf,
  date,
  stateName,
  operationName,
  subscriptionStatus,
  type Account,
  type Audit,
  type BatchInfo,
  type Counter,
  type Overview,
  type Page,
  type Plan,
  type PlanCatalog,
  type RecordItem,
  type RecordOperation,
  type Reset,
  type User,
  type MemberSummary,
  type MemberSummaryRow,
  type PlanHistoryItem,
  type ProxyItem,
  type GroupItem,
  type LoginCredential,
  type LoginExportFormat,
  type Capabilities,
  type LifecycleBatch,
  type CascadeBatch,
} from "./api";
import {
  readSubscriptionPolicy,
  SubscriptionPolicyFields,
  StopRuleSource,
  StopScheduleEditor,
  stopState,
  stopTime,
} from "./StopSchedule";
import { Proxies } from "./Proxies";
import { AccountCost, AwsReports } from "./AwsReports";
import { Groups } from "./Groups";
import { GroupJoinNotice, LifecycleHistory, LifecycleRecovery, NativeMemberHistory, NativeSubscriptionDialog } from "./NativeSubscriptions";
import { useLifecycleAdmission } from "./nativeSubscriptionRequests";
import { activeNativeGroup, canCancelRecord, nativeAccess } from "./nativeSubscriptionsLogic";
import { JsonExport } from "./JsonExport";
import { PasswordBatches } from "./PasswordBatches";
import { CurrentPlanFacts, PlanChangeManager, RecordPlanLabel } from "./PlanChangeManager";
import { isPlanChangeOperation, planChangeDirection, planHistoryTime } from "./planChangesLogic";
import { canUseAuthRecord, credentialLabel, credentialText, authStateLabel } from "./authLogic";
import { CredentialDetails } from "./AuthBatches";
import { LoginExportActions } from "./AuthSelection";
import { LoginExportMenu } from "./LoginExportMenu";
import { CascadeDialog, CascadeHistory, CascadeSubmissionRecovery } from "./CascadeDeletion";
import { useCascadeAdmission } from "./cascadeRequests";
import {
  canSubscribeRecord, createSsoIntent, ownedCreationGroups, runSsoCreation, runRecoverableSubmission,
  subscriptionRequest, type SsoCreationBody, type SsoCreationIntent,
} from "./groupsLogic";

const AppContext = createContext<{
  user: User;
  capabilities: Capabilities;
  refresh: () => void;
  notify: (s: string, error?: boolean) => void;
}>(null!);
const useApp = () => useContext(AppContext);
export function useData<T>(path: string, poll = 0) {
  const [data, setData] = useState<T | null>(null),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(true);
  const generation = useRef(0);
  const activePath = useRef<string | null>(null);
  const refresh = useCallback(async () => {
    if (activePath.current !== path) return;
    const current = generation.current;
    const isCurrent = () => activePath.current === path && generation.current === current;
    try {
      const result = await api<T>(path);
      if (isCurrent()) {
        setData(result);
        setError("");
      }
    } catch (e) {
      if (isCurrent()) setError((e as Error).message);
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, [path]);
  useEffect(() => {
    activePath.current = path;
    generation.current += 1;
    setLoading(true);
    setData(null);
    setError("");
    void refresh();
    const t = poll ? window.setInterval(refresh, poll) : undefined;
    return () => {
      activePath.current = null;
      generation.current += 1;
      window.clearInterval(t);
    };
  }, [path, poll, refresh]);
  return { data, error, loading, refresh };
}
function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}
function ErrorBox({ text }: { text?: string }) {
  return text ? (
    <div className="error" role="alert">
      {text}
    </div>
  ) : null;
}
function Empty({ children }: { children: ReactNode }) {
  return (
    <div className="empty">
      <span className="empty-icon">◇</span>
      <p>{children}</p>
    </div>
  );
}
function Header({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}
function Badge({ state }: { state: string }) {
  return (
    <span className={`badge ${state}`}>
      <i />
      {stateName[state] || state}
    </span>
  );
}
function Modal({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null),
    close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const before = document.activeElement as HTMLElement;
    ref.current
      ?.querySelector<HTMLElement>("input,button,select,textarea")
      ?.focus();
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape") close.current();
      if (e.key === "Tab") {
        const els = Array.from(
          ref.current?.querySelectorAll<HTMLElement>(
            "button:not(:disabled),input,select,textarea,a[href]",
          ) || [],
        );
        const first = els[0],
          last = els[els.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last?.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first?.focus();
        }
      }
    };
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("keydown", key);
      before?.focus();
    };
  }, []);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="modal"
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="modal-title">
          <h2>{title}</h2>
          <button className="icon-button" onClick={onClose} aria-label="关闭">
            ×
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
function Pager({
  page,
  total,
  onPage,
  pageSize = 30,
}: {
  page: number;
  total: number;
  onPage: (p: number) => void;
  pageSize?: number;
}) {
  return (
    <div className="pager">
      <span>共 {total} 条记录</span>
      <div>
        <button
          className="secondary"
          disabled={page <= 1}
          onClick={() => onPage(page - 1)}
        >
          上一页
        </button>
        <span>
          {page} / {Math.max(1, Math.ceil(total / pageSize))}
        </span>
        <button
          className="secondary"
          disabled={page * pageSize >= total}
          onClick={() => onPage(page + 1)}
        >
          下一页
        </button>
      </div>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState<User | null>(null),
    [capabilities, setCapabilities] = useState<Capabilities>({ plan_changes_enabled: false }),
    [loading, setLoading] = useState(true),
    [toast, setToast] = useState<{ text: string; error?: boolean } | null>(
      null,
    );
  const notify = useCallback(
    (text: string, error = false) => setToast({ text, error }),
    [],
  );
  const refresh = useCallback(() => {
    api<{ user: User; csrf: string; capabilities?: Capabilities }>("/auth/me")
      .then((r) => {
        setCsrf(r.csrf);
        setUser(r.user);
        setCapabilities({ plan_changes_enabled: r.capabilities?.plan_changes_enabled === true });
      })
      .catch(() => setUser(null))
      .finally(() => setLoading(false));
  }, []);
  useEffect(() => {
    refresh();
    const fn = () => setUser(null);
    window.addEventListener("session-expired", fn);
    return () => window.removeEventListener("session-expired", fn);
  }, [refresh]);
  useEffect(() => {
    if (toast) {
      const t = setTimeout(() => setToast(null), 6000);
      return () => clearTimeout(t);
    }
  }, [toast]);
  if (loading) return <div className="loading">正在加载工作台…</div>;
  if (!user) return <Login onLogin={refresh} />;
  const isAdmin = user.role === "admin";
  const nav = [
    ["/", "工作台", "▦"],
    ["/provisioning", "批次开通", "▣"],
    ["/create", "创建 SSO", "＋"],
    ["/subscribe", "开通 Kiro 订阅", "◇"],
    ["/records", "任务记录", "☷"],
    ["/sso", "SSO 用户", "♙"],
    ["/groups", "AWS 分组", "▤"],
    ["/json-export", "JSON 导出", "⇩"],
    ["/aws-reports", "AWS 报表", "▥"],
    ...(!isAdmin ? [["/counts", "我的次数", "◷"]] : []),
    ...(isAdmin
      ? [
          ["/users", "用户管理", "♧"],
          ["/aws", "AWS 账号", "☁"],
          ["/proxies", "代理池", "⇄"],
          ["/plans", "套餐管理", "◇"],
        ]
      : []),
    ["/audit", "操作记录", "≡"],
  ];
  return (
    <AppContext.Provider value={{ user, capabilities, refresh, notify }}>
      <div className="app-shell">
        <aside className="sidebar">
          <div className="brand">
            <div className="brand-mark">K</div>
            <div>
              Kiro<span>订阅控制台</span>
            </div>
          </div>
          <div className="nav-label">{isAdmin ? "管理空间" : "我的空间"}</div>
          <nav>
            {nav.map(([to, label, icon]) => (
              <NavLink key={to} to={to} end={to === "/"}>
                <span aria-hidden>{icon}</span>
                {label}
              </NavLink>
            ))}
          </nav>
          <div className="sidebar-footer">
            <span className="online-dot" />
            AWS 订阅管理<div>创建 · 开通 · 记录</div>
          </div>
        </aside>
        <div className="workspace">
          <header className="topbar">
            <span>{isAdmin ? "管理员" : "子用户"}工作空间</span>
            <div>
              <span className="avatar">{user.display_name.slice(0, 1)}</span>
              <strong>{user.display_name}</strong>
              <NavLink to="/password">修改密码</NavLink>
              <button
                className="text-button"
                onClick={async () => {
                  await api("/auth/logout", "POST");
                  setUser(null);
                }}
              >
                退出
              </button>
            </div>
          </header>
          <main key={user.id}>
            {user.must_change_password ? (
              <Password required />
            ) : (
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/provisioning" element={<Provisioning key={`${user.id}:${user.role}`} user={user} notify={notify} />} />
                <Route path="/create" element={<CreateSso />} />
                <Route path="/batch" element={<LegacyCreate />} />
                <Route path="/batch-status" element={<BatchStatusPage />} />
                <Route
                  path="/subscribe"
                  element={<Records key="subscribe" directory subscribeMode />}
                />
                <Route path="/records" element={<Records key="records" />} />
                <Route path="/sso" element={<Records key="sso" directory />} />
                <Route path="/groups" element={<Groups key={user.id} user={user} notify={notify} />} />
                <Route path="/json-export" element={<JsonExport key={user.id} user={user} notify={notify} />} />
                <Route path="/aws-reports" element={<AwsReports key={`${user.id}:${user.role}`} user={user} notify={notify} />} />
                <Route
                  path="/counts"
                  element={
                    isAdmin ? <Navigate to="/users" replace /> : <Counts />
                  }
                />
                <Route path="/audit" element={<AuditPage />} />
                <Route path="/password" element={<Password />} />
                {isAdmin && (
                  <>
                    <Route path="/users" element={<Users />} />
                    <Route path="/aws" element={<Accounts />} />
                    <Route
                      path="/proxies"
                      element={<Proxies notify={notify} />}
                    />
                    <Route path="/plans" element={<Plans />} />
                  </>
                )}
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            )}
          </main>
          <footer className="page-footer">
            Kiro Console <span>账号归属清晰，每次开通有据可查。</span>
          </footer>
        </div>
        {toast && (
          <div className={`toast ${toast.error ? "bad" : ""}`} role="status">
            {toast.text}
            <button onClick={() => setToast(null)} aria-label="关闭通知">
              ×
            </button>
          </div>
        )}
      </div>
    </AppContext.Provider>
  );
}
function Login({ onLogin }: { onLogin: () => void }) {
  const [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError("");
    const f = new FormData(e.currentTarget);
    try {
      const r = await api<{ csrf: string }>("/auth/login", "POST", {
        username: f.get("username"),
        password: f.get("password"),
      });
      setCsrf(r.csrf);
      onLogin();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="login-screen">
      <div className="login-story">
        <div className="brand">
          <div className="brand-mark">K</div>
          <div>
            Kiro<span>订阅控制台</span>
          </div>
        </div>
        <div>
          <span className="eyebrow">为每一次开通，留下清晰记录</span>
          <h1>
            连接 AWS。
            <br />
            管理你的 Kiro。
          </h1>
          <p>
            在分配的 AWS 账号中创建用户、开通订阅，
            <br />
            集中查看登录信息与套餐使用次数。
          </p>
          <div className="login-flow">
            <span>创建身份</span>
            <i>→</i>
            <span>开通订阅</span>
            <i>→</i>
            <span>记录结果</span>
          </div>
        </div>
        <small>你的账号与创建记录，仅授权用户可见。</small>
      </div>
      <div className="login-form">
        <form onSubmit={submit}>
          <span className="eyebrow">欢迎回来</span>
          <h2>登录工作台</h2>
          <p className="muted">使用管理员为你创建的平台账号。</p>
          <ErrorBox text={error} />
          <Field label="用户名">
            <input name="username" autoComplete="username" required autoFocus />
          </Field>
          <Field label="密码">
            <input
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </Field>
          <button className="primary full" disabled={busy}>
            {busy ? "正在登录…" : "登录"}
            <span>→</span>
          </button>
        </form>
      </div>
    </div>
  );
}
function Password({ required = false }: { required?: boolean }) {
  const { refresh, notify } = useApp(),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const navigate = useNavigate();
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    if (f.get("new") !== f.get("confirm")) {
      setError("两次输入的新密码不一致");
      return;
    }
    setBusy(true);
    try {
      const r = await api<{ csrf: string }>("/auth/change-password", "POST", {
        old_password: f.get("old"),
        new_password: f.get("new"),
      });
      setCsrf(r.csrf);
      notify("密码已修改");
      refresh();
      navigate("/");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Header
        title={required ? "设置你的登录密码" : "修改密码"}
        description={
          required
            ? "首次登录或管理员重置密码后，需要设置新密码。"
            : "密码修改后，其他登录会话将失效。"
        }
      />
      <form className="panel narrow" onSubmit={submit}>
        <ErrorBox text={error} />
        <Field label="原密码">
          <input
            name="old"
            type="password"
            autoComplete="current-password"
            required
          />
        </Field>
        <Field label="新密码" hint="至少 12 个字符，建议组合字母、数字和符号。">
          <input
            name="new"
            type="password"
            autoComplete="new-password"
            minLength={12}
            required
          />
        </Field>
        <Field label="再次输入新密码">
          <input
            name="confirm"
            type="password"
            autoComplete="new-password"
            minLength={12}
            required
          />
        </Field>
        <button className="primary" disabled={busy}>
          保存新密码
        </button>
      </form>
    </>
  );
}
function Dashboard() {
  const { user } = useApp(),
    { data, error, loading } = useData<Overview>("/overview", 10000);
  return (
    <>
      <Header
        title="订阅工作台"
        description="查看开通进度、套餐次数和最近的工作。"
        action={
          <NavLink className="primary" to="/create">
            ＋ 创建 SSO
          </NavLink>
        }
      />
      <ErrorBox text={error} />
      {loading ? (
        <p>正在读取…</p>
      ) : (
        data && (
          <>
            <div className="summary-strip">
              <div>
                <small>成功开通</small>
                <strong>
                  {data.subscribed || 0}
                  <em>个订阅</em>
                </strong>
              </div>
              <div>
                <small>正在处理</small>
                <strong>
                  {(data.states.queued || 0) + (data.states.running || 0)}
                </strong>
              </div>
              <div>
                <small>需要关注</small>
                <strong
                  className={
                    data.states.failed || data.states.needs_review
                      ? "warning-text"
                      : ""
                  }
                >
                  {(data.states.failed || 0) + (data.states.needs_review || 0)}
                </strong>
              </div>
              <div>
                <small>{user.role === "admin" ? "平台用户" : "创建记录"}</small>
                <strong>
                  {user.role === "admin" ? data.members : data.total}
                </strong>
              </div>
            </div>
            <div className="lifecycle-totals">
              <NavLink to="/sso?status=cancelled">
                <span>累计取消订阅</span>
                <strong>{data.cancelled_subscriptions || 0}</strong>
                <small>查看记录 →</small>
              </NavLink>
              <NavLink to="/sso?status=deleted">
                <span>累计删除 SSO</span>
                <strong>{data.deleted_sso || 0}</strong>
                <small>查看记录 →</small>
              </NavLink>
              <p>
                按用户记录统计，含已取消续订。取消或删除后，原套餐、订阅时间与累计开通次数保留。
              </p>
            </div>
            <section className="panel">
              <div className="section-heading">
                <div>
                  <h2>套餐开通次数</h2>
                  <p>每种套餐独立计算，重置后历史仍然保留。</p>
                </div>
                <NavLink to={user.role === "admin" ? "/users" : "/counts"}>
                  {user.role === "admin"
                    ? "设置子用户权限与次数 →"
                    : "查看明细 →"}
                </NavLink>
              </div>
              {user.role === "admin" ? (
                <AdminCounterTable summary={data.member_summary} />
              ) : data.counters.length ? (
                <CounterTable counters={data.counters} />
              ) : (
                <Empty>管理员尚未设置套餐开通次数，请联系管理员。</Empty>
              )}
            </section>
            {user.role === "admin" && (
              <section className="panel backup-panel">
                <div className="backup-symbol">↥</div>
                <div>
                  <h2>每小时数据备份</h2>
                  <p>
                    {data.backup?.status === "ok"
                      ? `最近成功：${date(data.backup.completed_at)}`
                      : data.backup?.status === "failed"
                        ? "最近备份失败，请检查服务器备份任务。"
                        : data.backup?.status === "stale"
                          ? `已超过 90 分钟没有新备份。最近成功：${date(data.backup.completed_at)}`
                          : "备份尚未完成配置或首次运行。"}
                  </p>
                  <small>
                    保存账号、订阅、次数与重置记录，以及恢复所需配置。
                  </small>
                </div>
                <span
                  className={`badge ${data.backup?.status === "ok" ? "completed" : "needs_review"}`}
                >
                  {data.backup?.status === "ok" ? "备份正常" : "需要关注"}
                </span>
              </section>
            )}
          </>
        )
      )}
    </>
  );
}
function CounterTable({
  counters,
  action,
}: {
  counters: Counter[];
  action?: (c: Counter) => ReactNode;
}) {
  const { user } = useApp();
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {user.role === "admin" && <th>子用户</th>}
            <th>套餐</th>
            <th>本轮开通 / 上限</th>
            <th>处理中</th>
            <th>历史累计</th>
            <th>当前轮次</th>
            {action && <th>操作</th>}
          </tr>
        </thead>
        <tbody>
          {counters.map((c) => (
            <tr key={c.id}>
              {user.role === "admin" && <td>{c.username}</td>}
              <td>
                <strong>{c.plan_name}</strong>
              </td>
              <td>
                <div className="usage-cell">
                  <span>
                    <b>{c.used_count}</b> / {c.limit_count} 次
                  </span>
                  <progress
                    aria-label={`${c.plan_name}已用次数`}
                    value={c.used_count}
                    max={Math.max(1, c.limit_count)}
                  />
                </div>
              </td>
              <td>{c.pending_count}</td>
              <td className="mono">{c.lifetime_count} 次</td>
              <td>第 {c.cycle_number} 轮</td>
              {action && <td>{action(c)}</td>}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AdminCounterTable({ summary }: { summary?: MemberSummary }) {
  const [history, setHistory] = useState<{
    user: MemberSummaryRow;
    plan: number;
  } | null>(null);
  if (!summary?.users.length)
    return <Empty>创建子用户后，为每种套餐设置开通次数。</Empty>;
  return (
    <>
      <div className="table-wrap">
        <table className="admin-counter-table">
          <thead>
            <tr>
              <th>用户</th>
              <th>SSO 用户</th>
              {summary.plans.map((p) => (
                <th key={p.id}>{p.name}</th>
              ))}
              <th>处理中</th>
              <th>管理</th>
            </tr>
          </thead>
          <tbody>
            {summary.users.map((u) => (
              <tr key={u.id}>
                <td className="member-label">
                  <strong>{u.display_name}</strong>
                  <small>{u.username}</small>
                  <small>
                    {u.role === "admin" ? "管理员" : "普通用户"}
                    {!u.active ? " · 已停用" : ""}
                  </small>
                </td>
                <td>
                  <NavLink
                    className="sso-count-link"
                    to={`/sso?owner_id=${u.id}`}
                  >
                    {u.sso_active}
                    <small>当前用户</small>
                  </NavLink>
                  <small>历史 {u.sso_total} 名</small>
                  <NavLink
                    className="lifecycle-count-link"
                    to={`/sso?owner_id=${u.id}&status=deleted`}
                  >
                    已删除 {u.deleted_sso}
                  </NavLink>
                  <NavLink
                    className="lifecycle-count-link"
                    to={`/sso?owner_id=${u.id}&status=cancelled`}
                  >
                    取消订阅 {u.cancelled_subscriptions}
                  </NavLink>
                </td>
                {summary.plans.map((p) => {
                  const c = u.counters.find((x) => x.plan_id === p.id);
                  return (
                    <td key={p.id} className="plan-summary-cell">
                      <span className="plan-current">
                        {u.role === "admin" ? (
                          <b>不限</b>
                        ) : c ? (
                          <>
                            <b>{c.used_count}</b>
                            <span> / {c.limit_count}</span>
                          </>
                        ) : (
                          <span className="muted">未设置</span>
                        )}
                      </span>
                      <button
                        className="plan-history-link"
                        aria-label={`查看 ${u.username} 的 ${p.name} 历史`}
                        onClick={() => setHistory({ user: u, plan: p.id })}
                      >
                        累计 {c?.lifetime_count || 0} 次 ↗
                      </button>
                      <small>
                        {u.role === "member"
                          ? `第 ${c?.cycle_number || 1} 轮 · `
                          : ""}
                        处理中 {c?.pending_count || 0}
                      </small>
                    </td>
                  );
                })}
                <td>
                  <span
                    className={u.pending_tasks ? "pending-number" : "muted"}
                  >
                    {u.pending_tasks}
                  </span>
                </td>
                <td>
                  <NavLink to={`/users?edit=${u.id}`}>权限与次数</NavLink>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {history && (
        <MemberPlanHistory
          key={`${history.user.id}:${history.plan}`}
          user={history.user}
          plans={summary.plans}
          initialPlan={history.plan}
          onClose={() => setHistory(null)}
        />
      )}
    </>
  );
}

function MemberPlanHistory({
  user,
  plans,
  initialPlan,
  onClose,
}: {
  user: MemberSummaryRow;
  plans: MemberSummary["plans"];
  initialPlan: number;
  onClose: () => void;
}) {
  const [plan, setPlan] = useState(initialPlan),
    [kind, setKind] = useState("subscriptions"),
    [page, setPage] = useState(1);
  const history = useData<Page<PlanHistoryItem>>(
    `/admin/users/${user.id}/plan-history?plan_id=${plan}&kind=${kind}&page=${page}`,
  );
  const counter = user.counters.find((c) => c.plan_id === plan);
  return (
    <Modal title={`${user.username} · 套餐历史`} onClose={onClose}>
      <Field label="套餐">
        <SearchableSelect aria-label="套餐"
          value={plan}
          onChange={(e) => {
            setPlan(Number(e.target.value));
            setPage(1);
          }}
        >
          {plans.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </SearchableSelect>
      </Field>
      <p className="info-note">
        {user.role === "admin"
          ? "管理员不限次数"
          : `本轮 ${counter?.used_count || 0} / ${counter?.limit_count || 0} 次 · 第 ${counter?.cycle_number || 1} 轮`}{" "}
        · 历史累计 {counter?.lifetime_count || 0} 次 · 处理中{" "}
        {counter?.pending_count || 0}
      </p>
      <div className="tabs">
        {[
          ["subscriptions", "开通 / 变更记录"],
          ["resets", "重置记录"],
        ].map(([value, label]) => (
          <button
            key={value}
            className={kind === value ? "active" : ""}
            onClick={() => {
              setKind(value);
              setPage(1);
            }}
          >
            {label}
          </button>
        ))}
      </div>
      <ErrorBox text={history.error} />
      {history.data?.items.length ? (
        <div className="member-history-list">
          {history.data.items.map((r) => (
            <article key={`${r.event_kind || kind}:${r.id}`}>
              <div>
                <strong>
                  {kind === "subscriptions"
                    ? r.username
                    : `第 ${r.cycle_number} 轮重置`}
                </strong>
                <small>{date(planHistoryTime(r))}</small>
              </div>
              {kind === "subscriptions" ? (
                <p>
                  {r.event_kind === "plan_change" ? <>{r.from_plan_name || "原套餐"} → {r.plan_name} · 套餐变更{r.direction ? ` · ${planChangeDirection[r.direction]}` : ""}</> : r.event_kind === "group_activation" ? <>{r.plan_name} · 原生分组授权</> : <>{r.plan_name} · 首次开通</>} ·{" "}
                  {r.cycle_number ? `第 ${r.cycle_number} 轮` : "管理员不限次数"} ·{" "}
                  {r.event_kind === "plan_change" ? "已生效" : subscriptionStatus(r)}
                  {r.sso_deleted_at ? " · SSO 已删除" : ""}
                  {r.cancelled_at && (
                    <small>取消时间：{date(r.cancelled_at)}</small>
                  )}
                  {r.sso_deleted_at && (
                    <small>删除时间：{date(r.sso_deleted_at)}</small>
                  )}
                </p>
              ) : (
                <>
                  <p>
                    该轮开通 {r.used_count} / {r.previous_limit} 次 → 新上限{" "}
                    {r.new_limit} 次
                  </p>
                  <small>
                    {r.actor_name} · {r.reason}
                  </small>
                </>
              )}
            </article>
          ))}
        </div>
      ) : (
        <Empty>
          {history.loading
            ? "正在读取历史…"
            : kind === "subscriptions"
              ? "该套餐暂无成功开通或生效变更记录。"
              : "该套餐暂无重置记录。"}
        </Empty>
      )}
      <Pager
        page={page}
        total={history.data?.total || 0}
        pageSize={20}
        onPage={setPage}
      />
    </Modal>
  );
}
function LegacyCreate() {
  const [params] = useSearchParams();
  const batchId = params.get("batch_id");
  return (
    <Navigate
      to={batchId ? `/batch-status?batch_id=${batchId}` : "/create?mode=list"}
      replace
    />
  );
}
const batchKind = {
  sso: "仅创建 SSO",
  subscribed: "创建 SSO 并订阅 Kiro",
  subscribe_existing: "为已有 SSO 订阅 Kiro",
};
const batchState: Record<string, string> = {
  ...stateName,
  running: "处理中",
  completed: "已完成",
  failed: "处理失败",
};

function sequenceRows(pattern: string, emailTemplate: string) {
  const match = pattern
    .trim()
    .match(/^([a-zA-Z0-9_.-]{1,60})-(\d{1,7})-(\d{1,7})$/);
  if (!match) return { items: [], error: "格式示例：member-01-10" };
  const first = Number(match[2]),
    last = Number(match[3]);
  if (first < 1 || last < first || last > 1000000 || last - first + 1 > 100)
    return {
      items: [],
      error: "起始编号至少为 1，每批 1–100 个，结束编号不超过 1000000。",
    };
  return {
    items: Array.from({ length: last - first + 1 }, (_, i) => ({
      username: `${match[1]}-${first + i}`,
      email: emailTemplate
        .trim()
        .split("{n}")
        .join(String(first + i)),
    })),
    error: "",
  };
}
function CreateSso() {
  const { user } = useApp();
  const groups = useData<GroupItem[]>("/groups", 4000);
  const accounts = useData<Account[]>("/accounts"),
    history = useData<BatchInfo[]>("/batches", 5000);
  const [params, setParams] = useSearchParams();
  const [mode, setMode] = useState(
      params.get("mode") === "list" ? "list" : "single",
    ),
    [username, setUsername] = useState(""),
    [email, setEmail] = useState(""),
    [autoExport, setAutoExport] = useState(false),
    [accountId, setAccountId] = useState(params.get("account_id") || ""),
    [groupChoice, setGroupChoice] = useState(params.get("group_id") || ""),
    [newGroupName, setNewGroupName] = useState(""),
    [rows, setRows] = useState(""),
    [pattern, setPattern] = useState(""),
    [emailTemplate, setEmailTemplate] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const storageKey = `kiro-sso-creation:${user.id}`;
  const [pending, setPending] = useState<SsoCreationIntent | null>(() => {
    try { return JSON.parse(sessionStorage.getItem(storageKey) || "null"); } catch { return null; }
  });
  const [savedGroup, setSavedGroup] = useState<SsoCreationIntent["group"]>();
  const availableGroups = ownedCreationGroups(groups.data || [], user.id, Number(accountId));
  const joinedGroup = availableGroups.find(group => group.id === groupChoice);
  function remember(next: SsoCreationIntent | null) {
    if (next) sessionStorage.setItem(storageKey, JSON.stringify(next));
    else sessionStorage.removeItem(storageKey);
    setPending(next);
  }
  async function execute(intent: SsoCreationIntent) {
    setBusy(true);
    setError("");
    try {
      const outcome = await runRecoverableSubmission(intent, (path, body) => api(path, "POST", body), remember,
        (post, checkpoint) => runSsoCreation(intent, post, checkpoint));
      if (outcome.state === "accepted") {
        setParams({ batch_id: outcome.result.id });
        history.refresh();
        return;
      }
      setError(outcome.error.message);
      if (outcome.state === "rejected") {
        const saved = outcome.intent;
        const first = saved.body.items?.[0];
        setAccountId(String(saved.body.aws_account_id));
        setAutoExport(saved.body.export_credentials);
        setMode(saved.body.sequence ? "sequence" : saved.body.items?.length === 1 ? "single" : "list");
        setUsername(first?.username || "");
        setEmail(first?.email || "");
        setRows((saved.body.items || []).map(r => r.email ? `${r.username},${r.email}` : r.username).join("\n"));
        setPattern(saved.body.sequence?.pattern || "");
        setEmailTemplate(saved.body.sequence?.email_template || "");
        setGroupChoice(saved.group?.id || saved.body.group_id || (saved.group ? "__new__" : ""));
        setNewGroupName(saved.group?.body.name || "");
        setSavedGroup(saved.group?.id ? saved.group : undefined);
        groups.refresh();
        history.refresh();
      }
    } finally { setBusy(false); }
  }
  const lines = rows.split(/\r?\n/).filter((s) => s.trim());
  const sequence = sequenceRows(pattern, emailTemplate);
  const total =
    mode === "single"
      ? 1
      : mode === "sequence"
        ? sequence.items.length
        : lines.length;
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    const items = [];
    if (mode === "single") {
      items.push({ username: username.trim(), email: email.trim() || null });
    } else if (mode === "list") {
      for (const [index, line] of lines.entries()) {
        const cells = line.split(/[,，\t]/).map((s) => s.trim());
        if (
          cells.length > 2 ||
          !/^[a-zA-Z0-9_.-]{2,70}$/.test(cells[0]) ||
          (cells[1] && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cells[1]))
        ) {
          setError(
            `第 ${index + 1} 行格式有误，请填写「用户名」或「用户名,邮箱」。`,
          );
          return;
        }
        items.push({ username: cells[0], email: cells[1] || null });
      }
    } else if (
      sequence.error ||
      sequence.items.some(
        (r) => r.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(r.email),
      )
    ) {
      setError(sequence.error || "邮箱模板格式不正确，可留空自动生成。");
      return;
    }
    const emails = (mode === "sequence" ? sequence.items : items)
      .map((r) => r.email?.toLowerCase())
      .filter(Boolean);
    if (new Set(emails).size !== emails.length) {
      setError("AWS 要求邮箱唯一：请使用含 {n} 的邮箱模板，或留空自动生成。");
      return;
    }
    if (total < 1 || total > 100) {
      setError("每批请填写 1–100 个用户。");
      return;
    }
    const body: SsoCreationBody = {
      kind: "sso",
      aws_account_id: Number(accountId),
      export_credentials: autoExport,
      ...(groupChoice && groupChoice !== "__new__" ? { group_id: groupChoice } : {}),
      ...(mode === "sequence"
        ? {
            sequence: {
              pattern: pattern.trim(),
              email_template: emailTemplate.trim(),
            },
          }
        : { items }),
    };
    try {
      if (groupChoice && groupChoice !== "__new__" && !availableGroups.some(g => g.id === groupChoice))
        throw new Error("请选择当前创建者在该 AWS 账号下可用的分组。");
      const intent = createSsoIntent(body, groupChoice === "__new__" ? { name: newGroupName, aws_account_id: Number(accountId) } : undefined);
      await execute(intent);
    } catch (e) { setError((e as Error).message); }
  }

  if (params.get("batch_id"))
    return (
      <Navigate
        to={`/batch-status?batch_id=${params.get("batch_id")}`}
        replace
      />
    );
  return (
    <>
      <Header
        title="创建 SSO 用户"
        description="单个创建、用户列表或按编号批量生成，每批最多 100 人。单独创建 SSO 免费；加入生效中的原生分组会自动授予付费套餐并计次。"
        action={
          <NavLink className="primary" to="/subscribe">
            批量订阅 Kiro →
          </NavLink>
        }
      />
      <div className="create-layout">
        <form className="panel" onSubmit={submit}>
          <ErrorBox text={error || accounts.error || groups.error} />
          {pending && <div className="info-note group-recovery" role="status"><strong>上次创建请求的结果尚待确认。</strong><p>{pending.group ? `分组：${pending.group.body.name}。` : ""}将继续原批次，避免重复创建分组或 SSO。刷新页面后仍可继续。</p><button type="button" className="secondary" disabled={busy} onClick={() => void execute(pending)}>{busy ? "正在确认…" : "继续上次创建"}</button>{pending.group?.id && <NavLink to={`/groups?group_id=${encodeURIComponent(pending.group.id)}`}>查看分组进度</NavLink>}</div>}
          {savedGroup?.id && <p className="info-note">分组“{savedGroup.body.name}”已有保存的创建记录，本次 SSO 请求未受理。<NavLink to={`/groups?group_id=${encodeURIComponent(savedGroup.id)}`}>查看分组进度</NavLink>；修改输入后可继续使用该分组。</p>}
          <fieldset className="resource-fields" disabled={busy || !!pending}>
          <Field label="AWS 账号">
            <SearchableSelect aria-label="AWS 账号"
              required
              value={accountId}
              onChange={(e) => { setAccountId(e.target.value); setGroupChoice(""); }}
              disabled={busy}
            >
              <option value="">请选择已绑定的 AWS 账号</option>
              {accounts.data
                ?.filter((a) => a.active)
                .map((a) => (
                  <option key={a.id} value={a.id}>
                    {accountLabel(a)} · {a.region}
                  </option>
                ))}
            </SearchableSelect>
          </Field>
          <Field label="加入分组" hint="分组属于同一 AWS 账号和当前创建者；加入原生订阅生效中的分组会自动获得套餐并消耗次数。">
            <SearchableSelect aria-label="加入分组" value={groupChoice} onChange={e => setGroupChoice(e.target.value)} disabled={!accountId}>
              <option value="">不加入分组</option>
              {availableGroups.map(group => <option key={group.id} value={group.id}>{group.name}{group.state === "creating" ? "（正在创建）" : ""}</option>)}
              <option value="__new__">创建新分组</option>
            </SearchableSelect>
          </Field>
          <GroupJoinNotice group={joinedGroup} count={total} />
          {activeNativeGroup(joinedGroup) && <label className="check-line" key={joinedGroup?.native_subscription?.id}><input type="checkbox" required />我已确认加入分组将自动获得付费套餐并消耗次数</label>}
          {groupChoice === "__new__" && <Field label="新分组名称" hint="先创建分组，再提交本批 SSO；分组尚未就绪时，SSO 任务会等待。"><input required maxLength={1024} value={newGroupName} onChange={e => setNewGroupName(e.target.value)} placeholder="例如：研发团队" /></Field>}
          <div className="creation-modes" aria-label="创建方式">
            {[
              ["single", "单个创建"],
              ["list", "批量列表"],
              ["sequence", "按编号创建"],
            ].map(([value, label]) => (
              <button
                type="button"
                key={value}
                aria-pressed={mode === value}
                className={mode === value ? "active" : ""}
                disabled={busy}
                onClick={() => setMode(value)}
              >
                {label}
              </button>
            ))}
          </div>
          {mode === "single" ? (
            <>
              <Field
                label="用户名"
                hint="字母、数字、点、横线或下划线；系统追加短编号保证唯一。"
              >
                <input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  minLength={2}
                  maxLength={70}
                  pattern="[a-zA-Z0-9_.\-]+"
                  placeholder="例如 team-member"
                  required
                  disabled={busy}
                />
              </Field>
              <Field
                label="用户邮箱（可选）"
                hint="留空用用户名和随机字母域名生成邮箱；需要接收邮件时填写真实邮箱。"
              >
                <input
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  type="email"
                  placeholder="留空自动生成，或填写已有邮箱"
                  disabled={busy}
                />
              </Field>
            </>
          ) : mode === "list" ? (
            <Field
              label="用户列表"
              hint="每行填写「用户名」或「用户名,邮箱」；邮箱留空自动生成，用户名追加随机后缀。"
            >
              <textarea
                required
                rows={8}
                value={rows}
                onChange={(e) => setRows(e.target.value)}
                placeholder={"user01\nuser02,user02@example.com"}
                disabled={busy}
                spellCheck={false}
              />
            </Field>
          ) : (
            <>
              <Field
                label="编号范围"
                hint="member-01-10 → member-1 至 member-10；此模式不追加随机后缀。"
              >
                <input
                  value={pattern}
                  onChange={(e) => setPattern(e.target.value)}
                  placeholder="member-01-10"
                  required
                  disabled={busy}
                />
              </Field>
              <Field
                label="邮箱模板（可选）"
                hint="留空从 a–z 中随机组合 8–12 个字母作为域名；填写时用 {n} 替换编号。随机地址不保证能收邮件。"
              >
                <input
                  value={emailTemplate}
                  onChange={(e) => setEmailTemplate(e.target.value)}
                  placeholder="留空自动生成，或 member+{n}@example.com"
                  disabled={busy}
                />
              </Field>
              {pattern && (
                <p className="muted">
                  {sequence.error ||
                    `将生成 ${total} 名用户：${sequence.items[0].username} 至 ${sequence.items[total - 1].username}`}
                </p>
              )}
              {sequence.items.length > 0 && (
                <details className="advanced">
                  <summary>预览生成用户（{total} 名）</summary>
                  <div className="sequence-preview">
                    {sequence.items.map((r) => (
                      <div key={r.username}>
                        <strong>{r.username}</strong>
                        <small>
                          {r.email ||
                            `${r.username}@随机字母.com（提交后生成）`}
                        </small>
                      </div>
                    ))}
                  </div>
                </details>
              )}
            </>
          )}
          <label className="check-line export-option">
            <input
              type="checkbox"
              checked={autoExport}
              onChange={(e) => setAutoExport(e.target.checked)}
              disabled={busy}
            />
            <span>
              创建完成后自动导出登录信息 CSV
              <small>
                包含登录地址、用户名与一次性密码；也可稍后在 SSO 用户目录导出。
              </small>
            </span>
          </label>
          <p className="muted">
            本批 {total} / 100 名用户。创建结果会逐项保存。
          </p>
          <button
            className="primary"
            disabled={busy || total < 1 || total > 100}
          >
            {busy
              ? "正在提交…"
              : total
                ? `创建 ${total} 名 SSO 用户`
                : "批量创建 SSO 用户"}
          </button>
          </fieldset>
        </form>
        <aside className="panel count-aside">
          <h2>SSO 与 Kiro 分开管理</h2>
          <p>
            单独创建 SSO 会生成身份、登录地址和一次性密码。加入生效中的原生分组时会同时获得该组套餐，按创建者对应套餐次数计数；其他用户可在订阅页面按人开通。
          </p>
          <p>
            按编号生成会使用准确的用户名，例如
            member-1。编号已被使用时会提示调整范围。
          </p>
          <NavLink to="/subscribe">打开 Kiro 订阅页面 →</NavLink>
        </aside>
      </div>
      <section className="panel batch-history">
        <h2>最近批次</h2>
        <ErrorBox text={history.error} />
        {history.data?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>创建时间</th>
                  <th>类型</th>
                  <th>进度</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {history.data.map((b) => (
                  <tr key={b.id}>
                    <td>{date(b.created_at)}</td>
                    <td>{batchKind[b.kind]}</td>
                    <td>
                      {b.states.completed} / {b.total} 已完成
                      {b.states.failed + b.states.needs_review > 0 && (
                        <small>
                          {b.states.failed + b.states.needs_review} 项需要关注
                        </small>
                      )}
                    </td>
                    <td>
                      <button
                        className="text-button"
                        onClick={() => setParams({ batch_id: b.id })}
                      >
                        查看进度
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty>暂无批次。</Empty>
        )}
      </section>
    </>
  );
}

function BatchStatusPage() {
  const [params] = useSearchParams();
  const id = params.get("batch_id");
  if (!id) return <Navigate to="/records" replace />;
  return (
    <>
      <Header
        title="任务进度"
        description="每个用户独立保存处理结果。刷新或重新登录后仍可查看。"
        action={
          <NavLink className="secondary" to="/subscribe">
            开通 Kiro 订阅 →
          </NavLink>
        }
      />
      <BatchProgress id={id} />
    </>
  );
}

function BatchProgress({ id }: { id: string }) {
  const section = useRef<HTMLElement>(null);
  useEffect(() => {
    section.current?.scrollIntoView({ block: "start" });
  }, [id]);
  const batch = useData<BatchInfo>(`/batches/${id}`, 2500),
    { notify, user } = useApp();
  const [busy, setBusy] = useState("");
  const [exporting, setExporting] = useState(false),
    [exportMessage, setExportMessage] = useState("");
  const attemptedExport = useRef("");
  async function exportBatch(format: LoginExportFormat = "csv") {
    setExporting(true);
    try {
      const count = await downloadCsv({ batch_id: id, format });
      const message = `已发起 ${count} 名用户的 ${format.toUpperCase()} 下载；若浏览器未开始下载，可再次点击导出。`;
      setExportMessage(message);
      notify(`已导出 ${count} 名用户的登录信息`);
      return true;
    } catch (e) {
      setExportMessage((e as Error).message);
      notify((e as Error).message, true);
      return false;
    } finally {
      setExporting(false);
    }
  }
  useEffect(() => {
    const b = batch.data;
    if (
      !b ||
      !b.export_credentials ||
      b.owner_id !== user.id ||
      b.states.queued + b.states.running > 0
    )
      return;
    const ids = b.items
      ?.filter((r) => r.has_credentials)
      .map((r) => r.id)
      .sort()
      .join(",");
    if (!ids) return;
    const key = `sso-csv:${user.id}:${id}`;
    const signature = `${key}:${ids}`;
    if (attemptedExport.current === signature) return;
    try {
      if (sessionStorage.getItem(key) === ids) return;
    } catch {
      /* downloads still work without storage */
    }
    attemptedExport.current = signature;
    void exportBatch().then((ok) => {
      if (ok) {
        try {
          sessionStorage.setItem(key, ids);
        } catch {
          /* optional deduplication */
        }
      }
    });
  }, [batch.data, id, user.id]);
  async function retry(recordId: string) {
    setBusy(recordId);
    try {
      await api(`/subscriptions/${recordId}/retry`, "POST");
      batch.refresh();
      notify("已提交继续处理");
    } catch (e) {
      notify((e as Error).message, true);
    } finally {
      setBusy("");
    }
  }
  const b = batch.data;
  return (
    <section ref={section} className="panel batch-progress">
      <div className="section-heading">
        <div>
          <h2>批次进度{b && ` · ${batchKind[b.kind]}`}</h2>
          <p>
            {b &&
              `${b.states.completed} / ${b.total} 已完成 · ${b.states.queued + b.states.running} 处理中 · ${b.states.failed + b.states.needs_review} 需要关注`}
          </p>
        </div>
        <div className="row-actions">
          <LoginExportMenu ariaLabel="导出批次登录信息" label={exporting ? "正在导出…" : "导出"}
            disabled={exporting || !batch.data?.items?.some(r => r.has_credentials)}
            scopes={[{ onExport: format => { void exportBatch(format); } }]} />
          <NavLink to="/sso">查看用户与登录信息 →</NavLink>
        </div>
      </div>
      {batch.data?.export_credentials && (
        <p className="muted">
          已选择完成后自动导出；仅包含当前有可用登录信息的用户。
        </p>
      )}
      {exportMessage && (
        <p className="info-note" role="status">
          {exportMessage}
        </p>
      )}
      <ErrorBox text={batch.error} />
      {b && (
        <>
          <progress
            aria-label="批次完成进度"
            value={b.states.completed + b.states.failed + b.states.needs_review}
            max={b.total}
          />
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>用户</th>
                  <th>结果</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {b.items?.map((item) => (
                  <tr key={item.id}>
                    <td>
                      <strong className="mono">{item.username}</strong>
                      <small>{item.email}</small>
                    </td>
                    <td>
                      <span className={`badge ${item.state}`}>
                        {batchState[item.state]}
                      </span>
                      {item.error && (
                        <small className="warning-text">{item.error}</small>
                      )}
                    </td>
                    <td>
                      {["failed", "needs_review"].includes(item.state) ? (
                        <button
                          className="text-button"
                          disabled={busy === item.id}
                          onClick={() => retry(item.id)}
                        >
                          {item.state === "needs_review"
                            ? "核对结果"
                            : "继续处理"}
                        </button>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}

function Records({
  directory = false,
  subscribeMode = false,
}: {
  directory?: boolean;
  subscribeMode?: boolean;
}) {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const ownerFilter = params.get("owner_id");
  const groupFilter = params.get("group_id");
  const accountFilter = params.get("aws_account_id");
  const accounts = useData<Account[]>("/accounts");
  const groups = useData<GroupItem[]>("/groups", 4000);
  const plans = useData<Plan[]>("/plans");
  const selectionRows = useRef(new Map<string, RecordItem>());
  const selectionRequest = useRef(0);
  const [selected, setSelected] = useState<string[]>([]),
    [selecting, setSelecting] = useState(false),
    [bulk, setBulk] = useState(false),
    [bulkError, setBulkError] = useState("");
  const [passwordOpen, setPasswordOpen] = useState(params.has("password_batch") || params.has("passwords"));
  useEffect(() => {
    if (params.has("password_batch") || params.has("passwords")) setPasswordOpen(true);
  }, [params]);
  const bulkIntent = useRef({ payload: "", key: "" });
  const eligible = canSubscribeRecord;
  const exportable = (r: RecordItem) =>
    r.has_password && !r.sso_deleted_at && !r.operation && !r.operation_pending;
  const selectable = (r: RecordItem) => !subscribeMode || eligible(r);
  const [page, setPage] = useState(1),
    [taskFilter, setTaskFilter] = useState(""),
    [q, setQ] = useState(""),
    [search, setSearch] = useState("");
  const filter = directory
    ? (params.get("status") ?? (subscribeMode ? "unsubscribed" : ""))
    : taskFilter;
  const scope = {
    ...(directory ? { status: filter } : { state: filter }), q: search,
    ...(ownerFilter ? { owner_id: Number(ownerFilter) } : {}),
    ...(accountFilter ? { aws_account_id: Number(accountFilter) } : {}),
    ...(groupFilter ? { group_id: groupFilter } : {}),
  };
  const scopeQuery = recordQuery(scope);
  const selectedScope = useRef(scopeQuery);
  const { data, error, refresh } = useData<Page<RecordItem>>(
    `/${directory ? "sso-users" : "subscriptions"}?page=${page}&${scopeQuery}`,
    4000,
  );
  const [credential, setCredential] = useState<LoginCredential | null>(null),
    [busy, setBusy] = useState(""),
    [detail, setDetail] = useState<RecordItem | null>(null);
  const { user, notify } = useApp();
  const [cancelOpen, setCancelOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const deletionScope = `${directory}:${subscribeMode}:${scopeQuery}:${JSON.stringify([user.id, user.role, user.active, user.account_ids, accounts.data?.map(account => [account.id, account.active, account.deleted_at, account.proxy_id, account.proxy_status])])}`;
  const deletion = useCascadeAdmission(user.id, deletionScope);
  function deletionAccepted(_batch: CascadeBatch) { setDeleteOpen(false); setSelected([]); void refresh(); notify("级联删除已受理，可查看取消订阅与删除的逐步进度"); }
  const [latestLifecycleBatch, setLatestLifecycleBatch] = useState<LifecycleBatch | null>(null);
  const cancellation = useLifecycleAdmission(user.id, `${directory}:${subscribeMode}:${scopeQuery}`);
  function lifecycleAccepted(batch: LifecycleBatch) { setLatestLifecycleBatch(batch); setCancelOpen(false); setSelected([]); void refresh(); notify("订阅操作已受理，可查看逐项进度"); }
  useEffect(() => {
    selectedScope.current = scopeQuery;
    selectionRequest.current += 1;
    selectionRows.current.clear();
    setSelected([]);
    setSelecting(false);
    setPage(1);
    setBulk(false);
    setCancelOpen(false);
    setDeleteOpen(false);
    return () => {
      selectionRequest.current += 1;
    };
  }, [scopeQuery, subscribeMode, directory, user.id]);
  useEffect(() => {
    data?.items.forEach((r) => selectionRows.current.set(r.id, r));
  }, [data]);
  const selectedRecords = (selectedScope.current === scopeQuery ? selected : []).map(
    (id) =>
      data?.items.find((r) => r.id === id) || selectionRows.current.get(id),
  );
  const subscribableCount = selectedRecords.filter(
    (r) => r && eligible(r),
  ).length;
  const exportableCount = selectedRecords.filter(
    (r) => r && exportable(r),
  ).length;
  const canSubscribeSelection =
    selected.length > 0 && subscribableCount === selected.length;
  const canExportSelection =
    selected.length > 0 && exportableCount === selected.length;
  const authRecords = selectedRecords.filter((record): record is RecordItem => !!record);
  const canConvertSelection = selected.length > 0 && authRecords.length === selected.length && authRecords.every(record => canUseAuthRecord(record, user, "json_export"));
  const pageIds = data?.items.filter(selectable).map((r) => r.id) || [];
  const pageSelectedCount = pageIds.filter((id) =>
    selected.includes(id),
  ).length;
  const pageSelected =
    pageIds.length > 0 && pageSelectedCount === pageIds.length;
  const selectionBusy = selecting || busy === "bulk" || busy === "export" || cancellation.busy || deletion.busy;
  const canCancelSelection = selected.length > 0 && authRecords.length === selected.length && authRecords.every(canCancelRecord);
  const canDeleteSelection = selected.length > 0 && authRecords.length === selected.length && authRecords.every(record =>
    record.sso_user_id && !record.sso_deleted_at && !record.operation_pending && !record.operation && ["completed", "failed"].includes(record.state));
  function selectPage(checked: boolean) {
    data?.items.forEach((r) => selectionRows.current.set(r.id, r));
    if (checked) {
      const ids = [...new Set([...selected, ...pageIds])];
      setSelected(ids.slice(0, 100));
      if (ids.length > 100) notify("最多选择 100 名用户，已保留前 100 名。");
    } else {
      setSelected(selected.filter((id) => !pageIds.includes(id)));
    }
  }
  async function selectFiltered() {
    const requestId = ++selectionRequest.current;
    setSelecting(true);
    try {
      const result = await api<Page<RecordItem>>(
        `/sso-users?page_size=100&${scopeQuery}`,
      );
      if (requestId !== selectionRequest.current) return;
      result.items.forEach((r) => selectionRows.current.set(r.id, r));
      const ids = result.items.filter(selectable).map((r) => r.id);
      setSelected(ids);
      notify(
        result.total > 100
          ? `筛选结果共 ${result.total} 名，已从前 100 名中选中 ${ids.length} 名用户`
          : `已选中筛选结果中的 ${ids.length} 名用户`,
      );
    } catch (e) {
      if (requestId === selectionRequest.current)
        notify((e as Error).message, true);
    } finally {
      if (requestId === selectionRequest.current) setSelecting(false);
    }
  }
  async function exportRecords(ids?: string[], format: LoginExportFormat = "csv") {
    setBusy("export");
    try {
      const count = await downloadLogins(loginExportBody(scope, ids, format));
      notify(`已导出 ${count} 名 SSO 用户的登录信息 ${format.toUpperCase()}`);
    } catch (e) {
      notify((e as Error).message, true);
    } finally {
      setBusy("");
    }
  }
  async function subscribeSelected(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy("bulk");
    setBulkError("");
    const form = new FormData(e.currentTarget);
    const body = subscriptionRequest(selected, Number(form.get("plan_id")), readSubscriptionPolicy(form), groupFilter || undefined);
    const payload = JSON.stringify(body);
    if (bulkIntent.current.payload !== payload)
      bulkIntent.current = { payload, key: crypto.randomUUID() };
    try {
      const batch = await api<BatchInfo>("/batches/subscribe", "POST", {
        ...body,
        request_key: bulkIntent.current.key,
      });
      navigate(`/batch-status?batch_id=${batch.id}`);
    } catch (e) {
      setBulkError((e as Error).message);
    } finally {
      setBusy("");
    }
  }
  async function view(r: RecordItem) {
    setBusy(r.id);
    try {
      setCredential(await api(`/subscriptions/${r.id}/credentials`, "POST"));
    } catch (e) {
      notify((e as Error).message, true);
    } finally {
      setBusy("");
    }
  }
  async function retry(r: RecordItem) {
    setBusy(r.id);
    try {
      await api(`/subscriptions/${r.id}/retry`, "POST");
      notify("已提交继续处理");
      refresh();
    } catch (e) {
      notify((e as Error).message, true);
    } finally {
      setBusy("");
    }
  }
  async function copy() {
    if (!credential) return;
    try {
      await navigator.clipboard.writeText(
        credentialText(credential),
      );
      notify("登录信息已复制");
    } catch {
      notify("浏览器不支持自动复制，请选中登录信息手动复制", true);
    }
  }
  return (
    <>
      <Header
        title={
          subscribeMode ? "开通 Kiro 订阅" : directory ? "SSO 用户" : "任务记录"
        }
        description={
          subscribeMode
            ? "按明确选择的 SSO 用户逐人开通个人订阅（USER），分组仅用于筛选用户。每名用户独立消耗创建者该套餐次数；原生分组订阅请前往 AWS 分组。"
            : directory
              ? "管理企业 Identity Center 用户，保留套餐绑定与订阅历史。"
              : user.role === "admin"
                ? "查看所有子用户的账号、开通结果与归属。"
                : "查看自己创建的账号、订阅状态和登录信息。"
        }
        action={
          <NavLink className="primary" to="/create">
            ＋ 创建 SSO
          </NavLink>
        }
      />
      <ErrorBox text={error || groups.error || accounts.error} />
      {ownerFilter && user.role === "admin" && (
        <p className="info-note">
          正在查看指定用户的记录。
          <button
            className="text-button"
            onClick={() => {
              setParams((old) => {
                const next = new URLSearchParams(old);
                next.delete("owner_id");
                return next;
              });
              setPage(1);
              setSelected([]);
            }}
          >
            显示全部创建者
          </button>
        </p>
      )}
      {directory && (
        <div className="selection-toolbar" aria-label="SSO 批量选择">
          <span aria-live="polite">
            已选 <strong>{selected.length}</strong> / 100 名 SSO 用户
          </span>
          <button
            className="secondary"
            disabled={selectionBusy || !pageIds.length}
            onClick={() => selectPage(!pageSelected)}
          >
            {pageSelected ? "取消本页选择" : "全选本页"}
          </button>
          <button
            className="secondary"
            disabled={selectionBusy || !data?.total}
            onClick={selectFiltered}
          >
            {selecting
              ? "正在选择…"
              : (data?.total || 0) > 100
                ? "选中筛选结果前 100 人"
                : "全选筛选结果"}
          </button>
          <button
            className="text-button"
            disabled={selectionBusy || !selected.length}
            onClick={() => setSelected([])}
          >
            清空选择
          </button>
          <small>翻页保留选择；更换筛选条件会清空。</small>
        </div>
      )}
      {directory && (
        <div className="bulk-toolbar">
          <button
            className="primary"
            disabled={!canSubscribeSelection || selectionBusy}
            onClick={() => {
              setBulkError("");
              setBulk(true);
            }}
          >
            批量订阅
          </button>
          {!subscribeMode && (
            <>
              <button className="danger" disabled={selectionBusy || !!cancellation.pending || !canCancelSelection} onClick={() => setCancelOpen(true)}>批量取消订阅</button>
              <button className="secondary" disabled={selectionBusy || !canConvertSelection}
                onClick={() => navigate("/json-export", { state: { records: authRecords.map(record => ({
                  id: record.id, username: record.username, owner_id: record.owner_id, account_name: record.account_name,
                  state: record.state, has_password: record.has_password, credential_state: record.credential_state,
                  sso_user_id: record.sso_user_id, sso_deleted_at: record.sso_deleted_at, operation_pending: record.operation_pending || !!record.operation, operation: null,
                })) } })}>前往 JSON 导出</button>
              <button className="secondary" disabled={selectionBusy} onClick={() => setPasswordOpen(true)}>批量改密 / 查看记录</button>
              <button className="danger" disabled={selectionBusy || !!deletion.pending || !canDeleteSelection} onClick={() => setDeleteOpen(true)}>删除所选 SSO</button>
              <LoginExportActions selected={selected} canExportSelection={canExportSelection} hasResults={!!data?.total} busy={selectionBusy} onExport={exportRecords} />
            </>
          )}
          <NavLink to="/create?mode=list">创建 SSO →</NavLink>
          {selected.length > 0 && (
            <span>
              所选用户中可订阅 {subscribableCount} 名
              {!subscribeMode && `，可导出 ${exportableCount} 名`}
              ；全部满足条件后可批量操作。
            </span>
          )}
        </div>
      )}
      {directory && !subscribeMode && <LifecycleRecovery admission={cancellation} onAccepted={lifecycleAccepted} />}
      {directory && !subscribeMode && <CascadeSubmissionRecovery admission={deletion} onAccepted={deletionAccepted} />}
      {directory && !subscribeMode && deleteOpen && <CascadeDialog key={deletionScope} actorId={user.id} scope={deletionScope} kind="sso" ids={selected} admission={deletion} close={() => setDeleteOpen(false)} onAccepted={deletionAccepted} />}
      {directory && !subscribeMode && <CascadeHistory actorId={user.id} scope={deletionScope} groupId={groupFilter || undefined} kind="sso" onChanged={() => void refresh()} />}
      {directory && !subscribeMode && (
        <p className="export-caption">
          CSV 和 TXT 包含登录地址、用户名、最新保存的密码和密码类型（一次性 / 永久）。密码状态待核对时仅导出待核对提示；用户自行改密后，已保存密码可能失效。
        </p>
      )}
      {directory && !subscribeMode && passwordOpen && <PasswordBatches key={`${user.id}:${scopeQuery}`} user={user} records={authRecords} sourceGroupId={groupFilter || undefined} notify={notify} onChanged={refresh} onClose={() => {
        setPasswordOpen(false);
        setParams(old => { const next = new URLSearchParams(old); next.delete("password_batch"); next.delete("passwords"); return next; });
      }} />}
      <section className="panel no-padding">
        <div className="table-toolbar">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setSearch(q);
              setPage(1);
            }}
          >
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              aria-label="搜索用户名、姓名或邮箱"
              placeholder="搜索用户名、姓名或邮箱"
            />
            <button className="secondary">搜索</button>
          </form>
          <SearchableSelect aria-label="按 AWS 账号筛选" value={accountFilter || ""} onChange={e => setParams(old => { const next = new URLSearchParams(old); if (e.target.value) next.set("aws_account_id", e.target.value); else next.delete("aws_account_id"); return next; })}>
            <option value="">全部 AWS 账号</option>{accounts.data?.map(account => <option key={account.id} value={account.id}>{accountLabel(account)}</option>)}
          </SearchableSelect>
          {directory && <SearchableSelect aria-label="按分组筛选" value={groupFilter || ""} onChange={e => setParams(old => { const next = new URLSearchParams(old); if (e.target.value) next.set("group_id", e.target.value); else next.delete("group_id"); return next; })}>
            <option value="">全部分组</option>{groups.data?.filter(group => !accountFilter || group.aws_account_id === Number(accountFilter) || group.id === groupFilter).map(group => <option key={group.id} value={group.id}>{group.name}{group.deleted_at ? "（历史）" : ""}</option>)}
          </SearchableSelect>}
          <SearchableSelect
            aria-label="按状态筛选"
            value={filter}
            onChange={(e) => {
              const value = e.target.value;
              if (directory)
                setParams((old) => {
                  const next = new URLSearchParams(old);
                  next.set("status", value);
                  return next;
                });
              else setTaskFilter(value);
              setPage(1);
            }}
          >
            <option value="">全部状态</option>
            {Object.entries(
              directory
                ? {
                    unsubscribed: "可开通订阅",
                    active: "SSO 存在",
                    cancelled: "取消订阅记录",
                    deleted: "SSO 已删除",
                    scheduled: "已设置定时停止",
                    schedule_attention: "定时停止需处理",
                  }
                : stateName,
            ).map(([k, v]) => (
              <option key={k} value={k}>
                {v}
              </option>
            ))}
          </SearchableSelect>
        </div>
        {data?.items.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  {directory && (
                    <th>
                      <input
                        type="checkbox"
                        aria-label={
                          subscribeMode
                            ? "选择本页未绑定套餐的 SSO"
                            : "全选本页 SSO 用户"
                        }
                        checked={pageSelected}
                        ref={(element) => {
                          if (element)
                            element.indeterminate =
                              pageSelectedCount > 0 && !pageSelected;
                        }}
                        disabled={selectionBusy || !pageIds.length}
                        onChange={(e) => selectPage(e.target.checked)}
                      />
                    </th>
                  )}
                  <th>账号</th>
                  <th>套餐 / AWS</th>
                  {user.role === "admin" && <th>创建者</th>}
                  <th>{directory ? "SSO / 订阅状态" : "开通 / 订阅状态"}</th>
                  <th>{directory ? "订阅 / 变更时间" : "创建时间"}</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((r) => (
                  <tr
                    key={r.id}
                    className={
                      directory && selected.includes(r.id)
                        ? "selected-record"
                        : undefined
                    }
                    aria-selected={
                      directory ? selected.includes(r.id) : undefined
                    }
                  >
                    {directory && (
                      <td>
                        <input
                          type="checkbox"
                          aria-label={`选择 ${r.username}`}
                          checked={selected.includes(r.id)}
                          disabled={
                            selectionBusy ||
                            !selectable(r) ||
                            (selected.length >= 100 && !selected.includes(r.id))
                          }
                          onChange={(e) =>
                            setSelected(
                              e.target.checked
                                ? [...selected, r.id]
                                : selected.filter((id) => id !== r.id),
                            )
                          }
                        />
                      </td>
                    )}
                    <td>
                      {r.internal_id && <small className="mono">内部 ID：{r.internal_id}</small>}
                      <strong className="mono">{r.username}</strong>
                      {directory && <small>{r.sso_display_name || "—"}</small>}
                      <small>{r.email}</small>
                      {r.group_id && <small><NavLink to={`/groups?group_id=${encodeURIComponent(r.group_id)}`}>{groups.data?.find(g => g.id === r.group_id)?.name || "所属分组"}</NavLink></small>}
                    </td>
                    <td>
                      <RecordPlanLabel record={r} directory={directory} />
                      <small>{r.account_name}</small>
                    </td>
                    {user.role === "admin" && <td>{r.owner_name}</td>}
                    <td>
                      {directory ? (
                        <span
                          className={`badge ${r.sso_deleted_at ? "failed" : "completed"}`}
                        >
                          {r.sso_deleted_at ? "SSO 已删除" : "SSO 存在"}
                        </span>
                      ) : r.provision_only && r.state === "completed" ? (
                        <span className="badge completed">SSO 已创建</span>
                      ) : (
                        <Badge state={r.state} />
                      )}
                      <small>{subscriptionStatus(r)}</small>
                      <RetryStatus value={r} />
                      {directory && <StopRuleSource record={r} group={groups.data?.find(g => g.id === r.group_id)} />}
                      {r.stop_schedule && r.stop_schedule.mode !== "none" && (
                        <small>
                          定时停止 · {stopState[r.stop_schedule.state]}
                        </small>
                      )}
                      {r.operation_pending && !r.operation && <small>有任务正在处理或待核对</small>}
                      {r.operation && (
                        <small>
                          {operationName[r.operation.kind]} ·{" "}
                          {authStateLabel[r.operation.state] || "处理中"}
                        </small>
                      )}
                      {r.error && !r.propagation_state && (
                        <button
                          className="error-link"
                          onClick={() => setDetail(r)}
                        >
                          查看原因
                        </button>
                      )}
                    </td>
                    <td className="date-cell">
                      {date(directory ? r.subscribed_at : r.created_at)}
                      {directory && r.cancelled_at && (
                        <small>取消：{date(r.cancelled_at)}</small>
                      )}
                      {directory && r.sso_deleted_at && (
                        <small>删除：{date(r.sso_deleted_at)}</small>
                      )}
                      {r.stop_schedule?.stop_at && (
                        <small>截止：{stopTime(r.stop_schedule.stop_at)}</small>
                      )}
                    </td>
                    <td>
                      <div className="row-actions">
                        {directory && eligible(r) && (
                          <button
                            className="text-button"
                            onClick={() => {
                              setSelected([r.id]);
                              setBulkError("");
                              setBulk(true);
                            }}
                          >
                            开通订阅
                          </button>
                        )}
                        <button
                          className="text-button"
                          onClick={() => setDetail(r)}
                        >
                          详情 / 管理
                        </button>
                        <button
                          className="text-button"
                          disabled={!r.has_password || !!r.sso_deleted_at || r.operation_pending || busy === r.id}
                          onClick={() => view(r)}
                        >
                          登录信息
                        </button>
                        {directory && !subscribeMode && (
                          <LoginExportMenu
                            className="text-button"
                            ariaLabel={`导出 ${r.username} 的登录信息`}
                            disabled={!exportable(r) || selectionBusy}
                            scopes={[{ onExport: format => { void exportRecords([r.id], format); } }]}
                          />
                        )}
                        {["failed", "needs_review"].includes(r.state) &&
                          !r.sso_deleted_at &&
                          !r.operation && !r.operation_pending && (
                            <button
                              className="text-button"
                              disabled={busy === r.id}
                              onClick={() => retry(r)}
                            >
                              {r.state === "needs_review"
                                ? "核对结果"
                                : "继续处理"}
                            </button>
                          )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty>
            {data
              ? directory
                ? "暂无 SSO 用户。创建流程生成 SSO 后会显示在这里。"
                : "暂无创建记录，创建你的第一个 Kiro 账号。"
              : "正在读取创建记录…"}
          </Empty>
        )}
        <Pager page={page} total={data?.total || 0} onPage={setPage} />
      </section>
      {directory && !subscribeMode && <LifecycleHistory key={user.id} actorId={user.id} initialBatch={latestLifecycleBatch} />}
      {cancelOpen && <NativeSubscriptionDialog key={`cancel:${user.id}:${scopeQuery}`} kind="user_cancel" user={user} records={authRecords} admission={cancellation} close={() => setCancelOpen(false)} onAccepted={lifecycleAccepted} />}
      {bulk && (
        <Modal
          title={
            selected.length === 1 ? "开通 Kiro 订阅" : "批量开通 Kiro 订阅"
          }
          onClose={() => {
            if (busy !== "bulk") setBulk(false);
          }}
        >
          <form onSubmit={subscribeSelected}>
            <ErrorBox text={bulkError || plans.error} />
            <p>
              为所选 {selected.length} 个 SSO
              用户开通同一套餐。每个用户按创建者的该套餐次数独立计数。
            </p>
            <Field label="Kiro 套餐">
              <SearchableSelect aria-label="Kiro 套餐" name="plan_id" required>
                <option value="">请选择套餐</option>
                {plans.data
                  ?.filter((p) => p.active)
                  .map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
              </SearchableSelect>
            </Field>
            <SubscriptionPolicyFields records={selectedRecords.filter((r): r is RecordItem => !!r)} groups={groups.data || []} />
            <label className="check-line">
              <input type="checkbox" required />
              确认实际开通 AWS 企业订阅，并按对应套餐计费。
            </label>
            <button className="primary" disabled={busy === "bulk"}>
              {busy === "bulk" ? "正在提交…" : `开通 ${selected.length} 个订阅`}
            </button>
          </form>
        </Modal>
      )}
      {credential && (
        <Modal title="账号登录信息" onClose={() => setCredential(null)}>
          <CredentialDetails credential={credential} />
          <div className="modal-actions">
            <button className="primary" onClick={copy}>
              复制登录信息
            </button>
          </div>
        </Modal>
      )}
      {detail && (
        <RecordManager
          initial={detail}
          onClose={() => setDetail(null)}
          onChanged={refresh}
          onCredentials={(r) => {
            setDetail(null);
            view(r);
          }}
        />
      )}
    </>
  );
}
function RecordManager({
  initial,
  onClose,
  onChanged,
  onCredentials,
}: {
  initial: RecordItem;
  onClose: () => void;
  onChanged: () => void;
  onCredentials: (r: RecordItem) => void;
}) {
  const record = useData<RecordItem>(`/subscriptions/${initial.id}`, 3000);
  const groups = useData<GroupItem[]>("/groups", 3000);
  const history = useData<RecordOperation[]>(
    `/subscriptions/${initial.id}/operations`,
    3000,
  );
  const r = record.data || initial;
  const { user, capabilities, notify } = useApp();
  const [deleteOpen, setDeleteOpen] = useState(false);
  const deletionScope = JSON.stringify([user.id, user.role, user.active, user.account_ids, r.id, r.owner_id, r.aws_account_id, r.group_id]);
  const deletion = useCascadeAdmission(user.id, deletionScope);
  function deletionAccepted(_batch: CascadeBatch) { setDeleteOpen(false); void record.refresh(); void history.refresh(); onChanged(); notify("取消订阅后删除已受理，可查看逐步进度"); }
  const [action, setAction] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const requestKey = useRef(crypto.randomUUID());
  const blocked =
    busy || r.operation_pending || !!r.operation || !["completed", "failed"].includes(r.state);
  const canRecoverInitialPassword = !busy && !r.operation_pending && !r.operation
    && r.state === "needs_review" && r.step === "password_pending";
  function choose(kind: string) {
    requestKey.current = crypto.randomUUID();
    setError("");
    setAction(kind);
  }
  async function submit(
    e?: FormEvent<HTMLFormElement>,
    immediateKind?: string,
  ) {
    e?.preventDefault();
    const f = e ? new FormData(e.currentTarget) : null;
    const kind = immediateKind || action;
    setBusy(true);
    setError("");
    try {
      if (kind === "resolve") {
        await api(`/admin/subscriptions/${r.id}/resolve-unsubscribed`, "POST", {
          reason: f?.get("reason"),
          confirmed_in_aws: f?.get("confirmed") === "on",
        });
      } else if (kind === "retry" && r.operation) {
        await api(
          `/subscriptions/${r.id}/operations/${r.operation.id}/retry`,
          "POST",
          { confirm_username: f?.get("confirm_username") },
        );
      } else {
        const body: Record<string, unknown> = {
          kind,
          request_key: requestKey.current,
        };
        if (kind === "update_sso") {
          body.display_name = f?.get("display_name");
          body.email = f?.get("email");
        }
        if (kind === "cancel_subscription")
          body.cancellation_mode = f?.get("cancellation_mode");
        if (!["sync_status", "update_sso"].includes(kind))
          body.confirm_username = f?.get("confirm_username");
        await api(`/subscriptions/${r.id}/operations`, "POST", body);
      }
      setAction("");
      requestKey.current = crypto.randomUUID();
      await record.refresh();
      await history.refresh();
      onChanged();
      notify(
        kind === "resolve" ? "已记录核实结果" : "操作已提交，结果会自动更新",
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const isGone = !!r.sso_deleted_at;
  const actionTitle =
    action === "retry"
      ? `再次处理：${operationName[r.operation?.kind || ""] || "待核对操作"}`
      : operationName[action];
  return (
    <Modal
      title={r.sso_user_id ? "SSO 用户详情" : "开通详情"}
      onClose={onClose}
    >
      {r.internal_id && <p className="mono">内部 ID：{r.internal_id} · AWS 编号：{r.account_number} · 批次：{r.provisioning_batch_number}</p>}
      <p className="mono record-username">{r.username}</p>
      <ErrorBox
        text={error || record.error || history.error || r.error || ""}
      />
      <dl className="record-facts">
        <div>
          <dt>SSO 状态</dt>
          <dd>
            {r.sso_user_id
              ? isGone
                ? "已删除（历史保留）"
                : "存在"
              : "尚未创建"}
          </dd>
        </div>
        <div>
          <dt>Kiro 订阅状态</dt>
          <dd>{subscriptionStatus(r)}</dd>
        </div>
        <div>
          <dt>姓名</dt>
          <dd>{r.sso_display_name || "—"}</dd>
        </div>
        <div>
          <dt>邮箱</dt>
          <dd>{r.email}</dd>
        </div>
        <div>
          <dt>首次开通套餐 · 只读</dt>
          <dd>{r.plan_name}</dd>
        </div>
        <div>
          <dt>首次订阅时间 · 只读</dt>
          <dd>{date(r.subscribed_at)}</dd>
        </div>
        <CurrentPlanFacts record={r} />
        {r.pending_plan && <div>
          <dt>待生效降级</dt>
          <dd>{r.pending_plan.name || r.pending_plan.subscription_type}<small>预计 {date(r.pending_plan.expected_effective_at)} · 以 AWS 确认为准</small></dd>
        </div>}
        <div>
          <dt>AWS 账号</dt>
          <dd>{r.account_name}</dd>
        </div>
        <div>
          <dt>创建者</dt>
          <dd>{r.owner_name}</dd>
        </div>
        <div><dt>所属分组</dt><dd>{r.group_id ? <NavLink to={`/groups?group_id=${encodeURIComponent(r.group_id)}`}>{groups.data?.find(g => g.id === r.group_id)?.name || "查看分组"}</NavLink> : "未加入分组"}</dd></div>
        <div>
          <dt>最新密码生成时间</dt>
          <dd>{date(r.password_generated_at)}</dd>
        </div>
        <div><dt>当前密码类型</dt><dd>{credentialLabel(r.credential_state)}</dd></div>
        <div>
          <dt>最近同步 AWS</dt>
          <dd>{date(r.last_synced_at)}</dd>
        </div>
        {r.cancelled_at && (
          <div>
            <dt>取消操作时间</dt>
            <dd>{date(r.cancelled_at)}</dd>
          </div>
        )}
        {r.access_ends_at && (
          <div>
            <dt>AWS 停止访问时间</dt>
            <dd>{date(r.access_ends_at)}</dd>
          </div>
        )}
        {isGone && (
          <div>
            <dt>SSO 删除记录时间</dt>
            <dd>{date(r.sso_deleted_at)}</dd>
          </div>
        )}
      </dl>
      <p className="muted">
        {r.counted
          ? "本次成功开通已计数。取消订阅、删除 SSO 或重置密码均不返还次数。"
          : "本次尚未计入成功次数。"}
      </p>
      <StopScheduleEditor
        record={r}
        group={groups.data?.find(g => g.id === r.group_id)}
        blocked={blocked}
        onChanged={() => {
          record.refresh();
          onChanged();
        }}
      />
      {(r.subscription_source === "GROUP" || r.native_group_subscription) && <NativeMemberHistory key={`member-history:${user.id}:${r.id}`} actorId={user.id} record={r} />}
      {r.operation_pending && !r.operation && <div className="operation-progress" role="status">有任务正在处理或待核对，完成后可继续操作。</div>}
      {r.operation && (
        <div className="operation-progress" role="status">
          <strong>
            {r.operation.automatic ? "定时停止 · " : ""}
            {operationName[r.operation.kind]} ·{" "}
            {authStateLabel[r.operation.state] || "正在处理"}
          </strong>
          {r.operation.error && <p>{r.operation.error}</p>}
          {r.operation.kind === "cascade_delete" ? <p>在下方“级联删除进度与历史”查看原范围和只读核对结果。</p> : r.operation.principal_type === "GROUP" ? <NavLink className="secondary" to={`/groups?group_id=${encodeURIComponent(r.native_group_subscription?.group_id || r.group_id || "")}`}>前往分组订阅核对</NavLink> : isPlanChangeOperation(r.operation.kind) ? capabilities.plan_changes_enabled ? <p>在下方“套餐变更”中查看历史或只读核对 AWS。</p> : <p>此站点未启用套餐变更，请联系管理员。</p> : r.operation.kind.startsWith("auth_") ? <NavLink className="secondary" to={r.operation.kind === "auth_json_export" ? "/json-export" : "/sso?passwords=1"} onClick={onClose}>前往{r.operation.kind === "auth_json_export" ? " JSON 导出" : "批量改密"}查看批次</NavLink> : r.operation.state === "needs_review" && (
            ["attach", "detach"].includes(r.operation.kind) && r.group_id ?
              <NavLink className="secondary" to={`/groups?group_id=${encodeURIComponent(r.group_id)}`}>前往分组核对</NavLink> :
              <button className="secondary" disabled={busy} onClick={() => choose("retry")}>核对 / 再次处理</button>
          )}
        </div>
      )}
      {r.sso_user_id && (
        <div className="record-actions">
          <button
            className="secondary"
            disabled={blocked}
            onClick={() => submit(undefined, "sync_status")}
          >
            同步 AWS 状态
          </button>
          {!isGone && (
            <>
              <button
                className="secondary"
                disabled={blocked}
                onClick={() => choose("update_sso")}
              >
                更新姓名 / 邮箱
              </button>
              <button
                className="secondary"
                disabled={blocked && !canRecoverInitialPassword}
                onClick={() => choose("reset_password")}
              >
                重置一次性密码
              </button>
              <button
                className="secondary"
                disabled={!r.has_password || busy || r.operation_pending}
                onClick={() => onCredentials(r)}
              >
                查看登录信息
              </button>
            </>
          )}
          {(r.counted || r.subscription_status === "active") &&
            !r.cancelled_at &&
            r.subscription_status !== "cancelled" && (
              <button
                className="secondary"
                disabled={blocked}
                onClick={() => choose("cancel_subscription")}
              >
                取消订阅
              </button>
            )}
          {!isGone && (
            <button
              className="danger"
              disabled={blocked || deletion.busy || !!deletion.pending}
              onClick={() => setDeleteOpen(true)}
            >
              删除 SSO 用户
            </button>
          )}
        </div>
      )}
      {r.sso_user_id && <PlanChangeManager enabled={capabilities.plan_changes_enabled} key={`${user.id}:${r.id}`} actorId={user.id} record={r} onChanged={() => {
        void record.refresh(); void history.refresh(); onChanged();
      }} />}
      {user.role === "admin" && r.state === "needs_review" && (
        <button className="secondary" onClick={() => choose("resolve")}>
          核实未开通
        </button>
      )}
      {action && (
        <form className="record-action-form" onSubmit={submit} key={action}>
          <h3>{action === "resolve" ? "核实未开通" : actionTitle}</h3>
          {action === "update_sso" ? (
            <>
              <Field label="姓名（显示名称）">
                <input
                  name="display_name"
                  required
                  maxLength={100}
                  defaultValue={r.sso_display_name || ""}
                />
              </Field>
              <Field label="邮箱">
                <input
                  name="email"
                  required
                  type="email"
                  maxLength={254}
                  defaultValue={r.email}
                />
              </Field>
              <p className="muted">
                更新后同步到企业 Identity Center，用户名和订阅历史保持只读。
              </p>
            </>
          ) : action === "resolve" ? (
            <>
              <p className="muted">
                等待至少 10 分钟，在 AWS
                确认未开通后释放处理中次数。系统会再次核对。
              </p>
              <Field label="核实说明">
                <textarea
                  name="reason"
                  minLength={5}
                  maxLength={500}
                  required
                />
              </Field>
              <label className="check">
                <input type="checkbox" name="confirmed" required />
                我已在 AWS 确认对应订阅未开通
              </label>
            </>
          ) : (
            <>
              {action === "cancel_subscription" && (
                <>
                  <p>
                    {nativeAccess(r) ? "移出 AWS 组并停止该组授权，保留 SSO。独立 USER 和其他 GROUP 授权继续保留，其他组成员继续保留授权。" : "取消该用户的独立 USER 订阅分配，其他 GROUP 授权、SSO 用户和订阅历史保留。当月费用按 AWS 规则结算。"}
                  </p>
                  <Field label="停止访问时间">
                    <SearchableSelect aria-label="停止访问时间"
                      name="cancellation_mode"
                      defaultValue={
                        r.supports_scheduled_cancellation && !nativeAccess(r)
                          ? "END_OF_PERIOD"
                          : "IMMEDIATE"
                      }
                    >
                      {r.supports_scheduled_cancellation && !nativeAccess(r) && (
                        <option value="END_OF_PERIOD">月底停止访问</option>
                      )}
                      <option value="IMMEDIATE">立即停止访问</option>
                    </SearchableSelect>
                  </Field>
                  {r.supports_scheduled_cancellation && !nativeAccess(r) && (
                    <p className="muted">
                      选择月底停止访问后，可同步 AWS
                      到期时间；到期后的应用分配清理按 AWS 控制台提示处理。
                    </p>
                  )}
                </>
              )}
              {(action === "reset_password" ||
                (action === "retry" &&
                  r.operation?.kind === "reset_password")) && (
                <p>
                  将生成新的一次性密码，之前的密码可能立即失效。成功后可在“登录信息”查看最新密码。
                </p>
              )}
              {action === "retry" && r.operation?.kind !== "reset_password" && (
                <p className="muted">
                  只读核对 AWS 已有结果；结果仍不明确时保留待核对，不重复发送操作。
                </p>
              )}
              <Field label="输入用户名以确认">
                <input
                  name="confirm_username"
                  required
                  autoComplete="off"
                  placeholder={r.username}
                />
              </Field>
            </>
          )}
          <div className="modal-actions">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => setAction("")}
            >
              返回
            </button>
            <button
              className={action === "delete_sso" ? "danger" : "primary"}
              disabled={busy}
            >
              {busy ? "提交中…" : "确认提交"}
            </button>
          </div>
        </form>
      )}
      <CascadeSubmissionRecovery admission={deletion} onAccepted={deletionAccepted} />
      {deleteOpen && <CascadeDialog actorId={user.id} scope={deletionScope} kind="sso" ids={[r.id]} admission={deletion} close={() => setDeleteOpen(false)} onAccepted={deletionAccepted} />}
      <CascadeHistory actorId={user.id} scope={deletionScope} recordId={r.id} onChanged={() => { void record.refresh(); onChanged(); }} />
      <section className="record-history">
        <h3>用户操作历史</h3>
        <p className="muted">
          创建于 {date(r.created_at)} · 处理结果：
          {r.provision_only && r.state === "completed"
            ? "SSO 已创建"
            : stateName[r.state]}
        </p>
        {history.data?.length ? (
          history.data.map((op) => (
            <article key={op.id}>
              <div>
                <strong>
                  {op.automatic ? "定时停止 · " : ""}
                  {operationName[op.kind]}
                </strong>
                <span>
                  {
                    (
                      {
                        queued: "待处理",
                        running: "处理中",
                        completed: "已完成",
                        failed: "失败",
                        needs_review: "待核对",
                      } as Record<string, string>
                    )[op.state]
                  }
                </span>
              </div>
              <small>
                {date(op.created_at)} · {op.actor_name}
              </small>
              {op.error && <p className="error-text">{op.error}</p>}
            </article>
          ))
        ) : (
          <p className="muted">暂无后续操作。</p>
        )}
      </section>
    </Modal>
  );
}
function Counts() {
  const counters = useData<Counter[]>("/counters"),
    history = useData<Reset[]>("/counter-resets"),
    { user, notify } = useApp();
  const [tab, setTab] = useState("current"),
    [reset, setReset] = useState<Counter | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!reset) return;
    setBusy(true);
    const f = new FormData(e.currentTarget);
    try {
      await api(`/admin/counters/${reset.id}/reset`, "POST", {
        limit_count: Number(f.get("limit")),
        reason: f.get("reason"),
      });
      setReset(null);
      notify("次数已重置，上一轮记录已保存");
      counters.refresh();
      history.refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Header
        title="套餐次数"
        description="按用户和套餐分别记录开通次数，重置不会删除历史。"
      />
      <div className="tabs">
        <button
          className={tab === "current" ? "active" : ""}
          onClick={() => setTab("current")}
        >
          本轮次数
        </button>
        <button
          className={tab === "history" ? "active" : ""}
          onClick={() => setTab("history")}
        >
          重置历史
        </button>
      </div>
      <ErrorBox text={counters.error || history.error} />
      <section className="panel no-padding">
        {tab === "current" ? (
          counters.data?.length ? (
            <CounterTable
              counters={counters.data}
              action={
                user.role === "admin"
                  ? (c) => (
                      <button
                        className="text-button"
                        disabled={c.pending_count > 0}
                        onClick={() => {
                          setError("");
                          setReset(c);
                        }}
                      >
                        重置次数
                      </button>
                    )
                  : undefined
              }
            />
          ) : (
            <Empty>暂无套餐次数。管理员可在“子用户”中设置。</Empty>
          )
        ) : history.data?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>用户 / 套餐</th>
                  <th>结束轮次</th>
                  <th>该轮开通</th>
                  <th>新上限</th>
                  <th>原因</th>
                  <th>操作者 / 时间</th>
                </tr>
              </thead>
              <tbody>
                {history.data.map((r) => (
                  <tr key={r.id}>
                    <td>
                      {r.username}
                      <small>{r.plan_name}</small>
                    </td>
                    <td>第 {r.cycle_number} 轮</td>
                    <td>
                      {r.used_count} / {r.previous_limit} 次
                    </td>
                    <td>{r.new_limit} 次</td>
                    <td>{r.reason}</td>
                    <td>
                      {r.actor_name}
                      <small>{date(r.created_at)}</small>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty>暂无重置记录。每次重置都会保留原计数和操作原因。</Empty>
        )}
      </section>
      {reset && (
        <Modal title="重置套餐次数" onClose={() => setReset(null)}>
          <form onSubmit={submit}>
            <ErrorBox text={error} />
            <p>
              {reset.username} · {reset.plan_name}
            </p>
            <div className="info-note">
              第 {reset.cycle_number} 轮已开通 {reset.used_count}{" "}
              次。重置后将开始第 {reset.cycle_number + 1} 轮，历史累计{" "}
              {reset.lifetime_count} 次继续保留。
            </div>
            <Field label="新一轮开通次数上限">
              <input
                name="limit"
                type="number"
                min={0}
                max={1000000}
                defaultValue={reset.limit_count}
                required
              />
            </Field>
            <Field label="重置原因">
              <textarea
                name="reason"
                minLength={2}
                maxLength={500}
                required
                placeholder="例如：为下一批成员开通订阅"
              />
            </Field>
            <div className="modal-actions">
              <button
                className="secondary"
                type="button"
                onClick={() => setReset(null)}
              >
                取消
              </button>
              <button className="primary" disabled={busy}>
                保存历史并重置
              </button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}
function Users() {
  const users = useData<User[]>("/admin/users"),
    accounts = useData<Account[]>("/accounts"),
    plans = useData<Plan[]>("/plans"),
    counters = useData<Counter[]>("/counters"),
    resetHistory = useData<Reset[]>("/counter-resets");
  const { notify, user: currentUser, refresh: refreshUser } = useApp();
  const [params, setParams] = useSearchParams();
  const [creating, setCreating] = useState(false),
    [editing, setEditing] = useState<User | null>(null),
    [editingRole, setEditingRole] = useState<User["role"]>("member"),
    [passwordUser, setPasswordUser] = useState<User | null>(null),
    [deleting, setDeleting] = useState<User | null>(null),
    [busy, setBusy] = useState(false),
    [resetting, setResetting] = useState<number | null>(null),
    [search, setSearch] = useState(""),
    [error, setError] = useState("");
  useEffect(() => {
    const id = Number(params.get("edit"));
    const u = users.data?.find((item) => item.id === id);
    if (u) {
      setEditing(u);
      setEditingRole(u.role);
      setParams({}, { replace: true });
    }
  }, [params, users.data]);
  async function removeUser() {
    if (!deleting) return;
    setBusy(true);
    setError("");
    try {
      await api(`/admin/users/${deleting.id}`, "DELETE");
      setDeleting(null);
      notify("用户已删除，订阅与审计历史已保留");
      users.refresh();
      counters.refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function resetPlan(c: Counter) {
    setResetting(c.id);
    setError("");
    try {
      await api(
        `/admin/users/${c.user_id}/counters/${c.plan_id}/reset`,
        "POST",
        { expected_cycle: c.cycle_number },
      );
      await counters.refresh();
      await resetHistory.refresh();
      notify(`${c.plan_name} 已按当前设置重置，累计次数与历史已保留`);
    } catch (e) {
      setError((e as Error).message);
      await counters.refresh();
    } finally {
      setResetting(null);
    }
  }
  async function create(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    try {
      await api("/admin/users", "POST", {
        username: f.get("username"),
        display_name: f.get("display_name"),
        password: f.get("password"),
        role: f.get("role"),
      });
      setCreating(false);
      notify("用户已创建，首次登录需要修改密码");
      users.refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function savePermissions(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!editing) return;
    const f = new FormData(e.currentTarget);
    setBusy(true);
    try {
      if (editingRole === "member") {
        await api(`/admin/users/${editing.id}/bindings`, "PUT", {
          account_ids: f.getAll("account").map(Number),
        });
        for (const p of plans.data || []) {
          await api(`/admin/users/${editing.id}/counters/${p.id}`, "PUT", {
            limit_count: Number(f.get(`plan-${p.id}`)),
          });
        }
      }
      const displayName = String(f.get("display_name") || "").trim();
      if (
        editing.role !== editingRole ||
        editing.display_name !== displayName
      ) {
        await api(`/admin/users/${editing.id}`, "PATCH", {
          role: editingRole,
          display_name: displayName,
        });
        if (editing.id === currentUser.id) refreshUser();
      }
      notify("用户权限与次数已保存");
      setEditing(null);
      users.refresh();
      counters.refresh();
    } catch (e) {
      setError(
        `${(e as Error).message}；已成功保存的设置会保留，请核对后重试。`,
      );
      counters.refresh();
      users.refresh();
    } finally {
      setBusy(false);
    }
  }
  async function toggle(u: User) {
    try {
      await api(`/admin/users/${u.id}`, "PATCH", { active: !u.active });
      notify(u.active ? "用户已停用" : "用户已启用");
      users.refresh();
    } catch (e) {
      notify((e as Error).message, true);
    }
  }
  async function password(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!passwordUser) return;
    setBusy(true);
    try {
      await api(`/admin/users/${passwordUser.id}`, "PATCH", {
        password: new FormData(e.currentTarget).get("password"),
      });
      notify("登录密码已重置，用户下次登录需修改");
      setPasswordUser(null);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Header
        title="用户管理"
        description="设置普通用户或管理员；为普通用户分配 AWS 账号和各套餐开通次数。"
        action={
          <button
            className="primary"
            onClick={() => {
              setError("");
              setCreating(true);
            }}
          >
            ＋ 创建用户
          </button>
        }
      />
      <ErrorBox
        text={users.error || accounts.error || plans.error || counters.error}
      />
      <div className="resource-filters">
        <input
          type="search"
          aria-label="搜索平台用户"
          placeholder="搜索用户名或显示名称"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>
      <section className="panel no-padding">
        {users.data?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>用户</th>
                  <th>角色</th>
                  <th>AWS 绑定</th>
                  <th>账号状态</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {users.data
                  .filter((u) =>
                    `${u.username} ${u.display_name}`
                      .toLowerCase()
                      .includes(search.trim().toLowerCase()),
                  )
                  .map((u) => (
                    <tr key={u.id}>
                      <td>
                        <strong>{u.display_name}</strong>
                        <small>{u.username}</small>
                        {u.id === currentUser.id && <small>当前账号</small>}
                      </td>
                      <td>{u.role === "admin" ? "管理员" : "普通用户"}</td>
                      <td>
                        {u.role === "admin"
                          ? "所有 AWS 账号"
                          : u.account_ids?.length
                            ? u.account_ids
                                .map(
                                  (id) =>
                                    accounts.data?.find((a) => a.id === id)
                                      ?.name || `#${id}`,
                                )
                                .join("、")
                            : "尚未分配"}
                      </td>
                      <td>
                        <span
                          className={`badge ${u.active ? "completed" : "failed"}`}
                        >
                          {u.active ? "正常" : "已停用"}
                        </span>
                      </td>
                      <td>
                        <div className="row-actions">
                          <button
                            className="text-button"
                            onClick={() => {
                              setError("");
                              setEditing(u);
                              setEditingRole(u.role);
                            }}
                          >
                            设置权限与次数
                          </button>
                          {u.id === currentUser.id ? (
                            <NavLink to="/password">修改密码</NavLink>
                          ) : (
                            <>
                              <button
                                className="text-button"
                                onClick={() => {
                                  setError("");
                                  setPasswordUser(u);
                                }}
                              >
                                重置密码
                              </button>
                              <button
                                className="text-button"
                                onClick={() => toggle(u)}
                              >
                                {u.active ? "停用" : "启用"}
                              </button>
                              {!u.active && (
                                <button
                                  className="text-button danger-text"
                                  onClick={() => {
                                    setError("");
                                    setDeleting(u);
                                  }}
                                >
                                  删除
                                </button>
                              )}
                            </>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty>创建用户，并设置角色与权限。</Empty>
        )}
      </section>
      {creating && (
        <Modal title="创建用户" onClose={() => setCreating(false)}>
          <form onSubmit={create}>
            <ErrorBox text={error} />
            <Field label="用户名">
              <input
                name="username"
                pattern="[a-zA-Z0-9_.\-]{3,80}"
                autoComplete="off"
                required
              />
            </Field>
            <Field label="显示名称">
              <input name="display_name" maxLength={100} required />
            </Field>
            <Field
              label="用户角色"
              hint="普通用户只访问自己的数据；管理员可管理所有用户、AWS 账号和订阅，开通次数不限。"
            >
              <SearchableSelect aria-label="用户角色" name="role" defaultValue="member">
                <option value="member">普通用户</option>
                <option value="admin">管理员</option>
              </SearchableSelect>
            </Field>
            <Field
              label="初始密码"
              hint="至少 12 个字符，用户首次登录必须修改。"
            >
              <input
                name="password"
                type="password"
                minLength={12}
                autoComplete="new-password"
                required
              />
            </Field>
            <div className="modal-actions">
              <button className="primary" disabled={busy}>
                创建用户
              </button>
            </div>
          </form>
        </Modal>
      )}
      {deleting && (
        <Modal
          title={`删除用户 ${deleting.username}`}
          onClose={() => !busy && setDeleting(null)}
        >
          <ErrorBox text={error} />
          <p>删除后，该用户将从管理列表移除，无法登录或再次启用。</p>
          <p className="info-note">
            已有 SSO、订阅、套餐次数及审计历史会保留，管理员仍可管理这些
            SSO。存在处理中或待核对任务时，需要先处理完成。
          </p>
          <div className="modal-actions">
            <button
              className="secondary"
              disabled={busy}
              onClick={() => setDeleting(null)}
            >
              取消
            </button>
            <button className="danger" disabled={busy} onClick={removeUser}>
              {busy ? "正在删除…" : "删除用户"}
            </button>
          </div>
        </Modal>
      )}
      {editing && (
        <Modal
          title={`${editing.display_name} · 权限与次数`}
          onClose={() => setEditing(null)}
        >
          <form onSubmit={savePermissions}>
            <ErrorBox text={error} />
            <Field label="显示名称">
              <input
                name="display_name"
                defaultValue={editing.display_name}
                maxLength={100}
                required
                disabled={busy}
              />
            </Field>
            <Field
              label="用户角色"
              hint={
                editing.id === currentUser.id
                  ? "当前登录账号的管理员角色不能降低。"
                  : "修改角色后，该用户需重新登录；普通用户的原次数和历史继续保留。"
              }
            >
              <SearchableSelect aria-label="用户角色"
                value={editingRole}
                disabled={editing.id === currentUser.id || busy}
                onChange={(e) => setEditingRole(e.target.value as User["role"])}
              >
                <option value="member">普通用户</option>
                <option value="admin">管理员</option>
              </SearchableSelect>
            </Field>
            {editingRole === "admin" ? (
              <p className="info-note">
                管理员可以管理所有用户、AWS 账号、SSO
                和订阅，拥有全部管理权限，开通次数不限。
              </p>
            ) : (
              <>
                <h3>可使用的 AWS 账号</h3>
                <AccountBindings key={editing.id} accounts={accounts.data || []} selected={editing.account_ids || []} disabled={busy} />
                {!accounts.data?.length && (
                  <p className="muted">请先在 AWS 账号页面添加账号。</p>
                )}
                <h3>每种套餐的开通次数上限</h3>
                <p className="muted">
                  修改上限会保留本轮已用次数。“一键重置”按已保存的上限恢复次数，历史累计不变。修改输入框后请先保存，再重置。
                </p>
                {plans.data?.map((p) => {
                  const c = counters.data?.find(
                    (c) => c.user_id === editing.id && c.plan_id === p.id,
                  );
                  return (
                    <div key={p.id} className="plan-permission">
                      <Field
                        label={`${p.name} · 本轮已开通 ${c?.used_count || 0} 次`}
                      >
                        <input
                          name={`plan-${p.id}`}
                          type="number"
                          min={(c?.used_count || 0) + (c?.pending_count || 0)}
                          max={1000000}
                          defaultValue={c?.limit_count || 0}
                          required
                        />
                      </Field>
                      <div className="plan-permission-info">
                        <small>
                          剩余{" "}
                          {Math.max(
                            0,
                            (c?.limit_count || 0) -
                              (c?.used_count || 0) -
                              (c?.pending_count || 0),
                          )}{" "}
                          / 已设置 {c?.limit_count || 0} · 处理中{" "}
                          {c?.pending_count || 0} · 累计{" "}
                          {c?.lifetime_count || 0}
                        </small>
                        <button
                          type="button"
                          className="secondary"
                          disabled={
                            !c ||
                            !!c.pending_count ||
                            resetting !== null ||
                            busy
                          }
                          onClick={() => c && resetPlan(c)}
                        >
                          {resetting === c?.id ? "重置中…" : "一键重置"}
                        </button>
                      </div>
                      {!c && (
                        <small className="muted">
                          先保存次数设置即可启用重置。
                        </small>
                      )}
                    </div>
                  );
                })}
              </>
            )}
            <div className="modal-actions">
              <button className="primary" disabled={busy || resetting !== null}>
                保存权限与次数
              </button>
            </div>
          </form>
          <section className="record-history">
            <h3>次数重置历史</h3>
            <ErrorBox text={resetHistory.error} />
            {resetHistory.data
              ?.filter((x) => x.username === editing.username)
              .slice(0, 20)
              .map((x) => (
                <article key={x.id}>
                  <strong>
                    {x.plan_name} · 第 {x.cycle_number} 轮
                  </strong>
                  <p>
                    已用 {x.used_count} 次 → 恢复 {x.new_limit} 次
                  </p>
                  <small>
                    {date(x.created_at)} · {x.actor_name} · {x.reason}
                  </small>
                </article>
              ))}
            {!resetHistory.data?.some(
              (x) => x.username === editing.username,
            ) && <p className="muted">暂无重置记录。</p>}
          </section>
        </Modal>
      )}
      {passwordUser && (
        <Modal
          title={`重置 ${passwordUser.username} 的登录密码`}
          onClose={() => setPasswordUser(null)}
        >
          <form onSubmit={password}>
            <ErrorBox text={error} />
            <Field label="新的初始密码">
              <input
                name="password"
                type="password"
                minLength={12}
                required
                autoComplete="new-password"
              />
            </Field>
            <div className="modal-actions">
              <button className="primary" disabled={busy}>
                重置登录密码
              </button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}
function ResourceFilters({
  search,
  setSearch,
  status,
  setStatus,
}: {
  search: string;
  setSearch: (value: string) => void;
  status: string;
  setStatus: (value: string) => void;
}) {
  return (
    <div className="resource-filters">
      <input
        type="search"
        aria-label="搜索配置"
        placeholder="搜索名称、账号或代码"
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />
      <SearchableSelect
        aria-label="配置状态"
        value={status}
        onChange={(e) => setStatus(e.target.value)}
      >
        <option value="current">当前配置</option>
        <option value="active">已启用</option>
        <option value="inactive">已停用</option>
        <option value="deleted">已删除</option>
      </SearchableSelect>
    </div>
  );
}
function matchesResource(
  resource: Account | Plan,
  search: string,
  status: string,
) {
  const stateMatches =
    status === "deleted"
      ? !!resource.deleted_at
      : !resource.deleted_at &&
        (status === "current" || resource.active === (status === "active"));
  const values =
    "code" in resource
      ? `${resource.name} ${resource.code}`
      : `${resource.account_number || ""} ${resource.name} ${resource.aws_account_id || ""} ${resource.region} ${resource.subscription_region || ""}`;
  return (
    stateMatches && values.toLowerCase().includes(search.trim().toLowerCase())
  );
}
function ResourceRemoval({
  resource,
  kind,
  onClose,
  onDone,
}: {
  resource: Account | Plan;
  kind: "aws" | "plans";
  onClose: () => void;
  onDone: () => void;
}) {
  const [confirmation, setConfirmation] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const { notify } = useApp();
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await api(`/admin/${kind}/${resource.id}`, "DELETE", {
        confirm_name: confirmation,
      });
      notify("配置已移到已删除列表，历史记录已保留");
      onDone();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Modal
      title={`删除${kind === "aws" ? " AWS 账号" : "套餐"}配置`}
      onClose={() => !busy && onClose()}
    >
      <form onSubmit={submit}>
        <ErrorBox text={error} />
        <p>将「{resource.name}」移到已删除列表，可在列表中恢复。</p>
        <p className="info-note">
          {kind === "aws"
            ? "删除的是本控制台中的账号配置，会解除子用户绑定并停止使用此配置。AWS 中的 SSO 用户和 Kiro 订阅保持原状，费用继续按实际订阅结算。恢复并启用后可继续管理。"
            : "删除后停止使用此套餐开通新订阅。已开通的 AWS 订阅保持原状，原套餐、订阅时间、次数和重置历史继续保留。"}
        </p>
        <p className="muted">
          关联历史 {resource.usage?.records || 0} 条
          {kind === "aws"
            ? `，现存 SSO ${resource.usage?.sso_active || 0} 名`
            : ""}
          。存在处理中或待核对任务时需先处理完成。
        </p>
        <Field label={`请输入完整名称：${resource.name}`}>
          <input
            aria-label="确认删除名称"
            autoComplete="off"
            value={confirmation}
            onChange={(e) => setConfirmation(e.target.value)}
            required
            disabled={busy}
          />
        </Field>
        <div className="modal-actions">
          <button
            type="button"
            className="secondary"
            disabled={busy}
            onClick={onClose}
          >
            取消
          </button>
          <button
            className="danger"
            disabled={busy || confirmation !== resource.name}
          >
            {busy ? "正在删除…" : "确认删除配置"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
function Accounts() {
  const accounts = useData<Account[]>("/accounts?include_deleted=true"),
    proxies = useData<ProxyItem[]>("/admin/proxies"),
    { notify, user } = useApp();
  const [editing, setEditing] = useState<Account | Partial<Account> | null>(
      null,
    ),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [deleting, setDeleting] = useState<Account | null>(null),
    [search, setSearch] = useState(""),
    [status, setStatus] = useState("current"),
    [profileIndex, setProfileIndex] = useState(0),
    [selectedProxy, setSelectedProxy] = useState<number | "">(""),
    [discoveries, setDiscoveries] = useState<
      (Account & { profile_name: string })[]
    >([]);
  const formRef = useRef<HTMLFormElement>(null);
  useEffect(() => {
    setSelectedProxy(editing?.proxy_id ?? "");
  }, [editing]);
  const visible = accounts.data?.filter((a) =>
    matchesResource(a, search, status),
  );
  async function changeStatus(a: Account, restore = false) {
    setBusy(true);
    try {
      await api(
        `/admin/aws/${a.id}/${restore ? "restore" : "status"}`,
        restore ? "POST" : "PATCH",
        restore ? undefined : { active: !a.active },
      );
      notify(
        restore
          ? "AWS 配置已恢复为停用状态，请核对后启用并重新绑定用户"
          : a.active
            ? "AWS 账号已停用"
            : "AWS 账号已启用",
      );
      if (restore) setStatus("current");
      await accounts.refresh();
    } catch (e) {
      notify((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  async function detect() {
    const f = new FormData(formRef.current!);
    setBusy(true);
    setError("");
    setNotice("");
    try {
      const d = await api<{
        profiles: (Account & { profile_name: string })[];
        message?: string;
        warnings?: string[];
      }>("/admin/aws/discover", "POST", {
        access_key_id: f.get("access_key_id"),
        secret_access_key: f.get("secret_access_key"),
        region: f.get("region"),
        subscription_region: f.get("subscription_region"),
        proxy_id: f.get("proxy_id") ? Number(f.get("proxy_id")) : null,
      });
      setDiscoveries(d.profiles);
      setProfileIndex(0);
      setNotice(d.warnings?.join("；") || "");
      if (d.profiles[0]) fill(d.profiles[0]);
      if (d.message) setError(d.message);
      else notify("已读取 AWS 配置，请核对后保存");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  function fill(p: Partial<Account>) {
    for (const [k, v] of Object.entries(p)) {
      const input = formRef.current?.elements.namedItem(k) as
        | HTMLInputElement
        | HTMLSelectElement
        | null;
      if (input && typeof v === "string") input.value = v;
    }
  }
  function regionChanged() {
    setDiscoveries([]);
    setProfileIndex(0);
    setError("");
    setNotice("区域已更改，请重新检测当前区域的 AWS 配置。");
    fill({
      identity_store_id: "",
      instance_arn: "",
      application_arn: "",
      profile_arn: "",
      portal_url: "",
      control_plane: "kiro",
    });
  }
  async function save(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget),
      body: Record<string, unknown> = {};
    for (const [k, v] of f.entries()) body[k] = v;
    if (Boolean(body.access_key_id) !== Boolean(body.secret_access_key)) {
      setError("轮换密钥需要同时填写 AK 和 SK；两项都留空则保留现有密钥。");
      return;
    }
    if (!body.access_key_id) {
      delete body.access_key_id;
      delete body.secret_access_key;
    }
    body.active = f.get("active") === "on";
    body.proxy_id = f.get("proxy_id") ? Number(f.get("proxy_id")) : null;
    const profileRegion = String(body.profile_arn || "").split(":")[3];
    if (profileRegion && profileRegion !== body.subscription_region) {
      setError(
        `所选 Kiro 配置位于 ${profileRegion}，请重新检测 ${body.subscription_region} 区域的配置。身份中心区域可保持不同。`,
      );
      return;
    }
    setBusy(true);
    setError("");
    try {
      await api(
        editing?.id ? `/admin/aws/${editing.id}` : "/admin/aws",
        editing?.id ? "PUT" : "POST",
        body,
      );
      notify("AWS 账号已验证并保存");
      setEditing(null);
      accounts.refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Header
        title="AWS 账号"
        description="由管理员保存访问密钥，验证后绑定给子用户使用。"
        action={
          <button
            className="primary"
            onClick={() => {
              setError("");
              setNotice("");
              setDiscoveries([]);
              setEditing({
                region: "us-east-1",
                subscription_region: "us-east-1",
                control_plane: "kiro",
                active: true,
              });
            }}
          >
            ＋ 添加 AWS 账号
          </button>
        }
      />
      <ErrorBox text={accounts.error} />
      <ResourceFilters
        search={search}
        setSearch={setSearch}
        status={status}
        setStatus={setStatus}
      />
      <div className="account-grid">
        {visible?.map((a) => (
          <section className="panel account-card" key={a.id}>
            <div className="section-heading">
              <span className="aws-logo">AWS</span>
              <span className={`badge ${a.active ? "completed" : "failed"}`}>
                {a.deleted_at ? "已删除" : a.active ? "可使用" : "已停用"}
              </span>
            </div>
            <h2>{a.account_number && <span className="mono">{a.account_number} · </span>}{a.name}</h2>
            <p className="mono muted">{a.aws_account_id}</p>
            <dl>
              <div>
                <dt>身份中心区域</dt>
                <dd>{a.region}</dd>
              </div>
              <div>
                <dt>订阅区域</dt>
                <dd>{a.subscription_region}</dd>
              </div>
              <div>
                <dt>访问代理</dt>
                <dd>
                  {a.proxy_id
                    ? `${a.proxy_name || "代理不存在"}${a.proxy_status === "disabled" ? "（已停用）" : ""}`
                    : "直接连接"}
                </dd>
              </div>
            </dl>
            <p className="muted resource-summary">
              绑定 {a.bound_users || 0} 人 · SSO {a.usage?.sso_active || 0} 名 ·
              历史 {a.usage?.records || 0} 条
            </p>
            <AccountCost user={user} account={a} />
            {a.deleted_at && (
              <p className="muted">删除时间：{date(a.deleted_at)}</p>
            )}
            <button
              className="secondary full"
              onClick={() => {
                setError("");
                setDiscoveries([]);
                setEditing(a);
                setNotice("");
              }}
            >
              {a.deleted_at ? "查看配置" : "管理配置"}
            </button>
            <div className="resource-actions">
              {a.deleted_at ? (
                <button
                  className="secondary"
                  disabled={busy}
                  onClick={() => changeStatus(a, true)}
                >
                  恢复配置
                </button>
              ) : (
                <>
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() => changeStatus(a)}
                  >
                    {a.active ? "停用" : "启用"}
                  </button>
                  <button
                    className="danger"
                    disabled={busy}
                    onClick={() => setDeleting(a)}
                  >
                    删除配置
                  </button>
                </>
              )}
            </div>
          </section>
        ))}
      </div>
      {visible?.length === 0 && (
        <section className="panel">
          <Empty>
            {status === "deleted"
              ? "暂无已删除的 AWS 配置。"
              : search
                ? "没有匹配的 AWS 账号。"
                : "暂无此状态的 AWS 账号，可添加账号或调整筛选。"}
          </Empty>
        </section>
      )}
      {deleting && (
        <ResourceRemoval
          resource={deleting}
          kind="aws"
          onClose={() => setDeleting(null)}
          onDone={() => {
            setDeleting(null);
            accounts.refresh();
          }}
        />
      )}
      {editing && (
        <Modal
          title={
            editing.deleted_at
              ? "已删除 AWS 配置 · 只读"
              : editing.id
                ? "管理 AWS 账号"
                : "添加 AWS 账号"
          }
          onClose={() => !busy && setEditing(null)}
        >
          <form ref={formRef} onSubmit={save}>
            <ErrorBox text={error} />
            {editing.deleted_at && (
              <p className="info-note">
                配置已删除。需要修改或使用时，请先关闭此窗口并恢复配置。
              </p>
            )}
            <fieldset
              className="resource-fields"
              disabled={busy || !!editing.deleted_at}
            >
              {notice && <p className="info-note">{notice}</p>}
              <Field label="AWS 编号" hint="批次开通使用；仅英文字母和数字，保存时转为小写。修改不改变已受理的内部 ID。">
                <input aria-label="AWS 编号" name="account_number" defaultValue={editing.account_number || ""} maxLength={24} pattern="[A-Za-z0-9]*" placeholder="例如：a" />
              </Field>
              <Field label="账号名称">
                <input
                  name="name"
                  defaultValue={editing.name}
                  maxLength={100}
                  required
                  placeholder="例如：团队主账号"
                />
              </Field>
              <ErrorBox text={proxies.error} />
              <Field
                label="访问代理"
                hint="检测配置、身份中心与 Kiro 请求都会使用此代理。代理不可用时请求会停止。"
              >
                <SearchableSelect aria-label="访问代理"
                  name="proxy_id"
                  value={selectedProxy}
                  onChange={(e) =>
                    setSelectedProxy(
                      e.target.value ? Number(e.target.value) : "",
                    )
                  }
                  disabled={proxies.loading || !!proxies.error}
                >
                  <option value="">直接连接（不使用代理）</option>
                  {editing.proxy_id &&
                    !proxies.data?.some(
                      (proxy) => proxy.id === editing.proxy_id,
                    ) && (
                      <option value={editing.proxy_id}>
                        原绑定代理不可用，请重新选择
                      </option>
                    )}
                  {proxies.data?.map((proxy) => (
                    <option
                      key={proxy.id}
                      value={proxy.id}
                      disabled={!proxy.enabled && selectedProxy !== proxy.id}
                    >
                      {proxy.name} · {proxy.host}:{proxy.port}
                      {proxy.enabled ? "" : "（已停用）"}
                    </option>
                  ))}
                </SearchableSelect>
              </Field>
              <div className="form-grid">
                <Field
                  label="身份中心区域"
                  hint="SSO 用户所在区域，可以与 Kiro 订阅区域不同。"
                >
                  <input
                    name="region"
                    defaultValue={editing.region}
                    required
                    onChange={regionChanged}
                    disabled={busy}
                  />
                </Field>
                <Field label="订阅区域">
                  <SearchableSelect aria-label="订阅区域"
                    name="subscription_region"
                    defaultValue={editing.subscription_region}
                    onChange={regionChanged}
                    disabled={busy}
                  >
                    <option value="us-east-1">us-east-1</option>
                    <option value="eu-central-1">eu-central-1</option>
                  </SearchableSelect>
                </Field>
                <Field
                  label="Access Key ID"
                  hint={editing.id ? "留空保留现有密钥" : ""}
                >
                  <input
                    name="access_key_id"
                    autoComplete="off"
                    required={!editing.id}
                  />
                </Field>
                <Field label="Secret Access Key">
                  <input
                    name="secret_access_key"
                    type="password"
                    autoComplete="new-password"
                    required={!editing.id}
                  />
                </Field>
              </div>
              <button
                className="secondary"
                type="button"
                disabled={busy || proxies.loading || !!proxies.error}
                onClick={detect}
              >
                {busy ? "正在验证…" : "检测并读取 AWS 配置"}
              </button>
              {discoveries.length > 0 && (
                <Field label="检测到的 Kiro 配置">
                  <SearchableSelect aria-label="检测到的 Kiro 配置"
                    value={profileIndex}
                    onChange={(e) => {
                      setProfileIndex(Number(e.target.value));
                      fill(discoveries[Number(e.target.value)]);
                    }}
                  >
                    {discoveries.map((p, i) => (
                      <option key={i} value={i}>
                        {p.profile_name} · {p.subscription_region}
                      </option>
                    ))}
                  </SearchableSelect>
                </Field>
              )}
              <details className="advanced" open>
                <summary>Identity Center 与 Kiro 配置</summary>
                <Field label="Identity Store ID">
                  <input
                    name="identity_store_id"
                    defaultValue={editing.identity_store_id}
                    required
                  />
                </Field>
                <Field label="Instance ARN">
                  <input
                    name="instance_arn"
                    defaultValue={editing.instance_arn}
                    required
                  />
                </Field>
                <Field label="Application ARN">
                  <input
                    name="application_arn"
                    defaultValue={editing.application_arn}
                    required
                  />
                </Field>
                <Field label="Kiro Profile ARN">
                  <input
                    name="profile_arn"
                    defaultValue={editing.profile_arn}
                    required
                  />
                </Field>
                <Field label="配置类型">
                  <SearchableSelect aria-label="配置类型"
                    name="control_plane"
                    defaultValue={editing.control_plane}
                  >
                    <option value="legacy">AWS CodeWhisperer / Kiro</option>
                    <option value="kiro">Kiro Control Plane</option>
                  </SearchableSelect>
                </Field>
                <Field label="AWS 登录门户">
                  <input
                    name="portal_url"
                    type="url"
                    defaultValue={editing.portal_url}
                    required
                    placeholder="https://d-xxxxxxxxxx.awsapps.com/start"
                  />
                </Field>
              </details>
              <label className="check">
                <input
                  type="checkbox"
                  name="active"
                  defaultChecked={editing.active}
                />
                启用此 AWS 账号
              </label>
              <div className="modal-actions">
                {!editing.deleted_at && (
                  <button
                    className="primary"
                    disabled={busy || proxies.loading || !!proxies.error}
                  >
                    验证并保存
                  </button>
                )}
              </div>
            </fieldset>
          </form>
        </Modal>
      )}
    </>
  );
}
function Plans() {
  const plans = useData<Plan[]>("/plans?include_deleted=true"),
    catalog = useData<PlanCatalog>("/plan-catalog"),
    { notify } = useApp();
  const [editing, setEditing] = useState<Partial<Plan> | null>(null),
    [deleting, setDeleting] = useState<Plan | null>(null),
    [search, setSearch] = useState(""),
    [status, setStatus] = useState("current"),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const visible = plans.data?.filter((p) => matchesResource(p, search, status));
  async function changeStatus(p: Plan, restore = false) {
    setBusy(true);
    try {
      await api(
        `/admin/plans/${p.id}/${restore ? "restore" : "status"}`,
        restore ? "POST" : "PATCH",
        restore ? undefined : { active: !p.active },
      );
      notify(
        restore
          ? "套餐已恢复为停用状态，原次数和历史已保留"
          : p.active
            ? "套餐已停用"
            : "套餐已启用",
      );
      if (restore) setStatus("current");
      await plans.refresh();
    } catch (e) {
      notify((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  async function save(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    setBusy(true);
    try {
      await api(
        editing?.id ? `/admin/plans/${editing.id}` : "/admin/plans",
        editing?.id ? "PUT" : "POST",
        {
          name: f.get("name"),
          code: f.get("code"),
          subscription_type: f.get("subscription_type"),
          active: f.get("active") === "on",
        },
      );
      setEditing(null);
      plans.refresh();
      notify("套餐已保存");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <Header
        title="套餐管理"
        description="套餐对应真实 Kiro 订阅类型，可分别为子用户设置开通次数。"
        action={
          <button
            className="primary"
            disabled={!catalog.data}
            onClick={() => {
              setError("");
              setEditing({ active: true });
            }}
          >
            ＋ 添加套餐
          </button>
        }
      />
      <ErrorBox text={plans.error || catalog.error} />
      <ResourceFilters
        search={search}
        setSearch={setSearch}
        status={status}
        setStatus={setStatus}
      />
      {catalog.data && (
        <p className="muted catalog-note">
          官方商业区参考月价，按用户计费、未含税，以 AWS 实际账单为准。
          核对日期：{catalog.data.checked_at} ·{" "}
          <a href={catalog.data.pricing_url} target="_blank" rel="noreferrer">
            官方价格 ↗
          </a>
        </p>
      )}
      <div className="plan-grid">
        {visible?.map((p) => (
          <section className="panel plan-card" key={p.id}>
            <div className="section-heading">
              <span className="plan-symbol">◇</span>
              <span className={`badge ${p.active ? "completed" : "failed"}`}>
                {p.deleted_at ? "已删除" : p.active ? "已启用" : "已停用"}
              </span>
            </div>
            <h2>{p.name}</h2>
            {p.reference ? (
              <>
                <p className="plan-price">
                  <strong>${p.reference.monthly_price_usd}</strong>
                  <span> / 用户 / 月</span>
                </p>
                <p className="muted">
                  每月含 {p.reference.monthly_credits.toLocaleString()} Kiro
                  credits
                </p>
              </>
            ) : (
              <p className="muted">AWS / Kiro 实际订阅</p>
            )}
            <p className="mono plan-code">{p.code}</p>
            <p className="muted resource-summary">
              关联历史 {p.usage?.records || 0} 条
            </p>
            {p.deleted_at && (
              <p className="muted">删除时间：{date(p.deleted_at)}</p>
            )}
            <button
              className="secondary full"
              onClick={() => {
                setError("");
                setEditing(p);
              }}
            >
              {p.deleted_at ? "查看套餐" : "编辑套餐"}
            </button>
            <div className="resource-actions">
              {p.deleted_at ? (
                <button
                  className="secondary"
                  disabled={busy}
                  onClick={() => changeStatus(p, true)}
                >
                  恢复套餐
                </button>
              ) : (
                <>
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() => changeStatus(p)}
                  >
                    {p.active ? "停用" : "启用"}
                  </button>
                  <button
                    className="danger"
                    disabled={busy}
                    onClick={() => setDeleting(p)}
                  >
                    删除配置
                  </button>
                </>
              )}
            </div>
          </section>
        ))}
      </div>
      {visible?.length === 0 && (
        <section className="panel">
          <Empty>
            {status === "deleted"
              ? "暂无已删除的套餐。"
              : "没有匹配的套餐，可调整筛选或添加套餐。"}
          </Empty>
        </section>
      )}
      <p className="muted">
        平台按成功开通订阅的次数计数；每名子用户的各套餐开通次数仍由管理员分别设置。
      </p>
      {deleting && (
        <ResourceRemoval
          resource={deleting}
          kind="plans"
          onClose={() => setDeleting(null)}
          onDone={() => {
            setDeleting(null);
            plans.refresh();
          }}
        />
      )}
      {editing && (
        <Modal
          title={
            editing.deleted_at
              ? "已删除套餐 · 只读"
              : editing.id
                ? "编辑套餐"
                : "添加套餐"
          }
          onClose={() => !busy && setEditing(null)}
        >
          <form onSubmit={save}>
            <ErrorBox text={error} />
            {editing.deleted_at && (
              <p className="info-note">
                套餐已删除。需要修改或开通新订阅时，请先恢复套餐。
              </p>
            )}
            <fieldset
              className="resource-fields"
              disabled={busy || !!editing.deleted_at}
            >
              <Field label="套餐名称">
                <input
                  name="name"
                  defaultValue={editing.name}
                  required
                  maxLength={100}
                />
              </Field>
              <Field label="套餐代码">
                <input
                  name="code"
                  defaultValue={editing.code}
                  required
                  pattern="[a-z0-9_\-]{2,50}"
                />
              </Field>
              <Field label="对应 AWS 订阅">
                <SearchableSelect aria-label="对应 AWS 订阅"
                  name="subscription_type"
                  defaultValue={editing.subscription_type}
                >
                  {catalog.data?.items.map((tier) => (
                    <option
                      key={tier.subscription_type}
                      value={tier.subscription_type}
                    >
                      {tier.name}
                    </option>
                  ))}
                </SearchableSelect>
              </Field>
              <label className="check">
                <input
                  name="active"
                  type="checkbox"
                  defaultChecked={editing.active}
                />
                启用此套餐
              </label>
              <div className="modal-actions">
                {!editing.deleted_at && (
                  <button className="primary" disabled={busy}>
                    保存套餐
                  </button>
                )}
              </div>
            </fieldset>
          </form>
        </Modal>
      )}
    </>
  );
}
function AuditPage() {
  const { user } = useApp();
  const [page, setPage] = useState(1),
    { data, error } = useData<Page<Audit>>(`/audit?page=${page}`);
  return (
    <>
      <Header
        title="操作记录"
        description={
          user.role === "admin"
            ? "查看平台完整操作审计。"
            : "仅显示你本人执行的操作。"
        }
      />
      <ErrorBox text={error} />
      <section className="panel no-padding">
        {data?.items.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>时间</th>
                  <th>操作者</th>
                  <th>操作详情</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((r) => (
                  <tr key={r.id}>
                    <td className="date-cell">{date(r.created_at)}</td>
                    <td>{r.actor_name}</td>
                    <td>{r.detail}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <Empty>暂无操作记录。</Empty>
        )}
        <Pager page={page} total={data?.total || 0} onPage={setPage} />
      </section>
    </>
  );
}
