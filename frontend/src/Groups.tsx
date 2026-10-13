import { accountLabel } from "./provisioningLogic";
import { SearchableSelect } from "./SearchableSelect";
import { RetryStatus } from "./RetryStatus";
import {
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { NavLink, useSearchParams } from "react-router-dom";
import {
  api,
  date,
  groupJsonUrl,
  subscriptionStatus,
  type Account,
  type GroupDetail,
  type GroupItem,
  type GroupJob,
  type GroupPolicyPreview,
  type GroupPolicyRequest,
  type User,
  type LifecycleBatch,
  type CascadeBatch,
} from "./api";
import {
  policySummary,
  readStopPolicy,
  StopPolicyFields,
  StopRuleSource,
  StopScheduleEditor,
} from "./StopSchedule";
import {
  policyPreviewCurrent,
  runRecoverableSubmission,
  groupMemberStatus,
} from "./groupsLogic";
import { useGroupAccess, useGroupJobRecovery, useRemote, type GroupAccess } from "./groupRequests";
import { PasswordBatches } from "./PasswordBatches";
import { RecordPlanLabel } from "./PlanChangeManager";
import { GroupJoinNotice, LifecycleHistory, LifecycleRecovery, NativeGroupHistory, NativeSubscriptionDialog } from "./NativeSubscriptions";
import { useLifecycleAdmission } from "./nativeSubscriptionRequests";
import { activeNativeGroup, canCancelGroup, canSubscribeGroup, currentGroupSelection, filterGroups, groupSearchPath, nativeGrantStates } from "./nativeSubscriptionsLogic";
import { AwsGroupValue, GroupAwsPanel } from "./GroupAwsObservation";
import { useGroupObservations, type ObservationEntry } from "./groupObservationRequests";
import { GroupMemberManager } from "./GroupMembers";
import { CascadeDialog, CascadeHistory, CascadeSubmissionRecovery } from "./CascadeDeletion";
import { useCascadeAdmission } from "./cascadeRequests";

const groupState: Record<string, string> = {
  creating: "正在创建",
  linking: "正在关联",
  ready: "可用",
  updating: "正在更新",
  deleting: "正在删除",
  failed: "处理失败",
  needs_review: "待核对",
  deleted: "已删除 · 历史保留",
};
const jobKind: Record<string, string> = {
  create: "创建分组",
  link: "关联 AWS 分组",
  rename: "重命名分组",
  delete: "删除空分组",
  attach: "加入成员",
  detach: "移出成员",
};
const jobState: Record<string, string> = {
  queued: "等待处理",
  running: "正在处理",
  completed: "已完成",
  failed: "处理失败",
  needs_review: "待核对",
  cancelled: "已停止",
};
const skipReason: Record<string, string> = {
  sso_deleted: "SSO 已删除",
  plan_already_bound: "已绑定套餐",
  operation_pending: "存在处理中或待核对任务",
  sso_not_ready: "SSO 尚未就绪",
  membership_not_confirmed: "正在确认分组成员关系",
  existing_subscription: "已有订阅或待核对",
  group_not_ready: "分组尚未就绪",
  group_deadline_expired: "分组停止时间已过",
  deadline_expired: "个人停止时间已过",
  historical: "已取消或删除，保留历史",
  individual_override: "保留个人规则",
};
function GroupBadge({ state }: { state: string }) {
  return (
    <span
      className={`badge ${state === "ready" ? "completed" : ["failed", "needs_review"].includes(state) ? "failed" : ""}`}
    >
      <i />
      {groupState[state] || jobState[state] || "处理中"}
    </span>
  );
}
function ErrorBox({ text }: { text?: string }) {
  return text ? (
    <div className="error" role="alert">
      {text}
    </div>
  ) : null;
}
function GroupDialog({
  title,
  busy,
  close,
  children,
}: {
  title: string;
  busy: boolean;
  close: () => void;
  children: ReactNode;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    dialog.current?.showModal();
  }, []);
  return (
    <dialog
      ref={dialog}
      className="modal proxy-dialog group-dialog"
      aria-label={title}
      onCancel={(e) => {
        e.preventDefault();
        if (!busy) close();
      }}
    >
      <div className="modal-title">
        <h2>{title}</h2>
        <button
          className="icon-button"
          disabled={busy}
          aria-label="关闭"
          onClick={close}
        >
          ×
        </button>
      </div>
      {children}
    </dialog>
  );
}
interface GroupMutation {
  path: string;
  body: Record<string, unknown>;
  title: string;
}
type Mutate = (request: GroupMutation) => Promise<boolean>;
function readSavedMutation(key: string): GroupMutation | null {
  try {
    return JSON.parse(sessionStorage.getItem(key) || "null");
  } catch {
    return null;
  }
}

export function Groups({
  user,
  notify,
}: {
  user: User;
  notify: (message: string, error?: boolean) => void;
}) {
  const [params, setParams] = useSearchParams();
  const groupId = params.get("group_id");

  const actorScope = JSON.stringify([user.id, user.role, user.active, user.must_change_password, user.account_ids]);
  const accounts = useRemote<Account[]>("/accounts", 4000, user.id, actorScope);
  const owners = useRemote<User[]>(
    user.role === "admin" ? "/admin/users" : null,
    0, user.id, actorScope,
  );
  const [accountFilter, setAccountFilter] = useState("");
  const [ownerFilter, setOwnerFilter] = useState("");
  const [search, setSearch] = useState("");
  const [memberSearch, setMemberSearch] = useState("");
  const [stateFilter, setStateFilter] = useState("");
  const accountScope = JSON.stringify(accounts.data?.map(account => [account.id, account.active, account.deleted_at, account.aws_account_id,
    account.region, account.subscription_region, account.control_plane, account.identity_store_id, account.application_arn, account.profile_arn, account.proxy_id, account.proxy_status]));
  const permissionScope = `${actorScope}:${accountScope}:${accounts.forbidden}`;
  const access = useGroupAccess(user.id, permissionScope);
  const groups = useRemote<GroupItem[]>(groupSearchPath({ account: accountFilter, q: search, member: memberSearch }), 4000, user.id, permissionScope);
  const scope = `${permissionScope}:${groupId || ""}:${accountFilter}:${ownerFilter}:${stateFilter}:${search}:${memberSearch}`;
  const [selected, setSelected] = useState<string[]>([]);
  const selectionScope = useRef(scope);
  const [nativeAction, setNativeAction] = useState<"group_subscribe" | "group_cancel" | null>(null);
  const [latestBatch, setLatestBatch] = useState<LifecycleBatch | null>(null);
  const admission = useLifecycleAdmission(user.id, scope);
  const deletion = useCascadeAdmission(user.id, scope);
  const [deleteOpen, setDeleteOpen] = useState(false);
  useEffect(() => { selectionScope.current = scope; setSelected([]); setNativeAction(null); setDeleteOpen(false); }, [scope]);
  const filtered = filterGroups(groups.data || [], ownerFilter, stateFilter).filter(group => access.canAccess(group.id) && (user.role === "admin" || accounts.data?.some(account => account.id === group.aws_account_id && account.active && !account.deleted_at)));
  const observations = useGroupObservations(user.id, scope, groupId ? [] : filtered, access);
  const selectedIds = selectionScope.current === scope ? currentGroupSelection(selected, filtered) : [];
  const selectedGroups = selectedIds.map(id => filtered.find(group => group.id === id)!);
  function accepted(batch: LifecycleBatch) { observations.invalidate(batch.items.map(item => item.id)); setRefreshVersion(value => value + 1); setLatestBatch(batch); setNativeAction(null); setSelected([]); void groups.refresh(); notify("订阅请求已受理，可查看逐项进度"); }
  function deletionAccepted(batch: CascadeBatch) { observations.invalidate(batch.items.map(item => item.target_id)); setRefreshVersion(value => value + 1); setDeleteOpen(false); setSelected([]); void groups.refresh(); notify("取消订阅与删除分组已受理，可查看逐步进度"); }
  const [creating, setCreating] = useState<"create" | "link" | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [refreshVersion, setRefreshVersion] = useState(0);
  const storageKey = `kiro-group-request:${user.id}`;
  const [pending, setPending] = useState<GroupMutation | null>(() =>
    readSavedMutation(storageKey),
  );
  const users = owners.data || [user];
  const ownerName = (id: number) =>
    users.find((u) => u.id === id)?.display_name || "已停用或删除的用户";
  const accountName = (id: number) =>
    accounts.data?.find((a) => a.id === id)?.name || "已停用或删除的账号";
  async function mutate(request: GroupMutation): Promise<boolean> {
    if (busy) return false;
    if (pending && JSON.stringify(pending) !== JSON.stringify(request)) {
      setError("请先继续上次提交，确认结果后再发起新操作。");
      return false;
    }
    setBusy(true);
    setError("");
    try {
      const outcome = await runRecoverableSubmission(
        request,
        (path, body) => api(path, "POST", body),
        next => {
          if (next) sessionStorage.setItem(storageKey, JSON.stringify(next));
          else sessionStorage.removeItem(storageKey);
          setPending(next);
        },
        send => send<GroupItem | GroupJob>(request.path, request.body),
      );
      setCreating(null);
      if (outcome.state !== "accepted") {
        setError(outcome.error.message);
        if (outcome.state === "rejected") {
          setRefreshVersion(v => v + 1);
          await groups.refresh();
        }
        return false;
      }
      setRefreshVersion(v => v + 1);
      await groups.refresh();
      if (request.path === "/groups" || request.path === "/groups/link")
        setParams({ group_id: outcome.result.id });
      notify(`${request.title}已提交，处理进度会自动更新`);
      return true;
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <CascadeSubmissionRecovery admission={deletion} onAccepted={deletionAccepted} />
      {pending && (
        <section className="info-note group-recovery" role="status">
          <strong>上次“{pending.title}”的结果尚待确认。</strong>
          <p>
            继续使用原请求确认结果，避免重复创建或操作。刷新页面后也可继续。
          </p>
          <button
            className="secondary"
            disabled={busy}
            onClick={() => void mutate(pending)}
          >
            {busy ? "正在确认…" : "继续上次提交"}
          </button>
        </section>
      )}
      <ErrorBox text={error} />
      {(!groupId || access.canAccess(groupId)) && <LifecycleRecovery admission={admission} onAccepted={accepted} />}
      {groupId ? (
        <GroupDetails
          key={`${permissionScope}:${groupId}`}
          groupId={groupId}
          user={user}
          ownerName={ownerName}
          accountName={accountName}
          busy={busy}
          hasPending={!!pending}
          mutate={mutate}
          notify={notify}
          refreshVersion={refreshVersion}
          admission={admission}
          onAccepted={accepted}
          scope={scope}
          access={access}
          accountIds={accounts.data?.filter(account => account.active && !account.deleted_at).map(account => account.id) || []}
          accountsLoaded={accounts.data !== null || accounts.forbidden}
        />
      ) : (
        <>
          <div className="page-heading">
            <div>
              <h1>AWS 分组</h1>
              <p>
                按创建者与 AWS 账号管理真实分组，统一设置成员的停止订阅规则。
              </p>
            </div>
            <div className="proxy-buttons">
              {user.role === "admin" && (
                <button
                  className="secondary"
                  disabled={busy || !!pending}
                  onClick={() => {
                    setError("");
                    setCreating("link");
                  }}
                >
                  关联已有 AWS 分组
                </button>
              )}
              <button
                className="primary"
                disabled={busy || !!pending}
                onClick={() => {
                  setError("");
                  setCreating("create");
                }}
              >
                ＋ 创建分组
              </button>
            </div>
          </div>
          <ErrorBox text={groups.error || accounts.error || owners.error} />
          <section className="panel no-padding">
            <div className="table-toolbar group-filters">
              <input
                aria-label="搜索分组名称"
                placeholder="搜索分组名称"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              <input aria-label="搜索成员用户名" placeholder="搜索成员用户名（选择完整组）" value={memberSearch} onChange={event => setMemberSearch(event.target.value)} />
              <SearchableSelect aria-label="按分组状态筛选" value={stateFilter} onChange={event => setStateFilter(event.target.value)}><option value="">全部分组状态</option>{Object.entries(groupState).map(([state, label]) => <option key={state} value={state}>{label}</option>)}</SearchableSelect>
              <SearchableSelect
                aria-label="按 AWS 账号筛选"
                value={accountFilter}
                onChange={(e) => setAccountFilter(e.target.value)}
              >
                <option value="">全部 AWS 账号</option>
                {[
                  ...new Set((accounts.data || []).map((a) => a.id)),
                ].map((id) => (
                  <option key={id} value={id}>
                    {accounts.data?.find(a => a.id === id) ? accountLabel(accounts.data.find(a => a.id === id)!) : accountName(id)}
                  </option>
                ))}
              </SearchableSelect>
              {user.role === "admin" && (
                <SearchableSelect
                  aria-label="按创建者筛选"
                  value={ownerFilter}
                  onChange={(e) => setOwnerFilter(e.target.value)}
                >
                  <option value="">全部创建者</option>
                  {[...new Set(users.map((owner) => owner.id))].map(
                    (id) => (
                      <option key={id} value={id}>
                        {ownerName(id)}
                      </option>
                    ),
                  )}
                </SearchableSelect>
              )}
              <button
                className="secondary"
                onClick={() => void groups.refresh()}
              >
                刷新本地列表
              </button>
              <button className="secondary" disabled={observations.busy || !filtered.some(group => group.remote_id)} onClick={() => void observations.refresh(filtered)}>
                {observations.busy ? `正在读取 AWS ${observations.progress.done} / ${observations.progress.total}` : "刷新当前列表的 AWS 状态"}
              </button>
            </div>
            <div className="selection-toolbar" aria-label="分组批量选择">
              <span>已选 <strong>{selectedIds.length}</strong> / 100 个分组</span>
              {!!selectedGroups.length && selectedGroups.every(group => group.state === "ready" && !group.active_job_id && !group.deleted_at && !!group.remote_id)
                ? <NavLink className="secondary" to={groupJsonUrl(selectedIds)}>导出选中分组 JSON</NavLink>
                : <button className="secondary" disabled>导出选中分组 JSON</button>}
              <button className="primary" disabled={busy || !!pending || admission.busy || !!admission.pending || !selectedGroups.length || !selectedGroups.every(canSubscribeGroup)} onClick={() => setNativeAction("group_subscribe")}>开通原生分组订阅</button>
              <button className="danger" disabled={busy || !!pending || admission.busy || !!admission.pending || !selectedGroups.length || !selectedGroups.every(canCancelGroup)} onClick={() => setNativeAction("group_cancel")}>取消分组订阅</button>
              <button className="danger" disabled={busy || !!pending || admission.busy || deletion.busy || !!deletion.pending || !selectedGroups.length || selectedGroups.some(group => group.deleted_at || !["ready", "failed"].includes(group.state) || group.state === 'ready' && !!group.active_job_id)} onClick={() => setDeleteOpen(true)}>删除所选分组与全部 SSO</button>
              <button className="text-button" onClick={() => setSelected([])}>清空选择</button>
              <small>筛选成员用户名仍选择完整分组；更改筛选条件会清空选择。</small>
            </div>
            <GroupDirectoryTable groups={filtered} selected={selectedIds} onSelection={setSelected} disabled={admission.busy || !!admission.pending} isAdmin={user.role === "admin"} ownerName={ownerName} accountName={accountName}
              observations={observations.entries} awsBusy={observations.busy} onRefresh={group => void observations.refresh([group])} />
            {!filtered.length && (
              <div className="empty">
                <p>
                  {groups.loading
                    ? "正在读取分组…"
                    : groups.error
                      ? "暂时无法读取分组，请重试。"
                      : groups.data?.length
                        ? "没有符合筛选条件的分组。"
                        : "暂无分组。创建后可添加 SSO 成员并统一设置停止规则。"}
                </p>
              </div>
            )}
          </section>
        </>
      )}
      {(!groupId || access.canAccess(groupId)) && <LifecycleHistory key={`history:${permissionScope}:${groupId || "all"}`} actorId={user.id} initialBatch={latestBatch} groupId={groupId || undefined} />}
      {(!groupId || access.canAccess(groupId)) && <CascadeHistory actorId={user.id} scope={scope} groupId={groupId || undefined} kind="group" onChanged={() => { setRefreshVersion(value => value + 1); void groups.refresh(); }} />}
      {deleteOpen && <CascadeDialog key={scope} actorId={user.id} scope={scope} kind="group" ids={selectedIds} admission={deletion} close={() => setDeleteOpen(false)} onAccepted={deletionAccepted} />}
      {nativeAction && <NativeSubscriptionDialog key={`${scope}:${nativeAction}`} kind={nativeAction} user={user} groups={selectedGroups} admission={admission} close={() => setNativeAction(null)} onAccepted={accepted} />}
      {creating && (
        <CreateGroupDialog
          kind={creating}
          user={user}
          users={users}
          accounts={accounts.data || []}
          busy={busy || !!pending}
          error={error}
          close={() => setCreating(null)}
          mutate={mutate}
        />
      )}
    </>
  );
}

export function GroupDirectoryTable({ groups, isAdmin, ownerName, accountName, selected = [], onSelection, disabled = false, observations = {}, awsBusy = false, onRefresh }: {
  groups: GroupItem[]; isAdmin: boolean; ownerName: (id: number) => string; accountName: (id: number) => string;
  selected?: string[]; onSelection?: (ids: string[]) => void; disabled?: boolean;
  observations?: Record<string, ObservationEntry>; awsBusy?: boolean; onRefresh?: (group: GroupItem) => void;
}) {
  return (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    {onSelection && <th><input type="checkbox" aria-label="选择当前结果中的分组" disabled={disabled || !groups.some(group => !group.deleted_at)} checked={groups.some(group => !group.deleted_at) && groups.filter(group => !group.deleted_at).every(group => selected.includes(group.id))} onChange={event => onSelection(event.target.checked ? currentGroupSelection(groups.map(group => group.id), groups) : [])} /></th>}
                    <th>分组</th>
                    <th>AWS 账号{isAdmin ? " / 创建者" : ""}</th>
                    <th>AWS 成员 / 本地记录</th>
                    <th>当前 Kiro 套餐 / 状态</th>
                    <th>待生效套餐 / 取消日期</th>
                    <th>停止截止 / 分组规则</th>
                    <th>本地任务状态</th>
                    <th>创建时间</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {groups.map((g) => (
                    <tr key={g.id} className={selected.includes(g.id) ? "selected-record" : undefined}>
                      {onSelection && <td><input type="checkbox" aria-label={`选择分组 ${g.name}`} checked={selected.includes(g.id)} disabled={disabled || !!g.deleted_at || selected.length >= 100 && !selected.includes(g.id)} onChange={event => onSelection(event.target.checked ? [...selected, g.id] : selected.filter(id => id !== g.id))} /></td>}
                      <td>
                        <NavLink
                          className="group-name"
                          to={`/groups?group_id=${encodeURIComponent(g.id)}`}
                        >
                          {observations[g.id]?.data?.directory.name || (g.state === "linking" && g.name === g.remote_id
                            ? "正在关联的分组"
                            : g.name)}
                        </NavLink>
                        <small>本地名称：{g.name}</small>
                        {observations[g.id]?.data && <small>查询：{date(observations[g.id].data!.queried_at)}</small>}
                        {g.native_subscription && <small>本地订阅记录：{g.native_subscription.plan_name} · GROUP · {nativeGrantStates[g.native_subscription.state]}</small>}
                      </td>
                      <td>
                        {accountName(g.aws_account_id)}
                        {isAdmin && (
                          <small>{ownerName(g.owner_id)}</small>
                        )}
                      </td>
                      <td>
                        <AwsGroupValue entry={observations[g.id]} field="members" />
                        {g.counts ? <>
                          <small>本地成员记录 {g.counts.total} 条</small>
                          <small>本地已创建 SSO {g.counts.active} 人 · 可订阅 {g.counts.eligible} 人</small>
                          {g.counts.unconfirmed !== undefined && <small>尚未确认创建 {g.counts.unconfirmed} 人 · 本地确认加组 {g.counts.joined} 人</small>}
                          <small>累计已订阅 {g.counts.subscribed} 人</small>
                        </> : <span className="muted">统计暂不可用</span>}
                      </td>
                      <td><AwsGroupValue entry={observations[g.id]} field="subscription" /></td>
                      <td><AwsGroupValue entry={observations[g.id]} field="pending" /></td>
                      <td>
                        <span className="rule-source-label from-group">
                          分组规则
                        </span>
                        <small>{policySummary(g.policy)}</small>
                        {g.native_subscription?.stop_at && <small>本地执行截止：{date(g.native_subscription.stop_at)}</small>}
                      </td>
                      <td>
                        <GroupBadge state={g.state} />
                        {g.error && (
                          <small className="error-text">{g.error}</small>
                        )}
                      </td>
                      <td className="date-cell">
                        {date(g.created_at)}
                        {g.deleted_at && (
                          <small>删除：{date(g.deleted_at)}</small>
                        )}
                      </td>
                      <td>
                        <NavLink
                          to={`/groups?group_id=${encodeURIComponent(g.id)}`}
                        >
                          {g.deleted_at ? "查看历史" : "详情 / 管理"}
                        </NavLink>
                        {onRefresh && <button className="text-button" disabled={awsBusy || !g.remote_id} aria-label={`刷新 ${g.name} 的 AWS 状态`} onClick={() => onRefresh(g)}>刷新 AWS 状态</button>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
  );
}

function CreateGroupDialog({
  kind,
  user,
  users,
  accounts,
  busy,
  error,
  close,
  mutate,
}: {
  kind: "create" | "link";
  user: User;
  users: User[];
  accounts: Account[];
  busy: boolean;
  error: string;
  close: () => void;
  mutate: Mutate;
}) {
  const [accountId, setAccountId] = useState("");
  const [ownerId, setOwnerId] = useState(String(user.id));
  const [localError, setLocalError] = useState("");
  const key = useRef(crypto.randomUUID());
  const remote = useRemote<{ id: string; name: string; description: string }[]>(
    kind === "link" && accountId ? `/admin/aws/${accountId}/groups` : null,
  );
  const selectedOwner = users.find((u) => u.id === Number(ownerId));
  const allowedAccounts = accounts.filter(
    (a) =>
      a.active &&
      (selectedOwner?.role === "admin" ||
        selectedOwner?.account_ids?.includes(a.id) ||
        (user.role !== "admin" && Number(ownerId) === user.id)),
  );
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const name = String(f.get("name") || "").trim();
    if (kind === "create" && !name) {
      setLocalError("请填写分组名称。");
      return;
    }
    const body = {
      aws_account_id: Number(accountId),
      owner_id: Number(ownerId),
      request_key: key.current,
      ...(kind === "link" ? { remote_id: f.get("remote_id") } : { name }),
    };
    if (
      await mutate({
        path: kind === "link" ? "/groups/link" : "/groups",
        body,
        title: kind === "link" ? "关联分组" : "创建分组",
      })
    )
      close();
  }
  return (
    <GroupDialog
      title={kind === "link" ? "关联已有 AWS 分组" : "创建 AWS 分组"}
      busy={busy}
      close={close}
    >
      <form onSubmit={submit}>
        <ErrorBox text={localError || error || remote.error} />
        <fieldset className="resource-fields" disabled={busy}>
          {user.role === "admin" && (
            <label className="field">
              <span>分组创建者</span>
              <SearchableSelect aria-label="分组创建者"
                required
                value={ownerId}
                onChange={(e) => {
                  setOwnerId(e.target.value);
                  setAccountId("");
                }}
              >
                {users
                  .filter((u) => u.active)
                  .map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.display_name} · {u.username}
                    </option>
                  ))}
              </SearchableSelect>
            </label>
          )}
          <label className="field">
            <span>AWS 账号</span>
            <SearchableSelect aria-label="AWS 账号"
              required
              value={accountId}
              onChange={(e) => setAccountId(e.target.value)}
            >
              <option value="">请选择 AWS 账号</option>
              {allowedAccounts.map((a) => (
                <option key={a.id} value={a.id}>
                  {accountLabel(a)} · {a.region}
                </option>
              ))}
            </SearchableSelect>
            <small>分组成员必须属于同一创建者与 AWS 账号。</small>
          </label>
          {kind === "create" ? (
            <label className="field">
              <span>分组名称</span>
              <input
                name="name"
                required
                maxLength={1024}
                placeholder="例如：研发团队"
              />
            </label>
          ) : (
            <label className="field">
              <span>可关联的 AWS 分组</span>
              <SearchableSelect aria-label="可关联的 AWS 分组"
                key={accountId}
                name="remote_id"
                required
                disabled={!accountId || remote.loading}
              >
                <option value="">
                  {remote.loading ? "正在读取…" : "请选择尚未关联的分组"}
                </option>
                {remote.data?.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </SearchableSelect>
              {accountId &&
                !remote.loading &&
                !remote.error &&
                !remote.data?.length && (
                  <small>该账号没有可关联的 AWS 分组。</small>
                )}
            </label>
          )}
          <p className="info-note">
            {kind === "link"
              ? "关联后由该创建者管理；AWS 中已有但未由平台管理的成员关系会保留。"
              : "分组会先在 AWS 创建。未开通原生订阅时加入成员免费；生效中的原生分组会自动授权并按人计次。"}
          </p>
          <div className="modal-actions">
            <button type="button" className="secondary" onClick={close}>
              取消
            </button>
            <button className="primary">
              {busy ? "正在提交…" : kind === "link" ? "关联分组" : "创建分组"}
            </button>
          </div>
        </fieldset>
      </form>
    </GroupDialog>
  );
}

function GroupDetails({
  groupId,
  user,
  ownerName,
  accountName,
  busy,
  mutate,
  notify,
  refreshVersion,
  hasPending,
  admission,
  onAccepted,
  scope,
  accountIds,
  accountsLoaded,
  access,
}: {
  groupId: string;
  user: User;
  ownerName: (id: number) => string;
  accountName: (id: number) => string;
  busy: boolean;
  hasPending: boolean;
  mutate: Mutate;
  notify: (message: string, error?: boolean) => void;
  refreshVersion: number;
  admission: ReturnType<typeof useLifecycleAdmission>;
  onAccepted: (batch: LifecycleBatch) => void;
  scope: string;
  accountIds: number[];
  accountsLoaded: boolean;
  access: GroupAccess;
}) {
  const permitted = access.canAccess(groupId), denied = () => access.deny(groupId);
  const detail = useRemote<GroupDetail>(permitted ? `/groups/${groupId}` : null, 3000, user.id, scope, denied);
  const accessible = permitted && (user.role === "admin" || !!detail.data && accountIds.includes(detail.data.aws_account_id));
  useEffect(() => { if (detail.data && accountsLoaded && !accessible) access.deny(groupId); }, [detail.data, accountsLoaded, accessible, access.deny, groupId]);
  const observations = useGroupObservations(user.id, scope, detail.data && accessible && !detail.forbidden ? [detail.data] : [], access);
  const [params, setParams] = useSearchParams();
  const [passwordOpen, setPasswordOpen] = useState(params.has("password_batch"));
  useEffect(() => { if (params.has("password_batch")) setPasswordOpen(true); }, [params]);
  const jobs = useRemote<GroupJob[]>(permitted ? `/groups/${groupId}/jobs` : null, 3000, user.id, scope, denied);
  const [action, setAction] = useState<"rename" | "delete" | null>(
    null,
  );
  const [ruleRecordId, setRuleRecordId] = useState<string | null>(null);
  const [subscriptionOpen, setSubscriptionOpen] = useState<"group_subscribe" | "group_cancel" | null>(null);
  const recovery = useGroupJobRecovery(user.id, groupId, scope, access);
  const deletion = useCascadeAdmission(user.id, `${scope}:${groupId}`);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [error, setError] = useState("");
  const requestKey = useRef(crypto.randomUUID());
  useEffect(() => {
    observations.invalidate([groupId]);
    void detail.refresh();
    void jobs.refresh();
  }, [refreshVersion, detail.refresh, jobs.refresh]);
  useEffect(() => {
    if (hasPending && !busy) {
      setAction(null);
    }
  }, [hasPending, busy]);
  const group = accessible ? detail.data : null;
  if (!group)
    return (
      <>
        <NavLink to="/groups">← 分组目录</NavLink>
        <ErrorBox text={detail.error} />
        <div className="empty">
          <p>
            {!permitted ? "当前分组访问权限已变化，请重新加载页面核对。" : detail.loading
              ? "正在读取分组…"
              : "无法读取该分组，请刷新后重试。"}
          </p>
          <button className="secondary" onClick={() => { if (permitted) void detail.refresh(); else window.location.reload(); }}>
            {permitted ? "重新读取" : "重新加载页面"}
          </button>
        </div>
      </>
    );
  const ready =
    group.state === "ready" &&
    !group.active_job_id &&
    !group.deleted_at &&
    !hasPending && accessible;
  const failedJob = jobs.data?.find((j) => j.id === group.active_job_id);
  const recoverFailed =
    group.state === "failed" &&
    failedJob?.state === "failed" &&
    failedJob.phase === "ready" &&
    !failedJob.record_id &&
    !hasPending;
  const recoverName =
    recoverFailed &&
    !group.remote_id &&
    ["create", "rename"].includes(failedJob.kind);
  const discardCancelledCreate =
    group.state === "failed" && !group.remote_id && !group.active_job_id &&
    !group.deleted_at && !hasPending &&
    !!jobs.data?.some(j => j.kind === "create" && j.state === "cancelled" && j.phase === "ready" && !j.record_id);
  const canCascadeDelete = ready || (accessible && !hasPending && !group.deleted_at && group.state === 'failed' &&
    (!group.active_job_id || failedJob && ['failed', 'cancelled'].includes(failedJob.state) && failedJob.phase === 'ready' && !failedJob.record_id));
  const canEmptyDelete = !group.members.some(
    (r) =>
      !r.sso_deleted_at ||
      r.operation_pending ||
      !!r.operation ||
      ["queued", "running", "needs_review"].includes(r.state),
  );
  const ruleRecord = group.members.find((r) => r.id === ruleRecordId);
  function choose(next: typeof action) {
    requestKey.current = crypto.randomUUID();
    setError("");
    setAction(next);
  }
  async function submitAction(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!group) return;
    const f = new FormData(e.currentTarget);
    if (action === "delete" && f.get("confirm_name") !== group.name) {
      setError("请完整输入分组名称以确认删除。");
      return;
    }
    const kind = action;
    const body: Record<string, unknown> = {
      kind,
      expected_revision: group.revision,
      request_key: requestKey.current,
    };
    if (kind === "rename") {
      body.name = String(f.get("name") || "").trim();
      if (!body.name) {
        setError("请填写分组名称。");
        return;
      }
    }
    if (
      await mutate({
        path: `/groups/${group.id}/jobs`,
        body,
        title: jobKind[kind || ""],
      })
    ) {
      setAction(null);
    }
  }
  async function retry() {
    if (!failedJob || !access.canAccess(groupId)) return;
    setError("");
    if (await recovery.submit(failedJob)) {
      observations.invalidate([groupId]);
      await detail.refresh();
      await jobs.refresh();
      notify("已提交核对与继续处理");
    }
  }
  return (
    <>
      <NavLink to="/groups" className="group-back">
        ← 分组目录
      </NavLink>
      <div className="page-heading">
        <div>
          <h1 className="group-title">
            {observations.entries[group.id]?.data?.directory.name || (group.state === "linking" && group.name === group.remote_id
              ? "正在关联的分组"
              : group.name)}
          </h1>
          <p>
            {accountName(group.aws_account_id)} · {ownerName(group.owner_id)} ·{" "}
            <GroupBadge state={group.state} />
          </p>
          <p className="muted">本地名称：{group.name}</p>
        </div>
        <div className="proxy-buttons">
          <button
            className="secondary"
            disabled={busy || !(ready || recoverName)}
            onClick={() => choose("rename")}
          >
            重命名
          </button>
          <button
            className="danger"
            disabled={busy || !(ready || recoverFailed || discardCancelledCreate) || !canEmptyDelete}
            title={
              canEmptyDelete
                ? discardCancelledCreate ? "删除尚未在 AWS 创建的本地空分组" : "确认 AWS 分组为空后删除"
                : "请先移出或删除全部现存成员，并等待所有任务完成"
            }
            onClick={() => choose("delete")}
          >
            删除空分组
          </button>
          <button className="danger" disabled={busy || deletion.busy || !!deletion.pending || !canCascadeDelete} onClick={() => setDeleteOpen(true)}>
            删除分组与全部 SSO
          </button>
        </div>
      </div>
      <ErrorBox text={error || recovery.error || detail.error || group.error || jobs.error} />
      <CascadeSubmissionRecovery admission={deletion} onAccepted={() => { setDeleteOpen(false); observations.invalidate([group.id]); void detail.refresh(); notify("级联删除已受理，可查看逐步进度"); }} />
      {deleteOpen && accessible && <CascadeDialog key={`${scope}:${group.id}`} actorId={user.id} scope={`${scope}:${groupId}`} kind="group" ids={[group.id]} admission={deletion} close={() => setDeleteOpen(false)}
        onAccepted={() => { setDeleteOpen(false); observations.invalidate([group.id]); void detail.refresh(); notify("级联删除已受理，可查看逐步进度"); }} />}
      <CascadeHistory actorId={user.id} scope={`${scope}:${groupId}`} groupId={group.id} onChanged={() => { observations.invalidate([group.id]); void detail.refresh(); void jobs.refresh(); }} />
      {!ready && !group.deleted_at && (
        <div className="info-note" role="status">
          {discardCancelledCreate
            ? "创建已停止，仅保留本地记录；可删除空分组并保留操作历史。"
            : group.state === "needs_review"
            ? "上次操作的 AWS 结果尚待核对。可继续同一任务核对实际结果。"
            : group.state === "failed"
              ? "分组任务失败，查看下方原因后可继续同一任务。"
              : "分组操作正在后台处理，进度会自动更新。"}
        </div>
      )}
      {group.deleted_at && (
        <p className="info-note">
          分组已删除于 {date(group.deleted_at)}。成员与操作历史保留，只读展示。
        </p>
      )}
      <GroupAwsPanel entry={observations.entries[group.id]} busy={observations.busy} disabled={!accessible || !group.remote_id} refresh={() => void observations.refresh([group])} />
      <section className="panel group-overview">
        <h2>本地成员记录与停止规则</h2>
        <div className="group-counts">
          <span>
            本地记录（含创建任务） <strong>{group.counts.total}</strong>
          </span>
          <span>
            本地已创建 SSO <strong>{group.counts.active}</strong>
          </span>
          {group.counts.unconfirmed !== undefined && <span>尚未确认创建 <strong>{group.counts.unconfirmed}</strong></span>}
          {group.counts.joined !== undefined && <span>本地确认加组 <strong>{group.counts.joined}</strong></span>}
          <span>
            可开通订阅 <strong>{group.counts.eligible}</strong>
          </span>
          <span>
            曾订阅 <strong>{group.counts.subscribed}</strong>
          </span>
          <span>
            已取消 <strong>{group.counts.cancelled}</strong>
          </span>
          <span>
            已删除 <strong>{group.counts.deleted}</strong>
          </span>
        </div>
        <div className="rule-source">
          <span className="rule-source-label from-group">分组规则</span>
          <strong>{policySummary(group.policy)}</strong>
        </div>
        <p className="muted">
          新成员默认继承分组规则。原生分组的天数从本次分组开通起算，后来加入者继承剩余时长；个人更早的截止时间继续生效。
        </p>
      </section>
      <GroupJoinNotice group={group} />
      <section className="panel group-kiro-actions" aria-label="Kiro 分组订阅管理"><h2>Kiro 分组订阅管理</h2>
        <p className="muted">开通与取消以整组为单位；原生订阅与个人 USER 订阅分别保留。</p>
        <div className="proxy-buttons"><button className="primary" disabled={busy || !ready || !!admission.pending || admission.busy || !canSubscribeGroup(group)} onClick={() => setSubscriptionOpen("group_subscribe")}>开通原生分组订阅</button>
          <button className="danger" disabled={busy || !ready || !!admission.pending || admission.busy || !canCancelGroup(group)} onClick={() => setSubscriptionOpen("group_cancel")}>取消分组订阅</button>
          <NavLink className="secondary" to={`/subscribe?group_id=${encodeURIComponent(group.id)}`}>按用户批量订阅</NavLink></div>
      </section>
      <GroupMemberManager key={`${scope}:${group.id}`} group={group} user={user} scope={scope} access={access} accessible={accessible && !detail.forbidden} blocked={busy || !ready || admission.busy || !!admission.pending}
        onChanged={() => { observations.invalidate([group.id]); void detail.refresh(); void jobs.refresh(); }} />
      <section className="panel no-padding group-members">
        <div className="group-section-heading">
          <div>
            <h2>成员</h2>
            <p className="muted">包括计划创建、失败和历史记录，不代表这些用户都已存在。AWS 实际成员以上方“刷新 AWS 状态”的查询为准；已创建用户可在 SSO 目录查看，未完成任务可在原批次恢复。</p>
          </div>
          <div className="proxy-buttons">
            {(group.owner_id === user.id || user.role === "admin") && !group.deleted_at && ready &&
              <NavLink className="secondary" to={groupJsonUrl([group.id])}>导出整组 JSON</NavLink>}
            {group.owner_id === user.id && !group.deleted_at && <>
              <button className="secondary" disabled={busy || !ready} onClick={() => setPasswordOpen(true)}>批量改密</button>
            </>}
            <button className="text-button" onClick={() => setPasswordOpen(true)}>改密记录</button>
            <NavLink
              className="secondary"
              to={`/sso?group_id=${encodeURIComponent(group.id)}`}
            >
              查看 SSO 目录
            </NavLink>
          </div>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>SSO 用户</th>
                <th>订阅 / 原套餐</th>
                <th>停止规则来源</th>
                <th>成员状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {group.members.map((r) => (
                <tr key={r.id}>
                  <td>
                    <strong>{r.username}</strong>
                    <small>{r.email}</small>
                  </td>
                  <td>
                    {subscriptionStatus(r)}
                    <RecordPlanLabel record={r} directory />
                    <small>首次套餐：{r.plan_name}</small>
                    {r.subscribed_at && (
                      <small>订阅：{date(r.subscribed_at)}</small>
                    )}
                  </td>
                  <td>
                    <StopRuleSource record={r} group={group} />
                  </td>
                  <td>
                    {groupMemberStatus(r)}
                    <RetryStatus value={r} />
                    {r.error && !r.propagation_state && <small className="muted">{r.error}</small>}
                  </td>
                  <td>
                    <div className="row-actions">
                      <button
                        className="text-button"
                        onClick={() => setRuleRecordId(r.id)}
                      >
                        {group.deleted_at || r.sso_deleted_at || r.cancelled_at
                          ? "查看历史规则"
                          : "查看 / 设置规则"}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!group.members.length && (
          <div className="empty">
            <p>暂无成员。添加已有 SSO，或创建新 SSO 时选择此分组。</p>
            {user.id === group.owner_id && ready && (
              <NavLink
                to={`/create?group_id=${encodeURIComponent(group.id)}&account_id=${group.aws_account_id}`}
              >
                创建分组成员 →
              </NavLink>
            )}
          </div>
        )}
      </section>
      <NativeGroupHistory key={`native-history:${scope}:${group.id}`} actorId={user.id} group={group} />
      {passwordOpen && <PasswordBatches key={`${user.id}:${group.id}`} user={user} groupId={group.id} notify={notify} onChanged={() => void detail.refresh()} onClose={() => {
        setPasswordOpen(false);
        setParams(old => { const next = new URLSearchParams(old); next.delete("password_batch"); return next; });
      }} />}
      <GroupPolicyEditor
        key={`${group.id}:${group.policy.revision}`}
        group={group}
        blocked={busy || !ready}
        onChanged={() => {
          void detail.refresh();
          notify("分组停止规则已保存");
        }}
      />
      <section className="panel group-jobs">
        <div className="group-section-heading">
          <div>
            <h2>操作进度与历史</h2>
            <p className="muted">最近 100 项操作；刷新页面后继续追踪。</p>
          </div>
          {["failed", "needs_review"].includes(group.state) &&
            group.active_job_id && failedJob && !failedJob.member_batch_id && (
              <button
                className="secondary"
                disabled={busy || recovery.busy}
                onClick={retry}
              >
                {recovery.busy ? "正在提交…" : "核对并继续同一任务"}
              </button>
            )}
        </div>
        {jobs.data?.length ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>操作</th>
                  <th>成员</th>
                  <th>状态</th>
                  <th>时间</th>
                  <th>结果 / 原因</th>
                </tr>
              </thead>
              <tbody>
                {jobs.data.map((j) => (
                  <tr key={j.id}>
                    <td>{jobKind[j.kind] || "分组操作"}</td>
                    <td>
                      {j.record_id
                        ? group.members.find((r) => r.id === j.record_id)
                            ?.username || "成员记录"
                        : "—"}
                    </td>
                    <td>{jobState[j.state] || "处理中"}</td>
                    <td className="date-cell">
                      {date(j.created_at)}
                      {j.finished_at && (
                        <small>完成：{date(j.finished_at)}</small>
                      )}
                    </td>
                    <td>
                      {j.error ||
                        (j.state === "completed"
                          ? "处理完成"
                          : j.state === "needs_review"
                            ? "需要核对 AWS 实际结果"
                            : "—")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="muted">
            {jobs.loading ? "正在读取操作记录…" : "暂无可查看的操作记录。"}
          </p>
        )}
      </section>
      {(action === "rename" || action === "delete") && (
        <GroupDialog
          title={
            action === "rename"
                ? "重命名分组"
                : "删除空分组"
          }
          busy={busy}
          close={() => {
            setAction(null);
          }}
        >
          <form onSubmit={submitAction}>
            <ErrorBox text={error} />
            <fieldset className="resource-fields" disabled={busy}>
              {action === "rename" ? (
                <label className="field">
                  <span>新的分组名称</span>
                  <input
                    name="name"
                    required
                    maxLength={1024}
                    defaultValue={group.name}
                  />
                </label>
              ) : (
                <>
                  <p>
                    {discardCancelledCreate
                      ? <>删除「{group.name}」的本地记录；创建任务已停止，操作历史保留。</>
                      : <>删除「{group.name}」。提交后还会核对 AWS 分组为空；已删除成员的历史保留。</>}
                  </p>
                  <label className="field">
                    <span>输入分组名称确认</span>
                    <input name="confirm_name" required autoComplete="off" />
                  </label>
                </>
              )}
              <div className="modal-actions">
                <button
                  className="secondary"
                  type="button"
                  onClick={() => {
                    setAction(null);
                  }}
                >
                  取消
                </button>
                <button className={action === "delete" ? "danger" : "primary"}>
                  {busy
                    ? "正在提交…"
                    : action === "rename"
                        ? "保存名称"
                        : "确认删除空分组"}
                </button>
              </div>
            </fieldset>
          </form>
        </GroupDialog>
      )}
      {ruleRecord && (
        <GroupDialog
          title={`${ruleRecord.username} · 停止规则`}
          busy={false}
          close={() => setRuleRecordId(null)}
        >
          <p className="muted">
            原绑定套餐：{ruleRecord.plan_name} · 订阅时间：
            {date(ruleRecord.subscribed_at)}（只读）
          </p>
          <StopScheduleEditor
            record={ruleRecord}
            group={group}
            blocked={busy || !ready || ruleRecord.operation_pending}
            onChanged={() => void detail.refresh()}
          />
        </GroupDialog>
      )}
      {subscriptionOpen && (
        <NativeSubscriptionDialog kind={subscriptionOpen} user={user} groups={[group]} admission={admission}
          close={() => setSubscriptionOpen(null)} onAccepted={batch => { observations.invalidate([group.id]); setSubscriptionOpen(null); void detail.refresh(); onAccepted(batch); }} />
      )}
    </>
  );
}


function GroupPolicyEditor({
  group,
  blocked,
  onChanged,
}: {
  group: GroupDetail;
  blocked: boolean;
  onChanged: () => void;
}) {
  const [review, setReview] = useState<{
    request: GroupPolicyRequest;
    result: GroupPolicyPreview;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const form = useRef<HTMLFormElement>(null);
  function readRequest(): GroupPolicyRequest {
    const data = new FormData(form.current!);
    return {
      policy: readStopPolicy(data),
      expected_revision: group.policy.revision,
      overwrite_individual: data.get("overwrite_individual") === "on",
    };
  }
  async function preview(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError("");
    setReview(null);
    try {
      const request = readRequest();
      const result = await api<GroupPolicyPreview>(
        `/groups/${group.id}/policy/preview`,
        "POST",
        request,
      );
      setReview({ request, result });
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function save() {
    if (!review || !form.current?.reportValidity()) return;
    if (
      !policyPreviewCurrent(
        review.request,
        readRequest(),
        group.policy.revision,
      )
    ) {
      setReview(null);
      setError("规则已变化，请重新预览后保存。");
      return;
    }
    setBusy(true);
    setError("");
    try {
      await api(`/groups/${group.id}/policy`, "PUT", review.request);
      setReview(null);
      onChanged();
    } catch (e) {
      setReview(null);
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const name = (id: string) =>
    group.members.find((r) => r.id === id)?.username || "成员记录";
  return (
    <section className="panel group-policy-panel">
      <h2>分组停止订阅规则</h2>
      <p className="muted">
        修改前先预览影响范围。已取消、已删除的记录保留原规则；新加入的成员使用保存后的规则。
      </p>
      <ErrorBox text={error} />
      {group.deleted_at ? (
        <p>{policySummary(group.policy)}</p>
      ) : (
        <form ref={form} onSubmit={preview} onChange={() => setReview(null)}>
          <fieldset className="resource-fields" disabled={blocked || busy}>
            <StopPolicyFields initial={group.policy} nativeGroup={activeNativeGroup(group)} subscribedAt={activeNativeGroup(group) ? group.native_subscription?.activated_at : undefined} />
            <label className="check-line">
              <input type="checkbox" name="overwrite_individual" />
              同时覆盖成员的个人规则
            </label>
            <p className="muted">
              默认保留个人设置；勾选后，这些成员恢复使用分组规则。
            </p>
            <div className="proxy-buttons">
              <button className="secondary">
                {busy ? "正在处理…" : "预览影响范围"}
              </button>
              <button
                type="button"
                className="primary"
                disabled={!review || !!review.result.conflict_count}
                onClick={save}
              >
                保存已预览的规则
              </button>
            </div>
          </fieldset>
        </form>
      )}
      {review && (
        <div className="group-policy-preview" role="status">
          <h3>本次修改预览</h3>
          <p>
            <strong>影响 {review.result.affected_count} 人</strong> · 跳过{" "}
            {review.result.skipped_count} 人 · 冲突{" "}
            {review.result.conflict_count} 人
          </p>
          <p>
            {policySummary(review.request.policy)} ·{" "}
            {review.request.overwrite_individual
              ? "覆盖个人规则"
              : "保留个人规则"}
          </p>
          {review.result.conflict_count > 0 && (
            <p className="error">
              有成员正在处理或待核对，请等待任务完成后重新预览。此次规则尚未保存。
            </p>
          )}
          <details>
            <summary>查看成员明细</summary>
            <ul className="group-preview-list">
              {review.result.affected_ids.map((id) => (
                <li key={id}>{name(id)} · 将应用新规则</li>
              ))}
              {review.result.skipped.map((r) => (
                <li key={r.id}>
                  {name(r.id)} · {skipReason[r.reason] || "暂不处理"}
                </li>
              ))}
              {review.result.conflicts.map((r) => (
                <li key={r.id}>
                  {name(r.id)} · {skipReason[r.reason] || "待核对"}
                </li>
              ))}
            </ul>
          </details>
        </div>
      )}
    </section>
  );
}
