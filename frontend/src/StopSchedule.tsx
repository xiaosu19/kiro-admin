import { SearchableSelect } from "./SearchableSelect";
import { useState, type FormEvent } from "react";
import { NavLink } from "react-router-dom";
import { canEditStopRule, resetToGroupRequest } from "./groupsLogic";
import { nativeAccess, independentUserAccess } from "./nativeSubscriptionsLogic";
import {
  api,
  type RecordItem,
  type GroupItem,
  type StopPolicy,
  type StopSchedule,
} from "./api";

export const stopState: Record<string, string> = {
  waiting: "等待开通后计时",
  scheduled: "等待到期",
  blocked: "执行受阻",
  queued: "正在停止",
  running: "正在停止",
  needs_review: "待核对",
  failed: "执行失败",
  completed: "已完成",
  disabled: "已关闭",
};
export function stopTime(value: string | null) {
  return value
    ? new Date(value.endsWith("Z") ? value : value + "Z").toLocaleString(
        "zh-CN",
        {
          timeZone: "Asia/Shanghai",
          hour12: false,
        },
      ) + " (UTC+8)"
    : "等待开通成功";
}
function localInput(value: string | null) {
  return value
    ? new Date(
        new Date(value.endsWith("Z") ? value : value + "Z").getTime() +
          8 * 3600000,
      )
        .toISOString()
        .slice(0, 16)
    : "";
}
export function readStopPolicy(form: FormData): StopPolicy {
  const mode = form.get("stop_mode") as StopPolicy["mode"];
  if (mode === "days") return { mode, days: Number(form.get("stop_days")) };
  if (mode === "at")
    return {
      mode,
      stop_at: new Date(String(form.get("stop_at")) + "+08:00").toISOString(),
    };
  return { mode: "none" };
}

function userDeadline(record: RecordItem) {
  const principal = record.stop_schedule?.principal_type;
  return principal ? principal === "USER" : independentUserAccess(record);
}

export function StopPolicyFields({
  initial,
  subscribedAt,
  nativeGroup = false,
  independentUser = false,
  maxStopAt,
  namePrefix = "",
  labelPrefix = "",
  value,
  onChange,
}: {
  initial?: Pick<StopSchedule, "mode" | "days" | "stop_at"> | null;
  subscribedAt?: string | null;
  nativeGroup?: boolean;
  independentUser?: boolean;
  maxStopAt?: string | null;
  namePrefix?: string;
  labelPrefix?: string;
  value?: StopPolicy;
  onChange?: (value: StopPolicy) => void;
}) {
  const [localMode, setMode] = useState(initial?.mode || "none");
  const mode = value?.mode || localMode;
  return (
    <fieldset className="stop-policy">
      <legend>{labelPrefix}定时停止订阅</legend>
      <label className="field">
        <span>停止方式</span>
        <SearchableSelect aria-label={`${labelPrefix}停止方式`}
          name={`${namePrefix}stop_mode`}
          value={mode}
          onChange={(e) => {
            const next = e.target.value as StopPolicy["mode"];
            setMode(next);
            onChange?.(next === "days" ? { mode: next, days: value?.days || 30 } : next === "at" ? { mode: next, stop_at: value?.stop_at || "" } : { mode: next });
          }}
        >
          <option value="none">不定时停止</option>
          <option value="days">开通后若干天</option>
          <option value="at">指定日期时间</option>
        </SearchableSelect>
      </label>
      {mode === "days" && (
        <label className="field">
          <span>开通后天数</span>
          <input
            name={`${namePrefix}stop_days`}
            aria-label={`${labelPrefix}开通后天数`}
            type="number"
            min={1}
            max={3650}
            step={1}
            required
            defaultValue={value ? undefined : initial?.days || 30}
            value={value ? value.days ?? "" : undefined}
            onChange={onChange ? e => onChange({ mode: "days", days: Number(e.target.value) }) : undefined}
          />
          <small>
            {nativeGroup ? subscribedAt ? `从本次分组开通 ${stopTime(subscribedAt)} 共同起算；后来加入的成员继承剩余时长。` : "从本次分组实际开通共同起算；后来加入的成员继承剩余时长。" : subscribedAt
              ? `从原订阅时间 ${stopTime(subscribedAt)} 起算`
              : "从每个用户实际开通成功的时间起算，1 天为 24 小时。"}
          </small>
        </label>
      )}
      {mode === "at" && (
        <label className="field">
          <span>截止日期时间（UTC+8，北京 / 新加坡时间）</span>
          <input
            name={`${namePrefix}stop_at`}
            aria-label={`${labelPrefix}截止日期时间`}
            type="datetime-local"
            required
            defaultValue={value ? undefined : localInput(initial?.stop_at || null)}
            value={value ? localInput(value.stop_at || null) : undefined}
            onChange={onChange ? e => onChange({ mode: "at", stop_at: e.target.value ? new Date(e.target.value + "+08:00").toISOString() : "" }) : undefined}
            max={maxStopAt ? localInput(maxStopAt) : undefined}
          />
        </label>
      )}
      {mode !== "none" && (
        <p className="muted">
          {independentUser ? "到期仅取消独立 USER 授权，GROUP 授权继续保留。" : "到期自动取消目标授权，其他独立授权继续保留。"}保留 SSO 用户。实际生效以 AWS 返回结果为准；当月费用仍按 AWS 规则结算。
        </p>
      )}
      {nativeGroup && <p className="muted">共同截止时间会停止完整分组授权并保留成员关系。可在执行前修改、重设或关闭；个人规则按其授权来源单独执行。</p>}
    </fieldset>
  );
}

export function StopScheduleEditor({
  record,
  group,
  blocked,
  onChanged,
}: {
  record: RecordItem;
  group?: GroupItem | null;
  blocked: boolean;
  onChanged: () => void;
}) {
  const [editing, setEditing] = useState<{
    schedule: StopSchedule | null;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const schedule = record.stop_schedule;
  const eligible = canEditStopRule(record);
  const individuallySet = !!schedule && (schedule.individual_override || !schedule.source_group_id);
  const inherited = nativeAccess(record) && !userDeadline(record);
  async function save(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (blocked || !eligible) { setError("该用户当前无法修改停止规则，请刷新后重试。"); return; }
    setBusy(true);
    setError("");
    try {
      const policy = readStopPolicy(new FormData(e.currentTarget));
      if (inherited && record.controlling_group_stop_at && policy.mode === "at") {
        const requested = Date.parse(policy.stop_at!);
        const limit = Date.parse(record.controlling_group_stop_at.endsWith("Z") ? record.controlling_group_stop_at : `${record.controlling_group_stop_at}Z`);
        if (requested > limit) throw new Error("个人停止时间不能超过分组共同停止时间。");
      }
      await api(`/subscriptions/${record.id}/stop-schedule`, "PUT", {
        policy,
        expected_revision: editing?.schedule?.revision || 0,
      });
      setEditing(null);
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function reset() {
    if (!group || blocked || !eligible) return;
    setBusy(true);
    setError("");
    try {
      await api(`/subscriptions/${record.id}/stop-schedule/reset-to-group`, "POST", resetToGroupRequest(record, group));
      setEditing(null);
      onChanged();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  if (!eligible && !schedule && !record.group_id) return null;
  return (
    <section className="stop-schedule" aria-label="定时停止订阅设置">
      <div className="stop-heading">
        <h3>定时停止订阅</h3>
        <span
          className={`badge ${["blocked", "failed", "needs_review"].includes(schedule?.state || "") ? "failed" : ""}`}
        >
          {schedule ? stopState[schedule.state] || schedule.state : "未设置"}
        </span>
      </div>
      <StopRuleSource record={record} group={group} />
      {inherited && <p className="info-note">分组共同停止：{record.controlling_group_stop_at ? stopTime(record.controlling_group_stop_at) : "未设置"}。个人规则可更早移出该成员并停止组授权；不能延长到超过分组共同截止时间。关闭个人规则后仍受分组截止时间约束。</p>}
      {eligible && (
        <p className="muted">
          {inherited ? "可在执行前修改、重设或关闭个人规则。更早的个人截止时间仅影响该成员，保留 SSO。" : "可单独延后、重新设置或关闭。单独保存后，该用户将保留自己的规则。"}
        </p>
      )}
      {schedule && schedule.mode !== "none" && (
        <>
          <p>
            {schedule.mode === "days"
              ? `开通后 ${schedule.days} 天`
              : "指定截止时间"}{" "}
            · {stopTime(schedule.stop_at)}
          </p>
          {schedule.completed_at && (
            <p className="muted">处理完成：{stopTime(schedule.completed_at)}</p>
          )}
        </>
      )}
      {schedule?.error && (
        <p className="error" role="alert">
          {schedule.error}
        </p>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {editing ? (
        <form onSubmit={save}>
          <StopPolicyFields
            initial={editing.schedule}
            subscribedAt={inherited ? undefined : record.subscribed_at}
            independentUser={userDeadline(record)}
            maxStopAt={inherited ? record.controlling_group_stop_at : undefined}
          />
          <div className="modal-actions">
            <button
              type="button"
              className="secondary"
              disabled={busy}
              onClick={() => {
                setEditing(null);
                setError("");
              }}
            >
              返回
            </button>
            <button className="primary" disabled={busy || blocked || !eligible}>
              {busy ? "保存中…" : "保存定时停止"}
            </button>
          </div>
        </form>
      ) : (
        eligible && (
          <button
            className="secondary"
            disabled={blocked || busy}
            onClick={() => {
              setEditing({ schedule });
              setError("");
            }}
          >
            {record.group_id ? "单独设置停止规则" : schedule ? "修改 / 重设截止时间" : "设置定时停止"}
          </button>
        )
      )}
      {eligible && record.group_id && individuallySet && !editing && (
        <div className="group-reset-rule">
          <p className="muted">当前分组规则：{group ? policySummary(group.policy) : "正在读取…"}</p>
          <button type="button" className="secondary" disabled={busy || blocked || !group || group.state !== "ready" || !!group.active_job_id} onClick={reset}>
            {busy ? "恢复中…" : "恢复分组规则"}
          </button>
        </div>
      )}
      {!eligible && (record.sso_deleted_at || record.cancelled_at || ["cancelled", "cancel_scheduled"].includes(record.subscription_status)) && (
        <p className="muted">已取消或删除的历史记录保留原规则，不再修改。</p>
      )}
    </section>
  );
}

export function policySummary(policy?: { mode: string; days?: number | null; stop_at?: string | null } | null) {
  if (!policy || policy.mode === "none") return "不定时停止";
  return policy.mode === "days" ? `开通后 ${policy.days} 天停止` : `${stopTime(policy.stop_at || null)} 停止`;
}
export function StopRuleSource({ record, group }: { record: RecordItem; group?: GroupItem | null }) {
  const individual = !!record.stop_schedule && (record.stop_schedule.individual_override || !record.stop_schedule.source_group_id);
  const inherited = !!record.group_id && !individual;
  return (
    <div className="rule-source">
      <span className={`rule-source-label ${inherited ? "from-group" : ""}`}>{inherited ? "分组规则" : "个人规则"}</span>
      <span>{inherited && group && <NavLink to={`/groups?group_id=${encodeURIComponent(group.id)}`}>{group.name} · </NavLink>}{inherited && !record.stop_schedule && !group ? "正在读取分组规则…" : policySummary(record.stop_schedule || (inherited ? group?.policy : null))}</span>
      {individual && userDeadline(record) && <small>个人截止时间仅取消独立 USER 授权，GROUP 授权按各分组规则保留。</small>}
      {nativeAccess(record) && <small>分组共同停止：{record.controlling_group_stop_at ? stopTime(record.controlling_group_stop_at) : "未设置"}；后来加入继承剩余时长{individual && !userDeadline(record) ? "，个人更早截止时间继续有效" : ""}。</small>}
    </div>
  );
}
export function readSubscriptionPolicy(form: FormData): StopPolicy | undefined {
  return form.get("stop_override") === "individual" ? readStopPolicy(form) : undefined;
}
export function SubscriptionPolicyFields({ records, groups }: { records: RecordItem[]; groups: GroupItem[] }) {
  const [override, setOverride] = useState(false);
  return (
    <div className="subscription-policy-choice">
      <label className="field">
        <span>停止规则</span>
        <SearchableSelect aria-label="停止规则" name="stop_override" value={override ? "individual" : "inherit"} onChange={e => setOverride(e.target.value === "individual")}>
          <option value="inherit">沿用各用户当前规则（默认）</option>
          <option value="individual">为所选用户单独设置</option>
        </SearchableSelect>
      </label>
      {override ? <><p className="info-note">以下设置将成为每名所选用户的个人规则；选择“不定时停止”也会覆盖分组规则。</p><StopPolicyFields /></> : (
        <details className="advanced" open={records.length <= 3}>
          <summary>查看将沿用的规则（{records.length} 人）</summary>
          <div className="group-rule-list">{records.map(record => <div key={record.id}><strong>{record.username}</strong><StopRuleSource record={record} group={groups.find(g => g.id === record.group_id)} /></div>)}</div>
        </details>
      )}
    </div>
  );
}
