import {
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { api, date, type ProxyItem } from "./api";

const probeStatus: Record<string, string> = {
  failed: "探测失败，请重新探测", auth_failed: "认证失败，请检查已保存的用户名和密码",
  timeout: "探测超时，请检查代理网络", connect: "连接失败，请检查代理地址和端口",
  tls: "TLS 验证失败，请检查代理链路", invalid_response: "响应无效，未获得有效出口 IP",
};

function ProxyDialog({
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
      className="modal proxy-dialog"
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
          aria-label="关闭"
          disabled={busy}
          onClick={close}
        >
          ×
        </button>
      </div>
      {children}
    </dialog>
  );
}

export function Proxies({
  notify,
}: {
  notify: (message: string, error?: boolean) => void;
}) {
  const [rows, setRows] = useState<ProxyItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [formError, setFormError] = useState("");
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState<ProxyItem | "new" | null>(null);
  const [importing, setImporting] = useState(false);
  const [deleting, setDeleting] = useState<ProxyItem | null>(null);
  const [releasingDeleted, setReleasingDeleted] = useState<ProxyItem | null>(null);
  const [clearAuth, setClearAuth] = useState(false);
  async function refresh() {
    try {
      setRows(await api<ProxyItem[]>("/admin/proxies"));
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }
  useEffect(() => {
    void refresh();
  }, []);
  async function action(proxy: ProxyItem, probe = false) {
    setBusy(true);
    try {
      const updated = await api<ProxyItem>(
        `/admin/proxies/${proxy.id}${probe ? "/probe" : ""}`,
        probe ? "POST" : "PATCH",
        probe ? undefined : { enabled: !proxy.enabled },
      );
      await refresh();
      notify(
        probe
          ? updated.last_probe_status === "ok"
            ? `探测成功，出口 IP：${updated.egress_ip}`
            : probeStatus[updated.last_probe_status || "failed"] || "探测失败"
          : updated.enabled
            ? "代理已启用"
            : `代理已停用，${updated.binding_count} 个绑定账号的 AWS 请求将被阻止`,
        probe && updated.last_probe_status !== "ok",
      );
    } catch (e) {
      notify((e as Error).message, true);
    } finally {
      setBusy(false);
    }
  }
  async function save(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    const existing = editing && editing !== "new" ? editing : null;
    const body = existing
      ? {
          name: form.get("name"),
          host: form.get("host"),
          port: Number(form.get("port")),
          username: form.get("username") || "",
          password: form.get("password") || "",
          clear_auth: clearAuth,
          enabled: form.get("enabled") === "on",
        }
      : {
          name: form.get("name"),
          address: form.get("address"),
          enabled: form.get("enabled") === "on",
        };
    setBusy(true);
    setFormError("");
    try {
      await api(
        existing ? `/admin/proxies/${existing.id}` : "/admin/proxies",
        existing ? "PATCH" : "POST",
        body,
      );
      setEditing(null);
      await refresh();
      notify("代理配置已保存");
    } catch (e) {
      setFormError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function importRows(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const form = new FormData(e.currentTarget);
    setBusy(true);
    setFormError("");
    try {
      const result = await api<{ items: ProxyItem[] }>(
        "/admin/proxies/import",
        "POST",
        {
          name_prefix: form.get("name_prefix"),
          addresses: form.get("addresses"),
        },
      );
      setImporting(false);
      await refresh();
      notify(`已导入 ${result.items.length} 个代理`);
    } catch (e) {
      setFormError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const current = editing && editing !== "new" ? editing : null;
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>代理池</h1>
          <p>管理 SOCKS5 代理，并在 AWS 账号中指定访问出口。</p>
        </div>
        <div className="proxy-buttons">
          <button
            className="secondary"
            disabled={busy}
            onClick={() => {
              setFormError("");
              setImporting(true);
            }}
          >
            批量导入
          </button>
          <button
            className="primary"
            disabled={busy}
            onClick={() => {
              setFormError("");
              setClearAuth(false);
              setEditing("new");
            }}
          >
            ＋ 添加代理
          </button>
        </div>
      </div>
      {error && (
        <div className="error" role="alert">
          {error}
        </div>
      )}
      <p className="info-note">
        已绑定代理的 AWS 账号会使用该代理访问身份中心与
        Kiro。代理停用或连接失败时，请求会停止；可在 AWS 账号页面调整绑定。
      </p>
      <section className="panel no-padding">
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>代理</th>
                <th>状态 / 认证</th>
                <th>绑定账号</th>
                <th>最近探测</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((proxy) => (
                <tr key={proxy.id}>
                  <td>
                    <strong>{proxy.name}</strong>
                    <div className="mono muted">
                      {proxy.host.includes(":")
                        ? `[${proxy.host}]`
                        : proxy.host}
                      :{proxy.port}
                    </div>
                  </td>
                  <td>
                    <span
                      className={`badge ${proxy.enabled ? "completed" : "failed"}`}
                    >
                      {proxy.enabled ? "已启用" : "已停用"}
                    </span>
                    <div className="muted">
                      {proxy.auth_configured ? "认证已保存 · ••••••" : "无认证"}
                    </div>
                  </td>
                  <td>
                    <div>当前配置：{proxy.binding_count - (proxy.deleted_binding_count ?? 0)} 个</div>
                    {!!proxy.deleted_binding_count && (
                      <div className="muted">已删除配置：{proxy.deleted_binding_count} 个</div>
                    )}
                  </td>
                  <td>
                    <span
                      className={
                        proxy.last_probe_status && proxy.last_probe_status !== "ok"
                          ? "proxy-failed"
                          : ""
                      }
                    >
                      {proxy.last_probe_status === "ok"
                        ? proxy.egress_ip
                        : proxy.last_probe_status
                          ? probeStatus[proxy.last_probe_status] || "探测失败"
                          : "尚未探测"}
                    </span>
                    {proxy.last_probe_at && (
                      <div className="muted">{date(proxy.last_probe_at)}</div>
                    )}
                  </td>
                  <td>
                    <div className="proxy-buttons">
                      <button
                        className="secondary"
                        disabled={busy}
                        onClick={() => void action(proxy, true)}
                      >
                        探测
                      </button>
                      <button
                        className="secondary"
                        disabled={busy}
                        onClick={() => {
                          setFormError("");
                          setClearAuth(false);
                          setEditing(proxy);
                        }}
                      >
                        编辑
                      </button>
                      <button
                        className="secondary"
                        disabled={busy}
                        onClick={() => void action(proxy)}
                      >
                        {proxy.enabled ? "停用" : "启用"}
                      </button>
                      <button
                        className="danger"
                        disabled={busy || proxy.binding_count > 0}
                        title={
                          proxy.binding_count > (proxy.deleted_binding_count ?? 0)
                            ? "请先在 AWS 账号页面解除当前配置绑定"
                            : proxy.binding_count
                              ? "请先解除旧配置绑定"
                            : "删除代理"
                        }
                        onClick={() => {
                          setFormError("");
                          setDeleting(proxy);
                        }}
                      >
                        删除
                      </button>
                      {!!proxy.deleted_binding_count && (
                        <button
                          className="secondary"
                          disabled={busy}
                          onClick={() => {
                            setFormError("");
                            setReleasingDeleted(proxy);
                          }}
                        >
                          解除旧配置绑定
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {(loading || !rows.length) && (
          <div className="empty">
            <p>
              {loading
                ? "正在加载代理…"
                : "暂无代理。添加或导入后，可在 AWS 账号中选择。"}
            </p>
          </div>
        )}
      </section>
      {editing && (
        <ProxyDialog
          title={current ? "编辑代理" : "添加 SOCKS5 代理"}
          busy={busy}
          close={() => setEditing(null)}
        >
          <form onSubmit={save} autoComplete="off">
            {formError && (
              <div className="error" role="alert">
                {formError}
              </div>
            )}
            <fieldset className="resource-fields" disabled={busy}>
              <label className="field">
                <span>代理名称</span>
                <input
                  name="name"
                  required
                  maxLength={100}
                  defaultValue={current?.name}
                  placeholder="例如：新加坡出口"
                />
              </label>
              {current ? (
                <>
                  <div className="form-grid">
                    <label className="field">
                      <span>IP 地址</span>
                      <input
                        name="host"
                        required
                        maxLength={45}
                        defaultValue={current.host}
                      />
                    </label>
                    <label className="field">
                      <span>端口</span>
                      <input
                        name="port"
                        type="number"
                        required
                        min={1}
                        max={65535}
                        defaultValue={current.port}
                      />
                    </label>
                    <label className="field">
                      <span>新用户名</span>
                      <input
                        name="username"
                        autoComplete="off"
                        disabled={clearAuth}
                        maxLength={255}
                        placeholder="留空保留现有认证"
                      />
                    </label>
                    <label className="field">
                      <span>新密码</span>
                      <input
                        name="password"
                        type="password"
                        autoComplete="new-password"
                        disabled={clearAuth}
                        maxLength={255}
                        placeholder="留空保留现有认证"
                      />
                    </label>
                  </div>
                  <p className="muted">
                    认证信息已隐藏。需要替换时，请同时填写新用户名和密码。
                  </p>
                  <label className="check">
                    <input
                      type="checkbox"
                      checked={clearAuth}
                      onChange={(e) => setClearAuth(e.target.checked)}
                    />
                    清除已保存认证（仅用于无需认证的代理）
                  </label>
                  {current.binding_count > 0 && (
                    <p className="info-note">
                      此代理绑定了 {current.binding_count} 个 AWS
                      账号。修改将影响后续请求，停用后这些账号的请求会停止。
                    </p>
                  )}
                </>
              ) : (
                <label className="field">
                  <span>代理地址与认证</span>
                  <input
                    name="address"
                    type="password"
                    autoComplete="new-password"
                    required
                    maxLength={1100}
                    placeholder="IP:端口:用户名:密码"
                  />
                  <small>
                    按 IP:端口:用户名:密码 填写；IPv6 使用
                    [IP]:端口:用户名:密码。
                  </small>
                </label>
              )}
              <label className="check">
                <input
                  name="enabled"
                  type="checkbox"
                  defaultChecked={current?.enabled ?? true}
                />
                启用此代理
              </label>
              <div className="modal-actions">
                <button
                  className="secondary"
                  type="button"
                  onClick={() => setEditing(null)}
                >
                  取消
                </button>
                <button className="primary">
                  {busy ? "正在保存…" : "保存代理"}
                </button>
              </div>
            </fieldset>
          </form>
        </ProxyDialog>
      )}
      {importing && (
        <ProxyDialog
          title="批量导入 SOCKS5 代理"
          busy={busy}
          close={() => setImporting(false)}
        >
          <form onSubmit={importRows} autoComplete="off">
            {formError && (
              <div className="error" role="alert">
                {formError}
              </div>
            )}
            <fieldset className="resource-fields" disabled={busy}>
              <label className="field">
                <span>名称前缀</span>
                <input
                  name="name_prefix"
                  required
                  maxLength={80}
                  defaultValue={`导入 ${new Date().toISOString().slice(0, 19).replace("T", " ")}`}
                />
                <small>会依次加上序号，为每条代理命名。</small>
              </label>
              <label className="field">
                <span>代理列表</span>
                <textarea
                  name="addresses"
                  rows={8}
                  required
                  spellCheck={false}
                  autoComplete="off"
                  maxLength={110000}
                  placeholder={"IP:端口:用户名:密码\n每行一条，最多 100 条"}
                />
                <small>导入前会校验所有行，任一行有误时不保存任何条目。</small>
              </label>
              <div className="modal-actions">
                <button
                  className="secondary"
                  type="button"
                  onClick={() => setImporting(false)}
                >
                  取消
                </button>
                <button className="primary">
                  {busy ? "正在导入…" : "导入代理"}
                </button>
              </div>
            </fieldset>
          </form>
        </ProxyDialog>
      )}
      {releasingDeleted && (
        <ProxyDialog
          title="解除旧配置绑定"
          busy={busy}
          close={() => setReleasingDeleted(null)}
        >
          {formError && <div className="error" role="alert">{formError}</div>}
          <p>确定解除「{releasingDeleted.name}」与 {releasingDeleted.deleted_binding_count} 个已删除 AWS 配置的绑定？</p>
          <p>恢复这些旧配置后将默认直接连接；如需使用代理，请在管理配置中重新选择。</p>
          <div className="modal-actions">
            <button className="secondary" disabled={busy} onClick={() => setReleasingDeleted(null)}>取消</button>
            <button
              className="danger"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setFormError("");
                try {
                  await api(`/admin/proxies/${releasingDeleted.id}/release-deleted-bindings`, "POST");
                  setReleasingDeleted(null);
                  await refresh();
                  notify("已解除已删除 AWS 配置的代理绑定");
                } catch (e) {
                  setFormError((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              确认解除
            </button>
          </div>
        </ProxyDialog>
      )}
      {deleting && (
        <ProxyDialog
          title="删除代理"
          busy={busy}
          close={() => setDeleting(null)}
        >
          {formError && (
            <div className="error" role="alert">
              {formError}
            </div>
          )}
          <p>确定删除「{deleting.name}」及已保存的代理认证？</p>
          <div className="modal-actions">
            <button
              className="secondary"
              disabled={busy}
              onClick={() => setDeleting(null)}
            >
              取消
            </button>
            <button
              className="danger"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                setFormError("");
                try {
                  await api(`/admin/proxies/${deleting.id}`, "DELETE");
                  setDeleting(null);
                  await refresh();
                  notify("代理已删除");
                } catch (e) {
                  setFormError((e as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              确认删除
            </button>
          </div>
        </ProxyDialog>
      )}
    </>
  );
}
