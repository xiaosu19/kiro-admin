import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useLocation } from "react-router-dom";
import { groupRequest } from "./api";
import { SearchableSelect } from "./SearchableSelect";

type Protocol = "claude_messages" | "claude_messages_bearer" | "openai_chat" | "openai_responses";
interface Settings {
  revision: number;
  protocol: Protocol;
  endpoint: string;
  model: string;
  enabled: boolean;
  timeout_seconds: number;
  key_configured: boolean;
  updated_at: string | null;
}
const protocols: [Protocol, string, string][] = [
  ["claude_messages", "Claude Messages", "/messages"],
  ["claude_messages_bearer", "Claude Messages（Bearer 认证）", "/messages"],
  ["openai_chat", "OpenAI Chat Completions", "/chat/completions"],
  ["openai_responses", "OpenAI Responses", "/responses"],
];
const testErrors: Record<string, string> = {
  captcha_unavailable: "请先保存并启用自己的密钥。",
  captcha_invalid_configuration: "请检查接口地址、模型和密钥格式。",
  captcha_timeout: "接口请求超时，请检查网络或调整超时。",
  captcha_provider_failed: "接口请求失败，请检查协议、地址、模型权限、密钥和余额。",
  captcha_invalid_response: "接口未返回完整的识别文字，请确认模型支持图片输入。",
  recognition_mismatch: "接口已响应，但测试图片识别不正确，请尝试其他视觉模型。",
};

export function AiRecognitionNotice() {
  const location = useLocation();
  const params = new URLSearchParams(location.pathname === "/json-export" ? location.search : "");
  params.set("ai_settings", "1");
  return <p className="info-note ai-recognition-note">
    图像验证码使用你在 <Link to={`/json-export?${params}`}>AI 识别设置</Link> 中选择的接口和模型。
    未配置、挑战不支持或识别达到上限时，需要你继续处理。
  </p>;
}

export function AiSettings({ notify }: { notify: (message: string, error?: boolean) => void }) {
  const [saved, setSaved] = useState<Settings | null>(null);
  const [form, setForm] = useState<Settings | null>(null);
  const [key, setKey] = useState("");
  const [clear, setClear] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [testResult, setTestResult] = useState("");
  const active = useRef(false);
  useEffect(() => {
    active.current = true;
    const controller = new AbortController();
    groupRequest<Settings>("/ai-settings", "GET", undefined, () => active.current && !controller.signal.aborted, controller.signal)
      .then(value => { if (value) { setSaved(value); setForm(value); setError(""); } })
      .catch(e => { if (active.current && !controller.signal.aborted) setError((e as Error).message); });
    return () => { active.current = false; controller.abort(); };
  }, []);
  const dirty = JSON.stringify(saved) !== JSON.stringify(form) || !!key || clear;
  function update(patch: Partial<Settings>) {
    setForm(current => current ? { ...current, ...patch } : current);
    setTestResult("");
  }
  async function save(event: FormEvent) {
    event.preventDefault();
    if (!form || busy) return;
    setBusy(true); setError(""); setTestResult("");
    try {
      const value = await groupRequest<Settings>("/ai-settings", "PUT", {
        revision: form.revision, protocol: form.protocol, endpoint: form.endpoint,
        model: form.model, enabled: form.enabled, timeout_seconds: form.timeout_seconds,
        ...(key ? { api_key: key } : {}), clear_key: clear,
      }, () => active.current);
      if (value) {
        setSaved(value); setForm(value); setKey(""); setClear(false);
        notify("个人 AI 识别设置已保存");
      }
    } catch (e) { if (active.current) setError((e as Error).message); }
    finally { if (active.current) setBusy(false); }
  }
  async function test() {
    if (!saved || busy || dirty) return;
    setBusy(true); setError(""); setTestResult("");
    try {
      const result = await groupRequest<{ ok: boolean; code: string }>("/ai-settings/test", "POST",
        { revision: saved.revision }, () => active.current);
      if (result) {
        if (result.ok) setTestResult("测试图片识别正确。实际验证码是否通过仍由登录页面确认。");
        else setError(testErrors[result.code] || "测试失败，请检查识别服务配置。");
      }
    } catch (e) { if (active.current) setError((e as Error).message); }
    finally { if (active.current) setBusy(false); }
  }
  return <>
    <section className="panel ai-settings-panel" aria-label="我的 AI 识别设置">
      <h2>AI 识别设置</h2>
      <p>为你发起的 JSON 转换和改密任务选择图像验证码识别服务。</p>
      <div className="ai-settings-scope"><strong>我的识别服务</strong>
        <span className={`badge ${saved?.enabled && saved.key_configured ? "success" : ""}`}>
          {saved?.enabled && saved.key_configured ? "已启用" : "未启用"}</span></div>
      <p className="muted">管理员与子用户分别保存配置。你的任务只使用你的密钥，其他用户无法查看或借用。</p>
      {error && <div className="error" role="alert">{error}</div>}
      {!form ? !error && <p role="status">正在读取个人设置…</p> : <form onSubmit={save}>
        <fieldset disabled={busy} className="ai-settings-fields">
          <label className="field"><span>接口协议</span><SearchableSelect aria-label="接口协议" value={form.protocol} onChange={event => {
            const protocol = event.target.value as Protocol;
            const suffix = protocols.find(item => item[0] === protocol)![2];
            update({ protocol, endpoint: form.endpoint.replace(/\/(?:chat\/completions|responses|messages)\/?$/, suffix) });
          }}>{protocols.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</SearchableSelect></label>
          <label className="field"><span>接口地址</span><input aria-label="接口地址" type="url" value={form.endpoint} required maxLength={2048}
            placeholder="https://api.example.com/v1" onChange={event => update({ endpoint: event.target.value })} />
            <small>支持公网 HTTPS 基础地址、/v1 地址或完整接口路径。保存时自动补全当前协议路径。</small></label>
          <div className="ai-settings-row">
            <label className="field"><span>模型名称</span><input aria-label="模型名称" value={form.model} required maxLength={200}
              placeholder="填写服务商提供的视觉模型名称" onChange={event => update({ model: event.target.value })} /></label>
            <label className="field"><span>单次超时（秒）</span><input aria-label="单次超时（秒）" type="number" min={1} max={60} step={1} required
              value={form.timeout_seconds} onChange={event => update({ timeout_seconds: Number(event.target.value) })} /></label>
          </div>
          <label className="field"><span>API 密钥</span><input aria-label="API 密钥" type="password" value={key} autoComplete="off" maxLength={4096}
            disabled={clear} placeholder={saved?.key_configured ? "已保存，留空保留原密钥" : "填写你自己的 API 密钥"}
            onChange={event => { setKey(event.target.value); setTestResult(""); }} />
            <small>{saved?.key_configured ? "密钥已加密保存，无法回显。" : "密钥仅用于你自己的识别请求。"}</small></label>
          {saved?.key_configured && <label className="check"><input type="checkbox" checked={clear} onChange={event => {
            setClear(event.target.checked); setKey(""); if (event.target.checked) update({ enabled: false });
          }} />清除已保存的密钥</label>}
          <label className="check"><input type="checkbox" checked={form.enabled} disabled={clear}
            onChange={event => update({ enabled: event.target.checked })} />为我的任务启用自动图像识别</label>
        </fieldset>
        <div className="actions ai-settings-actions">
          <button className="primary" disabled={busy || !dirty}>{busy ? "正在处理…" : "保存设置"}</button>
          <button type="button" className="secondary" disabled={busy || dirty || !saved?.enabled || !saved.key_configured}
            onClick={() => void test()}>测试已保存配置</button>
        </div>
        <p className="muted">测试会向你的服务商发送一张固定测试图片，可能产生少量费用。修改配置后请先保存。</p>
      </form>}
      {testResult && <p className="info-note" role="status">{testResult}</p>}
    </section>
  </>;
}
