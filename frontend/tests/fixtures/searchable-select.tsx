import React, { useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { SearchableSelect } from "../../src/SearchableSelect";
import { AccountBindings } from "../../src/AccountBindings";
import { PlanChangeTargets } from "../../src/PlanChangeManager";
import { options as planOptions, record } from "../plan-change-fixtures.mjs";
import "../../src/styles.css";

const accounts = Array.from({ length: 120 }, (_, id) => ({ id, name: `研发 Account ${id}`, region: "us-east-1", active: true }));
function Fixture() {
  const [value, setValue] = useState("account-1"), [locked, setLocked] = useState(false), [changes, setChanges] = useState<string[]>([]), [data, setData] = useState(""), [plan, setPlan] = useState(3);
  const dialog = useRef<HTMLDialogElement>(null), [modalData, setModalData] = useState("");
  const choices = <><option value="">请选择账号</option>{accounts.map(account => <option key={account.id} value={`account-${account.id}`} disabled={account.id === 98}>{account.name}</option>)}<optgroup label="禁用分组" disabled><option value="disabled-group">禁止选择</option></optgroup></>;
  return <main style={{ padding: 16, maxWidth: 700 }}>
    <button type="button" onClick={() => dialog.current?.showModal()}>打开原生弹窗</button>
    <dialog ref={dialog} className="modal proxy-dialog group-dialog" aria-label="原生弹窗测试">
      <button type="button">弹窗内其他按钮</button>
      <form onSubmit={event => { event.preventDefault(); setModalData(String(new FormData(event.currentTarget).get("modal_account"))); }}>
        <label className="field"><span>弹窗账号</span><SearchableSelect aria-label="弹窗账号" name="modal_account" defaultValue="" required>{choices}</SearchableSelect></label>
        <button type="submit">提交弹窗表单</button>
        <output data-testid="modal-data">{modalData}</output>
        <div style={{ height: 700 }} />
        <button type="button" onClick={() => dialog.current?.close()}>关闭原生弹窗</button>
      </form>
    </dialog>
    <button type="button" onClick={() => setLocked(!locked)}>切换冻结</button>
    <button type="button" onClick={() => setValue("account-42")}>更新受控值</button>
    <button type="button" onClick={() => { (document.querySelector('select[name="default"]') as HTMLSelectElement).value = "account-42"; setChanges(old => [...old, "filled"]); }}>填充探测配置</button>
    <form id="selection-form" onSubmit={event => { event.preventDefault(); setData(JSON.stringify([...new FormData(event.currentTarget)])); }}>
      <fieldset className="resource-fields" disabled={locked}>
        <label className="field"><span>受控账号</span><SearchableSelect aria-label="受控账号" name="controlled" value={value} onChange={event => { const change = `${event.target.name}:${event.target.value}:${event.currentTarget.value}`; setValue(event.target.value); setChanges(old => [...old, change]); }}>{choices}</SearchableSelect></label>
        <label className="field"><span>默认账号</span><SearchableSelect aria-label="默认账号" name="default" defaultValue="account-7">{choices}</SearchableSelect></label>
        <label className="field"><span>必填账号</span><SearchableSelect aria-label="必填账号" name="required" required defaultValue="">{choices}</SearchableSelect></label>
        <SearchableSelect aria-label="固定账号" name="fixed" value="account-1" onChange={() => {}}>{choices}</SearchableSelect>
        <label>下一个输入<input aria-label="下一个输入" /></label>
      </fieldset>
      <AccountBindings accounts={accounts} selected={[1]} disabled={locked} />
      <PlanChangeTargets record={record} options={planOptions} value={plan} disabled={locked} onChange={setPlan} />
      <button type="submit">提交表单</button><button type="reset">重置表单</button>
    </form>
    <output data-testid="changes">{JSON.stringify(changes)}</output><output data-testid="data">{data}</output>
    <button type="button">外部按钮</button>
  </main>;
}
createRoot(document.getElementById("root")!).render(<Fixture />);
