import { accountLabel } from "./provisioningLogic";
import { useState } from "react";
import type { Account } from "./api";
import { matchesSelection } from "./selectionSearch";

export function AccountBindings({ accounts, selected, disabled = false }: { accounts: Account[]; selected: number[]; disabled?: boolean }) {
  const [query, setQuery] = useState("");
  const visible = (account: Account) => matchesSelection(query, account.account_number, account.name, account.id, account.aws_account_id, account.region);
  return <div className="account-bindings">
    <input type="search" aria-label="搜索可绑定 AWS 账号" placeholder="搜索账号名称、ID 或区域" value={query} disabled={disabled} onChange={event => setQuery(event.target.value)} onKeyDown={event => { if (event.key === "Enter") event.preventDefault(); }} />
    <div className="checkbox-list">
      {accounts.map(account => <label key={account.id} hidden={!visible(account)}>
        <input type="checkbox" name="account" value={account.id} defaultChecked={selected.includes(account.id)} disabled={disabled} />
        <span>{accountLabel(account)}<small>{account.region}{!account.active ? " · 已停用" : ""}</small></span>
      </label>)}
    </div>
    {!!accounts.length && !accounts.some(visible) && <p className="selection-empty" role="status">没有匹配的 AWS 账号，已勾选项会保留。</p>}
  </div>;
}
