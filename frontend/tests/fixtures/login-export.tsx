import React, { useState } from "react";
import { createRoot } from "react-dom/client";
import { LoginExportActions } from "../../src/AuthSelection";
import { ProvisioningDownloads } from "../../src/Provisioning";
import "../../src/styles.css";

function Fixture() {
  const [busy, setBusy] = useState(false), [selected, setSelected] = useState(["a", "b"]), [downloads, setDownloads] = useState<unknown[]>([]);
  return <main style={{ padding: 16 }}>
    <div className="bulk-toolbar" data-testid="list-exports"><LoginExportActions selected={selected} canExportSelection={!!selected.length} hasResults busy={busy} onExport={(ids, format) => setDownloads(old => [...old, { ids, format }])} /></div>
    <button type="button" onClick={() => setSelected([])}>清空选择</button>
    <button type="button" onClick={() => setBusy(!busy)}>切换忙碌</button>
    <button type="button" onClick={() => window.setTimeout(() => setBusy(true), 200)}>延迟忙碌</button>
    <section aria-label="账号批次下载"><ProvisioningDownloads actorId={2} batch={{ id: "parent", actor_id: 2 }} account={{ id: "child", exports: { csv: false, txt: true, json: false }, items: [{ credentials_ready: true }] } as never} disabled={busy} onDownload={request => setDownloads(old => [...old, request])} /></section>
    <output data-testid="downloads" style={{ overflowWrap: "anywhere" }}>{JSON.stringify(downloads)}</output>
  </main>;
}
createRoot(document.getElementById("root")!).render(<Fixture />);
