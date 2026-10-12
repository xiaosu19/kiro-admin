import { useEffect, useRef } from "react";
import type { LoginExportFormat } from "./api";

const formats: readonly LoginExportFormat[] = ["csv", "txt"];
interface ExportScope {
  label?: string;
  formats?: readonly LoginExportFormat[];
  disabled?: boolean;
  onExport: (format: LoginExportFormat) => void;
}

export function LoginExportMenu({ scopes, disabled = false, label = "导出", ariaLabel = "导出登录信息", className = "secondary" }: {
  scopes: ExportScope[]; disabled?: boolean; label?: string; ariaLabel?: string; className?: string;
}) {
  const dialog = useRef<HTMLDialogElement>(null), trigger = useRef<HTMLButtonElement>(null);
  const blocked = disabled || !scopes.some(scope => !scope.disabled && (scope.formats ?? formats).length > 0);
  useEffect(() => { if (blocked) dialog.current?.close(); }, [blocked]);

  function choose(scope: ExportScope, format: LoginExportFormat) {
    if (blocked || scope.disabled || trigger.current?.matches(":disabled") || !dialog.current?.open || !(scope.formats ?? formats).includes(format)) return;
    dialog.current.close();
    scope.onExport(format);
  }

  return <div className="login-export">
    <button ref={trigger} type="button" className={className} aria-label={ariaLabel} aria-haspopup="dialog" disabled={blocked}
      onClick={() => { if (!blocked && !trigger.current?.matches(":disabled") && !dialog.current?.open) dialog.current?.showModal(); }}>{label}</button>
    <dialog ref={dialog} className="modal proxy-dialog login-export-dialog" aria-label={ariaLabel} onClick={event => {
      if (event.target !== event.currentTarget) return;
      const bounds = event.currentTarget.getBoundingClientRect();
      if (event.clientX < bounds.left || event.clientX > bounds.right || event.clientY < bounds.top || event.clientY > bounds.bottom) dialog.current?.close();
    }}>
      <h2>选择导出格式</h2>
      {scopes.map((scope, index) => <fieldset key={index} className="login-export-scope" disabled={blocked || scope.disabled}>
        <legend className={scope.label ? undefined : "sr-only"}>{scope.label || "文件格式"}</legend>
        <div className="login-export-formats">{(scope.formats ?? formats).map(format => <button key={format} type="button" className="secondary"
          disabled={blocked || !!scope.disabled} onClick={() => choose(scope, format)}>{format === "csv" ? "CSV 表格" : "TXT 登录信息"}</button>)}</div>
      </fieldset>)}
      <div className="modal-actions"><button type="button" className="secondary" onClick={() => dialog.current?.close()}>取消</button></div>
    </dialog>
  </div>;
}
