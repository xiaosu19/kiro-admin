import {
  Children, isValidElement, useEffect, useId, useRef, useState,
  type CSSProperties, type KeyboardEvent, type ReactNode, type SelectHTMLAttributes,
} from "react";
import { createPortal } from "react-dom";
import { matchesSelection } from "./selectionSearch";

type Props = Omit<SelectHTMLAttributes<HTMLSelectElement>, "multiple" | "size">;
type Choice = { value: string; label: string; disabled: boolean; hidden: boolean };

function textContent(node: ReactNode): string {
  return Children.toArray(node).map(child => isValidElement<{ children?: ReactNode }>(child)
    ? textContent(child.props.children) : String(child)).join("");
}

function readChoices(children: ReactNode, inheritedDisabled = false): Choice[] {
  return Children.toArray(children).flatMap(child => {
    if (!isValidElement<{ value?: string | number; label?: string; disabled?: boolean; hidden?: boolean; children?: ReactNode }>(child)) return [];
    const disabled = inheritedDisabled || !!child.props.disabled;
    if (child.type === "option") {
      const text = textContent(child.props.children).trim();
      return [{ value: String(child.props.value ?? text), label: child.props.label ?? text, disabled, hidden: !!child.props.hidden }];
    }
    return readChoices(child.props.children, disabled);
  });
}

/** The native select owns form submission, validation and reset behavior. */
export function SearchableSelect({ children, value, defaultValue, disabled, required, onChange, onInvalid,
  id, className, style, autoFocus, tabIndex, "aria-label": label, "aria-labelledby": labelledBy,
  "aria-describedby": describedBy, ...props }: Props) {
  const generatedId = useId(), controlId = id || `choice-${generatedId}`, listId = `${controlId}-list`;
  const choices = readChoices(children);
  const [internalValue, setInternalValue] = useState(() => String(defaultValue ?? choices.find(choice => !choice.disabled)?.value ?? ""));
  const [open, setOpen] = useState(false), [query, setQuery] = useState(""), [activeValue, setActiveValue] = useState<string | null>(null);
  const [inheritedDisabled, setInheritedDisabled] = useState(false), [invalid, setInvalid] = useState(false);
  const [position, setPosition] = useState<CSSProperties>({ visibility: "hidden" });
  const native = useRef<HTMLSelectElement>(null), trigger = useRef<HTMLButtonElement>(null), panel = useRef<HTMLDivElement>(null), search = useRef<HTMLInputElement>(null);
  const selectedValue = value !== undefined ? String(value) : internalValue;
  const selected = choices.find(choice => choice.value === selectedValue);
  const visible = choices.filter(choice => !choice.hidden && matchesSelection(query, choice.label, choice.value));
  const enabled = visible.filter(choice => !choice.disabled);
  const active = enabled.find(choice => choice.value === activeValue);
  const blocked = !!disabled || inheritedDisabled;
  const searchLabel = `搜索${label || props.title || "选项"}`;
  const activeId = active ? `${listId}-${choices.indexOf(active)}` : undefined;

  function close(restoreFocus = false) {
    setOpen(false); setQuery(""); setActiveValue(null);
    if (restoreFocus) trigger.current?.focus();
  }
  function show(direction?: "first" | "last") {
    if (!native.current || native.current.matches(":disabled")) return;
    trigger.current?.focus();
    setQuery(""); setOpen(true);
    const available = choices.filter(choice => !choice.disabled && !choice.hidden);
    setActiveValue(direction === "last" ? available[available.length - 1]?.value ?? null :
      available.find(choice => choice.value === selectedValue)?.value ?? available[0]?.value ?? null);
  }
  function choose(choice: Choice) {
    const select = native.current;
    if (!select || select.matches(":disabled") || choice.disabled) return;
    if (select.value !== choice.value) {
      select.value = choice.value;
      // A real change event preserves existing event.target/currentTarget handlers.
      select.dispatchEvent(new Event("change", { bubbles: true }));
    }
    setInvalid(false); close(true);
  }
  function move(direction: number) {
    if (!enabled.length) return setActiveValue(null);
    const index = enabled.findIndex(choice => choice.value === activeValue);
    setActiveValue(enabled[(index + direction + enabled.length) % enabled.length].value);
  }
  function searchKey(event: KeyboardEvent<HTMLInputElement>) {
    if (event.nativeEvent.isComposing) return;
    if (event.key === "ArrowDown" || event.key === "ArrowUp") { event.preventDefault(); move(event.key === "ArrowDown" ? 1 : -1); }
    else if (event.key === "Enter") { event.preventDefault(); if (active) choose(active); }
    else if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); close(true); }
    // Restore the original tab position before the browser advances focus.
    else if (event.key === "Tab") close(true);
  }

  useEffect(() => {
    const select = native.current;
    if (!select) return;
    if (value === undefined) setInternalValue(select.value);
    let timer: number | undefined;
    const reset = (event: Event) => {
      window.clearTimeout(timer);
      // Reset's default action runs after event listeners and their microtasks.
      timer = window.setTimeout(() => {
        if (event.defaultPrevented || native.current !== select) return;
        if (value === undefined) setInternalValue(select.value);
        else select.value = String(value);
        setInvalid(false); close();
      }, 0);
    };
    select.form?.addEventListener("reset", reset);
    return () => { select.form?.removeEventListener("reset", reset); window.clearTimeout(timer); };
  }, [value, children]);

  useEffect(() => {
    const select = native.current;
    if (!select) return;
    const check = () => setInheritedDisabled(select.matches(":disabled"));
    check();
    const observer = new MutationObserver(check);
    for (let ancestor = select.parentElement; ancestor; ancestor = ancestor.parentElement) {
      if (ancestor.tagName === "FIELDSET") observer.observe(ancestor, { attributes: true, attributeFilter: ["disabled"] });
    }
    return () => observer.disconnect();
  }, [disabled]);
  useEffect(() => { if (blocked) close(); }, [blocked]);

  useEffect(() => {
    if (!open) return;
    const reposition = () => {
      const rect = trigger.current!.getBoundingClientRect();
      const width = Math.min(Math.max(rect.width, 260), window.innerWidth - 16);
      const above = rect.top, below = window.innerHeight - rect.bottom;
      const upward = below < 280 && above > below;
      const maxHeight = Math.max(0, Math.min(360, (upward ? above : below) - 12));
      setPosition({ position: "fixed", width, left: Math.max(8, Math.min(rect.left, window.innerWidth - width - 8)),
        maxHeight, ...(upward ? { bottom: window.innerHeight - rect.top + 4 } : { top: rect.bottom + 4 }) });
    };
    const outside = (event: Event) => {
      if (!panel.current?.contains(event.target as Node) && !trigger.current?.contains(event.target as Node)) close();
    };
    reposition();
    document.addEventListener("pointerdown", outside, true);
    document.addEventListener("focusin", outside);
    window.addEventListener("resize", reposition);
    window.addEventListener("scroll", reposition, true);
    return () => {
      document.removeEventListener("pointerdown", outside, true);
      document.removeEventListener("focusin", outside);
      window.removeEventListener("resize", reposition);
      window.removeEventListener("scroll", reposition, true);
    };
  }, [open]);
  useEffect(() => { if (open && position.visibility !== "hidden") search.current?.focus({ preventScroll: true }); }, [open, position.visibility]);
  useEffect(() => {
    if (!open || !activeId || position.visibility === "hidden") return;
    const option = document.getElementById(activeId), list = document.getElementById(listId);
    if (!option || !list) return;
    const itemBounds = option.getBoundingClientRect(), listBounds = list.getBoundingClientRect();
    // Scroll only the popup, never the dialog/page behind it.
    if (itemBounds.top < listBounds.top) list.scrollTop -= listBounds.top - itemBounds.top;
    else if (itemBounds.bottom > listBounds.bottom) list.scrollTop += itemBounds.bottom - listBounds.bottom;
  }, [open, activeId, position.visibility, listId]);

  return <span className={`searchable-select${className ? ` ${className}` : ""}`} style={style}>
    <button ref={trigger} id={controlId} type="button" role="combobox" className="searchable-select-trigger"
      aria-label={label} aria-labelledby={labelledBy} aria-describedby={[describedBy, invalid ? `${controlId}-error` : ""].filter(Boolean).join(" ") || undefined}
      aria-expanded={open} aria-controls={listId} aria-haspopup="listbox" aria-required={required || undefined} aria-invalid={invalid || undefined}
      disabled={blocked} autoFocus={autoFocus} tabIndex={tabIndex} title={props.title}
      onClick={() => open ? close() : show()}
      onKeyDown={event => {
        if (["ArrowDown", "ArrowUp", "Enter", " "].includes(event.key)) {
          event.preventDefault(); show(event.key === "ArrowUp" ? "last" : "first");
        } else if (event.key === "Escape") close();
      }}><span>{selected?.label || "请选择"}</span><span aria-hidden="true" className="searchable-select-arrow">⌄</span></button>
    <select {...props} ref={native} value={value} defaultValue={defaultValue} disabled={disabled} required={required}
      className="searchable-select-native" tabIndex={-1} aria-hidden="true"
      onChange={event => { if (value === undefined) setInternalValue(event.currentTarget.value); setInvalid(false); onChange?.(event); }}
      onInvalid={event => { onInvalid?.(event); if (!event.defaultPrevented) { event.preventDefault(); setInvalid(true); show(); } }}>
      {children}
    </select>
    {invalid && <span id={`${controlId}-error`} className="error-text selection-validation">请选择一项。</span>}
    {open && createPortal(<div ref={panel} className="searchable-select-panel" style={position} onClick={event => event.stopPropagation()}>
      <input ref={search} type="search" role="combobox" aria-label={searchLabel} placeholder="搜索名称或 ID…" value={query}
        aria-expanded="true" aria-controls={listId} aria-autocomplete="list" aria-activedescendant={activeId} disabled={blocked}
        onKeyDown={searchKey} onChange={event => {
          const next = event.target.value; setQuery(next);
          setActiveValue(choices.find(choice => !choice.disabled && !choice.hidden && matchesSelection(next, choice.label, choice.value))?.value ?? null);
        }} />
      <div id={listId} role="listbox" aria-label={label || "选项"} aria-labelledby={labelledBy} className="searchable-select-options">
        {visible.map(choice => <div key={choice.value} id={`${listId}-${choices.indexOf(choice)}`} role="option"
          aria-selected={choice.value === selectedValue} aria-disabled={choice.disabled || undefined}
          className={`searchable-select-option${choice.value === activeValue ? " active" : ""}`}
          onPointerMove={() => { if (!choice.disabled) setActiveValue(choice.value); }}
          onMouseDown={event => event.preventDefault()} onClick={() => choose(choice)}>
          <span>{choice.label}</span>{choice.value === selectedValue && <span aria-hidden="true">✓</span>}
        </div>)}
      </div>
      {!visible.length && <p className="selection-empty" role="status">没有匹配的选项</p>}
      {selected && query && <p className="selection-current">已选：{selected.label}</p>}
    </div>, trigger.current?.closest("dialog[open]") || document.body)}
  </span>;
}
