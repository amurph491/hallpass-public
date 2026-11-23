import { KeyboardEvent, ReactNode, useRef } from "react";

type Tab<T extends string> = { id: T; label: ReactNode };

/** An ARIA tablist; the caller renders the active panel with `tabPanelProps`. */
export function Tabs<T extends string>({ tabs, active, onChange, label }: { tabs: Tab<T>[]; active: T; onChange: (id: T) => void; label: string }) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  function onKey(event: KeyboardEvent, index: number) {
    const delta = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (!delta) return;
    event.preventDefault();
    const next = (index + delta + tabs.length) % tabs.length;
    refs.current[next]?.focus();
    onChange(tabs[next].id);
  }
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((tab, index) => (
        <button
          key={tab.id}
          ref={element => { refs.current[index] = element; }}
          type="button"
          role="tab"
          id={`tab-${tab.id}`}
          aria-selected={active === tab.id}
          aria-controls={`panel-${tab.id}`}
          tabIndex={active === tab.id ? 0 : -1}
          className="tab"
          onClick={() => onChange(tab.id)}
          onKeyDown={event => onKey(event, index)}
        >
          {tab.label}
        </button>
      ))}
    </div>
  );
}

export function tabPanelProps(id: string) {
  return { role: "tabpanel", id: `panel-${id}`, "aria-labelledby": `tab-${id}`, tabIndex: 0 } as const;
}
