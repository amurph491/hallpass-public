import { KeyboardEvent, useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router";
import { Activity, Blocks, Bot, House, ShieldCheck, LucideIcon, Search } from "lucide-react";
import { COUNTED_SECTIONS, SECTIONS, Section, navLabel, sectionPath } from "./routes";
import { useManagementSession } from "./ManagementSession";

const icons: Record<Section, LucideIcon> = {
  home: House,
  agents: Bot,
  apps: Blocks,
  approvals: ShieldCheck,
  activity: Activity
};

/** One global search hit: where it lives and how to open it. */
export type SearchItem = { key: string; name: string; meta: string; kind: string; open: () => void };

export function Wordmark() {
  return <span className="wordmark"><img src="/hallpass-head.webp" alt="" width={30} height={23} />hallpass</span>;
}

export function AdminSidebar({ section, counts }: { section: Section; counts: Partial<Record<Section, number>> }) {
  const session = useManagementSession();
  return (
    <aside className="sidebar">
      <Link className="sidebar-brand" to={sectionPath("home")} aria-label="Hallpass home"><Wordmark /></Link>
      <button type="button" className="sidebar-workspace" onClick={session?.switchTenant} aria-label="Switch workspace">
        <strong>{session?.session.tenant?.name || session?.session.tenant?.tenantId}</strong>
        <small>{session?.session.tenant?.breakGlass ? "Emergency administrator (time-boxed)" : "Administrator"}</small>
      </button>
      <nav className="nav" aria-label="Admin">
        {SECTIONS.map(item => {
          const Icon = icons[item];
          return (
            <Link key={item} to={sectionPath(item)} className="nav-item" aria-current={section === item ? "page" : undefined}>
              <Icon aria-hidden />
              {navLabel(item)}
              {COUNTED_SECTIONS.includes(item) && <span className="nav-count">{counts[item] ?? 0}</span>}
            </Link>
          );
        })}
      </nav>
      <div className="sidebar-footer">
        <button type="button" className="btn btn-ghost" onClick={() => void session?.signOut()}>Sign out</button>
      </div>
    </aside>
  );
}

type TopbarProps = { title: string; searchable: SearchItem[] };

export function AdminTopbar({ title, searchable }: TopbarProps) {
  const session = useManagementSession();
  const listId = useId();
  const [active, setActive] = useState(0);
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.platform);

  useEffect(() => {
    function onKey(event: globalThis.KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        input.current?.focus();
        input.current?.select();
      }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const term = query.trim().toLowerCase();
  const matches = term.length > 1
    ? searchable.filter(item => `${item.name} ${item.meta}`.toLowerCase().includes(term)).slice(0, 6)
    : [];

  function pick(item: SearchItem) {
    setQuery("");
    setOpen(false);
    input.current?.blur();
    item.open();
  }

  function onInputKey(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Escape") { setQuery(""); setOpen(false); input.current?.blur(); }
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault(); setOpen(true);
      if (matches.length) setActive(index => (index + (event.key === "ArrowDown" ? 1 : -1) + matches.length) % matches.length);
    }
    if (event.key === "Enter" && open && matches[active]) { event.preventDefault(); pick(matches[active]); }
  }

  return (
    <header className="topbar">
      <div className="breadcrumbs">
        <span>{session?.session.tenant?.name || session?.session.tenant?.tenantId}</span>
        <span aria-hidden>/</span>
        <strong>{title}</strong>
      </div>
      <div className="search" onBlur={event => { if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false); }}>
        <Search aria-hidden />
        <input
          ref={input}
          className="input"
          type="search"
          value={query}
          onChange={event => { setQuery(event.target.value); setActive(0); setOpen(true); }}
          onFocus={() => setOpen(true)}
          onKeyDown={onInputKey}
          placeholder="Search agents, apps, tools…"
          aria-label="Search the workspace"
          role="combobox"
          aria-autocomplete="list"
          aria-expanded={open && term.length > 1}
          aria-controls={listId}
          aria-activedescendant={open && matches[active] ? `${listId}-${active}` : undefined}
        />
        <kbd aria-hidden>{isMac ? "⌘K" : "Ctrl K"}</kbd>
        {open && term.length > 1 && (
          <div id={listId} className="search-results" role="listbox" aria-label="Search results">
            {matches.length ? matches.map((item, index) => (
              <button key={item.key} id={`${listId}-${index}`} type="button" role="option" aria-selected={active === index} onMouseMove={() => setActive(index)} onClick={() => pick(item)}>
                <strong>{item.name}</strong>
                <span>{item.kind} · {item.meta}</span>
              </button>
            )) : <div className="empty-result">No matches for “{query.trim()}”</div>}
          </div>
        )}
      </div>
    </header>
  );
}
