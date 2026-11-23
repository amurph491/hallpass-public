export type Section = "home" | "agents" | "apps" | "approvals" | "activity";

export const SECTIONS: Section[] = ["home", "agents", "apps", "approvals", "activity"];

/** Sections whose sidebar entry shows a collection count. */
export const COUNTED_SECTIONS: Section[] = ["agents", "apps", "approvals"];

export const sectionCopy: Record<Section, { title: string; subtitle: string }> = {
  home: { title: "Home", subtitle: "Your agents, what they did recently, and anything that needs you." },
  agents: { title: "Agents", subtitle: "Each agent signs in with its own key and can use only the access you give it." },
  apps: { title: "Apps", subtitle: "Apps Hallpass can reach for your agents. Their credentials stay on the server." },
  approvals: { title: "Approvals", subtitle: "Requests your agents made that wait for your decision." },
  activity: { title: "Activity", subtitle: "Every call your agents made and every access test, newest first." }
};

export function navLabel(section: Section): string {
  return sectionCopy[section].title;
}

export const ADMIN_BASE = "/admin";

export function sectionPath(section: Section): string {
  return section === "home" ? ADMIN_BASE : `${ADMIN_BASE}/${section}`;
}

export type AgentTab = "access" | "key" | "setup" | "activity";
export const AGENT_TABS: AgentTab[] = ["access", "key", "setup", "activity"];

export function agentPath(agentId: string, tab: AgentTab = "access"): string {
  const base = `${ADMIN_BASE}/agents/${encodeURIComponent(agentId)}`;
  return tab === "access" ? base : `${base}?tab=${tab}`;
}

export function parseAgentTab(value: string | null): AgentTab {
  return AGENT_TABS.find(tab => tab === value) ?? "access";
}

export function parseSection(value: string | undefined): Section | undefined {
  return SECTIONS.find(section => section === value);
}

export function appPath(appId: string): string {
  return `${ADMIN_BASE}/apps/${encodeURIComponent(appId)}`;
}

/**
 * Screens folded into others by the redesign: Setup and Delegations into Agents,
 * Decisions into Activity, Tools and Connections into Apps, Overview into Home.
 */
const RETIRED: Record<string, Section> = {
  setup: "agents",
  delegations: "agents",
  decisions: "activity",
  tools: "apps",
  connections: "apps",
  overview: "home"
};

export type AdminRoute =
  | { kind: "section"; section: Section }
  | { kind: "agent"; agentId: string }
  | { kind: "app"; appId: string }
  | { kind: "redirect"; to: string };

/** Resolves the path below /admin, e.g. "", "apps", "agents/<id>". */
export function resolveAdminPath(rest: string): AdminRoute {
  const [first, second, ...extra] = rest.split("/").filter(Boolean);
  if (!first) return { kind: "section", section: "home" };
  if (first === "agents" && second && !extra.length) return { kind: "agent", agentId: decodeURIComponent(second) };
  if (first === "apps" && second && !extra.length) return { kind: "app", appId: decodeURIComponent(second) };
  if (second) return { kind: "redirect", to: ADMIN_BASE };
  if (RETIRED[first]) return { kind: "redirect", to: sectionPath(RETIRED[first]) };
  const section = parseSection(first);
  if (!section || section === "home") return { kind: "redirect", to: ADMIN_BASE };
  return { kind: "section", section };
}

/** Maps pre-router links such as `/admin#connections`, which the Slack OAuth callback still uses. */
export function legacyHashPath(hash: string): string | undefined {
  const name = hash.replace(/^#/, "");
  if (RETIRED[name]) return sectionPath(RETIRED[name]);
  const section = parseSection(name);
  return section ? sectionPath(section) : undefined;
}
