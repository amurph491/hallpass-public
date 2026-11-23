import type { Agent } from "../../api/client";
import { readJson, writeJson } from "../../lib/storage";

export type ClientKey = "codex" | "claude" | "antigravity" | "other";
export type Client = { key: ClientKey; title: string; configPath?: string };

/**
 * Local MCP clients the installer can register. The client is a display and
 * setup label only; the agent ID in the key is the authenticated identity.
 */
export const CLIENTS: Client[] = [
  { key: "codex", title: "Codex CLI", configPath: "~/.codex/config.toml" },
  { key: "claude", title: "Claude Code", configPath: "~/.claude.json" },
  { key: "antigravity", title: "Google Antigravity", configPath: "~/.gemini/config/mcp_config.json" },
  { key: "other", title: "Other MCP client" }
];

export function clientFor(key: ClientKey): Client {
  return CLIENTS.find(client => client.key === key) ?? CLIENTS[CLIENTS.length - 1];
}

const AGENT_CLIENTS_KEY = "hallpass.agentClients";
/** An earlier setup page stored client -> agent; read once so existing choices carry over. */
const LEGACY_CLIENT_AGENTS_KEY = "hallpass.pr4.clientAgents";

function isClientKey(value: unknown): value is ClientKey {
  return CLIENTS.some(client => client.key === value);
}

export function loadAgentClients(): Record<string, ClientKey> {
  const saved = readJson(AGENT_CLIENTS_KEY);
  const result: Record<string, ClientKey> = {};
  if (saved && typeof saved === "object") {
    for (const [agentId, key] of Object.entries(saved)) if (isClientKey(key)) result[agentId] = key;
  }
  const legacy = readJson(LEGACY_CLIENT_AGENTS_KEY);
  if (legacy && typeof legacy === "object") {
    for (const [key, agentId] of Object.entries(legacy)) {
      if (isClientKey(key) && typeof agentId === "string" && agentId && !result[agentId]) result[agentId] = key;
    }
  }
  return result;
}

export function saveAgentClients(value: Record<string, ClientKey>): void {
  writeJson(AGENT_CLIENTS_KEY, value);
}

/** The remembered client for an agent, else a guess from its name, else "other". */
export function clientOf(agent: Agent, remembered: Record<string, ClientKey>): ClientKey {
  if (remembered[agent.id]) return remembered[agent.id];
  const name = agent.name.toLowerCase();
  if (name.includes("codex")) return "codex";
  if (name.includes("claude")) return "claude";
  if (name.includes("antigravity") || name.includes("gemini")) return "antigravity";
  return "other";
}

/** The packaged bridge's install location. */
export const HALLPASS_CLI = `"$HOME/.local/share/hallpass/bridge/bin/hallpass"`;

const DNS_LABEL = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?";
const DNS_NAME = new RegExp(`^${DNS_LABEL}(\\.${DNS_LABEL})+$`);

/**
 * The endpoint rule shared by the bridge and the installer: `https://` to one exact host (optional port), or
 * `http://` to a numeric loopback address only. No user info, path, query, or fragment. Returns the normalized
 * `scheme://authority`, or undefined when the value would be refused. An accepted value holds only host and port
 * characters, so it is safe to place in a shell command.
 */
export function acceptedEndpoint(value: string): string | undefined {
  let url: URL;
  try { url = new URL(value); } catch { return undefined; }
  const barePath = url.pathname === "/" || url.pathname === "";
  if (url.username || url.password || url.search || url.hash || value.includes("?") || value.includes("#") || !barePath) return undefined;
  const host = url.hostname.toLowerCase();
  if (url.protocol === "https:" && host.length <= 253 && (DNS_NAME.test(host) || /^\[[0-9a-f:.]+\]$/.test(host))) {
    return `https://${url.host.toLowerCase()}`;
  }
  const loopback = /^127\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (url.protocol === "http:" && ((loopback && loopback.slice(1).every(part => Number(part) <= 255)) || host === "[::1]")) {
    return `http://${url.host.toLowerCase()}`;
  }
  return undefined;
}

/**
 * Where the instance serves the bridge package, or undefined when the admin origin is not an address the installer
 * accepts. The installer refuses `http://localhost`, so a `localhost` host is written as numeric loopback.
 */
export function downloadsBase(adminOrigin: string): string | undefined {
  let origin: URL;
  try { origin = new URL(adminOrigin); } catch { return undefined; }
  if (origin.hostname === "localhost") origin.hostname = "127.0.0.1";
  const accepted = acceptedEndpoint(origin.origin);
  return accepted && `${accepted}/downloads`;
}

/**
 * The MCP server name a client lists this agent under: `hallpass-` and a slug of 1-24 lowercase letters, numerals, and
 * inner hyphens. The same rule as `hallpass --name` and the installer. A name that passes holds only `[a-z0-9-]`, so it
 * is safe to place in a shell command and in a TOML bare key. It labels the client entry only; the agent ID in the key
 * is the identity, and a name never selects an agent, tenant, or credential.
 */
// The slug is capped at 24 so a client's full tool name stays within the 64-character tool-name limit, for example
// `mcp__hallpass-<24>__slack_search_messages` is 59 characters, leaving room for longer tool names.
export const SERVER_NAME_PATTERN = /^hallpass-[a-z0-9](?:[a-z0-9-]{0,22}[a-z0-9])?$/;

/** `hallpass-` plus the first 8 hex characters of the agent ID (what the CLI uses when no name is given). */
export function defaultServerName(agentId: string): string {
  const hex = agentId.toLowerCase().replace(/[^0-9a-f]/g, "").slice(0, 8);
  return hex ? `hallpass-${hex}` : "hallpass-agent";
}

/**
 * The server name for an agent, derived from its display name: lowercased, each run of characters outside `a-z0-9`
 * becomes one `-`, the ends are trimmed, and the slug is cut to 24 characters (and trimmed again, since a cut can leave
 * a trailing `-`). An empty slug falls back to {@link defaultServerName}. Two agents with the same display name get the
 * same name; the CLI refuses the second one in a client rather than overwrite the first.
 */
export function serverNameFor(agent: { id: string; name: string }): string {
  const slug = agent.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 24).replace(/-+$/, "");
  const name = slug ? `hallpass-${slug}` : defaultServerName(agent.id);
  return SERVER_NAME_PATTERN.test(name) ? name : defaultServerName(agent.id);
}

/** The prefix Claude Code gives every tool of this server, for example `mcp__hallpass-research__slack_search_messages`. */
export const claudeToolPrefix = (serverName: string) => `mcp__${serverName}__`;

function checkedServerName(serverName: string): string {
  // Reached only by a programming error: every caller passes serverNameFor(...). Never emit an unchecked name.
  if (!SERVER_NAME_PATTERN.test(serverName)) throw new Error("invalid MCP server name");
  return serverName;
}

/**
 * Commands for one agent and client. They contain the agent ID, the client name, and URLs, never a key: the
 * installed CLI prompts for the key on the terminal, hidden. `agentApiUrl` must already pass {@link acceptedEndpoint}, and
 * `serverName` {@link SERVER_NAME_PATTERN}.
 */
export function connectCommands(agentId: string, client: Exclude<ClientKey, "other">, agentApiUrl: string, serverName: string) {
  const name = checkedServerName(serverName);
  const connect = `${HALLPASS_CLI} connect ${client} --agent ${agentId} --url ${agentApiUrl} --name ${name}`;
  return {
    /** For a machine that already has the bridge installed. */
    connect,
    /** The key was replaced on the server, and this machine still holds the previous one. */
    rotate: `${connect} --rotate`,
    /** A different server already uses this name in the client. */
    replace: `${connect} --replace`,
    /** Names the entry explicitly, so it checks the one shown here even on a machine that recorded another name. */
    doctor: `${HALLPASS_CLI} doctor --client ${client} --agent ${agentId} --name ${name}`
  };
}

/** One command that installs or upgrades the bridge from this instance, then runs `hallpass connect`. */
export function installerCommand(downloadsBaseUrl: string, agentId: string, client: Exclude<ClientKey, "other">, agentApiUrl: string, serverName: string): string {
  const name = checkedServerName(serverName);
  return `curl -fsSL ${downloadsBaseUrl}/install.sh | sh -s -- --from ${downloadsBaseUrl} --url ${agentApiUrl} --agent ${agentId} --client ${client} --name ${name}`;
}

/** Manual MCP configuration for a source checkout. It references the key file path only. */
export function manualClientConfig(client: ClientKey, checkoutPath: string, credentialPath: string, agentApiUrl: string, serverName: string): string {
  const name = checkedServerName(serverName);
  const root = checkoutPath.startsWith("/") ? checkoutPath : "<ABSOLUTE_WSL_CHECKOUT>";
  const launcher = `${root.replace(/\/$/, "")}/bridge/bin/hallpass-bridge`;
  const credential = credentialPath || "<ABSOLUTE_CREDENTIAL_FILE_PATH>";
  const env = { HALLPASS_AGENT_API_URL: agentApiUrl, HALLPASS_AGENT_CREDENTIAL_FILE: credential };
  if (client === "codex") {
    return `[mcp_servers.${name}]\ncommand = ${JSON.stringify(launcher)}\nenv = { HALLPASS_AGENT_API_URL = ${JSON.stringify(agentApiUrl)}, HALLPASS_AGENT_CREDENTIAL_FILE = ${JSON.stringify(credential)} }`;
  }
  if (client === "claude") {
    return JSON.stringify({ mcpServers: { [name]: { type: "stdio", command: launcher, env } } }, null, 2);
  }
  return JSON.stringify({ mcpServers: { [name]: { command: launcher, env } } }, null, 2);
}

const SETUP_PATHS_KEY = "hallpass.manualSetupPaths";

export type ManualPaths = { checkoutPath: string; credentialPath: string };

export function loadManualPaths(): ManualPaths {
  const saved = readJson(SETUP_PATHS_KEY) as Partial<Record<keyof ManualPaths, unknown>> | null;
  return {
    checkoutPath: typeof saved?.checkoutPath === "string" ? saved.checkoutPath : "",
    credentialPath: typeof saved?.credentialPath === "string" ? saved.credentialPath : ""
  };
}

export function saveManualPaths(value: ManualPaths): void {
  writeJson(SETUP_PATHS_KEY, value);
}
