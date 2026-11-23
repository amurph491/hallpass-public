import assert from "node:assert/strict";
import test from "node:test";
import type { Agent, AgentCredential, Capability, Connection, Delegation, Resource, Tool } from "../src/api/client.ts";
import { appStatus, buildApps } from "../src/lib/apps.ts";
import { attentionItems, setupSteps } from "../src/lib/home.ts";
import { buildRequests } from "../src/lib/requests.ts";

const now = Date.parse("2026-09-24T12:00:00Z");
const slack: Resource = { id: "r1", name: "Demo Slack workspace", type: "provider", provider: "slack" };
const read: Capability = { id: "c1", name: "Slack.Message.Read", action: "read", resourceId: "r1" };
const send: Capability = { id: "c2", name: "Slack.Message.Send", action: "write", resourceId: "r1" };
const tools: Tool[] = [
  { name: "slack_search_messages", label: "Search Slack messages", resourceId: "r1", capabilityId: "c1", capability: "Slack.Message.Read", trusted: true },
  { name: "slack_guess", label: "Suggested tool", resourceId: "r1", capabilityId: "c1", capability: "Slack.Message.Read", trusted: false }
];
const agent: Agent = { id: "a1", name: "local codex" };
const grant: Delegation = { id: "d1", granteeId: "a1", capabilityId: "c1", capability: "Slack.Message.Read", grantor: "owner", grantee: "local codex", status: "active" };
const connection = (status: string, extra: Partial<Connection> = {}): Connection => ({ id: `k-${status}`, resourceId: "r1", provider: "slack", status, createdAt: "2026-09-20T00:00:00Z", ...extra });
const catalog = (extra: { connections?: Connection[]; delegations?: Delegation[]; agents?: Agent[] } = {}) =>
  ({ resources: [slack], capabilities: [read, send], tools, connections: [], delegations: [], agents: [agent], ...extra });

test("an app groups capabilities with their tools and the agents holding them", () => {
  const [app] = buildApps(catalog({ connections: [connection("active")], delegations: [grant, { ...grant, id: "d2", status: "revoked" }] }), now);
  assert.equal(app.provider, "Slack");
  assert.equal(app.status.label, "Connected");
  assert.deepEqual(app.capabilities.map(item => [item.label, item.tools.map(tool => tool.name), item.agents.map(a => a.name)]), [
    ["Read Slack messages", ["slack_search_messages"], ["local codex"]],
    ["Send Slack messages", [], []]
  ]);
});

test("untrusted mappings are never shown as usable tools; they are always blocked", () => {
  const [app] = buildApps(catalog(), now);
  assert.deepEqual(app.blockedTools.map(tool => tool.name), ["slack_guess"]);
  assert.ok(!app.capabilities.some(item => item.tools.some(tool => tool.name === "slack_guess")));
});

test("app status prefers an active connection and treats past expiry as expired", () => {
  assert.equal(appStatus(undefined).label, "Not connected");
  assert.equal(appStatus(connection("disabled")).label, "Disconnected");
  assert.equal(appStatus(connection("active", { expiresAt: "2026-09-24T11:00:00Z" }), now).label, "Expired");
  const [app] = buildApps(catalog({ connections: [connection("disabled", { createdAt: "2026-09-23T00:00:00Z" }), connection("active")] }), now);
  assert.equal(app.status.label, "Connected");
});

const key: AgentCredential = { id: "k", prefix: "p" };
test("setup steps are done only when server data proves them", () => {
  const done = (input: Parameters<typeof setupSteps>[0]) => setupSteps(input, now).map(step => step.done);
  const apps = buildApps(catalog({ connections: [connection("active")] }), now);
  assert.deepEqual(done({ apps: buildApps(catalog(), now), agents: [], delegations: [], credentialsByAgent: {}, hasCompletedExecution: false }), [false, false, false, false, false]);
  assert.deepEqual(done({ apps, agents: [agent], delegations: [grant], credentialsByAgent: { a1: [key] }, hasCompletedExecution: false }), [true, true, true, true, false]);
  assert.deepEqual(done({ apps, agents: [agent], delegations: [grant], credentialsByAgent: { a1: [key] }, hasCompletedExecution: true }), [true, true, true, true, true]);
  // A key on an agent without access doesn't count as a connected client.
  assert.deepEqual(done({ apps, agents: [agent], delegations: [], credentialsByAgent: { a1: [key] }, hasCompletedExecution: false }), [true, true, false, false, false]);
});

test("attention lists expired keys, lost connections, and recent blocked or unknown agent calls", () => {
  const apps = buildApps(catalog({ connections: [connection("disabled")] }), now);
  const requests = buildRequests(
    [
      { requestId: "b", decision: "deny", title: "", reason: "NoMatchingAuthority", principalId: "a1", authorizationSource: "AGENT_CALL", checkedAt: "2026-09-24T11:00:00Z" },
      { requestId: "t", decision: "deny", title: "", reason: "NoMatchingAuthority", principalId: "a1", authorizationSource: "HUMAN_PREVIEW", checkedAt: "2026-09-24T11:00:00Z" },
      { requestId: "old", decision: "deny", title: "", reason: "NoMatchingAuthority", principalId: "a1", authorizationSource: "AGENT_CALL", checkedAt: "2026-09-20T11:00:00Z" }
    ],
    []
  );
  const items = attentionItems({ apps, agents: [agent], delegations: [grant], credentialsByAgent: { a1: [{ ...key, expiresAt: "2026-09-24T00:00:00Z" }] }, requests }, now);
  assert.deepEqual(items.map(item => [item.kind, item.count]), [["key", undefined], ["app", undefined], ["blocked", 1]]);
});

test("attention includes recent provider failures from agents, excluding tests and older calls", () => {
  const requests = buildRequests([], [
    { requestId: "failure", correlationId: "x", agentId: "a1", tool: "slack_search_messages", capability: "Slack.Message.Read", eventKind: "PROVIDER_UNAVAILABLE", safeOutcome: "FAILED_PROVIDER_UNAVAILABLE", authorizationSource: "AGENT_CALL", occurredAt: "2026-09-24T11:00:00Z" },
    { requestId: "preview", correlationId: "x", agentId: "a1", tool: "slack_search_messages", capability: "Slack.Message.Read", eventKind: "PROVIDER_REJECTED", safeOutcome: "FAILED_PROVIDER_REJECTED", authorizationSource: "HUMAN_PREVIEW", occurredAt: "2026-09-24T11:00:00Z" },
    { requestId: "old", correlationId: "x", agentId: "a1", tool: "slack_search_messages", capability: "Slack.Message.Read", eventKind: "PROVIDER_REJECTED", safeOutcome: "FAILED_PROVIDER_REJECTED", authorizationSource: "AGENT_CALL", occurredAt: "2026-09-20T11:00:00Z" }
  ]);
  const items = attentionItems({ apps: [], agents: [agent], delegations: [], credentialsByAgent: { a1: [key] }, requests }, now);
  assert.deepEqual(items.map(item => [item.kind, item.count]), [["failed", 1]]);
});
