import assert from "node:assert/strict";
import test from "node:test";
import type { AgentCredential, Connection, Delegation } from "../src/api/client.ts";
import { currentCredential } from "../src/lib/access.ts";
import { activeGrants, lastUsed, pastGrants } from "../src/lib/agents.ts";
import { appStatus } from "../src/lib/apps.ts";
import { capabilityLabel } from "../src/lib/capabilities.ts";
import { authorizationSourceLabel, credentialStatus } from "../src/lib/labels.ts";

const grant = (status: string, expiresAt?: string): Delegation => ({
  id: status,
  granteeId: "agent-1",
  capabilityId: "slack-read",
  grantor: "owner",
  grantee: "agent",
  capability: "Slack.Message.Read",
  status,
  expiresAt
});

test("the current credential is the first unrevoked one", () => {
  const revoked: AgentCredential = { id: "old", prefix: "old", revokedAt: "2026-09-01T00:00:00Z" };
  const live: AgentCredential = { id: "new", prefix: "new" };
  assert.equal(currentCredential([revoked, live])?.id, "new");
  assert.equal(currentCredential([revoked]), undefined);
  assert.equal(currentCredential(undefined), undefined);
});

test("key status distinguishes missing, revoked, expired, and active", () => {
  const now = Date.parse("2026-09-24T12:00:00Z");
  assert.equal(credentialStatus(undefined, now).label, "No key");
  assert.equal(credentialStatus({ id: "a", prefix: "p", revokedAt: "2026-09-01T00:00:00Z" }, now).label, "Revoked");
  assert.equal(credentialStatus({ id: "a", prefix: "p", expiresAt: "2026-09-24T12:00:00Z" }, now).label, "Expired");
  assert.equal(credentialStatus({ id: "a", prefix: "p", expiresAt: "2026-09-25T00:00:00Z" }, now).label, "Active");
});

test("activity origin labels distinguish agent calls, previews, and legacy rows", () => {
  assert.equal(authorizationSourceLabel("AGENT_CALL"), "Agent call");
  assert.equal(authorizationSourceLabel("HUMAN_PREVIEW"), "Access test");
  assert.equal(authorizationSourceLabel(undefined), "Not recorded");
});

test("an agent's active grants exclude revoked, expired, and other agents' grants", () => {
  const now = Date.parse("2026-09-24T12:00:00Z");
  const all = [grant("active"), grant("revoked"), grant("active", "2026-09-24T11:00:00Z"), { ...grant("active"), id: "other", granteeId: "agent-2" }];
  all[0].id = "live";
  all[2].id = "expired";
  assert.deepEqual(activeGrants(all, "agent-1", now).map(item => item.id), ["live"]);
  assert.deepEqual(pastGrants(all, "agent-1", now).map(item => item.id).sort(), ["expired", "revoked"]);
});

test("last used is the most recent use across keys", () => {
  assert.equal(lastUsed([{ id: "a", prefix: "a", lastUsedAt: "2026-09-01T00:00:00Z" }, { id: "b", prefix: "b", lastUsedAt: "2026-09-20T00:00:00Z" }, { id: "c", prefix: "c" }]), "2026-09-20T00:00:00Z");
  assert.equal(lastUsed([]), undefined);
});

test("capabilities get plain names with a readable fallback", () => {
  assert.equal(capabilityLabel("Slack.Message.Read"), "Read Slack messages");
  assert.equal(capabilityLabel("GitHub.Issue.Write"), "Write GitHub Issue");
  assert.equal(capabilityLabel("Custom"), "Custom");
});

test("app status requires reconnect for reauthorization and leaves active connections connected", () => {
  const connection = (status: string): Connection => ({
    id: status,
    resourceId: "resource-1",
    provider: "slack",
    status,
    createdAt: "2026-09-24T12:00:00Z"
  });
  assert.deepEqual(appStatus(connection("needs_reauth")), {
    key: "needs_reauth",
    label: "Reconnect required",
    tone: "warning"
  });
  assert.equal(appStatus(connection("active")).key, "connected");
  assert.notEqual(appStatus(connection("needs_reauth")).key, "connected");
});
