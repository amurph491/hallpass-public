import assert from "node:assert/strict";
import test from "node:test";
import { agentPath, appPath, legacyHashPath, parseAgentTab, resolveAdminPath, sectionPath } from "../src/app/routes.ts";

test("sections map to admin paths with home at the root", () => {
  assert.equal(sectionPath("home"), "/admin");
  assert.equal(sectionPath("agents"), "/admin/agents");
});

test("admin paths resolve to sections, agent pages, or redirects", () => {
  assert.deepEqual(resolveAdminPath(""), { kind: "section", section: "home" });
  assert.deepEqual(resolveAdminPath("apps"), { kind: "section", section: "apps" });
  assert.deepEqual(resolveAdminPath("agents/a%2Fb"), { kind: "agent", agentId: "a/b" });
  assert.deepEqual(resolveAdminPath("apps/r-1"), { kind: "app", appId: "r-1" });
  assert.deepEqual(resolveAdminPath("home"), { kind: "redirect", to: "/admin" });
  assert.deepEqual(resolveAdminPath("nope"), { kind: "redirect", to: "/admin" });
  assert.deepEqual(resolveAdminPath("activity/x"), { kind: "redirect", to: "/admin" });
  assert.deepEqual(resolveAdminPath("apps/x/y"), { kind: "redirect", to: "/admin" });
  assert.deepEqual(resolveAdminPath("agents/x/y"), { kind: "redirect", to: "/admin" });
});

test("retired Tools, Connections and Overview screens redirect to Apps and Home", () => {
  assert.deepEqual(resolveAdminPath("tools"), { kind: "redirect", to: "/admin/apps" });
  assert.deepEqual(resolveAdminPath("connections"), { kind: "redirect", to: "/admin/apps" });
  assert.deepEqual(resolveAdminPath("overview"), { kind: "redirect", to: "/admin" });
  assert.equal(appPath("a/b"), "/admin/apps/a%2Fb");
});

test("retired Decisions screen redirects to Activity", () => {
  assert.deepEqual(resolveAdminPath("decisions"), { kind: "redirect", to: "/admin/activity" });
  assert.equal(legacyHashPath("#decisions"), "/admin/activity");
});

test("retired Setup and Delegations screens redirect to Agents", () => {
  assert.deepEqual(resolveAdminPath("setup"), { kind: "redirect", to: "/admin/agents" });
  assert.deepEqual(resolveAdminPath("delegations"), { kind: "redirect", to: "/admin/agents" });
  assert.equal(legacyHashPath("#setup"), "/admin/agents");
  assert.equal(legacyHashPath("#delegations"), "/admin/agents");
});

test("legacy hash links, including the Slack OAuth callback, resolve to paths", () => {
  assert.equal(legacyHashPath("#connections"), "/admin/apps");
  assert.equal(legacyHashPath("#overview"), "/admin");
  assert.equal(legacyHashPath("#nope"), undefined);
  assert.equal(legacyHashPath(""), undefined);
});

test("agent paths carry the tab except for the default", () => {
  assert.equal(agentPath("abc"), "/admin/agents/abc");
  assert.equal(agentPath("abc", "setup"), "/admin/agents/abc?tab=setup");
  assert.equal(parseAgentTab("key"), "key");
  assert.equal(parseAgentTab("bogus"), "access");
  assert.equal(parseAgentTab(null), "access");
});
