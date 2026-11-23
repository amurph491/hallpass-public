import assert from "node:assert/strict";
import test from "node:test";
import type { CheckResult, ExecutionEvent } from "../src/api/client.ts";
import { buildRequests, filterRequests, parseFilters, reasonLabel, requestAction, requestExplanation, requestTimeline } from "../src/lib/requests.ts";

const event = (requestId: string, eventKind: string, occurredAt: string, safeOutcome = ""): ExecutionEvent => ({
  requestId, eventKind, occurredAt, safeOutcome, correlationId: `c-${requestId}`, agentId: "agent-1", tool: "slack_search_messages", capability: "Slack.Message.Read", authorizationSource: "AGENT_CALL"
});
const decision = (requestId: string, outcome: CheckResult["decision"], checkedAt: string, extra: Partial<CheckResult> = {}): CheckResult => ({
  requestId, decision: outcome, checkedAt, title: "", reason: outcome === "allow" ? "authorized" : "CapabilityNotDelegated(d-1)", principalId: "agent-1", tool: "slack_search_messages", authorizationSource: "AGENT_CALL", ...extra
});
const resultOf = (decisions: CheckResult[], events: ExecutionEvent[]) => buildRequests(decisions, events)[0].result.label;

test("decisions and lifecycle events join into one request by request ID", () => {
  const requests = buildRequests(
    [decision("a", "allow", "2026-09-24T12:00:00Z"), decision("b", "deny", "2026-09-24T12:05:00Z")],
    [event("a", "EXECUTION_COMPLETED", "2026-09-24T12:00:02Z"), event("a", "LEASE_ISSUED", "2026-09-24T12:00:01Z")]
  );
  assert.deepEqual(requests.map(request => [request.requestId, request.result.label]), [["b", "Blocked"], ["a", "Succeeded"]]);
  assert.deepEqual(requests[1].events.map(item => item.eventKind), ["LEASE_ISSUED", "EXECUTION_COMPLETED"]);
  assert.equal(requests[1].capability, "Slack.Message.Read");
});

test("lease issuance or redemption alone is never reported as success", () => {
  const allow = [decision("r", "allow", "2026-09-24T12:00:00Z")];
  assert.equal(resultOf(allow, [event("r", "LEASE_ISSUED", "2026-09-24T12:00:01Z"), event("r", "LEASE_REDEEMED", "2026-09-24T12:00:02Z")]), "In progress");
  assert.equal(resultOf(allow, [event("r", "LEASE_REDEEMED", "2026-09-24T12:00:01Z"), event("r", "AUTHORITY_CHANGED", "2026-09-24T12:00:02Z")]), "Blocked");
  assert.equal(resultOf(allow, [event("r", "PROVIDER_UNAVAILABLE", "2026-09-24T12:00:02Z")]), "Failed");
  assert.equal(resultOf(allow, [event("r", "COMPLETION_UNKNOWN", "2026-09-24T12:00:02Z")]), "Outcome unknown");
  assert.equal(resultOf(allow, [event("r", "EXECUTION_COMPLETED", "2026-09-24T12:00:03Z")]), "Succeeded");
  assert.equal(resultOf([decision("r", "require_approval", "2026-09-24T12:00:00Z")], []), "Needs approval");
});

test("tests are allowed or blocked and never report execution", () => {
  const preview = decision("t", "allow", "2026-09-24T12:00:00Z", { authorizationSource: "HUMAN_PREVIEW" });
  const [request] = buildRequests([preview], []);
  assert.equal(request.source, "test");
  assert.equal(request.result.label, "Allowed");
  assert.match(requestTimeline(request).map(step => step.label).join("|"), /^Access allowed\|Nothing sent to Slack$/);
});

test("legacy rows without provenance have an unknown source", () => {
  assert.equal(buildRequests([decision("r", "deny", "2026-09-24T12:00:00Z", { authorizationSource: undefined })], [])[0].source, "unknown");
});

test("the timeline and explanation say why a call stopped", () => {
  const [changed] = buildRequests([decision("r", "allow", "2026-09-24T12:00:00Z")], [event("r", "LEASE_ISSUED", "2026-09-24T12:00:01Z"), event("r", "AUTHORITY_CHANGED", "2026-09-24T12:00:02Z")]);
  assert.deepEqual(requestTimeline(changed).map(step => step.label), ["Access allowed", "Execution pass issued", "Access changed before the call"]);
  assert.match(requestExplanation(changed) ?? "", /Slack was never called/);
  const [expired] = buildRequests([], [event("r", "REDEMPTION_DENIED", "2026-09-24T12:00:02Z", "DENIED_EXPIRED")]);
  assert.match(requestExplanation(expired) ?? "", /expired/);
  const [blocked] = buildRequests([decision("r", "deny", "2026-09-24T12:00:00Z")], []);
  assert.equal(requestExplanation(blocked), "This agent hasn’t been given this access.");
});

test("journal reason codes become sentences and unknown codes stay generic", () => {
  assert.equal(reasonLabel("NoMatchingAuthority"), "No access grant or policy covers this action.");
  assert.equal(reasonLabel("unmapped_tool"), "This tool isn’t mapped to a capability, so it’s always blocked.");
  assert.equal(reasonLabel("InactiveDelegation(3f2a)"), "The agent’s access for this was removed or has expired.");
  assert.equal(reasonLabel("The delegated capability and owner policy allow this action."), "The delegated capability and owner policy allow this action.");
  assert.equal(reasonLabel("SomethingNew"), "Authorization was denied.");
});

test("filters come from the URL, ignore unknown values, and combine", () => {
  const now = Date.parse("2026-09-24T12:00:00Z");
  const requests = buildRequests(
    [decision("old", "deny", "2026-09-20T12:00:00Z"), decision("new", "deny", "2026-09-24T11:30:00Z"), decision("other", "deny", "2026-09-24T11:30:00Z", { principalId: "agent-2" })],
    [event("ok", "EXECUTION_COMPLETED", "2026-09-24T11:59:00Z")]
  );
  assert.deepEqual(parseFilters(new URLSearchParams("result=bogus&range=1y&source=test&agent=agent-1")), { agent: "agent-1", result: undefined, source: "test", range: undefined });
  const ids = (filters: Parameters<typeof filterRequests>[1]) => filterRequests(requests, filters, now).map(request => request.requestId).sort();
  assert.deepEqual(ids({ result: "blocked", range: "24h" }), ["new", "other"]);
  assert.deepEqual(ids({ result: "blocked", agent: "agent-1" }), ["new", "old"]);
  assert.deepEqual(ids({ result: "succeeded" }), ["ok"]);
});

test("actions use the capability's plain name and flag unmapped tools", () => {
  assert.deepEqual(requestAction({ capability: "Slack.Message.Read" }, []), { label: "Read Slack messages", capability: "Slack.Message.Read" });
  assert.deepEqual(requestAction({ tool: "slack_search_messages" }, [{ name: "slack_search_messages", label: "Search", capability: "Slack.Message.Read", trusted: true }]).label, "Read Slack messages");
  assert.equal(requestAction({ tool: "unknown_demo_tool" }, []).label, "Unmapped tool");
});
