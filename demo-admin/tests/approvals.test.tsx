import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { ApiStatusError, controlPlaneApi, invalidateSessionRequests, loadManagementSession, type Approval } from "../src/api/client.ts";
import { ApprovalsView } from "../src/features/approvals/ApprovalsView.tsx";
import { approvalErrorMessage, relativeTime } from "../src/lib/approvals.ts";
import { COUNTED_SECTIONS, SECTIONS, resolveAdminPath, sectionPath } from "../src/app/routes.ts";

const NOW = Date.parse("2026-10-01T12:00:00Z");
const approval = (preview: Record<string, unknown>): Approval => ({
  id: "ap-1", tool: "github_create_issue", operation: "github.issue.create.v1", agentId: "agent-1", capability: "GitHub.Issue.Create", action: "Execute",
  resourceId: "res-1", preview, requestedAt: "2026-10-01T11:57:00Z", expiresAt: "2026-10-01T12:12:00Z"
});
const view = (approvals: Approval[], errors: Record<string, string | undefined> = {}) => renderToStaticMarkup(
  <ApprovalsView approvals={approvals} agentName={id => id === "agent-1" ? "Research Agent" : id} resourceName={id => id === "res-1" ? "acme/widgets" : id}
    errors={errors} now={NOW} busy={false} onDecide={() => undefined} />
);

test("the approvals client uses the documented paths, methods and CSRF header", async t => {
  const calls: { path: string; method: string; csrf: string | null }[] = [];
  t.mock.method(globalThis, "fetch", async (path: string, init?: RequestInit) => {
    if (path === "/api/session") return new Response(JSON.stringify({ userId: "u", csrfToken: "csrf-1", memberships: [] }));
    calls.push({ path, method: init?.method ?? "GET", csrf: new Headers(init?.headers).get("X-CSRF-Token") });
    return new Response(JSON.stringify(path === "/api/approvals" ? { approvals: [approval({ title: "x" })] } : approval({})));
  });
  invalidateSessionRequests();
  await loadManagementSession();
  const list = await controlPlaneApi.approvals();
  await controlPlaneApi.decideApproval("ap/1", "approve");
  await controlPlaneApi.decideApproval("ap-2", "deny");
  assert.equal(list[0]?.preview.title, "x");
  assert.deepEqual(calls.map(c => `${c.method} ${c.path}`), ["GET /api/approvals", "POST /api/approvals/ap%2F1/approve", "POST /api/approvals/ap-2/deny"]);
  assert.equal(calls[1]?.csrf, "csrf-1");
  assert.equal(calls[2]?.csrf, "csrf-1");
});

test("a failed decision surfaces the server's status", async t => {
  t.mock.method(globalThis, "fetch", async () => new Response("{}", { status: 409 }));
  await assert.rejects(controlPlaneApi.decideApproval("ap-1", "approve"), (e: unknown) => e instanceof ApiStatusError && e.status === 409);
});

test("string preview values render as escaped text, never HTML", () => {
  const html = view([approval({ body: "<img src=x onerror=alert(1)><script>boom()</script>" })]);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;&lt;script&gt;boom\(\)&lt;\/script&gt;/);
  assert.doesNotMatch(html, /<img|<script/);
  assert.match(html, /approval-preview/);
});

test("nested values render as formatted JSON and null as a dash", () => {
  const html = view([approval({ labels: ["a", "b"], meta: { n: 1 }, assignee: null })]);
  assert.match(html, /\[\n  &quot;a&quot;,\n  &quot;b&quot;\n\]/);
  assert.match(html, /\{\n  &quot;n&quot;: 1\n\}/);
  assert.match(html, /<dt>assignee<\/dt><dd>—<\/dd>/);
});

test("a card names the agent, tool, target and relative times, explains the grant, and offers both decisions", () => {
  const html = view([approval({ title: "Bug" })]);
  assert.match(html, /Research Agent/);
  assert.match(html, /github_create_issue/);
  assert.match(html, /acme\/widgets/);
  assert.match(html, /requested 3 minutes ago/);
  assert.match(html, /expires in 12 minutes/);
  assert.match(html, /exactly this request, once, until its displayed expiry/);
  assert.match(html, />Approve</);
  assert.match(html, />Deny</);
});

test("an unknown resource falls back to its ID, and an empty queue says so", () => {
  assert.match(view([{ ...approval({}), resourceId: "res-9" }]), /on res-9/);
  assert.match(view([]), /Nothing is waiting for you/);
});

test("each failing status has its own message, shown inline on the card", () => {
  const messages = [403, 404, 409, 410, 503].map(status => approvalErrorMessage(new ApiStatusError(status)));
  assert.equal(new Set(messages).size, 5);
  assert.match(approvalErrorMessage(new ApiStatusError(410)), /expired/);
  assert.match(view([approval({})], { "ap-1": messages[2] }), /role="alert">This request was already decided/);
});

test("approvals is a counted navigation section with its own route", () => {
  assert.ok(SECTIONS.includes("approvals"));
  assert.ok(COUNTED_SECTIONS.includes("approvals"));
  assert.deepEqual(resolveAdminPath("approvals"), { kind: "section", section: "approvals" });
  assert.equal(sectionPath("approvals"), "/admin/approvals");
});

test("relative times read in both directions", () => {
  assert.equal(relativeTime("2026-10-01T12:00:10Z", NOW), "just now");
  assert.equal(relativeTime("2026-10-01T10:00:00Z", NOW), "2 hours ago");
  assert.equal(relativeTime("not a date", NOW), "—");
});
