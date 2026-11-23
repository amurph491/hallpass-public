import assert from "node:assert/strict";
import test from "node:test";
import { loginNotice, sessionGate } from "../src/lib/session.ts";
const methods = { oidc: true, developmentBootstrap: false };
const tenant = { tenantId: "t", name: "Example", role: "ADMIN" as const, breakGlass: false };
test("only a verified administrator workspace opens the control plane", () => {
  assert.equal(sessionGate(undefined, methods).kind, "sign-in");
  assert.equal(sessionGate({ userId: "u", memberships: [tenant] }, methods).kind, "choose-tenant");
  assert.equal(sessionGate({ userId: "u", tenant, memberships: [tenant] }, methods).kind, "ready");
  assert.equal(sessionGate({ userId: "u", tenant: { ...tenant, role: "MEMBER" }, memberships: [] }, methods).kind, "choose-tenant");
});
test("login notices never echo untrusted query text", () => {
  assert.equal(loginNotice("<script>"), undefined);
  assert.match(loginNotice("no_access")!, /no.*access/);
});
