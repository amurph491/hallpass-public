import assert from "node:assert/strict";
import test from "node:test";
import { bridgeVersion, controlPlaneApi, invalidateSessionRequests, loadManagementSession, parseBridgeVersion, SESSION_EXPIRED_EVENT } from "../src/api/client.ts";

const session = (token: string) => new Response(JSON.stringify({ userId: "human", csrfToken: token, tenant: { tenantId: "t", role: "ADMIN", name: "Workspace" }, memberships: [] }), { status: 200 });

test("restoring a session restores CSRF for subsequent mutations", async t => {
  let header: string | undefined;
  t.mock.method(globalThis, "fetch", async (path: string, init?: RequestInit) => {
    if (path === "/api/session") return session("restored-csrf");
    header = new Headers(init?.headers).get("X-CSRF-Token") ?? undefined;
    return new Response(JSON.stringify({ id: "agent", name: "Agent" }));
  });
  invalidateSessionRequests();
  await loadManagementSession();
  await controlPlaneApi.createAgent({ name: "Agent" });
  assert.equal(header, "restored-csrf");
});

test("a retired session response cannot replace the new workspace CSRF token", async t => {
  let completeOld!: (response: Response) => void;
  let reads = 0;
  let header: string | null = null;
  t.mock.method(globalThis, "fetch", async (path: string, init?: RequestInit) => {
    if (path === "/api/session") {
      if (++reads === 1) return new Promise<Response>(resolve => { completeOld = resolve; });
      return session("new-workspace-csrf");
    }
    header = new Headers(init?.headers).get("X-CSRF-Token");
    return new Response(JSON.stringify({ id: "agent", name: "Agent" }));
  });
  invalidateSessionRequests();
  const old = loadManagementSession();
  invalidateSessionRequests();
  await loadManagementSession();
  completeOld(session("retired-workspace-csrf"));
  await old;
  await controlPlaneApi.createAgent({ name: "Agent" });
  assert.equal(header, "new-workspace-csrf");
});

test("only a current request rejection expires the session; error bodies stay private", async t => {
  const events: string[] = [];
  const previous = Object.getOwnPropertyDescriptor(globalThis, "window");
  Object.defineProperty(globalThis, "window", { configurable: true, value: { dispatchEvent: (event: Event) => { events.push(event.type); } } });
  t.after(() => { if (previous) Object.defineProperty(globalThis, "window", previous); else Reflect.deleteProperty(globalThis, "window"); });
  let finish!: (response: Response) => void;
  t.mock.method(globalThis, "fetch", () => new Promise<Response>(resolve => { finish = resolve; }));
  invalidateSessionRequests();
  const retired = controlPlaneApi.agents();
  invalidateSessionRequests();
  finish(new Response("private response body", { status: 401 }));
  await assert.rejects(retired, /session/i);
  assert.deepEqual(events, []);
  const current = controlPlaneApi.agents();
  finish(new Response("private response body", { status: 401 }));
  await assert.rejects(current, /session/i);
  assert.deepEqual(events, [SESSION_EXPIRED_EVENT]);
});

test("the session carries the agent API address the server reports", async t => {
  t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ userId: "human", csrfToken: "c", tenant: { tenantId: "t", role: "ADMIN" }, memberships: [], agentApiUrl: "https://agents.example.com" })));
  invalidateSessionRequests();
  assert.equal((await loadManagementSession())?.agentApiUrl, "https://agents.example.com");
  t.mock.method(globalThis, "fetch", async () => session("older-server"));
  invalidateSessionRequests();
  assert.equal((await loadManagementSession())?.agentApiUrl, undefined);
});

test("the bridge version parser accepts release labels only", () => {
  assert.equal(parseBridgeVersion("0.1.0\n"), "0.1.0");
  assert.equal(parseBridgeVersion("2026.09.29-abc123"), "2026.09.29-abc123");
  for (const bad of ["", "<!doctype html><html>", "1.0 && rm -rf ~", "a\nb", "x".repeat(65)]) assert.equal(parseBridgeVersion(bad), null, bad);
});

test("the bridge version is available only from a successful, non-HTML /downloads/VERSION", async t => {
  const seen: string[] = [];
  const answer = (response: Response | Error) => t.mock.method(globalThis, "fetch", async (path: string, init?: RequestInit) => {
    seen.push(path);
    assert.equal(init?.credentials, "omit");
    if (response instanceof Error) throw response;
    return response;
  });
  answer(new Response("0.1.0\n", { status: 200, headers: { "Content-Type": "text/plain" } }));
  assert.equal(await bridgeVersion(), "0.1.0");
  assert.deepEqual(seen, ["/downloads/VERSION"]);
  // The local stack answers 404; an SPA fallback answers 200 with the app shell; an outage throws.
  answer(new Response("not found", { status: 404 }));
  assert.equal(await bridgeVersion(), null);
  answer(new Response("0.1.0", { status: 200, headers: { "Content-Type": "text/html" } }));
  assert.equal(await bridgeVersion(), null);
  answer(new Response("<!doctype html>", { status: 200 }));
  assert.equal(await bridgeVersion(), null);
  answer(new Error("offline"));
  assert.equal(await bridgeVersion(), null);
});
