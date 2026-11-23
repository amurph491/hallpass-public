import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { QueryClientProvider } from "@tanstack/react-query";
import { ApiStatusError, connectionStartMessage, controlPlaneApi, type Connection, type Resource } from "../src/api/client.ts";
import { createQueryClient } from "../src/api/queries.ts";
import { AdminContext, type AdminContextValue } from "../src/app/AdminContext.tsx";
import { AppPage, CONNECTABLE_PROVIDERS, providerKey } from "../src/features/apps/AppPage.tsx";
import { appStatus, type App } from "../src/lib/apps.ts";

function appFor(provider: "Slack" | "GitHub" | "Linear" | "Notion" | "HubSpot", connection?: Connection): App {
  const resource: Resource = { id: `${provider}-provider`, name: provider, type: "provider", provider: provider.toUpperCase() };
  return { id: resource.id, name: provider, provider, resource, connection, connections: connection ? [connection] : [], status: appStatus(connection), capabilities: [], blockedTools: [] };
}

function render(app: App, client = createQueryClient()) {
  const admin = { busy: false, connectProvider: async () => undefined, disconnect: async () => true, mutate: async () => undefined } as unknown as AdminContextValue;
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <MemoryRouter><AdminContext.Provider value={admin}><AppPage app={app} /></AdminContext.Provider></MemoryRouter>
    </QueryClientProvider>
  );
}

test("GitHub start posts to the lowercase provider route and returns the authorization URL", async t => {
  const calls: Array<[string, string | undefined]> = [];
  t.mock.method(globalThis, "fetch", async (path: string, init?: RequestInit) => {
    calls.push([path, init?.method]);
    return new Response(JSON.stringify({ authorizationUrl: "https://github.com/apps/hallpass/installations/new" }));
  });
  assert.equal(providerKey(appFor("GitHub")), "github");
  assert.equal(await controlPlaneApi.startConnection(providerKey(appFor("GitHub"))), "https://github.com/apps/hallpass/installations/new");
  assert.deepEqual(calls, [["/api/connections/github/start", "POST"]]);
});

test("Slack start still uses the slack route", async t => {
  const calls: string[] = [];
  t.mock.method(globalThis, "fetch", async (path: string) => { calls.push(path); return new Response(JSON.stringify({ authorizationUrl: "https://slack.com/oauth" })); });
  await controlPlaneApi.startConnection(providerKey(appFor("Slack")));
  assert.deepEqual(calls, ["/api/connections/slack/start"]);
});

test("503 and 409 starts produce provider-specific errors and reject without a URL", async t => {
  for (const status of [503, 409]) {
    t.mock.method(globalThis, "fetch", async () => new Response(JSON.stringify({ error: "x" }), { status }));
    await assert.rejects(controlPlaneApi.startConnection("github"), error => error instanceof ApiStatusError && error.status === status);
    t.mock.restoreAll();
  }
  assert.match(connectionStartMessage("github", new ApiStatusError(503)), /GitHub is not configured on this server/);
  assert.match(connectionStartMessage("github", new ApiStatusError(409)), /GitHub is not provisioned/);
  assert.match(connectionStartMessage("slack", new ApiStatusError(503)), /Slack is not configured on this server/);
});

test("GitHub app page offers Connect with the GitHub setup guidance", () => {
  assert.deepEqual([...CONNECTABLE_PROVIDERS], ["Slack", "GitHub", "Linear", "Notion", "Google", "HubSpot"]);
  const html = render(appFor("GitHub"));
  assert.match(html, /Connect GitHub account/);
  assert.match(html, /HALLPASS_GITHUB_APP_ID/);
  assert.match(html, /github_app_private_key\.pem/);
  assert.match(html, /github_client_secret/);
  assert.match(html, /only owners can install apps/);
  assert.match(html, /Only select repositories/);
  assert.match(html, /second, narrower step/);
  assert.doesNotMatch(html, /HALLPASS_SLACK_CLIENT_ID/);
});

test("Slack app page keeps its Slack callout", () => {
  const html = render(appFor("Slack"));
  assert.match(html, /Connect Slack account/);
  assert.match(html, /HALLPASS_SLACK_CLIENT_ID/);
  assert.doesNotMatch(html, /HALLPASS_GITHUB_APP_ID/);
});

test("GitHub repositories are listed by full name with the numeric ID as secondary text", () => {
  const connection: Connection = { id: "conn-gh", resourceId: "GitHub-provider", provider: "GITHUB", status: "active", accountLabel: "acme", createdAt: "2026-09-29T12:00:00Z" };
  const client = createQueryClient();
  client.setQueryData(["connections", connection.id, "resources"], {
    resources: [{ id: "root", kind: "github.installation", externalId: "42", name: "acme", root: true }],
    available: [{ selectionKey: "github.repository|1001", kind: "github.repository", externalId: "1001", name: "acme/payments" }]
  });
  const html = render(appFor("GitHub", connection), client);
  assert.match(html, /acme\/payments/);
  assert.match(html, /github\.repository · 1001/);
  assert.match(html, /Save resource selection/);
});

test("Linear offers a connection flow without another provider's setup instructions", async t => {
  const html = render(appFor("Linear"));
  assert.match(html, /Connect Linear account/);
  assert.doesNotMatch(html, /HALLPASS_SLACK_CLIENT_ID|HALLPASS_GITHUB_APP_ID/);
  const calls: string[] = [];
  t.mock.method(globalThis, "fetch", async (path: string) => {
    calls.push(path);
    return new Response(JSON.stringify({ authorizationUrl: "https://example.com/authorize" }));
  });
  await controlPlaneApi.startConnection(providerKey(appFor("Linear")));
  assert.deepEqual(calls, ["/api/connections/linear/start"]);
});

test("Notion offers a connection flow without another provider's setup instructions", async t => {
  const html = render(appFor("Notion"));
  assert.match(html, /Connect Notion account/);
  assert.doesNotMatch(html, /HALLPASS_SLACK_CLIENT_ID|HALLPASS_GITHUB_APP_ID/);
  const calls: string[] = [];
  t.mock.method(globalThis, "fetch", async (path: string) => {
    calls.push(path);
    return new Response(JSON.stringify({ authorizationUrl: "https://example.com/authorize" }));
  });
  await controlPlaneApi.startConnection(providerKey(appFor("Notion")));
  assert.deepEqual(calls, ["/api/connections/notion/start"]);
});

test("HubSpot offers a connection flow with its own setup guidance and no other provider's", async t => {
  const html = render(appFor("HubSpot"));
  assert.match(html, /Connect HubSpot account/);
  assert.match(html, /HALLPASS_HUBSPOT_CLIENT_ID/);
  assert.match(html, /hubspot_client_secret/);
  assert.doesNotMatch(html, /HALLPASS_SLACK_CLIENT_ID|HALLPASS_GITHUB_APP_ID|HALLPASS_GOOGLE_DRIVE_CLIENT_ID/);
  const calls: string[] = [];
  t.mock.method(globalThis, "fetch", async (path: string) => {
    calls.push(path);
    return new Response(JSON.stringify({ authorizationUrl: "https://app.hubspot.com/oauth/authorize" }));
  });
  await controlPlaneApi.startConnection(providerKey(appFor("HubSpot")));
  assert.deepEqual(calls, ["/api/connections/hubspot/start"]);
});
