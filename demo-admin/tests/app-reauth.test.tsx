import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { QueryClientProvider } from "@tanstack/react-query";
import type { Connection, Resource } from "../src/api/client.ts";
import { createQueryClient } from "../src/api/queries.ts";
import { AdminContext, type AdminContextValue } from "../src/app/AdminContext.tsx";
import { AppPage } from "../src/features/apps/AppPage.tsx";
import { appStatus, type App } from "../src/lib/apps.ts";

test("a needs-reauth app offers reconnect and disconnect without showing cached resource choices", () => {
  const connection: Connection = {
    id: "connection-reauth",
    resourceId: "slack-provider",
    provider: "SLACK",
    status: "needs_reauth",
    accountLabel: "Research workspace",
    createdAt: "2026-09-29T12:00:00Z"
  };
  const resource: Resource = {
    id: "slack-provider",
    name: "Slack",
    type: "provider",
    provider: "SLACK"
  };
  const app: App = {
    id: resource.id,
    name: resource.name,
    provider: "Slack",
    resource,
    connection,
    connections: [connection],
    status: appStatus(connection),
    capabilities: [],
    blockedTools: []
  };
  const admin = {
    busy: false,
    connectProvider: () => undefined,
    reconnect: () => undefined,
    disconnect: async () => true,
    mutate: async () => undefined
  } as unknown as AdminContextValue;
  const client = createQueryClient();
  client.setQueryData(["connections", connection.id, "resources"], {
    resources: [{ id: "old-root", kind: "slack.workspace", externalId: "T1", name: "Old workspace", root: true }],
    available: [{ selectionKey: "slack.channel|C1", kind: "slack.channel", externalId: "C1", name: "Private channel from stale cache" }]
  });

  const html = renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/admin/apps/slack-provider"]}>
        <AdminContext.Provider value={admin}>
          <AppPage app={app} />
        </AdminContext.Provider>
      </MemoryRouter>
    </QueryClientProvider>
  );

  assert.match(html, /Reconnect required/);
  assert.match(html, /Provider access must be reconnected/);
  assert.match(html, /Calls through this connection are blocked/);
  assert.match(html, /agent access and selected resources are kept/);
  assert.doesNotMatch(html, /Connect another Slack account/);
  assert.match(html, />Reconnect Slack<\/button>/);
  assert.match(html, />Disconnect<\/button>/);
  assert.doesNotMatch(html, /Resources available to agents|Save resource selection|Private channel from stale cache/);
  assert.doesNotMatch(html, /Resource details are temporarily unavailable/);
});
