import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AccessPicker } from "../src/features/agents/AccessPicker.tsx";
import { useGrantResources } from "../src/features/agents/useGrantResources.ts";
import type { Capability, Resource } from "../src/api/client.ts";

const catalog: Resource[] = [
  { id: "slack-catalog", name: "Slack", type: "provider", provider: "slack" },
  { id: "github-catalog", name: "GitHub", type: "provider", provider: "github" }
];
const capability: Capability = { id: "read", name: "Slack.Message.Read", action: "read", resourceId: "slack-catalog" };

test("grants match the provider catalog to account roots without offering another provider's resources", () => {
  const resources: Resource[] = [
    { id: "workspace", name: "Research workspace", type: "account", provider: "SLACK" },
    { id: "channel", name: "Selected channel", type: "channel", provider: "slack" },
    { id: "organization", name: "Other organization", type: "account", provider: "github" }
  ];
  const html = renderToStaticMarkup(<AccessPicker capabilities={[capability]} resources={resources}
    catalogResources={catalog} selected={[]} held={["read|workspace"]} onChange={() => undefined} />);
  assert.match(html, /Research workspace/);
  assert.match(html, /Selected channel/);
  assert.match(html, /disabled="".*checked=""/);
  assert.doesNotMatch(html, /Other organization/);
});

test("an active connection's grant choices use current selections and exclude stale catalog children", () => {
  const client = new QueryClient();
  client.setQueryData(["connections", "connection", "resources"], { resources: [
    { id: "workspace", name: "Current workspace", kind: "slack.workspace", externalId: "T1", root: true },
    { id: "channel", name: "Current channel", kind: "slack.channel", externalId: "C1", root: false }
  ], available: [] });
  function Choices() {
    const resources = useGrantResources([{ id: "connection", resourceId: "workspace", provider: "SLACK", status: "active" }],
      [...catalog, { id: "old", name: "Deselected channel", type: "channel", provider: "slack" }]);
    return <ul>{resources.map(resource => <li key={resource.id}>{resource.name}</li>)}</ul>;
  }
  const html = renderToStaticMarkup(<QueryClientProvider client={client}><Choices /></QueryClientProvider>);
  assert.match(html, /Current workspace/);
  assert.match(html, /Current channel/);
  assert.doesNotMatch(html, /Deselected channel|<li>Slack<\/li>/);
  client.clear();
});
