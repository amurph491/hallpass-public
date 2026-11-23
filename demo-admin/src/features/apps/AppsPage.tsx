import { Link } from "react-router";
import { ChevronRight, TriangleAlert } from "lucide-react";
import { useAdmin } from "../../app/AdminContext";
import { appPath } from "../../app/routes";
import type { App } from "../../lib/apps";
import { formatDate } from "../../lib/format";
import { Card } from "../../ui/Card";
import { EmptyState } from "../../ui/Feedback";
import { Pill } from "../../ui/Pill";

export function AppMark({ app }: { app: App }) {
  return <span className="app-mark" aria-hidden>{app.provider[0]}</span>;
}

/** Shown until Slack is connected, because a failed OAuth start is a server configuration problem. */
export function SlackSetupCallout() {
  return (
    <div className="callout callout-warning">
      <TriangleAlert aria-hidden />
      <p><strong>Slack OAuth must be configured on the server first.</strong> Set <code>HALLPASS_SLACK_CLIENT_ID</code> and put the client secret in <code>.secrets/slack_client_secret</code>, then refresh. A failed start shows an error; it never marks Slack connected.</p>
    </div>
  );
}

/** Shown until GitHub is connected. Install rules on the GitHub side are outside Hallpass's control. */
export function GitHubSetupCallout() {
  return (
    <div className="callout callout-warning">
      <TriangleAlert aria-hidden />
      <div>
        <p><strong>The GitHub App must be configured on the server first.</strong> Set <code>HALLPASS_GITHUB_APP_ID</code> and the related GitHub App settings, and provide <code>.secrets/github_app_private_key.pem</code> and <code>.secrets/github_client_secret</code>, then refresh. A failed start shows an error; it never marks GitHub connected.</p>
        <p>In a GitHub organization only owners can install apps; members can only request an install. When installing, choose <strong>Only select repositories</strong>. Selecting repositories in Hallpass afterwards is a second, narrower step that limits what agents can reach.</p>
      </div>
    </div>
  );
}

/** Shown until Google is connected. Only files picked in Hallpass's Picker become available. */
export function GoogleSetupCallout() {
  return (
    <div className="callout callout-warning">
      <TriangleAlert aria-hidden />
      <div>
        <p><strong>Google Drive must be configured on the server first.</strong> Set <code>HALLPASS_GOOGLE_DRIVE_CLIENT_ID</code> and provide <code>.secrets/google_drive_client_secret</code>, then refresh. A failed start shows an error; it never marks Google connected.</p>
        <p>Only the files you pick become available to agents; Hallpass does not see the rest of your Drive. This is your personal Drive: only you can grant agents access to your files.</p>
      </div>
    </div>
  );
}

/** Shown until HubSpot is connected. One portal; the administrator picks the CRM object types agents may reach. */
export function HubSpotSetupCallout() {
  return (
    <div className="callout callout-warning">
      <TriangleAlert aria-hidden />
      <div>
        <p><strong>HubSpot must be configured on the server first.</strong> Set <code>HALLPASS_HUBSPOT_CLIENT_ID</code> and provide <code>.secrets/hubspot_client_secret</code>, then refresh. A failed start shows an error; it never marks HubSpot connected.</p>
        <p>You connect one HubSpot portal and choose which CRM object types (contacts, deals) agents may reach. Updating deal properties requires approval.</p>
      </div>
    </div>
  );
}

function summary(app: App): string {
  const agents = new Set(app.capabilities.flatMap(item => item.agents.map(agent => agent.id))).size;
  const parts = [
    app.connections.length > 1 ? `${app.connections.length} connected accounts` : app.connection?.workspaceLabel ? `Workspace ${app.connection.workspaceLabel}` : app.provider,
    `${app.capabilities.length} ${app.capabilities.length === 1 ? "capability" : "capabilities"}`,
    agents ? `${agents} ${agents === 1 ? "agent has" : "agents have"} access` : "No agents have access"
  ];
  return parts.join(" · ");
}

export function AppsPage({ apps }: { apps: App[] }) {
  const { data } = useAdmin();
  const slackConnected = apps.some(app => app.provider === "Slack" && app.status.key === "connected");
  if (!apps.length) return <Card><EmptyState title="No apps yet">Apps appear here once they’re in this workspace’s catalog.</EmptyState></Card>;
  return (
    <div className="stack">
      {!slackConnected && !data.connections.length && <SlackSetupCallout />}
      <div className="app-list">
        {apps.map(app => (
          <Link key={app.id} to={appPath(app.id)} className="card app-card">
            <AppMark app={app} />
            <span className="app-card-body">
              <strong>{app.name}</strong>
              <small>{summary(app)}</small>
              {app.connection?.createdAt && app.status.key === "connected" && <small>Connected {formatDate(app.connection.createdAt)}</small>}
            </span>
            <Pill tone={app.status.tone}>{app.status.label}</Pill>
            <ChevronRight aria-hidden className="app-card-chevron" />
          </Link>
        ))}
      </div>
    </div>
  );
}
