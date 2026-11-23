import { useEffect, useRef, useState } from "react";
import { Link } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, Plus, ShieldCheck } from "lucide-react";
import { useAdmin } from "../../app/AdminContext";
import { agentPath, sectionPath } from "../../app/routes";
import { controlPlaneApi, type Connection } from "../../api/client";
import { queryKeys } from "../../api/queries";
import type { App } from "../../lib/apps";
import { pickDriveFiles, pickerErrorMessage } from "./googlePicker";
import { formatDate } from "../../lib/format";
import { Button } from "../../ui/Button";
import { Card } from "../../ui/Card";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState } from "../../ui/Feedback";
import { Pill } from "../../ui/Pill";
import { AppMark, GitHubSetupCallout, GoogleSetupCallout, HubSpotSetupCallout, SlackSetupCallout } from "./AppsPage";

/** Providers whose connect flow the server implements. Display only: the server decides what is provisioned. */
export const CONNECTABLE_PROVIDERS: readonly string[] = ["Slack", "GitHub", "Linear", "Notion", "Google", "HubSpot"];

/** The lowercase catalog provider key used in `/api/connections/{provider}/start`. */
export const providerKey = (app: App): string => app.provider.toLowerCase();

function ProviderConnection({ app, connection }: { app: App; connection: Connection }) {
  const { busy, mutate, disconnect, reconnect } = useAdmin();
  const queryClient = useQueryClient();
  const key = ["connections", connection.id, "resources"] as const;
  const needsReauth = connection.status === "needs_reauth";
  const active = connection.status === "active";
  const listing = useQuery({ queryKey: key, queryFn: () => controlPlaneApi.connectionResources(connection.id), enabled: active });
  const [selected, setSelected] = useState<string[]>([]);
  const [confirming, setConfirming] = useState(false);

  const isGoogle = connection.provider.toLowerCase() === "google";
  const pickerConfig = useQuery({ queryKey: ["connections", "google", "picker-config"], queryFn: controlPlaneApi.googlePickerConfig, enabled: isGoogle && active, retry: false });
  const [pickerError, setPickerError] = useState<string>();
  const [picking, setPicking] = useState(false);
  /** Picked file IDs (not tokens) waiting for the refreshed listing, so they can be pre-checked. */
  const pickedIds = useRef<string[]>([]);

  useEffect(() => {
    const keys = (listing.data?.resources ?? []).filter(resource => !resource.root).map(resource => `${resource.kind}|${resource.externalId}`);
    const picked = pickedIds.current;
    pickedIds.current = [];
    const pickedKeys = (listing.data?.available ?? []).filter(resource => picked.includes(resource.externalId)).map(resource => resource.selectionKey);
    setSelected([...new Set([...keys, ...pickedKeys])]);
  }, [listing.data]);

  async function addFromDrive() {
    const config = pickerConfig.data;
    if (!config) return;
    setPickerError(undefined);
    setPicking(true);
    try {
      const result = await pickDriveFiles(config);
      if (result.status === "cancelled") { setPickerError("No files were picked."); return; }
      pickedIds.current = result.ids;
      const refreshed = await listing.refetch();
      if (pickedIds.current.length) { // data unchanged, so the effect did not run: apply the picks directly
        const picked = pickedIds.current;
        pickedIds.current = [];
        const keys = (refreshed.data?.available ?? []).filter(resource => picked.includes(resource.externalId)).map(resource => resource.selectionKey);
        setSelected(current => [...new Set([...current, ...keys])]);
      }
    } catch (error) {
      setPickerError(pickerErrorMessage(error));
    } finally {
      setPicking(false);
    }
  }

  async function saveSelection() {
    await mutate(
      () => controlPlaneApi.selectConnectionResources(connection.id, selected),
      [queryKeys.connections, key],
      { success: "Resource selection updated. Calls use the new scope immediately.", failure: "Resource selection could not be updated." }
    );
  }

  async function confirmDisconnect() {
    if (await disconnect(connection)) setConfirming(false);
  }

  const root = listing.data?.resources.find(resource => resource.root);
  const hasPicker = (listing.data?.available.length ?? 0) > 0;

  return (
    <Card title={connection.workspaceLabel || connection.accountLabel || app.provider} description={`Connection health · ${connection.status}`}>
      <div className="card-body">
        <dl className="kv">
          {connection.workspaceLabel && <div><dt>Workspace</dt><dd>{connection.workspaceLabel}</dd></div>}
          {connection.accountLabel && <div><dt>Account</dt><dd className="mono">{connection.accountLabel}</dd></div>}
          {connection.externalAccountId && <div><dt>Provider account ID</dt><dd className="mono">{connection.externalAccountId}</dd></div>}
          {root && <div><dt>Authority root</dt><dd>{root.name} <span className="faint mono">{root.kind}</span></dd></div>}
          <div><dt>Connected</dt><dd>{formatDate(connection.createdAt)}</dd></div>
          <div><dt>Credential expiry</dt><dd>{connection.expiresAt ? formatDate(connection.expiresAt) : "Provider managed"}</dd></div>
        </dl>
        {listing.isError && active && <p className="muted">Resource details are temporarily unavailable.</p>}
        {needsReauth && <div className="callout" role="status">
          <p>Provider access must be reconnected. Calls through this connection are blocked until then. Reconnect with the same {app.provider} account; agent access and selected resources are kept.</p>
          <Button variant="primary" disabled={busy} onClick={() => void reconnect(connection)}>Reconnect {app.provider}</Button>
        </div>}
        {active && isGoogle && pickerConfig.data && <div>
          <Button disabled={busy || picking} onClick={() => void addFromDrive()}>Add files from Google Drive</Button>
          {pickerError && <p className="muted" role="alert">{pickerError}</p>}
        </div>}
        {active && hasPicker ? (
          <fieldset className="plain-list" disabled={listing.isPending || busy}>
            <legend>Resources available to agents</legend>
            {listing.data?.available.map(resource => (
              <label key={resource.selectionKey} className="checkbox-row">
                <input type="checkbox" checked={selected.includes(resource.selectionKey)} onChange={event => setSelected(current => event.target.checked ? [...current, resource.selectionKey] : current.filter(key => key !== resource.selectionKey))} />
                <span>{resource.name}<small className="mono">{resource.kind} · {resource.externalId}</small></span>
              </label>
            ))}
            <Button disabled={busy || listing.isPending} onClick={() => void saveSelection()}>Save resource selection</Button>
          </fieldset>
        ) : active ? <p className="muted">This connector currently authorizes operations at its account root.</p> : null}
        <div className="callout">
          <ShieldCheck aria-hidden />
          <p>The {app.provider} credential stays on the Hallpass server. Agents never receive it, and every call is checked against current access.</p>
        </div>
        <Button variant="danger" disabled={busy} onClick={() => setConfirming(true)}>Disconnect</Button>
      </div>
      {confirming && <ConfirmDialog title={`Disconnect ${app.provider}?`} confirmLabel="Disconnect" busy={busy} onConfirm={() => void confirmDisconnect()} onCancel={() => setConfirming(false)}>
        Calls through this connection stop immediately. Agent grants remain visible and can be revoked separately.
      </ConfirmDialog>}
    </Card>
  );
}

export function AppPage({ app }: { app: App | undefined }) {
  const { busy, connectProvider } = useAdmin();
  const [connectError, setConnectError] = useState<string>();

  async function connect(target: App) {
    setConnectError(undefined);
    setConnectError(await connectProvider(providerKey(target)));
  }

  if (!app) return (
    <div className="card">
      <EmptyState title="App not found" action={<Link className="btn btn-secondary" to={sectionPath("apps")}>Back to apps</Link>}>
        It may have been removed, or the link is wrong.
      </EmptyState>
    </div>
  );

  const canConnect = CONNECTABLE_PROVIDERS.includes(app.provider);
  return (
    <>
      <Link className="back-link" to={sectionPath("apps")}><ChevronLeft aria-hidden />Apps</Link>
      <div className="page-header">
        <div className="app-header">
          <AppMark app={app} />
          <div>
            <h1>{app.name}</h1>
            <div className="meta-row"><span>{app.provider}</span><Pill tone={app.status.tone}>{app.status.label}</Pill></div>
          </div>
        </div>
        {canConnect && (app.provider !== "Slack" || !app.connections.some(connection => connection.status === "active" || connection.status === "needs_reauth")) && <Button variant="primary" icon={<Plus aria-hidden />} disabled={busy} onClick={() => void connect(app)}>Connect {app.connections.length ? "another " : ""}{app.provider} account</Button>}
      </div>

      <div className="stack">
        {connectError && <div className="callout callout-warning" role="alert"><p>{connectError}</p></div>}
        {canConnect && !app.connections.length && (app.provider === "GitHub" ? <GitHubSetupCallout /> : app.provider === "Google" ? <GoogleSetupCallout /> : app.provider === "HubSpot" ? <HubSpotSetupCallout /> : app.provider === "Slack" ? <SlackSetupCallout /> : null)}
        <Card title="Connection" description="Provider login and agent authority are separate steps.">
          <div className="card-body">
            {app.connections.length ? app.connections.map(connection => <ProviderConnection key={connection.id} app={app} connection={connection} />) : <p className="muted">No provider account is connected yet. Agents cannot use this app until a person connects an account and separately grants access.</p>}
          </div>
        </Card>

        <Card className="table-card" title="What agents can do here" description="Capabilities and agent grants on this provider catalog.">
          {app.capabilities.length ? <div className="table-wrap">
            <table className="table table-stack">
              <caption className="visually-hidden">Capabilities in {app.name}</caption>
              <thead><tr><th>Capability</th><th>Agents with access</th><th>Tools</th></tr></thead>
              <tbody>{app.capabilities.map(item => <tr key={item.capability.id}>
                <td data-label="Capability"><span className="cell-primary"><strong>{item.label}</strong><small className="mono">{item.capability.name}</small></span></td>
                <td data-label="Agents with access">{item.agents.length ? <span className="link-list">{item.agents.map(agent => <Link key={agent.id} to={agentPath(agent.id)}>{agent.name}</Link>)}</span> : <span className="faint">None</span>}</td>
                <td data-label="Tools">{item.tools.length ? <span className="cell-primary">{item.tools.map(tool => <span key={tool.name}>{tool.label}<small className="mono"> {tool.name}</small></span>)}</span> : <span className="faint">None</span>}</td>
              </tr>)}</tbody>
            </table>
          </div> : <EmptyState title="No capabilities">This app has nothing agents can be given access to yet.</EmptyState>}
          <div className="card-body card-foot"><p className="faint">Give or remove access from each agent’s page. Changes apply on the agent’s next call.</p></div>
        </Card>
        {app.blockedTools.length > 0 && <Card className="table-card" title="Always blocked" description="These tools have no trusted capability mapping.">
          <ul className="plain-list">{app.blockedTools.map(tool => <li key={tool.name}><span>{tool.label}</span><span className="mono faint">{tool.name}</span></li>)}</ul>
        </Card>}
      </div>
    </>
  );
}
