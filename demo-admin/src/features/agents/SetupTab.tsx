import { ReactNode, useEffect, useState } from "react";
import { Link } from "react-router";
import { CircleCheck, CircleDashed, LoaderCircle } from "lucide-react";
import type { Agent } from "../../api/client";
import { useBridgeDownloads, useExecutionWatch } from "../../api/queries";
import { useAdmin } from "../../app/AdminContext";
import { agentPath } from "../../app/routes";
import { activeGrants } from "../../lib/agents";
import { currentCredential } from "../../lib/access";
import { credentialStatus } from "../../lib/labels";
import { Button } from "../../ui/Button";
import { Card } from "../../ui/Card";
import { Field } from "../../ui/Field";
import { CLIENTS, ClientKey, acceptedEndpoint, clientFor, downloadsBase, installerCommand, loadManualPaths, manualClientConfig, saveManualPaths, serverNameFor } from "./clients";
import { Command } from "./Command";
import { ConnectCommands, ServerNameNote } from "./ConnectCommands";

type StepState = "done" | "todo" | "waiting" | "error";

function Step({ state, title, children }: { state: StepState; title: string; children?: ReactNode }) {
  const Icon = state === "done" ? CircleCheck : state === "waiting" ? LoaderCircle : CircleDashed;
  return (
    <li className={`setup-step setup-step-${state}`}>
      <Icon aria-hidden className="setup-step-icon" />
      <div className="setup-step-body">
        <strong>{title}<span className="visually-hidden"> ({state === "done" ? "done" : state === "waiting" ? "waiting" : state === "error" ? "unavailable" : "to do"})</span></strong>
        {children}
      </div>
    </li>
  );
}

function ManualSetup({ client, agentApiUrl, serverName }: { client: ClientKey; agentApiUrl: string; serverName: string }) {
  const [paths, setPaths] = useState(loadManualPaths);
  useEffect(() => saveManualPaths(paths), [paths]);
  const config = manualClientConfig(client, paths.checkoutPath, paths.credentialPath, agentApiUrl, serverName);
  const target = clientFor(client);
  return (
    <div className="disclosure-body">
      <p className="muted">For a source checkout without the packaged installer. Build the bridge once with <code>sbt -batch bridge/stageRuntimeClasspath</code>, save the key in a file only you can read (mode <code>0600</code>), then add this entry to {target.configPath ? <code>{target.configPath}</code> : "your client’s MCP configuration"}. It holds the file path and the agent API address, never the key.</p>
      <Field label="Checkout path"><input className="input input-mono" value={paths.checkoutPath} onChange={event => setPaths(current => ({ ...current, checkoutPath: event.target.value }))} placeholder="/home/you/dev/hallpass" spellCheck={false} /></Field>
      <Field label="Key file path"><input className="input input-mono" value={paths.credentialPath} onChange={event => setPaths(current => ({ ...current, credentialPath: event.target.value }))} placeholder="/home/you/.config/hallpass/credentials/agent" spellCheck={false} /></Field>
      <Command value={config} label="Client configuration" />
    </div>
  );
}

/** The single "Connect <client>" step. It renders commands only from validated URLs and never from a key. */
function ConnectStep({ agent, client, state, agentApiUrl }: { agent: Agent; client: Exclude<ClientKey, "other">; state: StepState; agentApiUrl: string }) {
  const { adminOrigin } = useAdmin();
  const downloads = useBridgeDownloads();
  const base = downloads.version ? downloadsBase(adminOrigin) : undefined;
  const title = clientFor(client).title;
  const serverName = serverNameFor(agent);
  const notice = <p className="muted">These commands contain this agent’s ID and the URLs, never its key. The connect step asks for the key: paste the one you just created (the prompt is hidden).</p>;

  if (downloads.pending) {
    return <Step state={state} title={`Connect ${title}`}><p className="muted" aria-live="polite">Checking whether this instance provides the bridge installer…</p></Step>;
  }

  if (base && downloads.version) {
    return (
      <Step state={state} title={`Connect ${title}`}>
        <p className="muted">Run this on the machine where {title} runs. It installs or upgrades the bridge (version <span className="mono">{downloads.version}</span>) from this instance, asks for the key, registers {title}, and checks the connection. Restart {title} afterwards.</p>
        <Command value={installerCommand(base, agent.id, client, agentApiUrl, serverName)} label="Install and connect command" />
        <ServerNameNote client={client} serverName={serverName} />
        {notice}
        <details className="disclosure">
          <summary>Already installed on this machine?</summary>
          <div className="disclosure-body">
            <ConnectCommands agentId={agent.id} client={client} agentApiUrl={agentApiUrl} serverName={serverName} />
          </div>
        </details>
      </Step>
    );
  }

  return (
    <Step state={state} title={`Connect ${title}`}>
      <p className="muted">This instance doesn’t provide the bridge installer. With the bridge already installed, run this on the machine where {title} runs. Restart {title} afterwards.</p>
      <ConnectCommands agentId={agent.id} client={client} agentApiUrl={agentApiUrl} serverName={serverName} />
      <ServerNameNote client={client} serverName={serverName} />
      {notice}
      <p className="muted">The local stack builds the bridge from a source checkout with <code>sbt bridge/stageRuntimeClasspath</code>. See <em>Set up manually</em> below to point a client at that build.</p>
    </Step>
  );
}

export function SetupTab({ agent }: { agent: Agent }) {
  const { data, clientOf, setClient, openKeyDialog, busy, agentApiUrl: reportedUrl } = useAdmin();
  const client = clientOf(agent);
  const key = currentCredential(data.credentialsByAgent[agent.id]);
  const keyStatus = credentialStatus(key);
  const grants = activeGrants(data.delegations, agent.id);
  const watch = useExecutionWatch(agent.id);
  const completed = watch.completed;
  // The server reports the address; the browser applies the same endpoint rule as the bridge before using it.
  const agentApiUrl = reportedUrl ? acceptedEndpoint(reportedUrl) : undefined;
  // A completed call proves the bridge was installed, connected, and registered.
  const connected: StepState = completed ? "done" : "todo";

  return (
    <div className="stack">
      <Card
        title="Connect a client"
        description="Run these on the machine where the client runs. The commands contain this agent’s ID and URLs, never its key."
        actions={
          <label className="inline-select">
            <span className="visually-hidden">Client</span>
            <select className="select" value={client} onChange={event => setClient(agent.id, event.target.value as ClientKey)}>
              {CLIENTS.map(item => <option key={item.key} value={item.key}>{item.title}</option>)}
            </select>
          </label>
        }
      >
        <div className="card-body">
          <ol className="setup-steps">
            <Step state={grants.length ? "done" : "todo"} title="Give it access">
              {grants.length
                ? <p className="muted">{grants.length} {grants.length === 1 ? "capability" : "capabilities"} granted.</p>
                : <p className="muted">Without access every call is denied. <Link className="btn-link" to={agentPath(agent.id, "access")}>Give access</Link></p>}
            </Step>
            <Step state={keyStatus.key === "active" ? "done" : "todo"} title="Create a key">
              {keyStatus.key === "active" && key
                ? <p className="muted">Active key <span className="mono">{key.prefix}</span>. Lost it? <Link className="btn-link" to={agentPath(agent.id, "key")}>Replace it</Link>, then connect again below.</p>
                : <div>
                    {keyStatus.key === "expired" && <p className="field-error" role="status">This key has expired. Replace it before connecting or making a call.</p>}
                    <Button variant="primary" onClick={() => openKeyDialog(agent)} disabled={busy}>{keyStatus.key === "expired" ? "Replace key" : "Create key"}</Button>
                  </div>}
            </Step>
            {!agentApiUrl ? (
              <Step state="error" title="Connect a client">
                <p className="field-error" role="alert">Hallpass didn’t report a usable agent API address, so setup commands can’t be shown. Reload the page; if this continues, check the server’s <code>HALLPASS_AGENT_PUBLIC_URL</code>.</p>
              </Step>
            ) : client === "other" ? (
              <Step state={connected} title="Configure your client">
                <p className="muted">The packaged installer supports Codex CLI, Claude Code, and Google Antigravity. For another stdio MCP client, add this entry to its MCP configuration.</p>
                <ManualSetup client={client} agentApiUrl={agentApiUrl} serverName={serverNameFor(agent)} />
              </Step>
            ) : (
              <ConnectStep agent={agent} client={client} state={connected} agentApiUrl={agentApiUrl} />
            )}
            <Step state={completed ? "done" : watch.error ? "error" : "waiting"} title="Make a first call">
              {completed
                ? <p className="muted">A completed call has been recorded for this agent. This confirms prior setup, even when it is outside the recent activity window.</p>
                : watch.error ? <div role="alert"><p className="field-error">Execution history is unavailable. Setup status could not be refreshed.</p><Button onClick={watch.retry}>Retry</Button></div>
                : <p className="muted" aria-live="polite">Waiting for a completed call from this agent. Ask the client to search Slack; this updates on its own.</p>}
            </Step>
          </ol>
        </div>
      </Card>
      {client !== "other" && agentApiUrl && (
        <details className="disclosure">
          <summary>Set up manually</summary>
          <ManualSetup client={client} agentApiUrl={agentApiUrl} serverName={serverNameFor(agent)} />
        </details>
      )}
    </div>
  );
}
