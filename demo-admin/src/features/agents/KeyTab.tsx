import { useState } from "react";
import { Agent, controlPlaneApi } from "../../api/client";
import { queryKeys } from "../../api/queries";
import { useAdmin } from "../../app/AdminContext";
import { currentCredential } from "../../lib/access";
import { formatDate } from "../../lib/format";
import { credentialStatus } from "../../lib/labels";
import { Button } from "../../ui/Button";
import { Card } from "../../ui/Card";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { EmptyState } from "../../ui/Feedback";
import { Pill } from "../../ui/Pill";

export function KeyTab({ agent }: { agent: Agent }) {
  const { data, busy, mutate, openKeyDialog } = useAdmin();
  const [revoking, setRevoking] = useState(false);
  const keys = data.credentialsByAgent[agent.id] ?? [];
  const current = currentCredential(keys);
  const previous = keys.filter(key => key !== current);
  const status = credentialStatus(current);

  async function revoke() {
    if (!current) return;
    await mutate(() => controlPlaneApi.revokeAgentCredential(agent.id, current.id), [queryKeys.agentCredentials(agent.id)], {
      success: "Key revoked. The agent can no longer sign in.",
      failure: "The key could not be revoked."
    });
    setRevoking(false);
  }

  return (
    <div className="stack">
      <Card
        title="Agent key"
        description="The local bridge signs in as this agent with this key. It is shown once when created and never stored in readable form."
        actions={current ? <>
          <Button onClick={() => openKeyDialog(agent)} disabled={busy}>Replace key</Button>
          <Button variant="danger" onClick={() => setRevoking(true)} disabled={busy}>Revoke</Button>
        </> : undefined}
      >
        {current ? (
          <div className="card-body">
            <dl className="kv">
              <div><dt>Status</dt><dd><Pill tone={status.tone}>{status.label}</Pill></dd></div>
              <div><dt>Prefix</dt><dd className="mono">{current.prefix}</dd></div>
              <div><dt>Created</dt><dd>{formatDate(current.createdAt)}</dd></div>
              <div><dt>Expires</dt><dd>{current.expiresAt ? formatDate(current.expiresAt) : "Never"}</dd></div>
              <div><dt>Last used</dt><dd>{current.lastUsedAt ? formatDate(current.lastUsedAt) : "Not yet"}</dd></div>
            </dl>
          </div>
        ) : (
          <EmptyState title="No key" action={<Button variant="primary" onClick={() => openKeyDialog(agent)} disabled={busy}>Create key</Button>}>
            Create a key so a local client can sign in as {agent.name}.
          </EmptyState>
        )}
      </Card>
      {previous.length > 0 && (
        <details className="disclosure">
          <summary>Previous keys ({previous.length})</summary>
          <div className="table-wrap">
            <table className="table">
              <caption className="visually-hidden">Previous keys</caption>
              <thead><tr><th>Prefix</th><th>Status</th><th>Created</th><th>Last used</th></tr></thead>
              <tbody>
                {previous.map(key => (
                  <tr key={key.id}>
                    <td className="mono">{key.prefix}</td>
                    <td><Pill tone={credentialStatus(key).tone}>{credentialStatus(key).label}</Pill></td>
                    <td className="cell-muted cell-nowrap">{formatDate(key.createdAt)}</td>
                    <td className="cell-muted cell-nowrap">{key.lastUsedAt ? formatDate(key.lastUsedAt) : "Never"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
      {revoking && (
        <ConfirmDialog title={`Revoke ${agent.name}’s key?`} confirmLabel="Revoke key" busy={busy} onCancel={() => setRevoking(false)} onConfirm={() => void revoke()}>
          Clients using it can no longer sign in as this agent. Its access settings are kept, and you can create a new key afterwards.
        </ConfirmDialog>
      )}
    </div>
  );
}
