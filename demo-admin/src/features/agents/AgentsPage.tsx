import type { ReactNode } from "react";
import { Link } from "react-router";
import type { Agent } from "../../api/client";
import { useAdmin } from "../../app/AdminContext";
import { agentPath } from "../../app/routes";
import { activeGrants, lastUsed } from "../../lib/agents";
import { currentCredential } from "../../lib/access";
import { capabilityLabel } from "../../lib/capabilities";
import { formatDate } from "../../lib/format";
import { credentialStatus } from "../../lib/labels";
import { Card } from "../../ui/Card";
import { EmptyState } from "../../ui/Feedback";
import { Pill } from "../../ui/Pill";
import { clientFor } from "./clients";

export function AgentsPage({ query, addButton }: { query: string; addButton: ReactNode }) {
  const { data, clientOf } = useAdmin();
  const { agents, delegations, credentialsByAgent } = data;
  const term = query.trim().toLowerCase();
  const matches = (agent: Agent) => !term || `${agent.name} ${agent.description ?? ""} ${clientFor(clientOf(agent)).title}`.toLowerCase().includes(term);
  const rows = agents.filter(matches);

  if (!agents.length) return (
    <Card>
      <EmptyState title="No agents yet" action={addButton}>Add an agent for each client that should use your connected apps.</EmptyState>
    </Card>
  );

  return (
    <Card className="table-card">
      {rows.length ? (
        <div className="table-wrap">
          <table className="table table-interactive">
            <caption className="visually-hidden">Agents</caption>
            <thead>
              <tr><th>Agent</th><th>Client</th><th>Access</th><th>Key</th><th>Last active</th></tr>
            </thead>
            <tbody>
              {rows.map(agent => {
                const grants = activeGrants(delegations, agent.id);
                const key = credentialStatus(currentCredential(credentialsByAgent[agent.id]));
                const active = lastUsed(credentialsByAgent[agent.id]);
                return (
                  <tr key={agent.id}>
                    <td>
                      <span className="cell-primary">
                        <Link className="row-link" to={agentPath(agent.id)}>{agent.name}</Link>
                        {agent.description && <small>{agent.description}</small>}
                      </span>
                    </td>
                    <td className="cell-muted cell-nowrap">{clientFor(clientOf(agent)).title}</td>
                    <td>{grants.length ? grants.map(grant => capabilityLabel(grant.capability)).join(", ") : <span className="faint">No access</span>}</td>
                    <td><Pill tone={key.tone}>{key.label}</Pill></td>
                    <td className="cell-muted cell-nowrap">{active ? formatDate(active) : "Never"}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : <EmptyState title="No matches">No agent matches “{query}”.</EmptyState>}
    </Card>
  );
}
