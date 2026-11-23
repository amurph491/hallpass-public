import { FormEvent, useRef, useState } from "react";
import { Link } from "react-router";
import { Plus } from "lucide-react";
import { Agent, Delegation, controlPlaneApi } from "../../api/client";
import { queryKeys } from "../../api/queries";
import { useAdmin } from "../../app/AdminContext";
import { sectionPath } from "../../app/routes";
import { activeGrants, pastGrants } from "../../lib/agents";
import { capabilityLabel } from "../../lib/capabilities";
import { formatDate } from "../../lib/format";
import { Button } from "../../ui/Button";
import { Card } from "../../ui/Card";
import { ConfirmDialog } from "../../ui/ConfirmDialog";
import { Dialog } from "../../ui/Dialog";
import { EmptyState } from "../../ui/Feedback";
import { Pill } from "../../ui/Pill";
import { AccessPicker } from "./AccessPicker";
import { ConstraintSummary, LimitValues } from "./LimitValues";
import { ConstraintDraftRow, buildConstraints, delegationPayload, factsFor } from "../../lib/constraints";
import { useGrantResources } from "./useGrantResources";

function GiveAccessDialog({ agent, held, onClose }: { agent: Agent; held: string[]; onClose: () => void }) {
  const { data, busy, mutate } = useAdmin();
  const addressableResources = useGrantResources(data.connections, data.resources);
  const [selected, setSelected] = useState<string[]>([]);
  const [completed, setCompleted] = useState<string[]>([]);
  const [limits, setLimits] = useState<ConstraintDraftRow[]>([]);
  const limitResult = buildConstraints(limits);
  const capabilityNames = selected.map(item => data.capabilities.find(capability => capability.id === item.split("|")[0])?.name ?? "");
  const inFlight = useRef(false);
  const [error, setError] = useState<string>();
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (inFlight.current) return;
    inFlight.current = true;
    setError(undefined);
    const done = await mutate(
      async () => {
          for (const item of selected.filter(id => !held.includes(id) && !completed.includes(id))) {
            const [capabilityId, resourceId] = item.split("|");
            await controlPlaneApi.createDelegation(delegationPayload({ agentId: agent.id, capabilityId, resourceId }, limitResult.ok ? limitResult.constraints : undefined));
            setCompleted(current => [...current, item]);
            setSelected(current => current.filter(id => id !== item));
          }
        },
      [queryKeys.delegations],
      { success: `Access given to ${agent.name}`, failure: "Access could not be given.", onError: setError }
    );
    inFlight.current = false;
    if (done) onClose();
  }
  return (
    <Dialog
      className="dialog-wide"
      title={`Give ${agent.name} access`}
      description="Hallpass rejects any grant that exceeds your own authority."
      onClose={onClose}
      onSubmit={submit}
      dismissible={!busy}
      footer={<>
        <Button disabled={busy} onClick={onClose}>Cancel</Button>
        <Button type="submit" variant="primary" disabled={!selected.some(id => !held.includes(id) && !completed.includes(id)) || !limitResult.ok || busy}>{busy ? "Saving…" : "Give access"}</Button>
      </>}
    >
      {data.capabilities.length && addressableResources.length
        ? <AccessPicker capabilities={data.capabilities} resources={addressableResources} catalogResources={data.resources} selected={selected.filter(id => !held.includes(id) && !completed.includes(id))} onChange={setSelected} held={[...held, ...completed]} />
        : <p className="muted">No capabilities are available. <Link className="btn-link" to={sectionPath("apps")}>Connect Slack</Link> first.</p>}
      {data.capabilities.length > 0 && addressableResources.length > 0 && <LimitValues rows={limits} onChange={setLimits} facts={factsFor(capabilityNames)} />}
      {completed.length > 0 && <p role="status">{completed.length} access {completed.length === 1 ? "grant saved" : "grants saved"}. Only unfinished selections will be submitted.</p>}
      {error && <p className="field-error" role="alert">{error}</p>}
    </Dialog>
  );
}

export function AccessTab({ agent }: { agent: Agent }) {
  const { data, busy, mutate } = useAdmin();
  const [giving, setGiving] = useState(false);
  const [removing, setRemoving] = useState<Delegation>();
  const grants = activeGrants(data.delegations, agent.id);
  const past = pastGrants(data.delegations, agent.id);
  const resourceName = (grant: Delegation) => data.resources.find(resource => resource.id === grant.resourceId)?.name || grant.resource || "—";

  async function remove(grant: Delegation) {
    await mutate(() => controlPlaneApi.revokeDelegation(grant.id), [queryKeys.delegations], {
      success: `${capabilityLabel(grant.capability)} grant removed. Calls are checked against any remaining access.`,
      failure: "Access could not be removed."
    });
    setRemoving(undefined);
  }

  const giveButton = <Button variant="primary" icon={<Plus aria-hidden />} onClick={() => setGiving(true)}>Give access</Button>;

  return (
    <div className="stack">
      <Card className="table-card" title="Access" description="What this agent may do. Every call is checked against this list at the moment it is made." actions={grants.length ? giveButton : undefined}>
        {grants.length ? (
          <div className="table-wrap">
            <table className="table">
              <caption className="visually-hidden">Current access</caption>
              <thead><tr><th>Capability</th><th>Resource</th><th>Given</th><th>Expires</th><th><span className="visually-hidden">Actions</span></th></tr></thead>
              <tbody>
                {grants.map(grant => (
                  <tr key={grant.id}>
                    <td><span className="cell-primary"><strong>{capabilityLabel(grant.capability)}</strong><small className="mono">{grant.capability}</small><ConstraintSummary constraints={grant.constraints} /></span></td>
                    <td className="cell-muted">{resourceName(grant)}</td>
                    <td className="cell-muted cell-nowrap">{formatDate(grant.createdAt)}</td>
                    <td className="cell-muted cell-nowrap">{grant.expiresAt ? formatDate(grant.expiresAt) : "Never"}</td>
                    <td className="cell-actions"><Button variant="danger" size="sm" disabled={busy} onClick={() => setRemoving(grant)}>Remove</Button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState title="No access yet" action={giveButton}>Until you give it access, every call this agent makes is denied.</EmptyState>
        )}
      </Card>
      {past.length > 0 && (
        <details className="disclosure">
          <summary>Removed or expired ({past.length})</summary>
          <div className="table-wrap">
            <table className="table">
              <caption className="visually-hidden">Removed or expired access</caption>
              <thead><tr><th>Capability</th><th>Status</th><th>Given</th><th>Ended</th></tr></thead>
              <tbody>
                {past.map(grant => (
                  <tr key={grant.id}>
                    <td><span className="cell-primary">{capabilityLabel(grant.capability)}<small className="mono">{grant.capability}</small></span></td>
                    <td><Pill tone="muted">{grant.revokedAt || grant.status === "revoked" ? "Removed" : grant.status === "active" ? "Expired" : grant.status}</Pill></td>
                    <td className="cell-muted cell-nowrap">{formatDate(grant.createdAt)}</td>
                    <td className="cell-muted cell-nowrap">{formatDate(grant.revokedAt || grant.expiresAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
      {giving && <GiveAccessDialog agent={agent} held={grants.map(grant => `${grant.capabilityId || ""}|${grant.resourceId || ""}`).filter(Boolean)} onClose={() => setGiving(false)} />}
      {removing && (
        <ConfirmDialog
          title={`Remove ${capabilityLabel(removing.capability)} from ${agent.name}?`}
          confirmLabel="Remove access"
          busy={busy}
          onCancel={() => setRemoving(undefined)}
          onConfirm={() => void remove(removing)}
        >
          This removes one grant. Another active grant may still authorize the same capability. Future calls are checked against the remaining access.
        </ConfirmDialog>
      )}
    </div>
  );
}
