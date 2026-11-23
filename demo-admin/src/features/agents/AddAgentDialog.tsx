import { FormEvent, useRef, useState } from "react";
import { Link } from "react-router";
import type { Agent } from "../../api/client";
import { controlPlaneApi } from "../../api/client";
import { activeGrants } from "../../lib/agents";
import { queryKeys } from "../../api/queries";
import { useAdmin } from "../../app/AdminContext";
import { sectionPath } from "../../app/routes";
import { Button } from "../../ui/Button";
import { Dialog } from "../../ui/Dialog";
import { Field } from "../../ui/Field";
import { AccessPicker } from "./AccessPicker";
import { ConstraintSummary, LimitValues } from "./LimitValues";
import { ConstraintDraftRow, buildConstraints, delegationPayload, factsFor } from "../../lib/constraints";
import { useGrantResources } from "./useGrantResources";
import { CLIENTS, ClientKey } from "./clients";

type Props = { onClose: () => void; onDone: (agent: Agent) => void };

/**
 * Two steps: create the agent, then choose its access. Client connection
 * happens on the agent's Client setup tab, where the key is issued.
 */
export function AddAgentDialog({ onClose, onDone }: Props) {
  const { data, busy, mutate, setClient } = useAdmin();
  const addressableResources = useGrantResources(data.connections, data.resources);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [client, setClientChoice] = useState<ClientKey>("codex");
  const [agent, setAgent] = useState<Agent>();
  const [selected, setSelected] = useState<string[]>([]);
  const [completed, setCompleted] = useState<string[]>([]);
  const [limits, setLimits] = useState<ConstraintDraftRow[]>([]);
  const limitResult = buildConstraints(limits);
  const capabilityNames = selected.map(item => data.capabilities.find(capability => capability.id === item.split("|")[0])?.name ?? "");
  const inFlight = useRef(false);
  const [error, setError] = useState<string>();

  const held = agent ? activeGrants(data.delegations, agent.id).map(grant => `${grant.capabilityId || ""}|${grant.resourceId || ""}`) : [];

  async function create(event: FormEvent) {
    event.preventDefault();
    if (!name.trim()) return;
    setError(undefined);
    const created = await mutate(
      () => controlPlaneApi.createAgent({ name: name.trim(), ...(description.trim() ? { description: description.trim() } : {}) }),
      [queryKeys.agents],
      { success: `${name.trim()} created`, failure: "The agent could not be created.", onError: setError }
    );
    if (created) {
      setClient(created.value.id, client);
      setAgent(created.value);
    }
  }

  async function grant(event: FormEvent) {
    event.preventDefault();
    if (!agent || inFlight.current) return;
    inFlight.current = true;
    setError(undefined);
    if (selected.length) {
      const granted = await mutate(
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
      if (!granted) { inFlight.current = false; return; }
    }
    inFlight.current = false;
    onDone(agent);
  }

  if (!agent) return (
    <Dialog
      className="dialog-wide"
      title="Add agent"
      description="Step 1 of 2 · An agent is one identity, usually one client on one machine."
      onClose={onClose}
      onSubmit={create}
      footer={<>
        <Button onClick={onClose}>Cancel</Button>
        <Button type="submit" variant="primary" disabled={!name.trim() || busy}>{busy ? "Creating…" : "Continue"}</Button>
      </>}
    >
      <Field label="Name"><input className="input" autoFocus value={name} onChange={event => setName(event.target.value)} placeholder="Codex on my laptop" /></Field>
      <Field label="Description" hint="Optional."><input className="input" value={description} onChange={event => setDescription(event.target.value)} /></Field>
      <fieldset className="choice-group">
        <legend className="field-label">Client</legend>
        <div className="choice-grid">
          {CLIENTS.map(item => (
            <label key={item.key} className="choice">
              <input type="radio" name="client" value={item.key} checked={client === item.key} onChange={() => setClientChoice(item.key)} />
              <span>{item.title}</span>
            </label>
          ))}
        </div>
        <span className="field-hint">Used for setup instructions only. The agent’s key, not the client, identifies it.</span>
      </fieldset>
      {completed.length > 0 && <p role="status">{completed.length} access {completed.length === 1 ? "grant saved" : "grants saved"}. Only unfinished selections will be submitted.</p>}
      {error && <p className="field-error" role="alert">{error}</p>}
    </Dialog>
  );

  return (
    <Dialog
      className="dialog-wide"
      title={`What can ${agent.name} do?`}
      description="Step 2 of 2 · Choose its access. It starts with none, and you can change this any time."
      onClose={() => onDone(agent)}
      onSubmit={grant}
      dismissible={!busy}
      footer={<>
        <Button disabled={busy} onClick={() => onDone(agent)}>Skip for now</Button>
        <Button type="submit" variant="primary" disabled={!limitResult.ok || busy}>{busy ? "Saving…" : selected.length ? "Give access and continue" : "Continue"}</Button>
      </>}
    >
      {data.capabilities.length && addressableResources.length
        ? <AccessPicker capabilities={data.capabilities} resources={addressableResources} catalogResources={data.resources} selected={selected.filter(id => !held.includes(id) && !completed.includes(id))} onChange={setSelected} held={[...held, ...completed]} />
        : <p className="muted">No capabilities are available yet. <Link className="btn-link" to={sectionPath("apps")}>Connect Slack</Link> first, then give access from the agent’s page.</p>}
      {data.capabilities.length > 0 && addressableResources.length > 0 && <LimitValues rows={limits} onChange={setLimits} facts={factsFor(capabilityNames)} />}
      {completed.length > 0 && <p role="status">{completed.length} access {completed.length === 1 ? "grant saved" : "grants saved"}. Only unfinished selections will be submitted.</p>}
      {error && <p className="field-error" role="alert">{error}</p>}
    </Dialog>
  );
}
