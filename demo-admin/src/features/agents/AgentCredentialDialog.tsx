import { FormEvent, useEffect, useRef, useState } from "react";
import { TriangleAlert } from "lucide-react";
import { Agent, AgentCredential, controlPlaneApi } from "../../api/client";
import { formatDate } from "../../lib/format";
import { Button } from "../../ui/Button";
import { CopyButton } from "../../ui/CopyButton";
import { Dialog } from "../../ui/Dialog";
import { Field } from "../../ui/Field";
import { ClientKey, clientFor } from "./clients";

type Props = {
  agent: Agent;
  /** The credential to rotate; enrollment when absent. */
  credential?: AgentCredential;
  /** The client this agent is set up for; names the next step. */
  client: ClientKey;
  onClose: () => void;
  onChanged: () => void;
};

/**
 * Creates or replaces an agent key and discloses it exactly once.
 *
 * The plaintext value lives only in this component (a ref for copying, state for
 * display) and is dropped on close. It deliberately bypasses the query cache. The
 * disclosure can only be closed with its button, so it is never lost by accident.
 */
export function AgentCredentialDialog({ agent, credential, client, onClose, onChanged }: Props) {
  const [expiresAt, setExpiresAt] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [disclosure, setDisclosure] = useState<{ credential: string; prefix: string; expiresAt?: string; rotated: boolean }>();
  const inFlight = useRef(false);
  const disclosureRef = useRef<string | undefined>(undefined);
  useEffect(() => () => { disclosureRef.current = undefined; }, []);

  function close() {
    if (inFlight.current) return;
    disclosureRef.current = undefined;
    setDisclosure(undefined);
    onClose();
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(undefined);
    try {
      const input = expiresAt ? { expiresAt: new Date(expiresAt).toISOString() } : {};
      const result = credential
        ? await controlPlaneApi.rotateAgentCredential(agent.id, credential.id, input)
        : await controlPlaneApi.enrollAgentCredential(agent.id, input);
      disclosureRef.current = result.credential;
      setDisclosure({ credential: result.credential, prefix: result.prefix, expiresAt: result.expiresAt, rotated: Boolean(credential) });
      onChanged();
    } catch (exception) {
      setError(exception instanceof Error ? exception.message : "The key could not be created.");
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }

  if (disclosure) {
    return (
      <Dialog
        key="disclosure"
        className="dialog-wide"
        title="Copy this key now"
        description={`This is the only time Hallpass can show ${agent.name}’s key.`}
        onClose={close}
        dismissible={false}
        footer={<>
          <CopyButton size="md" label="Copy key" getText={() => disclosureRef.current} onError={() => setError("Copy failed. Select the key and copy it manually before closing.")} />
          <Button variant="primary" onClick={close}>I’ve saved it</Button>
        </>}
      >
        <code className="secret-value" aria-label="Agent key">{disclosure.credential}</code>
        <div className="secret-meta">
          <span>Prefix <strong className="mono">{disclosure.prefix}</strong></span>
          <span>Expires <strong>{disclosure.expiresAt ? formatDate(disclosure.expiresAt) : "Never"}</strong></span>
        </div>
        {client !== "other" ? (
          <p className="field-hint">Next, run the Connect command for {clientFor(client).title} on the Setup tab and paste this key when it asks (the prompt is hidden). On a machine that already holds this agent’s previous key, use its <code>--rotate</code> variant. Never put the key in a command, a shared file, or chat.</p>
        ) : (
          <p className="field-hint">Save it in a file only you can read (mode 0600) and point your client’s bridge at that file.</p>
        )}
        <div className="callout callout-warning">
          <TriangleAlert aria-hidden />
          <p>This key signs a client in as {agent.name}. It is not a Slack credential and grants no access by itself.{disclosure.rotated ? " The previous key has stopped working." : ""}</p>
        </div>
        {error && <p className="field-error" role="alert">{error}</p>}
      </Dialog>
    );
  }

  return (
    <Dialog
      key="issue"
      title={credential ? "Replace key" : "Create key"}
      description={<>Create a key that lets a client sign in as <strong>{agent.name}</strong>.{credential ? " The current key stops working as soon as the new one is created." : ""}</>}
      onClose={close}
      onSubmit={submit}
      dismissible={!busy}
      footer={<>
        <Button disabled={busy} onClick={close}>Cancel</Button>
        <Button type="submit" variant="primary" disabled={busy}>{busy ? "Creating…" : credential ? "Replace key" : "Create key"}</Button>
      </>}
    >
      <Field label="Expires" hint="Optional. Leave empty for no expiry."><input className="input" type="datetime-local" disabled={busy} value={expiresAt} onChange={event => setExpiresAt(event.target.value)} /></Field>
      {error && <p className="field-error" role="alert">{error}</p>}
    </Dialog>
  );
}
