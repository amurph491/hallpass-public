import { Command } from "./Command";
import { ClientKey, claudeToolPrefix, clientFor, connectCommands } from "./clients";

/**
 * Where this agent appears in the client. The name is unique per client: the CLI refuses a name another agent already
 * uses instead of overwriting it, so two agents whose display names give the same name need different `--name` values.
 */
export function ServerNameNote({ client, serverName }: { client: ClientKey; serverName: string }) {
  const title = clientFor(client).title;
  return (
    <div className="stack">
      <p className="muted">Appears in {title} as <code>{serverName}</code>{client === "claude" && <>; its tools are named <code>{claudeToolPrefix(serverName)}…</code></>}.</p>
      <p className="muted">A name must be unique per client, and it only labels this entry: the key decides which agent connects. To use another name, change the value after <code>--name</code> (it starts with <code>hallpass-</code>). If another agent already uses this name in {title}, the command stops without changing anything.</p>
    </div>
  );
}

/**
 * Commands for a machine that already has the bridge installed. Every command contains the agent ID and URLs and none
 * contains a key: `hallpass connect` prompts for it, hidden. Replacing a key on the server does not change the file on
 * a machine that holds the old one, so that case has its own command (`--rotate`).
 */
export function ConnectCommands({ agentId, client, agentApiUrl, serverName }: { agentId: string; client: ClientKey; agentApiUrl: string; serverName: string }) {
  if (client === "other") return null;
  const commands = connectCommands(agentId, client, agentApiUrl, serverName);
  return (
    <div className="stack">
      <div className="field">
        <span className="field-label">Connect this machine</span>
        <Command value={commands.connect} label="Connect command" />
      </div>
      <div className="field">
        <span className="field-label">This machine holds a previous key for this agent</span>
        <Command value={commands.rotate} label="Replace stored key command" />
        <p className="field-hint">Use this after replacing the key, even if the old key was revoked. It overwrites the stored key.</p>
      </div>
      <div className="field">
        <span className="field-label">A different server named <code>{serverName}</code> is already registered in {clientFor(client).title}</span>
        <Command value={commands.replace} label="Replace registration command" />
      </div>
      <div className="field">
        <span className="field-label">Check the connection</span>
        <Command value={commands.doctor} label="Check command" />
        <p className="field-hint">Confirms the key, API, registration, and which tools are visible. It does not call Slack.</p>
      </div>
    </div>
  );
}
