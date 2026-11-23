import { createContext, useContext } from "react";
import type { Agent, Connection } from "../api/client";
import type { useControlPlane } from "../api/queries";
import type { ClientKey } from "../features/agents/clients";

export type MutationOptions = { success: string; failure: string; onError?: (message: string) => void };

export type AdminContextValue = {
  data: ReturnType<typeof useControlPlane>;
  busy: boolean;
  /** This page's origin, from which the packaged bridge is downloaded. */
  adminOrigin: string;
  /** The server-configured address client machines use for the agent API. Undefined if the server did not report one. */
  agentApiUrl: string | undefined;
  /** Runs one control-plane write with the shared busy flag, then refreshes the given reads. */
  mutate: <T>(action: () => Promise<T>, keys: ReadonlyArray<readonly unknown[]>, options: MutationOptions) => Promise<{ value: T } | undefined>;
  notify: (message: string) => void;
  /** Opens the enroll/rotate dialog; the one-time key never leaves that dialog. */
  openKeyDialog: (agent: Agent) => void;
  clientOf: (agent: Agent) => ClientKey;
  setClient: (agentId: string, client: ClientKey) => void;
  /** Starts Slack OAuth in this tab. The server holds the resulting credential. */
  connectSlack: () => void;
  /** Starts provider OAuth in this tab. Resolves to an error message when the start failed; never marks a provider connected. */
  connectProvider: (provider: string) => Promise<string | undefined>;
  /** Reconnects a connection that needs reauthorization in place; its grants and selections are kept. */
  reconnect: (connection: Connection) => void;
  disconnect: (connection: Connection) => Promise<boolean>;
};

export const AdminContext = createContext<AdminContextValue | null>(null);

export function useAdmin(): AdminContextValue {
  const value = useContext(AdminContext);
  if (!value) throw new Error("useAdmin must be used inside AdminApp.");
  return value;
}
