import type { AgentCredential } from "../api/client";

/** The credential an agent currently authenticates with, if any. */
export function currentCredential(credentials: AgentCredential[] | undefined): AgentCredential | undefined {
  return credentials?.find(credential => !credential.revokedAt);
}
