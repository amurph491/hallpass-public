import type { AgentCredential, AuthorizationSource } from "../api/client";

export type Tone = "healthy" | "warning" | "muted" | "danger";

/** Where a request came from. Rows recorded before sources were tracked have none. */
export function authorizationSourceLabel(source?: AuthorizationSource | null): string {
  return source === "AGENT_CALL" ? "Agent call" : source === "HUMAN_PREVIEW" ? "Access test" : "Not recorded";
}

export type KeyStatus = { key: "active" | "none" | "revoked" | "expired"; label: string; badge: string; tone: Tone };

/** An agent key's state: `label` for a key's own row, `badge` where the agent is the subject. */
export function credentialStatus(credential?: AgentCredential, now = Date.now()): KeyStatus {
  if (!credential) return { key: "none", label: "No key", badge: "No key", tone: "muted" };
  if (credential.revokedAt) return { key: "revoked", label: "Revoked", badge: "Key revoked", tone: "muted" };
  if (credential.expiresAt && new Date(credential.expiresAt).getTime() <= now) return { key: "expired", label: "Expired", badge: "Key expired", tone: "warning" };
  return { key: "active", label: "Active", badge: "Key active", tone: "healthy" };
}
