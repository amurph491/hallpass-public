import type { AgentCredential, Delegation } from "../api/client";

/** Active, unexpired grants held by one agent. */
export function activeGrants(delegations: Delegation[], agentId: string, now = Date.now()): Delegation[] {
  return delegations.filter(item =>
    item.granteeId === agentId && item.status === "active" && (!item.expiresAt || Date.parse(item.expiresAt) > now));
}

/** Grants that no longer apply: revoked, expired, or otherwise inactive. */
export function pastGrants(delegations: Delegation[], agentId: string, now = Date.now()): Delegation[] {
  const active = new Set(activeGrants(delegations, agentId, now).map(item => item.id));
  return delegations.filter(item => item.granteeId === agentId && !active.has(item.id));
}

/** The most recent time any of the agent's keys authenticated. */
export function lastUsed(credentials: AgentCredential[] | undefined): string | undefined {
  return (credentials ?? [])
    .map(item => item.lastUsedAt)
    .filter((value): value is string => Boolean(value))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0];
}
