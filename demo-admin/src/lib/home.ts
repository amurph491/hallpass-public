import type { Agent, AgentCredential, Delegation } from "../api/client";
import { currentCredential } from "./access";
import { activeGrants } from "./agents";
import type { App } from "./apps";
import { credentialStatus } from "./labels";
import { ActivityRequest, filterRequests } from "./requests";

/*
 * Home's checklist is derived from server state only, never from clicks, so a
 * step is done only when the data proves it. The last step needs a request
 * whose lifecycle reached EXECUTION_COMPLETED. Once it has, Home stops showing
 * the checklist and reports later problems as attention items instead.
 */

export type SetupStepKey = "connect" | "agent" | "access" | "key" | "call";
export type SetupStep = { key: SetupStepKey; done: boolean; agent?: Agent };

type SetupInput = {
  apps: App[];
  agents: Agent[];
  delegations: Delegation[];
  credentialsByAgent: Record<string, AgentCredential[]>;
};

const hasKey = (credentials: AgentCredential[] | undefined, now: number) => credentialStatus(currentCredential(credentials), now).key === "active";

export function setupSteps({ apps, agents, delegations, credentialsByAgent, hasCompletedExecution }: SetupInput & { hasCompletedExecution: boolean }, now = Date.now()): SetupStep[] {
  const withAccess = agents.filter(agent => activeGrants(delegations, agent.id, now).length > 0);
  const ready = withAccess.filter(agent => hasKey(credentialsByAgent[agent.id], now));
  return [
    { key: "connect", done: apps.some(app => app.status.key === "connected") },
    { key: "agent", done: agents.length > 0 },
    { key: "access", done: withAccess.length > 0, agent: agents[0] },
    { key: "key", done: ready.length > 0, agent: withAccess[0] ?? agents[0] },
    { key: "call", done: hasCompletedExecution, agent: ready[0] ?? withAccess[0] ?? agents[0] }
  ];
}

export type AttentionItem = { key: string; kind: "key" | "app" | "blocked" | "failed" | "unknown"; count?: number; agent?: Agent; app?: App };

/** Things an admin should look at: expired keys, apps that lost their connection, and recent blocked, failed, or unknown agent calls in the loaded history window. */
export function attentionItems({ apps, agents, credentialsByAgent, requests }: SetupInput & { requests: ActivityRequest[] }, now = Date.now()): AttentionItem[] {
  const items: AttentionItem[] = [];
  for (const agent of agents) {
    if (credentialStatus(currentCredential(credentialsByAgent[agent.id]), now).key === "expired") items.push({ key: `key-${agent.id}`, kind: "key", agent });
  }
  for (const app of apps) {
    if (app.status.key === "expired" || app.status.key === "disconnected") items.push({ key: `app-${app.id}`, kind: "app", app });
  }
  const blocked = filterRequests(requests, { result: "blocked", source: "agent", range: "24h" }, now).length;
  if (blocked) items.push({ key: "blocked", kind: "blocked", count: blocked });
  const failed = filterRequests(requests, { result: "failed", source: "agent", range: "24h" }, now).length;
  if (failed) items.push({ key: "failed", kind: "failed", count: failed });
  const unknown = filterRequests(requests, { result: "unknown", source: "agent", range: "24h" }, now).length;
  if (unknown) items.push({ key: "unknown", kind: "unknown", count: unknown });
  return items;
}
