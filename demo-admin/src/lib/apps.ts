import type { Agent, Capability, Connection, Delegation, Resource, Tool } from "../api/client";
import { capabilityLabel } from "./capabilities";
import type { Tone } from "./labels";

/*
 * An app is one resource Hallpass can reach, with its server-held connection.
 * The connection says how Hallpass signs in to the app; the capabilities and
 * grants say what each agent may do there. The two are shown separately.
 */

export type AppStatus = { key: "connected" | "expired" | "needs_reauth" | "disconnected" | "not_connected"; label: string; tone: Tone };
export type AppCapability = { capability: Capability; label: string; tools: Tool[]; agents: Agent[] };
export type App = {
  id: string;
  name: string;
  provider: string;
  resource: Resource;
  connection?: Connection;
  connections: Connection[];
  status: AppStatus;
  capabilities: AppCapability[];
  /** Tools with no trusted capability mapping. Every call to them is blocked. */
  blockedTools: Tool[];
};

export function providerName(provider?: string): string {
  if (!provider) return "App";
  return provider.toLowerCase() === "github" ? "GitHub" : provider[0].toUpperCase() + provider.slice(1).toLowerCase();
}

const live = (expiresAt: string | undefined, now: number) => !expiresAt || Date.parse(expiresAt) > now;

/** The connection that decides an app's status: an active one if any, otherwise the newest. */
function connectionsFor(resource: Resource, connections: Connection[]): Connection[] {
  const mine = connections
    .filter(item => item.provider.toLowerCase() === (resource.provider ?? "").toLowerCase())
    .sort((a, b) => (Date.parse(b.createdAt ?? "") || 0) - (Date.parse(a.createdAt ?? "") || 0));
  return mine;
}

export function appStatus(connection: Connection | undefined, now = Date.now()): AppStatus {
  if (!connection) return { key: "not_connected", label: "Not connected", tone: "muted" };
  if (connection.status === "needs_reauth") return { key: "needs_reauth", label: "Reconnect required", tone: "warning" };
  if (connection.status === "expired" || (connection.status === "active" && !live(connection.expiresAt, now))) return { key: "expired", label: "Expired", tone: "warning" };
  if (connection.status === "active") return { key: "connected", label: "Connected", tone: "healthy" };
  return { key: "disconnected", label: "Disconnected", tone: "muted" };
}

type Catalog = { resources: Resource[]; capabilities: Capability[]; tools: Tool[]; connections: Connection[]; delegations: Delegation[]; agents: Agent[] };

export function buildApps({ resources, capabilities, tools, connections, delegations, agents }: Catalog, now = Date.now()): App[] {
  return resources.filter(resource => resource.type.toLowerCase() === "provider").map(resource => {
    const providerConnections = connectionsFor(resource, connections);
    const connection = providerConnections.find(item => item.status === "active") ?? providerConnections[0];
    const appTools = tools.filter(tool => tool.resourceId === resource.id);
    const mapsTo = (tool: Tool, capability: Capability) => tool.capabilityId === capability.id || (!tool.capabilityId && tool.capability === capability.name);
    const appCapabilities = capabilities
      .filter(capability => capability.resourceId === resource.id)
      .map(capability => {
        const holders = new Set(delegations
          .filter(grant => grant.status === "active" && live(grant.expiresAt, now) && (grant.capabilityId === capability.id || (!grant.capabilityId && grant.capability === capability.name)))
          .map(grant => grant.granteeId));
        return {
          capability,
          label: capabilityLabel(capability.name),
          tools: appTools.filter(tool => tool.trusted && mapsTo(tool, capability)),
          agents: agents.filter(agent => holders.has(agent.id))
        };
      });
    return {
      id: resource.id,
      name: resource.name,
      provider: providerName(resource.provider),
      resource,
      connection,
      connections: providerConnections,
      status: appStatus(connection, now),
      capabilities: appCapabilities,
      blockedTools: appTools.filter(tool => !tool.trusted || !appCapabilities.some(item => mapsTo(tool, item.capability)))
    };
  });
}
