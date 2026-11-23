import { QueryClient, useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { AgentCredential, bridgeVersion, controlPlaneApi } from "./client";
import { buildRequests } from "../lib/requests";

/*
 * Read-side cache for control-plane state.
 *
 * Only credential-free reads belong here. One-time agent credentials returned by
 * enrollment or rotation must never pass through this cache or a useMutation
 * result: TanStack keeps both in memory after the component that asked has gone.
 * Call controlPlaneApi directly for those and invalidate `agentCredentials`.
 */

export function createQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      // Errors surface immediately with an explicit retry, matching the pre-cache UI.
      queries: { retry: false, refetchOnWindowFocus: false }
    }
  });
}

export const queryKeys = {
  agents: ["agents"] as const,
  agentCredentials: (agentId: string) => ["agents", agentId, "credentials"] as const,
  resources: ["resources"] as const,
  capabilities: ["capabilities"] as const,
  tools: ["tools"] as const,
  connections: ["connections"] as const,
  delegations: ["delegations"] as const,
  approvals: ["approvals"] as const,
  decisions: ["decisions"] as const,
  executions: (agentId: string, limit: number) => ["executions", agentId, limit] as const,
  request: (requestId: string) => ["executions", "request", requestId] as const,
  executionSummary: (agentId?: string) => ["execution-summary", agentId ?? "workspace"] as const,
  bridgeDownloads: ["bridge-downloads"] as const,
};

export const useAgents = () => useQuery({ queryKey: queryKeys.agents, queryFn: controlPlaneApi.agents });
export const useResources = () => useQuery({ queryKey: queryKeys.resources, queryFn: controlPlaneApi.resources });
export const useCapabilities = () => useQuery({ queryKey: queryKeys.capabilities, queryFn: controlPlaneApi.capabilities });
export const useTools = () => useQuery({ queryKey: queryKeys.tools, queryFn: controlPlaneApi.tools });
export const useConnections = () => useQuery({ queryKey: queryKeys.connections, queryFn: controlPlaneApi.connections });
export const useDelegations = () => useQuery({ queryKey: queryKeys.delegations, queryFn: controlPlaneApi.delegations });
export const useDecisions = () => useQuery({ queryKey: queryKeys.decisions, queryFn: controlPlaneApi.decisions });

export function useAgentCredentials(agentIds: string[]) {
  return useQueries({
    queries: agentIds.map(agentId => ({
      queryKey: queryKeys.agentCredentials(agentId),
      queryFn: () => controlPlaneApi.agentCredentials(agentId)
    })),
    combine: results => ({
      byAgent: Object.fromEntries(agentIds.map((agentId, index) => [agentId, results[index]?.data ?? []])) as Record<string, AgentCredential[]>,
      pending: results.some(result => result.isPending),
      error: results.find(result => result.error)?.error ?? null
    })
  });
}

/** Events returned per history read. The server caps a page at 100. */
export const HISTORY_LIMIT = 100;

/**
 * Recent requests, joined from the decision journal and the execution history.
 * Pass an agent to read that agent's history instead of the whole workspace's.
 */
export function useActivity(agentId?: string) {
  const decisions = useDecisions();
  const events = useQuery({
    queryKey: queryKeys.executions(agentId ?? "all", HISTORY_LIMIT),
    queryFn: () => controlPlaneApi.executions(agentId, HISTORY_LIMIT)
  });
  const scoped = (decisions.data ?? []).filter(decision => !agentId || decision.principalId === agentId);
  return {
    requests: buildRequests(scoped, events.data ?? []),
    loading: decisions.isPending || events.isPending,
    fetching: decisions.isFetching || events.isFetching,
    error: decisions.isError || events.isError,
    refetch: () => { void decisions.refetch(); void events.refetch(); }
  };
}

/** Setup completion comes from the entire durable history, rather than the recent activity window. */
export const useExecutionSummary = () =>
  useQuery({ queryKey: queryKeys.executionSummary(), queryFn: () => controlPlaneApi.executionSummary() });

/** One request's lifecycle, read by request ID so a shared link works on any screen. */
export const useRequestEvents = (requestId: string) =>
  useQuery({ queryKey: queryKeys.request(requestId), queryFn: () => controlPlaneApi.requestEvents(requestId) });

/** Everything the admin shell renders, loaded together with one loading and error state. */
export function useControlPlane() {
  const agents = useAgents();
  const resources = useResources();
  const capabilities = useCapabilities();
  const tools = useTools();
  const connections = useConnections();
  const delegations = useDelegations();
  const decisions = useDecisions();
  const credentials = useAgentCredentials((agents.data ?? []).map(agent => agent.id));
  const queries = [agents, resources, capabilities, tools, connections, delegations, decisions];
  const failed = queries.find(query => query.error)?.error ?? credentials.error;
  return {
    agents: agents.data ?? [],
    resources: resources.data ?? [],
    capabilities: capabilities.data ?? [],
    tools: tools.data ?? [],
    connections: connections.data ?? [],
    delegations: delegations.data ?? [],
    decisions: decisions.data ?? [],
    credentialsByAgent: credentials.byAgent,
    loading: queries.some(query => query.isPending) || credentials.pending,
    error: failed ? (failed instanceof Error ? failed.message : "Hallpass isn’t responding right now. Try again in a moment.") : undefined
  };
}

export function useRefetchAll() {
  const client = useQueryClient();
  return () => client.refetchQueries({ type: "active" });
}

/**
 * The published bridge version, fetched once per workspace session. A null version means this instance serves no
 * packaged bridge (the local stack), which is a normal answer rather than an error.
 */
export function useBridgeDownloads(): { pending: boolean; version: string | null } {
  const query = useQuery({
    queryKey: queryKeys.bridgeDownloads,
    queryFn: bridgeVersion,
    staleTime: Infinity,
    gcTime: Infinity
  });
  return { pending: query.isPending, version: query.data ?? null };
}

const WATCH_INTERVAL_MS = 5000;

/** Polls durable per-agent completion evidence; a short activity page is not setup state. */
export function useExecutionWatch(agentId: string) {
  const query = useQuery({
    queryKey: queryKeys.executionSummary(agentId),
    queryFn: () => controlPlaneApi.executionSummary(agentId),
    refetchInterval: current => current.state.data?.hasCompletedExecution || current.state.error ? false : WATCH_INTERVAL_MS
  });
  return { completed: query.data?.hasCompletedExecution === true, error: query.isError, retry: () => void query.refetch() };
}

/** How often the approvals queue re-reads while its page is open. */
export const APPROVALS_POLL_MS = 15_000;

/** Pending approvals. Pass `poll` from the queue page so new requests appear; the sidebar badge reads without polling. */
export const useApprovals = (poll = false) =>
  useQuery({ queryKey: queryKeys.approvals, queryFn: controlPlaneApi.approvals, refetchInterval: poll ? APPROVALS_POLL_MS : false });
