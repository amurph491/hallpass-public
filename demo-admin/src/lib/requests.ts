import type { CheckResult, ExecutionEvent, Tool } from "../api/client";
import { capabilityLabel } from "./capabilities";
import type { Tone } from "./labels";

/*
 * One Activity row per authorization request. Agent calls record a decision
 * and, when allowed, execution lifecycle events under the same request ID;
 * access tests record only a decision. Lease issuance or redemption is never
 * treated as completion: only EXECUTION_COMPLETED counts as success.
 */

export type ResultKey = "succeeded" | "blocked" | "approval" | "failed" | "unknown" | "in_progress" | "allowed";
export type SourceKey = "agent" | "test" | "unknown";
export type RequestResult = { key: ResultKey; label: string; tone: Tone };

export type ActivityRequest = {
  requestId: string;
  agentId?: string;
  tool?: string;
  /** Capability ID such as "Slack.Message.Read", when the request carried one. */
  capability?: string;
  /** When the request started: the access check, or the first lifecycle event. */
  at: string;
  source: SourceKey;
  decision?: CheckResult;
  /** Lifecycle events, oldest first. */
  events: ExecutionEvent[];
  result: RequestResult;
};

export const RESULTS: Record<ResultKey, RequestResult> = {
  succeeded: { key: "succeeded", label: "Succeeded", tone: "healthy" },
  allowed: { key: "allowed", label: "Allowed", tone: "healthy" },
  in_progress: { key: "in_progress", label: "In progress", tone: "muted" },
  approval: { key: "approval", label: "Needs approval", tone: "warning" },
  blocked: { key: "blocked", label: "Blocked", tone: "danger" },
  failed: { key: "failed", label: "Failed", tone: "danger" },
  unknown: { key: "unknown", label: "Outcome unknown", tone: "warning" }
};

export const SOURCES: Record<SourceKey, string> = { agent: "Agent", test: "Test", unknown: "Unknown" };

/** Lifecycle events that stop a call after authorization but before the provider is called. */
const STOPPED_BEFORE_PROVIDER = ["REDEMPTION_DENIED", "AUTHORITY_CHANGED", "CONNECTION_UNAVAILABLE", "COORDINATION_UNAVAILABLE"];

export function requestResult(decision: CheckResult | undefined, events: ExecutionEvent[], source: SourceKey): RequestResult {
  if (decision?.decision === "deny") return RESULTS.blocked;
  if (decision?.decision === "require_approval") return RESULTS.approval;
  const kinds = events.map(event => event.eventKind);
  if (kinds.includes("EXECUTION_COMPLETED")) return RESULTS.succeeded;
  if (kinds.includes("COMPLETION_UNKNOWN")) return RESULTS.unknown;
  if (kinds.some(kind => kind.startsWith("PROVIDER_"))) return RESULTS.failed;
  if (kinds.some(kind => STOPPED_BEFORE_PROVIDER.includes(kind))) return RESULTS.blocked;
  if (kinds.length) return RESULTS.in_progress;
  // An allowed test never runs; an allowed agent call with no events yet has not reached execution.
  return source === "test" || decision ? RESULTS.allowed : RESULTS.unknown;
}

function sourceOf(decision: CheckResult | undefined, events: ExecutionEvent[]): SourceKey {
  const source = decision?.authorizationSource ?? events.find(event => event.authorizationSource)?.authorizationSource;
  return source === "AGENT_CALL" ? "agent" : source === "HUMAN_PREVIEW" ? "test" : "unknown";
}

const time = (value?: string) => (value ? Date.parse(value) : NaN);

/** Joins decisions and lifecycle events by request ID, newest request first. */
export function buildRequests(decisions: CheckResult[], events: ExecutionEvent[]): ActivityRequest[] {
  const eventsById = new Map<string, ExecutionEvent[]>();
  for (const event of events) eventsById.set(event.requestId, [...(eventsById.get(event.requestId) ?? []), event]);
  const decisionsById = new Map<string, CheckResult>();
  for (const decision of decisions) if (decision.requestId) decisionsById.set(decision.requestId, decision);

  const ids = new Set([...decisionsById.keys(), ...eventsById.keys()]);
  return [...ids]
    .map(requestId => {
      const decision = decisionsById.get(requestId);
      const lifecycle = [...(eventsById.get(requestId) ?? [])].sort((a, b) => time(a.occurredAt) - time(b.occurredAt));
      const first = lifecycle[0];
      const source = sourceOf(decision, lifecycle);
      return {
        requestId,
        agentId: decision?.principalId || first?.agentId || undefined,
        tool: decision?.tool || first?.tool || undefined,
        capability: first?.capability || undefined,
        at: decision?.checkedAt || first?.occurredAt || "",
        source,
        decision,
        events: lifecycle,
        result: requestResult(decision, lifecycle, source)
      };
    })
    .sort((a, b) => (time(b.at) || 0) - (time(a.at) || 0));
}

export type TimeRange = "1h" | "24h" | "7d";
export const RANGES: Record<TimeRange, { label: string; ms: number }> = {
  "1h": { label: "Last hour", ms: 3_600_000 },
  "24h": { label: "Last 24 hours", ms: 86_400_000 },
  "7d": { label: "Last 7 days", ms: 604_800_000 }
};

export type ActivityFilters = { agent?: string; result?: ResultKey; source?: SourceKey; range?: TimeRange };

const isKey = <K extends string>(record: Record<K, unknown>, value: string | null): value is K => value !== null && Object.prototype.hasOwnProperty.call(record, value);

/** Reads filters from URL search params, ignoring values that are not recognised. */
export function parseFilters(params: URLSearchParams): ActivityFilters {
  const result = params.get("result");
  const source = params.get("source");
  const range = params.get("range");
  return {
    agent: params.get("agent") || undefined,
    result: isKey(RESULTS, result) ? result : undefined,
    source: isKey(SOURCES, source) ? source : undefined,
    range: isKey(RANGES, range) ? range : undefined
  };
}

export function filterRequests(requests: ActivityRequest[], filters: ActivityFilters, now = Date.now()): ActivityRequest[] {
  const since = filters.range ? now - RANGES[filters.range].ms : undefined;
  return requests.filter(request =>
    (!filters.agent || request.agentId === filters.agent) &&
    (!filters.result || request.result.key === filters.result) &&
    (!filters.source || request.source === filters.source) &&
    (since === undefined || time(request.at) >= since)
  );
}

/** Journal reason codes, such as "CapabilityNotDelegated(<id>)", as plain sentences. */
const REASONS: Record<string, string> = {
  authorized: "An active access grant and the owner’s policy allow it.",
  capabilitynotdelegated: "This agent hasn’t been given this access.",
  nomatchingauthority: "No access grant or policy covers this action.",
  unmappedtool: "This tool isn’t mapped to a capability, so it’s always blocked.",
  inactivedelegation: "The agent’s access for this was removed or has expired.",
  delegationconstraintsnotsatisfied: "The conditions on the agent’s access weren’t met.",
  explicitdeny: "A policy explicitly blocks this action.",
  tenantmismatch: "The request crossed workspaces, so it was blocked.",
  invaliddelegationchain: "The chain of access grants isn’t valid.",
  approvalrequired: "A policy requires approval before this can run."
};

export function reasonLabel(reason: string | undefined): string | undefined {
  if (!reason) return undefined;
  const code = reason.split("(")[0].replace(/[^a-z]/gi, "").toLowerCase();
  if (REASONS[code]) return REASONS[code];
  // Test responses already carry a sentence; bare codes we don't know stay generic.
  return /\s/.test(reason.trim()) ? reason : "Authorization was denied.";
}

export type TimelineStep = { key: string; label: string; detail?: string; at?: string; tone: Tone };

const REDEMPTION_DETAIL: Record<string, string> = {
  DENIED_EXPIRED: "The pass expired before it was used.",
  DENIED_ALREADY_REDEEMED: "The pass had already been used.",
  DENIED_WRONG_AUDIENCE: "The pass was for a different executor.",
  DENIED_UNKNOWN_LEASE: "Hallpass didn’t recognise the pass."
};

function eventStep(event: ExecutionEvent, provider: string): Omit<TimelineStep, "key" | "at"> {
  switch (event.eventKind) {
    case "LEASE_ISSUED": return { label: "Execution pass issued", detail: "Single-use and short-lived, for this call only.", tone: "muted" };
    case "LEASE_REDEEMED": return { label: "Execution pass used", detail: `Hallpass rechecked current access before calling ${provider}.`, tone: "muted" };
    case "REDEMPTION_DENIED": return { label: "Execution pass rejected", detail: REDEMPTION_DETAIL[event.safeOutcome] ?? `${provider} was never called.`, tone: "danger" };
    case "AUTHORITY_CHANGED": return { label: "Access changed before the call", detail: `The agent’s access changed after the check, so ${provider} was never called.`, tone: "danger" };
    case "CONNECTION_UNAVAILABLE": return { label: `${provider} connection unavailable`, detail: `${provider} is disconnected or its credential is missing, so it was never called.`, tone: "danger" };
    case "COORDINATION_UNAVAILABLE": return { label: "Couldn’t confirm current access", detail: `Hallpass failed closed, so ${provider} was never called.`, tone: "danger" };
    case "PROVIDER_REJECTED": return { label: `${provider} rejected the call`, tone: "danger" };
    case "PROVIDER_UNAVAILABLE": return { label: `${provider} didn’t respond`, tone: "danger" };
    case "EXECUTION_COMPLETED": return { label: "Completed", detail: `${provider} answered. Its credential never left the server.`, tone: "healthy" };
    case "COMPLETION_UNKNOWN": return { label: "Outcome unknown", detail: `${provider} may have completed it, but the result couldn’t be recorded. It was not retried.`, tone: "warning" };
    default: return { label: event.eventKind.replace(/_/g, " ").toLowerCase().replace(/^\w/, c => c.toUpperCase()), tone: "muted" };
  }
}

/** "Slack.Message.Read" or "slack_search_messages" -> "Slack". */
export function providerOf(request: Pick<ActivityRequest, "capability" | "tool">): string {
  const name = request.capability?.split(".")[0] || request.tool?.split("_")[0] || "";
  return name ? name[0].toUpperCase() + name.slice(1) : "the provider";
}

/** The access check, then each lifecycle event, oldest first. */
export function requestTimeline(request: ActivityRequest): TimelineStep[] {
  const provider = providerOf(request);
  const { decision } = request;
  const check: TimelineStep = decision
    ? {
        key: "check",
        label: decision.decision === "allow" ? "Access allowed" : decision.decision === "require_approval" ? "Approval required" : "Access blocked",
        detail: reasonLabel(decision.reason),
        at: decision.checkedAt,
        tone: decision.decision === "allow" ? "healthy" : decision.decision === "require_approval" ? "warning" : "danger"
      }
    // A pass is only issued from a successful check, so its absence here means the record is outside the loaded window.
    : { key: "check", label: "Access allowed", detail: "The check record is older than the loaded history.", tone: "healthy" };
  const steps = [check, ...request.events.map((event, index) => ({ key: `${index}-${event.eventKind}`, at: event.occurredAt, ...eventStep(event, provider) }))];
  if (request.source === "test") steps.push({ key: "test", label: `Nothing sent to ${provider}`, detail: "Tests only check access.", tone: "muted" });
  return steps;
}

/** The one sentence that explains how the request ended. */
export function requestExplanation(request: ActivityRequest): string | undefined {
  const { decision } = request;
  if (decision && (decision.decision !== "allow" || request.result.key === "allowed")) return reasonLabel(decision.reason);
  const steps = requestTimeline(request);
  const last = steps[steps.length - 1];
  return last?.detail ?? last?.label;
}

/** What the request tried to do, in words, with the capability ID when one is known. */
export function requestAction(request: Pick<ActivityRequest, "capability" | "tool">, tools: Tool[]): { label: string; capability?: string } {
  const tool = tools.find(item => item.name === request.tool);
  const capability = request.capability || tool?.capability;
  if (capability) return { label: capabilityLabel(capability), capability };
  return { label: tool?.label || "Unmapped tool" };
}
