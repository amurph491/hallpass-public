export type Decision = "allow" | "deny" | "require_approval";

export type Agent = { id: string; name: string; description?: string; createdAt?: string };
/** Metadata is safe to render repeatedly. It can never reproduce a bridge credential. */
export type AgentCredential = { id: string; prefix: string; createdAt?: string; expiresAt?: string; revokedAt?: string; lastUsedAt?: string; label?: string };
/** This is intentionally only returned from a successful enrollment or rotation response. */
export type OneTimeAgentCredential = AgentCredential & { credential: string };
export type Resource = { id: string; name: string; type: string; provider?: string; externalId?: string };
export type Capability = { id: string; name: string; action: string; resourceId?: string; resource?: string };
export type Tool = { id?: string; name: string; label: string; resourceId?: string; capabilityId?: string; capability?: string; mappingSource?: string; trusted: boolean };
export type Delegation = { id: string; grantorId?: string; grantor: string; granteeId: string; grantee: string; capabilityId?: string; capability: string; resourceId?: string; resource?: string; status: string; createdAt?: string; expiresAt?: string; revokedAt?: string; constraints?: { value_in?: Record<string, string[]> } };
export type Connection = { id: string; resourceId: string; provider: string; status: string; accountLabel?: string; externalAccountId?: string; workspaceLabel?: string; expiresAt?: string; createdAt?: string };
export type ConnectionResource = { id: string; kind: string; externalId: string; name: string; selectedAt?: string; root: boolean };
export type SelectableConnectionResource = { selectionKey: string; kind: string; externalId: string; name: string };
export type ConnectionResourceListing = { resources: ConnectionResource[]; available: SelectableConnectionResource[] };
export type AuthorizationSource = "AGENT_CALL" | "HUMAN_PREVIEW";
export type ExecutionSummary = { hasCompletedExecution: boolean };
export type ExecutionEvent = { requestId: string; correlationId: string; agentId: string; tool: string; capability: string; eventKind: string; safeOutcome: string; occurredAt: string; authorizationSource?: AuthorizationSource };
export type CheckResult = { id?: string; requestId?: string; authorizationSource?: AuthorizationSource; decision: Decision; title: string; reason: string; principal?: string; principalId?: string; tool?: string; capability?: string; policy?: string; delegation?: string; resource?: string; checkedAt?: string; correlationId?: string };
export type CheckRequest = { agentId: string; tool: string; correlationId?: string };
export type CreateDelegationRequest = { agentId: string; capabilityId: string; resourceId?: string; expiresAt?: string; constraints?: { value_in: Record<string, string[]> } };

/** A request an agent made that needs a human decision. `preview` is the exact argument set the approval would allow. */
export type Approval = { id: string; tool: string; operation: string; agentId: string; capability: string; action: string; resourceId: string; preview: Record<string, unknown>; requestedAt: string; expiresAt: string };
export type ApprovalDecision = "approve" | "deny";

type JsonObject = Record<string, unknown>;
let csrfToken: string | undefined;
let sessionVersion = 0;
export const SESSION_EXPIRED_EVENT = "hallpass:session-expired";
export function invalidateSessionRequests() { ++sessionVersion; }


function unsafeMethod(method: string | undefined): boolean {
  return method !== undefined && !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const version = sessionVersion;
  const response = await fetch(path, {
    ...init,
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(unsafeMethod(init?.method) && csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
      ...init?.headers
    }
  });
  if (!response.ok) {
    if (response.status === 401 && version === sessionVersion) {
      csrfToken = undefined;
      if (typeof window !== "undefined") window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT));
    }
    // Never surface a response body here. Enrollment responses are deliberately
    // secret-bearing, and an intermediary must not turn one into a UI error.
    throw new ApiStatusError(response.status);
  }
  if (response.status === 204) return undefined as T;
  return response.json() as Promise<T>;
}

/** An HTTP failure carrying only its status; the response body is never kept. */
export class ApiStatusError extends Error {
  constructor(readonly status: number) {
    super(safeHttpError(status));
  }
}

/** Display copy for a failed connection start, from status alone. Nothing here is read from the response body. */
export function connectionStartMessage(provider: string, exception: unknown): string {
  const displayNames: Record<string, string> = { github: "GitHub", slack: "Slack", google: "Google", linear: "Linear", notion: "Notion", hubspot: "HubSpot" };
  const name = displayNames[provider.toLowerCase()] ?? provider;
  if (exception instanceof ApiStatusError) {
    if (exception.status === 503) return `${name} is not configured on this server. Ask the operator to finish the ${name} OAuth setup, then try again.`;
    if (exception.status === 409) return `${name} is not provisioned for this workspace. An owner must provision it before it can be connected.`;
  }
  return exception instanceof Error ? exception.message : `${name} connection could not start.`;
}

export type TenantMembership = { tenantId: string; name?: string; role: "ADMIN" | "MEMBER"; breakGlass: boolean };
/** The signed-in person. The session cookie is HttpOnly; only the derived CSRF token reaches script. */
export type ManagementSession = {
  userId: string;
  tenant?: TenantMembership;
  memberships: TenantMembership[];
  /** Where client machines reach the agent API, as configured on the server. Display only; it selects nothing. */
  agentApiUrl?: string;
};
export type LoginMethods = { oidc: boolean; developmentBootstrap: boolean };

/** Starts single sign-on. It is a top-level navigation, so the identity provider's redirect returns here. */
export const oidcStartPath = "/api/auth/oidc/start";

function normalizeMembership(raw: JsonObject): TenantMembership {
  return { tenantId: string(raw.tenantId), name: string(raw.name) || undefined, role: raw.role === "ADMIN" ? "ADMIN" : "MEMBER", breakGlass: raw.breakGlass === true };
}

/** Restores the current session after a reload or a login redirect. Returns undefined when signed out. */
export async function loadManagementSession(): Promise<ManagementSession | undefined> {
  const version = sessionVersion;
  const response = await fetch("/api/session", { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (response.status === 401) { if (version === sessionVersion) csrfToken = undefined; return undefined; }
  if (!response.ok) throw new Error(safeHttpError(response.status));
  const value = await response.json() as JsonObject;
  const token = string(value.csrfToken);
  if (!token) throw new Error("The management session could not be established.");
  if (version === sessionVersion) csrfToken = token;
  const memberships = Array.isArray(value.memberships) ? (value.memberships as JsonObject[]).map(normalizeMembership) : [];
  const tenant = value.tenant && typeof value.tenant === "object" ? normalizeMembership(value.tenant as JsonObject) : undefined;
  return { userId: string(value.userId), tenant, memberships, agentApiUrl: string(value.agentApiUrl) || undefined };
}

/** A release label such as `0.1.0` or `2026.09.29-abc123`. The pattern also rejects an HTML page served in its place. */
const BRIDGE_VERSION = /^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$/;

/** The bridge version an instance publishes, or null when it publishes none (the local stack answers 404). */
export function parseBridgeVersion(text: string): string | null {
  const version = text.trim();
  return BRIDGE_VERSION.test(version) ? version : null;
}

/**
 * Whether this instance serves the packaged bridge under `/downloads`, and which version. Any failure means "not
 * available": the packaged installer is optional, and an unreachable file must not block setup.
 */
export async function bridgeVersion(): Promise<string | null> {
  try {
    const response = await fetch("/downloads/VERSION", { credentials: "omit", headers: { Accept: "text/plain" } });
    if (!response.ok || (response.headers.get("Content-Type") ?? "").toLowerCase().includes("html")) return null;
    return parseBridgeVersion(await response.text());
  } catch {
    return null;
  }
}

export async function loginMethods(): Promise<LoginMethods> {
  const value = await request<JsonObject>("/api/auth/methods");
  return { oidc: value.oidc === true, developmentBootstrap: value.developmentBootstrap === true };
}

export async function selectTenant(tenantId: string): Promise<void> {
  await request<void>("/api/session/tenant", { method: "POST", body: JSON.stringify({ tenantId }) });
}

export async function signOut(): Promise<void> {
  await request<void>("/api/session/logout", { method: "POST" });
  csrfToken = undefined;
}

/** Exchanges a locally supplied bootstrap value for an HttpOnly browser session.
  * The value stays only in the caller's temporary input and is never persisted.
  */
export async function bootstrapAdminSession(bootstrap: string): Promise<void> {
  const response = await fetch("/api/admin/session", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "X-Hallpass-Admin-Bootstrap": bootstrap
    }
  });
  if (response.status === 401 || response.status === 403) throw new Error("That admin key wasn’t accepted. Copy it again from .secrets/admin_bootstrap.");
  if (!response.ok) throw new Error(safeHttpError(response.status));
  const value = await response.json() as JsonObject;
  const token = string(value.csrfToken);
  if (!token) throw new Error("Sign-in didn’t complete. Try again.");
  csrfToken = token;
}

function arrayFrom<T>(data: T[] | JsonObject, keys: string[]): T[] {
  if (Array.isArray(data)) return data;
  for (const key of keys) if (Array.isArray(data[key])) return data[key] as T[];
  return [];
}

function string(value: unknown, fallback = ""): string { return typeof value === "string" ? value : fallback; }
function optionalDate(value: unknown): string | undefined {
  const candidate = string(value).trim();
  return candidate && Number.isFinite(Date.parse(candidate)) ? candidate : undefined;
}

function normalizeAgent(raw: JsonObject): Agent {
  return { id: string(raw.id), name: string(raw.name, string(raw.label, "Unnamed agent")), description: string(raw.description) || undefined, createdAt: string(raw.createdAt) || undefined };
}

function safeHttpError(status: number): string {
  if (status === 400) return "The request was not valid.";
  if (status === 401) return "Your admin session has ended. Refresh and sign in again.";
  if (status === 403) return "This action is not permitted.";
  if (status === 404) return "That item no longer exists. Refresh to see the current state.";
  if (status === 409) return "Something changed since this page loaded. Refresh and try again.";
  if (status === 413) return "The request is too large.";
  if (status === 415) return "The request format is not supported.";
  if (status >= 500) return "Hallpass isn’t responding right now. Try again in a moment.";
  return "The request couldn’t be completed.";
}

function normalizeAgentCredential(raw: JsonObject): AgentCredential {
  return {
    id: string(raw.credentialId, string(raw.id)),
    prefix: string(raw.prefix, string(raw.selector, "Unavailable")),
    createdAt: optionalDate(raw.createdAt),
    expiresAt: optionalDate(raw.expiresAt),
    revokedAt: optionalDate(raw.revokedAt),
    lastUsedAt: optionalDate(raw.lastUsedAt),
    label: string(raw.label) || undefined
  };
}

function normalizeOneTimeAgentCredential(raw: JsonObject): OneTimeAgentCredential {
  const metadata = normalizeAgentCredential(raw);
  const credential = string(raw.credential);
  if (!credential) throw new Error("The enrollment response did not contain a credential.");
  return { ...metadata, credential };
}

function normalizeResource(raw: JsonObject): Resource {
  return { id: string(raw.id, string(raw.resourceId)), name: string(raw.name, string(raw.label, "Unnamed resource")), type: string(raw.type, "provider"), provider: string(raw.provider) || undefined, externalId: string(raw.externalId) || undefined };
}

function normalizeCapability(raw: JsonObject): Capability {
  const descriptor = (raw.descriptor || {}) as JsonObject;
  return { id: string(raw.id), name: string(raw.name, string(raw.label, "Unnamed capability")), action: string(raw.action, string(descriptor.action)), resourceId: string(raw.resourceId, string(descriptor.resourceId)) || undefined, resource: string(raw.resource) || undefined };
}

function normalizeTool(raw: JsonObject): Tool {
  const mapping = (raw.mapping || {}) as JsonObject;
  const capability = (raw.capability || {}) as JsonObject;
  return { id: string(raw.id) || undefined, name: string(raw.name, string(raw.tool)), label: string(raw.label, string(raw.name, string(raw.tool))), resourceId: string(raw.resourceId, string(raw.resource)) || undefined, capabilityId: string(raw.capabilityId, string(mapping.capabilityId, string(capability.id))) || undefined, capability: string(raw.capabilityName, string(mapping.capability, string(capability.name, string(capability.label)))) || undefined, mappingSource: string(raw.mappingSource, string(mapping.source, string(raw.source))) || undefined, trusted: typeof mapping.trusted === "boolean" ? mapping.trusted : typeof raw.trusted === "boolean" ? raw.trusted : false };
}

export function normalizeConstraints(raw: unknown): Delegation["constraints"] {
  const valueIn = raw && typeof raw === "object" ? (raw as JsonObject).value_in : undefined;
  if (!valueIn || typeof valueIn !== "object" || Array.isArray(valueIn)) return undefined;
  const out: Record<string, string[]> = {};
  for (const [key, values] of Object.entries(valueIn as JsonObject)) if (Array.isArray(values)) out[key] = values.filter((v): v is string => typeof v === "string");
  return Object.keys(out).length ? { value_in: out } : undefined;
}

function normalizeDelegation(raw: JsonObject): Delegation {
  const grantor = (raw.grantor || {}) as JsonObject;
  const grantee = (raw.grantee || {}) as JsonObject;
  const capability = (raw.capability || {}) as JsonObject;
  const revokedAt = string(raw.revokedAt) || undefined;
  return { id: string(raw.id), grantorId: string(raw.grantorId, string(grantor.id)) || undefined, grantor: string(raw.grantorName, string(grantor.name, string(grantor.label, "Demo authority owner"))), granteeId: string(raw.granteeId, string(grantee.id)), grantee: string(raw.granteeName, string(grantee.name, string(grantee.label, "Agent"))), capabilityId: string(raw.capabilityId, string(capability.id)) || undefined, capability: string(raw.capabilityName, string(raw.capability, string(capability.name, string(capability.label, "Capability")))), resourceId: string(raw.resourceId) || undefined, resource: string(raw.resourceName) || undefined, status: string(raw.status, revokedAt ? "revoked" : "active").toLowerCase(), createdAt: string(raw.createdAt, string(raw.validFrom)) || undefined, expiresAt: string(raw.expiresAt) || undefined, revokedAt, constraints: normalizeConstraints(raw.constraints) };
}

function normalizeDecision(raw: JsonObject): CheckResult {
  const evidence = (raw.evidence || {}) as JsonObject;
  const requiredCapability = (evidence.requiredCapability || {}) as JsonObject;
  const outcome = string(raw.decision, string(raw.outcome, "denied")).toLowerCase();
  const decision: Decision = outcome === "allow" || outcome === "allowed" ? "allow" : outcome.includes("approval") ? "require_approval" : "deny";
  const tool = string(raw.tool);
  const delegationIds = Array.isArray(evidence.delegationIds) ? evidence.delegationIds.join(", ") : "";
  const policyId = string(evidence.policyId);
  const policyVersion = string(evidence.policyVersion);
  const directDelegations = Array.isArray(raw.delegationIds) ? raw.delegationIds.join(", ") : "";
  const directPolicyId = string(raw.policyId);
  const directPolicyVersion = string(raw.policyVersion);
  return { id: string(raw.id, string(raw.requestId, string(raw.correlationId))) || undefined, requestId: string(raw.requestId) || undefined, authorizationSource: raw.authorizationSource === "AGENT_CALL" || raw.authorizationSource === "HUMAN_PREVIEW" ? raw.authorizationSource : undefined, decision, title: string(raw.title, tool ? `Invoke ${tool}` : decision === "allow" ? "Action authorized" : decision === "require_approval" ? "Approval required" : "Action denied"), reason: string(raw.message, string(raw.reason, "No matching authority was found.")), principal: string(raw.principalName, string(raw.principal)) || undefined, principalId: string(raw.principalId) || undefined, tool: tool || undefined, capability: string(raw.capabilityName, string(raw.capability, string(raw.action, string(evidence.capability, string(evidence.action, string(requiredCapability.label)))))) || undefined, policy: string(raw.policy, directPolicyId ? `${directPolicyId}${directPolicyVersion ? ` · v${directPolicyVersion}` : ""}` : policyId ? `${policyId}${policyVersion ? ` · v${policyVersion}` : ""}` : "") || undefined, delegation: string(raw.delegation, directDelegations || string(evidence.delegation, delegationIds)) || undefined, resource: string(raw.resourceName, string(raw.resource, string(raw.resourceId, string(evidence.resource, string(evidence.resourceId))))) || undefined, checkedAt: string(raw.checkedAt, string(raw.decidedAt, string(raw.occurredAt, string(raw.evaluatedAt)))) || undefined, correlationId: string(raw.correlationId) || undefined };
}
function normalizeConnection(raw: JsonObject): Connection { return { id: string(raw.id), resourceId: string(raw.resourceId), provider: string(raw.provider, "slack"), status: string(raw.status, "error").toLowerCase(), accountLabel: string(raw.accountLabel) || undefined, externalAccountId: string(raw.externalAccountId) || undefined, workspaceLabel: string(raw.workspaceLabel) || undefined, expiresAt: optionalDate(raw.expiresAt), createdAt: optionalDate(raw.createdAt) }; }

function normalizeConnectionResources(raw: JsonObject): ConnectionResourceListing {
  const resources = arrayFrom<JsonObject>(raw, ["resources"]).map(item => ({
    id: string(item.id), kind: string(item.kind), externalId: string(item.externalId), name: string(item.name),
    selectedAt: optionalDate(item.selectedAt), root: item.root === true
  }));
  const available = arrayFrom<JsonObject>(raw, ["available"]).map(item => ({
    selectionKey: string(item.selectionKey), kind: string(item.kind), externalId: string(item.externalId), name: string(item.name)
  }));
  return { resources, available };
}

function normalizeApproval(raw: JsonObject): Approval {
  const preview = raw.preview && typeof raw.preview === "object" && !Array.isArray(raw.preview) ? raw.preview as Record<string, unknown> : {};
  return { id: string(raw.id), tool: string(raw.tool), operation: string(raw.operation), agentId: string(raw.agentId), capability: string(raw.capability), action: string(raw.action), resourceId: string(raw.resourceId), preview, requestedAt: string(raw.requestedAt), expiresAt: string(raw.expiresAt) };
}

export const controlPlaneApi = {
  approvals: async (): Promise<Approval[]> => arrayFrom<JsonObject>(await request("/api/approvals"), ["approvals"]).map(normalizeApproval),
  /** Approving allows exactly this request once; the agent must retry it. Denying ends it. The CSRF header is attached to every non-GET. */
  decideApproval: async (id: string, decision: ApprovalDecision): Promise<Approval> => normalizeApproval(await request<JsonObject>(`/api/approvals/${encodeURIComponent(id)}/${decision}`, { method: "POST" })),
  async executionSummary(agentId?: string): Promise<{ hasCompletedExecution: boolean }> {
    const params = agentId ? `?agentId=${encodeURIComponent(agentId)}` : "";
    const value = await request<JsonObject>(`/api/executions/summary${params}`);
    if (typeof value.hasCompletedExecution !== "boolean") throw new Error("Execution history is unavailable.");
    return { hasCompletedExecution: value.hasCompletedExecution };
  },
  agents: async (): Promise<Agent[]> => arrayFrom<JsonObject>(await request("/api/agents"), ["agents", "items"]).map(normalizeAgent),
  createAgent: async (input: { name: string; description?: string }): Promise<Agent> => normalizeAgent(await request<JsonObject>("/api/agents", { method: "POST", body: JSON.stringify(input) })),
  agentCredentials: async (agentId: string): Promise<AgentCredential[]> => arrayFrom<JsonObject>(await request(`/api/agents/${encodeURIComponent(agentId)}/credentials`), ["credentials", "items"]).map(normalizeAgentCredential),
  enrollAgentCredential: async (agentId: string, input: { expiresAt?: string }): Promise<OneTimeAgentCredential> => normalizeOneTimeAgentCredential(await request<JsonObject>(`/api/agents/${encodeURIComponent(agentId)}/credentials`, { method: "POST", body: JSON.stringify(input) })),
  revokeAgentCredential: async (agentId: string, credentialId: string): Promise<void> => request<void>(`/api/agents/${encodeURIComponent(agentId)}/credentials/${encodeURIComponent(credentialId)}/revoke`, { method: "POST" }),
  rotateAgentCredential: async (agentId: string, credentialId: string, input: { expiresAt?: string }): Promise<OneTimeAgentCredential> => normalizeOneTimeAgentCredential(await request<JsonObject>(`/api/agents/${encodeURIComponent(agentId)}/credentials/${encodeURIComponent(credentialId)}/rotate`, { method: "POST", body: JSON.stringify(input) })),
  resources: async (): Promise<Resource[]> => arrayFrom<JsonObject>(await request("/api/resources"), ["resources", "items"]).map(normalizeResource),
  capabilities: async (): Promise<Capability[]> => arrayFrom<JsonObject>(await request("/api/capabilities"), ["capabilities", "items"]).map(normalizeCapability),
  tools: async (): Promise<Tool[]> => arrayFrom<JsonObject>(await request("/api/tools"), ["tools", "items"]).map(normalizeTool),
  connections: async (): Promise<Connection[]> => arrayFrom<JsonObject>(await request("/api/connections"), ["connections", "items"]).map(normalizeConnection),
  startConnection: async (provider: string): Promise<string> => string((await request<JsonObject>(`/api/connections/${encodeURIComponent(provider)}/start`, { method: "POST" })).authorizationUrl),
  connectionResources: async (id: string): Promise<ConnectionResourceListing> => normalizeConnectionResources(await request<JsonObject>(`/api/connections/${encodeURIComponent(id)}/resources`)),
  selectConnectionResources: async (id: string, resources: string[]): Promise<void> => request<void>(`/api/connections/${encodeURIComponent(id)}/resources`, { method: "PUT", body: JSON.stringify({ resources }) }),
  /** Public Picker settings (never a token). Null when the server has Picker unconfigured (404). */
  googlePickerConfig: async (): Promise<{ clientId: string; apiKey: string; appId: string; scope: string } | null> => {
    try {
      const raw = await request<JsonObject>("/api/connections/google/picker-config");
      return { clientId: string(raw.clientId), apiKey: string(raw.apiKey), appId: string(raw.appId), scope: string(raw.scope) };
    } catch (exception) {
      if (exception instanceof ApiStatusError && exception.status === 404) return null;
      throw exception;
    }
  },
  reauthorizeConnection: async (id: string): Promise<string> => string((await request<JsonObject>(`/api/connections/${encodeURIComponent(id)}/reauthorize`, { method: "POST" })).authorizationUrl),
  disconnect: async (id: string): Promise<void> => request<void>(`/api/connections/${encodeURIComponent(id)}/disconnect`, { method: "POST" }),
  delegations: async (): Promise<Delegation[]> => arrayFrom<JsonObject>(await request("/api/delegations"), ["delegations", "items"]).map(normalizeDelegation),
  createDelegation: async (input: CreateDelegationRequest): Promise<Delegation> => normalizeDelegation(await request<JsonObject>("/api/delegations", { method: "POST", body: JSON.stringify(input) })),
  revokeDelegation: async (id: string): Promise<Delegation> => normalizeDelegation(await request<JsonObject>(`/api/delegations/${encodeURIComponent(id)}/revoke`, { method: "POST" })),
  check: async (input: CheckRequest): Promise<CheckResult> => normalizeDecision(await request<JsonObject>("/api/authorization/check", { method: "POST", body: JSON.stringify(input) })),
  decisions: async (): Promise<CheckResult[]> => arrayFrom<JsonObject>(await request("/api/authorization/decisions"), ["decisions", "items"]).map(normalizeDecision),
  /** Lifecycle events for one agent, or for the whole workspace when no agent is given. */
  executions: async (agentId: string | undefined, limit = 25): Promise<ExecutionEvent[]> => arrayFrom<JsonObject>(await request(`/api/executions?${agentId ? `agentId=${encodeURIComponent(agentId)}&` : ""}limit=${encodeURIComponent(String(limit))}`), ["executions"]).map(normalizeExecutionEvent),
  /** Lifecycle events for one request; a request with none (a test, or a blocked call) is an empty list. */
  requestEvents: async (requestId: string): Promise<ExecutionEvent[]> => {
    try {
      return arrayFrom<JsonObject>(await request(`/api/executions/${encodeURIComponent(requestId)}?limit=100`), ["events"]).map(normalizeExecutionEvent);
    } catch (exception) {
      if (exception instanceof Error && exception.message === safeHttpError(404)) return [];
      throw exception;
    }
  }
};

function normalizeExecutionEvent(raw: JsonObject): ExecutionEvent {
  return { requestId: string(raw.requestId), correlationId: string(raw.correlationId), agentId: string(raw.agentId), tool: string(raw.tool), capability: string(raw.capability), eventKind: string(raw.eventKind), safeOutcome: string(raw.safeOutcome), occurredAt: string(raw.occurredAt), authorizationSource: raw.authorizationSource === "AGENT_CALL" || raw.authorizationSource === "HUMAN_PREVIEW" ? raw.authorizationSource : undefined };
}
