-- Execution lifecycle evidence. These rows are deliberately typed and
-- append-only: no request payloads, provider results, headers, credentials,
-- verifier material, secret references, or arbitrary exception text belong in
-- this audit surface.
--
-- The extra composite keys make the tenant/request/correlation and
-- tenant/credential/agent relationships enforceable by foreign keys. They are
-- added here rather than weakening the audit schema to independent UUIDs.
ALTER TABLE authorization_requests
  ADD CONSTRAINT authorization_requests_tenant_id_id_correlation_id_unique
  UNIQUE (tenant_id, id, correlation_id);

ALTER TABLE capabilities
  ADD CONSTRAINT capabilities_tenant_id_id_resource_id_action_unique
  UNIQUE (tenant_id, id, resource_id, action);

ALTER TABLE agent_credentials
  ADD CONSTRAINT agent_credentials_tenant_id_id_agent_principal_id_unique
  UNIQUE (tenant_id, id, agent_principal_id);

CREATE TABLE execution_audit_events (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  authorization_request_id uuid NOT NULL,
  correlation_id text NOT NULL
    CHECK (btrim(correlation_id) <> '' AND char_length(correlation_id) <= 128),
  agent_principal_id uuid NOT NULL,
  -- A catalog identifier is used instead of an unbounded external tool name.
  tool_id uuid NOT NULL,
  capability_id uuid NOT NULL,
  resource_id uuid NOT NULL,
  action text NOT NULL CHECK (action IN ('READ', 'WRITE', 'EXECUTE', 'DELETE')),
  policy_id uuid,
  policy_version integer,
  -- This is an enrollment credential identity only, never bearer/verifier data.
  agent_credential_id uuid,
  event_kind text NOT NULL CHECK (event_kind IN (
    'LEASE_ISSUED',
    'LEASE_REDEEMED',
    'REDEMPTION_DENIED',
    'AUTHORITY_CHANGED',
    'CONNECTION_UNAVAILABLE',
    'PROVIDER_REJECTED',
    'PROVIDER_UNAVAILABLE',
    'EXECUTION_COMPLETED',
    'COMPLETION_UNKNOWN'
  )),
  safe_outcome text NOT NULL CHECK (safe_outcome IN (
    'ISSUED',
    'REDEEMED',
    'DENIED_UNKNOWN_LEASE',
    'DENIED_EXPIRED',
    'DENIED_ALREADY_REDEEMED',
    'DENIED_WRONG_AUDIENCE',
    'DENIED_AUTHORITY_CHANGED',
    'DENIED_CONNECTION_UNAVAILABLE',
    'FAILED_PROVIDER_REJECTED',
    'FAILED_PROVIDER_UNAVAILABLE',
    'COMPLETED',
    'UNKNOWN'
  )),
  -- Event producers must supply the actual lifecycle time; a write-time
  -- default could incorrectly make a delayed persistence appear contemporaneous.
  occurred_at timestamptz NOT NULL,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, authorization_request_id, correlation_id)
    REFERENCES authorization_requests(tenant_id, id, correlation_id),
  FOREIGN KEY (tenant_id, agent_principal_id)
    REFERENCES agents(tenant_id, principal_id),
  FOREIGN KEY (tenant_id, tool_id)
    REFERENCES tools(tenant_id, resource_id),
  -- Every recorded tool/capability pair must exist in the tenant catalog.
  FOREIGN KEY (tenant_id, tool_id, capability_id)
    REFERENCES tool_capability_mappings(tenant_id, tool_id, capability_id),
  FOREIGN KEY (tenant_id, capability_id, resource_id, action)
    REFERENCES capabilities(tenant_id, id, resource_id, action),
  FOREIGN KEY (tenant_id, resource_id)
    REFERENCES resources(tenant_id, id),
  FOREIGN KEY (tenant_id, policy_id, policy_version)
    REFERENCES policies(tenant_id, id, version),
  FOREIGN KEY (tenant_id, agent_credential_id, agent_principal_id)
    REFERENCES agent_credentials(tenant_id, id, agent_principal_id),
  CHECK (
    (policy_id IS NULL AND policy_version IS NULL)
    OR (policy_id IS NOT NULL AND policy_version IS NOT NULL)
  ),
  -- Event kind and outcome are a closed vocabulary, not provider-supplied text.
  CHECK (
    (event_kind = 'LEASE_ISSUED' AND safe_outcome = 'ISSUED')
    OR (event_kind = 'LEASE_REDEEMED' AND safe_outcome = 'REDEEMED')
    OR (
      event_kind = 'REDEMPTION_DENIED'
      AND safe_outcome IN (
        'DENIED_UNKNOWN_LEASE',
        'DENIED_EXPIRED',
        'DENIED_ALREADY_REDEEMED',
        'DENIED_WRONG_AUDIENCE'
      )
    )
    OR (event_kind = 'AUTHORITY_CHANGED' AND safe_outcome = 'DENIED_AUTHORITY_CHANGED')
    OR (event_kind = 'CONNECTION_UNAVAILABLE' AND safe_outcome = 'DENIED_CONNECTION_UNAVAILABLE')
    OR (event_kind = 'PROVIDER_REJECTED' AND safe_outcome = 'FAILED_PROVIDER_REJECTED')
    OR (event_kind = 'PROVIDER_UNAVAILABLE' AND safe_outcome = 'FAILED_PROVIDER_UNAVAILABLE')
    OR (event_kind = 'EXECUTION_COMPLETED' AND safe_outcome = 'COMPLETED')
    OR (event_kind = 'COMPLETION_UNKNOWN' AND safe_outcome = 'UNKNOWN')
  )
);

-- AuthorizationEvidence contains an ordered vector. A PostgreSQL UUID array
-- cannot enforce each element's tenant-scoped delegation FK, so preserve the
-- complete ordered chain in a normalized child table instead.
CREATE TABLE execution_audit_event_delegations (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  execution_audit_event_id uuid NOT NULL,
  delegation_position smallint NOT NULL CHECK (delegation_position BETWEEN 0 AND 63),
  delegation_id uuid NOT NULL,
  PRIMARY KEY (tenant_id, execution_audit_event_id, delegation_position),
  UNIQUE (tenant_id, execution_audit_event_id, delegation_id),
  FOREIGN KEY (tenant_id, execution_audit_event_id)
    REFERENCES execution_audit_events(tenant_id, id),
  FOREIGN KEY (tenant_id, delegation_id)
    REFERENCES delegations(tenant_id, id)
);

-- Request history and the UI's tenant-scoped, cursor-bounded history view.
CREATE INDEX execution_audit_events_tenant_request_occurred_idx
  ON execution_audit_events (tenant_id, authorization_request_id, occurred_at DESC, id DESC);
CREATE INDEX execution_audit_events_tenant_occurred_idx
  ON execution_audit_events (tenant_id, occurred_at DESC, id DESC);
CREATE INDEX execution_audit_event_delegations_tenant_delegation_idx
  ON execution_audit_event_delegations (tenant_id, delegation_id);

ALTER TABLE execution_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE execution_audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON execution_audit_events
  USING (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid);

ALTER TABLE execution_audit_event_delegations ENABLE ROW LEVEL SECURITY;
ALTER TABLE execution_audit_event_delegations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON execution_audit_event_delegations
  USING (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid);
