-- Auth.ai durable state. Authorization semantics remain in the pure kernel;
-- these constraints and RLS policies provide persistence-layer defense in depth.

CREATE TABLE tenants (
  id uuid PRIMARY KEY,
  name text NOT NULL CHECK (btrim(name) <> ''),
  slug text NOT NULL UNIQUE CHECK (slug = lower(slug) AND slug ~ '^[a-z0-9][a-z0-9-]*$'),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE principals (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  kind text NOT NULL CHECK (kind IN ('HUMAN', 'AGENT', 'SERVICE')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, id, kind)
);

CREATE TABLE human_identities (
  tenant_id uuid NOT NULL,
  principal_id uuid PRIMARY KEY,
  principal_kind text NOT NULL DEFAULT 'HUMAN' CHECK (principal_kind = 'HUMAN'),
  external_id text,
  identity_provider text,
  FOREIGN KEY (tenant_id, principal_id, principal_kind) REFERENCES principals(tenant_id, id, kind),
  CHECK ((external_id IS NULL) = (identity_provider IS NULL))
);

CREATE TABLE agents (
  tenant_id uuid NOT NULL,
  principal_id uuid PRIMARY KEY,
  principal_kind text NOT NULL DEFAULT 'AGENT' CHECK (principal_kind = 'AGENT'),
  name text NOT NULL CHECK (btrim(name) <> ''),
  description text,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, principal_id, principal_kind) REFERENCES principals(tenant_id, id, kind)
);

CREATE TABLE models (
  id uuid PRIMARY KEY,
  provider text NOT NULL CHECK (btrim(provider) <> ''),
  model_name text NOT NULL CHECK (btrim(model_name) <> ''),
  version text,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE resources (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  resource_type text NOT NULL CHECK (btrim(resource_type) <> ''),
  name text,
  provider text,
  parent_resource_id uuid,
  external_id text,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, parent_resource_id) REFERENCES resources(tenant_id, id)
);

CREATE TABLE tools (
  tenant_id uuid NOT NULL,
  resource_id uuid NOT NULL,
  protocol text NOT NULL CHECK (btrim(protocol) <> ''),
  input_schema jsonb,
  output_schema jsonb,
  description text,
  danger_level text,
  PRIMARY KEY (tenant_id, resource_id),
  FOREIGN KEY (tenant_id, resource_id) REFERENCES resources(tenant_id, id)
);

CREATE TABLE capabilities (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  namespace text NOT NULL CHECK (btrim(namespace) <> ''),
  name text NOT NULL CHECK (btrim(name) <> ''),
  description text,
  parent_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, namespace, name),
  FOREIGN KEY (tenant_id, parent_id) REFERENCES capabilities(tenant_id, id)
);

CREATE TABLE tool_capability_mappings (
  tenant_id uuid NOT NULL,
  tool_id uuid NOT NULL,
  capability_id uuid NOT NULL,
  mapping_source text NOT NULL CHECK (mapping_source IN ('PROVIDER_DEFINED', 'SERVER_DECLARED', 'CUSTOMER_DEFINED', 'AUTHAI_SUGGESTED')),
  confidence text,
  trusted boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, tool_id, capability_id),
  FOREIGN KEY (tenant_id, tool_id) REFERENCES tools(tenant_id, resource_id),
  FOREIGN KEY (tenant_id, capability_id) REFERENCES capabilities(tenant_id, id),
  CHECK (mapping_source <> 'AUTHAI_SUGGESTED' OR trusted = false)
);

CREATE TABLE connections (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  provider text NOT NULL CHECK (btrim(provider) <> ''),
  external_account_id text,
  owner_principal_id uuid,
  status text NOT NULL CHECK (status IN ('ACTIVE', 'DISABLED', 'ERROR')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, owner_principal_id) REFERENCES principals(tenant_id, id)
);

CREATE TABLE credential_references (
  tenant_id uuid NOT NULL,
  connection_id uuid PRIMARY KEY,
  secret_reference text NOT NULL CHECK (btrim(secret_reference) <> ''),
  credential_type text NOT NULL CHECK (btrim(credential_type) <> ''),
  expires_at timestamptz,
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections(tenant_id, id)
);

CREATE TABLE policies (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  name text NOT NULL CHECK (btrim(name) <> ''),
  version integer NOT NULL CHECK (version > 0),
  status text NOT NULL CHECK (status IN ('DRAFT', 'ACTIVE', 'RETIRED')),
  definition jsonb NOT NULL CHECK (jsonb_typeof(definition) = 'object'),
  created_by uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, id, version),
  UNIQUE (tenant_id, name, version),
  FOREIGN KEY (tenant_id, created_by) REFERENCES principals(tenant_id, id)
);

CREATE TABLE policy_bindings (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  policy_id uuid NOT NULL,
  subject_principal_id uuid,
  resource_id uuid,
  priority integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, policy_id) REFERENCES policies(tenant_id, id),
  FOREIGN KEY (tenant_id, subject_principal_id) REFERENCES principals(tenant_id, id),
  FOREIGN KEY (tenant_id, resource_id) REFERENCES resources(tenant_id, id),
  CHECK (subject_principal_id IS NOT NULL OR resource_id IS NOT NULL)
);

CREATE TABLE delegations (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  grantor_principal_id uuid NOT NULL,
  grantee_principal_id uuid NOT NULL,
  parent_delegation_id uuid,
  constraints jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(constraints) = 'object'),
  valid_from timestamptz NOT NULL,
  expires_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, grantor_principal_id) REFERENCES principals(tenant_id, id),
  FOREIGN KEY (tenant_id, grantee_principal_id) REFERENCES principals(tenant_id, id),
  FOREIGN KEY (tenant_id, parent_delegation_id) REFERENCES delegations(tenant_id, id),
  CHECK (grantor_principal_id <> grantee_principal_id),
  CHECK (expires_at IS NULL OR expires_at > valid_from),
  CHECK (revoked_at IS NULL OR revoked_at >= valid_from)
);

CREATE TABLE delegated_capabilities (
  tenant_id uuid NOT NULL,
  delegation_id uuid NOT NULL,
  capability_id uuid NOT NULL,
  resource_id uuid NOT NULL,
  actions text[] NOT NULL CHECK (cardinality(actions) > 0),
  PRIMARY KEY (tenant_id, delegation_id, capability_id, resource_id),
  FOREIGN KEY (tenant_id, delegation_id) REFERENCES delegations(tenant_id, id),
  FOREIGN KEY (tenant_id, capability_id) REFERENCES capabilities(tenant_id, id),
  FOREIGN KEY (tenant_id, resource_id) REFERENCES resources(tenant_id, id),
  CHECK (actions <@ ARRAY['READ', 'WRITE', 'EXECUTE', 'DELETE']::text[])
);

CREATE TABLE authorization_requests (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  subject_principal_id uuid NOT NULL,
  model_id uuid REFERENCES models(id),
  resource_id uuid NOT NULL,
  action text NOT NULL CHECK (action IN ('READ', 'WRITE', 'EXECUTE', 'DELETE')),
  context jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(context) = 'object'),
  correlation_id text NOT NULL CHECK (btrim(correlation_id) <> ''),
  requested_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, subject_principal_id) REFERENCES principals(tenant_id, id),
  FOREIGN KEY (tenant_id, resource_id) REFERENCES resources(tenant_id, id)
);

CREATE TABLE authorization_decisions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  request_id uuid NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('ALLOW', 'DENY', 'REQUIRE_APPROVAL')),
  reason_code text NOT NULL CHECK (btrim(reason_code) <> ''),
  policy_id uuid,
  policy_version integer CHECK (policy_version IS NULL OR policy_version > 0),
  delegation_id uuid,
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(evidence) = 'object'),
  decided_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, request_id) REFERENCES authorization_requests(tenant_id, id),
  FOREIGN KEY (tenant_id, policy_id, policy_version) REFERENCES policies(tenant_id, id, version) MATCH FULL,
  FOREIGN KEY (tenant_id, delegation_id) REFERENCES delegations(tenant_id, id)
);

CREATE TABLE audit_events (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  correlation_id text NOT NULL CHECK (btrim(correlation_id) <> ''),
  event_type text NOT NULL CHECK (btrim(event_type) <> ''),
  actor_principal_id uuid,
  payload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, actor_principal_id) REFERENCES principals(tenant_id, id)
);

CREATE INDEX principals_tenant_kind_idx ON principals (tenant_id, kind);
CREATE UNIQUE INDEX human_identities_external_idx
  ON human_identities (tenant_id, identity_provider, external_id)
  WHERE external_id IS NOT NULL;
CREATE INDEX resources_tenant_type_idx ON resources (tenant_id, resource_type);
CREATE INDEX delegations_active_idx ON delegations (tenant_id, grantee_principal_id, valid_from, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX authorization_requests_correlation_idx ON authorization_requests (tenant_id, correlation_id);
CREATE INDEX audit_events_tenant_occurred_idx ON audit_events (tenant_id, occurred_at DESC);

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants
  USING (id = nullif(current_setting('authai.tenant_id', true), '')::uuid)
  WITH CHECK (id = nullif(current_setting('authai.tenant_id', true), '')::uuid);

-- Application transactions must first execute:
--   SELECT set_config('authai.tenant_id', '<tenant uuid>', true)
-- Missing or malformed tenant context denies access rather than widening it.
DO $rls$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'principals', 'human_identities', 'agents', 'resources', 'tools',
    'capabilities', 'tool_capability_mappings', 'connections',
    'credential_references', 'policies', 'policy_bindings', 'delegations',
    'delegated_capabilities', 'authorization_requests',
    'authorization_decisions', 'audit_events'
  ]
  LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = nullif(current_setting(''authai.tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = nullif(current_setting(''authai.tenant_id'', true), '''')::uuid)',
      table_name
    );
  END LOOP;
END
$rls$;
