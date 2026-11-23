-- OAuth lifecycle state and a resource-bound connection. Credentials remain
-- outside PostgreSQL; credential_references stores only an opaque reference.
ALTER TABLE connections
  ADD COLUMN resource_id uuid,
  ADD COLUMN workspace_label text,
  ADD COLUMN token_expires_at timestamptz,
  ADD CONSTRAINT connections_resource_fk FOREIGN KEY (tenant_id, resource_id) REFERENCES resources(tenant_id, id);

ALTER TABLE connections DROP CONSTRAINT connections_status_check;
ALTER TABLE connections ADD CONSTRAINT connections_status_check
  CHECK (status IN ('CONNECTING', 'ACTIVE', 'DISABLED', 'ERROR'));

CREATE UNIQUE INDEX connections_active_resource_idx
  ON connections (tenant_id, resource_id)
  WHERE status = 'ACTIVE' AND resource_id IS NOT NULL;

CREATE TABLE oauth_states (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  state_hash bytea NOT NULL CHECK (octet_length(state_hash) = 32),
  provider text NOT NULL CHECK (provider = 'SLACK'),
  resource_id uuid NOT NULL,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, state_hash),
  FOREIGN KEY (tenant_id, resource_id) REFERENCES resources(tenant_id, id),
  CHECK (expires_at > created_at)
);

ALTER TABLE oauth_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_states FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_states
  USING (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid);
