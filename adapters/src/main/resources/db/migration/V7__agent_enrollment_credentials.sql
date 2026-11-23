-- Local agent authentication credentials are distinct from provider credentials.
-- Only a keyed verifier and safe lifecycle metadata are durable; bearer plaintext
-- and secret-store references must never be persisted here.

-- The primary keys make each subtype globally identifiable, while these keys
-- make tenant-preserving subtype references enforceable in PostgreSQL.
ALTER TABLE human_identities
  ADD CONSTRAINT human_identities_tenant_principal_unique UNIQUE (tenant_id, principal_id);

ALTER TABLE agents
  ADD CONSTRAINT agents_tenant_principal_unique UNIQUE (tenant_id, principal_id);

CREATE TABLE agent_credentials (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  agent_principal_id uuid NOT NULL,
  selector text NOT NULL CHECK (selector ~ '^[A-Za-z0-9_-]{16,32}$'),
  verifier bytea NOT NULL CHECK (octet_length(verifier) = 32),
  verifier_algorithm text NOT NULL CHECK (verifier_algorithm = 'HMAC_SHA256_V1'),
  verifier_key_id text NOT NULL
    CHECK (btrim(verifier_key_id) <> '' AND char_length(verifier_key_id) <= 128),
  label text CHECK (label IS NULL OR (btrim(label) <> '' AND char_length(label) <= 120)),
  issued_by_human_principal_id uuid,
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz,
  revoked_at timestamptz,
  last_used_at timestamptz,
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, selector),
  FOREIGN KEY (tenant_id, agent_principal_id)
    REFERENCES agents(tenant_id, principal_id),
  FOREIGN KEY (tenant_id, issued_by_human_principal_id)
    REFERENCES human_identities(tenant_id, principal_id),
  CHECK (expires_at IS NULL OR expires_at > created_at),
  CHECK (revoked_at IS NULL OR revoked_at >= created_at),
  CHECK (last_used_at IS NULL OR last_used_at >= created_at)
);

-- Rotation revokes then inserts atomically. This index makes two live
-- credentials for an agent impossible while retaining historical metadata.
CREATE UNIQUE INDEX agent_credentials_one_unrevoked_per_agent_idx
  ON agent_credentials (tenant_id, agent_principal_id)
  WHERE revoked_at IS NULL;

-- Supports bounded credential-history views without relying on the active-row
-- uniqueness index, and keeps all tenant-scoped lookups indexed.
CREATE INDEX agent_credentials_tenant_agent_created_idx
  ON agent_credentials (tenant_id, agent_principal_id, created_at DESC);

ALTER TABLE agent_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_credentials
  USING (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid);
