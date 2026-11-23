-- Kernel actions are security semantics and must not be inferred from capability names.
ALTER TABLE capabilities
  ADD COLUMN action text CHECK (action IN ('READ', 'WRITE', 'EXECUTE', 'DELETE')),
  ADD COLUMN resource_id uuid,
  ADD CONSTRAINT capabilities_resource_fk
    FOREIGN KEY (tenant_id, resource_id) REFERENCES resources(tenant_id, id);

-- Unmapped attempts still need durable evidence even though no trusted target
-- resource/action can be assigned to them.
ALTER TABLE authorization_requests
  ALTER COLUMN resource_id DROP NOT NULL,
  ALTER COLUMN action DROP NOT NULL;
