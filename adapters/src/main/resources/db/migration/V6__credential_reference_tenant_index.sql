-- Keep tenant-scoped credential-reference lookups and composite-FK checks indexed.
CREATE INDEX credential_references_tenant_connection_idx
  ON credential_references (tenant_id, connection_id);
