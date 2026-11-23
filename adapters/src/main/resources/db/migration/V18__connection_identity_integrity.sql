-- Keep the applied V17 migration immutable. OAuth intent is tenant-bound, and
-- provider casing cannot create a second active connection to the same account.
ALTER TABLE oauth_states
  ADD CONSTRAINT oauth_states_intended_connection_fk
  FOREIGN KEY (tenant_id, intended_connection_id) REFERENCES connections(tenant_id, id);

DROP INDEX connections_active_account_idx;
CREATE UNIQUE INDEX connections_active_account_idx
  ON connections (tenant_id, lower(provider), external_account_id)
  WHERE status = 'ACTIVE' AND external_account_id IS NOT NULL;
