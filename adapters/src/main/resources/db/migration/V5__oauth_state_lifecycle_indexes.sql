-- OAuth state is short-lived and one-time. These tenant-first indexes bound callback lookup and lifecycle cleanup.
CREATE INDEX IF NOT EXISTS oauth_states_expiry_cleanup_idx ON oauth_states (tenant_id, expires_at);
CREATE INDEX IF NOT EXISTS oauth_states_consumed_cleanup_idx ON oauth_states (tenant_id, consumed_at) WHERE consumed_at IS NOT NULL;
