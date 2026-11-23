-- OAuth refresh: immutable encrypted versions, with a durable fail-closed marker
-- before a potentially rotating token request. A lost response requires reauth.
ALTER TABLE connections DROP CONSTRAINT connections_status_check;
ALTER TABLE connections ADD CONSTRAINT connections_status_check
  CHECK (status IN ('CONNECTING', 'ACTIVE', 'DISABLED', 'ERROR', 'NEEDS_REAUTH'));

-- The two narrowly updatable pointer columns were granted in V17's callback.
-- Credential type, connection and tenant remain immutable for the runtime role.
-- Secret references are opaque and also support the development file store;
-- therefore existence is checked by the store before publication, not a FK
-- limited to production's provider_secrets table.
