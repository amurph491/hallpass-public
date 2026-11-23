-- Move connections from the shared provider catalog row to their own
-- provider-verified account root. The active external-account index remains
-- the uniqueness boundary; the legacy catalog-resource index would prevent
-- multiple connections to distinct roots for one provider.
-- A reservation has no provider-verified root yet. The root is attached after
-- OAuth succeeds, so resource_id must be nullable during that lifecycle.
ALTER TABLE connections ALTER COLUMN resource_id DROP NOT NULL;
ALTER TABLE connections ADD COLUMN account_label text;
DROP INDEX IF EXISTS connections_active_resource_idx;
