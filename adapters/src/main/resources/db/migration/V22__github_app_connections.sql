-- GitHub App installations.
--
-- 1. GitHub's resource kinds. The application's operation registry declares
--    the same kinds; the resource placement trigger (V17) uses this table to place
--    runtime-created roots and selected repositories.
INSERT INTO resource_kinds (wire, provider, parent_wire, resource_type, custody)
VALUES
  ('github.installation', 'github', NULL, 'ACCOUNT', 'WORKSPACE'),
  ('github.repository', 'github', 'github.installation', 'REPOSITORY', NULL);

-- 2. One tenant per external account, for providers whose account is not
--    owned by a tenant. A GitHub App installation belongs
--    to a GitHub organization or user, not to an Auth.ai tenant. Without this
--    rule, a member of the same organization could bind that organization's
--    installation to a second tenant. Within one tenant, V17/V18's active
--    account index already allows at most one active connection per account.
--
--    The claim lives in the identity directory: it is pre-tenant data that a
--    tenant-scoped transaction could not otherwise see across tenants. The
--    runtime role has no privileges on it; a SECURITY DEFINER trigger keeps it
--    equal to the claiming connections in the same transaction, the same
--    pattern as directory_agent_credential_routes (V12).
CREATE TABLE directory_connection_account_claims (
  provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9]{1,31}$'),
  external_account_id text NOT NULL CHECK (btrim(external_account_id) <> '' AND length(external_account_id) <= 256),
  tenant_id uuid NOT NULL,
  connection_id uuid NOT NULL,
  PRIMARY KEY (provider, external_account_id),
  UNIQUE (tenant_id, connection_id),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections(tenant_id, id)
);

-- Enabled but not forced, and without policies: only the owning migration
-- role and the SECURITY DEFINER functions it owns can use the table.
ALTER TABLE directory_connection_account_claims ENABLE ROW LEVEL SECURITY;

-- A connection claims its account while it is ACTIVE or NEEDS_REAUTH (a
-- reconnect of the same tenant's connection must not be stolen meanwhile).
-- A second tenant's activation then fails with a unique violation, inside the
-- transaction that tried to activate it. Only providers listed here claim
-- globally; every other provider's accounts may be connected by many tenants.
CREATE FUNCTION authai_sync_connection_account_claim() RETURNS trigger
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    DELETE FROM public.directory_connection_account_claims
     WHERE tenant_id = OLD.tenant_id AND connection_id = OLD.id;
  END IF;
  IF lower(NEW.provider) IN ('github')
     AND NEW.status IN ('ACTIVE', 'NEEDS_REAUTH')
     AND NEW.external_account_id IS NOT NULL THEN
    INSERT INTO public.directory_connection_account_claims (provider, external_account_id, tenant_id, connection_id)
    VALUES (lower(NEW.provider), NEW.external_account_id, NEW.tenant_id, NEW.id);
  END IF;
  RETURN NULL;
END
$$;

CREATE TRIGGER connections_account_claim_sync
  AFTER INSERT OR UPDATE OF status, external_account_id, provider, tenant_id ON connections
  FOR EACH ROW EXECUTE FUNCTION authai_sync_connection_account_claim();

-- No GitHub connection can exist before this migration, so there is nothing
-- to backfill.

REVOKE ALL ON FUNCTION authai_sync_connection_account_claim() FROM PUBLIC;
