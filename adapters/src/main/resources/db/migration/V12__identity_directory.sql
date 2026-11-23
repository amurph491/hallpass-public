-- Identity directory: the pre-tenant lookups that forced RLS otherwise makes
-- impossible. Agent bearer credentials carry only a selector, and an external
-- login carries only (issuer, subject); both must be routed to a tenant before
-- any tenant-owned row can be read.
--
-- These tables are deliberately not tenant-scoped by RLS policy, so they are
-- closed instead:
--   * the runtime role has no privileges on them (afterMigrate.sql grants none);
--   * RLS is enabled with no policy, so any non-owner sees no rows even if a
--     stray grant appears;
--   * the runtime role reaches them only through the SECURITY DEFINER
--     functions below, which return routing data (tenant, user, principal,
--     role) and never verifier material or tenant data.
--
-- A routing answer is not authentication. An agent credential is authenticated
-- only by the tenant-bound HMAC verification inside the routed tenant, so a
-- route pointing at the wrong tenant still fails.

CREATE TABLE directory_users (
  id uuid PRIMARY KEY,
  status text NOT NULL CHECK (status IN ('ACTIVE', 'DISABLED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  disabled_at timestamptz,
  CHECK ((status = 'DISABLED') = (disabled_at IS NOT NULL))
);

-- An identity-provider account, keyed by the provider's issuer and its stable
-- subject. It never contains a credential.
CREATE TABLE directory_external_identities (
  issuer text NOT NULL CHECK (btrim(issuer) = issuer AND issuer <> '' AND char_length(issuer) <= 512),
  subject text NOT NULL CHECK (btrim(subject) = subject AND subject <> '' AND char_length(subject) <= 255),
  user_id uuid NOT NULL REFERENCES directory_users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (issuer, subject)
);
CREATE INDEX directory_external_identities_user_idx ON directory_external_identities (user_id);

-- A user's standing in one tenant. The human principal is the tenant-owned
-- identity that authority (policies, delegations) is attached to; the composite
-- key keeps a membership from naming another tenant's principal.
CREATE TABLE directory_tenant_memberships (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  user_id uuid NOT NULL REFERENCES directory_users(id),
  human_principal_id uuid NOT NULL,
  role text NOT NULL CHECK (role IN ('ADMIN', 'MEMBER')),
  status text NOT NULL CHECK (status IN ('ACTIVE', 'REMOVED')),
  created_at timestamptz NOT NULL DEFAULT now(),
  removed_at timestamptz,
  PRIMARY KEY (tenant_id, user_id),
  UNIQUE (tenant_id, human_principal_id),
  FOREIGN KEY (tenant_id, human_principal_id) REFERENCES human_identities(tenant_id, principal_id),
  CHECK ((status = 'REMOVED') = (removed_at IS NOT NULL))
);
CREATE INDEX directory_tenant_memberships_user_idx ON directory_tenant_memberships (user_id);

-- Selector -> tenant for unrevoked agent credentials. The primary key makes a
-- selector route to at most one tenant: a colliding selector in a second
-- tenant fails that enrollment rather than making routing ambiguous.
CREATE TABLE directory_agent_credential_routes (
  selector text PRIMARY KEY CHECK (selector ~ '^[A-Za-z0-9_-]{16,32}$'),
  tenant_id uuid NOT NULL,
  credential_id uuid NOT NULL,
  UNIQUE (tenant_id, credential_id),
  FOREIGN KEY (tenant_id, credential_id) REFERENCES agent_credentials(tenant_id, id)
);

DO $directory$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'directory_users', 'directory_external_identities',
    'directory_tenant_memberships', 'directory_agent_credential_routes'
  ]
  LOOP
    -- Enabled but not forced, and without policies: the owning migration role
    -- (and the SECURITY DEFINER functions it owns) can use the table; every
    -- other role sees and changes nothing.
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
  END LOOP;
END
$directory$;

-- Keeps the route set equal to the unrevoked credentials, inside the same
-- transaction as the credential change. Because it is a trigger, no
-- application path can enroll, rotate, or revoke without updating routing.
CREATE FUNCTION authai_sync_agent_credential_route() RETURNS trigger
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    DELETE FROM public.directory_agent_credential_routes
     WHERE tenant_id = OLD.tenant_id AND credential_id = OLD.id;
  END IF;
  IF NEW.revoked_at IS NULL THEN
    INSERT INTO public.directory_agent_credential_routes (selector, tenant_id, credential_id)
    VALUES (NEW.selector, NEW.tenant_id, NEW.id);
  END IF;
  RETURN NULL;
END
$$;

CREATE TRIGGER agent_credentials_route_sync
  AFTER INSERT OR UPDATE OF revoked_at, selector, tenant_id ON agent_credentials
  FOR EACH ROW EXECUTE FUNCTION authai_sync_agent_credential_route();

-- Backfill routes for credentials that already exist. The migration owner is
-- subject to forced RLS, so it lifts the force for this one statement; the
-- transaction restores it before anything else can observe the table.
ALTER TABLE agent_credentials NO FORCE ROW LEVEL SECURITY;
INSERT INTO directory_agent_credential_routes (selector, tenant_id, credential_id)
SELECT selector, tenant_id, id FROM agent_credentials WHERE revoked_at IS NULL;
ALTER TABLE agent_credentials FORCE ROW LEVEL SECURITY;

-- Routing API for the runtime role. Each function is SECURITY DEFINER with a
-- pinned search_path and fully qualified names, and returns routing data only.

-- The candidate tenant for an agent credential selector, or NULL.
CREATE FUNCTION authai_agent_credential_tenant(p_selector text) RETURNS uuid
  LANGUAGE sql STABLE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  SELECT tenant_id FROM public.directory_agent_credential_routes WHERE selector = p_selector
$$;

-- The active user for an identity-provider account, or NULL. A disabled user
-- resolves to nothing.
CREATE FUNCTION authai_user_for_external_identity(p_issuer text, p_subject text) RETURNS uuid
  LANGUAGE sql STABLE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  SELECT u.id
    FROM public.directory_external_identities i
    JOIN public.directory_users u ON u.id = i.user_id
   WHERE i.issuer = p_issuer AND i.subject = p_subject AND u.status = 'ACTIVE'
$$;

-- The active memberships of an active user. A disabled user or a removed
-- membership yields no row.
CREATE FUNCTION authai_active_memberships(p_user_id uuid)
  RETURNS TABLE (tenant_id uuid, human_principal_id uuid, role text)
  LANGUAGE sql STABLE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  SELECT m.tenant_id, m.human_principal_id, m.role
    FROM public.directory_tenant_memberships m
    JOIN public.directory_users u ON u.id = m.user_id
   WHERE m.user_id = p_user_id AND m.status = 'ACTIVE' AND u.status = 'ACTIVE'
$$;

-- PostgreSQL grants EXECUTE to PUBLIC by default. afterMigrate.sql grants the
-- routing functions to the runtime role only.
REVOKE ALL ON FUNCTION authai_sync_agent_credential_route() FROM PUBLIC;
REVOKE ALL ON FUNCTION authai_agent_credential_tenant(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION authai_user_for_external_identity(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION authai_active_memberships(uuid) FROM PUBLIC;
