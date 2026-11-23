-- connection roots, runtime
-- resource selection, and generic OAuth and credential rows.
--
-- The resource hierarchy is: the owner-provisioned provider catalog resource
-- (kind IS NULL), then one connection root created at runtime when a
-- connection is made, then the children an administrator selects under it.
-- Owner policies stay on the catalog resource and cover everything below it
-- through the kernel's trusted scope.

-- 1. Resource kinds: global, code-defined reference data. Each provider
--    registers its kinds here in a new migration; the application's operation
--    registry must agree (checked at startup).
CREATE TABLE resource_kinds (
  wire text PRIMARY KEY CHECK (wire ~ '^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$'),
  provider text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9]{1,31}$'),
  parent_wire text REFERENCES resource_kinds(wire),
  resource_type text NOT NULL CHECK (resource_type NOT IN ('PROVIDER', 'TOOL') AND btrim(resource_type) <> ''),
  -- Declared on roots only; descendants inherit their root's custody.
  custody text CHECK (custody IN ('WORKSPACE', 'PERSONAL')),
  CHECK ((parent_wire IS NULL) = (custody IS NOT NULL)),
  CHECK (starts_with(wire, provider || '.'))
);

INSERT INTO resource_kinds (wire, provider, parent_wire, resource_type, custody)
VALUES ('slack.workspace', 'slack', NULL, 'ACCOUNT', 'WORKSPACE');

-- A child kind's provider must be its parent's provider.
CREATE FUNCTION authai_check_resource_kind() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, public
AS $$
BEGIN
  IF NEW.parent_wire IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM public.resource_kinds p WHERE p.wire = NEW.parent_wire AND p.provider = NEW.provider
  ) THEN
    RAISE EXCEPTION 'a resource kind''s parent must belong to the same provider' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER resource_kinds_provider_lineage
  BEFORE INSERT OR UPDATE ON resource_kinds
  FOR EACH ROW EXECUTE FUNCTION authai_check_resource_kind();

-- 2. Resources gain their kind, the connection they were selected through, and
--    their custodian. Catalog rows keep all three NULL.
ALTER TABLE resources
  ADD COLUMN kind text REFERENCES resource_kinds(wire),
  ADD COLUMN connection_id uuid,
  ADD COLUMN custodian_principal_id uuid,
  -- Set by the insert trigger, never by the caller; one root per connection.
  ADD COLUMN connection_root boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT resources_connection_fk
    FOREIGN KEY (tenant_id, connection_id) REFERENCES connections(tenant_id, id),
  ADD CONSTRAINT resources_custodian_fk
    FOREIGN KEY (tenant_id, custodian_principal_id) REFERENCES principals(tenant_id, id),
  ADD CONSTRAINT resources_kind_connection_check CHECK ((kind IS NULL) = (connection_id IS NULL)),
  ADD CONSTRAINT resources_kind_external_id_check CHECK (kind IS NULL OR (external_id IS NOT NULL AND btrim(external_id) <> '')),
  ADD CONSTRAINT resources_root_kind_check CHECK (NOT connection_root OR kind IS NOT NULL),
  ADD CONSTRAINT resources_connection_external_key UNIQUE (tenant_id, connection_id, kind, external_id),
  -- Target of connection_resources' composite key, so a selection always names
  -- the resource's own connection, kind, and external ID.
  ADD CONSTRAINT resources_selection_key UNIQUE (tenant_id, id, connection_id, kind, external_id);

CREATE UNIQUE INDEX resources_one_root_per_connection_idx
  ON resources (tenant_id, connection_id) WHERE connection_root;

-- Resource placement: the runtime role may insert only connection-scoped resources, and only
-- where the catalog says they belong. Catalog rows (kind IS NULL) may be
-- inserted only by the table owner, which is the migration and provisioning
-- role. The function runs as the caller, so its lookups are subject to the
-- same tenant row-level security as the insert.
CREATE FUNCTION authai_check_resource_insert() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, public
AS $$
DECLARE
  table_owner oid;
  registered public.resource_kinds%ROWTYPE;
  connection_provider text;
  connection_status text;
  connection_owner uuid;
  parent_kind text;
  parent_connection uuid;
  parent_custodian uuid;
  custodian_kind text;
BEGIN
  SELECT relowner INTO table_owner FROM pg_catalog.pg_class WHERE oid = TG_RELID;
  NEW.connection_root := false;

  IF NEW.kind IS NULL THEN
    IF NEW.custodian_principal_id IS NOT NULL THEN
      RAISE EXCEPTION 'a catalog resource has no custodian' USING ERRCODE = '23514';
    END IF;
    IF NOT pg_catalog.pg_has_role(current_user, table_owner, 'USAGE') THEN
      RAISE EXCEPTION 'catalog resources are provisioned by the owner' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
  END IF;

  SELECT * INTO registered FROM public.resource_kinds WHERE wire = NEW.kind;
  IF NOT FOUND OR NEW.resource_type <> registered.resource_type THEN
    RAISE EXCEPTION 'resource type does not match its registered kind' USING ERRCODE = '23514';
  END IF;

  SELECT lower(c.provider), c.status, c.owner_principal_id
    INTO connection_provider, connection_status, connection_owner
    FROM public.connections c
   WHERE c.tenant_id = NEW.tenant_id AND c.id = NEW.connection_id;
  IF NOT FOUND OR connection_status <> 'ACTIVE' THEN
    RAISE EXCEPTION 'resources are added only under an active connection' USING ERRCODE = '23514';
  END IF;
  IF connection_provider <> registered.provider THEN
    RAISE EXCEPTION 'resource kind is not registered for the connection''s provider' USING ERRCODE = '23514';
  END IF;

  IF registered.parent_wire IS NULL THEN
    -- A connection root sits directly under its provider's catalog resource.
    IF NOT EXISTS (
      SELECT 1 FROM public.resources p
       WHERE p.tenant_id = NEW.tenant_id AND p.id = NEW.parent_resource_id
         AND p.kind IS NULL AND p.resource_type = 'PROVIDER'
         AND lower(p.provider) = registered.provider AND p.parent_resource_id IS NULL
    ) THEN
      RAISE EXCEPTION 'a connection root must be under its provider''s catalog resource' USING ERRCODE = '23514';
    END IF;
    IF registered.custody = 'PERSONAL' THEN
      SELECT p.kind INTO custodian_kind FROM public.principals p
       WHERE p.tenant_id = NEW.tenant_id AND p.id = NEW.custodian_principal_id;
      IF NEW.custodian_principal_id IS NULL OR connection_owner IS NULL
         OR NEW.custodian_principal_id <> connection_owner OR custodian_kind IS DISTINCT FROM 'HUMAN' THEN
        RAISE EXCEPTION 'a personal root''s custodian is the human who owns the connection' USING ERRCODE = '23514';
      END IF;
    ELSIF NEW.custodian_principal_id IS NOT NULL THEN
      RAISE EXCEPTION 'a workspace root has no custodian' USING ERRCODE = '23514';
    END IF;
    NEW.connection_root := true;
  ELSE
    -- A child sits under a resource of its registered parent kind, through the
    -- same connection, and inherits that resource's custody exactly.
    SELECT p.kind, p.connection_id, p.custodian_principal_id
      INTO parent_kind, parent_connection, parent_custodian
      FROM public.resources p
     WHERE p.tenant_id = NEW.tenant_id AND p.id = NEW.parent_resource_id;
    IF NOT FOUND OR parent_kind IS DISTINCT FROM registered.parent_wire
       OR parent_connection IS DISTINCT FROM NEW.connection_id THEN
      RAISE EXCEPTION 'a selected resource must be under its registered parent kind in the same connection' USING ERRCODE = '23514';
    END IF;
    IF NEW.custodian_principal_id IS DISTINCT FROM parent_custodian THEN
      RAISE EXCEPTION 'a selected resource inherits its parent''s custody' USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER resources_insert_check
  BEFORE INSERT ON resources
  FOR EACH ROW EXECUTE FUNCTION authai_check_resource_insert();

-- 3. Selections. A resource below a root is addressable only while it has an
--    open selection; deselection closes the row and never deletes it.
CREATE TABLE connection_resources (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  connection_id uuid NOT NULL,
  resource_id uuid NOT NULL,
  kind text NOT NULL,
  external_id text NOT NULL,
  selected_by uuid NOT NULL,
  selected_at timestamptz NOT NULL,
  deselected_at timestamptz,
  PRIMARY KEY (tenant_id, resource_id, selected_at),
  FOREIGN KEY (tenant_id, connection_id) REFERENCES connections(tenant_id, id),
  FOREIGN KEY (tenant_id, resource_id, connection_id, kind, external_id)
    REFERENCES resources(tenant_id, id, connection_id, kind, external_id),
  FOREIGN KEY (tenant_id, selected_by) REFERENCES principals(tenant_id, id),
  CHECK (deselected_at IS NULL OR deselected_at >= selected_at)
);

-- At most one open selection per resource, and each external resource
-- open under at most one connection per tenant, so resolving a reference is
-- never ambiguous.
CREATE UNIQUE INDEX connection_resources_open_resource_idx
  ON connection_resources (tenant_id, resource_id) WHERE deselected_at IS NULL;
CREATE UNIQUE INDEX connection_resources_open_external_idx
  ON connection_resources (tenant_id, kind, external_id) WHERE deselected_at IS NULL;

ALTER TABLE connection_resources ENABLE ROW LEVEL SECURITY;
ALTER TABLE connection_resources FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON connection_resources
  USING (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid);

-- Deselection is one-way: only deselected_at may change, and only from NULL.
CREATE FUNCTION authai_check_selection_update() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, public
AS $$
BEGIN
  IF OLD.deselected_at IS NOT NULL OR NEW.deselected_at IS NULL
     OR (NEW.tenant_id, NEW.connection_id, NEW.resource_id, NEW.kind, NEW.external_id, NEW.selected_by, NEW.selected_at)
        IS DISTINCT FROM
        (OLD.tenant_id, OLD.connection_id, OLD.resource_id, OLD.kind, OLD.external_id, OLD.selected_by, OLD.selected_at)
  THEN
    RAISE EXCEPTION 'a selection can only be closed, once' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER connection_resources_close_only
  BEFORE UPDATE ON connection_resources
  FOR EACH ROW EXECUTE FUNCTION authai_check_selection_update();

-- 4. Connections: at most one active connection per external root
--    account. connections_active_resource_idx stays while Slack uses the shared
--    catalog root; dropping it would let two active Slack
--    connections share one resource.
CREATE UNIQUE INDEX connections_active_account_idx
  ON connections (tenant_id, provider, external_account_id)
  WHERE status = 'ACTIVE' AND external_account_id IS NOT NULL;

-- 5. Generic OAuth state: any registered provider, bound to an intended
--    connection, a PKCE verifier held in the secret store (never plaintext),
--    and a digest of the redirect it was issued for.
ALTER TABLE oauth_states DROP CONSTRAINT oauth_states_provider_check;
ALTER TABLE oauth_states
  ADD CONSTRAINT oauth_states_provider_check
    CHECK (provider IN ('SLACK', 'GITHUB', 'LINEAR', 'NOTION', 'GOOGLE', 'HUBSPOT')),
  ADD COLUMN intended_connection_id uuid,
  ADD COLUMN pkce_verifier_reference text CHECK (pkce_verifier_reference ~ '^sec_[A-Za-z0-9_-]{22,128}$'),
  ADD COLUMN redirect_binding_digest bytea CHECK (octet_length(redirect_binding_digest) = 32);

-- 6. Credential references: a closed set of credential shapes. Refresh
--    repoints secret_reference at a new, insert-only secret version.
ALTER TABLE credential_references
  ADD CONSTRAINT credential_references_type_check
    CHECK (credential_type IN ('SLACK_OAUTH', 'OAUTH_REFRESHABLE', 'GITHUB_APP_INSTALLATION'));
