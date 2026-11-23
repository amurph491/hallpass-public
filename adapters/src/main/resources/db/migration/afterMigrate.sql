-- Flyway afterMigrate callback: converges the runtime role's table privileges on
-- every migrate. It is not a versioned migration, so it may change; migrations
-- stay append-only.
--
-- The runtime role receives only the privileges the application uses. Audit and
-- decision evidence is append-only for it: INSERT and SELECT, never UPDATE or
-- DELETE. It never receives TRUNCATE, REFERENCES, or TRIGGER, and it owns
-- nothing, so it cannot disable row-level security. Schema USAGE (and the
-- absence of CREATE) is granted by the role bootstrap, not here.
--
-- A table missing from this matrix gets no privileges, so it fails closed, and
-- PostgresSchemaInvariantsSuite fails until the table is classified here.
--
-- In in-process development the runtime role is the migrating owner, so there
-- is nothing to grant and revoking would strip the owner's own privileges.
DO $$
DECLARE
  runtime_role text := '${runtime_role}';
  table_name text;
  function_signature text;
BEGIN
  IF runtime_role = current_user THEN
    RETURN;
  END IF;

  EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA public FROM %I', runtime_role);
  EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, %I', runtime_role);

  -- Lifecycle state the application updates in place.
  FOREACH table_name IN ARRAY ARRAY[
    'agent_credentials',
    'connections',
    'delegations'
  ] LOOP
    EXECUTE format('GRANT SELECT, INSERT, UPDATE ON %I TO %I', table_name, runtime_role);
  END LOOP;

  -- Envelope-encrypted provider secrets: written once, read by the trusted
  -- executor, and deleted when a connection cannot be created. Only the
  -- owner-run rewrap job updates them.
  IF to_regclass('public.provider_secrets') IS NOT NULL THEN
    EXECUTE format('GRANT SELECT, INSERT, DELETE ON provider_secrets TO %I', runtime_role);
  END IF;

  -- Runtime-selected resources and their selections (V17). A resource row is
  -- insert-only, and its insert trigger admits only connection-scoped rows in
  -- their registered place. A selection is closed by setting deselected_at
  -- once (enforced by trigger) and never deleted.
  IF to_regclass('public.connection_resources') IS NOT NULL THEN
    EXECUTE format('GRANT SELECT, INSERT ON resources TO %I', runtime_role);
    EXECUTE format('GRANT SELECT, INSERT ON connection_resources TO %I', runtime_role);
    EXECUTE format('GRANT UPDATE (deselected_at) ON connection_resources TO %I', runtime_role);
    -- Token refresh repoints a connection at a new, insert-only secret version.
    EXECUTE format('GRANT UPDATE (secret_reference, expires_at) ON credential_references TO %I', runtime_role);
    -- Code-defined resource kinds; global reference data.
    EXECUTE format('GRANT SELECT ON resource_kinds TO %I', runtime_role);
  END IF;

  -- Approvals (V24): created by agent calls, decided once by their approver,
  -- consumed once by the approved retry. Never deleted.
  IF to_regclass('public.approvals') IS NOT NULL THEN
    EXECUTE format('GRANT SELECT, INSERT ON approvals TO %I', runtime_role);
    EXECUTE format('GRANT UPDATE (status, decided_by, decided_at, consumed_at, consumed_request_id) ON approvals TO %I', runtime_role);
  END IF;

  -- Single-use OAuth state is consumed by deletion.
  EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_states TO %I', runtime_role);

  -- Agent identities and grant records the application creates but never
  -- modifies.
  FOREACH table_name IN ARRAY ARRAY[
    'principals',
    'agents',
    'credential_references',
    'delegated_capabilities'
  ] LOOP
    EXECUTE format('GRANT SELECT, INSERT ON %I TO %I', table_name, runtime_role);
  END LOOP;

  -- Tenants, human identities, the provider catalog, and policies are
  -- provisioned by AuthAiProvisionMain as the owner. The API only reads them.
  -- (Before V17, resources is read-only too.)
  IF to_regclass('public.connection_resources') IS NULL THEN
    EXECUTE format('GRANT SELECT ON resources TO %I', runtime_role);
  END IF;
  FOREACH table_name IN ARRAY ARRAY[
    'tenants',
    'human_identities',
    'tools',
    'capabilities',
    'tool_capability_mappings',
    'policies',
    'policy_bindings'
  ] LOOP
    EXECUTE format('GRANT SELECT ON %I TO %I', table_name, runtime_role);
  END LOOP;

  -- Append-only authorization and execution evidence.
  FOREACH table_name IN ARRAY ARRAY[
    'authorization_requests',
    'authorization_decisions',
    'audit_events',
    'execution_audit_events',
    'execution_audit_event_delegations'
  ] LOOP
    EXECUTE format('GRANT SELECT, INSERT ON %I TO %I', table_name, runtime_role);
  END LOOP;

  -- Not yet written by the application.
  EXECUTE format('GRANT SELECT ON models TO %I', runtime_role);

  -- Readiness and schema validation read migration history.
  EXECUTE format('GRANT SELECT ON flyway_schema_history TO %I', runtime_role);

  -- The identity directory (directory_* tables) gets no table privileges. The
  -- runtime role routes, signs people in, and manages sessions through these
  -- SECURITY DEFINER functions only.
  FOREACH function_signature IN ARRAY ARRAY[
    'authai_agent_credential_tenant(text)',
    'authai_user_for_external_identity(text, text)',
    'authai_active_memberships(uuid)',
    'authai_begin_login(bytea, bytea, text, text, integer)',
    'authai_consume_login_attempt(bytea, bytea)',
    'authai_create_session(bytea, uuid, uuid, uuid, text, integer, integer)',
    'authai_resolve_session(bytea)',
    'authai_select_session_tenant(bytea, uuid)',
    'authai_revoke_session(bytea)',
    'authai_agent_selector_locked(bytea)',
    'authai_record_agent_authentication_rejection(bytea, text, inet)'
  ] LOOP
    -- A migration run with an explicit earlier target predates these functions.
    IF to_regprocedure(function_signature) IS NOT NULL THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO %I', function_signature, runtime_role);
    END IF;
  END LOOP;
END
$$;
