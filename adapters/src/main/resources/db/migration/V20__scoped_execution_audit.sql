-- The capability catalog identifies an operation at its provider catalog root;
-- an execution record identifies the account root or selected child authorized
-- for that operation. Preserve tenant and action integrity without requiring
-- these two resources to be the same row.
ALTER TABLE capabilities
  ADD CONSTRAINT capabilities_tenant_id_id_action_unique UNIQUE (tenant_id, id, action);

-- V8's inline FK has a PostgreSQL-generated name. Locate that one capability
-- constraint explicitly rather than guessing its truncated identifier.
DO $$
DECLARE
  capability_constraint text;
BEGIN
  SELECT conname INTO STRICT capability_constraint
    FROM pg_constraint
   WHERE conrelid = 'public.execution_audit_events'::regclass
     AND confrelid = 'public.capabilities'::regclass
     AND contype = 'f';
  EXECUTE format('ALTER TABLE public.execution_audit_events DROP CONSTRAINT %I', capability_constraint);
END
$$;

ALTER TABLE execution_audit_events
  ADD CONSTRAINT execution_audit_capability_action_fk
  FOREIGN KEY (tenant_id, capability_id, action)
  REFERENCES capabilities(tenant_id, id, action);
-- V8's separate (tenant_id, resource_id), tool/mapping, policy, and credential
-- foreign keys remain intact, as do its append-only privileges and tenant RLS.
