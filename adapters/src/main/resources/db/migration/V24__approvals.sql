-- single-use human approvals bound to one
-- exact invocation.
--
-- An agent call whose deciding policy is REQUIRE_APPROVAL creates a PENDING
-- row naming the invocation's binding digest, the required capability
-- (capability, action, resource), the deciding policy version, and the human
-- who may approve it (the root of authority). The approver decides once; an
-- APPROVED row is consumed at most once, by a retry of the same invocation
-- that re-authorizes from scratch. Rows are never deleted.
CREATE TABLE approvals (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  agent_principal_id uuid NOT NULL,
  approver_principal_id uuid NOT NULL,
  operation_id text NOT NULL CHECK (operation_id ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){1,4}@[1-9][0-9]{0,3}$'),
  -- The catalog tool the agent called, for display. Never consulted for authority.
  tool_name text NOT NULL CHECK (tool_name ~ '^[A-Za-z0-9_]{1,128}$'),
  binding_digest text NOT NULL CHECK (binding_digest ~ '^[0-9a-f]{64}$'),
  capability_id uuid NOT NULL,
  action text NOT NULL CHECK (action IN ('READ', 'WRITE', 'EXECUTE', 'DELETE')),
  resource_id uuid NOT NULL,
  policy_id uuid NOT NULL,
  policy_version integer NOT NULL CHECK (policy_version > 0),
  -- The canonical, typed arguments the approver sees. Tenant data, never a
  -- credential; bounded so a request cannot store an arbitrary document.
  preview jsonb NOT NULL CHECK (jsonb_typeof(preview) = 'object' AND octet_length(preview::text) <= 131072),
  requested_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'DENIED')),
  decided_by uuid,
  decided_at timestamptz,
  consumed_at timestamptz,
  consumed_request_id uuid,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, agent_principal_id) REFERENCES principals(tenant_id, id),
  FOREIGN KEY (tenant_id, approver_principal_id) REFERENCES principals(tenant_id, id),
  FOREIGN KEY (tenant_id, decided_by) REFERENCES principals(tenant_id, id),
  FOREIGN KEY (tenant_id, capability_id) REFERENCES capabilities(tenant_id, id),
  FOREIGN KEY (tenant_id, resource_id) REFERENCES resources(tenant_id, id),
  FOREIGN KEY (tenant_id, policy_id, policy_version) REFERENCES policies(tenant_id, id, version),
  CHECK (expires_at > requested_at),
  CHECK ((status = 'PENDING') = (decided_by IS NULL)),
  CHECK ((decided_by IS NULL) = (decided_at IS NULL)),
  CHECK (decided_by IS NULL OR decided_by = approver_principal_id),
  CHECK (decided_at IS NULL OR decided_at >= requested_at),
  CHECK ((consumed_at IS NULL) = (consumed_request_id IS NULL)),
  CHECK (consumed_at IS NULL OR (status = 'APPROVED' AND consumed_at >= decided_at))
);

CREATE INDEX approvals_pending_idx ON approvals (tenant_id, approver_principal_id, requested_at) WHERE status = 'PENDING';

ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON approvals
  USING (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = nullif(current_setting('authai.tenant_id', true), '')::uuid);

-- The only transitions: PENDING -> APPROVED | DENIED (once), and APPROVED ->
-- consumed (once). Everything else about a row is immutable; afterMigrate.sql
-- also limits the runtime role's UPDATE to the decision and consumption
-- columns. A new row must start PENDING and unconsumed.
CREATE FUNCTION authai_check_approval_transition() RETURNS trigger
  LANGUAGE plpgsql
  SET search_path = pg_catalog, public
AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.status <> 'PENDING' OR NEW.decided_by IS NOT NULL OR NEW.consumed_at IS NOT NULL THEN
      RAISE EXCEPTION 'an approval starts pending and unconsumed' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF (NEW.id, NEW.tenant_id, NEW.agent_principal_id, NEW.approver_principal_id, NEW.operation_id, NEW.tool_name, NEW.binding_digest,
      NEW.capability_id, NEW.action, NEW.resource_id, NEW.policy_id, NEW.policy_version, NEW.preview,
      NEW.requested_at, NEW.expires_at)
     IS DISTINCT FROM
     (OLD.id, OLD.tenant_id, OLD.agent_principal_id, OLD.approver_principal_id, OLD.operation_id, OLD.tool_name, OLD.binding_digest,
      OLD.capability_id, OLD.action, OLD.resource_id, OLD.policy_id, OLD.policy_version, OLD.preview,
      OLD.requested_at, OLD.expires_at) THEN
    RAISE EXCEPTION 'an approval''s request is immutable' USING ERRCODE = '23514';
  END IF;
  IF OLD.status <> 'PENDING' AND (NEW.status, NEW.decided_by, NEW.decided_at)
       IS DISTINCT FROM (OLD.status, OLD.decided_by, OLD.decided_at) THEN
    RAISE EXCEPTION 'an approval is decided once' USING ERRCODE = '23514';
  END IF;
  IF OLD.consumed_at IS NOT NULL AND (NEW.consumed_at, NEW.consumed_request_id)
       IS DISTINCT FROM (OLD.consumed_at, OLD.consumed_request_id) THEN
    RAISE EXCEPTION 'an approval is consumed once' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER approvals_transition_check
  BEFORE INSERT OR UPDATE ON approvals
  FOR EACH ROW EXECUTE FUNCTION authai_check_approval_transition();

REVOKE ALL ON FUNCTION authai_check_approval_transition() FROM PUBLIC;
