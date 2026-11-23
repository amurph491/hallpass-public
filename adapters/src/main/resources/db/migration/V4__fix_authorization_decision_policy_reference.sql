-- A denial may legitimately have no matching policy.  MATCH FULL on the
-- tenant/policy composite key incorrectly rejects that case because tenant_id
-- is always present while policy_id and policy_version are null.
ALTER TABLE authorization_decisions
  DROP CONSTRAINT authorization_decisions_tenant_id_policy_id_policy_version_fkey;

ALTER TABLE authorization_decisions
  ADD CONSTRAINT authorization_decisions_policy_fields_consistent
  CHECK (
    (policy_id IS NULL AND policy_version IS NULL)
    OR
    (policy_id IS NOT NULL AND policy_version IS NOT NULL)
  );

-- MATCH SIMPLE is intentional: an entirely-null policy reference is valid,
-- while the check above rejects partially populated policy references.
ALTER TABLE authorization_decisions
  ADD CONSTRAINT authorization_decisions_tenant_id_policy_id_policy_version_fkey
  FOREIGN KEY (tenant_id, policy_id, policy_version)
  REFERENCES policies(tenant_id, id, version);
