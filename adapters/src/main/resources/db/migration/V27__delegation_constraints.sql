-- Delegation constraints carry a typed, bounded allowlist document (see DelegationConstraintsJson). The
-- application decodes it strictly on every load; this bound keeps a delegation from carrying an unbounded document.
ALTER TABLE delegations
  ADD CONSTRAINT delegations_constraints_size CHECK (octet_length(constraints::text) <= 65536);
