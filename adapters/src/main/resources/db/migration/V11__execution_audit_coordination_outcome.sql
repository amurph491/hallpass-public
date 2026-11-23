-- A tenant gate that cannot be acquired, or whose ownership cannot be proven
-- before dispatch, is a known "not dispatched" outcome. Recording it as
-- COMPLETION_UNKNOWN would hide it among outcomes that may have reached the
-- provider, so it gets its own closed-vocabulary pair.
--
-- V8 declared these checks without names. Replace every CHECK on this table
-- that constrains event_kind or safe_outcome, then add named equivalents.
DO $$
DECLARE
  constraint_name text;
BEGIN
  FOR constraint_name IN
    SELECT con.conname
    FROM pg_constraint con
    WHERE con.conrelid = 'execution_audit_events'::regclass
      AND con.contype = 'c'
      AND (
        pg_get_constraintdef(con.oid) LIKE '%event_kind%'
        OR pg_get_constraintdef(con.oid) LIKE '%safe_outcome%'
      )
  LOOP
    EXECUTE format('ALTER TABLE execution_audit_events DROP CONSTRAINT %I', constraint_name);
  END LOOP;
END
$$;

ALTER TABLE execution_audit_events
  ADD CONSTRAINT execution_audit_events_event_kind_check CHECK (event_kind IN (
    'LEASE_ISSUED',
    'LEASE_REDEEMED',
    'REDEMPTION_DENIED',
    'AUTHORITY_CHANGED',
    'CONNECTION_UNAVAILABLE',
    'COORDINATION_UNAVAILABLE',
    'PROVIDER_REJECTED',
    'PROVIDER_UNAVAILABLE',
    'EXECUTION_COMPLETED',
    'COMPLETION_UNKNOWN'
  ));

ALTER TABLE execution_audit_events
  ADD CONSTRAINT execution_audit_events_safe_outcome_check CHECK (safe_outcome IN (
    'ISSUED',
    'REDEEMED',
    'DENIED_UNKNOWN_LEASE',
    'DENIED_EXPIRED',
    'DENIED_ALREADY_REDEEMED',
    'DENIED_WRONG_AUDIENCE',
    'DENIED_AUTHORITY_CHANGED',
    'DENIED_CONNECTION_UNAVAILABLE',
    'DENIED_COORDINATION_UNAVAILABLE',
    'FAILED_PROVIDER_REJECTED',
    'FAILED_PROVIDER_UNAVAILABLE',
    'COMPLETED',
    'UNKNOWN'
  ));

ALTER TABLE execution_audit_events
  ADD CONSTRAINT execution_audit_events_kind_outcome_check CHECK (
    (event_kind = 'LEASE_ISSUED' AND safe_outcome = 'ISSUED')
    OR (event_kind = 'LEASE_REDEEMED' AND safe_outcome = 'REDEEMED')
    OR (
      event_kind = 'REDEMPTION_DENIED'
      AND safe_outcome IN (
        'DENIED_UNKNOWN_LEASE',
        'DENIED_EXPIRED',
        'DENIED_ALREADY_REDEEMED',
        'DENIED_WRONG_AUDIENCE'
      )
    )
    OR (event_kind = 'AUTHORITY_CHANGED' AND safe_outcome = 'DENIED_AUTHORITY_CHANGED')
    OR (event_kind = 'CONNECTION_UNAVAILABLE' AND safe_outcome = 'DENIED_CONNECTION_UNAVAILABLE')
    OR (event_kind = 'COORDINATION_UNAVAILABLE' AND safe_outcome = 'DENIED_COORDINATION_UNAVAILABLE')
    OR (event_kind = 'PROVIDER_REJECTED' AND safe_outcome = 'FAILED_PROVIDER_REJECTED')
    OR (event_kind = 'PROVIDER_UNAVAILABLE' AND safe_outcome = 'FAILED_PROVIDER_UNAVAILABLE')
    OR (event_kind = 'EXECUTION_COMPLETED' AND safe_outcome = 'COMPLETED')
    OR (event_kind = 'COMPLETION_UNKNOWN' AND safe_outcome = 'UNKNOWN')
  );
