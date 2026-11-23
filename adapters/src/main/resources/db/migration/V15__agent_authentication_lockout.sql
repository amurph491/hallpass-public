-- Agent authentication lockout and the audit of rejected presentations.
--
-- A failed presentation may route to no tenant, so both are directory tables:
-- closed to the runtime role (no grants, RLS enabled without policies) and
-- reached only through the SECURITY DEFINER functions below.
--
-- Neither table holds bearer material. The selector is stored only as a
-- domain-separated SHA-256 digest computed by the application, which is enough
-- to lock and correlate attempts against one credential without keeping the
-- credential's public identifier.

-- Wrong-secret failures per selector in the current window, and any active
-- lockout. Shared by every instance, so an attacker cannot spread attempts.
CREATE TABLE directory_agent_authentication_failures (
  selector_digest bytea PRIMARY KEY CHECK (octet_length(selector_digest) = 32),
  failures integer NOT NULL CHECK (failures >= 0),
  window_started_at timestamptz NOT NULL,
  locked_until timestamptz
);

-- Append-only audit of rejected presentations.
CREATE TABLE directory_agent_authentication_rejections (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  reason text NOT NULL CHECK (reason IN (
    'MALFORMED_CREDENTIAL', 'UNROUTED_CREDENTIAL', 'UNKNOWN_CREDENTIAL', 'EXPIRED_CREDENTIAL',
    'REVOKED_CREDENTIAL', 'WRONG_SECRET', 'CREDENTIAL_NO_LONGER_ACTIVE', 'INVALID_STORED_CREDENTIAL', 'LOCKED'
  )),
  selector_digest bytea CHECK (octet_length(selector_digest) = 32),
  client_address inet
);
CREATE INDEX directory_agent_authentication_rejections_time_idx ON directory_agent_authentication_rejections (occurred_at);
CREATE INDEX directory_agent_authentication_rejections_selector_idx
  ON directory_agent_authentication_rejections (selector_digest, occurred_at) WHERE selector_digest IS NOT NULL;

ALTER TABLE directory_agent_authentication_failures ENABLE ROW LEVEL SECURITY;
ALTER TABLE directory_agent_authentication_rejections ENABLE ROW LEVEL SECURITY;

-- Whether a selector is locked right now.
CREATE FUNCTION authai_agent_selector_locked(p_selector_digest bytea) RETURNS boolean
  LANGUAGE sql STABLE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  SELECT coalesce((
    SELECT locked_until > now()
      FROM public.directory_agent_authentication_failures
     WHERE selector_digest = p_selector_digest
  ), false)
$$;

-- Records one rejection. A wrong secret also counts toward the selector's
-- lockout: 10 failures within 15 minutes lock it for 15 minutes. The window
-- restarts once it has passed. Nothing else changes the count.
CREATE FUNCTION authai_record_agent_authentication_rejection(
  p_selector_digest bytea,
  p_reason text,
  p_client_address inet
) RETURNS void
  LANGUAGE plpgsql VOLATILE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  INSERT INTO public.directory_agent_authentication_rejections (reason, selector_digest, client_address)
  VALUES (p_reason, p_selector_digest, p_client_address);
  IF p_reason = 'WRONG_SECRET' AND p_selector_digest IS NOT NULL THEN
    INSERT INTO public.directory_agent_authentication_failures AS f (selector_digest, failures, window_started_at)
    VALUES (p_selector_digest, 1, now())
    ON CONFLICT (selector_digest) DO UPDATE
      SET failures = CASE WHEN f.window_started_at <= now() - interval '15 minutes' THEN 1 ELSE f.failures + 1 END,
          window_started_at = CASE WHEN f.window_started_at <= now() - interval '15 minutes' THEN now() ELSE f.window_started_at END;
    UPDATE public.directory_agent_authentication_failures
       SET locked_until = now() + interval '15 minutes'
     WHERE selector_digest = p_selector_digest
       AND failures >= 10
       AND (locked_until IS NULL OR locked_until <= now());
  END IF;
END
$$;

REVOKE ALL ON FUNCTION authai_agent_selector_locked(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION authai_record_agent_authentication_rejection(bytea, text, inet) FROM PUBLIC;
