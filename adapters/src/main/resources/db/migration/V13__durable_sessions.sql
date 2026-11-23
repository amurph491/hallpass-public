-- Durable browser sessions, OIDC login state, and break-glass elevation.
--
-- A session cookie and an OIDC callback carry no tenant, so both are looked up
-- before a tenant is known. Like the V12 identity directory, these tables are
-- closed to the runtime role (no grants, RLS enabled with no policy) and are
-- reached only through the SECURITY DEFINER functions below.
--
-- Secrets are never stored. The session token, the login state, and the
-- browser binding are stored only as SHA-256 digests computed by the
-- application with a distinct domain-separation prefix per use. The CSRF token
-- is derived from the session token in the same way, so it is not stored
-- either. The PKCE code verifier is kept only until its single use and is
-- deleted when the login attempt is consumed.
--
-- The database clock (now()) decides every expiry here, so instances with
-- skewed clocks agree on whether a session or login attempt is still valid.

-- One pending OIDC login. The state is single-use (consumed by deletion) and
-- valid only from the browser that started it: the callback must present the
-- browser-binding cookie whose digest was stored with the state.
CREATE TABLE directory_login_attempts (
  state_hash bytea PRIMARY KEY CHECK (octet_length(state_hash) = 32),
  binding_hash bytea NOT NULL CHECK (octet_length(binding_hash) = 32),
  nonce text NOT NULL CHECK (nonce ~ '^[A-Za-z0-9_-]{43,128}$'),
  code_verifier text NOT NULL CHECK (code_verifier ~ '^[A-Za-z0-9._~-]{43,128}$'),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '15 minutes')
);
CREATE INDEX directory_login_attempts_expiry_idx ON directory_login_attempts (expires_at);

-- A signed-in browser. tenant_id is the tenant the person is currently acting
-- in; it is NULL until one is selected. It is only a selection: every request
-- still re-resolves the user's current membership in that tenant.
CREATE TABLE directory_sessions (
  token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
  id uuid NOT NULL UNIQUE,
  user_id uuid NOT NULL REFERENCES directory_users(id),
  tenant_id uuid REFERENCES tenants(id),
  login_method text NOT NULL CHECK (login_method IN ('OIDC', 'DEVELOPMENT_BOOTSTRAP')),
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  absolute_expires_at timestamptz NOT NULL,
  idle_timeout_seconds integer NOT NULL CHECK (idle_timeout_seconds BETWEEN 60 AND 86400),
  revoked_at timestamptz,
  revocation_reason text CHECK (revocation_reason IN ('LOGOUT', 'USER_DISABLED', 'MEMBERSHIP_REMOVED')),
  CHECK ((revoked_at IS NULL) = (revocation_reason IS NULL)),
  CHECK (absolute_expires_at > created_at AND absolute_expires_at <= created_at + interval '24 hours')
);
CREATE INDEX directory_sessions_user_idx ON directory_sessions (user_id) WHERE revoked_at IS NULL;

-- A time-boxed ADMIN role in one tenant, granted by an operator job running as
-- the schema owner. It confers the ADMIN membership role only, never policies
-- or delegations, so it can contain (revoke, disconnect) but cannot create
-- authority the principal did not already hold. Rows are the audit record of
-- the grant; revocation only sets revoked_at.
CREATE TABLE directory_break_glass_grants (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  user_id uuid NOT NULL REFERENCES directory_users(id),
  human_principal_id uuid NOT NULL,
  reason text NOT NULL CHECK (btrim(reason) = reason AND char_length(reason) BETWEEN 10 AND 1000),
  granted_by text NOT NULL CHECK (btrim(granted_by) = granted_by AND char_length(granted_by) BETWEEN 1 AND 200),
  granted_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  FOREIGN KEY (tenant_id, human_principal_id) REFERENCES human_identities(tenant_id, principal_id),
  CHECK (expires_at > granted_at AND expires_at <= granted_at + interval '4 hours'),
  CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);
CREATE INDEX directory_break_glass_grants_user_idx ON directory_break_glass_grants (user_id, tenant_id);

-- Append-only audit of session lifecycle, including which break-glass grant
-- (if any) a tenant selection relied on. Written only by the functions below.
CREATE TABLE directory_session_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES directory_sessions(id),
  user_id uuid NOT NULL REFERENCES directory_users(id),
  tenant_id uuid REFERENCES tenants(id),
  kind text NOT NULL CHECK (kind IN ('CREATED', 'TENANT_SELECTED', 'LOGGED_OUT', 'REVOKED')),
  login_method text CHECK (login_method IN ('OIDC', 'DEVELOPMENT_BOOTSTRAP')),
  break_glass_grant_id uuid REFERENCES directory_break_glass_grants(id),
  occurred_at timestamptz NOT NULL DEFAULT now(),
  CHECK ((kind = 'CREATED') = (login_method IS NOT NULL)),
  CHECK (break_glass_grant_id IS NULL OR kind = 'TENANT_SELECTED')
);
CREATE INDEX directory_session_events_session_idx ON directory_session_events (session_id, id);

DO $directory$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'directory_login_attempts', 'directory_sessions',
    'directory_break_glass_grants', 'directory_session_events'
  ]
  LOOP
    -- As in V12: enabled, not forced, no policies. Only the owner (and the
    -- SECURITY DEFINER functions it owns) can use these tables.
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
  END LOOP;
END
$directory$;

-- Memberships now include active break-glass elevation. The return type
-- changes, so the V12 function is replaced rather than redefined.
DROP FUNCTION authai_active_memberships(uuid);

-- The active memberships of an active user, one row per tenant. An unexpired,
-- unrevoked break-glass grant makes the role ADMIN in that tenant and is
-- reported, so the caller can tell elevated access from standing access. A
-- standing ADMIN membership needs no elevation and reports none.
CREATE FUNCTION authai_active_memberships(p_user_id uuid)
  RETURNS TABLE (tenant_id uuid, human_principal_id uuid, role text, break_glass_grant_id uuid)
  LANGUAGE sql STABLE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
  WITH active_user AS (
    SELECT id FROM public.directory_users WHERE id = p_user_id AND status = 'ACTIVE'
  ),
  standing AS (
    SELECT m.tenant_id, m.human_principal_id, m.role
      FROM public.directory_tenant_memberships m
      JOIN active_user u ON u.id = m.user_id
     WHERE m.status = 'ACTIVE'
  ),
  elevated AS (
    SELECT DISTINCT ON (g.tenant_id) g.tenant_id, g.human_principal_id, g.id
      FROM public.directory_break_glass_grants g
      JOIN active_user u ON u.id = g.user_id
     WHERE g.revoked_at IS NULL AND g.expires_at > now()
     ORDER BY g.tenant_id, g.expires_at DESC, g.id
  )
  SELECT coalesce(s.tenant_id, e.tenant_id),
         coalesce(s.human_principal_id, e.human_principal_id),
         CASE WHEN e.id IS NOT NULL THEN 'ADMIN' ELSE s.role END,
         CASE WHEN s.role = 'ADMIN' THEN NULL ELSE e.id END
    FROM standing s
    FULL JOIN elevated e ON e.tenant_id = s.tenant_id
$$;

-- Starts an OIDC login. Expired attempts are purged first, and at most 10000
-- unexpired attempts may exist at once, so the unauthenticated start endpoint
-- cannot grow the table without bound. Returns false at the cap.
CREATE FUNCTION authai_begin_login(
  p_state_hash bytea,
  p_binding_hash bytea,
  p_nonce text,
  p_code_verifier text,
  p_ttl_seconds integer
) RETURNS boolean
  LANGUAGE plpgsql VOLATILE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF p_ttl_seconds IS NULL OR p_ttl_seconds < 60 OR p_ttl_seconds > 900 THEN
    RAISE EXCEPTION 'login attempt lifetime must be between 60 and 900 seconds';
  END IF;
  DELETE FROM public.directory_login_attempts WHERE expires_at <= now();
  IF (SELECT count(*) FROM public.directory_login_attempts) >= 10000 THEN
    RETURN false;
  END IF;
  INSERT INTO public.directory_login_attempts (state_hash, binding_hash, nonce, code_verifier, expires_at)
  VALUES (p_state_hash, p_binding_hash, p_nonce, p_code_verifier, now() + make_interval(secs => p_ttl_seconds));
  RETURN true;
END
$$;

-- Consumes a login attempt. The row is deleted whether or not the binding
-- matches, so a state can be tried once only. Returns the nonce and PKCE
-- verifier only for the binding that started the login, before expiry.
CREATE FUNCTION authai_consume_login_attempt(p_state_hash bytea, p_binding_hash bytea)
  RETURNS TABLE (nonce text, code_verifier text)
  LANGUAGE plpgsql VOLATILE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  attempt public.directory_login_attempts%ROWTYPE;
BEGIN
  DELETE FROM public.directory_login_attempts a
   WHERE a.state_hash = p_state_hash
  RETURNING a.* INTO attempt;
  IF FOUND AND attempt.binding_hash = p_binding_hash AND attempt.expires_at > now() THEN
    nonce := attempt.nonce;
    code_verifier := attempt.code_verifier;
    RETURN NEXT;
  END IF;
END
$$;

-- Creates a session for an active user. A tenant may be selected at creation
-- only if the user currently has it among their active memberships. Returns
-- false, creating nothing, for an inactive user or an unavailable tenant.
CREATE FUNCTION authai_create_session(
  p_token_hash bytea,
  p_session_id uuid,
  p_user_id uuid,
  p_tenant_id uuid,
  p_login_method text,
  p_absolute_seconds integer,
  p_idle_seconds integer
) RETURNS boolean
  LANGUAGE plpgsql VOLATILE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  grant_id uuid;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.directory_users WHERE id = p_user_id AND status = 'ACTIVE') THEN
    RETURN false;
  END IF;
  IF p_tenant_id IS NOT NULL THEN
    SELECT m.break_glass_grant_id INTO grant_id
      FROM public.authai_active_memberships(p_user_id) m
     WHERE m.tenant_id = p_tenant_id;
    IF NOT FOUND THEN
      RETURN false;
    END IF;
  END IF;
  INSERT INTO public.directory_sessions (
    token_hash, id, user_id, tenant_id, login_method, absolute_expires_at, idle_timeout_seconds
  ) VALUES (
    p_token_hash, p_session_id, p_user_id, p_tenant_id, p_login_method,
    now() + make_interval(secs => p_absolute_seconds), p_idle_seconds
  );
  INSERT INTO public.directory_session_events (session_id, user_id, kind, login_method)
  VALUES (p_session_id, p_user_id, 'CREATED', p_login_method);
  IF p_tenant_id IS NOT NULL THEN
    INSERT INTO public.directory_session_events (session_id, user_id, tenant_id, kind, break_glass_grant_id)
    VALUES (p_session_id, p_user_id, p_tenant_id, 'TENANT_SELECTED', grant_id);
  END IF;
  RETURN true;
END
$$;

-- The live session for a token digest: unrevoked, within its absolute and idle
-- lifetimes, and belonging to an active user. Refreshes last_seen_at at most
-- once a minute, which bounds writes and makes idle expiry accurate to a
-- minute. Membership in the selected tenant is not checked here; the caller
-- re-resolves it on every request.
CREATE FUNCTION authai_resolve_session(p_token_hash bytea)
  RETURNS TABLE (session_id uuid, user_id uuid, tenant_id uuid)
  LANGUAGE plpgsql VOLATILE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  live_session public.directory_sessions%ROWTYPE;
BEGIN
  SELECT s.* INTO live_session
    FROM public.directory_sessions s
    JOIN public.directory_users u ON u.id = s.user_id
   WHERE s.token_hash = p_token_hash
     AND s.revoked_at IS NULL
     AND s.absolute_expires_at > now()
     AND s.last_seen_at + make_interval(secs => s.idle_timeout_seconds) > now()
     AND u.status = 'ACTIVE';
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF live_session.last_seen_at < now() - interval '60 seconds' THEN
    UPDATE public.directory_sessions SET last_seen_at = now() WHERE token_hash = p_token_hash;
  END IF;
  session_id := live_session.id;
  user_id := live_session.user_id;
  tenant_id := live_session.tenant_id;
  RETURN NEXT;
END
$$;

-- Selects the tenant a live session acts in. The user must currently have it
-- among their active memberships (standing or break-glass); the selection is
-- audited with the grant it relied on.
CREATE FUNCTION authai_select_session_tenant(p_token_hash bytea, p_tenant_id uuid) RETURNS boolean
  LANGUAGE plpgsql VOLATILE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  live record;
  grant_id uuid;
BEGIN
  SELECT r.session_id, r.user_id INTO live FROM public.authai_resolve_session(p_token_hash) r;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  SELECT m.break_glass_grant_id INTO grant_id
    FROM public.authai_active_memberships(live.user_id) m
   WHERE m.tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  UPDATE public.directory_sessions SET tenant_id = p_tenant_id WHERE token_hash = p_token_hash;
  INSERT INTO public.directory_session_events (session_id, user_id, tenant_id, kind, break_glass_grant_id)
  VALUES (live.session_id, live.user_id, p_tenant_id, 'TENANT_SELECTED', grant_id);
  RETURN true;
END
$$;

-- Ends a session on logout. Revoking an already-ended session is a no-op.
CREATE FUNCTION authai_revoke_session(p_token_hash bytea) RETURNS void
  LANGUAGE plpgsql VOLATILE
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
  ended public.directory_sessions%ROWTYPE;
BEGIN
  UPDATE public.directory_sessions
     SET revoked_at = now(), revocation_reason = 'LOGOUT'
   WHERE token_hash = p_token_hash AND revoked_at IS NULL
  RETURNING * INTO ended;
  IF FOUND THEN
    INSERT INTO public.directory_session_events (session_id, user_id, tenant_id, kind)
    VALUES (ended.id, ended.user_id, ended.tenant_id, 'LOGGED_OUT');
  END IF;
END
$$;

-- Disabling a user revokes every session they hold; removing a membership
-- revokes their sessions in that tenant. Requests already re-check both, so
-- this is defense in depth, and it keeps re-enabling a user from reviving an
-- old session.
CREATE FUNCTION authai_revoke_sessions_on_directory_change() RETURNS trigger
  LANGUAGE plpgsql
  SECURITY DEFINER
  SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
  IF TG_TABLE_NAME = 'directory_users' THEN
    WITH ended AS (
      UPDATE public.directory_sessions
         SET revoked_at = now(), revocation_reason = 'USER_DISABLED'
       WHERE user_id = NEW.id AND revoked_at IS NULL
      RETURNING id, user_id, tenant_id
    )
    INSERT INTO public.directory_session_events (session_id, user_id, tenant_id, kind)
    SELECT id, user_id, tenant_id, 'REVOKED' FROM ended;
  ELSE
    WITH ended AS (
      UPDATE public.directory_sessions
         SET revoked_at = now(), revocation_reason = 'MEMBERSHIP_REMOVED'
       WHERE user_id = NEW.user_id AND tenant_id = NEW.tenant_id AND revoked_at IS NULL
      RETURNING id, user_id, tenant_id
    )
    INSERT INTO public.directory_session_events (session_id, user_id, tenant_id, kind)
    SELECT id, user_id, tenant_id, 'REVOKED' FROM ended;
  END IF;
  RETURN NULL;
END
$$;

CREATE TRIGGER directory_users_revoke_sessions
  AFTER UPDATE OF status ON directory_users
  FOR EACH ROW WHEN (NEW.status = 'DISABLED' AND OLD.status <> 'DISABLED')
  EXECUTE FUNCTION authai_revoke_sessions_on_directory_change();

CREATE TRIGGER directory_tenant_memberships_revoke_sessions
  AFTER UPDATE OF status ON directory_tenant_memberships
  FOR EACH ROW WHEN (NEW.status = 'REMOVED' AND OLD.status <> 'REMOVED')
  EXECUTE FUNCTION authai_revoke_sessions_on_directory_change();

REVOKE ALL ON FUNCTION authai_active_memberships(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION authai_begin_login(bytea, bytea, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION authai_consume_login_attempt(bytea, bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION authai_create_session(bytea, uuid, uuid, uuid, text, integer, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION authai_resolve_session(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION authai_select_session_tenant(bytea, uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION authai_revoke_session(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION authai_revoke_sessions_on_directory_change() FROM PUBLIC;

-- Slack OAuth state is now bound to the browser session that started it, as
-- well as to that session's tenant. State created before this migration gets
-- an all-zero binding, which no session digest can equal, so it fails closed.
ALTER TABLE oauth_states
  ADD COLUMN session_binding bytea NOT NULL
    DEFAULT '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea
    CHECK (octet_length(session_binding) = 32);
ALTER TABLE oauth_states ALTER COLUMN session_binding DROP DEFAULT;
