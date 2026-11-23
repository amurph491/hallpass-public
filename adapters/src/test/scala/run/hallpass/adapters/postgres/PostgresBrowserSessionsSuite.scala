package run.hallpass.adapters.postgres

import java.security.SecureRandom
import java.sql.DriverManager
import java.time.Duration
import java.util.UUID
import scala.compiletime.uninitialized
import cats.effect.IO
import cats.syntax.all.*
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import org.typelevel.doobie.util.transactor.Transactor
import run.hallpass.application.*
import run.hallpass.kernel.*

/** Durable sessions, OIDC login attempts, and break-glass elevation, exercised as the production-shaped runtime role
  * (external migrations, separate owner). The owner stands in for operators: it provisions tenants, changes the
  * directory, moves clocks backwards on rows, and grants break-glass. */
final class PostgresBrowserSessionsSuite extends CatsEffectSuite:
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(120, "s")
  private var container: PostgreSQLContainer[?] = uninitialized
  private var dockerAvailable = false
  private val Owner = "authai_owner"
  private val App = "authai_app"
  private val Password = "test-password"
  private val runtimeRole = RuntimeRole.parse(App).toOption.get
  private val random = SecureRandom()
  private val policy = SessionPolicy.default

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      val connection = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
      try
        val statement = connection.createStatement()
        statement.execute(s"create role $Owner login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"create role $App login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"grant connect on database test to $Owner, $App")
        statement.execute("revoke create on schema public from public")
        statement.execute(s"grant usage, create on schema public to $Owner")
        statement.execute(s"grant usage on schema public to $App")
      finally connection.close()

  override def afterAll(): Unit = if dockerAvailable then container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  private def config(user: String): DatabaseConfig =
    DatabaseConfig
      .fromEnvironment(Map("HALLPASS_DB_URL" -> container.getJdbcUrl, "HALLPASS_DB_USER" -> user, "HALLPASS_DB_PASSWORD" -> Password))
      .toOption
      .get

  private lazy val prepared: IO[Unit] = PostgresDatabase.migrateAsOwner(config(Owner), runtimeRole).void

  private def asOwner[A](program: Transactor[IO] => IO[A]): IO[A] =
    prepared *> PostgresDatabase.ownerResource(config(Owner)).use(program)

  private def asRuntimeRole[A](program: Transactor[IO] => IO[A]): IO[A] =
    prepared *> PostgresDatabase.resourceWithSchema(config(App), MigrationMode.External).use((xa, _) => program(xa))

  private def owner(statement: Fragment): IO[Int] = asOwner(xa => statement.update.run.transact(xa))

  private def account(subject: String = UUID.randomUUID().toString): ExternalIdentity =
    ExternalIdentity.from("https://idp.example.com", subject).toOption.get

  private def provisionTenant(administrator: ExternalIdentity = account()): IO[ProvisionedTenant] =
    val slug = s"tenant-${UUID.randomUUID().toString.take(8)}"
    asOwner(xa => TenantProvisioning.provision(xa, TenantProvisioningRequest.from("Test tenant", slug, administrator).toOption.get))

  /** Adds `user` to `tenant` with a fresh principal and the given role, as an operator would. */
  private def addMember(tenant: TenantId, user: DirectoryUserId, role: String): IO[Principal.Human] =
    val principal = UserId.random()
    asOwner: xa =>
      (TenantSession.establish(tenant) *>
        sql"insert into principals(id, tenant_id, kind) values (${principal.toString}::uuid, ${tenant.toString}::uuid, 'HUMAN')".update.run *>
        sql"insert into human_identities(tenant_id, principal_id) values (${tenant.toString}::uuid, ${principal.toString}::uuid)".update.run *>
        sql"""insert into directory_tenant_memberships(tenant_id, user_id, human_principal_id, role, status)
              values (${tenant.toString}::uuid, ${user.toString}::uuid, ${principal.toString}::uuid, $role, 'ACTIVE')""".update.run)
        .transact(xa)
        .as(Principal.Human(principal))

  /** A directory user with no memberships. */
  private def lonelyUser(person: ExternalIdentity): IO[DirectoryUserId] =
    val user = DirectoryUserId.random()
    owner(
      sql"""with u as (insert into directory_users(id, status) values (${user.toString}::uuid, 'ACTIVE') returning id)
            insert into directory_external_identities(issuer, subject, user_id) select ${person.issuer}, ${person.subject}, id from u"""
    ).as(user)

  private def newToken(): SessionToken = SessionToken.generate(random)

  private def events(session: SessionId): IO[Vector[(String, Option[UUID])]] =
    asOwner(xa =>
      sql"select kind, break_glass_grant_id from directory_session_events where session_id = ${session.value} order by id"
        .query[(String, Option[UUID])].to[Vector].transact(xa)
    )

  test("a session is created, resolved, re-selected, and logged out, with an audit trail and no stored secret") {
    requireDocker()
    for
      first <- provisionTenant()
      token = newToken()
      id = SessionId.random()
      outcome <- asRuntimeRole: xa =>
        val sessions = PostgresBrowserSessions(xa)
        for
          created <- sessions.create(token.lookup, id, first.administrator, Some(first.tenant), LoginMethod.Oidc, policy)
          live <- sessions.resolve(token.lookup)
          foreign <- sessions.selectTenant(token.lookup, TenantId.random())
          wrongToken <- sessions.resolve(newToken().lookup)
          _ <- sessions.revoke(token.lookup)
          afterLogout <- sessions.resolve(token.lookup)
          reselect <- sessions.selectTenant(token.lookup, first.tenant)
        yield (created, live, foreign, wrongToken, afterLogout, reselect)
      trail <- events(id)
      stored <- asOwner(xa =>
        sql"select token_hash from directory_sessions where id = ${id.value}".query[Array[Byte]].unique.transact(xa)
      )
    yield
      val (created, live, foreign, wrongToken, afterLogout, reselect) = outcome
      assertEquals(created, Right(true))
      assertEquals(live, Right(Some(LiveSession(id, first.administrator, Some(first.tenant)))))
      assertEquals(foreign, Right(false))
      assertEquals(wrongToken, Right(None))
      assertEquals(afterLogout, Right(None))
      assertEquals(reselect, Right(false), "a logged-out session cannot select a tenant")
      assertEquals(trail.map(_._1), Vector("CREATED", "TENANT_SELECTED", "LOGGED_OUT"))
      assert(!java.util.Arrays.equals(stored, token.cookieValue.getBytes("US-ASCII")))
      assert(stored.sameElements(token.lookup.toArray), "only the lookup digest is stored")
  }

  test("a session cannot be created for a disabled user or in a tenant the user is not a member of") {
    requireDocker()
    for
      member <- provisionTenant()
      other <- provisionTenant()
      disabled <- provisionTenant()
      _ <- owner(sql"update directory_users set status = 'DISABLED', disabled_at = now() where id = ${disabled.administrator.toString}::uuid")
      outcome <- asRuntimeRole: xa =>
        val sessions = PostgresBrowserSessions(xa)
        (
          sessions.create(newToken().lookup, SessionId.random(), member.administrator, Some(other.tenant), LoginMethod.Oidc, policy),
          sessions.create(newToken().lookup, SessionId.random(), disabled.administrator, None, LoginMethod.Oidc, policy)
        ).tupled
    yield assertEquals(outcome, (Right(false), Right(false)))
  }

  test("sessions expire by idle time and by absolute lifetime on the database clock, and activity extends idle time") {
    requireDocker()
    for
      tenant <- provisionTenant()
      idle = newToken()
      active = newToken()
      absolute = newToken()
      _ <- asRuntimeRole: xa =>
        val sessions = PostgresBrowserSessions(xa)
        Vector(idle, active, absolute).traverse(token =>
          sessions.create(token.lookup, SessionId.random(), tenant.administrator, Some(tenant.tenant), LoginMethod.Oidc, policy)
        )
      // 31 minutes without activity exceeds the 30-minute idle timeout; 5 minutes does not.
      _ <- owner(sql"update directory_sessions set last_seen_at = now() - interval '31 minutes' where token_hash = ${idle.lookup.toArray}")
      _ <- owner(sql"update directory_sessions set last_seen_at = now() - interval '5 minutes' where token_hash = ${active.lookup.toArray}")
      _ <- owner(
        sql"""update directory_sessions set created_at = now() - interval '9 hours', absolute_expires_at = now() - interval '1 hour'
              where token_hash = ${absolute.lookup.toArray}"""
      )
      resolved <- asRuntimeRole: xa =>
        val sessions = PostgresBrowserSessions(xa)
        Vector(idle, active, absolute).traverse(token => sessions.resolve(token.lookup).map(_.map(_.nonEmpty)))
      touched <- asOwner(xa =>
        sql"select last_seen_at > now() - interval '1 minute' from directory_sessions where token_hash = ${active.lookup.toArray}"
          .query[Boolean].unique.transact(xa)
      )
    yield
      assertEquals(resolved, Vector(Right(false), Right(true), Right(false)))
      assert(touched, "resolving an active session refreshes its idle deadline")
  }

  test("disabling a user revokes their sessions for good; removing a membership revokes sessions in that tenant only") {
    requireDocker()
    for
      first <- provisionTenant()
      second <- provisionTenant()
      _ <- addMember(second.tenant, first.administrator, "ADMIN")
      inFirst = newToken()
      inSecond = newToken()
      _ <- asRuntimeRole: xa =>
        val sessions = PostgresBrowserSessions(xa)
        sessions.create(inFirst.lookup, SessionId.random(), first.administrator, Some(first.tenant), LoginMethod.Oidc, policy) *>
          sessions.create(inSecond.lookup, SessionId.random(), first.administrator, Some(second.tenant), LoginMethod.Oidc, policy)
      _ <- owner(
        sql"""update directory_tenant_memberships set status = 'REMOVED', removed_at = now()
              where tenant_id = ${second.tenant.toString}::uuid and user_id = ${first.administrator.toString}::uuid"""
      )
      afterRemoval <- asRuntimeRole(xa => Vector(inFirst, inSecond).traverse(token => PostgresBrowserSessions(xa).resolve(token.lookup).map(_.map(_.nonEmpty))))
      _ <- owner(sql"update directory_users set status = 'DISABLED', disabled_at = now() where id = ${first.administrator.toString}::uuid")
      _ <- owner(sql"update directory_users set status = 'ACTIVE', disabled_at = null where id = ${first.administrator.toString}::uuid")
      afterReenable <- asRuntimeRole(xa => PostgresBrowserSessions(xa).resolve(inFirst.lookup))
      reasons <- asOwner(xa =>
        sql"""select revocation_reason from directory_sessions where token_hash in (${inFirst.lookup.toArray}, ${inSecond.lookup.toArray})
              order by revocation_reason"""
          .query[String].to[Vector].transact(xa)
      )
    yield
      assertEquals(afterRemoval, Vector(Right(true), Right(false)))
      assertEquals(afterReenable, Right(None), "re-enabling a user must not revive a revoked session")
      assertEquals(reasons, Vector("MEMBERSHIP_REMOVED", "USER_DISABLED"))
  }

  test("a login attempt is single-use, bound to the starting browser, expires, and is capped") {
    requireDocker()
    val pending = PendingLogin(OidcNonce.generate(random), PkceVerifier.generate(random))
    def digest(): SecretDigest = LoginState.generate(random).digest
    val (state, binding, stolen, stale, staleBinding) = (digest(), digest(), digest(), digest(), digest())
    for
      outcome <- asRuntimeRole: xa =>
        val attempts = PostgresBrowserSessions(xa)
        for
          _ <- attempts.begin(state, binding, pending, Duration.ofMinutes(10))
          first <- attempts.consume(state, binding)
          replay <- attempts.consume(state, binding)
          _ <- attempts.begin(stolen, binding, pending, Duration.ofMinutes(10))
          wrongBrowser <- attempts.consume(stolen, digest())
          rightBrowserAfter <- attempts.consume(stolen, binding)
          _ <- attempts.begin(stale, staleBinding, pending, Duration.ofMinutes(10))
        yield (first, replay, wrongBrowser, rightBrowserAfter)
      _ <- owner(
        sql"""update directory_login_attempts set created_at = now() - interval '20 minutes', expires_at = now() - interval '10 minutes'
              where state_hash = ${stale.toArray}"""
      )
      expired <- asRuntimeRole(xa => PostgresBrowserSessions(xa).consume(stale, staleBinding))
      verifierLeft <- asOwner(xa => sql"select count(*) from directory_login_attempts".query[Long].unique.transact(xa))
      // Fill to the cap with unexpired attempts, as an unauthenticated flood would.
      _ <- owner(
        sql"""insert into directory_login_attempts(state_hash, binding_hash, nonce, code_verifier, expires_at)
              select sha256(('flood' || i)::bytea), sha256(('bind' || i)::bytea), ${pending.nonce.value}, ${pending.verifier.value},
                     now() + interval '10 minutes'
                from generate_series(1, 10000) i"""
      )
      capped <- asRuntimeRole(xa => PostgresBrowserSessions(xa).begin(digest(), digest(), pending, Duration.ofMinutes(10)))
      _ <- owner(sql"delete from directory_login_attempts")
    yield
      val (first, replay, wrongBrowser, rightBrowserAfter) = outcome
      assertEquals(first.map(_.map(_.nonce.value)), Right(Some(pending.nonce.value)))
      assertEquals(replay, Right(None))
      assertEquals(wrongBrowser, Right(None))
      assertEquals(rightBrowserAfter, Right(None), "a wrong-browser attempt burns the state")
      assertEquals(expired, Right(None))
      assertEquals(verifierLeft, 0L, "consumed and expired attempts, and their PKCE verifiers, are gone")
      assertEquals(capped, Left(LoginStoreError.TooManyPendingLogins))
  }

  test("an OIDC login leaves no state, binding, nonce, verifier, code, session cookie, or CSRF token in the directory tables") {
    requireDocker()
    val code = "authorization-code-" + UUID.randomUUID()
    for
      person <- IO.pure(account())
      tenant <- provisionTenant(person)
      secrets <- asRuntimeRole: xa =>
        val store = PostgresBrowserSessions(xa)
        // A provider that captures what the login handed it and returns the provisioned administrator.
        IO.ref(Option.empty[(LoginState, PendingLogin)]).flatMap: seen =>
          val provider = new IdentityProvider:
            def authorizationUri(state: LoginState, nonce: OidcNonce, verifier: PkceVerifier) =
              seen.set(Some(state -> PendingLogin(nonce, verifier))).as(Right(java.net.URI.create("https://idp.example.com/authorize")))
            def verify(presented: AuthorizationCode, pending: PendingLogin) = IO.pure(Right(person))
          val login = HumanLogin(Some(provider), store, store, HumanAuthenticator[IO](PostgresIdentityDirectory(xa)))
          for
            redirect <- login.start.map(_.fold(error => fail(s"expected a redirect: $error"), identity))
            (state, pending) <- seen.get.map(_.getOrElse(fail("expected the provider to see the login")))
            session <- login.complete(state.value, code, Some(redirect.binding.cookieValue))
              .map(_.fold(error => fail(s"expected a session: $error"), identity))
          yield Vector(state.value, redirect.binding.cookieValue, pending.nonce.value, pending.verifier.value, code,
            session.token.cookieValue, session.token.csrfToken)
      rows <- asOwner(xa =>
        sql"""select row_to_json(t)::text from directory_login_attempts t
              union all select row_to_json(t)::text from directory_sessions t
              union all select row_to_json(t)::text from directory_session_events t"""
          .query[String].to[Vector].transact(xa)
      )
    yield
      assert(rows.exists(_.contains(tenant.tenant.toString)), "the login wrote a session for the tenant")
      secrets.foreach(secret => assert(!rows.exists(_.contains(secret)), "a login secret was persisted"))
  }

  test("break-glass elevates a member to ADMIN until it expires or is revoked, and the selection records the grant") {
    requireDocker()
    val person = account()
    for
      tenant <- provisionTenant()
      user <- lonelyUser(person)
      memberPrincipal <- addMember(tenant.tenant, user, "MEMBER")
      request = BreakGlassRequest.from(tenant.tenant, person, "INC-1: administrators locked out", "on-call", Duration.ofMinutes(30)).toOption.get
      grant <- asOwner(xa => BreakGlass.grant(xa, request)).map(_.fold(error => fail(s"grant failed: $error"), identity))
      elevated <- asRuntimeRole(xa => PostgresIdentityDirectory(xa).activeMemberships(user))
      token = newToken()
      id = SessionId.random()
      _ <- asRuntimeRole(xa => PostgresBrowserSessions(xa).create(token.lookup, id, user, Some(tenant.tenant), LoginMethod.Oidc, policy))
      trail <- events(id)
      _ <- owner(sql"update directory_break_glass_grants set granted_at = now() - interval '2 hours', expires_at = now() - interval '1 minute' where id = ${grant.id.value}")
      expired <- asRuntimeRole(xa => PostgresIdentityDirectory(xa).activeMemberships(user))
      second <- asOwner(xa => BreakGlass.grant(xa, request)).map(_.fold(error => fail(s"grant failed: $error"), identity))
      revoked <- asOwner(xa => BreakGlass.revoke(xa, second.id))
      revokedTwice <- asOwner(xa => BreakGlass.revoke(xa, second.id))
      afterRevoke <- asRuntimeRole(xa => PostgresIdentityDirectory(xa).activeMemberships(user))
    yield
      assertEquals(grant.principal, memberPrincipal, "elevation reuses the member's principal")
      assertEquals(elevated.map(_.map(m => (m.role, m.breakGlass))), Right(Vector((MembershipRole.Admin, Some(grant.id)))))
      assertEquals(trail, Vector("CREATED" -> None, "TENANT_SELECTED" -> Some(grant.id.value)))
      assertEquals(expired.map(_.map(m => (m.role, m.breakGlass))), Right(Vector((MembershipRole.Member, None))))
      assert(revoked && !revokedTwice)
      assertEquals(afterRevoke.map(_.map(_.role)), Right(Vector(MembershipRole.Member)))
  }

  test("break-glass grants a role, not authority: the elevated principal cannot delegate") {
    requireDocker()
    val person = account()
    for
      tenant <- provisionTenant()
      user <- lonelyUser(person)
      request = BreakGlassRequest.from(tenant.tenant, person, "INC-2: contain a leaked credential", "on-call", Duration.ofMinutes(15)).toOption.get
      grant <- asOwner(xa => BreakGlass.grant(xa, request)).map(_.fold(error => fail(s"grant failed: $error"), identity))
      outcome <- asRuntimeRole: xa =>
        val controlPlane = PostgresControlPlane(xa)
        for
          human <- HumanAuthenticator[IO](PostgresIdentityDirectory(xa)).authenticate(user, tenant.tenant, java.time.Instant.now())
          agent <- controlPlane.create(tenant.tenant, CreateAgent("break-glass probe", None)).map(_.toOption.get)
          capability <- controlPlane.capabilities(tenant.tenant).map(_.find(c => c.name == "Slack.Message.Read" && c.descriptor.action == Action.Read).get)
          // Grants name a connection root, so the tenant connects one Slack workspace first.
          connections = PostgresConnectionRepository(xa)
          connection = ConnectionId.random()
          workspace = ExternalId.parse("T-BREAKGLASS").get
          _ <- connections.reserve(tenant.tenant, connection, "SLACK", tenant.administratorPrincipal, java.time.Instant.now())
          activated <- connections.activateReserved(
            tenant.tenant,
            connection,
            ConnectionActivation(
              tenant.administratorPrincipal, workspace, None, None, None, "SLACK_OAUTH", SecretReference.random(),
              run.hallpass.adapters.slack.Slack.workspace, workspace, "Break-glass workspace", None, singleActiveRoot = true
            ),
            java.time.Instant.now()
          )
          root = activated.toOption.get.resource
          attempt = (grantor: Principal.Human) =>
            controlPlane.create(
              tenant.tenant,
              CreateDelegation(grantor, Principal.Agent(agent.id), capability.id, root, capability.descriptor.action, None)
            )
          elevated <- attempt(grant.principal)
          standing <- attempt(tenant.administratorPrincipal)
        yield (human.map(h => (h.role, h.breakGlass.nonEmpty)), elevated, standing.isRight)
      unknown <- asOwner(xa =>
        BreakGlass.grant(xa, BreakGlassRequest.from(tenant.tenant, account(), "INC-3: nobody by that name", "on-call", Duration.ofMinutes(5)).toOption.get)
      )
      runtimeAttempt <- asRuntimeRole(xa => BreakGlass.grant(xa, request).attempt)
    yield
      val (human, elevated, standing) = outcome
      assertEquals(human, Right((MembershipRole.Admin, true)))
      assertEquals(elevated.left.toOption, Some(DelegationError.GrantorLacksAuthority))
      assert(standing, "the provisioned administrator, who holds owner policies, can delegate")
      assertEquals(unknown, Left(BreakGlassError.UnknownUser))
      assert(runtimeAttempt.isLeft, "the runtime role cannot grant break-glass")
  }

  test("break-glass requests are bounded to four hours and need a reason") {
    val tenant = TenantId.random()
    val person = account()
    assert(BreakGlassRequest.from(tenant, person, "a real reason", "op", Duration.ofMinutes(241)).isLeft)
    assert(BreakGlassRequest.from(tenant, person, "short", "op", Duration.ofMinutes(10)).isLeft)
    assert(BreakGlassRequest.from(tenant, person, "a real reason", "", Duration.ofMinutes(10)).isLeft)
    assert(BreakGlassRequest.from(tenant, person, "a real reason", "op", Duration.ofMinutes(240)).isRight)
  }
