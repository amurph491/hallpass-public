package run.hallpass.adapters.postgres

import java.sql.{DriverManager, SQLException}
import java.time.Instant
import java.util.UUID
import scala.compiletime.uninitialized
import cats.effect.IO
import cats.syntax.all.*
import munit.CatsEffectSuite
import org.flywaydb.core.Flyway
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.util.transactor.Transactor
import run.hallpass.adapters.security.{AgentCredentialHmacKey, AgentCredentialHmacSha256, AgentCredentialKeyRing}
import run.hallpass.application.*
import run.hallpass.kernel.*

/** The identity directory and agent credential routing, exercised as the production-shaped runtime role (external
  * migrations, separate owner). Tenants are provisioned by the owner, as `HallpassProvisionMain` does. */
final class PostgresIdentityDirectorySuite extends CatsEffectSuite:
  // The first test in the suite migrates a fresh container, which is slow while other suites start theirs.
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(120, "s")
  private var container: PostgreSQLContainer[?] = uninitialized
  private var dockerAvailable = false
  private val Owner = "authai_owner"
  private val App = "authai_app"
  private val Password = "test-password"
  private val runtimeRole = RuntimeRole.parse(App).toOption.get
  private val now = Instant.parse("2026-09-27T12:00:00Z")
  private val RoutingFunctions = Set(
    "authai_agent_credential_tenant(text)",
    "authai_user_for_external_identity(text,text)",
    "authai_active_memberships(uuid)",
    "authai_begin_login(bytea,bytea,text,text,integer)",
    "authai_consume_login_attempt(bytea,bytea)",
    "authai_create_session(bytea,uuid,uuid,uuid,text,integer,integer)",
    "authai_resolve_session(bytea)",
    "authai_select_session_tenant(bytea,uuid)",
    "authai_revoke_session(bytea)",
    "authai_agent_selector_locked(bytea)",
    "authai_record_agent_authentication_rejection(bytea,text,inet)"
  )
  private val DirectoryTables =
    Vector(
      "directory_users", "directory_external_identities", "directory_tenant_memberships", "directory_agent_credential_routes",
      "directory_login_attempts", "directory_sessions", "directory_break_glass_grants", "directory_session_events",
      "directory_agent_authentication_failures", "directory_agent_authentication_rejections",
      "directory_connection_account_claims"
    )

  private val crypto =
    val key = AgentCredentialHmacKey.fromBytes("directory-test", Array.fill[Byte](32)(23)).toOption.get
    AgentCredentialHmacSha256(AgentCredentialKeyRing.from("directory-test", Seq(key)).toOption.get)
  private val request = AgentCredentialEnrollmentRequest.from(Some("directory test"), None).toOption.get

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      superuser("test"): statement =>
        statement.execute(s"create role $Owner login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"create role $App login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute("create database legacy")
        statement.execute(s"grant connect on database test to $Owner, $App")
        statement.execute(s"grant connect on database legacy to $Owner, $App")
      Vector("test", "legacy").foreach: database =>
        superuser(database): statement =>
          statement.execute("revoke create on schema public from public")
          statement.execute(s"grant usage, create on schema public to $Owner")
          statement.execute(s"grant usage on schema public to $App")

  override def afterAll(): Unit = if dockerAvailable then container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  private def url(database: String): String =
    container.getJdbcUrl.replace("/test?", s"/$database?").replace("/test", s"/$database")

  private def superuser(database: String)(use: java.sql.Statement => Unit): Unit =
    val connection = DriverManager.getConnection(url(database), container.getUsername, container.getPassword)
    try use(connection.createStatement())
    finally connection.close()

  private def config(user: String, database: String = "test"): DatabaseConfig =
    DatabaseConfig
      .fromEnvironment(Map("HALLPASS_DB_URL" -> url(database), "HALLPASS_DB_USER" -> user, "HALLPASS_DB_PASSWORD" -> Password))
      .toOption
      .get

  private lazy val prepared: IO[Unit] =
    PostgresDatabase.migrateAsOwner(config(Owner), runtimeRole) *>
      PostgresDatabase.ownerResource(config(Owner)).use(DemoBootstrap.run)

  private def asOwner[A](program: Transactor[IO] => IO[A]): IO[A] =
    prepared *> PostgresDatabase.ownerResource(config(Owner)).use(program)

  private def asRuntimeRole[A](program: Transactor[IO] => IO[A]): IO[A] =
    prepared *> PostgresDatabase.resourceWithSchema(config(App), MigrationMode.External).use((xa, _) => program(xa))

  private def identity(subject: String): ExternalIdentity =
    ExternalIdentity.from("https://idp.example.com", subject).toOption.get

  /** A fresh tenant, provisioned by the owner. */
  private def provisionTenant(subject: String = UUID.randomUUID().toString): IO[ProvisionedTenant] =
    val slug = s"tenant-${UUID.randomUUID().toString.take(8)}"
    asOwner(xa => TenantProvisioning.provision(xa, TenantProvisioningRequest.from("Test tenant", slug, identity(subject)).toOption.get))

  private def administrator(directory: PostgresIdentityDirectory, user: DirectoryUserId, tenant: TenantId): IO[AuthenticatedHuman] =
    HumanAuthenticator[IO](directory)
      .authenticate(user, tenant, now)
      .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"administrator: $error"))))

  private def enrolledAgent(
      xa: Transactor[IO],
      actor: AuthenticatedHuman
  ): IO[(AgentId, OneTimeAgentCredentialDisclosure)] =
    val credentials = PostgresAgentCredentials(xa)
    for
      agent <- PostgresControlPlane(xa)
        .create(actor.tenant, CreateAgent(s"agent-${UUID.randomUUID().toString.take(6)}", None))
        .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(error.toString))))
      disclosure <- AgentEnrollmentService(credentials, crypto)
        .enroll(actor, agent.id, request, now)
        .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(error.toString))))
    yield agent.id -> disclosure

  private def authenticator(xa: Transactor[IO]): AgentAuthenticator[IO] =
    AgentAuthenticator[IO](PostgresIdentityDirectory(xa), PostgresAgentCredentials(xa), crypto)

  private def sqlState(result: Either[Throwable, ?]): Option[String] = result match
    case Left(error: SQLException) => Some(error.getSQLState)
    case _                         => None

  test("agents in two tenants authenticate through one listener, each into its own tenant") {
    requireDocker()
    for
      tenantB <- provisionTenant()
      outcome <- asRuntimeRole: xa =>
        val directory = PostgresIdentityDirectory(xa)
        for
          adminA <- administrator(directory, DemoBootstrap.AdministratorUser, DemoBootstrap.Tenant)
          adminB <- administrator(directory, tenantB.administrator, tenantB.tenant)
          (agentA, credentialA) <- enrolledAgent(xa, adminA)
          (agentB, credentialB) <- enrolledAgent(xa, adminB)
          routeA <- directory.candidateTenant(credentialA.credential.selector)
          routeB <- directory.candidateTenant(credentialB.credential.selector)
          contextA <- authenticator(xa).authenticate(credentialA.credential, UnverifiedExecutionClaims.empty, now)
          contextB <- authenticator(xa).authenticate(credentialB.credential, UnverifiedExecutionClaims.empty, now)
        yield (agentA, agentB, credentialB, routeA, routeB, contextA, contextB)
    yield
      val (agentA, agentB, credentialB, routeA, routeB, contextA, contextB) = outcome
      assertEquals(routeA, Right(Some(DemoBootstrap.Tenant)))
      assertEquals(routeB, Right(Some(tenantB.tenant)))
      assertEquals(contextA.map(context => context.tenant -> context.agentId), Right(DemoBootstrap.Tenant -> agentA))
      assertEquals(contextB.map(context => context.tenant -> context.agentId), Right(tenantB.tenant -> agentB))
      assertEquals(credentialB.metadata.issuedBy, Some(tenantB.administratorPrincipal.id))
  }

  test("rotation moves the route and revocation removes it in the same transaction") {
    requireDocker()
    asRuntimeRole: xa =>
      val directory = PostgresIdentityDirectory(xa)
      val credentials = PostgresAgentCredentials(xa)
      for
        admin <- administrator(directory, DemoBootstrap.AdministratorUser, DemoBootstrap.Tenant)
        (agent, original) <- enrolledAgent(xa, admin)
        rotated <- AgentEnrollmentService(credentials, crypto)
          .rotate(admin, agent, original.metadata.id, request, now.plusSeconds(1))
          .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(error.toString))))
        originalRoute <- directory.candidateTenant(original.credential.selector)
        rotatedRoute <- directory.candidateTenant(rotated.credential.selector)
        _ <- AgentEnrollmentService(credentials, crypto).revoke(admin, agent, rotated.metadata.id, now.plusSeconds(2))
        revokedRoute <- directory.candidateTenant(rotated.credential.selector)
        afterRevocation <- authenticator(xa).authenticate(rotated.credential, UnverifiedExecutionClaims.empty, now.plusSeconds(3))
        afterRotation <- authenticator(xa).authenticate(original.credential, UnverifiedExecutionClaims.empty, now.plusSeconds(3))
      yield
        assertEquals(originalRoute, Right(None))
        assertEquals(rotatedRoute, Right(Some(DemoBootstrap.Tenant)))
        assertEquals(revokedRoute, Right(None))
        assertEquals(afterRevocation, Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.UnroutedCredential)))
        assertEquals(afterRotation, Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.UnroutedCredential)))
  }

  test("a selector already routed to one tenant cannot be enrolled in another, and the failed enrollment leaves nothing") {
    requireDocker()
    for
      tenantB <- provisionTenant()
      outcome <- asRuntimeRole: xa =>
        val directory = PostgresIdentityDirectory(xa)
        val credentials = PostgresAgentCredentials(xa)
        for
          adminA <- administrator(directory, DemoBootstrap.AdministratorUser, DemoBootstrap.Tenant)
          (_, credentialA) <- enrolledAgent(xa, adminA)
          agentB <- PostgresControlPlane(xa)
            .create(tenantB.tenant, CreateAgent("collider", None))
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(error.toString))))
          generated <- crypto.issue(tenantB.tenant)
          colliding = GeneratedAgentCredential.issue(
            AgentCredentialId.random(),
            credentialA.credential,
            generated.verifier,
            generated.verifierMetadata
          )
          collision <- credentials.enroll(tenantB.tenant, agentB.id, colliding, request, tenantB.administratorPrincipal, now)
          route <- directory.candidateTenant(credentialA.credential.selector)
          stored <- credentials.metadataFor(tenantB.tenant, agentB.id)
        yield (collision, route, stored)
    yield
      val (collision, route, stored) = outcome
      assertEquals(collision, Left(AgentEnrollmentError.PersistenceFailure))
      assertEquals(route, Right(Some(DemoBootstrap.Tenant)))
      assertEquals(stored, Vector.empty, "the colliding credential must roll back with its route")
  }

  test("a forged route to another tenant never authenticates, even against a copied verifier") {
    requireDocker()
    for
      tenantB <- provisionTenant()
      (agentA, credentialA) <- asRuntimeRole: xa =>
        administrator(PostgresIdentityDirectory(xa), DemoBootstrap.AdministratorUser, DemoBootstrap.Tenant)
          .flatMap(enrolledAgent(xa, _))
      selector = credentialA.credential.selector.value
      // Corrupt the directory as only a superuser could: repoint the selector at tenant B, and plant a row in tenant B
      // with the same selector and a copy of tenant A's verifier. Replica mode skips the foreign key and route trigger.
      _ <- IO.blocking(superuser("test"): statement =>
        statement.execute("set session_replication_role = replica")
        statement.execute(s"update directory_agent_credential_routes set tenant_id = '${tenantB.tenant}' where selector = '$selector'")
      )
      unrowed <- asRuntimeRole(xa => authenticator(xa).authenticate(credentialA.credential, UnverifiedExecutionClaims.empty, now))
      agentB <- asRuntimeRole(xa =>
        PostgresControlPlane(xa)
          .create(tenantB.tenant, CreateAgent("impostor", None))
          .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(error.toString))))
      )
      _ <- IO.blocking(superuser("test"): statement =>
        statement.execute("set session_replication_role = replica")
        statement.execute(
          s"""insert into agent_credentials(id, tenant_id, agent_principal_id, selector, verifier, verifier_algorithm, verifier_key_id)
              select gen_random_uuid(), '${tenantB.tenant}', '${agentB.id}', selector, verifier, verifier_algorithm, verifier_key_id
                from agent_credentials where tenant_id = '${DemoBootstrap.Tenant}' and selector = '$selector'"""
        )
      )
      copied <- asRuntimeRole(xa => authenticator(xa).authenticate(credentialA.credential, UnverifiedExecutionClaims.empty, now))
    yield
      assertEquals(unrowed, Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.UnknownCredential)))
      assertEquals(copied, Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.WrongSecret)))
  }

  test("disabled users and removed or deleted memberships resolve to nothing") {
    requireDocker()
    val subject = UUID.randomUUID().toString
    for
      first <- provisionTenant(subject)
      second <- provisionTenant(subject)
      third <- provisionTenant(subject)
      initial <- asRuntimeRole: xa =>
        val directory = PostgresIdentityDirectory(xa)
        (directory.userFor(identity(subject)), directory.activeMemberships(first.administrator)).tupled
      _ <- asOwner: xa =>
        (sql"""update directory_tenant_memberships set status = 'REMOVED', removed_at = now()
               where tenant_id = ${first.tenant.toString}::uuid""".update.run *>
          sql"delete from directory_tenant_memberships where tenant_id = ${second.tenant.toString}::uuid".update.run).transact(xa)
      afterRemoval <- asRuntimeRole: xa =>
        val humans = HumanAuthenticator[IO](PostgresIdentityDirectory(xa))
        (
          humans.authenticate(first.administrator, first.tenant, now),
          humans.authenticate(second.administrator, second.tenant, now),
          humans.authenticate(third.administrator, third.tenant, now)
        ).tupled
      _ <- asOwner: xa =>
        sql"""update directory_users set status = 'DISABLED', disabled_at = now()
               where id = ${third.administrator.toString}::uuid""".update.run.transact(xa)
      afterDisable <- asRuntimeRole: xa =>
        val directory = PostgresIdentityDirectory(xa)
        val humans = HumanAuthenticator[IO](directory)
        (directory.userFor(identity(subject)), humans.authenticate(third.administrator, third.tenant, now)).tupled
    yield
      assertEquals(first.administrator, second.administrator, "one identity keeps one directory user across tenants")
      assertEquals(initial._1, Right(Some(first.administrator)))
      assertEquals(initial._2.map(_.map(_.tenant).toSet), Right(Set(first.tenant, second.tenant, third.tenant)))
      assertEquals(initial._2.map(_.map(_.role).toSet), Right(Set(MembershipRole.Admin)))
      assertEquals(afterRemoval._1.left.toOption, Some(HumanAuthenticationError.NoActiveMembership))
      assertEquals(afterRemoval._2.left.toOption, Some(HumanAuthenticationError.NoActiveMembership))
      assertEquals(afterRemoval._3.map(_.tenant), Right(third.tenant))
      assertEquals(afterDisable._1, Right(None))
      assertEquals(afterDisable._2.left.toOption, Some(HumanAuthenticationError.NoActiveMembership))
  }

  test("the runtime role reaches the directory only through the routing functions") {
    requireDocker()
    for
      direct <- asRuntimeRole: xa =>
        DirectoryTables.traverse: table =>
          (fr"select count(*) from" ++ Fragment.const(table)).query[Long].unique.transact(xa).attempt.map(table -> sqlState(_))
      trigger <- asRuntimeRole(xa => sql"select authai_sync_agent_credential_route()".query[String].unique.transact(xa).attempt)
      claimTrigger <- asRuntimeRole(xa => sql"select authai_sync_connection_account_claim()".query[String].unique.transact(xa).attempt)
      functions <- asOwner: xa =>
        sql"""select p.oid::regprocedure::text, p.prosecdef, coalesce(array_to_string(p.proconfig, ','), ''),
                     has_function_privilege($App, p.oid, 'EXECUTE'),
                     has_function_privilege('public', p.oid, 'EXECUTE')
                from pg_proc p join pg_namespace n on n.oid = p.pronamespace
               where n.nspname = 'public'"""
          .query[(String, Boolean, String, Boolean, Boolean)]
          .to[Vector]
          .transact(xa)
      rowSecurity <- asOwner: xa =>
        sql"""select c.relname, c.relrowsecurity, c.relforcerowsecurity,
                     exists(select 1 from pg_policies p where p.schemaname = 'public' and p.tablename = c.relname)
                from pg_class c join pg_namespace n on n.oid = c.relnamespace
               where n.nspname = 'public' and c.relkind = 'r' and c.relname like 'directory%'"""
          .query[(String, Boolean, Boolean, Boolean)]
          .to[Vector]
          .transact(xa)
    yield
      assertEquals(direct.filterNot(_._2.contains("42501")), Vector.empty, "directory tables readable by the runtime role")
      assertEquals(sqlState(trigger), Some("42501"), "the route trigger function must not be callable")
      assertEquals(sqlState(claimTrigger), Some("42501"), "the account claim trigger function must not be callable")
      val normalized = functions.map((signature, definer, config, runtime, public) =>
        (signature.replace(" ", ""), definer, config, runtime, public)
      )
      assertEquals(normalized.filter(_._4).map(_._1).toSet, RoutingFunctions, "functions the runtime role can execute")
      assertEquals(normalized.filter(_._5).map(_._1), Vector.empty, "functions executable by PUBLIC")
      normalized.filter(function => RoutingFunctions(function._1)).foreach: (signature, definer, config, _, _) =>
        assert(definer, s"$signature must be SECURITY DEFINER")
        assertEquals(config, "search_path=pg_catalog, pg_temp", s"$signature must pin its search_path")
      assertEquals(rowSecurity.map(_._1).toSet, DirectoryTables.toSet)
      assert(
        rowSecurity.forall((_, enabled, forced, hasPolicy) => enabled && !forced && !hasPolicy),
        s"directory tables must enable RLS without policies, so only the owner sees rows: $rowSecurity"
      )
  }

  test("only the owner can provision, and a duplicate slug changes nothing") {
    requireDocker()
    val slug = s"dup-${UUID.randomUUID().toString.take(8)}"
    val latecomer = identity(UUID.randomUUID().toString)
    for
      runtimeAttempt <- asRuntimeRole(xa =>
        TenantProvisioning.provision(xa, TenantProvisioningRequest.from("Runtime", slug, identity("runtime")).toOption.get).attempt
      )
      _ <- asOwner(xa => TenantProvisioning.provision(xa, TenantProvisioningRequest.from("First", slug, identity("first")).toOption.get))
      duplicate <- asOwner(xa =>
        TenantProvisioning.provision(xa, TenantProvisioningRequest.from("Second", slug, latecomer).toOption.get).attempt
      )
      latecomerUser <- asRuntimeRole(xa => PostgresIdentityDirectory(xa).userFor(latecomer))
    yield
      assertEquals(sqlState(runtimeAttempt), Some("42501"))
      assertEquals(sqlState(duplicate), Some("23505"))
      assertEquals(latecomerUser, Right(None), "a failed provisioning must not leave a directory user behind")
  }

  test("the directory migration backfills routes for credentials that already exist") {
    requireDocker()
    val legacy = config(Owner, database = "legacy")
    val tenant = UUID.randomUUID()
    val agent = UUID.randomUUID()
    val credential = UUID.randomUUID()
    val revoked = UUID.randomUUID()
    val otherAgent = UUID.randomUUID()
    val verifier = "\\x" + "ab" * 32
    for
      _ <- IO.blocking(
        Flyway
          .configure()
          .dataSource(legacy.jdbcUrl, legacy.user, legacy.password.orNull)
          .locations("classpath:db/migration")
          .placeholders(java.util.Map.of("runtime_role", App))
          .target("11")
          .load()
          .migrate()
      )
      _ <- IO.blocking:
        val connection = DriverManager.getConnection(url("legacy"), Owner, Password)
        try
          connection.setAutoCommit(false)
          val statement = connection.createStatement()
          statement.execute(s"select set_config('authai.tenant_id', '$tenant', true)")
          statement.execute(s"insert into tenants(id, name, slug) values ('$tenant', 'Legacy', 'legacy')")
          Vector(agent, otherAgent).foreach: id =>
            statement.execute(s"insert into principals(id, tenant_id, kind) values ('$id', '$tenant', 'AGENT')")
            statement.execute(s"insert into agents(tenant_id, principal_id, name) values ('$tenant', '$id', 'legacy')")
          statement.execute(
            s"""insert into agent_credentials(id, tenant_id, agent_principal_id, selector, verifier, verifier_algorithm, verifier_key_id)
                values ('$credential', '$tenant', '$agent', 'legacy-selector-0001', '$verifier', 'HMAC_SHA256_V1', 'k1'),
                       ('$revoked', '$tenant', '$otherAgent', 'legacy-selector-0002', '$verifier', 'HMAC_SHA256_V1', 'k1')"""
          )
          statement.execute(s"update agent_credentials set revoked_at = created_at where id = '$revoked'")
          connection.commit()
        finally connection.close()
      _ <- PostgresDatabase.migrateAsOwner(legacy, runtimeRole)
      routes <- PostgresDatabase.resourceWithSchema(config(App, database = "legacy"), MigrationMode.External).use: (xa, _) =>
        val directory = PostgresIdentityDirectory(xa)
        (
          directory.candidateTenant(AgentCredentialSelector.parse("legacy-selector-0001").toOption.get),
          directory.candidateTenant(AgentCredentialSelector.parse("legacy-selector-0002").toOption.get)
        ).tupled
      forced <- PostgresDatabase.ownerResource(legacy).use: xa =>
        sql"select relforcerowsecurity from pg_class where relname = 'agent_credentials'".query[Boolean].unique.transact(xa)
    yield
      assertEquals(routes._1, Right(Some(TenantId.parse(tenant.toString).toOption.get)))
      assertEquals(routes._2, Right(None), "a revoked credential must not be routed")
      assert(forced, "the backfill must restore forced row-level security")
  }
