package run.hallpass.adapters.postgres

import java.sql.{DriverManager, SQLException}
import java.time.{Duration, Instant}
import java.util.UUID
import java.util.concurrent.atomic.AtomicInteger
import scala.compiletime.uninitialized
import cats.effect.IO
import cats.effect.unsafe.implicits.global
import cats.syntax.all.*
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.adapters.github.GitHub
import run.hallpass.adapters.security.{AgentCredentialHmacKey, AgentCredentialKeyRing, AgentCredentialHmacSha256}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** V22 (GitHub resource kinds and the one-tenant-per-installation claim) and the Postgres provider connection
  * resolver, against PostgreSQL 18 with the production owner/runtime role split. */
final class PostgresGitHubConnectionsSuite extends CatsEffectSuite:
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(180, "s")
  private val Owner = "authai_owner"
  private val App = "authai_app"
  private val Password = "test-password"
  private var container: PostgreSQLContainer[?] = uninitialized
  private var dockerAvailable = false
  private var ownerXa: Transactor[IO] = uninitialized
  private var runtimeXa: Transactor[IO] = uninitialized
  private var release: IO[Unit] = IO.unit
  private val now = Instant.parse("2026-09-30T12:00:00Z")
  private val audience = ExecutorAudience.parse("test.github.resolver").getOrElse(fail("audience"))
  private val capabilityKey = CapabilityKey.parse("GitHub.Issue.Read").getOrElse(fail("capability"))
  private val runtimeRole = RuntimeRole.parse(App).toOption.get

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      val admin = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
      try
        val statement = admin.createStatement()
        statement.execute(s"create role $Owner login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"create role $App login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"grant connect on database test to $Owner, $App")
        statement.execute("revoke create on schema public from public")
        statement.execute(s"grant usage, create on schema public to $Owner")
        statement.execute(s"grant usage on schema public to $App")
      finally admin.close()
      val setup = for
        _ <- PostgresDatabase.migrateAsOwner(config(Owner), runtimeRole)
        owner <- PostgresDatabase.resource(config(Owner)).allocated
        runtime <- PostgresDatabase.resourceWithSchema(config(App), MigrationMode.External).allocated
      yield (owner, runtime)
      val ((owner, releaseOwner), ((runtime, _), releaseRuntime)) = setup.unsafeRunSync()
      ownerXa = owner
      runtimeXa = runtime
      release = releaseRuntime *> releaseOwner

  override def afterAll(): Unit =
    if dockerAvailable then
      release.unsafeRunSync()
      container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  private def config(user: String): DatabaseConfig =
    DatabaseConfig
      .fromEnvironment(Map("HALLPASS_DB_URL" -> container.getJdbcUrl, "HALLPASS_DB_USER" -> user, "HALLPASS_DB_PASSWORD" -> Password))
      .toOption
      .get

  // ---- fixtures -----------------------------------------------------------------------------------------------------

  private val installationCounter = new AtomicInteger(1000)
  private def freshInstallation(): String = (installationCounter.incrementAndGet() + 7_000_000).toString

  private def newTenant(): IO[ProvisionedTenant] =
    val slug = s"gh-${UUID.randomUUID().toString.take(8)}"
    val request = TenantProvisioningRequest
      .from("GitHub fixture", slug, ExternalIdentity.from("urn:hallpass:github-test", UUID.randomUUID().toString).toOption.get)
      .toOption
      .get
    TenantProvisioning.provision(ownerXa, request)

  private final case class Installation(
      tenant: ProvisionedTenant,
      connection: ConnectionId,
      root: ResourceId,
      account: String,
      secret: SecretReference
  )

  private lazy val connections = new PostgresConnectionRepository(runtimeXa)
  private lazy val resources = new PostgresConnectionResources(runtimeXa)

  private def reserveAndActivate(
      tenant: ProvisionedTenant,
      connection: ConnectionId,
      account: String,
      secret: SecretReference,
      credentialType: String = GitHub.CredentialType,
      provider: String = "GITHUB"
  ): IO[Either[ConnectionActivationError, Unit]] =
    connections.reserve(tenant.tenant, connection, provider, tenant.administratorPrincipal, now) *>
      connections.activateReserved(
        tenant.tenant, connection,
        ConnectionActivation(tenant.administratorPrincipal, ExternalId.parse(account).get, Some("octo-org"), Some("octo-org"),
          None, credentialType, secret, if provider == "GITHUB" then GitHub.installation else run.hallpass.adapters.slack.Slack.workspace,
          ExternalId.parse(account).get, "octo-org", None, false),
        now
      ).map(_.map(_ => ()))

  private def installation(
      tenant: ProvisionedTenant,
      account: String = freshInstallation(),
      credentialType: String = GitHub.CredentialType
  ): IO[Installation] =
    val connection = ConnectionId.random()
    val secret = SecretReference.random()
    for
      activated <- reserveAndActivate(tenant, connection, account, secret, credentialType)
      _ <- IO.fromEither(activated.leftMap(error => RuntimeException(s"activation failed: $error")))
      root <- resources.listFor(tenant.tenant, connection).flatMap(all =>
        IO.fromOption(all.find(_.kind == GitHub.installation.wire))(RuntimeException("connection root missing")))
    yield Installation(tenant, connection, root.id, account, secret)

  private def selectRepository(i: Installation, repository: String = freshInstallation()): IO[ResourceId] =
    resources
      .select(
        i.tenant.tenant, i.connection, GitHub.repository, ExternalId.parse(repository).get, s"repo-$repository", i.root,
        i.tenant.administratorPrincipal, now
      )
      .flatMap(result => IO.fromEither(result.map(_.id).leftMap(error => RuntimeException(s"selection failed: $error"))))

  private def repositoryTarget(i: Installation, repository: ResourceId): IO[SelectedResource[GitHub.Repository]] =
    for
      external <- tenantSql(i.tenant.tenant)(
        sql"select external_id from resources where id=${repository.toString}::uuid".query[String].unique
      )
      resolved <- ResourceResolver(new PostgresControlPlane(runtimeXa)).resolve(
        i.tenant.tenant, GitHub.repository, ResourceLocator.Selected(ExternalRef[GitHub.Repository](ExternalId.parse(external).get))
      )
      target <- IO.fromEither(resolved.leftMap(reason => RuntimeException(s"target resolution failed: $reason")))
    yield target

  private def rootTarget(i: Installation): IO[SelectedResource[GitHub.Installation]] =
    ResourceResolver(new PostgresControlPlane(runtimeXa))
      .resolve(i.tenant.tenant, GitHub.installation, ResourceLocator.ConnectionRoot())
      .flatMap(result => IO.fromEither(result.leftMap(reason => RuntimeException(s"root resolution failed: $reason"))))

  private def tenantSql[A](tenant: TenantId)(query: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> query).transact(runtimeXa)

  /** Runs one statement as the container's bootstrap superuser with triggers and foreign keys bypassed, to model a
    * corrupted row the resolver must still refuse. Tests only; the runtime and owner roles cannot do this. */
  private def corrupt(statementText: String): IO[Unit] = IO.blocking:
    val connection = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
    try
      val statement = connection.createStatement()
      statement.execute("set session_replication_role = replica")
      statement.executeUpdate(statementText)
    finally connection.close()

  private def sqlState[A](result: Either[Throwable, A]): Option[String] = result.left.toOption.collect:
    case failure: SQLException => failure.getSQLState

  private def claims(account: String): IO[Vector[UUID]] =
    sql"select tenant_id from directory_connection_account_claims where provider='github' and external_account_id=$account"
      .query[UUID].to[Vector].transact(ownerXa)

  /** A redeemed lease for `selected`, produced by the same authorization, broker, and store path execution uses. */
  private def redeemedLease[K](tenant: ProvisionedTenant, selected: SelectedResource[K]): IO[RedeemedExecutionLease] =
    val controlPlane = new PostgresControlPlane(runtimeXa)
    val credentialRepository = new PostgresAgentCredentials(runtimeXa)
    val directory = new PostgresIdentityDirectory(runtimeXa)
    val key = AgentCredentialHmacKey.fromBytes("github-test", Array.fill[Byte](32)(31)).toOption.get
    val crypto = AgentCredentialHmacSha256(AgentCredentialKeyRing.from("github-test", Seq(key)).toOption.get)
    val enrollment = AgentEnrollmentService(credentialRepository, crypto)
    val authenticator = AgentAuthenticator[IO](directory, credentialRepository, crypto)
    val enrollmentRequest = AgentCredentialEnrollmentRequest.from(Some("GitHub resolver test"), None).toOption.get
    val requestId = AuthorizationRequestId.random()
    for
      administrator <- HumanAuthenticator[IO](directory).authenticate(tenant.administrator, tenant.tenant, now)
        .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"administrator authentication failed: $error"))))
      agent <- controlPlane.create(tenant.tenant, CreateAgent("GitHub resolver agent", None))
        .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"agent creation failed: $error")), IO.pure))
      disclosure <- enrollment.enroll(administrator, agent.id, enrollmentRequest, now)
        .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"agent enrollment failed: $error")), IO.pure))
      authenticatedResult <- authenticator.authenticate(disclosure.credential, UnverifiedExecutionClaims.empty, now)
      authenticated <- IO.fromEither(authenticatedResult.leftMap(error => RuntimeException(s"agent authentication failed: $error")))
      agentId = authenticated.agentId
      policy = Policy(
        PolicyId.random(), PolicyVersion.from(1).get,
        NonEmptySet.one(PolicyStatement(Principal.Agent(agentId), selected.resource, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow))
      )
      request = AuthorizationRequest(
        requestId, tenant.tenant, IdentityChain.direct(Principal.Agent(agentId)), selected.scope,
        capabilityKey, Action.Read, AuthorizationContext.empty
      )
      capability = AuthorizationEngine.authorize(Policies(Vector(policy)), request, Vector.empty, now) match
        case AuthorizationResult.Authorized(value) => value
        case other => fail(s"authorization fixture failed: $other")
      binding = InvocationBinding.compute(
        tenant.tenant, agentId, OperationId.parse("github.issues.list@1").get,
        capabilityKey, Action.Read, selected.resource, selected.kind, selected.externalId, io.circe.Json.obj()
      )
      metadata = ExecutionAuditMetadata.authenticatedInvocation(
        authenticated, ExecutionAuditCorrelationId.parse("github-resolver-integration").get,
        ResourceId.random(), CatalogCapabilityId.parse("00000000-0000-4000-8000-000000000001").get, binding
      )
      store <- InMemoryExecutionLeaseStore.create(Clock.fixed(now), Duration.ofSeconds(10), 100)
      audit <- InMemoryExecutionAuditRecorder.create
      issued <- InMemoryCredentialBroker(store, Clock.fixed(now), Duration.ofSeconds(60), audit).issueLease(capability, requestId, audience, metadata)
      redeemed <- store.redeem(issued.id, audience, now)
    yield redeemed match
      case LeaseRedemption.Redeemed(value) => value
      case other => fail(s"lease redemption fixture failed: $other")

  private final class CountingSecrets(contents: Map[SecretReference, ProviderSecret]) extends SecretStore[IO]:
    val reads = new AtomicInteger(0)
    def get(binding: SecretBinding, reference: SecretReference): IO[Either[SecretStoreError, ProviderSecret]] =
      IO(reads.incrementAndGet()) *> IO.pure(contents.get(reference).toRight(SecretStoreError.NotFound))
    def put(binding: SecretBinding, secret: ProviderSecret): IO[SecretReference] = IO.raiseError(RuntimeException("unexpected write"))
    def delete(binding: SecretBinding, reference: SecretReference): IO[Unit] = IO.raiseError(RuntimeException("unexpected delete"))

  private def resolver(secrets: SecretStore[IO]) = RepositoryProviderConnectionResolver(runtimeXa, secrets, Clock.fixed(now))
  private def secretsFor(i: Installation) = CountingSecrets(Map(i.secret -> ProviderSecret.fromUtf8("installation-record")))

  private def assertDenied[K](
      i: Installation,
      lease: RedeemedExecutionLease,
      target: SelectedResource[K],
      expected: ConnectionError,
      provider: ProviderId = ProviderId.GitHub,
      credentialType: String = GitHub.CredentialType
  ): IO[Unit] =
    val secrets = secretsFor(i)
    resolver(secrets).activeConnectionFor(lease, target, provider, credentialType).map: result =>
      assertEquals(result.map(_ => ()), Left(expected))
      assertEquals(secrets.reads.get, 0, "no secret may be read on a denial")

  // ---- resolver -----------------------------------------------------------------------------------------------------

  test("the resolver returns the connection and its secret for a selected repository and for the root") {
    requireDocker()
    for
      tenant <- newTenant()
      i <- installation(tenant)
      repository <- selectRepository(i)
      target <- repositoryTarget(i, repository)
      root <- rootTarget(i)
      lease <- redeemedLease(tenant, target)
      rootLease <- redeemedLease(tenant, root)
      secrets = secretsFor(i)
      resolved <- resolver(secrets).activeConnectionFor(lease, target, ProviderId.GitHub, GitHub.CredentialType)
      rootResolved <- resolver(secrets).activeConnectionFor(rootLease, root, ProviderId.GitHub, GitHub.CredentialType)
    yield
      assertEquals(resolved.map(_.connection.id), Right(i.connection))
      assertEquals(resolved.map(value => new String(ProviderSecret.bytes(value.secret), "UTF-8")), Right("installation-record"))
      assertEquals(rootResolved.map(_.connection.id), Right(i.connection))
      assertEquals(secrets.reads.get, 2)
  }

  test("the resolver refuses a deselected repository before reading the secret") {
    requireDocker()
    for
      tenant <- newTenant()
      i <- installation(tenant)
      repository <- selectRepository(i)
      target <- repositoryTarget(i, repository)
      lease <- redeemedLease(tenant, target)
      deselected <- resources.deselect(tenant.tenant, repository, now)
      _ = assertEquals(deselected, Right(()))
      _ <- assertDenied(i, lease, target, ConnectionError.NotFound)
    yield ()
  }

  test("the resolver refuses a NEEDS_REAUTH connection and a disabled connection") {
    requireDocker()
    for
      tenant <- newTenant()
      i <- installation(tenant)
      repository <- selectRepository(i)
      target <- repositoryTarget(i, repository)
      lease <- redeemedLease(tenant, target)
      _ <- tenantSql(tenant.tenant)(sql"update connections set status='NEEDS_REAUTH' where id=${i.connection.toString}::uuid".update.run)
      _ <- assertDenied(i, lease, target, ConnectionError.NotFound)
      _ <- tenantSql(tenant.tenant)(sql"update connections set status='ACTIVE' where id=${i.connection.toString}::uuid".update.run)
      disabled <- connections.disable(tenant.tenant, i.connection)
      _ = assertEquals(disabled, Right(()))
      _ <- assertDenied(i, lease, target, ConnectionError.NotFound)
    yield ()
  }

  test("the resolver refuses an expired credential reference") {
    requireDocker()
    for
      tenant <- newTenant()
      i <- installation(tenant)
      repository <- selectRepository(i)
      target <- repositoryTarget(i, repository)
      lease <- redeemedLease(tenant, target)
      _ <- tenantSql(tenant.tenant)(
        sql"update credential_references set expires_at=${now.minusSeconds(1)} where connection_id=${i.connection.toString}::uuid".update.run
      )
      _ <- assertDenied(i, lease, target, ConnectionError.NotFound)
    yield ()
  }

  test("the resolver refuses another credential type, and a connection of another provider") {
    requireDocker()
    for
      tenant <- newTenant()
      i <- installation(tenant)
      repository <- selectRepository(i)
      target <- repositoryTarget(i, repository)
      lease <- redeemedLease(tenant, target)
      _ <- assertDenied(i, lease, target, ConnectionError.NotFound, credentialType = "OAUTH_REFRESHABLE")
      _ <- corrupt(s"update connections set provider='SLACK' where id='${i.connection}'")
      _ <- assertDenied(i, lease, target, ConnectionError.NotFound)
    yield ()
  }

  test("the resolver refuses a resource whose stored kind is not the target's kind") {
    requireDocker()
    for
      tenant <- newTenant()
      i <- installation(tenant)
      repository <- selectRepository(i)
      target <- repositoryTarget(i, repository)
      lease <- redeemedLease(tenant, target)
      _ <- corrupt(s"update resources set kind='github.installation' where id='${repository}'")
      _ <- assertDenied(i, lease, target, ConnectionError.NotFound)
    yield ()
  }

  test("the resolver refuses a resource whose stored external ID is not the target's") {
    requireDocker()
    for
      tenant <- newTenant()
      i <- installation(tenant)
      repository <- selectRepository(i)
      target <- repositoryTarget(i, repository)
      lease <- redeemedLease(tenant, target)
      _ <- corrupt(s"update resources set external_id='424242' where id='${repository}'")
      _ <- assertDenied(i, lease, target, ConnectionError.NotFound)
    yield ()
  }

  test("the resolver refuses a lease and target that disagree on tenant, resource, or provider before any query") {
    requireDocker()
    for
      tenant <- newTenant()
      other <- newTenant()
      i <- installation(tenant)
      j <- installation(other)
      repository <- selectRepository(i)
      otherRepository <- selectRepository(j)
      target <- repositoryTarget(i, repository)
      otherTarget <- repositoryTarget(j, otherRepository)
      root <- rootTarget(i)
      lease <- redeemedLease(tenant, target)
      _ <- assertDenied(i, lease, otherTarget, ConnectionError.InvalidState)
      _ <- assertDenied(i, lease, root, ConnectionError.InvalidState)
      _ <- assertDenied(i, lease, target, ConnectionError.InvalidState, provider = ProviderId.Slack)
    yield ()
  }

  test("a missing secret fails closed as a missing credential") {
    requireDocker()
    for
      tenant <- newTenant()
      i <- installation(tenant)
      repository <- selectRepository(i)
      target <- repositoryTarget(i, repository)
      lease <- redeemedLease(tenant, target)
      result <- resolver(CountingSecrets(Map.empty)).activeConnectionFor(lease, target, ProviderId.GitHub, GitHub.CredentialType)
    yield assertEquals(result.map(_ => ()), Left(ConnectionError.MissingCredential))
  }

  // ---- V22 ----------------------------------------------------------------------------------------------------------

  test("an installation cannot be activated in a second tenant while the first connection claims it") {
    requireDocker()
    val account = freshInstallation()
    for
      first <- newTenant()
      second <- newTenant()
      _ <- installation(first, account)
      id = ConnectionId.random()
      attempt <- reserveAndActivate(second, id, account, SecretReference.random()).attempt
      claimed <- claims(account)
      status <- tenantSql(second.tenant)(sql"select status from connections where id=${id.toString}::uuid".query[String].unique)
    yield
      assertEquals(sqlState(attempt), Some("23505"))
      assertEquals(claimed, Vector(UUID.fromString(first.tenant.toString)), "the failed activation must leave no second claim")
      assertEquals(status, "CONNECTING", "the failed activation must roll back with its claim")
  }

  test("disabling the first connection releases the installation for another tenant") {
    requireDocker()
    val account = freshInstallation()
    for
      first <- newTenant()
      second <- newTenant()
      i <- installation(first, account)
      id = ConnectionId.random()
      blocked <- reserveAndActivate(second, id, account, SecretReference.random()).attempt
      disabled <- connections.disable(first.tenant, i.connection)
      afterDisable <- claims(account)
      retried <- connections.activateReserved(
        second.tenant, id,
        ConnectionActivation(second.administratorPrincipal, ExternalId.parse(account).get, None, None, None,
          GitHub.CredentialType, SecretReference.random(), GitHub.installation, ExternalId.parse(account).get, "octo", None, false), now
      )
      afterRetry <- claims(account)
    yield
      assert(blocked.isLeft)
      assertEquals(disabled, Right(()))
      assertEquals(afterDisable, Vector.empty)
      assert(retried.isRight)
      assertEquals(afterRetry, Vector(UUID.fromString(second.tenant.toString)))
  }

  test("NEEDS_REAUTH keeps the claim, so another tenant cannot take the installation") {
    requireDocker()
    val account = freshInstallation()
    for
      first <- newTenant()
      second <- newTenant()
      i <- installation(first, account)
      _ <- tenantSql(first.tenant)(sql"update connections set status='NEEDS_REAUTH' where id=${i.connection.toString}::uuid".update.run)
      kept <- claims(account)
      blocked <- reserveAndActivate(second, ConnectionId.random(), account, SecretReference.random()).attempt
      _ <- tenantSql(first.tenant)(sql"update connections set status='ACTIVE' where id=${i.connection.toString}::uuid".update.run)
      restored <- claims(account)
    yield
      assertEquals(kept, Vector(UUID.fromString(first.tenant.toString)))
      assertEquals(sqlState(blocked), Some("23505"))
      assertEquals(restored, Vector(UUID.fromString(first.tenant.toString)))
  }

  test("a provider outside the claim list may connect the same external account in two tenants") {
    requireDocker()
    val account = s"T${UUID.randomUUID().toString.take(8)}"
    for
      first <- newTenant()
      second <- newTenant()
      a <- reserveAndActivate(first, ConnectionId.random(), account, SecretReference.random(), "SLACK_OAUTH", "SLACK")
      b <- reserveAndActivate(second, ConnectionId.random(), account, SecretReference.random(), "SLACK_OAUTH", "SLACK")
      slackClaims <- sql"select count(*) from directory_connection_account_claims where external_account_id=$account"
        .query[Long].unique.transact(ownerXa)
    yield
      assertEquals((a, b), (Right(()), Right(())))
      assertEquals(slackClaims, 0L)
  }

  test("the runtime role has no access to account claims and cannot run the trigger function") {
    requireDocker()
    for
      select <- sql"select count(*) from directory_connection_account_claims".query[Long].unique.transact(runtimeXa).attempt
      insert <- sql"""insert into directory_connection_account_claims(provider, external_account_id, tenant_id, connection_id)
                       values ('github','1',${UUID.randomUUID()},${UUID.randomUUID()})""".update.run.transact(runtimeXa).attempt
      delete <- sql"delete from directory_connection_account_claims".update.run.transact(runtimeXa).attempt
      trigger <- sql"select authai_sync_connection_account_claim()".query[String].unique.transact(runtimeXa).attempt
    yield
      assertEquals(sqlState(select), Some("42501"))
      assertEquals(sqlState(insert), Some("42501"))
      assertEquals(sqlState(delete), Some("42501"))
      assertEquals(sqlState(trigger), Some("42501"))
  }

  test("the GitHub resource kinds exist, and a repository is admitted only under an installation") {
    requireDocker()
    for
      kinds <- sql"select wire, parent_wire, resource_type from resource_kinds where provider='github' order by wire"
        .query[(String, Option[String], String)].to[Vector].transact(ownerXa)
      tenant <- newTenant()
      i <- installation(tenant)
      underRoot <- resources.select(
        tenant.tenant, i.connection, GitHub.repository, ExternalId.parse(freshInstallation()).get, "repo", i.root,
        tenant.administratorPrincipal, now
      )
      catalog <- tenantSql(tenant.tenant)(
        sql"select id from resources where resource_type='PROVIDER' and provider='github'".query[UUID].unique
      )
      underCatalog <- resources.select(
        tenant.tenant, i.connection, GitHub.repository, ExternalId.parse(freshInstallation()).get, "repo",
        ResourceId.parse(catalog.toString).toOption.get, tenant.administratorPrincipal, now
      )
    yield
      assertEquals(kinds, Vector(("github.installation", None, "ACCOUNT"), ("github.repository", Some("github.installation"), "REPOSITORY")))
      assert(underRoot.isRight, s"a repository under its installation must be admitted: $underRoot")
      assert(underCatalog.isLeft, "a repository directly under the catalog resource must be refused")
  }
