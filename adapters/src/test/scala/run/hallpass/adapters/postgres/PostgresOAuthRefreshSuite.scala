package run.hallpass.adapters.postgres

import java.sql.DriverManager
import java.net.InetSocketAddress
import java.net.URI
import java.nio.charset.StandardCharsets
import java.time.{Duration, Instant}
import java.util.UUID
import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}
import com.sun.net.httpserver.HttpServer
import cats.effect.{IO, Resource}
import cats.syntax.all.*
import scala.compiletime.uninitialized
import scala.concurrent.duration.*
import cats.effect.unsafe.implicits.global
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.adapters.oauth.OAuthTokenJsonCodec
import run.hallpass.adapters.oauth.OAuthRefreshClient
import run.hallpass.adapters.security.{AgentCredentialHmacKey, AgentCredentialKeyRing, AgentCredentialHmacSha256}
import run.hallpass.adapters.secrets.{KeyEncryptionService, KeyServiceError, WrappedDataKey, EnvelopeSecretStore}
import run.hallpass.adapters.slack.Slack
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Exercises the refresh repository with PostgreSQL 18's production owner/runtime role split. */
final class PostgresOAuthRefreshSuite extends CatsEffectSuite:
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(120, "s")
  private val Owner = "authai_owner"
  private val Runtime = "authai_app"
  private val Password = "test-password"
  private var container: PostgreSQLContainer[?] = uninitialized
  private var ownerConfig: DatabaseConfig = uninitialized
  private var runtimeConfig: DatabaseConfig = uninitialized
  private var dockerAvailable = false
  private val now = Instant.parse("2026-09-30T12:00:00Z")
  private val audience = ExecutorAudience.parse("test.oauth.refresh.executor").getOrElse(fail("audience"))
  private val capabilityKey = CapabilityKey.parse("Slack.Message.Read").getOrElse(fail("capability"))
  private val codec = new OAuthTokenJsonCodec

  private final class TestKeys extends KeyEncryptionService:
    val keyName = "integration-test"
    def wrap(dataKey: Array[Byte], tenant: TenantId): IO[Either[KeyServiceError, WrappedDataKey]] =
      IO.pure(Right(WrappedDataKey.fromStored("test:" + java.util.Base64.getEncoder.encodeToString(dataKey))))
    def unwrap(wrapped: WrappedDataKey, tenant: TenantId): IO[Either[KeyServiceError, Array[Byte]]] =
      IO(java.util.Base64.getDecoder.decode(wrapped.value.stripPrefix("test:"))).attempt.map:
        case Right(value) => Right(value)
        case Left(_)      => Left(KeyServiceError.Rejected)
    def rewrap(wrapped: WrappedDataKey, tenant: TenantId): IO[Either[KeyServiceError, WrappedDataKey]] = IO.pure(Right(wrapped))
    def current(wrapped: WrappedDataKey): IO[Either[KeyServiceError, Boolean]] = IO.pure(Right(true))

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      val admin = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
      try
        val statement = admin.createStatement()
        statement.execute(s"create role $Owner login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"create role $Runtime login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"grant connect on database test to $Owner, $Runtime")
        statement.execute("revoke create on schema public from public")
        statement.execute(s"grant usage, create on schema public to $Owner")
        statement.execute(s"grant usage on schema public to $Runtime")
      finally admin.close()
      def configFor(user: String) = DatabaseConfig.fromEnvironment(Map(
        "HALLPASS_DB_URL" -> container.getJdbcUrl,
        "HALLPASS_DB_USER" -> user,
        "HALLPASS_DB_PASSWORD" -> Password
      )).toOption.get
      ownerConfig = configFor(Owner)
      runtimeConfig = configFor(Runtime)

  override def afterAll(): Unit = if dockerAvailable then container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  private def runtimeDatabase: Resource[IO, Transactor[IO]] =
    Resource.eval(PostgresDatabase.migrateAsOwner(ownerConfig, RuntimeRole.parse(Runtime).toOption.get)) *>
      Resource.eval(PostgresDatabase.resource(ownerConfig).use(DemoBootstrap.run)) *>
      PostgresDatabase.resourceWithSchema(runtimeConfig, MigrationMode.External).map(_._1)

  private def withOwner[A](f: Transactor[IO] => IO[A]): IO[A] = PostgresDatabase.resource(ownerConfig).use(f)

  private final case class Account(
      tenant: TenantId,
      human: Principal.Human,
      administrator: DirectoryUserId,
      connection: ConnectionId,
      resource: ResourceId
  )

  private def createAccount(xa: Transactor[IO], tenant: TenantId, human: Principal.Human, administrator: DirectoryUserId): IO[Account] =
    val connections = new PostgresConnectionRepository(xa)
    val id = ConnectionId.random()
    val secret = SecretReference.random()
    val external = ExternalId.parse(s"T${UUID.randomUUID().toString.take(8)}").getOrElse(fail("external id"))
    for
      _ <- connections.reserve(tenant, id, "SLACK", human, now)
      activated <- connections.activateReserved(
        tenant,
        id,
        ConnectionActivation(
          human, external, Some("OAuth fixture"), Some("OAuth fixture"), Some(now.minusSeconds(10)), "OAUTH_REFRESHABLE",
          secret, Slack.workspace, external, "OAuth fixture", None, singleActiveRoot = false
        ),
        now
      )
      connection <- IO.fromEither(activated.leftMap(error => RuntimeException(s"activation failed: $error")))
    yield Account(tenant, human, administrator, id, connection.resource)

  private def addSecondTenant(xa: Transactor[IO]): IO[Account] =
    val request = TenantProvisioningRequest.from(
      "OAuth isolation fixture", s"oauth-${UUID.randomUUID().toString.take(8)}",
      ExternalIdentity.from("urn:hallpass:oauth-refresh-test", UUID.randomUUID().toString).toOption.get
    ).toOption.get
    TenantProvisioning.provision(xa, request).flatMap(saved => createAccount(xa, saved.tenant, saved.administratorPrincipal, saved.administrator))

  private def freshAccount(xa: Transactor[IO]): IO[Account] = withOwner(addSecondTenant)

  private def target(xa: Transactor[IO], account: Account): IO[SelectedResource[Slack.Workspace]] =
    ResourceResolver(new PostgresControlPlane(xa)).resolve(account.tenant, Slack.workspace, ResourceLocator.ConnectionRoot()).flatMap:
      case Right(value) => IO.pure(value)
      case Left(reason) => IO.raiseError(RuntimeException(s"target resolution failed: $reason"))

  private def issueRedeemedLease(
      xa: Transactor[IO],
      account: Account,
      selected: SelectedResource[Slack.Workspace]
  ): IO[RedeemedExecutionLease] =
    val controlPlane = new PostgresControlPlane(xa)
    val credentialRepository = new PostgresAgentCredentials(xa)
    val directory = new PostgresIdentityDirectory(xa)
    val key = AgentCredentialHmacKey.fromBytes("oauth-refresh-test", Array.fill[Byte](32)(29)).toOption.get
    val keyRing = AgentCredentialKeyRing.from("oauth-refresh-test", Seq(key)).toOption.get
    val crypto = AgentCredentialHmacSha256(keyRing)
    val enrollment = AgentEnrollmentService(credentialRepository, crypto)
    val authenticator = AgentAuthenticator[IO](directory, credentialRepository, crypto)
    val enrollmentRequest = AgentCredentialEnrollmentRequest.from(Some("OAuth refresh test"), None).toOption.get
    val scope = selected.scope
    val requestId = AuthorizationRequestId.random()
    for
      administrator <- HumanAuthenticator[IO](directory).authenticate(account.administrator, account.tenant, now)
        .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"administrator authentication failed: $error"))))
      agent <- controlPlane.create(account.tenant, CreateAgent("OAuth refresh test agent", None))
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
        requestId, account.tenant, IdentityChain.direct(Principal.Agent(agentId)), scope,
        capabilityKey, Action.Read, AuthorizationContext.empty
      )
      capability = AuthorizationEngine.authorize(Policies(Vector(policy)), request, Vector.empty, now) match
        case AuthorizationResult.Authorized(value) => value
        case other => fail(s"authorization fixture failed: $other")
      binding = InvocationBinding.compute(
        account.tenant, agentId, OperationId.parse("slack.search.messages@1").get,
        capabilityKey, Action.Read, selected.resource, Slack.workspace, selected.externalId, io.circe.Json.obj()
      )
      metadata = ExecutionAuditMetadata.authenticatedInvocation(
        authenticated, ExecutionAuditCorrelationId.parse("oauth-refresh-integration").get,
        ResourceId.random(), CatalogCapabilityId.parse("00000000-0000-4000-8000-000000000001").get, binding
      )
      store <- InMemoryExecutionLeaseStore.create(Clock.fixed(now), Duration.ofSeconds(10), 100)
      audit <- InMemoryExecutionAuditRecorder.create
      issued <- InMemoryCredentialBroker(store, Clock.fixed(now), Duration.ofSeconds(60), audit).issueLease(capability, requestId, audience, metadata)
      redeemed <- store.redeem(issued.id, audience, now)
    yield redeemed match
      case LeaseRedemption.Redeemed(value) => value
      case other => fail(s"lease redemption fixture failed: $other")

  private final class MemorySecrets(initial: SecretReference, initialValue: ProviderSecret) extends SecretStore[IO]:
    private var contents = Map(initial -> initialValue)
    private var accesses = Vector.empty[String]
    @volatile var failPut = false
    def events: IO[Vector[String]] = IO(accesses)
    def stored(reference: SecretReference): IO[Option[ProviderSecret]] = IO(contents.get(reference))
    def get(binding: SecretBinding, reference: SecretReference): IO[Either[SecretStoreError, ProviderSecret]] = IO:
      accesses :+= s"get:${reference.value}"
      contents.get(reference).toRight(SecretStoreError.NotFound)
    def put(binding: SecretBinding, secret: ProviderSecret): IO[SecretReference] = IO:
      accesses :+= "put"
      if failPut then throw RuntimeException("injected secret store failure")
      val reference = SecretReference.random()
      contents = contents.updated(reference, secret)
      reference
    def delete(binding: SecretBinding, reference: SecretReference): IO[Unit] = IO:
      accesses :+= s"delete:${reference.value}"
      contents -= reference

  private final class RecordingRefresher(
      statusAtExchange: IO[String],
      response: Either[OAuthRefreshError, OAuthTokens] = Right(OAuthTokens.from("fresh-access", Some("fresh-refresh"), now.plusSeconds(3600)).get)
  ) extends OAuthTokenRefresher:
    private var count = 0
    private var observed = Vector.empty[String]
    def calls: IO[Int] = IO(count)
    def observedStatus: IO[Vector[String]] = IO(observed)
    def refresh(tokens: OAuthTokens): IO[Either[OAuthRefreshError, OAuthTokens]] =
      IO(count += 1) *> statusAtExchange.flatTap(value => IO(observed :+= value)) *> IO.sleep(100.millis).as(response)

  private def state(xa: Transactor[IO], account: Account): IO[(String, String)] =
    (TenantSession.establish(account.tenant) *>
      sql"select c.status, cr.secret_reference from connections c join credential_references cr on cr.tenant_id=c.tenant_id and cr.connection_id=c.id where c.tenant_id=${account.tenant.toString}::uuid and c.id=${account.connection.toString}::uuid and cr.credential_type='OAUTH_REFRESHABLE'"
        .query[(String, String)].unique).transact(xa)

  private def prepareSecrets(xa: Transactor[IO], account: Account, old: SecretReference): IO[Unit] =
    (TenantSession.establish(account.tenant) *>
      (sql"update credential_references set secret_reference=${old.value}, expires_at=${now.minusSeconds(10)} where tenant_id=${account.tenant.toString}::uuid and connection_id=${account.connection.toString}::uuid and credential_type='OAUTH_REFRESHABLE'".update.run *>
        sql"update connections set token_expires_at=${now.minusSeconds(10)} where tenant_id=${account.tenant.toString}::uuid and id=${account.connection.toString}::uuid".update.run).void).transact(xa)

  private def refreshResource(xa: Transactor[IO], secrets: SecretStore[IO], refresher: OAuthTokenRefresher) =
    PostgresOAuthRefreshRepository.resource(runtimeConfig, xa).map: repository =>
      RefreshableOAuth[Slack.Workspace](ProviderId.Slack, repository, secrets, codec, refresher, Clock.fixed(now), RefreshTokenRotation.Rotating)

  private final class CrashBeforePublishRepository(delegate: OAuthRefreshRepository) extends OAuthRefreshRepository:
    def withCredential[K](lease: RedeemedExecutionLease, target: SelectedResource[K], provider: ProviderId)(
        use: LockedOAuthCredential => IO[Either[ConnectionError, OAuthTokens]]
    ): IO[Either[ConnectionError, OAuthTokens]] =
      delegate.withCredential(lease, target, provider): slot =>
        use(new LockedOAuthCredential:
          val binding = slot.binding
          val reference = slot.reference
          val expiresAt = slot.expiresAt
          def requireReauthorization(at: Instant) = slot.requireReauthorization(at)
          def restore(at: Instant) = slot.restore(at)
          def publish(reference: SecretReference, expiresAt: Instant, at: Instant) =
            IO.raiseError(RuntimeException("simulated process loss before pointer commit"))
        )

  private def withTokenEndpoint(xa: Transactor[IO], account: Account)
      : Resource[IO, (OAuthRefreshClient, AtomicInteger, AtomicReference[String])] =
    Resource.make(IO.blocking:
      val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
      val calls = new AtomicInteger(0)
      val observed = new AtomicReference[String]("")
      server.createContext("/token", exchange =>
        calls.incrementAndGet()
        observed.set(state(xa, account).unsafeRunSync()._1)
        val body = """{"access_token":"fresh-access","refresh_token":"fresh-refresh","token_type":"Bearer","expires_in":3600}""".getBytes(StandardCharsets.UTF_8)
        exchange.sendResponseHeaders(200, body.length)
        val output = exchange.getResponseBody
        try output.write(body)
        finally output.close()
      )
      server.start()
      val endpoint = URI.create(s"http://127.0.0.1:${server.getAddress.getPort}/token")
      val config = OAuthRefreshClient.Config.from(endpoint, "integration-client", "integration-secret", allowHttpLoopback = true)
        .fold(message => throw IllegalArgumentException(message), identity)
      (server, OAuthRefreshClient.create(config, Clock.fixed(now)), calls, observed)
    )((server, _, _, _) => IO.blocking(server.stop(0))).map((_, client, calls, observed) => (client, calls, observed))

  test("independent repository instances single-flight an expired refresh and publish before returning credentials") {
    requireDocker()
    runtimeDatabase.use: xa =>
      for
        account <- freshAccount(xa)
        selected <- target(xa, account)
        secretStore = EnvelopeSecretStore(new TestKeys, new PostgresProviderSecrets(xa))
        old <- secretStore.put(SecretBinding(account.tenant, account.connection), codec.encode(OAuthTokens.from("old-access", Some("old-refresh"), now.minusSeconds(10)).get))
        _ <- prepareSecrets(xa, account, old)
        leases <- List.fill(2)(issueRedeemedLease(xa, account, selected)).sequence
        result <- withTokenEndpoint(xa, account).use: (refresher, endpointCalls, observedStatus) =>
          PostgresOAuthRefreshRepository.resource(runtimeConfig, xa).use: first =>
            PostgresOAuthRefreshRepository.resource(runtimeConfig, xa).use: second =>
              val one = RefreshableOAuth[Slack.Workspace](ProviderId.Slack, first, secretStore, codec, refresher, Clock.fixed(now), RefreshTokenRotation.Rotating)
              val two = RefreshableOAuth[Slack.Workspace](ProviderId.Slack, second, secretStore, codec, refresher, Clock.fixed(now), RefreshTokenRotation.Rotating)
              List(one.credentialFor(leases.head, selected), two.credentialFor(leases.last, selected)).parSequence
                .map(values => (values, endpointCalls.get(), observedStatus.get()))
        finalState <- state(xa, account)
        newPointer = finalState._2
        stored <- secretStore.get(SecretBinding(account.tenant, account.connection), SecretReference.parse(newPointer).get)
        secretRows <- (TenantSession.establish(account.tenant) *>
          sql"select count(*) from provider_secrets where tenant_id=${account.tenant.toString}::uuid and connection_id=${account.connection.toString}::uuid".query[Long].unique).transact(xa)
        immutableUpdate <- (TenantSession.establish(account.tenant) *>
          sql"update provider_secrets set ciphertext=ciphertext where tenant_id=${account.tenant.toString}::uuid".update.run).transact(xa).attempt
        secondLease <- issueRedeemedLease(xa, account, selected)
        secondResult <- withTokenEndpoint(xa, account).use: (refresher, endpointCalls, _) =>
          refreshResource(xa, secretStore, refresher).use(_.credentialFor(secondLease, selected)).map(result => (result, endpointCalls.get()))
      yield
        assertEquals(result._1.map(_.map(_.accessToken)), List(Right("fresh-access"), Right("fresh-access")))
        assertEquals(result._2, 1, "independent repository instances must share one token exchange")
        assertEquals(result._3, "NEEDS_REAUTH", "the durable marker commits before the token endpoint is called")
        assertEquals(finalState._1, "ACTIVE")
        assertNotEquals(newPointer, old.value)
        assert(stored.exists(value => codec.decode(value).exists(_.refreshToken.contains("fresh-refresh"))))
        assertEquals(secretRows, 1L, "old immutable version is cleaned up only after the new pointer is committed")
        assert(immutableUpdate.isLeft, "runtime cannot update append-only encrypted secret rows")
        assertEquals(secondResult._1.map(_.accessToken), Right("fresh-access"))
        assertEquals(secondResult._2, 0, "fresh metadata avoids another OAuth exchange")
  }

  test("replacement-store failure leaves the old pointer and durable reauthorization marker; retry is stopped") {
    requireDocker()
    runtimeDatabase.use: xa =>
      for
        account <- freshAccount(xa)
        selected <- target(xa, account)
        old <- IO(SecretReference.random())
        _ <- prepareSecrets(xa, account, old)
        secrets <- IO(new MemorySecrets(old, codec.encode(OAuthTokens.from("old-access", Some("old-refresh"), now.minusSeconds(10)).get)))
        _ = secrets.failPut = true
        refresher = new RecordingRefresher(state(xa, account).map(_._1))
        lease <- issueRedeemedLease(xa, account, selected)
        strategyResult <- refreshResource(xa, secrets, refresher).use(_.credentialFor(lease, selected))
        durable <- state(xa, account)
        listed <- new PostgresConnectionRepository(xa).list(account.tenant)
        leaseAgain <- issueRedeemedLease(xa, account, selected)
        retry <- refreshResource(xa, secrets, refresher).use(_.credentialFor(leaseAgain, selected))
        calls <- refresher.calls
      yield
        assertEquals(strategyResult, Left(ConnectionError.PersistenceFailure))
        assertEquals(durable, "NEEDS_REAUTH" -> old.value)
        assertEquals(listed.find(_.id == account.connection).map(_.status), Some(ConnectionStatus.NeedsReauth))
        assertEquals(retry, Left(ConnectionError.NotFound))
        assertEquals(calls, 1)
  }

  test("provider rejection commits NEEDS_REAUTH and prevents a second exchange") {
    requireDocker()
    runtimeDatabase.use: xa =>
      for
        account <- freshAccount(xa)
        selected <- target(xa, account)
        old <- IO(SecretReference.random())
        _ <- prepareSecrets(xa, account, old)
        secrets <- IO(new MemorySecrets(old, codec.encode(OAuthTokens.from("old-access", Some("old-refresh"), now.minusSeconds(10)).get)))
        refresher = new RecordingRefresher(state(xa, account).map(_._1), Left(OAuthRefreshError.Rejected))
        first <- issueRedeemedLease(xa, account, selected)
        result <- refreshResource(xa, secrets, refresher).use(_.credentialFor(first, selected))
        after <- state(xa, account)
        second <- issueRedeemedLease(xa, account, selected)
        retry <- refreshResource(xa, secrets, refresher).use(_.credentialFor(second, selected))
        calls <- refresher.calls
      yield
        assertEquals(result, Left(ConnectionError.MissingCredential))
        assertEquals(after, "NEEDS_REAUTH" -> old.value)
        assertEquals(retry, Left(ConnectionError.NotFound))
        assertEquals(calls, 1)
  }

  test("crash after immutable replacement insert leaves the old pointer and both versions readable") {
    requireDocker()
    runtimeDatabase.use: xa =>
      for
        account <- freshAccount(xa)
        selected <- target(xa, account)
        secretStore = EnvelopeSecretStore(new TestKeys, new PostgresProviderSecrets(xa))
        old <- secretStore.put(SecretBinding(account.tenant, account.connection), codec.encode(OAuthTokens.from("old-access", Some("old-refresh"), now.minusSeconds(10)).get))
        _ <- prepareSecrets(xa, account, old)
        lease <- issueRedeemedLease(xa, account, selected)
        (result, endpointCalls) <- withTokenEndpoint(xa, account).use: (refresher, calls, _) =>
          PostgresOAuthRefreshRepository.resource(runtimeConfig, xa).use: repository =>
            val strategy = RefreshableOAuth[Slack.Workspace](
              ProviderId.Slack, new CrashBeforePublishRepository(repository), secretStore, codec, refresher, Clock.fixed(now), RefreshTokenRotation.Rotating
            )
            strategy.credentialFor(lease, selected).map(_ -> calls)
        durable <- state(xa, account)
        refs <- (TenantSession.establish(account.tenant) *>
          sql"select reference from provider_secrets where tenant_id=${account.tenant.toString}::uuid and connection_id=${account.connection.toString}::uuid order by reference"
            .query[String].to[Vector]).transact(xa)
        oldTokens <- secretStore.get(SecretBinding(account.tenant, account.connection), old)
        orphan = refs.map(SecretReference.parse).flatten.find(_ != old).get
        replacement <- secretStore.get(SecretBinding(account.tenant, account.connection), orphan)
        retryLease <- issueRedeemedLease(xa, account, selected)
        retry <- withTokenEndpoint(xa, account).use: (refresher, calls, _) =>
          PostgresOAuthRefreshRepository.resource(runtimeConfig, xa).use: repository =>
            RefreshableOAuth[Slack.Workspace](ProviderId.Slack, repository, secretStore, codec, refresher, Clock.fixed(now), RefreshTokenRotation.Rotating)
              .credentialFor(retryLease, selected).map(_ -> calls)
      yield
        assertEquals(result, Left(ConnectionError.PersistenceFailure))
        assertEquals(endpointCalls.get(), 1)
        assertEquals(durable, "NEEDS_REAUTH" -> old.value)
        assertEquals(refs.size, 2, "the immutable replacement survives a crash before its pointer transaction")
        assertEquals(oldTokens.toOption.flatMap(codec.decode(_).toOption).map(_.accessToken), Some("old-access"))
        assertEquals(replacement.toOption.flatMap(codec.decode(_).toOption).flatMap(_.refreshToken), Some("fresh-refresh"))
        assertEquals(retry._1, Left(ConnectionError.NotFound))
        assertEquals(retry._2.get(), 0, "NEEDS_REAUTH prevents a repeated exchange")
  }

  test("cross-tenant and mismatched targets fail before any secret lookup") {
    requireDocker()
    runtimeDatabase.use: xa =>
      for
        first <- freshAccount(xa)
        other <- freshAccount(xa)
        firstTarget <- target(xa, first)
        otherTarget <- target(xa, other)
        firstLease <- issueRedeemedLease(xa, first, firstTarget)
        reference <- IO(SecretReference.random())
        secrets <- IO(new MemorySecrets(reference, codec.encode(OAuthTokens.from("access", Some("refresh"), now.plusSeconds(3600)).get)))
        refresher = new RecordingRefresher(IO.pure("ACTIVE"))
        otherProvider = ProviderId.parse("other").getOrElse(fail("provider"))
        result <- PostgresOAuthRefreshRepository.resource(runtimeConfig, xa).use: repository =>
          val strategy = RefreshableOAuth[Slack.Workspace](ProviderId.Slack, repository, secrets, codec, refresher, Clock.fixed(now), RefreshTokenRotation.Rotating)
          val wrongProvider = RefreshableOAuth[Slack.Workspace](otherProvider, repository, secrets, codec, refresher, Clock.fixed(now), RefreshTokenRotation.Rotating)
          (strategy.credentialFor(firstLease, otherTarget), wrongProvider.credentialFor(firstLease, firstTarget)).tupled
        events <- secrets.events
        calls <- refresher.calls
      yield
        assertEquals(result._1, Left(ConnectionError.InvalidState))
        assertEquals(result._2, Left(ConnectionError.InvalidState))
        assertEquals(events, Vector.empty)
        assertEquals(calls, 0)
  }

  // ---- credential state is not authority, recovery in place ---------------------------------------

  private def rejected(xa: Transactor[IO], account: Account, selected: SelectedResource[Slack.Workspace], error: OAuthRefreshError) =
    for
      old <- IO(SecretReference.random())
      _ <- prepareSecrets(xa, account, old)
      secrets <- IO(new MemorySecrets(old, codec.encode(OAuthTokens.from("old-access", Some("old-refresh"), now.minusSeconds(10)).get)))
      refresher = new RecordingRefresher(state(xa, account).map(_._1), Left(error))
      lease <- issueRedeemedLease(xa, account, selected)
      result <- refreshResource(xa, secrets, refresher).use(_.credentialFor(lease, selected))
    yield (old, result)

  test("a connection needing reauthorization is a credential failure, not revoked authority") {
    requireDocker()
    runtimeDatabase.use: xa =>
      for
        account <- freshAccount(xa)
        selected <- target(xa, account)
        _ <- rejected(xa, account, selected, OAuthRefreshError.Rejected)
        status <- state(xa, account).map(_._1)
        // Revalidation and resolution read the same addressability as before the refresh failed.
        scope <- new PostgresControlPlane(xa).currentScope(account.tenant, account.resource)
        resolved <- ResourceResolver(new PostgresControlPlane(xa)).resolve(account.tenant, Slack.workspace, ResourceLocator.ConnectionRoot())
      yield
        assertEquals(status, "NEEDS_REAUTH")
        assertEquals(scope.map(_.target.id), Some(account.resource))
        assertEquals(resolved.map(_.resource), Right(account.resource))
  }

  test("a refresh request that was never sent restores ACTIVE with the old pointer") {
    requireDocker()
    runtimeDatabase.use: xa =>
      for
        account <- freshAccount(xa)
        selected <- target(xa, account)
        (old, result) <- rejected(xa, account, selected, OAuthRefreshError.NotSent)
        after <- state(xa, account)
      yield
        assertEquals(result, Left(ConnectionError.MissingCredential))
        assertEquals(after, "ACTIVE" -> old.value)
  }

  test("reauthorizing in place swaps the credential for the same account and refuses another account") {
    requireDocker()
    runtimeDatabase.use: xa =>
      val connections = new PostgresConnectionRepository(xa)
      for
        account <- freshAccount(xa)
        selected <- target(xa, account)
        (old, _) <- rejected(xa, account, selected, OAuthRefreshError.Rejected)
        external <- (TenantSession.establish(account.tenant) *>
          sql"select external_account_id from connections where tenant_id=${account.tenant.toString}::uuid and id=${account.connection.toString}::uuid"
            .query[String].unique).transact(xa)
        accountId = ExternalId.parse(external).get
        other = ExternalId.parse("T-SOMEONE-ELSE").get
        fresh = SecretReference.random()
        expiry = Some(now.plusSeconds(3600))
        mismatch <- connections.reauthorize(account.tenant, account.connection,
          ConnectionReauthorization(account.human, other, other, expiry, "OAUTH_REFRESHABLE", fresh), now)
        stillNeeds <- state(xa, account)
        swapped <- connections.reauthorize(account.tenant, account.connection,
          ConnectionReauthorization(account.human, accountId, accountId, expiry, "OAUTH_REFRESHABLE", fresh), now)
        after <- state(xa, account)
        again <- connections.reauthorize(account.tenant, account.connection,
          ConnectionReauthorization(account.human, accountId, accountId, expiry, "OAUTH_REFRESHABLE", SecretReference.random()), now)
        root <- target(xa, account)
      yield
        assertEquals(mismatch, Left(ConnectionActivationError.AccountMismatch))
        assertEquals(stillNeeds, "NEEDS_REAUTH" -> old.value)
        assertEquals(swapped, Right(old))
        assertEquals(after, "ACTIVE" -> fresh.value)
        assertEquals(again, Left(ConnectionActivationError.NotReserved), "an active connection is not reauthorized")
        assertEquals(root.resource, account.resource, "the same root, so grants and selections still apply")
  }

  test("a grant built with OAuthGrant.refreshable is usable on its first execution without a refresh") {
    requireDocker()
    runtimeDatabase.use: xa =>
      val connections = new PostgresConnectionRepository(xa)
      for
        base <- freshAccount(xa)
        // A second connection in a fresh tenant would be refused by the active external-account index only for the same account; use a new one.
        tokens = OAuthTokens.from("first-access", Some("first-refresh"), now.plusSeconds(3600).plusNanos(123456789)).get
        workspace = ExternalId.parse(s"T${UUID.randomUUID().toString.take(8)}").get
        grant = OAuthGrant.refreshable(tokens, codec, workspace, workspace, "Refreshable", None, None)
        secrets <- IO(new MemorySecrets(SecretReference.random(), ProviderSecret.fromUtf8("unused")))
        id = ConnectionId.random()
        reference <- secrets.put(SecretBinding(base.tenant, id), grant.secret)
        _ <- (TenantSession.establish(base.tenant) *>
          sql"update connections set status='DISABLED' where tenant_id=${base.tenant.toString}::uuid and id=${base.connection.toString}::uuid".update.run).transact(xa)
        _ <- connections.reserve(base.tenant, id, "SLACK", base.human, now)
        activated <- connections.activateReserved(base.tenant, id, ConnectionActivation(
          base.human, workspace, None, None, grant.expiresAt, OAuthGrant.RefreshableCredentialType, reference,
          Slack.workspace, workspace, "Refreshable", None, singleActiveRoot = true
        ), now)
        connection = activated.getOrElse(fail(s"activation failed: $activated"))
        account = base.copy(connection = id, resource = connection.resource)
        selected <- target(xa, account)
        lease <- issueRedeemedLease(xa, account, selected)
        refresher = new RecordingRefresher(IO.pure("unused"), Left(OAuthRefreshError.Unavailable))
        result <- refreshResource(xa, secrets, refresher).use(_.credentialFor(lease, selected))
        calls <- refresher.calls
      yield
        assertEquals(result.map(_.accessToken), Right("first-access"))
        assertEquals(calls, 0)
  }
