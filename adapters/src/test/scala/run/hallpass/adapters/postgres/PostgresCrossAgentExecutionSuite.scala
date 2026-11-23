package run.hallpass.adapters.postgres

import java.net.{InetSocketAddress, URI}
import java.net.http.HttpClient
import java.nio.charset.StandardCharsets
import java.sql.DriverManager
import java.time.{Duration, Instant}
import java.util.concurrent.atomic.AtomicInteger
import cats.effect.{IO, Resource}
import cats.syntax.all.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import scala.compiletime.uninitialized
import com.sun.net.httpserver.HttpServer
import run.hallpass.adapters.security.{AgentCredentialHmacKey, AgentCredentialKeyRing, AgentCredentialHmacSha256}
import io.circe.Json
import run.hallpass.adapters.slack.{SlackOperations, SlackSearchMessagesClient, SlackSearchMessagesOperation}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Exercises the durable authorization path through PostgreSQL and the real brokered Slack executor.
  *
  * It runs in the production database shape: a migration owner applies the schema and grants, and every repository
  * operation below runs as the separate, non-owning runtime role in external mode. It is therefore also evidence that
  * the `afterMigrate` privilege matrix is sufficient for the full execution and revocation path. */
final class PostgresCrossAgentExecutionSuite extends CatsEffectSuite:
  // The first test in the suite migrates a fresh container, which is slow while other suites start theirs.
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(120, "s")
  private var container: PostgreSQLContainer[?] = uninitialized
  private var ownerConfig: DatabaseConfig = uninitialized
  private var config: DatabaseConfig = uninitialized
  private var dockerAvailable = false

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      val admin = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
      try
        val statement = admin.createStatement()
        statement.execute("create role authai_owner login password 'test-password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute("create role hallpass login password 'test-password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute("grant connect on database test to authai_owner, hallpass")
        statement.execute("revoke create on schema public from public")
        statement.execute("grant usage, create on schema public to authai_owner")
        statement.execute("grant usage on schema public to hallpass")
      finally admin.close()
      def configFor(user: String) = DatabaseConfig.fromEnvironment(Map(
        "HALLPASS_DB_URL" -> container.getJdbcUrl,
        "HALLPASS_DB_USER" -> user,
        "HALLPASS_DB_PASSWORD" -> "test-password"
      )).toOption.get
      ownerConfig = configFor("authai_owner")
      config = configFor("hallpass")

  /** The migration job runs as the owner; the application then connects only as the runtime role. */
  private def runtimeDatabase: Resource[IO, org.typelevel.doobie.util.transactor.Transactor[IO]] =
    Resource.eval(PostgresDatabase.migrateAsOwner(ownerConfig, RuntimeRole.parse("hallpass").toOption.get)) *>
      Resource.eval(PostgresDatabase.resource(ownerConfig).use(DemoBootstrap.run)) *>
      PostgresDatabase.resourceWithSchema(config, MigrationMode.External).map(_._1)

  override def afterAll(): Unit = if dockerAvailable then container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  test("revoking one of three enrolled agents prevents secret/provider access while the other two execute") {
    requireDocker()
    withSlackServer.use: (providerCalls, endpoint) =>
      runtimeDatabase.use: xa =>
        val repository = new PostgresControlPlane(xa)
        val credentialRepository = new PostgresAgentCredentials(xa)
        val connectionRepository = new PostgresConnectionRepository(xa)
        val audit = new PostgresExecutionAudit(xa)
        val secretReads = new AtomicInteger(0)
        val connectionId = ConnectionId.random()
        val secretReference = SecretReference.random()
        val secretStore = new CountingSecrets(secretReference, secretReads)
        val now = Instant.now()
        val key = AgentCredentialHmacKey.fromBytes("integration-test", Array.fill[Byte](32)(17)).toOption.get
        val keyRing = AgentCredentialKeyRing.from("integration-test", Seq(key)).toOption.get
        val credentialCrypto = AgentCredentialHmacSha256(keyRing)
        val directory = PostgresIdentityDirectory(xa)
        val authenticator = AgentAuthenticator[IO](directory, credentialRepository, credentialCrypto)
        val enrollment = AgentEnrollmentService(credentialRepository, credentialCrypto)
        val enrollmentRequest = AgentCredentialEnrollmentRequest.from(Some("integration test"), None).toOption.get
        val searchArguments = Json.obj("query" -> Json.fromString("roadmap"))

        for
          // The runtime role cannot provision; the owner seeded the tenant before this role connected.
          administrator <- HumanAuthenticator[IO](directory)
            .authenticate(DemoBootstrap.AdministratorUser, DemoBootstrap.Tenant, now)
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"administrator: $error"))))
          agents <- Vector("Codex", "Claude Code", "Antigravity").traverse(name =>
            repository.create(DemoBootstrap.Tenant, CreateAgent(name, None)).flatMap(_.fold(
              error => IO.raiseError(RuntimeException(s"agent creation failed: $error")), IO.pure
            ))
          )
          capabilities <- repository.capabilities(DemoBootstrap.Tenant)
          readCapability <- IO.fromOption(capabilities.find(_.name == "Slack.Message.Read"))(
            RuntimeException("Slack read capability missing")
          )
          createdConnection <- SlackConnectionFixture.create(xa, connectionId, secretReference, now)
          delegations <- agents.traverse(agent => repository.create(DemoBootstrap.Tenant, CreateDelegation(
            DemoBootstrap.Human,
            Principal.Agent(agent.id),
            readCapability.id,
            createdConnection.resource,
            readCapability.descriptor.action,
            None
          )).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"grant failed: $error")), IO.pure)))
          disclosures <- agents.traverse(agent => enrollment.enroll(
            administrator,
            agent.id,
            enrollmentRequest,
            Instant.now()
          ).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"enrollment failed: $error")), IO.pure)))
          contexts <- disclosures.traverse(disclosure => authenticator.authenticate(
            disclosure.credential,
            UnverifiedExecutionClaims.empty,
            Instant.now()
          ).map(_.fold(error => throw RuntimeException(s"agent authentication failed: $error"), identity)))
          connections <- connectionRepository.list(DemoBootstrap.Tenant)
          leases <- InMemoryExecutionLeaseStore.create
          gate <- SingleProcessTenantExecutionMutationGate.create
          validator = DurableLeaseAuthorityValidator(CurrentStateExecutionRevalidator(
            credentialRepository,
            repository,
            repository,
            repository
          ))
          broker = InMemoryCredentialBroker(leases, Clock.system, Duration.ofMinutes(1), audit)
          registry <- IO.fromEither(
            OperationRegistry
              .from(Vector(SlackOperations.searchMessages(
                SlackSearchMessagesClient(endpoint, HttpClient.newHttpClient(), Duration.ofSeconds(3)),
                new RepositoryConnectionResolver(connectionRepository, secretStore)
              )))
              .leftMap(error => RuntimeException(s"invalid operation registry: $error"))
          )
          executor = ProviderExecutionService(leases, Clock.system, audit, validator, gate)
          tools = AgentToolService(registry, ResourceResolver(repository), repository, repository, broker, executor)
          discoveries <- contexts.traverse(context => tools.discover(context, SlackSearchMessagesOperation.id, Instant.now()))
          revoked <- repository.revoke(DemoBootstrap.Tenant, delegations.head.id, Instant.now())
          denied <- tools.execute(
            contexts.head,
            SlackSearchMessagesOperation.id,
            searchArguments,
            Instant.now()
          )
          secretReadsAfterDenied = secretReads.get()
          providerCallsAfterDenied = providerCalls.get()
          expiredValidFrom = Instant.now().minusSeconds(120)
          expiredAt = Instant.now().minusSeconds(60)
          expiredGrant <- repository.create(DemoBootstrap.Tenant, CreateDelegation(
            DemoBootstrap.Human,
            Principal.Agent(agents.head.id),
            readCapability.id,
            createdConnection.resource,
            readCapability.descriptor.action,
            Some(Instant.now().plusSeconds(300))
          )).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"expired grant fixture failed: $error")), IO.pure))
          _ <- (TenantSession.establish(DemoBootstrap.Tenant) *>
            sql"update delegations set valid_from=${expiredValidFrom}, expires_at=${expiredAt} where id=${expiredGrant.id.toString}::uuid".update.run
          ).transact(xa)
          deniedExpired <- tools.execute(
            contexts.head,
            SlackSearchMessagesOperation.id,
            searchArguments,
            Instant.now()
          )
          secretReadsAfterExpired = secretReads.get()
          providerCallsAfterExpired = providerCalls.get()
          regrant <- repository.create(DemoBootstrap.Tenant, CreateDelegation(
            DemoBootstrap.Human,
            Principal.Agent(agents.head.id),
            readCapability.id,
            createdConnection.resource,
            readCapability.descriptor.action,
            None
          )).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"regrant failed: $error")), IO.pure))
          restored <- tools.execute(
            contexts.head,
            SlackSearchMessagesOperation.id,
            searchArguments,
            Instant.now()
          )
          completed <- contexts.tail.traverse(context => tools.execute(
            context,
            SlackSearchMessagesOperation.id,
            searchArguments,
            Instant.now()
          ))
          history <- audit.recent(DemoBootstrap.Tenant, None, 20)
        yield
          assertEquals(createdConnection.id, connectionId)
          assert(createdConnection.resource != DemoBootstrap.SlackResource)
          assertEquals(createdConnection.externalAccountId, Some("T123"))
          assertEquals(createdConnection.accountLabel, Some("Demo account"))
          assertEquals(connections.map(_.id), Vector(connectionId))
          assert(revoked.isRight)
          assertEquals(discoveries.flatten.size, 3)
          assert(discoveries.flatten.forall(_.result.isInstanceOf[AuthorizationResult.Authorized]))
          assert(denied.isInstanceOf[AgentToolExecutionResult.Denied])
          assertEquals(secretReadsAfterDenied, 0)
          assertEquals(providerCallsAfterDenied, 0)
          assert(deniedExpired.isInstanceOf[AgentToolExecutionResult.Denied])
          assertEquals(secretReadsAfterExpired, 0)
          assertEquals(providerCallsAfterExpired, 0)
          assert(regrant.id != delegations.head.id)
          assert(regrant.id != expiredGrant.id)
          assert(restored.isInstanceOf[AgentToolExecutionResult.Completed])
          assertEquals(completed.size, 2)
          assert(completed.forall(_.isInstanceOf[AgentToolExecutionResult.Completed]))
          assertEquals(secretReads.get(), 3)
          assertEquals(providerCalls.get(), 3)
          assertEquals(history.count(_.eventKind == ExecutionHistoryEventKind.ExecutionCompleted), 3)
          assertEquals(history.map(_.agentId).toSet, agents.map(_.id).toSet)
    }

  private def withSlackServer: Resource[IO, (AtomicInteger, URI)] =
    Resource.make(IO.blocking:
      val calls = new AtomicInteger(0)
      val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
      server.createContext("/", exchange =>
        calls.incrementAndGet()
        val body = """{"ok":true,"messages":{"matches":[]}}""".getBytes(StandardCharsets.UTF_8)
        exchange.sendResponseHeaders(200, body.length)
        val output = exchange.getResponseBody
        try output.write(body)
        finally output.close()
      )
      server.start()
      (calls, server, URI.create(s"http://127.0.0.1:${server.getAddress.getPort}/"))
    )((_, server, _) => IO.blocking(server.stop(0))).map((calls, _, endpoint) => calls -> endpoint)

  private final class CountingSecrets(reference: SecretReference, reads: AtomicInteger) extends SecretStore[IO]:
    def put(binding: SecretBinding, secret: ProviderSecret) = IO.pure(reference)
    def get(binding: SecretBinding, requested: SecretReference) = IO:
      reads.incrementAndGet()
      if requested == reference then Right(ProviderSecret.fromUtf8("xoxb-integration-test-token"))
      else Left(SecretStoreError.NotFound)
    def delete(binding: SecretBinding, requested: SecretReference) = IO.unit
