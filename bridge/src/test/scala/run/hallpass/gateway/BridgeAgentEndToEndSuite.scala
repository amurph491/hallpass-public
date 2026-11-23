package run.hallpass.gateway

import java.net.{InetSocketAddress, URI}
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.nio.charset.StandardCharsets
import java.sql.DriverManager
import java.time.{Duration, Instant}
import java.util.concurrent.atomic.AtomicInteger
import cats.effect.{IO, Resource}
import cats.effect.std.Dispatcher
import cats.syntax.all.*
import io.circe.{Json, JsonObject}
import io.circe.parser.parse
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import scala.compiletime.uninitialized
import scala.concurrent.duration.*
import scala.jdk.CollectionConverters.*
import com.sun.net.httpserver.HttpServer
import run.hallpass.adapters.postgres.*
import run.hallpass.adapters.security.{AgentCredentialHmacKey, AgentCredentialKeyRing, AgentCredentialHmacSha256}
import run.hallpass.adapters.slack.{Slack, SlackOperations, SlackSearchMessagesClient}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Runs the actual stdio bridge across the HTTP, PostgreSQL, authorization, secret, and provider boundaries. */
final class BridgeAgentEndToEndSuite extends CatsEffectSuite:
  private var container: PostgreSQLContainer[?] = uninitialized
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
        statement.execute("create role hallpass login password 'test-password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute("grant connect on database test to hallpass")
        statement.execute("grant usage, create on schema public to hallpass")
      finally admin.close()
      config = DatabaseConfig.fromEnvironment(Map(
        "HALLPASS_DB_URL" -> container.getJdbcUrl,
        "HALLPASS_DB_USER" -> "hallpass",
        "HALLPASS_DB_PASSWORD" -> "test-password"
      )).toOption.get

  override def afterAll(): Unit = if dockerAvailable then container.stop()

  test("three real bridges have isolated agents and revoking one grant does not affect the other two") {
    assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")
    withSlackServer.use: (providerCalls, endpoint) =>
      PostgresDatabase.resource(config).use: xa =>
        val repository = new PostgresControlPlane(xa)
        val credentialRepository = new PostgresAgentCredentials(xa)
        val connectionRepository = new PostgresConnectionRepository(xa)
        val audit = new PostgresExecutionAudit(xa)
        val secretReads = new AtomicInteger(0)
        val secretReference = SecretReference.random()
        val secretStore = new CountingSecrets(secretReference, secretReads)
        val now = Instant.now()
        val key = AgentCredentialHmacKey.fromBytes("integration-test", Array.fill[Byte](32)(19)).toOption.get
        val keyRing = AgentCredentialKeyRing.from("integration-test", Seq(key)).toOption.get
        val credentialCrypto = AgentCredentialHmacSha256(keyRing)
        val directory = PostgresIdentityDirectory(xa)
        val enrollment = AgentEnrollmentService(credentialRepository, credentialCrypto)
        val authenticator = AgentAuthenticator[IO](directory, credentialRepository, credentialCrypto)
        val credentials = AgentCredentialServices(authenticator, enrollment)

        for
          _ <- DemoBootstrap.run(xa)
          administrator <- HumanAuthenticator[IO](directory)
            .authenticate(DemoBootstrap.AdministratorUser, DemoBootstrap.Tenant, now)
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"administrator: $error"))))
          agents <- List("Codex CLI", "Claude Code", "Google Antigravity").traverse: label =>
            repository.create(DemoBootstrap.Tenant, CreateAgent(s"bridge integration: $label", None)).flatMap(
              _.fold(error => IO.raiseError(RuntimeException(s"agent creation failed: $error")), IO.pure)
            )
          capabilities <- repository.capabilities(DemoBootstrap.Tenant)
          readCapability <- IO.fromOption(capabilities.find(_.name == "Slack.Message.Read"))(
            RuntimeException("Slack read capability missing")
          )
          connectionId = ConnectionId.random()
          _ <- connectionRepository.reserve(DemoBootstrap.Tenant, connectionId, "SLACK", DemoBootstrap.Human, now)
          activated <- connectionRepository.activateReserved(
            DemoBootstrap.Tenant,
            connectionId,
            ConnectionActivation(
              DemoBootstrap.Human, ExternalId.parse("T-BRIDGE").getOrElse(fail("workspace ID")), Some("test"),
              Some("test workspace"), None, "SLACK_OAUTH", secretReference, Slack.workspace,
              ExternalId.parse("T-BRIDGE").getOrElse(fail("workspace ID")), "test workspace", None, singleActiveRoot = true
            ),
            now
          )
          connection <- IO.fromEither(activated.leftMap(error => RuntimeException(s"connection activation failed: $error")))
          delegations <- agents.traverse: agent =>
            repository.create(DemoBootstrap.Tenant, CreateDelegation(
              DemoBootstrap.Human,
              Principal.Agent(agent.id),
              readCapability.id,
              connection.resource,
              readCapability.descriptor.action,
              None
            )).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"grant failed: $error")), IO.pure))
          enrollmentRequest = AgentCredentialEnrollmentRequest.from(Some("bridge integration"), None).toOption.get
          disclosures <- agents.traverse: agent =>
            enrollment.enroll(administrator, agent.id, enrollmentRequest, now).flatMap(
              _.fold(error => IO.raiseError(RuntimeException(s"enrollment failed: $error")), IO.pure)
            )
          wireCredentials = disclosures.map(disclosure =>
            String(PresentedAgentCredential.canonicalBytes(disclosure.credential), StandardCharsets.US_ASCII)
          )
          _ <- IO(assertEquals(agents.map(_.id).distinct.size, 3))
          _ <- IO(assertEquals(wireCredentials.distinct.size, 3))
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
                RepositoryConnectionResolver(connectionRepository, secretStore)
              )))
              .leftMap(error => RuntimeException(s"invalid operation registry: $error"))
          )
          executor = ProviderExecutionService(leases, Clock.system, audit, validator, gate)
          tools = AgentToolService(registry, ResourceResolver(repository), repository, repository, broker, executor)
          api = AgentApi(AgentApiDependencies(credentials, Some(tools)))
          _ <- Dispatcher.parallel[IO].use: dispatcher =>
            AgentHttpServer.resource(api, port = 0).use: server =>
              val apiEndpoint = s"http://127.0.0.1:${server.address.getPort}"
              val identityUri = URI.create(s"$apiEndpoint/api/agent/identity")
              val httpClient = HttpClient.newHttpClient()
              val wrongCredentialRequest = HttpRequest.newBuilder(identityUri)
                .header("Authorization", "Bearer ac1.invalid.invalid").GET().build()
              withBridges(apiEndpoint, wireCredentials).use: bridges =>
                for
                  identities <- wireCredentials.traverse: credential =>
                    val request = HttpRequest.newBuilder(identityUri)
                      .header("Authorization", s"Bearer $credential").GET().build()
                    IO.blocking(httpClient.send(request, HttpResponse.BodyHandlers.ofString()))
                  _ <- IO(identities.zip(agents).zip(wireCredentials).foreach { case ((identity, agent), credential) =>
                    assertEquals(identity.statusCode(), 200)
                    assertEquals(identity.headers().firstValue("Cache-Control").orElse(""), "no-store")
                    assertEquals(parse(identity.body()).toOption.flatMap(_.hcursor.get[String]("agentId").toOption), Some(agent.id.toString))
                    assert(!identity.body().contains(credential))
                  })
                  rejected <- IO.blocking(httpClient.send(wrongCredentialRequest, HttpResponse.BodyHandlers.ofString()))
                  _ <- IO(assertEquals(rejected.statusCode(), 401))
                  visibleTools <- bridges.traverse(_.listTools)
                  _ <- IO(visibleTools.foreach(names => assert(names.contains("slack_search_messages"), s"bridge tools: $names")))
                  initialCalls <- bridges.traverse(_.callSearch("roadmap"))
                  _ <- IO(initialCalls.foreach: success =>
                    assert(!success.isError, s"authorized bridge call failed: ${success.content}")
                    assert(success.content.contains("provider-result"))
                  )
                  _ <- IO(assertEquals(secretReads.get(), 3))
                  _ <- IO(assertEquals(providerCalls.get(), 3))
                  revoked <- repository.revoke(DemoBootstrap.Tenant, delegations(1).id, Instant.now())
                  _ <- IO(assert(revoked.isRight))
                  denied <- bridges(1).callSearch("roadmap")
                  _ <- IO(assert(denied.isError, "revoked bridge call should return an MCP tool error"))
                  _ <- IO(assert(denied.content.contains("Authorization denied")))
                  codexContinues <- bridges.head.callSearch("roadmap")
                  antigravityContinues <- bridges(2).callSearch("roadmap")
                  _ <- IO(assert(!codexContinues.isError, s"Codex was affected by another agent's revocation: ${codexContinues.content}"))
                  _ <- IO(assert(!antigravityContinues.isError, s"Antigravity was affected by another agent's revocation: ${antigravityContinues.content}"))
                  revokedCredential <- enrollment.revoke(
                    administrator,
                    agents(1).id,
                    disclosures(1).metadata.id,
                    Instant.now()
                  )
                  _ <- IO(assert(revokedCredential.isRight))
                  revokedIdentityRequest = HttpRequest.newBuilder(identityUri)
                    .header("Authorization", s"Bearer ${wireCredentials(1)}").GET().build()
                  revokedIdentity <- IO.blocking(httpClient.send(revokedIdentityRequest, HttpResponse.BodyHandlers.ofString()))
                  _ <- IO(assertEquals(revokedIdentity.statusCode(), 401))
                  history <- agents.traverse(agent => audit.recent(DemoBootstrap.Tenant, Some(agent.id), 100))
                  _ <- IO(assertEquals(history.map(_.count(_.eventKind == ExecutionHistoryEventKind.ExecutionCompleted)), List(2, 1, 2)))
                  _ <- IO(assert(history.flatten.map(_.agentId).toSet == agents.map(_.id).toSet))
                yield
                  assertEquals(secretReads.get(), 5)
                  assertEquals(providerCalls.get(), 5)
        yield ()
  }

  private def withSlackServer: Resource[IO, (AtomicInteger, URI)] =
    Resource.make(IO.blocking:
      val calls = new AtomicInteger(0)
      val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
      server.createContext("/", exchange =>
        calls.incrementAndGet()
        val body = """{"ok":true,"messages":{"matches":[{"channel_id":"C1","ts":"1.0","text":"provider-result","username":"tester"}]}}""".getBytes(StandardCharsets.UTF_8)
        exchange.sendResponseHeaders(200, body.length)
        val output = exchange.getResponseBody
        try output.write(body)
        finally output.close()
      )
      server.start()
      (calls, server, URI.create(s"http://127.0.0.1:${server.getAddress.getPort}/"))
    )((_, server, _) => IO.blocking(server.stop(0))).map((calls, _, endpoint) => calls -> endpoint)

  private def withBridge(endpoint: String, credential: String): Resource[IO, BridgeProcess] =
    Resource.make(IO.blocking:
      val launcher = java.nio.file.Path.of("bin", "hallpass-bridge").toAbsolutePath.toString
      val builder = new ProcessBuilder(launcher)
      builder.environment().put("HALLPASS_AGENT_API_URL", endpoint)
      builder.environment().put("HALLPASS_AGENT_CREDENTIAL", credential)
      val process = builder.start()
      new BridgeProcess(process, credential)
    )(_.close)

  private def withBridges(endpoint: String, credentials: List[String]): Resource[IO, List[BridgeProcess]] =
    credentials.traverse(withBridge(endpoint, _))

  private final class BridgeProcess(process: Process, credential: String):
    private val stderr = new java.util.concurrent.atomic.AtomicReference("")
    private val stderrReader = new Thread(() =>
      stderr.set(String(process.getErrorStream.readAllBytes(), StandardCharsets.UTF_8))
    )
    stderrReader.setDaemon(true)
    stderrReader.start()
    private val input = new java.io.PrintWriter(process.getOutputStream, true, StandardCharsets.UTF_8)
    private val output = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream, StandardCharsets.UTF_8))
    private val nextId = new AtomicInteger(1)

    def listTools: IO[Set[String]] =
      for
        _ <- request("initialize", Json.obj(
          "protocolVersion" -> Json.fromString("2025-03-26"),
          "capabilities" -> Json.obj(),
          "clientInfo" -> Json.obj("name" -> Json.fromString("hallpass-e2e"), "version" -> Json.fromString("1"))
        )).void
        _ <- notify("notifications/initialized")
        tools <- pollTools(30)
      yield tools

    def callSearch(query: String): IO[ToolReply] =
      request("tools/call", Json.obj(
        "name" -> Json.fromString("slack_search_messages"),
        "arguments" -> Json.obj("query" -> Json.fromString(query))
      )).map: response =>
        val result = response.hcursor.downField("result")
        val error = result.get[Boolean]("isError").getOrElse(false)
        val content = result.downField("content").focus.flatMap(_.asArray).flatMap(_.headOption)
          .flatMap(_.hcursor.get[String]("text").toOption).getOrElse("")
        ToolReply(error, content)

    private def pollTools(remaining: Int): IO[Set[String]] =
      request("tools/list", Json.obj()).flatMap: response =>
        val names = response.hcursor.downField("result").downField("tools").focus.flatMap(_.asArray)
          .toVector.flatten.flatMap(_.hcursor.get[String]("name").toOption).toSet
        if names.contains("slack_search_messages") then IO.pure(names)
        else if remaining <= 1 then IO.raiseError(AssertionError("bridge did not expose the authorized tool"))
        else IO.sleep(200.millis) *> pollTools(remaining - 1)

    private def request(method: String, params: Json): IO[Json] =
      val id = nextId.getAndIncrement()
      val message = Json.obj("jsonrpc" -> Json.fromString("2.0"), "id" -> Json.fromInt(id),
        "method" -> Json.fromString(method), "params" -> params)
      IO.blocking:
        input.println(message.noSpaces)
        var result: Option[Json] = None
        while result.isEmpty do
          val line = output.readLine()
          if line == null then
            val diagnostic = stderr.get().replace(credential, "<redacted>")
            throw AssertionError(s"bridge exited before replying to MCP request: $diagnostic")
          val parsed = parse(line).fold(error => throw AssertionError(s"invalid MCP JSON-RPC: $error"), identity)
          if parsed.hcursor.get[Int]("id").toOption.contains(id) then result = Some(parsed)
        result.get
      .timeout(15.seconds)

    private def notify(method: String): IO[Unit] = IO.blocking:
      input.println(Json.obj("jsonrpc" -> Json.fromString("2.0"), "method" -> Json.fromString(method)).noSpaces)

    def close: IO[Unit] = IO.blocking:
      process.destroy()
      if !process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS) then process.destroyForcibly()
      input.close()
      output.close()
      stderrReader.join(1000)
      assert(!stderr.get().contains(credential), "bridge diagnostics must not contain its bearer credential")

  private final case class ToolReply(isError: Boolean, content: String)

  private final class CountingSecrets(reference: SecretReference, reads: AtomicInteger) extends SecretStore[IO]:
    def put(binding: SecretBinding, secret: ProviderSecret) = IO.pure(reference)
    def get(binding: SecretBinding, requested: SecretReference) = IO:
      reads.incrementAndGet()
      if requested == reference then Right(ProviderSecret.fromUtf8("xoxb-integration-test-token"))
      else Left(SecretStoreError.NotFound)
    def delete(binding: SecretBinding, requested: SecretReference) = IO.unit
