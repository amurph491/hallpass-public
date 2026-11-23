package run.hallpass.gateway

import java.net.{InetSocketAddress, URI}
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.nio.charset.StandardCharsets
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.sql.DriverManager
import java.time.{Duration, Instant}
import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}
import cats.effect.{IO, Resource}
import cats.syntax.all.*
import io.circe.Json
import io.circe.parser.parse
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import scala.compiletime.uninitialized
import scala.concurrent.duration.*
import com.sun.net.httpserver.HttpServer
import run.hallpass.adapters.github.*
import run.hallpass.adapters.postgres.*
import run.hallpass.adapters.security.{AgentCredentialHmacKey, AgentCredentialKeyRing, AgentCredentialHmacSha256}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** GitHub through the real stdio bridge, agent HTTP API, PostgreSQL, authorization, credential strategy, and a fake
  * GitHub.
  *
  * One agent is delegated `GitHub.Issue.Read` on repository A only. The installation also has B (selected, not
  * delegated) and C (installed on GitHub, never selected in Hallpass). A works; B and C are denied before any secret
  * read or token mint; deselecting A and revoking the grant each block the next call the same way. */
final class BridgeGitHubEndToEndSuite extends CatsEffectSuite:
  private var container: PostgreSQLContainer[?] = uninitialized
  private var config: DatabaseConfig = uninitialized
  private var dockerAvailable = false

  private val installation = 4242L
  private val repositories = Map(1001L -> "octo/alpha", 1002L -> "octo/beta", 1003L -> "octo/gamma")

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

  test("a repository-scoped GitHub grant works in its repository only, and deselection and revocation block the next call") {
    assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")
    withFakeGitHub.use: github =>
      PostgresDatabase.resource(config).use: xa =>
        val repository = new PostgresControlPlane(xa)
        val credentialRepository = new PostgresAgentCredentials(xa)
        val connectionRepository = new PostgresConnectionRepository(xa)
        val resources = PostgresConnectionResources(xa)
        val audit = new PostgresExecutionAudit(xa)
        val secretReads = new AtomicInteger(0)
        val secretReference = SecretReference.random()
        val registration = GitHubAppRegistration(77, "Iv1.e2eclient", "hallpass-e2e")
        val stored = GitHubInstallationRecord.encode(
          GitHubInstallationRecord(registration.registrationKey, GitHubInstallationId.from(installation).get)
        )
        val secretStore = new CountingSecrets(secretReference, stored, secretReads)
        val now = Instant.now()
        val key = AgentCredentialHmacKey.fromBytes("integration-test", Array.fill[Byte](32)(23)).toOption.get
        val credentialCrypto = AgentCredentialHmacSha256(AgentCredentialKeyRing.from("integration-test", Seq(key)).toOption.get)
        val directory = PostgresIdentityDirectory(xa)
        val enrollment = AgentEnrollmentService(credentialRepository, credentialCrypto)
        val credentials = AgentCredentialServices(AgentAuthenticator[IO](directory, credentialRepository, credentialCrypto), enrollment)
        val human = DemoBootstrap.Human
        val tenant = DemoBootstrap.Tenant

        def select(root: ConnectionResource, id: Long): IO[ConnectionResource] =
          resources
            .select(tenant, root.connection, GitHub.repository, ExternalId.parse(id.toString).get, repositories(id), root.id, human, Instant.now())
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"select failed: $error"))))

        for
          _ <- DemoBootstrap.run(xa)
          administrator <- HumanAuthenticator[IO](directory)
            .authenticate(DemoBootstrap.AdministratorUser, tenant, now)
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"administrator: $error"))))
          agent <- repository.create(tenant, CreateAgent("bridge integration: GitHub", None))
            .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"agent creation failed: $error")), IO.pure))
          connectionId = ConnectionId.random()
          _ <- connectionRepository.reserve(tenant, connectionId, "GITHUB", human, now)
          activated <- connectionRepository.activateReserved(
            tenant, connectionId,
            ConnectionActivation(human, ExternalId.parse(s"github.com:installation:$installation").get,
              Some("octo"), Some("Organization"), None, GitHub.CredentialType, secretReference,
              GitHub.installation, ExternalId.parse(installation.toString).get, "octo", None, false),
            now
          )
          connection <- IO.fromEither(activated.leftMap(error => RuntimeException(s"connection activation failed: $error")))
          root <- resources.listFor(tenant, connectionId).flatMap(all =>
            IO.fromOption(all.find(_.id == connection.resource))(RuntimeException("connection root missing")))
          alpha <- select(root, 1001L)
          _ <- select(root, 1002L)
          capabilities <- repository.capabilities(tenant)
          issueRead <- IO.fromOption(capabilities.find(_.name == "GitHub.Issue.Read"))(RuntimeException("GitHub issue read capability missing"))
          grant <- repository.create(tenant, CreateDelegation(
            human, Principal.Agent(agent.id), issueRead.id, alpha.id, issueRead.descriptor.action, None
          )).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"grant failed: $error")), IO.pure))
          disclosure <- enrollment
            .enroll(administrator, agent.id, AgentCredentialEnrollmentRequest.from(Some("github e2e"), None).toOption.get, now)
            .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"enrollment failed: $error")), IO.pure))
          wireCredential = String(PresentedAgentCredential.canonicalBytes(disclosure.credential), StandardCharsets.US_ASCII)
          leases <- InMemoryExecutionLeaseStore.create
          gate <- SingleProcessTenantExecutionMutationGate.create
          validator = DurableLeaseAuthorityValidator(CurrentStateExecutionRevalidator(credentialRepository, repository, repository, repository))
          broker = InMemoryCredentialBroker(leases, Clock.system, Duration.ofMinutes(1), audit)
          http = HttpClient.newHttpClient()
          endpoints = GitHubEndpoints(github.uri, github.uri)
          app = GitHubAppClient(registration, GitHubAppSecrets(github.signingKey, "e2e-client-secret"), endpoints, http, Clock.system)
          registry <- IO.fromEither(
            OperationRegistry
              .from(
                GitHubReadOperations.all(registration, RepositoryProviderConnectionResolver(xa, secretStore), app, endpoints, http) ++
                  GitHubWriteOperations.all(registration, RepositoryProviderConnectionResolver(xa, secretStore), app, endpoints, http)
              )
              .leftMap(error => RuntimeException(s"invalid operation registry: $error"))
          )
          executor = ProviderExecutionService(leases, Clock.system, audit, validator, gate)
          tools = AgentToolService(registry, ResourceResolver(repository), repository, repository, broker, executor)
          api = AgentApi(AgentApiDependencies(credentials, Some(tools)))
          _ <- AgentHttpServer.resource(api, port = 0).use: server =>
            val apiEndpoint = s"http://127.0.0.1:${server.address.getPort}"
            withBridge(apiEndpoint, wireCredential).use: bridge =>
              def unchanged(reads: Int, mints: Int, calls: Int): IO[Unit] = IO:
                assertEquals(secretReads.get(), reads, "secret reads")
                assertEquals(github.mints.get(), mints, "token mints")
                assertEquals(github.providerCalls.get(), calls, "provider calls")
              for
                visible <- bridge.listTools("github_issues_list")
                _ <- IO(assert(visible.contains("github_issues_list"), s"bridge tools: $visible"))
                _ <- IO(assert(!visible.contains("github_pulls_list"), "pull request reads were never granted"))
                listing <- agentTools(apiEndpoint, wireCredential)
                _ <- IO(assertEquals(targetsOf(listing, "github_issues_list"), Vector("1001"), "only the delegated repository is offered"))
                allowed <- bridge.call("github_issues_list", Json.obj("repository_id" -> Json.fromString("1001")))
                _ <- IO(assert(!allowed.isError, s"authorized GitHub call failed: ${allowed.content}"))
                _ <- IO(assert(allowed.content.contains("provider-issue"), allowed.content))
                _ <- IO(assertEquals(github.lastNarrowing.get(), Some(Vector(1001L))))
                _ <- IO(assertEquals(github.lastPath.get(), Some("/repos/octo/alpha/issues")))
                _ <- unchanged(1, 1, 1)
                // The bridge enforces the discovery hint client-side, so send what a modified client could send.
                selectedNotGranted <- directCall(apiEndpoint, wireCredential, "1002")
                _ <- IO(assertEquals(selectedNotGranted, 403))
                // The bridge enforces the discovery hint client-side, so send what a modified client could send.
                notSelected <- directCall(apiEndpoint, wireCredential, "1003")
                _ <- IO(assertEquals(notSelected, 403))
                _ <- unchanged(1, 1, 1)
                deselected <- gate.withinMutation(tenant)(resources.deselect(tenant, alpha.id, Instant.now()))
                _ <- IO(assert(deselected.isRight, s"deselection failed: $deselected"))
                afterDeselect <- directCall(apiEndpoint, wireCredential, "1001")
                _ <- IO(assertEquals(afterDeselect, 403))
                _ <- unchanged(1, 1, 1)
                _ <- select(root, 1001L)
                reselected <- bridge.call("github_issues_list", Json.obj("repository_id" -> Json.fromString("1001")))
                _ <- IO(assert(!reselected.isError, s"reselected repository call failed: ${reselected.content}"))
                _ <- unchanged(2, 2, 2)
                // Capability separation: issue read on A never authorizes issue creation on A.
                createWithReadOnly <- directCall(apiEndpoint, wireCredential, "1001", "github_issues_create", Json.obj("title" -> Json.fromString("e2e")))
                _ <- IO(assertEquals(createWithReadOnly, 403))
                _ <- unchanged(2, 2, 2)
                issueCreate <- IO.fromOption(capabilities.find(_.name == "GitHub.Issue.Create"))(RuntimeException("GitHub issue create capability missing"))
                alphaNow <- resources.listFor(tenant, connectionId).map(_.find(_.externalId.value == "1001").get)
                _ <- repository.create(tenant, CreateDelegation(
                  human, Principal.Agent(agent.id), issueCreate.id, alphaNow.id, issueCreate.descriptor.action, None
                )).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"create grant failed: $error")), IO.pure))
                // The bridge refreshes its tool list on its own schedule; the server path is what is under test.
                created <- directCall(apiEndpoint, wireCredential, "1001", "github_issues_create", Json.obj("title" -> Json.fromString("e2e issue")))
                _ <- IO(assertEquals(created, 200))
                _ <- IO(assertEquals(github.lastNarrowing.get(), Some(Vector(1001L))))
                _ <- unchanged(3, 3, 3)
                createInB <- directCall(apiEndpoint, wireCredential, "1002", "github_issues_create", Json.obj("title" -> Json.fromString("e2e")))
                _ <- IO(assertEquals(createInB, 403))
                _ <- unchanged(3, 3, 3)
                revoked <- repository.revoke(tenant, grant.id, Instant.now())
                _ <- IO(assert(revoked.isRight))
                afterRevoke <- directCall(apiEndpoint, wireCredential, "1001")
                _ <- IO(assertEquals(afterRevoke, 403))
                _ <- unchanged(3, 3, 3)
                history <- audit.recent(tenant, Some(agent.id), 100)
              yield
                assertEquals(history.count(_.eventKind == ExecutionHistoryEventKind.ExecutionCompleted), 3)
                assertEquals(github.creates.get(), 1)
                assert(!listing.noSpaces.contains("ghs_"), "no token reaches the agent")
                assert(!allowed.content.contains(FakeGitHub.Token))
        yield ()
  }

  /** The agent API's tool listing, read directly to inspect the discovery hint in the schema. */
  private def agentTools(endpoint: String, credential: String): IO[Json] = IO.blocking:
    val request = HttpRequest.newBuilder(URI.create(s"$endpoint/api/agent/tools"))
      .header("Authorization", s"Bearer $credential").GET().build()
    val response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())
    assertEquals(response.statusCode(), 200)
    parse(response.body()).fold(error => throw AssertionError(s"invalid tools JSON: $error"), identity)

  /** A tool call sent straight to the agent API, as a client ignoring the schema hint would. Returns the status. */
  private def directCall(
      endpoint: String,
      credential: String,
      repository: String,
      tool: String = "github_issues_list",
      extra: Json = Json.obj()
  ): IO[Int] = IO.blocking:
    val body = Json.obj("arguments" -> Json.obj("repository_id" -> Json.fromString(repository)).deepMerge(extra)).noSpaces
    val request = HttpRequest.newBuilder(URI.create(s"$endpoint/api/agent/tools/$tool/call"))
      .header("Authorization", s"Bearer $credential").header("Content-Type", "application/json")
      .POST(HttpRequest.BodyPublishers.ofString(body)).build()
    HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString()).statusCode()

  private def targetsOf(listing: Json, tool: String): Vector[String] =
    listing.hcursor.downField("tools").focus.flatMap(_.asArray).toVector.flatten
      .find(_.hcursor.get[String]("name").toOption.contains(tool))
      .flatMap(_.hcursor.downField("inputSchema").downField("properties").downField("repository_id").downField("oneOf").focus)
      .flatMap(_.asArray).toVector.flatten
      .flatMap(_.hcursor.get[String]("const").toOption)

  private object FakeGitHub:
    val Token = "ghs_fakeInstallationTokenForE2E"

  private final class FakeGitHub(val uri: URI, val signingKey: RSAPrivateKey):
    val mints = AtomicInteger(0)
    val providerCalls = AtomicInteger(0)
    val creates = AtomicInteger(0)
    val lastNarrowing = AtomicReference[Option[Vector[Long]]](None)
    val lastPath = AtomicReference[Option[String]](None)

  /** Mints installation tokens narrowed to the requested repositories (dropping any the installation lacks), and
    * answers issue listings that carry the minted token. The App JWT is checked for shape only. */
  private def withFakeGitHub: Resource[IO, FakeGitHub] =
    Resource.make(IO.blocking:
      val generator = KeyPairGenerator.getInstance("RSA")
      generator.initialize(2048)
      val key = generator.generateKeyPair().getPrivate.asInstanceOf[RSAPrivateKey]
      val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
      val fake = new FakeGitHub(URI.create(s"http://127.0.0.1:${server.getAddress.getPort}"), key)
      def respond(exchange: com.sun.net.httpserver.HttpExchange, status: Int, body: Json): Unit =
        val bytes = body.noSpaces.getBytes(StandardCharsets.UTF_8)
        exchange.getResponseHeaders.add("Content-Type", "application/json")
        exchange.sendResponseHeaders(status, bytes.length)
        val output = exchange.getResponseBody
        try output.write(bytes)
        finally output.close()
      server.createContext(s"/app/installations/$installation/access_tokens", exchange =>
        val authorization = Option(exchange.getRequestHeaders.getFirst("Authorization")).getOrElse("")
        if exchange.getRequestMethod != "POST" || !authorization.startsWith("Bearer ") || authorization.count(_ == '.') != 2 then
          respond(exchange, 401, Json.obj("message" -> Json.fromString("Bad credentials")))
        else
          fake.mints.incrementAndGet()
          val request = parse(String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)).getOrElse(Json.obj())
          val requested = request.hcursor.get[Vector[Long]]("repository_ids").toOption
          fake.lastNarrowing.set(requested)
          val granted = requested.getOrElse(repositories.keys.toVector.sorted).filter(repositories.contains)
          val permissions = request.hcursor.downField("permissions").focus.getOrElse(Json.obj())
          respond(exchange, 201, Json.obj(
            "token" -> Json.fromString(FakeGitHub.Token),
            "expires_at" -> Json.fromString(Instant.now().plusSeconds(3600).toString),
            "permissions" -> permissions.deepMerge(Json.obj("metadata" -> Json.fromString("read"))),
            "repository_selection" -> Json.fromString("selected"),
            "repositories" -> Json.arr(granted.map(id =>
              Json.obj("id" -> Json.fromLong(id), "full_name" -> Json.fromString(repositories(id)))
            )*)
          ))
      )
      server.createContext("/repos/", exchange =>
        val authorization = Option(exchange.getRequestHeaders.getFirst("Authorization")).getOrElse("")
        if authorization != s"Bearer ${FakeGitHub.Token}" then respond(exchange, 401, Json.obj())
        else
          fake.providerCalls.incrementAndGet()
          fake.lastPath.set(Some(exchange.getRequestURI.getPath))
          if exchange.getRequestMethod == "POST" then
            fake.creates.incrementAndGet()
            respond(exchange, 201, Json.obj("number" -> Json.fromInt(8), "html_url" -> Json.fromString("https://github.com/octo/alpha/issues/8")))
          else respond(exchange, 200, Json.arr(Json.obj(
            "number" -> Json.fromInt(7),
            "title" -> Json.fromString("provider-issue"),
            "state" -> Json.fromString("open"),
            "user" -> Json.obj("login" -> Json.fromString("octocat")),
            "labels" -> Json.arr(),
            "created_at" -> Json.fromString("2026-09-01T00:00:00Z"),
            "updated_at" -> Json.fromString("2026-09-02T00:00:00Z"),
            "html_url" -> Json.fromString("https://github.com/octo/alpha/issues/7"),
            "body" -> Json.fromString("body")
          )))
      )
      server.start()
      server -> fake
    )((server, _) => IO.blocking(server.stop(0))).map(_._2)

  private def withBridge(endpoint: String, credential: String): Resource[IO, BridgeProcess] =
    Resource.make(IO.blocking:
      val launcher = java.nio.file.Path.of("bin", "hallpass-bridge").toAbsolutePath.toString
      val builder = new ProcessBuilder(launcher)
      builder.environment().put("HALLPASS_AGENT_API_URL", endpoint)
      builder.environment().put("HALLPASS_AGENT_CREDENTIAL", credential)
      new BridgeProcess(builder.start(), credential)
    )(_.close)

  private final class BridgeProcess(process: Process, credential: String):
    private val stderr = new AtomicReference("")
    private val stderrReader = new Thread(() => stderr.set(String(process.getErrorStream.readAllBytes(), StandardCharsets.UTF_8)))
    stderrReader.setDaemon(true)
    stderrReader.start()
    private val input = new java.io.PrintWriter(process.getOutputStream, true, StandardCharsets.UTF_8)
    private val output = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream, StandardCharsets.UTF_8))
    private val nextId = new AtomicInteger(1)

    def listTools(expected: String): IO[Set[String]] =
      for
        _ <- request("initialize", Json.obj(
          "protocolVersion" -> Json.fromString("2025-03-26"),
          "capabilities" -> Json.obj(),
          "clientInfo" -> Json.obj("name" -> Json.fromString("hallpass-e2e"), "version" -> Json.fromString("1"))
        )).void
        _ <- notify("notifications/initialized")
        tools <- pollTools(expected, 30)
      yield tools

    def call(name: String, arguments: Json): IO[ToolReply] =
      request("tools/call", Json.obj("name" -> Json.fromString(name), "arguments" -> arguments)).map: response =>
        val result = response.hcursor.downField("result")
        val error = result.get[Boolean]("isError").getOrElse(false)
        val content = result.downField("content").focus.flatMap(_.asArray).flatMap(_.headOption)
          .flatMap(_.hcursor.get[String]("text").toOption).getOrElse("")
        ToolReply(error, content)

    private def pollTools(expected: String, remaining: Int): IO[Set[String]] =
      request("tools/list", Json.obj()).flatMap: response =>
        val names = response.hcursor.downField("result").downField("tools").focus.flatMap(_.asArray)
          .toVector.flatten.flatMap(_.hcursor.get[String]("name").toOption).toSet
        if names.contains(expected) then IO.pure(names)
        else if remaining <= 1 then IO.raiseError(AssertionError(s"bridge did not expose $expected: $names"))
        else IO.sleep(200.millis) *> pollTools(expected, remaining - 1)

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
            throw AssertionError(s"bridge exited before replying: ${stderr.get().replace(credential, "<redacted>")}")
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

  private final class CountingSecrets(reference: SecretReference, stored: ProviderSecret, reads: AtomicInteger) extends SecretStore[IO]:
    def put(binding: SecretBinding, secret: ProviderSecret) = IO.pure(reference)
    def get(binding: SecretBinding, requested: SecretReference) = IO:
      reads.incrementAndGet()
      if requested == reference then Right(stored) else Left(SecretStoreError.NotFound)
    def delete(binding: SecretBinding, requested: SecretReference) = IO.unit
