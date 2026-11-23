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
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*


/** Human approval through the real stdio bridge, agent HTTP API, ApprovalService, PostgreSQL (PostgresApprovalStore),
  * and a fake GitHub. The deciding owner policy for WRITE is REQUIRE_APPROVAL; a retry with the approved
  * ID executes exactly once, and nothing else (pending, denied, other arguments, revoked authority) ever does. */
final class BridgeApprovalEndToEndSuite extends CatsEffectSuite:
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

  test("a REQUIRE_APPROVAL write waits for a human decision, then executes once for exactly the approved invocation") {
    assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")
    withFakeGitHub.use: github =>
      PostgresDatabase.resource(config).use: xa =>
        val repository = new PostgresControlPlane(xa)
        val credentialRepository = new PostgresAgentCredentials(xa)
        val connectionRepository = new PostgresConnectionRepository(xa)
        val resources = PostgresConnectionResources(xa)
        val audit = new PostgresExecutionAudit(xa)
        val approvalStore = PostgresApprovalStore(xa)
        val approvalService = ApprovalService(approvalStore)
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

        /** The deciding owner policy for WRITE on the GitHub provider becomes REQUIRE_APPROVAL, for the demo human.
          * Deny and approval precede allow, so this overrides the provisioned allow. */
        def requireApprovalForWrites: IO[Unit] =
          val policy = java.util.UUID.randomUUID().toString
          val binding = java.util.UUID.randomUUID().toString
          val definition = """{"action":"WRITE","effect":"REQUIRE_APPROVAL"}"""
          val program: ConnectionIO[Unit] =
            for
              _ <- TenantSession.establish(tenant)
              _ <- sql"""insert into policies(id,tenant_id,name,version,status,definition,created_by)
                         values ($policy::uuid,${tenant.toString}::uuid,'GitHub write requires approval',1,'ACTIVE',$definition::jsonb,${human.id.toString}::uuid)""".update.run
              rows <- sql"""insert into policy_bindings(id,tenant_id,policy_id,subject_principal_id,resource_id)
                            select $binding::uuid,${tenant.toString}::uuid,$policy::uuid,${human.id.toString}::uuid,r.id
                              from resources r
                             where r.tenant_id=${tenant.toString}::uuid and r.resource_type='PROVIDER' and r.provider='github'""".update.run
              _ <- if rows == 1 then ().pure[ConnectionIO] else FC.raiseError[Unit](RuntimeException("no GitHub provider resource"))
            yield ()
          program.transact(xa)

        for
          _ <- DemoBootstrap.run(xa)
          _ <- requireApprovalForWrites
          administrator <- HumanAuthenticator[IO](directory)
            .authenticate(DemoBootstrap.AdministratorUser, tenant, now)
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"administrator: $error"))))
          agent <- repository.create(tenant, CreateAgent("bridge integration: approvals", None))
            .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"agent creation failed: $error")), IO.pure))
          connectionId = ConnectionId.random()
          _ <- connectionRepository.reserve(tenant, connectionId, "GITHUB", human, now)
          activated <- connectionRepository.activateReserved(
            tenant, connectionId, ConnectionActivation(
            human, ExternalId.parse(s"github.com:installation:$installation").get,
            Some("octo"), Some("Organization"), None, GitHub.CredentialType, secretReference,
            GitHub.installation, ExternalId.parse(installation.toString).get, "octo", None, false), now
          )
          _ <- IO.fromEither(activated.leftMap(error => RuntimeException(s"connection activation failed: $error")))
          root <- resources.listFor(tenant, connectionId).flatMap(rows => IO.fromOption(rows.find(_.kind == GitHub.installation.wire))(RuntimeException("connection root missing")))
          alpha <- select(root, 1001L)
          _ <- select(root, 1002L)
          capabilities <- repository.capabilities(tenant)
          issueCreate <- IO.fromOption(capabilities.find(_.name == "GitHub.Issue.Create"))(RuntimeException("GitHub issue create capability missing"))
          grant <- repository.create(tenant, CreateDelegation(
            human, Principal.Agent(agent.id), issueCreate.id, alpha.id, issueCreate.descriptor.action, None
          )).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"create grant failed: $error")), IO.pure))
          disclosure <- enrollment
            .enroll(administrator, agent.id, AgentCredentialEnrollmentRequest.from(Some("approval e2e"), None).toOption.get, now)
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
          tools = AgentToolService(registry, ResourceResolver(repository), repository, repository, broker, executor, approvals = approvalStore)
          api = AgentApi(AgentApiDependencies(credentials, Some(tools)))
          _ <- AgentHttpServer.resource(api, port = 0).use: server =>
            val apiEndpoint = s"http://127.0.0.1:${server.address.getPort}"
            withBridge(apiEndpoint, wireCredential).use: bridge =>
              def counts(mints: Int, creates: Int): IO[Unit] = IO:
                assertEquals(github.mints.get(), mints, "token mints")
                assertEquals(github.creates.get(), creates, "provider creates")
                assertEquals(github.providerCalls.get(), creates, "provider requests")
              def args(title: String): Json = Json.obj("repository_id" -> Json.fromString("1001"), "title" -> Json.fromString(title))
              def pendingRows: IO[Vector[ApprovalRecord]] = approvalService.pending(administrator, Instant.now())
              def allRows: IO[Int] = (TenantSession.establish(tenant) *>
                sql"select count(*) from approvals where tenant_id=${tenant.toString}::uuid".query[Int].unique).transact(xa)
              def decide(record: ApprovalRecord, approve: Boolean): IO[ApprovalRecord] =
                gate.withinMutation(tenant)(IO.defer(approvalService.decide(administrator, record.id, approve, Instant.now())))
                  .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"decision failed: $error"))))
              def stored(record: ApprovalRecord): IO[ApprovalRecord] =
                approvalStore.find(tenant, record.id).flatMap(IO.fromOption(_)(RuntimeException("approval row missing")))
              /** Calls through the bridge and returns the one new pending approval it created. */
              def requestApproval(title: String): IO[ApprovalRecord] =
                for
                  reply <- bridge.call("github_issues_create", args(title))
                  pending <- pendingRows
                  record <- IO.fromOption(pending.find(_.preview.noSpaces.contains(title)))(RuntimeException(s"no pending approval for $title: ${reply.content}"))
                  _ <- IO(assert(reply.isError && reply.content.contains(record.id.toString), s"approval id missing: ${reply.content}"))
                yield record
              for
                // An approval-required tool must be listed, or the agent could never request the approval.
                visible <- bridge.listTools("github_issues_create")
                _ <- IO(assert(visible.contains("github_issues_create"), s"bridge tools: $visible"))
                // 1. A required approval: not executed, one PENDING row bound to the invocation and the human.
                first <- bridge.call("github_issues_create", args("needs approval"))
                _ <- IO(assert(first.isError, s"unapproved create must not succeed: ${first.content}"))
                _ <- IO(assert(first.content.contains("same arguments"), first.content))
                pending1 <- pendingRows
                _ <- IO(assertEquals(pending1.size, 1))
                record = pending1.head
                _ <- IO(assert(first.content.contains(record.id.toString), s"reply names the approval: ${first.content}"))
                row <- stored(record)
                _ <- IO:
                  assertEquals(row.status, ApprovalStatus.Pending)
                  assertEquals(row.approver, human)
                  assertEquals(row.agent, agent.id)
                  assert(row.binding.value.matches("[0-9a-f]{64}"), "binding digest")
                  assertEquals(row.preview.hcursor.get[String]("title").toOption, Some("needs approval"))
                  assertEquals(row.consumedAt, None)
                _ <- counts(0, 0)
                // 2. The identical call before the decision: still pending under the same id, one row, nothing minted.
                second <- bridge.call("github_issues_create", args("needs approval"))
                _ <- IO(assert(second.isError && second.content.contains(record.id.toString), s"same pending approval: ${second.content}"))
                _ <- allRows.map(count => assertEquals(count, 1, "approval rows"))
                _ <- counts(0, 0)
                // 3. The human approves it, under the mutation gate as the admin route does.
                decided <- decide(record, approve = true)
                _ <- IO(assertEquals(decided.status, ApprovalStatus.Approved))
                _ <- counts(0, 0)
                // 4. The identical bridge retry carries the approved id: one mint narrowed to A, one create, row consumed.
                executed <- bridge.call("github_issues_create", args("needs approval"))
                _ <- IO(assert(!executed.isError, s"approved create failed: ${executed.content}"))
                _ <- IO(assert(executed.content.contains("Created issue"), executed.content))
                _ <- IO(assertEquals(github.lastNarrowing.get(), Some(Vector(1001L))))
                _ <- counts(1, 1)
                consumed <- stored(record)
                _ <- IO(assert(consumed.consumedAt.isDefined, "approval consumed by the retry"))
                // 5. Single use: the same call again needs a new approval and never creates a second issue.
                again <- bridge.call("github_issues_create", args("needs approval"))
                _ <- IO(assert(again.isError, s"second use must not execute: ${again.content}"))
                _ <- counts(1, 1)
                renewed <- pendingRows
                _ <- IO(assertEquals(renewed.size, 1, "a new pending approval, never a second create"))
                _ <- IO(assert(renewed.head.id != record.id))
                // 6. An approved id presented with other arguments is refused, and the approval is not consumed.
                other <- requestApproval("approved title")
                _ <- decide(other, approve = true)
                mismatched <- directCall(apiEndpoint, wireCredential, "1001", "github_issues_create",
                  Json.obj("title" -> Json.fromString("different title")), Some(other.id.toString))
                _ <- IO(assertEquals(mismatched, 403))
                _ <- counts(1, 1)
                _ <- stored(other).map(r => assertEquals(r.consumedAt, None))
                // 8. A denied approval never executes, with the id presented.
                denied <- requestApproval("denied title")
                _ <- decide(denied, approve = false)
                afterDenied <- bridge.call("github_issues_create", args("denied title"))
                _ <- IO(assert(afterDenied.isError, afterDenied.content))
                directDenied <- directCall(apiEndpoint, wireCredential, "1001", "github_issues_create",
                  Json.obj("title" -> Json.fromString("denied title")), Some(denied.id.toString))
                _ <- IO(assertEquals(directDenied, 403))
                _ <- counts(1, 1)
                // 7. Approved, then the delegation is revoked: the retry is refused and the approval stays unconsumed.
                revokedCase <- requestApproval("revoked title")
                _ <- decide(revokedCase, approve = true)
                revoked <- repository.revoke(tenant, grant.id, Instant.now())
                _ <- IO(assert(revoked.isRight))
                afterRevoke <- bridge.call("github_issues_create", args("revoked title"))
                _ <- IO(assert(afterRevoke.isError, afterRevoke.content))
                directRevoked <- directCall(apiEndpoint, wireCredential, "1001", "github_issues_create",
                  Json.obj("title" -> Json.fromString("revoked title")), Some(revokedCase.id.toString))
                _ <- IO(assertEquals(directRevoked, 403))
                _ <- counts(1, 1)
                _ <- stored(revokedCase).map(r => assertEquals(r.consumedAt, None))
              yield
                // 9. No provider token reaches the agent.
                List(first, second, executed, again, afterDenied, afterRevoke).foreach: reply =>
                  assert(!reply.content.contains(FakeGitHub.Token), "no token reaches the agent")
                  assert(!reply.content.contains("ghs_"), "no token reaches the agent")
        yield ()
  }

  /** A tool call sent straight to the agent API, as a client ignoring the bridge would. Returns the status. */
  private def directCall(
      endpoint: String,
      credential: String,
      repository: String,
      tool: String,
      extra: Json,
      approval: Option[String]
  ): IO[Int] = IO.blocking:
    val arguments = Json.obj("repository_id" -> Json.fromString(repository)).deepMerge(extra)
    val body = Json.fromFields(Vector("arguments" -> arguments) ++ approval.map(id => "approval_id" -> Json.fromString(id))).noSpaces
    val request = HttpRequest.newBuilder(URI.create(s"$endpoint/api/agent/tools/$tool/call"))
      .header("Authorization", s"Bearer $credential").header("Content-Type", "application/json")
      .POST(HttpRequest.BodyPublishers.ofString(body)).build()
    val response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())
    assert(!response.body().contains(FakeGitHub.Token), "no token reaches the agent")
    response.statusCode()

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
