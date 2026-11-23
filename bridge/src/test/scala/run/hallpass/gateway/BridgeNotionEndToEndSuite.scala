package run.hallpass.gateway

import java.net.{InetSocketAddress, URI}
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.nio.charset.StandardCharsets
import java.sql.DriverManager
import java.time.{Duration, Instant}
import java.util.UUID
import java.util.concurrent.atomic.{AtomicBoolean, AtomicInteger, AtomicReference}
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
import run.hallpass.adapters.notion.*
import run.hallpass.adapters.postgres.*
import run.hallpass.adapters.security.{AgentCredentialHmacKey, AgentCredentialKeyRing, AgentCredentialHmacSha256}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Notion through the real stdio bridge, agent HTTP API, PostgreSQL (catalog and approvals), NotionCredentials via
  * RepositoryProviderConnectionResolver, and a fake Notion. Read on page A works; page B (selected, not
  * granted) is denied before any secret read; append waits for approval and then executes exactly once. */
final class BridgeNotionEndToEndSuite extends CatsEffectSuite:
  private var container: PostgreSQLContainer[?] = uninitialized
  private var config: DatabaseConfig = uninitialized
  private var dockerAvailable = false

  private val workspaceId = UUID.randomUUID().toString
  private val pageA = UUID.randomUUID().toString
  private val pageB = UUID.randomUUID().toString
  private val botId = UUID.randomUUID().toString

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

  test("Notion read works on its page, append needs approval and runs once, and B, replay, provider failure, and revocation are blocked") {
    assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")
    withFakeNotion.use: notion =>
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
        val record = NotionTokenRecord
          .from(FakeNotion.Token, Some(FakeNotion.Refresh), NotionId.parse(botId).get, NotionId.parse(workspaceId).get).get
        val secretStore = new CountingSecrets(secretReference, NotionTokenRecord.encode(record), secretReads)
        val now = Instant.now()
        val key = AgentCredentialHmacKey.fromBytes("integration-test", Array.fill[Byte](32)(23)).toOption.get
        val credentialCrypto = AgentCredentialHmacSha256(AgentCredentialKeyRing.from("integration-test", Seq(key)).toOption.get)
        val directory = PostgresIdentityDirectory(xa)
        val enrollment = AgentEnrollmentService(credentialRepository, credentialCrypto)
        val credentials = AgentCredentialServices(AgentAuthenticator[IO](directory, credentialRepository, credentialCrypto), enrollment)
        val human = DemoBootstrap.Human
        val tenant = DemoBootstrap.Tenant

        def select(root: ConnectionResource, id: String, name: String): IO[ConnectionResource] =
          resources
            .select(tenant, root.connection, Notion.page, ExternalId.parse(id).get, name, root.id, human, Instant.now())
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"select failed: $error"))))

        def grant(agent: AgentId, name: String, target: ConnectionResource) =
          for
            capabilities <- repository.capabilities(tenant)
            capability <- IO.fromOption(capabilities.find(_.name == name))(RuntimeException(s"$name capability missing"))
            created <- repository.create(tenant, CreateDelegation(
              human, Principal.Agent(agent), capability.id, target.id, capability.descriptor.action, None
            )).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"grant failed: $error")), IO.pure))
          yield created

        for
          _ <- DemoBootstrap.run(xa)
          administrator <- HumanAuthenticator[IO](directory)
            .authenticate(DemoBootstrap.AdministratorUser, tenant, now)
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"administrator: $error"))))
          agent <- repository.create(tenant, CreateAgent("bridge integration: Notion", None))
            .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"agent creation failed: $error")), IO.pure))
          connectionId = ConnectionId.random()
          _ <- connectionRepository.reserve(tenant, connectionId, "NOTION", human, now)
          activated <- connectionRepository.activateReserved(
            tenant, connectionId, ConnectionActivation(
            human, ExternalId.parse(workspaceId).get, Some("workspace"), Some("Workspace"), None,
            Notion.CredentialType, secretReference, Notion.workspace, ExternalId.parse(workspaceId).get,
            "workspace", None, false), now
          )
          _ <- IO.fromEither(activated.leftMap(error => RuntimeException(s"connection activation failed: $error")))
          root <- resources.listFor(tenant, connectionId).flatMap(rows => IO.fromOption(rows.find(_.kind == Notion.workspace.wire))(RuntimeException("connection root missing")))
          a <- select(root, pageA, "Page A")
          _ <- select(root, pageB, "Page B")
          readGrant <- grant(agent.id, "Notion.Page.Read", a)
          _ <- grant(agent.id, "Notion.Page.Append", a)
          disclosure <- enrollment
            .enroll(administrator, agent.id, AgentCredentialEnrollmentRequest.from(Some("notion e2e"), None).toOption.get, now)
            .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"enrollment failed: $error")), IO.pure))
          wireCredential = String(PresentedAgentCredential.canonicalBytes(disclosure.credential), StandardCharsets.US_ASCII)
          leases <- InMemoryExecutionLeaseStore.create
          gate <- SingleProcessTenantExecutionMutationGate.create
          validator = DurableLeaseAuthorityValidator(CurrentStateExecutionRevalidator(credentialRepository, repository, repository, repository))
          broker = InMemoryCredentialBroker(leases, Clock.system, Duration.ofMinutes(1), audit)
          http = HttpClient.newHttpClient()
          endpoints = NotionEndpoints(notion.uri, notion.uri)
          registry <- IO.fromEither(
            OperationRegistry
              .from(NotionOperations.all(new NotionCredentials(RepositoryProviderConnectionResolver(xa, secretStore)), endpoints, http))
              .leftMap(error => RuntimeException(s"invalid operation registry: $error"))
          )
          executor = ProviderExecutionService(leases, Clock.system, audit, validator, gate)
          tools = AgentToolService(registry, ResourceResolver(repository), repository, repository, broker, executor, approvals = approvalStore)
          api = AgentApi(AgentApiDependencies(credentials, Some(tools)))
          _ <- AgentHttpServer.resource(api, port = 0).use: server =>
            val apiEndpoint = s"http://127.0.0.1:${server.address.getPort}"
            withBridge(apiEndpoint, wireCredential).use: bridge =>
              def unchanged(reads: Int, gets: Int, patches: Int): IO[Unit] = IO:
                assertEquals(secretReads.get(), reads, "secret reads")
                assertEquals(notion.gets.get(), gets, "provider GET requests")
                assertEquals(notion.patches.get(), patches, "provider PATCH requests")
              val paragraphs = Vector("first appended paragraph", "second appended paragraph")
              def appendArgs(page: String, texts: Vector[String]): Json =
                Json.obj("page_id" -> Json.fromString(page), "paragraphs" -> Json.arr(texts.map(Json.fromString)*))
              def pendingRows: IO[Vector[ApprovalRecord]] = approvalService.pending(administrator, Instant.now())
              def decide(approval: ApprovalRecord, approve: Boolean): IO[ApprovalRecord] =
                gate.withinMutation(tenant)(IO.defer(approvalService.decide(administrator, approval.id, approve, Instant.now())))
                  .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"decision failed: $error"))))
              for
                visible <- bridge.listTools("notion_pages_get")
                _ <- IO(assert(visible.contains("notion_pages_get"), s"bridge tools: $visible"))
                // 1. Reads on A through the bridge carry the stored bearer and the API version.
                page <- bridge.call("notion_pages_get", Json.obj("page_id" -> Json.fromString(pageA)))
                _ <- IO(assert(!page.isError, s"authorized page read failed: ${page.content}"))
                _ <- IO(assert(page.content.contains("Provider Page Title"), page.content))
                _ <- IO(assertEquals(notion.lastPath.get(), Some(s"/v1/pages/$pageA")))
                _ <- unchanged(1, 1, 0)
                children <- bridge.call("notion_blocks_children_list", Json.obj("page_id" -> Json.fromString(pageA)))
                _ <- IO(assert(!children.isError, s"children list failed: ${children.content}"))
                _ <- IO(assert(children.content.contains("paragraph: block one") && children.content.contains("paragraph: block two"), children.content))
                _ <- IO(assertEquals(notion.lastPath.get(), Some(s"/v1/blocks/$pageA/children")))
                _ <- unchanged(2, 2, 0)
                _ <- IO:
                  assertEquals(notion.lastAuthorization.get(), s"Bearer ${FakeNotion.Token}")
                  assertEquals(notion.lastVersion.get(), Notion.ApiVersion)
                // 2. Page B is selected but not granted: denied before any secret read or request.
                onB <- directCall(apiEndpoint, wireCredential, "notion_pages_get", Json.obj("page_id" -> Json.fromString(pageB)), None)
                _ <- IO(assertEquals(onB.status, 403))
                _ <- unchanged(2, 2, 0)
                // 3. Append needs approval: nothing is sent; one PENDING row previews exactly the paragraphs.
                first <- bridge.call("notion_blocks_append", appendArgs(pageA, paragraphs))
                _ <- IO(assert(first.isError, s"unapproved append must not succeed: ${first.content}"))
                pending <- pendingRows
                _ <- IO(assertEquals(pending.size, 1))
                approval = pending.head
                _ <- IO(assert(first.content.contains(approval.id.toString), s"reply names the approval: ${first.content}"))
                _ <- IO:
                  assertEquals(approval.status, ApprovalStatus.Pending)
                  assertEquals(approval.preview.hcursor.get[Vector[String]]("paragraphs").toOption, Some(paragraphs))
                _ <- unchanged(2, 2, 0)
                // 4. Approved under the gate: the identical bridge call appends exactly once.
                decided <- decide(approval, approve = true)
                _ <- IO(assertEquals(decided.status, ApprovalStatus.Approved))
                _ <- unchanged(2, 2, 0)
                appended <- bridge.call("notion_blocks_append", appendArgs(pageA, paragraphs))
                _ <- IO(assert(!appended.isError, s"approved append failed: ${appended.content}"))
                _ <- unchanged(3, 2, 1)
                _ <- IO:
                  assertEquals(notion.lastPatchPath.get(), Some(s"/v1/blocks/$pageA/children"))
                  assertEquals(notion.lastPatchTexts.get(), paragraphs)
                consumed <- approvalStore.find(tenant, approval.id).flatMap(IO.fromOption(_)(RuntimeException("approval row missing")))
                _ <- IO(assert(consumed.consumedAt.isDefined, "approval consumed by the retry"))
                // 5. The consumed id cannot authorize a different paragraph.
                replay <- directCall(apiEndpoint, wireCredential, "notion_blocks_append",
                  appendArgs(pageA, Vector("a different paragraph")), Some(approval.id.toString))
                _ <- IO(assertEquals(replay.status, 403))
                _ <- unchanged(3, 2, 1)
                // 6. A provider authentication failure is an error result, and nothing else happens.
                _ <- IO(notion.rejectReads.set(true))
                failed <- bridge.call("notion_pages_get", Json.obj("page_id" -> Json.fromString(pageA)))
                _ <- IO(assert(failed.isError, s"provider 401 must be an error: ${failed.content}"))
                _ <- unchanged(4, 3, 1)
                _ <- IO(notion.rejectReads.set(false))
                restored <- bridge.call("notion_pages_get", Json.obj("page_id" -> Json.fromString(pageA)))
                _ <- IO(assert(!restored.isError, s"read after restore failed: ${restored.content}"))
                _ <- unchanged(5, 4, 1)
                // 7. Revoking the read grant blocks the next read before any secret read or request.
                revoked <- repository.revoke(tenant, readGrant.id, Instant.now())
                _ <- IO(assert(revoked.isRight))
                afterRevoke <- directCall(apiEndpoint, wireCredential, "notion_pages_get", Json.obj("page_id" -> Json.fromString(pageA)), None)
                _ <- IO(assertEquals(afterRevoke.status, 403))
                _ <- unchanged(5, 4, 1)
              yield
                // 8. Neither the bearer nor the refresh token reaches the agent.
                List(page.content, children.content, first.content, appended.content, failed.content, restored.content,
                  onB.body, replay.body, afterRevoke.body).foreach: text =>
                  assert(!text.contains(FakeNotion.Token), "no bearer reaches the agent")
                  assert(!text.contains(FakeNotion.Refresh), "no refresh token reaches the agent")
        yield ()
  }

  private final case class DirectReply(status: Int, body: String)

  /** A tool call sent straight to the agent API, as a client ignoring the bridge would. */
  private def directCall(endpoint: String, credential: String, tool: String, arguments: Json, approval: Option[String]): IO[DirectReply] =
    IO.blocking:
      val body = Json.fromFields(Vector("arguments" -> arguments) ++ approval.map(id => "approval_id" -> Json.fromString(id))).noSpaces
      val request = HttpRequest.newBuilder(URI.create(s"$endpoint/api/agent/tools/$tool/call"))
        .header("Authorization", s"Bearer $credential").header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body)).build()
      val response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())
      DirectReply(response.statusCode(), response.body())

  private object FakeNotion:
    val Token = "ntn_fakeBotTokenForE2E"
    val Refresh = "ntn_fakeRefreshTokenForE2E"

  private final class FakeNotion(val uri: URI):
    val gets = AtomicInteger(0)
    val patches = AtomicInteger(0)
    val rejectReads = AtomicBoolean(false)
    val lastPath = AtomicReference[Option[String]](None)
    val lastAuthorization = AtomicReference("")
    val lastVersion = AtomicReference("")
    val lastPatchPath = AtomicReference[Option[String]](None)
    val lastPatchTexts = AtomicReference[Vector[String]](Vector.empty)

  /** Answers page, children, and append requests for page A only; every request must carry the stored bearer. */
  private def withFakeNotion: Resource[IO, FakeNotion] =
    Resource.make(IO.blocking:
      val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
      val fake = new FakeNotion(URI.create(s"http://127.0.0.1:${server.getAddress.getPort}"))
      def respond(exchange: com.sun.net.httpserver.HttpExchange, status: Int, body: Json): Unit =
        val bytes = body.noSpaces.getBytes(StandardCharsets.UTF_8)
        exchange.getResponseHeaders.add("Content-Type", "application/json")
        exchange.sendResponseHeaders(status, bytes.length)
        val output = exchange.getResponseBody
        try output.write(bytes)
        finally output.close()
      def paragraph(text: String): Json = Json.obj(
        "object" -> Json.fromString("block"),
        "type" -> Json.fromString("paragraph"),
        "paragraph" -> Json.obj("rich_text" -> Json.arr(Json.obj("plain_text" -> Json.fromString(text))))
      )
      server.createContext("/v1/", exchange =>
        val authorization = Option(exchange.getRequestHeaders.getFirst("Authorization")).getOrElse("")
        val path = exchange.getRequestURI.getPath
        if authorization != s"Bearer ${FakeNotion.Token}" then respond(exchange, 401, Json.obj())
        else if exchange.getRequestMethod == "PATCH" then
          val body = parse(String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)).getOrElse(Json.obj())
          fake.patches.incrementAndGet()
          fake.lastAuthorization.set(authorization)
          fake.lastVersion.set(Option(exchange.getRequestHeaders.getFirst("Notion-Version")).getOrElse(""))
          fake.lastPatchPath.set(Some(path))
          fake.lastPatchTexts.set(
            body.hcursor.downField("children").focus.flatMap(_.asArray).toVector.flatten
              .flatMap(_.hcursor.downField("paragraph").downField("rich_text").downArray.downField("text").get[String]("content").toOption)
          )
          respond(exchange, 200, Json.obj("object" -> Json.fromString("list"), "results" -> Json.arr()))
        else
          fake.gets.incrementAndGet()
          fake.lastAuthorization.set(authorization)
          fake.lastVersion.set(Option(exchange.getRequestHeaders.getFirst("Notion-Version")).getOrElse(""))
          fake.lastPath.set(Some(path))
          if fake.rejectReads.get() then respond(exchange, 401, Json.obj("message" -> Json.fromString("unauthorized")))
          else if path == s"/v1/pages/$pageA" then respond(exchange, 200, Json.obj(
            "object" -> Json.fromString("page"),
            "id" -> Json.fromString(pageA),
            "url" -> Json.fromString("https://www.notion.so/page-a"),
            "last_edited_time" -> Json.fromString("2026-09-02T00:00:00.000Z"),
            "archived" -> Json.False,
            "properties" -> Json.obj("Name" -> Json.obj(
              "type" -> Json.fromString("title"),
              "title" -> Json.arr(Json.obj("plain_text" -> Json.fromString("Provider Page Title")))
            ))
          ))
          else if path == s"/v1/blocks/$pageA/children" then respond(exchange, 200, Json.obj(
            "object" -> Json.fromString("list"),
            "results" -> Json.arr(paragraph("block one"), paragraph("block two")),
            "has_more" -> Json.False
          ))
          else respond(exchange, 404, Json.obj())
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
