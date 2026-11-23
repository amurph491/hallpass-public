package run.hallpass.gateway

import java.net.{InetSocketAddress, URI}
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.nio.charset.StandardCharsets
import java.sql.DriverManager
import java.time.{Duration, Instant}
import java.util.UUID
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}
import scala.jdk.CollectionConverters.*
import cats.effect.{IO, Resource}
import cats.syntax.all.*
import io.circe.Json
import io.circe.parser.parse
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import scala.compiletime.uninitialized
import scala.concurrent.duration.*
import com.sun.net.httpserver.{HttpExchange, HttpServer}
import run.hallpass.adapters.linear.*
import run.hallpass.adapters.oauth.{OAuthRefreshClient, OAuthTokenJsonCodec}
import run.hallpass.adapters.postgres.*
import run.hallpass.adapters.security.{AgentCredentialHmacKey, AgentCredentialKeyRing, AgentCredentialHmacSha256}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Linear through the real stdio bridge, agent HTTP API, PostgreSQL, authorization, refreshable OAuth, and a fake
  * Linear.
  *
  * The connection's stored access token is already expired, so the first call refreshes it against the fake token
  * endpoint and rotates the stored credential. One agent holds `Linear.Issue.Read` on team A only; team B is selected
  * but never delegated. Denials, revocation, and deselection must each stop the call before any GraphQL request or
  * refresh. No token reaches an agent API response. */
final class BridgeLinearEndToEndSuite extends CatsEffectSuite:
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(180, "s")
  private var container: PostgreSQLContainer[?] = uninitialized
  private var config: DatabaseConfig = uninitialized
  private var dockerAvailable = false

  private val teamA = "11111111-1111-4111-8111-111111111111"
  private val teamB = "22222222-2222-4222-8222-222222222222"
  private val organization = "33333333-3333-4333-8333-333333333333"
  private val oldAccess = "lin_old_access_token_e2e"
  private val oldRefresh = "lin_old_refresh_token_e2e"
  private val codec = new OAuthTokenJsonCodec

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

  private def storedCredential(xa: Transactor[IO], tenant: TenantId, connection: ConnectionId): IO[(Instant, String)] =
    (TenantSession.establish(tenant) *>
      sql"select expires_at, secret_reference from credential_references where tenant_id=${tenant.toString}::uuid and connection_id=${connection.toString}::uuid and credential_type='OAUTH_REFRESHABLE'"
        .query[(Instant, String)].unique).transact(xa)

  test("Linear: refresh on first use, team-scoped grants, create idempotency key, revocation and deselection, no token in responses") {
    assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")
    withFakeLinear.use: linear =>
      PostgresDatabase.resource(config).use: xa =>
        val repository = new PostgresControlPlane(xa)
        val credentialRepository = new PostgresAgentCredentials(xa)
        val connectionRepository = new PostgresConnectionRepository(xa)
        val resources = PostgresConnectionResources(xa)
        val audit = new PostgresExecutionAudit(xa)
        val secrets = new MemorySecrets
        val key = AgentCredentialHmacKey.fromBytes("integration-test", Array.fill[Byte](32)(23)).toOption.get
        val credentialCrypto = AgentCredentialHmacSha256(AgentCredentialKeyRing.from("integration-test", Seq(key)).toOption.get)
        val directory = PostgresIdentityDirectory(xa)
        val enrollment = AgentEnrollmentService(credentialRepository, credentialCrypto)
        val credentials = AgentCredentialServices(AgentAuthenticator[IO](directory, credentialRepository, credentialCrypto), enrollment)
        val human = DemoBootstrap.Human
        val tenant = DemoBootstrap.Tenant
        val now = Instant.now()
        // OAuthTokens carries microsecond precision, which is also what PostgreSQL stores.
        val expired = now.truncatedTo(java.time.temporal.ChronoUnit.MICROS).minusSeconds(60)

        def select(root: ConnectionResource, external: String, name: String): IO[ConnectionResource] =
          resources
            .select(tenant, root.connection, Linear.team, ExternalId.parse(external).get, name, root.id, human, Instant.now())
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"select failed: $error"))))

        for
          _ <- DemoBootstrap.run(xa)
          administrator <- HumanAuthenticator[IO](directory)
            .authenticate(DemoBootstrap.AdministratorUser, tenant, now)
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"administrator: $error"))))
          agent <- repository.create(tenant, CreateAgent("bridge integration: Linear", None))
            .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"agent creation failed: $error")), IO.pure))
          connectionId = ConnectionId.random()
          initialReference <- secrets.put(SecretBinding(tenant, connectionId),
            codec.encode(OAuthTokens.from(oldAccess, Some(oldRefresh), expired).get))
          _ <- connectionRepository.reserve(tenant, connectionId, "LINEAR", human, now)
          activated <- connectionRepository.activateReserved(
            tenant, connectionId, ConnectionActivation(
            human, ExternalId.parse(s"linear.app:organization:$organization").get,
            Some("Linear e2e"), Some("Organization"), Some(expired), Linear.CredentialType, initialReference,
            Linear.organization, ExternalId.parse(organization).get, "Linear e2e", None, false
            ), now
          )
          _ <- IO.fromEither(activated.leftMap(error => RuntimeException(s"connection activation failed: $error")))
          // The token expiry the refresh path reads must equal the stored token's expiry.
          _ <- (TenantSession.establish(tenant) *>
            sql"update credential_references set expires_at=$expired where tenant_id=${tenant.toString}::uuid and connection_id=${connectionId.toString}::uuid and credential_type='OAUTH_REFRESHABLE'".update.run *>
            sql"update connections set token_expires_at=$expired where tenant_id=${tenant.toString}::uuid and id=${connectionId.toString}::uuid".update.run).transact(xa)
          root <- resources.listFor(tenant, connectionId).flatMap(rows => IO.fromOption(rows.find(_.kind == Linear.organization.wire))(RuntimeException("connection root missing")))
          alpha <- select(root, teamA, "Team A")
          _ <- select(root, teamB, "Team B")
          capabilities <- repository.capabilities(tenant)
          issueRead <- IO.fromOption(capabilities.find(_.name == "Linear.Issue.Read"))(RuntimeException("Linear issue read capability missing"))
          issueCreate <- IO.fromOption(capabilities.find(_.name == "Linear.Issue.Create"))(RuntimeException("Linear issue create capability missing"))
          grant <- repository.create(tenant, CreateDelegation(
            human, Principal.Agent(agent.id), issueRead.id, alpha.id, issueRead.descriptor.action, None
          )).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"grant failed: $error")), IO.pure))
          disclosure <- enrollment
            .enroll(administrator, agent.id, AgentCredentialEnrollmentRequest.from(Some("linear e2e"), None).toOption.get, now)
            .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"enrollment failed: $error")), IO.pure))
          wireCredential = String(PresentedAgentCredential.canonicalBytes(disclosure.credential), StandardCharsets.US_ASCII)
          leases <- InMemoryExecutionLeaseStore.create
          gate <- SingleProcessTenantExecutionMutationGate.create
          validator = DurableLeaseAuthorityValidator(CurrentStateExecutionRevalidator(credentialRepository, repository, repository, repository))
          broker = InMemoryCredentialBroker(leases, Clock.system, Duration.ofMinutes(1), audit)
          http = HttpClient.newHttpClient()
          endpoints = LinearEndpoints(URI.create(s"${linear.uri}/authorize"), URI.create(s"${linear.uri}/oauth/token"), URI.create(s"${linear.uri}/graphql"))
          refreshConfig <- IO.fromEither(
            OAuthRefreshClient.Config.from(endpoints.token, "linear-e2e-client", "linear-e2e-secret", allowHttpLoopback = true)
              .leftMap(message => RuntimeException(message))
          )
          bodies <- OAuthRefreshClient.resource(refreshConfig, Clock.system).use: refresher =>
            PostgresOAuthRefreshRepository.resource(config, xa).use: refreshRepository =>
              val graphql = new LinearGraphQl(endpoints, http)
              val oauth = new RefreshableOAuth[Linear.Team](ProviderId.Linear, refreshRepository, secrets, codec, refresher, Clock.system, RefreshTokenRotation.Rotating)
              for
                registry <- IO.fromEither(
                  OperationRegistry.from(LinearOperations.all(new LinearCredentials(oauth), graphql))
                    .leftMap(error => RuntimeException(s"invalid operation registry: $error"))
                )
                executor = ProviderExecutionService(leases, Clock.system, audit, validator, gate)
                tools = AgentToolService(registry, ResourceResolver(repository), repository, repository, broker, executor)
                api = AgentApi(AgentApiDependencies(credentials, Some(tools)))
                outcome <- AgentHttpServer.resource(api, port = 0).use: server =>
                  val apiEndpoint = s"http://127.0.0.1:${server.address.getPort}"
                  withBridge(apiEndpoint, wireCredential).use: bridge =>
                    val bodies = new ConcurrentLinkedQueue[String]()
                    def call(tool: String, args: Json): IO[Int] =
                      directCall(apiEndpoint, wireCredential, tool, args).map: (status, body) =>
                        bodies.add(body)
                        status
                    def team(id: String, extra: (String, Json)*): Json = Json.obj(("team_id" -> Json.fromString(id)) +: extra*)
                    def graphqlFor(id: String): Int = linear.graphqlByTeam(id).get()
                    def refreshes: Int = linear.refreshes.get()
                    for
                      visible <- bridge.listTools("linear_issues_list")
                      _ <- IO(assert(visible.contains("linear_issues_list"), s"bridge tools: $visible"))
                      _ <- IO(assert(!visible.contains("linear_issues_create"), "create was never granted"))
                      before <- storedCredential(xa, tenant, connectionId)
                      _ <- IO(assertEquals(before._1.toEpochMilli, expired.toEpochMilli, "stored expiry equals the token expiry"))
                      first <- bridge.call("linear_issues_list", team(teamA))
                      _ <- IO(assert(!first.isError, s"authorized Linear list failed: ${first.content}"))
                      _ <- IO(assert(first.content.contains("fake-linear-issue"), first.content))
                      _ <- IO(assertEquals(refreshes, 1, "exactly one refresh"))
                      _ <- IO(assertEquals(linear.refreshTokensSeen.asScala.toList, List(oldRefresh)))
                      _ <- IO(assertEquals(graphqlFor(teamA), 1))
                      _ <- IO(assertEquals(linear.bearersSeen.asScala.toList, List(linear.currentAccess.get()), "GraphQL used the new token"))
                      _ <- IO(assertNotEquals(linear.currentAccess.get(), oldAccess))
                      rotated <- storedCredential(xa, tenant, connectionId)
                      stored <- secrets.get(SecretBinding(tenant, connectionId), SecretReference.parse(rotated._2).get)
                      decoded = stored.toOption.flatMap(codec.decode(_).toOption)
                      _ <- IO(assertEquals(decoded.map(_.accessToken), Some(linear.currentAccess.get())))
                      _ <- IO(assertEquals(decoded.flatMap(_.refreshToken), Some(linear.currentRefresh.get())))
                      _ <- IO(assertNotEquals(decoded.flatMap(_.refreshToken), Some(oldRefresh)))
                      second <- bridge.call("linear_issues_list", team(teamA))
                      _ <- IO(assert(!second.isError, s"second list failed: ${second.content}"))
                      _ <- IO(assertEquals(refreshes, 1, "a fresh token needs no second refresh"))
                      _ <- IO(assertEquals(graphqlFor(teamA), 2))
                      // The bridge enforces the discovery hint client-side, so send what a modified client could send.
                      inB <- call("linear_issues_list", team(teamB))
                      _ <- IO(assertEquals(inB, 403))
                      _ <- IO(assertEquals(graphqlFor(teamB), 0))
                      _ <- IO(assertEquals(refreshes, 1))
                      createReadOnly <- call("linear_issues_create", team(teamA, "title" -> Json.fromString("e2e")))
                      _ <- IO(assertEquals(createReadOnly, 403))
                      _ <- IO(assertEquals(linear.creates.size(), 0))
                      _ <- repository.create(tenant, CreateDelegation(
                        human, Principal.Agent(agent.id), issueCreate.id, alpha.id, issueCreate.descriptor.action, None
                      )).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"create grant failed: $error")), IO.pure))
                      created <- call("linear_issues_create", team(teamA, "title" -> Json.fromString("e2e issue")))
                      _ <- IO(assertEquals(created, 200))
                      _ <- IO(assertEquals(linear.creates.size(), 1))
                      createdAgain <- call("linear_issues_create", team(teamA, "title" -> Json.fromString("e2e issue")))
                      _ <- IO(assertEquals(createdAgain, 200))
                      ids = linear.creates.asScala.toList
                      _ <- IO(assertEquals(ids.size, 2))
                      _ <- IO(assert(ids.forall(i => scala.util.Try(UUID.fromString(i)).isSuccess), s"issue IDs are UUIDs: $ids"))
                      _ <- IO(assertNotEquals(ids.head, ids.last, "a new lease derives a new key"))
                      _ <- IO(assertEquals(linear.createTeams.asScala.toSet, Set(teamA)))
                      revoked <- repository.revoke(tenant, grant.id, Instant.now())
                      _ <- IO(assert(revoked.isRight))
                      afterRevoke <- call("linear_issues_list", team(teamA))
                      _ <- IO(assertEquals(afterRevoke, 403))
                      _ <- IO(assertEquals(graphqlFor(teamA), 2 + 2, "only the two creates reached GraphQL after the list calls"))
                      _ <- IO(assertEquals(refreshes, 1))
                      deselected <- gate.withinMutation(tenant)(resources.deselect(tenant, alpha.id, Instant.now()))
                      _ <- IO(assert(deselected.isRight, s"deselection failed: $deselected"))
                      afterDeselect <- call("linear_issues_create", team(teamA, "title" -> Json.fromString("e2e after deselect")))
                      _ <- IO(assertEquals(afterDeselect, 403))
                      _ <- IO(assertEquals(linear.creates.size(), 2))
                      _ <- IO(assertEquals(graphqlFor(teamA), 4))
                      _ <- IO(assertEquals(refreshes, 1))
                    yield bodies.asScala.toList :+ first.content :+ second.content
              yield outcome
        yield
          val tokens = List(oldAccess, oldRefresh, linear.currentAccess.get(), linear.currentRefresh.get())
          bodies.foreach(body => tokens.foreach(token => assert(!body.contains(token), "no token reaches the agent")))
  }

  /** A tool call sent straight to the agent API, as a client ignoring the schema hint would. */
  private def directCall(endpoint: String, credential: String, tool: String, arguments: Json): IO[(Int, String)] = IO.blocking:
    val request = HttpRequest.newBuilder(URI.create(s"$endpoint/api/agent/tools/$tool/call"))
      .header("Authorization", s"Bearer $credential").header("Content-Type", "application/json")
      .POST(HttpRequest.BodyPublishers.ofString(Json.obj("arguments" -> arguments).noSpaces)).build()
    val response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())
    (response.statusCode(), response.body())

  private final class FakeLinear(val uri: URI):
    val refreshes = AtomicInteger(0)
    val currentAccess = AtomicReference(oldAccess)
    val currentRefresh = AtomicReference(oldRefresh)
    val refreshTokensSeen = new ConcurrentLinkedQueue[String]()
    val bearersSeen = new ConcurrentLinkedQueue[String]()
    val creates = new ConcurrentLinkedQueue[String]()
    val createTeams = new ConcurrentLinkedQueue[String]()
    val graphqlByTeam = Map(teamA -> AtomicInteger(0), teamB -> AtomicInteger(0))

  /** `/oauth/token` rotates both tokens on every refresh; `/graphql` dispatches on the fixed document text and rejects
    * any bearer other than the current access token. */
  private def withFakeLinear: Resource[IO, FakeLinear] =
    Resource.make(IO.blocking:
      val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
      val fake = new FakeLinear(URI.create(s"http://127.0.0.1:${server.getAddress.getPort}"))
      def respond(exchange: HttpExchange, status: Int, body: Json): Unit =
        val bytes = body.noSpaces.getBytes(StandardCharsets.UTF_8)
        exchange.getResponseHeaders.add("Content-Type", "application/json")
        exchange.sendResponseHeaders(status, bytes.length)
        val output = exchange.getResponseBody
        try output.write(bytes)
        finally output.close()
      def form(exchange: HttpExchange): Map[String, String] =
        String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8).split('&').toList.flatMap: pair =>
          pair.split("=", 2).toList match
            case k :: v :: Nil => Some(java.net.URLDecoder.decode(k, "UTF-8") -> java.net.URLDecoder.decode(v, "UTF-8"))
            case _             => None
        .toMap
      server.createContext("/oauth/token", exchange =>
        val fields = form(exchange)
        if exchange.getRequestMethod != "POST" || !fields.get("grant_type").contains("refresh_token") || !fields.get("refresh_token").contains(fake.currentRefresh.get()) then
          respond(exchange, 400, Json.obj("error" -> Json.fromString("invalid_grant")))
        else
          val n = fake.refreshes.incrementAndGet()
          fields.get("refresh_token").foreach(fake.refreshTokensSeen.add)
          val access = s"lin_access_rotated_$n"
          val refresh = s"lin_refresh_rotated_$n"
          fake.currentAccess.set(access)
          fake.currentRefresh.set(refresh)
          respond(exchange, 200, Json.obj(
            "access_token" -> Json.fromString(access), "refresh_token" -> Json.fromString(refresh),
            "token_type" -> Json.fromString("Bearer"), "expires_in" -> Json.fromInt(3600)
          ))
      )
      server.createContext("/graphql", exchange =>
        val authorization = Option(exchange.getRequestHeaders.getFirst("Authorization")).getOrElse("")
        val body = parse(String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)).getOrElse(Json.obj())
        val query = body.hcursor.get[String]("query").getOrElse("")
        val variables = body.hcursor.downField("variables")
        if authorization != s"Bearer ${fake.currentAccess.get()}" then
          respond(exchange, 401, Json.obj("errors" -> Json.arr(Json.obj("message" -> Json.fromString("unauthorized")))))
        else
          fake.bearersSeen.add(authorization.stripPrefix("Bearer "))
          if query.contains("issueCreate") then
            val input = variables.downField("input")
            val id = input.get[String]("id").getOrElse("")
            val team = input.get[String]("teamId").getOrElse("")
            fake.creates.add(id)
            fake.createTeams.add(team)
            fake.graphqlByTeam.get(team).foreach(_.incrementAndGet())
            respond(exchange, 200, Json.obj("data" -> Json.obj("issueCreate" -> Json.obj(
              "success" -> Json.True,
              "issue" -> Json.obj("id" -> Json.fromString(id), "identifier" -> Json.fromString("ENG-9"), "url" -> Json.fromString("https://linear.app/e2e/issue/ENG-9"))
            ))))
          else if query.contains("issues(first") then
            val team = variables.get[String]("team").getOrElse("")
            fake.graphqlByTeam.get(team).foreach(_.incrementAndGet())
            respond(exchange, 200, Json.obj("data" -> Json.obj("team" -> Json.obj(
              "id" -> Json.fromString(team),
              "issues" -> Json.obj("nodes" -> Json.arr(Json.obj(
                "id" -> Json.fromString("44444444-4444-4444-8444-444444444444"),
                "identifier" -> Json.fromString("ENG-1"), "title" -> Json.fromString("fake-linear-issue"),
                "url" -> Json.fromString("https://linear.app/e2e/issue/ENG-1"), "updatedAt" -> Json.fromString("2026-09-30T00:00:00Z"),
                "state" -> Json.obj("name" -> Json.fromString("Todo"))
              )))
            ))))
          else if query.contains("issue(id") then
            respond(exchange, 200, Json.obj("data" -> Json.obj("issue" -> Json.Null)))
          else respond(exchange, 400, Json.obj("errors" -> Json.arr(Json.obj("message" -> Json.fromString("unknown document")))))
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


  private final class MemorySecrets extends SecretStore[IO]:
    private val contents = new java.util.concurrent.ConcurrentHashMap[SecretReference, ProviderSecret]()
    def put(binding: SecretBinding, secret: ProviderSecret) = IO:
      val reference = SecretReference.random()
      contents.put(reference, secret)
      reference
    def get(binding: SecretBinding, requested: SecretReference) = IO:
      Option(contents.get(requested)).toRight(SecretStoreError.NotFound)
    def delete(binding: SecretBinding, requested: SecretReference) = IO(contents.remove(requested)).void
