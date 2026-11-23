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
import run.hallpass.adapters.google.*
import run.hallpass.adapters.oauth.{OAuthRefreshClient, OAuthTokenJsonCodec}
import run.hallpass.adapters.postgres.*
import run.hallpass.adapters.security.{AgentCredentialHmacKey, AgentCredentialKeyRing, AgentCredentialHmacSha256}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Google Drive through the real stdio bridge, agent HTTP API, PostgreSQL (catalog, custody trigger, refresh
  * repository), non-rotating refreshable OAuth, and a fake Google.
  *
  * The google.account root is under personal custody: its custodian is H1. A1 holds `Google.DriveFile.Read` on file F1
  * from H1. A2 holds the same grant on F1 from H2, an ADMIN of the same tenant with the same owner policy binding; the
  * root of H2's authority is not the custodian, so it must be refused before any secret, refresh, or Google request. */
final class BridgeGoogleDriveEndToEndSuite extends CatsEffectSuite:
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(180, "s")
  private var container: PostgreSQLContainer[?] = uninitialized
  private var config: DatabaseConfig = uninitialized
  private var dockerAvailable = false

  private val fileOne = "1AbCdEfGhIjKlMnOpQrSt"
  private val fileTwo = "2ZyXwVuTsRqPoNmLkJiHg"
  private val accountSub = "104857295019283746501"
  private val oldAccess = "ya29.old_access_token_e2e"
  private val oldRefresh = "1//old_refresh_token_e2e"
  private val newAccess = "ya29.new_access_token_e2e"
  private val docText = "exported google doc text e2e"
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

  test("Google Drive: refresh once, export, file-scoped grant, personal custody refuses another administrator, deselection, no token in responses") {
    assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")
    withFakeGoogle.use: google =>
      PostgresDatabase.resource(config).use: xa =>
        val repository = new PostgresControlPlane(xa)
        val credentialRepository = new PostgresAgentCredentials(xa)
        val connectionRepository = new PostgresConnectionRepository(xa)
        val resources = PostgresConnectionResources(xa)
        val audit = new PostgresExecutionAudit(xa)
        val secrets = new MemorySecrets
        val key = AgentCredentialHmacKey.fromBytes("integration-test", Array.fill[Byte](32)(29)).toOption.get
        val credentialCrypto = AgentCredentialHmacSha256(AgentCredentialKeyRing.from("integration-test", Seq(key)).toOption.get)
        val directory = PostgresIdentityDirectory(xa)
        val enrollment = AgentEnrollmentService(credentialRepository, credentialCrypto)
        val credentials = AgentCredentialServices(AgentAuthenticator[IO](directory, credentialRepository, credentialCrypto), enrollment)
        val h1 = DemoBootstrap.Human
        val h2: Principal.Human = Principal.Human(UserId.random())
        val h2User = UUID.randomUUID()
        val tenant = DemoBootstrap.Tenant
        val now = Instant.now()
        // OAuthTokens carries microsecond precision, which is also what PostgreSQL stores.
        val expired = now.truncatedTo(java.time.temporal.ChronoUnit.MICROS).minusSeconds(60)

        def select(root: ConnectionResource, external: String, name: String): IO[ConnectionResource] =
          resources
            .select(tenant, root.connection, Google.driveFile, ExternalId.parse(external).get, name, root.id, h1, Instant.now())
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"select failed: $error"))))

        def newAgent(label: String, administrator: AuthenticatedHuman) =
          for
            agent <- repository.create(tenant, CreateAgent(label, None))
              .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"agent creation failed: $error")), IO.pure))
            disclosure <- enrollment
              .enroll(administrator, agent.id, AgentCredentialEnrollmentRequest.from(Some("google e2e"), None).toOption.get, now)
              .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"enrollment failed: $error")), IO.pure))
          yield agent -> String(PresentedAgentCredential.canonicalBytes(disclosure.credential), StandardCharsets.US_ASCII)

        for
          _ <- DemoBootstrap.run(xa)
          administrator <- HumanAuthenticator[IO](directory)
            .authenticate(DemoBootstrap.AdministratorUser, tenant, now)
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"administrator: $error"))))
          // H2: a second ACTIVE ADMIN of the same tenant, inserted as the owner role provisioning uses, then bound to the
          // Google owner policy by the same code that adds a provider to an existing tenant.
          _ <- (TenantSession.establish(tenant) *>
            sql"insert into principals(id,tenant_id,kind) values (${h2.id.toString}::uuid,${tenant.toString}::uuid,'HUMAN')".update.run *>
            sql"insert into human_identities(tenant_id,principal_id) values (${tenant.toString}::uuid,${h2.id.toString}::uuid)".update.run *>
            sql"insert into directory_users(id,status) values ($h2User::uuid,'ACTIVE')".update.run *>
            sql"insert into directory_external_identities(issuer,subject,user_id) values ('urn:hallpass:e2e','h2',$h2User::uuid)".update.run *>
            sql"""insert into directory_tenant_memberships(tenant_id,user_id,human_principal_id,role,status)
                  values (${tenant.toString}::uuid,$h2User::uuid,${h2.id.toString}::uuid,'ADMIN','ACTIVE')""".update.run).transact(xa)
          added <- ProviderCatalogProvisioning.addToExisting(xa, "demo", ExistingTenantProvider.Google)
          _ <- IO(assertEquals(added.map(_.administrators), Some(2), "both administrators are bound to the Google owner policy"))
          connectionId = ConnectionId.random()
          initialReference <- secrets.put(SecretBinding(tenant, connectionId),
            codec.encode(OAuthTokens.from(oldAccess, Some(oldRefresh), expired).get))
          _ <- connectionRepository.reserve(tenant, connectionId, "GOOGLE", h1, now)
          activated <- connectionRepository.activateReserved(
            tenant, connectionId, ConnectionActivation(
            h1, ExternalId.parse(s"accounts.google.com:$accountSub").get,
            Some("h1@example.test"), None, Some(expired), Google.CredentialType, initialReference,
            Google.account, ExternalId.parse(accountSub).get, "H1 Google account", Some(h1.id), false
            ), now
          )
          _ <- IO.fromEither(activated.leftMap(error => RuntimeException(s"connection activation failed: $error")))
          // The token expiry the refresh path reads must equal the stored token's expiry.
          _ <- (TenantSession.establish(tenant) *>
            sql"update credential_references set expires_at=$expired where tenant_id=${tenant.toString}::uuid and connection_id=${connectionId.toString}::uuid and credential_type='OAUTH_REFRESHABLE'".update.run *>
            sql"update connections set token_expires_at=$expired where tenant_id=${tenant.toString}::uuid and id=${connectionId.toString}::uuid".update.run).transact(xa)
          root <- resources.listFor(tenant, connectionId).flatMap(rows => IO.fromOption(rows.find(_.kind == Google.account.wire))(RuntimeException("connection root missing")))
          one <- select(root, fileOne, "File one")
          _ <- select(root, fileTwo, "File two")
          capabilities <- repository.capabilities(tenant)
          fileRead <- IO.fromOption(capabilities.find(_.name == "Google.DriveFile.Read"))(RuntimeException("Google file read capability missing"))
          agentOne <- newAgent("bridge integration: Google A1", administrator)
          agentTwo <- newAgent("bridge integration: Google A2", administrator)
          _ <- repository.create(tenant, CreateDelegation(
            h1, Principal.Agent(agentOne._1.id), fileRead.id, one.id, fileRead.descriptor.action, None
          )).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"grant failed: $error")), IO.pure))
          // Observed: delegation creation refuses H2 with GrantorLacksAuthority (custody is enforced at grant time), so no A2
          // delegation exists. If that ever changes, the call below must still be refused as a custodian mismatch.
          h2Grant <- repository.create(tenant, CreateDelegation(
            h2, Principal.Agent(agentTwo._1.id), fileRead.id, one.id, fileRead.descriptor.action, None
          ))
          leases <- InMemoryExecutionLeaseStore.create
          gate <- SingleProcessTenantExecutionMutationGate.create
          validator = DurableLeaseAuthorityValidator(CurrentStateExecutionRevalidator(credentialRepository, repository, repository, repository))
          broker = InMemoryCredentialBroker(leases, Clock.system, Duration.ofMinutes(1), audit)
          http = HttpClient.newHttpClient()
          endpoints = GoogleEndpoints(
            URI.create(s"${google.uri}/authorize"), URI.create(s"${google.uri}/token"),
            URI.create(s"${google.uri}/userinfo"), google.uri
          )
          refreshConfig <- IO.fromEither(
            OAuthRefreshClient.Config.from(endpoints.token, "google-e2e-client", "google-e2e-secret", allowHttpLoopback = true)
              .leftMap(message => RuntimeException(message))
          )
          bodies <- OAuthRefreshClient.resource(refreshConfig, Clock.system).use: refresher =>
            PostgresOAuthRefreshRepository.resource(config, xa).use: refreshRepository =>
              val oauth = new RefreshableOAuth[Google.DriveFile](ProviderId.Google, refreshRepository, secrets, codec, refresher, Clock.system, RefreshTokenRotation.NonRotating)
              for
                registry <- IO.fromEither(
                  OperationRegistry.from(GoogleDriveOperations.all(new GoogleDriveCredentials(oauth), endpoints, http))
                    .leftMap(error => RuntimeException(s"invalid operation registry: $error"))
                )
                executor = ProviderExecutionService(leases, Clock.system, audit, validator, gate)
                tools = AgentToolService(registry, ResourceResolver(repository), repository, repository, broker, executor)
                api = AgentApi(AgentApiDependencies(credentials, Some(tools)))
                outcome <- AgentHttpServer.resource(api, port = 0).use: server =>
                  val apiEndpoint = s"http://127.0.0.1:${server.address.getPort}"
                  withBridge(apiEndpoint, agentOne._2).use: bridge =>
                    val bodies = new ConcurrentLinkedQueue[String]()
                    def call(credential: String, tool: String, args: Json): IO[Int] =
                      directCall(apiEndpoint, credential, tool, args).map: (status, body) =>
                        bodies.add(body)
                        status
                    def file(id: String): Json = Json.obj("file_id" -> Json.fromString(id))
                    def requests: Int = google.driveRequests.size()
                    def refreshes: Int = google.refreshes.get()
                    for
                      visible <- bridge.listTools("drive_files_get")
                      _ <- IO(assert(visible.contains("drive_files_get"), s"bridge tools: $visible"))
                      before <- storedCredential(xa, tenant, connectionId)
                      _ <- IO(assertEquals(before._1.toEpochMilli, expired.toEpochMilli, "stored expiry equals the token expiry"))
                      // 1. Expired token: one refresh, then the metadata GET with the new token.
                      secretReadsBefore = secrets.reads.get()
                      first <- bridge.call("drive_files_get", file(fileOne))
                      _ <- IO(assert(!first.isError, s"authorized Drive get failed: ${first.content}"))
                      _ <- IO(assert(first.content.contains("fake-google-file"), first.content))
                      _ <- IO(assertEquals(refreshes, 1, "exactly one refresh"))
                      _ <- IO(assertEquals(google.refreshTokensSeen.asScala.toList, List(oldRefresh)))
                      _ <- IO(assertEquals(google.driveRequests.asScala.toList, List(s"/drive/v3/files/$fileOne?fields=")))
                      _ <- IO(assertEquals(google.bearersSeen.asScala.toList, List(newAccess), "Drive used the new token"))
                      _ <- IO(assert(secrets.reads.get() > secretReadsBefore, "the first call read the stored credential"))
                      rotated <- storedCredential(xa, tenant, connectionId)
                      stored <- secrets.get(SecretBinding(tenant, connectionId), SecretReference.parse(rotated._2).get)
                      decoded = stored.toOption.flatMap(codec.decode(_).toOption)
                      _ <- IO(assertEquals(decoded.map(_.accessToken), Some(newAccess)))
                      _ <- IO(assertEquals(decoded.flatMap(_.refreshToken), Some(oldRefresh), "NonRotating keeps the original refresh token"))
                      second <- bridge.call("drive_files_get", file(fileOne))
                      _ <- IO(assert(!second.isError, s"second get failed: ${second.content}"))
                      _ <- IO(assertEquals(refreshes, 1, "a fresh token needs no second refresh"))
                      _ <- IO(assertEquals(requests, 2))
                      // 2. Export of a Google Doc: metadata, then export as text/plain.
                      _ <- IO(google.fileOneMimeType.set("application/vnd.google-apps.document"))
                      exported <- bridge.call("drive_files_export_text", file(fileOne))
                      _ <- IO(assert(!exported.isError, s"export failed: ${exported.content}"))
                      _ <- IO(assert(exported.content.contains(docText), exported.content))
                      _ <- IO(assertEquals(google.exportMimeTypes.asScala.toList, List("text/plain")))
                      _ <- IO(assertEquals(requests, 4, "export is one metadata GET and one export GET"))
                      _ <- IO(assertEquals(refreshes, 1))
                      // 3. F2 is selected but never delegated: refused with no request and no refresh. The direct call
                      //    sends what a client ignoring the discovery hint could send.
                      readsBeforeDenials = secrets.reads.get()
                      inTwo <- call(agentOne._2, "drive_files_get", file(fileTwo))
                      _ <- IO(assertEquals(inTwo, 403))
                      _ <- IO(assertEquals(requests, 4))
                      _ <- IO(assertEquals(refreshes, 1))
                      // 4. Personal custody. Record which path refused H2's grant.
                      a2Status <- h2Grant match
                        case Left(refusal) =>
                          // Refused at creation (observed): assert the refusal and skip A2's call.
                          assertEquals(refusal, DelegationError.GrantorLacksAuthority)
                          IO.pure(Option.empty[Int])
                        case Right(_) =>
                          // Delegation creation accepted H2's grant; the call must be refused as CustodianMismatch.
                          call(agentTwo._2, "drive_files_get", file(fileOne)).map(Some(_))
                      _ <- IO(a2Status.foreach(status => assertEquals(status, 403, "A2's root of authority is not the custodian")))
                      _ <- IO(assertEquals(requests, 4, "A2 reached no Google request"))
                      _ <- IO(assertEquals(refreshes, 1, "A2 triggered no refresh"))
                      _ <- IO(assertEquals(secrets.reads.get(), readsBeforeDenials, "denials read no secret"))
                      // 5. Deselect F1 under the mutation gate: the next call is refused before any request.
                      deselected <- gate.withinMutation(tenant)(resources.deselect(tenant, one.id, Instant.now()))
                      _ <- IO(assert(deselected.isRight, s"deselection failed: $deselected"))
                      afterDeselect <- call(agentOne._2, "drive_files_get", file(fileOne))
                      _ <- IO(assertEquals(afterDeselect, 403))
                      _ <- IO(assertEquals(requests, 4))
                      _ <- IO(assertEquals(refreshes, 1))
                      _ <- IO(assertEquals(secrets.reads.get(), readsBeforeDenials))
                    yield bodies.asScala.toList :+ first.content :+ second.content :+ exported.content
              yield outcome
        yield
          // 6. No token reaches an agent response.
          val tokens = List(oldAccess, oldRefresh, newAccess)
          bodies.foreach(body => tokens.foreach(token => assert(!body.contains(token), "no token reaches the agent")))
  }

  /** A tool call sent straight to the agent API, as a client ignoring the schema hint would. */
  private def directCall(endpoint: String, credential: String, tool: String, arguments: Json): IO[(Int, String)] = IO.blocking:
    val request = HttpRequest.newBuilder(URI.create(s"$endpoint/api/agent/tools/$tool/call"))
      .header("Authorization", s"Bearer $credential").header("Content-Type", "application/json")
      .POST(HttpRequest.BodyPublishers.ofString(Json.obj("arguments" -> arguments).noSpaces)).build()
    val response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())
    (response.statusCode(), response.body())

  private final class FakeGoogle(val uri: URI):
    val refreshes = AtomicInteger(0)
    val refreshTokensSeen = new ConcurrentLinkedQueue[String]()
    val bearersSeen = new ConcurrentLinkedQueue[String]()
    val driveRequests = new ConcurrentLinkedQueue[String]()
    val exportMimeTypes = new ConcurrentLinkedQueue[String]()
    val fileOneMimeType = AtomicReference("application/pdf")

  /** `/token` accepts only the original refresh token and, as Google does, never returns a new one; `/drive/v3/files/...`
    * rejects any bearer other than the refreshed access token. */
  private def withFakeGoogle: Resource[IO, FakeGoogle] =
    Resource.make(IO.blocking:
      val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
      val fake = new FakeGoogle(URI.create(s"http://127.0.0.1:${server.getAddress.getPort}"))
      def respond(exchange: HttpExchange, status: Int, body: Array[Byte], contentType: String): Unit =
        exchange.getResponseHeaders.add("Content-Type", contentType)
        exchange.sendResponseHeaders(status, body.length)
        val output = exchange.getResponseBody
        try output.write(body)
        finally output.close()
      def json(exchange: HttpExchange, status: Int, body: Json): Unit =
        respond(exchange, status, body.noSpaces.getBytes(StandardCharsets.UTF_8), "application/json")
      def form(exchange: HttpExchange): Map[String, String] =
        String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8).split('&').toList.flatMap: pair =>
          pair.split("=", 2).toList match
            case k :: v :: Nil => Some(java.net.URLDecoder.decode(k, "UTF-8") -> java.net.URLDecoder.decode(v, "UTF-8"))
            case _             => None
        .toMap
      server.createContext("/token", exchange =>
        val fields = form(exchange)
        if exchange.getRequestMethod != "POST" || !fields.get("grant_type").contains("refresh_token") || !fields.get("refresh_token").contains(oldRefresh) then
          json(exchange, 400, Json.obj("error" -> Json.fromString("invalid_grant")))
        else
          fake.refreshes.incrementAndGet()
          fields.get("refresh_token").foreach(fake.refreshTokensSeen.add)
          json(exchange, 200, Json.obj(
            "access_token" -> Json.fromString(newAccess), "token_type" -> Json.fromString("Bearer"),
            "expires_in" -> Json.fromInt(3600), "scope" -> Json.fromString(Google.DriveScopes.mkString(" "))
          ))
      )
      server.createContext("/drive/v3/files/", exchange =>
        val authorization = Option(exchange.getRequestHeaders.getFirst("Authorization")).getOrElse("")
        if authorization != s"Bearer $newAccess" then
          json(exchange, 401, Json.obj("error" -> Json.obj("code" -> Json.fromInt(401))))
        else
          fake.bearersSeen.add(authorization.stripPrefix("Bearer "))
          val path = exchange.getRequestURI.getPath
          val query = Option(exchange.getRequestURI.getRawQuery).getOrElse("")
          fake.driveRequests.add(path + (if query.startsWith("fields=") then "?fields=" else if query.isEmpty then "" else "?" + query))
          val rest = path.stripPrefix("/drive/v3/files/")
          if rest.endsWith("/export") then
            val mime = query.split('&').toList.collectFirst { case q if q.startsWith("mimeType=") => java.net.URLDecoder.decode(q.stripPrefix("mimeType="), "UTF-8") }
            mime.foreach(fake.exportMimeTypes.add)
            respond(exchange, 200, docText.getBytes(StandardCharsets.UTF_8), "text/plain")
          else
            val mimeType = if rest == fileOne then fake.fileOneMimeType.get() else "application/pdf"
            json(exchange, 200, Json.obj(
              "id" -> Json.fromString(rest), "name" -> Json.fromString("fake-google-file"),
              "mimeType" -> Json.fromString(mimeType), "modifiedTime" -> Json.fromString("2026-09-30T00:00:00Z"),
              "trashed" -> Json.False
            ))
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
    val reads = AtomicInteger(0)
    private val contents = new java.util.concurrent.ConcurrentHashMap[SecretReference, ProviderSecret]()
    def put(binding: SecretBinding, secret: ProviderSecret) = IO:
      val reference = SecretReference.random()
      contents.put(reference, secret)
      reference
    def get(binding: SecretBinding, requested: SecretReference) = IO:
      reads.incrementAndGet()
      Option(contents.get(requested)).toRight(SecretStoreError.NotFound)
    def delete(binding: SecretBinding, requested: SecretReference) = IO(contents.remove(requested)).void
