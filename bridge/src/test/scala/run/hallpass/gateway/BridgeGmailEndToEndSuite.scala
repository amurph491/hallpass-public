package run.hallpass.gateway

import java.net.{InetSocketAddress, URI}
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.nio.charset.StandardCharsets
import java.sql.DriverManager
import java.time.{Duration, Instant}
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

/** Gmail send, the irreversible operation, through the real stdio bridge, agent HTTP API, PostgreSQL
  * (catalog, custody, approvals, delegation constraints, refresh repository), refreshable OAuth, and a fake Gmail
  *. A send needs approval, goes out exactly once for exactly the approved message, is limited to the
  * delegated recipient allowlist before approval is considered, and an unknown outcome is never retried. */
final class BridgeGmailEndToEndSuite extends CatsEffectSuite:
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(180, "s")
  private var container: PostgreSQLContainer[?] = uninitialized
  private var config: DatabaseConfig = uninitialized
  private var dockerAvailable = false

  private val accountSub = "104857295019283746501"
  private val oldAccess = "ya29.old_access_token_e2e"
  private val oldRefresh = "1//old_refresh_token_e2e"
  private val newAccess = "ya29.new_access_token_e2e"
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

  private def values(names: String*): NonEmptySet[ContextValue] =
    NonEmptySet.from(names.map(n => ContextValue.parse(n).get).toSet).get

  private def str(value: String): Json = Json.fromString(value)
  private def strings(values: String*): Json = Json.arr(values.map(str)*)

  test("Gmail send: approval, exactly one send, recipient allowlist, normalization, header injection, unknown outcome, no token in responses") {
    assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")
    withFakeGmail.use: gmail =>
      PostgresDatabase.resource(config).use: xa =>
        val repository = new PostgresControlPlane(xa)
        val credentialRepository = new PostgresAgentCredentials(xa)
        val connectionRepository = new PostgresConnectionRepository(xa)
        val resources = PostgresConnectionResources(xa)
        val audit = new PostgresExecutionAudit(xa)
        val approvalStore = PostgresApprovalStore(xa)
        val approvalService = ApprovalService(approvalStore)
        val secrets = new MemorySecrets
        val key = AgentCredentialHmacKey.fromBytes("integration-test", Array.fill[Byte](32)(37)).toOption.get
        val credentialCrypto = AgentCredentialHmacSha256(AgentCredentialKeyRing.from("integration-test", Seq(key)).toOption.get)
        val directory = PostgresIdentityDirectory(xa)
        val enrollment = AgentEnrollmentService(credentialRepository, credentialCrypto)
        val credentials = AgentCredentialServices(AgentAuthenticator[IO](directory, credentialRepository, credentialCrypto), enrollment)
        val h1 = DemoBootstrap.Human
        val tenant = DemoBootstrap.Tenant
        val now = Instant.now()
        val expired = now.truncatedTo(java.time.temporal.ChronoUnit.MICROS).minusSeconds(60)

        for
          _ <- DemoBootstrap.run(xa)
          administrator <- HumanAuthenticator[IO](directory)
            .authenticate(DemoBootstrap.AdministratorUser, tenant, now)
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"administrator: $error"))))
          agent <- repository.create(tenant, CreateAgent("bridge integration: Gmail", None))
            .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"agent creation failed: $error")), IO.pure))
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
          _ <- (TenantSession.establish(tenant) *>
            sql"update credential_references set expires_at=$expired where tenant_id=${tenant.toString}::uuid and connection_id=${connectionId.toString}::uuid and credential_type='OAUTH_REFRESHABLE'".update.run *>
            sql"update connections set token_expires_at=$expired where tenant_id=${tenant.toString}::uuid and id=${connectionId.toString}::uuid".update.run).transact(xa)
          root <- resources.listFor(tenant, connectionId).flatMap(rows => IO.fromOption(rows.find(_.kind == Google.account.wire))(RuntimeException("connection root missing")))
          mailbox <- resources
            .select(tenant, root.connection, Google.mailbox, ExternalId.parse(accountSub).get, "H1 mailbox", root.id, h1, Instant.now())
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"select failed: $error"))))
          capabilities <- repository.capabilities(tenant)
          mailSend <- IO.fromOption(capabilities.find(_.name == "Google.Mail.Send"))(RuntimeException("Google.Mail.Send capability missing"))
          _ <- IO(assertEquals(mailSend.descriptor.action, Action.Write))
          _ <- repository.create(tenant, CreateDelegation(
            h1, Principal.Agent(agent.id), mailSend.id, mailbox.id, mailSend.descriptor.action, None,
            Constraints(Set(Constraint.ValueIn(Google.RecipientsFact, values("alice@example.com", "bob@example.com"))))
          )).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"grant failed: $error")), IO.pure))
          disclosure <- enrollment
            .enroll(administrator, agent.id, AgentCredentialEnrollmentRequest.from(Some("gmail e2e"), None).toOption.get, now)
            .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"enrollment failed: $error")), IO.pure))
          wireCredential = String(PresentedAgentCredential.canonicalBytes(disclosure.credential), StandardCharsets.US_ASCII)
          leases <- InMemoryExecutionLeaseStore.create
          gate <- SingleProcessTenantExecutionMutationGate.create
          validator = DurableLeaseAuthorityValidator(CurrentStateExecutionRevalidator(credentialRepository, repository, repository, repository))
          broker = InMemoryCredentialBroker(leases, Clock.system, Duration.ofMinutes(1), audit)
          http = HttpClient.newHttpClient()
          endpoints = GoogleEndpoints(
            URI.create(s"${gmail.uri}/authorize"), URI.create(s"${gmail.uri}/token"),
            URI.create(s"${gmail.uri}/userinfo"), gmail.uri, gmail.uri
          )
          refreshConfig <- IO.fromEither(
            OAuthRefreshClient.Config.from(endpoints.token, "google-e2e-client", "google-e2e-secret", allowHttpLoopback = true)
              .leftMap(message => RuntimeException(message))
          )
          bodies <- OAuthRefreshClient.resource(refreshConfig, Clock.system).use: refresher =>
            PostgresOAuthRefreshRepository.resource(config, xa).use: refreshRepository =>
              val oauth = new RefreshableOAuth[Google.Mailbox](ProviderId.Google, refreshRepository, secrets, codec, refresher, Clock.system, RefreshTokenRotation.NonRotating)
              for
                registry <- IO.fromEither(
                  OperationRegistry.from(GmailOperations.all(new GmailCredentials(oauth), endpoints, http, Duration.ofSeconds(2)))
                    .leftMap(error => RuntimeException(s"invalid operation registry: $error"))
                )
                executor = ProviderExecutionService(leases, Clock.system, audit, validator, gate)
                tools = AgentToolService(registry, ResourceResolver(repository), repository, repository, broker, executor, approvals = approvalStore)
                api = AgentApi(AgentApiDependencies(credentials, Some(tools)))
                outcome <- AgentHttpServer.resource(api, port = 0).use: server =>
                  val apiEndpoint = s"http://127.0.0.1:${server.address.getPort}"
                  withBridge(apiEndpoint, wireCredential).use: bridge =>
                    val seen = new ConcurrentLinkedQueue[String]()
                    def call(args: Json, approval: Option[String] = None): IO[(Int, String)] =
                      directCall(apiEndpoint, wireCredential, "gmail_messages_send", args, approval).map: reply =>
                        seen.add(reply._2)
                        reply
                    def send(to: Seq[String], subject: String, body: String, bcc: Seq[String] = Nil): Json = Json.obj(
                      "mailbox" -> str(accountSub), "to" -> strings(to*), "bcc" -> strings(bcc*),
                      "subject" -> str(subject), "body" -> str(body)
                    )
                    def pendingRows: IO[Vector[ApprovalRecord]] = approvalService.pending(administrator, Instant.now())
                    def pendingCount: IO[Int] = pendingRows.map(_.size)
                    def pendingFor(subject: String): IO[ApprovalRecord] =
                      pendingRows.flatMap: rows =>
                        IO.fromOption(rows.find(_.preview.hcursor.get[String]("subject").contains(subject)))(
                          RuntimeException(s"no pending approval for $subject"))
                    def decide(record: ApprovalRecord): IO[ApprovalRecord] =
                      gate.withinMutation(tenant)(IO.defer(approvalService.decide(administrator, record.id, true, Instant.now())))
                        .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"decision failed: $error"))))
                    def dismiss(record: ApprovalRecord): IO[ApprovalRecord] =
                      gate.withinMutation(tenant)(IO.defer(approvalService.decide(administrator, record.id, false, Instant.now())))
                        .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"approval dismissal failed: $error"))))
                    def sends: Int = gmail.sendRequests.get()
                    def unknownEvents: IO[Int] =
                      (TenantSession.establish(tenant) *>
                        sql"select count(*) from execution_audit_events where tenant_id=${tenant.toString}::uuid and event_kind='COMPLETION_UNKNOWN'"
                          .query[Int].unique).transact(xa)
                    for
                      visible <- bridge.listTools("gmail_messages_send")
                      _ <- IO(assert(visible.contains("gmail_messages_send"), s"bridge tools: $visible"))
                      // 1. Approval required: nothing is sent, nothing is read, and the preview is exactly the message.
                      readsBefore = secrets.reads.get()
                      first <- bridge.call("gmail_messages_send", send(Seq("alice@example.com"), "Status", "Hello"))
                      _ <- IO(assert(first.isError, s"an unapproved send must not succeed: ${first.content}"))
                      _ <- IO(assertEquals(sends, 0))
                      _ <- IO(assertEquals(gmail.refreshes.get(), 0))
                      _ <- IO(assertEquals(secrets.reads.get(), readsBefore, "the approval wait read no secret"))
                      pending <- pendingRows
                      _ <- IO(assertEquals(pending.size, 1))
                      approval = pending.head
                      _ <- IO(assert(first.content.contains(approval.id.toString), s"reply names the approval: ${first.content}"))
                      _ <- IO:
                        assertEquals(approval.status, ApprovalStatus.Pending)
                        assertEquals(approval.preview, Json.obj(
                          "mailbox" -> str(accountSub), "to" -> strings("alice@example.com"), "cc" -> strings(), "bcc" -> strings(),
                          "subject" -> str("Status"), "body" -> str("Hello")
                        ))
                      // 2. Approved: the identical bridge call sends exactly once, as approved.
                      _ <- decide(approval).map(decided => assertEquals(decided.status, ApprovalStatus.Approved))
                      _ <- IO(assertEquals(sends, 0))
                      applied <- bridge.call("gmail_messages_send", send(Seq("alice@example.com"), "Status", "Hello"))
                      _ <- IO(assert(!applied.isError, s"approved send failed: ${applied.content}"))
                      _ <- IO(assertEquals(gmail.requests.asScala.toList, List("POST /gmail/v1/users/me/messages/send")))
                      _ <- IO(assertEquals(gmail.refreshes.get(), 1, "exactly one refresh"))
                      _ <- IO(assertEquals(gmail.refreshTokensSeen.asScala.toList, List(oldRefresh)))
                      _ <- IO(assertEquals(gmail.bearersSeen.asScala.toList, List(newAccess), "Gmail used the new token"))
                      _ <- IO(assert(secrets.reads.get() > readsBefore, "the send read the stored credential"))
                      _ <- IO:
                        val message = gmail.messages.asScala.toList
                        assertEquals(message.size, 1)
                        val (head, body) = message.head
                        assert(head.contains("To: alice@example.com"), head)
                        assert(head.contains("Subject: Status"), head)
                        assert(!head.contains("Bcc:") && !head.contains("Cc:"), head)
                        assertEquals(body, "Hello")
                      consumed <- approvalStore.find(tenant, approval.id).flatMap(IO.fromOption(_)(RuntimeException("approval row missing")))
                      _ <- IO(assert(consumed.consumedAt.isDefined, "approval consumed by the send"))
                      _ <- IO(assertEquals(consumed.status, ApprovalStatus.Approved))
                      // 3. The same arguments again need a new approval: never a second send.
                      again <- bridge.call("gmail_messages_send", send(Seq("alice@example.com"), "Status", "Hello"))
                      _ <- IO(assert(again.isError, s"a repeated send must not succeed: ${again.content}"))
                      _ <- IO(assertEquals(sends, 1))
                      // 4-5. Recipients outside the delegated allowlist are denied before approval is considered.
                      pendingBefore <- pendingCount
                      readsBeforeDenials = secrets.reads.get()
                      carol <- call(send(Seq("carol@example.com"), "Status", "Hello"))
                      _ <- IO(assertEquals(carol._1, 403))
                      mixed <- call(send(Seq("alice@example.com"), "Status", "Hello", bcc = Seq("carol@example.com")))
                      _ <- IO(assertEquals(mixed._1, 403))
                      pendingAfterDenials <- pendingCount
                      _ <- IO(assertEquals(pendingAfterDenials, pendingBefore, "denials created no approval"))
                      _ <- IO(assertEquals(sends, 1))
                      _ <- IO(assertEquals(secrets.reads.get(), readsBeforeDenials, "denials read no secret"))
                      // 6. Case is normalized, so an uppercase allowlisted address needs approval; the preview is lowercase.
                      upper <- call(send(Seq("ALICE@EXAMPLE.COM"), "Upper", "Hello"))
                      _ <- IO(assertEquals(upper._1, 409))
                      upperApproval <- pendingFor("Upper")
                      _ <- IO(assertEquals(upperApproval.preview.hcursor.get[List[String]]("to"), Right(List("alice@example.com"))))
                      _ <- IO(assertEquals(sends, 1))
                      // 7. Header injection through the subject is refused as invalid arguments.
                      pendingBeforeInjection <- pendingCount
                      injected <- call(send(Seq("alice@example.com"), "x\r\nBcc: mallory@example.com", "Hello"))
                      _ <- IO(assertEquals(injected._1, 400))
                      afterInjection <- pendingCount
                      _ <- IO(assertEquals(afterInjection, pendingBeforeInjection, "invalid arguments created no approval"))
                      _ <- IO(assertEquals(sends, 1))
                      // 8. An unknown outcome: the fake answers after the client timeout. Exactly one request, never retried.
                      slowFirst <- bridge.call("gmail_messages_send", send(Seq("bob@example.com"), "Slow", "Hello"))
                      _ <- IO(assert(slowFirst.isError))
                      slowApproval <- pendingFor("Slow")
                      _ <- decide(slowApproval)
                      _ <- IO(gmail.delayMillis.set(4000))
                      unknown <- bridge.call("gmail_messages_send", send(Seq("bob@example.com"), "Slow", "Hello"))
                      _ <- IO(gmail.delayMillis.set(0))
                      _ <- IO(assert(unknown.isError && unknown.content.contains("may have completed"), s"outcome unknown message: ${unknown.content}"))
                      _ <- IO(assertEquals(sends, 2, "exactly one request reached the fake for the slow send"))
                      recorded <- unknownEvents
                      _ <- IO(assertEquals(recorded, 1, "the execution audit records CompletionUnknown"))
                      retry <- call(send(Seq("bob@example.com"), "Slow", "Hello"), Some(slowApproval.id.toString))
                      _ <- IO(assert(retry._1 != 200, s"a consumed approval cannot send again: ${retry._1}"))
                      retryBridge <- bridge.call("gmail_messages_send", send(Seq("bob@example.com"), "Slow", "Hello"))
                      _ <- IO(assert(retryBridge.isError))
                      _ <- IO(assertEquals(sends, 2, "no retry reached the fake"))
                      // A provider 503 after accepting an approved POST has an unknown outcome and cannot be replayed.
                      serverErrorArgs = send(Seq("bob@example.com"), "ServerError", "Hello")
                      serverErrorRequest <- call(serverErrorArgs)
                      _ <- IO(assertEquals(serverErrorRequest._1, 409, serverErrorRequest._2))
                      serverErrorApproval <- pendingFor("ServerError")
                      _ <- decide(serverErrorApproval)
                      _ <- IO(gmail.failNextPost.set(true))
                      beforeServerErrorSends = sends
                      serverError <- call(serverErrorArgs, Some(serverErrorApproval.id.toString))
                      _ <- IO(assertEquals(serverError._1, 502, serverError._2))
                      _ <- IO(assert(serverError._2.contains("outcome_unknown"), serverError._2))
                      _ <- IO(assertEquals(sends, beforeServerErrorSends + 1, "exactly one POST reached Gmail before its 503"))
                      _ <- IO(assertEquals(gmail.requests.asScala.count(_.startsWith("POST ")), beforeServerErrorSends + 1))
                      consumedServerError <- approvalStore.find(tenant, serverErrorApproval.id)
                        .flatMap(IO.fromOption(_)(RuntimeException("server error approval row missing")))
                      _ <- IO(assert(consumedServerError.consumedAt.isDefined, "approved POST attempt consumed its approval"))
                      consumedRetry <- call(serverErrorArgs, Some(serverErrorApproval.id.toString))
                      _ <- IO(assert(consumedRetry._1 != 200, s"consumed approval cannot send again: ${consumedRetry._1}"))
                      freshRetry <- call(serverErrorArgs)
                      _ <- IO(assertEquals(freshRetry._1, 409, freshRetry._2))
                      _ <- IO(assert(freshRetry._2.contains("approval_required"), freshRetry._2))
                      _ <- IO(assertEquals(sends, beforeServerErrorSends + 1, "retry and fresh approval request sent no POST"))
                      freshApproval <- pendingFor("ServerError")
                      _ <- dismiss(freshApproval)
                      _ <- unknownEvents.map(count => assertEquals(count, 2, "both unknown outcomes are audited"))
                      _ <- IO(assertEquals(gmail.refreshes.get(), 1))
                    yield seen.asScala.toList ++ List(first.content, applied.content, again.content, unknown.content, retryBridge.content, serverError._2)
              yield outcome
        yield
          // 9. No token reaches an agent response.
          val tokens = List(oldAccess, oldRefresh, newAccess)
          bodies.foreach(body => tokens.foreach(token => assert(!body.contains(token), "no token reaches the agent")))
  }

  /** A tool call sent straight to the agent API, as a client ignoring the schema hint would. */
  private def directCall(endpoint: String, credential: String, tool: String, arguments: Json, approval: Option[String]): IO[(Int, String)] = IO.blocking:
    val envelope = Json.obj("arguments" -> arguments).deepMerge(approval.fold(Json.obj())(id => Json.obj("approval_id" -> str(id))))
    val request = HttpRequest.newBuilder(URI.create(s"$endpoint/api/agent/tools/$tool/call"))
      .header("Authorization", s"Bearer $credential").header("Content-Type", "application/json")
      .POST(HttpRequest.BodyPublishers.ofString(envelope.noSpaces)).build()
    val response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())
    (response.statusCode(), response.body())

  private final class FakeGmail(val uri: URI):
    val refreshes = AtomicInteger(0)
    val sendRequests = AtomicInteger(0)
    val delayMillis = AtomicInteger(0)
    val failNextPost = java.util.concurrent.atomic.AtomicBoolean(false)
    val refreshTokensSeen = new ConcurrentLinkedQueue[String]()
    val bearersSeen = new ConcurrentLinkedQueue[String]()
    val requests = new ConcurrentLinkedQueue[String]()
    /** (decoded headers, decoded body) of every message accepted. */
    val messages = new ConcurrentLinkedQueue[(String, String)]()

  /** `/token` accepts only the original refresh token and never returns a new one; the send endpoint rejects any other
    * bearer, records and decodes the raw message, and can answer after a delay. */
  private def withFakeGmail: Resource[IO, FakeGmail] =
    Resource.make(IO.blocking:
      val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
      server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool: runnable =>
        val thread = new Thread(runnable)
        thread.setDaemon(true)
        thread)
      val fake = new FakeGmail(URI.create(s"http://127.0.0.1:${server.getAddress.getPort}"))
      def json(exchange: HttpExchange, status: Int, body: Json): Unit =
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
      server.createContext("/gmail/v1/users/me/messages/send", exchange =>
        val authorization = Option(exchange.getRequestHeaders.getFirst("Authorization")).getOrElse("")
        if authorization != s"Bearer $newAccess" then json(exchange, 401, Json.obj("error" -> Json.obj("code" -> Json.fromInt(401))))
        else
          fake.bearersSeen.add(authorization.stripPrefix("Bearer "))
          fake.requests.add(exchange.getRequestMethod + " " + exchange.getRequestURI.getPath)
          val raw = parse(String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)).toOption
            .flatMap(_.hcursor.get[String]("raw").toOption).getOrElse("")
          val decoded = String(java.util.Base64.getUrlDecoder.decode(raw), StandardCharsets.US_ASCII)
          val split = decoded.indexOf("\r\n\r\n")
          val head = decoded.take(split)
          val body = String(java.util.Base64.getMimeDecoder.decode(decoded.drop(split + 4)), StandardCharsets.UTF_8)
          fake.messages.add(head -> body)
          fake.sendRequests.incrementAndGet()
          val failThisPost = fake.failNextPost.compareAndSet(true, false)
          val delay = fake.delayMillis.get()
          if delay > 0 then Thread.sleep(delay.toLong)
          try
            if failThisPost then json(exchange, 503, Json.obj("error" -> Json.obj("status" -> Json.fromString("UNAVAILABLE"))))
            else json(exchange, 200, Json.obj("id" -> Json.fromString("msg-" + fake.sendRequests.get()), "threadId" -> Json.fromString("t1")))
          catch case _: java.io.IOException => () // the client gave up before the answer
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
