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
import run.hallpass.adapters.hubspot.*
import run.hallpass.adapters.oauth.{OAuthRefreshClient, OAuthTokenJsonCodec}
import run.hallpass.adapters.postgres.*
import run.hallpass.adapters.security.{AgentCredentialHmacKey, AgentCredentialKeyRing, AgentCredentialHmacSha256}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** HubSpot through the real stdio bridge, agent HTTP API, PostgreSQL (catalog, approvals, delegation constraints,
  * refresh repository), non-rotating refreshable OAuth, and a fake HubSpot. Reads work on deals; contacts
  * are not delegated; a deal update needs approval and runs once; a field outside the delegated allowlist is denied
  * before approval is considered. */
final class BridgeHubSpotEndToEndSuite extends CatsEffectSuite:
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(180, "s")
  private var container: PostgreSQLContainer[?] = uninitialized
  private var config: DatabaseConfig = uninitialized
  private var dockerAvailable = false

  private val hubId = "12345678"
  private val dealId = "4242"
  private val contactId = "777"
  private val oldAccess = "CJ_old_access_token_e2e"
  private val oldRefresh = "hs-old-refresh-token-e2e"
  private val newAccess = "CJ_new_access_token_e2e"
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

  test("HubSpot: refresh once, deal read, contacts undelegated, update needs approval and runs once, allowlist denies before approval, revocation, no token in responses") {
    assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")
    withFakeHubSpot.use: hubspot =>
      PostgresDatabase.resource(config).use: xa =>
        val repository = new PostgresControlPlane(xa)
        val credentialRepository = new PostgresAgentCredentials(xa)
        val connectionRepository = new PostgresConnectionRepository(xa)
        val resources = PostgresConnectionResources(xa)
        val audit = new PostgresExecutionAudit(xa)
        val approvalStore = PostgresApprovalStore(xa)
        val approvalService = ApprovalService(approvalStore)
        val secrets = new MemorySecrets
        val key = AgentCredentialHmacKey.fromBytes("integration-test", Array.fill[Byte](32)(31)).toOption.get
        val credentialCrypto = AgentCredentialHmacSha256(AgentCredentialKeyRing.from("integration-test", Seq(key)).toOption.get)
        val directory = PostgresIdentityDirectory(xa)
        val enrollment = AgentEnrollmentService(credentialRepository, credentialCrypto)
        val credentials = AgentCredentialServices(AgentAuthenticator[IO](directory, credentialRepository, credentialCrypto), enrollment)
        val human = DemoBootstrap.Human
        val tenant = DemoBootstrap.Tenant
        val now = Instant.now()
        val expired = now.truncatedTo(java.time.temporal.ChronoUnit.MICROS).minusSeconds(60)

        def select(root: ConnectionResource, external: ExternalId, name: String): IO[ConnectionResource] =
          resources
            .select(tenant, root.connection, HubSpot.objectType, ExternalId.parse(s"$hubId:${external.value}").get, name, root.id, human, Instant.now())
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"select failed: $error"))))

        def grant(agent: AgentId, name: String, target: ConnectionResource, constraints: Constraints = Constraints.empty) =
          for
            capabilities <- repository.capabilities(tenant)
            capability <- IO.fromOption(capabilities.find(_.name == name))(RuntimeException(s"$name capability missing"))
            created <- repository.create(tenant, CreateDelegation(
              human, Principal.Agent(agent), capability.id, target.id, capability.descriptor.action, None, constraints
            )).flatMap(_.fold(error => IO.raiseError(RuntimeException(s"grant failed: $error")), IO.pure))
          yield created

        for
          _ <- DemoBootstrap.run(xa)
          administrator <- HumanAuthenticator[IO](directory)
            .authenticate(DemoBootstrap.AdministratorUser, tenant, now)
            .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"administrator: $error"))))
          agent <- repository.create(tenant, CreateAgent("bridge integration: HubSpot", None))
            .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"agent creation failed: $error")), IO.pure))
          connectionId = ConnectionId.random()
          initialReference <- secrets.put(SecretBinding(tenant, connectionId),
            codec.encode(OAuthTokens.from(oldAccess, Some(oldRefresh), expired).get))
          _ <- connectionRepository.reserve(tenant, connectionId, "HUBSPOT", human, now)
          activated <- connectionRepository.activateReserved(
            tenant, connectionId, ConnectionActivation(
            human, ExternalId.parse(hubId).get, Some("portal"), Some("Portal"), Some(expired),
            HubSpot.CredentialType, initialReference, HubSpot.portal, ExternalId.parse(hubId).get, "Portal", None, false
            ), now
          )
          _ <- IO.fromEither(activated.leftMap(error => RuntimeException(s"connection activation failed: $error")))
          _ <- (TenantSession.establish(tenant) *>
            sql"update credential_references set expires_at=$expired where tenant_id=${tenant.toString}::uuid and connection_id=${connectionId.toString}::uuid and credential_type='OAUTH_REFRESHABLE'".update.run *>
            sql"update connections set token_expires_at=$expired where tenant_id=${tenant.toString}::uuid and id=${connectionId.toString}::uuid".update.run).transact(xa)
          root <- resources.listFor(tenant, connectionId).flatMap(rows => IO.fromOption(rows.find(_.kind == HubSpot.portal.wire))(RuntimeException("connection root missing")))
          _ <- select(root, HubSpot.Contacts, "Contacts")
          deals <- select(root, HubSpot.Deals, "Deals")
          _ <- grant(agent.id, "HubSpot.Deal.Read", deals)
          updateGrant <- grant(agent.id, "HubSpot.Deal.Update", deals,
            Constraints(Set(Constraint.ValueIn(HubSpot.PropertiesFact, values("dealstage", "amount")))))
          disclosure <- enrollment
            .enroll(administrator, agent.id, AgentCredentialEnrollmentRequest.from(Some("hubspot e2e"), None).toOption.get, now)
            .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"enrollment failed: $error")), IO.pure))
          wireCredential = String(PresentedAgentCredential.canonicalBytes(disclosure.credential), StandardCharsets.US_ASCII)
          leases <- InMemoryExecutionLeaseStore.create
          gate <- SingleProcessTenantExecutionMutationGate.create
          validator = DurableLeaseAuthorityValidator(CurrentStateExecutionRevalidator(credentialRepository, repository, repository, repository))
          broker = InMemoryCredentialBroker(leases, Clock.system, Duration.ofMinutes(1), audit)
          http = HttpClient.newHttpClient()
          endpoints = HubSpotEndpoints(URI.create(s"${hubspot.uri}/authorize"), hubspot.uri)
          refreshConfig <- IO.fromEither(
            OAuthRefreshClient.Config.from(endpoints.token, "hubspot-e2e-client", "hubspot-e2e-secret", allowHttpLoopback = true)
              .leftMap(message => RuntimeException(message))
          )
          bodies <- OAuthRefreshClient.resource(refreshConfig, Clock.system).use: refresher =>
            PostgresOAuthRefreshRepository.resource(config, xa).use: refreshRepository =>
              val oauth = new RefreshableOAuth[HubSpot.ObjectType](ProviderId.HubSpot, refreshRepository, secrets, codec, refresher, Clock.system, RefreshTokenRotation.NonRotating)
              for
                registry <- IO.fromEither(
                  OperationRegistry.from(HubSpotOperations.all(new HubSpotCredentials(oauth), endpoints, http))
                    .leftMap(error => RuntimeException(s"invalid operation registry: $error"))
                )
                executor = ProviderExecutionService(leases, Clock.system, audit, validator, gate)
                tools = AgentToolService(registry, ResourceResolver(repository), repository, repository, broker, executor, approvals = approvalStore)
                api = AgentApi(AgentApiDependencies(credentials, Some(tools)))
                outcome <- AgentHttpServer.resource(api, port = 0).use: server =>
                  val apiEndpoint = s"http://127.0.0.1:${server.address.getPort}"
                  withBridge(apiEndpoint, wireCredential).use: bridge =>
                    val seen = new ConcurrentLinkedQueue[String]()
                    def call(tool: String, args: Json): IO[(Int, String)] =
                      directCall(apiEndpoint, wireCredential, tool, args).map: reply =>
                        seen.add(reply._2)
                        reply
                    def update(properties: (String, String)*): Json = Json.obj(
                      "object_type" -> Json.fromString(s"$hubId:deals"),
                      "deal_id" -> Json.fromString(dealId),
                      "properties" -> Json.obj(properties.map((k, v) => k -> Json.fromString(v))*)
                    )
                    def pendingRows: IO[Vector[ApprovalRecord]] = approvalService.pending(administrator, Instant.now())
                    def requests: List[String] = hubspot.requests.asScala.toList
                    def patches: List[(String, String)] = hubspot.patches.asScala.toList
                    def noPending(label: String): IO[Unit] = pendingRows.map(rows => assertEquals(rows.size, 0, label))
                    for
                      visible <- bridge.listTools("hubspot_deals_get")
                      _ <- IO(assert(visible.contains("hubspot_deals_get"), s"bridge tools: $visible"))
                      // 1. Expired token: one refresh, then the deal GET with the new token.
                      readsBefore = secrets.reads.get()
                      first <- bridge.call("hubspot_deals_get", Json.obj("object_type" -> Json.fromString(s"$hubId:deals"), "record_id" -> Json.fromString(dealId)))
                      _ <- IO(assert(!first.isError, s"authorized deal get failed: ${first.content}"))
                      _ <- IO(assert(first.content.contains("fake-deal"), first.content))
                      _ <- IO(assertEquals(hubspot.refreshes.get(), 1, "exactly one refresh"))
                      _ <- IO(assertEquals(hubspot.refreshTokensSeen.asScala.toList, List(oldRefresh)))
                      _ <- IO(assertEquals(requests.map(_.takeWhile(_ != '?')), List(s"GET /crm/v3/objects/deals/$dealId")))
                      _ <- IO(assertEquals(hubspot.bearersSeen.asScala.toList, List(newAccess), "HubSpot used the new token"))
                      _ <- IO(assert(secrets.reads.get() > readsBefore, "the first call read the stored credential"))
                      // 2. Contacts are selected but not delegated: refused with no request.
                      readsAfterRead = secrets.reads.get()
                      contacts <- call("hubspot_contacts_get", Json.obj("object_type" -> Json.fromString(s"$hubId:contacts"), "record_id" -> Json.fromString(contactId)))
                      _ <- IO(assertEquals(contacts._1, 403))
                      _ <- IO(assertEquals(requests.size, 1, "no contacts request"))
                      _ <- IO(assertEquals(secrets.reads.get(), readsAfterRead, "denial read no secret"))
                      // A record ID cannot select another portal's same object type.
                      otherPortal <- call("hubspot_deals_get", Json.obj("object_type" -> Json.fromString("87654321:deals"), "record_id" -> Json.fromString(dealId)))
                      _ <- IO(assertEquals(otherPortal._1, 403))
                      _ <- IO(assertEquals(requests.size, 1, "unselected portal made no CRM request"))
                      _ <- IO(assertEquals(secrets.reads.get(), readsAfterRead, "unselected portal denial read no secret"))
                      // 3. Allowed field, approval required: nothing is sent; the pending preview has exactly that property.
                      firstUpdate <- bridge.call("hubspot_deals_update_properties", update("dealstage" -> "closedwon"))
                      _ <- IO(assert(firstUpdate.isError, s"unapproved update must not succeed: ${firstUpdate.content}"))
                      pending <- pendingRows
                      _ <- IO(assertEquals(pending.size, 1))
                      approval = pending.head
                      _ <- IO(assert(firstUpdate.content.contains(approval.id.toString), s"reply names the approval: ${firstUpdate.content}"))
                      _ <- IO:
                        assertEquals(approval.status, ApprovalStatus.Pending)
                        val properties = approval.preview.hcursor.downField("properties").focus.flatMap(_.asObject).map(_.toMap)
                        assertEquals(properties, Some(Map("dealstage" -> Json.fromString("closedwon"))))
                      _ <- IO(assertEquals(patches, Nil, "no PATCH before approval"))
                      _ <- IO(assertEquals(secrets.reads.get(), readsAfterRead, "approval wait read no secret"))
                      // 4. Approved under the gate: the identical bridge call patches exactly once.
                      decided <- gate.withinMutation(tenant)(IO.defer(approvalService.decide(administrator, approval.id, true, Instant.now())))
                        .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"decision failed: $error"))))
                      _ <- IO(assertEquals(decided.status, ApprovalStatus.Approved))
                      _ <- IO(assertEquals(patches, Nil))
                      applied <- bridge.call("hubspot_deals_update_properties", update("dealstage" -> "closedwon"))
                      _ <- IO(assert(!applied.isError, s"approved update failed: ${applied.content}"))
                      _ <- IO(assertEquals(patches, List(s"/crm/v3/objects/deals/$dealId" -> """{"properties":{"dealstage":"closedwon"}}""")))
                      _ <- IO(assertEquals(hubspot.refreshes.get(), 1, "the fresh token needs no second refresh"))
                      consumed <- approvalStore.find(tenant, approval.id).flatMap(IO.fromOption(_)(RuntimeException("approval row missing")))
                      _ <- IO(assert(consumed.consumedAt.isDefined, "approval consumed by the retry"))
                      _ <- noPending("nothing pending after execution")
                      // 5. A field outside the allowlist is denied by the delegation, before approval and before any request.
                      readsBeforeDenials = secrets.reads.get()
                      outside <- call("hubspot_deals_update_properties", update("dealname" -> "x"))
                      _ <- IO(assertEquals(outside._1, 403))
                      _ <- noPending("outside-allowlist update created no approval")
                      _ <- IO(assertEquals(patches.size, 1))
                      // 6. One value outside the allowlist is enough.
                      mixed <- call("hubspot_deals_update_properties", update("dealstage" -> "a", "dealname" -> "b"))
                      _ <- IO(assertEquals(mixed._1, 403))
                      _ <- noPending("mixed update created no approval")
                      _ <- IO(assertEquals(patches.size, 1))
                      // A 503 after the fake provider receives the PATCH is an unknown outcome; replay is forbidden.
                      uncertain <- bridge.call("hubspot_deals_update_properties", update("amount" -> "200"))
                      _ <- IO(assert(uncertain.isError))
                      uncertainApproval <- pendingRows.map(_.head)
                      _ <- gate.withinMutation(tenant)(IO.defer(approvalService.decide(administrator, uncertainApproval.id, true, Instant.now())))
                        .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"decision failed: $error"))))
                      _ <- IO(hubspot.failNextPatch.set(true))
                      failedPatch <- directCall(apiEndpoint, wireCredential, "hubspot_deals_update_properties", update("amount" -> "200"), Some(uncertainApproval.id.toString))
                      _ <- IO(assertEquals(failedPatch._1, 502, failedPatch._2))
                      _ <- IO(assert(failedPatch._2.contains("outcome_unknown"), failedPatch._2))
                      _ <- IO(assertEquals(patches.size, 2, "provider received exactly one failed PATCH"))
                      consumedRetry <- directCall(apiEndpoint, wireCredential, "hubspot_deals_update_properties", update("amount" -> "200"), Some(uncertainApproval.id.toString))
                      _ <- IO(assert(consumedRetry._1 != 200, "consumed approval cannot execute again"))
                      _ <- IO(assertEquals(patches.size, 2))
                      retry <- directCall(apiEndpoint, wireCredential, "hubspot_deals_update_properties", update("amount" -> "200"))
                      _ <- IO(assertEquals(retry._1, 409, retry._2))
                      _ <- IO(assert(retry._2.contains("approval_required"), retry._2))
                      retryApproval <- pendingRows.map(_.head)
                      _ <- gate.withinMutation(tenant)(IO.defer(approvalService.decide(administrator, retryApproval.id, false, Instant.now())))
                        .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(s"retry approval dismissal failed: $error"))))
                      _ <- IO(assertEquals(patches.size, 2, "retry did not issue another PATCH"))
                      unknownAudit <- (TenantSession.establish(tenant) *>
                        sql"select count(*) from execution_audit_events where tenant_id=${tenant.toString}::uuid and event_kind='COMPLETION_UNKNOWN' and safe_outcome='UNKNOWN'".query[Int].unique).transact(xa)
                      _ <- IO(assert(unknownAudit >= 1, s"completion unknown audit row missing; retry status=${retry._1}"))
                      readsAfterUnknown = secrets.reads.get()
                      // 7. Revocation: an allowed-field update is denied with no approval and no PATCH.
                      revoked <- repository.revoke(tenant, updateGrant.id, Instant.now())
                      _ <- IO(assert(revoked.isRight))
                      afterRevoke <- call("hubspot_deals_update_properties", update("amount" -> "100"))
                      _ <- IO(assertEquals(afterRevoke._1, 403))
                      _ <- noPending("revoked update created no approval")
                      _ <- IO(assertEquals(patches.size, 2))
                      _ <- IO(assertEquals(secrets.reads.get(), readsAfterUnknown, "revocation denial read no secret"))
                      _ <- IO(assertEquals(hubspot.refreshes.get(), 1))
                    yield seen.asScala.toList ++ List(first.content, firstUpdate.content, applied.content)
              yield outcome
        yield
          // 8. No token reaches an agent response.
          val tokens = List(oldAccess, oldRefresh, newAccess)
          bodies.foreach(body => tokens.foreach(token => assert(!body.contains(token), "no token reaches the agent")))
  }

  /** A tool call sent straight to the agent API, as a client ignoring the schema hint would. */
  private def directCall(endpoint: String, credential: String, tool: String, arguments: Json, approval: Option[String] = None): IO[(Int, String)] = IO.blocking:
    val envelope = Json.obj("arguments" -> arguments).deepMerge(approval.fold(Json.obj())(id => Json.obj("approval_id" -> Json.fromString(id))))
    val request = HttpRequest.newBuilder(URI.create(s"$endpoint/api/agent/tools/$tool/call"))
      .header("Authorization", s"Bearer $credential").header("Content-Type", "application/json")
      .POST(HttpRequest.BodyPublishers.ofString(envelope.noSpaces)).build()
    val response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString())
    (response.statusCode(), response.body())

  private final class FakeHubSpot(val uri: URI):
    val refreshes = AtomicInteger(0)
    val refreshTokensSeen = new ConcurrentLinkedQueue[String]()
    val bearersSeen = new ConcurrentLinkedQueue[String]()
    /** "METHOD /path?query" of every CRM request that carried the refreshed token. */
    val requests = new ConcurrentLinkedQueue[String]()
    val patches = new ConcurrentLinkedQueue[(String, String)]()
    val failNextPatch = java.util.concurrent.atomic.AtomicBoolean(false)

  /** `/oauth/v1/token` accepts only the original refresh token; `/crm/v3/objects/...` rejects any other bearer. */
  private def withFakeHubSpot: Resource[IO, FakeHubSpot] =
    Resource.make(IO.blocking:
      val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
      val fake = new FakeHubSpot(URI.create(s"http://127.0.0.1:${server.getAddress.getPort}"))
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
      server.createContext("/oauth/v1/token", exchange =>
        val fields = form(exchange)
        if exchange.getRequestMethod != "POST" || !fields.get("grant_type").contains("refresh_token") || !fields.get("refresh_token").contains(oldRefresh) then
          json(exchange, 400, Json.obj("error" -> Json.fromString("invalid_grant")))
        else
          fake.refreshes.incrementAndGet()
          fields.get("refresh_token").foreach(fake.refreshTokensSeen.add)
          json(exchange, 200, Json.obj(
            "access_token" -> Json.fromString(newAccess), "token_type" -> Json.fromString("bearer"),
            "expires_in" -> Json.fromInt(1800), "refresh_token" -> Json.fromString(oldRefresh)
          ))
      )
      server.createContext("/crm/v3/objects/", exchange =>
        val authorization = Option(exchange.getRequestHeaders.getFirst("Authorization")).getOrElse("")
        if authorization != s"Bearer $newAccess" then json(exchange, 401, Json.obj("status" -> Json.fromString("error")))
        else
          fake.bearersSeen.add(authorization.stripPrefix("Bearer "))
          val path = exchange.getRequestURI.getPath
          val query = Option(exchange.getRequestURI.getRawQuery).fold("")("?" + _)
          val body = String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)
          fake.requests.add(s"${exchange.getRequestMethod} $path$query")
          val id = path.split('/').last
          if exchange.getRequestMethod == "PATCH" then
            fake.patches.add(path -> body)
            if fake.failNextPatch.compareAndSet(true, false) then json(exchange, 503, Json.obj("status" -> Json.fromString("temporary_error")))
            else json(exchange, 200, Json.obj("id" -> Json.fromString(id), "properties" -> Json.obj("dealstage" -> Json.fromString("closedwon"))))
          else
            json(exchange, 200, Json.obj(
              "id" -> Json.fromString(id),
              "properties" -> Json.obj("dealname" -> Json.fromString("fake-deal"), "amount" -> Json.fromString("100")),
              "createdAt" -> Json.fromString("2026-09-01T00:00:00Z"), "updatedAt" -> Json.fromString("2026-09-02T00:00:00Z"),
              "archived" -> Json.False
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
