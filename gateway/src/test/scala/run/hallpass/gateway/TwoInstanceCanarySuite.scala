package run.hallpass.gateway

import java.net.{InetSocketAddress, ServerSocket, URI}
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.SecureRandom
import java.sql.DriverManager
import java.time.Instant
import java.util.{Base64, UUID}
import java.util.concurrent.{CountDownLatch, TimeUnit}
import java.util.concurrent.atomic.AtomicInteger
import scala.compiletime.uninitialized
import scala.concurrent.duration.*
import cats.effect.{IO, Resource as EffectResource}
import cats.syntax.all.*
import com.sun.net.httpserver.HttpServer
import io.circe.Json
import io.circe.parser.parse
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import org.typelevel.doobie.util.transactor.Transactor
import run.hallpass.adapters.postgres.*
import run.hallpass.adapters.secrets.LocalEncryptedSecretStore
import run.hallpass.adapters.slack.Slack
import run.hallpass.application.*
import run.hallpass.kernel.*

/** The canary: two live server instances (the production composition, `HallpassDemoApiMain.server`) on their own
  * ports, sharing one PostgreSQL through the split owner/runtime roles and the PostgreSQL tenant gate, with a fake
  * Slack provider. Everything the checks do goes over HTTP to the listeners.
  *
  *   1. Cross-tenant isolation holds across instances.
  *   2. A revocation made on instance B blocks the next execution on instance A, before any provider request.
  *   3. Gate failover: while instance A holds the tenant gate mid-dispatch, a mutation on B cannot commit; once A's gate
  *      session dies (what PostgreSQL sees when an instance crashes or is partitioned), B's mutation commits promptly.
  */
final class TwoInstanceCanarySuite extends CatsEffectSuite:
  override val munitIOTimeout: Duration = 240.seconds
  private var postgres: PostgreSQLContainer[?] = uninitialized
  private var dockerAvailable = false
  private val Owner = "authai_owner"
  private val App = "authai_app"
  private val Password = "canary-password"
  private val http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build()
  private val random = SecureRandom()

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      postgres = PostgreSQLContainer("postgres:18.6-alpine")
      postgres.start()
      superuser: statement =>
        statement.execute(s"create role $Owner login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"create role $App login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"grant connect on database test to $Owner, $App")
        statement.execute("revoke create on schema public from public")
        statement.execute(s"grant usage, create on schema public to $Owner")
        statement.execute(s"grant usage on schema public to $App")

  override def afterAll(): Unit = if dockerAvailable then postgres.stop()

  private def superuser[A](use: java.sql.Statement => A): A =
    val connection = connect(attemptsLeft = 60)
    try use(connection.createStatement())
    finally connection.close()

  /** Under load, the mapped port can refuse briefly after the container reports it started. */
  private def connect(attemptsLeft: Int): java.sql.Connection =
    try DriverManager.getConnection(postgres.getJdbcUrl, postgres.getUsername, postgres.getPassword)
    catch
      case refused: java.sql.SQLException if attemptsLeft > 1 =>
        Thread.sleep(500)
        connect(attemptsLeft - 1)

  private def database(user: String): DatabaseConfig =
    DatabaseConfig
      .fromEnvironment(Map("HALLPASS_DB_URL" -> postgres.getJdbcUrl, "HALLPASS_DB_USER" -> user, "HALLPASS_DB_PASSWORD" -> Password))
      .fold(error => fail(error), identity)

  private def freePort(): Int =
    val socket = ServerSocket(0)
    try socket.getLocalPort
    finally socket.close()

  /** A fake Slack search endpoint. When `hold` is set, the next request blocks until it is released. */
  private final class FakeSlack(val calls: AtomicInteger, val arrived: CountDownLatch, val release: CountDownLatch, val endpoint: URI):
    @volatile var hold: Boolean = false

  private def fakeSlack: EffectResource[IO, FakeSlack] =
    EffectResource.make(IO.blocking:
      val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
      server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool())
      val arrived = CountDownLatch(1)
      val release = CountDownLatch(1)
      val fake = FakeSlack(AtomicInteger(0), arrived, release, URI.create(s"http://127.0.0.1:${server.getAddress.getPort}/api/search.messages"))
      server.createContext("/", exchange =>
        fake.calls.incrementAndGet()
        if fake.hold then
          arrived.countDown()
          release.await(60, TimeUnit.SECONDS)
        val body = """{"ok":true,"messages":{"matches":[{"channel_id":"C1","ts":"1.0","text":"canary-result","username":"tester"}]}}"""
          .getBytes(StandardCharsets.UTF_8)
        exchange.sendResponseHeaders(200, body.length.toLong)
        val output = exchange.getResponseBody
        try output.write(body)
        finally output.close()
      )
      server.start()
      server -> fake
    )((server, _) => IO.blocking(server.stop(0))).map(_._2)

  private final case class Instance(name: String, management: Int, agent: Int):
    def origin = s"http://127.0.0.1:$management"

  private def environment(instance: Instance, slack: FakeSlack, secrets: java.nio.file.Path, masterKey: String, agentKey: String) =
    Map(
      "HALLPASS_ENV" -> "development",
      "HALLPASS_DB_URL" -> postgres.getJdbcUrl,
      "HALLPASS_DB_USER" -> App,
      "HALLPASS_DB_PASSWORD" -> Password,
      "HALLPASS_DB_MIGRATIONS" -> "external",
      "HALLPASS_TENANT_GATE" -> "postgres",
      "HALLPASS_TENANT_GATE_ACQUIRE_TIMEOUT_MS" -> "2000",
      "HALLPASS_AGENT_HTTP_PORT" -> instance.agent.toString,
      "HALLPASS_AGENT_CREDENTIAL_ACTIVE_KEY_ID" -> "canary",
      "HALLPASS_AGENT_CREDENTIAL_HMAC_KEYS" -> s"canary:$agentKey",
      // Each instance sees itself as the admin origin; in a deployment both sit behind one ingress origin.
      "HALLPASS_ADMIN_ORIGIN" -> instance.origin,
      "HALLPASS_ADMIN_BOOTSTRAP" -> Base64.getUrlEncoder.encodeToString(Array.fill[Byte](32)(3)),
      "HALLPASS_SLACK_CLIENT_ID" -> "canary-client",
      "HALLPASS_SLACK_CLIENT_SECRET" -> "canary-client-secret",
      "HALLPASS_SLACK_REDIRECT_URI" -> s"${instance.origin}/api/oauth/slack/callback",
      "HALLPASS_SLACK_SEARCH_URL" -> slack.endpoint.toString,
      "HALLPASS_SECRET_STORE" -> "local",
      "HALLPASS_SECRET_DIRECTORY" -> secrets.toString,
      "HALLPASS_SECRET_MASTER_KEY" -> masterKey
    )

  private def server(instance: Instance, environment: Map[String, String]): EffectResource[IO, Unit] =
    EffectResource
      .eval(IO.fromEither(ServerConfig.fromEnvironment(List(instance.management.toString), environment).leftMap(IllegalStateException(_))))
      .flatMap(HallpassDemoApiMain.server)

  /** An administrator's durable session, as OIDC login would create it; every instance accepts it. */
  private final case class Admin(tenant: TenantId, token: SessionToken)

  private def signIn(xa: Transactor[IO], provisioned: ProvisionedTenant): IO[Admin] =
    val token = SessionToken.generate(random)
    PostgresBrowserSessions(xa)
      .create(token.lookup, SessionId.random(), provisioned.administrator, Some(provisioned.tenant), LoginMethod.Oidc, SessionPolicy.default)
      .map(created => assertEquals(created, Right(true)))
      .as(Admin(provisioned.tenant, token))

  private def management(instance: Instance, admin: Admin, method: String, path: String, body: Option[Json] = None): IO[(Int, Json)] =
    IO.blocking:
      val builder = HttpRequest
        .newBuilder(URI.create(instance.origin + path))
        .timeout(java.time.Duration.ofSeconds(30))
        .header("Cookie", s"hallpass_admin_session=${admin.token.cookieValue}")
        .header("X-CSRF-Token", admin.token.csrfToken)
        .header("Origin", instance.origin)
        .header("Content-Type", "application/json")
      val request = body match
        case Some(json) => builder.method(method, HttpRequest.BodyPublishers.ofString(json.noSpaces)).build()
        case None       => builder.method(method, HttpRequest.BodyPublishers.noBody()).build()
      val response = http.send(request, HttpResponse.BodyHandlers.ofString())
      response.statusCode() -> parse(Option(response.body()).filter(_.nonEmpty).getOrElse("{}")).getOrElse(Json.Null)

  private def agentCall(instance: Instance, bearer: String): IO[Int] =
    IO.blocking:
      val request = HttpRequest
        .newBuilder(URI.create(s"http://127.0.0.1:${instance.agent}${AgentApi.callPath("slack_search_messages")}"))
        .timeout(java.time.Duration.ofSeconds(60))
        .header("Authorization", s"Bearer $bearer")
        .header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString("""{"arguments":{"query":"canary"}}"""))
        .build()
      http.send(request, HttpResponse.BodyHandlers.discarding()).statusCode()

  private def json(value: Json, field: String): String =
    value.hcursor.get[String](field).fold(error => fail(s"missing $field in $value: $error"), identity)

  test("two live instances: tenant isolation, cross-instance revocation, and gate failover") {
    assume(dockerAvailable, "Docker is required for the two-instance canary")
    val masterKey = Base64.getEncoder.encodeToString(Array.fill[Byte](32)(5))
    val agentKey = Base64.getEncoder.encodeToString(Array.fill[Byte](32)(7))
    val secrets = Files.createTempDirectory("hallpass-canary-secrets")
    val a = Instance("A", freePort(), freePort())
    val b = Instance("B", freePort(), freePort())
    def account() = ExternalIdentity.from("https://idp.example.com", UUID.randomUUID().toString).toOption.get
    def tenantRequest(name: String) = TenantProvisioningRequest.from(name, s"canary-${UUID.randomUUID().toString.take(8)}", account()).toOption.get

    val resources =
      for
        _ <- EffectResource.eval(PostgresDatabase.migrateAsOwner(database(Owner), RuntimeRole.parse(App).toOption.get))
        slack <- fakeSlack
        (tenantA, tenantB) <- EffectResource.eval(
          (
            TenantProvisioning.provision(database(Owner), tenantRequest("Canary A")),
            TenantProvisioning.provision(database(Owner), tenantRequest("Canary B"))
          ).tupled
        )
        (xa, _) <- PostgresDatabase.resourceWithSchema(database(App), MigrationMode.External)
        _ <- server(a, environment(a, slack, secrets, masterKey, agentKey))
        _ <- server(b, environment(b, slack, secrets, masterKey, agentKey))
      yield (slack, tenantA, tenantB, xa)

    resources.use:
      case (slack, tenantA, tenantB, xa) =>
      for
        adminA <- signIn(xa, tenantA)
        adminB <- signIn(xa, tenantB)
        // Tenant A's Slack connection, stored the way the OAuth callback stores it.
        capability <- PostgresControlPlane(xa).capabilities(tenantA.tenant).map(_.find(c => c.name == "Slack.Message.Read" && c.descriptor.action == Action.Read).get)
        store <- IO.fromEither(LocalEncryptedSecretStore.create(secrets, masterKey).leftMap(IllegalStateException(_)))
        connectionId = ConnectionId.random()
        reference <- store.put(SecretBinding(tenantA.tenant, connectionId), ProviderSecret.fromUtf8("xoxb-canary-token"))
        now = Instant.now()
        connections = PostgresConnectionRepository(xa)
        _ <- connections.reserve(tenantA.tenant, connectionId, "SLACK", tenantA.administratorPrincipal, now)
        workspace = ExternalId.parse("T-CANARY").getOrElse(fail("workspace ID"))
        activated <- connections.activateReserved(
          tenantA.tenant,
          connectionId,
          ConnectionActivation(
            tenantA.administratorPrincipal, workspace, None, Some("Canary workspace"), None, "SLACK_OAUTH", reference,
            Slack.workspace, workspace, "Canary workspace", None, singleActiveRoot = true
          ),
          now
        )
        connection <- IO.fromEither(activated.leftMap(error => RuntimeException(s"connection activation failed: $error")))
        // Tenant A's administrator enrolls an agent and grants it Slack read, all through instance A.
        (_, agent) <- management(a, adminA, "POST", "/api/agents", Some(Json.obj("name" -> Json.fromString("canary-agent"))))
        agentId = json(agent, "id")
        (_, enrolled) <- management(a, adminA, "POST", s"/api/agents/$agentId/credentials", Some(Json.obj()))
        bearer = json(enrolled, "credential")
        (_, granted) <- management(a, adminA, "POST", "/api/delegations", Some(Json.obj("agentId" -> Json.fromString(agentId), "capabilityId" -> Json.fromString(capability.id), "resourceId" -> Json.fromString(connection.resource.toString))))
        delegationId = json(granted, "id")

        // 1. Cross-tenant isolation, across instances.
        (_, agentsSeenByB) <- management(b, adminB, "GET", "/api/agents")
        (foreignRevoke, _) <- management(b, adminB, "POST", s"/api/delegations/$delegationId/revoke")
        (_, agentsSeenByAOnB) <- management(b, adminA, "GET", "/api/agents")
        callOnA <- agentCall(a, bearer)
        callOnB <- agentCall(b, bearer)
        callsAfterBoth = slack.calls.get()

        // 2. A revocation on B blocks the next execution on A before any provider request.
        (revokedStatus, _) <- management(b, adminA, "POST", s"/api/delegations/$delegationId/revoke")
        deniedOnA <- agentCall(a, bearer)
        callsAfterDenial = slack.calls.get()

        // 3. Gate failover. A holds the tenant gate while its Slack request is in flight.
        (_, regranted) <- management(a, adminA, "POST", "/api/delegations", Some(Json.obj("agentId" -> Json.fromString(agentId), "capabilityId" -> Json.fromString(capability.id), "resourceId" -> Json.fromString(connection.resource.toString))))
        secondDelegation = json(regranted, "id")
        _ <- IO(slack.hold = true)
        inFlight <- agentCall(a, bearer).start
        _ <- IO.blocking(assert(slack.arrived.await(30, TimeUnit.SECONDS), "instance A never reached the provider"))
        (blockedWhileHeld, _) <- management(b, adminA, "POST", s"/api/delegations/$secondDelegation/revoke")
        // Instance A "crashes": PostgreSQL ends its gate session, which releases the lock it held.
        terminated <- IO.blocking(superuser: statement =>
          val result = statement.executeQuery(
            "select count(pg_terminate_backend(pid)) from pg_locks where locktype = 'advisory' and granted and pid <> pg_backend_pid()"
          )
          result.next()
          result.getInt(1)
        )
        (failoverTime, (revokedAfterFailover, _)) <- management(b, adminA, "POST", s"/api/delegations/$secondDelegation/revoke").timed
        _ <- IO(slack.release.countDown())
        inFlightStatus <- inFlight.joinWithNever
        _ <- IO(slack.hold = false)
        recoveredOnA <- agentCall(a, bearer)
      yield
        val agentIds = (value: Json) => value.hcursor.downField("agents").values.toVector.flatten.flatMap(_.hcursor.get[String]("id").toOption)
        assert(!agentIds(agentsSeenByB).contains(agentId), "tenant B's administrator must not see tenant A's agent")
        assertEquals(foreignRevoke, 404, "tenant B cannot revoke tenant A's delegation")
        assert(agentIds(agentsSeenByAOnB).contains(agentId), "tenant A's durable session works on instance B")
        assertEquals((callOnA, callOnB), (200, 200), "one credential works on both instances")
        assertEquals(callsAfterBoth, 2)
        assertEquals(revokedStatus, 200)
        assertEquals(deniedOnA, 403, "revocation on B denies the next call on A")
        assertEquals(callsAfterDenial, callsAfterBoth, "no provider request after revocation")
        assertEquals(blockedWhileHeld, 503, "a mutation cannot commit while another instance holds the gate")
        assert(terminated >= 1, "the holder's gate session existed")
        assertEquals(revokedAfterFailover, 200, "after the holder dies, the mutation commits")
        assert(failoverTime < 10.seconds, s"failover took $failoverTime")
        assert(Set(200, 502, 503).contains(inFlightStatus), s"the in-flight call ends with a recorded outcome, got $inFlightStatus")
        assertEquals(recoveredOnA, 403, "instance A recovers its gate and enforces the revocation made on B")
  }
