package run.hallpass.adapters.google

import java.net.{InetSocketAddress, URI}
import java.net.http.HttpClient
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import cats.effect.IO
import munit.CatsEffectSuite
import com.sun.net.httpserver.{HttpExchange, HttpServer}
import run.hallpass.adapters.oauth.OAuthTokenJsonCodec
import run.hallpass.application.*
import run.hallpass.kernel.*

/** Exercises the management path end to end: stored refreshable record -> service -> Google discovery -> selection. */
final class GoogleDiscoveryPipelineSuite extends CatsEffectSuite:
  private val now = Instant.parse("2026-10-01T12:00:00Z")
  private val tenant = TenantId.random()
  private val owner: Principal.Human = Principal.Human(UserId.random())
  private val connectionId = ConnectionId.random()
  private val catalog = ResourceId.random()
  private val root = ConnectionResource(ResourceId.random(), connectionId, Google.account.wire,
    ExternalId.parse("google-subject").get, "Account", catalog, None, None)
  private val connection = Connection(connectionId, catalog, "GOOGLE", ConnectionStatus.Active,
    None, None, None, now, now)
  private val reference = SecretReference.random()
  private val access = "google-access-token"
  private val refresh = "google-refresh-token"
  private val fixedClock = new Clock[IO]:
    def now: IO[Instant] = IO.pure(GoogleDiscoveryPipelineSuite.this.now)

  private final class World(secret: ProviderSecret):
    var selected = Vector.empty[SelectableProviderResource]
    var selectedRows = Vector.empty[ConnectionResource]
    val states: OAuthStateRepository[IO] = new OAuthStateRepository[IO]:
      def create(t: TenantId, r: ResourceId, s: OAuthState, b: OAuthSessionBinding, e: Instant) = IO.unit
      def consume(t: TenantId, s: OAuthState, b: OAuthSessionBinding, n: Instant) = IO.pure(Left(OAuthError.InvalidState))
      def purgeExpired(t: TenantId, n: Instant) = IO.pure(0L)
      def createBound(t: TenantId, r: ResourceId, p: ProviderId, c: ConnectionId, d: Array[Byte], v: Option[SecretReference],
          s: OAuthState, b: OAuthSessionBinding, e: Instant) = IO.unit
      def consumeBound(t: TenantId, p: ProviderId, d: Array[Byte], s: OAuthState, b: OAuthSessionBinding, n: Instant) =
        IO.pure(Left(OAuthError.InvalidState))
    val connections: ConnectionRepository[IO] = new ConnectionRepository[IO]:
      def create(t: TenantId, c: Connection, s: SecretReference) = IO.pure(c)
      def findForResource(t: TenantId, r: ResourceId) = IO.pure(None)
      def disable(t: TenantId, id: ConnectionId) = IO.pure(Left(ConnectionError.NotFound))
      def list(t: TenantId) = IO.pure(Vector(connection))
      def secretReference(t: TenantId, id: ConnectionId) = IO.pure(Some(reference))
    val secrets: SecretStore[IO] = new SecretStore[IO]:
      def put(b: SecretBinding, s: ProviderSecret) = IO.pure(reference)
      def get(b: SecretBinding, r: SecretReference) = IO.pure(Right(secret))
      def delete(b: SecretBinding, r: SecretReference) = IO.unit
    val resources: ConnectionResourceRepository = new ConnectionResourceRepository:
      def createRoot(t: TenantId, c: ConnectionId, k: ResourceKind[?], e: ExternalId, d: String, u: Option[UserId]) =
        IO.pure(Left(ConnectionResourceError.PersistenceFailure))
      def select(t: TenantId, c: ConnectionId, k: ResourceKind[?], e: ExternalId, d: String, p: ResourceId,
          s: Principal.Human, at: Instant) = IO.pure(Left(ConnectionResourceError.PersistenceFailure))
      def deselect(t: TenantId, r: ResourceId, at: Instant) = IO.pure(Left(ConnectionResourceError.NotFound))
      def listFor(t: TenantId, c: ConnectionId) = IO.pure(Vector(root))
      override def replaceSelection(t: TenantId, c: ConnectionId, s: Principal.Human,
          values: Vector[SelectableProviderResource], at: Instant) =
        IO.delay:
          selected = values
          selectedRows = values.map(value => ConnectionResource(
            ResourceId.random(), c, value.kind.wire, value.externalId, value.displayName, root.id, None, None
          ))
          Right(selectedRows)
    val gate: TenantExecutionMutationGate[IO] = new TenantExecutionMutationGate[IO]:
      def withinExecution[A](t: TenantId)(op: ExecutionGatePermit[IO] => IO[A]) = IO.raiseError(IllegalStateException("unused"))
      def withinMutation[A](t: TenantId)(op: IO[A]) = op

  private def withServer[A](body: String)(f: URI => IO[A]): IO[(A, Int)] =
    cats.effect.Resource.make(IO.blocking:
      val calls = AtomicInteger(0)
      val server = HttpServer.create(InetSocketAddress(java.net.InetAddress.getLoopbackAddress, 0), 0)
      server.createContext("/", (exchange: HttpExchange) =>
        calls.incrementAndGet()
        val token = exchange.getRequestHeaders.getFirst("Authorization")
        val status = if token == s"Bearer $access" then 200 else 401
        val bytes = (if status == 200 then body else "{}").getBytes(StandardCharsets.UTF_8)
        exchange.sendResponseHeaders(status, bytes.length.toLong)
        exchange.getResponseBody.write(bytes)
        exchange.close()
      )
      server.start()
      server -> calls
    )((server, _) => IO.blocking(server.stop(0))).use: (server, calls) =>
      f(URI.create(s"http://127.0.0.1:${server.getAddress.getPort}")).map(_ -> calls.get())

  private def run(
      expiresAt: Instant,
      encodedOverride: Option[ProviderSecret] = None,
      gmailSend: Boolean = false,
      mailboxOnly: Boolean = false
  ) =
    val encoded = encodedOverride.getOrElse(OAuthTokenJsonCodec().encode(
      OAuthTokens.from(access, Some(refresh), expiresAt).get
    ))
    val world = World(encoded)
    val body = """{"files":[{"id":"file000000000001","name":"Quarterly report","mimeType":"text/plain"}]}"""
    withServer(body): base =>
      val endpoints = GoogleEndpoints(base.resolve("/authorize"), base.resolve("/token"), base.resolve("/userinfo"), base)
      val google = GoogleConnector(GoogleOAuthClient("client-id", "client-secret", None, None), endpoints,
        HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(), fixedClock,
        URI.create("https://hallpass.example/oauth/callback"), gmailSend = gmailSend)
      val service = new OAuthConnectionService(world.states, world.connections, world.secrets, world.resources,
        Vector(google), fixedClock, tokenCodec = Some(OAuthTokenJsonCodec()))
      for
        listing <- service.connectionResources(tenant, connectionId)
        selected <- service.replaceResources(tenant, owner, connectionId,
          listing.toOption.toVector.flatMap(_.available
            .filter(item => !mailboxOnly || (item.kind eq Google.mailbox)).map(_.selectionKey)), world.gate)
      yield (listing, selected, world.selected, world.selectedRows)
    .map { case ((listing, selected, persisted, rows), calls) => (listing, selected, persisted, rows, calls) }

  test("stored refreshable record discovers Google files and server-side selection uses that listing") {
    run(now.plusSeconds(600)).map: (listing, selected, persisted, rows, calls) =>
      assertEquals(listing.toOption.get.available.map(_.displayName), Vector("Quarterly report"))
      assert(selected.isRight)
      assertEquals(persisted.map(_.externalId.value), Vector("file000000000001"))
      assertEquals(calls, 2)
      assertEquals(rows.map(_.parent), Vector(root.id))
  }

  test("Gmail discovery passes only the unexpired access token and mailbox selection keeps its account parent") {
    run(now.plusSeconds(600), gmailSend = true, mailboxOnly = true).map: (listing, selected, persisted, rows, calls) =>
      val available = listing.toOption.get.available
      val mailbox = available.find(_.kind eq Google.mailbox).get
      assertEquals(mailbox.externalId.value, root.externalId.value)
      assertEquals(mailbox.parentExternalId.value, root.externalId.value)
      assertEquals(mailbox.displayName, "Mailbox (send) — Account")
      assert(selected.isRight)
      assertEquals(persisted.map(_.kind.wire), Vector(Google.mailbox.wire))
      assertEquals(rows.map(_.kind), Vector(Google.mailbox.wire))
      assertEquals(rows.map(_.parent), Vector(root.id))
      // Each management listing performs only the existing Drive listing request; mailbox discovery is local.
      assertEquals(calls, 2)
  }

  test("expired and malformed stored records fail closed before a Google call") {
    for
      expired <- run(now)
      malformed <- run(now.plusSeconds(600), Some(ProviderSecret.fromUtf8("not-json")))
    yield
      assertEquals(expired._1, Left(OAuthError.ProviderRejected))
      assertEquals(expired._3, Vector.empty)
      assertEquals(expired._5, 0)
      assertEquals(malformed._1, Left(OAuthError.ProviderRejected))
      assertEquals(malformed._3, Vector.empty)
      assertEquals(malformed._5, 0)
  }
