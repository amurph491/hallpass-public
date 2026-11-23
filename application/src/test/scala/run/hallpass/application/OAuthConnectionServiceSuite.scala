package run.hallpass.application

import java.net.URI
import java.time.Instant
import cats.effect.{IO, Ref}
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.kernel.*

final class OAuthConnectionServiceSuite extends CatsEffectSuite:
  private val tenant = TenantId.random()
  private val catalog = ResourceId.random()
  private val owner: Principal.Human = Principal.Human(UserId.random())
  private val session = SessionToken.generate(java.security.SecureRandom()).oauthBinding
  private val now = Instant.parse("2026-10-01T12:00:00Z")
  private val provider = ProviderId.parse("fakeprov").get
  private sealed trait Account
  private sealed trait Team
  private given account: ResourceKind[Account] =
    ResourceKind.root[Account]("fakeprov.account", provider, ResourceType.Account, Custody.Workspace)
  private val team = ResourceKind.child[Team, Account]("fakeprov.team", ResourceType.Custom)
  private val accountId = ExternalId.parse("A-1").get
  private val grant = OAuthGrant(ProviderSecret.fromUtf8("provider-token"), accountId, accountId, "Account", None, None, None)

  /** Records every interaction so tests can assert ordering and gate placement. */
  private final class World(
      val events: Ref[IO, Vector[String]],
      val held: Ref[IO, Boolean],
      val stored: Ref[IO, Map[SecretReference, Array[Byte]]],
      val bound: Ref[IO, Option[(ConnectionId, Option[SecretReference])]],
      val consumed: Ref[IO, Boolean],
      val reservationOpen: Ref[IO, Boolean]
  ):
    def log(event: String): IO[Unit] = held.get.flatMap(inside => events.update(_ :+ s"$event${if inside then "@gate" else ""}"))

    val gate: TenantExecutionMutationGate[IO] = new TenantExecutionMutationGate[IO]:
      def withinExecution[A](t: TenantId)(operation: ExecutionGatePermit[IO] => IO[A]): IO[A] =
        IO.raiseError(IllegalStateException("not expected"))
      def withinMutation[A](t: TenantId)(operation: IO[A]): IO[A] =
        held.set(true) *> operation.guarantee(held.set(false))

    val secrets: SecretStore[IO] = new SecretStore[IO]:
      def put(binding: SecretBinding, secret: ProviderSecret) =
        IO.delay(SecretReference.random()).flatTap(reference =>
          stored.update(_.updated(reference, ProviderSecret.bytes(secret))) *> log("secret.put")
        )
      def get(binding: SecretBinding, reference: SecretReference) =
        log("secret.get") *> stored.get.map(_.get(reference).map(ProviderSecret.fromBytes).toRight(SecretStoreError.NotFound))
      def delete(binding: SecretBinding, reference: SecretReference) =
        log("secret.delete") *> stored.update(_ - reference)

    val states: OAuthStateRepository[IO] = new OAuthStateRepository[IO]:
      def create(t: TenantId, r: ResourceId, s: OAuthState, b: OAuthSessionBinding, e: Instant) = IO.unit
      def consume(t: TenantId, s: OAuthState, b: OAuthSessionBinding, n: Instant) = IO.pure(Left(OAuthError.InvalidState))
      def purgeExpired(t: TenantId, n: Instant) = IO.pure(0L)
      def createBound(t: TenantId, r: ResourceId, p: ProviderId, c: ConnectionId, d: Array[Byte],
                      v: Option[SecretReference], s: OAuthState, b: OAuthSessionBinding, e: Instant) =
        bound.set(Some(c -> v))
      def consumeBound(t: TenantId, p: ProviderId, d: Array[Byte], s: OAuthState, b: OAuthSessionBinding, n: Instant) =
        consumed.getAndSet(true).flatMap:
          case true => IO.pure(Left(OAuthError.StateAlreadyUsed))
          case false =>
            bound.get.map:
              case Some((connection, verifier)) => Right(OAuthStateBinding(catalog, p, connection, verifier))
              case None                         => Left(OAuthError.InvalidState)

    def connections(activation: ConnectionActivation => IO[Either[ConnectionActivationError, Connection]]) =
      new ConnectionRepository[IO]:
        def create(t: TenantId, connection: Connection, secret: SecretReference) = IO.raiseError(IllegalStateException())
        def findForResource(t: TenantId, r: ResourceId) = IO.pure(None)
        def disable(t: TenantId, id: ConnectionId) = IO.pure(Left(ConnectionError.NotFound))
        def list(t: TenantId) = IO.pure(Vector(activeConnection))
        def secretReference(t: TenantId, id: ConnectionId) = stored.get.map(_.keys.headOption)
        override def reserve(t: TenantId, id: ConnectionId, p: String, o: Principal.Human, at: Instant)(using
            cats.ApplicativeError[IO, Throwable]
        ) = reservationOpen.set(true) *> log("reserve")
        override def activateReserved(t: TenantId, id: ConnectionId, value: ConnectionActivation, at: Instant)(using
            cats.Applicative[IO]
        ) = log("activate") *> activation(value).flatTap:
          case Right(_) => reservationOpen.set(false)
          case Left(_)  => IO.unit
        override def failReserved(t: TenantId, id: ConnectionId, at: Instant)(using cats.Applicative[IO]) =
          log("failReserved") *> reservationOpen.getAndSet(false)

  private val activeConnection = Connection(
    ConnectionId.random(), ResourceId.random(), "FAKEPROV", ConnectionStatus.Active, None, None, None, now, now
  )
  private val root = ConnectionResource(ResourceId.random(), activeConnection.id, account.wire, accountId, "Account", catalog, None, None)

  private def world: IO[World] =
    (
      Ref.of[IO, Vector[String]](Vector.empty),
      Ref.of[IO, Boolean](false),
      Ref.of[IO, Map[SecretReference, Array[Byte]]](Map.empty),
      Ref.of[IO, Option[(ConnectionId, Option[SecretReference])]](None),
      Ref.of[IO, Boolean](false),
      Ref.of[IO, Boolean](false)
    ).mapN(World(_, _, _, _, _, _))

  private def connector(
      w: World,
      pkce: Boolean = false,
      discovery: Option[ResourceDiscovery] = None,
      result: Either[OAuthError, OAuthGrant] = Right(grant),
      sentChallenge: Option[Ref[IO, Option[String]]] = None,
      receivedVerifier: Option[Ref[IO, Option[String]]] = None
  ): ProviderConnector = new ProviderConnector:
    val provider = OAuthConnectionServiceSuite.this.provider
    val rootKind = account
    val redirectUri = URI.create("https://hallpass.test/api/oauth/fakeprov/callback")
    val credentialType = "FAKE_OAUTH"
    val singleActiveRoot = true
    val usesPkce = pkce
    val resourceDiscovery = discovery
    def authorizationUri(state: OAuthState, verifier: Option[PkceVerifier]) =
      sentChallenge.traverse_(_.set(verifier.map(_.challenge))).as(URI.create("https://provider.test/authorize"))
    def exchange(callback: OAuthCallback, verifier: Option[PkceVerifier]) =
      w.log("exchange") *> receivedVerifier.traverse_(_.set(verifier.map(_.challenge))).as(result)

  private def resources(w: World, onReplace: IO[Unit] = IO.unit): ConnectionResourceRepository = new ConnectionResourceRepository:
    def createRoot(t: TenantId, c: ConnectionId, k: ResourceKind[?], e: ExternalId, d: String, u: Option[UserId]) =
      IO.raiseError(IllegalStateException("roots are created by activation"))
    def select(t: TenantId, c: ConnectionId, k: ResourceKind[?], e: ExternalId, d: String, p: ResourceId,
               s: Principal.Human, at: Instant) = IO.raiseError(IllegalStateException())
    def deselect(t: TenantId, r: ResourceId, at: Instant) = IO.raiseError(IllegalStateException())
    def listFor(t: TenantId, c: ConnectionId) = IO.pure(Vector(root))
    override def replaceSelection(t: TenantId, c: ConnectionId, s: Principal.Human,
                                  values: Vector[SelectableProviderResource], at: Instant) =
      w.log("replaceSelection") *> onReplace.as(Right(Vector(root)))

  private def service(w: World, c: ProviderConnector, repository: ConnectionRepository[IO]) =
    new OAuthConnectionService(w.states, repository, w.secrets, resources(w), Vector(c), new Clock[IO]:
      def now: IO[Instant] = IO.pure(OAuthConnectionServiceSuite.this.now)
    )

  private def callback = OAuthCallback(OAuthState.parse("a" * 43).get, "authorization-code")
  private val activated: ConnectionActivation => IO[Either[ConnectionActivationError, Connection]] =
    _ => IO.pure(Right(activeConnection))

  test("exchange and credential storage run outside the gate; only activation runs inside it") {
    for
      w <- world
      c = connector(w)
      s = service(w, c, w.connections(activated))
      _ <- s.startConnection("fakeprov", tenant, catalog, owner, session, now)
      result <- s.completeConnection("fakeprov", tenant, owner, session, callback, w.gate, now)
      events <- w.events.get
    yield
      assertEquals(result, Right(activeConnection))
      assertEquals(events, Vector("reserve", "exchange", "secret.put", "activate@gate"))
  }

  test("state is consumed once, so a replayed callback never reaches the provider") {
    for
      w <- world
      s = service(w, connector(w), w.connections(activated))
      _ <- s.startConnection("fakeprov", tenant, catalog, owner, session, now)
      _ <- s.completeConnection("fakeprov", tenant, owner, session, callback, w.gate, now)
      replay <- s.completeConnection("fakeprov", tenant, owner, session, callback, w.gate, now)
      exchanges <- w.events.get.map(_.count(_ == "exchange"))
    yield
      assertEquals(replay, Left(OAuthError.StateAlreadyUsed))
      assertEquals(exchanges, 1)
  }

  test("a refused activation deletes the new credential and fails the reservation") {
    for
      w <- world
      s = service(w, connector(w), w.connections(_ => IO.pure(Left(ConnectionActivationError.AccountAlreadyConnected))))
      _ <- s.startConnection("fakeprov", tenant, catalog, owner, session, now)
      result <- s.completeConnection("fakeprov", tenant, owner, session, callback, w.gate, now)
      remaining <- w.stored.get
      events <- w.events.get
    yield
      assertEquals(result, Left(OAuthError.AccountAlreadyConnected))
      assert(remaining.isEmpty, "the credential of a refused activation must be deleted")
      assert(events.contains("failReserved"))
  }

  test("a second root of a single-root provider is reported as already connected") {
    for
      w <- world
      s = service(w, connector(w), w.connections(_ => IO.pure(Left(ConnectionActivationError.RootKindInUse))))
      _ <- s.startConnection("fakeprov", tenant, catalog, owner, session, now)
      result <- s.completeConnection("fakeprov", tenant, owner, session, callback, w.gate, now)
    yield assertEquals(result, Left(OAuthError.ProviderAlreadyConnected))
  }

  test("a failure after activation committed never deletes the live credential") {
    for
      w <- world
      // The activation commits (the reservation closes) and then the read-back fails.
      failing = (_: ConnectionActivation) =>
        w.reservationOpen.set(false) *> IO.raiseError[Either[ConnectionActivationError, Connection]](IllegalStateException("read failed"))
      s = service(w, connector(w), w.connections(failing))
      _ <- s.startConnection("fakeprov", tenant, catalog, owner, session, now)
      result <- s.completeConnection("fakeprov", tenant, owner, session, callback, w.gate, now).attempt
      remaining <- w.stored.get
    yield
      assert(result.isLeft, "an infrastructure failure stays a failure")
      assertEquals(remaining.size, 1)
  }

  test("a rejected exchange stores nothing and fails the reservation") {
    for
      w <- world
      s = service(w, connector(w, result = Left(OAuthError.ProviderRejected)), w.connections(activated))
      _ <- s.startConnection("fakeprov", tenant, catalog, owner, session, now)
      result <- s.completeConnection("fakeprov", tenant, owner, session, callback, w.gate, now)
      events <- w.events.get
    yield
      assertEquals(result, Left(OAuthError.ProviderRejected))
      assert(!events.contains("secret.put"))
      assert(!events.exists(_.startsWith("activate")))
      assert(events.contains("failReserved"))
  }

  test("PKCE: the stored verifier matches the sent challenge, reaches the exchange, and is deleted") {
    for
      w <- world
      sent <- Ref.of[IO, Option[String]](None)
      received <- Ref.of[IO, Option[String]](None)
      s = service(w, connector(w, pkce = true, sentChallenge = Some(sent), receivedVerifier = Some(received)), w.connections(activated))
      _ <- s.startConnection("fakeprov", tenant, catalog, owner, session, now)
      boundVerifier <- w.bound.get.map(_.flatMap(_._2))
      _ <- s.completeConnection("fakeprov", tenant, owner, session, callback, w.gate, now)
      challenge <- sent.get
      exchanged <- received.get
      remaining <- w.stored.get
    yield
      assert(boundVerifier.nonEmpty, "the verifier is bound to state by reference")
      assert(challenge.nonEmpty)
      assertEquals(exchanged, challenge)
      assert(boundVerifier.forall(reference => !remaining.contains(reference)), "the verifier is single-use")
  }

  test("PKCE: state without a verifier is refused before the provider exchange") {
    for
      w <- world
      s = service(w, connector(w, pkce = true), w.connections(activated))
      _ <- s.startConnection("fakeprov", tenant, catalog, owner, session, now)
      _ <- w.bound.update(_.map((connection, _) => connection -> None))
      result <- s.completeConnection("fakeprov", tenant, owner, session, callback, w.gate, now)
      events <- w.events.get
    yield
      assertEquals(result, Left(OAuthError.InvalidState))
      assert(!events.contains("exchange"))
  }

  test("a connector without discovery never reads the stored provider credential") {
    for
      w <- world
      s = service(w, connector(w), w.connections(activated))
      _ <- w.secrets.put(SecretBinding(tenant, activeConnection.id), ProviderSecret.fromUtf8("stored"))
      listing <- s.connectionResources(tenant, activeConnection.id)
      events <- w.events.get
    yield
      assertEquals(listing.map(_.available), Right(Vector.empty))
      assert(!events.contains("secret.get"))
  }

  test("selection: provider discovery runs outside the gate and the replacement inside it") {
    val child = SelectableProviderResource(team, ExternalId.parse("T-1").get, "Team", accountId)
    for
      w <- world
      discovery = new ResourceDiscovery:
        def selectableResources(credential: ProviderSecret, r: ConnectionResource) =
          w.log("discover").as(Right(Vector(child)))
      s = service(w, connector(w, discovery = Some(discovery)), w.connections(activated))
      _ <- w.secrets.put(SecretBinding(tenant, activeConnection.id), ProviderSecret.fromUtf8("stored"))
      result <- s.replaceResources(tenant, owner, activeConnection.id, Vector(child.selectionKey), w.gate)
      unknown <- s.replaceResources(tenant, owner, activeConnection.id, Vector("fakeprov.team|T-404"), w.gate)
      events <- w.events.get
    yield
      assert(result.isRight)
      assertEquals(unknown, Left(ConnectionResourceError.InvalidPlacement))
      assertEquals(events.filter(event => event.startsWith("discover") || event.startsWith("replace")),
        Vector("discover", "replaceSelection@gate", "discover"))
  }

  // ---- reconnect in place and refreshable discovery ------------------------------------------------------------------

  private val needsReauth = activeConnection.copy(status = ConnectionStatus.NeedsReauth, externalAccountId = Some("A-1"))

  private def reauthRepository(
      w: World,
      current: Ref[IO, Connection],
      previous: SecretReference,
      outcome: ConnectionReauthorization => Either[ConnectionActivationError, SecretReference]
  ) = new ConnectionRepository[IO]:
    def create(t: TenantId, connection: Connection, secret: SecretReference) = IO.raiseError(IllegalStateException())
    def findForResource(t: TenantId, r: ResourceId) = IO.pure(None)
    def disable(t: TenantId, id: ConnectionId) = IO.pure(Left(ConnectionError.NotFound))
    def list(t: TenantId) = current.get.map(Vector(_))
    def secretReference(t: TenantId, id: ConnectionId) = IO.pure(Some(previous))
    override def activateReserved(t: TenantId, id: ConnectionId, value: ConnectionActivation, at: Instant)(using
        cats.Applicative[IO]
    ) = w.log("activate").as(Left(ConnectionActivationError.NotReserved))
    override def reauthorize(t: TenantId, id: ConnectionId, value: ConnectionReauthorization, at: Instant)(using
        cats.Applicative[IO]
    ) = w.log("reauthorize") *> IO.pure(outcome(value)).flatTap:
      case Right(_) => current.update(_.copy(status = ConnectionStatus.Active))
      case Left(_)  => IO.unit

  test("reconnecting a connection that needs reauthorization replaces its credential in place") {
    for
      w <- world
      previous <- w.secrets.put(SecretBinding(tenant, needsReauth.id), ProviderSecret.fromUtf8("old"))
      current <- Ref.of[IO, Connection](needsReauth)
      repository = reauthRepository(w, current, previous, _ => Right(previous))
      s = service(w, connector(w), repository)
      started <- s.startReauthorization(tenant, needsReauth.id, owner, session, now)
      boundConnection <- w.bound.get.map(_.map(_._1))
      result <- s.completeConnection("fakeprov", tenant, owner, session, callback, w.gate, now)
      remaining <- w.stored.get
      events <- w.events.get
    yield
      assert(started.isRight)
      assertEquals(boundConnection, Some(needsReauth.id), "state is bound to the existing connection")
      assertEquals(result.map(_.status), Right(ConnectionStatus.Active))
      assert(events.contains("reauthorize@gate"))
      assert(!events.exists(_.startsWith("activate")), "reauthorization never creates a new connection")
      assert(!remaining.contains(previous), "the superseded credential is deleted after the swap")
      assertEquals(remaining.size, 1)
  }

  test("a reconnect that signs in to another account is refused and keeps the old credential") {
    for
      w <- world
      previous <- w.secrets.put(SecretBinding(tenant, needsReauth.id), ProviderSecret.fromUtf8("old"))
      current <- Ref.of[IO, Connection](needsReauth)
      repository = reauthRepository(w, current, previous, _ => Left(ConnectionActivationError.AccountMismatch))
      s = service(w, connector(w), repository)
      _ <- s.startReauthorization(tenant, needsReauth.id, owner, session, now)
      result <- s.completeConnection("fakeprov", tenant, owner, session, callback, w.gate, now)
      remaining <- w.stored.get
      status <- current.get.map(_.status)
    yield
      assertEquals(result, Left(OAuthError.AccountMismatch))
      assertEquals(remaining.keySet, Set(previous))
      assertEquals(status, ConnectionStatus.NeedsReauth)
  }

  test("an active connection cannot be reauthorized") {
    for
      w <- world
      s = service(w, connector(w), w.connections(activated))
      result <- s.startReauthorization(tenant, activeConnection.id, owner, session, now)
    yield assertEquals(result, Left(OAuthError.InvalidState))
  }

  test("discovery for a refreshable connection receives only an unexpired access token") {
    final class PlainCodec extends OAuthTokenCodec:
      def encode(tokens: OAuthTokens) =
        ProviderSecret.fromUtf8(s"${tokens.accessToken} ${tokens.refreshToken.getOrElse("-")} ${tokens.expiresAt}")
      def decode(secret: ProviderSecret) =
        new String(ProviderSecret.bytes(secret), java.nio.charset.StandardCharsets.UTF_8).split(' ') match
          case Array(access, refresh, expiry) =>
            OAuthTokens.from(access, Option.when(refresh != "-")(refresh), Instant.parse(expiry)).toRight(ConnectionError.MissingCredential)
          case _ => Left(ConnectionError.MissingCredential)
    def run(expiresAt: Instant) =
      for
        w <- world
        seen <- Ref.of[IO, Option[String]](None)
        discovery = new ResourceDiscovery:
          def selectableResources(credential: ProviderSecret, r: ConnectionResource) =
            seen.set(Some(new String(ProviderSecret.bytes(credential), java.nio.charset.StandardCharsets.UTF_8))).as(Right(Vector.empty))
        base = connector(w, discovery = Some(discovery))
        refreshable = new ProviderConnector:
          export base.{provider, rootKind, redirectUri, singleActiveRoot, usesPkce, resourceDiscovery, authorizationUri, exchange}
          val credentialType = OAuthGrant.RefreshableCredentialType
        tokens = OAuthTokens.from("access-1", Some("refresh-1"), expiresAt).get
        _ <- w.secrets.put(SecretBinding(tenant, activeConnection.id), new PlainCodec().encode(tokens))
        s = new OAuthConnectionService(w.states, w.connections(activated), w.secrets, resources(w), Vector(refreshable),
          new Clock[IO]:
            def now: IO[Instant] = IO.pure(OAuthConnectionServiceSuite.this.now)
          , tokenCodec = Some(new PlainCodec()))
        listing <- s.connectionResources(tenant, activeConnection.id)
        credential <- seen.get
      yield (listing.isRight, credential)
    for
      fresh <- run(now.plusSeconds(600))
      expired <- run(now.minusSeconds(1))
    yield
      assertEquals(fresh, (true, Some("access-1")))
      assertEquals(expired, (false, None))
  }
