package run.hallpass.application

import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.{Duration, Instant}
import java.util.Base64
import cats.effect.IO
import cats.syntax.all.*
import cats.effect.kernel.Ref
import munit.CatsEffectSuite
import run.hallpass.kernel.*

/** The generic provider connection flow (start, callback, resource listing and selection), with and without PKCE,
  * against in-memory fakes. The fakes implement the single-use, session, provider, redirect, and expiry rules of the
  * durable state repository so that the service is exercised against faithful collaborators. */
final class ProviderConnectionFlowSuite extends CatsEffectSuite:
  private sealed trait TRoot
  private val testProvider = ProviderId.parse("test").getOrElse(fail("provider"))
  private val otherProvider = ProviderId.parse("other").getOrElse(fail("provider"))
  private val workspaceRoot: ResourceKind[TRoot] =
    ResourceKind.root[TRoot]("test.account", testProvider, ResourceType.Account, Custody.Workspace)
  private val personalRoot: ResourceKind[TRoot] =
    ResourceKind.root[TRoot]("test.mailbox", testProvider, ResourceType.Account, Custody.Personal)

  private val tenant = TenantId.random()
  private val catalog = ResourceId.random()
  private val owner: Principal.Human = Principal.Human(UserId.random())
  private val t0 = Instant.parse("2026-01-01T00:00:00Z")
  private val random = java.security.SecureRandom()
  private val sessionA = SessionToken.generate(random).oauthBinding
  private val sessionB = SessionToken.generate(random).oauthBinding
  private val redirect = URI.create("https://hallpass.example.test/callback/test")

  private def ext(value: String): ExternalId = ExternalId.parse(value).getOrElse(fail(s"external id $value"))
  private val tokenText = "provider-access-token-value"
  private val defaultGrant = OAuthGrant(
    ProviderSecret.fromUtf8(tokenText), ext("account-1"), ext("root-1"), "Root display", Some("account label"),
    Some("workspace label"), None
  )

  private enum Mode:
    case Ok, Refuse, Raise

  private def challengeOf(verifier: String): String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(
      MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII))
    )

  private def stateIn(uri: URI): OAuthState =
    val raw = uri.getQuery.split("&").collectFirst { case p if p.startsWith("state=") => p.drop(6) }.getOrElse(fail("no state"))
    OAuthState.parse(raw).getOrElse(fail("bad state"))

  private final case class StateRecord(
      provider: ProviderId,
      connection: ConnectionId,
      redirect: Vector[Byte],
      pkce: Option[SecretReference],
      session: OAuthSessionBinding,
      expiresAt: Instant,
      consumed: Boolean
  )
  private final case class RootCall(kind: String, externalId: ExternalId, displayName: String, custodian: Option[UserId])

  /** All collaborators and their recordings. Every knob defaults to success. */
  private final class World(
      val states: Ref[IO, Map[String, StateRecord]],
      val conns: Ref[IO, Map[ConnectionId, Connection]],
      val secretRefs: Ref[IO, Map[ConnectionId, SecretReference]],
      val failed: Ref[IO, Vector[ConnectionId]],
      val attached: Ref[IO, Vector[ConnectionId]],
      val stored: Ref[IO, Map[SecretReference, (SecretBinding, Array[Byte])]],
      val puts: Ref[IO, Vector[SecretBinding]],
      val gets: Ref[IO, Int],
      val deletes: Ref[IO, Vector[SecretReference]],
      val roots: Ref[IO, Vector[RootCall]],
      val rootRows: Ref[IO, Vector[ConnectionResource]],
      val replaced: Ref[IO, Vector[Vector[SelectableProviderResource]]],
      val challenges: Ref[IO, Vector[Option[String]]],
      val exchanges: Ref[IO, Vector[Option[String]]],
      val putsAllowed: Ref[IO, Int],
      val activate: Ref[IO, Mode],
      val createRootFails: Ref[IO, Boolean],
      val attachFails: Ref[IO, Boolean],
      val reserveFails: Ref[IO, Boolean],
      val pkceBindFails: Ref[IO, Boolean],
      val bindFails: Ref[IO, Boolean],
      val exchangeResult: Ref[IO, Either[OAuthError, OAuthGrant]],
      val available: Ref[IO, Vector[SelectableProviderResource]],
      val listedWith: Ref[IO, Vector[String]]
  ):
    val stateRepository: OAuthStateRepository[IO] = new OAuthStateRepository[IO]:
      def create(t: TenantId, r: ResourceId, s: OAuthState, b: OAuthSessionBinding, expiresAt: Instant) = IO.unit
      def consume(t: TenantId, s: OAuthState, b: OAuthSessionBinding, now: Instant) = IO.pure(Left(OAuthError.InvalidState))
      // Expiry is observable through consumeBound, so housekeeping here removes nothing.
      def purgeExpired(t: TenantId, now: Instant) = IO.pure(0L)
      override def createBound(
          t: TenantId, r: ResourceId, p: ProviderId, c: ConnectionId, rb: Array[Byte], ref: Option[SecretReference],
          s: OAuthState, b: OAuthSessionBinding, expiresAt: Instant
      ): IO[Unit] =
        (if ref.isDefined then pkceBindFails else bindFails).get.flatMap: refused =>
          if refused then IO.raiseError(RuntimeException("bind refused"))
          else states.update(_ + (s.value -> StateRecord(p, c, rb.toVector, ref, b, expiresAt, false)))
      override def consumeBound(
          t: TenantId, p: ProviderId, rb: Array[Byte], s: OAuthState, b: OAuthSessionBinding, now: Instant
      ): IO[Either[OAuthError, OAuthStateBinding]] =
        states.modify: all =>
          all.get(s.value) match
            case None => (all, Left(OAuthError.InvalidState))
            case Some(rec) if rec.session != b || rec.provider != p || rec.redirect != rb.toVector =>
              (all, Left(OAuthError.InvalidState))
            case Some(rec) if rec.consumed => (all, Left(OAuthError.StateAlreadyUsed))
            case Some(rec) if !rec.expiresAt.isAfter(now) => (all, Left(OAuthError.ExpiredState))
            case Some(rec) =>
              (all.updated(s.value, rec.copy(consumed = true)), Right(OAuthStateBinding(catalog, rec.provider, rec.connection, rec.pkce)))

    val connectionRepository: ConnectionRepository[IO] = new ConnectionRepository[IO]:
      def create(t: TenantId, c: Connection, s: SecretReference) = IO.raiseError(RuntimeException("not used"))
      def findForResource(t: TenantId, r: ResourceId) = IO.pure(None)
      def disable(t: TenantId, id: ConnectionId) = IO.pure(Right(()))
      def list(t: TenantId) = conns.get.map(_.values.toVector)
      def secretReference(t: TenantId, id: ConnectionId) = secretRefs.get.map(_.get(id))
      override def reserve(t: TenantId, id: ConnectionId, p: String, o: Principal.Human, at: Instant)(using
          cats.ApplicativeError[IO, Throwable]
      ): IO[Unit] =
        reserveFails.get.flatMap: refused =>
          if refused then IO.raiseError(RuntimeException("reserve refused"))
          else conns.update(_ + (id -> Connection(id, catalog, p, ConnectionStatus.Connecting, None, None, None, at, at)))
      override def activateReserved(
          t: TenantId, id: ConnectionId, a: ConnectionActivation, at: Instant
      )(using cats.Applicative[IO]): IO[Either[ConnectionActivationError, Connection]] =
        activate.get.flatMap:
          case Mode.Raise => IO.raiseError(RuntimeException("database unavailable"))
          case Mode.Refuse => IO.pure(Left(ConnectionActivationError.InvalidPlacement))
          case Mode.Ok =>
            (createRootFails.get, attachFails.get).tupled.flatMap: (rootFailure, attachFailure) =>
              if rootFailure || attachFailure then IO.pure(Left(ConnectionActivationError.InvalidPlacement))
              else
                val row = ConnectionResource(ResourceId.random(), id, a.rootKind.wire, a.rootExternalId,
                  a.rootDisplayName, catalog, a.rootCustodian, None)
                secretRefs.update(_ + (id -> a.secret)) *>
                  conns.update(_.updatedWith(id)(_.map(_.copy(
                    status = ConnectionStatus.Active, accountLabel = a.accountLabel, workspaceLabel = a.workspaceLabel,
                    expiresAt = a.expiresAt, externalAccountId = Some(a.externalAccountId.value)
                  )))) *>
                  roots.update(_ :+ RootCall(a.rootKind.wire, a.rootExternalId, a.rootDisplayName, a.rootCustodian)) *>
                  rootRows.update(_ :+ row) *> attached.update(_ :+ id) *> conns.get.map(all => Right(all(id)))
      override def failReserved(t: TenantId, id: ConnectionId, at: Instant)(using cats.Applicative[IO]): IO[Boolean] =
        failed.update(_ :+ id) *> conns.update(_.updatedWith(id)(_.map(_.copy(status = ConnectionStatus.Error)))).as(true)

    val secretStore: SecretStore[IO] = new SecretStore[IO]:
      def put(binding: SecretBinding, secret: ProviderSecret) =
        putsAllowed.modify(n => (n - 1, n > 0)).flatMap: allowed =>
          if !allowed then IO.raiseError(RuntimeException("secret store unavailable"))
          else
            val reference = SecretReference.random()
            puts.update(_ :+ binding) *> stored.update(_ + (reference -> (binding -> ProviderSecret.bytes(secret)))).as(reference)
      def get(binding: SecretBinding, reference: SecretReference) =
        gets.update(_ + 1) *> stored.get.map: all =>
          if all.get(reference).exists(_._1 == binding) then Right(ProviderSecret.fromBytes(all(reference)._2))
          else Left(SecretStoreError.NotFound)
      def delete(binding: SecretBinding, reference: SecretReference) =
        deletes.update(_ :+ reference) *> stored.update(_ - reference)

    val resourceRepository: ConnectionResourceRepository = new ConnectionResourceRepository:
      def createRoot(t: TenantId, c: ConnectionId, kind: ResourceKind[?], e: ExternalId, name: String, custodian: Option[UserId]) =
        createRootFails.get.flatMap: refused =>
          if refused then IO.pure(Left(ConnectionResourceError.PersistenceFailure))
          else
            val row = ConnectionResource(ResourceId.random(), c, kind.wire, e, name, catalog, custodian, None)
            roots.update(_ :+ RootCall(kind.wire, e, name, custodian)) *> rootRows.update(_ :+ row).as(Right(row))
      def select(t: TenantId, c: ConnectionId, k: ResourceKind[?], e: ExternalId, n: String, p: ResourceId, by: Principal.Human, at: Instant) =
        IO.pure(Left(ConnectionResourceError.PersistenceFailure))
      def deselect(t: TenantId, r: ResourceId, at: Instant) = IO.pure(Left(ConnectionResourceError.NotFound))
      def listFor(t: TenantId, c: ConnectionId) = rootRows.get.map(_.filter(_.connection == c))
      override def replaceSelection(
          t: TenantId, c: ConnectionId, by: Principal.Human, resources: Vector[SelectableProviderResource], at: Instant
      ) = replaced.update(_ :+ resources).as(Right(Vector.empty))

    def connector(
        pkce: Boolean,
        id: ProviderId = testProvider,
        callback: URI = redirect,
        root: ResourceKind[TRoot] = workspaceRoot
    ): ProviderConnector = new ProviderConnector:
      def provider: ProviderId = id
      def rootKind: ResourceKind[?] = root
      def redirectUri: URI = callback
      def credentialType: String = "OAUTH_TOKEN"
      override def usesPkce: Boolean = pkce
      def singleActiveRoot: Boolean = false
      def authorizationUri(state: OAuthState): IO[URI] =
        IO.pure(URI.create(s"https://provider.test/authorize?state=${state.value}"))
      override def authorizationUri(state: OAuthState, challenge: Option[PkceVerifier]): IO[URI] =
        challenges.update(_ :+ challenge.map(_.challenge)) *>
          IO.pure(URI.create(
            s"https://provider.test/authorize?state=${state.value}" +
              challenge.fold("")(c => s"&code_challenge=${c.challenge}&code_challenge_method=S256")
          ))
      def exchange(callback: OAuthCallback): IO[Either[OAuthError, OAuthGrant]] = exchangeResult.get
      override def exchange(callback: OAuthCallback, verifier: Option[PkceVerifier]): IO[Either[OAuthError, OAuthGrant]] =
        exchanges.update(_ :+ verifier.map(_.value)) *> exchangeResult.get
      def resourceDiscovery: Option[ResourceDiscovery] = Some(new ResourceDiscovery:
        def selectableResources(credential: ProviderSecret, rootResource: ConnectionResource) =
          listedWith.update(_ :+ String(ProviderSecret.bytes(credential), StandardCharsets.UTF_8)) *> available.get.map(Right(_))
      )

    def service(
        connector: ProviderConnector,
        withResources: Boolean = true,
        extra: Vector[ProviderConnector] = Vector.empty
    ): OAuthConnectionService =
      new OAuthConnectionService(
        stateRepository, connectionRepository, secretStore, resourceRepository,
        (if withResources then Vector(connector) ++ extra else Vector.empty),
        new Clock[IO]:
          def now = IO.pure(t0.plusSeconds(5))
      )

  private def world: IO[World] =
    for
      states <- Ref.of[IO, Map[String, StateRecord]](Map.empty)
      conns <- Ref.of[IO, Map[ConnectionId, Connection]](Map.empty)
      secretRefs <- Ref.of[IO, Map[ConnectionId, SecretReference]](Map.empty)
      failed <- Ref.of[IO, Vector[ConnectionId]](Vector.empty)
      attached <- Ref.of[IO, Vector[ConnectionId]](Vector.empty)
      stored <- Ref.of[IO, Map[SecretReference, (SecretBinding, Array[Byte])]](Map.empty)
      puts <- Ref.of[IO, Vector[SecretBinding]](Vector.empty)
      gets <- Ref.of[IO, Int](0)
      deletes <- Ref.of[IO, Vector[SecretReference]](Vector.empty)
      roots <- Ref.of[IO, Vector[RootCall]](Vector.empty)
      rootRows <- Ref.of[IO, Vector[ConnectionResource]](Vector.empty)
      replaced <- Ref.of[IO, Vector[Vector[SelectableProviderResource]]](Vector.empty)
      challenges <- Ref.of[IO, Vector[Option[String]]](Vector.empty)
      exchanges <- Ref.of[IO, Vector[Option[String]]](Vector.empty)
      putsAllowed <- Ref.of[IO, Int](Int.MaxValue)
      activate <- Ref.of[IO, Mode](Mode.Ok)
      f1 <- Ref.of[IO, Boolean](false)
      f2 <- Ref.of[IO, Boolean](false)
      f3 <- Ref.of[IO, Boolean](false)
      f4 <- Ref.of[IO, Boolean](false)
      f5 <- Ref.of[IO, Boolean](false)
      result <- Ref.of[IO, Either[OAuthError, OAuthGrant]](Right(defaultGrant))
      available <- Ref.of[IO, Vector[SelectableProviderResource]](Vector.empty)
      listed <- Ref.of[IO, Vector[String]](Vector.empty)
    yield World(
      states, conns, secretRefs, failed, attached, stored, puts, gets, deletes, roots, rootRows, replaced, challenges,
      exchanges, putsAllowed, activate, f1, f2, f3, f4, f5, result, available, listed
    )

  private def start(svc: OAuthConnectionService, session: OAuthSessionBinding = sessionA, name: String = "test") =
    svc.startConnection(name, tenant, catalog, owner, session, t0)

  private def complete(
      svc: OAuthConnectionService,
      uri: URI,
      session: OAuthSessionBinding = sessionA,
      at: Instant = t0.plusSeconds(5),
      name: String = "test"
  ) = gate.flatMap(g => svc.completeConnection(name, tenant, owner, session, OAuthCallback(stateIn(uri), "code"), g, at))

  private def gate = SingleProcessTenantExecutionMutationGate.create

  private def startOk(svc: OAuthConnectionService): IO[URI] =
    start(svc).map(_.getOrElse(fail("start failed")))

  private def onlyConnection(w: World): IO[ConnectionId] =
    w.conns.get.map: all =>
      assertEquals(all.size, 1)
      all.keys.head

  private def storedText(w: World): IO[Vector[String]] =
    w.stored.get.map(_.values.map(v => String(v._2, StandardCharsets.UTF_8)).toVector)

  // ---- non-PKCE ------------------------------------------------------------------------------------------------

  test("non-PKCE: start reserves the connection, binds state to it, and returns the connector's URI") {
    for
      w <- world
      uri <- startOk(w.service(w.connector(pkce = false)))
      id <- onlyConnection(w)
      conn <- w.conns.get.map(_(id))
      state <- w.states.get.map(_.values.toVector)
      challenges <- w.challenges.get
      puts <- w.puts.get
    yield
      assertEquals(uri.getHost, "provider.test")
      assertEquals(conn.status, ConnectionStatus.Connecting)
      assertEquals(conn.provider, "TEST")
      assertEquals(state.map(s => (s.connection, s.provider, s.pkce)), Vector((id, testProvider, None)))
      assertEquals(challenges, Vector(None))
      assertEquals(puts, Vector.empty)
      assert(!uri.toString.contains("code_challenge"))
  }

  test("non-PKCE: complete exchanges once, stores the secret under (tenant, reserved connection), activates, roots and attaches") {
    for
      w <- world
      svc = w.service(w.connector(pkce = false))
      uri <- startOk(svc)
      id <- onlyConnection(w)
      result <- complete(svc, uri)
      exchanges <- w.exchanges.get
      puts <- w.puts.get
      texts <- storedText(w)
      roots <- w.roots.get
      attached <- w.attached.get
      failed <- w.failed.get
      ref <- w.secretRefs.get
    yield
      assertEquals(result.map(c => (c.id, c.status)), Right((id, ConnectionStatus.Active)))
      assertEquals(exchanges, Vector(None))
      assertEquals(puts, Vector(SecretBinding(tenant, id)))
      assertEquals(texts, Vector(tokenText))
      assertEquals(ref.keySet, Set(id))
      assertEquals(roots, Vector(RootCall("test.account", ext("root-1"), "Root display", None)))
      assertEquals(attached, Vector(id))
      assertEquals(failed, Vector.empty)
  }

  test("a personal root's custodian is the session's human") {
    for
      w <- world
      svc = w.service(w.connector(pkce = false, root = personalRoot))
      uri <- startOk(svc)
      _ <- complete(svc, uri)
      roots <- w.roots.get
    yield assertEquals(roots.map(r => (r.kind, r.custodian)), Vector(("test.mailbox", Some(owner.id))))
  }

  // ---- PKCE ----------------------------------------------------------------------------------------------------

  test("PKCE: start stores only the verifier under (tenant, reserved connection) and sends only its S256 challenge") {
    for
      w <- world
      uri <- startOk(w.service(w.connector(pkce = true)))
      id <- onlyConnection(w)
      puts <- w.puts.get
      texts <- storedText(w)
      challenges <- w.challenges.get
      record <- w.states.get.map(_.values.head)
      refs <- w.stored.get.map(_.keySet)
    yield
      assertEquals(puts, Vector(SecretBinding(tenant, id)))
      assertEquals(texts.size, 1)
      val verifier = texts.head
      assert(PkceVerifier.parse(verifier).isDefined)
      assertEquals(challenges, Vector(Some(challengeOf(verifier))))
      assert(!challengeOf(verifier).contains("="), "no padding")
      assert(!uri.toString.contains(verifier), "the authorization URI never carries the verifier")
      assert(uri.toString.contains(s"code_challenge=${challengeOf(verifier)}"))
      assertEquals(record.pkce.map(Set(_)), Some(refs))
  }

  test("PKCE: complete passes the same verifier to exchange and deletes the verifier secret afterwards") {
    for
      w <- world
      svc = w.service(w.connector(pkce = true))
      uri <- startOk(svc)
      id <- onlyConnection(w)
      verifier <- storedText(w).map(_.head)
      verifierRef <- w.stored.get.map(_.keys.head)
      result <- complete(svc, uri)
      exchanges <- w.exchanges.get
      deletes <- w.deletes.get
      texts <- storedText(w)
      puts <- w.puts.get
    yield
      assertEquals(result.map(_.id), Right(id))
      assertEquals(exchanges, Vector(Some(verifier)))
      assert(deletes.contains(verifierRef))
      assertEquals(texts, Vector(tokenText), "only the provider credential remains")
      assertEquals(puts, Vector.fill(2)(SecretBinding(tenant, id)))
  }

  test("PKCE: the verifier is deleted when exchange fails") {
    for
      w <- world
      svc = w.service(w.connector(pkce = true))
      uri <- startOk(svc)
      id <- onlyConnection(w)
      _ <- w.exchangeResult.set(Left(OAuthError.ProviderRejected))
      result <- complete(svc, uri)
      texts <- storedText(w)
      failed <- w.failed.get
    yield
      assertEquals(result, Left(OAuthError.ProviderRejected))
      assertEquals(texts, Vector.empty)
      assertEquals(failed, Vector(id))
  }

  test("PKCE: a malformed stored verifier is InvalidState, exchange is not called, and the secret is deleted") {
    for
      w <- world
      svc = w.service(w.connector(pkce = true))
      uri <- startOk(svc)
      id <- onlyConnection(w)
      ref <- w.stored.get.map(_.keys.head)
      _ <- w.stored.update(_.updated(ref, (SecretBinding(tenant, id), "too short".getBytes(StandardCharsets.US_ASCII))))
      result <- complete(svc, uri)
      exchanges <- w.exchanges.get
      texts <- storedText(w)
      failed <- w.failed.get
    yield
      assertEquals(result, Left(OAuthError.InvalidState))
      assertEquals(exchanges, Vector.empty)
      assertEquals(texts, Vector.empty)
      assertEquals(failed, Vector(id))
  }

  test("PKCE: a verifier that cannot be read is InvalidState without calling exchange") {
    for
      w <- world
      svc = w.service(w.connector(pkce = true))
      uri <- startOk(svc)
      id <- onlyConnection(w)
      _ <- w.stored.set(Map.empty)
      result <- complete(svc, uri)
      exchanges <- w.exchanges.get
      failed <- w.failed.get
    yield
      assertEquals(result, Left(OAuthError.InvalidState))
      assertEquals(exchanges, Vector.empty)
      assertEquals(failed, Vector(id))
  }

  test("PKCE: a verifier stored under another connection's binding is not readable") {
    for
      w <- world
      svc = w.service(w.connector(pkce = true))
      uri <- startOk(svc)
      ref <- w.stored.get.map(_.keys.head)
      verifier <- storedText(w).map(_.head)
      _ <- w.stored.update(_.updated(ref, (SecretBinding(tenant, ConnectionId.random()), verifier.getBytes(StandardCharsets.US_ASCII))))
      result <- complete(svc, uri)
      exchanges <- w.exchanges.get
    yield
      assertEquals(result, Left(OAuthError.InvalidState))
      assertEquals(exchanges, Vector.empty)
  }

  test("a PKCE provider whose state has no verifier reference is InvalidState, exchange is not called, reservation failed") {
    for
      w <- world
      uri <- startOk(w.service(w.connector(pkce = false)))
      id <- onlyConnection(w)
      result <- complete(w.service(w.connector(pkce = true)), uri)
      exchanges <- w.exchanges.get
      failed <- w.failed.get
    yield
      assertEquals(result, Left(OAuthError.InvalidState))
      assertEquals(exchanges, Vector.empty)
      assertEquals(failed, Vector(id))
  }

  test("a non-PKCE provider whose state has a verifier reference is InvalidState, exchange is not called, reservation failed") {
    for
      w <- world
      uri <- startOk(w.service(w.connector(pkce = true)))
      id <- onlyConnection(w)
      result <- complete(w.service(w.connector(pkce = false)), uri)
      exchanges <- w.exchanges.get
      failed <- w.failed.get
    yield
      assertEquals(result, Left(OAuthError.InvalidState))
      assertEquals(exchanges, Vector.empty)
      assertEquals(failed, Vector(id))
  }

  // Invariant: the verifier is deleted after the callback whatever the outcome. In this mismatch case the service
  // returns without deleting the stored verifier, which stays encrypted in the secret store. Reported as a defect; the
  // test pins the intended behaviour and is expected to fail until the service is fixed.
  test("a non-PKCE provider refusing a state that carries a verifier still deletes the verifier") {
    for
      w <- world
      uri <- startOk(w.service(w.connector(pkce = true)))
      _ <- complete(w.service(w.connector(pkce = false)), uri)
      texts <- storedText(w)
    yield assertEquals(texts, Vector.empty)
  }

  // ---- state rules ---------------------------------------------------------------------------------------------

  test("state replay is StateAlreadyUsed and exchange runs once in total") {
    for
      w <- world
      svc = w.service(w.connector(pkce = false))
      uri <- startOk(svc)
      first <- complete(svc, uri)
      second <- complete(svc, uri)
      exchanges <- w.exchanges.get
    yield
      assert(first.isRight)
      assertEquals(second, Left(OAuthError.StateAlreadyUsed))
      assertEquals(exchanges.size, 1)
  }

  test("PKCE replay is StateAlreadyUsed and does not read the secret store again") {
    for
      w <- world
      svc = w.service(w.connector(pkce = true))
      uri <- startOk(svc)
      _ <- complete(svc, uri)
      before <- w.gets.get
      second <- complete(svc, uri)
      after <- w.gets.get
      exchanges <- w.exchanges.get
    yield
      assertEquals(second, Left(OAuthError.StateAlreadyUsed))
      assertEquals(after, before)
      assertEquals(exchanges.size, 1)
  }

  test("another browser session's callback is InvalidState, does not consume the state, and does not fail the reservation") {
    for
      w <- world
      svc = w.service(w.connector(pkce = false))
      uri <- startOk(svc)
      foreign <- complete(svc, uri, session = sessionB)
      exchangesAfterForeign <- w.exchanges.get
      failed <- w.failed.get
      own <- complete(svc, uri)
    yield
      assertEquals(foreign, Left(OAuthError.InvalidState))
      assertEquals(exchangesAfterForeign, Vector.empty)
      assertEquals(failed, Vector.empty)
      assert(own.isRight)
  }

  test("an expired state is ExpiredState and exchange is not called") {
    for
      w <- world
      svc = w.service(w.connector(pkce = false))
      uri <- startOk(svc)
      result <- complete(svc, uri, at = t0.plus(Duration.ofMinutes(11)))
      exchanges <- w.exchanges.get
    yield
      assertEquals(result, Left(OAuthError.ExpiredState))
      assertEquals(exchanges, Vector.empty)
  }

  test("a callback for a different provider is refused and its state stays usable by the right provider") {
    for
      w <- world
      other = w.connector(pkce = false, id = otherProvider)
      svc = w.service(w.connector(pkce = false), extra = Vector(other))
      uri <- startOk(svc)
      wrong <- complete(svc, uri, name = "other")
      unknown <- complete(svc, uri, name = "nobody")
      exchangesAfter <- w.exchanges.get
      right <- complete(svc, uri)
    yield
      assertEquals(wrong, Left(OAuthError.InvalidState))
      assertEquals(unknown, Left(OAuthError.ProviderRejected))
      assertEquals(exchangesAfter, Vector.empty)
      assert(right.isRight)
  }

  test("a callback to a different configured redirect is refused") {
    for
      w <- world
      uri <- startOk(w.service(w.connector(pkce = false)))
      other = w.connector(pkce = false, callback = URI.create("https://evil.example.test/callback/test"))
      result <- complete(w.service(other), uri)
      exchanges <- w.exchanges.get
    yield
      assertEquals(result, Left(OAuthError.InvalidState))
      assertEquals(exchanges, Vector.empty)
  }

  test("a forged state that was never issued is InvalidState") {
    for
      w <- world
      svc = w.service(w.connector(pkce = false))
      result <- gate.flatMap(g => svc.completeConnection("test", tenant, owner, sessionA, OAuthCallback(OAuthState.parse("z" * 43).get, "code"), g, t0))
      exchanges <- w.exchanges.get
    yield
      assertEquals(result, Left(OAuthError.InvalidState))
      assertEquals(exchanges, Vector.empty)
  }

  test("a flow with an unconfigured provider or with an unknown provider is ProviderRejected before any effect") {
    for
      w <- world
      noResources <- start(w.service(w.connector(pkce = false), withResources = false))
      unknown <- start(w.service(w.connector(pkce = false)), name = "nobody")
      conns <- w.conns.get
    yield
      assertEquals(noResources, Left(OAuthError.ProviderRejected))
      assertEquals(unknown, Left(OAuthError.ProviderRejected))
      assertEquals(conns, Map.empty)
  }

  // ---- failures after reservation --------------------------------------------------------------------------------

  private def assertFailedAndClean(w: World, id: ConnectionId): IO[Unit] =
    for
      failed <- w.failed.get
      texts <- storedText(w)
      status <- w.conns.get.map(_(id).status)
      attached <- w.attached.get
    yield
      assertEquals(failed, Vector(id))
      assertEquals(texts, Vector.empty, "no credential remains stored")
      assertEquals(status, ConnectionStatus.Error)
      assertEquals(attached, Vector.empty)

  for pkce <- Vector(false, true) do
    val label = if pkce then "PKCE" else "non-PKCE"

    test(s"$label: an exchange error fails the reservation and stores nothing") {
      for
        w <- world
        svc = w.service(w.connector(pkce = pkce))
        uri <- startOk(svc)
        id <- onlyConnection(w)
        _ <- w.exchangeResult.set(Left(OAuthError.InvalidProviderResponse))
        result <- complete(svc, uri)
        _ <- assertFailedAndClean(w, id)
      yield assertEquals(result, Left(OAuthError.InvalidProviderResponse))
    }

    test(s"$label: a refused secret put fails the reservation") {
      for
        w <- world
        svc = w.service(w.connector(pkce = pkce))
        uri <- startOk(svc)
        id <- onlyConnection(w)
        _ <- w.putsAllowed.set(0)
        result <- complete(svc, uri)
        _ <- assertFailedAndClean(w, id)
      yield assertEquals(result, Left(OAuthError.ProviderRejected))
    }

    test(s"$label: activateReserved returning Left deletes the credential and fails the reservation") {
      for
        w <- world
        svc = w.service(w.connector(pkce = pkce))
        uri <- startOk(svc)
        id <- onlyConnection(w)
        _ <- w.activate.set(Mode.Refuse)
        result <- complete(svc, uri)
        _ <- assertFailedAndClean(w, id)
      yield assertEquals(result, Left(OAuthError.ProviderRejected))
    }

    test(s"$label: activateReserved raising propagates infrastructure failure and cleans the reservation") {
      for
        w <- world
        svc = w.service(w.connector(pkce = pkce))
        uri <- startOk(svc)
        id <- onlyConnection(w)
        _ <- w.activate.set(Mode.Raise)
        result <- complete(svc, uri).attempt
        _ <- assertFailedAndClean(w, id)
      yield assert(result.left.exists(_.getMessage == "database unavailable"))
    }

    test(s"$label: a root creation failure deletes the credential and fails the reservation") {
      for
        w <- world
        svc = w.service(w.connector(pkce = pkce))
        uri <- startOk(svc)
        id <- onlyConnection(w)
        _ <- w.createRootFails.set(true)
        result <- complete(svc, uri)
        _ <- assertFailedAndClean(w, id)
      yield assertEquals(result, Left(OAuthError.ProviderRejected))
    }

    test(s"$label: an attachRoot failure deletes the credential and fails the reservation") {
      for
        w <- world
        svc = w.service(w.connector(pkce = pkce))
        uri <- startOk(svc)
        id <- onlyConnection(w)
        _ <- w.attachFails.set(true)
        result <- complete(svc, uri)
        _ <- assertFailedAndClean(w, id)
      yield assertEquals(result, Left(OAuthError.ProviderRejected))
    }

  // ---- start failures --------------------------------------------------------------------------------------------

  test("a refused reservation is ProviderRejected and binds no state") {
    for
      w <- world
      _ <- w.reserveFails.set(true)
      result <- start(w.service(w.connector(pkce = true)))
      states <- w.states.get
      puts <- w.puts.get
    yield
      assertEquals(result, Left(OAuthError.ProviderRejected))
      assertEquals(states, Map.empty)
      assertEquals(puts, Vector.empty)
  }

  test("non-PKCE: a state binding failure fails the reservation") {
    for
      w <- world
      _ <- w.bindFails.set(true)
      result <- start(w.service(w.connector(pkce = false)))
      failed <- w.failed.get
      conns <- w.conns.get
    yield
      assertEquals(result, Left(OAuthError.ProviderRejected))
      assertEquals(failed, conns.keys.toVector)
      assertEquals(conns.size, 1)
  }

  test("PKCE: a failed secret put fails the reservation and binds no state") {
    for
      w <- world
      _ <- w.putsAllowed.set(0)
      result <- start(w.service(w.connector(pkce = true)))
      failed <- w.failed.get
      states <- w.states.get
    yield
      assertEquals(result, Left(OAuthError.ProviderRejected))
      assertEquals(failed.size, 1)
      assertEquals(states, Map.empty)
  }

  test("a start failure after the PKCE verifier was stored fails the reservation and deletes the verifier") {
    for
      w <- world
      _ <- w.pkceBindFails.set(true)
      result <- start(w.service(w.connector(pkce = true)))
      failed <- w.failed.get
      conns <- w.conns.get
      puts <- w.puts.get
      texts <- storedText(w)
      deletes <- w.deletes.get
    yield
      assertEquals(result, Left(OAuthError.ProviderRejected))
      assertEquals(failed, conns.keys.toVector)
      assertEquals(puts.size, 1)
      assertEquals(texts.size, 0, "no verifier is left behind")
      assertEquals(deletes.size, 1)
  }

  // ---- connectionResources / replaceResources --------------------------------------------------------------------

  private def selectable(id: String): SelectableProviderResource =
    SelectableProviderResource(workspaceRoot, ext(id), "name", ext("root-1"))

  private def connected(w: World): IO[(OAuthConnectionService, ConnectionId)] =
    val svc = w.service(w.connector(pkce = false))
    for
      uri <- startOk(svc)
      id <- onlyConnection(w)
      done <- complete(svc, uri)
    yield
      assert(done.isRight)
      (svc, id)

  test("connectionResources lists current resources and the provider's selectable ones with the stored credential") {
    for
      w <- world
      connectedFlow <- connected(w)
      (svc, id) = connectedFlow
      _ <- w.available.set(Vector(selectable("r1"), selectable("r2")))
      listing <- svc.connectionResources(tenant, id)
      used <- w.listedWith.get
    yield
      assertEquals(listing.map(_.available.map(_.externalId.value)), Right(Vector("r1", "r2")))
      assertEquals(listing.map(_.current.map(_.kind)), Right(Vector("test.account")))
      assertEquals(used, Vector(tokenText))
  }

  test("connectionResources refuses an unknown connection, a missing root, and an inactive connection") {
    for
      w <- world
      connectedFlow <- connected(w)
      (svc, id) = connectedFlow
      unknown <- svc.connectionResources(tenant, ConnectionId.random())
      saved <- w.rootRows.get
      _ <- w.rootRows.set(Vector.empty)
      noRoot <- svc.connectionResources(tenant, id)
      _ <- w.rootRows.set(saved)
      _ <- w.conns.update(_.updatedWith(id)(_.map(_.copy(status = ConnectionStatus.Disabled))))
      inactive <- svc.connectionResources(tenant, id)
      used <- w.listedWith.get
    yield
      assertEquals(unknown.map(_ => ()), Left(OAuthError.InvalidState))
      assertEquals(noRoot.map(_ => ()), Left(OAuthError.InvalidState))
      assertEquals(inactive.map(_ => ()), Left(OAuthError.InvalidState))
      assertEquals(used, Vector.empty)
  }

  test("connectionResources is ProviderRejected when the secret cannot be read or no credential reference exists") {
    for
      w <- world
      connectedFlow <- connected(w)
      (svc, id) = connectedFlow
      refs <- w.secretRefs.get
      savedSecrets <- w.stored.get
      _ <- w.stored.set(Map.empty)
      unreadable <- svc.connectionResources(tenant, id)
      _ <- w.stored.set(savedSecrets)
      _ <- w.secretRefs.set(Map.empty)
      missing <- svc.connectionResources(tenant, id)
      used <- w.listedWith.get
    yield
      assertEquals(refs.keySet, Set(id))
      assertEquals(unreadable.map(_ => ()), Left(OAuthError.ProviderRejected))
      assertEquals(missing.map(_ => ()), Left(OAuthError.ProviderRejected))
      assertEquals(used, Vector.empty)
  }

  test("connectionResources without a resource repository is InvalidState") {
    for
      w <- world
      result <- w.service(w.connector(pkce = false), withResources = false).connectionResources(tenant, ConnectionId.random())
    yield assertEquals(result.map(_ => ()), Left(OAuthError.InvalidState))
  }

  test("replaceResources selects only the provider's available resources that were requested") {
    for
      w <- world
      connectedFlow <- connected(w)
      (svc, id) = connectedFlow
      _ <- w.available.set(Vector(selectable("r1"), selectable("r2"), selectable("r3")))
      result <- gate.flatMap(g => svc.replaceResources(tenant, owner, id, Vector("test.account|r3", "test.account|r1"), g))
      replaced <- w.replaced.get
    yield
      assert(result.isRight)
      assertEquals(replaced.map(_.map(_.externalId.value).toSet), Vector(Set("r1", "r3")))
  }

  test("replaceResources with an empty selection clears it, and a request outside the available set is InvalidPlacement") {
    for
      w <- world
      connectedFlow <- connected(w)
      (svc, id) = connectedFlow
      _ <- w.available.set(Vector(selectable("r1")))
      cleared <- gate.flatMap(g => svc.replaceResources(tenant, owner, id, Vector.empty, g))
      foreign <- gate.flatMap(g => svc.replaceResources(tenant, owner, id, Vector("test.account|r1", "test.account|nope"), g))
      wrongKind <- gate.flatMap(g => svc.replaceResources(tenant, owner, id, Vector("test.other|r1"), g))
      replaced <- w.replaced.get
    yield
      assert(cleared.isRight)
      assertEquals(foreign, Left(ConnectionResourceError.InvalidPlacement))
      assertEquals(wrongKind, Left(ConnectionResourceError.InvalidPlacement))
      assertEquals(replaced, Vector(Vector.empty))
  }

  test("replaceResources refuses duplicates, an unavailable connection, and an unconfigured provider") {
    for
      w <- world
      connectedFlow <- connected(w)
      (svc, id) = connectedFlow
      _ <- w.available.set(Vector(selectable("r1")))
      duplicate <- gate.flatMap(g => svc.replaceResources(tenant, owner, id, Vector("test.account|r1", "test.account|r1"), g))
      unknown <- gate.flatMap(g => svc.replaceResources(tenant, owner, ConnectionId.random(), Vector.empty, g))
      bare <- gate.flatMap(g => w.service(w.connector(pkce = false), withResources = false).replaceResources(tenant, owner, id, Vector.empty, g))
      replaced <- w.replaced.get
    yield
      assertEquals(duplicate, Left(ConnectionResourceError.AlreadySelected))
      assertEquals(unknown, Left(ConnectionResourceError.ConnectionUnavailable))
      assertEquals(bare, Left(ConnectionResourceError.ConnectionUnavailable))
      assertEquals(replaced, Vector.empty)
  }
