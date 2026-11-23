package run.hallpass.application

import java.time.{Duration, Instant}
import cats.effect.{IO, Ref}
import cats.effect.std.Semaphore
import cats.syntax.all.*
import scala.concurrent.duration.*
import munit.CatsEffectSuite
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

final class RefreshableOAuthSuite extends CatsEffectSuite:
  private sealed trait Account
  private val provider = ProviderId.parse("sample").getOrElse(fail("provider"))
  private val otherProvider = ProviderId.parse("other").getOrElse(fail("provider"))
  private given accountKind: ResourceKind[Account] = ResourceKind.root[Account]("sample.account", provider, ResourceType.Account, Custody.Workspace)
  private val otherKind = ResourceKind.root[Account]("other.account", otherProvider, ResourceType.Account, Custody.Workspace)
  private val now = Instant.parse("2026-09-30T12:00:00Z")
  private val tenant = TenantId.random()
  private val agentId = AgentId.random()
  private val resource = Resource(ResourceId.random(), tenant, ResourceType.Account, None, "acct", None)
  private val otherResource = Resource(ResourceId.random(), tenant, ResourceType.Account, None, "other", None)
  private val scope = ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope"))
  private val target = SelectedResource.trusted(accountKind, ExternalId.parse("acct").getOrElse(fail("external id")), scope)
  private val otherTarget = SelectedResource.trusted(accountKind, ExternalId.parse("other").getOrElse(fail("external id")), ResourceScope.fromPath(Vector(otherResource)).getOrElse(fail("other scope")))
  private val wrongProviderTarget = SelectedResource.trusted(otherKind, ExternalId.parse("acct").getOrElse(fail("external id")), scope)
  private val audience = ExecutorAudience.parse("test.oauth.executor").getOrElse(fail("audience"))
  private val capabilityKey = CapabilityKey.parse("Sample.Account.Read").getOrElse(fail("capability key"))
  private val refreshSecret = "refresh-secret-value"
  private val accessSecret = "access-secret-value"

  private def tokens(access: String, refresh: Option[String], expires: Instant): OAuthTokens =
    OAuthTokens.from(access, refresh, expires).getOrElse(fail("invalid token fixture"))

  test("token expiry is truncated to PostgreSQL precision and rendering redacts both tokens") {
    val expiry = Instant.parse("2026-09-30T12:00:00.123456789Z")
    val value = tokens("access-value-for-redaction", Some("refresh-value-for-redaction"), expiry)
    assertEquals(value.expiresAt, Instant.parse("2026-09-30T12:00:00.123456Z"))
    assert(!value.toString.contains("access-value-for-redaction"))
    assert(!value.toString.contains("refresh-value-for-redaction"))
  }

  private final class Codec extends OAuthTokenCodec:
    def encode(value: OAuthTokens): ProviderSecret =
      ProviderSecret.fromUtf8(s"${value.accessToken}|${value.refreshToken.getOrElse("")}|${value.expiresAt}")
    def decode(secret: ProviderSecret): Either[ConnectionError, OAuthTokens] =
      String(ProviderSecret.bytes(secret), java.nio.charset.StandardCharsets.UTF_8).split("\\|", -1).toList match
        case access :: refresh :: expiry :: Nil =>
          Either.catchNonFatal(Instant.parse(expiry)).toOption
            .flatMap(at => OAuthTokens.from(access, Option.when(refresh.nonEmpty)(refresh), at))
            .toRight(ConnectionError.InvalidState)
        case _ => Left(ConnectionError.InvalidState)

  private final class MemorySecrets(initial: (SecretReference, ProviderSecret)) extends SecretStore[IO]:
    private val values = Ref.unsafe[IO, Map[SecretReference, ProviderSecret]](Map(initial))
    val gets = Ref.unsafe[IO, Vector[SecretReference]](Vector.empty)
    val puts = Ref.unsafe[IO, Vector[(SecretReference, ProviderSecret)]](Vector.empty)
    val deletes = Ref.unsafe[IO, Vector[SecretReference]](Vector.empty)
    @volatile var failGet = false
    @volatile var failPut = false
    @volatile var failDelete = false
    def put(binding: SecretBinding, secret: ProviderSecret): IO[SecretReference] =
      if failPut then IO.raiseError(RuntimeException("put unavailable"))
      else IO(SecretReference.random()).flatMap: reference =>
        values.update(_.updated(reference, secret)) *> puts.update(_ :+ (reference -> secret)).as(reference)
    def get(binding: SecretBinding, reference: SecretReference): IO[Either[SecretStoreError, ProviderSecret]] =
      gets.update(_ :+ reference) *> (if failGet then IO.pure(Left(SecretStoreError.Unavailable)) else values.get.map(_.get(reference).toRight(SecretStoreError.NotFound)))
    def delete(binding: SecretBinding, reference: SecretReference): IO[Unit] =
      if failDelete then IO.raiseError(RuntimeException("delete unavailable"))
      else values.update(_ - reference) *> deletes.update(_ :+ reference)
    def contains(reference: SecretReference): IO[Boolean] = values.get.map(_.contains(reference))
    def secretAt(reference: SecretReference): IO[Option[ProviderSecret]] = values.get.map(_.get(reference))

  private final class FakeSlot(
      val binding: SecretBinding,
      val initialReference: SecretReference,
      val initialExpiry: Option[Instant],
      val marker: Ref[IO, Vector[Instant]],
      val publishResult: Ref[IO, Either[ConnectionError, Unit]],
      val pointer: Ref[IO, (SecretReference, Option[Instant])],
      val restored: Ref[IO, Vector[Instant]] = Ref.unsafe[IO, Vector[Instant]](Vector.empty)
  ) extends LockedOAuthCredential:
    def reference: SecretReference = initialReference
    def expiresAt: Option[Instant] = initialExpiry
    def requireReauthorization(at: Instant): IO[Either[ConnectionError, Unit]] = marker.update(_ :+ at).as(Right(()))
    def restore(at: Instant): IO[Either[ConnectionError, Unit]] = restored.update(_ :+ at).as(Right(()))
    def publish(reference: SecretReference, expiresAt: Instant, at: Instant): IO[Either[ConnectionError, Unit]] =
      publishResult.get.flatTap:
        case Right(_) => pointer.set((reference, Some(expiresAt)))
        case Left(_)  => IO.unit

  private final class FakeRepository(slot: FakeSlot, lock: Semaphore[IO]) extends OAuthRefreshRepository:
    val calls = Ref.unsafe[IO, Int](0)
    @volatile var reject: Option[ConnectionError] = None
    def withCredential[K](lease: RedeemedExecutionLease, target: SelectedResource[K], requestedProvider: ProviderId)(use: LockedOAuthCredential => IO[Either[ConnectionError, OAuthTokens]]) =
      calls.update(_ + 1) *> (reject match
        case Some(error) => IO.pure(Left(error))
        case None => lock.permit.use: _ =>
          slot.pointer.get.flatMap: (reference, expiry) =>
            use(new FakeSlot(slot.binding, reference, expiry, slot.marker, slot.publishResult, slot.pointer, slot.restored)))

  private final class FakeRefresher(result: Either[OAuthRefreshError, OAuthTokens]) extends OAuthTokenRefresher:
    val calls = Ref.unsafe[IO, Int](0)
    @volatile var effect: IO[Either[OAuthRefreshError, OAuthTokens]] = IO.pure(result)
    def refresh(current: OAuthTokens): IO[Either[OAuthRefreshError, OAuthTokens]] = calls.update(_ + 1) *> IO.defer(effect)

  private def redeemedLease: IO[RedeemedExecutionLease] =
    val requestId = AuthorizationRequestId.random()
    val request = AuthorizationRequest(
      requestId, tenant, IdentityChain.direct(Principal.Agent(agentId)), scope, capabilityKey,
      Action.Read, AuthorizationContext.empty
    )
    val policy = Policy(
      PolicyId.random(), PolicyVersion.from(1).getOrElse(fail("policy version")),
      NonEmptySet.one(PolicyStatement(Principal.Agent(agentId), resource.id, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow))
    )
    val capability = AuthorizationEngine.authorize(Policies(Vector(policy)), request, Vector.empty, now) match
      case AuthorizationResult.Authorized(value) => value
      case other => fail(s"authorization fixture failed: $other")
    val binding = InvocationBinding.compute(tenant, agentId, OperationId.parse("sample.read@1").getOrElse(fail("operation id")),
      capabilityKey, Action.Read, resource.id, accountKind, target.externalId, io.circe.Json.obj())
    val metadata = ExecutionAuditMetadata.authenticatedInvocation(
      AuthenticatedAgentContext.authenticated(tenant, agentId, AgentCredentialId.random(), now, UnverifiedExecutionClaims.empty),
      ExecutionAuditCorrelationId.parse("refresh-suite").getOrElse(fail("correlation")), ResourceId.random(),
      CatalogCapabilityId.parse("00000000-0000-4000-8000-000000000001").getOrElse(fail("catalog capability")), binding
    )
    for
      store <- InMemoryExecutionLeaseStore.create(Clock.fixed(now), Duration.ofSeconds(10), 100)
      audit <- InMemoryExecutionAuditRecorder.create
      issued <- InMemoryCredentialBroker(store, Clock.fixed(now), Duration.ofSeconds(60), audit)
        .issueLease(capability, requestId, audience, metadata)
      result <- store.redeem(issued.id, audience, now)
    yield result match
      case LeaseRedemption.Redeemed(value) => value
      case other => fail(s"lease redemption fixture failed: $other")

  private def fixture(
      current: OAuthTokens = tokens(accessSecret, Some(refreshSecret), now.plusSeconds(3600)),
      slotExpiry: Option[Instant] = Some(now.plusSeconds(3600)),
      publish: Either[ConnectionError, Unit] = Right(())
  ) =
    val reference = SecretReference.random()
    val binding = SecretBinding(tenant, ConnectionId.random())
    for
      secrets <- IO(new MemorySecrets(reference -> new Codec().encode(current)))
      marker <- Ref.of[IO, Vector[Instant]](Vector.empty)
      publishResult <- Ref.of[IO, Either[ConnectionError, Unit]](publish)
      pointer <- Ref.of[IO, (SecretReference, Option[Instant])]((reference, slotExpiry))
      slot = new FakeSlot(binding, reference, slotExpiry, marker, publishResult, pointer)
      lock <- Semaphore[IO](1)
      repository = new FakeRepository(slot, lock)
      refresher = new FakeRefresher(Right(tokens("new-access", Some("new-refresh"), now.plusSeconds(7200))))
    yield (secrets, slot, repository, refresher, marker, pointer, reference)

  test("fresh token is returned without refresh or reauthorization marker") {
    for
      lease <- redeemedLease
      f <- fixture()
      (secrets, _, repository, refresher, marker, _, reference) = f
      result <- new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, Clock.fixed(now), RefreshTokenRotation.Rotating).credentialFor(lease, target)
      gets <- secrets.gets.get
      marks <- marker.get
      calls <- refresher.calls.get
    yield
      assertEquals(result.map(_.accessToken), Right(accessSecret))
      assertEquals(gets, Vector(reference))
      assertEquals(calls, 0)
      assertEquals(marks, Vector.empty)
  }

  test("refresh stores and publishes rotated tokens before returning and deletes old version") {
    for
      lease <- redeemedLease
      f <- fixture(current = tokens(accessSecret, Some(refreshSecret), now.plusSeconds(10)), slotExpiry = Some(now.plusSeconds(10)))
      (secrets, _, repository, refresher, marker, pointer, oldReference) = f
      result <- new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, Clock.fixed(now), RefreshTokenRotation.Rotating).credentialFor(lease, target)
      puts <- secrets.puts.get
      deletes <- secrets.deletes.get
      current <- pointer.get
      marks <- marker.get
      refreshCalls <- refresher.calls.get
      stored <- secrets.secretAt(current._1)
      repositoryCalls <- repository.calls.get
    yield
      assertEquals(result.map(_.accessToken), Right("new-access"))
      assertEquals(refreshCalls, 1)
      assertEquals(marks, Vector(now))
      assertEquals(puts.size, 1)
      assertEquals(current._2, Some(now.plusSeconds(7200)))
      assertNotEquals(current._1, oldReference)
      assertEquals(deletes, Vector(oldReference))
      assertEquals(stored.map(new Codec().decode(_).map(_.refreshToken)), Some(Right(Some("new-refresh"))))
      assertEquals(repositoryCalls, 1)
  }

  test("near expiry without refresh token marks reauthorization and fails closed") {
    for
      lease <- redeemedLease
      f <- fixture(current = tokens(accessSecret, None, now.plusSeconds(10)), slotExpiry = Some(now.plusSeconds(10)))
      (secrets, _, repository, refresher, marker, _, _) = f
      result <- new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, Clock.fixed(now), RefreshTokenRotation.Rotating).credentialFor(lease, target)
      marks <- marker.get
      calls <- refresher.calls.get
    yield
      assertEquals(result, Left(ConnectionError.MissingCredential))
      assertEquals(marks, Vector(now))
      assertEquals(calls, 0)
  }

  test("stored token expiry must match the locked reference expiry") {
    for
      lease <- redeemedLease
      f <- fixture(slotExpiry = Some(now.plusSeconds(4000)))
      (secrets, _, repository, refresher, marker, _, _) = f
      result <- new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, Clock.fixed(now), RefreshTokenRotation.Rotating).credentialFor(lease, target)
      marks <- marker.get
      calls <- refresher.calls.get
    yield
      assertEquals(result, Left(ConnectionError.InvalidState))
      assertEquals(marks, Vector.empty)
      assertEquals(calls, 0)
  }

  test("a missing locked expiry fails closed") {
    for
      lease <- redeemedLease
      f <- fixture(slotExpiry = None)
      (secrets, _, repository, refresher, marker, _, _) = f
      result <- new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, Clock.fixed(now), RefreshTokenRotation.Rotating).credentialFor(lease, target)
      calls <- refresher.calls.get
      marks <- marker.get
    yield
      assertEquals(result, Left(ConnectionError.InvalidState))
      assertEquals(calls, 0)
      assertEquals(marks, Vector.empty)
  }

  test("refresh rejection and endpoint failure leave marker set and never publish") {
    List(Right(Left(OAuthRefreshError.Rejected)), Left(RuntimeException("endpoint unavailable"))).traverse_ { outcome =>
      for
        lease <- redeemedLease
        f <- fixture(current = tokens(accessSecret, Some(refreshSecret), now.plusSeconds(10)), slotExpiry = Some(now.plusSeconds(10)))
        (secrets, _, repository, refresher, marker, pointer, oldReference) = f
        _ = refresher.effect = outcome.fold(IO.raiseError, IO.pure)
        result <- new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, Clock.fixed(now), RefreshTokenRotation.Rotating).credentialFor(lease, target)
        marks <- marker.get
        current <- pointer.get
        puts <- secrets.puts.get
      yield
        assertEquals(result, Left(ConnectionError.MissingCredential))
        assertEquals(marks, Vector(now))
        assertEquals(current._1, oldReference)
        assertEquals(puts, Vector.empty)
    }
  }

  test("secret read or replacement write failure does not return provider credentials") {
    List(false, true).traverse_ { writeFailure =>
      for
        lease <- redeemedLease
        f <- fixture(current = tokens(accessSecret, Some(refreshSecret), now.plusSeconds(10)), slotExpiry = Some(now.plusSeconds(10)))
        (secrets, _, repository, refresher, marker, pointer, oldReference) = f
        _ = if writeFailure then secrets.failPut = true else secrets.failGet = true
        result <- new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, Clock.fixed(now), RefreshTokenRotation.Rotating).credentialFor(lease, target)
        marks <- marker.get
        current <- pointer.get
        refreshCalls <- refresher.calls.get
      yield
        assertEquals(result, Left(if writeFailure then ConnectionError.PersistenceFailure else ConnectionError.MissingCredential))
        assertEquals(current._1, oldReference)
        assertEquals(refreshCalls, if writeFailure then 1 else 0)
        assertEquals(marks, if writeFailure then Vector(now) else Vector.empty)
    }
  }

  test("publish failure preserves old pointer and does not delete potentially referenced secret") {
    for
      lease <- redeemedLease
      f <- fixture(current = tokens(accessSecret, Some(refreshSecret), now.plusSeconds(10)), slotExpiry = Some(now.plusSeconds(10)), publish = Left(ConnectionError.PersistenceFailure))
      (secrets, _, repository, refresher, _, pointer, oldReference) = f
      result <- new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, Clock.fixed(now), RefreshTokenRotation.Rotating).credentialFor(lease, target)
      current <- pointer.get
      puts <- secrets.puts.get
      deletes <- secrets.deletes.get
      replacementExists <- secrets.contains(puts.head._1)
    yield
      assertEquals(result, Left(ConnectionError.PersistenceFailure))
      assertEquals(current._1, oldReference)
      assertEquals(deletes, Vector.empty)
      assert(replacementExists)
  }

  test("old-version cleanup failure does not discard successfully published token") {
    for
      lease <- redeemedLease
      f <- fixture(current = tokens(accessSecret, Some(refreshSecret), now.plusSeconds(10)), slotExpiry = Some(now.plusSeconds(10)))
      (secrets, _, repository, refresher, _, pointer, _) = f
      _ = secrets.failDelete = true
      result <- new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, Clock.fixed(now), RefreshTokenRotation.Rotating).credentialFor(lease, target)
      current <- pointer.get
    yield
      assertEquals(result.map(_.accessToken), Right("new-access"))
      assertEquals(current._2, Some(now.plusSeconds(7200)))
  }

  test("concurrent expired requests serialize and only one refresh publishes") {
    for
      lease <- redeemedLease
      f <- fixture(current = tokens(accessSecret, Some(refreshSecret), now.plusSeconds(10)), slotExpiry = Some(now.plusSeconds(10)))
      (secrets, _, repository, refresher, _, _, _) = f
      strategy = new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, Clock.fixed(now), RefreshTokenRotation.Rotating)
      results <- List.fill(2)(strategy.credentialFor(lease, target)).parSequence
      refreshCalls <- refresher.calls.get
      puts <- secrets.puts.get
    yield
      assertEquals(results.map(_.map(_.accessToken)), List(Right("new-access"), Right("new-access")))
      assertEquals(refreshCalls, 1)
      assertEquals(puts.size, 1)
  }

  test("wrong target or provider fails before repository access") {
    for
      lease <- redeemedLease
      f <- fixture()
      (secrets, _, repository, refresher, _, _, _) = f
      strategy = new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, Clock.fixed(now), RefreshTokenRotation.Rotating)
      wrongResource <- strategy.credentialFor(lease, otherTarget)
      wrongKind <- strategy.credentialFor(lease, wrongProviderTarget)
      calls <- repository.calls.get
    yield
      assertEquals(wrongResource, Left(ConnectionError.InvalidState))
      assertEquals(wrongKind, Left(ConnectionError.InvalidState))
      assertEquals(calls, 0)
  }

  // ---- failure classification, rotation policy, and cancellation ------------------------------------------------------

  private def expiring = fixture(current = tokens(accessSecret, Some(refreshSecret), now.plusSeconds(10)), slotExpiry = Some(now.plusSeconds(10)))

  private def refreshWith(
      error: OAuthRefreshError,
      rotation: RefreshTokenRotation
  ): IO[(Either[ConnectionError, OAuthTokens], Vector[Instant], Vector[Instant])] =
    for
      lease <- redeemedLease
      f <- expiring
      (secrets, slot, repository, refresher, marker, _, _) = f
      _ <- IO(refresher.effect = IO.pure(Left(error)))
      result <- new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, Clock.fixed(now), rotation)
        .credentialFor(lease, target)
      marks <- marker.get
      restores <- slot.restored.get
    yield (result, marks, restores)

  test("a refresh request that was never sent clears the marker, even for a rotating provider") {
    refreshWith(OAuthRefreshError.NotSent, RefreshTokenRotation.Rotating).map: (result, marks, restores) =>
      assertEquals(result, Left(ConnectionError.MissingCredential))
      assertEquals(marks, Vector(now))
      assertEquals(restores, Vector(now))
  }

  test("an unanswered request to a rotating provider leaves reauthorization required") {
    refreshWith(OAuthRefreshError.Unavailable, RefreshTokenRotation.Rotating).map: (result, _, restores) =>
      assertEquals(result, Left(ConnectionError.MissingCredential))
      assertEquals(restores, Vector.empty)
  }

  test("a non-rotating provider keeps its refresh token through an unanswered request, but not through a rejection") {
    for
      unavailable <- refreshWith(OAuthRefreshError.Unavailable, RefreshTokenRotation.NonRotating)
      invalid <- refreshWith(OAuthRefreshError.InvalidResponse, RefreshTokenRotation.NonRotating)
      rejected <- refreshWith(OAuthRefreshError.Rejected, RefreshTokenRotation.NonRotating)
    yield
      assertEquals(unavailable._3, Vector(now))
      assertEquals(invalid._3, Vector(now))
      assertEquals(rejected._3, Vector.empty)
      assertEquals(rejected._1, Left(ConnectionError.MissingCredential))
  }

  test("cancellation during the exchange still stores and publishes the rotated token") {
    for
      lease <- redeemedLease
      f <- expiring
      (secrets, _, repository, refresher, _, pointer, oldReference) = f
      arrived <- cats.effect.Deferred[IO, Unit]
      release <- cats.effect.Deferred[IO, Unit]
      rotated = tokens("new-access", Some("new-refresh"), now.plusSeconds(7200))
      _ <- IO(refresher.effect = arrived.complete(()) *> release.get.as(Right(rotated)))
      fiber <- new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, Clock.fixed(now), RefreshTokenRotation.Rotating)
        .credentialFor(lease, target).start
      _ <- arrived.get
      cancelled <- (fiber.cancel).start
      _ <- release.complete(())
      _ <- cancelled.join
      current <- pointer.get
    yield
      assertNotEquals(current._1, oldReference, "the rotated token was published despite cancellation")
      assertEquals(current._2, Some(now.plusSeconds(7200)))
  }
