package run.hallpass.gateway

import java.net.{InetAddress, URI}
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.Base64
import scala.concurrent.duration.*
import com.sun.net.httpserver.Headers
import cats.effect.{IO, Ref}
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.application.*
import run.hallpass.kernel.*

/** The recent-rejection table in front of agent authentication. The incident: a stale bridge presenting one revoked
  * bearer about once a second drained the address's failure budget, so its owner's valid calls from the same address
  * got 429. */
final class RecentAgentRejectionsProtectionSuite extends CatsEffectSuite:
  private val tenant = TenantId.random()
  private val now = Instant.parse("2026-09-28T12:00:00Z")
  private val client = InetAddress.getByName("203.0.113.50")
  private val proxy = InetAddress.getByName("10.0.0.6")
  private val goodSecret = secret(4)

  private def secret(seed: Int): String = Base64.getUrlEncoder.withoutPadding.encodeToString(Array.fill[Byte](32)(seed.toByte))
  private def selectorOf(value: String): AgentCredentialSelector = AgentCredentialSelector.parse(value).getOrElse(fail("selector"))
  private def bearer(selector: String, secretValue: String = goodSecret): String = s"ac1.$selector.$secretValue"

  private val validSelector = "validselector0001"
  private val revokedSelector = "revokedselector01"
  private val unroutedSelector = "unroutedselector1"
  private val lockedSelector = "lockedselector001"
  private val targetSelector = "targetselector001"
  private val unknownSelector = "unknownselector01"

  private final case class Recorded(reason: AgentRejectionReason, selector: Option[AgentCredentialSelector])

  /** Records counters as "metric:attribute" strings. */
  private final class RecordingTelemetry(val counters: Ref[IO, Vector[String]]) extends Telemetry:
    def span[A](span: TraceSpan, attributes: SafeAttribute*)(body: IO[A]): IO[A] = body
    def finished(span: TraceSpan, startedAt: FiniteDuration, failed: Boolean, attributes: SafeAttribute*): IO[Unit] = IO.unit
    def increment(metric: CounterMetric, attributes: SafeAttribute*): IO[Unit] =
      counters.update(_ :+ s"${metric.name}:${attributes.mkString(",")}")
    def record(metric: HistogramMetric, seconds: Double, attributes: SafeAttribute*): IO[Unit] = IO.unit

  private final class Fixture(
      val routeCalls: Ref[IO, Int],
      val lookups: Ref[IO, Int],
      val verifications: Ref[IO, Int],
      val lockChecks: Ref[IO, Int],
      val audit: Ref[IO, Vector[Recorded]],
      val locked: Ref[IO, Set[String]],
      val lockoutOutage: Ref[IO, Boolean],
      val lookupOutage: Ref[IO, Boolean],
      val lookupErrors: Ref[IO, Map[String, AgentCredentialLookupError]],
      val counters: Ref[IO, Vector[String]],
      val limiter: FailedAuthenticationLimiter,
      val recent: RecentAgentRejections
  ):
    private val lockout = new AgentAuthenticationLockout:
      def isLocked(requested: AgentCredentialSelector) =
        lockChecks.update(_ + 1) *> lockoutOutage.get.flatMap: outage =>
          if outage then IO.pure(Left(DirectoryError.Unavailable))
          else locked.get.map(set => Right(set.contains(requested.value)))
      def recordRejection(requested: Option[AgentCredentialSelector], reason: AgentRejectionReason, address: Option[InetAddress]) =
        audit.update(_ :+ Recorded(reason, requested)).as(Right(()))

    private val routes = new AgentCredentialRoutes[IO]:
      def candidateTenant(requested: AgentCredentialSelector) =
        routeCalls.update(_ + 1).as(Right(Option.when(requested.value != unroutedSelector)(tenant)))

    private val repository = new AgentCredentialAuthenticationRepository[IO]:
      def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) =
        lookups.update(_ + 1) *> (lookupOutage.get, lookupErrors.get).flatMapN: (outage, errors) =>
          IO.pure:
            if outage then Left(AgentCredentialLookupError.Unavailable)
            else
              errors.get(s.value) match
                case Some(error) => Left(error)
                case None =>
                  Right(new StoredAgentCredential(
                    tenant, AgentCredentialId.random(), AgentId.random(), s,
                    StoredAgentCredentialVerifier.fromBytes(Array.fill[Byte](32)(4)).getOrElse(fail("verifier")),
                    CredentialVerifierMetadata(CredentialVerifierAlgorithm.HmacSha256, "test-key"), now, None, None, None
                  ))
      def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))

    /** A bearer verifies only when it carries the one good secret. */
    private val verifier = new AgentCredentialVerifier[IO]:
      def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) =
        verifications.update(_ + 1).as(String(PresentedAgentCredential.canonicalBytes(p), StandardCharsets.US_ASCII).endsWith(goodSecret))

    val api: AgentApi =
      val authenticator = new AgentAuthenticator[IO](routes, repository, verifier)
      AgentApi(
        AgentApiDependencies(
          AgentCredentialServices(authenticator, null.asInstanceOf[AgentEnrollmentService[IO]]),
          None,
          AgentAuthenticationProtection(Some(limiter), lockout, trustedProxies = 1, Some(recent))
        ),
        telemetry = new RecordingTelemetry(counters)
      )

    def identity(authorization: Option[String]): IO[DemoApiResponse] =
      val headers = new Headers()
      authorization.foreach(headers.add("Authorization", _))
      headers.add("X-Forwarded-For", s"198.51.100.1, ${client.getHostAddress}")
      api.handle("GET", AgentApi.IdentityPath, headers, URI.create("http://agents.example.test" + AgentApi.IdentityPath), Array.emptyByteArray, Some(proxy))

    def present(selector: String, secretValue: String = goodSecret): IO[DemoApiResponse] =
      identity(Some(s"Bearer ${bearer(selector, secretValue)}"))

    /** Everything a request can cost besides the response: route, lookup, verification, lockout, and audit work. */
    def work: IO[(Int, Int, Int, Int, Int)] =
      (routeCalls.get, lookups.get, verifications.get, lockChecks.get, audit.get.map(_.size)).tupled

  private def fixture(
      capacity: Int = 20,
      time: IO[FiniteDuration] = IO.pure(Duration.Zero),
      maximumEntries: Int = RecentAgentRejections.DefaultMaximumEntries
  ): IO[Fixture] =
    (
      Ref.of[IO, Int](0),
      Ref.of[IO, Int](0),
      Ref.of[IO, Int](0),
      Ref.of[IO, Int](0),
      Ref.of[IO, Vector[Recorded]](Vector.empty),
      Ref.of[IO, Set[String]](Set.empty),
      Ref.of[IO, Boolean](false),
      Ref.of[IO, Boolean](false),
      Ref.of[IO, Map[String, AgentCredentialLookupError]](Map(revokedSelector -> AgentCredentialLookupError.Revoked, unknownSelector -> AgentCredentialLookupError.Unknown)),
      Ref.of[IO, Vector[String]](Vector.empty),
      FailedAuthenticationLimiter.create(capacity = capacity, refillEvery = 1.hour),
      RecentAgentRejections.create(now = time, maximumEntries = maximumEntries)
    ).mapN(Fixture(_, _, _, _, _, _, _, _, _, _, _, _))

  test("incident: a revoked bearer presented 60 times does not exhaust the address budget, and a valid bearer still works") {
    for
      f <- fixture()
      responses <- f.present(revokedSelector).replicateA(60)
      lookups <- f.lookups.get
      valid <- f.present(validSelector)
    yield
      assert(responses.forall(_.status == 401), "every repeat is a 401, never a 429")
      assertEquals(lookups, 1, "only the first presentation reaches the credential store")
      assertEquals(valid.status, 200, "the owner's valid call from the same address is not throttled")
  }

  test("incident: an unrouted bearer presented 60 times does not exhaust the address budget either") {
    for
      f <- fixture()
      responses <- f.present(unroutedSelector).replicateA(60)
      routes <- f.routeCalls.get
      valid <- f.present(validSelector)
    yield
      assert(responses.forall(_.status == 401))
      assertEquals(routes, 1)
      assertEquals(valid.status, 200)
  }

  test("without the table the same 60 presentations exhaust the budget and a valid bearer is refused (the incident)") {
    val repository = new AgentCredentialAuthenticationRepository[IO]:
      def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) =
        IO.pure(Left(AgentCredentialLookupError.Revoked))
      def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
    val verifier = new AgentCredentialVerifier[IO]:
      def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) =
        IO.pure(true)
    for
      limiter <- FailedAuthenticationLimiter.create(refillEvery = 1.hour)
      api = AgentApi(
        AgentApiDependencies(
          AgentCredentialServices(
            new AgentAuthenticator[IO](_ => IO.pure(Right(Some(tenant))), repository, verifier),
            null.asInstanceOf[AgentEnrollmentService[IO]]
          ),
          None,
          AgentAuthenticationProtection(Some(limiter), AgentAuthenticationLockout.disabled, trustedProxies = 1)
        )
      )
      call = (selector: String) =>
        val headers = new Headers()
        headers.add("Authorization", s"Bearer ${bearer(selector)}")
        headers.add("X-Forwarded-For", client.getHostAddress)
        api.handle("GET", AgentApi.IdentityPath, headers, URI.create("http://agents.example.test" + AgentApi.IdentityPath), Array.emptyByteArray, Some(proxy))
      responses <- call(revokedSelector).replicateA(60)
      next <- call(validSelector)
    yield
      assertEquals(responses.count(_.status == 401), 20)
      assertEquals(responses.count(_.status == 429), 40)
      assertEquals(next.status, 429, "the shared address is throttled for everyone behind it, valid credential or not")
  }

  test("a repeat costs no limiter admission, lockout lookup, verification, database work, or audit write, and is counted") {
    for
      f <- fixture(capacity = 2)
      first <- f.present(revokedSelector)
      before <- f.work
      auditBefore <- f.audit.get
      repeats <- f.present(revokedSelector).replicateA(5)
      after <- f.work
      auditAfter <- f.audit.get
      counters <- f.counters.get
      neighbour <- f.present(validSelector)
    yield
      assertEquals(first.status, 401)
      assertEquals(auditBefore.map(_.reason), Vector(AgentRejectionReason.RevokedCredential))
      assertEquals(after, before, "route, lookup, verification, lockout, and audit counters do not move")
      assertEquals(auditAfter, auditBefore)
      assert(repeats.forall(_.status == 401))
      assertEquals(
        counters.count(_ == "hallpass.agent.authentication.failures:hallpass.reason=repeat_rejection"),
        5
      )
      assertEquals(neighbour.status, 200, "a budget of two was spent once, by the first rejection only, so one token remains for the neighbour")
  }

  test("a cached repeat is byte-identical to any other rejection's 401") {
    for
      f <- fixture()
      fresh <- f.present(revokedSelector)
      repeated <- f.present(revokedSelector)
      unknown <- f.present(unknownSelector)
      malformed <- f.identity(Some("Bearer nonsense"))
    yield
      assertEquals(fresh.status, 401)
      assertEquals(repeated, fresh)
      assertEquals(repeated.body.noSpaces, AgentApi.unauthorized.body.noSpaces)
      assertEquals(repeated.headers, AgentApi.unauthorized.headers)
      assertEquals(repeated, unknown)
      assertEquals(repeated, malformed)
  }

  test("varying secrets for a real selector are not cached: they are throttled and reach the lockout path") {
    for
      f <- fixture(capacity = 5)
      wrong <- (10 to 24).toList.traverse(seed => f.present(validSelector, secret(seed)))
      audit <- f.audit.get
      lockChecks <- f.lockChecks.get
      verifications <- f.verifications.get
    yield
      assertEquals(wrong.count(_.status == 401), 5, "each distinct guess spent a token")
      assertEquals(wrong.count(_.status == 429), 10)
      assertEquals(audit.map(_.reason), Vector.fill(5)(AgentRejectionReason.WrongSecret))
      assertEquals(lockChecks, 5, "every admitted guess consulted the durable lockout")
      assertEquals(verifications, 5)
  }

  test("a wrong secret is remembered only for that exact bearer, so the real secret still authenticates") {
    for
      f <- fixture()
      wrong <- f.present(targetSelector, secret(9))
      wrongAgain <- f.present(targetSelector, secret(9))
      other <- f.present(targetSelector, secret(10))
      real <- f.present(targetSelector)
      audit <- f.audit.get
    yield
      assertEquals((wrong.status, wrongAgain.status, other.status), (401, 401, 401))
      assertEquals(real.status, 200, "the table never turns a valid bearer into a rejection")
      assertEquals(audit.map(_.reason), Vector(AgentRejectionReason.WrongSecret, AgentRejectionReason.WrongSecret))
  }

  test("a locked selector is not cached: once unlocked, its valid bearer authenticates") {
    for
      f <- fixture()
      _ <- f.locked.set(Set(lockedSelector))
      locked <- f.present(lockedSelector).replicateA(3)
      lockChecksWhileLocked <- f.lockChecks.get
      _ <- f.locked.set(Set.empty)
      unlocked <- f.present(lockedSelector)
      audit <- f.audit.get
    yield
      assert(locked.forall(_.status == 401))
      assertEquals(lockChecksWhileLocked, 3, "each repeat while locked still asks the lockout store")
      assertEquals(unlocked.status, 200, "lockout is temporary, so it must not outlive itself through the table")
      assertEquals(audit.map(_.reason), Vector.fill(3)(AgentRejectionReason.Locked))
  }

  test("an unavailable lockout store is not cached") {
    for
      f <- fixture()
      _ <- f.lockoutOutage.set(true)
      outage <- f.present(validSelector).replicateA(3)
      _ <- f.lockoutOutage.set(false)
      recovered <- f.present(validSelector)
      counters <- f.counters.get
    yield
      assert(outage.forall(_.status == 503))
      assertEquals(recovered.status, 200)
      assert(!counters.exists(_.contains("repeat_rejection")))
  }

  test("an unavailable credential store is not cached") {
    for
      f <- fixture()
      _ <- f.lookupOutage.set(true)
      outage <- f.present(validSelector).replicateA(3)
      _ <- f.lookupOutage.set(false)
      recovered <- f.present(validSelector)
    yield
      assert(outage.forall(_.status == 503))
      assertEquals(recovered.status, 200)
  }

  test("a stored credential that is invalid is not cached, so an operator repair takes effect at once") {
    for
      f <- fixture()
      _ <- f.lookupErrors.set(Map(validSelector -> AgentCredentialLookupError.InvalidStoredCredential))
      broken <- f.present(validSelector).replicateA(3)
      lookupsBroken <- f.lookups.get
      _ <- f.lookupErrors.set(Map.empty)
      repaired <- f.present(validSelector)
    yield
      assert(broken.forall(_.status == 401))
      assertEquals(lookupsBroken, 3, "every repeat re-read the store")
      assertEquals(repaired.status, 200)
  }

  test("a success is never cached, and a rejected bearer that is rotated gets a fresh, unaffected bearer") {
    for
      f <- fixture()
      ok <- f.present(validSelector).replicateA(3)
      lookups <- f.lookups.get
      _ <- f.present(revokedSelector)
      rotated <- f.present("rotatedselector01")
    yield
      assert(ok.forall(_.status == 200))
      assertEquals(lookups, 3, "each authenticated request still verifies against the store")
      assertEquals(rotated.status, 200)
  }

  test("missing and malformed credentials keep consuming budget and are never cached") {
    for
      f <- fixture(capacity = 3)
      missing <- f.identity(None)
      malformed <- f.identity(Some("Bearer nonsense"))
      third <- f.identity(Some("Bearer nonsense"))
      throttled <- f.identity(Some("Bearer nonsense"))
    yield assertEquals((missing.status, malformed.status, third.status, throttled.status), (401, 401, 401, 429))
  }

  test("a repeat is forgotten after the TTL and consumes budget again") {
    for
      clock <- Ref.of[IO, FiniteDuration](Duration.Zero)
      f <- fixture(time = clock.get)
      _ <- f.present(revokedSelector)
      _ <- clock.set(9.minutes)
      _ <- f.present(revokedSelector)
      lookupsWhileFresh <- f.lookups.get
      _ <- clock.set(19.minutes + 1.second)
      _ <- f.present(revokedSelector)
      lookupsAfterSilence <- f.lookups.get
    yield
      assertEquals(lookupsWhileFresh, 1)
      assertEquals(lookupsAfterSilence, 2)
  }

  test("when the table is full of live entries, a new rejection is not remembered and keeps spending budget") {
    for
      f <- fixture(capacity = 3, maximumEntries = 1)
      _ <- f.present(revokedSelector)
      _ <- f.present(unknownSelector)
      _ <- f.present(unknownSelector)
      lookups <- f.lookups.get
      last <- f.present(unknownSelector)
    yield
      assertEquals(lookups, 3, "the refused entry re-reads the store each time")
      assertEquals(last.status, 429, "and drains the address budget: three tokens were spent by three rejections")
  }
