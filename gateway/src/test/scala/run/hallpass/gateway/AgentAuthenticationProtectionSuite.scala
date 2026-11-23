package run.hallpass.gateway

import java.net.{InetAddress, URI}
import java.time.Instant
import java.util.Base64
import scala.concurrent.duration.*
import com.sun.net.httpserver.Headers
import cats.effect.{Deferred, IO, Ref}
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.application.*
import run.hallpass.kernel.*

final class AgentAuthenticationProtectionSuite extends CatsEffectSuite:
  private val tenant = TenantId.random()
  private val now = Instant.parse("2026-09-28T12:00:00Z")
  private val selector = AgentCredentialSelector.parse("protectionselect").getOrElse(fail("selector"))
  private val bearer = s"ac1.${selector.value}.${Base64.getUrlEncoder.withoutPadding.encodeToString(Array.fill[Byte](32)(4))}"
  private val client = InetAddress.getByName("203.0.113.40")
  private val proxy = InetAddress.getByName("10.0.0.5")

  private final case class Recorded(selector: Option[AgentCredentialSelector], reason: AgentRejectionReason, client: Option[InetAddress])

  private final class Fixture(
      val lookups: Ref[IO, Int],
      val audit: Ref[IO, Vector[Recorded]],
      val locked: Ref[IO, Either[DirectoryError, Boolean]],
      val secretMatches: Ref[IO, Boolean],
      val limiter: FailedAuthenticationLimiter,
      val lookupBarrier: Ref[IO, Option[Deferred[IO, Unit]]],
      val twoLookups: Deferred[IO, Unit]
  ):
    private val lockout = new AgentAuthenticationLockout:
      def isLocked(requested: AgentCredentialSelector) = locked.get
      def recordRejection(requested: Option[AgentCredentialSelector], reason: AgentRejectionReason, address: Option[InetAddress]) =
        audit.update(_ :+ Recorded(requested, reason, address)).as(Right(()))
    private val stored = new StoredAgentCredential(
      tenant, AgentCredentialId.random(), AgentId.random(), selector,
      StoredAgentCredentialVerifier.fromBytes(Array.fill[Byte](32)(4)).getOrElse(fail("verifier")),
      CredentialVerifierMetadata(CredentialVerifierAlgorithm.HmacSha256, "test-key"), now, None, None, None
    )
    private val repository = new AgentCredentialAuthenticationRepository[IO]:
      def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) =
        lookups.updateAndGet(_ + 1).flatMap(count => twoLookups.complete(()).void.whenA(count == 2)) *>
          lookupBarrier.get.flatMap(_.traverse_(_.get)).as(Right(stored))
      def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
    private val verifier = new AgentCredentialVerifier[IO]:
      def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) = secretMatches.get
    val api: AgentApi =
      val authenticator = new AgentAuthenticator[IO](_ => IO.pure(Right(Some(tenant))), repository, verifier)
      AgentApi(AgentApiDependencies(
        AgentCredentialServices(authenticator, null.asInstanceOf[AgentEnrollmentService[IO]]),
        None,
        AgentAuthenticationProtection(Some(limiter), lockout, trustedProxies = 1)
      ))

    def identity(authorization: Option[String] = Some(s"Bearer $bearer")): IO[DemoApiResponse] =
      val headers = new Headers()
      authorization.foreach(headers.add("Authorization", _))
      headers.add("X-Forwarded-For", s"198.51.100.1, ${client.getHostAddress}")
      api.handle("GET", AgentApi.IdentityPath, headers, URI.create("http://agents.example.test" + AgentApi.IdentityPath), Array.emptyByteArray, Some(proxy))

  private def fixture(capacity: Int = 20): IO[Fixture] =
    (
      Ref.of[IO, Int](0),
      Ref.of[IO, Vector[Recorded]](Vector.empty),
      Ref.of[IO, Either[DirectoryError, Boolean]](Right(false)),
      Ref.of[IO, Boolean](true),
      FailedAuthenticationLimiter.create(capacity = capacity, refillEvery = 1.hour),
      Ref.of[IO, Option[Deferred[IO, Unit]]](None),
      Deferred[IO, Unit]
    ).mapN(Fixture(_, _, _, _, _, _, _))

  test("a wrong secret is rejected, counted against the forwarded client, and audited without the credential") {
    for
      f <- fixture()
      _ <- f.secretMatches.set(false)
      response <- f.identity()
      audit <- f.audit.get
    yield
      assertEquals(response.status, 401)
      assertEquals(audit, Vector(Recorded(Some(selector), AgentRejectionReason.WrongSecret, Some(client))))
      assert(!audit.toString.contains(bearer.split('.').last), "the audit never receives the secret")
  }

  test("a client out of failure budget gets 429 before any lookup or verification") {
    for
      f <- fixture(capacity = 2)
      _ <- f.secretMatches.set(false)
      _ <- f.identity().replicateA_(2)
      lookupsBefore <- f.lookups.get
      _ <- f.secretMatches.set(true)
      throttled <- f.identity()
      lookupsAfter <- f.lookups.get
    yield
      assertEquals(throttled.status, 429)
      assert(throttled.headers.get("Retry-After").exists(_.toLongOption.exists(_ > 0)))
      assertEquals(lookupsAfter, lookupsBefore, "throttled requests do no credential work, even with a valid secret")
  }

  test("a locked selector is refused like any other rejection, without verification, and audited as locked") {
    for
      f <- fixture()
      _ <- f.locked.set(Right(true))
      response <- f.identity()
      lookups <- f.lookups.get
      audit <- f.audit.get
    yield
      assertEquals(response.status, 401, "a lockout must not reveal that the selector exists")
      assertEquals(response.body, AgentApi.unauthorized.body)
      assertEquals(lookups, 0)
      assertEquals(audit.map(_.reason), Vector(AgentRejectionReason.Locked))
  }

  test("40 simultaneous failures admit only the burst budget before lookup and verification") {
    for
      f <- fixture(capacity = 2)
      release <- Deferred[IO, Unit]
      rejected <- Deferred[IO, Unit]
      throttled <- Ref.of[IO, Int](0)
      _ <- f.lookupBarrier.set(Some(release))
      _ <- f.secretMatches.set(false)
      requests <- (1 to 40).toList.parTraverse(_ => f.identity().flatTap(response =>
        if response.status == 429 then
          throttled.updateAndGet(_ + 1).flatMap(count => rejected.complete(()).void.whenA(count == 38))
        else IO.unit
      )).start
      _ <- (f.twoLookups.get, rejected.get).parTupled.timeout(3.seconds)
      lookupsBeforeRelease <- f.lookups.get
      _ <- release.complete(())
      responses <- requests.joinWithNever
      afterBurst <- f.identity()
      audit <- f.audit.get
    yield
      assertEquals(lookupsBeforeRelease, 2, "only two attempts may enter credential lookup while they are pending")
      assertEquals(responses.count(_.status == 401), 2)
      assertEquals(responses.count(_.status == 429), 38)
      assertEquals(afterBurst.status, 429)
      assertEquals(audit.size, 2, "throttled traffic does no rejection-audit work")
  }

  test("successful authentication refunds the budget before dispatching the authenticated request") {
    for
      f <- fixture(capacity = 1)
      successes <- f.identity().replicateA(10)
      _ <- f.secretMatches.set(false)
      failure <- f.identity()
      throttled <- f.identity()
    yield
      assert(successes.forall(_.status == 200))
      assertEquals(failure.status, 401)
      assertEquals(throttled.status, 429)
  }

  test("an unavailable lockout store fails closed, and a valid credential still works when it is healthy") {
    for
      f <- fixture(capacity = 1)
      _ <- f.locked.set(Left(DirectoryError.Unavailable))
      outage <- f.identity()
      repeatedOutage <- f.identity()
      _ <- f.locked.set(Right(false))
      healthy <- f.identity()
    yield
      assertEquals(outage.status, 503)
      assertEquals(repeatedOutage.status, 503, "infrastructure failures refund their reservation")
      assertEquals(healthy.status, 200)
  }

  test("transport-level rejections count against the client too") {
    for
      f <- fixture(capacity = 1)
      missing <- f.identity(authorization = None)
      next <- f.identity()
    yield
      assertEquals(missing.status, 401)
      assertEquals(next.status, 429)
  }
