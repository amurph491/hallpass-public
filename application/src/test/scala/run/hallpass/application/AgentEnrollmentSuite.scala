package run.hallpass.application

import java.time.Instant
import cats.effect.IO
import cats.effect.kernel.Ref
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.kernel.*

final class AgentEnrollmentSuite extends CatsEffectSuite:
  private val tenant = TenantId.random()
  private val administrator: Principal.Human = Principal.Human(UserId.random())
  private val actor = AuthenticatedHuman.authenticated(
    TenantMembership(DirectoryUserId.random(), tenant, administrator, MembershipRole.Admin),
    Instant.parse("2026-09-20T10:15:30Z")
  )
  private val agentId = AgentId.random()
  private val selector = AgentCredentialSelector.parse("safe-selector-value1").toOption.get
  private val plaintext = PresentedAgentCredential.parse(s"ac1.${selector.value}.${"A" * 43}").toOption.get
  private val verifier = StoredAgentCredentialVerifier.fromBytes(Array.fill(32)(2.toByte)).toOption.get
  private val verification = CredentialVerifierMetadata(CredentialVerifierAlgorithm.HmacSha256, "local-v1")
  private val now = Instant.parse("2026-09-20T10:15:30Z")

  private def generated: GeneratedAgentCredential =
    GeneratedAgentCredential.issue(AgentCredentialId.random(), plaintext, verifier, verification)

  private def metadata(credential: GeneratedAgentCredential): AgentCredentialMetadata =
    AgentCredentialMetadata(credential.credentialId, agentId, selector, now, None, None, None, Some("local bridge"), None)

  private def request = AgentCredentialEnrollmentRequest.from(Some("local bridge"), None).toOption.get

  test("enrollment writes in the actor's tenant, records the issuer, and discloses plaintext only after the write") {
    for
      writes <- Ref.of[IO, Vector[TenantId]](Vector.empty)
      issued <- Ref.of[IO, Int](0)
      value = generated
      issuer = new AgentCredentialIssuer[IO]:
        def issue(t: TenantId) = issued.update(_ + 1).as(value)
      repository = new AgentCredentialEnrollmentRepository[IO]:
        def enroll(t: TenantId, a: AgentId, g: GeneratedAgentCredential, r: AgentCredentialEnrollmentRequest, by: Principal.Human, at: Instant) =
          writes.update(_ :+ t).as(Right(metadata(g).copy(issuedBy = Some(by.id))))
        def rotate(t: TenantId, a: AgentId, previous: AgentCredentialId, g: GeneratedAgentCredential, r: AgentCredentialEnrollmentRequest, by: Principal.Human, at: Instant) = IO.pure(Left(AgentEnrollmentError.PersistenceFailure))
        def revoke(t: TenantId, a: AgentId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
        def metadataFor(t: TenantId, a: AgentId) = IO.pure(Vector.empty)
      result <- new AgentEnrollmentService(repository, issuer).enroll(actor, agentId, request, now)
      storedTenants <- writes.get
      issueCount <- issued.get
    yield
      val disclosure = result.toOption.get
      assertEquals(storedTenants, Vector(tenant))
      assertEquals(disclosure.metadata.issuedBy, Some(administrator.id))
      assertEquals(issueCount, 1)
      assertEquals(disclosure.credential, plaintext)
      assertEquals(disclosure.metadata.selector, selector)
      assert(!disclosure.toString.contains("z" * 43))
      assert(!disclosure.metadata.toString.contains("z" * 43))
  }

  test("failed enrollment never returns a disclosure") {
    val issuer = new AgentCredentialIssuer[IO]:
      def issue(t: TenantId) = IO.pure(generated)
    val repository = new AgentCredentialEnrollmentRepository[IO]:
      def enroll(t: TenantId, a: AgentId, g: GeneratedAgentCredential, r: AgentCredentialEnrollmentRequest, by: Principal.Human, at: Instant) =
        IO.pure(Left(AgentEnrollmentError.ExistingActiveCredential))
      def rotate(t: TenantId, a: AgentId, previous: AgentCredentialId, g: GeneratedAgentCredential, r: AgentCredentialEnrollmentRequest, by: Principal.Human, at: Instant) = IO.pure(Left(AgentEnrollmentError.PersistenceFailure))
      def revoke(t: TenantId, a: AgentId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
      def metadataFor(t: TenantId, a: AgentId) = IO.pure(Vector.empty)
    new AgentEnrollmentService(repository, issuer).enroll(actor, agentId, request, now).map: result =>
      assertEquals(result, Left(AgentEnrollmentError.ExistingActiveCredential))
  }

  test("expired enrollment input fails before credential generation") {
    for
      generatedCount <- Ref.of[IO, Int](0)
      issuer = new AgentCredentialIssuer[IO]:
        def issue(t: TenantId) = generatedCount.update(_ + 1).as(generated)
      repository = unusedRepository
      expired = AgentCredentialEnrollmentRequest.from(None, Some(now)).toOption.get
      result <- new AgentEnrollmentService(repository, issuer).enroll(actor, agentId, expired, now)
      count <- generatedCount.get
    yield
      assertEquals(result, Left(AgentEnrollmentError.InvalidRequest(AgentEnrollmentRequestError.InvalidExpiry)))
      assertEquals(count, 0)
  }

  test("rotation uses the repository's atomic lifecycle operation and returns a new one-time disclosure") {
    for
      rotated <- Ref.of[IO, Boolean](false)
      value = generated
      issuer = new AgentCredentialIssuer[IO]:
        def issue(t: TenantId) = IO.pure(value)
      repository = new AgentCredentialEnrollmentRepository[IO]:
        def enroll(t: TenantId, a: AgentId, g: GeneratedAgentCredential, r: AgentCredentialEnrollmentRequest, by: Principal.Human, at: Instant) = IO.pure(Left(AgentEnrollmentError.PersistenceFailure))
        def rotate(t: TenantId, a: AgentId, previous: AgentCredentialId, g: GeneratedAgentCredential, r: AgentCredentialEnrollmentRequest, by: Principal.Human, at: Instant) =
          rotated.set(true).as(Right(metadata(g)))
        def revoke(t: TenantId, a: AgentId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
        def metadataFor(t: TenantId, a: AgentId) = IO.pure(Vector.empty)
      result <- new AgentEnrollmentService(repository, issuer).rotate(actor, agentId, AgentCredentialId.random(), request, now)
      wasRotated <- rotated.get
    yield
      assert(wasRotated)
      assertEquals(result.map(_.credential), Right(plaintext))
  }

  private val unusedRepository = new AgentCredentialEnrollmentRepository[IO]:
    def enroll(t: TenantId, a: AgentId, g: GeneratedAgentCredential, r: AgentCredentialEnrollmentRequest, by: Principal.Human, at: Instant) = IO.pure(Left(AgentEnrollmentError.PersistenceFailure))
    def rotate(t: TenantId, a: AgentId, previous: AgentCredentialId, g: GeneratedAgentCredential, r: AgentCredentialEnrollmentRequest, by: Principal.Human, at: Instant) = IO.pure(Left(AgentEnrollmentError.PersistenceFailure))
    def revoke(t: TenantId, a: AgentId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
    def metadataFor(t: TenantId, a: AgentId) = IO.pure(Vector.empty)
