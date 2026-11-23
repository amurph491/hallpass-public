package run.hallpass.application

import java.time.Instant
import cats.effect.IO
import cats.effect.kernel.Ref
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.kernel.*

final class AgentAuthenticationSuite extends CatsEffectSuite:
  private val tenant = TenantId.random()
  private val otherTenant = TenantId.random()
  private val selector = AgentCredentialSelector.parse("selector-value-1234").toOption.get
  private val presented = PresentedAgentCredential.parse(s"ac1.${selector.value}.${"A" * 43}").toOption.get
  private val verifier = StoredAgentCredentialVerifier.fromBytes(Array.fill(32)(7.toByte)).toOption.get
  private val verification = CredentialVerifierMetadata(CredentialVerifierAlgorithm.HmacSha256, "local-v1")
  private val credentialId = AgentCredentialId.random()
  private val agentId = AgentId.random()
  private val now = Instant.parse("2026-09-20T10:15:30Z")

  private def routesTo(candidate: Option[TenantId]): AgentCredentialRoutes[IO] = _ => IO.pure(Right(candidate))
  private val routed = routesTo(Some(tenant))

  private def stored(boundTenant: TenantId = tenant): StoredAgentCredential =
    new StoredAgentCredential(boundTenant, credentialId, agentId, selector, verifier, verification, now, None, None, None)

  test("credential parsing is strict and secret formatting is redacted") {
    assert(PresentedAgentCredential.parse("ac1.bad.short").isLeft)
    assert(PresentedAgentCredential.parse(s"ac2.${selector.value}.${"A" * 43}").isLeft)
    assert(PresentedAgentCredential.parse(s"ac1.${selector.value}.${"s" * 42}").isLeft)
    assertEquals(presented.selector, selector)
    assert(!presented.toString.contains("s" * 43))
    assertEquals(presented.toString, "PresentedAgentCredential(<redacted>)")
    assert(!verifier.toString.contains("7"))
    assertEquals(verifier.toString, "StoredAgentCredentialVerifier(<redacted>)")
  }

  test("successful authentication creates an agent-only trusted context after recording use") {
    for
      calls <- Ref.of[IO, Vector[String]](Vector.empty)
      repository = new AgentCredentialAuthenticationRepository[IO]:
        def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) =
          calls.update(_ :+ s"lookup:$t:$s").as(Right(stored(t)))
        def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) =
          calls.update(_ :+ s"used:$t:$id").as(Right(()))
      verifierPort = new AgentCredentialVerifier[IO]:
        def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) =
          calls.update(_ :+ s"verify:$t").as(true)
      model = UnverifiedModelClaim.from("openai", "codex", Some("test")).toOption.get
      claims = UnverifiedExecutionClaims.from(Some(model), None)
      result <- new AgentAuthenticator(routed, repository, verifierPort).authenticate(presented, claims, now)
      recorded <- calls.get
    yield
      val context = result.toOption.get
      assertEquals(context.tenant, tenant)
      assertEquals(context.principal, Principal.Agent(agentId))
      assertEquals(context.agentId, agentId)
      assertEquals(context.credentialId, credentialId)
      assertEquals(context.authenticatedAt, now)
      assertEquals(context.unverifiedClaims, claims)
      assertEquals(recorded.map(_.takeWhile(_ != ':')), Vector("lookup", "verify", "used"))
  }

  test("the routed candidate tenant scopes every lookup and an unknown credential there is rejected") {
    for
      seenTenant <- Ref.of[IO, Option[TenantId]](None)
      repository = new AgentCredentialAuthenticationRepository[IO]:
        def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) =
          seenTenant.set(Some(t)) *> IO.pure(Left(AgentCredentialLookupError.Unknown))
        def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
      verifierPort = new AgentCredentialVerifier[IO]:
        def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) = IO.pure(true)
      result <- new AgentAuthenticator(routesTo(Some(otherTenant)), repository, verifierPort).authenticate(
        presented,
        UnverifiedExecutionClaims.empty,
        now
      )
      observed <- seenTenant.get
    yield
      assertEquals(observed, Some(otherTenant))
      assertEquals(result, Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.UnknownCredential)))
  }

  test("tenant-mismatched stored rows fail closed before verifier or last-used update") {
    for
      calls <- Ref.of[IO, Int](0)
      repository = new AgentCredentialAuthenticationRepository[IO]:
        def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) = IO.pure(Right(stored(otherTenant)))
        def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = calls.update(_ + 1).as(Right(()))
      verifierPort = new AgentCredentialVerifier[IO]:
        def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) =
          calls.update(_ + 1).as(true)
      result <- new AgentAuthenticator(routed, repository, verifierPort).authenticate(presented, UnverifiedExecutionClaims.empty, now)
      observedCalls <- calls.get
    yield
      assertEquals(result, Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.InvalidStoredCredential)))
      assertEquals(observedCalls, 0)
  }

  List(
    AgentCredentialLookupError.Unknown -> AgentCredentialRejection.UnknownCredential,
    AgentCredentialLookupError.Expired -> AgentCredentialRejection.ExpiredCredential,
    AgentCredentialLookupError.Revoked -> AgentCredentialRejection.RevokedCredential,
    AgentCredentialLookupError.InvalidStoredCredential -> AgentCredentialRejection.InvalidStoredCredential
  ).foreach:
    case (lookupError, rejection) =>
      test(s"$lookupError is rejected before verifier invocation") {
        for
          verifierCalls <- Ref.of[IO, Int](0)
          repository = new AgentCredentialAuthenticationRepository[IO]:
            def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) = IO.pure(Left(lookupError))
            def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
          verifierPort = new AgentCredentialVerifier[IO]:
            def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) =
              verifierCalls.update(_ + 1).as(true)
          result <- new AgentAuthenticator(routed, repository, verifierPort).authenticate(presented, UnverifiedExecutionClaims.empty, now)
          calls <- verifierCalls.get
        yield
          assertEquals(result, Left(AgentAuthenticationError.Rejected(rejection)))
          assertEquals(calls, 0)
      }

  test("wrong secret and revoked-after-verification both fail closed") {
    for
      uses <- Ref.of[IO, Int](0)
      repository = new AgentCredentialAuthenticationRepository[IO]:
        def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) = IO.pure(Right(stored(t)))
        def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = uses.update(_ + 1).as(Left(AgentCredentialUseError.NoLongerActive))
      badVerifier = new AgentCredentialVerifier[IO]:
        def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) = IO.pure(false)
      trueVerifier = new AgentCredentialVerifier[IO]:
        def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) = IO.pure(true)
      wrong <- new AgentAuthenticator(routed, repository, badVerifier).authenticate(presented, UnverifiedExecutionClaims.empty, now)
      revoked <- new AgentAuthenticator(routed, repository, trueVerifier).authenticate(presented, UnverifiedExecutionClaims.empty, now)
      useCount <- uses.get
    yield
      assertEquals(wrong, Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.WrongSecret)))
      assertEquals(revoked, Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.CredentialNoLongerActive)))
      assertEquals(useCount, 1)
  }

  test("an unrouted selector is rejected before any tenant lookup or verification") {
    for
      calls <- Ref.of[IO, Int](0)
      repository = new AgentCredentialAuthenticationRepository[IO]:
        def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) =
          calls.update(_ + 1).as(Right(stored(t)))
        def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = calls.update(_ + 1).as(Right(()))
      verifierPort = new AgentCredentialVerifier[IO]:
        def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) =
          calls.update(_ + 1).as(true)
      result <- new AgentAuthenticator(routesTo(None), repository, verifierPort).authenticate(presented, UnverifiedExecutionClaims.empty, now)
      observed <- calls.get
    yield
      assertEquals(result, Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.UnroutedCredential)))
      assertEquals(observed, 0)
  }

  test("an unavailable directory is an infrastructure failure, not a rejection") {
    val unavailable: AgentCredentialRoutes[IO] = _ => IO.pure(Left(DirectoryError.Unavailable))
    val repository = new AgentCredentialAuthenticationRepository[IO]:
      def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) = IO.pure(Right(stored(t)))
      def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
    val verifierPort = new AgentCredentialVerifier[IO]:
      def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) = IO.pure(true)
    new AgentAuthenticator(unavailable, repository, verifierPort)
      .authenticate(presented, UnverifiedExecutionClaims.empty, now)
      .map(result => assertEquals(result, Left(AgentAuthenticationError.Unavailable)))
  }

  test("a route to the wrong tenant fails verification, because the verifier is bound to the tenant") {
    // A colliding selector in another tenant: the route points there, a row with that selector exists there, but its
    // verifier was computed for a different credential and tenant, so tenant-bound verification rejects it.
    for
      verifiedIn <- Ref.of[IO, Vector[TenantId]](Vector.empty)
      repository = new AgentCredentialAuthenticationRepository[IO]:
        def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) = IO.pure(Right(stored(t)))
        def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
      tenantBound = new AgentCredentialVerifier[IO]:
        def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) =
          verifiedIn.update(_ :+ t).as(t == tenant)
      result <- new AgentAuthenticator(routesTo(Some(otherTenant)), repository, tenantBound)
        .authenticate(presented, UnverifiedExecutionClaims.empty, now)
      observed <- verifiedIn.get
    yield
      assertEquals(observed, Vector(otherTenant))
      assertEquals(result, Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.WrongSecret)))
  }

  test("unverified execution claims are bounded and never become a trusted model identity") {
    assert(UnverifiedModelClaim.from("", "codex", None).isLeft)
    assert(UnverifiedExecutionClaim.from(" " * 129).isLeft)
    val claim = UnverifiedExecutionClaim.from("local-codex-bridge").toOption.get
    val context = AuthenticatedAgentContext.authenticated(tenant, agentId, credentialId, now, UnverifiedExecutionClaims.from(None, Some(claim)))
    assertEquals(context.principal, Principal.Agent(agentId))
    assertEquals(context.unverifiedClaims.execution, Some(claim))
  }
