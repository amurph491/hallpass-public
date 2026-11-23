package run.hallpass.kernel.authorization

import java.time.Instant
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop.forAll
import run.hallpass.kernel.*

final class AuthorizationEngineSuite extends ScalaCheckSuite:
  private val now = Instant.parse("2026-08-31T12:00:00Z")
  private val tenant = TenantId.random()
  private val otherTenant = TenantId.random()
  private val human = Principal.Human(UserId.random())
  private val agent = Principal.Agent(AgentId.random())
  private val resource = Resource(ResourceId.random(), tenant, ResourceType.Tool, None, "tool", custodian = None)
  private val scope = ResourceScope.fromPath(Vector(resource)).getOrElse(fail("single-resource scope"))
  private val version = PolicyVersion.from(1).getOrElse(fail("positive version"))
  private def key(value: String): CapabilityKey = CapabilityKey.parse(value).getOrElse(fail(s"invalid key $value"))
  private val readIssues = key("GitHub.Issue.Read")
  private val readContents = key("GitHub.Contents.Read")

  private def request(
      subject: Principal = human,
      chain: Vector[DelegationId] = Vector.empty,
      requestTenant: TenantId = tenant,
      capability: CapabilityKey = readIssues
  ) =
    AuthorizationRequest(
      AuthorizationRequestId.random(),
      requestTenant,
      IdentityChain(subject, chain, None, ExecutionContext.LocalProcess),
      scope,
      capability,
      Action.Read,
      AuthorizationContext.empty
    )

  private def policies(
      subject: Principal,
      effect: Effect = Effect.Allow,
      allowlist: Option[NonEmptySet[CapabilityKey]] = None
  ): Policies =
    val statement =
      PolicyStatement(subject, resource.id, NonEmptySet.one(Action.Read), allowlist, Constraints.empty, effect)
    Policies(Vector(Policy(PolicyId.random(), version, NonEmptySet.one(statement))))

  test("denies by default") {
    assertEquals(
      AuthorizationEngine.evaluate(Policies.empty, request(), Vector.empty, now),
      AuthorizationDecision.Deny(DenialReason.NoMatchingAuthority)
    )
  }

  test("denies a cross-tenant request before evaluating policy") {
    assertEquals(
      AuthorizationEngine.evaluate(policies(human), request(requestTenant = otherTenant), Vector.empty, now),
      AuthorizationDecision.Deny(DenialReason.TenantMismatch)
    )
  }

  test("deny takes precedence over allow") {
    val result = AuthorizationEngine.evaluate(
      Policies(policies(human).values ++ policies(human, Effect.Deny).values),
      request(),
      Vector.empty,
      now
    )
    assert(result.isInstanceOf[AuthorizationDecision.Deny])
  }

  test("a valid delegation enables an agent under its grantor policy") {
    val delegation = Delegation(
      DelegationId.random(),
      human,
      agent,
      None,
      NonEmptySet.one(CapabilityDescriptor(resource.id, Action.Read, readIssues)),
      Constraints.empty,
      now.minusSeconds(1),
      None,
      None
    )
    val result =
      AuthorizationEngine.authorize(policies(human), request(agent, Vector(delegation.id)), Vector(delegation), now)
    assert(result.isInstanceOf[AuthorizationResult.Authorized])
  }

  test("delegation attenuation rejects capability escalation") {
    val parent = Delegation(
      DelegationId.random(),
      human,
      agent,
      None,
      NonEmptySet.one(CapabilityDescriptor(resource.id, Action.Read, readIssues)),
      Constraints.empty,
      now,
      None,
      None
    )
    val child = Delegation(
      DelegationId.random(),
      agent,
      Principal.Service(ServiceId.random()),
      Some(parent.id),
      NonEmptySet.one(CapabilityDescriptor(resource.id, Action.Write, readIssues)),
      Constraints.empty,
      now,
      None,
      None
    )
    assertEquals(Delegation.validateChild(parent, child, Map(resource.id -> scope).get), Left(DelegationValidationError.CapabilityEscalation))
  }

  property("a delegation without the requested action always denies") {
    forAll(Gen.oneOf(Action.Write, Action.Execute, Action.Delete)) { otherAction =>
      val delegation = Delegation(
        DelegationId.random(),
        human,
        agent,
        None,
        NonEmptySet.one(CapabilityDescriptor(resource.id, otherAction, readIssues)),
        Constraints.empty,
        now.minusSeconds(1),
        None,
        None
      )
      val result =
        AuthorizationEngine.evaluate(policies(human), request(agent, Vector(delegation.id)), Vector(delegation), now)
      assertEquals(result, AuthorizationDecision.Deny(DenialReason.CapabilityNotDelegated(delegation.id)))
    }
  }

  test("a delegated capability key does not authorize another key on the same resource and action") {
    val delegation = Delegation(
      DelegationId.random(),
      human,
      agent,
      None,
      NonEmptySet.one(CapabilityDescriptor(resource.id, Action.Read, readIssues)),
      Constraints.empty,
      now.minusSeconds(1),
      None,
      None
    )
    val chain = Vector(delegation)
    assert(
      AuthorizationEngine.evaluate(policies(human), request(agent, Vector(delegation.id)), chain, now)
        .isInstanceOf[AuthorizationDecision.Allow]
    )
    assertEquals(
      AuthorizationEngine.evaluate(
        policies(human),
        request(agent, Vector(delegation.id), capability = readContents),
        chain,
        now
      ),
      AuthorizationDecision.Deny(DenialReason.CapabilityNotDelegated(delegation.id))
    )
  }

  test("a policy capability allowlist matches only the listed keys") {
    val onlyIssues = Some(NonEmptySet.one(readIssues))
    assert(
      AuthorizationEngine.evaluate(policies(human, allowlist = onlyIssues), request(), Vector.empty, now)
        .isInstanceOf[AuthorizationDecision.Allow]
    )
    assertEquals(
      AuthorizationEngine.evaluate(
        policies(human, allowlist = onlyIssues),
        request(capability = readContents),
        Vector.empty,
        now
      ),
      AuthorizationDecision.Deny(DenialReason.NoMatchingAuthority)
    )
  }

  test("a deny scoped to one capability key does not block another key") {
    val denyContents = policies(human, Effect.Deny, Some(NonEmptySet.one(readContents)))
    val combined = Policies(policies(human).values ++ denyContents.values)
    assert(
      AuthorizationEngine.evaluate(combined, request(), Vector.empty, now).isInstanceOf[AuthorizationDecision.Allow]
    )
    assert(
      AuthorizationEngine.evaluate(combined, request(capability = readContents), Vector.empty, now)
        .isInstanceOf[AuthorizationDecision.Deny]
    )
  }

  test("evidence and the authorized capability carry the capability key") {
    AuthorizationEngine.authorize(policies(human), request(), Vector.empty, now) match
      case AuthorizationResult.Authorized(capability) =>
        assertEquals(capability.capability, readIssues)
        assertEquals(capability.evidence.requiredCapability, CapabilityDescriptor(resource.id, Action.Read, readIssues))
      case other => fail(s"expected authorization, got $other")
  }

  test("delegation attenuation rejects a child that swaps the capability key") {
    val parent = Delegation(
      DelegationId.random(),
      human,
      agent,
      None,
      NonEmptySet.one(CapabilityDescriptor(resource.id, Action.Read, readIssues)),
      Constraints.empty,
      now,
      None,
      None
    )
    val child = Delegation(
      DelegationId.random(),
      agent,
      Principal.Service(ServiceId.random()),
      Some(parent.id),
      NonEmptySet.one(CapabilityDescriptor(resource.id, Action.Read, readContents)),
      Constraints.empty,
      now,
      None,
      None
    )
    assertEquals(Delegation.validateChild(parent, child, Map(resource.id -> scope).get), Left(DelegationValidationError.CapabilityEscalation))
  }

  test("capability keys are Provider.Object.Verb with up to six capitalized segments") {
    List("Slack.Message.Read", "GitHub.Issue.Create", "HubSpot.Deal.Properties.Update", "A.B.C.D.E.F").foreach: value =>
      assertEquals(CapabilityKey.parse(value).map(_.value), Right(value))
    assertEquals(CapabilityKey.parse(""), Left(CapabilityKeyError.Empty))
    assertEquals(CapabilityKey.parse("Slack.Message"), Left(CapabilityKeyError.TooFewSegments))
    assertEquals(CapabilityKey.parse("A.B.C.D.E.F.G"), Left(CapabilityKeyError.TooManySegments))
    assertEquals(CapabilityKey.parse("A.B." + "C" * 200), Left(CapabilityKeyError.TooLong))
    List(
      "slack.Message.Read",
      "Slack..Read",
      "Slack.Message.",
      ".Slack.Message.Read",
      "Slack.Message.Read ",
      "Slack.Message.Re-ad",
      "Slack.Message.Réad",
      "Slack.Message.1Read"
    ).foreach: value =>
      assertEquals(CapabilityKey.parse(value), Left(CapabilityKeyError.InvalidSegment), value)
  }

  test("parses a canonical agent id without admitting raw UUIDs to callers") {
    val uuid = "fc30cfdc-b0f5-4f34-8c48-29ab1d0d717a"
    assert(AgentId.parse(uuid).isRight)
  }

  test("rejects malformed or whitespace-padded agent ids") {
    assertEquals(AgentId.parse("not-a-uuid"), Left(IdentifierParseError.InvalidUuid))
    assertEquals(AgentId.parse(" fc30cfdc-b0f5-4f34-8c48-29ab1d0d717a"), Left(IdentifierParseError.InvalidUuid))
  }

  test("identity chains retain model and execution context as authorization evidence") {
    val model = ModelIdentity(ModelId.random(), "anthropic", "claude", Some("3.7"))
    val chain = IdentityChain(agent, Vector.empty, Some(model), ExecutionContext.LocalProcess)
    assertEquals(chain.model, Some(model))
    assertEquals(chain.executionContext, ExecutionContext.LocalProcess)
  }
