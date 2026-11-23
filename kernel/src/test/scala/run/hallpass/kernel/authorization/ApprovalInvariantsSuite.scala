package run.hallpass.kernel.authorization

import java.time.Instant
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop.forAll
import run.hallpass.kernel.*

/** An approval satisfies a REQUIRE_APPROVAL outcome only when it covers exactly this invocation. Every property
  * first asserts an authorized baseline, then mutates one field of the approval (or the world). */
final class ApprovalInvariantsSuite extends ScalaCheckSuite:
  private val at = Instant.parse("2026-09-27T12:00:00Z")
  private val segments = for
    head <- Gen.alphaUpperChar
    tail <- Gen.listOfN(6, Gen.alphaNumChar).map(_.mkString)
  yield s"$head$tail"
  private val keys: Gen[CapabilityKey] =
    Gen.listOfN(3, segments).map(parts => CapabilityKey.parse(parts.mkString(".")).getOrElse(fail("generated key")))
  private val actions = Gen.oneOf(Action.values.toSeq)
  private val bindings: Gen[ApprovalBinding] =
    Gen.listOfN(64, Gen.oneOf("0123456789abcdef".toSeq)).map(cs => ApprovalBinding.parse(cs.mkString).getOrElse(fail("binding")))
  private def nonEmpty[A](values: Set[A]): NonEmptySet[A] = NonEmptySet.from(values).getOrElse(fail("empty set"))

  private final case class Scenario(
      request: AuthorizationRequest,
      policies: Policies,
      chain: Vector[Delegation],
      binding: ApprovalBinding,
      approval: GrantedApproval
  ):
    def run(
        approval: Option[GrantedApproval] = Some(approval),
        policies: Policies = policies,
        chain: Vector[Delegation] = chain,
        request: AuthorizationRequest = request,
        binding: ApprovalBinding = binding
    ): AuthorizationResult = AuthorizationEngine.authorizeWithApproval(policies, request, chain, binding, approval, at)
    def plain(policies: Policies = policies, chain: Vector[Delegation] = chain, request: AuthorizationRequest = request) =
      AuthorizationEngine.authorize(policies, request, chain, at)
    def required: ApprovalRequest =
      AuthorizationEngine.evaluate(policies, request, chain, at) match
        case AuthorizationDecision.RequireApproval(required) => required
        case other => fail(s"baseline must require approval: $other")

  private val scenarios: Gen[Scenario] = for
    tenantUuid <- Gen.uuid
    resourceUuid <- Gen.uuid
    humanUuid <- Gen.uuid
    agentUuids <- Gen.choose(1, 4).flatMap(n => Gen.listOfN(n, Gen.uuid))
    delegationUuids <- Gen.listOfN(agentUuids.size, Gen.uuid)
    direct <- Gen.oneOf(true, false)
    action <- actions
    key <- keys
    binding <- bindings
    lifetime <- Gen.chooseNum(1L, 86400L)
    ttl <- Gen.chooseNum(1L, 86400L)
  yield
    val tenant = TenantId.parse(tenantUuid.toString).getOrElse(fail("tenant"))
    val resource = Resource(
      ResourceId.parse(resourceUuid.toString).getOrElse(fail("resource")), tenant, ResourceType.Api, None, "generated", None
    )
    val human: Principal.Human = Principal.Human(UserId.parse(humanUuid.toString).getOrElse(fail("human")))
    val agents = agentUuids.map(id => Principal.Agent(AgentId.parse(id.toString).getOrElse(fail("agent")))).toVector
    val ids = delegationUuids.map(id => DelegationId.parse(id.toString).getOrElse(fail("delegation"))).toVector
    val capabilities = NonEmptySet.one(CapabilityDescriptor(resource.id, action, key))
    // Either the human delegates down a chain to the agent, or the human acts directly with no chain.
    val chain =
      if direct then Vector.empty[Delegation]
      else
        agents.indices
          .map: index =>
            Delegation(
              ids(index),
              if index == 0 then human else agents(index - 1),
              agents(index),
              if index == 0 then None else Some(ids(index - 1)),
              capabilities, Constraints.empty, at.minusSeconds(lifetime), Some(at.plusSeconds(lifetime)), None
            )
          .toVector
    val subject: Principal = if direct then human else agents.last
    val request = AuthorizationRequest(
      AuthorizationRequestId.random(), tenant,
      IdentityChain(subject, chain.map(_.id), None, ExecutionContext.LocalProcess),
      ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope")), key, action, AuthorizationContext.empty
    )
    val policy = Policy(
      PolicyId.random(), PolicyVersion.from(1).getOrElse(fail("version")),
      NonEmptySet.one(PolicyStatement(human, resource.id, NonEmptySet.one(action), None, Constraints.empty, Effect.RequireApproval))
    )
    val approval = GrantedApproval(
      ApprovalId.random(), tenant, subject, human, binding, request.requiredCapability, policy.id, policy.version,
      at.plusSeconds(ttl)
    )
    Scenario(request, Policies(Vector(policy)), chain, binding, approval)

  private def withEffect(s: Scenario, effect: Effect): Policies =
    Policies(s.policies.values.map(p => p.copy(statements = nonEmpty(p.statements.toSet.map(_.copy(effect = effect))))))

  private def baseline(s: Scenario): Unit =
    s.run() match
      case AuthorizationResult.Authorized(_) => ()
      case other => fail(s"authorized baseline expected: $other")

  private def assertMismatch(s: Scenario, approval: GrantedApproval, clue: String): Unit =
    baseline(s)
    assertEquals(s.run(Some(approval)), AuthorizationResult.Denied(DenialReason.ApprovalMismatch), clue)

  property("a matching approval authorizes with the approval id and the request's policy, version, and delegations") {
    forAll(scenarios) { s =>
      s.run() match
        case AuthorizationResult.Authorized(capability) =>
          val required = s.required
          val evidence = capability.evidence
          assertEquals(evidence.approval, Some(s.approval.id))
          assertEquals(evidence.policyId, required.policyId)
          assertEquals(evidence.policyVersion, required.policyVersion)
          assertEquals(evidence.delegationIds, s.chain.map(_.id))
          assertEquals(evidence.requiredCapability, required.requiredCapability)
        case other => fail(s"expected authorized: $other")
    }
  }

  property("an approval for another tenant is a mismatch") {
    forAll(scenarios, Gen.uuid) { (s, uuid) =>
      val other = TenantId.parse(uuid.toString).getOrElse(fail("tenant"))
      if other != s.request.tenant then assertMismatch(s, s.approval.copy(tenant = other), "tenant")
    }
  }

  property("an approval for another principal is a mismatch") {
    forAll(scenarios, Gen.uuid, Gen.oneOf(true, false)) { (s, uuid, asAgent) =>
      val other: Principal =
        if asAgent then Principal.Agent(AgentId.parse(uuid.toString).getOrElse(fail("agent")))
        else Principal.Human(UserId.parse(uuid.toString).getOrElse(fail("user")))
      if other != s.request.identity.subject then assertMismatch(s, s.approval.copy(principal = other), "principal")
    }
  }

  property("an approval bound to a different invocation digest is a mismatch") {
    forAll(scenarios, bindings) { (s, other) =>
      if other != s.binding then assertMismatch(s, s.approval.copy(binding = other), "binding")
    }
  }

  property("an approval for a different resource, action, or capability key is a mismatch") {
    forAll(scenarios, Gen.uuid, actions, keys) { (s, uuid, action, key) =>
      val required = s.approval.requiredCapability
      val otherResource = ResourceId.parse(uuid.toString).getOrElse(fail("resource"))
      if otherResource != required.resource then
        assertMismatch(s, s.approval.copy(requiredCapability = required.copy(resource = otherResource)), "resource")
      if action != required.action then
        assertMismatch(s, s.approval.copy(requiredCapability = required.copy(action = action)), "action")
      if key != required.capability then
        assertMismatch(s, s.approval.copy(requiredCapability = required.copy(capability = key)), "key")
    }
  }

  property("an approval for a different policy id or version is a mismatch") {
    forAll(scenarios, Gen.chooseNum(2, 1000)) { (s, version) =>
      assertMismatch(s, s.approval.copy(policyId = PolicyId.random()), "policy id")
      val other = PolicyVersion.from(version).getOrElse(fail("version"))
      assertMismatch(s, s.approval.copy(policyVersion = other), "policy version")
    }
  }

  property("an approver who is not the root of authority is a mismatch") {
    forAll(scenarios, Gen.uuid) { (s, uuid) =>
      val other: Principal.Human = Principal.Human(UserId.parse(uuid.toString).getOrElse(fail("user")))
      if (other: Principal) != AuthorizationEngine.rootOf(s.request, s.chain) then
        assertMismatch(s, s.approval.copy(approver = other), "approver")
    }
  }

  property("the approver is the chain's root human, whatever the chain length, and no other human qualifies") {
    forAll(scenarios) { s =>
      assertEquals(AuthorizationEngine.rootOf(s.request, s.chain), s.approval.approver: Principal)
      assertMismatch(s, s.approval.copy(approver = Principal.Human(UserId.random())), "other human")
    }
  }

  property("an approval expires exactly at its expiry instant and never after") {
    forAll(scenarios, Gen.chooseNum(0L, 86400L)) { (s, elapsed) =>
      baseline(s)
      assertEquals(
        s.run(Some(s.approval.copy(expiresAt = at))), AuthorizationResult.Denied(DenialReason.ApprovalMismatch), "exactly at"
      )
      assertEquals(
        s.run(Some(s.approval.copy(expiresAt = at.minusSeconds(elapsed)))),
        AuthorizationResult.Denied(DenialReason.ApprovalMismatch), "before"
      )
      assert(s.run(Some(s.approval.copy(expiresAt = at.plusNanos(1)))).isInstanceOf[AuthorizationResult.Authorized])
    }
  }

  property("an approval never changes a Deny outcome") {
    forAll(scenarios) { s =>
      val denying = withEffect(s, Effect.Deny)
      baseline(s)
      val expected = s.plain(denying)
      assert(expected.isInstanceOf[AuthorizationResult.Denied])
      assertEquals(s.run(policies = denying), expected)
      assertEquals(s.run(approval = None, policies = denying), expected)
    }
  }

  property("an approval never changes an Allow outcome and is not recorded on it") {
    forAll(scenarios) { s =>
      val allowing = withEffect(s, Effect.Allow)
      baseline(s)
      s.run(policies = allowing) match
        case AuthorizationResult.Authorized(capability) =>
          assertEquals(capability.evidence.approval, None)
          assertEquals(s.run(policies = allowing), s.plain(allowing))
        case other => fail(s"expected authorized: $other")
    }
  }

  property("an unusable approval is irrelevant to Allow and Deny outcomes") {
    forAll(scenarios) { s =>
      val garbage = s.approval.copy(tenant = TenantId.random(), expiresAt = at.minusSeconds(1))
      assertEquals(s.run(Some(garbage), withEffect(s, Effect.Allow)), s.plain(withEffect(s, Effect.Allow)))
      assertEquals(s.run(Some(garbage), withEffect(s, Effect.Deny)), s.plain(withEffect(s, Effect.Deny)))
    }
  }

  property("without an approval the result is identical to authorize, whatever the policy effect") {
    forAll(scenarios, Gen.oneOf(Effect.values.toSeq)) { (s, effect) =>
      baseline(s)
      val policies = withEffect(s, effect)
      assertEquals(s.run(approval = None, policies = policies), s.plain(policies))
    }
  }

  property("a required approval that is missing asks for approval and never authorizes") {
    forAll(scenarios) { s =>
      baseline(s)
      assertEquals(s.run(approval = None), AuthorizationResult.ApprovalRequired(s.required))
    }
  }

  property("an approval cannot rescue a revoked or expired delegation") {
    forAll(scenarios.suchThat(_.chain.nonEmpty), Gen.chooseNum(0, 100), Gen.chooseNum(0L, 86400L), Gen.oneOf(true, false)) {
      (s, link, elapsed, revoke) =>
        baseline(s)
        val index = link % s.chain.size
        val broken =
          if revoke then s.chain(index).copy(revokedAt = Some(at.minusSeconds(elapsed)))
          else s.chain(index).copy(expiresAt = Some(at.minusSeconds(elapsed)))
        val chain = s.chain.updated(index, broken)
        assertEquals(s.run(chain = chain), AuthorizationResult.Denied(DenialReason.InactiveDelegation(broken.id)))
        assertEquals(s.run(chain = chain), s.run(approval = None, chain = chain))
    }
  }

  property("an approval cannot rescue a missing claimed chain") {
    forAll(scenarios.suchThat(_.chain.nonEmpty)) { s =>
      baseline(s)
      assertEquals(s.run(chain = Vector.empty), AuthorizationResult.Denied(DenialReason.InvalidDelegationChain))
    }
  }

  property("an approval cannot rescue a cross-tenant request") {
    forAll(scenarios, Gen.uuid) { (s, uuid) =>
      val other = TenantId.parse(uuid.toString).getOrElse(fail("tenant"))
      if other != s.request.tenant then
        baseline(s)
        val crossTenant = s.request.copy(tenant = other)
        assertEquals(
          s.run(Some(s.approval.copy(tenant = other)), request = crossTenant),
          AuthorizationResult.Denied(DenialReason.TenantMismatch)
        )
        assertEquals(s.run(request = crossTenant), AuthorizationResult.Denied(DenialReason.TenantMismatch))
    }
  }
