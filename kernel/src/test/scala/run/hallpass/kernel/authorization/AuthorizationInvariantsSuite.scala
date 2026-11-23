package run.hallpass.kernel.authorization

import java.time.Instant
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop.forAll
import run.hallpass.kernel.*

/** Generate complete, linked chains so that restrictive mutations are checked against real authority. */
final class AuthorizationInvariantsSuite extends ScalaCheckSuite:
  private val at = Instant.parse("2026-09-27T12:00:00Z")
  private val actions = Gen.oneOf(Action.values.toSeq)
  private val effects = Gen.oneOf(Effect.values.toSeq)
  private val segments = for
    head <- Gen.alphaUpperChar
    tail <- Gen.listOfN(6, Gen.alphaNumChar).map(_.mkString)
  yield s"$head$tail"
  private val keys: Gen[CapabilityKey] =
    Gen.listOfN(3, segments).map(parts => CapabilityKey.parse(parts.mkString(".")).getOrElse(fail("generated key")))
  private val nonEmptyActions = Gen.someOf(Action.values.toSeq).map(_.toSet).suchThat(_.nonEmpty)
  private def nonEmpty[A](values: Set[A]): NonEmptySet[A] =
    NonEmptySet.from(values).getOrElse(fail("generated empty set"))

  private case class Scenario(request: AuthorizationRequest, policies: Policies, chain: Vector[Delegation]):
    def evaluate(
        currentChain: Vector[Delegation] = chain,
        currentPolicies: Policies = policies,
        currentRequest: AuthorizationRequest = request
    ): AuthorizationDecision = AuthorizationEngine.evaluate(currentPolicies, currentRequest, currentChain, at)

  private val scenarios: Gen[Scenario] = for
    tenantUuid <- Gen.uuid
    resourceUuid <- Gen.uuid
    humanUuid <- Gen.uuid
    agentUuids <- Gen.nonEmptyListOf(Gen.uuid).map(_.take(8))
    delegationUuids <- Gen.listOfN(agentUuids.size, Gen.uuid)
    action <- actions
    key <- keys
    extraActions <- nonEmptyActions
    lifetime <- Gen.chooseNum(1L, 86400L)
  yield
    val tenant = TenantId.parse(tenantUuid.toString).getOrElse(fail("tenant"))
    val resource = Resource(
      ResourceId.parse(resourceUuid.toString).getOrElse(fail("resource")),
      tenant,
      ResourceType.Api,
      None,
      "generated",
      custodian = None
    )
    val human = Principal.Human(UserId.parse(humanUuid.toString).getOrElse(fail("human")))
    val agents = agentUuids.map(id => Principal.Agent(AgentId.parse(id.toString).getOrElse(fail("agent")))).toVector
    val ids = delegationUuids.map(id => DelegationId.parse(id.toString).getOrElse(fail("delegation"))).toVector
    val capabilities = nonEmpty((extraActions + action).map(CapabilityDescriptor(resource.id, _, key)))
    val chain = agents.indices
      .map: index =>
        Delegation(
          ids(index),
          if index == 0 then human else agents(index - 1),
          agents(index),
          if index == 0 then None else Some(ids(index - 1)),
          capabilities,
          Constraints.empty,
          at.minusSeconds(lifetime),
          Some(at.plusSeconds(lifetime)),
          None
        )
      .toVector
    val request = AuthorizationRequest(
      AuthorizationRequestId.random(),
      tenant,
      IdentityChain(agents.last, ids, None, ExecutionContext.LocalProcess),
      ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope")),
      key,
      action,
      AuthorizationContext.empty
    )
    val policy = Policy(
      PolicyId.random(),
      PolicyVersion.from(1).getOrElse(fail("version")),
      NonEmptySet.one(
        PolicyStatement(human, resource.id, nonEmpty(extraActions + action), None, Constraints.empty, Effect.Allow)
      )
    )
    Scenario(request, Policies(Vector(policy)), chain)

  private def withEffect(scenario: Scenario, effect: Effect): Policies =
    Policies(
      scenario.policies.values.map(policy =>
        policy.copy(statements = nonEmpty(policy.statements.toSet.map(_.copy(effect = effect))))
      )
    )

  property("no root policy denies even a complete active delegation chain") {
    forAll(scenarios) { scenario =>
      assert(scenario.evaluate().isInstanceOf[AuthorizationDecision.Allow])
      assertEquals(
        scenario.evaluate(currentPolicies = Policies.empty),
        AuthorizationDecision.Deny(DenialReason.NoMatchingAuthority)
      )
    }
  }

  property("deny and approval take precedence over allow in any generated policy ordering") {
    forAll(scenarios, Gen.nonEmptyListOf(effects)) { (scenario, orderedEffects) =>
      val policies = Policies(orderedEffects.toVector.flatMap(effect => withEffect(scenario, effect).values))
      val result = scenario.evaluate(currentPolicies = policies)
      if orderedEffects.contains(Effect.Deny) then assert(result.isInstanceOf[AuthorizationDecision.Deny])
      else if orderedEffects.contains(Effect.RequireApproval) then
        assert(result.isInstanceOf[AuthorizationDecision.RequireApproval])
      else assert(result.isInstanceOf[AuthorizationDecision.Allow])
    }
  }

  property("revoking any link never increases authority and denies at the revocation boundary") {
    forAll(scenarios, effects, Gen.chooseNum(0, 100), Gen.chooseNum(0L, 86400L)) { (scenario, effect, link, elapsed) =>
      val index = link % scenario.chain.size
      val revoked = scenario.chain(index).copy(revokedAt = Some(at.minusSeconds(elapsed)))
      assertEquals(
        scenario.evaluate(scenario.chain.updated(index, revoked), withEffect(scenario, effect)),
        AuthorizationDecision.Deny(DenialReason.InactiveDelegation(revoked.id))
      )
    }
  }

  property("expiring any link denies at expiry and afterwards") {
    forAll(scenarios, Gen.chooseNum(0, 100), Gen.chooseNum(0L, 86400L)) { (scenario, link, elapsed) =>
      val index = link % scenario.chain.size
      val expired = scenario.chain(index).copy(expiresAt = Some(at.minusSeconds(elapsed)))
      assertEquals(
        scenario.evaluate(scenario.chain.updated(index, expired)),
        AuthorizationDecision.Deny(DenialReason.InactiveDelegation(expired.id))
      )
    }
  }

  property("future authority cannot authorize before its validity window") {
    forAll(scenarios, Gen.chooseNum(0, 100), Gen.chooseNum(1L, 86400L)) { (scenario, link, delay) =>
      val index = link % scenario.chain.size
      val future = scenario.chain(index).copy(validFrom = at.plusSeconds(delay))
      assertEquals(
        scenario.evaluate(scenario.chain.updated(index, future)),
        AuthorizationDecision.Deny(DenialReason.InactiveDelegation(future.id))
      )
    }
  }

  property("cross-tenant requests deny regardless of policy effect or delegation chain") {
    forAll(scenarios, Gen.uuid, effects) { (scenario, uuid, effect) =>
      val other = TenantId.parse(uuid.toString).getOrElse(fail("tenant"))
      if other != scenario.request.tenant then
        assertEquals(
          scenario.evaluate(
            currentPolicies = withEffect(scenario, effect),
            currentRequest = scenario.request.copy(tenant = other)
          ),
          AuthorizationDecision.Deny(DenialReason.TenantMismatch)
        )
    }
  }

  property("a child claiming authority absent from its parent cannot authorize") {
    forAll(scenarios, actions) { (scenario, requested) =>
      val retained = Action.values.toSet - requested
      val parent = scenario.chain.head
        .copy(capabilities = nonEmpty(retained.map(CapabilityDescriptor(scenario.request.resource.id, _, scenario.request.capability))))
      val chain = scenario.chain.updated(0, parent)
      assertEquals(
        scenario.evaluate(chain, currentRequest = scenario.request.copy(action = requested)),
        AuthorizationDecision.Deny(DenialReason.CapabilityNotDelegated(parent.id))
      )
    }
  }

  property("removing a capability from any link never creates an authorized action") {
    forAll(scenarios, actions, effects, Gen.chooseNum(0, 100)) { (scenario, removed, effect, link) =>
      val index = link % scenario.chain.size
      val delegation = scenario.chain(index)
      val remaining = delegation.capabilities.toSet - CapabilityDescriptor(scenario.request.resource.id, removed, scenario.request.capability)
      if remaining.nonEmpty then
        val policies = withEffect(scenario, effect)
        val before = scenario.evaluate(currentPolicies = policies)
        val after = scenario.evaluate(
          scenario.chain.updated(index, delegation.copy(capabilities = nonEmpty(remaining))),
          policies
        )
        if after.isInstanceOf[AuthorizationDecision.Allow] then assert(before.isInstanceOf[AuthorizationDecision.Allow])
        if removed == scenario.request.action then
          assertEquals(after, AuthorizationDecision.Deny(DenialReason.CapabilityNotDelegated(delegation.id)))
    }
  }

  property("a claimed delegation chain cannot be replaced by direct principal authority") {
    forAll(scenarios) { scenario =>
      val direct = Policies(
        scenario.policies.values.map(policy =>
          policy.copy(
            statements = nonEmpty(policy.statements.toSet.map(_.copy(subject = scenario.request.identity.subject)))
          )
        )
      )
      assertEquals(
        scenario.evaluate(Vector.empty, direct),
        AuthorizationDecision.Deny(DenialReason.InvalidDelegationChain)
      )
    }
  }

  property("broken parent links and principal links fail closed") {
    forAll(scenarios.suchThat(_.chain.size >= 2)) { scenario =>
      val child = scenario.chain(1)
      assertEquals(
        scenario.evaluate(scenario.chain.updated(1, child.copy(parent = None))),
        AuthorizationDecision.Deny(DenialReason.InvalidDelegationChain)
      )
      assertEquals(
        scenario.evaluate(scenario.chain.updated(1, child.copy(grantor = child.grantee))),
        AuthorizationDecision.Deny(DenialReason.InvalidDelegationChain)
      )
    }
  }

  property("a delegated capability key never authorizes a different key on the same resource and action") {
    forAll(scenarios, keys, effects) { (scenario, other, effect) =>
      if other != scenario.request.capability then
        assertEquals(
          scenario.evaluate(
            currentPolicies = withEffect(scenario, effect),
            currentRequest = scenario.request.copy(capability = other)
          ),
          AuthorizationDecision.Deny(DenialReason.CapabilityNotDelegated(scenario.chain.head.id))
        )
    }
  }

  property("a policy capability allowlist grants only the keys it lists") {
    forAll(scenarios, keys) { (scenario, other) =>
      def allowlisted(allowed: CapabilityKey) = Policies(
        scenario.policies.values.map(policy =>
          policy.copy(statements = nonEmpty(policy.statements.toSet.map(_.copy(capabilities = Some(NonEmptySet.one(allowed))))))
        )
      )
      assert(scenario.evaluate(currentPolicies = allowlisted(scenario.request.capability)).isInstanceOf[AuthorizationDecision.Allow])
      if other != scenario.request.capability then
        assertEquals(
          scenario.evaluate(currentPolicies = allowlisted(other)),
          AuthorizationDecision.Deny(DenialReason.NoMatchingAuthority)
        )
    }
  }

  property("a child delegation that changes the capability key is rejected as escalation") {
    forAll(scenarios.suchThat(_.chain.size >= 2), keys) { (scenario, other) =>
      if other != scenario.request.capability then
        val child = scenario.chain(1)
        val swapped = child.copy(capabilities =
          nonEmpty(child.capabilities.toSet.map(descriptor => descriptor.copy(capability = other)))
        )
        assertEquals(
          Delegation.validateChild(scenario.chain.head, swapped, Map(scenario.request.resource.id -> scenario.request.scope).get),
          Left(DelegationValidationError.CapabilityEscalation)
        )
    }
  }
