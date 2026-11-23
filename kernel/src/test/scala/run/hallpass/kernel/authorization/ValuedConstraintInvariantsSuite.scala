package run.hallpass.kernel.authorization

import java.time.Instant
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop.forAll
import run.hallpass.kernel.*

/** Valued constraints (`ValueIn`) over set-valued facts, in delegations and policy statements. Each property first
  * establishes an authorized baseline so it cannot pass only because everything was denied. */
final class ValuedConstraintInvariantsSuite extends ScalaCheckSuite:
  private val at = Instant.parse("2026-09-27T12:00:00Z")
  private val key = CapabilityKey.parse("Test.Message.Send").getOrElse(fail("key"))
  private val factKey = ContextKey("test.recipients")
  private val otherFactKey = ContextKey("test.other")

  private val values: Gen[ContextValue] =
    Gen.choose(1, 8).flatMap(n => Gen.listOfN(n, Gen.alphaLowerChar).map(cs => ContextValue(cs.mkString + "@x.test")))
  private val allowlists: Gen[Set[ContextValue]] = Gen.choose(1, 6).flatMap(n => Gen.listOfN(n, values).map(_.toSet))
  private def nes[A](values: Set[A]): NonEmptySet[A] = NonEmptySet.from(values).getOrElse(fail("empty set"))
  private def subsetOf(set: Set[ContextValue]): Gen[Set[ContextValue]] = Gen.someOf(set.toSeq).map(_.toSet)
  private val withSubset: Gen[(Set[ContextValue], Set[ContextValue])] = allowlists.flatMap(a => subsetOf(a).map(a -> _))
  /** A value guaranteed to be outside `allowed` (generated values all end in `@x.test`). */
  private val outsider: ContextValue = ContextValue("outside@y.test")

  private val tenant = TenantId.random()
  private val human = Principal.Human(UserId.random())
  private val agent = Principal.Agent(AgentId.random())
  private val resource = Resource(ResourceId.random(), tenant, ResourceType.Api, None, "r", custodian = None)
  private val scope = ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope"))
  private val descriptor = CapabilityDescriptor(resource.id, Action.Write, key)

  private def delegationWith(constraints: Constraints) = Delegation(
    DelegationId.random(), human, agent, None, NonEmptySet.one(descriptor), constraints,
    at.minusSeconds(60), Some(at.plusSeconds(60)), None
  )
  private def policies(constraints: Constraints) = Policies(
    Vector(
      Policy(
        PolicyId.random(),
        PolicyVersion.from(1).getOrElse(fail("version")),
        NonEmptySet.one(PolicyStatement(human, resource.id, NonEmptySet.one(Action.Write), None, constraints, Effect.Allow))
      )
    )
  )
  private def request(context: AuthorizationContext, chain: Vector[Delegation]) = AuthorizationRequest(
    AuthorizationRequestId.random(), tenant,
    IdentityChain(agent, chain.map(_.id), None, ExecutionContext.LocalProcess), scope, key, Action.Write, context
  )
  private def facts(values: Set[ContextValue]) = AuthorizationContext.withFacts(Map.empty, Map(factKey -> values))
  private def valueIn(allowed: Set[ContextValue]) = Constraints(Set(Constraint.ValueIn(factKey, nes(allowed))))
  private def isAllow(d: AuthorizationDecision) = d.isInstanceOf[AuthorizationDecision.Allow]

  private def viaDelegation(allowed: Set[ContextValue], context: AuthorizationContext): AuthorizationDecision =
    val d = delegationWith(valueIn(allowed))
    AuthorizationEngine.evaluate(policies(Constraints.empty), request(context, Vector(d)), Vector(d), at)
  private def viaPolicy(allowed: Set[ContextValue], context: AuthorizationContext): AuthorizationDecision =
    val d = delegationWith(Constraints.empty)
    AuthorizationEngine.evaluate(policies(valueIn(allowed)), request(context, Vector(d)), Vector(d), at)

  property("a delegation ValueIn authorizes any subset of its allowlist, including the empty set") {
    forAll(withSubset) { (allowed, subset) =>
      assert(isAllow(viaDelegation(allowed, facts(subset))))
      assert(isAllow(viaDelegation(allowed, facts(Set.empty))))
    }
  }

  property("a policy statement ValueIn authorizes subsets and denies when a value is outside") {
    forAll(withSubset) { (allowed, subset) =>
      assert(isAllow(viaPolicy(allowed, facts(subset))))
      assert(isAllow(viaPolicy(allowed, facts(Set.empty))))
      assertEquals(
        viaPolicy(allowed, facts(subset + outsider)),
        AuthorizationDecision.Deny(DenialReason.NoMatchingAuthority)
      )
      assertEquals(
        viaPolicy(allowed, AuthorizationContext.empty),
        AuthorizationDecision.Deny(DenialReason.NoMatchingAuthority)
      )
    }
  }

  property("adding a value outside the allowlist turns an allow into DelegationConstraintsNotSatisfied") {
    forAll(withSubset) { (allowed, subset) =>
      val d = delegationWith(valueIn(allowed))
      def evaluate(context: AuthorizationContext) =
        AuthorizationEngine.evaluate(policies(Constraints.empty), request(context, Vector(d)), Vector(d), at)
      assert(isAllow(evaluate(facts(subset))), "baseline")
      assertEquals(
        evaluate(facts(subset + outsider)),
        AuthorizationDecision.Deny(DenialReason.DelegationConstraintsNotSatisfied(d.id))
      )
    }
  }

  property("a missing fact, or a different fact key, in a complete context denies") {
    forAll(allowlists) { allowed =>
      val d = delegationWith(valueIn(allowed))
      for context <- Vector(
          AuthorizationContext.empty,
          AuthorizationContext(Map.empty),
          AuthorizationContext.withFacts(Map.empty, Map(otherFactKey -> allowed))
        )
      do
        assertEquals(
          AuthorizationEngine.evaluate(policies(Constraints.empty), request(context, Vector(d)), Vector(d), at),
          AuthorizationDecision.Deny(DenialReason.DelegationConstraintsNotSatisfied(d.id))
        )
    }
  }

  property("shrinking the allowlist never authorizes more") {
    forAll(allowlists.flatMap(a => subsetOf(a).flatMap(n => subsetOf(a).map(o => (a, n, o))))) { (wide, narrow, offered) =>
      assert(isAllow(viaDelegation(wide, facts(offered))), "baseline: offered is within the wide list")
      if narrow.nonEmpty then
        if isAllow(viaDelegation(narrow, facts(offered))) then assert(offered.subsetOf(narrow))
        assertEquals(isAllow(viaDelegation(narrow, facts(offered))), offered.subsetOf(narrow))
    }
  }

  property("factsNotEvaluated satisfies fact constraints; empty and withFacts contexts are complete") {
    forAll(allowlists) { allowed =>
      val constraints = valueIn(allowed)
      assert(constraints.satisfiedBy(AuthorizationContext.factsNotEvaluated))
      assert(!constraints.satisfiedBy(AuthorizationContext.empty))
      assert(!constraints.satisfiedBy(AuthorizationContext.withFacts(Map.empty, Map.empty)))
      assert(!constraints.satisfiedBy(AuthorizationContext(Map.empty)))
      assert(isAllow(viaDelegation(allowed, AuthorizationContext.factsNotEvaluated)))
      assert(isAllow(viaPolicy(allowed, AuthorizationContext.factsNotEvaluated)))
    }
  }

  private val parentScopes: ResourceId => Option[ResourceScope] = Map(resource.id -> scope).get
  private def childOf(parent: Delegation, constraints: Constraints) = Delegation(
    DelegationId.random(), agent, Principal.Agent(AgentId.random()), Some(parent.id), NonEmptySet.one(descriptor),
    constraints, parent.validFrom, parent.expiresAt, None
  )

  property("a child carrying the parent's ValueIn, from an equal but distinct NonEmptySet, is accepted") {
    forAll(allowlists) { allowed =>
      val parent = delegationWith(valueIn(allowed))
      val rebuilt = nes(allowed.toList.reverse.toSet)
      val child = childOf(parent, Constraints(Set(Constraint.ValueIn(factKey, rebuilt))))
      assertEquals(Delegation.validateChild(parent, child, parentScopes), Right(child))
    }
  }

  property("a child that drops or changes the parent's ValueIn is ConstraintEscalation") {
    forAll(allowlists) { allowed =>
      val parent = delegationWith(valueIn(allowed))
      val children = Vector(
        childOf(parent, Constraints.empty),
        childOf(parent, valueIn(allowed + outsider)),
        childOf(parent, Constraints(Set(Constraint.ValueIn(otherFactKey, nes(allowed)))))
      )
      for child <- children do
        assertEquals(
          Delegation.validateChild(parent, child, parentScopes),
          Left(DelegationValidationError.ConstraintEscalation)
        )
    }
  }

  property("a child may add a ValueIn to an unconstrained or constrained parent") {
    forAll(allowlists, allowlists) { (a, b) =>
      val bare = delegationWith(Constraints.empty)
      val first = childOf(bare, Constraints(Set(Constraint.ValueIn(factKey, nes(b)))))
      assertEquals(Delegation.validateChild(bare, first, parentScopes), Right(first))
      val constrained = delegationWith(valueIn(a))
      val both = childOf(
        constrained,
        Constraints(constrained.constraints.values + Constraint.ValueIn(otherFactKey, nes(b)))
      )
      assertEquals(Delegation.validateChild(constrained, both, parentScopes), Right(both))
    }
  }

  property("NonEmptySet equality and hashCode are structural") {
    forAll(allowlists, allowlists) { (a, b) =>
      val x = nes(a)
      val y = nes(a.toList.reverse.toSet)
      assertEquals(x, y)
      assertEquals(x.hashCode, y.hashCode)
      assertEquals(nes(b) == x, a == b)
      assert(!x.equals(a), "a NonEmptySet is not equal to the Set it wraps")
      assertEquals(NonEmptySet.from(Set.empty[ContextValue]), None)
    }
  }
