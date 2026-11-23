package run.hallpass.kernel

import java.time.Instant
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop.forAll

final class DelegationInvariantsSuite extends ScalaCheckSuite:
  private val at = Instant.parse("2026-09-27T12:00:00Z")
  private val resource = ResourceId.random()
  private val scopes: ResourceId => Option[ResourceScope] = Map(
    resource -> ResourceScope
      .fromPath(Vector(Resource(resource, TenantId.random(), ResourceType.Api, None, "api", custodian = None)))
      .getOrElse(fail("scope"))
  ).get
  private val human = Principal.Human(UserId.random())
  private val agent = Principal.Agent(AgentId.random())
  private val service = Principal.Service(ServiceId.random())
  private val key = CapabilityKey.parse("Slack.Message.Read").getOrElse(fail("static key"))
  private val actionSets = Gen.someOf(Action.values.toSeq).map(_.toSet).suchThat(_.nonEmpty)
  private def capabilities(actions: Set[Action]) =
    NonEmptySet.from(actions.map(CapabilityDescriptor(resource, _, key))).getOrElse(fail("empty capabilities"))
  private def parent(actions: Set[Action], lifetime: Long) =
    Delegation(
      DelegationId.random(),
      human,
      agent,
      None,
      capabilities(actions),
      Constraints.empty,
      at,
      Some(at.plusSeconds(lifetime)),
      None
    )
  private def child(parent: Delegation, actions: Set[Action], expiry: Option[Instant]) =
    parent.copy(
      id = DelegationId.random(),
      grantor = agent,
      grantee = service,
      parent = Some(parent.id),
      capabilities = capabilities(actions),
      expiresAt = expiry
    )

  property("child validation accepts only capabilities within parent authority") {
    forAll(actionSets, actionSets) { (parentActions, childActions) =>
      val grant = parent(parentActions, 60)
      val delegated = child(grant, childActions, grant.expiresAt)
      val result = Delegation.validateChild(grant, delegated, scopes)
      if childActions.subsetOf(parentActions) then assertEquals(result, Right(delegated))
      else assertEquals(result, Left(DelegationValidationError.CapabilityEscalation))
    }
  }

  property("a child cannot remove or extend a finite parent expiry") {
    forAll(actionSets, Gen.chooseNum(1L, 86400L), Gen.chooseNum(1L, 86400L)) { (actions, lifetime, extension) =>
      val grant = parent(actions, lifetime)
      assertEquals(
        Delegation.validateChild(grant, child(grant, actions, None), scopes),
        Left(DelegationValidationError.InvalidValidityWindow)
      )
      assertEquals(
        Delegation.validateChild(grant, child(grant, actions, Some(at.plusSeconds(lifetime + extension))), scopes),
        Left(DelegationValidationError.InvalidValidityWindow)
      )
      val bounded = child(grant, actions, grant.expiresAt)
      assertEquals(Delegation.validateChild(grant, bounded, scopes), Right(bounded))
    }
  }

  property("a child cannot weaken parent context constraints") {
    forAll(actionSets, Gen.alphaNumStr.suchThat(_.nonEmpty)) { (actions, value) =>
      val constraints = Constraints(Set(Constraint.RequireContext(ContextKey("scope"), ContextValue(value))))
      val grant = parent(actions, 60).copy(constraints = constraints)
      val delegated = child(grant, actions, grant.expiresAt)
      assertEquals(Delegation.validateChild(grant, delegated, scopes), Right(delegated))
      assertEquals(
        Delegation.validateChild(grant, delegated.copy(constraints = Constraints.empty), scopes),
        Left(DelegationValidationError.ConstraintEscalation)
      )
    }
  }
