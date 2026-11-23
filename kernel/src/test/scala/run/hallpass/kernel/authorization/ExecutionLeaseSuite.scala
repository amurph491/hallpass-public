package run.hallpass.kernel.authorization

import java.time.Instant
import munit.FunSuite
import run.hallpass.kernel.*

final class ExecutionLeaseSuite extends FunSuite:
  private val localExecutor = ExecutorAudience.parse("test.local.executor").getOrElse(fail("executor"))
  private val otherExecutor = ExecutorAudience.parse("test.other.executor").getOrElse(fail("executor"))
  private val issuedAt = Instant.parse("2026-09-01T12:00:00Z")
  private val tenant = TenantId.random()
  private val grantor = Principal.Human(UserId.random())
  private val principal = Principal.Agent(AgentId.random())
  private val resource =
    Resource(ResourceId.random(), tenant, ResourceType.Provider, None, "slack-workspace", custodian = None)
  private val policyId = PolicyId.random()
  private val delegationId = DelegationId.random()
  private val version = PolicyVersion.from(1).getOrElse(fail("positive policy version"))
  private val key = CapabilityKey.parse("Slack.Message.Read").getOrElse(fail("static key"))
  private val delegatedCapability = CapabilityDescriptor(resource.id, Action.Read, key)
  private val delegation = Delegation(
    delegationId,
    grantor,
    principal,
    None,
    NonEmptySet.one(delegatedCapability),
    Constraints.empty,
    issuedAt.minusSeconds(1),
    None,
    None
  )
  private val policy = Policies(
    Vector(
      Policy(
        policyId,
        version,
        NonEmptySet.one(
          PolicyStatement(grantor, resource.id, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow)
        )
      )
    )
  )
  private val request = AuthorizationRequest(
    AuthorizationRequestId.random(),
    tenant,
    IdentityChain(principal, Vector(delegationId), None, ExecutionContext.LocalProcess),
    ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope")),
    key,
    Action.Read,
    AuthorizationContext.empty
  )

  private val capability = AuthorizationEngine.authorize(policy, request, Vector(delegation), issuedAt) match
    case AuthorizationResult.Authorized(value) => value
    case other                                 => fail(s"expected authorization, received $other")

  private def lease(expiresAt: Instant = issuedAt.plusSeconds(60)): ExecutionLease =
    ExecutionLease
      .issueForBroker(capability, request.id, localExecutor, issuedAt, expiresAt)
      .fold(error => fail(s"expected lease issuance, received $error"), identity)

  test("an expired lease fails validation") {
    assertEquals(
      lease(issuedAt.plusSeconds(1)).validateFor(localExecutor, issuedAt.plusSeconds(1)),
      Left(ExecutionLeaseValidationError.Expired)
    )
  }

  test("a lease validates only for its matching executor audience") {
    val executionLease = lease()

    assertEquals(
      executionLease.validateFor(localExecutor, issuedAt.plusSeconds(1)),
      Right(executionLease)
    )
    assertEquals(
      executionLease.validateFor(otherExecutor, issuedAt.plusSeconds(1)),
      Left(ExecutionLeaseValidationError.WrongAudience)
    )
  }

  test("issued leases preserve the authorized capability and its evidence") {
    val executionLease = lease()

    assertEquals(executionLease.principal, capability.principal)
    assertEquals(executionLease.resource, capability.resource)
    assertEquals(executionLease.capability, key)
    assertEquals(executionLease.action, capability.action)
    assertEquals(executionLease.evidence, capability.evidence)
    assertEquals(executionLease.evidence.policyId, policyId)
    assertEquals(executionLease.evidence.delegationIds, Vector(delegationId))
  }

  test("issuance rejects an empty validity window") {
    assertEquals(
      ExecutionLease.issueForBroker(capability, request.id, localExecutor, issuedAt, issuedAt),
      Left(ExecutionLeaseIssuanceError.InvalidValidityWindow)
    )
  }
