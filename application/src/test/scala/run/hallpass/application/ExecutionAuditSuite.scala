package run.hallpass.application

import java.time.Instant

import cats.effect.IO
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

final class ExecutionAuditSuite extends CatsEffectSuite:
  private val slackReadKey = CapabilityKey.parse("Slack.Message.Read").getOrElse(fail("capability key"))
  private val localExecutor = ExecutorAudience.parse("test.local.executor").getOrElse(fail("executor"))
  private val requestId = AuthorizationRequestId.random()
  private val tenant = TenantId.random()
  private val principal = Principal.Agent(AgentId.random())
  private val resourceId = ResourceId.random()
  private val policyId = PolicyId.random()
  private val delegationId = DelegationId.random()
  private val policyVersion = PolicyVersion.from(1).getOrElse(fail("policy version"))
  private val evidence =
    AuthorizationEvidence(policyId, policyVersion, Vector(delegationId), CapabilityDescriptor(resourceId, Action.Read, slackReadKey))
  private val issuedAt = Instant.parse("2026-09-01T12:00:00Z")
  private val resource = Resource(resourceId, tenant, ResourceType.Provider, None, "audit-resource", None)
  private val resourceScope = ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope"))
  private val request = AuthorizationRequest(
    requestId,
    tenant,
    IdentityChain.direct(principal),
    resourceScope,
    slackReadKey,
    Action.Read,
    AuthorizationContext.empty
  )
  private val capability = AuthorizationEngine.authorize(
    Policies(Vector(Policy(policyId, policyVersion, NonEmptySet.one(
      PolicyStatement(principal, resourceId, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow)
    )))),
    request,
    Vector.empty,
    issuedAt
  ) match
    case AuthorizationResult.Authorized(value) => value
    case other                                 => fail(s"expected authorized capability, received $other")
  private val lease = ExecutionLease
    .issueForBroker(capability, requestId, localExecutor, issuedAt, issuedAt.plusSeconds(60))
    .fold(error => fail(s"lease issuance failed: $error"), identity)
  private val agentId = principal match
    case Principal.Agent(id) => id
    case _                   => fail("agent principal")
  private val operation = OperationId.parse("test.audit.read@1").getOrElse(fail("operation"))
  private val context = ExecutionAuditContext
    .fromLease(
      lease,
      ExecutionAuditMetadata.authenticatedInvocation(
        AuthenticatedAgentContext.authenticated(
          tenant,
          agentId,
          AgentCredentialId.random(),
          issuedAt,
          UnverifiedExecutionClaims.empty
        ),
        ExecutionAuditCorrelationId.parse("execution-audit-suite").getOrElse(fail("correlation")),
        ResourceId.random(),
        CatalogCapabilityId.parse("00000000-0000-4000-8000-000000000003").getOrElse(fail("capability")),
        InvocationBinding.compute(
          tenant,
          agentId,
          operation,
          slackReadKey,
          Action.Read,
          resourceId,
          PipelineProvider.workspace,
          PipelineProvider.externalId("audit-resource"),
          io.circe.Json.obj("query" -> io.circe.Json.fromString("roadmap"))
        )
      )
    )
    .fold(error => fail(s"audit context failed: $error"), identity)

  test("successful execution records issuance, redemption, and completion for one request") {
    val events = Vector(
      ExecutionAuditEvent.LeaseIssued(context, issuedAt),
      ExecutionAuditEvent.LeaseRedeemed(context, issuedAt.plusSeconds(1)),
      ExecutionAuditEvent.ExecutionCompleted(context, issuedAt.plusSeconds(2))
    )

    InMemoryExecutionAuditRecorder.create.flatMap: recorder =>
      events.traverse_(recorder.record) *> recorder.recorded.map: recorded =>
        assertEquals(recorded, events)
        assert(recorded.forall:
          case ExecutionAuditEvent.LeaseIssued(eventContext, _)   => eventContext.authorizationRequestId == requestId
          case ExecutionAuditEvent.LeaseRedeemed(eventContext, _) => eventContext.authorizationRequestId == requestId
          case ExecutionAuditEvent.ExecutionCompleted(eventContext, _) =>
            eventContext.authorizationRequestId == requestId
          case _ => false)
  }

  test("failed redemption records a sanitized denial outcome and no execution event") {
    val denial =
      ExecutionAuditEvent.RedemptionDenied(lease.id, localExecutor, LeaseRedemptionDenial.WrongAudience, issuedAt)

    InMemoryExecutionAuditRecorder.create.flatMap: recorder =>
      recorder.record(denial) *> recorder.recorded.map: recorded =>
        assertEquals(recorded, Vector(denial))
        assertEquals(recorded.collect { case event: ExecutionAuditEvent.ExecutionCompleted => event }, Vector.empty)
        assertEquals(recorded.collect { case event: ExecutionAuditEvent.ExecutionFailed => event }, Vector.empty)
  }

  test("an authorization denial produces no lease lifecycle audit records") {
    InMemoryExecutionAuditRecorder.create
      .flatMap(_.recorded)
      .map: recorded =>
        assertEquals(recorded, Vector.empty)
  }
