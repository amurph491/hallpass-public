package run.hallpass.application

import java.time.Instant

import cats.effect.IO
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

final class InMemoryExecutionLeaseStoreSuite extends CatsEffectSuite:
  private val slackReadKey = CapabilityKey.parse("Slack.Message.Read").getOrElse(fail("capability key"))
  private val localExecutor = ExecutorAudience.parse("test.local.executor").getOrElse(fail("executor"))
  private val otherExecutor = ExecutorAudience.parse("test.other.executor").getOrElse(fail("executor"))
  private val issuedAt = Instant.parse("2026-09-01T12:00:00Z")
  private val expiresAt = issuedAt.plusSeconds(60)
  private val tenant = TenantId.random()
  private val principal = Principal.Agent(AgentId.random())
  private val resource = ResourceId.random()
  private val resourceRecord = Resource(resource, tenant, ResourceType.Provider, None, "slack-workspace", None)
  private val resourceScope = ResourceScope.fromPath(Vector(resourceRecord)).getOrElse(fail("scope"))
  private val policyId = PolicyId.random()
  private val authorizationRequest = AuthorizationRequest(
    AuthorizationRequestId.random(),
    tenant,
    IdentityChain.direct(principal),
    resourceScope,
    slackReadKey,
    Action.Read,
    AuthorizationContext.empty
  )
  private val allowPolicy = Policies(
    Vector(
      Policy(
        policyId,
        PolicyVersion.from(1).getOrElse(fail("positive policy version")),
        NonEmptySet.one(
          PolicyStatement(principal, resource, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow)
        )
      )
    )
  )
  private val authorizedCapability = AuthorizationEngine.authorize(
    allowPolicy,
    authorizationRequest,
    Vector.empty,
    issuedAt
  ) match
    case AuthorizationResult.Authorized(capability) => capability
    case result                                     => fail(s"expected authorized capability, received $result")

  private def lease(expires: Instant = expiresAt, audience: ExecutorAudience = localExecutor): ExecutionLease =
    ExecutionLease
      .issueForBroker(
        authorizedCapability,
        AuthorizationRequestId.random(),
        audience,
        issuedAt,
        expires
      )
      .fold(error => fail(s"could not issue lease: $error"), identity)

  private def context(executionLease: ExecutionLease): ExecutionAuditContext =
    val agentId = executionLease.principal match
      case Principal.Agent(id) => id
      case _                   => fail("test lease must be issued to an agent")
    val correlation = ExecutionAuditCorrelationId.parse("lease-store-test").getOrElse(fail("correlation"))
    val capability = CatalogCapabilityId.parse("00000000-0000-4000-8000-000000000002")
      .getOrElse(fail("catalog capability"))
    val operation = OperationId.parse("test.lease.read@1").getOrElse(fail("operation"))
    ExecutionAuditContext
      .fromLease(
        executionLease,
        ExecutionAuditMetadata.authenticatedInvocation(
          AuthenticatedAgentContext.authenticated(
            tenant,
            agentId,
            AgentCredentialId.random(),
            issuedAt,
            UnverifiedExecutionClaims.empty
          ),
          correlation,
          ResourceId.random(),
          capability,
          InvocationBinding.compute(
            tenant,
            agentId,
            operation,
            slackReadKey,
            Action.Read,
            resource,
            PipelineProvider.workspace,
            PipelineProvider.externalId(resourceRecord.externalId),
            io.circe.Json.obj("query" -> io.circe.Json.fromString("roadmap"))
          )
        )
      )
      .fold(error => fail(s"could not build context: $error"), identity)

  test("an unknown lease is not redeemable") {
    InMemoryExecutionLeaseStore.create
      .flatMap(_.redeem(ExecutionLeaseId.random(), localExecutor, issuedAt))
      .map: result =>
        assertEquals(result, LeaseRedemption.Unknown)
  }

  test("an expired lease is not marked redeemed") {
    val executionLease = lease(expires = issuedAt.plusSeconds(1))
    InMemoryExecutionLeaseStore.create.flatMap: store =>
      store.issue(executionLease, context(executionLease)) *> store
        .redeem(executionLease.id, localExecutor, executionLease.expiresAt)
        .flatMap: first =>
          store
            .redeem(executionLease.id, localExecutor, issuedAt)
            .map: second =>
              assertEquals(first, LeaseRedemption.Expired)
              assert(second match
                case LeaseRedemption.Redeemed(redeemed) => redeemed.id == executionLease.id
                case _                                  => false)
  }

  test("a wrong audience does not redeem a lease") {
    val executionLease = lease()
    InMemoryExecutionLeaseStore.create.flatMap: store =>
      store.issue(executionLease, context(executionLease)) *> store
        .redeem(executionLease.id, otherExecutor, issuedAt)
        .flatMap: wrongAudience =>
          store
            .redeem(executionLease.id, localExecutor, issuedAt)
            .map: matchingAudience =>
              assertEquals(wrongAudience, LeaseRedemption.WrongAudience)
              assert(matchingAudience match
                case LeaseRedemption.Redeemed(redeemed) => redeemed.id == executionLease.id
                case _                                  => false)
  }

  test("a lease can be redeemed once") {
    val executionLease = lease()
    InMemoryExecutionLeaseStore.create.flatMap: store =>
      store.issue(executionLease, context(executionLease)) *> store
        .redeem(executionLease.id, localExecutor, issuedAt)
        .flatMap: first =>
          store
            .redeem(executionLease.id, localExecutor, issuedAt)
            .map: second =>
              assert(first match
                case LeaseRedemption.Redeemed(redeemed) => redeemed.id == executionLease.id
                case _                                  => false)
              assertEquals(second, LeaseRedemption.AlreadyRedeemed)
  }

  test("parallel matching redeemers produce exactly one redemption") {
    val executionLease = lease()
    InMemoryExecutionLeaseStore.create.flatMap: store =>
      store.issue(executionLease, context(executionLease)) *> List
        .fill(64)(store.redeem(executionLease.id, localExecutor, issuedAt))
        .parSequence
        .map: results =>
          assertEquals(results.count(_.isInstanceOf[LeaseRedemption.Redeemed]), 1)
          assertEquals(results.count(_ == LeaseRedemption.AlreadyRedeemed), 63)
  }

  private def clockAt(start: Instant): (java.util.concurrent.atomic.AtomicReference[Instant], Clock[IO]) =
    val current = new java.util.concurrent.atomic.AtomicReference(start)
    current -> new Clock[IO]:
      def now: IO[Instant] = IO(current.get())

  test("expired leases are pruned so memory stays bounded, and pruning never makes a lease redeemable") {
    val (time, clock) = clockAt(issuedAt)
    val first = lease()
    val second = lease()
    for
      store <- InMemoryExecutionLeaseStore.create(clock, java.time.Duration.ofSeconds(10), 10)
      _ <- store.issue(first, context(first))
      _ <- store.issue(second, context(second))
      redeemed <- store.redeem(first.id, localExecutor, issuedAt.plusSeconds(1))
      beforeExpiry <- store.size
      _ <- IO(time.set(expiresAt.plusSeconds(1)))
      third = lease(expires = expiresAt.plusSeconds(120))
      _ <- store.issue(third, context(third))
      afterPrune <- store.size
      replayed <- store.redeem(first.id, localExecutor, expiresAt.plusSeconds(1))
      unredeemed <- store.redeem(second.id, localExecutor, expiresAt.plusSeconds(1))
    yield
      assert(redeemed.isInstanceOf[LeaseRedemption.Redeemed])
      assertEquals(beforeExpiry, 2)
      assertEquals(afterPrune, 1)
      assertEquals(replayed, LeaseRedemption.Unknown)
      assertEquals(unredeemed, LeaseRedemption.Unknown)
  }

  test("pruning is rate-limited to the configured interval") {
    val (time, clock) = clockAt(issuedAt)
    val early = lease(expires = issuedAt.plusSeconds(1))
    for
      store <- InMemoryExecutionLeaseStore.create(clock, java.time.Duration.ofSeconds(30), 10)
      _ <- store.issue(early, context(early))
      _ <- IO(time.set(issuedAt.plusSeconds(5)))
      next = lease()
      _ <- store.issue(next, context(next))
      retained <- store.size
      expiredRedemption <- store.redeem(early.id, localExecutor, issuedAt.plusSeconds(5))
    yield
      assertEquals(retained, 2)
      assertEquals(expiredRedemption, LeaseRedemption.Expired)
  }

  test("a full store refuses issuance instead of growing without bound") {
    val (_, clock) = clockAt(issuedAt)
    val leases = Vector.fill(3)(lease())
    for
      store <- InMemoryExecutionLeaseStore.create(clock, java.time.Duration.ofSeconds(10), 2)
      _ <- store.issue(leases(0), context(leases(0)))
      _ <- store.issue(leases(1), context(leases(1)))
      overflow <- store.issue(leases(2), context(leases(2))).attempt
      reissue <- store.issue(leases(0), context(leases(0))).attempt
      size <- store.size
      refused <- store.redeem(leases(2).id, localExecutor, issuedAt.plusSeconds(1))
    yield
      assertEquals(overflow, Left(ExecutionLeaseStoreFull()))
      assertEquals(reissue, Right(()))
      assertEquals(size, 2)
      assertEquals(refused, LeaseRedemption.Unknown)
  }

  test("a lease issued by one instance's store is unknown to another instance, so it fails closed") {
    val issued = lease()
    for
      issuingInstance <- InMemoryExecutionLeaseStore.create
      otherInstance <- InMemoryExecutionLeaseStore.create
      _ <- issuingInstance.issue(issued, context(issued))
      elsewhere <- otherInstance.redeem(issued.id, localExecutor, issuedAt.plusSeconds(1))
      local <- issuingInstance.redeem(issued.id, localExecutor, issuedAt.plusSeconds(1))
    yield
      assertEquals(elsewhere, LeaseRedemption.Unknown)
      assert(local.isInstanceOf[LeaseRedemption.Redeemed])
  }
