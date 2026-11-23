package run.hallpass.application

import java.time.{Duration, Instant}
import java.util.concurrent.atomic.AtomicInteger
import cats.effect.IO
import cats.effect.kernel.Ref
import cats.syntax.all.*
import io.circe.Json
import munit.CatsEffectSuite
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Approvals at the pipeline: a REQUIRE_APPROVAL policy creates a pending approval bound to the exact invocation; a retry
  * carrying the approved ID runs once, and nothing else (changed arguments, another agent, expiry, revocation, a new
  * policy version, a lost race) can use it. */
final class AgentApprovalFlowSuite extends CatsEffectSuite:
  import PipelineProvider.given

  private val key = PipelineProvider.capabilityKey("Test.Message.Read")
  private val tenant = TenantId.random()
  private val agentId = AgentId.random()
  private val agent = Principal.Agent(agentId)
  private val human: Principal.Human = Principal.Human(UserId.random())
  private val otherHuman: Principal.Human = Principal.Human(UserId.random())
  private val tool = PipelineProvider.toolId("test_search_messages")
  private val operationId = PipelineProvider.operationId("test.search.messages@1")
  private val at = Instant.parse("2026-09-20T12:00:00Z")
  private val ttl = Duration.ofMinutes(15)
  private val arguments = Json.obj("query" -> Json.fromString("from:alex roadmap"))
  private val changedArguments = Json.obj("query" -> Json.fromString("from:alex payroll"))
  private val query = SearchQuery.parse("from:alex roadmap").getOrElse(fail("query"))
  private val rootExternalId = PipelineProvider.externalId("workspace")
  private val resource = Resource(ResourceId.random(), tenant, ResourceType.Provider, None, rootExternalId.value, None)
  private val resourceScope = ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope"))
  private val descriptor = CapabilityDescriptor(resource.id, Action.Read, key)
  private val capability = CatalogCapability("00000000-0000-4000-8000-000000000005", "Test.Message.Read", descriptor)
  private val catalogTool = ResourceId.random()
  private val delegation = Delegation(
    DelegationId.random(), human, agent, None, NonEmptySet.one(descriptor), Constraints.empty, Instant.EPOCH, None, None
  )
  private val policyId = PolicyId.random()
  private val operation = PipelineOperation[PipelineProvider.Workspace](
    operationId, tool, PipelineProvider.workspace, ResourceLocator.ConnectionRoot()
  )

  private def version(n: Int) = PolicyVersion.from(n).getOrElse(fail("version"))
  private def policy(effect: Effect, v: Int = 1) = Policies(
    Vector(
      Policy(
        policyId, version(v),
        NonEmptySet.one(PolicyStatement(human, resource.id, NonEmptySet.one(Action.Read), None, Constraints.empty, effect))
      )
    )
  )
  private def authenticatedAs(id: AgentId) =
    AuthenticatedAgentContext.authenticated(tenant, id, AgentCredentialId.random(), at, UnverifiedExecutionClaims.empty)
  private def authenticated = authenticatedAs(agentId)

  /** A faithful in-memory port: every transition is one atomic `Ref` update, so single-use consume has one winner. */
  private final class InMemoryApprovalStore(records: Ref[IO, Map[ApprovalId, ApprovalRecord]]) extends ApprovalStore:
    var consumeAttempts = new AtomicInteger(0)
    def create(record: ApprovalRecord) = records.update(_ + (record.id -> record))
    def find(t: TenantId, id: ApprovalId) = records.get.map(_.get(id).filter(_.tenant == t))
    def pendingFor(t: TenantId, approver: Principal.Human, now: Instant, limit: Int) =
      records.get.map(
        _.values.filter(r => r.tenant == t && r.approver == approver && r.status == ApprovalStatus.Pending && now.isBefore(r.expiresAt))
          .toVector.sortBy(_.requestedAt)(using Ordering[Instant].reverse).take(limit)
      )
    def decide(t: TenantId, id: ApprovalId, approver: Principal.Human, approve: Boolean, now: Instant) =
      records.modify: all =>
        all.get(id).filter(_.tenant == t) match
          case None => all -> Left(ApprovalDecisionError.NotFound)
          case Some(r) if r.approver != approver => all -> Left(ApprovalDecisionError.NotApprover)
          case Some(r) if r.status != ApprovalStatus.Pending => all -> Left(ApprovalDecisionError.AlreadyDecided)
          case Some(r) if !now.isBefore(r.expiresAt) => all -> Left(ApprovalDecisionError.Expired)
          case Some(r) =>
            val decided = r.copy(status = if approve then ApprovalStatus.Approved else ApprovalStatus.Denied, decidedAt = Some(now))
            (all + (id -> decided)) -> Right(decided)
    def consume(t: TenantId, id: ApprovalId, a: AgentId, binding: ApprovalBinding, request: AuthorizationRequestId, now: Instant) =
      IO.delay(consumeAttempts.incrementAndGet()) *> records.modify: all =>
        all.get(id) match
          case Some(r)
              if r.tenant == t && r.agent == a && r.binding == binding && r.status == ApprovalStatus.Approved &&
                r.consumedAt.isEmpty && now.isBefore(r.expiresAt) =>
            (all + (id -> r.copy(consumedAt = Some(now)))) -> true
          case _ => all -> false
    def record(id: ApprovalId): IO[ApprovalRecord] = find(tenant, id).map(_.getOrElse(fail("approval missing")))
    def all: IO[Vector[ApprovalRecord]] = records.get.map(_.values.toVector)

  private final class CountingClient extends ProviderOperationClient[SearchQuery, PipelineProvider.Workspace, Unit]:
    val calls = new AtomicInteger(0)
    def dispatch(target: SelectedResource[PipelineProvider.Workspace], input: SearchQuery, credential: Unit): IO[ToolResult] =
      IO.delay { calls.incrementAndGet(); ToolResult("provider-result") }

  private final class Fixture(
      val service: AgentToolService,
      val store: InMemoryApprovalStore,
      val authority: Ref[IO, AuthoritySnapshot],
      val journal: Ref[IO, Vector[AuthorizationEvent]],
      val audit: InMemoryExecutionAuditRecorder,
      val client: CountingClient,
      val credentials: PipelineCredentials[PipelineProvider.Workspace]
  ):
    def leases: IO[Int] = audit.recorded.map(_.count(_.isInstanceOf[ExecutionAuditEvent.LeaseIssued]))
    def noLease: IO[Unit] = leases.map(assertEquals(_, 0, "no lease may be issued"))
    def run(arg: Json = arguments, id: Option[ApprovalId] = None, now: Instant = at, as: AuthenticatedAgentContext = authenticated) =
      service.execute(as, operationId, arg, now, id)

  private def snapshot(policies: Policies, delegations: Vector[Delegation] = Vector(delegation)) =
    AuthoritySnapshot(resourceScope, capability, policies, delegations, Some(catalogTool))

  private def fixture(
      policies: Policies = policy(Effect.RequireApproval),
      wrap: ApprovalStore => ApprovalStore = identity
  ): IO[Fixture] =
    for
      events <- Ref.of[IO, Vector[AuthorizationEvent]](Vector.empty)
      current <- Ref.of[IO, AuthoritySnapshot](snapshot(policies))
      records <- Ref.of[IO, Map[ApprovalId, ApprovalRecord]](Map.empty)
      clock = Clock.fixed(at)
      leaseStore <- InMemoryExecutionLeaseStore.create(clock, InMemoryExecutionLeaseStore.DefaultPruneInterval, 100)
      audit <- InMemoryExecutionAuditRecorder.create
      gate <- SingleProcessTenantExecutionMutationGate.create
      store = new InMemoryApprovalStore(records)
      catalog = new ResourceCatalog:
        def rootScope(t: TenantId, kind: ResourceKind[?]) = IO.pure(Some(rootExternalId -> resourceScope))
        def selectedScope(t: TenantId, kind: ResourceKind[?], externalId: ExternalId) = IO.pure(None)
        def currentScope(t: TenantId, resourceId: ResourceId) = IO.pure(Some(resourceScope).filter(_.target.id == resourceId))
      repository = new AuthorityRepository[IO]:
        def snapshotFor(t: TenantId, principal: Principal, externalTool: String) = current.get.map(Right(_))
        def snapshotWithin(t: TenantId, principal: Principal, externalTool: String, scope: ResourceScope) =
          current.get.map(Right(_))
      journal = new AuthorizationJournal[IO]:
        def record(t: TenantId, event: AuthorizationEvent) = events.update(_ :+ event)
        def recent(t: TenantId, limit: Int) = IO.pure(Vector.empty)
      client = new CountingClient
      credentials = new PipelineCredentials[PipelineProvider.Workspace]()
      registry = OperationRegistry
        .from(Vector(RegisteredOperation(operation, client, credentials)))
        .fold(error => fail(s"registry: $error"), identity)
      allow = new LeaseAuthorityValidator[IO]:
        def validate(lease: RedeemedExecutionLease, now: Instant) = IO.pure(Right(()))
      executor = ProviderExecutionService(leaseStore, clock, audit, allow, gate)
      broker = InMemoryCredentialBroker(leaseStore, clock, Duration.ofSeconds(60), audit)
      service = AgentToolService(registry, ResourceResolver(catalog), repository, journal, broker, executor, approvals = wrap(store), approvalTtl = ttl)
    yield Fixture(service, store, current, events, audit, client, credentials)

  private def requested(f: Fixture): IO[ApprovalRecord] =
    f.run().flatMap:
      case AgentToolExecutionResult.ApprovalRequired(_, _, Some(record)) => IO.pure(record)
      case other => IO.raiseError(AssertionError(s"expected an approval request, received $other"))

  private def approved(f: Fixture): IO[ApprovalRecord] =
    requested(f).flatMap: record =>
      f.store.decide(tenant, record.id, human, approve = true, at.plusSeconds(60)).flatMap:
        case Right(decided) => IO.pure(decided)
        case Left(error) => IO.raiseError(AssertionError(s"approval refused: $error"))

  private def assertMismatch(result: AgentToolExecutionResult, clue: String = ""): Unit =
    result match
      case AgentToolExecutionResult.Denied(_, DenialReason.ApprovalMismatch) => ()
      case other => fail(s"$clue expected Denied(ApprovalMismatch), received $other")

  private val later = at.plusSeconds(120)

  test("the first call returns a pending approval bound to the exact invocation, with no lease or provider call") {
    for
      f <- fixture()
      result <- f.run()
      records <- f.store.all
      _ <- f.noLease
    yield
      val target = SelectedResource.trusted(PipelineProvider.workspace, rootExternalId, resourceScope)
      val digest = InvocationBinding.of(tenant, agentId, operation, target, query).digest.value
      result match
        case AgentToolExecutionResult.ApprovalRequired(_, required, Some(record)) =>
          assertEquals(records, Vector(record))
          assertEquals(record.status, ApprovalStatus.Pending)
          assertEquals(record.binding.value, digest)
          assertEquals(record.approver, human)
          assertEquals(record.agent, agentId)
          assertEquals(record.tenant, tenant)
          assertEquals(record.preview, operation.canonical(query))
          assertEquals(record.requestedAt, at)
          assertEquals(record.expiresAt, at.plus(ttl))
          assertEquals(record.requiredCapability, required.requiredCapability)
          assertEquals((record.policyId, record.policyVersion), (required.policyId, required.policyVersion))
          assertEquals((record.decidedAt, record.consumedAt), (None, None))
        case other => fail(s"expected approval request, received $other")
      assertEquals(f.client.calls.get, 0)
      assertEquals(f.credentials.resolutions, Vector.empty)
  }

  test("retrying with the id before approval returns the same pending approval, with no lease and no new record") {
    for
      f <- fixture()
      record <- requested(f)
      result <- f.run(id = Some(record.id), now = later)
      after <- f.store.record(record.id)
      records <- f.store.all
      _ <- f.noLease
    yield
      result match
        case AgentToolExecutionResult.ApprovalRequired(_, _, Some(same)) => assertEquals(same.id, record.id)
        case other => fail(s"expected the same pending approval, got $other")
      assertEquals(after.status, ApprovalStatus.Pending)
      assertEquals(f.client.calls.get, 0)
      assertEquals(records.size, 1, "an early retry never creates a new approval")
  }

  test("after approval the retry completes once and consumes the record; a second retry is denied") {
    for
      f <- fixture()
      record <- approved(f)
      first <- f.run(id = Some(record.id), now = later)
      consumed <- f.store.record(record.id)
      second <- f.run(id = Some(record.id), now = later)
      leases <- f.leases
    yield
      first match
        case AgentToolExecutionResult.Completed(snapshot, ToolResult("provider-result")) =>
          snapshot.result match
            case AuthorizationResult.Authorized(authorized) => assertEquals(authorized.evidence.approval, Some(record.id))
            case other => fail(s"expected authorized, received $other")
        case other => fail(s"expected completion, received $other")
      assertEquals(consumed.consumedAt, Some(later))
      assertMismatch(second, "second use")
      assertEquals(f.client.calls.get, 1)
      assertEquals(leases, 1)
  }

  test("a retry with changed arguments is denied and does not consume the approval") {
    for
      f <- fixture()
      record <- approved(f)
      result <- f.run(arg = changedArguments, id = Some(record.id), now = later)
      after <- f.store.record(record.id)
      _ <- f.noLease
    yield
      assertMismatch(result)
      assertEquals(after.consumedAt, None)
      assertEquals(f.client.calls.get, 0)
  }

  test("a changed-argument attempt leaves the original approval usable for the approved arguments") {
    for
      f <- fixture()
      record <- approved(f)
      _ <- f.run(arg = changedArguments, id = Some(record.id), now = later)
      result <- f.run(id = Some(record.id), now = later)
    yield
      assert(result.isInstanceOf[AgentToolExecutionResult.Completed], s"received $result")
      assertEquals(f.client.calls.get, 1)
  }

  test("another agent cannot use the approval") {
    val other = AgentId.random()
    for
      f <- fixture()
      record <- approved(f)
      result <- f.run(id = Some(record.id), now = later, as = authenticatedAs(other))
      after <- f.store.record(record.id)
      _ <- f.noLease
    yield
      assert(result.isInstanceOf[AgentToolExecutionResult.Denied], s"received $result")
      assertMismatch(result)
      assertEquals(after.consumedAt, None)
      assertEquals(f.client.calls.get, 0)
  }

  test("an expired approval is denied and not consumed, including at exactly its expiry") {
    for
      f <- fixture()
      record <- approved(f)
      atExpiry <- f.run(id = Some(record.id), now = record.expiresAt)
      afterExpiry <- f.run(id = Some(record.id), now = record.expiresAt.plusSeconds(1))
      after <- f.store.record(record.id)
      _ <- f.noLease
    yield
      assertMismatch(atExpiry, "at expiry")
      assertMismatch(afterExpiry, "after expiry")
      assertEquals(after.consumedAt, None)
      assertEquals(f.client.calls.get, 0)
  }

  test("a denied approval cannot be used") {
    for
      f <- fixture()
      record <- requested(f)
      decided <- f.store.decide(tenant, record.id, human, approve = false, at.plusSeconds(60))
      result <- f.run(id = Some(record.id), now = later)
      _ <- f.noLease
    yield
      assertEquals(decided.map(_.status), Right(ApprovalStatus.Denied))
      assertMismatch(result)
      assertEquals(f.client.calls.get, 0)
  }

  test("only the root human can decide an approval; another human cannot approve it") {
    for
      f <- fixture()
      record <- requested(f)
      wrong <- f.store.decide(tenant, record.id, otherHuman, approve = true, at.plusSeconds(60))
      result <- f.run(id = Some(record.id), now = later)
    yield
      assertEquals(wrong, Left(ApprovalDecisionError.NotApprover))
      // The refused decision left it pending, so the retry is told the same approval is still required.
      result match
        case AgentToolExecutionResult.ApprovalRequired(_, _, Some(same)) => assertEquals(same.id, record.id)
        case other => fail(s"expected the same pending approval, got $other")
      assertEquals(f.client.calls.get, 0)
  }

  test("revoking the delegation after approval denies the retry with the revocation reason and keeps the approval") {
    for
      f <- fixture()
      record <- approved(f)
      _ <- f.authority.set(snapshot(policy(Effect.RequireApproval), Vector(delegation.copy(revokedAt = Some(at.plusSeconds(90))))))
      result <- f.run(id = Some(record.id), now = later)
      after <- f.store.record(record.id)
      _ <- f.noLease
    yield
      result match
        case AgentToolExecutionResult.Denied(_, DenialReason.InactiveDelegation(id)) => assertEquals(id, delegation.id)
        case other => fail(s"expected the revocation denial, received $other")
      assertEquals(after.consumedAt, None)
      assertEquals(f.store.consumeAttempts.get, 0)
      assertEquals(f.client.calls.get, 0)
  }

  test("a new policy version after approval invalidates it") {
    for
      f <- fixture()
      record <- approved(f)
      _ <- f.authority.set(snapshot(policy(Effect.RequireApproval, v = 2)))
      result <- f.run(id = Some(record.id), now = later)
      after <- f.store.record(record.id)
      _ <- f.noLease
    yield
      assertMismatch(result)
      assertEquals(after.consumedAt, None)
      assertEquals(f.client.calls.get, 0)
  }

  test("an unknown approval id is a mismatch and never becomes a new approval") {
    for
      f <- fixture()
      result <- f.run(id = Some(ApprovalId.random()), now = later)
      records <- f.store.all
      _ <- f.noLease
    yield
      assertMismatch(result)
      assertEquals(records, Vector.empty)
      assertEquals(f.client.calls.get, 0)
  }

  test("an approval id presented under an ALLOW policy completes and is not consumed") {
    for
      f <- fixture()
      record <- approved(f)
      _ <- f.authority.set(snapshot(policy(Effect.Allow)))
      result <- f.run(id = Some(record.id), now = later)
      after <- f.store.record(record.id)
    yield
      result match
        case AgentToolExecutionResult.Completed(snapshot, _) =>
          snapshot.result match
            case AuthorizationResult.Authorized(authorized) => assertEquals(authorized.evidence.approval, None)
            case other => fail(s"expected authorized, received $other")
        case other => fail(s"expected completion, received $other")
      assertEquals(after.consumedAt, None)
      assertEquals(f.store.consumeAttempts.get, 0)
      assertEquals(f.client.calls.get, 1)
  }

  test("an approval id presented under a DENY policy stays denied for the policy reason and is not consumed") {
    for
      f <- fixture()
      record <- approved(f)
      _ <- f.authority.set(snapshot(policy(Effect.Deny)))
      result <- f.run(id = Some(record.id), now = later)
      after <- f.store.record(record.id)
    yield
      result match
        case AgentToolExecutionResult.Denied(_, DenialReason.ExplicitDeny(id, _)) => assertEquals(id, policyId)
        case other => fail(s"expected explicit denial, received $other")
      assertEquals(after.consumedAt, None)
      assertEquals(f.client.calls.get, 0)
  }

  test("concurrent retries with one approved id yield exactly one completion and one provider call") {
    for
      f <- fixture()
      record <- approved(f)
      results <- List.fill(16)(f.run(id = Some(record.id), now = later)).parSequence
      after <- f.store.record(record.id)
      leases <- f.leases
    yield
      assertEquals(results.count(_.isInstanceOf[AgentToolExecutionResult.Completed]), 1)
      results.filterNot(_.isInstanceOf[AgentToolExecutionResult.Completed]).foreach(assertMismatch(_, "loser"))
      assertEquals(f.client.calls.get, 1)
      assertEquals(leases, 1)
      assertEquals(after.consumedAt, Some(later))
  }

  test("every decision is journaled with its final result, including a consume that loses the race") {
    for
      f <- fixture()
      record <- approved(f)
      before <- f.journal.get
      winner <- f.run(id = Some(record.id), now = later)
      loser <- f.run(id = Some(record.id), now = later)
      events <- f.journal.get
    yield
      // requested (1) + the retry that completed + the retry that lost, in order
      assertEquals(before.size, 1)
      assertEquals(events.size, 3)
      assert(events(0).result.isInstanceOf[AuthorizationResult.ApprovalRequired])
      (winner, events(1).result) match
        case (AgentToolExecutionResult.Completed(snapshot, _), AuthorizationResult.Authorized(authorized)) =>
          assertEquals(events(1).requestId, snapshot.requestId)
          assertEquals(authorized.evidence.approval, Some(record.id))
        case other => fail(s"unexpected winner journal $other")
      assertEquals(events(2).result, AuthorizationResult.Denied(DenialReason.ApprovalMismatch))
      loser match
        case AgentToolExecutionResult.Denied(snapshot, DenialReason.ApprovalMismatch) =>
          assertEquals(events(2).requestId, snapshot.requestId)
        case other => fail(s"expected denial, received $other")
  }

  test("a consume that loses after the kernel accepted is journaled as denied and runs nothing") {
    // A competing instance consumes between the service's find and its consume.
    def racing(base: ApprovalStore): ApprovalStore = new ApprovalStore:
      def create(r: ApprovalRecord) = base.create(r)
      def find(t: TenantId, id: ApprovalId) = base.find(t, id)
      def pendingFor(t: TenantId, a: Principal.Human, now: Instant, limit: Int) = base.pendingFor(t, a, now, limit)
      def decide(t: TenantId, id: ApprovalId, a: Principal.Human, approve: Boolean, now: Instant) =
        base.decide(t, id, a, approve, now)
      def consume(t: TenantId, id: ApprovalId, a: AgentId, b: ApprovalBinding, r: AuthorizationRequestId, now: Instant) =
        base.consume(t, id, a, b, r, now) *> base.consume(t, id, a, b, r, now)
    for
      g <- fixture(wrap = racing)
      record <- approved(g)
      result <- g.run(id = Some(record.id), now = later)
      events <- g.journal.get
    yield
      assertMismatch(result)
      assertEquals(events.lastOption.map(_.result), Some(AuthorizationResult.Denied(DenialReason.ApprovalMismatch)))
      assertEquals(g.client.calls.get, 0)
  }
