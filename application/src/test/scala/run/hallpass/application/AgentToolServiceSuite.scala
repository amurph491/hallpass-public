package run.hallpass.application

import java.time.{Duration, Instant}
import cats.effect.IO
import cats.effect.kernel.Ref
import cats.syntax.all.*
import io.circe.Json
import munit.CatsEffectSuite
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** The generic agent pipeline: decode, resolve, authorize, lease, execute. Each negative test pins the step at which
  * the call stops and shows that nothing later (authority load, lease, credential, provider request) ran. */
final class AgentToolServiceSuite extends CatsEffectSuite:
  import PipelineProvider.given

  private val slackReadKey = PipelineProvider.capabilityKey("Test.Message.Read")
  private val tenant = TenantId.random()
  private val agentId = AgentId.random()
  private val agent = Principal.Agent(agentId)
  private val human = Principal.Human(UserId.random())
  private val credentialId = AgentCredentialId.random()
  private val tool = PipelineProvider.toolId("test_search_messages")
  private val operationId = PipelineProvider.operationId("test.search.messages@1")
  private val at = Instant.parse("2026-09-20T12:00:00Z")
  private val arguments = Json.obj("query" -> Json.fromString("from:alex roadmap"))
  private val query = SearchQuery.parse("from:alex roadmap").getOrElse(fail("query"))
  private val rootExternalId = PipelineProvider.externalId("workspace")
  private val resource = Resource(ResourceId.random(), tenant, ResourceType.Provider, None, rootExternalId.value, None)
  private val resourceScope = ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope"))
  private val descriptor = CapabilityDescriptor(resource.id, Action.Read, slackReadKey)
  private val capability = CatalogCapability("00000000-0000-4000-8000-000000000005", "Test.Message.Read", descriptor)
  private val catalogTool = ResourceId.random()
  private val delegation = Delegation(
    DelegationId.random(),
    human,
    agent,
    None,
    NonEmptySet.one(descriptor),
    Constraints.empty,
    Instant.EPOCH,
    None,
    None
  )
  private val operation = PipelineOperation[PipelineProvider.Workspace](
    operationId,
    tool,
    PipelineProvider.workspace,
    ResourceLocator.ConnectionRoot()
  )

  private def authenticated =
    AuthenticatedAgentContext.authenticated(tenant, agentId, credentialId, at, UnverifiedExecutionClaims.empty)

  private def policy(effect: Effect) = Policies(
    Vector(
      Policy(
        PolicyId.random(),
        PolicyVersion.from(1).getOrElse(fail("version")),
        NonEmptySet.one(PolicyStatement(human, resource.id, NonEmptySet.one(Action.Read), None, Constraints.empty, effect))
      )
    )
  )

  private def snapshot(
      policies: Policies = policy(Effect.Allow),
      mapped: CatalogCapability = capability
  ): AuthoritySnapshot = AuthoritySnapshot(resourceScope, mapped, policies, Vector(delegation), Some(catalogTool))

  private final class Catalog(root: Option[(ExternalId, ResourceScope)]) extends ResourceCatalog:
    var rootCalls = Vector.empty[(TenantId, String)]
    var selectedCalls = 0
    def rootScope(t: TenantId, kind: ResourceKind[?]): IO[Option[(ExternalId, ResourceScope)]] =
      IO.delay:
        rootCalls = rootCalls :+ (t -> kind.wire)
        root
    def selectedScope(t: TenantId, kind: ResourceKind[?], externalId: ExternalId): IO[Option[ResourceScope]] =
      IO.delay:
        selectedCalls += 1
        None
    def currentScope(t: TenantId, resourceId: ResourceId): IO[Option[ResourceScope]] =
      IO.pure(Some(resourceScope).filter(_.target.id == resourceId))

  private final class RecordingAuthority(result: Either[AuthorityLoadError, AuthoritySnapshot])
      extends AuthorityRepository[IO]:
    var unscopedCalls = Vector.empty[(TenantId, Principal, String)]
    var scopedCalls = Vector.empty[(TenantId, Principal, String, ResourceScope)]
    def snapshotFor(t: TenantId, principal: Principal, externalTool: String) =
      IO.delay:
        unscopedCalls = unscopedCalls :+ (t, principal, externalTool)
        result
    def snapshotWithin(t: TenantId, principal: Principal, externalTool: String, scope: ResourceScope) =
      IO.delay:
        scopedCalls = scopedCalls :+ (t, principal, externalTool, scope)
        result
    def loads: Int = unscopedCalls.size + scopedCalls.size

  /** Issues real leases (so the audit context and binding are the production ones) and remembers each request. */
  private final class RecordingBroker(delegate: CredentialBroker[IO]) extends CredentialBroker[IO]:
    var requestIds = Vector.empty[AuthorizationRequestId]
    def issueLease(
        authorized: AuthorizedCapability,
        requestId: AuthorizationRequestId,
        requestedAudience: ExecutorAudience,
        auditMetadata: ExecutionAuditMetadata
    ): IO[ExecutionLease] =
      IO.delay { requestIds = requestIds :+ requestId } *>
        delegate.issueLease(authorized, requestId, requestedAudience, auditMetadata)

  private object AllowCurrentState extends LeaseAuthorityValidator[IO]:
    def validate(lease: RedeemedExecutionLease, now: Instant) = IO.pure(Right(()))

  private final class Fixture(
      val catalog: Catalog,
      val authority: RecordingAuthority,
      val journalEvents: Ref[IO, Vector[AuthorizationEvent]],
      val broker: RecordingBroker,
      val audit: InMemoryExecutionAuditRecorder,
      val client: PipelineClient[PipelineProvider.Workspace],
      val credentials: PipelineCredentials[PipelineProvider.Workspace],
      val service: AgentToolService
  )

  private def fixture(
      authorityResult: Either[AuthorityLoadError, AuthoritySnapshot] = Right(snapshot()),
      root: Option[(ExternalId, ResourceScope)] = Some(rootExternalId -> resourceScope)
  ): IO[Fixture] =
    for
      events <- Ref.of[IO, Vector[AuthorizationEvent]](Vector.empty)
      clock = Clock.fixed(at)
      store <- InMemoryExecutionLeaseStore.create(clock, InMemoryExecutionLeaseStore.DefaultPruneInterval, 100)
      audit <- InMemoryExecutionAuditRecorder.create
      gate <- SingleProcessTenantExecutionMutationGate.create
      catalog = new Catalog(root)
      authority = new RecordingAuthority(authorityResult)
      journal = new AuthorizationJournal[IO]:
        def record(t: TenantId, event: AuthorizationEvent) = events.update(_ :+ event)
        def recent(t: TenantId, limit: Int) = IO.pure(Vector.empty)
      broker = new RecordingBroker(InMemoryCredentialBroker(store, clock, Duration.ofSeconds(60), audit))
      client = new PipelineClient[PipelineProvider.Workspace]()
      credentials = new PipelineCredentials[PipelineProvider.Workspace]()
      registered = RegisteredOperation(operation, client, credentials)
      registry = OperationRegistry.from(Vector(registered)).fold(error => fail(s"registry: $error"), identity)
      executor = ProviderExecutionService(store, clock, audit, AllowCurrentState, gate)
      service = AgentToolService(registry, ResourceResolver(catalog), authority, journal, broker, executor)
    yield Fixture(catalog, authority, events, broker, audit, client, credentials, service)

  private def untouched(f: Fixture): IO[Unit] =
    f.audit.recorded.map: recorded =>
      assertEquals(f.broker.requestIds, Vector.empty, "no lease may be issued")
      assertEquals(f.credentials.resolutions, Vector.empty, "no credential may be resolved")
      assertEquals(f.client.dispatches, Vector.empty, "no provider request may be sent")
      assertEquals(recorded, Vector.empty, "no execution lifecycle event may be recorded")

  test("an authorized call decodes, resolves, journals once, issues a bound lease, and completes") {
    for
      f <- fixture()
      result <- f.service.execute(authenticated, operationId, arguments, at)
      recorded <- f.journalEvents.get
      audit <- f.audit.recorded
    yield
      val target = SelectedResource.trusted(PipelineProvider.workspace, rootExternalId, resourceScope)
      val expectedBinding = InvocationBinding.of(tenant, agentId, operation, target, query)
      result match
        case AgentToolExecutionResult.Completed(snapshot, ToolResult("provider-result")) =>
          // One server request ID is shared by the journal, the lease, and the audit context.
          assertEquals(recorded.map(_.requestId), Vector(snapshot.requestId))
          assertEquals(recorded.map(_.correlationId), Vector(snapshot.correlationId))
          assertEquals(recorded.map(_.resource), Vector(Some(resource.id)))
          assertEquals(f.broker.requestIds, Vector(snapshot.requestId))
          val issued = audit.collect { case ExecutionAuditEvent.LeaseIssued(context, _) => context }
          assertEquals(issued.map(_.authorizationRequestId), Vector(snapshot.requestId))
          issued.head match
            case context: AuthenticatedExecutionAuditContext =>
              assertEquals(context.binding, expectedBinding)
              assertEquals(context.agentId, agentId)
              assertEquals(context.tenant, tenant)
        case other => fail(s"expected completed result, received $other")
      assertEquals(audit.collect { case _: ExecutionAuditEvent.LeaseRedeemed => 1 }.size, 1)
      assertEquals(audit.collect { case _: ExecutionAuditEvent.ExecutionCompleted => 1 }.size, 1)
      assertEquals(f.catalog.rootCalls, Vector(tenant -> "testprov.workspace"))
      assertEquals(f.authority.scopedCalls, Vector((tenant, agent, tool.value, resourceScope)))
      assertEquals(f.authority.unscopedCalls, Vector.empty)
      // The typed input and the resolved resource that were authorized are what reached the provider.
      assertEquals(f.client.dispatches, Vector(target -> query))
  }

  test("an unknown operation is reported before any resolution, authority load, or journal row") {
    for
      f <- fixture()
      result <- f.service.execute(authenticated, PipelineProvider.operationId("test.other.operation@1"), arguments, at)
      recorded <- f.journalEvents.get
      _ <- untouched(f)
    yield
      assertEquals(result, AgentToolExecutionResult.UnknownOperation)
      assertEquals(recorded, Vector.empty)
      assertEquals(f.catalog.rootCalls, Vector.empty)
      assertEquals(f.authority.loads, 0)
  }

  test("a different version of a registered operation is unknown") {
    for
      f <- fixture()
      result <- f.service.execute(authenticated, PipelineProvider.operationId("test.search.messages@2"), arguments, at)
      _ <- untouched(f)
    yield
      assertEquals(result, AgentToolExecutionResult.UnknownOperation)
      assertEquals(f.authority.loads, 0)
  }

  test("arguments that fail decoding are invalid, with no resolver call, authority load, or journal row") {
    val invalid = Vector(
      Json.fromString("not an object") -> ArgumentError.NotAnObject,
      Json.obj() -> ArgumentError.MissingField("query"),
      Json.obj("query" -> Json.fromString("   ")) -> ArgumentError.InvalidField("query"),
      Json.obj("query" -> Json.fromInt(3)) -> ArgumentError.InvalidField("query"),
      Json.obj("query" -> Json.fromString("roadmap"), "connection_id" -> Json.fromString("x")) ->
        ArgumentError.UnexpectedField
    )
    for
      f <- fixture()
      results <- invalid.traverse(sample => f.service.execute(authenticated, operationId, sample._1, at))
      recorded <- f.journalEvents.get
      _ <- untouched(f)
    yield
      assertEquals(results, invalid.map(sample => AgentToolExecutionResult.InvalidArguments(sample._2)))
      assertEquals(recorded, Vector.empty)
      assertEquals(f.catalog.rootCalls, Vector.empty)
      assertEquals(f.authority.loads, 0)
  }

  test("a resolver denial is journaled as ResourceNotSelected with no authority load or lease") {
    for
      f <- fixture(root = None)
      result <- f.service.execute(authenticated, operationId, arguments, at)
      recorded <- f.journalEvents.get
      _ <- untouched(f)
    yield
      result match
        case AgentToolExecutionResult.Denied(snapshot, DenialReason.ResourceNotSelected) =>
          assertEquals(recorded.map(_.requestId), Vector(snapshot.requestId))
          assertEquals(recorded.map(_.result), Vector(AuthorizationResult.Denied(DenialReason.ResourceNotSelected)))
          assertEquals(recorded.map(_.resource), Vector(None))
        case other => fail(s"expected ResourceNotSelected denial, received $other")
      assertEquals(f.catalog.rootCalls.size, 1)
      assertEquals(f.authority.loads, 0)
  }

  test("a catalog answer for a different tenant is denied before any authority load") {
    val foreign = Resource(ResourceId.random(), TenantId.random(), ResourceType.Provider, None, rootExternalId.value, None)
    val foreignScope = ResourceScope.fromPath(Vector(foreign)).getOrElse(fail("scope"))
    for
      f <- fixture(root = Some(rootExternalId -> foreignScope))
      result <- f.service.execute(authenticated, operationId, arguments, at)
      _ <- untouched(f)
    yield
      assert(result.isInstanceOf[AgentToolExecutionResult.Denied], s"received $result")
      assertEquals(f.authority.loads, 0)
  }

  test("a trusted mapping whose capability key differs from the operation's is denied as unmapped, with no lease") {
    val otherKey = PipelineProvider.capabilityKey("Test.Message.Export")
    val mapped = CatalogCapability(
      "00000000-0000-4000-8000-000000000006",
      "Test.Message.Export",
      CapabilityDescriptor(resource.id, Action.Read, otherKey)
    )
    for
      f <- fixture(authorityResult = Right(snapshot(mapped = mapped)))
      result <- f.service.execute(authenticated, operationId, arguments, at)
      recorded <- f.journalEvents.get
      _ <- untouched(f)
    yield
      assert(
        result match
          case AgentToolExecutionResult.Denied(_, DenialReason.UnmappedTool) => true
          case _                                                              => false,
        s"received $result"
      )
      assertEquals(recorded.size, 1)
      assertEquals(f.authority.scopedCalls.size, 1)
  }

  test("a trusted mapping whose action differs from the operation's is denied as unmapped, with no lease") {
    val mapped = CatalogCapability(
      "00000000-0000-4000-8000-000000000007",
      "Test.Message.Read",
      CapabilityDescriptor(resource.id, Action.Write, slackReadKey)
    )
    for
      f <- fixture(authorityResult = Right(snapshot(mapped = mapped)))
      result <- f.service.execute(authenticated, operationId, arguments, at)
      recorded <- f.journalEvents.get
      _ <- untouched(f)
    yield
      assert(
        result match
          case AgentToolExecutionResult.Denied(_, DenialReason.UnmappedTool) => true
          case _                                                              => false,
        s"received $result"
      )
      assertEquals(recorded.size, 1)
  }

  test("a tool with no trusted mapping is denied as unmapped and journaled") {
    for
      f <- fixture(authorityResult = Left(AuthorityLoadError.UnmappedTool))
      result <- f.service.execute(authenticated, operationId, arguments, at)
      recorded <- f.journalEvents.get
      _ <- untouched(f)
    yield
      assert(
        result match
          case AgentToolExecutionResult.Denied(_, DenialReason.UnmappedTool) => true
          case _                                                              => false,
        s"received $result"
      )
      assertEquals(recorded.size, 1)
  }

  test("a kernel denial is journaled but never issues a lease, resolves a credential, or executes") {
    for
      f <- fixture(authorityResult = Right(snapshot(policies = Policies.empty)))
      result <- f.service.execute(authenticated, operationId, arguments, at)
      recorded <- f.journalEvents.get
      _ <- untouched(f)
    yield
      assert(result.isInstanceOf[AgentToolExecutionResult.Denied], s"received $result")
      assertEquals(recorded.size, 1)
  }

  test("an explicit deny policy is journaled and never executes") {
    for
      f <- fixture(authorityResult = Right(snapshot(policies = policy(Effect.Deny))))
      result <- f.service.execute(authenticated, operationId, arguments, at)
      _ <- untouched(f)
    yield assert(result.isInstanceOf[AgentToolExecutionResult.Denied], s"received $result")
  }

  test("approval-required authority never issues a lease, resolves a credential, or executes") {
    for
      f <- fixture(authorityResult = Right(snapshot(policies = policy(Effect.RequireApproval))))
      result <- f.service.execute(authenticated, operationId, arguments, at)
      recorded <- f.journalEvents.get
      _ <- untouched(f)
    yield
      assert(result.isInstanceOf[AgentToolExecutionResult.ApprovalRequired], s"received $result")
      assertEquals(recorded.size, 1)
  }

  test("an authority load failure stays a failed effect, not a denial, and journals nothing") {
    for
      f <- fixture(authorityResult = Left(AuthorityLoadError.PersistenceFailure))
      result <- f.service.execute(authenticated, operationId, arguments, at).attempt
      recorded <- f.journalEvents.get
      _ <- untouched(f)
    yield
      assertEquals(result, Left(AuthoritySnapshotUnavailable(AuthorityLoadError.PersistenceFailure)))
      assertEquals(recorded, Vector.empty)
  }

  test("an invalid stored authority stays a failed effect, not a denial") {
    for
      f <- fixture(authorityResult = Left(AuthorityLoadError.InvalidStoredAuthority))
      result <- f.service.execute(authenticated, operationId, arguments, at).attempt
      _ <- untouched(f)
    yield assertEquals(result, Left(AuthoritySnapshotUnavailable(AuthorityLoadError.InvalidStoredAuthority)))
  }

  test("discovery uses a fresh evaluation without journaling, resolving arguments, or issuing a lease") {
    for
      f <- fixture()
      snapshot <- f.service.discover(authenticated, operationId, at)
      recorded <- f.journalEvents.get
      _ <- untouched(f)
    yield
      assert(snapshot.exists(_.result.isInstanceOf[AuthorizationResult.Authorized]))
      assertEquals(recorded, Vector.empty)
      assertEquals(f.catalog.rootCalls, Vector.empty)
      assertEquals(f.authority.unscopedCalls, Vector((tenant, agent, tool.value)))
  }

  test("discovery of an unknown operation is absent and loads no authority") {
    for
      f <- fixture()
      snapshot <- f.service.discover(authenticated, PipelineProvider.operationId("test.other.operation@1"), at)
    yield
      assertEquals(snapshot, None)
      assertEquals(f.authority.loads, 0)
  }

  test("discovery denies when the trusted mapping disagrees with the operation's contract") {
    val mapped = CatalogCapability(
      "00000000-0000-4000-8000-000000000008",
      "Test.Message.Read",
      CapabilityDescriptor(resource.id, Action.Delete, slackReadKey)
    )
    for
      f <- fixture(authorityResult = Right(snapshot(mapped = mapped)))
      snapshot <- f.service.discover(authenticated, operationId, at)
    yield assertEquals(snapshot.map(_.result), Some(AuthorizationResult.Denied(DenialReason.UnmappedTool)))
  }
