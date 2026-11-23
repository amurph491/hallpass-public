package run.hallpass.application

import java.time.{Duration, Instant}
import cats.effect.IO
import cats.effect.kernel.Ref
import io.circe.Json
import munit.CatsEffectSuite
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** A fact-constrained delegation through the generic pipeline. The fake operation derives a `test.recipients` fact set
  * from its typed input (the whitespace-separated words of the query), so the facts are never free-form arguments. */
final class ValuedConstraintPipelineSuite extends CatsEffectSuite:
  import PipelineProvider.given

  private val recipientsKey = ContextKey("test.recipients")
  private val capabilityKey = PipelineProvider.capabilityKey("Test.Message.Read")
  private val tenant = TenantId.random()
  private val agentId = AgentId.random()
  private val agent = Principal.Agent(agentId)
  private val human = Principal.Human(UserId.random())
  private val credentialId = AgentCredentialId.random()
  private val tool = PipelineProvider.toolId("test_search_messages")
  private val operationId = PipelineProvider.operationId("test.search.messages@1")
  private val at = Instant.parse("2026-09-20T12:00:00Z")
  private val rootExternalId = PipelineProvider.externalId("workspace")
  private val resource = Resource(ResourceId.random(), tenant, ResourceType.Provider, None, rootExternalId.value, None)
  private val resourceScope = ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope"))
  private val descriptor = CapabilityDescriptor(resource.id, Action.Read, capabilityKey)
  private val capability = CatalogCapability("00000000-0000-4000-8000-000000000005", "Test.Message.Read", descriptor)
  private val catalogTool = ResourceId.random()

  private val allowlist = Set("a@x.test", "b@x.test").map(ContextValue(_))
  private val delegation = Delegation(
    DelegationId.random(), human, agent, None, NonEmptySet.one(descriptor),
    Constraints(Set(Constraint.ValueIn(recipientsKey, NonEmptySet.from(allowlist).getOrElse(fail("allowlist"))))),
    Instant.EPOCH, None, None
  )
  private val policies = Policies(
    Vector(
      Policy(
        PolicyId.random(),
        PolicyVersion.from(1).getOrElse(fail("version")),
        NonEmptySet.one(PolicyStatement(human, resource.id, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow))
      )
    )
  )

  /** Delegates everything to the plain pipeline operation except the facts. */
  private object RecipientOperation extends OperationDescriptor[SearchQuery, PipelineProvider.Workspace]:
    private val base = PipelineOperation[PipelineProvider.Workspace](
      operationId, PipelineProvider.toolId("test_search_messages"), PipelineProvider.workspace, ResourceLocator.ConnectionRoot()
    )
    def id = base.id
    def tool = base.tool
    def description = base.description
    def capability = base.capability
    def action = base.action
    def target = base.target
    def audience = base.audience
    def inputSchema = base.inputSchema
    def decode(arguments: Json) = base.decode(arguments)
    def locate(input: SearchQuery) = base.locate(input)
    def canonical(input: SearchQuery) = base.canonical(input)
    def facts(input: SearchQuery): AuthorizationContext =
      AuthorizationContext.withFacts(
        Map.empty,
        Map(recipientsKey -> input.value.split("\\s+").filter(_.nonEmpty).map(ContextValue(_)).toSet)
      )

  private def call(words: String*): Json = Json.obj("query" -> Json.fromString(words.mkString(" ")))
  private def authenticated =
    AuthenticatedAgentContext.authenticated(tenant, agentId, credentialId, at, UnverifiedExecutionClaims.empty)

  private final class Catalog extends ResourceCatalog:
    def rootScope(t: TenantId, kind: ResourceKind[?]) = IO.pure(Some(rootExternalId -> resourceScope))
    def selectedScope(t: TenantId, kind: ResourceKind[?], externalId: ExternalId) = IO.pure(None)
    def currentScope(t: TenantId, resourceId: ResourceId) = IO.pure(Some(resourceScope).filter(_.target.id == resourceId))

  /** Serves the delegation from a Ref; `revokeAfterLoads` flips it to revoked once that many loads have been served. */
  private final class Authority(delegations: Ref[IO, Vector[Delegation]], revokeAfterLoads: Option[Int])
      extends AuthorityRepository[IO]:
    var loads = 0
    def snapshotFor(t: TenantId, p: Principal, externalTool: String) =
      snapshotWithin(t, p, externalTool, resourceScope)
    def snapshotWithin(t: TenantId, p: Principal, externalTool: String, scope: ResourceScope) =
      for
        _ <- IO.delay { loads += 1 }
        _ <- IO.whenA(revokeAfterLoads.contains(loads - 1))(
          delegations.update(_.map(_.copy(revokedAt = Some(at.minusSeconds(1)))))
        )
        current <- delegations.get
      yield Right(AuthoritySnapshot(scope, capability, policies, current, Some(catalogTool)))

  private final class Fixture(
      val authority: Authority,
      val events: Ref[IO, Vector[AuthorizationEvent]],
      val issued: Ref[IO, Int],
      val audit: InMemoryExecutionAuditRecorder,
      val client: PipelineClient[PipelineProvider.Workspace],
      val credentials: PipelineCredentials[PipelineProvider.Workspace],
      val service: AgentToolService
  )

  private def fixture(revokeAfterLoads: Option[Int] = None, realRevalidation: Boolean = false): IO[Fixture] =
    for
      journalEvents <- Ref.of[IO, Vector[AuthorizationEvent]](Vector.empty)
      issued <- Ref.of[IO, Int](0)
      delegations <- Ref.of[IO, Vector[Delegation]](Vector(delegation))
      clock = Clock.fixed(at)
      store <- InMemoryExecutionLeaseStore.create(clock, InMemoryExecutionLeaseStore.DefaultPruneInterval, 100)
      audit <- InMemoryExecutionAuditRecorder.create
      gate <- SingleProcessTenantExecutionMutationGate.create
      catalog = new Catalog
      authority = new Authority(delegations, revokeAfterLoads)
      journal = new AuthorizationJournal[IO]:
        def record(t: TenantId, event: AuthorizationEvent) = journalEvents.update(_ :+ event)
        def recent(t: TenantId, limit: Int) = IO.pure(Vector.empty)
      inner = InMemoryCredentialBroker(store, clock, Duration.ofSeconds(60), audit)
      broker = new CredentialBroker[IO]:
        def issueLease(c: AuthorizedCapability, r: AuthorizationRequestId, a: ExecutorAudience, m: ExecutionAuditMetadata) =
          issued.update(_ + 1) *> inner.issueLease(c, r, a, m)
      client = new PipelineClient[PipelineProvider.Workspace]()
      credentials = new PipelineCredentials[PipelineProvider.Workspace]()
      registry = OperationRegistry.from(Vector(RegisteredOperation(RecipientOperation, client, credentials)))
        .fold(error => fail(s"registry: $error"), identity)
      validator: LeaseAuthorityValidator[IO] =
        if realRevalidation then
          val revalidator = new CurrentStateExecutionRevalidator(
            new AgentCredentialCurrentStateRepository[IO]:
              def ensureActive(t: TenantId, c: AgentCredentialId, a: AgentId, checkedAt: Instant) = IO.pure(Right(()))
            ,
            authority,
            new TrustedToolLookup[IO]:
              def externalToolFor(t: TenantId, toolResource: ResourceId) = IO.pure(Right(tool))
            ,
            catalog
          )
          DurableLeaseAuthorityValidator(revalidator)
        else
          new LeaseAuthorityValidator[IO]:
            def validate(lease: RedeemedExecutionLease, now: Instant) = IO.pure(Right(()))
      executor = ProviderExecutionService(store, clock, audit, validator, gate)
      service = AgentToolService(registry, ResourceResolver(catalog), authority, journal, broker, executor)
    yield Fixture(authority, journalEvents, issued, audit, client, credentials, service)

  test("a call whose derived recipients are within the allowlist completes") {
    for
      f <- fixture()
      result <- f.service.execute(authenticated, operationId, call("a@x.test", "b@x.test"), at)
    yield
      assert(result.isInstanceOf[AgentToolExecutionResult.Completed], s"received $result")
      assertEquals(f.client.dispatches.size, 1)
  }

  test("a call with a recipient outside the allowlist is denied and journaled before any lease, credential, or provider call") {
    for
      f <- fixture()
      result <- f.service.execute(authenticated, operationId, call("a@x.test", "evil@y.test"), at)
      recorded <- f.events.get
      leases <- f.issued.get
      audit <- f.audit.recorded
    yield
      result match
        case AgentToolExecutionResult.Denied(_, DenialReason.DelegationConstraintsNotSatisfied(id)) =>
          assertEquals(id, delegation.id)
        case other => fail(s"expected constraint denial, received $other")
      assertEquals(recorded.size, 1)
      assertEquals(recorded.map(_.result), Vector(AuthorizationResult.Denied(DenialReason.DelegationConstraintsNotSatisfied(delegation.id))))
      assertEquals(leases, 0)
      assertEquals(audit, Vector.empty)
      assertEquals(f.credentials.resolutions, Vector.empty)
      assertEquals(f.client.dispatches, Vector.empty)
  }

  test("the operation stays visible in discovery despite its fact constraint") {
    for
      f <- fixture()
      visible <- f.service.visibleOperations(authenticated, at)
      snapshot <- f.service.discover(authenticated, operationId, at)
      leases <- f.issued.get
    yield
      assertEquals(visible.map(_.id), Vector(operationId))
      assert(snapshot.exists(_.result.isInstanceOf[AuthorizationResult.Authorized]))
      assertEquals(leases, 0)
      assertEquals(f.client.dispatches, Vector.empty)
  }

  test("an issued lease for an allowed invocation passes revalidation, which does not re-evaluate facts") {
    for
      f <- fixture(realRevalidation = true)
      result <- f.service.execute(authenticated, operationId, call("a@x.test"), at)
    yield
      assert(result.isInstanceOf[AgentToolExecutionResult.Completed], s"received $result")
      // One load to authorize, then at least one more to revalidate.
      assert(f.authority.loads >= 2, s"loads: ${f.authority.loads}")
      assertEquals(f.client.dispatches.size, 1)
  }

  test("a delegation revoked after authorization still fails revalidation before credential or provider access") {
    for
      // The second authority load (revalidation) sees the revocation.
      f <- fixture(revokeAfterLoads = Some(1), realRevalidation = true)
      result <- f.service.execute(authenticated, operationId, call("a@x.test"), at).attempt
      leases <- f.issued.get
    yield
      assertEquals(leases, 1, "authorization itself succeeded")
      assert(result.isLeft || result.exists(!_.isInstanceOf[AgentToolExecutionResult.Completed]), s"received $result")
      assertEquals(f.credentials.resolutions, Vector.empty)
      assertEquals(f.client.dispatches, Vector.empty)
  }
