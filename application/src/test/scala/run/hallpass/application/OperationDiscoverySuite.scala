package run.hallpass.application

import java.time.{Duration, Instant}
import cats.effect.IO
import cats.effect.kernel.Ref
import cats.syntax.all.*
import io.circe.Json
import munit.CatsEffectSuite
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

final class OperationDiscoverySuite extends CatsEffectSuite:
  import PipelineProvider.given

  private val tenant = TenantId.random()
  private val agentId = AgentId.random()
  private val agent = Principal.Agent(agentId)
  private val human = Principal.Human(UserId.random())
  private val at = Instant.parse("2026-09-20T12:00:00Z")
  private val authenticated = AuthenticatedAgentContext.authenticated(
    tenant, agentId, AgentCredentialId.random(), at, UnverifiedExecutionClaims.empty
  )
  private val root = Resource(ResourceId.random(), tenant, ResourceType.Provider, None, "workspace", None)
  private val child = Resource(ResourceId.random(), tenant, ResourceType.Repository, Some(root.id), "repository-1", None)
  private val scope = ResourceScope.fromPath(Vector(child, root)).getOrElse(fail("scope"))
  private val key = PipelineProvider.capabilityKey("Test.Message.Read")
  private val capability = CatalogCapability(
    "00000000-0000-4000-8000-000000000005", "Test.Message.Read", CapabilityDescriptor(root.id, Action.Read, key)
  )
  private val grant = Delegation(
    DelegationId.random(), human, agent, None,
    NonEmptySet.one(CapabilityDescriptor(child.id, Action.Read, key)),
    Constraints.empty, Instant.EPOCH, None, None
  )
  private val policies = Policies(Vector(Policy(
    PolicyId.random(), PolicyVersion.from(1).getOrElse(fail("version")),
    NonEmptySet.one(PolicyStatement(human, root.id, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow))
  )))
  private val descriptor = PipelineOperation[PipelineProvider.Item](
    PipelineProvider.operationId("test.repository.search@1"),
    PipelineProvider.toolId("test_repository_search"),
    PipelineProvider.item,
    ResourceLocator.Selected(ExternalRef[PipelineProvider.Item](PipelineProvider.externalId(child.externalId)))
  )

  private final case class Fixture(
      service: AgentToolService,
      scopes: Ref[IO, Vector[ResourceScope]],
      grants: Ref[IO, Vector[Delegation]],
      client: PipelineClient[PipelineProvider.Item],
      credentials: PipelineCredentials[PipelineProvider.Item],
      audit: InMemoryExecutionAuditRecorder
  )

  private def fixture(failure: Option[AuthorityLoadError] = None): IO[Fixture] =
    for
      scopes <- Ref.of[IO, Vector[ResourceScope]](Vector(scope))
      grants <- Ref.of[IO, Vector[Delegation]](Vector(grant))
      catalog = new ResourceCatalog:
        override def discoveryScopes(t: TenantId, kind: ResourceKind[?]) = scopes.get
        def rootScope(t: TenantId, kind: ResourceKind[?]): IO[Option[(ExternalId, ResourceScope)]] = IO.pure(None)
        def selectedScope(t: TenantId, kind: ResourceKind[?], id: ExternalId) =
          scopes.get.map(_.find(_.target.externalId == id.value))
        def currentScope(t: TenantId, id: ResourceId) = scopes.get.map(_.find(_.target.id == id))
      authority = new AuthorityRepository[IO]:
        def snapshotFor(t: TenantId, p: Principal, tool: String): IO[Either[AuthorityLoadError, AuthoritySnapshot]] =
          IO.raiseError(AssertionError("discovery must evaluate authority at the selected target"))
        def snapshotWithin(t: TenantId, p: Principal, tool: String, target: ResourceScope): IO[Either[AuthorityLoadError, AuthoritySnapshot]] =
          grants.get.map(ds => failure.fold[Either[AuthorityLoadError, AuthoritySnapshot]](
            Right(AuthoritySnapshot(target, capability, policies, ds, Some(ResourceId.random())))
          )(Left(_)))
      journal = new AuthorizationJournal[IO]:
        def record(t: TenantId, event: AuthorizationEvent) = IO.unit
        def recent(t: TenantId, limit: Int) = IO.pure(Vector.empty)
      clock = Clock.fixed(at)
      store <- InMemoryExecutionLeaseStore.create
      audit <- InMemoryExecutionAuditRecorder.create
      gate <- SingleProcessTenantExecutionMutationGate.create
      client = PipelineClient[PipelineProvider.Item]()
      credentials = PipelineCredentials[PipelineProvider.Item]()
      registry = OperationRegistry.from(Vector(RegisteredOperation(descriptor, client, credentials)))
        .fold(error => fail(s"registry: $error"), identity)
      validator = new LeaseAuthorityValidator[IO]:
        def validate(lease: RedeemedExecutionLease, now: Instant) = IO.pure(Right(()))
      executor = ProviderExecutionService(store, clock, audit, validator, gate)
      service = AgentToolService(
        registry, ResourceResolver(catalog), authority, journal,
        InMemoryCredentialBroker(store, clock, Duration.ofSeconds(60), audit), executor
      )
    yield Fixture(service, scopes, grants, client, credentials, audit)

  test("a child-only grant exposes its operation without a lease, credential read, or dispatch") {
    for
      f <- fixture()
      visible <- f.service.visibleOperations(authenticated, at)
      events <- f.audit.recorded
    yield
      assertEquals(visible.map(_.id), Vector(descriptor.id))
      assertEquals(events, Vector.empty)
      assertEquals(f.credentials.resolutions, Vector.empty)
      assertEquals(f.client.dispatches, Vector.empty)
  }

  test("revocation hides the operation and independently denies a direct invocation") {
    for
      f <- fixture()
      before <- f.service.visibleOperations(authenticated, at)
      _ <- f.grants.set(Vector(grant.copy(revokedAt = Some(at))))
      after <- f.service.visibleOperations(authenticated, at)
      call <- f.service.execute(authenticated, descriptor.id, Json.obj("query" -> Json.fromString("roadmap")), at)
      events <- f.audit.recorded
    yield
      assertEquals(before.map(_.id), Vector(descriptor.id))
      assertEquals(after, Vector.empty)
      assert(call.isInstanceOf[AgentToolExecutionResult.Denied])
      assertEquals(events, Vector.empty)
      assertEquals(f.credentials.resolutions, Vector.empty)
      assertEquals(f.client.dispatches, Vector.empty)
  }

  test("deselection hides the operation") {
    for
      f <- fixture()
      _ <- f.scopes.set(Vector.empty)
      visible <- f.service.visibleOperations(authenticated, at)
    yield assertEquals(visible, Vector.empty)
  }

  test("a foreign discovery scope fails closed") {
    val foreign = child.copy(tenant = TenantId.random(), parent = None)
    val foreignScope = ResourceScope.fromPath(Vector(foreign)).getOrElse(fail("scope"))
    for
      f <- fixture()
      _ <- f.scopes.set(Vector(foreignScope))
      result <- f.service.visibleOperations(authenticated, at).attempt
    yield assertEquals(result, Left(AuthoritySnapshotUnavailable(AuthorityLoadError.InvalidStoredAuthority)))
  }

  test("an authority failure stays a failure, never a partial successful tool list") {
    for
      f <- fixture(Some(AuthorityLoadError.PersistenceFailure))
      result <- f.service.visibleOperations(authenticated, at).attempt
    yield assertEquals(result, Left(AuthoritySnapshotUnavailable(AuthorityLoadError.PersistenceFailure)))
  }
