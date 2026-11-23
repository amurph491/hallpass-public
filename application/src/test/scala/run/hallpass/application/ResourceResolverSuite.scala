package run.hallpass.application

import cats.effect.IO
import munit.CatsEffectSuite
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.DenialReason

final class ResourceResolverSuite extends CatsEffectSuite:
  import PipelineProvider.given

  private val tenant = TenantId.random()
  private val human = Principal.Human(UserId.random())
  private val workspaceExternalId = PipelineProvider.externalId("workspace")
  private val workspaceResource =
    Resource(ResourceId.random(), tenant, ResourceType.Provider, None, workspaceExternalId.value, None)
  private val workspaceScope = ResourceScope.fromPath(Vector(workspaceResource)).getOrElse(fail("scope"))
  private val itemExternalId = PipelineProvider.externalId("item-1")
  private val itemResource =
    Resource(ResourceId.random(), tenant, ResourceType.Repository, Some(workspaceResource.id), itemExternalId.value, None)
  private val itemScope =
    ResourceScope.fromPath(Vector(itemResource, workspaceResource)).getOrElse(fail("scope"))

  private val mailboxExternalId = PipelineProvider.externalId("alex@example.com")
  private def mailboxResource(custodian: Option[Principal]) =
    Resource(ResourceId.random(), tenant, ResourceType.Account, None, mailboxExternalId.value, custodian)
  private def scopeOf(resource: Resource) = ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope"))

  private final class Catalog(
      root: Option[(ExternalId, ResourceScope)] = None,
      selected: Option[ResourceScope] = None
  ) extends ResourceCatalog:
    var rootCalls = Vector.empty[(TenantId, String)]
    var selectedCalls = Vector.empty[(TenantId, String, ExternalId)]
    def rootScope(t: TenantId, kind: ResourceKind[?]): IO[Option[(ExternalId, ResourceScope)]] =
      IO.delay:
        rootCalls = rootCalls :+ (t -> kind.wire)
        root
    def selectedScope(t: TenantId, kind: ResourceKind[?], externalId: ExternalId): IO[Option[ResourceScope]] =
      IO.delay:
        selectedCalls = selectedCalls :+ (t, kind.wire, externalId)
        selected
    def currentScope(t: TenantId, resource: ResourceId): IO[Option[ResourceScope]] =
      IO.raiseError(AssertionError("resolution must not use currentScope"))

  private def resolveRoot(catalog: Catalog) =
    ResourceResolver(catalog).resolve(tenant, PipelineProvider.workspace, ResourceLocator.ConnectionRoot())

  private def denied[K](result: Either[DenialReason, SelectedResource[K]]): Unit =
    assertEquals(result.left.toOption, Some(DenialReason.ResourceNotSelected), s"received $result")

  test("ConnectionRoot resolves when the catalog returns a consistent scope") {
    val catalog = Catalog(root = Some(workspaceExternalId -> workspaceScope))
    resolveRoot(catalog).map: result =>
      result match
        case Right(target) =>
          assert(target.kind eq PipelineProvider.workspace)
          assertEquals(target.externalId, workspaceExternalId)
          assertEquals(target.scope, workspaceScope)
          assertEquals(target.resource, workspaceResource.id)
          assertEquals(target.tenant, tenant)
        case Left(reason) => fail(s"expected resolution, received $reason")
      assertEquals(catalog.rootCalls, Vector(tenant -> "testprov.workspace"))
  }

  test("ConnectionRoot on a kind that is not a root is denied without consulting the catalog") {
    val catalog = Catalog(root = Some(itemExternalId -> itemScope))
    ResourceResolver(catalog).resolve(tenant, PipelineProvider.item, ResourceLocator.ConnectionRoot()).map: result =>
      denied(result)
      assertEquals(catalog.rootCalls, Vector.empty)
  }

  test("ConnectionRoot is denied when the catalog has no root for the tenant") {
    val catalog = Catalog(root = None)
    resolveRoot(catalog).map: result =>
      denied(result)
      assertEquals(catalog.rootCalls.size, 1)
  }

  test("a scope that belongs to another tenant is denied") {
    val foreign =
      Resource(ResourceId.random(), TenantId.random(), ResourceType.Provider, None, workspaceExternalId.value, None)
    resolveRoot(Catalog(root = Some(workspaceExternalId -> scopeOf(foreign)))).map(denied)
  }

  test("a scope whose target external ID differs from the one asked for is denied") {
    val other = workspaceResource.copy(externalId = "another-workspace")
    resolveRoot(Catalog(root = Some(workspaceExternalId -> scopeOf(other)))).map(denied)
  }

  test("a scope whose target resource type differs from the kind's is denied") {
    val other = workspaceResource.copy(resourceType = ResourceType.Account)
    resolveRoot(Catalog(root = Some(workspaceExternalId -> scopeOf(other)))).map(denied)
  }

  test("a personal-custody kind is denied when its scope has no custodian") {
    val catalog = Catalog(root = Some(mailboxExternalId -> scopeOf(mailboxResource(None))))
    ResourceResolver(catalog)
      .resolve(tenant, PipelineProvider.mailbox, ResourceLocator.ConnectionRoot())
      .map(denied)
  }

  test("a personal-custody kind resolves when its scope names a custodian") {
    val scope = scopeOf(mailboxResource(Some(human)))
    val catalog = Catalog(root = Some(mailboxExternalId -> scope))
    ResourceResolver(catalog)
      .resolve(tenant, PipelineProvider.mailbox, ResourceLocator.ConnectionRoot())
      .map: result =>
        result match
          case Right(target) =>
            assertEquals(target.scope.custodian, Some(human))
            assertEquals(target.externalId, mailboxExternalId)
          case Left(reason) => fail(s"expected resolution, received $reason")
  }

  test("a workspace-custody kind does not require a custodian") {
    assertEquals(workspaceScope.custodian, None)
    resolveRoot(Catalog(root = Some(workspaceExternalId -> workspaceScope))).map(result => assert(result.isRight))
  }

  test("Selected delegates to the catalog's selectedScope and resolves a consistent answer") {
    val catalog = Catalog(selected = Some(itemScope))
    val locator = ResourceLocator.Selected(ExternalRef[PipelineProvider.Item](itemExternalId))
    ResourceResolver(catalog).resolve(tenant, PipelineProvider.item, locator).map: result =>
      result match
        case Right(target) =>
          assert(target.kind eq PipelineProvider.item)
          assertEquals(target.externalId, itemExternalId)
          assertEquals(target.scope, itemScope)
          assertEquals(target.resource, itemResource.id)
        case Left(reason) => fail(s"expected resolution, received $reason")
      assertEquals(catalog.selectedCalls, Vector((tenant, "testprov.item", itemExternalId)))
      assertEquals(catalog.rootCalls, Vector.empty)
  }

  test("Selected is denied when nothing is selected") {
    val catalog = Catalog(selected = None)
    val locator = ResourceLocator.Selected(ExternalRef[PipelineProvider.Item](itemExternalId))
    ResourceResolver(catalog).resolve(tenant, PipelineProvider.item, locator).map: result =>
      denied(result)
      assertEquals(catalog.selectedCalls.size, 1)
  }

  test("Selected is denied when the catalog answers with a different resource than the one asked for") {
    val catalog = Catalog(selected = Some(itemScope))
    val locator = ResourceLocator.Selected(ExternalRef[PipelineProvider.Item](PipelineProvider.externalId("item-2")))
    ResourceResolver(catalog).resolve(tenant, PipelineProvider.item, locator).map(denied)
  }

  test("Selected with a reference of another kind instance is denied without consulting the catalog") {
    val lookalike = ResourceKind.root[PipelineProvider.Workspace](
      "testprov.workspace",
      PipelineProvider.id,
      ResourceType.Provider,
      Custody.Workspace
    )
    val catalog = Catalog(selected = Some(workspaceScope))
    val locator = ResourceLocator.Selected(ExternalRef[PipelineProvider.Workspace](workspaceExternalId)(using lookalike))
    ResourceResolver(catalog).resolve(tenant, PipelineProvider.workspace, locator).map: result =>
      denied(result)
      assertEquals(catalog.selectedCalls, Vector.empty)
  }
