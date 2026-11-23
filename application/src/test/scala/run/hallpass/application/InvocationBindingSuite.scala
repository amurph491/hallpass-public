package run.hallpass.application

import io.circe.Json
import munit.FunSuite
import run.hallpass.kernel.*

final class InvocationBindingSuite extends FunSuite:
  private val tenant = TenantId.random()
  private val agent = AgentId.random()
  private val operation = PipelineProvider.operationId("test.search.messages@1")
  private val capability = PipelineProvider.capabilityKey("Test.Message.Read")
  private val resource = ResourceId.random()
  private val input = Json.obj("query" -> Json.fromString("roadmap"), "limit" -> Json.fromInt(5))

  private def binding(
      tenant: TenantId = tenant,
      agent: AgentId = agent,
      operation: OperationId = operation,
      capability: CapabilityKey = capability,
      action: Action = Action.Read,
      resource: ResourceId = resource,
      kind: ResourceKind[?] = PipelineProvider.workspace,
      externalId: ExternalId = PipelineProvider.externalId("workspace"),
      input: Json = input
  ): InvocationBinding = InvocationBinding.compute(tenant, agent, operation, capability, action, resource, kind, externalId, input)

  test("equal inputs produce equal bindings") {
    assertEquals(binding(), binding())
    assertEquals(binding().digest.value, binding().digest.value)
  }

  test("the digest is 64 lower-case hexadecimal characters") {
    val digest = binding().digest.value
    assertEquals(digest.length, 64)
    assert(digest.matches("[0-9a-f]{64}"), digest)
  }

  test("the binding records its operation and resource") {
    assertEquals(binding().operation, operation)
    assertEquals(binding().resource, resource)
  }

  test("JSON object key order in the canonical input does not change the digest, at any depth") {
    val reordered = Json.obj("limit" -> Json.fromInt(5), "query" -> Json.fromString("roadmap"))
    assertEquals(binding(input = reordered), binding())
    val nestedA = Json.obj("filter" -> Json.obj("a" -> Json.fromInt(1), "b" -> Json.fromInt(2)), "z" -> Json.True)
    val nestedB = Json.obj("z" -> Json.True, "filter" -> Json.obj("b" -> Json.fromInt(2), "a" -> Json.fromInt(1)))
    assertEquals(binding(input = nestedA), binding(input = nestedB))
  }

  test("array order is significant") {
    val forward = Json.obj("ids" -> Json.arr(Json.fromInt(1), Json.fromInt(2)))
    val backward = Json.obj("ids" -> Json.arr(Json.fromInt(2), Json.fromInt(1)))
    assertNotEquals(binding(input = forward).digest.value, binding(input = backward).digest.value)
  }

  test("changing any bound element changes the digest") {
    val base = binding().digest.value
    val changed = Vector(
      "tenant" -> binding(tenant = TenantId.random()),
      "agent" -> binding(agent = AgentId.random()),
      "operation version" -> binding(operation = PipelineProvider.operationId("test.search.messages@2")),
      "operation name" -> binding(operation = PipelineProvider.operationId("test.search.threads@1")),
      "capability" -> binding(capability = PipelineProvider.capabilityKey("Test.Message.Export")),
      "action" -> binding(action = Action.Write),
      "resource" -> binding(resource = ResourceId.random()),
      "external ID" -> binding(externalId = PipelineProvider.externalId("another-workspace")),
      "kind" -> binding(kind = PipelineProvider.mailbox),
      "provider" -> binding(kind = ResourceKind.root[PipelineProvider.Workspace](
        "otherprov.workspace",
        ProviderId.parse("otherprov").getOrElse(fail("provider")),
        ResourceType.Provider,
        Custody.Workspace
      )),
      "input value" -> binding(input = Json.obj("query" -> Json.fromString("other"), "limit" -> Json.fromInt(5))),
      "input field" -> binding(input = Json.obj("query" -> Json.fromString("roadmap"))),
      "input type" -> binding(input = Json.obj("query" -> Json.fromString("roadmap"), "limit" -> Json.fromString("5")))
    )
    changed.foreach: (name, other) =>
      assertNotEquals(other.digest.value, base, s"changing the $name must change the digest")
  }

  test("every action yields a distinct digest") {
    val digests = Action.values.toVector.map(action => binding(action = action).digest.value)
    assertEquals(digests.distinct.size, Action.values.length)
  }

  test("field boundaries are unambiguous: moving text between fields changes the digest") {
    val a = binding(input = Json.obj("a" -> Json.fromString("xy"), "b" -> Json.fromString("z")))
    val b = binding(input = Json.obj("a" -> Json.fromString("x"), "b" -> Json.fromString("yz")))
    assertNotEquals(a.digest.value, b.digest.value)
  }

  test("changing only the provider external ID on one catalog resource changes the binding") {
    val descriptor = PipelineOperation[PipelineProvider.Workspace](
      operation,
      PipelineProvider.toolId("test_search_messages"),
      PipelineProvider.workspace,
      ResourceLocator.ConnectionRoot()
    )
    def target(external: String) =
      val scopeRoot = Resource(resource, tenant, ResourceType.Provider, None, external, None)
      val scope = ResourceScope.fromPath(Vector(scopeRoot)).getOrElse(fail("scope"))
      SelectedResource.trusted(PipelineProvider.workspace, PipelineProvider.externalId(external), scope)
    val query = SearchQuery.parse("roadmap").getOrElse(fail("query"))
    val first = target("workspace")
    val second = target("another-workspace")
    assertEquals(first.resource, second.resource)
    val firstBinding = InvocationBinding.of(tenant, agent, descriptor, first, query)
    val secondBinding = InvocationBinding.of(tenant, agent, descriptor, second, query)
    assertEquals(firstBinding.externalId, first.externalId)
    assertNotEquals(firstBinding.digest.value, secondBinding.digest.value)
  }

  test("of() binds the descriptor's canonical form of the typed input and the resolved resource") {
    import PipelineProvider.given
    val descriptor = PipelineOperation[PipelineProvider.Workspace](
      operation,
      PipelineProvider.toolId("test_search_messages"),
      PipelineProvider.workspace,
      ResourceLocator.ConnectionRoot()
    )
    val scopeRoot = Resource(resource, tenant, ResourceType.Provider, None, "workspace", None)
    val scope = ResourceScope.fromPath(Vector(scopeRoot)).getOrElse(fail("scope"))
    val target = SelectedResource.trusted(PipelineProvider.workspace, PipelineProvider.externalId("workspace"), scope)
    val query = SearchQuery.parse("roadmap").getOrElse(fail("query"))
    val expected = binding(input = Json.obj("query" -> Json.fromString("roadmap")))
    assertEquals(InvocationBinding.of(tenant, agent, descriptor, target, query), expected)
    val otherQuery = SearchQuery.parse("budget").getOrElse(fail("query"))
    assertNotEquals(InvocationBinding.of(tenant, agent, descriptor, target, otherQuery), expected)
  }
