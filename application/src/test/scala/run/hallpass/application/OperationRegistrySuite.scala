package run.hallpass.application

import munit.FunSuite
import run.hallpass.kernel.*

final class OperationRegistrySuite extends FunSuite:
  import PipelineProvider.given

  private def workspaceOperation(id: String, tool: String) =
    PipelineFixtures.registered(
      PipelineOperation[PipelineProvider.Workspace](
        PipelineProvider.operationId(id),
        PipelineProvider.toolId(tool),
        PipelineProvider.workspace,
        ResourceLocator.ConnectionRoot()
      )
    )

  private def itemOperation(id: String, tool: String) =
    PipelineFixtures.registered(
      PipelineOperation[PipelineProvider.Item](
        PipelineProvider.operationId(id),
        PipelineProvider.toolId(tool),
        PipelineProvider.item,
        ResourceLocator.Selected(ExternalRef[PipelineProvider.Item](PipelineProvider.externalId("item-1")))
      )
    )

  test("a valid registry finds each operation by its versioned ID and nothing else") {
    val first = workspaceOperation("test.search.messages@1", "test_search_messages")
    val second = itemOperation("test.items.read@1", "test_items_read")
    OperationRegistry.from(Vector(first, second)) match
      case Right(registry) =>
        assertEquals(registry.all.size, 2)
        assertEquals(registry.find(first.descriptor.id).map(_.descriptor.id), Some(first.descriptor.id))
        assertEquals(registry.find(second.descriptor.id).map(_.descriptor.id), Some(second.descriptor.id))
        assertEquals(registry.find(PipelineProvider.operationId("test.search.messages@2")), None)
        assertEquals(registry.find(PipelineProvider.operationId("test.unknown.operation@1")), None)
      case Left(error) => fail(s"expected a valid registry, received $error")
  }

  test("an empty registry is valid and finds nothing") {
    OperationRegistry.from(Vector.empty) match
      case Right(registry) =>
        assertEquals(registry.all, Vector.empty)
        assertEquals(registry.find(PipelineProvider.operationId("test.search.messages@1")), None)
      case Left(error) => fail(s"expected a valid registry, received $error")
  }

  test("a duplicate operation ID is rejected") {
    val result = OperationRegistry.from(
      Vector(
        workspaceOperation("test.search.messages@1", "test_search_messages"),
        workspaceOperation("test.search.messages@1", "test_other_tool")
      )
    )
    assertEquals(
      result.left.toOption,
      Some(OperationRegistryError.DuplicateOperation(PipelineProvider.operationId("test.search.messages@1")))
    )
  }

  test("two versions of one operation are distinct operations, but may not share a tool") {
    val versions = OperationRegistry.from(
      Vector(
        workspaceOperation("test.search.messages@1", "test_search_messages"),
        workspaceOperation("test.search.messages@2", "test_search_messages_v2")
      )
    )
    assert(versions.isRight, s"received $versions")
    val sharedTool = OperationRegistry.from(
      Vector(
        workspaceOperation("test.search.messages@1", "test_search_messages"),
        workspaceOperation("test.search.messages@2", "test_search_messages")
      )
    )
    assertEquals(
      sharedTool.left.toOption,
      Some(OperationRegistryError.DuplicateTool(PipelineProvider.toolId("test_search_messages")))
    )
  }

  test("a duplicate tool is rejected") {
    val result = OperationRegistry.from(
      Vector(
        workspaceOperation("test.search.messages@1", "test_search_messages"),
        itemOperation("test.items.read@1", "test_search_messages")
      )
    )
    assertEquals(
      result.left.toOption,
      Some(OperationRegistryError.DuplicateTool(PipelineProvider.toolId("test_search_messages")))
    )
  }

  test("two distinct kind declarations that share a wire name conflict") {
    val impostor = ResourceKind.root[PipelineProvider.Workspace](
      "testprov.workspace",
      PipelineProvider.id,
      ResourceType.Account,
      Custody.Workspace
    )
    val conflicting = PipelineFixtures.registered(
      PipelineOperation[PipelineProvider.Workspace](
        PipelineProvider.operationId("test.other.read@1"),
        PipelineProvider.toolId("test_other_read"),
        impostor,
        ResourceLocator.ConnectionRoot()
      )
    )
    val result =
      OperationRegistry.from(Vector(workspaceOperation("test.search.messages@1", "test_search_messages"), conflicting))
    assertEquals(result.left.toOption, Some(OperationRegistryError.ConflictingKind("testprov.workspace")))
  }

  test("a child kind's lineage shares one declaration of its root with other operations on that root") {
    val result = OperationRegistry.from(
      Vector(
        workspaceOperation("test.search.messages@1", "test_search_messages"),
        itemOperation("test.items.read@1", "test_items_read")
      )
    )
    assert(result.isRight, s"received $result")
    assertEquals(PipelineProvider.item.lineage.map(_.wire), Vector("testprov.item", "testprov.workspace"))
    assert(PipelineProvider.item.parent.exists(_ eq PipelineProvider.workspace))
  }
