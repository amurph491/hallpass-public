package run.hallpass.gateway

import io.circe.Json
import munit.FunSuite
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Discovery's target hints are a display aid. They must annotate only the declared target argument, stay bounded,
  * and never change a schema for operations without one. */
final class AgentToolTargetsSuite extends FunSuite:
  private sealed trait Root
  private sealed trait Item
  private given root: ResourceKind[Root] = ResourceKind.root("test.root", ProviderId.parse("test").get, ResourceType.Account, Custody.Workspace)
  private given item: ResourceKind[Item] = ResourceKind.child[Item, Root]("test.item", ResourceType.Repository)

  private val tenant = TenantId.random()
  private val rootResource = Resource(ResourceId.random(), tenant, ResourceType.Account, None, "root", None)

  private def target(externalId: String, name: String): DiscoveryTarget =
    val resource = Resource(ResourceId.random(), tenant, ResourceType.Repository, Some(rootResource.id), externalId, None)
    DiscoveryTarget(ResourceScope.fromPath(Vector(resource, rootResource)).toOption.get, name)

  private val schema = Json.obj(
    "type" -> Json.fromString("object"),
    "properties" -> Json.obj(
      "repository_id" -> Json.obj("type" -> Json.fromString("string")),
      "limit" -> Json.obj("type" -> Json.fromString("integer"))
    ),
    "required" -> Json.arr(Json.fromString("repository_id")),
    "additionalProperties" -> Json.False
  )

  private final class Descriptor(argument: Option[String]) extends OperationDescriptor[Unit, Item]:
    val id: OperationId = OperationId.parse("test.items.read@1").get
    val tool: ExternalToolId = ExternalToolId.parse("test_items_read").get
    val description = "Read items."
    val capability: CapabilityKey = CapabilityKey.parse("Test.Item.Read").toOption.get
    val action: Action = Action.Read
    val target: ResourceKind[Item] = item
    val audience: ExecutorAudience = ExecutorAudience.parse("hallpass.local.test").get
    val inputSchema: Json = schema
    def decode(arguments: Json) = Right(())
    override def targetArgument: Option[String] = argument
    def locate(input: Unit) = ResourceLocator.Selected(ExternalRef[Item](ExternalId.parse("1").get))
    def facts(input: Unit) = AuthorizationContext.empty
    def canonical(input: Unit) = Json.obj()

  test("targets become titled oneOf constants on the declared argument only") {
    val rendered = AgentApi.withTargets(Descriptor(Some("repository_id")), Vector(target("2", "octo/zeta"), target("1", "octo/alpha")))
    val property = rendered.hcursor.downField("properties").downField("repository_id")
    assertEquals(property.get[String]("type").toOption, Some("string"))
    assertEquals(
      property.downField("oneOf").focus,
      Some(Json.arr(
        Json.obj("const" -> Json.fromString("1"), "title" -> Json.fromString("octo/alpha")),
        Json.obj("const" -> Json.fromString("2"), "title" -> Json.fromString("octo/zeta"))
      ))
    )
    assertEquals(rendered.hcursor.downField("properties").downField("limit").focus, schema.hcursor.downField("properties").downField("limit").focus)
    assertEquals(rendered.hcursor.downField("required").focus, schema.hcursor.downField("required").focus)
  }

  test("no target argument, or no targets, leaves the schema unchanged") {
    assertEquals(AgentApi.withTargets(Descriptor(None), Vector(target("1", "octo/alpha"))), schema)
    assertEquals(AgentApi.withTargets(Descriptor(Some("repository_id")), Vector.empty), schema)
  }

  test("an argument the schema does not declare leaves the schema unchanged") {
    assertEquals(AgentApi.withTargets(Descriptor(Some("missing")), Vector(target("1", "octo/alpha"))), schema)
  }

  test("the listing is bounded and titles are bounded and free of control characters") {
    val many = (1 to 200).toVector.map(index => target(index.toString, s"octo/repo-$index\u0000\n" + ("x" * 300)))
    val rendered = AgentApi.withTargets(Descriptor(Some("repository_id")), many)
    val choices = rendered.hcursor.downField("properties").downField("repository_id").downField("oneOf").focus.flatMap(_.asArray).get
    assertEquals(choices.size, AgentApi.MaximumListedTargets)
    val titles = choices.flatMap(_.hcursor.get[String]("title").toOption)
    assert(titles.forall(title => title.length <= 100 && !title.exists(Character.isISOControl)))
    // Within the bridge's 16 KiB schema bound.
    assert(rendered.noSpaces.getBytes("UTF-8").length <= 16 * 1024)
  }
