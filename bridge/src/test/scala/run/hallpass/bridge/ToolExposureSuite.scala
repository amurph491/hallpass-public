package run.hallpass.bridge

import java.io.{ByteArrayOutputStream, PipedInputStream, PipedOutputStream}
import cats.effect.{IO, Ref, Resource}
import cats.effect.std.Dispatcher
import io.circe.Json
import io.circe.parser.parse
import io.modelcontextprotocol.json.McpJsonDefaults
import io.modelcontextprotocol.server.{McpServer, McpSyncServer}
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider
import io.modelcontextprotocol.spec.McpSchema
import munit.CatsEffectSuite
import scala.jdk.CollectionConverters.*

/** The exposure diff, the circe-to-MCP schema conversion, and the real MCP server registry. */
final class ToolExposureSuite extends CatsEffectSuite:
  private def objectSchema(extra: (String, Json)*): Json = Json.obj((("type" -> Json.fromString("object")) +: extra)*)
  private def tool(name: String, description: String = "A tool.", schema: Json = objectSchema()): AgentTool =
    AgentTool(name, description, schema)
  private def registered(tool: AgentTool): RegisteredTool = RegisteredTool(tool.name, Some(tool.description), Some(tool.inputSchema))

  /** A real MCP server whose stdin never reaches end of file, so its session stays open like the bridge's does. */
  private def realServer: Resource[IO, McpSyncServer] =
    Resource.make(IO.blocking:
      McpServer
        .sync(new StdioServerTransportProvider(
          McpJsonDefaults.getMapper(),
          new PipedInputStream(new PipedOutputStream()),
          new ByteArrayOutputStream()
        ))
        .serverInfo("test", "0")
        .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
        .build()
    )(server => IO.blocking(server.close()).handleError(_ => ()))

  /** A registry that records every mutation and notification, in order. */
  private final class FakeRegistry(initial: Vector[AgentTool], refuses: Set[String] = Set.empty) extends ToolRegistry:
    private val state = Ref.unsafe[IO, Vector[AgentTool]](initial)
    private val log = Ref.unsafe[IO, Vector[String]](Vector.empty)
    def registered: IO[Vector[RegisteredTool]] = state.get.map(_.map(ToolExposureSuite.this.registered))
    def add(tool: AgentTool): IO[Boolean] =
      if refuses.contains(tool.name) then log.update(_ :+ s"refused ${tool.name}").as(false)
      else state.update(_ :+ tool) *> log.update(_ :+ s"add ${tool.name}").as(true)
    def remove(name: String): IO[Unit] = state.update(_.filterNot(_.name == name)) *> log.update(_ :+ s"remove $name")
    def notifyChanged: IO[Unit] = log.update(_ :+ "notify")
    def names: IO[Vector[String]] = state.get.map(_.map(_.name))
    def events: IO[Vector[String]] = log.get

  test("a first poll adds every tool and notifies once") {
    val registry = FakeRegistry(Vector.empty)
    for
      _ <- ToolExposure.reconcile(registry, Vector(tool("a"), tool("b")))
      events <- registry.events
      _ <- IO(assertEquals(events, Vector("add a", "add b", "notify")))
    yield ()
  }

  test("an identical poll changes nothing and sends no notification") {
    val tools = Vector(tool("a", schema = objectSchema("x" -> Json.fromInt(1))), tool("b"))
    val registry = FakeRegistry(tools)
    ToolExposure.reconcile(registry, tools) *> registry.events.map(events => assertEquals(events, Vector.empty))
  }

  test("tools no longer listed are removed, new ones are added, and the change is announced once") {
    val registry = FakeRegistry(Vector(tool("keep"), tool("gone")))
    for
      _ <- ToolExposure.reconcile(registry, Vector(tool("keep"), tool("new")))
      names <- registry.names
      events <- registry.events
      _ <- IO:
        assertEquals(names.toSet, Set("keep", "new"))
        assertEquals(events, Vector("remove gone", "add new", "notify"))
    yield ()
  }

  test("a tool whose description or schema changed is replaced, not edited, and notified once") {
    val registry = FakeRegistry(Vector(tool("described"), tool("shaped"), tool("same")))
    for
      _ <- ToolExposure.reconcile(
        registry,
        Vector(tool("described", "New words."), tool("shaped", schema = objectSchema("required" -> Json.arr())), tool("same"))
      )
      events <- registry.events
      _ <- IO(assertEquals(events, Vector("remove described", "remove shaped", "add described", "add shaped", "notify")))
    yield ()
  }

  test("a tool the server refuses is skipped, the others are still exposed, and a refused-only poll does not notify") {
    val registry = FakeRegistry(Vector.empty, refuses = Set("bad"))
    for
      _ <- ToolExposure.reconcile(registry, Vector(tool("bad"), tool("good")))
      names <- registry.names
      events <- registry.events
      _ <- ToolExposure.reconcile(registry, Vector(tool("bad"), tool("good")))
      repeated <- registry.events
      _ <- IO:
        assertEquals(names, Vector("good"))
        assertEquals(events, Vector("refused bad", "add good", "notify"))
        assertEquals(repeated, events ++ Vector("refused bad"))
    yield ()
  }

  test("an empty poll result hides every tool with one notification") {
    val registry = FakeRegistry(Vector(tool("a"), tool("b")))
    for
      _ <- ToolExposure.reconcile(registry, Vector.empty)
      names <- registry.names
      events <- registry.events
      _ <- IO:
        assertEquals(names, Vector.empty)
        assertEquals(events, Vector("remove a", "remove b", "notify"))
    yield ()
  }

  test("a registered tool whose description or schema cannot be read back is replaced") {
    val unreadable = RegisteredTool("a", None, None)
    assertEquals(ToolExposure.plan(Vector(unreadable), Vector(tool("a"))), ToolChanges(Vector("a"), Vector(tool("a"))))
  }

  test("numbers compare by value, so an integer stored as a long is not a change") {
    val stored = RegisteredTool("a", Some("A tool."), Some(objectSchema("maxLength" -> Json.fromLong(1000L))))
    assert(ToolExposure.plan(Vector(stored), Vector(tool("a", schema = objectSchema("maxLength" -> Json.fromInt(1000))))).isEmpty)
  }

  private val rich: Json = parse(
    """{"type":"object","properties":{"query":{"type":"string","minLength":1,"maxLength":1000},
      |"limit":{"type":"integer","minimum":0,"maximum":9007199254740993,"default":25},
      |"ratio":{"type":"number","exclusiveMinimum":0.5,"const":0.12345678901234567890123456789},"enabled":{"type":"boolean","default":false},
      |"note":{"type":["string","null"],"default":null},
      |"tags":{"type":"array","items":{"type":"string","enum":["a","b"]}},
      |"nested":{"type":"object","properties":{"deep":{"type":"array","prefixItems":[{"type":"integer"},{"type":"null"}]}}}},
      |"required":["query"],"additionalProperties":false}""".stripMargin
  ).fold(error => throw error, identity)

  test("the schema converter round-trips nested objects, arrays, numbers, booleans, and null") {
    val java = JsonConversion.toJava(rich)
    assertEquals(JsonConversion.fromJava(java), Some(rich))
  }

  test("the schema converter produces plain Java collections and boxed scalars") {
    val converted = JsonConversion.objectToJava(rich).getOrElse(fail("not an object"))
    assertEquals(converted.get("type"), "object")
    assertEquals(converted.get("required"), java.util.List.of("query"))
    assertEquals(converted.get("additionalProperties"), java.lang.Boolean.FALSE)
    val properties = converted.get("properties").asInstanceOf[java.util.Map[String, Object]]
    val limit = properties.get("limit").asInstanceOf[java.util.Map[String, Object]]
    assertEquals(limit.get("minimum"), Int.box(0))
    assertEquals(limit.get("maximum"), Long.box(9007199254740993L))
    val ratio = properties.get("ratio").asInstanceOf[java.util.Map[String, Object]]
    assertEquals(ratio.get("exclusiveMinimum"), new java.math.BigDecimal("0.5"))
    assertEquals(properties.get("note").asInstanceOf[java.util.Map[String, Object]].get("default"), null)
    assertEquals(JsonConversion.objectToJava(Json.arr()), None)
  }

  test("the converter's reverse direction refuses values that are not plain JSON") {
    assertEquals(JsonConversion.fromJava(Double.box(Double.NaN)), None)
    assertEquals(JsonConversion.fromJava(Double.box(Double.PositiveInfinity)), None)
    assertEquals(JsonConversion.fromJava(new Object), None)
    assertEquals(JsonConversion.fromJava(java.util.Map.of(Int.box(1), "x")), None)
    assertEquals(JsonConversion.fromJava(null), Some(Json.Null))
  }

  test("the MCP tool definition carries the server's description and converted schema") {
    val definition = McpStdioServer.toolDefinition(tool("github_issues_list", "Lists issues.", rich))
    assertEquals(definition.name(), "github_issues_list")
    assertEquals(definition.description(), "Lists issues.")
    assertEquals(JsonConversion.fromJava(definition.inputSchema()), Some(rich))
  }

  test("against a real MCP server, exposure adds, replaces, and removes tools, notifying once per change and never spuriously") {
    Dispatcher.parallel[IO].use: dispatcher =>
      AgentApiFixture.client("{}").flatMap(client => realServer.map(server => (client, server))).use: (client, server) =>
        val underlying = McpStdioServer.registry(server, client, dispatcher, _ => IO.unit, Ref.unsafe[IO, Set[AgentTool]](Set.empty))
        val notifications = Ref.unsafe[IO, Int](0)
        val counting = new ToolRegistry:
          def registered = underlying.registered
          def add(tool: AgentTool) = underlying.add(tool)
          def remove(name: String) = underlying.remove(name)
          def notifyChanged = notifications.update(_ + 1) *> underlying.notifyChanged
        def exposedNames = IO.blocking(server.listTools().asScala.map(_.name()).toSet)
        def exposedDescription(name: String) = IO.blocking(server.listTools().asScala.find(_.name() == name).map(_.description()))
        val one = tool("one", schema = rich)
        val two = tool("two", schema = objectSchema("maxLength" -> Json.fromInt(7)))
        for
          _ <- ToolExposure.reconcile(counting, Vector(one, two))
          afterAdd <- exposedNames
          _ <- ToolExposure.reconcile(counting, Vector(one, two))
          _ <- ToolExposure.reconcile(counting, Vector(one, two))
          afterRepeat <- notifications.get
          _ <- ToolExposure.reconcile(counting, Vector(one.copy(description = "Changed."), two))
          replaced <- exposedDescription("one")
          _ <- ToolExposure.reconcile(counting, Vector(two))
          afterRemove <- exposedNames
          _ <- ToolExposure.reconcile(counting, Vector.empty)
          afterHide <- exposedNames
          total <- notifications.get
          _ <- IO:
            assertEquals(afterAdd, Set("one", "two"))
            assertEquals(afterRepeat, 1, "an unchanged poll must not notify")
            assertEquals(replaced, Some("Changed."))
            assertEquals(afterRemove, Set("two"))
            assertEquals(afterHide, Set.empty[String])
            assertEquals(total, 4)
        yield ()
  }

  test("against a real MCP server, a schema the SDK refuses is skipped and reported once, without hiding other tools") {
    Dispatcher.parallel[IO].use: dispatcher =>
      AgentApiFixture.client("{}").flatMap(client => realServer.map(server => (client, server))).use: (client, server) =>
        val lines = Ref.unsafe[IO, Vector[String]](Vector.empty)
        val registry = McpStdioServer.registry(server, client, dispatcher, line => lines.update(_ :+ line), Ref.unsafe[IO, Set[AgentTool]](Set.empty))
        // `items` must be a schema in JSON Schema 2020-12; the array form is the obsolete tuple syntax.
        val refused = tool("refused", schema = objectSchema("items" -> Json.arr(Json.obj())))
        for
          _ <- ToolExposure.reconcile(registry, Vector(refused, tool("accepted")))
          _ <- ToolExposure.reconcile(registry, Vector(refused, tool("accepted")))
          names <- IO.blocking(server.listTools().asScala.map(_.name()).toSet)
          reported <- lines.get
          _ <- IO:
            assertEquals(names, Set("accepted"))
            assertEquals(reported, Vector("Hallpass tool refused was not exposed: its input schema is not a valid JSON Schema."))
        yield ()
  }
