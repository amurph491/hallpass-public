package run.hallpass.bridge

import cats.effect.IO
import cats.syntax.all.*
import io.circe.Json
import io.circe.parser.parse
import munit.CatsEffectSuite

/** The tool list and tool call contract: bounds on what the server may list and on what the bridge will send. */
final class AgentToolsSuite extends CatsEffectSuite:
  private val ToolResult = """{"content":"ok","correlationId":"request-1"}"""

  private def schema(extra: (String, Json)*): Json =
    Json.obj((("type" -> Json.fromString("object")) +: extra)*)

  private val searchSchema: Json = schema(
    "properties" -> Json.obj("query" -> Json.obj("type" -> Json.fromString("string"))),
    "required" -> Json.arr(Json.fromString("query"))
  )

  private def listed(name: String, description: String = "Does a thing.", inputSchema: Json = searchSchema): Json =
    Json.obj(
      "name" -> Json.fromString(name),
      "description" -> Json.fromString(description),
      "inputSchema" -> inputSchema
    )

  private def body(tools: Json*): String = Json.obj("tools" -> Json.arr(tools*)).noSpaces

  private def list(response: String) = AgentApiFixture.client(response).use(_.listTools)

  /** A schema whose root object is `depth` levels deep, counting the root as 1. */
  private def nested(depth: Int): Json =
    if depth <= 1 then schema() else schema("x" -> nested(depth - 1))

  /** A schema whose compact serialization is exactly `bytes` long. */
  private def sized(bytes: Int): Json =
    val empty = schema("pad" -> Json.fromString("")).noSpaces.length
    schema("pad" -> Json.fromString("a" * (bytes - empty)))

  test("lists several tools with their descriptions and schemas exactly as sent") {
    list(body(listed("slack_search_messages"), listed("github_issues_list", "Lists issues.", nested(3)), listed("Tool_2"))).map: result =>
      assertEquals(
        result,
        Right(Vector(
          AgentTool("slack_search_messages", "Does a thing.", searchSchema),
          AgentTool("github_issues_list", "Lists issues.", nested(3)),
          AgentTool("Tool_2", "Does a thing.", searchSchema)
        ))
      )
  }

  test("an empty list is valid and means no tools") {
    list(body()).map(result => assertEquals(result, Right(Vector.empty)))
  }

  test("one invalid tool is dropped and the valid ones are kept") {
    val invalid = Vector(
      "bad name" -> listed("a/b"),
      "empty name" -> listed(""),
      "long name" -> listed("a" * 65),
      "dash in name" -> listed("a-b"),
      "unicode name" -> listed("café"),
      "oversize schema" -> listed("big_schema", inputSchema = sized(16 * 1024 + 1)),
      "deep schema" -> listed("deep_schema", inputSchema = nested(33)),
      "array schema" -> listed("array_schema", inputSchema = Json.arr()),
      "non-object type" -> listed("string_type", inputSchema = Json.obj("type" -> Json.fromString("string"))),
      "missing type" -> listed("no_type", inputSchema = Json.obj("properties" -> Json.obj())),
      "control character" -> listed("control_char", description = "line\nbreak"),
      "empty description" -> listed("no_description", description = ""),
      "long description" -> listed("long_description", description = "d" * 1025),
      "extra key" -> listed("extra_key").mapObject(_.add("annotations", Json.obj())),
      "missing key" -> listed("missing_key").mapObject(_.remove("description")),
      "not an object" -> Json.fromString("tool")
    )
    invalid.traverse_ : (label, entry) =>
      list(body(listed("kept_before"), entry, listed("kept_after"))).map: result =>
        assertEquals(result.map(_.map(_.name)), Right(Vector("kept_before", "kept_after")), label)
  }

  test("every invalid tool at once still leaves the valid ones") {
    val entries = Vector(listed("a/b"), listed("kept"), listed("big", inputSchema = sized(20000)), listed("deep", inputSchema = nested(40)))
    list(body(entries*)).map(result => assertEquals(result.map(_.map(_.name)), Right(Vector("kept"))))
  }

  test("schema depth 32 and size 16 KiB are accepted, one more is not") {
    for
      accepted <- list(body(listed("depth_32", inputSchema = nested(32)), listed("size_limit", inputSchema = sized(16 * 1024))))
      dropped <- list(body(listed("depth_33", inputSchema = nested(33)), listed("size_over", inputSchema = sized(16 * 1024 + 1))))
      _ <- IO:
        assertEquals(accepted.map(_.map(_.name)), Right(Vector("depth_32", "size_limit")))
        assertEquals(dropped, Right(Vector.empty))
    yield ()
  }

  test("a description of 1024 characters is accepted and 1 character is the minimum") {
    list(body(listed("longest", description = "d" * 1024), listed("shortest", description = "d"))).map: result =>
      assertEquals(result.map(_.map(_.name)), Right(Vector("longest", "shortest")))
  }

  test("64 tools are accepted and 65 make the whole response invalid") {
    def many(count: Int) = body((1 to count).map(index => listed(s"tool_$index"))*)
    for
      accepted <- list(many(64))
      rejected <- list(many(65))
      _ <- IO:
        assertEquals(accepted.map(_.size), Right(64))
        assertEquals(rejected, Left(AgentApiError.InvalidResponse))
    yield ()
  }

  test("duplicate tool names make the whole response invalid") {
    list(body(listed("same"), listed("other"), listed("same", "A different description."))).map: result =>
      assertEquals(result, Left(AgentApiError.InvalidResponse))
  }

  test("a malformed root is invalid") {
    for
      results <- List("[]", "{}", """{"tools":{}}""", """{"tools":"x"}""", """{"other":[]}""", "not json", "").traverse(list)
      _ <- IO(results.foreach(result => assertEquals(result, Left(AgentApiError.InvalidResponse))))
    yield ()
  }

  test("the tool list is a GET with the bearer only in Authorization") {
    AgentApiFixture.endpointAndClientRecording(body(listed("one"))).use: (_, client, recorder) =>
      client.listTools.map: _ =>
        val request = recorder.requests.head
        assertEquals(recorder.requests.size, 1)
        assertEquals((request.method, request.path), ("GET", "/api/agent/tools"))
        assertEquals(request.authorization, Some(s"Bearer ${AgentApiFixture.credential}"))
  }

  private val unsafeNames = List("../x", "a/b", "%2e", "%2e%2e", "a b", "a?b", "a#b", "a.b", "a" * 65, "", "café", "a\nb", "..")

  test("callTool refuses unsafe tool names without sending any request") {
    AgentApiFixture.endpointAndClientRecording(ToolResult).use: (_, client, recorder) =>
      unsafeNames.traverse(name => client.callTool(name, Json.obj())).map: results =>
        results.zip(unsafeNames).foreach((result, name) => assertEquals(result, Left(AgentApiError.InvalidRequest), name))
        assertEquals(recorder.requests, Nil)
  }

  test("callTool accepts names of 1 to 64 letters, digits, and underscores") {
    AgentApiFixture.endpointAndClientRecording(ToolResult).use: (_, client, recorder) =>
      val names = List("a", "A_9", "a" * 64)
      names.traverse(name => client.callTool(name, Json.obj())).map: results =>
        results.foreach(result => assertEquals(result, Right(AgentToolResult("ok", "request-1"))))
        assertEquals(recorder.requests.map(_.path), names.map(name => s"/api/agent/tools/$name/call"))
  }

  test("callTool refuses arguments that are not a JSON object or are over 15 KiB, without sending a request") {
    val overLimit = Json.obj("pad" -> Json.fromString("a" * (15 * 1024)))
    AgentApiFixture.endpointAndClientRecording(ToolResult).use: (_, client, recorder) =>
      val refused = List(
        Json.arr(), Json.fromString("x"), Json.Null, Json.fromInt(1), Json.True, Json.arr(Json.obj()), overLimit
      )
      refused.traverse(arguments => client.callTool("some_tool", arguments)).map: results =>
        results.foreach(result => assertEquals(result, Left(AgentApiError.InvalidRequest)))
        assertEquals(recorder.requests, Nil)
  }

  test("callTool accepts arguments of exactly 15 KiB") {
    val empty = Json.obj("pad" -> Json.fromString("")).noSpaces.length
    val atLimit = Json.obj("pad" -> Json.fromString("a" * (15 * 1024 - empty)))
    assertEquals(atLimit.noSpaces.length, 15 * 1024)
    AgentApiFixture.endpointAndClientRecording(ToolResult).use: (_, client, recorder) =>
      client.callTool("some_tool", atLimit).map: result =>
        assertEquals(result, Right(AgentToolResult("ok", "request-1")))
        assertEquals(recorder.requests.size, 1)
  }

  test("callTool posts {\"arguments\":...} unchanged to the tool's call path, with the bearer only in Authorization") {
    val arguments = Json.obj(
      "query" -> Json.fromString("röadmap \"quoted\""),
      "limit" -> Json.fromInt(5),
      "ratio" -> Json.fromDoubleOrNull(0.5),
      "flag" -> Json.False,
      "nothing" -> Json.Null,
      "nested" -> Json.obj("list" -> Json.arr(Json.fromInt(1), Json.obj("deep" -> Json.True)))
    )
    AgentApiFixture.endpointAndClientRecording(ToolResult).use: (_, client, recorder) =>
      client.callTool("github_issues_get", arguments).map: result =>
        assertEquals(result, Right(AgentToolResult("ok", "request-1")))
        val request = recorder.requests.head
        assertEquals(recorder.requests.size, 1)
        assertEquals((request.method, request.path), ("POST", "/api/agent/tools/github_issues_get/call"))
        assertEquals(request.authorization, Some(s"Bearer ${AgentApiFixture.credential}"))
        assertEquals(parse(request.body), Right(Json.obj("arguments" -> arguments)))
        assert(!request.body.contains(AgentApiFixture.credential), "the bearer must not appear in the body")
        val elsewhere = request.headers.removed("Authorization").values.flatten
        assert(elsewhere.forall(!_.contains(AgentApiFixture.credential)), "the bearer must appear only in Authorization")
        assert(!request.path.contains(AgentApiFixture.credential))
  }

  test("an empty arguments object is forwarded as {}") {
    AgentApiFixture.endpointAndClientRecording(ToolResult).use: (_, client, recorder) =>
      client.callTool("some_tool", Json.obj()).map: _ =>
        assertEquals(recorder.requests.head.body, """{"arguments":{}}""")
  }
