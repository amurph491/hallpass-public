package run.hallpass.bridge

import cats.effect.IO
import cats.syntax.all.*
import cats.effect.std.Dispatcher
import io.circe.Json
import io.circe.parser.parse
import io.modelcontextprotocol.spec.McpSchema
import munit.CatsEffectSuite
import scala.jdk.CollectionConverters.*

/** The MCP call handler: arguments pass through unchanged and every refusal has a provider-neutral message. */
final class McpToolHandlingSuite extends CatsEffectSuite:
  private def text(result: McpSchema.CallToolResult): String =
    result.content().asScala.collectFirst { case content: McpSchema.TextContent => content.text() }.getOrElse("")

  private def callWith(status: Int): IO[McpSchema.CallToolResult] =
    Dispatcher.parallel[IO].use: dispatcher =>
      AgentApiFixture.client("{}", status).use: client =>
        IO.blocking(McpStdioServer.handle(client, dispatcher, McpSchema.CallToolRequest.builder("any_tool").build()))

  test("a missing provider connection is reported without naming a provider") {
    callWith(424).map: result =>
      assert(result.isError)
      assertEquals(
        text(result),
        "This tool's provider is not connected in Hallpass, or its connection is unavailable. " +
          "An administrator can connect it in the Hallpass admin UI."
      )
  }

  test("an ambiguous tool-call failure says the outcome is unknown and must not be retried automatically") {
    List(408, 500, 502, 503, 504).traverse_ : status =>
      callWith(status).map: result =>
        assert(result.isError)
        assert(text(result).contains("may have completed"))
        assert(text(result).contains("do not retry automatically"))
  }

  test("a 400 says the arguments were rejected and a 404 says the tool is gone") {
    for
      invalid <- callWith(400)
      missing <- callWith(404)
      denied <- callWith(403)
      approval <- callWith(409)
      _ <- IO:
        assertEquals(text(invalid), "Hallpass rejected the tool arguments.")
        assertEquals(text(missing), "Hallpass no longer offers this tool.")
        assertEquals(text(denied), "Authorization denied.")
        assertEquals(text(approval), "Approval is required.")
        List(invalid, missing, denied, approval).foreach(result => assert(result.isError))
    yield ()
  }

  test("the call handler forwards arguments unchanged, and absent arguments become {}") {
    val nested: Map[String, Object] = Map(
      "query" -> "roadmap",
      "limit" -> Int.box(3),
      "filters" -> Map[String, Object](
        "tags" -> java.util.Arrays.asList[Object]("a", Int.box(1), null, java.lang.Boolean.TRUE)
      ).asJava,
      "nothing" -> null
    )
    Dispatcher.parallel[IO].use: dispatcher =>
      AgentApiFixture.endpointAndClientRecording("""{"content":"ok","correlationId":"c-1"}""").use: (_, client, recorder) =>
        for
          withArguments <- IO.blocking(
            McpStdioServer.handle(client, dispatcher, McpSchema.CallToolRequest.builder("github_issues_list").arguments(nested.asJava).build())
          )
          withoutArguments <- IO.blocking(
            McpStdioServer.handle(client, dispatcher, McpSchema.CallToolRequest.builder("github_issues_list").build())
          )
          _ <- IO:
            assert(!withArguments.isError && !withoutArguments.isError)
            assertEquals(text(withArguments), "ok")
            assertEquals(recorder.requests.map(_.path), List.fill(2)("/api/agent/tools/github_issues_list/call"))
            assertEquals(
              recorder.requests.map(request => parse(request.body)),
              List(
                Right(Json.obj("arguments" -> Json.obj(
                  "query" -> Json.fromString("roadmap"),
                  "limit" -> Json.fromInt(3),
                  "filters" -> Json.obj("tags" -> Json.arr(Json.fromString("a"), Json.fromInt(1), Json.Null, Json.True)),
                  "nothing" -> Json.Null
                ))),
                Right(Json.obj("arguments" -> Json.obj()))
              )
            )
        yield ()
  }

  test("arguments that are not plain JSON are refused without a request") {
    Dispatcher.parallel[IO].use: dispatcher =>
      AgentApiFixture.endpointAndClientRecording("{}").use: (_, client, recorder) =>
        val unusual = Map[String, Object]("value" -> Double.box(Double.NaN)).asJava
        IO.blocking(McpStdioServer.handle(client, dispatcher, McpSchema.CallToolRequest.builder("any_tool").arguments(unusual).build())).map: result =>
          assertEquals(text(result), "Hallpass rejected the tool arguments.")
          assertEquals(recorder.requests, Nil)
  }

  test("a tool name the bridge cannot send safely is refused without a request") {
    Dispatcher.parallel[IO].use: dispatcher =>
      AgentApiFixture.endpointAndClientRecording("{}").use: (_, client, recorder) =>
        IO.blocking(McpStdioServer.handle(client, dispatcher, McpSchema.CallToolRequest.builder("../escape").build())).map: result =>
          assertEquals(text(result), "Hallpass rejected the tool arguments.")
          assertEquals(recorder.requests, Nil)
  }
