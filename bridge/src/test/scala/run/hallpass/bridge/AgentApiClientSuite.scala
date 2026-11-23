package run.hallpass.bridge

import cats.effect.{IO, Resource}
import cats.syntax.all.*
import io.circe.Json
import munit.CatsEffectSuite
import scala.concurrent.duration.*

final class AgentApiClientSuite extends CatsEffectSuite:
  private val ToolName = "slack_search_messages"
  private val Arguments = Json.obj("query" -> Json.fromString("roadmap"))

  private def withClient(
      response: String,
      status: Int = 200,
      headers: List[(String, String)] = Nil
  ): Resource[IO, AgentApiClient] = AgentApiFixture.client(response, status, headers)

  test("accepts empty and multiline sanitized result content") {
    for
      empty <- withClient("""{"content":"","correlationId":"request-123"}""").use(_.callTool(ToolName, Arguments))
      multiline <- withClient("""{"content":"first result\nsecond result","correlationId":"request-456"}""").use(_.callTool(ToolName, Arguments))
      _ <- IO:
        assertEquals(empty, Right(AgentToolResult("", "request-123")))
        assertEquals(multiline, Right(AgentToolResult("first result\nsecond result", "request-456")))
    yield ()
  }

  test("maps each refusal to its own error, so the MCP client can say what to fix") {
    def statusOf(status: Int) =
      withClient("{\"error\":\"x\",\"message\":\"y\"}", status).use(_.callTool(ToolName, Arguments))
    for
      denied <- statusOf(403)
      approval <- statusOf(409)
      connection <- statusOf(424)
      outage <- statusOf(503)
      invalid <- statusOf(400)
      missing <- statusOf(404)
      unknown <- statusOf(502)
      _ <- IO:
        assertEquals(unknown, Left(AgentApiError.OutcomeUnknown))
        assertEquals(invalid, Left(AgentApiError.InvalidRequest))
        assertEquals(missing, Left(AgentApiError.NotFound))
        assertEquals(denied, Left(AgentApiError.Denied))
        assertEquals(approval, Left(AgentApiError.ApprovalRequired))
        assertEquals(connection, Left(AgentApiError.ConnectionUnavailable))
        assertEquals(outage, Left(AgentApiError.OutcomeUnknown))
    yield ()
  }

  test("a 401 is Unauthorized on both the tool list and a tool call") {
    val body = "{\"error\":\"unauthorized\"}"
    for
      listed <- withClient(body, 401).use(_.listTools)
      called <- withClient(body, 401).use(_.callTool(ToolName, Arguments))
      _ <- IO:
        assertEquals(listed, Left(AgentApiError.Unauthorized))
        assertEquals(called, Left(AgentApiError.Unauthorized))
    yield ()
  }

  test("a 429 carries the Retry-After delta-seconds, on both the tool list and a tool call") {
    def limited(value: String) = withClient("{}", 429, List("Retry-After" -> value))
    for
      listed <- limited("17").use(_.listTools)
      called <- limited("17").use(_.callTool(ToolName, Arguments))
      _ <- IO:
        assertEquals(listed, Left(AgentApiError.RateLimited(Some(17.seconds))))
        assertEquals(called, Left(AgentApiError.RateLimited(Some(17.seconds))))
    yield ()
  }

  test("a 429 without Retry-After is RateLimited with no hint") {
    for
      listed <- withClient("{}", 429).use(_.listTools)
      called <- withClient("{}", 429).use(_.callTool(ToolName, Arguments))
      _ <- IO:
        assertEquals(listed, Left(AgentApiError.RateLimited(None)))
        assertEquals(called, Left(AgentApiError.RateLimited(None)))
    yield ()
  }

  test("a Retry-After outside 1s..5 minutes is bounded, and a malformed one is ignored") {
    def hinted(value: String) = withClient("{}", 429, List("Retry-After" -> value)).use(_.listTools)
    for
      zero <- hinted("0")
      huge <- hinted("86400")
      overflow <- hinted("99999999999999999999999")
      date <- hinted("Wed, 21 Oct 2026 07:28:00 GMT")
      negative <- hinted("-5")
      fraction <- hinted("1.5")
      empty <- hinted("")
      _ <- IO:
        assertEquals(zero, Left(AgentApiError.RateLimited(Some(1.second))))
        assertEquals(huge, Left(AgentApiError.RateLimited(Some(5.minutes))))
        for malformed <- List(overflow, date, negative, fraction, empty) do
          assertEquals(malformed, Left(AgentApiError.RateLimited(None)))
    yield ()
  }

  test("a repeated Retry-After header is ignored rather than merged") {
    withClient("{}", 429, List("Retry-After" -> "5", "Retry-After" -> "200")).use(_.listTools).map: result =>
      assertEquals(result, Left(AgentApiError.RateLimited(None)))
  }

  test("timeouts and server errors stay Unavailable, and Retry-After on them is not interpreted") {
    for
      outage <- withClient("{}", 503, List("Retry-After" -> "60")).use(_.listTools)
      timeout <- withClient("{}", 408).use(_.listTools)
      _ <- IO:
        assertEquals(outage, Left(AgentApiError.Unavailable))
        assertEquals(timeout, Left(AgentApiError.Unavailable))
    yield ()
  }

  test("rejects control characters in correlation IDs and result content other than line breaks") {
    for
      invalidCorrelation <- withClient("""{"content":"ok","correlationId":"request\n123"}""").use(_.callTool(ToolName, Arguments))
      invalidContent <- withClient("""{"content":"first\u0001second","correlationId":"request-123"}""").use(_.callTool(ToolName, Arguments))
      _ <- IO:
        assertEquals(invalidCorrelation, Left(AgentApiError.OutcomeUnknown))
        assertEquals(invalidContent, Left(AgentApiError.OutcomeUnknown))
    yield ()
  }

  test("a proxy timeout or server error on a tool call is unknown, while tool listing stays unavailable") {
    List(408, 500, 502, 503, 504).traverse_ : status =>
      AgentApiFixture.endpointAndClientRecording("{}", status).use: (_, client, recorder) =>
        for
          called <- client.callTool(ToolName, Arguments)
          listed <- client.listTools
        yield
          assertEquals(called, Left(AgentApiError.OutcomeUnknown))
          assertEquals(listed, Left(AgentApiError.Unavailable))
          assertEquals(recorder.requests.count(_.method == "POST"), 1)
  }

  test("a truncated success response after a tool call is unknown and the call is never retried") {
    AgentApiFixture.endpointAndClientRecording(
      """{"content":"ok","correlationId":"request-123"}""",
      truncateResponse = true
    ).use: (_, client, recorder) =>
      client.callTool(ToolName, Arguments).map: result =>
        assertEquals(result, Left(AgentApiError.OutcomeUnknown))
        assertEquals(recorder.requests.size, 1)
  }

  test("a local timeout after the server receives a tool call is unknown and is never retried") {
    AgentApiFixture.endpointAndClientRecording(
      """{"content":"ok","correlationId":"request-123"}""",
      delayMillis = 12000
    ).use: (_, client, recorder) =>
      client.callTool(ToolName, Arguments).map: result =>
        assertEquals(result, Left(AgentApiError.OutcomeUnknown))
        assertEquals(recorder.requests.size, 1)
  }

  test("a malformed successful tool response is unknown because execution may already have completed") {
    withClient("not json").use(_.callTool(ToolName, Arguments)).map: result =>
      assertEquals(result, Left(AgentApiError.OutcomeUnknown))
  }
