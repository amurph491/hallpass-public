package run.hallpass.bridge

import cats.syntax.all.*
import cats.effect.{ExitCode, IO, Ref}
import cats.effect.std.Dispatcher
import io.circe.Json
import io.modelcontextprotocol.spec.McpSchema
import munit.CatsEffectSuite
import scala.concurrent.duration.*
import scala.jdk.CollectionConverters.*
import scala.util.control.NoStackTrace

/** Scheduling, startup, and client-facing messages, all without real sleeps or a live MCP transport. */
final class BridgeRefreshSuite extends CatsEffectSuite:
  import McpStdioServer.Poll

  private case object Stop extends RuntimeException with NoStackTrace

  private val ToolName = "slack_search_messages"
  private val objectSchema: Json = Json.obj("type" -> Json.fromString("object"))
  private val listed: Poll = Right(Vector(AgentTool(ToolName, "Search messages in the authorized Slack workspace.", objectSchema)))
  private val hidden: Vector[String] = Vector.empty
  private val shown: Vector[String] = Vector(ToolName)
  private val unlisted: Poll = Right(Vector.empty)

  private final case class Observed(sleeps: List[FiniteDuration], exposures: List[Vector[String]], logs: List[String], polls: Int)

  /** Runs the loop against scripted polls, stopping at the sleep that follows the last scripted poll. */
  private def drive(
      initial: Poll,
      polls: List[IO[Poll]],
      expose: (Vector[String], Ref[IO, List[Vector[String]]]) => IO[Unit] = (names, ref) => ref.update(_ :+ names)
  ): IO[Observed] =
    for
      script <- Ref.of[IO, List[IO[Poll]]](polls)
      sleeps <- Ref.of[IO, List[FiniteDuration]](Nil)
      exposures <- Ref.of[IO, List[Vector[String]]](Nil)
      logs <- Ref.of[IO, List[String]](Nil)
      polled <- Ref.of[IO, Int](0)
      poll = script.modify:
        case next :: rest => (rest, next)
        case Nil          => (Nil, IO.raiseError[Poll](AssertionError("polled past the script")))
      sleep = (delay: FiniteDuration) =>
        sleeps.updateAndGet(_ :+ delay).flatMap(all => IO.raiseWhen(all.size > polls.size)(Stop))
      _ <- McpStdioServer.RefreshLoop
        .start(
          poll = poll.flatten.flatTap(_ => polled.update(_ + 1)),
          expose = tools => expose(tools.map(_.name), exposures),
          log = line => logs.update(_ :+ line),
          jitter = IO.pure(0.0),
          sleep = sleep,
          initial = initial
        )
        .attempt
        .flatMap(result => IO(assertEquals(result.left.toOption, Some(Stop))))
      observed <- (sleeps.get, exposures.get, logs.get, polled.get).mapN(Observed.apply)
    yield observed

  test("a revoked credential backs off 5s, 10s, 20s instead of polling every second, and logs one line each way") {
    drive(
      initial = listed,
      polls = List(
        IO.pure(Left(AgentApiError.Unauthorized)),
        IO.pure(Left(AgentApiError.Unauthorized)),
        IO.pure(Left(AgentApiError.Unauthorized)),
        IO.pure(listed)
      )
    ).map: observed =>
      assertEquals(observed.sleeps, List(1, 5, 10, 20, 1).map(_.seconds))
      assertEquals(observed.exposures, List(hidden, hidden, hidden, shown))
      assertEquals(observed.logs.size, 2, observed.logs.toString)
      assert(observed.logs.head.contains("rejected"), observed.logs.head)
      assert(observed.logs.last.contains("reachable again"), observed.logs.last)
  }

  test("a credential rejected at startup schedules the first poll after 5s, not 1s") {
    drive(initial = Left(AgentApiError.Unauthorized), polls = List(IO.pure(Left(AgentApiError.Unauthorized)))).map: observed =>
      assertEquals(observed.sleeps, List(5.seconds, 10.seconds))
      assertEquals(observed.logs.size, 1)
  }

  test("a rate limit hint sets the next wait, and the tools are hidden until the API answers again") {
    drive(
      initial = listed,
      polls = List(IO.pure(Left(AgentApiError.RateLimited(Some(30.seconds)))), IO.pure(listed))
    ).map: observed =>
      assertEquals(observed.sleeps, List(1.second, 30.seconds, 1.second))
      assertEquals(observed.exposures, List(hidden, shown))
      assertEquals(observed.logs.size, 2)
  }

  test("outages back off from 2s, and a thrown poll is an outage that hides every tool") {
    drive(
      initial = listed,
      polls = List(
        IO.pure(Left(AgentApiError.Unavailable)),
        IO.raiseError(new RuntimeException("boom")),
        IO.pure(Left(AgentApiError.TimedOut)),
        IO.pure(unlisted)
      )
    ).map: observed =>
      assertEquals(observed.sleeps, List(1, 2, 4, 8, 1).map(_.seconds))
      assertEquals(observed.exposures, List.fill(4)(hidden))
      assertEquals(observed.logs.size, 2)
  }

  test("a healthy poll without the tool keeps the base interval and logs nothing") {
    drive(initial = unlisted, polls = List(IO.pure(unlisted), IO.pure(unlisted))).map: observed =>
      assertEquals(observed.sleeps, List.fill(3)(1.second))
      assertEquals(observed.exposures, List(hidden, hidden))
      assertEquals(observed.logs, Nil)
  }

  test("a failed exposure update falls back to hiding every tool and the loop keeps running") {
    drive(
      initial = listed,
      polls = List(IO.pure(listed), IO.pure(listed)),
      expose = (names, ref) =>
        // Showing the tool fails; hiding it succeeds.
        if names.nonEmpty then IO.raiseError(new RuntimeException("transport closed")) else ref.update(_ :+ names)
    ).map: observed =>
      assertEquals(observed.exposures, List(hidden, hidden))
      assertEquals(observed.polls, 2)
  }

  test("the loop exposes exactly the tools of the latest successful poll, and none after a failure") {
    def tool(name: String) = AgentTool(name, s"$name description", objectSchema)
    val first: Poll = Right(Vector(tool("alpha"), tool("beta")))
    val second: Poll = Right(Vector(tool("beta"), tool("gamma")))
    drive(
      initial = first,
      polls = List(IO.pure(first), IO.pure(second), IO.pure(Left(AgentApiError.Unavailable)), IO.pure(Right(Vector.empty)), IO.pure(first))
    ).map: observed =>
      assertEquals(
        observed.exposures,
        List(Vector("alpha", "beta"), Vector("beta", "gamma"), hidden, hidden, Vector("alpha", "beta"))
      )
  }

  test("an Unauthorized poll after startup hides every tool") {
    drive(initial = listed, polls = List(IO.pure(Left(AgentApiError.Unauthorized)))).map: observed =>
      assertEquals(observed.exposures, List(hidden))
  }

  test("startup does not serve when the API rejects the credential, and exits non-zero with one clear stderr line") {
    AgentApiFixture.endpointAndClient("{}", 401).use: (endpoint, client) =>
      for
        served <- Ref.of[IO, Boolean](false)
        lines <- Ref.of[IO, List[String]](Nil)
        exit <- BridgeStartup.launch(client, endpoint, line => lines.update(_ :+ line))(_ => served.set(true).as(ExitCode.Success))
        written <- lines.get
        wasServed <- served.get
      yield
        assert(!wasServed, "the MCP server must not start")
        assertNotEquals(exit, ExitCode.Success)
        assertEquals(written.size, 1)
        val line = written.head
        assert(line.contains("rejected") && line.contains("revoked, expired, or unknown"), line)
        assert(line.contains(endpoint.toString), line)
        assert(line.contains("hallpass doctor --client"), line)
        assert(!line.contains(AgentApiFixture.credential) && !line.contains('\n'), line)
  }

  test("startup still serves, with no tools, after a rate limit or an outage") {
    def outcome(status: Int, headers: List[(String, String)]) =
      AgentApiFixture.endpointAndClient("{}", status, headers).use: (endpoint, client) =>
        for
          initial <- Ref.of[IO, Option[Poll]](None)
          lines <- Ref.of[IO, List[String]](Nil)
          exit <- BridgeStartup.launch(client, endpoint, line => lines.update(_ :+ line))(poll => initial.set(Some(poll)).as(ExitCode.Success))
          seen <- initial.get
          written <- lines.get
        yield (exit, seen, written)
    for
      limited <- outcome(429, List("Retry-After" -> "9"))
      outage <- outcome(503, Nil)
      _ <- IO:
        assertEquals(limited, (ExitCode.Success, Some(Left(AgentApiError.RateLimited(Some(9.seconds)))), Nil))
        assertEquals(outage, (ExitCode.Success, Some(Left(AgentApiError.Unavailable)), Nil))
    yield ()
  }

  test("startup serves normally when the credential is accepted") {
    val body = """{"tools":[{"name":"slack_search_messages","description":"Search messages in the authorized Slack workspace.","inputSchema":{"type":"object","properties":{"query":{"type":"string","minLength":1,"maxLength":1000}},"required":["query"],"additionalProperties":false}}]}"""
    AgentApiFixture.endpointAndClient(body).use: (endpoint, client) =>
      BridgeStartup.launch(client, endpoint, _ => IO.unit)(poll => IO.pure(if poll.isRight then ExitCode.Success else ExitCode.Error))
        .map(exit => assertEquals(exit, ExitCode.Success))
  }

  private def toolCall(status: Int, headers: List[(String, String)] = Nil): IO[McpSchema.CallToolResult] =
    Dispatcher.parallel[IO].use: dispatcher =>
      AgentApiFixture.client("{}", status, headers).use: client =>
        IO.blocking:
          val request = McpSchema.CallToolRequest.builder(ToolName).arguments(Map[String, Object]("query" -> "roadmap").asJava).build()
          McpStdioServer.handle(client, dispatcher, request)

  private def text(result: McpSchema.CallToolResult): String =
    result.content().asScala.collectFirst { case content: McpSchema.TextContent => content.text() }.getOrElse("")

  test("a tool call rejected with 401 tells the user to fix the credential, not that the API is unavailable") {
    toolCall(401).map: result =>
      assert(result.isError)
      val message = text(result)
      assert(message.contains("rejected this agent's credential"), message)
      assert(message.contains("hallpass doctor"), message)
      assert(!message.contains("unavailable"), message)
  }

  test("a tool call rate limited with Retry-After says how long to wait") {
    toolCall(429, List("Retry-After" -> "12")).map: result =>
      assert(result.isError)
      assertEquals(text(result), "Hallpass is rate limiting this agent. Retry after 12 seconds.")
  }

  test("a tool call rate limited without a hint still says it is rate limited") {
    toolCall(429).map: result =>
      assert(result.isError)
      assert(text(result).contains("rate limiting"), text(result))
  }

  test("a tool-call outage preserves the unknown-outcome warning") {
    toolCall(503).map: result =>
      assert(result.isError)
      assertEquals(
        text(result),
        "The provider may have completed this operation, but Hallpass could not confirm it. " +
          "Check the result in the provider before trying again; do not retry automatically."
      )
  }
