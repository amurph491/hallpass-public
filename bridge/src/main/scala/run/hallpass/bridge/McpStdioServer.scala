package run.hallpass.bridge

import java.util.{List as JList, Map as JMap}
import java.net.URI
import cats.effect.{ExitCode, IO, IOApp, Ref, Resource}
import cats.effect.std.{Dispatcher, Random}
import cats.syntax.all.*
import io.circe.Json
import io.modelcontextprotocol.json.McpJsonDefaults
import io.modelcontextprotocol.server.{McpServer, McpServerFeatures, McpSyncServer}
import io.modelcontextprotocol.server.transport.StdioServerTransportProvider
import io.modelcontextprotocol.spec.McpSchema
import scala.concurrent.duration.*
import scala.jdk.CollectionConverters.*

/** What the MCP server currently has registered for one tool; `None` fields mean the SDK's value could not be read back. */
private[bridge] final case class RegisteredTool(name: String, description: Option[String], schema: Option[Json])

/** The part of the MCP server the bridge mutates, so the exposure diff can be tested without a transport. */
private[bridge] trait ToolRegistry:
  def registered: IO[Vector[RegisteredTool]]
  /** `false` when the server refused the tool (for example an invalid schema); the other tools are unaffected. */
  def add(tool: AgentTool): IO[Boolean]
  def remove(name: String): IO[Unit]
  def notifyChanged: IO[Unit]

/** Tools to remove, then tools to add. A changed tool appears in both: it is replaced, never edited in place. */
private[bridge] final case class ToolChanges(remove: Vector[String], add: Vector[AgentTool]):
  def isEmpty: Boolean = remove.isEmpty && add.isEmpty

private[bridge] object ToolExposure:
  /** Compares the server's registered tools with exactly the tools from the latest successful poll. */
  def plan(registered: Vector[RegisteredTool], desired: Vector[AgentTool]): ToolChanges =
    val current = registered.map(tool => tool.name -> tool).toMap
    val wanted = desired.map(tool => tool.name -> tool).toMap
    def unchanged(tool: AgentTool): Boolean =
      current.get(tool.name).exists(existing =>
        existing.description.contains(tool.description) && existing.schema.contains(tool.inputSchema)
      )
    ToolChanges(
      remove = registered.map(_.name).filter(name => wanted.get(name).forall(tool => !unchanged(tool))),
      add = desired.filterNot(unchanged)
    )

  /**
    * Applies the diff and announces an actual change once. An empty `desired` hides every tool. A tool the server
    * refuses is skipped without affecting the others, and a poll that changes nothing sends no notification.
    */
  def reconcile(registry: ToolRegistry, desired: Vector[AgentTool]): IO[Unit] =
    registry.registered.flatMap: registered =>
      val changes = plan(registered, desired)
      for
        _ <- changes.remove.traverse_(registry.remove)
        added <- changes.add.traverse(registry.add)
        _ <- registry.notifyChanged.whenA(changes.remove.nonEmpty || added.contains(true))
      yield ()

/** Plain Java collections are what the MCP SDK serializes; circe values never reach it directly. */
private[bridge] object JsonConversion:
  def toJava(json: Json): Object =
    json.fold[Object](
      jsonNull = null,
      jsonBoolean = Boolean.box,
      jsonNumber = number =>
        number.toInt.map(Int.box)
          .orElse(number.toLong.map(Long.box))
          .orElse(number.toBigInt.map(_.bigInteger))
          .getOrElse(new java.math.BigDecimal(number.toString)),
      jsonString = identity,
      jsonArray = values =>
        val list = new java.util.ArrayList[Object](values.size)
        values.foreach(value => list.add(toJava(value)))
        list,
      jsonObject = fields =>
        val map = new java.util.LinkedHashMap[String, Object]()
        fields.toIterable.foreach((key, value) => map.put(key, toJava(value)))
        map
    )

  def objectToJava(json: Json): Option[JMap[String, Object]] =
    json.asObject.map(_ => toJava(json).asInstanceOf[JMap[String, Object]])

  /** `None` when the value is not plain JSON (an unknown class, a non-string key, NaN or infinity). */
  def fromJava(value: Object): Option[Json] =
    value match
      case null => Some(Json.Null)
      case text: String => Some(Json.fromString(text))
      case flag: java.lang.Boolean => Some(Json.fromBoolean(flag))
      case n @ (_: java.lang.Integer | _: java.lang.Long | _: java.lang.Short | _: java.lang.Byte) =>
        Some(Json.fromLong(n.asInstanceOf[Number].longValue))
      case n: java.math.BigInteger => Some(Json.fromBigInt(BigInt(n)))
      case n: java.math.BigDecimal => Some(Json.fromBigDecimal(BigDecimal(n)))
      case n: java.lang.Double => Json.fromDouble(n)
      case n: java.lang.Float => Json.fromFloat(n)
      case map: JMap[?, ?] =>
        map.entrySet().asScala.toVector
          .traverse: entry =>
            entry.getKey match
              case key: String => fromJava(entry.getValue.asInstanceOf[Object]).map(key -> _)
              case _ => None
          .map(Json.fromFields)
      case list: JList[?] => list.asScala.toVector.traverse(item => fromJava(item.asInstanceOf[Object])).map(Json.fromValues)
      case _ => None

/** MCP adapter only: all authority and provider execution remain behind the authenticated Agent API. */
object McpStdioServer:
  type Poll = Either[AgentApiError, Vector[AgentTool]]

  private def writeStderr(line: String): IO[Unit] = IO.delay(System.err.println(line))

  /**
    * `initial` is the startup poll, so the first tool list needs no second request. Later polls follow
    * [[RefreshPolicy]]. stdout belongs to the MCP transport, so the only diagnostics are single stderr lines.
    */
  def resource(client: AgentApiClient, initial: Poll): Resource[IO, McpSyncServer] =
    for
      dispatcher <- Dispatcher.parallel[IO]
      random <- Resource.eval(Random.scalaUtilRandom[IO])
      server <- Resource.make(IO.delay(start()))(server => IO.blocking(server.close()).handleError(_ => ()))
      rejected <- Resource.eval(Ref.of[IO, Set[AgentTool]](Set.empty))
      toolRegistry = registry(server, client, dispatcher, writeStderr, rejected)
      expose = (tools: Vector[AgentTool]) => ToolExposure.reconcile(toolRegistry, tools)
      // The startup poll is exposed before the loop begins. A failure hides everything rather than half-exposing.
      _ <- Resource.eval(expose(exposed(initial)).handleErrorWith(_ => expose(Vector.empty).handleError(_ => ())))
      _ <- Resource.make(
        RefreshLoop.start(
          poll = client.listTools,
          expose = expose,
          log = writeStderr,
          jitter = random.nextDouble,
          sleep = IO.sleep,
          initial = initial
        ).start
      )(fiber => fiber.cancel)
    yield server

  /** Only a successful poll is evidence of current tools; any failure exposes none. */
  private def exposed(poll: Poll): Vector[AgentTool] = poll.getOrElse(Vector.empty)

  private def start(): McpSyncServer =
    McpServer
      .sync(new StdioServerTransportProvider(McpJsonDefaults.getMapper()))
      .serverInfo("hallpass-local-agent-bridge", "0.1.0")
      .capabilities(McpSchema.ServerCapabilities.builder().tools(true).build())
      .build()

  /**
    * The MCP SDK refuses a tool whose schema is not valid JSON Schema 2020-12. That tool is skipped and reported once
    * per distinct tool; it never stops the other tools from being exposed.
    */
  private[bridge] def registry(
      server: McpSyncServer,
      client: AgentApiClient,
      dispatcher: Dispatcher[IO],
      log: String => IO[Unit],
      rejected: Ref[IO, Set[AgentTool]]
  ): ToolRegistry =
    new ToolRegistry:
      def registered: IO[Vector[RegisteredTool]] =
        IO.blocking:
          server.listTools().asScala.toVector.map: tool =>
            RegisteredTool(tool.name(), Option(tool.description()), Option(tool.inputSchema()).flatMap(JsonConversion.fromJava(_)))
      def add(tool: AgentTool): IO[Boolean] =
        IO.blocking(server.addTool(toolSpecification(client, dispatcher, tool))).as(true).recoverWith:
          case _: IllegalArgumentException =>
            rejected.modify(seen => (if seen.size >= 256 then Set(tool) else seen + tool, !seen.contains(tool))).flatMap: firstTime =>
              log(s"Hallpass tool ${tool.name} was not exposed: its input schema is not a valid JSON Schema.").handleError(_ => ()).whenA(firstTime)
            .as(false)
      def remove(name: String): IO[Unit] = IO.blocking(server.removeTool(name))
      def notifyChanged: IO[Unit] = IO.blocking(server.notifyToolsListChanged())

  /** The refresh loop with every effect injected, so scheduling can be tested with a recording sleep. */
  private[bridge] object RefreshLoop:
    def start(
        poll: IO[Poll],
        expose: Vector[AgentTool] => IO[Unit],
        log: String => IO[Unit],
        jitter: IO[Double],
        sleep: FiniteDuration => IO[Unit],
        initial: Poll
    ): IO[Nothing] =
      // Nothing here can grant authority: a failed exposure hides every tool, and the server checks every call.
      def observe(previous: RefreshState, result: Poll): IO[(FiniteDuration, RefreshState)] =
        jitter.flatMap: sample =>
          val (delay, state) = RefreshPolicy.next(previous, RefreshOutcome.of(result), sample)
          RefreshPolicy.transition(previous.health, state.health).traverse_(line => log(line).handleError(_ => ())).as((delay, state))

      def cycle(pending: (FiniteDuration, RefreshState)): IO[(FiniteDuration, RefreshState)] =
        val (delay, previous) = pending
        // Delay every cycle, rather than only the first evaluation of an infinite program.
        sleep(delay) *> poll.attempt.flatMap: attempted =>
          // A bridge bearer or gateway failure is not evidence that the previous authority still applies.
          val result: Poll = attempted.fold(_ => Left(AgentApiError.Unavailable), identity)
          expose(exposed(result)).handleErrorWith(_ => expose(Vector.empty).handleError(_ => ())) *> observe(previous, result)

      observe(RefreshState.initial, initial).flatMap(_.iterateForeverM(cycle))

  private def toolSpecification(client: AgentApiClient, dispatcher: Dispatcher[IO], tool: AgentTool): McpServerFeatures.SyncToolSpecification =
    McpServerFeatures.SyncToolSpecification
      .builder()
      .tool(toolDefinition(tool))
      .callHandler((_, request) => handle(client, dispatcher, request))
      .build()

  /** The server's description and schema are passed through unchanged; `AgentApiClient` has already bounded them. */
  private[bridge] def toolDefinition(tool: AgentTool): McpSchema.Tool =
    val schema = JsonConversion.objectToJava(tool.inputSchema).getOrElse(JMap.of[String, Object]())
    McpSchema.Tool.builder(tool.name, schema).description(tool.description).build()

  /**
    * The MCP Java SDK requires a synchronous callback; the outbound call is bounded by the HTTP client. Arguments are
    * forwarded unchanged: the server validates them, and [[AgentApiClient.callTool]] only bounds their shape and size.
    */
  private[bridge] def handle(
      client: AgentApiClient,
      dispatcher: Dispatcher[IO],
      request: McpSchema.CallToolRequest
  ): McpSchema.CallToolResult =
    argumentsOf(request) match
      case None => error(Messages.InvalidArguments)
      case Some(arguments) =>
        dispatcher.unsafeRunSync(client.callTool(request.name(), arguments)) match
          case Right(result) => success(result.content)
          case Left(AgentApiError.Denied) => error("Authorization denied.")
          case Left(AgentApiError.ApprovalRequired) => error("Approval is required.")
          case Left(AgentApiError.ApprovalPending(id)) => error(Messages.approvalPending(id))
          case Left(AgentApiError.ConnectionUnavailable) => error(Messages.ConnectionUnavailable)
          case Left(AgentApiError.Unauthorized) => error(Messages.CredentialRejected)
          case Left(AgentApiError.RateLimited(retryAfter)) => error(Messages.rateLimited(retryAfter))
          case Left(AgentApiError.InvalidRequest) => error(Messages.InvalidArguments)
          case Left(AgentApiError.NotFound) => error(Messages.ToolNotOffered)
          case Left(AgentApiError.OutcomeUnknown) => error(Messages.OutcomeUnknown)
          case Left(_) => error("Hallpass agent API is currently unavailable.")

  /** An absent `arguments` means no arguments; anything that is not plain JSON is refused without a request. */
  private def argumentsOf(request: McpSchema.CallToolRequest): Option[Json] =
    Option(request.arguments()) match
      case None => Some(Json.obj())
      case Some(arguments) => JsonConversion.fromJava(arguments)

  /** Text shown to the MCP client. It names what to fix and never includes a credential or a response body. */
  private[bridge] object Messages:
    val CredentialRejected: String =
      "Hallpass rejected this agent's credential; it may be revoked, expired, or unknown. Run " +
        "`hallpass doctor --client <client> --agent <agent>`, import a valid credential with " +
        "`hallpass credential import --rotate` (a revoked credential file still exists), and restart this client."
    val ConnectionUnavailable: String =
      "This tool's provider is not connected in Hallpass, or its connection is unavailable. " +
        "An administrator can connect it in the Hallpass admin UI."
    val InvalidArguments: String = "Hallpass rejected the tool arguments."
    val ToolNotOffered: String = "Hallpass no longer offers this tool."
    val OutcomeUnknown: String =
      "The provider may have completed this operation, but Hallpass could not confirm it. " +
        "Check the result in the provider before trying again; do not retry automatically."

    /** `id` is a validated approval UUID. */
    def approvalPending(id: String): String =
      s"Approval is required. An Hallpass administrator must approve this exact request (approval $id). " +
        "After it is approved, call the tool again with exactly the same arguments."

    def rateLimited(retryAfter: Option[FiniteDuration]): String =
      retryAfter match
        case Some(delay) =>
          val seconds = math.max(1L, (delay.toMillis + 999) / 1000)
          s"Hallpass is rate limiting this agent. Retry after $seconds seconds."
        case None => "Hallpass is rate limiting this agent. Retry in a few seconds."

  private def success(text: String): McpSchema.CallToolResult =
    McpSchema.CallToolResult.builder(JList.of(McpSchema.TextContent.builder(text).build())).build()

  private def error(text: String): McpSchema.CallToolResult =
    McpSchema.CallToolResult.builder(JList.of(McpSchema.TextContent.builder(text).build())).isError(true).build()

/** Startup: a credential the API rejects will not recover within this session, so the bridge refuses to serve. */
private[bridge] object BridgeStartup:
  val CredentialRejectedExit: ExitCode = ExitCode(2)

  def rejectedMessage(endpoint: URI): String =
    s"Hallpass rejected this agent's credential (revoked, expired, or unknown) at $endpoint. " +
      "Run `hallpass doctor --client <client> --agent <agent>` and re-import a valid credential with `hallpass credential import --rotate`."

  /**
    * `serve` runs only when the credential was not rejected. Any other startup failure still serves, with no tools
    * exposed, so the refresh loop can recover from an outage. The endpoint is the normalized scheme and authority.
    */
  def launch(client: AgentApiClient, endpoint: URI, stderr: String => IO[Unit])(
      serve: McpStdioServer.Poll => IO[ExitCode]
  ): IO[ExitCode] =
    client.listTools.flatMap:
      case Left(AgentApiError.Unauthorized) => stderr(rejectedMessage(endpoint)).as(CredentialRejectedExit)
      case initial                          => serve(initial)

object HallpassMcpMain extends IOApp:
  def run(args: List[String]): IO[ExitCode] =
    if args.nonEmpty then
      IO.delay(System.err.println("Hallpass local agent bridge accepts no command-line arguments.")).as(ExitCode.Error)
    else
      BridgeConfig.load() match
        case Left(_) => IO.delay(System.err.println("Hallpass local agent bridge configuration is invalid.")).as(ExitCode.Error)
        case Right(config) =>
          AgentApiClient.resource(config).use: client =>
            BridgeStartup.launch(client, config.endpoint, line => IO.delay(System.err.println(line))): initial =>
              McpStdioServer.resource(client, initial)
                .evalTap(_ => IO.delay(System.err.println("Hallpass local agent bridge started.")))
                .use(_ => IO.never.as(ExitCode.Success))
