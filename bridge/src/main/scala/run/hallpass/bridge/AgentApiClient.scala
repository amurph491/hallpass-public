package run.hallpass.bridge

import java.io.InputStream
import java.net.URI
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.Executors
import cats.effect.{IO, Resource}
import cats.syntax.all.*
import io.circe.{Json, JsonObject}
import io.circe.parser.parse
import scala.concurrent.duration.*

enum AgentApiError:
  case Unauthorized, Denied, ApprovalRequired, ConnectionUnavailable, InvalidResponse, ResponseTooLarge, Unavailable, TimedOut
  /** A tool call whose result could not be confirmed: the provider may have applied the operation.
    * Includes transport failures and proxy errors, since the request may have reached the server. Never retried. */
  case OutcomeUnknown
  /** The bridge refused to send the call (bad name or arguments shape/size), or the server answered 400. */
  case InvalidRequest
  /** A 409 that names the pending approval created for this exact call. The bridge has remembered it for a retry. */
  case ApprovalPending(approvalId: String)
  /** The server answered 404: it no longer offers this tool. */
  case NotFound
  /** The agent API asked this client to slow down. `retryAfter` is the server's hint, already bounded by [[RetryAfter]]. */
  case RateLimited(retryAfter: Option[FiniteDuration])

/**
  * Only the delta-seconds form of `Retry-After` is honored. An HTTP-date, a fraction, a sign, or anything else is
  * ignored rather than interpreted, and a valid value is bounded so a hostile or broken server cannot park the bridge.
  */
private[bridge] object RetryAfter:
  val Minimum: FiniteDuration = 1.second
  val Maximum: FiniteDuration = 5.minutes
  private val DeltaSeconds = "[0-9]{1,18}".r

  def parse(header: Option[String]): Option[FiniteDuration] =
    header.map(_.trim).collect:
      case value @ DeltaSeconds() => value.toLong.seconds.max(Minimum).min(Maximum)

/**
  * A tool exactly as the server listed it. `inputSchema` is an untrusted description handed to the MCP client; the
  * bridge bounds its size and shape but never interprets it, and the server validates every call's arguments.
  */
final case class AgentTool private[bridge] (name: String, description: String, inputSchema: Json)
final case class AgentToolResult private[bridge] (content: String, correlationId: String)

/**
  * Narrow client for the fixed local agent API. It has no generic request method so a bearer cannot be sent to a
  * caller-selected origin or path, and it never retries a tool invocation.
  */
final class AgentApiClient private (config: BridgeConfig, client: HttpClient, approvals: ApprovalMemory):
  import AgentApiClient.*

  def listTools: IO[Either[AgentApiError, Vector[AgentTool]]] =
    exchange(toolsUri, "GET", None).map:
      case Reply(200, body, _) => decodeToolList(body)
      case Reply(401, _, _)    => Left(AgentApiError.Unauthorized)
      case Reply(429, _, retryAfter) => Left(AgentApiError.RateLimited(retryAfter))
      case Reply(408 | 500 | 502 | 503 | 504, _, _) => Left(AgentApiError.Unavailable)
      case _           => Left(AgentApiError.InvalidResponse)

  /**
    * Forwards `arguments` unchanged to the named operation. Nothing is sent unless the name is one safe path segment
    * and the arguments are a bounded JSON object; the server is authoritative for everything else.
    */
  def callTool(name: String, arguments: Json): IO[Either[AgentApiError, AgentToolResult]] =
    if !isValidToolName(name) || !arguments.isObject || compactBytes(arguments) > MaximumArgumentBytes then
      IO.pure(Left(AgentApiError.InvalidRequest))
    else
      val key = ApprovalMemory.keyOf(name, arguments)
      approvals.recall(key).flatMap: remembered =>
        val fields = Vector("arguments" -> arguments) ++ remembered.map(id => "approval_id" -> Json.fromString(id))
        exchange(config.endpoint.resolve(s"/api/agent/tools/$name/call"), "POST", Some(Json.fromFields(fields).noSpaces)).flatMap:
          case Reply(409, body, _) =>
            ApprovalMemory.pendingApproval(body) match
              case Some(pending) => approvals.remember(key, pending).as(Left(AgentApiError.ApprovalPending(pending.id)))
              case None => approvals.forget(key).as(Left(AgentApiError.ApprovalRequired))
          // Any other answer ends this approval: it was consumed, denied, or did not match. It is never sent again.
          case reply => approvals.forget(key).whenA(remembered.nonEmpty).as(toolOutcome(reply))

  private def toolOutcome(reply: Reply): Either[AgentApiError, AgentToolResult] =
    reply match
      case Reply(200, body, _) => decodeToolResult(body).leftMap(_ => AgentApiError.OutcomeUnknown)
      case Reply(400, _, _)    => Left(AgentApiError.InvalidRequest)
      case Reply(401, _, _)    => Left(AgentApiError.Unauthorized)
      case Reply(403, _, _)    => Left(AgentApiError.Denied)
      case Reply(404, _, _)    => Left(AgentApiError.NotFound)
      case Reply(424, _, _)    => Left(AgentApiError.ConnectionUnavailable)
      case Reply(429, _, retryAfter) => Left(AgentApiError.RateLimited(retryAfter))
      case Reply(408 | 500 | 502 | 503 | 504, _, _) => Left(AgentApiError.OutcomeUnknown)
      case _           => Left(AgentApiError.InvalidResponse)

  private def exchange(uri: URI, method: String, payload: Option[String]): IO[Reply] =
    val builder = HttpRequest
      .newBuilder(uri)
      .timeout(RequestTimeout)
      .header("Accept", "application/json")
      .header("Authorization", s"Bearer ${config.credential.value}")
    val request = payload match
      case None => builder.GET().build()
      case Some(body) =>
        builder.header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build()
    responseResource(request)
      .use(response => readBody(response.statusCode(), retryAfterOf(response), response.body()))
      .timeoutTo(EffectTimeout, IO.raiseError(new java.net.http.HttpTimeoutException("request timed out")))
      .handleError:
        // A POST may have reached execution before its response was lost. Listing remains safe to retry.
        case _ if method == "POST" => Reply(502, Array.emptyByteArray, None)
        case _: java.net.http.HttpTimeoutException => Reply(504, Array.emptyByteArray, None)
        case _: java.util.concurrent.TimeoutException => Reply(504, Array.emptyByteArray, None)
        case _: BodyLimitExceeded => Reply(413, Array.emptyByteArray, None)
        case _ => Reply(503, Array.emptyByteArray, None)

  /**
    * Closing the body is part of the resource lifetime, so a timeout can interrupt a stalled read and release the
    * underlying connection. The timeout in [[exchange]] deliberately encloses both request submission and this read.
    */
  private def responseResource(request: HttpRequest): Resource[IO, HttpResponse[InputStream]] =
    Resource.make(
      IO.interruptibleMany(client.send(request, HttpResponse.BodyHandlers.ofInputStream()))
    )(response => IO.blocking(response.body().close()).handleError(_ => ()))

  /** Only a 429 carries a meaningful hint; a repeated header is ignored rather than merged. */
  private def retryAfterOf(response: HttpResponse[InputStream]): Option[FiniteDuration] =
    val values = response.headers().allValues("Retry-After")
    if values.size == 1 then RetryAfter.parse(Some(values.get(0))) else None

  private def readBody(status: Int, retryAfter: Option[FiniteDuration], stream: InputStream): IO[Reply] =
    IO.interruptibleMany:
        val bytes = stream.readNBytes(MaximumResponseBytes + 1)
        if bytes.length > MaximumResponseBytes then throw BodyLimitExceeded()
        Reply(status, bytes, retryAfter)

  /**
    * The list is bounded first, then each entry is judged alone: a malformed or oversize entry is dropped so one bad
    * tool cannot hide the rest, but a duplicate name makes the whole response untrustworthy.
    */
  private def decodeToolList(body: Array[Byte]): Either[AgentApiError, Vector[AgentTool]] =
    for
      json <- parseJson(body)
      root <- exactObject(json, Set("tools"))
      values <- root("tools").flatMap(_.asArray).map(_.toVector).toRight(AgentApiError.InvalidResponse)
      _ <- Either.cond(values.size <= MaximumTools, (), AgentApiError.InvalidResponse)
      names = values.flatMap(_.asObject.flatMap(_("name")).flatMap(_.asString))
      _ <- Either.cond(names.distinct.size == names.size, (), AgentApiError.InvalidResponse)
    yield values.flatMap(decodeListedTool)

  private def decodeListedTool(json: Json): Option[AgentTool] =
    for
      objectValue <- json.asObject.filter(_.keys.toSet == Set("name", "description", "inputSchema"))
      name <- objectValue("name").flatMap(_.asString).filter(isValidToolName)
      description <- objectValue("description").flatMap(_.asString).filter(isValidDescription)
      inputSchema <- objectValue("inputSchema").filter(isValidSchema)
    yield AgentTool(name, description, inputSchema)

  private def decodeToolResult(body: Array[Byte]): Either[AgentApiError, AgentToolResult] =
    for
      json <- parseJson(body)
      objectValue <- exactObject(json, Set("content", "correlationId"))
      content <- resultContentField(objectValue, "content")
      correlationId <- identifierField(objectValue, "correlationId", 128)
      result <- Either.cond(correlationId.nonEmpty, AgentToolResult(content, correlationId), AgentApiError.InvalidResponse)
    yield result

  private def parseJson(body: Array[Byte]): Either[AgentApiError, Json] =
    parse(new String(body, StandardCharsets.UTF_8)).leftMap(_ => AgentApiError.InvalidResponse)

  private def exactObject(json: Json, fields: Set[String]): Either[AgentApiError, JsonObject] =
    json.asObject.filter(_.keys.forall(fields)).toRight(AgentApiError.InvalidResponse)

  /** Result text may be empty and may contain line breaks between independently sanitized items. */
  private def resultContentField(value: JsonObject, field: String): Either[AgentApiError, String] =
    value(field)
      .flatMap(_.asString)
      .filter(text => text.length <= MaximumContentCharacters && text.forall(isAllowedResultCharacter))
      .toRight(AgentApiError.InvalidResponse)

  private def identifierField(value: JsonObject, field: String, maximum: Int): Either[AgentApiError, String] =
    value(field)
      .flatMap(_.asString)
      .filter(text => text.length <= maximum && !text.exists(Character.isISOControl))
      .toRight(AgentApiError.InvalidResponse)

  private def isAllowedResultCharacter(character: Char): Boolean =
    !Character.isISOControl(character) || character == '\n' || character == '\r'

  private val toolsUri = config.endpoint.resolve("/api/agent/tools")

object AgentApiClient:
  private val RequestTimeout = Duration.ofSeconds(10)
  private val EffectTimeout: scala.concurrent.duration.FiniteDuration =
    scala.concurrent.duration.FiniteDuration(11, java.util.concurrent.TimeUnit.SECONDS)
  private val MaximumResponseBytes = 1024 * 1024
  private val MaximumContentCharacters = 64 * 1024
  private[bridge] val MaximumTools = 64
  private[bridge] val MaximumSchemaBytes = 16 * 1024
  private[bridge] val MaximumSchemaDepth = 32
  private[bridge] val MaximumArgumentBytes = 15 * 1024
  private val MaximumDescriptionCharacters = 1024

  /** `[A-Za-z0-9_]{1,64}`: one safe URI path segment, so a name cannot steer the request elsewhere. */
  private[bridge] def isValidToolName(name: String): Boolean =
    name.nonEmpty && name.length <= 64 && name.forall(c => (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_')

  private def isValidDescription(text: String): Boolean =
    text.nonEmpty && text.length <= MaximumDescriptionCharacters && !text.exists(Character.isISOControl)

  /** Shape and size only; the schema's meaning is never interpreted. Depth is checked first so serialization stays cheap. */
  private[bridge] def isValidSchema(schema: Json): Boolean =
    schema.asObject.exists(_("type").flatMap(_.asString).contains("object")) &&
      depthWithin(schema, MaximumSchemaDepth) &&
      compactBytes(schema) <= MaximumSchemaBytes

  /** The root container is depth 1. Recursion stops at the limit, so a hostile document cannot exhaust the stack. */
  private def depthWithin(json: Json, remaining: Int): Boolean =
    if json.isObject || json.isArray then
      remaining >= 1 &&
        json.asObject.map(_.values).orElse(json.asArray).forall(_.forall(depthWithin(_, remaining - 1)))
    else true

  private def compactBytes(json: Json): Int = json.noSpaces.getBytes(StandardCharsets.UTF_8).length

  private final case class BodyLimitExceeded() extends RuntimeException

  /** A status, a bounded body, and the parsed `Retry-After` hint (never the raw header). */
  private final case class Reply(status: Int, body: Array[Byte], retryAfter: Option[FiniteDuration])

  def resource(config: BridgeConfig): Resource[IO, AgentApiClient] =
    Resource
      .make(IO.blocking(Executors.newFixedThreadPool(2)))(executor => IO.blocking(executor.shutdown()).void)
      .evalMap(executor => ApprovalMemory.create(IO.realTimeInstant).map(executor -> _))
      .map: (executor, memory) =>
        val client = HttpClient
          .newBuilder()
          .executor(executor)
          .connectTimeout(RequestTimeout)
          .followRedirects(HttpClient.Redirect.NEVER)
          .build()
        new AgentApiClient(config, client, memory)
