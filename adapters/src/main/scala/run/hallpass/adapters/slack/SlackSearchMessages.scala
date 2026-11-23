package run.hallpass.adapters.slack

import java.net.URI
import java.net.URLEncoder
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.nio.charset.StandardCharsets
import java.time.{Duration, Instant}
import cats.effect.IO
import cats.syntax.all.*
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*
import io.circe.{Decoder, Json}
import io.circe.parser.decode

opaque type SlackAccessToken = SlackAccessToken.Data
object SlackAccessToken:
  private[slack] final class Data private[slack] (private[slack] val raw: String):
    override def toString: String = "SlackAccessToken(<redacted>)"

  enum ValidationError:
    case Missing, ContainsWhitespace

  def parse(value: String): Either[ValidationError, SlackAccessToken] =
    if value.isEmpty then Left(ValidationError.Missing)
    else if value.exists(_.isWhitespace) then Left(ValidationError.ContainsWhitespace)
    else Right(Data(value))

  private[slack] def raw(token: SlackAccessToken): String = token.raw

trait SlackCapabilityCatalog:
  def searchCapability(tenant: TenantId): IO[Option[CapabilityDescriptor]]

object SlackCapabilityCatalog:
  val SearchTool: String = "slack_search_messages"

  /** The capability behind the tenant's trusted `slack_search_messages` mapping. */
  def fromCatalog(catalog: ControlPlaneCatalog[IO]): SlackCapabilityCatalog = tenant =>
    catalog.tools(tenant).map(_.find(tool => tool.name == SearchTool && tool.trusted).flatMap(_.capability).map(_.descriptor))

final case class SlackSearchMessage(channelId: String, timestamp: String, text: String, username: Option[String])
final case class SlackSearchMessages(messages: Vector[SlackSearchMessage])

/** Adapter registration; the kernel sees only the opaque ExecutorAudience value. */
object SlackExecutorAudience:
  val local: ExecutorAudience = ExecutorAudience
    .parse("hallpass.local.slack")
    .getOrElse(
      throw IllegalStateException("static executor audience is invalid")
    )

private final case class SlackMatches(matches: Vector[SlackSearchMessage])
private final case class SlackApiResponse(ok: Boolean, messages: Option[SlackMatches])

private given Decoder[SlackSearchMessage] = Decoder.instance: cursor =>
  for
    // Current search.messages responses use channel.id; older responses used channel_id.
    channel <- cursor
      .get[Option[String]]("channel_id")
      .flatMap:
        case Some(value) => Right(value)
        case None        => cursor.downField("channel").get[String]("id")
    timestamp <- cursor.get[String]("ts")
    text <- cursor.get[String]("text")
    username <- cursor.get[Option[String]]("username")
  yield SlackSearchMessage(channel, timestamp, text, username)

private given Decoder[SlackMatches] =
  Decoder.instance(_.get[Vector[SlackSearchMessage]]("matches").map(SlackMatches.apply))
private given Decoder[SlackApiResponse] = Decoder.instance: cursor =>
  for
    ok <- cursor.get[Boolean]("ok")
    messages <- cursor.get[Option[SlackMatches]]("messages")
  yield SlackApiResponse(ok, messages)

/** Slack's resource topology. The workspace is the connection root; until connection roots are stored it is the
  * tenant's provisioned Slack provider resource. */
object Slack:
  sealed trait Workspace
  given workspace: ResourceKind[Workspace] =
    ResourceKind.root("slack.workspace", ProviderId.Slack, ResourceType.Account, Custody.Workspace)

  val SearchMessagesTool: ExternalToolId =
    ExternalToolId.parse(SlackCapabilityCatalog.SearchTool).getOrElse(throw IllegalStateException("static tool is invalid"))

/** `slack.search.messages@1`: search messages the connected Slack user can see. */
object SlackSearchMessagesOperation extends OperationDescriptor[SearchQuery, Slack.Workspace]:
  val id: OperationId =
    OperationId.parse("slack.search.messages@1").getOrElse(throw IllegalStateException("static operation is invalid"))
  val tool: ExternalToolId = Slack.SearchMessagesTool
  val description: String = "Search messages in the configured Slack workspace."
  val capability: CapabilityKey =
    CapabilityKey.parse("Slack.Message.Read").getOrElse(throw IllegalStateException("static capability is invalid"))
  val action: Action = Action.Read
  val target: ResourceKind[Slack.Workspace] = Slack.workspace
  val audience: ExecutorAudience = SlackExecutorAudience.local
  val inputSchema: Json = Json.obj(
    "type" -> Json.fromString("object"),
    "properties" -> Json.obj(
      "query" -> Json.obj(
        "type" -> Json.fromString("string"),
        "minLength" -> Json.fromInt(1),
        "maxLength" -> Json.fromInt(SearchQuery.MaximumLength)
      )
    ),
    "required" -> Json.arr(Json.fromString("query")),
    "additionalProperties" -> Json.False
  )

  /** Exactly one field, `query`, a non-blank string of at most 1,000 characters. */
  def decode(arguments: Json): Either[ArgumentError, SearchQuery] =
    arguments.asObject.toRight(ArgumentError.NotAnObject).flatMap: fields =>
      if fields.keys.exists(_ != "query") then Left(ArgumentError.UnexpectedField)
      else
        fields("query") match
          case None        => Left(ArgumentError.MissingField("query"))
          case Some(value) =>
            value.asString.flatMap(SearchQuery.parse(_).toOption).toRight(ArgumentError.InvalidField("query"))

  def locate(input: SearchQuery): ResourceLocator[Slack.Workspace] = ResourceLocator.ConnectionRoot()
  def facts(input: SearchQuery): AuthorizationContext = AuthorizationContext.empty
  def canonical(input: SearchQuery): Json = Json.obj("query" -> Json.fromString(input.value))

/** Resolves the workspace token from the connection bound to the lease's authorized resource, after redemption. */
final class SlackConnectionCredentials(connections: ConnectionResolver[IO])
    extends CredentialStrategy[Slack.Workspace, SlackAccessToken]:
  def credentialFor(
      lease: RedeemedExecutionLease,
      target: SelectedResource[Slack.Workspace]
  ): IO[Either[ConnectionError, SlackAccessToken]] =
    connections.activeConnectionFor(lease).map:
      case Left(error)     => Left(error)
      case Right(resolved) =>
        SlackAccessToken
          .parse(new String(ProviderSecret.bytes(resolved.secret), StandardCharsets.UTF_8))
          .left
          .map(_ => ConnectionError.MissingCredential)

/** Sends `search.messages`. The request is built from the typed query only. */
final class SlackSearchMessagesClient(
    endpoint: URI,
    client: HttpClient,
    requestTimeout: Duration = Duration.ofSeconds(10)
) extends ProviderOperationClient[SearchQuery, Slack.Workspace, SlackAccessToken]:
  def dispatch(target: SelectedResource[Slack.Workspace], input: SearchQuery, token: SlackAccessToken): IO[ToolResult] =
    val body = "query=" + URLEncoder.encode(input.value, StandardCharsets.UTF_8)
    val request = HttpRequest
      .newBuilder(endpoint)
      .timeout(requestTimeout)
      .header("Authorization", "Bearer " + SlackAccessToken.raw(token))
      .header("Content-Type", "application/x-www-form-urlencoded")
      .header("Accept-Encoding", "identity")
      .POST(HttpRequest.BodyPublishers.ofString(body))
      .build()
    IO.blocking(client.send(request, HttpResponse.BodyHandlers.ofString()))
      .handleErrorWith: error =>
        if error.isInstanceOf[java.net.http.HttpTimeoutException] || error.isInstanceOf[java.net.ConnectException] then
          // These JDK transport exceptions don't contain request headers, so retaining the cause is safe and useful.
          IO.raiseError(ProviderExecutionException.withSafeCause(ProviderError.Timeout, error))
        else
          // Do not retain arbitrary client failures: third-party exception messages can include request details.
          IO.raiseError(ProviderExecutionException(ProviderError.Rejected))
      .flatMap: response =>
        if response.statusCode() == 401 || response.statusCode() == 403 then
          IO.raiseError(ProviderExecutionException(ProviderError.AuthenticationFailed))
        else if response.statusCode() / 100 != 2 then IO.raiseError(ProviderExecutionException(ProviderError.Rejected))
        else
          decode[SlackApiResponse](response.body()) match
            case Left(_)               => IO.raiseError(ProviderExecutionException(ProviderError.InvalidResponse))
            case Right(api) if !api.ok => IO.raiseError(ProviderExecutionException(ProviderError.Rejected))
            case Right(api)            =>
              val result = api.messages
                .map(_.matches)
                .getOrElse(Vector.empty)
                .map: message =>
                  s"${message.channelId} ${message.timestamp} ${message.username.getOrElse("unknown")}: ${message.text}"
              IO.pure(ToolResult(result.mkString("\n")))

object SlackOperations:
  def searchMessages(
      client: SlackSearchMessagesClient,
      connections: ConnectionResolver[IO]
  ): RegisteredOperation[SearchQuery, Slack.Workspace, SlackAccessToken] =
    RegisteredOperation(SlackSearchMessagesOperation, client, SlackConnectionCredentials(connections))
