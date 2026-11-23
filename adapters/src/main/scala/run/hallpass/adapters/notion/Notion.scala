package run.hallpass.adapters.notion

import java.net.URI
import java.nio.charset.StandardCharsets
import cats.effect.IO
import io.circe.{Json, parser}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Notion's resource topology: the workspace the integration is installed in is the connection
  * root; administrators select pages under it. Blocks are addressed only as children of a selected page. */
object Notion:
  sealed trait Workspace
  sealed trait Page

  given workspace: ResourceKind[Workspace] =
    ResourceKind.root("notion.workspace", ProviderId.Notion, ResourceType.Account, Custody.Workspace)
  given page: ResourceKind[Page] = ResourceKind.child[Page, Workspace]("notion.page", ResourceType.Document)

  val CredentialType = "NOTION_OAUTH"
  /** The API version every request sends (`Notion-Version`). Verify against current docs when bumping. */
  val ApiVersion = "2022-06-28"

object NotionExecutorAudience:
  val local: ExecutorAudience =
    ExecutorAudience.parse("hallpass.local.notion").getOrElse(throw IllegalStateException("static executor audience is invalid"))

final case class NotionEndpoints(authorize: URI, api: URI)
object NotionEndpoints:
  val Production: NotionEndpoints =
    NotionEndpoints(URI.create("https://api.notion.com/v1/oauth/authorize"), URI.create("https://api.notion.com"))

/** The public integration's OAuth client. The secret comes from a mounted file and is never rendered. */
final class NotionOAuthClient(val clientId: String, private[notion] val clientSecret: String):
  require(clientId.matches("[A-Za-z0-9._-]{1,128}"), "Notion client ID is invalid")
  override def toString: String = s"NotionOAuthClient($clientId, <redacted>)"

/** A Notion UUID (pages, blocks, workspaces), normalized to the hyphenated lowercase form. Notion also accepts and
  * returns the 32-hex form; both parse to the same value. */
opaque type NotionId = String
object NotionId:
  private val Hyphenated = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}".r
  private val Compact = "[0-9a-f]{32}".r
  def parse(value: String): Option[NotionId] =
    val lower = value.toLowerCase
    lower match
      case Hyphenated() => Some(lower)
      case Compact() =>
        Some(s"${lower.substring(0, 8)}-${lower.substring(8, 12)}-${lower.substring(12, 16)}-${lower.substring(16, 20)}-${lower.substring(20)}")
      case _ => None
  def fromExternal(value: ExternalId): Option[NotionId] = parse(value.value)
  extension (value: NotionId)
    def value: String = value
    def externalId: ExternalId = ExternalId.parse(value).get

/** What a Notion connection stores, encrypted: the bot's access token, its refresh token if Notion issued one (kept
  * for a later refresh flow; unused today), and the bot and workspace it belongs to. */
final class NotionTokenRecord private[notion] (
    private[notion] val accessToken: String,
    private[notion] val refreshToken: Option[String],
    val botId: NotionId,
    val workspaceId: NotionId
):
  override def toString: String = "NotionTokenRecord(<redacted>)"

object NotionTokenRecord:
  private def validToken(value: String): Boolean =
    value.nonEmpty && value.length <= 4096 && !value.exists(c => c.isWhitespace || Character.isISOControl(c))

  def from(accessToken: String, refreshToken: Option[String], botId: NotionId, workspaceId: NotionId): Option[NotionTokenRecord] =
    Option.when(validToken(accessToken) && refreshToken.forall(validToken))(
      NotionTokenRecord(accessToken, refreshToken, botId, workspaceId)
    )

  def encode(record: NotionTokenRecord): ProviderSecret =
    ProviderSecret.fromUtf8(
      Json.obj(
        "access_token" -> Json.fromString(record.accessToken),
        "refresh_token" -> record.refreshToken.fold(Json.Null)(Json.fromString),
        "bot_id" -> Json.fromString(record.botId.value),
        "workspace_id" -> Json.fromString(record.workspaceId.value)
      ).noSpaces
    )

  def decode(secret: ProviderSecret): Either[ConnectionError, NotionTokenRecord] =
    (for
      json <- parser.parse(String(ProviderSecret.bytes(secret), StandardCharsets.UTF_8)).toOption
      cursor = json.hcursor
      access <- cursor.get[String]("access_token").toOption
      refresh <- cursor.get[Option[String]]("refresh_token").toOption
      bot <- cursor.get[String]("bot_id").toOption.flatMap(NotionId.parse)
      workspace <- cursor.get[String]("workspace_id").toOption.flatMap(NotionId.parse)
      record <- from(access, refresh, bot, workspace)
    yield record).toRight(ConnectionError.InvalidState)

/** What a Notion operation dispatches with. Executor-private. */
final class NotionAccess private[notion] (private[notion] val accessToken: String):
  override def toString: String = "NotionAccess(<redacted>)"

/** Resolves the bot token for one redeemed lease: the connection is found server-side from the lease's selected page,
  * must be ACTIVE with a NOTION_OAUTH credential, and its stored record must name the workspace that is the page's
  * trusted catalog root. Notion publishes no token lifetime, so there is no refresh here: a revoked or expired token
  * fails at the provider as an authentication failure, and the administrator reconnects. */
final class NotionCredentials(connections: ProviderConnectionResolver) extends CredentialStrategy[Notion.Page, NotionAccess]:
  def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[Notion.Page]): IO[Either[ConnectionError, NotionAccess]] =
    val root = target.scope.path match
      case Vector(_, workspace, _) if workspace.resourceType == ResourceType.Account => NotionId.parse(workspace.externalId)
      case _                                                                       => None
    if lease.tenant != target.tenant || lease.resource != target.resource || !(target.kind eq Notion.page) then
      IO.pure(Left(ConnectionError.InvalidState))
    else
      root match
        case None => IO.pure(Left(ConnectionError.InvalidState))
        case Some(workspace) =>
          connections.activeConnectionFor(lease, target, ProviderId.Notion, Notion.CredentialType).map:
            case Left(error) => Left(error)
            case Right(resolved) =>
              NotionTokenRecord.decode(resolved.secret).flatMap: record =>
                Either.cond(record.workspaceId == workspace, NotionAccess(record.accessToken), ConnectionError.InvalidState)
