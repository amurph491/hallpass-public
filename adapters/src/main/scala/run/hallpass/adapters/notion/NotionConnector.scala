package run.hallpass.adapters.notion

import java.net.{URI, URLEncoder}
import java.net.http.{HttpClient, HttpRequest}
import java.nio.ByteBuffer
import java.nio.charset.{CodingErrorAction, StandardCharsets}
import java.util.Base64
import scala.concurrent.duration.*
import cats.effect.IO
import io.circe.Json
import io.circe.parser.parse
import run.hallpass.adapters.http.BoundedHttpResponse
import run.hallpass.application.*

/** The Notion public-integration OAuth flow (no PKCE; Notion does not document it).
  *
  * Start: `{authorize}?client_id&redirect_uri&response_type=code&owner=user&state`. Callback: POST `{api}/v1/oauth/token`
  * with HTTP Basic `client_id:client_secret`, headers `Notion-Version: Notion.ApiVersion` and JSON content type, body
  * `{"grant_type":"authorization_code","code":…,"redirect_uri":…}`. The response must carry `access_token`, `bot_id`
  * and `workspace_id` (UUIDs); `refresh_token` and `workspace_name` are optional.
  *
  * Grant: secret = NotionTokenRecord.encode(...); externalAccountId and rootExternalId = the workspace ID;
  * rootDisplayName and workspaceLabel = workspace_name (or "Notion workspace"); accountLabel = the owner user's name
  * when present; expiresAt = None; credential type NOTION_OAUTH.
  *
  * `selectableResources`: POST `{api}/v1/search` with `{"filter":{"property":"object","value":"page"},"page_size":100}`,
  * following `next_cursor` up to `pageLimit` pages, returning the pages the integration can access (that is, the pages
  * the user shared at consent) as SelectableProviderResource(Notion.page, page id, title (or "Untitled"), workspace).
  * The stored record must name the root's workspace. */
final class NotionConnector(
    client: NotionOAuthClient,
    endpoints: NotionEndpoints,
    http: HttpClient,
    val redirectUri: URI,
    pageLimit: Int = 1000
) extends ProviderConnector:
  val provider: ProviderId = ProviderId.Notion
  val rootKind: ResourceKind[?] = Notion.workspace
  val credentialType: String = Notion.CredentialType
  val singleActiveRoot: Boolean = false
  val usesPkce: Boolean = false
  def authorizationUri(state: OAuthState, pkce: Option[PkceVerifier]): IO[URI] = authorizationUri(state)
  def exchange(callback: OAuthCallback, pkce: Option[PkceVerifier]): IO[Either[OAuthError, OAuthGrant]] = exchange(callback)
  val resourceDiscovery: Option[ResourceDiscovery] = Some(new ResourceDiscovery:
    def selectableResources(credential: ProviderSecret, root: ConnectionResource) =
      NotionConnector.this.selectableResources(credential, root)
  )

  def authorizationUri(state: OAuthState): IO[URI] = IO.delay:
    val query = Vector(
      "client_id" -> client.clientId,
      "redirect_uri" -> redirectUri.toString,
      "response_type" -> "code",
      "owner" -> "user",
      "state" -> state.value
    ).map((key, value) => encode(key) + "=" + encode(value)).mkString("&")
    val base = endpoints.authorize.toString
    URI.create(base + (if endpoints.authorize.getRawQuery == null then "?" else "&") + query)

  def exchange(callback: OAuthCallback): IO[Either[OAuthError, OAuthGrant]] =
    IO.delay:
      val credentials =
        Base64.getEncoder.encodeToString((client.clientId + ":" + client.clientSecret).getBytes(StandardCharsets.UTF_8))
      val body = Json.obj(
        "grant_type" -> Json.fromString("authorization_code"),
        "code" -> Json.fromString(callback.code),
        "redirect_uri" -> Json.fromString(redirectUri.toString)
      ).noSpaces
      baseRequest(endpoints.api.resolve("/v1/oauth/token"))
        .header("Authorization", "Basic " + credentials)
        .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
        .build()
    .attempt.flatMap:
      case Left(_)        => IO.pure(Left(OAuthError.ProviderRejected))
      case Right(request) => post(request).map(_.flatMap(NotionConnector.decodeGrant))

  def selectableResources(credential: ProviderSecret, root: ConnectionResource): IO[Either[OAuthError, Vector[SelectableProviderResource]]] =
    NotionTokenRecord.decode(credential) match
      case Left(_) => IO.pure(Left(OAuthError.InvalidState))
      case Right(record)
          if root.kind != Notion.workspace.wire || !NotionId.fromExternal(root.externalId).contains(record.workspaceId) =>
        IO.pure(Left(OAuthError.InvalidState))
      case Right(record) =>
        search(record, None, 1, Vector.empty).map(_.map: pages =>
          pages.distinctBy(_._1.value)
            .map((id, title) => SelectableProviderResource(Notion.page, id.externalId, title, root.externalId))
            .sortBy(r => (r.displayName, r.externalId.value))
        )

  private def search(
      record: NotionTokenRecord,
      cursor: Option[String],
      page: Int,
      collected: Vector[(NotionId, String)]
  ): IO[Either[OAuthError, Vector[(NotionId, String)]]] =
    IO.delay:
      val fields = Vector(
        "filter" -> Json.obj("property" -> Json.fromString("object"), "value" -> Json.fromString("page")),
        "page_size" -> Json.fromInt(NotionConnector.PageSize)
      ) ++ cursor.map(c => "start_cursor" -> Json.fromString(c))
      baseRequest(endpoints.api.resolve("/v1/search"))
        .header("Authorization", "Bearer " + record.accessToken)
        .POST(HttpRequest.BodyPublishers.ofString(Json.fromFields(fields).noSpaces, StandardCharsets.UTF_8))
        .build()
    .attempt.flatMap:
      case Left(_) => IO.pure(Left(OAuthError.ProviderRejected))
      case Right(request) =>
        post(request).flatMap:
          case Left(error) => IO.pure(Left(error))
          case Right(json) =>
            NotionConnector.decodeSearchPage(json) match
              case Left(error) => IO.pure(Left(error))
              case Right((found, next)) =>
                val all = collected ++ found
                next match
                  case None                         => IO.pure(Right(all))
                  case Some(_) if page >= pageLimit => IO.pure(Right(all))
                  case Some(c) if cursor.contains(c) => IO.pure(Left(OAuthError.InvalidProviderResponse))
                  case Some(c)                      => search(record, Some(c), page + 1, all)

  private def baseRequest(uri: URI): HttpRequest.Builder =
    HttpRequest.newBuilder(uri)
      .timeout(RequestTimeout)
      .header("User-Agent", "hallpass")
      .header("Accept", "application/json")
      .header("Accept-Encoding", "identity")
      .header("Content-Type", "application/json")
      .header("Notion-Version", Notion.ApiVersion)

  /** One bounded exchange, never retried. Only a 200 is parsed, so a 3xx that was not followed is a rejection. Any
    * exception becomes an opaque error; its message is never read. */
  private def post(request: HttpRequest): IO[Either[OAuthError, Json]] =
    BoundedHttpResponse.send(http, request, NotionConnector.MaximumResponseBytes, RequestTimeout.toMillis.millis).attempt.map:
      case Left(error) =>
        val oversize = Iterator.iterate(error)(_.getCause).takeWhile(_ != null).take(8)
          .exists(e => e.isInstanceOf[IllegalStateException] && e.getMessage == NotionConnector.SizeLimitMessage)
        Left(if oversize then OAuthError.InvalidProviderResponse else OAuthError.ProviderRejected)
      case Right(response) =>
        val bytes = response.body()
        try
          if response.statusCode() == 200 then NotionConnector.decodeJson(bytes)
          else Left(OAuthError.ProviderRejected)
        finally java.util.Arrays.fill(bytes, 0.toByte)

  private val RequestTimeout = java.time.Duration.ofSeconds(10)

  private def encode(value: String): String =
    URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20")

object NotionConnector:
  val MaximumResponseBytes: Int = 1024 * 1024
  val PageSize: Int = 100
  val DefaultWorkspaceLabel = "Notion workspace"
  private val SizeLimitMessage = "HTTP response exceeds the size limit"
  private val MaximumTitleLength = 200

  private def decodeJson(bytes: Array[Byte]): Either[OAuthError, Json] =
    scala.util.Try(
      StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString
    ).toOption.flatMap(parse(_).toOption).filter(_.isObject).toRight(OAuthError.InvalidProviderResponse)

  private def validLabel(value: String): Boolean =
    value.trim.nonEmpty && value.length <= MaximumTitleLength && !value.exists(Character.isISOControl)

  private def decodeGrant(json: Json): Either[OAuthError, OAuthGrant] =
    val cursor = json.hcursor
    // Notion reports some failures as HTTP 200 with an `error` field.
    if json.asObject.exists(_.contains("error")) then Left(OAuthError.ProviderRejected)
    else
      val refresh: Option[Option[String]] = cursor.downField("refresh_token").focus match
        case None                        => Some(None)
        case Some(value) if value.isNull => Some(None)
        case Some(value)                 => value.asString.map(Some(_))
      (for
        access <- cursor.get[String]("access_token").toOption
        refreshToken <- refresh
        bot <- cursor.get[String]("bot_id").toOption.flatMap(NotionId.parse)
        workspace <- cursor.get[String]("workspace_id").toOption.flatMap(NotionId.parse)
        record <- NotionTokenRecord.from(access, refreshToken, bot, workspace)
      yield
        val name = cursor.get[String]("workspace_name").toOption.filter(validLabel).getOrElse(DefaultWorkspaceLabel)
        val owner = cursor.downField("owner").downField("user").get[String]("name").toOption.filter(validLabel)
        OAuthGrant(
          secret = NotionTokenRecord.encode(record),
          externalAccountId = workspace.externalId,
          rootExternalId = workspace.externalId,
          rootDisplayName = name,
          accountLabel = owner,
          workspaceLabel = Some(name),
          expiresAt = None
        )).toRight(OAuthError.InvalidProviderResponse)

  /** The usable pages of one search response and the next cursor (`None` once `has_more` is false). */
  private def decodeSearchPage(json: Json): Either[OAuthError, (Vector[(NotionId, String)], Option[String])] =
    val cursor = json.hcursor
    val results = cursor.get[Vector[Json]]("results").toOption
    val hasMore = cursor.get[Boolean]("has_more").toOption.getOrElse(false)
    val next = cursor.get[Option[String]]("next_cursor").toOption.flatten.filter(c => c.nonEmpty && c.length <= 1024)
    results match
      case None                               => Left(OAuthError.InvalidProviderResponse)
      case Some(_) if hasMore && next.isEmpty => Left(OAuthError.InvalidProviderResponse)
      case Some(entries) =>
        entries.foldLeft[Either[OAuthError, Vector[(NotionId, String)]]](Right(Vector.empty)): (acc, entry) =>
          acc.flatMap: collected =>
            val c = entry.hcursor
            val flagged = Vector("archived", "is_archived", "in_trash", "is_trashed")
              .exists(name => c.get[Boolean](name).toOption.contains(true))
            if c.get[String]("object").toOption.exists(_ != "page") || flagged then Right(collected)
            else
              c.get[String]("id").toOption.flatMap(NotionId.parse) match
                case None     => Left(OAuthError.InvalidProviderResponse)
                case Some(id) => Right(collected :+ (id -> title(entry)))
        .map(pages => (pages, if hasMore then next else None))

  private def title(entry: Json): String =
    val properties = entry.hcursor.downField("properties").focus.flatMap(_.asObject).map(_.values.toVector).getOrElse(Vector.empty)
    val raw = properties
      .find(_.hcursor.get[String]("type").toOption.contains("title"))
      .flatMap(_.hcursor.get[Vector[Json]]("title").toOption)
      .getOrElse(Vector.empty)
      .flatMap(_.hcursor.get[String]("plain_text").toOption)
      .mkString
    val cleaned = raw.split("\\s+").filter(_.nonEmpty).mkString(" ").take(MaximumTitleLength).trim
    if cleaned.isEmpty then "Untitled" else cleaned
