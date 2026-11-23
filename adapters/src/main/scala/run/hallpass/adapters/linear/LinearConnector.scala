package run.hallpass.adapters.linear

import java.net.{URI, URLEncoder}
import java.net.http.{HttpClient, HttpRequest}
import java.nio.ByteBuffer
import java.nio.charset.{CodingErrorAction, StandardCharsets}
import scala.concurrent.duration.*
import cats.data.EitherT
import cats.effect.IO
import io.circe.Json
import io.circe.parser.parse
import run.hallpass.adapters.http.BoundedHttpResponse
import run.hallpass.adapters.oauth.OAuthTokenJsonCodec
import run.hallpass.application.*

/** The Linear OAuth 2.0 connection flow, with PKCE (S256).
  *
  * Start sends the administrator to `{authorize}?client_id&redirect_uri&response_type=code&scope=read,write&state&
  * code_challenge&code_challenge_method=S256&prompt=consent`. The callback exchanges the code with the verifier at
  * `{token}` (form: grant_type=authorization_code, code, redirect_uri, client_id, client_secret, code_verifier) and
  * requires `access_token`, `refresh_token`, and a positive `expires_in`. It then asks GraphQL for the token's
  * organization (`viewer { id } organization { id name urlKey }`).
  *
  * Grant: secret = the OAuthTokens encoded by OAuthTokenJsonCodec; externalAccountId and rootExternalId = the
  * organization ID; rootDisplayName and workspaceLabel = organization name; accountLabel = the viewer's name;
  * expiresAt = the access token's expiry (credential_references and connections must agree, as RefreshableOAuth
  * requires).
  *
  * `selectableResources` lists teams (`teams(first: 100)`, following pageInfo up to 1,000) with the stored access
  * token. A management listing never refreshes: an expired token is `ProviderRejected`, and an agent call (which
  * refreshes inside the executor) or a reconnect restores it.
  */
final class LinearConnector(
    client: LinearOAuthClient,
    endpoints: LinearEndpoints,
    graphql: LinearGraphQl,
    http: HttpClient,
    clock: Clock[IO],
    val redirectUri: URI
) extends ProviderConnector:
  val provider: ProviderId = ProviderId.Linear
  val rootKind: ResourceKind[?] = Linear.organization
  val credentialType: String = Linear.CredentialType
  override val usesPkce: Boolean = true
  val singleActiveRoot: Boolean = false
  val resourceDiscovery: Option[ResourceDiscovery] = Some(new ResourceDiscovery:
    def selectableResources(credential: ProviderSecret, root: ConnectionResource) =
      if root.kind != Linear.organization.wire then IO.pure(Left(OAuthError.InvalidState))
      else listTeams(new String(ProviderSecret.bytes(credential), StandardCharsets.UTF_8), None, Vector.empty).map(_.map: teams =>
        teams.distinctBy(_.id.value).map(team =>
          SelectableProviderResource(Linear.team, team.id.externalId, s"${team.name} (${team.key})", root.externalId)
        ).sortBy(_.displayName)
      )
  )

  /** Without a challenge this provider refuses to start; PKCE is mandatory here. */
  def authorizationUri(state: OAuthState): IO[URI] = IO.raiseError(IllegalStateException("Linear requires PKCE"))
  override def authorizationUri(state: OAuthState, pkce: Option[PkceVerifier]): IO[URI] = pkce match
    case None => IO.raiseError(IllegalStateException("Linear requires PKCE"))
    case Some(challenge) =>
      IO.delay:
        val query = form(Vector(
          "client_id" -> client.clientId,
          "redirect_uri" -> redirectUri.toString,
          "response_type" -> "code",
          "scope" -> "read,write",
          "state" -> state.value,
          "code_challenge" -> challenge.challenge,
          "code_challenge_method" -> "S256",
          "prompt" -> "consent"
        ))
        URI.create(endpoints.authorize.toString + (if endpoints.authorize.getRawQuery == null then "?" else "&") + query)

  def exchange(callback: OAuthCallback): IO[Either[OAuthError, OAuthGrant]] = IO.pure(Left(OAuthError.InvalidState))
  override def exchange(callback: OAuthCallback, pkce: Option[PkceVerifier]): IO[Either[OAuthError, OAuthGrant]] = pkce match
    case None => IO.pure(Left(OAuthError.InvalidState))
    case Some(verifier) =>
      (for
        tokens <- EitherT(requestTokens(callback, verifier))
        identity <- EitherT(identify(tokens))
      yield OAuthGrant(
        secret = OAuthTokenJsonCodec().encode(tokens),
        externalAccountId = identity.organization.externalId,
        rootExternalId = identity.organization.externalId,
        rootDisplayName = identity.organizationName,
        accountLabel = identity.viewerName,
        workspaceLabel = Some(identity.organizationName),
        expiresAt = Some(tokens.expiresAt)
      )).value

  private final case class Identity(organization: LinearId, organizationName: String, viewerName: Option[String])

  private def requestTokens(callback: OAuthCallback, verifier: PkceVerifier): IO[Either[OAuthError, OAuthTokens]] =
    IO.delay:
      HttpRequest.newBuilder(endpoints.token)
        .timeout(RequestTimeout)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("User-Agent", "hallpass")
        .POST(HttpRequest.BodyPublishers.ofString(
          form(Vector(
            "grant_type" -> "authorization_code",
            "code" -> callback.code,
            "redirect_uri" -> redirectUri.toString,
            "client_id" -> client.clientId,
            "client_secret" -> client.clientSecret,
            "code_verifier" -> verifier.value
          )),
          StandardCharsets.UTF_8))
        .build()
    .attempt.flatMap:
      case Left(_) => IO.pure(Left(OAuthError.ProviderRejected))
      case Right(request) =>
        BoundedHttpResponse.send(http, request, LinearConnector.MaximumTokenResponseBytes, RequestTimeout.toMillis.millis).attempt.flatMap:
          case Left(_) => IO.pure(Left(OAuthError.ProviderRejected))
          case Right(response) =>
            val bytes = response.body()
            // Only a 200 is parsed; any other status, including a 3xx that was not followed, is a rejection.
            val parsed =
              try
                if response.statusCode() == 200 then LinearConnector.decodeTokenResponse(bytes)
                else Left(OAuthError.ProviderRejected)
              finally java.util.Arrays.fill(bytes, 0.toByte)
            parsed match
              case Left(error) => IO.pure(Left(error))
              case Right((access, refresh, lifetime)) =>
                clock.now.attempt.map:
                  case Left(_) => Left(OAuthError.ProviderRejected)
                  case Right(now) =>
                    scala.util.Try(now.plusSeconds(lifetime)).toOption
                      .flatMap(expiresAt => OAuthTokens.from(access, Some(refresh), expiresAt))
                      .toRight(OAuthError.InvalidProviderResponse)

  private def identify(tokens: OAuthTokens): IO[Either[OAuthError, Identity]] =
    graphql.execute(tokens.accessToken, LinearConnector.IdentityDocument, Json.obj()).map:
      case Left(error) => Left(LinearConnector.toOAuthError(error))
      case Right(data) =>
        val organization = data.hcursor.downField("organization")
        val parsed = for
          id <- organization.get[String]("id").toOption.flatMap(LinearId.parse)
          name <- organization.get[String]("name").toOption.filter(LinearConnector.validLabel)
        yield Identity(
          id,
          name,
          data.hcursor.downField("viewer").get[String]("name").toOption.filter(LinearConnector.validLabel)
        )
        parsed.toRight(OAuthError.InvalidProviderResponse)

  def selectableResources(credential: ProviderSecret, root: ConnectionResource): IO[Either[OAuthError, Vector[SelectableProviderResource]]] =
    if root.kind != Linear.organization.wire then IO.pure(Left(OAuthError.InvalidState))
    else
      OAuthTokenJsonCodec().decode(credential) match
        case Left(_) => IO.pure(Left(OAuthError.InvalidState))
        case Right(tokens) =>
          clock.now.flatMap: now =>
            // A management listing never refreshes; an expired token is rejected without a request.
            if !tokens.expiresAt.isAfter(now) then IO.pure(Left(OAuthError.ProviderRejected))
            else listTeams(tokens.accessToken, None, Vector.empty).map(_.map: teams =>
              teams.distinctBy(_.id.value).map(team =>
                SelectableProviderResource(Linear.team, team.id.externalId, s"${team.name} (${team.key})", root.externalId)
              ).sortBy(_.displayName)
            )

  private final case class TeamRow(id: LinearId, name: String, key: String)

  private def listTeams(token: String, after: Option[String], collected: Vector[TeamRow]): IO[Either[OAuthError, Vector[TeamRow]]] =
    val variables = Json.obj("first" -> Json.fromInt(LinearConnector.PageSize), "after" -> after.fold(Json.Null)(Json.fromString))
    graphql.execute(token, LinearConnector.TeamsDocument, variables).flatMap:
      case Left(error) => IO.pure(Left(LinearConnector.toOAuthError(error)))
      case Right(data) =>
        val teams = data.hcursor.downField("teams")
        val rows = teams.get[Vector[Json]]("nodes").toOption.flatMap: nodes =>
          val decoded = nodes.map: node =>
            for
              id <- node.hcursor.get[String]("id").toOption.flatMap(LinearId.parse)
              name <- node.hcursor.get[String]("name").toOption.filter(LinearConnector.validLabel)
              key <- node.hcursor.get[String]("key").toOption.filter(LinearConnector.validLabel)
            yield TeamRow(id, name, key)
          Option.when(decoded.forall(_.isDefined))(decoded.flatten)
        val page = teams.downField("pageInfo")
        val more = page.get[Boolean]("hasNextPage").toOption
        val cursor = page.get[String]("endCursor").toOption.filter(c => c.nonEmpty && c.length <= 1024)
        (rows, more) match
          case (Some(found), Some(hasMore)) =>
            val all = (collected ++ found).take(LinearConnector.MaximumTeams)
            if !hasMore || all.size >= LinearConnector.MaximumTeams then IO.pure(Right(all))
            else cursor match
              case Some(next) if !after.contains(next) => listTeams(token, Some(next), all)
              case _ => IO.pure(Left(OAuthError.InvalidProviderResponse))
          case _ => IO.pure(Left(OAuthError.InvalidProviderResponse))

  private val RequestTimeout = java.time.Duration.ofSeconds(10)

  private def form(fields: Vector[(String, String)]): String =
    fields.map((key, value) => encode(key) + "=" + encode(value)).mkString("&")
  private def encode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8)

object LinearConnector:
  val MaximumTokenResponseBytes: Int = 64 * 1024
  val MaximumLifetimeSeconds: Long = 365L * 24 * 60 * 60
  val PageSize: Int = 100
  val MaximumTeams: Int = 1000

  private[linear] val IdentityDocument = LinearDocument("query Identity { viewer { id name } organization { id name urlKey } }")
  private[linear] val TeamsDocument = LinearDocument(
    "query Teams($first: Int!, $after: String) { teams(first: $first, after: $after) { nodes { id name key } pageInfo { hasNextPage endCursor } } }"
  )

  private def validLabel(value: String): Boolean =
    value.trim.nonEmpty && value.length <= 200 && !value.exists(Character.isISOControl)

  /** Provider and transport failures are one rejection; only a malformed body is an invalid response. */
  private def toOAuthError(error: LinearApiError): OAuthError = error match
    case LinearApiError.InvalidResponse => OAuthError.InvalidProviderResponse
    case _ => OAuthError.ProviderRejected

  private def validToken(value: String): Boolean =
    value.nonEmpty && value.length <= 16384 && value.forall(c => !c.isWhitespace && !Character.isISOControl(c))

  private def decodeTokenResponse(bytes: Array[Byte]): Either[OAuthError, (String, String, Long)] =
    val fields = scala.util.Try(
      StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString
    ).toOption.flatMap(parse(_).toOption).flatMap(_.asObject)
    fields.flatMap: obj =>
      for
        _ <- Option.when(!obj.contains("error"))(())
        _ <- obj("token_type").fold(Some(()))(_.asString.filter(_.equalsIgnoreCase("Bearer")).map(_ => ()))
        access <- obj("access_token").flatMap(_.asString).filter(validToken)
        refresh <- obj("refresh_token").flatMap(_.asString).filter(validToken)
        lifetime <- obj("expires_in").flatMap(_.asNumber).flatMap(_.toLong)
          .filter(seconds => seconds > 0 && seconds <= MaximumLifetimeSeconds)
      yield (access, refresh, lifetime)
    .toRight(OAuthError.InvalidProviderResponse)
