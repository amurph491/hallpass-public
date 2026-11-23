package run.hallpass.adapters.hubspot

import java.net.{URI, URLEncoder}
import java.net.http.{HttpClient, HttpRequest}
import java.nio.ByteBuffer
import java.nio.charset.{CodingErrorAction, StandardCharsets}
import scala.concurrent.duration.*
import cats.data.EitherT
import cats.effect.IO
import cats.syntax.all.*
import io.circe.JsonObject
import io.circe.parser.parse
import run.hallpass.adapters.http.BoundedHttpResponse
import run.hallpass.adapters.oauth.OAuthTokenJsonCodec
import run.hallpass.application.*

/** HubSpot OAuth (authorization code). PKCE only if HubSpot's current docs support it (set `usesPkce` accordingly).
  *
  * Start: `{authorize}?client_id&redirect_uri&scope=<Scopes space-separated>&state` (+ PKCE params if supported).
  * Callback: POST `{api}/oauth/v1/token` form (grant_type=authorization_code, client_id, client_secret, redirect_uri,
  * code[, code_verifier]); require access_token, refresh_token, positive expires_in. Then
  * GET `{api}/oauth/v1/access-tokens/{access_token}` for `hub_id` (the portal; external account and root ID), `hub_domain`
  * (display), and `user` (account label), and require that its `scopes` contain every scope in HubSpot.Scopes.
  * Grant: OAuthTokenJsonCodec-encoded tokens; expiresAt = expiry; credential type OAUTH_REFRESHABLE.
  * `singleActiveRoot = false`. `resourceDiscovery` returns HubSpot.SelectableObjectTypes as
  * SelectableProviderResource(HubSpot.objectType, portal-qualified object reference, label, root external ID) without any request. */
final class HubSpotConnector(
    client: HubSpotOAuthClient,
    endpoints: HubSpotEndpoints,
    http: HttpClient,
    clock: Clock[IO],
    val redirectUri: URI
) extends ProviderConnector:
  val provider: ProviderId = ProviderId.HubSpot
  val rootKind: ResourceKind[?] = HubSpot.portal
  val credentialType: String = HubSpot.CredentialType
  val singleActiveRoot: Boolean = false
  /** HubSpot's OAuth v1 documentation describes no PKCE parameters, so none are sent. */
  def usesPkce: Boolean = false

  def authorizationUri(state: OAuthState, pkce: Option[PkceVerifier]): IO[URI] = pkce match
    case Some(_) => IO.raiseError(IllegalStateException("HubSpot does not use PKCE"))
    case None =>
      IO.delay:
        val query = form(Vector(
          "client_id" -> client.clientId,
          "redirect_uri" -> redirectUri.toString,
          "scope" -> HubSpot.Scopes.mkString(" "),
          "state" -> state.value
        ))
        URI.create(endpoints.authorize.toString + (if endpoints.authorize.getRawQuery == null then "?" else "&") + query)

  def exchange(callback: OAuthCallback, pkce: Option[PkceVerifier]): IO[Either[OAuthError, OAuthGrant]] = pkce match
    case Some(_) => IO.pure(Left(OAuthError.InvalidState))
    case None =>
      (for
        tokens <- EitherT(requestTokens(callback))
        identity <- EitherT(identify(tokens))
      yield OAuthGrant(
        secret = OAuthTokenJsonCodec().encode(tokens),
        externalAccountId = identity.portal,
        rootExternalId = identity.portal,
        rootDisplayName = identity.domain.getOrElse(s"HubSpot portal ${identity.portal.value}"),
        accountLabel = identity.user,
        workspaceLabel = identity.domain,
        expiresAt = Some(tokens.expiresAt)
      )).value

  /** Object types are fixed by the product, so no request is made. */
  val resourceDiscovery: Option[ResourceDiscovery] = Some(new ResourceDiscovery:
    def selectableResources(credential: ProviderSecret, root: ConnectionResource) =
      if root.kind != HubSpot.portal.wire then IO.pure(Left(OAuthError.InvalidState))
      else
        val selected = HubSpot.SelectableObjectTypes.traverse: (objectType, label) =>
          HubSpotObjectRef.forPortal(root.externalId, objectType)
            .map(ref => SelectableProviderResource(HubSpot.objectType, ref.externalId, label, root.externalId))
        IO.pure(selected.toRight(OAuthError.InvalidState))
  )

  private def requestTokens(callback: OAuthCallback): IO[Either[OAuthError, OAuthTokens]] =
    IO.delay:
      HttpRequest.newBuilder(endpoints.token)
        .timeout(RequestTimeout)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("User-Agent", "hallpass")
        .POST(HttpRequest.BodyPublishers.ofString(
          form(Vector(
            "grant_type" -> "authorization_code",
            "client_id" -> client.clientId,
            "client_secret" -> client.secretForRefresh,
            "redirect_uri" -> redirectUri.toString,
            "code" -> callback.code
          )),
          StandardCharsets.UTF_8))
        .build()
    .attempt.flatMap:
      case Left(_) => IO.pure(Left(OAuthError.ProviderRejected))
      case Right(request) =>
        fetch(request, HubSpotConnector.MaximumTokenResponseBytes)(HubSpotConnector.decodeTokenResponse).flatMap:
          case Left(error) => IO.pure(Left(error))
          case Right((access, refresh, lifetime)) =>
            clock.now.attempt.map:
              case Left(_) => Left(OAuthError.ProviderRejected)
              case Right(now) =>
                scala.util.Try(now.plusSeconds(lifetime)).toOption
                  .flatMap(expiresAt => OAuthTokens.from(access, Some(refresh), expiresAt))
                  .toRight(OAuthError.InvalidProviderResponse)

  /** One request: no redirect, no retry, bounded body. Only a 200 is parsed; the body bytes are zeroed afterwards. */
  private def fetch[A](request: HttpRequest, maximumBytes: Int)(parseBody: Array[Byte] => Either[OAuthError, A]): IO[Either[OAuthError, A]] =
    BoundedHttpResponse.send(http, request, maximumBytes, RequestTimeout.toMillis.millis).attempt.map:
      case Left(_) => Left(OAuthError.ProviderRejected)
      case Right(response) =>
        val bytes = response.body()
        try
          if response.statusCode() == 200 then parseBody(bytes) else Left(OAuthError.ProviderRejected)
        finally java.util.Arrays.fill(bytes, 0.toByte)

  private def identify(tokens: OAuthTokens): IO[Either[OAuthError, HubSpotConnector.Identity]] =
    IO.delay:
      val base = endpoints.api.toString.stripSuffix("/")
      val encoded = URLEncoder.encode(tokens.accessToken, StandardCharsets.UTF_8).replace("+", "%20")
      HttpRequest.newBuilder(URI.create(s"$base/oauth/v1/access-tokens/$encoded"))
        .timeout(RequestTimeout)
        .header("Accept", "application/json")
        .header("User-Agent", "hallpass")
        .GET()
        .build()
    .attempt.flatMap:
      case Left(_) => IO.pure(Left(OAuthError.ProviderRejected))
      case Right(request) => fetch(request, HubSpotConnector.MaximumIdentityResponseBytes)(HubSpotConnector.decodeIdentity)

  private val RequestTimeout = java.time.Duration.ofSeconds(10)

  private def form(fields: Vector[(String, String)]): String =
    fields.map((key, value) => encode(key) + "=" + encode(value)).mkString("&")
  private def encode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8)

object HubSpotConnector:
  val MaximumTokenResponseBytes: Int = 64 * 1024
  val MaximumIdentityResponseBytes: Int = 64 * 1024
  val MaximumLifetimeSeconds: Long = 24L * 60 * 60

  private final case class Identity(portal: ExternalId, domain: Option[String], user: Option[String])

  private def validToken(value: String): Boolean =
    value.nonEmpty && value.length <= 16384 && value.forall(c => !c.isWhitespace && !Character.isISOControl(c))

  private def validLabel(value: String): Boolean =
    value.trim.nonEmpty && value.length <= 200 && !value.exists(Character.isISOControl)

  private def parseObject(bytes: Array[Byte]): Option[JsonObject] =
    scala.util.Try(
      StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString
    ).toOption.flatMap(parse(_).toOption).flatMap(_.asObject)

  private def decodeTokenResponse(bytes: Array[Byte]): Either[OAuthError, (String, String, Long)] =
    parseObject(bytes).flatMap: obj =>
      for
        _ <- Option.when(!obj.contains("error"))(())
        _ <- obj("token_type").fold(Some(()))(_.asString.filter(_.equalsIgnoreCase("bearer")).map(_ => ()))
        access <- obj("access_token").flatMap(_.asString).filter(validToken)
        refresh <- obj("refresh_token").flatMap(_.asString).filter(validToken)
        lifetime <- obj("expires_in").flatMap(_.asNumber).flatMap(_.toLong)
          .filter(seconds => seconds > 0 && seconds <= MaximumLifetimeSeconds)
      yield (access, refresh, lifetime)
    .toRight(OAuthError.InvalidProviderResponse)

  /** `hub_id` must be a positive integral JSON number (the portal ID); the domain is display only. Every scope in
    * Every CRM scope in HubSpot.Scopes must have been granted (the base `oauth` scope may be omitted from token metadata). */
  private def decodeIdentity(bytes: Array[Byte]): Either[OAuthError, Identity] =
    val decoded = parseObject(bytes).flatMap: obj =>
      for
        hubId <- obj("hub_id").flatMap(_.asNumber).flatMap(_.toLong).filter(_ > 0)
        portal <- ExternalId.parse(hubId.toString)
        scopes <- obj("scopes").flatMap(_.asArray).flatMap(a => Option.when(a.forall(_.isString))(a.flatMap(_.asString).toSet))
      yield (
        scopes,
        Identity(
          portal,
          obj("hub_domain").flatMap(_.asString).filter(validLabel),
          obj("user").flatMap(_.asString).filter(validLabel)
        )
      )
    decoded.toRight(OAuthError.InvalidProviderResponse).flatMap: (scopes, identity) =>
      Either.cond(HubSpot.Scopes.filter(_ != "oauth").forall(scopes.contains), identity, OAuthError.ProviderRejected)
