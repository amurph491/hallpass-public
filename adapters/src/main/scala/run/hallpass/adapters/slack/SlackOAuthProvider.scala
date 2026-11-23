package run.hallpass.adapters.slack

import java.net.{URI, URLEncoder}
import java.net.http.{HttpClient, HttpRequest}
import java.nio.charset.StandardCharsets
import cats.effect.IO
import scala.concurrent.duration.*
import io.circe.parser.parse
import run.hallpass.adapters.http.BoundedHttpResponse
import run.hallpass.application.*

/** Slack-specific OAuth edge. Its error surface deliberately omits callback codes, provider response bodies, and
  * credential material.
  */
/** `userScopes` are requested as Slack OAuth V2 `user_scope`; Slack message search cannot use a bot token. */
final case class SlackOAuthConfig(clientId: String, clientSecret: String, redirectUri: URI, userScopes: Vector[String])

final class SlackOAuthProvider(
    config: SlackOAuthConfig,
    client: HttpClient = HttpClient.newHttpClient(),
    authorizeEndpoint: URI = URI.create("https://slack.com/oauth/v2/authorize"),
    tokenEndpoint: URI = URI.create("https://slack.com/api/oauth.v2.access")
) extends ProviderConnector:
  val provider: ProviderId = ProviderId.Slack
  val rootKind: ResourceKind[?] = Slack.workspace
  val redirectUri: URI = config.redirectUri
  val credentialType: String = "SLACK_OAUTH"

  /** Slack search addresses the workspace root without an argument, so one active workspace per tenant. */
  val singleActiveRoot: Boolean = true
  /** PKCE is not used for Slack's confidential-client flow; verify current Slack support before enabling it. */
  val usesPkce: Boolean = false
  /** Message search is authorized at the workspace root. No channel picker is exposed until the connector
    * has a reviewed, bounded channel discovery operation, so management never reads the Slack credential. */
  val resourceDiscovery: Option[ResourceDiscovery] = None

  def authorizationUri(state: OAuthState, pkce: Option[PkceVerifier]): IO[URI] = IO.delay:
    val query = Vector(
      "client_id" -> config.clientId,
      "redirect_uri" -> config.redirectUri.toString,
      "user_scope" -> config.userScopes.mkString(","),
      "state" -> state.value
    )
      .map((key, value) => encode(key) + "=" + encode(value))
      .mkString("&")
    URI.create(authorizeEndpoint.toString + "?" + query)

  def exchange(callback: OAuthCallback, pkce: Option[PkceVerifier]): IO[Either[OAuthError, OAuthGrant]] =
    val body = Vector(
      "client_id" -> config.clientId,
      "client_secret" -> config.clientSecret,
      "code" -> callback.code,
      "redirect_uri" -> config.redirectUri.toString
    )
      .map((key, value) => encode(key) + "=" + encode(value))
      .mkString("&")
    val request = HttpRequest
      .newBuilder(tokenEndpoint)
      .header("Content-Type", "application/x-www-form-urlencoded")
      .POST(HttpRequest.BodyPublishers.ofString(body))
      .build()
    // Bounded in time and size, and cancelable: a stalled token endpoint cannot hold a request open indefinitely.
    BoundedHttpResponse
      .send(client, request, SlackOAuthProvider.MaximumResponseBytes, SlackOAuthProvider.RequestTimeout)
      .attempt
      .map:
        case Left(_)                                           => Left(OAuthError.ProviderRejected)
        case Right(response) if response.statusCode / 100 != 2 => Left(OAuthError.ProviderRejected)
        case Right(response)                                   =>
          val body = response.body()
          try decodeGrant(new String(body, StandardCharsets.UTF_8))
          finally java.util.Arrays.fill(body, 0.toByte)

  private def decodeGrant(body: String): Either[OAuthError, OAuthGrant] =
    for
      json <- parse(body).left.map(_ => OAuthError.InvalidProviderResponse)
      cursor = json.hcursor
      ok <- cursor.get[Boolean]("ok").left.map(_ => OAuthError.InvalidProviderResponse)
      result <-
        if !ok || providerError(cursor) then Left(OAuthError.ProviderRejected)
        else
          for
            // OAuth V2 returns a bot token at the root and the requested user token here. search.messages accepts
            // only the latter, so never silently fall back to the root token.
            token <- cursor
              .downField("authed_user")
              .get[String]("access_token")
              .left
              .map(_ => OAuthError.InvalidProviderResponse)
            account <- cursor
              .downField("authed_user")
              .get[String]("id")
              .left
              .map(_ => OAuthError.InvalidProviderResponse)
            workspace <- cursor
              .downField("team")
              .get[Option[String]]("name")
              .left
              .map(_ => OAuthError.InvalidProviderResponse)
            teamId <- cursor.downField("team").get[String]("id").left.map(_ => OAuthError.InvalidProviderResponse)
            external <- ExternalId.parse(teamId).toRight(OAuthError.InvalidProviderResponse)
          yield OAuthGrant(ProviderSecret.fromUtf8(token), external, external, workspace.getOrElse(teamId), Some(account), workspace, None)
    yield result

  private def providerError(cursor: io.circe.HCursor): Boolean =
    cursor.get[String]("error").toOption.exists(_.nonEmpty) ||
      cursor.get[String]("error_description").toOption.exists(_.nonEmpty) ||
      cursor.downField("response_metadata").get[Vector[String]]("messages").toOption.exists(_.nonEmpty)

  private def encode(value: String) = URLEncoder.encode(value, StandardCharsets.UTF_8)

object SlackOAuthProvider:
  private val MaximumResponseBytes = 64 * 1024
  private val RequestTimeout = 10.seconds
