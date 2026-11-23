package run.hallpass.gateway

import java.net.URI
import cats.syntax.all.*
import run.hallpass.adapters.hubspot.{HubSpotEndpoints, HubSpotOAuthClient}

/** The platform HubSpot OAuth application, selected at startup.
  *
  * HubSpot is off when `HALLPASS_HUBSPOT_CLIENT_ID` is unset or blank. Once it is set, every other setting must be valid;
  * an invalid one refuses startup instead of silently disabling HubSpot:
  *   - `HALLPASS_HUBSPOT_REDIRECT_URI` (an absolute http(s) URL; https in production);
  *   - `HALLPASS_HUBSPOT_CLIENT_SECRET_FILE`, a mounted file only: there is no environment-variable form.
  *
  * `HALLPASS_HUBSPOT_AUTHORIZE_URL` and `HALLPASS_HUBSPOT_API_URL` override the HubSpot endpoints for a local fake provider
  * (the token endpoint is derived from the API URL). They are development-only: `ProductionGuard` refuses them,
  * because they decide where tokens are sent. Error messages name settings, never their values.
  */
private[gateway] object HubSpotRuntime:
  final case class Selection(client: HubSpotOAuthClient, endpoints: HubSpotEndpoints, redirectUri: URI)

  val ClientIdKey = "HALLPASS_HUBSPOT_CLIENT_ID"
  val RedirectUriKey = "HALLPASS_HUBSPOT_REDIRECT_URI"
  val ClientSecretFileKey = "HALLPASS_HUBSPOT_CLIENT_SECRET_FILE"
  val AuthorizeUrlKey = "HALLPASS_HUBSPOT_AUTHORIZE_URL"
  val ApiUrlKey = "HALLPASS_HUBSPOT_API_URL"
  val EndpointOverrideKeys: Vector[String] = Vector(AuthorizeUrlKey, ApiUrlKey)

  /** The environment-variable form of the secret. It is never read; its presence refuses startup. */
  private val ForbiddenSecretKey = "HALLPASS_HUBSPOT_CLIENT_SECRET"

  def fromEnvironment(environment: Map[String, String] = sys.env): Either[String, Option[Selection]] =
    environment.get(ClientIdKey).map(_.trim).filter(_.nonEmpty) match
      case None => Right(None)
      case Some(clientId) =>
        val production = environment.get("HALLPASS_ENV").exists(_.trim.equalsIgnoreCase("production"))
        for
          _ <- Either.cond(!environment.contains(ForbiddenSecretKey), (), s"$ForbiddenSecretKey is not supported; use ${ForbiddenSecretKey}_FILE with a mounted file")
          redirect <- required(environment, RedirectUriKey).flatMap(parseRedirect(_, production))
          clientSecret <- secretFile(environment, ClientSecretFileKey)
          authorize <- endpoint(environment, AuthorizeUrlKey, HubSpotEndpoints.Production.authorize)
          api <- endpoint(environment, ApiUrlKey, HubSpotEndpoints.Production.api)
          client <- Either
            .catchNonFatal(HubSpotOAuthClient(clientId, clientSecret))
            .left.map(_ => s"$ClientIdKey is invalid")
        yield Some(Selection(client, HubSpotEndpoints(authorize, api), redirect))

  private def httpUrl(raw: String): Option[URI] =
    Either
      .catchNonFatal(URI.create(raw))
      .toOption
      .filter(uri => uri.isAbsolute && uri.getHost != null && (uri.getScheme == "http" || uri.getScheme == "https"))

  private def parseRedirect(raw: String, production: Boolean): Either[String, URI] =
    httpUrl(raw)
      .toRight(s"$RedirectUriKey must be an absolute http(s) URL")
      .flatMap(uri => Either.cond(!production || uri.getScheme == "https", uri, s"$RedirectUriKey must be https in production"))

  private def endpoint(environment: Map[String, String], key: String, default: URI): Either[String, URI] =
    environment.get(key).map(_.trim).filter(_.nonEmpty) match
      case None => Right(default)
      case Some(raw) => httpUrl(raw).toRight(s"$key must be an absolute http(s) URL")

  private def required(environment: Map[String, String], key: String): Either[String, String] =
    environment.get(key).map(_.trim).filter(_.nonEmpty).toRight(s"Missing $key")

  private def secretFile(environment: Map[String, String], key: String): Either[String, String] =
    required(environment, key).flatMap: path =>
      Either
        .catchNonFatal(java.nio.file.Files.readString(java.nio.file.Path.of(path)).trim)
        .left.map(_ => s"Unable to read $key")
        .flatMap(value => Either.cond(value.nonEmpty, value, s"$key is empty"))
