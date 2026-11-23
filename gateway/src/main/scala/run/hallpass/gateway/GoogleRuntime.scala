package run.hallpass.gateway

import java.net.URI
import cats.syntax.all.*
import run.hallpass.adapters.google.{GoogleEndpoints, GoogleOAuthClient}

/** The platform Google OAuth application for Drive, selected at startup.
  *
  * Google Drive is off when `HALLPASS_GOOGLE_DRIVE_CLIENT_ID` is unset or blank. Once it is set, every other setting must be valid;
  * an invalid one refuses startup instead of silently disabling Google Drive:
  *   - `HALLPASS_GOOGLE_DRIVE_REDIRECT_URI` (an absolute http(s) URL; https in production);
  *   - `HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET_FILE`, a mounted file only: there is no environment-variable form.
  *
  * `HALLPASS_GOOGLE_PICKER_API_KEY` and `HALLPASS_GOOGLE_PICKER_APP_ID` (the Cloud project number, digits) are optional,
  * browser-visible Google Picker settings and not secrets; an invalid value refuses startup.
  *
  * `HALLPASS_GOOGLE_GMAIL_SEND_ENABLED` (`true` or `false`, default `false`; anything else refuses startup) adds the
  * gmail.send scope to the consent request and offers each account's mailbox as a selectable resource.
  *
  * `HALLPASS_GOOGLE_AUTHORIZE_URL`, `HALLPASS_GOOGLE_EXCHANGE_URL`, `HALLPASS_GOOGLE_USERINFO_URL` and
  * `HALLPASS_GOOGLE_DRIVE_API_URL` override the Google endpoints for a local fake provider. They are development-only:
  * `ProductionGuard` refuses them, because they decide where tokens are sent. (The token endpoint is named EXCHANGE so
  * the Compose secret scan, which flags environment keys containing TOKEN, stays meaningful.) Error messages name
  * settings, never their values.
  */
private[gateway] object GoogleRuntime:
  final case class Selection(client: GoogleOAuthClient, endpoints: GoogleEndpoints, redirectUri: URI, gmailSend: Boolean = false)

  val ClientIdKey = "HALLPASS_GOOGLE_DRIVE_CLIENT_ID"
  val RedirectUriKey = "HALLPASS_GOOGLE_DRIVE_REDIRECT_URI"
  val ClientSecretFileKey = "HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET_FILE"
  val PickerApiKeyKey = "HALLPASS_GOOGLE_PICKER_API_KEY"
  val PickerAppIdKey = "HALLPASS_GOOGLE_PICKER_APP_ID"
  val GmailSendEnabledKey = "HALLPASS_GOOGLE_GMAIL_SEND_ENABLED"
  val AuthorizeUrlKey = "HALLPASS_GOOGLE_AUTHORIZE_URL"
  val ExchangeUrlKey = "HALLPASS_GOOGLE_EXCHANGE_URL"
  val UserinfoUrlKey = "HALLPASS_GOOGLE_USERINFO_URL"
  val DriveApiUrlKey = "HALLPASS_GOOGLE_DRIVE_API_URL"
  val EndpointOverrideKeys: Vector[String] = Vector(AuthorizeUrlKey, ExchangeUrlKey, UserinfoUrlKey, DriveApiUrlKey)

  /** The environment-variable form of the secret. It is never read; its presence refuses startup. */
  private val ForbiddenSecretKey = "HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET"

  def fromEnvironment(environment: Map[String, String] = sys.env): Either[String, Option[Selection]] =
    environment.get(ClientIdKey).map(_.trim).filter(_.nonEmpty) match
      case None => Right(None)
      case Some(clientId) =>
        val production = environment.get("HALLPASS_ENV").exists(_.trim.equalsIgnoreCase("production"))
        for
          _ <- Either.cond(!environment.contains(ForbiddenSecretKey), (), s"$ForbiddenSecretKey is not supported; use ${ForbiddenSecretKey}_FILE with a mounted file")
          redirect <- required(environment, RedirectUriKey).flatMap(parseRedirect(_, production))
          clientSecret <- secretFile(environment, ClientSecretFileKey)
          pickerKey <- optional(environment, PickerApiKeyKey, "[A-Za-z0-9_-]{1,200}")
          appId <- optional(environment, PickerAppIdKey, "[0-9]{1,30}")
          gmailSend <- gmailEnabled(environment)
          authorize <- endpoint(environment, AuthorizeUrlKey, GoogleEndpoints.Production.authorize)
          token <- endpoint(environment, ExchangeUrlKey, GoogleEndpoints.Production.token)
          userinfo <- endpoint(environment, UserinfoUrlKey, GoogleEndpoints.Production.userinfo)
          driveApi <- endpoint(environment, DriveApiUrlKey, GoogleEndpoints.Production.driveApi)
          client <- Either
            .catchNonFatal(GoogleOAuthClient(clientId, clientSecret, pickerKey, appId))
            .left.map(_ => s"$ClientIdKey is invalid")
        yield Some(Selection(client, GoogleEndpoints(authorize, token, userinfo, driveApi), redirect, gmailSend))

  private def gmailEnabled(environment: Map[String, String]): Either[String, Boolean] =
    environment.get(GmailSendEnabledKey).map(_.trim) match
      case None | Some("") | Some("false") => Right(false)
      case Some("true") => Right(true)
      case Some(_) => Left(s"$GmailSendEnabledKey must be true or false")

  private def optional(environment: Map[String, String], key: String, pattern: String): Either[String, Option[String]] =
    environment.get(key).map(_.trim).filter(_.nonEmpty) match
      case None => Right(None)
      case Some(value) => Either.cond(value.matches(pattern), Some(value), s"$key is invalid")

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
