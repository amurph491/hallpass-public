package run.hallpass.gateway

import java.net.URI
import java.security.interfaces.RSAPrivateKey
import cats.syntax.all.*
import run.hallpass.adapters.github.{GitHubAppRegistration, GitHubAppSecrets, GitHubEndpoints, GitHubPrivateKey}

/** The platform GitHub App, selected at startup.
  *
  * GitHub is off when `HALLPASS_GITHUB_APP_ID` is unset or blank. Once it is set, every other setting must be valid; an
  * invalid one refuses startup instead of silently disabling GitHub:
  *   - `HALLPASS_GITHUB_CLIENT_ID`, `HALLPASS_GITHUB_APP_SLUG`, `HALLPASS_GITHUB_REDIRECT_URI` (plain values);
  *   - `HALLPASS_GITHUB_PRIVATE_KEY_FILE` (the App's PEM private key) and `HALLPASS_GITHUB_CLIENT_SECRET_FILE`, as mounted
  *     files only: there is no environment-variable form for either secret.
  *
  * `HALLPASS_GITHUB_API_URL` and `HALLPASS_GITHUB_WEB_URL` override the github.com endpoints for a local fake provider.
  * They are development-only: `ProductionGuard` refuses either one, because they decide where tokens and the App JWT
  * are sent. Error messages name settings, never their values.
  */
private[gateway] object GitHubRuntime:
  final case class Selection(
      registration: GitHubAppRegistration,
      secrets: GitHubAppSecrets,
      endpoints: GitHubEndpoints,
      redirectUri: URI
  )

  val AppIdKey = "HALLPASS_GITHUB_APP_ID"
  val ApiUrlKey = "HALLPASS_GITHUB_API_URL"
  val WebUrlKey = "HALLPASS_GITHUB_WEB_URL"

  val ClientIdKey = "HALLPASS_GITHUB_CLIENT_ID"
  val AppSlugKey = "HALLPASS_GITHUB_APP_SLUG"
  val RedirectUriKey = "HALLPASS_GITHUB_REDIRECT_URI"
  val PrivateKeyFileKey = "HALLPASS_GITHUB_PRIVATE_KEY_FILE"
  val ClientSecretFileKey = "HALLPASS_GITHUB_CLIENT_SECRET_FILE"
  /** Environment-variable forms of the secrets. They are never read; their presence refuses startup. */
  private val ForbiddenSecretKeys = Vector("HALLPASS_GITHUB_PRIVATE_KEY", "HALLPASS_GITHUB_CLIENT_SECRET")

  /** `parseKey` is injectable so validation can be tested without a real key; it must not echo its input in errors. */
  def fromEnvironment(
      environment: Map[String, String] = sys.env,
      parseKey: String => Either[String, RSAPrivateKey] = GitHubPrivateKey.parsePem
  ): Either[String, Option[Selection]] =
    environment.get(AppIdKey).map(_.trim).filter(_.nonEmpty) match
      case None => Right(None)
      case Some(rawAppId) =>
        val production = environment.get("HALLPASS_ENV").exists(_.trim.equalsIgnoreCase("production"))
        for
          _ <- ForbiddenSecretKeys
            .find(environment.contains)
            .fold[Either[String, Unit]](Right(()))(key => Left(s"$key is not supported; use ${key}_FILE with a mounted file"))
          appId <- rawAppId.toLongOption.filter(_ > 0).toRight(s"$AppIdKey must be a positive integer")
          clientId <- required(environment, ClientIdKey)
          slug <- required(environment, AppSlugKey)
          registration <- Either
            .catchNonFatal(GitHubAppRegistration(appId, clientId, slug))
            .left.map(_ => s"$AppIdKey, $ClientIdKey or $AppSlugKey is invalid")
          redirect <- required(environment, RedirectUriKey).flatMap(parseRedirect(_, production))
          keyText <- secretFile(environment, PrivateKeyFileKey)
          privateKey <- parseKey(keyText).left.map(_ => s"$PrivateKeyFileKey does not contain a valid RSA private key")
          clientSecret <- secretFile(environment, ClientSecretFileKey)
          api <- endpoint(environment, ApiUrlKey, GitHubEndpoints.DotCom.api)
          web <- endpoint(environment, WebUrlKey, GitHubEndpoints.DotCom.web)
        yield Some(Selection(registration, GitHubAppSecrets(privateKey, clientSecret), GitHubEndpoints(api, web), redirect))

  private def parseRedirect(raw: String, production: Boolean): Either[String, URI] =
    Either
      .catchNonFatal(URI.create(raw))
      .toOption
      .filter(uri => uri.isAbsolute && uri.getHost != null && (uri.getScheme == "http" || uri.getScheme == "https"))
      .toRight(s"$RedirectUriKey must be an absolute http(s) URL")
      .flatMap(uri => Either.cond(!production || uri.getScheme == "https", uri, s"$RedirectUriKey must be https in production"))

  private def endpoint(environment: Map[String, String], key: String, default: URI): Either[String, URI] =
    environment.get(key).map(_.trim).filter(_.nonEmpty) match
      case None => Right(default)
      case Some(raw) =>
        Either
          .catchNonFatal(URI.create(raw))
          .toOption
          .filter(uri => uri.isAbsolute && uri.getHost != null && (uri.getScheme == "http" || uri.getScheme == "https"))
          .toRight(s"$key must be an absolute http(s) URL")

  private def required(environment: Map[String, String], key: String): Either[String, String] =
    environment.get(key).map(_.trim).filter(_.nonEmpty).toRight(s"Missing $key")

  private def secretFile(environment: Map[String, String], key: String): Either[String, String] =
    required(environment, key).flatMap: path =>
      Either
        .catchNonFatal(java.nio.file.Files.readString(java.nio.file.Path.of(path)).trim)
        .left.map(_ => s"Unable to read $key")
        .flatMap(value => Either.cond(value.nonEmpty, value, s"$key is empty"))
