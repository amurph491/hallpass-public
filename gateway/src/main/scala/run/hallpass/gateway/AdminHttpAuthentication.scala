package run.hallpass.gateway

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.security.MessageDigest
import java.time.Duration
import java.net.URI
import com.sun.net.httpserver.Headers
import cats.effect.IO
import scala.jdk.CollectionConverters.*
import scala.util.Try
import run.hallpass.application.*
import run.hallpass.adapters.oidc.OidcConfig
import run.hallpass.kernel.TenantId

/** Browser-only protection for the control plane. Agent bearer credentials are never accepted here.
  *
  * Sessions are durable and shared by every instance ([[SessionStore]]). The cookie holds a random token; the server
  * stores only its digest and derives the CSRF token from it. A session records only who signed in (a directory user)
  * and which tenant they selected. Every request re-resolves that pair through the directory into an
  * [[AuthenticatedHuman]], so logout, a disabled user, or a removed membership takes effect on the next request on any
  * instance, and the tenant always comes from a current membership.
  *
  * Login is OIDC ([[HumanLogin]]). The development bootstrap login remains available only when a bootstrap secret is
  * configured, which `ProductionGuard` refuses in production. */
private[gateway] final class AdminHttpAuthentication private (
    config: AdminHttpAuthentication.RuntimeConfig,
    login: HumanLogin,
    sessions: SessionStore,
    humans: HumanAuthenticator[IO],
    developmentIdentity: ExternalIdentity,
    clock: Clock[IO],
    telemetry: Telemetry
):
  import AdminHttpAuthentication.*

  val cookies: Cookies = Cookies(config.secureCookies, config.policy)
  def oidcEnabled: Boolean = login.oidcConfigured
  def bootstrapEnabled: Boolean = config.bootstrap.nonEmpty

  /** Development only: signs in as the development administrator identity, which must resolve to exactly one active
    * administrator membership. */
  def bootstrapSession(headers: Headers): IO[Either[Rejection, NewSession]] =
    config.bootstrap match
      case None => IO.pure(Left(Rejection.LoginUnavailable))
      case Some(expected) =>
        if !sameOrigin(headers, config.origin) then IO.pure(Left(Rejection.OriginRejected))
        else if authorization(headers).nonEmpty then IO.pure(Left(Rejection.AgentAuthenticationNotAccepted))
        else if !(values(headers, BootstrapHeader) match
            case Vector(presented) => constantTimeEquals(presented, expected)
            case _                 => false)
        then IO.pure(Left(Rejection.InvalidBootstrap))
        else
          login.developmentSession(developmentIdentity).map:
            case Right(session)                  => Right(session)
            case Left(LoginFailure.Unavailable)  => Left(Rejection.Unavailable)
            case Left(_)                         => Left(Rejection.NoMembership)

  /** Starts an OIDC login from a top-level navigation. */
  def startLogin(headers: Headers): IO[Either[LoginFailure, LoginRedirect]] =
    if !sameHost(headers, config.origin) then IO.pure(Left(LoginFailure.InvalidCallback)) else login.start

  /** Completes an OIDC callback. Only the browser holding the login-binding cookie for this state can complete it. */
  def completeLogin(headers: Headers, query: Map[String, String]): IO[Either[LoginFailure, NewSession]] =
    if !sameHost(headers, config.origin) then IO.pure(Left(LoginFailure.InvalidCallback))
    else
      (query.get("state"), query.get("code")) match
        case (Some(state), Some(code)) => login.complete(state, code, cookie(headers, cookies.loginName))
        case _                         => IO.pure(Left(LoginFailure.InvalidCallback))

  /** The caller's live session, whether or not a tenant is selected. Unsafe methods require the CSRF token. */
  def session(method: String, headers: Headers): IO[Either[Rejection, BrowserSession]] =
    if authorization(headers).nonEmpty then IO.pure(Left(Rejection.AgentAuthenticationNotAccepted))
    else if !sameOrigin(headers, config.origin) then IO.pure(Left(Rejection.OriginRejected))
    else
      cookie(headers, cookies.sessionName).flatMap(SessionToken.parse) match
        case None => IO.pure(Left(Rejection.MissingSession))
        case Some(token) =>
          if unsafe(method) && !(values(headers, CsrfHeader) match
              case Vector(presented) => token.csrfMatches(presented)
              case _                 => false)
          then IO.pure(Left(Rejection.InvalidCsrf))
          else
            sessions.resolve(token.lookup).map:
              case Left(_)           => Left(Rejection.Unavailable)
              case Right(None)       => Left(Rejection.MissingSession)
              case Right(Some(live)) => Right(BrowserSession(token, live))

  /** A control-plane request: a live session with a selected tenant in which the user is still a member. */
  def authorize(method: String, headers: Headers): IO[Either[Rejection, (AuthenticatedHuman, BrowserSession)]] =
    session(method, headers).flatMap:
      case Left(rejection) => IO.pure(Left(rejection))
      case Right(browser) =>
        browser.live.tenant match
          case None => IO.pure(Left(Rejection.TenantSelectionRequired))
          case Some(tenant) =>
            telemetry.span(TraceSpan.HumanAuthentication, SafeAttribute.tenant(tenant))(
              clock.now.flatMap(now => humans.authenticate(browser.live.user, tenant, now))
            ).map:
                case Right(human)                               => Right(human -> browser)
                case Left(HumanAuthenticationError.Unavailable) => Left(Rejection.Unavailable)
                // The membership is gone. The session may still select another tenant, so it is not revoked here; the
                // directory trigger revokes sessions in a tenant when that membership is removed.
                case Left(_) => Left(Rejection.MembershipInactive)

  def memberships(user: DirectoryUserId): IO[Either[Rejection, Vector[TenantMembership]]] =
    humans.memberships(user).map(_.left.map(_ => Rejection.Unavailable))

  def selectTenant(browser: BrowserSession, tenant: TenantId): IO[Either[Rejection, Unit]] =
    sessions.selectTenant(browser.token.lookup, tenant).map:
      case Left(_)      => Left(Rejection.Unavailable)
      case Right(false) => Left(Rejection.NoMembership)
      case Right(true)  => Right(())

  def logout(browser: BrowserSession): IO[Either[Rejection, Unit]] =
    sessions.revoke(browser.token.lookup).map(_.left.map(_ => Rejection.Unavailable))

private[gateway] object AdminHttpAuthentication:
  val BootstrapPath = "/api/admin/session"
  val BootstrapHeader = "X-Hallpass-Admin-Bootstrap"
  val CsrfHeader = "X-CSRF-Token"

  enum Rejection:
    case InvalidBootstrap, MissingSession, InvalidCsrf, OriginRejected, AgentAuthenticationNotAccepted
    case NoMembership, MembershipInactive, TenantSelectionRequired, LoginUnavailable, Unavailable

  final case class BrowserSession(token: SessionToken, live: LiveSession)
  private[gateway] final case class Origin(value: String, host: String):
    def secure: Boolean = value.startsWith("https://")

  /** Cookie names and attributes. Over HTTPS the `__Host-` prefix makes the browser refuse the cookie unless it is
    * `Secure`, host-only, and `Path=/`, so a sibling subdomain cannot plant or overwrite it. Both cookies are `Lax`, so
    * the top-level redirects back from the identity provider and from Slack carry them, while cross-site subrequests do
    * not; unsafe methods still require the CSRF header. */
  final class Cookies(secure: Boolean, policy: SessionPolicy):
    private val prefix = if secure then "__Host-" else ""
    private val attributes = "; HttpOnly; SameSite=Lax; Path=/" + (if secure then "; Secure" else "")
    val sessionName: String = s"${prefix}hallpass_admin_session"
    val loginName: String = s"${prefix}hallpass_login"
    def session(token: SessionToken): String =
      s"$sessionName=${token.cookieValue}$attributes; Max-Age=${policy.absoluteLifetime.getSeconds}"
    def clearSession: String = s"$sessionName=$attributes; Max-Age=0"
    def login(binding: LoginBinding): String = s"$loginName=${binding.cookieValue}$attributes; Max-Age=600"
    def clearLogin: String = s"$loginName=$attributes; Max-Age=0"

  enum RuntimeConfigError:
    case UnableToReadBootstrapFile, InvalidBootstrap, InvalidOrigin, InsecureOrigin, NoLoginMethod
    case InvalidSessionLifetime(reason: String)
    case InvalidOidc(reason: String)

  /** Management login configuration. Secrets are server configuration, never browser assets. */
  final class RuntimeConfig private (
      val bootstrap: Option[String],
      val origin: Origin,
      val oidc: Option[OidcConfig],
      val policy: SessionPolicy
  ):
    def secureCookies: Boolean = origin.secure
    override def toString: String =
      s"AdminHttpRuntimeConfig(origin=${origin.value}, bootstrap=${bootstrap.fold("<disabled>")(_ => "<redacted>")}, oidc=$oidc)"

  object RuntimeConfig:
    private val BootstrapFile = "HALLPASS_ADMIN_BOOTSTRAP_FILE"
    private val BootstrapValue = "HALLPASS_ADMIN_BOOTSTRAP"
    private val AdminOrigin = "HALLPASS_ADMIN_ORIGIN"
    private val OidcIssuer = "HALLPASS_OIDC_ISSUER"
    private val OidcClientId = "HALLPASS_OIDC_CLIENT_ID"
    private val OidcClientSecret = "HALLPASS_OIDC_CLIENT_SECRET"
    private val OidcRedirect = "HALLPASS_OIDC_REDIRECT_URI"
    private val AbsoluteMinutes = "HALLPASS_ADMIN_SESSION_ABSOLUTE_MINUTES"
    private val IdleMinutes = "HALLPASS_ADMIN_SESSION_IDLE_MINUTES"
    val CallbackPath = "/api/auth/oidc/callback"

    /** Production (`HALLPASS_ENV=production`) requires an https origin and https OIDC endpoints. Whether a bootstrap
      * secret may be configured is `ProductionGuard`'s decision, not this parser's. */
    def fromEnvironment(environment: Map[String, String] = sys.env): Either[RuntimeConfigError, RuntimeConfig] =
      val production = environment.get("HALLPASS_ENV").exists(_.trim.equalsIgnoreCase("production"))
      for
        bootstrap <- secret(environment, BootstrapValue, BootstrapFile)
          .left.map(_ => RuntimeConfigError.UnableToReadBootstrapFile)
        _ <- Either.cond(bootstrap.forall(validBootstrap), (), RuntimeConfigError.InvalidBootstrap)
        origin <- parseOrigin(environment.get(AdminOrigin).map(_.trim).filter(_.nonEmpty).getOrElse("http://localhost:3000"))
        _ <- Either.cond(!production || origin.secure, (), RuntimeConfigError.InsecureOrigin)
        oidc <- oidcConfig(environment, origin, production)
        _ <- Either.cond(bootstrap.nonEmpty || oidc.nonEmpty, (), RuntimeConfigError.NoLoginMethod)
        policy <- sessionPolicy(environment)
      yield new RuntimeConfig(bootstrap, origin, oidc, policy)

    private def oidcConfig(
        environment: Map[String, String],
        origin: Origin,
        production: Boolean
    ): Either[RuntimeConfigError, Option[OidcConfig]] =
      def value(key: String) = environment.get(key).map(_.trim).filter(_.nonEmpty)
      value(OidcIssuer) match
        case None => Right(None)
        case Some(issuer) =>
          for
            clientId <- value(OidcClientId).toRight(RuntimeConfigError.InvalidOidc(s"$OidcClientId is required"))
            clientSecret <- secret(environment, OidcClientSecret, s"${OidcClientSecret}_FILE")
              .left.map(_ => RuntimeConfigError.InvalidOidc(s"unable to read ${OidcClientSecret}_FILE"))
            redirect = value(OidcRedirect).getOrElse(origin.value + CallbackPath)
            config <- OidcConfig.from(issuer, clientId, clientSecret, redirect, requireHttps = production)
              .left.map(RuntimeConfigError.InvalidOidc(_))
          yield Some(config)

    private def sessionPolicy(environment: Map[String, String]): Either[RuntimeConfigError, SessionPolicy] =
      def minutes(key: String, default: Duration): Either[RuntimeConfigError, Duration] =
        environment.get(key).map(_.trim).filter(_.nonEmpty) match
          case None => Right(default)
          case Some(raw) =>
            raw.toLongOption.filter(_ > 0).map(Duration.ofMinutes).toRight(RuntimeConfigError.InvalidSessionLifetime(s"$key must be a positive number of minutes"))
      for
        absolute <- minutes(AbsoluteMinutes, SessionPolicy.default.absoluteLifetime)
        idle <- minutes(IdleMinutes, SessionPolicy.default.idleTimeout)
        policy <- SessionPolicy.from(absolute, idle).left.map(RuntimeConfigError.InvalidSessionLifetime(_))
      yield policy

    private def secret(environment: Map[String, String], key: String, fileKey: String): Either[Unit, Option[String]] =
      environment.get(fileKey).map(_.trim).filter(_.nonEmpty) match
        case Some(file) =>
          Try(Files.readString(Path.of(file), StandardCharsets.UTF_8).trim).toEither.left.map(_ => ()).map(Some(_).filter(_.nonEmpty))
        case None => Right(environment.get(key).map(_.trim).filter(_.nonEmpty))

    private def validBootstrap(value: String): Boolean =
      value.length >= 32 && value.length <= 512 && value.forall(character => !Character.isISOControl(character))

    private def parseOrigin(value: String): Either[RuntimeConfigError, Origin] =
      Try(URI.create(value)).toOption
        .filter(uri => (uri.getScheme == "http" || uri.getScheme == "https") && Option(uri.getRawPath).forall(_.isEmpty) && uri.getRawQuery == null && uri.getRawFragment == null && uri.getHost != null)
        .map(uri => Origin(uri.toString.stripSuffix("/"), uri.getRawAuthority))
        .toRight(RuntimeConfigError.InvalidOrigin)

  def create(
      config: RuntimeConfig,
      login: HumanLogin,
      sessions: SessionStore,
      humans: HumanAuthenticator[IO],
      developmentIdentity: ExternalIdentity,
      clock: Clock[IO] = Clock.system,
      telemetry: Telemetry = Telemetry.noop
  ): AdminHttpAuthentication =
    new AdminHttpAuthentication(config, login, sessions, humans, developmentIdentity, clock, telemetry)

  private def values(headers: Headers, name: String): Vector[String] =
    headers.asScala.iterator.filter(_._1.equalsIgnoreCase(name)).flatMap(_._2.asScala).toVector
  private def authorization(headers: Headers): Vector[String] = values(headers, "Authorization")
  private[gateway] def cookie(headers: Headers, name: String): Option[String] =
    values(headers, "Cookie").flatMap(_.split(";").toVector).map(_.trim).collectFirst {
      case value if value.startsWith(s"$name=") => value.drop(name.length + 1)
    }.filter(_.nonEmpty)
  private def unsafe(method: String): Boolean = method != "GET" && method != "HEAD" && method != "OPTIONS"
  private def constantTimeEquals(presented: String, expected: String): Boolean =
    MessageDigest.isEqual(presented.getBytes(StandardCharsets.UTF_8), expected.getBytes(StandardCharsets.UTF_8))
  private def sameHost(headers: Headers, expected: Origin): Boolean =
    values(headers, "Host") == Vector(expected.host)
  private def sameOrigin(headers: Headers, expected: Origin): Boolean =
    sameHost(headers, expected) && (values(headers, "Origin") match
      case Vector()       => true
      case Vector(origin) => origin == expected.value
      case _              => false)
