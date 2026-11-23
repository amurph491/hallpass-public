package run.hallpass.application

import java.nio.charset.StandardCharsets
import java.security.{MessageDigest, SecureRandom}
import java.time.Duration
import java.util.{Base64, UUID}
import cats.effect.IO
import run.hallpass.kernel.TenantId

/** A SHA-256 digest of a browser secret, computed with a purpose prefix so one secret yields unrelated values for
  * different uses. Only digests are persisted; the secrets themselves stay in the browser. Comparison is constant-time.
  */
final class SecretDigest private (bytes: Array[Byte]):
  def toArray: Array[Byte] = bytes.clone()
  def matches(other: SecretDigest): Boolean = MessageDigest.isEqual(bytes, other.toArray)
  override def equals(other: Any): Boolean = other match
    case digest: SecretDigest => matches(digest)
    case _                    => false
  override def hashCode: Int = java.util.Arrays.hashCode(bytes)
  override def toString: String = "SecretDigest(<redacted>)"

object SecretDigest:
  private[application] def of(purpose: String, secret: String): SecretDigest =
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(purpose.getBytes(StandardCharsets.US_ASCII))
    digest.update(0.toByte)
    SecretDigest(digest.digest(secret.getBytes(StandardCharsets.US_ASCII)))

/** 32 random bytes, base64url without padding (43 characters). */
private[application] object BrowserSecret:
  private val Pattern = "[A-Za-z0-9_-]{43}".r
  def generate(random: SecureRandom): String =
    val bytes = Array.ofDim[Byte](32)
    random.nextBytes(bytes)
    Base64.getUrlEncoder.withoutPadding.encodeToString(bytes)
  def valid(value: String): Boolean = value match
    case Pattern() => true
    case _         => false
  def encode(digest: SecretDigest): String = Base64.getUrlEncoder.withoutPadding.encodeToString(digest.toArray)

/** Binds Slack OAuth state to the browser session that started it. Only a [[SessionToken]] can produce one. */
opaque type OAuthSessionBinding = SecretDigest
object OAuthSessionBinding:
  private[application] def of(digest: SecretDigest): OAuthSessionBinding = digest
  extension (binding: OAuthSessionBinding) def digest: SecretDigest = binding

/** The browser's session cookie value. The server stores only its lookup digest, and derives the CSRF token and the
  * OAuth binding from it, so none of the three is stored. */
final class SessionToken private (value: String):
  def cookieValue: String = value
  def lookup: SecretDigest = SecretDigest.of("authai.session.v1", value)

  /** Sent to the page by `GET /api/session` and required on every unsafe request. A cross-site page can neither read
    * it nor compute it without the HttpOnly cookie. */
  def csrfToken: String = BrowserSecret.encode(SecretDigest.of("authai.csrf.v1", value))
  def csrfMatches(presented: String): Boolean =
    MessageDigest.isEqual(csrfToken.getBytes(StandardCharsets.US_ASCII), presented.getBytes(StandardCharsets.US_ASCII))
  def oauthBinding: OAuthSessionBinding = OAuthSessionBinding.of(SecretDigest.of("authai.oauth-binding.v1", value))
  override def toString: String = "SessionToken(<redacted>)"

object SessionToken:
  def generate(random: SecureRandom): SessionToken = SessionToken(BrowserSecret.generate(random))
  def parse(value: String): Option[SessionToken] = Option.when(BrowserSecret.valid(value))(SessionToken(value))

/** The OIDC `state` parameter. It travels through the identity provider, so it is not trusted on its own: the callback
  * must also present the [[LoginBinding]] cookie of the browser that started the login. */
final class LoginState private (val value: String):
  def digest: SecretDigest = SecretDigest.of("authai.login-state.v1", value)
  override def toString: String = "LoginState(<redacted>)"
object LoginState:
  def generate(random: SecureRandom): LoginState = LoginState(BrowserSecret.generate(random))
  def parse(value: String): Option[LoginState] = Option.when(BrowserSecret.valid(value))(LoginState(value))

/** A short-lived cookie that ties a login callback to the browser that started it, which prevents login CSRF (an
  * attacker completing their own login in a victim's browser). */
final class LoginBinding private (val cookieValue: String):
  def digest: SecretDigest = SecretDigest.of("authai.login-binding.v1", cookieValue)
  override def toString: String = "LoginBinding(<redacted>)"
object LoginBinding:
  def generate(random: SecureRandom): LoginBinding = LoginBinding(BrowserSecret.generate(random))
  def parse(value: String): Option[LoginBinding] = Option.when(BrowserSecret.valid(value))(LoginBinding(value))

/** The OIDC nonce, echoed back inside the signed ID token. */
opaque type OidcNonce = String
object OidcNonce:
  def generate(random: SecureRandom): OidcNonce = BrowserSecret.generate(random)
  def parse(value: String): Option[OidcNonce] = Option.when(value.matches("[A-Za-z0-9_-]{43,128}"))(value)
  extension (nonce: OidcNonce)
    def value: String = nonce
    def matches(presented: String): Boolean =
      MessageDigest.isEqual(nonce.getBytes(StandardCharsets.US_ASCII), presented.getBytes(StandardCharsets.US_ASCII))

/** RFC 7636 PKCE verifier. Only its S256 challenge goes to the browser. */
final class PkceVerifier private (val value: String):
  def challenge: String =
    Base64.getUrlEncoder.withoutPadding.encodeToString(
      MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII))
    )
  override def toString: String = "PkceVerifier(<redacted>)"
object PkceVerifier:
  def generate(random: SecureRandom): PkceVerifier = PkceVerifier(BrowserSecret.generate(random))
  def parse(value: String): Option[PkceVerifier] =
    Option.when(value.matches("[A-Za-z0-9._~-]{43,128}"))(PkceVerifier(value))

/** An authorization code returned to the login callback. It is only redeemable with the matching PKCE verifier. */
final class AuthorizationCode private (val value: String):
  override def toString: String = "AuthorizationCode(<redacted>)"
object AuthorizationCode:
  def parse(value: String): Option[AuthorizationCode] =
    Option.when(value.nonEmpty && value.length <= 4096 && value.forall(character => character > ' ' && character < 127))(
      AuthorizationCode(value)
    )

/** What the server remembers about a login between redirect and callback. */
final case class PendingLogin(nonce: OidcNonce, verifier: PkceVerifier)

enum LoginMethod:
  case Oidc, DevelopmentBootstrap

/** Public, non-secret reference to a session, for audit. */
opaque type SessionId = UUID
object SessionId:
  def random(): SessionId = UUID.randomUUID()
  def fromUuid(value: UUID): SessionId = value
  extension (id: SessionId) def value: UUID = id

/** Absolute and idle lifetimes for a browser session. */
final case class SessionPolicy private (absoluteLifetime: Duration, idleTimeout: Duration)
object SessionPolicy:
  val default: SessionPolicy = SessionPolicy(Duration.ofHours(8), Duration.ofMinutes(30))
  def from(absoluteLifetime: Duration, idleTimeout: Duration): Either[String, SessionPolicy] =
    if absoluteLifetime.compareTo(Duration.ofMinutes(5)) < 0 || absoluteLifetime.compareTo(Duration.ofHours(24)) > 0 then
      Left("the absolute session lifetime must be between 5 minutes and 24 hours")
    else if idleTimeout.compareTo(Duration.ofMinutes(1)) < 0 || idleTimeout.compareTo(absoluteLifetime) > 0 then
      Left("the idle session timeout must be at least 1 minute and no longer than the absolute lifetime")
    else Right(SessionPolicy(absoluteLifetime, idleTimeout))

/** A session that is unrevoked, within its lifetimes, and owned by an active user. The tenant is only the current
  * selection; membership in it is re-resolved on every request. */
final case class LiveSession(id: SessionId, user: DirectoryUserId, tenant: Option[TenantId])

enum SessionStoreError:
  case Unavailable

/** Durable, shared session state. Every instance sees the same sessions, and revocation takes effect on the next
  * request anywhere. Implementations must decide expiry with one shared clock. */
trait SessionStore:
  /** Creates a session for an active user. A tenant can be selected at creation only if it is among the user's current
    * memberships. Returns false, creating nothing, otherwise. */
  def create(
      token: SecretDigest,
      id: SessionId,
      user: DirectoryUserId,
      tenant: Option[TenantId],
      method: LoginMethod,
      policy: SessionPolicy
  ): IO[Either[SessionStoreError, Boolean]]

  /** The live session for a token digest, refreshing its idle deadline. */
  def resolve(token: SecretDigest): IO[Either[SessionStoreError, Option[LiveSession]]]

  /** Selects a tenant among the user's current memberships. False if the session is not live or the tenant is not. */
  def selectTenant(token: SecretDigest, tenant: TenantId): IO[Either[SessionStoreError, Boolean]]

  def revoke(token: SecretDigest): IO[Either[SessionStoreError, Unit]]

enum LoginStoreError:
  case Unavailable, TooManyPendingLogins

/** Pending OIDC logins, shared across instances so the callback may land on any of them. */
trait LoginAttemptStore:
  def begin(state: SecretDigest, binding: SecretDigest, pending: PendingLogin, lifetime: Duration): IO[Either[LoginStoreError, Unit]]

  /** Consumes the attempt whatever the outcome. Returns it only for the binding that started it, before expiry. */
  def consume(state: SecretDigest, binding: SecretDigest): IO[Either[LoginStoreError, Option[PendingLogin]]]

enum IdentityProviderError:
  /** The provider could not be reached or answered unusably. Login fails closed; existing sessions are unaffected. */
  case Unavailable

  /** The provider refused the code, or its ID token failed validation. */
  case Rejected

/** An OpenID Connect provider. `verify` returns an identity only after validating the ID token's signature, issuer,
  * audience, expiry, and nonce. Provider metadata may be fetched lazily, so building the redirect can be unavailable. */
trait IdentityProvider:
  def authorizationUri(
      state: LoginState,
      nonce: OidcNonce,
      verifier: PkceVerifier
  ): IO[Either[IdentityProviderError, java.net.URI]]
  def verify(code: AuthorizationCode, pending: PendingLogin): IO[Either[IdentityProviderError, ExternalIdentity]]

/** Display names for the tenant picker. Callers ask only for tenants the person is currently a member of. */
trait TenantNames:
  def nameOf(tenant: TenantId): IO[Option[String]]
