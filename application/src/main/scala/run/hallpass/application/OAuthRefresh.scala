package run.hallpass.application

import java.time.Instant
import cats.effect.IO
import run.hallpass.kernel.*

/** Executor-private OAuth material. Its rendering is always credential-free. */
final class OAuthTokens private (
    val accessToken: String,
    val refreshToken: Option[String],
    val expiresAt: Instant
):
  override def toString: String = "OAuthTokens(<redacted>)"

object OAuthTokens:
  def from(accessToken: String, refreshToken: Option[String], expiresAt: Instant): Option[OAuthTokens] =
    def valid(value: String): Boolean =
      value != null && value.nonEmpty && value.length <= 16384 &&
        !value.exists(character => Character.isISOControl(character) || Character.isWhitespace(character))
    // PostgreSQL timestamptz has microsecond precision. Round downward before encrypting the same expiry;
    // otherwise metadata equality can reject a correctly rotated token on its next use.
    Option.when(expiresAt != null && valid(accessToken) && refreshToken.forall(valid))(
      new OAuthTokens(accessToken, refreshToken, expiresAt.truncatedTo(java.time.temporal.ChronoUnit.MICROS))
    )

enum OAuthRefreshError:
  /** The token endpoint refused the refresh token (for example `invalid_grant`). Reauthorization is required. */
  case Rejected
  /** The request may have reached the provider, but no usable answer came back. */
  case Unavailable
  case InvalidResponse
  /** The request provably never left this process (connection refused, DNS failure, connect timeout). The refresh
    * token cannot have been consumed. */
  case NotSent

/** Whether a provider replaces the refresh token on each refresh. A rotating provider may invalidate the old token as
  * soon as it receives the request, so an unanswered request leaves reauthorization required. A non-rotating provider
  * keeps the old token valid, so only an explicit rejection does. */
enum RefreshTokenRotation:
  case Rotating, NonRotating

/** Provider-specific refresh edge; implementations bound their request and never retry or expose response bodies. */
trait OAuthTokenRefresher:
  def refresh(tokens: OAuthTokens): IO[Either[OAuthRefreshError, OAuthTokens]]

/** Structured credential encoding lives at the adapter edge, never in ordinary database columns. */
trait OAuthTokenCodec:
  def encode(tokens: OAuthTokens): ProviderSecret
  def decode(secret: ProviderSecret): Either[ConnectionError, OAuthTokens]

/** Only the repository constructs this slot, after resolving the redeemed lease's connection under its lock. */
trait LockedOAuthCredential:
  def binding: SecretBinding
  def reference: SecretReference
  def expiresAt: Option[Instant]
  /** Commit BEFORE sending a potentially rotating refresh request. A crashed attempt requires reconnecting. */
  def requireReauthorization(at: Instant): IO[Either[ConnectionError, Unit]]
  /** Clears this attempt's marker when the old refresh token provably remains valid. Conditional on the pointer
    * being unchanged, so it can never revert a newer publication. */
  def restore(at: Instant): IO[Either[ConnectionError, Unit]]
  /** Publish an immutable secret version and restore ACTIVE in the same transaction. */
  def publish(reference: SecretReference, expiresAt: Instant, at: Instant): IO[Either[ConnectionError, Unit]]

trait OAuthRefreshRepository:
  /** Cross-instance single-flight. The callback is bounded and runs while the executor's tenant gate is held. */
  def withCredential[K](
      lease: RedeemedExecutionLease,
      target: SelectedResource[K],
      provider: ProviderId
  )(use: LockedOAuthCredential => IO[Either[ConnectionError, OAuthTokens]]): IO[Either[ConnectionError, OAuthTokens]]
