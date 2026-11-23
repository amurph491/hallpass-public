package run.hallpass.application

import java.time.Instant
import java.util.{Arrays, Base64}
import java.util.UUID
import run.hallpass.kernel.*
import cats.Monad
import cats.syntax.all.*

/** Identifier for an Hallpass agent authentication credential. It is not a provider credential or connection ID. */
opaque type AgentCredentialId = UUID
object AgentCredentialId:
  def random(): AgentCredentialId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, AgentCredentialId] =
    val canonicalUuid = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}".r
    value match
      case canonicalUuid() => Right(UUID.fromString(value))
      case _               => Left(IdentifierParseError.InvalidUuid)

/** A safe, random public selector. It is lookup/display metadata and never contains secret credential material. */
opaque type AgentCredentialSelector = String
object AgentCredentialSelector:
  private val Pattern = "[A-Za-z0-9_-]{16,32}".r

  def parse(value: String): Either[AgentCredentialParseError, AgentCredentialSelector] =
    value match
      case Pattern() => Right(value)
      case _         => Left(AgentCredentialParseError.InvalidSelector)

  extension (value: AgentCredentialSelector) def value: String = value

private[application] final class SecretCredential private[application] (val canonical: String, val selector: AgentCredentialSelector):
  override def toString: String = "PresentedAgentCredential(<redacted>)"

/** A bearer credential received from the local bridge. It intentionally has no JSON codec or public raw-string view. */
opaque type PresentedAgentCredential = SecretCredential
object PresentedAgentCredential:
  private val Pattern = "ac1\\.([A-Za-z0-9_-]{16,32})\\.([A-Za-z0-9_-]{43})".r

  def parse(value: String): Either[AgentCredentialParseError, PresentedAgentCredential] =
    value match
      case Pattern(selector, secret) if canonicalSecret(secret) =>
        AgentCredentialSelector.parse(selector).map(selectorValue => new SecretCredential(value, selectorValue))
      case _ => Left(AgentCredentialParseError.InvalidWireFormat)

  private def canonicalSecret(value: String): Boolean =
    var decoded = Array.emptyByteArray
    try
      decoded = Base64.getUrlDecoder.decode(value)
      decoded.length == 32 && Base64.getUrlEncoder.withoutPadding.encodeToString(decoded) == value
    catch case _: IllegalArgumentException => false
    finally Arrays.fill(decoded, 0.toByte)

  /** Only Hallpass security adapters should need this. It returns a copy suitable for keyed verification. */
  private[hallpass] def canonicalBytes(value: PresentedAgentCredential): Array[Byte] =
    value.canonical.getBytes(java.nio.charset.StandardCharsets.UTF_8)

  extension (value: PresentedAgentCredential)
    def selector: AgentCredentialSelector = value.selector
    def redacted: String = value.toString

private[application] final class SecretVerifier private[application] (val value: Array[Byte]):
  override def toString: String = "StoredAgentCredentialVerifier(<redacted>)"

/** Persistable verifier bytes, never the plaintext bearer credential. */
opaque type StoredAgentCredentialVerifier = SecretVerifier
object StoredAgentCredentialVerifier:
  def fromBytes(value: Array[Byte]): Either[AgentCredentialParseError, StoredAgentCredentialVerifier] =
    Either.cond(value.length == 32, new SecretVerifier(value.clone()), AgentCredentialParseError.InvalidVerifier)

  /** Returns a defensive copy for the persistence/cryptography adapter. */
  private[hallpass] def bytes(value: StoredAgentCredentialVerifier): Array[Byte] = value.value.clone()
  extension (value: StoredAgentCredentialVerifier) def redacted: String = value.toString

enum AgentCredentialParseError:
  case InvalidWireFormat, InvalidSelector, InvalidVerifier

enum CredentialVerifierAlgorithm:
  case HmacSha256

/** Safe provenance required to interpret a stored verifier; it deliberately excludes the verifier key. */
final case class CredentialVerifierMetadata(
    algorithm: CredentialVerifierAlgorithm,
    keyId: String
)

enum UnverifiedClaimError:
  case InvalidValue

/** Caller-supplied model label. It is deliberately not a kernel ModelIdentity. */
final case class UnverifiedModelClaim private (provider: String, name: String, version: Option[String])
object UnverifiedModelClaim:
  def from(
      provider: String,
      name: String,
      version: Option[String]
  ): Either[UnverifiedClaimError, UnverifiedModelClaim] =
    Either.cond(
      valid(provider, 64) && valid(name, 128) && version.forall(valid(_, 64)),
      UnverifiedModelClaim(provider, name, version),
      UnverifiedClaimError.InvalidValue
    )

  private def valid(value: String, maximum: Int): Boolean =
    value.nonEmpty && value.length <= maximum && value == value.trim && value.forall(character => !Character.isISOControl(character))

/** Caller-supplied execution label. It has no authority semantics. */
final case class UnverifiedExecutionClaim private (value: String)
object UnverifiedExecutionClaim:
  def from(value: String): Either[UnverifiedClaimError, UnverifiedExecutionClaim] =
    Either.cond(
      value.nonEmpty && value.length <= 128 && value == value.trim && value.forall(character => !Character.isISOControl(character)),
      UnverifiedExecutionClaim(value),
      UnverifiedClaimError.InvalidValue
    )

/** Bounded, explicitly untrusted telemetry retained separately from authorization identity. */
final case class UnverifiedExecutionClaims private (
    model: Option[UnverifiedModelClaim],
    execution: Option[UnverifiedExecutionClaim]
)
object UnverifiedExecutionClaims:
  val empty: UnverifiedExecutionClaims = UnverifiedExecutionClaims(None, None)
  def from(
      model: Option[UnverifiedModelClaim],
      execution: Option[UnverifiedExecutionClaim]
  ): UnverifiedExecutionClaims = UnverifiedExecutionClaims(model, execution)

/** Verified row returned only by a tenant-scoped credential lookup. */
final class StoredAgentCredential private[hallpass] (
    val tenant: TenantId,
    val id: AgentCredentialId,
    val agentId: AgentId,
    val selector: AgentCredentialSelector,
    val verifier: StoredAgentCredentialVerifier,
    val verifierMetadata: CredentialVerifierMetadata,
    val createdAt: Instant,
    val expiresAt: Option[Instant],
    val revokedAt: Option[Instant],
    val lastUsedAt: Option[Instant]
):
  override def toString: String =
    s"StoredAgentCredential(tenant=$tenant, id=$id, agentId=$agentId, selector=${selector.value}, verifier=<redacted>)"

enum AgentCredentialLookupError:
  case Unknown, Expired, Revoked, InvalidStoredCredential, Unavailable

enum AgentCredentialUseError:
  case NoLongerActive, Unavailable

/** A credential may have authenticated an invocation and be revoked before its lease is redeemed. This distinct,
  * ID-only lookup is used at execution time; it deliberately never accepts or re-verifies bearer material. */
enum AgentCredentialCurrentStateError:
  case NoLongerActive, Unavailable

enum AgentCredentialRejection:
  case UnroutedCredential, UnknownCredential, ExpiredCredential, RevokedCredential, WrongSecret, CredentialNoLongerActive, InvalidStoredCredential

enum AgentAuthenticationError:
  case Rejected(reason: AgentCredentialRejection)
  case Unavailable

/** The lookup is always scoped by one candidate tenant; implementations must not perform global token scans. */
trait AgentCredentialAuthenticationRepository[F[_]]:
  def credentialForAuthentication(
      tenant: TenantId,
      selector: AgentCredentialSelector,
      at: Instant
  ): F[Either[AgentCredentialLookupError, StoredAgentCredential]]

  /** Must update last-used only if this exact credential remains active in the same tenant. */
  def recordSuccessfulAuthentication(
      tenant: TenantId,
      credentialId: AgentCredentialId,
      at: Instant
  ): F[Either[AgentCredentialUseError, Unit]]

/** Execution-time credential check. The typed agent argument prevents a credential from one agent being reused as
  * evidence for another agent's lease. */
trait AgentCredentialCurrentStateRepository[F[_]]:
  def ensureActive(
      tenant: TenantId,
      credentialId: AgentCredentialId,
      agentId: AgentId,
      at: Instant
  ): F[Either[AgentCredentialCurrentStateError, Unit]]

/** Purpose-built verifier boundary. Implementations bind verification to the tenant and compare in constant time. */
trait AgentCredentialVerifier[F[_]]:
  def matches(
      tenant: TenantId,
      presented: PresentedAgentCredential,
      stored: StoredAgentCredentialVerifier,
      metadata: CredentialVerifierMetadata
  ): F[Boolean]

/** Converts an untrusted bearer credential into the only application-level authenticated agent context.
  *
  * The credential names no tenant. Its selector is routed to a candidate tenant through the directory, and the
  * tenant is established only by verifying the credential inside that tenant: the stored verifier is an HMAC bound to
  * the tenant, so a route that points at the wrong tenant finds no credential or fails verification. */
final class AgentAuthenticator[F[_]](
    routes: AgentCredentialRoutes[F],
    credentials: AgentCredentialAuthenticationRepository[F],
    verifier: AgentCredentialVerifier[F]
)(using F: Monad[F]):
  def authenticate(
      presented: PresentedAgentCredential,
      claims: UnverifiedExecutionClaims,
      at: Instant
  ): F[Either[AgentAuthenticationError, AuthenticatedAgentContext]] =
    routes.candidateTenant(presented.selector).flatMap:
      case Left(DirectoryError.Unavailable) => F.pure(Left(AgentAuthenticationError.Unavailable))
      case Right(None) =>
        F.pure(Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.UnroutedCredential)))
      case Right(Some(candidate)) => authenticateIn(candidate, presented, claims, at)

  private def authenticateIn(
      tenant: TenantId,
      presented: PresentedAgentCredential,
      claims: UnverifiedExecutionClaims,
      at: Instant
  ): F[Either[AgentAuthenticationError, AuthenticatedAgentContext]] =
    credentials.credentialForAuthentication(tenant, presented.selector, at).flatMap:
      case Left(error) => F.pure(Left(rejectLookup(error)))
      case Right(stored) if stored.tenant != tenant =>
        F.pure(Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.InvalidStoredCredential)))
      case Right(stored) =>
        verifier.matches(tenant, presented, stored.verifier, stored.verifierMetadata).flatMap:
          case false => F.pure(Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.WrongSecret)))
          case true =>
            credentials.recordSuccessfulAuthentication(tenant, stored.id, at).map:
              case Right(_) =>
                Right(AuthenticatedAgentContext.authenticated(tenant, stored.agentId, stored.id, at, claims))
              case Left(AgentCredentialUseError.NoLongerActive) =>
                Left(AgentAuthenticationError.Rejected(AgentCredentialRejection.CredentialNoLongerActive))
              case Left(AgentCredentialUseError.Unavailable) => Left(AgentAuthenticationError.Unavailable)

  private def rejectLookup(error: AgentCredentialLookupError): AgentAuthenticationError =
    error match
      case AgentCredentialLookupError.Unknown => AgentAuthenticationError.Rejected(AgentCredentialRejection.UnknownCredential)
      case AgentCredentialLookupError.Expired => AgentAuthenticationError.Rejected(AgentCredentialRejection.ExpiredCredential)
      case AgentCredentialLookupError.Revoked => AgentAuthenticationError.Rejected(AgentCredentialRejection.RevokedCredential)
      case AgentCredentialLookupError.InvalidStoredCredential =>
        AgentAuthenticationError.Rejected(AgentCredentialRejection.InvalidStoredCredential)
      case AgentCredentialLookupError.Unavailable => AgentAuthenticationError.Unavailable
