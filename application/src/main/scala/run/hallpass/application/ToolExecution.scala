package run.hallpass.application

import java.time.{Duration, Instant}
import cats.effect.IO
import cats.syntax.all.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

opaque type SearchQuery = String
object SearchQuery:
  enum ValidationError:
    case Empty, TooLong

  val MaximumLength = 1000

  def parse(value: String): Either[ValidationError, SearchQuery] =
    Option
      .when(value.trim.nonEmpty)(value)
      .toRight(ValidationError.Empty)
      .flatMap: query =>
        Either.cond(query.length <= MaximumLength, query, ValidationError.TooLong)

  extension (query: SearchQuery) def value: String = query

opaque type ExternalToolId = String
object ExternalToolId:
  def parse(value: String): Option[ExternalToolId] =
    Option.when(value.nonEmpty && value.forall(c => c.isLetterOrDigit || c == 95))(value)

  extension (tool: ExternalToolId) def value: String = tool

final case class ToolResult(content: String)

/** Issues authority evidence after authorization. It deliberately has no API for retrieving provider credentials: only
  * a trusted executor may do that after redeeming the resulting lease.
  */
trait CredentialBroker[F[_]]:
  def issueLease(
      capability: AuthorizedCapability,
      authorizationRequestId: AuthorizationRequestId,
      audience: ExecutorAudience,
      auditMetadata: ExecutionAuditMetadata
  ): F[ExecutionLease]

/** Effectful wall-clock time at the application boundary. Kernel evaluation receives an explicit Instant.
  * Implementations must read time when the effect runs; tests may inject fixed or advancing time.
  */
trait Clock[F[_]]:
  def now: F[Instant]

enum LeaseAuthorityDenial:
  /** Current credential, mapping, policy, or complete authority no longer matches the issued proof. */
  case CurrentStateChanged

trait LeaseAuthorityValidator[F[_]]:
  def validate(lease: RedeemedExecutionLease, now: Instant): F[Either[LeaseAuthorityDenial, Unit]]

object Clock:
  val system: Clock[IO] = new Clock[IO]:
    def now: IO[Instant] = IO.realTimeInstant

  def fixed(at: Instant): Clock[IO] = new Clock[IO]:
    def now: IO[Instant] = IO.pure(at)

/** Local prototype broker. The store write is intentionally the only side effect following issuance; provider
  * credential access belongs to a trusted executor.
  */
final class InMemoryCredentialBroker(
    store: ExecutionLeaseStore[IO],
    clock: Clock[IO],
    ttl: Duration,
    audit: ExecutionAudit[IO]
) extends CredentialBroker[IO]:
  require(!ttl.isNegative && !ttl.isZero, "execution lease TTL must be positive")

  def issueLease(
      capability: AuthorizedCapability,
      authorizationRequestId: AuthorizationRequestId,
      audience: ExecutorAudience,
      auditMetadata: ExecutionAuditMetadata
  ): IO[ExecutionLease] =
    clock.now.flatMap: issuedAt =>
      ExecutionLease.issueForBroker(capability, authorizationRequestId, audience, issuedAt, issuedAt.plus(ttl)) match
        case Left(error)  => IO.raiseError(ExecutionLeaseIssuanceException(error))
        case Right(lease) =>
          ExecutionAuditContext.forLease(lease, auditMetadata) match
            case Left(error) => IO.raiseError(ExecutionAuditContextException(error))
            case Right(context) =>
              store.issue(lease, context) *> audit.record(ExecutionAuditEvent.LeaseIssued(context, issuedAt)).as(lease)

final case class ExecutionLeaseIssuanceException(error: ExecutionLeaseIssuanceError)
    extends RuntimeException(error.toString)
final case class ExecutionAuditContextException(error: ExecutionAuditContextError)
    extends RuntimeException(error.toString)
