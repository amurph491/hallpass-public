package run.hallpass.application

import java.time.Instant
import java.nio.charset.StandardCharsets
import java.util.{Base64, UUID}
import cats.syntax.all.*

import run.hallpass.kernel.*

/** Closed, credential-free vocabulary persisted by the execution audit adapter. */
enum ExecutionHistoryEventKind:
  case LeaseIssued, LeaseRedeemed, RedemptionDenied, AuthorityChanged, ConnectionUnavailable
  case ProviderRejected, ProviderUnavailable, ExecutionCompleted, CompletionUnknown, CoordinationUnavailable

object ExecutionHistoryEventKind:
  def fromWire(value: String): Option[ExecutionHistoryEventKind] = value match
    case "LEASE_ISSUED"           => Some(LeaseIssued)
    case "LEASE_REDEEMED"         => Some(LeaseRedeemed)
    case "REDEMPTION_DENIED"      => Some(RedemptionDenied)
    case "AUTHORITY_CHANGED"      => Some(AuthorityChanged)
    case "CONNECTION_UNAVAILABLE" => Some(ConnectionUnavailable)
    case "PROVIDER_REJECTED"      => Some(ProviderRejected)
    case "PROVIDER_UNAVAILABLE"   => Some(ProviderUnavailable)
    case "EXECUTION_COMPLETED"   => Some(ExecutionCompleted)
    case "COMPLETION_UNKNOWN"     => Some(CompletionUnknown)
    case "COORDINATION_UNAVAILABLE" => Some(CoordinationUnavailable)
    case _                        => None

  extension (value: ExecutionHistoryEventKind) def wire: String = value match
    case LeaseIssued           => "LEASE_ISSUED"
    case LeaseRedeemed         => "LEASE_REDEEMED"
    case RedemptionDenied      => "REDEMPTION_DENIED"
    case AuthorityChanged      => "AUTHORITY_CHANGED"
    case ConnectionUnavailable => "CONNECTION_UNAVAILABLE"
    case ProviderRejected      => "PROVIDER_REJECTED"
    case ProviderUnavailable   => "PROVIDER_UNAVAILABLE"
    case ExecutionCompleted    => "EXECUTION_COMPLETED"
    case CompletionUnknown     => "COMPLETION_UNKNOWN"
    case CoordinationUnavailable => "COORDINATION_UNAVAILABLE"

enum ExecutionHistoryOutcome:
  case Issued, Redeemed, DeniedUnknownLease, DeniedExpired, DeniedAlreadyRedeemed, DeniedWrongAudience
  case DeniedAuthorityChanged, DeniedConnectionUnavailable, FailedProviderRejected, FailedProviderUnavailable
  case Completed, Unknown, DeniedCoordinationUnavailable

object ExecutionHistoryOutcome:
  def fromWire(value: String): Option[ExecutionHistoryOutcome] = value match
    case "ISSUED"                        => Some(Issued)
    case "REDEEMED"                      => Some(Redeemed)
    case "DENIED_UNKNOWN_LEASE"          => Some(DeniedUnknownLease)
    case "DENIED_EXPIRED"                => Some(DeniedExpired)
    case "DENIED_ALREADY_REDEEMED"       => Some(DeniedAlreadyRedeemed)
    case "DENIED_WRONG_AUDIENCE"         => Some(DeniedWrongAudience)
    case "DENIED_AUTHORITY_CHANGED"      => Some(DeniedAuthorityChanged)
    case "DENIED_CONNECTION_UNAVAILABLE" => Some(DeniedConnectionUnavailable)
    case "FAILED_PROVIDER_REJECTED"     => Some(FailedProviderRejected)
    case "FAILED_PROVIDER_UNAVAILABLE"  => Some(FailedProviderUnavailable)
    case "COMPLETED"                     => Some(Completed)
    case "UNKNOWN"                       => Some(Unknown)
    case "DENIED_COORDINATION_UNAVAILABLE" => Some(DeniedCoordinationUnavailable)
    case _                               => None

  extension (value: ExecutionHistoryOutcome) def wire: String = value match
    case Issued                        => "ISSUED"
    case Redeemed                      => "REDEEMED"
    case DeniedUnknownLease            => "DENIED_UNKNOWN_LEASE"
    case DeniedExpired                 => "DENIED_EXPIRED"
    case DeniedAlreadyRedeemed         => "DENIED_ALREADY_REDEEMED"
    case DeniedWrongAudience           => "DENIED_WRONG_AUDIENCE"
    case DeniedAuthorityChanged        => "DENIED_AUTHORITY_CHANGED"
    case DeniedConnectionUnavailable   => "DENIED_CONNECTION_UNAVAILABLE"
    case FailedProviderRejected        => "FAILED_PROVIDER_REJECTED"
    case FailedProviderUnavailable     => "FAILED_PROVIDER_UNAVAILABLE"
    case Completed                     => "COMPLETED"
    case Unknown                       => "UNKNOWN"
    case DeniedCoordinationUnavailable => "DENIED_COORDINATION_UNAVAILABLE"

/** Read model for the human admin. Labels originate in the trusted tenant catalog and confer no authority. */
final case class ExecutionHistoryEntry(
    requestId: AuthorizationRequestId,
    correlationId: ExecutionAuditCorrelationId,
    agentId: AgentId,
    tool: ExternalToolId,
    capability: String,
    eventKind: ExecutionHistoryEventKind,
    safeOutcome: ExecutionHistoryOutcome,
    occurredAt: Instant,
    cursor: Option[ExecutionHistoryCursor] = None,
    authorizationSource: Option[AuthorizationSource] = None
)

final case class ExecutionHistoryCursor private (occurredAt: Instant, eventId: UUID):
  def encode: String =
    val value = s"${occurredAt.toString}|$eventId".getBytes(StandardCharsets.UTF_8)
    Base64.getUrlEncoder.withoutPadding().encodeToString(value)

object ExecutionHistoryCursor:
  private[hallpass] def fromStored(occurredAt: Instant, eventId: UUID): ExecutionHistoryCursor =
    ExecutionHistoryCursor(occurredAt, eventId)

  def parse(raw: String): Option[ExecutionHistoryCursor] =
    if raw.isEmpty || raw.length > 256 then None
    else
      Either.catchNonFatal(new String(Base64.getUrlDecoder.decode(raw), StandardCharsets.UTF_8)).toOption.flatMap: decoded =>
        decoded.split("\\|", 2) match
          case Array(timestamp, id) =>
            for
              occurredAt <- Either.catchNonFatal(Instant.parse(timestamp)).toOption
              eventId <- Either.catchNonFatal(UUID.fromString(id)).toOption
            yield ExecutionHistoryCursor(occurredAt, eventId)
          case _ => None

final case class ExecutionHistoryPage(
    entries: Vector[ExecutionHistoryEntry],
    nextCursor: Option[ExecutionHistoryCursor]
)

trait ExecutionHistory[F[_]]:
  /** Durable setup evidence, independent of the current activity page. */
  def hasCompletedExecution(tenant: TenantId, agent: Option[AgentId] = None): F[Boolean]

  def recent(tenant: TenantId, agent: Option[AgentId], limit: Int): F[Vector[ExecutionHistoryEntry]]

  def page(
      tenant: TenantId,
      agent: Option[AgentId],
      limit: Int,
      cursor: Option[ExecutionHistoryCursor]
  ): F[ExecutionHistoryPage]

  def forRequest(
      tenant: TenantId,
      agent: Option[AgentId],
      requestId: AuthorizationRequestId,
      limit: Int,
      cursor: Option[ExecutionHistoryCursor]
  ): F[ExecutionHistoryPage]
