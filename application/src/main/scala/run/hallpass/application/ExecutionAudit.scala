package run.hallpass.application

import java.time.Instant
import java.util.UUID

import cats.effect.IO
import cats.effect.Ref
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.AuthorizationEvidence
import run.hallpass.kernel.authorization.ExecutorAudience
import run.hallpass.kernel.authorization.ExecutionLease

/** A bounded, server-generated correlation identifier that is safe to retain with execution evidence. */
opaque type ExecutionAuditCorrelationId = String
object ExecutionAuditCorrelationId:
  def parse(value: String): Option[ExecutionAuditCorrelationId] =
    Option.when(
      value.nonEmpty && value.length <= 128 && value == value.trim && value.forall(character => !Character.isISOControl(character))
    )(value)

  extension (value: ExecutionAuditCorrelationId) def value: String = value

/** The tenant catalog ID of a capability. It is distinct from a protocol tool name and from its descriptor. */
opaque type CatalogCapabilityId = UUID
object CatalogCapabilityId:
  def parse(value: String): Option[CatalogCapabilityId] =
    try Some(UUID.fromString(value))
    catch case _: IllegalArgumentException => None

  extension (value: CatalogCapabilityId) def value: UUID = value

/** Shared, credential-free invocation metadata. It is deliberately sealed so the broker can issue a lease only for an
  * explicit invocation origin: today, only an authenticated agent invocation. */
sealed trait ExecutionAuditMetadata:
  def tenant: TenantId
  def correlationId: ExecutionAuditCorrelationId
  def agentId: AgentId
  def toolId: ResourceId
  def capabilityId: CatalogCapabilityId

/** Metadata for an invocation which passed the agent-authentication boundary. The enrollment credential identity is
  * mandatory and derived from [[AuthenticatedAgentContext]], so callers cannot combine a tenant, principal, and
  * credential selected independently. */
final class AuthenticatedExecutionAuditMetadata private[application] (
    authenticated: AuthenticatedAgentContext,
    val correlationId: ExecutionAuditCorrelationId,
    val toolId: ResourceId,
    val capabilityId: CatalogCapabilityId,
    /** The exact invocation this lease may execute. */
    val binding: InvocationBinding
) extends ExecutionAuditMetadata:
  val tenant: TenantId = authenticated.tenant
  val agentId: AgentId = authenticated.agentId
  val agentCredentialId: AgentCredentialId = authenticated.credentialId

object ExecutionAuditMetadata:
  /** The authenticated context is the only source of the durable tenant, agent, and enrollment credential binding. */
  def authenticatedInvocation(
      authenticated: AuthenticatedAgentContext,
      correlationId: ExecutionAuditCorrelationId,
      toolId: ResourceId,
      capabilityId: CatalogCapabilityId,
      binding: InvocationBinding
  ): AuthenticatedExecutionAuditMetadata =
    new AuthenticatedExecutionAuditMetadata(authenticated, correlationId, toolId, capabilityId, binding)

enum ExecutionAuditContextError:
  case LeaseTenantDoesNotMatchInvocation
  case LeasePrincipalDoesNotMatchAuthenticatedAgent

/** Metadata shared by lifecycle audit events for one execution lease.
  *
  * This deliberately contains authorization evidence rather than a credential, request headers, or a provider response.
  * It is sufficient to explain why a trusted executor was permitted to attempt an operation without turning the audit
  * trail into a channel for provider secrets or payloads.
  *
  * Its constructor is private so an executable lifecycle event can only be formed from an issued lease and complete
  * server-created invocation metadata. In-memory recorders use the same complete shape as PostgreSQL; durability is
  * a recorder concern, never optional security metadata.
  */
sealed trait ExecutionAuditContext:
  def leaseId: ExecutionLeaseId
  def authorizationRequestId: AuthorizationRequestId
  def evidence: AuthorizationEvidence
  def audience: ExecutorAudience
  def metadata: ExecutionAuditMetadata
  final def tenant: TenantId = metadata.tenant
  final def correlationId: ExecutionAuditCorrelationId = metadata.correlationId
  final def agentId: AgentId = metadata.agentId
  final def toolId: ResourceId = metadata.toolId
  final def capabilityId: CatalogCapabilityId = metadata.capabilityId

final class AuthenticatedExecutionAuditContext private[application] (
    val leaseId: ExecutionLeaseId,
    val authorizationRequestId: AuthorizationRequestId,
    val evidence: AuthorizationEvidence,
    val audience: ExecutorAudience,
    val metadata: AuthenticatedExecutionAuditMetadata
) extends ExecutionAuditContext:
  def agentCredentialId: AgentCredentialId = metadata.agentCredentialId
  def binding: InvocationBinding = metadata.binding

object ExecutionAuditContext:
  /** Builds the durable authenticated context. The metadata itself carries a non-optional enrollment credential. */
  def fromLease(
      lease: ExecutionLease,
      metadata: AuthenticatedExecutionAuditMetadata
  ): Either[ExecutionAuditContextError, AuthenticatedExecutionAuditContext] =
    if lease.tenant != metadata.tenant then Left(ExecutionAuditContextError.LeaseTenantDoesNotMatchInvocation)
    else lease.principal match
      case Principal.Agent(id) if id == metadata.agentId =>
        Right(new AuthenticatedExecutionAuditContext(lease.id, lease.authorizationRequestId, lease.evidence, lease.audience, metadata))
      case _ => Left(ExecutionAuditContextError.LeasePrincipalDoesNotMatchAuthenticatedAgent)

  def forLease(
      lease: ExecutionLease,
      metadata: ExecutionAuditMetadata
  ): Either[ExecutionAuditContextError, ExecutionAuditContext] = metadata match
    case authenticated: AuthenticatedExecutionAuditMetadata => fromLease(lease, authenticated)

/** The reason a lease redemption was rejected, expressed without request data. */
enum LeaseRedemptionDenial:
  case UnknownLease
  case Expired
  case AlreadyRedeemed
  case WrongAudience

/** A sanitized category for an execution failure. Provider details stay at the adapter boundary. */
enum ExecutionFailure:
  case AuthorityRevoked
  case ConnectionUnavailable
  case ProviderUnavailable
  case ProviderRejected
  case Unexpected
  /** The provider may have completed, but durable completion evidence could not be committed. Never retry. */
  case CompletionUnknown
  /** The tenant gate could not be acquired or its ownership proven. Nothing was dispatched to the provider. */
  case CoordinationUnavailable

/** An append-only, credential-free record of a lease's lifecycle.
  *
  * `occurredAt` is supplied by the application boundary so event ordering and time remain explicit and testable.
  */
enum ExecutionAuditEvent:
  case LeaseIssued(context: ExecutionAuditContext, occurredAt: Instant)
  case RedemptionDenied(
      leaseId: ExecutionLeaseId,
      audience: ExecutorAudience,
      outcome: LeaseRedemptionDenial,
      occurredAt: Instant,
      context: Option[ExecutionAuditContext] = None
  )
  case LeaseRedeemed(context: ExecutionAuditContext, occurredAt: Instant)
  case ExecutionCompleted(context: ExecutionAuditContext, occurredAt: Instant)
  case ExecutionFailed(context: ExecutionAuditContext, outcome: ExecutionFailure, occurredAt: Instant)

/** Effect boundary for durable audit adapters. */
trait ExecutionAudit[F[_]]:
  def record(event: ExecutionAuditEvent): F[Unit]

/** An in-memory recorder for tests and local prototype composition.
  *
  * It is intentionally not a durable audit implementation. A later adapter can implement [[ExecutionAudit]] with
  * transactional persistence without changing the lifecycle event model.
  */
final class InMemoryExecutionAuditRecorder private (events: Ref[IO, Vector[ExecutionAuditEvent]])
    extends ExecutionAudit[IO]:
  def record(event: ExecutionAuditEvent): IO[Unit] = events.update(_ :+ event)

  def recorded: IO[Vector[ExecutionAuditEvent]] = events.get

object InMemoryExecutionAuditRecorder:
  def create: IO[InMemoryExecutionAuditRecorder] =
    Ref.of[IO, Vector[ExecutionAuditEvent]](Vector.empty).map(new InMemoryExecutionAuditRecorder(_))
