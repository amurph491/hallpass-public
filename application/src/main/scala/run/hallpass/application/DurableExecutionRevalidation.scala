package run.hallpass.application

import java.time.Instant
import scala.concurrent.duration.*
import cats.data.EitherT
import cats.effect.{IO, Ref, Resource as EffectResource}
import cats.effect.std.Semaphore
import cats.syntax.all.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Fail-closed reasons emitted after a one-time lease has been redeemed but before an external credential may be
  * resolved. They contain identifiers only where that helps an audit trail explain a denial.
  */
enum DurableExecutionRevalidationDenial:
  case LeaseContextMismatch
  case EnrollmentCredentialInactive
  case AuthorityUnavailable
  case AuthorityChanged

/** Current-state check for a redeemed execution. The private redeemed lease context is the binding between an
  * authenticated agent invocation and immutable kernel lease claims; callers cannot select its tenant, agent,
  * credential, tool, resource, action, or audience.
  */
trait DurableExecutionRevalidator[F[_]]:
  def revalidate(
      lease: RedeemedExecutionLease,
      now: Instant
  ): F[Either[DurableExecutionRevalidationDenial, Unit]]

/** Typed, fail-closed reasons a tenant gate could not provide or prove exclusion. None of them carry authority. */
enum TenantGateFailure:
  /** The bounded acquisition wait elapsed; the protected operation never started. */
  case AcquisitionTimedOut

  /** The coordinator could not be reached; the protected operation never started. */
  case CoordinatorUnavailable

  /** The holder can no longer prove it owns the gate; the caller must not dispatch. */
  case OwnershipLost

final case class TenantGateException(failure: TenantGateFailure) extends RuntimeException(failure.toString)

/** Evidence of holding a tenant's gate in execution (shared) mode. */
trait ExecutionGatePermit[F[_]]:
  /** Proves ownership is still held, or raises [[TenantGateException]] with `OwnershipLost`. Call immediately before
    * provider dispatch so a holder whose coordination was lost cannot race a committed mutation.
    */
  def confirmHeld: F[Unit]

/** Readers–writer serialization between execution and tenant-scoped authority mutations.
  *
  * Executions hold the gate shared: they may run concurrently with each other but never with a mutation. Mutations hold
  * it exclusive, and a queued mutation blocks later executions so revocation cannot be starved. Implementations must
  * retain the gate until the supplied effect completes, fails, or is cancelled; checking authority and then releasing
  * before secret/provider access would reintroduce the revocation race. Acquisition failures raise
  * [[TenantGateException]] before the operation starts. Release never turns a completed operation into a failure.
  */
trait TenantExecutionMutationGate[F[_]]:
  def withinExecution[A](tenant: TenantId)(operation: ExecutionGatePermit[F] => F[A]): F[A]
  def withinMutation[A](tenant: TenantId)(operation: F[A]): F[A]

/** Single-process readers–writer gate for local development and tests. It cannot coordinate multiple API instances.
  *
  * Each tenant has a fair semaphore with `maxConcurrentExecutions` permits: an execution takes one, a mutation takes
  * all of them. Cats Effect semaphores serve waiters in FIFO order, so a queued mutation blocks later executions. A
  * small creation mutex ensures concurrent first use of a tenant cannot create two independent semaphores. Tenant
  * semaphores remain for the lifetime of this local gate: evicting a semaphore with holders or waiters would create
  * independent gates for the same tenant and break exclusion. This is intended for bounded local use.
  */
final class SingleProcessTenantExecutionMutationGate private (
    creationMutex: Semaphore[IO],
    tenants: Ref[IO, Map[TenantId, Semaphore[IO]]],
    maxConcurrentExecutions: Int,
    acquisitionTimeout: FiniteDuration
) extends TenantExecutionMutationGate[IO]:
  private val heldPermit: ExecutionGatePermit[IO] = new ExecutionGatePermit[IO]:
    def confirmHeld: IO[Unit] = IO.unit

  def withinExecution[A](tenant: TenantId)(operation: ExecutionGatePermit[IO] => IO[A]): IO[A] =
    holding(tenant, 1L)(operation(heldPermit))

  def withinMutation[A](tenant: TenantId)(operation: IO[A]): IO[A] =
    holding(tenant, maxConcurrentExecutions.toLong)(operation)

  private def holding[A](tenant: TenantId, permits: Long)(operation: IO[A]): IO[A] =
    semaphoreFor(tenant).flatMap: semaphore =>
      EffectResource
        .makeFull[IO, Unit](poll =>
          poll(semaphore.acquireN(permits))
            .timeoutTo(acquisitionTimeout, IO.raiseError(TenantGateException(TenantGateFailure.AcquisitionTimedOut)))
        )(_ => semaphore.releaseN(permits))
        .use(_ => operation)

  private def semaphoreFor(tenant: TenantId): IO[Semaphore[IO]] =
    creationMutex.permit.use: _ =>
      tenants.get.flatMap:
        case existing if existing.contains(tenant) => IO.pure(existing(tenant))
        case _                                     =>
          Semaphore[IO](maxConcurrentExecutions.toLong).flatTap(semaphore =>
            tenants.update(_.updated(tenant, semaphore))
          )

object SingleProcessTenantExecutionMutationGate:
  val DefaultMaxConcurrentExecutions: Int = 32
  val DefaultAcquisitionTimeout: FiniteDuration = 30.seconds

  def create: IO[SingleProcessTenantExecutionMutationGate] =
    create(DefaultMaxConcurrentExecutions, DefaultAcquisitionTimeout)

  def create(
      maxConcurrentExecutions: Int,
      acquisitionTimeout: FiniteDuration
  ): IO[SingleProcessTenantExecutionMutationGate] =
    IO.raiseUnless(maxConcurrentExecutions >= 1)(
      IllegalArgumentException("maxConcurrentExecutions must be positive")
    ) *>
      (Semaphore[IO](1), Ref.of[IO, Map[TenantId, Semaphore[IO]]](Map.empty)).mapN: (creationMutex, tenants) =>
        new SingleProcessTenantExecutionMutationGate(
          creationMutex,
          tenants,
          maxConcurrentExecutions,
          acquisitionTimeout
        )

/** Reloads the trusted tool mapping and complete authority chain, then requires the same successful kernel evidence
  * that issued the lease. A newly valid alternative grant is intentionally insufficient: policy/mapping/delegation
  * changes require a fresh invocation.
  */
final class CurrentStateExecutionRevalidator(
    credentials: AgentCredentialCurrentStateRepository[IO],
    authority: AuthorityRepository[IO],
    tools: TrustedToolLookup[IO],
    resources: ResourceCatalog
) extends DurableExecutionRevalidator[IO]:
  def revalidate(
      lease: RedeemedExecutionLease,
      now: Instant
  ): IO[Either[DurableExecutionRevalidationDenial, Unit]] =
    lease.auditContext match
      case context: AuthenticatedExecutionAuditContext =>
        val validatedContext =
          lease.tenant == context.tenant &&
            lease.principal == Principal.Agent(context.agentId) &&
            lease.resource == context.evidence.requiredCapability.resource &&
            lease.capability == context.evidence.requiredCapability.capability &&
            lease.action == context.evidence.requiredCapability.action &&
            lease.audience == context.audience &&
            lease.authorizationRequestId == context.authorizationRequestId &&
            lease.evidence == context.evidence
        if !validatedContext then IO.pure(Left(DurableExecutionRevalidationDenial.LeaseContextMismatch))
        else
          val validation: EitherT[IO, DurableExecutionRevalidationDenial, Unit] = for
            _ <- EitherT(credentials.ensureActive(context.tenant, context.agentCredentialId, context.agentId, now))
              .leftMap:
                case AgentCredentialCurrentStateError.NoLongerActive =>
                  DurableExecutionRevalidationDenial.EnrollmentCredentialInactive
                case AgentCredentialCurrentStateError.Unavailable =>
                  DurableExecutionRevalidationDenial.AuthorityUnavailable
            tool <- EitherT(tools.externalToolFor(context.tenant, context.toolId))
              .leftMap(_ => DurableExecutionRevalidationDenial.AuthorityChanged)
            // The resource must still be addressable (selected, under an active connection) and is re-scoped from the
            // current catalog, so deselection and a changed ancestry behave like revocation.
            scope <- EitherT.fromOptionF(
              resources.currentScope(context.tenant, lease.resource).map(_.filter(scope =>
                scope.tenant == context.tenant &&
                  scope.target.id == lease.resource &&
                  scope.target.externalId == context.binding.externalId.value
              )),
              DurableExecutionRevalidationDenial.AuthorityChanged
            )
            snapshot <- EitherT(
              authority.snapshotWithin(context.tenant, Principal.Agent(context.agentId), tool.value, scope)
            ).leftMap(_ => DurableExecutionRevalidationDenial.AuthorityChanged)
            _ <- EitherT.fromEither[IO](validateSnapshot(context, lease, snapshot, now))
          yield ()
          validation.value

  private def validateSnapshot(
      context: AuthenticatedExecutionAuditContext,
      lease: RedeemedExecutionLease,
      snapshot: AuthoritySnapshot,
      now: Instant
  ): Either[DurableExecutionRevalidationDenial, Unit] =
    val sameMapping =
      snapshot.toolResourceId.contains(context.toolId) &&
        CatalogCapabilityId.parse(snapshot.capability.id).contains(context.capabilityId) &&
        snapshot.resource.id == lease.resource &&
        snapshot.resource.externalId == context.binding.externalId.value &&
        snapshot.capability.descriptor.capability == lease.capability &&
        snapshot.capability.descriptor.action == lease.action
    val request = AuthorizationRequest(
      lease.authorizationRequestId,
      context.tenant,
      IdentityChain(
        Principal.Agent(context.agentId),
        snapshot.delegations.map(_.id),
        None,
        ExecutionContext.LocalProcess
      ),
      snapshot.scope,
      lease.capability,
      lease.action,
      // The lease binds the exact input whose facts were evaluated in this request; constraints are immutable.
      AuthorizationContext.factsNotEvaluated
    )
    val sameEvidence = AuthorizationEngine.authorize(snapshot.policies, request, snapshot.delegations, now) match
      case AuthorizationResult.Authorized(capability) => capability.evidence == lease.evidence
      // An approved invocation (its approval already consumed in this request) is still current only while the same
      // policy version over the same chain would require approval for the same capability: revocation, a policy
      // change, or a new deny all change this.
      case AuthorizationResult.ApprovalRequired(required) if lease.evidence.approval.nonEmpty =>
        AuthorizationEvidence(
          required.policyId,
          required.policyVersion,
          snapshot.delegations.map(_.id),
          required.requiredCapability,
          lease.evidence.approval
        ) == lease.evidence
      case _ => false
    Either.cond(sameMapping && sameEvidence, (), DurableExecutionRevalidationDenial.AuthorityChanged)

/** Compatibility adapter for the executor's narrow lifecycle port. It intentionally preserves no detail from a mutable
  * authority failure: the executor only needs to know that current authority no longer permits credential access.
  */
final class DurableLeaseAuthorityValidator(
    revalidator: DurableExecutionRevalidator[IO]
) extends LeaseAuthorityValidator[IO]:
  def validate(lease: RedeemedExecutionLease, now: Instant): IO[Either[LeaseAuthorityDenial, Unit]] =
    revalidator.revalidate(lease, now).map(_.left.map(_ => LeaseAuthorityDenial.CurrentStateChanged))
