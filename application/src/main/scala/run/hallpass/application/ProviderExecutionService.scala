package run.hallpass.application

import java.time.Instant
import cats.effect.IO
import cats.syntax.all.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

final case class LeaseRedemptionException(denial: LeaseRedemptionDenial) extends RuntimeException(denial.toString)

/** The one trusted execution lifecycle for every provider operation.
  *
  * In order, and failing closed at each step:
  *   1. redeem the lease once, for the operation's audience;
  *   2. require that the lease binds this exact invocation (operation, capability, action, resolved resource, and
  *      canonical input), so a lease issued for one call cannot execute another;
  *   3. hold the tenant gate shared, re-check expiry, and revalidate current authority;
  *   4. resolve the provider credential through the operation's strategy;
  *   5. revalidate current authority at fresh time after credential acquisition, then confirm gate ownership;
  *   6. dispatch and record the outcome in one uncancelable region.
  *
  * No credential is resolved before step 4, and nothing reaches the provider before step 5. Every outcome after
  * redemption is recorded in the execution audit.
  */
final class ProviderExecutionService(
    leases: ExecutionLeaseStore[IO],
    clock: Clock[IO],
    audit: ExecutionAudit[IO],
    authority: LeaseAuthorityValidator[IO],
    gate: TenantExecutionMutationGate[IO],
    telemetry: Telemetry = Telemetry.noop
):
  def execute[In, K, C](
      leaseId: ExecutionLeaseId,
      operation: RegisteredOperation[In, K, C],
      input: In,
      target: SelectedResource[K]
  ): IO[ToolResult] =
    val descriptor = operation.descriptor
    val audience = descriptor.audience
    clock.now.flatMap: now =>
      leases
        .redeem(leaseId, audience, now)
        .flatMap:
          case LeaseRedemption.Redeemed(lease) =>
            val context = lease.auditContext
            if !bindsInvocation(lease, descriptor, input, target) then
              // A lease for another invocation: refuse before any current-state read or credential access.
              clock.now.flatMap: occurredAt =>
                recordThenRaise(
                  ExecutionAuditEvent.ExecutionFailed(context, ExecutionFailure.AuthorityRevoked, occurredAt),
                  ProviderExecutionException(ProviderError.BindingMismatch)
                )
            else
              recordAt(now => ExecutionAuditEvent.LeaseRedeemed(context, now)) *>
                gate
                  .withinExecution(lease.tenant): permit =>
                    clock.now.flatMap: dispatchAt =>
                      if !dispatchAt.isBefore(lease.expiresAt) then rejectExpired(leaseId, audience, context, dispatchAt)
                      else
                        authority.validate(lease, dispatchAt).flatMap:
                          case Left(_) =>
                            clock.now.flatMap: occurredAt =>
                              recordThenRaise(
                                ExecutionAuditEvent.ExecutionFailed(context, ExecutionFailure.AuthorityRevoked, occurredAt),
                                ProviderExecutionException(ProviderError.AuthorityRevoked)
                              )
                          case Right(_) =>
                            clock.now.flatMap: finalDispatchAt =>
                              if !finalDispatchAt.isBefore(lease.expiresAt) then
                                rejectExpired(leaseId, audience, context, finalDispatchAt)
                              else
                                def settle(outcome: Either[Throwable, ToolResult], dispatched: Boolean = false): IO[ToolResult] = outcome match
                                  case Right(result) =>
                                    recordAt(occurredAt => ExecutionAuditEvent.ExecutionCompleted(context, occurredAt))
                                      .as(result)
                                      .handleErrorWith: _ =>
                                        IO.raiseError(ProviderExecutionException(ProviderError.OutcomeUnknown))
                                  case Left(error) =>
                                    val reported = error match
                                      case ProviderExecutionException(ProviderError.Timeout | ProviderError.InvalidResponse)
                                          if dispatched && operation.descriptor.action != Action.Read =>
                                        ProviderExecutionException(ProviderError.OutcomeUnknown)
                                      case other => other
                                    clock.now.flatMap: occurredAt =>
                                      recordThenRaise(
                                        ExecutionAuditEvent.ExecutionFailed(context, failureCategory(reported), occurredAt),
                                        reported
                                      )
                                val acquireCredential = (permit.confirmHeld *> operation.credentials.credentialFor(lease, target))
                                  .onCancel(
                                    recordAt(at => ExecutionAuditEvent.ExecutionFailed(context, ExecutionFailure.ConnectionUnavailable, at))
                                      .attempt.void
                                  )
                                // Acquisition may finish an uncancelable refresh after cancellation was requested. Its
                                // failure outcome is then recorded before cancellation is observed; only the success
                                // path continues cancelable (polled) toward dispatch.
                                IO.uncancelable: poll =>
                                  poll(acquireCredential).attempt.flatMap:
                                    case Left(error) => settle(Left(error))
                                    case Right(Left(_)) =>
                                      settle(Left(ProviderExecutionException(ProviderError.ConnectionUnavailable)))
                                    case Right(Right(credential)) => poll:
                                      clock.now.flatMap: afterCredentials =>
                                        if !afterCredentials.isBefore(lease.expiresAt) then
                                          rejectExpired(leaseId, audience, context, afterCredentials)
                                        else
                                          // Token exchange/KMS work can outlast a delegation or enrollment credential.
                                          // The shared gate prevents mutations, but passage of time still needs validation.
                                          authority.validate(lease, afterCredentials).attempt.flatMap:
                                            case Left(error) => settle(Left(error))
                                            case Right(Left(_)) =>
                                              settle(Left(ProviderExecutionException(ProviderError.AuthorityRevoked)))
                                            case Right(Right(_)) =>
                                              clock.now.flatMap: beforeDispatch =>
                                                if !beforeDispatch.isBefore(lease.expiresAt) then
                                                  rejectExpired(leaseId, audience, context, beforeDispatch)
                                                else
                                                  // From here the provider may receive the request; cancellation waits for
                                                  // the bounded provider call and its audit record.
                                                  IO.uncancelable: _ =>
                                                    (permit.confirmHeld *>
                                                      telemetry.span(TraceSpan.ProviderDispatch, SafeAttribute.tenant(lease.tenant))(
                                                        operation.client.dispatch(target, input, credential)
                                                      )).attempt.flatMap(outcome => settle(outcome, dispatched = true))
                  .handleErrorWith:
                    // Only acquisition failures reach here unrecorded; failures inside the permit are already audited.
                    case error @ TenantGateException(
                          TenantGateFailure.AcquisitionTimedOut | TenantGateFailure.CoordinatorUnavailable
                        ) =>
                      clock.now.flatMap: occurredAt =>
                        recordThenRaise(
                          ExecutionAuditEvent.ExecutionFailed(context, ExecutionFailure.CoordinationUnavailable, occurredAt),
                          error
                        )
                    case error => IO.raiseError(error)
          case LeaseRedemption.Unknown =>
            denyRedemption(leaseId, audience, LeaseRedemptionDenial.UnknownLease, now)
          case LeaseRedemption.Expired =>
            denyRedemption(leaseId, audience, LeaseRedemptionDenial.Expired, now)
          case LeaseRedemption.AlreadyRedeemed =>
            denyRedemption(leaseId, audience, LeaseRedemptionDenial.AlreadyRedeemed, now)
          case LeaseRedemption.WrongAudience =>
            denyRedemption(leaseId, audience, LeaseRedemptionDenial.WrongAudience, now)

  /** The lease's claims and its recorded binding must describe exactly this operation, target, and input. The binding is
    * recomputed from the values about to be dispatched, never read from the request. */
  private def bindsInvocation[In, K](
      lease: RedeemedExecutionLease,
      descriptor: OperationDescriptor[In, K],
      input: In,
      target: SelectedResource[K]
  ): Boolean =
    lease.auditContext match
      case context: AuthenticatedExecutionAuditContext =>
        lease.principal == Principal.Agent(context.agentId) &&
        lease.tenant == target.tenant &&
        (target.kind eq descriptor.target) &&
        target.externalId.value == target.scope.target.externalId &&
        lease.resource == target.resource &&
        lease.capability == descriptor.capability &&
        lease.action == descriptor.action &&
        lease.audience == descriptor.audience &&
        context.binding == InvocationBinding.of(lease.tenant, context.agentId, descriptor, target, input)

  private def failureCategory(error: Throwable): ExecutionFailure = error match
    case ProviderExecutionException(ProviderError.ConnectionUnavailable) => ExecutionFailure.ConnectionUnavailable
    case ProviderExecutionException(ProviderError.AuthorityRevoked | ProviderError.BindingMismatch) => ExecutionFailure.AuthorityRevoked
    case ProviderExecutionException(ProviderError.AuthenticationFailed | ProviderError.Rejected) =>
      ExecutionFailure.ProviderRejected
    case ProviderExecutionException(ProviderError.OutcomeUnknown) => ExecutionFailure.CompletionUnknown
    case ProviderExecutionException(ProviderError.Timeout) => ExecutionFailure.ProviderUnavailable
    case TenantGateException(_)                            => ExecutionFailure.CoordinationUnavailable
    case _                                                 => ExecutionFailure.Unexpected

  private def record(event: ExecutionAuditEvent): IO[Unit] = audit.record(event)

  private def recordAt(event: Instant => ExecutionAuditEvent): IO[Unit] =
    clock.now.flatMap(now => record(event(now)))

  /** The original failure is what the caller sees; an audit failure while recording it must not mask it. */
  private def recordThenRaise(event: ExecutionAuditEvent, error: Throwable): IO[Nothing] =
    audit.record(event).attempt *> IO.raiseError(error)

  private def rejectExpired(
      leaseId: ExecutionLeaseId,
      audience: ExecutorAudience,
      context: ExecutionAuditContext,
      at: Instant
  ): IO[Nothing] =
    recordThenRaise(
      ExecutionAuditEvent.RedemptionDenied(leaseId, audience, LeaseRedemptionDenial.Expired, at, Some(context)),
      LeaseRedemptionException(LeaseRedemptionDenial.Expired)
    )

  private def denyRedemption(
      leaseId: ExecutionLeaseId,
      audience: ExecutorAudience,
      denial: LeaseRedemptionDenial,
      now: Instant
  ): IO[Nothing] =
    recordThenRaise(
      ExecutionAuditEvent.RedemptionDenied(leaseId, audience, denial, now),
      LeaseRedemptionException(denial)
    )
