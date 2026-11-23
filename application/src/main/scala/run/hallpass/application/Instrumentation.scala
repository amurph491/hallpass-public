package run.hallpass.application

import cats.effect.IO
import cats.syntax.all.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*
import SafeAttribute.Label

/** Decorators that add tracing and metrics to existing ports without changing their behavior. Each one passes results
  * and failures through unchanged; telemetry is recorded beside the operation, never instead of it. */
object Instrumented:
  private def label(value: scala.reflect.Enum): Label = Label.of(value)

  /** Counts every recorded decision by outcome, source, and denial reason, and traces the journal write. */
  def journal(underlying: AuthorizationJournal[IO], telemetry: Telemetry): AuthorizationJournal[IO] =
    new AuthorizationJournal[IO]:
      def record(tenant: TenantId, event: AuthorizationEvent): IO[Unit] =
        val (outcome, reason) = event.result match
          case AuthorizationResult.Authorized(_)       => Label.of("allowed") -> None
          case AuthorizationResult.Denied(denial)      => Label.of("denied") -> Some(label(denial))
          case AuthorizationResult.ApprovalRequired(_) => Label.of("approval_required") -> None
        val attributes = Vector(SafeAttribute.outcome(outcome), SafeAttribute.source(label(event.authorizationSource))) ++
          reason.map(SafeAttribute.reason)
        telemetry.span(TraceSpan.DecisionRecord, SafeAttribute.tenant(tenant), SafeAttribute.requestId(event.requestId))(
          underlying.record(tenant, event)
        ) *> telemetry.increment(CounterMetric.AuthorizationDecisions, attributes*)
      def recent(tenant: TenantId, limit: Int): IO[Vector[AuthorizationRecord]] = underlying.recent(tenant, limit)

  /** Traces each audit write and counts events by their safe outcome, including unknown provider outcomes. */
  def executionAudit(underlying: ExecutionAudit[IO], telemetry: Telemetry): ExecutionAudit[IO] =
    new ExecutionAudit[IO]:
      def record(event: ExecutionAuditEvent): IO[Unit] =
        val (kind, outcome) = event match
          case _: ExecutionAuditEvent.LeaseIssued               => Label.of("lease_issued") -> Label.of("issued")
          case denied: ExecutionAuditEvent.RedemptionDenied     => Label.of("redemption_denied") -> label(denied.outcome)
          case _: ExecutionAuditEvent.LeaseRedeemed             => Label.of("lease_redeemed") -> Label.of("redeemed")
          case _: ExecutionAuditEvent.ExecutionCompleted        => Label.of("execution_completed") -> Label.of("completed")
          case failed: ExecutionAuditEvent.ExecutionFailed      => Label.of("execution_failed") -> label(failed.outcome)
        val tenant = event match
          case ExecutionAuditEvent.RedemptionDenied(_, _, _, _, context) => context.map(_.tenant)
          case ExecutionAuditEvent.LeaseIssued(context, _)              => Some(context.tenant)
          case ExecutionAuditEvent.LeaseRedeemed(context, _)            => Some(context.tenant)
          case ExecutionAuditEvent.ExecutionCompleted(context, _)       => Some(context.tenant)
          case ExecutionAuditEvent.ExecutionFailed(context, _, _)       => Some(context.tenant)
        val attributes = Vector(SafeAttribute.kind(kind), SafeAttribute.outcome(outcome))
        telemetry.span(TraceSpan.AuditWrite, (attributes ++ tenant.map(SafeAttribute.tenant))*)(underlying.record(event)) *>
          telemetry.increment(CounterMetric.ExecutionEvents, attributes*)

  /** Records how long each caller waited for the tenant gate, as a finished span and a histogram, and counts gate
    * failures by kind, including an ownership check that fails immediately before dispatch. */
  def gate(underlying: TenantExecutionMutationGate[IO], telemetry: Telemetry): TenantExecutionMutationGate[IO] =
    new TenantExecutionMutationGate[IO]:
      def withinExecution[A](tenant: TenantId)(operation: ExecutionGatePermit[IO] => IO[A]): IO[A] =
        measured(tenant, Label.of("execution")): acquired =>
          underlying.withinExecution(tenant): permit =>
            acquired *> operation(new ExecutionGatePermit[IO]:
              def confirmHeld: IO[Unit] = permit.confirmHeld.onError:
                case TenantGateException(failure) => failed(tenant, Label.of("execution"), failure)
            )

      def withinMutation[A](tenant: TenantId)(operation: IO[A]): IO[A] =
        measured(tenant, Label.of("mutation"))(acquired => underlying.withinMutation(tenant)(acquired *> operation))

      /** `acquired` marks the moment the gate was granted; a failure before it is an acquisition failure. */
      private def measured[A](tenant: TenantId, mode: Label)(run: IO[Unit] => IO[A]): IO[A] =
        (IO.realTime, IO.monotonic, IO.ref(false)).tupled.flatMap: (startedAt, started, granted) =>
          val finish = (failedWait: Boolean) =>
            IO.monotonic.flatMap: now =>
              telemetry.finished(TraceSpan.GateWait, startedAt, failedWait, SafeAttribute.tenant(tenant), SafeAttribute.mode(mode)) *>
                telemetry.record(HistogramMetric.GateWaitDuration, (now - started).toNanos / 1e9, SafeAttribute.mode(mode))
          val acquired = granted.set(true) *> finish(false)
          run(acquired).onError:
            case TenantGateException(failure) =>
              granted.get.flatMap(alreadyGranted => IO.unlessA(alreadyGranted)(finish(true) *> failed(tenant, mode, failure)))

      private def failed(tenant: TenantId, mode: Label, failure: TenantGateFailure): IO[Unit] =
        telemetry.increment(CounterMetric.GateFailures, SafeAttribute.mode(mode), SafeAttribute.kind(label(failure)))

  /** Counts provider secret store failures by kind (a KMS outage shows up here as `unavailable`). */
  def secretStore(underlying: SecretStore[IO], telemetry: Telemetry): SecretStore[IO] =
    new SecretStore[IO]:
      def put(binding: SecretBinding, secret: ProviderSecret): IO[SecretReference] =
        underlying.put(binding, secret).onError(_ =>
          telemetry.increment(CounterMetric.SecretStoreErrors, SafeAttribute.kind(Label.of("write_failed")))
        )
      def get(binding: SecretBinding, reference: SecretReference): IO[Either[SecretStoreError, ProviderSecret]] =
        underlying.get(binding, reference).flatTap:
          case Left(error) => telemetry.increment(CounterMetric.SecretStoreErrors, SafeAttribute.kind(label(error)))
          case Right(_)    => IO.unit
      def delete(binding: SecretBinding, reference: SecretReference): IO[Unit] = underlying.delete(binding, reference)

  /** Traces server-side credential acquisition (connection lookup and secret decryption). */
  def connectionResolver(underlying: ConnectionResolver[IO], telemetry: Telemetry): ConnectionResolver[IO] =
    new ConnectionResolver[IO]:
      def activeConnectionFor(lease: RedeemedExecutionLease): IO[Either[ConnectionError, ResolvedConnection]] =
        telemetry.span(TraceSpan.CredentialAcquisition, SafeAttribute.tenant(lease.tenant))(
          underlying.activeConnectionFor(lease)
        )
