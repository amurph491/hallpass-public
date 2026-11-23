package run.hallpass.application

import java.time.Instant
import scala.concurrent.duration.*
import cats.effect.{IO, Ref}
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

final class InstrumentationSuite extends CatsEffectSuite:
  private val tenant = TenantId.random()

  /** Records what the decorators emit. */
  private final class Recording(
      val spans: Ref[IO, Vector[(String, Boolean, Set[SafeAttribute])]],
      val counters: Ref[IO, Vector[(CounterMetric, Set[SafeAttribute])]],
      val histograms: Ref[IO, Vector[(HistogramMetric, Double)]]
  ) extends Telemetry:
    def span[A](span: TraceSpan, attributes: SafeAttribute*)(body: IO[A]): IO[A] =
      body.attempt.flatTap(result => spans.update(_ :+ (span.name, result.isLeft, attributes.toSet))).rethrow
    def finished(span: TraceSpan, startedAt: FiniteDuration, failed: Boolean, attributes: SafeAttribute*): IO[Unit] =
      spans.update(_ :+ (span.name, failed, attributes.toSet))
    def increment(metric: CounterMetric, attributes: SafeAttribute*): IO[Unit] = counters.update(_ :+ (metric -> attributes.toSet))
    def record(metric: HistogramMetric, seconds: Double, attributes: SafeAttribute*): IO[Unit] = histograms.update(_ :+ (metric -> seconds))

  private def recording: IO[Recording] =
    (IO.ref(Vector.empty[(String, Boolean, Set[SafeAttribute])]), IO.ref(Vector.empty[(CounterMetric, Set[SafeAttribute])]), IO.ref(Vector.empty[(HistogramMetric, Double)]))
      .mapN(Recording(_, _, _))

  private def label(value: scala.reflect.Enum) = SafeAttribute.Label.of(value)

  test("enum labels use the case name in snake case, never constructor arguments") {
    assertEquals(label(DenialReason.InactiveDelegation(DelegationId.random())).value, "inactive_delegation")
    assertEquals(label(TenantGateFailure.AcquisitionTimedOut).value, "acquisition_timed_out")
    assertEquals(label(AuthorizationSource.HumanPreview).value, "human_preview")
  }

  test("the gate decorator records the wait, passes results through, and counts acquisition and ownership failures") {
    val refusing = new TenantExecutionMutationGate[IO]:
      def withinExecution[A](t: TenantId)(operation: ExecutionGatePermit[IO] => IO[A]): IO[A] =
        IO.raiseError(TenantGateException(TenantGateFailure.AcquisitionTimedOut))
      def withinMutation[A](t: TenantId)(operation: IO[A]): IO[A] = operation
    val losing = new TenantExecutionMutationGate[IO]:
      def withinExecution[A](t: TenantId)(operation: ExecutionGatePermit[IO] => IO[A]): IO[A] =
        operation(new ExecutionGatePermit[IO]:
          def confirmHeld = IO.raiseError(TenantGateException(TenantGateFailure.OwnershipLost))
        )
      def withinMutation[A](t: TenantId)(operation: IO[A]): IO[A] = operation
    for
      telemetry <- recording
      local <- SingleProcessTenantExecutionMutationGate.create
      passed <- Instrumented.gate(local, telemetry).withinExecution(tenant)(permit => permit.confirmHeld.as(42))
      mutated <- Instrumented.gate(local, telemetry).withinMutation(tenant)(IO.pure("changed"))
      timedOut <- Instrumented.gate(refusing, telemetry).withinExecution(tenant)(_ => IO.pure(1)).attempt
      lost <- Instrumented.gate(losing, telemetry).withinExecution(tenant)(permit => permit.confirmHeld.as(1)).attempt
      spans <- telemetry.spans.get
      counters <- telemetry.counters.get
      histograms <- telemetry.histograms.get
    yield
      assertEquals(passed, 42)
      assertEquals(mutated, "changed")
      assertEquals(timedOut.left.toOption, Some(TenantGateException(TenantGateFailure.AcquisitionTimedOut)))
      assertEquals(lost.left.toOption, Some(TenantGateException(TenantGateFailure.OwnershipLost)))
      val waits = spans.filter(_._1 == TraceSpan.GateWait.name)
      assertEquals(waits.map(_._2), Vector(false, false, true, false), "a timed-out wait is a failed span")
      assertEquals(histograms.count(_._1 == HistogramMetric.GateWaitDuration), 4)
      assertEquals(
        counters.map(_._2.find(_.key == "hallpass.kind").map(_.value)),
        Vector(Some("acquisition_timed_out"), Some("ownership_lost")),
        "each failure is counted once, by kind"
      )
  }

  test("the journal decorator counts decisions by outcome, source, and denial reason") {
    val event = (result: AuthorizationResult, source: AuthorizationSource) =>
      AuthorizationEvent(AuthorizationRequestId.random(), Principal.Agent(AgentId.random()), "slack_search_messages", None, None, result, "c", Instant.EPOCH, source)
    val underlying = new AuthorizationJournal[IO]:
      def record(t: TenantId, e: AuthorizationEvent) = IO.unit
      def recent(t: TenantId, limit: Int) = IO.pure(Vector.empty)
    for
      telemetry <- recording
      journal = Instrumented.journal(underlying, telemetry)
      _ <- journal.record(tenant, event(AuthorizationResult.Denied(DenialReason.UnmappedTool), AuthorizationSource.AgentCall))
      _ <- journal.record(tenant, event(AuthorizationResult.Denied(DenialReason.NoMatchingAuthority), AuthorizationSource.HumanPreview))
      counters <- telemetry.counters.get
    yield
      val values = counters.map(_._2.map(attribute => attribute.key -> attribute.value).toMap)
      assertEquals(values.map(_.get("hallpass.outcome")), Vector(Some("denied"), Some("denied")))
      assertEquals(values.map(_.get("hallpass.reason")), Vector(Some("unmapped_tool"), Some("no_matching_authority")))
      assertEquals(values.map(_.get("hallpass.source")), Vector(Some("agent_call"), Some("human_preview")))
  }

  test("a failing journal write still fails, and the span records the failure") {
    val broken = new AuthorizationJournal[IO]:
      def record(t: TenantId, e: AuthorizationEvent) = IO.raiseError(IllegalStateException("database down"))
      def recent(t: TenantId, limit: Int) = IO.pure(Vector.empty)
    val event = AuthorizationEvent(
      AuthorizationRequestId.random(), Principal.Agent(AgentId.random()), "t", None, None,
      AuthorizationResult.Denied(DenialReason.UnmappedTool), "c", Instant.EPOCH, AuthorizationSource.AgentCall
    )
    for
      telemetry <- recording
      result <- Instrumented.journal(broken, telemetry).record(tenant, event).attempt
      spans <- telemetry.spans.get
      counters <- telemetry.counters.get
    yield
      assert(result.isLeft, "instrumentation must not hide a persistence failure")
      assertEquals(spans.map(span => span._1 -> span._2), Vector(TraceSpan.DecisionRecord.name -> true))
      assertEquals(counters, Vector.empty, "an unrecorded decision is not counted as made")
  }
