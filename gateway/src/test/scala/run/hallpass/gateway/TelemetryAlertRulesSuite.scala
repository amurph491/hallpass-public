package run.hallpass.gateway

import java.nio.file.{Files, Path}
import munit.FunSuite
import run.hallpass.application.{CounterMetric, HistogramMetric}

/** Keeps the alert rules in step with the metrics the server defines, so a renamed metric cannot silently disable an
  * alert. */
final class TelemetryAlertRulesSuite extends FunSuite:
  private val rules: String =
    // sbt runs forked tests from the project directory; the rules live at the repository root.
    Vector(Path.of("deploy/observability/alerts.yaml"), Path.of("../deploy/observability/alerts.yaml"))
      .find(Files.isRegularFile(_))
      .map(Files.readString)
      .getOrElse(fail("deploy/observability/alerts.yaml is missing"))

  private def prometheus(name: String): String = name.replace('.', '_')
  private val known: Set[String] =
    CounterMetric.values.map(metric => prometheus(metric.name) + "_total").toSet ++
      HistogramMetric.values.flatMap: metric =>
        Vector("_bucket", "_sum", "_count").map(suffix => prometheus(metric.name) + "_seconds" + suffix)

  test("every metric an alert references is defined by the server") {
    // A metric reference is a name followed by a selector or range; label names are followed by `=` or `)`.
    val referenced = "(hallpass_[a-z0-9_]+)[{\\[]".r.findAllMatchIn(rules).map(_.group(1)).toSet
    assert(referenced.nonEmpty)
    assertEquals(referenced -- known, Set.empty[String], "alerts reference metrics the server does not define")
  }

  test("the required alerts exist") {
    Vector(
      "HallpassDeniedCallsSpike", "HallpassAuthorityLoadFailures", "HallpassGateFailures", "HallpassGateWaitHigh",
      "HallpassSecretStoreErrors", "HallpassExecutionOutcomeUnknown"
    ).foreach(alert => assert(rules.contains(s"alert: $alert"), s"missing alert $alert"))
  }

  test("alert label values use the telemetry vocabulary") {
    // Values the decorators emit for these outcomes; see Instrumented and ExecutionFailure.
    assert(rules.contains("""hallpass_outcome="completion_unknown""""))
    assert(rules.contains("""hallpass_outcome="connection_unavailable""""))
    assertEquals(run.hallpass.application.SafeAttribute.Label.of(run.hallpass.application.ExecutionFailure.CompletionUnknown).value, "completion_unknown")
    assertEquals(run.hallpass.application.SafeAttribute.Label.of(run.hallpass.application.ExecutionFailure.ConnectionUnavailable).value, "connection_unavailable")
  }
