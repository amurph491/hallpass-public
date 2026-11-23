package run.hallpass.gateway

import java.net.URI
import scala.concurrent.duration.FiniteDuration
import scala.util.Try
import cats.effect.{IO, Resource as EffectResource}
import cats.syntax.all.*
import org.typelevel.otel4s.Attribute
import org.typelevel.otel4s.metrics.{Counter, Histogram, Meter}
import org.typelevel.otel4s.oteljava.OtelJava
import org.typelevel.otel4s.trace.{SpanFinalizer, StatusCode, Tracer}
import run.hallpass.application.*

/** [[Telemetry]] over OpenTelemetry (otel4s on the OpenTelemetry Java SDK).
  *
  * Attributes come only from [[SafeAttribute]], so nothing here can add request data. Failures are recorded as an error
  * status and the exception's class name. The exception message and stack trace are deliberately not recorded:
  * messages can quote request or database values. Telemetry never fails the traced operation. */
private[gateway] final class OtelTelemetry private (
    tracer: Tracer[IO],
    counters: Map[CounterMetric, Counter[IO, Long]],
    histograms: Map[HistogramMetric, Histogram[IO, Double]]
) extends Telemetry:
  import OtelTelemetry.*

  def span[A](span: TraceSpan, attributes: SafeAttribute*)(body: IO[A]): IO[A] =
    tracer
      .spanBuilder(span.name)
      .addAttributes(attributes.map(otel))
      .withFinalizationStrategy(errorTypeOnly)
      .build
      .surround(body)

  def finished(span: TraceSpan, startedAt: FiniteDuration, failed: Boolean, attributes: SafeAttribute*): IO[Unit] =
    tracer
      .spanBuilder(span.name)
      .addAttributes(attributes.map(otel))
      .withStartTimestamp(startedAt)
      .build
      .use(active => IO.whenA(failed)(active.setStatus(StatusCode.Error)))
      .handleError(_ => ())

  def increment(metric: CounterMetric, attributes: SafeAttribute*): IO[Unit] =
    counters(metric).inc(attributes.map(otel)*).handleError(_ => ())

  def record(metric: HistogramMetric, seconds: Double, attributes: SafeAttribute*): IO[Unit] =
    histograms(metric).record(seconds, attributes.map(otel)*).handleError(_ => ())

private[gateway] object OtelTelemetry:
  private val InstrumentationScope = "run.hallpass"

  private def otel(attribute: SafeAttribute): Attribute[String] = Attribute(attribute.key, attribute.value)

  /** On failure: error status and `error.type` (the exception class). Never the message or stack trace. */
  private val errorTypeOnly: SpanFinalizer.Strategy =
    case cats.effect.Resource.ExitCase.Errored(error) =>
      SpanFinalizer.setStatus(StatusCode.Error) |+|
        SpanFinalizer.addAttribute(Attribute("error.type", error.getClass.getName))
    case cats.effect.Resource.ExitCase.Canceled =>
      SpanFinalizer.setStatus(StatusCode.Error) |+| SpanFinalizer.addAttribute(Attribute("error.type", "canceled"))

  /** Builds the telemetry from providers, creating every declared instrument up front. */
  def fromOtel(otel: OtelJava[IO]): IO[OtelTelemetry] =
    for
      tracer <- otel.tracerProvider.get(InstrumentationScope)
      meter <- otel.meterProvider.get(InstrumentationScope)
      telemetry <- instruments(tracer, meter)
    yield telemetry

  private[gateway] def instruments(tracer: Tracer[IO], meter: Meter[IO]): IO[OtelTelemetry] =
    for
      counters <- CounterMetric.values.toVector.traverse: metric =>
        meter.counter[Long](metric.name).withDescription(metric.description).create.map(metric -> _)
      histograms <- HistogramMetric.values.toVector.traverse: metric =>
        meter.histogram[Double](metric.name).withUnit("s").withDescription(metric.description).create.map(metric -> _)
    yield OtelTelemetry(tracer, counters.toMap, histograms.toMap)

/** Selects telemetry at startup. OpenTelemetry is on when `OTEL_EXPORTER_OTLP_ENDPOINT` is set, and then configured by
  * the standard `OTEL_*` variables (SDK autoconfiguration). Otherwise telemetry is a no-op, which is acceptable only
  * in development: production requires an https OTLP endpoint (see [[ProductionGuard]]). */
private[gateway] object TelemetryRuntime:
  val EndpointKey = "OTEL_EXPORTER_OTLP_ENDPOINT"

  enum Selection:
    case Disabled
    case Otlp(endpoint: URI)

  def fromEnvironment(environment: Map[String, String]): Either[String, Selection] =
    val production = environment.get("HALLPASS_ENV").exists(_.trim.equalsIgnoreCase("production"))
    environment.get(EndpointKey).map(_.trim).filter(_.nonEmpty) match
      case None => Right(Selection.Disabled)
      case Some(raw) =>
        Try(URI.create(raw)).toOption
          .filter(uri => uri.isAbsolute && uri.getHost != null && (uri.getScheme == "https" || (!production && uri.getScheme == "http")))
          .map(Selection.Otlp(_))
          .toRight(
            if production then s"$EndpointKey must be an https URL in production" else s"$EndpointKey must be an http(s) URL"
          )

  /** The SDK reads its settings from the process environment. Defaults: service name `hallpass-api` and no log export
    * (Hallpass emits no application logs through OpenTelemetry). Explicit `OTEL_*` settings override both. */
  def resource(selection: Selection): EffectResource[IO, Telemetry] =
    selection match
      case Selection.Disabled => EffectResource.pure(Telemetry.noop)
      case Selection.Otlp(_) =>
        OtelJava
          .autoConfigured[IO](
            _.addPropertiesSupplier(() =>
              java.util.Map.of("otel.service.name", "hallpass-api", "otel.logs.exporter", "none")
            )
          )
          .evalMap(OtelTelemetry.fromOtel)
