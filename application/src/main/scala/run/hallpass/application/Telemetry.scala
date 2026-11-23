package run.hallpass.application

import scala.concurrent.duration.FiniteDuration
import cats.effect.IO
import run.hallpass.kernel.*

/** Operations Hallpass traces. Span names are fixed strings, so request data can never become a span name. */
enum TraceSpan(val name: String):
  /** One HTTP request on either listener; carries the method and route template only, never the URL. */
  case HttpRequest extends TraceSpan("hallpass.http.request")
  case AgentAuthentication extends TraceSpan("hallpass.identity.agent")
  case HumanAuthentication extends TraceSpan("hallpass.identity.human")

  /** Tool resolution and capability mapping: one repository query loads the trusted mapping, the policies, and the
    * delegations for the tool, so both are covered by this span. */
  case AuthorityLoad extends TraceSpan("hallpass.authority.load")
  case PolicyEvaluation extends TraceSpan("hallpass.policy.evaluate")
  case DecisionRecord extends TraceSpan("hallpass.decision.record")
  case LeaseIssue extends TraceSpan("hallpass.lease.issue")
  case GateWait extends TraceSpan("hallpass.gate.wait")
  case CredentialAcquisition extends TraceSpan("hallpass.credential.acquire")
  case ProviderDispatch extends TraceSpan("hallpass.provider.dispatch")
  case AuditWrite extends TraceSpan("hallpass.audit.write")
  case OidcLogin extends TraceSpan("hallpass.login.oidc")

/** Counters. Names follow OpenTelemetry conventions; a Prometheus exporter renders `hallpass.x.y` as `hallpass_x_y_total`. */
enum CounterMetric(val name: String, val description: String):
  case AuthorizationDecisions
      extends CounterMetric("hallpass.authorization.decisions", "Authorization decisions by outcome and source")
  case AuthorityLoadFailures
      extends CounterMetric("hallpass.authority.load_failures", "Authority snapshots that could not be loaded")
  case GateFailures extends CounterMetric("hallpass.gate.failures", "Tenant gate acquisitions or ownership checks that failed")
  case SecretStoreErrors extends CounterMetric("hallpass.secret_store.errors", "Provider secret store failures by kind")
  case ExecutionEvents extends CounterMetric("hallpass.execution.events", "Execution audit events by safe outcome")
  case AgentAuthenticationFailures
      extends CounterMetric("hallpass.agent.authentication.failures", "Rejected agent credential presentations by reason")
  case LoginOutcomes extends CounterMetric("hallpass.login.outcomes", "Browser login attempts by outcome")
  case AgentAuthenticationThrottled
      extends CounterMetric("hallpass.agent.authentication.throttled", "Agent requests refused by a throttle or lockout, by kind")
  case HttpRequests extends CounterMetric("hallpass.http.requests", "HTTP requests by listener, route, and status class")

/** Histograms, in seconds. */
enum HistogramMetric(val name: String, val description: String):
  case GateWaitDuration extends HistogramMetric("hallpass.gate.wait.duration", "Time spent waiting for the tenant gate")
  case HttpRequestDuration extends HistogramMetric("hallpass.http.request.duration", "HTTP request duration")

/** A span or metric attribute. The constructor is private: attributes are built only from typed identifiers and closed
  * outcome vocabularies, so a bearer credential, OAuth code, provider token, or other free text cannot become an
  * attribute by accident. Every value is either a UUID-shaped identifier, a validated tool name, or a label from a fixed
  * set chosen in code. */
final class SafeAttribute private (val key: String, val value: String):
  override def equals(other: Any): Boolean = other match
    case attribute: SafeAttribute => attribute.key == key && attribute.value == value
    case _                        => false
  override def hashCode: Int = (key, value).hashCode
  override def toString: String = s"$key=$value"

object SafeAttribute:
  def tenant(id: TenantId): SafeAttribute = SafeAttribute("hallpass.tenant.id", id.toString)
  def agent(id: AgentId): SafeAttribute = SafeAttribute("hallpass.agent.id", id.toString)
  def requestId(id: AuthorizationRequestId): SafeAttribute = SafeAttribute("hallpass.request.id", id.toString)
  def tool(tool: ExternalToolId): SafeAttribute = SafeAttribute("hallpass.tool", tool.value)
  def outcome(value: Label): SafeAttribute = SafeAttribute("hallpass.outcome", value.value)
  def reason(value: Label): SafeAttribute = SafeAttribute("hallpass.reason", value.value)
  def source(value: Label): SafeAttribute = SafeAttribute("hallpass.source", value.value)
  def kind(value: Label): SafeAttribute = SafeAttribute("hallpass.kind", value.value)
  def mode(value: Label): SafeAttribute = SafeAttribute("hallpass.gate.mode", value.value)
  def listener(value: Label): SafeAttribute = SafeAttribute("hallpass.listener", value.value)
  def route(value: Label): SafeAttribute = SafeAttribute("http.route", value.value)
  def method(value: Label): SafeAttribute = SafeAttribute("http.request.method", value.value)
  def statusClass(value: Label): SafeAttribute = SafeAttribute("http.response.status_class", value.value)

  /** A label from a fixed vocabulary: a compile-time string literal, or the name of a code-defined enum case. Runtime
    * strings cannot become labels, so request text cannot be laundered into one. */
  final class Label private (val value: String):
    override def equals(other: Any): Boolean = other match
      case label: Label => label.value == value
      case _            => false
    override def hashCode: Int = value.hashCode
    override def toString: String = value

  object Label:
    private val Pattern = "[a-z0-9_{}/.-]{1,80}".r

    /** A literal. `requireConst` rejects any argument that is not a compile-time constant. */
    inline def of(inline value: String): Label =
      scala.compiletime.requireConst(value)
      literal(value)

    /** An enum case name, as snake case (`MissingCredential` becomes `missing_credential`). */
    def of(value: scala.reflect.Enum): Label = literal(value.productPrefix.replaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase)

    private[application] def literal(value: String): Label =
      value match
        case Pattern() => Label(value)
        case _         => throw IllegalArgumentException("telemetry labels must be lower-case vocabulary")

/** Tracing and metrics for the application. Implementations must not block, must never fail the traced operation, and
  * must record errors by exception type only, never by message (messages can quote request data). */
trait Telemetry:
  def span[A](span: TraceSpan, attributes: SafeAttribute*)(body: IO[A]): IO[A]

  /** Records a span that already finished, from `startedAt` (wall clock, from `IO.realTime`) until now. Used where the
    * measured interval is not an effect of its own, such as waiting for the tenant gate. */
  def finished(span: TraceSpan, startedAt: FiniteDuration, failed: Boolean, attributes: SafeAttribute*): IO[Unit]
  def increment(metric: CounterMetric, attributes: SafeAttribute*): IO[Unit]
  def record(metric: HistogramMetric, seconds: Double, attributes: SafeAttribute*): IO[Unit]

object Telemetry:
  /** Development default when no exporter is configured. */
  val noop: Telemetry = new Telemetry:
    def span[A](span: TraceSpan, attributes: SafeAttribute*)(body: IO[A]): IO[A] = body
    def finished(span: TraceSpan, startedAt: FiniteDuration, failed: Boolean, attributes: SafeAttribute*): IO[Unit] = IO.unit
    def increment(metric: CounterMetric, attributes: SafeAttribute*): IO[Unit] = IO.unit
    def record(metric: HistogramMetric, seconds: Double, attributes: SafeAttribute*): IO[Unit] = IO.unit
