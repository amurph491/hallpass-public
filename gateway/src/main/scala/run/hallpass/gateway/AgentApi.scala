package run.hallpass.gateway

import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.concurrent.{TimeoutException => JavaTimeoutException}
import com.sun.net.httpserver.Headers
import cats.effect.{IO, Resource as EffectResource}
import cats.syntax.all.*
import io.circe.Json
import io.circe.parser.parse
import scala.jdk.CollectionConverters.*
import org.http4s.server.Server
import run.hallpass.application.*
import run.hallpass.adapters.slack.SlackSearchMessagesOperation
import run.hallpass.kernel.authorization.{ApprovalId, AuthorizationResult}

/** Dependencies available to the deliberately narrow agent HTTP boundary.
  *
  * The authenticator owns construction of [[AuthenticatedAgentContext]] and
  * derives the tenant from the credential itself (directory routing, then
  * tenant-bound verification). The HTTP layer consequently has no tenant,
  * principal, credential broker, or provider-credential input that a bridge
  * can select.
  */
private[gateway] final case class AgentApiDependencies(
    credentials: AgentCredentialServices,
    tools: Option[AgentToolService],
    protection: AgentAuthenticationProtection = AgentAuthenticationProtection.none
)

/** Controls on agent authentication: a per-instance budget of failures per client address, a durable
  * cross-instance lockout of a selector after repeated wrong secrets, the audit of every rejection, and a per-instance
  * memory of bearers already rejected for a terminal reason, so that a stale client repeating one does not spend the
  * address budget or reach the database. */
private[gateway] final case class AgentAuthenticationProtection(
    limiter: Option[FailedAuthenticationLimiter],
    lockout: AgentAuthenticationLockout,
    trustedProxies: Int,
    recentRejections: Option[RecentAgentRejections] = None
)

private[gateway] object AgentAuthenticationProtection:
  val none: AgentAuthenticationProtection = AgentAuthenticationProtection(None, AgentAuthenticationLockout.disabled, 0)

/** Authenticated agent API. This is intentionally not a general tool proxy: it exposes exactly the operations in the
  * server's operation registry, each of which decodes its own arguments and is authorized independently on every call.
  */
private[gateway] final class AgentApi(
    dependencies: AgentApiDependencies,
    clock: Clock[IO] = Clock.system,
    telemetry: Telemetry = Telemetry.noop
):
  import AgentApi.*

  def handle(
      method: String,
      path: String,
      headers: Headers,
      requestUri: URI,
      body: Array[Byte],
      peer: Option[java.net.InetAddress] = None
  ): IO[DemoApiResponse] =
    val client = ClientAddress.resolve(peer, headers, dependencies.protection.trustedProxies)
    (method, path) match
      case ("GET", IdentityPath) => authenticated(headers, requestUri, client)(identity)
      case ("GET", ToolsPath) => authenticated(headers, requestUri, client)(discover)
      case ("POST", CallRoute(tool)) =>
        authenticated(headers, requestUri, client)(context => call(tool, headers, body, context))
      case _ => IO.pure(notFound)

  /** Order matters. A bearer this instance recently rejected for a terminal reason is answered with the usual 401
    * first: no budget, lockout lookup, verification, or audit write, only a telemetry count, so a stale client cannot
    * drain the budget it shares with its neighbours or grow the audit. Otherwise a client out of failure budget is
    * refused before any database or cryptographic work. A locked selector is refused before verification, with the
    * same 401 as any other rejection. Every other rejection is counted against the client and audited (reason, client
    * address, selector digest; never the credential). An outage of the lockout store fails closed as 503. The
    * recent-rejection table can only turn a request into a rejection, never into an authentication. */
  private def authenticated(
      headers: Headers,
      requestUri: URI,
      client: Option[java.net.InetAddress]
  )(
      next: AuthenticatedAgentContext => IO[DemoApiResponse]
  ): IO[DemoApiResponse] =
    val protection = dependencies.protection
    // Failures are counted by reason only; the presented credential never reaches telemetry.
    def failed(reason: SafeAttribute.Label): IO[Unit] =
      telemetry.increment(CounterMetric.AgentAuthenticationFailures, SafeAttribute.reason(reason))
    def rejected(selector: Option[AgentCredentialSelector], reason: AgentRejectionReason): IO[DemoApiResponse] =
      failed(SafeAttribute.Label.of(reason)) *>
        // An audit outage is counted but does not turn a rejection into a different response.
        protection.lockout.recordRejection(selector, reason, client).void.handleError(_ => ()).as(unauthorized)
    def throttled(retryAfter: scala.concurrent.duration.FiniteDuration): IO[DemoApiResponse] =
      telemetry.increment(CounterMetric.AgentAuthenticationThrottled, SafeAttribute.kind(SafeAttribute.Label.of("client_address"))).as(
        DemoApiResponse(
          429,
          Json.obj(
            "error" -> Json.fromString("too_many_requests"),
            "message" -> Json.fromString("Too many failed agent authentications. Try again later.")
          ),
          Map("Cache-Control" -> "no-store", "Retry-After" -> math.max(1L, retryAfter.toSeconds + 1).toString)
        )
      )

    def authenticate(
        parsed: Either[AgentHttpAuthentication.Rejection, PresentedAgentCredential]
    ): IO[Either[DemoApiResponse, AuthenticatedAgentContext]] =
      parsed match
        case Left(rejection) =>
          // Transport-level rejections consume their reservation too.
          failed(SafeAttribute.Label.of(rejection)).as(Left(unauthorized))
        case Right(presented) =>
          protection.lockout.isLocked(presented.selector).attempt.flatMap:
            case Left(_) | Right(Left(_)) => failed(SafeAttribute.Label.of("unavailable")).as(Left(unavailable))
            case Right(Right(true)) =>
              telemetry.increment(CounterMetric.AgentAuthenticationThrottled, SafeAttribute.kind(SafeAttribute.Label.of("selector_locked"))) *>
                rejected(Some(presented.selector), AgentRejectionReason.Locked).map(Left(_))
            case Right(Right(false)) =>
              telemetry.span(TraceSpan.AgentAuthentication)(
                clock.now
                  .flatMap(now =>
                    dependencies.credentials.authenticator.authenticate(
                      presented,
                      UnverifiedExecutionClaims.empty,
                      now
                    )
                  )
                  .attempt
              ).flatMap:
                  case Right(Right(context)) => IO.pure(Right(context))
                  case Right(Left(AgentAuthenticationError.Rejected(reason))) =>
                    // Only terminal rejections are remembered (see RecentAgentRejections); a failure to remember
                    // must not change the response.
                    protection.recentRejections.traverse_(_.remember(presented, reason).void.handleError(_ => ())) *>
                      rejected(Some(presented.selector), AgentRejectionReason.of(reason)).map(Left(_))
                  case Right(Left(AgentAuthenticationError.Unavailable)) | Left(_) =>
                    failed(SafeAttribute.Label.of("unavailable")).as(Left(unavailable))

    def admitted(
        parsed: Either[AgentHttpAuthentication.Rejection, PresentedAgentCredential]
    ): IO[Either[DemoApiResponse, AuthenticatedAgentContext]] =
      val admission = (protection.limiter, client).tupled match
        case Some((limiter, address)) => limiter.admit(address).map(_.map(Some(_)))
        case None => EffectResource.pure[IO, Either[scala.concurrent.duration.FiniteDuration, Option[FailedAuthenticationLimiter.Attempt]]](Right(None))
      admission.use:
        case Left(retryAfter) => throttled(retryAfter).map(Left(_))
        case Right(attempt) =>
          val refund = attempt.traverse_(_.refund)
          authenticate(parsed).flatTap:
            case Right(_) => refund
            case Left(response) if response.status == 503 => refund
            case _ => IO.unit
          .onError(_ => refund)

    // A malformed or missing credential is never cached: it names no bearer, and it keeps consuming budget.
    val parsed = AgentHttpAuthentication.parse(headers, requestUri)
    val repeated: IO[Boolean] = (parsed.toOption, protection.recentRejections).tupled match
      // If the table cannot answer, fall through to full authentication, which fails closed.
      case Some((presented, recent)) => recent.isRecentlyRejected(presented).handleError(_ => false)
      case None => IO.pure(false)
    repeated
      .flatMap:
        case true => failed(SafeAttribute.Label.of("repeat_rejection")).as(Left(unauthorized))
        case false => admitted(parsed)
      .flatMap:
        case Left(response) => IO.pure(response)
        // Release the authentication reservation before discovery or provider execution.
        case Right(context) => next(context)

  private def identity(context: AuthenticatedAgentContext): IO[DemoApiResponse] =
    IO.pure(ok(Json.obj("agentId" -> Json.fromString(context.agentId.toString))))

  private def discover(context: AuthenticatedAgentContext): IO[DemoApiResponse] =
    dependencies.tools match
      case None => IO.pure(unavailable)
      case Some(service) =>
        // A failed discovery is a failed effect: no partial list is ever returned.
        clock.now.flatMap(now => service.visibleOperationTargets(context, now))
          .attempt
          .map:
            case Right(operations) => ok(Json.obj("tools" -> Json.arr(operations.map(toolDefinition)*)))
            case Left(_)           => unavailable

  /** The tool name was validated by [[CallRoute]]. Authentication has already succeeded; an unknown name is then a
    * plain 404 that loads no authority and writes no journal row. */
  private def call(
      tool: ExternalToolId,
      headers: Headers,
      body: Array[Byte],
      context: AuthenticatedAgentContext
  ): IO[DemoApiResponse] =
    dependencies.tools match
      case None => IO.pure(unavailable)
      case Some(service) =>
        service.operationFor(tool) match
          case None => IO.pure(notFound)
          case Some(descriptor) =>
            parseArguments(tool, headers, body) match
              case Left(response) => IO.pure(response)
              case Right((arguments, approval)) =>
                clock.now.flatMap(now => service.execute(context, descriptor.id, arguments, now, approval)).attempt.map:
                  case Right(AgentToolExecutionResult.Completed(snapshot, result)) =>
                    ok(
                      Json.obj(
                        "content" -> Json.fromString(result.content),
                        "correlationId" -> Json.fromString(snapshot.correlationId)
                      )
                    )
                  case Right(AgentToolExecutionResult.Denied(_, _)) => denied
                  case Right(AgentToolExecutionResult.ApprovalRequired(_, _, record)) => approvalRequiredFor(record)
                  // The operation's own decoder is authoritative for the argument contract; the error carries no authority.
                  case Right(AgentToolExecutionResult.InvalidArguments(_)) => invalidRequest
                  case Right(AgentToolExecutionResult.UnknownOperation) => notFound
                  // Authorized, but the tenant's provider connection is missing, revoked by the provider, or its secret
                  // cannot be read (for example a key-service outage). Nothing was sent to the provider. The agent is told
                  // what an administrator must fix instead of seeing a generic outage.
                  case Left(ProviderExecutionException(ProviderError.ConnectionUnavailable)) =>
                    connectionUnavailable
                  // The provider may have applied a write. Say so, so neither the agent nor the bridge retries it.
                  case Left(ProviderExecutionException(ProviderError.OutcomeUnknown)) => outcomeUnknown
                  case Left(error) if isTimeout(error) => timedOut
                  case Left(_) => unavailable

  /** Size, media type, JSON syntax, and the envelope shape only. The operation's decoder checks the argument contract.
    *
    * The envelope is `{"arguments": <value>}` with an optional `"approval_id"`, and nothing else. */
  private def parseArguments(
      tool: ExternalToolId,
      headers: Headers,
      body: Array[Byte]
  ): Either[DemoApiResponse, (Json, Option[ApprovalId])] =
    if body.length > MaximumBodyBytes then Left(tooLarge)
    else if !isJsonContentType(headers) then Left(unsupportedMediaType)
    else
      parse(String(body, StandardCharsets.UTF_8)).leftMap(_ => invalidRequest).flatMap: json =>
        json.asObject.toRight(invalidRequest).flatMap: fields =>
          fields.toList match
            case List((ArgumentsField, arguments)) => Right(arguments -> None)
            case _ if fields.size == 2 && fields.contains(ArgumentsField) && fields.contains(ApprovalIdField) =>
              // A presented approval must be a well-formed ID; it is checked before any service call.
              fields(ApprovalIdField).flatMap(_.asString).toRight(invalidRequest)
                .flatMap(value => ApprovalId.parse(value).leftMap(_ => invalidRequest))
                .map(id => fields(ArgumentsField).getOrElse(Json.Null) -> Some(id))
            // Legacy alias, removed after one release: before the generic envelope, the Slack search body was the
            // arguments object itself (`{"query": ...}`). It applies to this one tool and only to an object that has
            // no `arguments` key; every other tool requires the envelope.
            case _ if tool.value == LegacyBareBodyTool.value && !fields.contains(ArgumentsField) => Right(json -> None)
            case _ => Left(invalidRequest)

  private def isJsonContentType(headers: Headers): Boolean =
    val values = headers.asScala.iterator
      .filter { case (name, _) => name.equalsIgnoreCase("Content-Type") }
      .flatMap { case (_, fields) => fields.asScala.iterator }
      .toVector
    values match
      case Vector(value) => value.split(";", 2).headOption.exists(_.trim.equalsIgnoreCase("application/json"))
      case _ => false

  private def isTimeout(error: Throwable): Boolean =
    @annotation.tailrec
    def loop(current: Throwable | Null): Boolean = current match
      case null => false
      case _: JavaTimeoutException | _: java.net.http.HttpTimeoutException => true
      case other => loop(other.getCause)
    loop(error)

private[gateway] object AgentApi:
  val IdentityPath = "/api/agent/identity"
  val ToolsPath = "/api/agent/tools"
  val MaximumBodyBytes = 16 * 1024
  private val ToolsPrefix = ToolsPath + "/"
  private val CallSuffix = "/call"
  private val ArgumentsField = "arguments"
  private val ApprovalIdField = "approval_id"
  private val LegacyBareBodyTool: ExternalToolId = SlackSearchMessagesOperation.tool

  /** The call path of a tool. The name is not validated here; [[CallRoute]] does that on every request. */
  def callPath(tool: String): String = s"$ToolsPrefix$tool$CallSuffix"

  /** Matches `/api/agent/tools/{name}/call` for exactly one path segment of `[A-Za-z0-9_]{1,64}` that parses as an
    * [[ExternalToolId]]. This is a literal prefix and suffix check on the raw path, not a pattern that could span
    * segments: a name containing `/`, `.`, or `%` (so neither `..` nor a percent-encoded separator) does not match and
    * the request is routed to 404. */
  private[gateway] object CallRoute:
    private val MaximumNameLength = 64
    def unapply(path: String): Option[ExternalToolId] =
      if path.startsWith(ToolsPrefix) && path.endsWith(CallSuffix) && path.length > ToolsPrefix.length + CallSuffix.length then
        val name = path.substring(ToolsPrefix.length, path.length - CallSuffix.length)
        Option
          .when(name.length <= MaximumNameLength && name.forall(c => (c < 128 && c.isLetterOrDigit) || c == '_'))(name)
          .flatMap(ExternalToolId.parse)
      else None

  private val noStore = Map("Cache-Control" -> "no-store")
  private def response(status: Int, body: Json): DemoApiResponse = DemoApiResponse(status, body, noStore)
  private def ok(body: Json): DemoApiResponse = response(200, body)
  private def error(status: Int, code: String, message: String): DemoApiResponse =
    response(status, Json.obj("error" -> Json.fromString(code), "message" -> Json.fromString(message)))

  val unauthorized: DemoApiResponse = error(401, "authentication_required", "Agent authentication is required.")
  val denied: DemoApiResponse = error(403, "authorization_denied", "Authorization denied this operation.")
  val approvalRequired: DemoApiResponse = error(409, "approval_required", "Approval is required.")
  /** `approval_id` and `expires_at` are present only when a pending approval was recorded for this exact invocation. */
  private[gateway] def approvalRequiredFor(record: Option[ApprovalRecord]): DemoApiResponse = record match
    case None => approvalRequired
    case Some(created) =>
      response(
        409,
        Json.obj(
          "error" -> Json.fromString("approval_required"),
          "message" -> Json.fromString("Approval is required."),
          "approval_id" -> Json.fromString(created.id.toString),
          "expires_at" -> Json.fromString(created.expiresAt.toString)
        )
      )
  val invalidRequest: DemoApiResponse = error(400, "invalid_request", "The request body or arguments are invalid.")
  val tooLarge: DemoApiResponse = error(413, "request_too_large", "The request body is too large.")
  val unsupportedMediaType: DemoApiResponse = error(415, "unsupported_media_type", "Content-Type must be application/json.")
  val unavailable: DemoApiResponse = error(503, "service_unavailable", "The agent tool service is currently unavailable.")
  val timedOut: DemoApiResponse = error(504, "gateway_timeout", "The agent tool operation timed out.")
  val connectionUnavailable: DemoApiResponse = error(
    424,
    "connection_unavailable",
    "The tool's provider connection is missing or unavailable. An administrator can connect or reconnect it in Hallpass."
  )
  val outcomeUnknown: DemoApiResponse = error(
    502,
    "outcome_unknown",
    "The provider may have completed this operation, but Hallpass could not confirm it. Check before trying again; do not retry automatically."
  )
  val notFound: DemoApiResponse = error(404, "not_found", "The requested agent endpoint does not exist.")

  private def toolDefinition(visible: VisibleOperation): Json =
    val descriptor = visible.descriptor
    Json.obj(
      "name" -> Json.fromString(descriptor.tool.value),
      "description" -> Json.fromString(descriptor.description),
      "inputSchema" -> withTargets(descriptor, visible.targets)
    )

  /** At most this many targets are listed in one tool's schema, so it stays within the bridge's schema bound. */
  private[gateway] val MaximumListedTargets = 50
  private val MaximumTargetTitle = 100

  /** Annotates the target argument with the selected resources this agent may currently address, as `oneOf` constants
    * titled with their display names. This is a hint for the model only: the server re-resolves and re-authorizes
    * every call, and a target outside this list (for example one past the listing bound) is still decided on its own.
    */
  private[gateway] def withTargets(descriptor: OperationDescriptor[?, ?], targets: Vector[DiscoveryTarget]): Json =
    descriptor.targetArgument match
      case Some(field) if targets.nonEmpty =>
        val choices = targets.sortBy(_.displayName).take(MaximumListedTargets).map: target =>
          val title = target.displayName.filterNot(Character.isISOControl).take(MaximumTargetTitle)
          Json.obj("const" -> Json.fromString(target.scope.target.externalId), "title" -> Json.fromString(title))
        descriptor.inputSchema.hcursor
          .downField("properties")
          .downField(field)
          .withFocus(_.mapObject(_.add("oneOf", Json.arr(choices*))))
          .top
          .getOrElse(descriptor.inputSchema)
      case _ => descriptor.inputSchema

/** A loopback-only listener which deliberately dispatches no browser/admin
  * routes. Keeping this server separate prevents an agent bearer credential
  * from ever falling through to the development management session.
  */
private[gateway] object AgentHttpServer:
  val DefaultPort = 8081

  /** The direct-process default is loopback. The wildcard binding exists only for a container whose port is itself
    * published on host loopback by Compose; accepting arbitrary interface names would make the local bearer boundary
    * too easy to expose accidentally. */
  sealed trait Binding:
    private[gateway] def host: String
  object Binding:
    case object Loopback extends Binding:
      private[gateway] val host = "127.0.0.1"
    case object ContainerInternal extends Binding:
      private[gateway] val host = "0.0.0.0"

    def fromEnvironment(environment: Map[String, String] = sys.env): Either[String, Binding] =
      environment.get("HALLPASS_AGENT_HTTP_BIND_HOST").map(_.trim).filter(_.nonEmpty) match
        case None | Some("127.0.0.1") => Right(Loopback)
        case Some("0.0.0.0")          => Right(ContainerInternal)
        case _ => Left("HALLPASS_AGENT_HTTP_BIND_HOST must be 127.0.0.1 or 0.0.0.0")

  def resource(
      api: AgentApi,
      port: Int = DefaultPort,
      binding: Binding = Binding.Loopback,
      settings: HttpListenerSettings = HttpListenerSettings.default,
      lifecycle: Option[ServerLifecycle] = None,
      telemetry: Telemetry = Telemetry.noop
  ): EffectResource[IO, Server] =
    EffectResource
      .eval(lifecycle.fold(ServerLifecycle.create(Vector.empty))(IO.pure))
      .flatMap: current =>
        HttpRuntime.serve(
          binding.host,
          port,
          settings.copy(maxBodyBytes = AgentApi.MaximumBodyBytes),
          current,
          request => api.handle(request.method, request.path, request.headers, request.uri, request.body, request.peer),
          HttpObservation(telemetry, SafeAttribute.Label.of("agent"), RouteTemplates.agent)
        )
