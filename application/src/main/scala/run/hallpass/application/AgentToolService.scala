package run.hallpass.application

import java.time.Instant
import java.util.UUID
import cats.effect.IO
import cats.syntax.all.*
import io.circe.Json
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Immutable outcome of one server-created agent invocation. The request ID and correlation ID are allocated once
  * before mapping lookup and are retained by the decision journal and any issued lease.
  */
final case class AgentAuthorizationSnapshot(
    requestId: AuthorizationRequestId,
    correlationId: String,
    tool: ExternalToolId,
    result: AuthorizationResult,
    occurredAt: Instant
)

enum AgentToolExecutionResult:
  case Completed(snapshot: AgentAuthorizationSnapshot, result: ToolResult)
  case Denied(snapshot: AgentAuthorizationSnapshot, reason: DenialReason)
  /** `approval` is the pending approval created for this exact invocation, when approvals are available. */
  case ApprovalRequired(snapshot: AgentAuthorizationSnapshot, request: ApprovalRequest, approval: Option[ApprovalRecord] = None)
  /** The arguments do not satisfy the operation's contract. Nothing was resolved, authorized, or journaled. */
  case InvalidArguments(error: ArgumentError)
  /** The server has no such operation. Nothing was resolved or authorized. */
  case UnknownOperation

/** An operation visible to an agent, with the selected targets it may currently address (empty for root targets).
  * Visibility is a user-experience aid and never grants authority. */
final case class VisibleOperation(descriptor: OperationDescriptor[?, ?], targets: Vector[DiscoveryTarget])

final case class AuthoritySnapshotUnavailable(error: AuthorityLoadError)
    extends RuntimeException(error.toString)

/** Application orchestration for authenticated agent operation calls.
  *
  * One generic pipeline serves every registered operation:
  *   1. decode the untrusted arguments into the operation's typed input;
  *   2. resolve the input's resource locator to a trusted, currently selected resource;
  *   3. load authority for the operation's catalog tool at that resource's scope, require the trusted mapping to agree
  *      with the operation's declared capability and action, and evaluate the pure kernel;
  *   4. issue a lease bound to this exact invocation;
  *   5. hand the same typed input and resolved resource to the trusted executor.
  *
  * The value decoded in step 1 is the value dispatched in step 5: nothing re-parses the arguments after authorization.
  * This service has no credential-resolution capability.
  */
final class AgentToolService(
    registry: OperationRegistry,
    resolver: ResourceResolver,
    authority: AuthorityRepository[IO],
    journal: AuthorizationJournal[IO],
    broker: CredentialBroker[IO],
    executor: ProviderExecutionService,
    telemetry: Telemetry = Telemetry.noop,
    approvals: ApprovalStore = ApprovalStore.unavailable,
    approvalTtl: java.time.Duration = java.time.Duration.ofMinutes(15)
):
  def execute(
      authenticated: AuthenticatedAgentContext,
      operation: OperationId,
      arguments: Json,
      at: Instant,
      approval: Option[ApprovalId] = None
  ): IO[AgentToolExecutionResult] =
    registry.find(operation) match
      case None => IO.pure(AgentToolExecutionResult.UnknownOperation)
      case Some(registered) =>
        registered match
          case typed: RegisteredOperation[in, k, c] => invoke(typed, authenticated, arguments, at, approval)

  /** The operation an agent-visible tool name selects, if any. */
  def operationFor(tool: ExternalToolId): Option[OperationDescriptor[?, ?]] = registry.findByTool(tool).map(_.descriptor)

  /** Operations this agent may currently see, by fresh discovery of each, ordered by tool name. A discovery failure is
    * a failed effect: the caller must not guess visibility. Visibility never grants authority. */
  def visibleOperations(authenticated: AuthenticatedAgentContext, at: Instant): IO[Vector[OperationDescriptor[?, ?]]] =
    visibleOperationTargets(authenticated, at).map(_.map(_.descriptor))

  /** [[visibleOperations]] with, for each operation that targets a selected child kind, the targets at which it is
    * currently visible to this agent. Root-targeted operations carry no targets. */
  def visibleOperationTargets(authenticated: AuthenticatedAgentContext, at: Instant): IO[Vector[VisibleOperation]] =
    registry.all.map(_.descriptor).sortBy(_.tool.value).traverseFilter: descriptor =>
      resolver.discoveryTargets(authenticated.tenant, descriptor.target).flatMap: targets =>
        // Evaluate every candidate, so an infrastructure failure never becomes a successful partial list.
        targets.traverse(target => visibleAt(authenticated, descriptor, target.scope, at).map(target -> _))
          .map: evaluated =>
            val visible = evaluated.collect { case (target, true) => target }
            Option.when(visible.nonEmpty)(
              VisibleOperation(descriptor, if descriptor.target.isRoot then Vector.empty else visible)
            )

  private def visibleAt(
      authenticated: AuthenticatedAgentContext,
      descriptor: OperationDescriptor[?, ?],
      scope: ResourceScope,
      at: Instant
  ): IO[Boolean] =
    loadAuthority(authenticated, descriptor.tool, Some(scope)).flatMap:
      case Left(AuthorityLoadError.UnmappedTool) => IO.pure(false)
      case Left(error) => unavailable(error)
      case Right(snapshot) if snapshot.scope != scope => unavailable(AuthorityLoadError.InvalidStoredAuthority)
      case Right(snapshot) =>
        IO.pure(
          agrees(descriptor, snapshot) &&
            (AuthorizationEngine.authorize(
              snapshot.policies,
              requestFor(authenticated, AuthorizationRequestId.random(), snapshot, scope, AuthorizationContext.factsNotEvaluated),
              snapshot.delegations,
              at
            ) match
              // An approval-required operation must be offered, or the agent could never request the approval. Every
              // call is still authorized independently; visibility grants nothing.
              case _: AuthorizationResult.Authorized | _: AuthorizationResult.ApprovalRequired => true
              case _: AuthorizationResult.Denied                                               => false)
        )

  /** Freshly evaluates an operation at its tool's mapped catalog resource, without arguments, a lease, or a journal
    * row. Visibility is a user-experience aid; every call is authorized independently. */
  def discover(
      authenticated: AuthenticatedAgentContext,
      operation: OperationId,
      at: Instant
  ): IO[Option[AgentAuthorizationSnapshot]] =
    registry.find(operation) match
      case None => IO.pure(None)
      case Some(registered) =>
        val descriptor = registered.descriptor
        IO.delay((AuthorizationRequestId.random(), UUID.randomUUID().toString)).flatMap: (requestId, correlationId) =>
          loadAuthority(authenticated, descriptor.tool, None).flatMap:
            case Left(AuthorityLoadError.UnmappedTool) =>
              IO.pure(Some(snapshotOf(requestId, correlationId, descriptor.tool, AuthorizationResult.Denied(DenialReason.UnmappedTool), at)))
            case Left(error) => unavailable(error)
            case Right(snapshot) =>
              val result =
                if !agrees(descriptor, snapshot) then AuthorizationResult.Denied(DenialReason.UnmappedTool)
                else
                  AuthorizationEngine.authorize(
                    snapshot.policies,
                    requestFor(authenticated, requestId, snapshot, snapshot.scope, AuthorizationContext.factsNotEvaluated),
                    snapshot.delegations,
                    at
                  )
              IO.pure(Some(snapshotOf(requestId, correlationId, descriptor.tool, result, at)))

  private def invoke[In, K, C](
      operation: RegisteredOperation[In, K, C],
      authenticated: AuthenticatedAgentContext,
      arguments: Json,
      at: Instant,
      presented: Option[ApprovalId]
  ): IO[AgentToolExecutionResult] =
    val descriptor = operation.descriptor
    descriptor.decode(arguments) match
      case Left(error) => IO.pure(AgentToolExecutionResult.InvalidArguments(error))
      case Right(input) =>
        IO.delay((AuthorizationRequestId.random(), UUID.randomUUID().toString)).flatMap: (requestId, correlationId) =>
          def conclude(
              result: AuthorizationResult,
              resource: Option[ResourceId],
              capability: Option[CapabilityDescriptor]
          ): IO[AgentAuthorizationSnapshot] =
            val snapshot = snapshotOf(requestId, correlationId, descriptor.tool, result, at)
            journal
              .record(
                authenticated.tenant,
                AuthorizationEvent(
                  requestId,
                  authenticated.principal,
                  descriptor.tool.value,
                  resource,
                  capability,
                  result,
                  correlationId,
                  at,
                  AuthorizationSource.AgentCall
                )
              )
              .as(snapshot)

          resolver.resolve(authenticated.tenant, descriptor.target, descriptor.locate(input)).flatMap:
            case Left(reason) =>
              conclude(AuthorizationResult.Denied(reason), None, None).flatMap(asExecutionResult)
            case Right(target) =>
              loadAuthority(authenticated, descriptor.tool, Some(target.scope)).flatMap:
                case Left(AuthorityLoadError.UnmappedTool) =>
                  conclude(AuthorizationResult.Denied(DenialReason.UnmappedTool), None, None).flatMap(asExecutionResult)
                case Left(error) => unavailable(error)
                case Right(snapshot) if !agrees(descriptor, snapshot) =>
                  // The code-defined contract and the tenant's trusted mapping disagree: neither is authority alone.
                  conclude(AuthorizationResult.Denied(DenialReason.UnmappedTool), None, None).flatMap(asExecutionResult)
                case Right(snapshot) =>
                  val request = requestFor(authenticated, requestId, snapshot, target.scope, descriptor.facts(input))
                  val binding = InvocationBinding.of(authenticated.tenant, authenticated.agentId, descriptor, target, input)
                  val approvalBinding = ApprovalBinding.parse(binding.digest.value)
                    .getOrElse(throw IllegalStateException("invocation digest is not a SHA-256 hex digest"))
                  authorizeApproved(authenticated, snapshot, request, approvalBinding, presented, at).flatMap: (result, stillPending) =>
                    conclude(result, Some(target.resource), Some(request.requiredCapability)).flatMap: decision =>
                      result match
                        case AuthorizationResult.ApprovalRequired(required) =>
                          // A pending approval for this exact invocation; the agent retries with its ID once approved.
                          // Retrying before the decision returns the same pending approval rather than a new one.
                          stillPending
                            .fold(requestApproval(authenticated, descriptor, snapshot, request, required, approvalBinding, input, at))(
                              pending => IO.pure(Some(pending))
                            )
                            .map(created => AgentToolExecutionResult.ApprovalRequired(decision, required, created))
                        case AuthorizationResult.Authorized(capability) =>
                          metadataFor(authenticated, correlationId, snapshot, binding) match
                            case None =>
                              IO.raiseError(IllegalStateException("authority snapshot lacks valid durable catalog evidence"))
                            case Some(metadata) =>
                              telemetry
                                .span(
                                  TraceSpan.LeaseIssue,
                                  SafeAttribute.tenant(authenticated.tenant),
                                  SafeAttribute.requestId(requestId)
                                )(broker.issueLease(capability, requestId, descriptor.audience, metadata))
                                .flatMap(lease => executor.execute(lease.id, operation, input, target))
                                .map(AgentToolExecutionResult.Completed(decision, _))
                        case _ => asExecutionResult(decision)

  /** Evaluates with the presented approval, if any, and consumes it atomically when the kernel accepted it.
    *
    * A presented approval that is still PENDING for this agent and this exact invocation (and unexpired) grants
    * nothing: evaluation proceeds without it, and the pending record is returned so the caller reports the same
    * approval again. A presented ID that is unknown, for another agent or invocation, denied, expired, already
    * consumed, or lost to a concurrent consumer is `ApprovalMismatch`; it never falls back to requesting a new one. */
  private def authorizeApproved(
      authenticated: AuthenticatedAgentContext,
      snapshot: AuthoritySnapshot,
      request: AuthorizationRequest,
      binding: ApprovalBinding,
      presented: Option[ApprovalId],
      at: Instant
  ): IO[(AuthorizationResult, Option[ApprovalRecord])] =
    presented match
      case None => authorize(authenticated, snapshot, request, at).map(_ -> None)
      case Some(id) =>
        approvals.find(authenticated.tenant, id).map(_.filter(_.agent == authenticated.agentId)).flatMap:
          case Some(pending)
              if pending.status == ApprovalStatus.Pending && pending.binding == binding && at.isBefore(pending.expiresAt) =>
            authorize(authenticated, snapshot, request, at).map:
              case required: AuthorizationResult.ApprovalRequired => required -> Some(pending)
              case other                                         => other -> None
          case found => (found.flatMap(_.granted) match
          case None => IO.pure(AuthorizationResult.Denied(DenialReason.ApprovalMismatch))
          case Some(granted) =>
            IO(AuthorizationEngine.authorizeWithApproval(snapshot.policies, request, snapshot.delegations, binding, Some(granted), at))
              .flatMap:
                case authorized @ AuthorizationResult.Authorized(capability) if capability.evidence.approval.contains(id) =>
                  approvals.consume(authenticated.tenant, id, authenticated.agentId, binding, request.id, at).map:
                    case true  => authorized
                    case false => AuthorizationResult.Denied(DenialReason.ApprovalMismatch)
                case other => IO.pure(other)
          ).map(_ -> None)

  private def requestApproval[In, K](
      authenticated: AuthenticatedAgentContext,
      descriptor: OperationDescriptor[In, K],
      snapshot: AuthoritySnapshot,
      request: AuthorizationRequest,
      required: ApprovalRequest,
      binding: ApprovalBinding,
      input: In,
      at: Instant
  ): IO[Option[ApprovalRecord]] =
    if approvals eq ApprovalStore.unavailable then IO.pure(None)
    else
      AuthorizationEngine.rootOf(request, snapshot.delegations) match
        // Only a human can approve; a chain without a human root cannot be approved.
        case approver: Principal.Human =>
          IO.delay(ApprovalId.random()).flatMap: id =>
            val record = ApprovalRecord(
              id, authenticated.tenant, authenticated.agentId, approver, descriptor.id, descriptor.tool, binding,
              snapshot.capability.id, required.requiredCapability, required.policyId, required.policyVersion,
              descriptor.canonical(input), at, at.plus(approvalTtl), ApprovalStatus.Pending, None, None
            )
            approvals.create(record).as(Some(record))
        case _ => IO.pure(None)

  private def loadAuthority(
      authenticated: AuthenticatedAgentContext,
      tool: ExternalToolId,
      scope: Option[ResourceScope]
  ): IO[Either[AuthorityLoadError, AuthoritySnapshot]] =
    val attributes =
      Vector(SafeAttribute.tenant(authenticated.tenant), SafeAttribute.agent(authenticated.agentId), SafeAttribute.tool(tool))
    telemetry.span(TraceSpan.AuthorityLoad, attributes*)(
      scope match
        case None        => authority.snapshotFor(authenticated.tenant, authenticated.principal, tool.value)
        case Some(value) => authority.snapshotWithin(authenticated.tenant, authenticated.principal, tool.value, value)
    )

  private def authorize(
      authenticated: AuthenticatedAgentContext,
      snapshot: AuthoritySnapshot,
      request: AuthorizationRequest,
      at: Instant
  ): IO[AuthorizationResult] =
    // The kernel evaluation is pure; the span measures it without giving it any effect.
    telemetry.span(
      TraceSpan.PolicyEvaluation,
      SafeAttribute.tenant(authenticated.tenant),
      SafeAttribute.agent(authenticated.agentId)
    )(IO(AuthorizationEngine.authorize(snapshot.policies, request, snapshot.delegations, at)))

  private def agrees(descriptor: OperationDescriptor[?, ?], snapshot: AuthoritySnapshot): Boolean =
    snapshot.capability.descriptor.capability == descriptor.capability &&
      snapshot.capability.descriptor.action == descriptor.action

  private def requestFor(
      authenticated: AuthenticatedAgentContext,
      requestId: AuthorizationRequestId,
      snapshot: AuthoritySnapshot,
      scope: ResourceScope,
      context: AuthorizationContext
  ): AuthorizationRequest =
    AuthorizationRequest(
      requestId,
      authenticated.tenant,
      IdentityChain(authenticated.principal, snapshot.delegations.map(_.id), None, ExecutionContext.LocalProcess),
      scope,
      snapshot.capability.descriptor.capability,
      snapshot.capability.descriptor.action,
      context
    )

  private def metadataFor(
      authenticated: AuthenticatedAgentContext,
      correlationId: String,
      snapshot: AuthoritySnapshot,
      binding: InvocationBinding
  ): Option[AuthenticatedExecutionAuditMetadata] =
    for
      correlation <- ExecutionAuditCorrelationId.parse(correlationId)
      catalogTool <- snapshot.toolResourceId
      capability <- CatalogCapabilityId.parse(snapshot.capability.id)
    yield ExecutionAuditMetadata.authenticatedInvocation(authenticated, correlation, catalogTool, capability, binding)

  private def unavailable[A](error: AuthorityLoadError): IO[A] =
    telemetry.increment(CounterMetric.AuthorityLoadFailures, SafeAttribute.kind(SafeAttribute.Label.of(error))) *>
      IO.raiseError(AuthoritySnapshotUnavailable(error))

  private def snapshotOf(
      requestId: AuthorizationRequestId,
      correlationId: String,
      tool: ExternalToolId,
      result: AuthorizationResult,
      at: Instant
  ): AgentAuthorizationSnapshot = AgentAuthorizationSnapshot(requestId, correlationId, tool, result, at)

  private def asExecutionResult(snapshot: AgentAuthorizationSnapshot): IO[AgentToolExecutionResult] =
    snapshot.result match
      case AuthorizationResult.Denied(reason) => IO.pure(AgentToolExecutionResult.Denied(snapshot, reason))
      case AuthorizationResult.ApprovalRequired(request) =>
        IO.pure(AgentToolExecutionResult.ApprovalRequired(snapshot, request, None))
      case AuthorizationResult.Authorized(_) =>
        IO.raiseError(IllegalStateException("authorized invocation lost its trusted request"))
