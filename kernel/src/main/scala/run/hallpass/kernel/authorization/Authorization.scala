package run.hallpass.kernel.authorization

import java.time.Instant
import run.hallpass.kernel.*

final case class AuthorizationRequest(
    id: AuthorizationRequestId,
    tenant: TenantId,
    identity: IdentityChain,
    /** The trusted path from the requested resource to its root. */
    scope: ResourceScope,
    capability: CapabilityKey,
    action: Action,
    context: AuthorizationContext
):
  def resource: Resource = scope.target
  def requiredCapability: CapabilityDescriptor = CapabilityDescriptor(scope.target.id, action, capability)

final case class AuthorizationEvidence(
    policyId: PolicyId,
    policyVersion: PolicyVersion,
    delegationIds: Vector[DelegationId],
    requiredCapability: CapabilityDescriptor,
    /** The human approval that satisfied a `RequireApproval` policy, when one did. */
    approval: Option[ApprovalId] = None
)

opaque type ApprovalId = java.util.UUID
object ApprovalId:
  def random(): ApprovalId = java.util.UUID.randomUUID()
  def parse(value: String): Either[IllegalArgumentException, ApprovalId] =
    scala.util.Try(java.util.UUID.fromString(value)).toEither.left.map(_ => IllegalArgumentException("invalid approval ID"))
      .filterOrElse(_.toString == value.toLowerCase, IllegalArgumentException("invalid approval ID"))
  extension (value: ApprovalId) def uuid: java.util.UUID = value

/** The digest of the exact invocation an approval covers (operation, canonical arguments, target, tenant, agent),
  * computed by the application. The kernel only compares it; a changed argument is a different digest. */
opaque type ApprovalBinding = String
object ApprovalBinding:
  private val Pattern = "[0-9a-f]{64}".r
  def parse(value: String): Option[ApprovalBinding] = Option.when(Pattern.matches(value))(value)
  extension (value: ApprovalBinding) def value: String = value

/** A human decision to allow one exact invocation once. The application loads it only when it is APPROVED and not yet
  * consumed, and consumes it atomically after the kernel accepts it. */
final case class GrantedApproval(
    id: ApprovalId,
    tenant: TenantId,
    /** The agent the invocation runs as. */
    principal: Principal,
    /** Who approved. Must be the root of authority for the invocation. */
    approver: Principal.Human,
    binding: ApprovalBinding,
    requiredCapability: CapabilityDescriptor,
    policyId: PolicyId,
    policyVersion: PolicyVersion,
    expiresAt: Instant
)

enum DenialReason:
  case UnmappedTool
  case TenantMismatch
  /** The requested resource is not currently selected under an active connection. Produced by the application's
    * resource resolver before evaluation. */
  case ResourceNotSelected
  /** The resource is under personal custody and the root of authority is not its custodian. */
  case CustodianMismatch
  case InvalidDelegationChain
  case InactiveDelegation(id: DelegationId)
  case CapabilityNotDelegated(id: DelegationId)
  case DelegationConstraintsNotSatisfied(id: DelegationId)
  case ExplicitDeny(policyId: PolicyId, policyVersion: PolicyVersion)
  case NoMatchingAuthority
  /** An approval was presented but does not cover this exact invocation, principal, policy version, or approver, or it
    * has expired. A mismatched approval never falls back to a fresh approval request. */
  case ApprovalMismatch

final case class ApprovalRequest(
    requestId: AuthorizationRequestId,
    policyId: PolicyId,
    policyVersion: PolicyVersion,
    requiredCapability: CapabilityDescriptor
)

enum AuthorizationDecision:
  case Allow(evidence: AuthorizationEvidence)
  case Deny(reason: DenialReason)
  case RequireApproval(request: ApprovalRequest)

opaque type AuthorizedCapability = AuthorizedCapability.Data
object AuthorizedCapability:
  private[authorization] final case class Data(
      tenant: TenantId,
      principal: Principal,
      resource: ResourceId,
      capability: CapabilityKey,
      action: Action,
      evidence: AuthorizationEvidence
  )
  private[authorization] def issue(
      request: AuthorizationRequest,
      evidence: AuthorizationEvidence
  ): AuthorizedCapability =
    Data(request.tenant, request.identity.subject, request.resource.id, request.capability, request.action, evidence)
  extension (value: AuthorizedCapability)
    def tenant: TenantId = value.tenant
    def principal: Principal = value.principal
    def resource: ResourceId = value.resource
    def capability: CapabilityKey = value.capability
    def action: Action = value.action
    def evidence: AuthorizationEvidence = value.evidence

enum AuthorizationResult:
  case Authorized(capability: AuthorizedCapability)
  case Denied(reason: DenialReason)
  case ApprovalRequired(request: ApprovalRequest)

object AuthorizationEngine:
  def evaluate(
      policies: Policies,
      request: AuthorizationRequest,
      delegations: Vector[Delegation],
      at: Instant
  ): AuthorizationDecision =
    if request.tenant != request.scope.tenant then AuthorizationDecision.Deny(DenialReason.TenantMismatch)
    else
      validateDelegations(request, delegations, at).fold(
        AuthorizationDecision.Deny.apply,
        root =>
          // Custody: a personal resource is authorized only when the root of authority is its custodian, whatever
          // policies exist.
          if !request.scope.custodian.forall(_ == root) then AuthorizationDecision.Deny(DenialReason.CustodianMismatch)
          else evaluatePolicy(policies, request, delegations, root)
      )

  def authorize(
      policies: Policies,
      request: AuthorizationRequest,
      delegations: Vector[Delegation],
      at: Instant
  ): AuthorizationResult =
    evaluate(policies, request, delegations, at) match
      case AuthorizationDecision.Allow(evidence) =>
        AuthorizationResult.Authorized(AuthorizedCapability.issue(request, evidence))
      case AuthorizationDecision.Deny(reason)              => AuthorizationResult.Denied(reason)
      case AuthorizationDecision.RequireApproval(approval) => AuthorizationResult.ApprovalRequired(approval)

  /** [[authorize]], where a `RequireApproval` outcome is satisfied by `approval` if, and only if, it covers exactly this
    * invocation: same tenant and principal, same binding digest, same required capability (resource, action, key),
    * the same deciding policy and version, an approver who is the root of authority, and an expiry after `at`.
    *
    * Allow and Deny outcomes are returned unchanged and never consume the approval; a presented approval that does not
    * match is `ApprovalMismatch`. Without an approval this is exactly [[authorize]]. */
  def authorizeWithApproval(
      policies: Policies,
      request: AuthorizationRequest,
      delegations: Vector[Delegation],
      binding: ApprovalBinding,
      approval: Option[GrantedApproval],
      at: Instant
  ): AuthorizationResult =
    (evaluate(policies, request, delegations, at), approval) match
      case (AuthorizationDecision.RequireApproval(required), Some(granted)) =>
        val root = rootOf(request, delegations)
        val covers =
          granted.tenant == request.tenant &&
            granted.principal == request.identity.subject &&
            granted.binding == binding &&
            granted.requiredCapability == required.requiredCapability &&
            granted.policyId == required.policyId &&
            granted.policyVersion == required.policyVersion &&
            (granted.approver: Principal) == root &&
            at.isBefore(granted.expiresAt)
        if covers then
          AuthorizationResult.Authorized(
            AuthorizedCapability.issue(
              request,
              AuthorizationEvidence(required.policyId, required.policyVersion, delegations.map(_.id), required.requiredCapability, Some(granted.id))
            )
          )
        else AuthorizationResult.Denied(DenialReason.ApprovalMismatch)
      case (AuthorizationDecision.Allow(evidence), _) =>
        AuthorizationResult.Authorized(AuthorizedCapability.issue(request, evidence))
      case (AuthorizationDecision.Deny(reason), _)                 => AuthorizationResult.Denied(reason)
      case (AuthorizationDecision.RequireApproval(required), None) => AuthorizationResult.ApprovalRequired(required)

  /** The root of authority for a chain the kernel accepted: the first grantor, or the subject acting directly. */
  def rootOf(request: AuthorizationRequest, delegations: Vector[Delegation]): Principal =
    delegations.headOption.fold(request.identity.subject)(_.grantor)

  private def evaluatePolicy(
      policies: Policies,
      request: AuthorizationRequest,
      delegations: Vector[Delegation],
      root: Principal
  ): AuthorizationDecision =
    val required = request.requiredCapability
    val matches = policies.values
      .flatMap(policy => policy.statements.toSet.map(policy -> _))
      .filter:
        case (_, statement) =>
          statement.subject == root &&
          request.scope.covers(statement.resource) &&
          statement.actions.contains(required.action) &&
          statement.matchesCapability(required.capability) &&
          statement.constraints.satisfiedBy(request.context)
    val decisive = matches
      .find(_._2.effect == Effect.Deny)
      .orElse(matches.find(_._2.effect == Effect.RequireApproval))
      .orElse(matches.find(_._2.effect == Effect.Allow))
    decisive match
      case None                      => AuthorizationDecision.Deny(DenialReason.NoMatchingAuthority)
      case Some((policy, statement)) =>
        statement.effect match
          case Effect.Deny => AuthorizationDecision.Deny(DenialReason.ExplicitDeny(policy.id, policy.version))
          case Effect.RequireApproval =>
            AuthorizationDecision.RequireApproval(ApprovalRequest(request.id, policy.id, policy.version, required))
          case Effect.Allow =>
            AuthorizationDecision.Allow(
              AuthorizationEvidence(policy.id, policy.version, delegations.map(_.id), required)
            )

  private def validateDelegations(
      request: AuthorizationRequest,
      delegations: Vector[Delegation],
      at: Instant
  ): Either[DenialReason, Principal] =
    val required = request.requiredCapability
    if request.identity.delegationIds != delegations.map(_.id) then Left(DenialReason.InvalidDelegationChain)
    else if delegations.lastOption.exists(_.grantee != request.identity.subject) then
      Left(DenialReason.InvalidDelegationChain)
    else
      delegations.toList match
        case Nil       => Right(request.identity.subject)
        case root :: _ =>
          @annotation.tailrec
          def validate(
              remaining: List[Delegation],
              previous: Option[Delegation]
          ): Either[DenialReason, Principal] = remaining match
            case Nil                => Right(root.grantor)
            case delegation :: rest =>
              val isLinked =
                previous.forall(parent => delegation.parent.contains(parent.id) && delegation.grantor == parent.grantee)
              if !isLinked then Left(DenialReason.InvalidDelegationChain)
              else if !delegation.isActiveAt(at) then Left(DenialReason.InactiveDelegation(delegation.id))
              else if !satisfies(delegation, required, request.scope) then
                Left(DenialReason.CapabilityNotDelegated(delegation.id))
              else if !delegation.constraints.satisfiedBy(request.context) then
                Left(DenialReason.DelegationConstraintsNotSatisfied(delegation.id))
              else validate(rest, Some(delegation))
          validate(delegations.toList, None)

  /** A delegated capability satisfies the requirement when it has the same key and action and its resource is the
    * requested resource or one of its trusted ancestors. */
  private def satisfies(delegation: Delegation, required: CapabilityDescriptor, scope: ResourceScope): Boolean =
    delegation.capabilities.toSet.exists(granted =>
      granted.capability == required.capability && granted.action == required.action && scope.covers(granted.resource)
    )
