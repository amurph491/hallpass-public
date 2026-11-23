package run.hallpass.kernel

import java.time.Instant

final class NonEmptySet[A] private (val toSet: Set[A]):
  def contains(value: A): Boolean = toSet.contains(value)
  // Structural, like the Set it wraps: two allowlists with the same members are the same constraint.
  override def equals(other: Any): Boolean = other match
    case that: NonEmptySet[?] => toSet == that.toSet
    case _                    => false
  override def hashCode: Int = toSet.hashCode
  override def toString: String = toSet.mkString("NonEmptySet(", ", ", ")")

object NonEmptySet:
  def one[A](value: A): NonEmptySet[A] = new NonEmptySet(Set(value))
  def from[A](values: Set[A]): Option[NonEmptySet[A]] = Option.when(values.nonEmpty)(new NonEmptySet(values))

enum Principal:
  case Human(id: UserId)
  case Agent(id: AgentId)
  case Service(id: ServiceId)

enum Action:
  case Read, Write, Execute, Delete

enum ResourceType:
  case Provider, Account, McpServer, Tool, Api, Database, Repository, Channel, Document, Team, Custom

final case class Resource(
    id: ResourceId,
    tenant: TenantId,
    resourceType: ResourceType,
    parent: Option[ResourceId],
    externalId: String,
    /** `Some(human)` for a resource under personal custody, such as one person's mailbox. Custody is set on a
      * connection root from the authenticated session and inherited by everything below it; it never comes from a
      * request. */
    custodian: Option[Principal]
)

/** Trusted containment: the path from a target resource up to its root, as recorded in Hallpass's catalog.
  *
  * Construction checks that the path is internally consistent: one tenant, every element the parent of the one before
  * it, ending at a resource with no parent, without repeats, no deeper than [[ResourceScope.MaximumDepth]], and naming
  * at most one custodian. It cannot check that the path came from the catalog; only the application's trusted
  * resolver builds scopes, and it never accepts a resource ID from an agent.
  */
opaque type ResourceScope = ResourceScope.Data
object ResourceScope:
  private[kernel] final case class Data(path: Vector[Resource], custodian: Option[Principal])

  enum Error:
    case Empty, TenantMismatch, BrokenParentLink, Cycle, TooDeep, ConflictingCustody

  val MaximumDepth = 8

  /** `path` runs from the target (first) to the root (last). */
  def fromPath(path: Vector[Resource]): Either[Error, ResourceScope] =
    path.headOption match
      case None => Left(Error.Empty)
      case Some(target) =>
        val custodians = path.flatMap(_.custodian).distinct
        if path.size > MaximumDepth then Left(Error.TooDeep)
        else if path.exists(_.tenant != target.tenant) then Left(Error.TenantMismatch)
        else if path.map(_.id).distinct.size != path.size then Left(Error.Cycle)
        else if !isLinked(path) then Left(Error.BrokenParentLink)
        else if custodians.size > 1 then Left(Error.ConflictingCustody)
        else Right(Data(path, custodians.headOption))

  private def isLinked(path: Vector[Resource]): Boolean =
    path.zip(path.drop(1)).forall((child, parent) => child.parent.contains(parent.id)) &&
      path.lastOption.exists(_.parent.isEmpty)

  extension (scope: ResourceScope)
    def target: Resource = scope.path.head
    def tenant: TenantId = scope.path.head.tenant
    /** Target first, root last. */
    def path: Vector[Resource] = scope.path
    /** True when `grant` is the target or one of its ancestors. A grant on a child never covers its parent or a
      * sibling. */
    def covers(grant: ResourceId): Boolean = scope.path.exists(_.id == grant)
    def custodian: Option[Principal] = scope.custodian
enum CapabilityKeyError:
  case Empty, TooLong, TooFewSegments, TooManySegments, InvalidSegment

/** The stable catalog identity of a capability, such as `GitHub.Issue.Create`: a provider, an object, and a verb,
  * optionally with further qualifying segments. Two capabilities with the same resource and action are still distinct
  * authority when their keys differ, so the key is part of every descriptor the kernel compares.
  */
opaque type CapabilityKey = String
object CapabilityKey:
  val MaximumLength = 200
  val MinimumSegments = 3
  val MaximumSegments = 6
  private val Segment = "[A-Z][A-Za-z0-9]{0,63}".r

  def parse(value: String): Either[CapabilityKeyError, CapabilityKey] =
    val segments = value.split("\\.", -1).toVector
    if value.isEmpty then Left(CapabilityKeyError.Empty)
    else if value.length > MaximumLength then Left(CapabilityKeyError.TooLong)
    else if segments.size < MinimumSegments then Left(CapabilityKeyError.TooFewSegments)
    else if segments.size > MaximumSegments then Left(CapabilityKeyError.TooManySegments)
    else if !segments.forall(Segment.matches) then Left(CapabilityKeyError.InvalidSegment)
    else Right(value)

  extension (key: CapabilityKey) def value: String = key

/** One unit of authority: an action on a resource, under one catalog capability. */
final case class CapabilityDescriptor(resource: ResourceId, action: Action, capability: CapabilityKey)

opaque type PolicyVersion = Int
object PolicyVersion:
  def from(value: Int): Option[PolicyVersion] = Option.when(value > 0)(value)

opaque type ContextKey = String
object ContextKey:
  private val Pattern = "[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*){0,4}".r
  def apply(value: String): ContextKey = value
  /** A namespaced fact name such as `gmail.recipients`. */
  def parse(value: String): Option[ContextKey] = Option.when(value.length <= 128 && Pattern.matches(value))(value)
  extension (key: ContextKey) def value: String = key

opaque type ContextValue = String
object ContextValue:
  val MaximumLength = 512
  def apply(value: String): ContextValue = value
  def parse(value: String): Option[ContextValue] =
    Option.when(value.nonEmpty && value.length <= MaximumLength && !value.exists(Character.isISOControl))(value)
  extension (value: ContextValue) def value: String = value

/** Facts about one invocation, derived by the application from its typed input (never from free-form arguments).
  *
  * `values` are single-valued facts; `facts` are set-valued facts such as an email's normalized recipients or the
  * CRM properties an update touches. `complete` is false only for [[AuthorizationContext.factsNotEvaluated]], where a
  * fact-based constraint is treated as satisfiable; every call is authorized with its real, complete facts. */
final case class AuthorizationContext private (
    values: Map[ContextKey, ContextValue],
    facts: Map[ContextKey, Set[ContextValue]],
    complete: Boolean
)
object AuthorizationContext:
  def apply(values: Map[ContextKey, ContextValue]): AuthorizationContext = new AuthorizationContext(values, Map.empty, true)
  def withFacts(values: Map[ContextKey, ContextValue], facts: Map[ContextKey, Set[ContextValue]]): AuthorizationContext =
    new AuthorizationContext(values, facts, true)
  val empty: AuthorizationContext = AuthorizationContext(Map.empty)
  /** For evaluations that are not the authorization of a call and where facts are absent or were already evaluated:
    * argument-free discovery (no invocation yet; visibility grants nothing), and execution revalidation (the lease
    * binds the exact input whose facts were evaluated in the same request, and delegation constraints are immutable).
    * Never use it to authorize a call. */
  val factsNotEvaluated: AuthorizationContext = new AuthorizationContext(Map.empty, Map.empty, false)

enum Constraint:
  case RequireContext(key: ContextKey, value: ContextValue)
  /** Every value of the set-valued fact `key` must be in `allowed`. The fact must be present (an empty set is
    * vacuously allowed); a missing fact fails closed, except in a context whose facts are not evaluated. */
  case ValueIn(key: ContextKey, allowed: NonEmptySet[ContextValue])

object Constraint:
  /** Bounds a stored allowlist so a delegation cannot carry an unbounded document. */
  val MaximumAllowedValues = 200

final case class Constraints(values: Set[Constraint]):
  def satisfiedBy(context: AuthorizationContext): Boolean =
    values.forall:
      case Constraint.RequireContext(key, value) =>
        context.values.get(key) match
          case Some(present) => present == value
          case None          => !context.complete
      case Constraint.ValueIn(key, allowed) =>
        context.facts.get(key) match
          case Some(present) => present.subsetOf(allowed.toSet)
          case None          => !context.complete
object Constraints:
  val empty: Constraints = Constraints(Set.empty)

enum Effect:
  case Allow, Deny, RequireApproval

/** A policy statement matches actions on a resource. When `capabilities` is present it also restricts which catalog
  * capabilities it matches; when absent it matches every capability for those actions.
  */
final case class PolicyStatement(
    subject: Principal,
    resource: ResourceId,
    actions: NonEmptySet[Action],
    capabilities: Option[NonEmptySet[CapabilityKey]],
    constraints: Constraints,
    effect: Effect
):
  def matchesCapability(key: CapabilityKey): Boolean = capabilities.forall(_.contains(key))
final case class Policy(id: PolicyId, version: PolicyVersion, statements: NonEmptySet[PolicyStatement])
final case class Policies(values: Vector[Policy])
object Policies:
  val empty: Policies = Policies(Vector.empty)

final case class Delegation(
    id: DelegationId,
    grantor: Principal,
    grantee: Principal,
    parent: Option[DelegationId],
    capabilities: NonEmptySet[CapabilityDescriptor],
    constraints: Constraints,
    validFrom: Instant,
    expiresAt: Option[Instant],
    revokedAt: Option[Instant]
):
  def isActiveAt(at: Instant): Boolean =
    !at.isBefore(validFrom) && expiresAt.forall(at.isBefore) && revokedAt.forall(at.isBefore)

enum DelegationValidationError:
  case ParentReferenceMissing, PrincipalChainBroken, UnknownResource, CapabilityEscalation, ConstraintEscalation,
    InvalidValidityWindow

object Delegation:
  /** Checks that `child` attenuates `parent`. Each child capability must be covered by a parent capability with the
    * same key and action whose resource is the child's resource or one of its ancestors, so a child may narrow to a
    * descendant but never widen to an ancestor or a sibling. `scopeOf` supplies the trusted scope of each child
    * capability's resource; a resource it does not know is rejected.
    */
  def validateChild(
      parent: Delegation,
      child: Delegation,
      scopeOf: ResourceId => Option[ResourceScope]
  ): Either[DelegationValidationError, Delegation] =
    val childScopes = child.capabilities.toSet.toVector.map(capability =>
      capability -> scopeOf(capability.resource).filter(_.target.id == capability.resource)
    )
    def covered(capability: CapabilityDescriptor, scope: ResourceScope): Boolean =
      parent.capabilities.toSet.exists(granted =>
        granted.capability == capability.capability && granted.action == capability.action &&
          scope.covers(granted.resource)
      )
    if child.parent != Some(parent.id) then Left(DelegationValidationError.ParentReferenceMissing)
    else if parent.grantee != child.grantor then Left(DelegationValidationError.PrincipalChainBroken)
    else if childScopes.exists(_._2.isEmpty) then Left(DelegationValidationError.UnknownResource)
    else if !childScopes.forall((capability, scope) => scope.exists(covered(capability, _))) then
      Left(DelegationValidationError.CapabilityEscalation)
    else if !parent.constraints.values.subsetOf(child.constraints.values) then
      Left(DelegationValidationError.ConstraintEscalation)
    else if child.validFrom.isBefore(parent.validFrom) || parent.expiresAt.exists(parentEnd =>
        child.expiresAt.forall(_.isAfter(parentEnd))
      )
    then Left(DelegationValidationError.InvalidValidityWindow)
    else Right(child)

final case class ModelIdentity(
    id: ModelId,
    provider: String,
    name: String,
    version: Option[String]
)

enum ExecutionContext:
  case LocalProcess
  case RemoteService

final case class IdentityChain(
    subject: Principal,
    delegationIds: Vector[DelegationId],
    model: Option[ModelIdentity],
    executionContext: ExecutionContext
)

object IdentityChain:
  def direct(subject: Principal, executionContext: ExecutionContext = ExecutionContext.LocalProcess): IdentityChain =
    IdentityChain(subject, Vector.empty, None, executionContext)
