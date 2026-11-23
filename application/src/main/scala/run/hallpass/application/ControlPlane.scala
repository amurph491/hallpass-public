package run.hallpass.application

import java.time.Instant
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*
import cats.syntax.all.*

final case class Agent(id: AgentId, name: String, description: Option[String], createdAt: Instant)
final case class CreateAgent(name: String, description: Option[String])
enum AgentError:
  case InvalidName, NotFound, Duplicate, PersistenceFailure

final case class CatalogResource(resource: Resource, name: String, provider: Option[String])
final case class CatalogCapability(id: String, name: String, descriptor: CapabilityDescriptor)
final case class CatalogTool(
    name: String,
    label: String,
    resource: ResourceId,
    capability: Option[CatalogCapability],
    mappingSource: Option[String],
    trusted: Boolean
)

final case class CreateDelegation(
    grantor: Principal,
    grantee: Principal,
    capabilityId: String,
    resource: ResourceId,
    action: Action,
    expiresAt: Option[Instant],
    constraints: Constraints = Constraints.empty
)
enum DelegationError:
  case InvalidRequest, GrantorLacksAuthority, NotFound, AlreadyRevoked, PersistenceFailure

enum AuthorityLoadError:
  case UnmappedTool
  /** More than one trusted interpretation exists for a tool. Selecting one would manufacture authority. */
  case AmbiguousMapping
  /** Persisted policy, mapping, delegation, or chain data cannot be represented by the kernel model. */
  case InvalidStoredAuthority
  case PersistenceFailure

/** Fully typed input loaded at the application boundary for one decision. */
final case class AuthoritySnapshot(
    /** The trusted catalog path from the mapped resource to its root. */
    scope: ResourceScope,
    capability: CatalogCapability,
    policies: Policies,
    delegations: Vector[Delegation],
    /** The catalog resource for the external tool. Legacy/in-memory snapshots may omit it, but durable execution
      * refuses to issue a lease without this mapping identity. */
    toolResourceId: Option[ResourceId] = None
):
  def resource: Resource = scope.target

enum AuthorizationSource:
  case AgentCall, HumanPreview

object AuthorizationSource:
  def fromWire(value: String): Option[AuthorizationSource] = value match
    case "AGENT_CALL"    => Some(AgentCall)
    case "HUMAN_PREVIEW" => Some(HumanPreview)
    case _               => None

  extension (value: AuthorizationSource) def wire: String = value match
    case AgentCall    => "AGENT_CALL"
    case HumanPreview => "HUMAN_PREVIEW"

final case class AuthorizationEvent(
    requestId: AuthorizationRequestId,
    principal: Principal,
    tool: String,
    resource: Option[ResourceId],
    capability: Option[CapabilityDescriptor],
    result: AuthorizationResult,
    correlationId: String,
    occurredAt: Instant,
    authorizationSource: AuthorizationSource
)

enum RecordedOutcome:
  case Allow, Deny, RequireApproval

final case class AuthorizationRecord(
    requestId: AuthorizationRequestId,
    principal: Principal,
    tool: String,
    resource: Option[ResourceId],
    action: Option[Action],
    /** Absent for unmapped tools and for decisions recorded before the key was journaled. */
    capability: Option[CapabilityKey],
    outcome: RecordedOutcome,
    reason: String,
    policyId: Option[PolicyId],
    policyVersion: Option[PolicyVersion],
    delegationIds: Vector[DelegationId],
    correlationId: String,
    occurredAt: Instant,
    authorizationSource: Option[AuthorizationSource]
)

trait AgentRepository[F[_]]:
  def create(tenant: TenantId, request: CreateAgent): F[Either[AgentError, Agent]]
  def find(tenant: TenantId, id: AgentId): F[Option[Agent]]
  def list(tenant: TenantId): F[Vector[Agent]]

trait AuthorityRepository[F[_]]:
  /** Authority for a tool at its mapped catalog resource. */
  def snapshotFor(
      tenant: TenantId,
      principal: Principal,
      externalTool: String
  ): F[Either[AuthorityLoadError, AuthoritySnapshot]]

  /** Authority for a tool at a resolved `scope`. The scope must cover the tool's mapped catalog resource; otherwise the
    * mapping does not apply there and loading fails with `InvalidStoredAuthority`. Policies and delegations are loaded
    * for the whole scope, and the snapshot's scope is `scope`. */
  def snapshotWithin(
      tenant: TenantId,
      principal: Principal,
      externalTool: String,
      scope: ResourceScope
  ): F[Either[AuthorityLoadError, AuthoritySnapshot]]

/** Resolves a server-recorded tool resource back to its protocol name for fresh authorization loading. The resource ID
  * originates in a private execution context, never an agent DTO. */
trait TrustedToolLookup[F[_]]:
  def externalToolFor(
      tenant: TenantId,
      toolId: ResourceId
  ): F[Either[AuthorityLoadError, ExternalToolId]]

trait DelegationRepository[F[_]]:
  def create(tenant: TenantId, request: CreateDelegation): F[Either[DelegationError, Delegation]]
  def revoke(tenant: TenantId, id: DelegationId, at: Instant): F[Either[DelegationError, Delegation]]
  def listForGrantee(tenant: TenantId, grantee: Principal): F[Vector[Delegation]]

trait AuthorizationJournal[F[_]]:
  def record(tenant: TenantId, event: AuthorizationEvent): F[Unit]
  def recent(tenant: TenantId, limit: Int): F[Vector[AuthorizationRecord]]

trait ControlPlaneCatalog[F[_]]:
  def resources(tenant: TenantId): F[Vector[CatalogResource]]
  def capabilities(tenant: TenantId): F[Vector[CatalogCapability]]
  def tools(tenant: TenantId): F[Vector[CatalogTool]]

enum ConnectionStatus:
  case Connecting, Active, Disabled, Error, NeedsReauth

/** Sanitized, durable connection metadata. It deliberately has no credential field. */
final case class Connection(
    id: ConnectionId,
    resource: ResourceId,
    provider: String,
    status: ConnectionStatus,
    accountLabel: Option[String],
    workspaceLabel: Option[String],
    expiresAt: Option[Instant],
    createdAt: Instant,
    updatedAt: Instant,
    externalAccountId: Option[String] = None
)

/** Opaque value returned by SecretStore; it is never a filesystem path or credential. */
opaque type SecretReference = String
object SecretReference:
  def parse(value: String): Option[SecretReference] =
    Option.when(value.matches("sec_[A-Za-z0-9_-]{22,128}"))(value)
  def random(): SecretReference = "sec_" + java.util.UUID.randomUUID().toString.replace("-", "")
  extension (value: SecretReference) def value: String = value

/** Edge-only provider material. The kernel never depends on this type. */
opaque type ProviderSecret = Array[Byte]
object ProviderSecret:
  def fromUtf8(value: String): ProviderSecret = value.getBytes(java.nio.charset.StandardCharsets.UTF_8)
  def fromBytes(value: Array[Byte]): ProviderSecret = value.clone()
  def bytes(value: ProviderSecret): Array[Byte] = value.clone()

/** Everything a verified callback publishes when it activates a reserved connection. */
final case class ConnectionActivation(
    owner: Principal.Human,
    externalAccountId: ExternalId,
    accountLabel: Option[String],
    workspaceLabel: Option[String],
    expiresAt: Option[Instant],
    credentialType: String,
    secret: SecretReference,
    rootKind: ResourceKind[?],
    rootExternalId: ExternalId,
    rootDisplayName: String,
    rootCustodian: Option[UserId],
    /** Operations of this provider address the connection root without an argument, so a second active root of the
      * same kind would make every such call ambiguous. */
    singleActiveRoot: Boolean
)

/** What a reauthorization callback proves: the same account and root, by a permitted human, with a new credential. */
final case class ConnectionReauthorization(
    by: Principal.Human,
    externalAccountId: ExternalId,
    rootExternalId: ExternalId,
    expiresAt: Option[Instant],
    credentialType: String,
    secret: SecretReference
)

enum ConnectionActivationError:
  /** The reservation is missing, already completed or failed, or was started by someone else. */
  case NotReserved
  /** Another active connection already holds this external account. */
  case AccountAlreadyConnected
  /** The provider supports one active root of this kind per tenant, and another is active. */
  case RootKindInUse
  /** The database refused the root's placement or custody. */
  case InvalidPlacement
  /** A reauthorization callback signed in to a different provider account or root than the connection's. */
  case AccountMismatch

enum ConnectionError:
  case NotFound, Disabled, MissingCredential, Ambiguous, InvalidState, PersistenceFailure
enum SecretStoreError:
  case NotFound, MalformedReference, DecryptionFailed, Unavailable

trait ConnectionRepository[F[_]]:
  def create(tenant: TenantId, connection: Connection, secret: SecretReference): F[Connection]
  def findForResource(tenant: TenantId, resource: ResourceId): F[Option[Connection]]
  def disable(tenant: TenantId, id: ConnectionId): F[Either[ConnectionError, Unit]]
  def list(tenant: TenantId): F[Vector[Connection]]
  def secretReference(tenant: TenantId, id: ConnectionId): F[Option[SecretReference]]

  /** Reserves the callback's intended connection ID before OAuth state is issued. No provider credential exists yet. */
  def reserve(
      tenant: TenantId,
      id: ConnectionId,
      provider: String,
      owner: Principal.Human,
      at: Instant
  )(using F: cats.ApplicativeError[F, Throwable]): F[Unit] =
    F.raiseError(UnsupportedOperationException("connection reservation unavailable"))

  /** Activates a reserved connection from a verified OAuth callback in one transaction: account metadata, the
    * server-side credential reference, and the provider-verified root resource are published together, or nothing is.
    * The caller holds the tenant mutation gate, which also serializes the single-root check below. */
  def activateReserved(tenant: TenantId, id: ConnectionId, activation: ConnectionActivation, at: Instant)(using
      F: cats.Applicative[F]
  ): F[Either[ConnectionActivationError, Connection]] =
    F.pure(Left(ConnectionActivationError.NotReserved))

  /** Replaces the credential of a connection that needs reauthorization, in place, and restores it to ACTIVE. The
    * callback must prove the same provider account and root; grants and selections are unchanged because the
    * authority they name is unchanged. Returns the superseded credential reference for deletion after commit. The
    * caller holds the tenant mutation gate. */
  def reauthorize(tenant: TenantId, id: ConnectionId, reauthorization: ConnectionReauthorization, at: Instant)(using
      F: cats.Applicative[F]
  ): F[Either[ConnectionActivationError, SecretReference]] =
    F.pure(Left(ConnectionActivationError.NotReserved))

  /** Marks a reservation that is still CONNECTING as failed. Returns false when the connection already left that
    * state (for example it was activated), in which case the caller must not clean up its credential. */
  def failReserved(tenant: TenantId, id: ConnectionId, at: Instant)(using F: cats.Applicative[F]): F[Boolean] =
    F.pure(false)

object ConnectionRepository:
  /** Safe compatibility default for control-plane-only composition roots. */
  val unavailable: ConnectionRepository[cats.effect.IO] = new ConnectionRepository[cats.effect.IO]:
    def create(tenant: TenantId, connection: Connection, secret: SecretReference) =
      cats.effect.IO.raiseError(IllegalStateException("connection repository unavailable"))
    def findForResource(tenant: TenantId, resource: ResourceId) = cats.effect.IO.pure(None)
    def disable(tenant: TenantId, id: ConnectionId) = cats.effect.IO.pure(Left(ConnectionError.NotFound))
    def list(tenant: TenantId) = cats.effect.IO.pure(Vector.empty)
    def secretReference(tenant: TenantId, id: ConnectionId) = cats.effect.IO.pure(None)

/** What a stored provider secret belongs to. Implementations bind ciphertext to it (as AEAD associated data and, where
  * the KMS supports it, as key-derivation context), so a secret moved to another tenant or connection fails to decrypt
  * rather than being disclosed there. */
final case class SecretBinding(tenant: TenantId, connection: ConnectionId)

/** Provider credential storage. An unavailable store (for example a KMS outage) is `SecretStoreError.Unavailable` on
  * read and a failed effect on write; callers fail closed and never retry in a loop. */
trait SecretStore[F[_]]:
  def put(binding: SecretBinding, secret: ProviderSecret): F[SecretReference]
  def get(binding: SecretBinding, reference: SecretReference): F[Either[SecretStoreError, ProviderSecret]]
  def delete(binding: SecretBinding, reference: SecretReference): F[Unit]

final case class ResolvedConnection(connection: Connection, secret: ProviderSecret)

/** This boundary is only callable after the trusted executor redeems a one-time lease. */
trait ConnectionResolver[F[_]]:
  def activeConnectionFor(lease: RedeemedExecutionLease): F[Either[ConnectionError, ResolvedConnection]]

/** Resolves the connection that owns a redeemed lease's authorized resource (a connection root or a selected child),
  * with its stored secret. Only credential strategies call it, after redemption, inside the executor's gate.
  *
  * The connection is found server-side from the lease's resource, never from a request. It must be ACTIVE, belong to
  * `provider`, and hold a credential reference of `credentialType`; the resource must still carry the target's kind
  * and external ID. Anything else is a `ConnectionError`, never a guess.
  */
trait ProviderConnectionResolver:
  def activeConnectionFor[K](
      lease: RedeemedExecutionLease,
      target: SelectedResource[K],
      provider: ProviderId,
      credentialType: String
  ): cats.effect.IO[Either[ConnectionError, ResolvedConnection]]

final class DynamicAuthorizationService[F[_]](
    authority: AuthorityRepository[F],
    journal: AuthorizationJournal[F]
)(using F: cats.Monad[F]):
  def authorize(
      tenant: TenantId,
      principal: Principal,
      tool: String,
      correlationId: String,
      at: Instant
  ): F[AuthorizationResult] =
    val requestId = AuthorizationRequestId.random()
    authority
      .snapshotFor(tenant, principal, tool)
      .flatMap:
        case Left(AuthorityLoadError.UnmappedTool) =>
          val result = AuthorizationResult.Denied(DenialReason.UnmappedTool)
          journal
            .record(tenant, AuthorizationEvent(requestId, principal, tool, None, None, result, correlationId, at, AuthorizationSource.HumanPreview))
            .as(result)
        case Left(_) =>
          val result = AuthorizationResult.Denied(DenialReason.NoMatchingAuthority)
          journal
            .record(tenant, AuthorizationEvent(requestId, principal, tool, None, None, result, correlationId, at, AuthorizationSource.HumanPreview))
            .as(result)
        case Right(snapshot) =>
          val chain = IdentityChain(principal, snapshot.delegations.map(_.id), None, ExecutionContext.LocalProcess)
          val request = AuthorizationRequest(
            requestId,
            tenant,
            chain,
            snapshot.scope,
            snapshot.capability.descriptor.capability,
            snapshot.capability.descriptor.action,
            AuthorizationContext.empty
          )
          val result = AuthorizationEngine.authorize(snapshot.policies, request, snapshot.delegations, at)
          journal
            .record(
              tenant,
              AuthorizationEvent(
                requestId,
                principal,
                tool,
                Some(snapshot.resource.id),
                Some(snapshot.capability.descriptor),
                result,
                correlationId,
                at,
                AuthorizationSource.HumanPreview
              )
            )
            .as(result)
