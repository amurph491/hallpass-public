package run.hallpass.application

import java.time.Instant
import cats.effect.IO
import run.hallpass.kernel.*

/** A runtime-created resource: a connection root or a selected child. */
final case class ConnectionResource(
    id: ResourceId,
    connection: ConnectionId,
    kind: String,
    externalId: ExternalId,
    displayName: String,
    parent: ResourceId,
    custodian: Option[UserId],
    /** Open selection time for a child; `None` for a root, which is selected while its connection is active. */
    selectedAt: Option[Instant]
)

enum ConnectionResourceError:
  /** The connection is missing, not active, or belongs to another provider. */
  case ConnectionUnavailable
  /** The kind is not registered, or the parent is not where the kind must sit. */
  case InvalidPlacement
  /** Custody does not match the connection's owner or the parent. */
  case InvalidCustody
  /** The external resource is already open under this or another connection in the tenant. */
  case AlreadySelected
  case NotFound
  case PersistenceFailure

final case class ConnectionResourceListing(
    current: Vector[ConnectionResource],
    available: Vector[SelectableProviderResource]
)

/** Runtime writes to the resource hierarchy. The database trigger is the authority on placement; this port maps
  * its refusals to explicit errors. Selection and deselection change authority, so callers run them under the
  * tenant's mutation gate. Nothing here is ever deleted.
  */
trait ConnectionResourceRepository:
  /** Creates the connection's root under its provider's catalog resource. A personal root's custodian must be the
    * connection's owner. At most one root exists per connection. */
  def createRoot(
      tenant: TenantId,
      connection: ConnectionId,
      kind: ResourceKind[?],
      externalId: ExternalId,
      displayName: String,
      custodian: Option[UserId]
  ): IO[Either[ConnectionResourceError, ConnectionResource]]

  /** Selects a child under `parent` (a resource of the kind's registered parent kind in the same connection): creates
    * its resource row if needed and opens a selection. The child inherits the parent's custody. Selecting an already
    * open resource is `AlreadySelected`. */
  def select(
      tenant: TenantId,
      connection: ConnectionId,
      kind: ResourceKind[?],
      externalId: ExternalId,
      displayName: String,
      parent: ResourceId,
      selectedBy: Principal.Human,
      at: Instant
  ): IO[Either[ConnectionResourceError, ConnectionResource]]

  /** Closes the open selection of `resource`. Closing an already closed or unknown selection is `NotFound`. */
  def deselect(tenant: TenantId, resource: ResourceId, at: Instant): IO[Either[ConnectionResourceError, Unit]]

  /** The connection's root and its currently selected children. */
  def listFor(tenant: TenantId, connection: ConnectionId): IO[Vector[ConnectionResource]]

  /** Atomically replaces the selected child set. Implementations must validate all placements before publishing any
    * deselection or selection. */
  def replaceSelection(
      tenant: TenantId,
      connection: ConnectionId,
      selectedBy: Principal.Human,
      resources: Vector[SelectableProviderResource],
      at: Instant
  ): IO[Either[ConnectionResourceError, Vector[ConnectionResource]]] =
    IO.pure(Left(ConnectionResourceError.PersistenceFailure))
