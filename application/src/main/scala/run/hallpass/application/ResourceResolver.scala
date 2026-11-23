package run.hallpass.application

import cats.effect.IO
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.DenialReason

/** Trusted catalog lookups behind the [[ResourceResolver]]. Every scope comes from Hallpass's own catalog, never from a
  * live provider lookup: asking the provider would use a credential before authorization.
  */
trait ResourceCatalog:
  /** The root resource for a provider's root kind, with its external ID and scope, or `None`.
    *
    * It is the single root of that kind under an active connection. With none, it falls back to the provider's
    * owner-provisioned catalog resource, which is how Slack works without per-connection roots; a missing
    * or disabled connection is then reported by the executor after authorization, as before. With more than one root
    * of the kind in the tenant, choosing one would be guessing, so the answer is `None`.
    */
  def rootScope(tenant: TenantId, root: ResourceKind[?]): IO[Option[(ExternalId, ResourceScope)]]

  /** The scope of the resource of `kind` with `externalId` that is currently addressable, or `None`. Addressable means
    * its connection is active and it, and every non-root resource above it, has an open selection. */
  def selectedScope(tenant: TenantId, kind: ResourceKind[?], externalId: ExternalId): IO[Option[ResourceScope]]

  /** Addressable targets of this kind for argument-free discovery. Only catalog metadata is read; visibility is
    * evaluated separately at each scope. The legacy catalog has one root and no selected children. */
  def discoveryScopes(tenant: TenantId, kind: ResourceKind[?]): IO[Vector[ResourceScope]] =
    if kind.isRoot then rootScope(tenant, kind).map(_.map(_._2).toVector)
    else IO.pure(Vector.empty)

  /** [[discoveryScopes]] with each target's catalog display name. The name is metadata for the agent-visible tool
    * description only; it is never matched or used for authorization or dispatch. */
  def discoveryTargets(tenant: TenantId, kind: ResourceKind[?]): IO[Vector[DiscoveryTarget]] =
    discoveryScopes(tenant, kind).map(_.map(scope => DiscoveryTarget(scope, scope.target.externalId)))

  /** The current scope of a resource an issued lease names, or `None` when it is no longer addressable (same rule as
    * `selectedScope`; a catalog resource is always addressable). Execution revalidates against this, so deselection
    * and disconnection behave like revocation. */
  def currentScope(tenant: TenantId, resource: ResourceId): IO[Option[ResourceScope]]

/** An addressable target found by argument-free discovery, with its display name (metadata only). */
final case class DiscoveryTarget(scope: ResourceScope, displayName: String)

/** Turns an untrusted [[ResourceLocator]] into a [[SelectedResource]], the only way to obtain one.
  *
  * Unknown, unselected, or inconsistent resources deny with `ResourceNotSelected` before any authority is loaded, any
  * secret is read, or any provider request is sent. Infrastructure failures stay failed effects.
  */
final class ResourceResolver(catalog: ResourceCatalog):
  /** Discovery never trusts a scope outside the authenticated tenant. A malformed catalog answer is a failure. */
  def discoveryScopes(tenant: TenantId, kind: ResourceKind[?]): IO[Vector[ResourceScope]] =
    discoveryTargets(tenant, kind).map(_.map(_.scope))

  def discoveryTargets(tenant: TenantId, kind: ResourceKind[?]): IO[Vector[DiscoveryTarget]] =
    catalog.discoveryTargets(tenant, kind).flatMap: targets =>
      val scopes = targets.map(_.scope)
      if scopes.exists(scope =>
          scope.tenant != tenant || (kind.custody == Custody.Personal && scope.custodian.isEmpty)
        )
      then IO.raiseError(AuthoritySnapshotUnavailable(AuthorityLoadError.InvalidStoredAuthority))
      else IO.pure(targets.distinctBy(_.scope.target.id))
  def resolve[K](
      tenant: TenantId,
      kind: ResourceKind[K],
      locator: ResourceLocator[K]
  ): IO[Either[DenialReason, SelectedResource[K]]] =
    locator match
      case ResourceLocator.ConnectionRoot() =>
        if !kind.isRoot then IO.pure(Left(DenialReason.ResourceNotSelected))
        else
          catalog.rootScope(tenant, kind).map:
            case Some((externalId, scope)) => accept(tenant, kind, externalId, scope)
            case None                      => Left(DenialReason.ResourceNotSelected)
      case ResourceLocator.Selected(ref) =>
        // ExternalRef[K] carries its own kind; it must be the operation's declared kind.
        if !(ref.kind eq kind) then IO.pure(Left(DenialReason.ResourceNotSelected))
        else
          catalog.selectedScope(tenant, kind, ref.id).map:
            case Some(scope) => accept(tenant, kind, ref.id, scope)
            case None        => Left(DenialReason.ResourceNotSelected)

  /** Rejects a catalog answer that does not describe the requested resource. */
  private def accept[K](
      tenant: TenantId,
      kind: ResourceKind[K],
      externalId: ExternalId,
      scope: ResourceScope
  ): Either[DenialReason, SelectedResource[K]] =
    val consistent =
      scope.tenant == tenant &&
        scope.target.externalId == externalId.value &&
        scope.target.resourceType == kind.resourceType &&
        (kind.custody == Custody.Workspace || scope.custodian.nonEmpty)
    Either.cond(consistent, SelectedResource.trusted(kind, externalId, scope), DenialReason.ResourceNotSelected)
