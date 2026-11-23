package run.hallpass.adapters.postgres

import java.time.Instant
import java.util.UUID
import cats.effect.{IO, Resource as EffectResource}
import cats.syntax.all.*
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.implicits.javatimedrivernative.*
import org.typelevel.doobie.postgres.implicits.*
import io.circe.Json
import io.circe.parser.parse
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*
import run.hallpass.kernel.authorization.AuthorizedCapability.*

/** PostgreSQL implementation of the control plane. Every public operation establishes transaction-local tenant
  * context before touching tenant data.
  */
final class PostgresControlPlane(xa: Transactor[IO], clock: Clock[IO] = Clock.system)
    extends AgentRepository[IO],
      AuthorityRepository[IO],
      TrustedToolLookup[IO],
      DelegationRepository[IO],
      AuthorizationJournal[IO],
      ControlPlaneCatalog[IO],
      ResourceCatalog,
      TenantNames:

  private def tenantProgram[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(xa)

  def nameOf(tenant: TenantId): IO[Option[String]] = tenantProgram(tenant):
    sql"select name from tenants where id = ${tenant.toString}::uuid".query[String].option

  def create(tenant: TenantId, request: CreateAgent): IO[Either[AgentError, Agent]] =
    request.name.trim match
      case ""   => IO.pure(Left(AgentError.InvalidName))
      case name =>
        clock.now.flatMap: now =>
          val id = AgentId.random()
          tenantProgram(tenant):
            for
              _ <-
                sql"insert into principals (id, tenant_id, kind) values (${id.toString}::uuid, ${tenant.toString}::uuid, 'AGENT')".update.run
              _ <-
                sql"insert into agents (tenant_id, principal_id, name, description, created_at) values (${tenant.toString}::uuid, ${id.toString}::uuid, $name, ${request.description}, $now)".update.run
            yield Right(Agent(id, name, request.description, now))
          .handleError(_ => Left(AgentError.PersistenceFailure))

  def find(tenant: TenantId, id: AgentId): IO[Option[Agent]] = tenantProgram(tenant):
    sql"select principal_id, name, description, created_at from agents where tenant_id = ${tenant.toString}::uuid and principal_id = ${id.toString}::uuid"
      .query[(UUID, String, Option[String], Instant)]
      .option
      .map(_.flatMap(agentFromRow))

  def list(tenant: TenantId): IO[Vector[Agent]] = tenantProgram(tenant):
    sql"select principal_id, name, description, created_at from agents where tenant_id = ${tenant.toString}::uuid order by created_at"
      .query[(UUID, String, Option[String], Instant)]
      .to[Vector]
      .map(_.flatMap(agentFromRow))

  def resources(tenant: TenantId): IO[Vector[CatalogResource]] = tenantProgram(tenant):
    sql"select id, resource_type, parent_resource_id, external_id, coalesce(name, external_id), provider from resources where tenant_id = ${tenant.toString}::uuid and resource_type <> 'TOOL' order by created_at"
      .query[(UUID, String, Option[UUID], Option[String], String, Option[String])]
      .to[Vector]
      .map(_.flatMap(resourceFromRow(tenant)))

  def capabilities(tenant: TenantId): IO[Vector[CatalogCapability]] = tenantProgram(tenant):
    sql"""select c.id, c.namespace || '.' || c.name, c.resource_id, c.action
             from capabilities c
            where c.tenant_id = ${tenant.toString}::uuid and c.resource_id is not null and c.action is not null
            order by c.namespace, c.name"""
      .query[(UUID, String, UUID, String)]
      .to[Vector]
      .map(_.flatMap(capabilityFromRow))

  def tools(tenant: TenantId): IO[Vector[CatalogTool]] = tenantProgram(tenant):
    sql"""select tr.external_id, coalesce(tr.name, tr.external_id), tr.parent_resource_id,
                  c.id, c.namespace || '.' || c.name, c.action, m.mapping_source, m.trusted
             from tools t join resources tr on tr.tenant_id=t.tenant_id and tr.id=t.resource_id
             left join tool_capability_mappings m on m.tenant_id=t.tenant_id and m.tool_id=t.resource_id
             left join capabilities c on c.tenant_id=m.tenant_id and c.id=m.capability_id
            where t.tenant_id=${tenant.toString}::uuid order by tr.external_id"""
      .query[
        (
            Option[String],
            String,
            Option[UUID],
            Option[UUID],
            Option[String],
            Option[String],
            Option[String],
            Option[Boolean]
        )
      ]
      .to[Vector]
      .map(_.flatMap(toolFromRow))

  def snapshotFor(
      tenant: TenantId,
      principal: Principal,
      externalTool: String
  ): IO[Either[AuthorityLoadError, AuthoritySnapshot]] = loadSnapshot(tenant, principal, externalTool, None)

  def snapshotWithin(
      tenant: TenantId,
      principal: Principal,
      externalTool: String,
      scope: ResourceScope
  ): IO[Either[AuthorityLoadError, AuthoritySnapshot]] = loadSnapshot(tenant, principal, externalTool, Some(scope))

  private def loadSnapshot(
      tenant: TenantId,
      principal: Principal,
      externalTool: String,
      requested: Option[ResourceScope]
  ): IO[Either[AuthorityLoadError, AuthoritySnapshot]] =
    tenantProgram(tenant):
      trustedMapping(tenant, externalTool).flatMap:
        case Left(error) => error.asLeft[AuthoritySnapshot].pure[ConnectionIO]
        // A resolved scope must lie under the tool's mapped catalog resource, in this tenant; otherwise the mapping
        // does not apply there.
        case Right((mapped, _, _))
            if requested.exists(scope => scope.tenant != tenant || !scope.covers(mapped.target.id)) =>
          AuthorityLoadError.InvalidStoredAuthority.asLeft[AuthoritySnapshot].pure[ConnectionIO]
        case Right((mapped, capability, toolResourceId)) =>
          requested.fold(defaultScope(tenant, mapped))(_.pure[ConnectionIO]).flatMap: scope =>
            loadDelegationChain(tenant, principal, capability, scope).flatMap:
              case Left(error) => error.asLeft[AuthoritySnapshot].pure[ConnectionIO]
              case Right(delegations) =>
                val root = delegations.headOption.fold(principal)(_.grantor)
                loadPolicies(tenant, root, scope, capability.descriptor.action).map:
                  _.map(policies => AuthoritySnapshot(scope, capability, Policies(policies), delegations, Some(toolResourceId)))
    .handleError(_ => Left(AuthorityLoadError.PersistenceFailure))

  /** Without a resolved scope (the human preview path), a tool mapped on a provider's catalog resource is evaluated
    * at that provider's single active connection root, as execution resolves it; grants name roots, never the
    * catalog resource. With no active root, or more than one, the catalog scope stays, and no grant matches there. */
  private def defaultScope(tenant: TenantId, mapped: ResourceScope): ConnectionIO[ResourceScope] =
    if mapped.target.resourceType != ResourceType.Provider then mapped.pure[ConnectionIO]
    else
      sql"""select r.id from resources r join connections c on c.tenant_id=r.tenant_id and c.id=r.connection_id
             where r.tenant_id=${tenant.toString}::uuid and r.parent_resource_id=${mapped.target.id.toString}::uuid
               and r.connection_root and c.status in ('ACTIVE', 'NEEDS_REAUTH')"""
        .query[UUID]
        .to[Vector]
        .flatMap:
          case Vector(root) =>
            ResourceId.parse(root.toString).toOption match
              case Some(id) => loadScope(tenant, id, addressableOnly = true).map(_.getOrElse(mapped))
              case None     => mapped.pure[ConnectionIO]
          case _ => mapped.pure[ConnectionIO]

  /** The single root of `root`'s kind under an active connection. With more than one active root, choosing one would
    * be guessing, so `None`; with roots that are all inactive, `None` too, so a disconnect behaves like revocation.
    * Only a kind with no roots at all falls back to the provider's single top-level catalog resource (how Slack works
    * until it moves onto connection roots). */
  def rootScope(tenant: TenantId, root: ResourceKind[?]): IO[Option[(ExternalId, ResourceScope)]] =
    tenantProgram(tenant):
      sql"""select r.id, r.external_id, c.status in ('ACTIVE', 'NEEDS_REAUTH') from resources r
              join connections c on c.tenant_id = r.tenant_id and c.id = r.connection_id
             where r.tenant_id=${tenant.toString}::uuid and r.kind=${root.wire} and r.connection_root"""
        .query[(UUID, Option[String], Boolean)]
        .to[Vector]
        .flatMap:
          case Vector() if root.custody == Custody.Workspace =>
            sql"""select id, external_id from resources
                   where tenant_id=${tenant.toString}::uuid and resource_type='PROVIDER' and kind is null
                     and provider=${root.provider.value} and parent_resource_id is null"""
              .query[(UUID, Option[String])]
              .to[Vector]
              .flatMap(rootWithScope(tenant, _, addressable = false))
          case roots =>
            rootWithScope(tenant, roots.collect { case (id, external, true) => (id, external) }, addressable = true)

  private def rootWithScope(
      tenant: TenantId,
      candidates: Vector[(UUID, Option[String])],
      addressable: Boolean
  ): ConnectionIO[Option[(ExternalId, ResourceScope)]] =
    candidates match
      case Vector((id, Some(external))) =>
        (ResourceId.parse(id.toString).toOption, ExternalId.parse(external)) match
          case (Some(resource), Some(externalId)) =>
            loadScope(tenant, resource, addressable).map(_.toOption.map(externalId -> _))
          case _ => Option.empty[(ExternalId, ResourceScope)].pure[ConnectionIO]
      // None, or more than one candidate: choosing one would be guessing.
      case _ => Option.empty[(ExternalId, ResourceScope)].pure[ConnectionIO]

  /** The resource of `kind` with `externalId` whose whole path is currently addressable. The same external resource
    * can have rows under several connections over time (a reconnect makes a new row); at most one can be addressable,
    * and more than one is ambiguous, so `None`. */
  def selectedScope(tenant: TenantId, kind: ResourceKind[?], externalId: ExternalId): IO[Option[ResourceScope]] =
    tenantProgram(tenant):
      sql"""select id from resources
             where tenant_id=${tenant.toString}::uuid and kind=${kind.wire} and external_id=${externalId.value}"""
        .query[UUID]
        .to[Vector]
        .flatMap: ids =>
          ids
            .flatMap(id => ResourceId.parse(id.toString).toOption)
            .traverse(resource => loadScope(tenant, resource, addressableOnly = true))
            .map(_.flatMap(_.toOption))
            .map:
              case Vector(scope) => Some(scope)
              case _             => None

  /** Argument-free discovery uses the same addressability rules as invocation resolution. Roots still require one
    * unambiguous connection; selected kinds enumerate every addressable target, so a child-only grant is visible. */
  override def discoveryScopes(tenant: TenantId, kind: ResourceKind[?]): IO[Vector[ResourceScope]] =
    discoveryTargets(tenant, kind).map(_.map(_.scope))

  override def discoveryTargets(tenant: TenantId, kind: ResourceKind[?]): IO[Vector[DiscoveryTarget]] =
    if kind.isRoot then rootScope(tenant, kind).map(_.map((_, scope) => DiscoveryTarget(scope, scope.target.externalId)).toVector)
    else
      tenantProgram(tenant):
        sql"""select id, name from resources
               where tenant_id=${tenant.toString}::uuid and kind=${kind.wire}
               order by id"""
          .query[(UUID, String)]
          .to[Vector]
          .flatMap: rows =>
            rows.traverse((id, name) =>
              ResourceId.parse(id.toString).toOption match
                case Some(resource) => loadScope(tenant, resource, addressableOnly = true).map(_.map(DiscoveryTarget(_, name)))
                case None => AuthorityLoadError.InvalidStoredAuthority.asLeft[DiscoveryTarget].pure[ConnectionIO]
            ).map(_.flatMap(_.toOption))

  /** A catalog resource (no kind) is always addressable; a connection resource only while its connection is active and
    * it and every non-root resource above it is selected. */
  def currentScope(tenant: TenantId, resource: ResourceId): IO[Option[ResourceScope]] =
    tenantProgram(tenant)(loadScope(tenant, resource, addressableOnly = true).map(_.toOption))

  def externalToolFor(
      tenant: TenantId,
      toolId: ResourceId
  ): IO[Either[AuthorityLoadError, ExternalToolId]] =
    tenantProgram(tenant):
      sql"""select external_id from resources
               where tenant_id=${tenant.toString}::uuid and id=${toolId.toString}::uuid and resource_type='TOOL'"""
        .query[Option[String]]
        .to[Vector]
        .map:
          case Vector(Some(value)) => ExternalToolId.parse(value).toRight(AuthorityLoadError.InvalidStoredAuthority)
          case Vector()            => Left(AuthorityLoadError.InvalidStoredAuthority)
          case _                   => Left(AuthorityLoadError.InvalidStoredAuthority)
    .handleError(_ => Left(AuthorityLoadError.PersistenceFailure))

  def create(tenant: TenantId, request: CreateDelegation): IO[Either[DelegationError, Delegation]] =
    clock.now.flatMap: now =>
      val id = DelegationId.random()
      val program = for
        capabilityRow <-
          sql"""select c.namespace || '.' || c.name, lower(r.provider)
                  from capabilities c join resources r on r.tenant_id=c.tenant_id and r.id=c.resource_id
                 where c.tenant_id=${tenant.toString}::uuid and c.id=${request.capabilityId}::uuid
                   and c.action=${actionWire(request.action)}"""
            .query[(String, Option[String])]
            .option
        capabilityKey = capabilityRow.flatMap((value, _) => CapabilityKey.parse(value).toOption)
        // The capability's key/action come from the trusted catalog row, while the target may be one selected child.
        // Current addressability is required so stale or deselected resources cannot receive a new delegation.
        scope <- loadScope(tenant, request.resource, addressableOnly = true)
        targetProvider <-
          sql"""select lower(provider) from resources
                 where tenant_id=${tenant.toString}::uuid and id=${request.resource.toString}::uuid"""
            .query[Option[String]]
            .option
            .map(_.flatten)
        // The target must be a connection root or a resource beneath one, of the capability's own provider. A grant on
        // the provider's catalog resource would cover every connection, including ones made after the grant.
        wellPlaced = capabilityRow.isEmpty || scope.isLeft || (
          scope.exists(_.target.resourceType != ResourceType.Provider) &&
            capabilityRow.flatMap(_._2).exists(provider => targetProvider.contains(provider))
        )
        authorized <- (request.grantor, capabilityKey, scope) match
          case _ if !wellPlaced => false.pure[ConnectionIO]
          case (grantor: Principal.Human, Some(key), Right(resourceScope)) =>
            grantorHasAuthority(tenant, grantor, resourceScope, key, request.action, now)
          // Chained delegation is intentionally not exposed by this API, and an unknown capability or resource
          // carries no authority to delegate.
          case _ => false.pure[ConnectionIO]
        result <-
          if !wellPlaced then DelegationError.InvalidRequest.asLeft[Delegation].pure[ConnectionIO]
          else if !authorized then DelegationError.GrantorLacksAuthority.asLeft[Delegation].pure[ConnectionIO]
          else
            for
              granteeExists <- principalExists(tenant, request.grantee)
              created <- (capabilityKey, DelegationConstraintsJson.encode(request.constraints)) match
                case (_, Left(_)) => DelegationError.InvalidRequest.asLeft[Delegation].pure[ConnectionIO]
                case (None, _) => DelegationError.InvalidRequest.asLeft[Delegation].pure[ConnectionIO]
                case (Some(_), _) if !granteeExists => DelegationError.InvalidRequest.asLeft[Delegation].pure[ConnectionIO]
                case (Some(key), Right(constraintsJson)) =>
                  val descriptor = CapabilityDescriptor(request.resource, request.action, key)
                  val delegation = Delegation(
                    id,
                    request.grantor,
                    request.grantee,
                    None,
                    NonEmptySet.one(descriptor),
                    request.constraints,
                    now,
                    request.expiresAt,
                    None
                  )
                  for
                    _ <- sql"""insert into delegations (id, tenant_id, grantor_principal_id, grantee_principal_id, valid_from, expires_at, constraints)
                             values (${id.toString}::uuid, ${tenant.toString}::uuid, ${principalId(
                        request.grantor
                      )}::uuid, ${principalId(request.grantee)}::uuid, $now, ${request.expiresAt}, ${constraintsJson.noSpaces}::jsonb)""".update.run
                    _ <- sql"""insert into delegated_capabilities (tenant_id, delegation_id, capability_id, resource_id, actions)
                             values (${tenant.toString}::uuid, ${id.toString}::uuid, ${request.capabilityId}::uuid, ${request.resource.toString}::uuid, ARRAY[${actionWire(
                        request.action
                      )}]::text[])""".update.run
                  yield Right(delegation)
            yield created
      yield result
      tenantProgram(tenant)(program).handleError(_ => Left(DelegationError.PersistenceFailure))

  def revoke(tenant: TenantId, id: DelegationId, at: Instant): IO[Either[DelegationError, Delegation]] =
    tenantProgram(tenant):
      loadDelegationById(tenant, id).flatMap:
        case None                                    => DelegationError.NotFound.asLeft[Delegation].pure[ConnectionIO]
        case Some(value) if value.revokedAt.nonEmpty =>
          DelegationError.AlreadyRevoked.asLeft[Delegation].pure[ConnectionIO]
        case Some(value) =>
          sql"update delegations set revoked_at=$at where tenant_id=${tenant.toString}::uuid and id=${id.toString}::uuid and revoked_at is null".update.run
            .map(_ => Right(value.copy(revokedAt = Some(at))))

  def listForGrantee(tenant: TenantId, grantee: Principal): IO[Vector[Delegation]] = tenantProgram(tenant):
    loadDelegations(tenant, fr"d.grantee_principal_id = ${principalId(grantee)}::uuid")

  def record(tenant: TenantId, event: AuthorizationEvent): IO[Unit] = tenantProgram(tenant):
    val (outcome, reason, policyId, version, delegationIds) = decisionFields(event.result)
    val decisionId = UUID.randomUUID().toString
    val evidence = Json
      .obj(
        "tool" -> Json.fromString(event.tool),
        "capability" -> event.capability.fold(Json.Null)(c =>
          Json.fromString(s"${c.resource}:${actionWire(c.action)}")
        ),
        "capabilityKey" -> event.capability.fold(Json.Null)(c => Json.fromString(c.capability.value)),
        "delegationIds" -> Json.arr(delegationIds.map(id => Json.fromString(id.toString))*)
      )
      .noSpaces
    for
      _ <- sql"""insert into authorization_requests (id, tenant_id, subject_principal_id, resource_id, action, authorization_source, correlation_id, requested_at)
                 values (${event.requestId.toString}::uuid, ${tenant.toString}::uuid, ${principalId(
          event.principal
        )}::uuid,
                         ${event.resource.map(_.toString)}::uuid, ${event.capability.map(c =>
          actionWire(c.action)
        )}, ${event.authorizationSource.wire}, ${event.correlationId}, ${event.occurredAt})""".update.run
      _ <-
        sql"""insert into authorization_decisions (id, tenant_id, request_id, outcome, reason_code, policy_id, policy_version, delegation_id, evidence, decided_at)
                 values ($decisionId::uuid, ${tenant.toString}::uuid, ${event.requestId.toString}::uuid, $outcome, $reason,
                         ${policyId.map(_.toString)}::uuid, ${version.map(_.toString.toInt)}, ${delegationIds.lastOption
            .map(_.toString)}::uuid, $evidence::jsonb, ${event.occurredAt})""".update.run
    yield ()

  def recent(tenant: TenantId, limit: Int): IO[Vector[AuthorizationRecord]] = tenantProgram(tenant):
    val safeLimit = limit.max(1).min(100)
    sql"""select r.id, r.subject_principal_id, p.kind, d.evidence->>'tool', r.resource_id, r.action,
                  d.evidence->>'capabilityKey', d.outcome, d.reason_code, d.policy_id, d.policy_version, d.delegation_id,
                  r.correlation_id, d.decided_at, r.authorization_source
             from authorization_decisions d join authorization_requests r on r.tenant_id=d.tenant_id and r.id=d.request_id
             join principals p on p.tenant_id=r.tenant_id and p.id=r.subject_principal_id
            where d.tenant_id=${tenant.toString}::uuid order by d.decided_at desc limit $safeLimit"""
      .query[
        (
            UUID,
            UUID,
            String,
            Option[String],
            Option[UUID],
            Option[String],
            Option[String],
            String,
            String,
            Option[UUID],
            Option[Int],
            Option[UUID],
            String,
            Instant,
            Option[String]
        )
      ]
      .to[Vector]
      .map(_.flatMap(recordFromRow))

  private def trustedMapping(
      tenant: TenantId,
      externalTool: String
  ): ConnectionIO[Either[AuthorityLoadError, (ResourceScope, CatalogCapability, ResourceId)]] =
    sql"""select tr.id, p.id, p.resource_type, p.parent_resource_id, p.external_id, coalesce(p.name, p.external_id), p.provider,
                  c.id, c.namespace || '.' || c.name, c.action
             from resources tr join tools t on t.tenant_id=tr.tenant_id and t.resource_id=tr.id
             join tool_capability_mappings m on m.tenant_id=t.tenant_id and m.tool_id=t.resource_id and m.trusted=true
             join capabilities c on c.tenant_id=m.tenant_id and c.id=m.capability_id
             join resources p on p.tenant_id=tr.tenant_id and p.id=tr.parent_resource_id
            where tr.tenant_id=${tenant.toString}::uuid and tr.external_id=$externalTool"""
      .query[(UUID, UUID, String, Option[UUID], Option[String], String, Option[String], UUID, String, String)]
      .to[Vector]
      .map:
        case Vector() => Left(AuthorityLoadError.UnmappedTool)
        case Vector(row) =>
          (for
            toolResourceId <- ResourceId.parse(row._1.toString).toOption
            resource <- resourceFromRow(tenant)((row._2, row._3, row._4, row._5, row._6, row._7)).headOption
            capability <- capabilityFromRow((row._8, row._9, row._2, row._10))
            if capability.descriptor.resource == resource.resource.id
          yield (resource.resource, capability, toolResourceId)).toRight(AuthorityLoadError.InvalidStoredAuthority)
        case _ => Left(AuthorityLoadError.AmbiguousMapping)
      .flatMap:
        case Left(error) => error.asLeft.pure[ConnectionIO]
        case Right((resource, capability, toolResourceId)) =>
          loadScope(tenant, resource.id).map(_.map(scope => (scope, capability, toolResourceId)))

  /** The trusted path from a resource to its root, read from `parent_resource_id`. At most one row more than the
    * kernel's maximum depth is read, so an over-deep or cyclic path reaches the kernel's validation and fails closed
    * instead of looping.
    *
    * Custody comes from `custodian_principal_id` and must name a HUMAN principal of this tenant; anything else is an
    * invalid stored path. With `addressableOnly`, the same statement also reports, per path element, whether it is
    * addressable (a catalog resource always; a connection resource only while its connection is ACTIVE or NEEDS_REAUTH: a credential that must be reauthorized is unavailable, not revoked authority, so the call fails at credential acquisition as CONNECTION_UNAVAILABLE and, unless it
    * is the connection root, it has an open selection). A path with any unaddressable element, or no row at all, is
    * refused (`InvalidStoredAuthority`); callers of the addressable forms only ever read that as `None`. */
  private def loadScope(
      tenant: TenantId,
      resource: ResourceId,
      addressableOnly: Boolean = false
  ): ConnectionIO[Either[AuthorityLoadError, ResourceScope]] =
    sql"""with recursive ancestry(id, resource_type, parent_resource_id, external_id, kind, connection_id, connection_root,
                                   custodian_principal_id, depth) as (
             select id, resource_type, parent_resource_id, external_id, kind, connection_id, connection_root,
                    custodian_principal_id, 1
               from resources where tenant_id=${tenant.toString}::uuid and id=${resource.toString}::uuid
             union all
             select r.id, r.resource_type, r.parent_resource_id, r.external_id, r.kind, r.connection_id, r.connection_root,
                    r.custodian_principal_id, a.depth + 1
               from resources r join ancestry a on r.id = a.parent_resource_id
              where r.tenant_id=${tenant.toString}::uuid and a.depth <= ${ResourceScope.MaximumDepth}
           )
           select a.id, a.resource_type, a.parent_resource_id, a.external_id, a.custodian_principal_id, p.kind,
                  a.kind is null or (
                    exists (select 1 from connections c
                             where c.tenant_id=${tenant.toString}::uuid and c.id = a.connection_id and c.status in ('ACTIVE', 'NEEDS_REAUTH'))
                    and (a.connection_root or exists (
                           select 1 from connection_resources s
                            where s.tenant_id=${tenant.toString}::uuid and s.resource_id = a.id and s.deselected_at is null))
                  )
             from ancestry a
             left join principals p on p.tenant_id=${tenant.toString}::uuid and p.id = a.custodian_principal_id
            order by a.depth"""
      .query[(UUID, String, Option[UUID], Option[String], Option[UUID], Option[String], Boolean)]
      .to[Vector]
      .map: rows =>
        if addressableOnly && (rows.isEmpty || rows.exists(!_._7)) then Left(AuthorityLoadError.InvalidStoredAuthority)
        else
          rows
            .traverse(row => scopeResourceFromRow(tenant)((row._1, row._2, row._3, row._4, row._5, row._6)).toRight(AuthorityLoadError.InvalidStoredAuthority))
            .flatMap(path => ResourceScope.fromPath(path).left.map(_ => AuthorityLoadError.InvalidStoredAuthority))

  /** Scopes for every resource a delegation chain names, for attenuation checks. */
  private def loadScopes(
      tenant: TenantId,
      resources: Set[ResourceId]
  ): ConnectionIO[Either[AuthorityLoadError, Map[ResourceId, ResourceScope]]] =
    resources.toVector
      .traverse(resource => loadScope(tenant, resource).map(_.map(resource -> _)))
      .map(_.sequence.map(_.toMap))

  /**
    * Load exactly one leaf delegation, then follow its declared parent references to the root.  We deliberately do
    * not concatenate independently matching grants: that would turn a set of alternatives into one asserted chain.
    */
  private def loadDelegationChain(
      tenant: TenantId,
      principal: Principal,
      capability: CatalogCapability,
      scope: ResourceScope
  ): ConnectionIO[Either[AuthorityLoadError, Vector[Delegation]]] =
    // A provider's catalog resource sits above every connection root of that provider, including roots connected
    // after a grant was made. Delegations name a connection root or a selected child, never the catalog resource,
    // so a stored grant on it confers nothing.
    val grantable = scope.path.filterNot(_.resourceType == ResourceType.Provider).map(_.id.toString).toList
    sql"""select d.id,
                  d.revoked_at is null and d.valid_from <= current_timestamp and
                    (d.expires_at is null or d.expires_at > current_timestamp),
                  d.created_at
             from delegations d join delegated_capabilities dc
               on dc.tenant_id=d.tenant_id and dc.delegation_id=d.id
            where d.tenant_id=${tenant.toString}::uuid
              and d.grantee_principal_id=${principalId(principal)}::uuid
              and dc.capability_id=${capability.id}::uuid
              and dc.resource_id = any($grantable::uuid[])
              and ${actionWire(capability.descriptor.action)} = any(dc.actions)
            order by d.created_at desc, d.id desc"""
      .query[(UUID, Boolean, Instant)]
      .to[Vector]
      .map: rows =>
        val candidates = rows.distinctBy(_._1)
        val currentlyValid = candidates.filter(_._2).map(_._1)
        if currentlyValid.nonEmpty then currentlyValid else candidates.headOption.map(_._1).toVector
      .flatMap:
        case Vector() => Right(Vector.empty).pure[ConnectionIO]
        case Vector(leaf) =>
          def follow(
              id: UUID,
              seen: Set[UUID],
              reverse: Vector[Delegation]
          ): ConnectionIO[Either[AuthorityLoadError, Vector[Delegation]]] =
            if seen.contains(id) || seen.size >= 32 then
              Left(AuthorityLoadError.InvalidStoredAuthority).pure[ConnectionIO]
            else
              DelegationId.parse(id.toString).toOption match
                case None => Left(AuthorityLoadError.InvalidStoredAuthority).pure[ConnectionIO]
                case Some(parsedId) =>
                  loadDelegationStrictById(tenant, parsedId).flatMap:
                    case None => Left(AuthorityLoadError.InvalidStoredAuthority).pure[ConnectionIO]
                    case Some(delegation) =>
                      val next = delegation +: reverse
                      delegation.parent match
                        case None =>
                          val named = next.flatMap(_.capabilities.toSet.map(_.resource)).toSet
                          loadScopes(tenant, named).map(_.flatMap: scopes =>
                            val linked = next.lastOption.exists(_.grantee == principal) &&
                              scopes.values.forall(_.target.resourceType != ResourceType.Provider) &&
                              next.zip(next.drop(1)).forall:
                                case (parent, child) => Delegation.validateChild(parent, child, scopes.get).isRight
                            Either.cond(linked, next, AuthorityLoadError.InvalidStoredAuthority))
                        case Some(parent) => follow(UUID.fromString(parent.toString), seen + id, next)
          follow(leaf, Set.empty, Vector.empty)
        case _ => Left(AuthorityLoadError.InvalidStoredAuthority).pure[ConnectionIO]

  private def loadDelegationById(tenant: TenantId, id: DelegationId): ConnectionIO[Option[Delegation]] =
    loadDelegations(tenant, fr"d.id=${id.toString}::uuid").map(_.headOption)

  private def loadDelegations(tenant: TenantId, predicate: Fragment): ConnectionIO[Vector[Delegation]] =
    loadDelegationsStrict(tenant, predicate).map(_.getOrElse(Vector.empty))

  private type DelegationRow =
    (
        UUID,
        UUID,
        String,
        UUID,
        String,
        Option[UUID],
        String,
        UUID,
        List[String],
        Instant,
        Option[Instant],
        Option[Instant],
        String
    )

  private def loadDelegationStrictById(tenant: TenantId, id: DelegationId): ConnectionIO[Option[Delegation]] =
    loadDelegationsStrict(tenant, fr"d.id=${id.toString}::uuid").map(_.toOption.flatMap(_.headOption))

  /** Decode every stored capability row. Non-empty JSON constraints are rejected until they have a full typed
    * representation; treating them as empty would make a persisted restriction disappear. */
  private def loadDelegationsStrict(
      tenant: TenantId,
      predicate: Fragment
  ): ConnectionIO[Either[AuthorityLoadError, Vector[Delegation]]] =
    (fr"""select d.id, d.grantor_principal_id, gp.kind, d.grantee_principal_id, ep.kind, d.parent_delegation_id,
                 d.constraints::text, dc.resource_id, dc.actions, d.valid_from, d.expires_at, d.revoked_at,
                 c.namespace || '.' || c.name
            from delegations d join principals gp on gp.tenant_id=d.tenant_id and gp.id=d.grantor_principal_id
            join principals ep on ep.tenant_id=d.tenant_id and ep.id=d.grantee_principal_id
            join delegated_capabilities dc on dc.tenant_id=d.tenant_id and dc.delegation_id=d.id
            join capabilities c on c.tenant_id=dc.tenant_id and c.id=dc.capability_id
           where d.tenant_id=${tenant.toString}::uuid and """ ++ predicate ++ fr" order by d.created_at asc, d.id asc")
      .query[DelegationRow]
      .to[Vector]
      .map: rows =>
        rows.groupBy(_._1).toVector.foldLeft[Either[AuthorityLoadError, Vector[Delegation]]](Right(Vector.empty)):
          case (Right(decoded), (_, grouped)) => delegationFromRows(grouped).map(decoded :+ _)
          case (left @ Left(_), _) => left

  private def delegationFromRows(rows: Vector[DelegationRow]): Either[AuthorityLoadError, Delegation] =
    rows.headOption.toRight(AuthorityLoadError.InvalidStoredAuthority).flatMap: first =>
      val consistentHeader = rows.forall: row =>
        row._1 == first._1 && row._2 == first._2 && row._3 == first._3 && row._4 == first._4 &&
          row._5 == first._5 && row._6 == first._6 && row._7 == first._7 && row._10 == first._10 &&
          row._11 == first._11 && row._12 == first._12
      for
        _ <- Either.cond(consistentHeader, (), AuthorityLoadError.InvalidStoredAuthority)
        id <- DelegationId.parse(first._1.toString).left.map(_ => AuthorityLoadError.InvalidStoredAuthority)
        grantor <- principalFromRow(first._2, first._3).toRight(AuthorityLoadError.InvalidStoredAuthority)
        grantee <- principalFromRow(first._4, first._5).toRight(AuthorityLoadError.InvalidStoredAuthority)
        parent <- first._6.traverse(value => DelegationId.parse(value.toString).left.map(_ => AuthorityLoadError.InvalidStoredAuthority))
        constraints <- constraintsFromJson(first._7)
        decodedCapabilities <- rows.foldLeft[Either[AuthorityLoadError, Set[CapabilityDescriptor]]](Right(Set.empty)):
          case (Right(decoded), row) =>
            for
              resource <- ResourceId.parse(row._8.toString).left.map(_ => AuthorityLoadError.InvalidStoredAuthority)
              key <- CapabilityKey.parse(row._13).left.map(_ => AuthorityLoadError.InvalidStoredAuthority)
              actions <- row._9.foldLeft[Either[AuthorityLoadError, Set[Action]]](Right(Set.empty)):
                case (Right(parsed), wire) =>
                  actionFromWire(wire).toRight(AuthorityLoadError.InvalidStoredAuthority).map(parsed + _)
                case (left @ Left(_), _) => left
              _ <- Either.cond(actions.nonEmpty, (), AuthorityLoadError.InvalidStoredAuthority)
            yield decoded ++ actions.map(action => CapabilityDescriptor(resource, action, key))
          case (left @ Left(_), _) => left
        capabilities <- NonEmptySet.from(decodedCapabilities).toRight(AuthorityLoadError.InvalidStoredAuthority)
        _ <- Either.cond(first._11.forall(_.isAfter(first._10)), (), AuthorityLoadError.InvalidStoredAuthority)
        _ <- Either.cond(first._12.forall(!_.isBefore(first._10)), (), AuthorityLoadError.InvalidStoredAuthority)
      yield Delegation(id, grantor, grantee, parent, capabilities, constraints, first._10, first._11, first._12)

  /** Policies bound to the subject on the target or any of its trusted ancestors. The kernel decides which of them
    * cover the request; a deny bound to an ancestor therefore blocks every descendant. */
  private def loadPolicies(
      tenant: TenantId,
      subject: Principal,
      scope: ResourceScope,
      action: Action
  ): ConnectionIO[Either[AuthorityLoadError, Vector[Policy]]] =
    sql"""select p.id, p.version, p.definition::text, b.resource_id
             from policies p join policy_bindings b on b.tenant_id=p.tenant_id and b.policy_id=p.id
            where p.tenant_id=${tenant.toString}::uuid and p.status='ACTIVE'
              and b.subject_principal_id=${principalId(subject)}::uuid
              and b.resource_id = any(${scope.path.map(_.id.toString).toList}::uuid[])
            order by b.priority desc, p.id asc"""
      .query[(UUID, Int, String, UUID)]
      .to[Vector]
      .map(_.foldLeft[Either[AuthorityLoadError, Vector[Policy]]](Right(Vector.empty)):
        case (Right(decoded), row) =>
          ResourceId
            .parse(row._4.toString)
            .left
            .map(_ => AuthorityLoadError.InvalidStoredAuthority)
            .flatMap(resource => policyFromRow(subject, resource, action)((row._1, row._2, row._3)))
            .map(policy => decoded ++ policy.toVector)
        case (left @ Left(_), _) => left)

  private def constraintsFromJson(value: String): Either[AuthorityLoadError, Constraints] =
    parse(value).toOption
      .flatMap(DelegationConstraintsJson.decode(_).toOption)
      .toRight(AuthorityLoadError.InvalidStoredAuthority)

  /** The durable JSON language supports `action`, `effect`, and an optional non-empty `capabilities` allowlist of
    * capability keys. Any additional policy semantics must be decoded into the kernel type before it can influence
    * authorization, so an unknown field, an empty allowlist, or an invalid key rejects the policy. */
  private def policyFromRow(
      subject: Principal,
      resource: ResourceId,
      requiredAction: Action
  )(row: (UUID, Int, String)): Either[AuthorityLoadError, Option[Policy]] =
    for
      json <- parse(row._3).toOption.toRight(AuthorityLoadError.InvalidStoredAuthority)
      objectValue <- json.asObject.toRight(AuthorityLoadError.InvalidStoredAuthority)
      // PostgreSQL jsonb objects are unordered and Circe's key collection is representation-dependent. Counting the
      // known fields that are present is equivalent to accepting only those fields, while still rejecting extras.
      _ <- Either.cond(
        objectValue("action").isDefined && objectValue("effect").isDefined &&
          objectValue.keys.size == 2 + objectValue("capabilities").size,
        (),
        AuthorityLoadError.InvalidStoredAuthority
      )
      capabilities <- objectValue("capabilities").traverse(policyCapabilitiesFromJson)
      actionValue <- objectValue("action").flatMap(_.asString).flatMap(actionFromWire).toRight(AuthorityLoadError.InvalidStoredAuthority)
      effect <- objectValue("effect").flatMap(_.asString).flatMap(effectFromWire).toRight(AuthorityLoadError.InvalidStoredAuthority)
      policyId <- PolicyId.parse(row._1.toString).left.map(_ => AuthorityLoadError.InvalidStoredAuthority)
      policyVersion <- PolicyVersion.from(row._2).toRight(AuthorityLoadError.InvalidStoredAuthority)
    yield Option.when(actionValue == requiredAction)(
      Policy(
        policyId,
        policyVersion,
        NonEmptySet.one(
          PolicyStatement(subject, resource, NonEmptySet.one(actionValue), capabilities, Constraints.empty, effect)
        )
      )
    )

  private def policyCapabilitiesFromJson(json: Json): Either[AuthorityLoadError, NonEmptySet[CapabilityKey]] =
    for
      values <- json.asArray.toRight(AuthorityLoadError.InvalidStoredAuthority)
      keys <- values.traverse(value =>
        value.asString.toRight(AuthorityLoadError.InvalidStoredAuthority).flatMap(key =>
          CapabilityKey.parse(key).left.map(_ => AuthorityLoadError.InvalidStoredAuthority)
        )
      )
      allowlist <- NonEmptySet.from(keys.toSet).toRight(AuthorityLoadError.InvalidStoredAuthority)
    yield allowlist

  /** A human may delegate what the kernel would let them exercise directly (allowed, or allowed after approval). An
    * unreadable policy grants nothing. */
  private def grantorHasAuthority(
      tenant: TenantId,
      grantor: Principal.Human,
      scope: ResourceScope,
      capability: CapabilityKey,
      action: Action,
      at: Instant
  ): ConnectionIO[Boolean] =
    loadPolicies(tenant, grantor, scope, action).map:
      case Left(_)         => false
      case Right(policies) =>
        val request = AuthorizationRequest(
          AuthorizationRequestId.random(),
          tenant,
          IdentityChain.direct(grantor),
          scope,
          capability,
          action,
          AuthorizationContext.empty
        )
        AuthorizationEngine.evaluate(Policies(policies), request, Vector.empty, at) match
          case AuthorizationDecision.Allow(_) | AuthorizationDecision.RequireApproval(_) => true
          case AuthorizationDecision.Deny(_)                                              => false

  private def principalExists(tenant: TenantId, principal: Principal): ConnectionIO[Boolean] =
    sql"select exists(select 1 from principals where tenant_id=${tenant.toString}::uuid and id=${principalId(principal)}::uuid)"
      .query[Boolean]
      .unique

  private def agentFromRow(row: (UUID, String, Option[String], Instant)): Option[Agent] =
    AgentId.parse(row._1.toString).toOption.map(Agent(_, row._2, row._3, row._4))
  private def resourceFromRow(
      tenant: TenantId
  )(row: (UUID, String, Option[UUID], Option[String], String, Option[String])): Vector[CatalogResource] =
    (for
      id <- ResourceId.parse(row._1.toString).toOption
      kind <- resourceTypeFromWire(row._2)
      parent <- row._3.traverse(value => ResourceId.parse(value.toString).toOption)
    yield CatalogResource(Resource(id, tenant, kind, parent, row._4.getOrElse(""), custodian = None), row._5, row._6)).toVector
  /** A path element with its custodian. Custody is `Some(human)` only when the stored custodian is a HUMAN principal;
    * a custodian of any other kind makes the row invalid (fail closed). */
  private def scopeResourceFromRow(
      tenant: TenantId
  )(row: (UUID, String, Option[UUID], Option[String], Option[UUID], Option[String])): Option[Resource] =
    for
      id <- ResourceId.parse(row._1.toString).toOption
      kind <- resourceTypeFromWire(row._2)
      parent <- row._3.traverse(value => ResourceId.parse(value.toString).toOption)
      custodian <- (row._5, row._6) match
        case (None, _)                 => Some(None)
        case (Some(user), Some("HUMAN")) => UserId.parse(user.toString).toOption.map(id => Some(Principal.Human(id)))
        case _                         => None
    yield Resource(id, tenant, kind, parent, row._4.getOrElse(""), custodian)
  private def capabilityFromRow(row: (UUID, String, UUID, String)): Option[CatalogCapability] = for
    resource <- ResourceId.parse(row._3.toString).toOption
    action <- actionFromWire(row._4)
    key <- CapabilityKey.parse(row._2).toOption
  yield CatalogCapability(row._1.toString, row._2, CapabilityDescriptor(resource, action, key))
  private def toolFromRow(
      row: (
          Option[String],
          String,
          Option[UUID],
          Option[UUID],
          Option[String],
          Option[String],
          Option[String],
          Option[Boolean]
      )
  ): Option[CatalogTool] = for
    name <- row._1
    resourceUuid <- row._3
    resource <- ResourceId.parse(resourceUuid.toString).toOption
  yield
    val capability = for
      id <- row._4; label <- row._5; actionName <- row._6; action <- actionFromWire(actionName)
      key <- CapabilityKey.parse(label).toOption
    yield CatalogCapability(id.toString, label, CapabilityDescriptor(resource, action, key))
    CatalogTool(name, row._2, resource, capability, row._7, row._8.getOrElse(false))

  private def recordFromRow(
      row: (
          UUID,
          UUID,
          String,
          Option[String],
          Option[UUID],
          Option[String],
          Option[String],
          String,
          String,
          Option[UUID],
          Option[Int],
          Option[UUID],
          String,
          Instant,
          Option[String]
      )
  ): Option[AuthorizationRecord] = for
    requestId <- AuthorizationRequestId.parse(row._1.toString).toOption
    principal <- principalFromRow(row._2, row._3)
    resource <- row._5.traverse(value => ResourceId.parse(value.toString).toOption)
    outcome <- outcomeFromWire(row._8)
    policyId <- row._10.traverse(value => PolicyId.parse(value.toString).toOption)
    policyVersion <- row._11.traverse(PolicyVersion.from)
    delegation <- row._12.traverse(value => DelegationId.parse(value.toString).toOption)
  yield AuthorizationRecord(
    requestId,
    principal,
    row._4.getOrElse("unknown"),
    resource,
    row._6.flatMap(actionFromWire),
    row._7.flatMap(value => CapabilityKey.parse(value).toOption),
    outcome,
    row._9,
    policyId,
    policyVersion,
    delegation.toVector,
    row._13,
    row._14,
    row._15.flatMap(AuthorizationSource.fromWire)
  )

  private def principalFromRow(id: UUID, kind: String): Option[Principal] = kind match
    case "HUMAN"   => UserId.parse(id.toString).toOption.map(Principal.Human.apply)
    case "AGENT"   => AgentId.parse(id.toString).toOption.map(Principal.Agent.apply)
    case "SERVICE" => ServiceId.parse(id.toString).toOption.map(Principal.Service.apply)
    case _         => None
  private def principalId(principal: Principal): String = principal match
    case Principal.Human(id)   => id.toString
    case Principal.Agent(id)   => id.toString
    case Principal.Service(id) => id.toString
  private def actionWire(action: Action): String = action.toString.toUpperCase
  private def actionFromWire(value: String): Option[Action] = Action.values.find(_.toString.equalsIgnoreCase(value))
  private def effectFromWire(value: String): Option[Effect] = value match
    case "ALLOW"            => Some(Effect.Allow)
    case "DENY"             => Some(Effect.Deny)
    case "REQUIRE_APPROVAL" => Some(Effect.RequireApproval)
    case _                  => None
  private def resourceTypeFromWire(value: String): Option[ResourceType] = value match
    case "PROVIDER"   => Some(ResourceType.Provider)
    case "ACCOUNT"    => Some(ResourceType.Account)
    case "TOOL"       => Some(ResourceType.Tool)
    case "MCP_SERVER" => Some(ResourceType.McpServer)
    case "API"        => Some(ResourceType.Api)
    case "DATABASE"   => Some(ResourceType.Database)
    case "REPOSITORY" => Some(ResourceType.Repository)
    case "CHANNEL"    => Some(ResourceType.Channel)
    case "DOCUMENT"   => Some(ResourceType.Document)
    case "TEAM"       => Some(ResourceType.Team)
    case "CUSTOM"     => Some(ResourceType.Custom)
    case _            => None
  private def outcomeFromWire(value: String): Option[RecordedOutcome] = value match
    case "ALLOW"            => Some(RecordedOutcome.Allow)
    case "DENY"             => Some(RecordedOutcome.Deny)
    case "REQUIRE_APPROVAL" => Some(RecordedOutcome.RequireApproval)
    case _                  => None
  private def decisionFields(
      result: AuthorizationResult
  ): (String, String, Option[PolicyId], Option[PolicyVersion], Vector[DelegationId]) = result match
    case AuthorizationResult.Authorized(capability) =>
      (
        "ALLOW",
        "authorized",
        Some(capability.evidence.policyId),
        Some(capability.evidence.policyVersion),
        capability.evidence.delegationIds
      )
    case AuthorizationResult.Denied(reason)            => ("DENY", reason.toString, None, None, Vector.empty)
    case AuthorizationResult.ApprovalRequired(request) =>
      ("REQUIRE_APPROVAL", "approval_required", Some(request.policyId), Some(request.policyVersion), Vector.empty)

object PostgresControlPlane:
  /** Composition-root resource that keeps Doobie's transactor capability inside the adapter module and installs
    * explicit development fixtures.
    */
  def demoResource(config: DatabaseConfig): EffectResource[IO, PostgresControlPlane] =
    PostgresDatabase.resource(config).evalTap(DemoBootstrap.run).map(new PostgresControlPlane(_))

/** Adapter-owned composition root keeps Doobie's Transactor out of the gateway. */
final case class DemoRepositories(
    controlPlane: PostgresControlPlane,
    connections: PostgresConnectionRepository,
    connectionResources: PostgresConnectionResources,
    oauthStates: PostgresOAuthStateRepository,
    agentCredentials: PostgresAgentCredentials,
    executionAudit: PostgresExecutionAudit,
    directory: PostgresIdentityDirectory,
    browserSessions: PostgresBrowserSessions,
    providerSecrets: PostgresProviderSecrets,
    agentAuthenticationLockout: PostgresAgentAuthenticationLockout,
    approvals: PostgresApprovalStore,
    /** Resolves a lease's connection for credential strategies, reading secrets from the given store. */
    providerConnections: SecretStore[IO] => ProviderConnectionResolver,
    /** The refresh single-flight repository. Acquired only when a refreshable provider is configured, because
      * it opens a dedicated lock pool. */
    oauthRefresh: EffectResource[IO, PostgresOAuthRefreshRepository],
    /** Readiness probe for the repository pool and schema version. */
    schemaReady: IO[Boolean]
)
object DemoRepositories:
  /** In-process (development) mode also seeds the demo tenant, because the API role is the schema owner there. External
    * mode never writes tenants, the catalog, or the directory: tenants are created by `HallpassProvisionMain`. */
  def resource(config: DatabaseConfig, mode: MigrationMode = MigrationMode.InProcess): EffectResource[IO, DemoRepositories] =
    PostgresDatabase
      .resourceWithSchema(config, mode)
      .evalTap((xa, _) => IO.whenA(mode == MigrationMode.InProcess)(DemoBootstrap.run(xa)))
      .map: (xa, version) =>
        DemoRepositories(
          new PostgresControlPlane(xa),
          new PostgresConnectionRepository(xa),
          new PostgresConnectionResources(xa),
          new PostgresOAuthStateRepository(xa),
          new PostgresAgentCredentials(xa),
          new PostgresExecutionAudit(xa),
          new PostgresIdentityDirectory(xa),
          new PostgresBrowserSessions(xa),
          new PostgresProviderSecrets(xa),
          new PostgresAgentAuthenticationLockout(xa),
          new PostgresApprovalStore(xa),
          secrets => new RepositoryProviderConnectionResolver(xa, secrets),
          PostgresOAuthRefreshRepository.resource(config, xa),
          PostgresDatabase.schemaAtLeast(xa, version)
        )

/** Replaceable, idempotent development fixture; deliberately not a migration. It provisions one tenant with fixed
  * identifiers through [[TenantProvisioning]], so the local demo exercises the same rows production provisioning
  * writes. */
object DemoBootstrap:
  val Tenant: TenantId = TenantId.parse("10000000-0000-4000-8000-000000000001").toOption.get
  val Human: Principal.Human = Principal.Human(UserId.parse("10000000-0000-4000-8000-000000000002").toOption.get)
  val AdministratorUser: DirectoryUserId = DirectoryUserId.parse("10000000-0000-4000-8000-000000000003").toOption.get
  val SlackResource: ResourceId = ResourceId.parse("10000000-0000-4000-8000-000000000005").toOption.get

  /** The identity the development bootstrap login signs in as. It exists only in databases this fixture seeded. */
  val DevelopmentAdministrator: ExternalIdentity =
    ExternalIdentity.from("urn:hallpass:development", "local-administrator").toOption.get

  private val Request =
    TenantProvisioningRequest.from("Demo workspace", "demo", DevelopmentAdministrator).toOption.get

  private val Ids = ProvisioningIds(
    Tenant,
    AdministratorUser,
    Human.id,
    SlackResource,
    UUID.fromString("10000000-0000-4000-8000-000000000010"),
    UUID.fromString("10000000-0000-4000-8000-000000000011"),
    UUID.fromString("10000000-0000-4000-8000-000000000012"),
    UUID.fromString("10000000-0000-4000-8000-000000000013"),
    UUID.fromString("10000000-0000-4000-8000-000000000014"),
    UUID.fromString("10000000-0000-4000-8000-000000000015"),
    UUID.fromString("10000000-0000-4000-8000-000000000016"),
    UUID.fromString("10000000-0000-4000-8000-000000000017"),
    GitHubCatalogIds(
      ResourceId.parse("10000000-0000-4000-8000-000000000018").toOption.get,
      UUID.fromString("10000000-0000-4000-8000-000000000019"),
      UUID.fromString("10000000-0000-4000-8000-000000000020"),
      UUID.fromString("10000000-0000-4000-8000-000000000021"),
      UUID.fromString("10000000-0000-4000-8000-000000000022"),
      UUID.fromString("10000000-0000-4000-8000-000000000023"),
      UUID.fromString("10000000-0000-4000-8000-000000000024"),
      UUID.fromString("10000000-0000-4000-8000-000000000025"),
      UUID.fromString("10000000-0000-4000-8000-000000000026"),
      UUID.fromString("10000000-0000-4000-8000-000000000027"),
      UUID.fromString("10000000-0000-4000-8000-000000000028"),
      UUID.fromString("10000000-0000-4000-8000-000000000029"),
      UUID.fromString("10000000-0000-4000-8000-000000000030")
    ),
    LinearCatalogIds(
      ResourceId.parse("10000000-0000-4000-8000-000000000031").toOption.get,
      UUID.fromString("10000000-0000-4000-8000-000000000032"),
      UUID.fromString("10000000-0000-4000-8000-000000000033"),
      UUID.fromString("10000000-0000-4000-8000-000000000034"),
      UUID.fromString("10000000-0000-4000-8000-000000000035"),
      UUID.fromString("10000000-0000-4000-8000-000000000036"),
      UUID.fromString("10000000-0000-4000-8000-000000000037"),
      UUID.fromString("10000000-0000-4000-8000-000000000038"),
      UUID.fromString("10000000-0000-4000-8000-000000000039"),
      UUID.fromString("10000000-0000-4000-8000-000000000040")
    ),
    NotionCatalogIds(
      ResourceId.parse("10000000-0000-4000-8000-000000000041").toOption.get,
      UUID.fromString("10000000-0000-4000-8000-000000000042"),
      UUID.fromString("10000000-0000-4000-8000-000000000043"),
      UUID.fromString("10000000-0000-4000-8000-000000000044"),
      UUID.fromString("10000000-0000-4000-8000-000000000045"),
      UUID.fromString("10000000-0000-4000-8000-000000000046"),
      UUID.fromString("10000000-0000-4000-8000-000000000047"),
      UUID.fromString("10000000-0000-4000-8000-000000000048"),
      UUID.fromString("10000000-0000-4000-8000-000000000049"),
      UUID.fromString("10000000-0000-4000-8000-000000000050")
    ),
    GoogleCatalogIds(
      ResourceId.parse("10000000-0000-4000-8000-000000000051").toOption.get,
      UUID.fromString("10000000-0000-4000-8000-000000000052"),
      UUID.fromString("10000000-0000-4000-8000-000000000053"),
      UUID.fromString("10000000-0000-4000-8000-000000000054"),
      UUID.fromString("10000000-0000-4000-8000-000000000055"),
      UUID.fromString("10000000-0000-4000-8000-000000000056"),
      UUID.fromString("10000000-0000-4000-8000-000000000068"),
      UUID.fromString("10000000-0000-4000-8000-000000000069"),
      UUID.fromString("10000000-0000-4000-8000-000000000070"),
      UUID.fromString("10000000-0000-4000-8000-000000000071")
    ),
    HubSpotCatalogIds(
      ResourceId.parse("10000000-0000-4000-8000-000000000057").toOption.get,
      UUID.fromString("10000000-0000-4000-8000-000000000058"),
      UUID.fromString("10000000-0000-4000-8000-000000000059"),
      UUID.fromString("10000000-0000-4000-8000-000000000060"),
      UUID.fromString("10000000-0000-4000-8000-000000000061"),
      UUID.fromString("10000000-0000-4000-8000-000000000062"),
      UUID.fromString("10000000-0000-4000-8000-000000000063"),
      UUID.fromString("10000000-0000-4000-8000-000000000064"),
      UUID.fromString("10000000-0000-4000-8000-000000000065"),
      UUID.fromString("10000000-0000-4000-8000-000000000066"),
      UUID.fromString("10000000-0000-4000-8000-000000000067")
    )
  )

  def run(xa: Transactor[IO]): IO[Unit] = TenantProvisioning.program(Request, Ids).transact(xa).void
