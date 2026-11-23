package run.hallpass.adapters.postgres

import java.sql.SQLException
import java.time.Instant
import java.util.UUID
import cats.effect.IO
import cats.syntax.all.*
import org.postgresql.util.PSQLException
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.implicits.javatimedrivernative.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.application.*
import run.hallpass.kernel.*

/** Runtime writes to the resource hierarchy, over V17.
  *
  * The database is the authority on placement: the `resources` insert trigger admits only connection-scoped rows, under
  * an active connection, of a registered kind and provider, in their registered place and custody, and the
  * `connection_resources` indexes make at most one selection open per resource and per external resource. This class
  * never tries to work around a refusal. It maps the refusal, identified by SQLSTATE and the trigger's message or the
  * violated constraint, to an explicit error; an unrecognised database failure is `PersistenceFailure`, never a
  * success, and a failure that is not a SQL error is left to fail the effect.
  *
  * Every transaction establishes the tenant context first, so row-level security scopes each statement. Nothing here
  * is deleted: deselection closes the open selection and reselection opens a new one.
  */
final class PostgresConnectionResources(xa: Transactor[IO]) extends ConnectionResourceRepository:
  import PostgresConnectionResources.*

  private def tenantProgram[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(xa)

  /** Runs a write, turning recognised database refusals and any other SQL failure into explicit errors. */
  private def guarded[A](
      tenant: TenantId
  )(program: ConnectionIO[Either[ConnectionResourceError, A]]): IO[Either[ConnectionResourceError, A]] =
    tenantProgram(tenant)(program).recover:
      case failure: SQLException => Left(refusal(failure))

  def createRoot(
      tenant: TenantId,
      connection: ConnectionId,
      kind: ResourceKind[?],
      externalId: ExternalId,
      displayName: String,
      custodian: Option[UserId]
  ): IO[Either[ConnectionResourceError, ConnectionResource]] =
    if !kind.isRoot then IO.pure(Left(ConnectionResourceError.InvalidPlacement))
    else
      guarded(tenant):
        catalogResource(tenant, kind.provider).flatMap: catalog =>
          val id = ResourceId.random()
          // With no single catalog resource the parent is left empty and the trigger refuses the row, which also
          // reports an inactive connection or a kind of another provider ahead of the missing placement.
          sql"""insert into resources (id, tenant_id, resource_type, name, provider, parent_resource_id, external_id,
                                        kind, connection_id, custodian_principal_id)
                 values (${id.toString}::uuid, ${tenant.toString}::uuid, ${resourceTypeWire(kind.resourceType)},
                         $displayName, ${kind.provider.value}, ${catalog.map(_.toString)}::uuid, ${externalId.value},
                         ${kind.wire}, ${connection.toString}::uuid, ${custodian.map(_.toString)}::uuid)""".update.run
            .as:
              catalog match
                case Some(parent) =>
                  Right(ConnectionResource(id, connection, kind.wire, externalId, displayName, parent, custodian, None))
                // Unreachable: the trigger refuses a root without a catalog parent.
                case None => Left(ConnectionResourceError.PersistenceFailure)

  def select(
      tenant: TenantId,
      connection: ConnectionId,
      kind: ResourceKind[?],
      externalId: ExternalId,
      displayName: String,
      parent: ResourceId,
      selectedBy: Principal.Human,
      at: Instant
  ): IO[Either[ConnectionResourceError, ConnectionResource]] =
    if kind.isRoot then IO.pure(Left(ConnectionResourceError.InvalidPlacement))
    else
      guarded(tenant):
        sql"select custodian_principal_id from resources where tenant_id=${tenant.toString}::uuid and id=${parent.toString}::uuid"
          .query[Option[UUID]]
          .option
          .flatMap:
            case None => ConnectionResourceError.InvalidPlacement.asLeft[ConnectionResource].pure[ConnectionIO]
            case Some(parentCustodian) =>
              val fresh = ResourceId.random()
              for
                // Always attempted, even when the row exists, so the trigger validates this placement on every
                // selection (active connection, provider, parent kind, same connection, inherited custody). An
                // existing row for the same (connection, kind, external ID) is reused.
                _ <-
                  sql"""insert into resources (id, tenant_id, resource_type, name, provider, parent_resource_id, external_id,
                                                kind, connection_id, custodian_principal_id)
                         values (${fresh.toString}::uuid, ${tenant.toString}::uuid, ${resourceTypeWire(kind.resourceType)},
                                 $displayName, ${kind.provider.value}, ${parent.toString}::uuid, ${externalId.value},
                                 ${kind.wire}, ${connection.toString}::uuid, ${parentCustodian}::uuid)
                         on conflict on constraint resources_connection_external_key do nothing""".update.run
                existing <-
                  sql"""select id, parent_resource_id, custodian_principal_id, coalesce(name, external_id)
                          from resources
                         where tenant_id=${tenant.toString}::uuid and connection_id=${connection.toString}::uuid
                           and kind=${kind.wire} and external_id=${externalId.value}"""
                    .query[(UUID, Option[UUID], Option[UUID], String)]
                    .option
                result <- existing match
                  case None =>
                    // The insert either created the row or conflicted with one that we cannot see: neither is a
                    // state this code can explain.
                    ConnectionResourceError.PersistenceFailure.asLeft[ConnectionResource].pure[ConnectionIO]
                  case Some((_, existingParent, _, _)) if !existingParent.contains(UUID.fromString(parent.toString)) =>
                    // The row exists elsewhere in the hierarchy; selecting it here would not change where it sits.
                    ConnectionResourceError.InvalidPlacement.asLeft[ConnectionResource].pure[ConnectionIO]
                  case Some((id, _, custodianId, name)) =>
                    val resolved = for
                      resource <- ResourceId.parse(id.toString).toOption
                      custodian <- custodianId.traverse(value => UserId.parse(value.toString).toOption)
                    yield (resource, custodian)
                    resolved match
                      case None => ConnectionResourceError.PersistenceFailure.asLeft[ConnectionResource].pure[ConnectionIO]
                      case Some((resource, custodian)) =>
                        sql"""insert into connection_resources (tenant_id, connection_id, resource_id, kind, external_id,
                                                                 selected_by, selected_at)
                               values (${tenant.toString}::uuid, ${connection.toString}::uuid, ${resource.toString}::uuid,
                                       ${kind.wire}, ${externalId.value}, ${selectedBy.id.toString}::uuid, $at)""".update.run
                          .as(Right(ConnectionResource(resource, connection, kind.wire, externalId, name, parent, custodian, Some(at))))
              yield result

  def deselect(tenant: TenantId, resource: ResourceId, at: Instant): IO[Either[ConnectionResourceError, Unit]] =
    guarded(tenant):
      sql"""update connection_resources set deselected_at=$at
             where tenant_id=${tenant.toString}::uuid and resource_id=${resource.toString}::uuid and deselected_at is null""".update.run
        .map:
          case 1 => Right(())
          case 0 => Left(ConnectionResourceError.NotFound)
          // The open-selection index allows at most one row; more than one is a broken invariant.
          case _ => Left(ConnectionResourceError.PersistenceFailure)

  def listFor(tenant: TenantId, connection: ConnectionId): IO[Vector[ConnectionResource]] =
    tenantProgram(tenant):
      sql"""select r.id, r.kind, r.external_id, coalesce(r.name, r.external_id), r.parent_resource_id,
                   r.custodian_principal_id, s.selected_at
              from resources r
              left join connection_resources s
                on s.tenant_id = r.tenant_id and s.resource_id = r.id and s.deselected_at is null
             where r.tenant_id=${tenant.toString}::uuid and r.connection_id=${connection.toString}::uuid
               and r.kind is not null and (r.connection_root or s.resource_id is not null)
             order by r.connection_root desc, s.selected_at, r.id"""
        .query[(UUID, String, String, String, Option[UUID], Option[UUID], Option[Instant])]
        .to[Vector]
        .flatMap(_.traverse(row => decode(connection, row)))

  override def replaceSelection(
      tenant: TenantId,
      connection: ConnectionId,
      selectedBy: Principal.Human,
      requested: Vector[SelectableProviderResource],
      at: Instant
  ): IO[Either[ConnectionResourceError, Vector[ConnectionResource]]] =
    val distinct = requested.map(value => value.kind.wire -> value.externalId.value).distinct
    if distinct.size != requested.size then IO.pure(Left(ConnectionResourceError.AlreadySelected))
    else
      guarded(tenant):
        for
          // Discovery ran outside the mutation gate, so the connection is re-checked here: a disconnect committed in
          // between makes the replacement fail rather than publish a stale selection.
          root <- sql"""select r.id, r.kind, r.external_id from resources r
                         join connections c on c.tenant_id=r.tenant_id and c.id=r.connection_id
                         where r.tenant_id=${tenant.toString}::uuid and r.connection_id=${connection.toString}::uuid
                           and r.connection_root and c.status='ACTIVE'
                         for update of c""".query[(UUID, String, String)].option
          result <- root match
            case None => ConnectionResourceError.ConnectionUnavailable.asLeft[Unit].pure[ConnectionIO]
            case Some((rootId, rootKind, rootExternal)) =>
              val ordered = requested.sortBy(_.kind.lineage.size)
              val reachable = ordered.foldLeft(Option(Set(rootKind -> rootExternal))): (known, item) =>
                known.flatMap: parents =>
                  item.kind.parent
                    .filter(parent => parents.contains(parent.wire -> item.parentExternalId.value))
                    .map(_ => parents + (item.kind.wire -> item.externalId.value))
              reachable match
                case None => ConnectionResourceError.InvalidPlacement.asLeft[Unit].pure[ConnectionIO]
                case Some(_) =>
                  for
                    open <- sql"""select r.id, r.kind, r.external_id from connection_resources s
                                   join resources r on r.tenant_id=s.tenant_id and r.id=s.resource_id
                                  where s.tenant_id=${tenant.toString}::uuid and s.connection_id=${connection.toString}::uuid
                                    and s.deselected_at is null""".query[(UUID, String, String)].to[Vector]
                    wanted = requested.map(value => value.kind.wire -> value.externalId.value).toSet
                    close = open.filterNot(row => wanted.contains(row._2 -> row._3))
                    _ <- close.traverse_((id, _, _) =>
                      sql"""update connection_resources set deselected_at=$at
                             where tenant_id=${tenant.toString}::uuid and resource_id=$id and deselected_at is null""".update.run.void
                    )
                    _ <- ordered.foldLeftM(Map((rootKind, rootExternal) -> rootId)): (parents, item) =>
                      // `reachable` above proved every parent is the root or an earlier item, so this lookup succeeds.
                      item.kind.parent.flatMap(kind => parents.get(kind.wire -> item.parentExternalId.value)) match
                        case None => new SQLException("Connection resource placement failed", "23514").raiseError[ConnectionIO, Map[(String, String), UUID]]
                        case Some(parentId) =>
                          for
                            _ <- sql"""insert into resources (id, tenant_id, resource_type, name, provider, parent_resource_id,
                                                                external_id, kind, connection_id, custodian_principal_id)
                                         values (${UUID.randomUUID()}::uuid, ${tenant.toString}::uuid,
                                                 ${resourceTypeWire(item.kind.resourceType)}, ${item.displayName},
                                                 ${item.kind.provider.value}, $parentId, ${item.externalId.value}, ${item.kind.wire},
                                                 ${connection.toString}::uuid,
                                                 (select custodian_principal_id from resources where tenant_id=${tenant.toString}::uuid and id=$parentId))
                                         on conflict on constraint resources_connection_external_key do nothing""".update.run
                            child <- sql"""select id from resources
                                              where tenant_id=${tenant.toString}::uuid and connection_id=${connection.toString}::uuid
                                                and kind=${item.kind.wire} and external_id=${item.externalId.value}
                                                and parent_resource_id=$parentId""".query[UUID].option
                            id <- child match
                              case Some(value) => value.pure[ConnectionIO]
                              case None => new SQLException("Connection resource placement failed", "23514").raiseError[ConnectionIO, UUID]
                            openAlready = open.exists(row => row._1 == id && wanted.contains(row._2 -> row._3))
                            _ <- if openAlready then ().pure[ConnectionIO] else
                              sql"""insert into connection_resources (tenant_id, connection_id, resource_id, kind, external_id,
                                                                               selected_by, selected_at)
                                       values (${tenant.toString}::uuid, ${connection.toString}::uuid, $id,
                                               ${item.kind.wire}, ${item.externalId.value}, ${selectedBy.id.toString}::uuid, $at)""".update.run.void
                          yield parents.updated(item.kind.wire -> item.externalId.value, id)
                  yield Right(())
        yield result
      .flatMap:
        case Left(error) => IO.pure(Left(error))
        case Right(_) => listFor(tenant, connection).map(Right(_))

  /** An undecodable stored row is a broken invariant, not an empty selection: the list fails rather than omitting it. */
  private def decode(
      connection: ConnectionId,
      row: (UUID, String, String, String, Option[UUID], Option[UUID], Option[Instant])
  ): ConnectionIO[ConnectionResource] =
    val decoded = for
      id <- ResourceId.parse(row._1.toString).toOption
      external <- ExternalId.parse(row._3)
      parent <- row._5.flatMap(value => ResourceId.parse(value.toString).toOption)
      custodian <- row._6.traverse(value => UserId.parse(value.toString).toOption)
    yield ConnectionResource(id, connection, row._2, external, row._4, parent, custodian, row._7)
    decoded match
      case Some(value) => value.pure[ConnectionIO]
      case None        => new IllegalStateException("Invalid stored connection resource").raiseError[ConnectionIO, ConnectionResource]

object PostgresConnectionResources:
  /** The provider's single owner-provisioned catalog resource, which a connection root sits under; `None` when there
    * is no such resource or more than one, so the root has no unambiguous place. */
  private[postgres] def catalogResource(tenant: TenantId, provider: ProviderId): ConnectionIO[Option[ResourceId]] =
    sql"""select id from resources
           where tenant_id=${tenant.toString}::uuid and kind is null and resource_type='PROVIDER'
             and lower(provider)=${provider.value} and parent_resource_id is null"""
      .query[UUID]
      .to[Vector]
      .map:
        case Vector(id) => ResourceId.parse(id.toString).toOption
        case _          => None

  /** The wire names `resources.resource_type` stores and `PostgresControlPlane` reads. */
  private[postgres] def resourceTypeWire(resourceType: ResourceType): String = resourceType match
    case ResourceType.Provider  => "PROVIDER"
    case ResourceType.Account   => "ACCOUNT"
    case ResourceType.Tool      => "TOOL"
    case ResourceType.McpServer => "MCP_SERVER"
    case ResourceType.Api       => "API"
    case ResourceType.Database  => "DATABASE"
    case ResourceType.Repository => "REPOSITORY"
    case ResourceType.Channel   => "CHANNEL"
    case ResourceType.Document  => "DOCUMENT"
    case ResourceType.Team      => "TEAM"
    case ResourceType.Custom    => "CUSTOM"

  // Trigger messages from V17's authai_check_resource_insert; SQLSTATE 23514 alone does not say which rule refused.
  private val ConnectionRefusals = Vector(
    "resources are added only under an active connection",
    "resource kind is not registered for the connection's provider"
  )
  private val PlacementRefusals = Vector(
    "resource type does not match its registered kind",
    "a connection root must be under its provider's catalog resource",
    "a selected resource must be under its registered parent kind in the same connection"
  )
  private val CustodyRefusals = Vector(
    "a personal root's custodian is the human who owns the connection",
    "a workspace root has no custodian",
    "a selected resource inherits its parent's custody"
  )
  private val SelectionConstraints = Set(
    "connection_resources_open_resource_idx",
    "connection_resources_open_external_idx",
    "resources_one_root_per_connection_idx",
    "resources_connection_external_key"
  )

  /** Maps a database refusal to an error. Anything not recognised is `PersistenceFailure`. */
  private[postgres] def refusal(failure: SQLException): ConnectionResourceError =
    val detail = failure match
      case server: PSQLException =>
        Option(server.getServerErrorMessage).map(message =>
          (Option(message.getMessage).getOrElse(""), Option(message.getConstraint))
        )
      case _ => None
    val (message, constraint) = detail.getOrElse(("", None))
    failure.getSQLState match
      case "23514" if ConnectionRefusals.contains(message) => ConnectionResourceError.ConnectionUnavailable
      case "23514" if PlacementRefusals.contains(message)  => ConnectionResourceError.InvalidPlacement
      case "23514" if CustodyRefusals.contains(message)    => ConnectionResourceError.InvalidCustody
      case "23505" if constraint.exists(SelectionConstraints.contains) => ConnectionResourceError.AlreadySelected
      case _                                                => ConnectionResourceError.PersistenceFailure
