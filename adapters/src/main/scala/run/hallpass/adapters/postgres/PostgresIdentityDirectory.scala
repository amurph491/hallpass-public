package run.hallpass.adapters.postgres

import java.util.UUID
import cats.effect.IO
import cats.syntax.all.*
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.application.*
import run.hallpass.kernel.*

/** Pre-tenant directory lookups. The runtime role has no privileges on the `directory_*` tables and reads them only
  * through the `SECURITY DEFINER` routing functions from V12, which return routing data and nothing else.
  *
  * No tenant context is set here: these queries run before a tenant is known, which is the point of the directory. A
  * row that fails to parse is treated as absent rather than as a routing answer. Database failures are reported as
  * [[DirectoryError.Unavailable]], never as "unknown". */
final class PostgresIdentityDirectory(xa: Transactor[IO]) extends AgentCredentialRoutes[IO], HumanDirectory[IO]:

  def candidateTenant(selector: AgentCredentialSelector): IO[Either[DirectoryError, Option[TenantId]]] =
    sql"select authai_agent_credential_tenant(${selector.value})"
      .query[Option[UUID]]
      .unique
      .transact(xa)
      .map(value => Right(value.flatMap(id => TenantId.parse(id.toString).toOption)))
      .handleError(_ => Left(DirectoryError.Unavailable))

  def userFor(identity: ExternalIdentity): IO[Either[DirectoryError, Option[DirectoryUserId]]] =
    sql"select authai_user_for_external_identity(${identity.issuer}, ${identity.subject})"
      .query[Option[UUID]]
      .unique
      .transact(xa)
      .map(value => Right(value.flatMap(id => DirectoryUserId.parse(id.toString).toOption)))
      .handleError(_ => Left(DirectoryError.Unavailable))

  def activeMemberships(user: DirectoryUserId): IO[Either[DirectoryError, Vector[TenantMembership]]] =
    sql"""select tenant_id, human_principal_id, role, break_glass_grant_id
            from authai_active_memberships(${user.toString}::uuid)
           order by tenant_id"""
      .query[(UUID, UUID, String, Option[UUID])]
      .to[Vector]
      .transact(xa)
      .map: rows =>
        Right(rows.flatMap: (tenant, principal, role, grant) =>
          for
            parsedTenant <- TenantId.parse(tenant.toString).toOption
            parsedPrincipal <- UserId.parse(principal.toString).toOption
            parsedRole <- role match
              case "ADMIN"  => Some(MembershipRole.Admin)
              case "MEMBER" => Some(MembershipRole.Member)
              case _        => None
            // An unparseable grant makes the whole row absent rather than silently dropping the elevation marker.
            parsedGrant <- grant match
              case None        => Some(None)
              case Some(value) => BreakGlassGrantId.parse(value.toString).toOption.map(Some(_))
          yield TenantMembership(user, parsedTenant, Principal.Human(parsedPrincipal), parsedRole, parsedGrant)
        )
      .handleError(_ => Left(DirectoryError.Unavailable))
