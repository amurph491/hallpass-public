package run.hallpass.adapters.postgres

import java.time.{Duration, Instant}
import java.util.UUID
import cats.effect.IO
import cats.syntax.all.*
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.application.*
import run.hallpass.kernel.*

enum BreakGlassRequestError:
  case InvalidReason, InvalidOperator, InvalidDuration

/** An operator's request to elevate one person to administrator in one tenant for a bounded time. */
final case class BreakGlassRequest private (
    tenant: TenantId,
    person: ExternalIdentity,
    reason: String,
    operator: String,
    duration: Duration
)

object BreakGlassRequest:
  val MaximumDuration: Duration = Duration.ofHours(4)

  def from(
      tenant: TenantId,
      person: ExternalIdentity,
      reason: String,
      operator: String,
      duration: Duration
  ): Either[BreakGlassRequestError, BreakGlassRequest] =
    if !text(reason, 10, 1000) then Left(BreakGlassRequestError.InvalidReason)
    else if !text(operator, 1, 200) then Left(BreakGlassRequestError.InvalidOperator)
    else if duration.compareTo(Duration.ofMinutes(1)) < 0 || duration.compareTo(MaximumDuration) > 0 then
      Left(BreakGlassRequestError.InvalidDuration)
    else Right(BreakGlassRequest(tenant, person, reason, operator, duration))

  private def text(value: String, minimum: Int, maximum: Int): Boolean =
    value == value.trim && value.length >= minimum && value.length <= maximum && !value.exists(Character.isISOControl)

enum BreakGlassError:
  /** No active directory user is linked to the identity-provider account. Break-glass never creates or re-enables one. */
  case UnknownUser
  case UnknownTenant

final case class BreakGlassGrant(id: BreakGlassGrantId, user: DirectoryUserId, principal: Principal.Human, expiresAt: Instant)

/** Emergency administrator access, as an operator action that runs as the schema owner (`HallpassBreakGlassMain`).
  *
  * There is no break-glass login. The elevated person still signs in through the identity provider; the grant only
  * makes their role in one tenant ADMIN until it expires or is revoked. It adds no policy or delegation, so the person
  * can revoke, disconnect, and inspect, but cannot delegate authority their principal does not already hold. The grant
  * row (who, by whom, why, until when) is the audit record, and each session's tenant selection records the grant it
  * relied on. */
object BreakGlass:
  def grant(config: DatabaseConfig, request: BreakGlassRequest): IO[Either[BreakGlassError, BreakGlassGrant]] =
    PostgresDatabase.ownerResource(config).use(grant(_, request))

  def revoke(config: DatabaseConfig, grant: BreakGlassGrantId): IO[Boolean] =
    PostgresDatabase.ownerResource(config).use(revoke(_, grant))

  def grant(xa: Transactor[IO], request: BreakGlassRequest): IO[Either[BreakGlassError, BreakGlassGrant]] =
    program(request).transact(xa)

  def revoke(xa: Transactor[IO], grant: BreakGlassGrantId): IO[Boolean] =
    sql"update directory_break_glass_grants set revoked_at = now() where id = ${grant.value} and revoked_at is null"
      .update.run.transact(xa).map(_ == 1)

  private def program(request: BreakGlassRequest): ConnectionIO[Either[BreakGlassError, BreakGlassGrant]] =
    val tenant = request.tenant.toString
    activeUser(request.person).flatMap:
      case None => BreakGlassError.UnknownUser.asLeft[BreakGlassGrant].pure[ConnectionIO]
      case Some(user) =>
        TenantSession.establish(request.tenant) *>
          sql"select exists(select 1 from tenants where id = $tenant::uuid)".query[Boolean].unique.flatMap:
            case false => BreakGlassError.UnknownTenant.asLeft[BreakGlassGrant].pure[ConnectionIO]
            case true =>
              for
                principal <- principalFor(request.tenant, user)
                id = BreakGlassGrantId.random()
                expiresAt <-
                  sql"""insert into directory_break_glass_grants
                          (id, tenant_id, user_id, human_principal_id, reason, granted_by, expires_at)
                        values (${id.value}, $tenant::uuid, ${user.toString}::uuid, ${principal.id.toString}::uuid,
                                ${request.reason}, ${request.operator},
                                now() + make_interval(secs => ${request.duration.getSeconds.toDouble}))
                        returning expires_at"""
                    .query[Instant]
                    .unique
              yield Right(BreakGlassGrant(id, user, principal, expiresAt))

  private def activeUser(identity: ExternalIdentity): ConnectionIO[Option[DirectoryUserId]] =
    sql"""select u.id from directory_external_identities i join directory_users u on u.id = i.user_id
          where i.issuer = ${identity.issuer} and i.subject = ${identity.subject} and u.status = 'ACTIVE'"""
      .query[UUID]
      .option
      .map(_.flatMap(id => DirectoryUserId.parse(id.toString).toOption))

  /** The person's principal in the tenant: the one their membership names (active or removed), or a new human
    * principal with no policies when they were never a member. */
  private def principalFor(tenant: TenantId, user: DirectoryUserId): ConnectionIO[Principal.Human] =
    sql"""select human_principal_id from directory_tenant_memberships
          where tenant_id = ${tenant.toString}::uuid and user_id = ${user.toString}::uuid"""
      .query[UUID]
      .option
      .flatMap:
        case Some(existing) =>
          UserId.parse(existing.toString) match
            case Right(id) => Principal.Human(id).pure[ConnectionIO]
            case Left(_)   => FC.raiseError(IllegalStateException("membership principal identifier is invalid"))
        case None =>
          val created = UserId.random()
          sql"insert into principals(id, tenant_id, kind) values (${created.toString}::uuid, ${tenant.toString}::uuid, 'HUMAN')".update.run *>
            sql"insert into human_identities(tenant_id, principal_id) values (${tenant.toString}::uuid, ${created.toString}::uuid)".update.run
              .as(Principal.Human(created))
