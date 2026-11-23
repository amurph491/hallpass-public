package run.hallpass.adapters.postgres

import java.time.Instant
import java.util.UUID
import java.sql.Connection as JdbcConnection
import java.security.MessageDigest
import java.nio.{ByteBuffer, charset}
import scala.util.control.NonFatal
import cats.effect.{IO, Resource}
import cats.syntax.all.*
import com.zaxxer.hikari.HikariDataSource
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.implicits.javatimedrivernative.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.application.*
import run.hallpass.kernel.*

/** A dedicated lock pool avoids starving the repository pool while waiting on another instance's refresh.
  * Session advisory locks span bounded network work; the reference row locks are short transactions only.
  * A durable NEEDS_REAUTH marker precedes every exchange. Even losing the lock session cannot permit a second
  * executor to reuse the old refresh token. Publication is conditional on both the marker and the old pointer.
  */
final class PostgresOAuthRefreshRepository private (xa: Transactor[IO], locks: HikariDataSource)
    extends OAuthRefreshRepository:
  private def tenantProgram[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(xa)

  def withCredential[K](lease: RedeemedExecutionLease, target: SelectedResource[K], provider: ProviderId)(
      use: LockedOAuthCredential => IO[Either[ConnectionError, OAuthTokens]]
  ): IO[Either[ConnectionError, OAuthTokens]] =
    if lease.tenant != target.tenant || lease.resource != target.resource || target.kind.provider != provider then
      IO.pure(Left(ConnectionError.InvalidState))
    else
      resolve(lease, target, provider).flatMap:
        case None => IO.pure(Left(ConnectionError.NotFound))
        case Some(connection) =>
          held(lease.tenant, connection).use: lock =>
            load(lease, target, provider, connection).flatMap:
              case None => IO.pure(Left(ConnectionError.NotFound))
              case Some((savedReference, expiry)) =>
                val slot = new LockedOAuthCredential:
                  val binding = SecretBinding(lease.tenant, connection)
                  val reference: SecretReference = savedReference
                  val expiresAt = expiry
                  def requireReauthorization(at: Instant): IO[Either[ConnectionError, Unit]] =
                    confirm(lock) *> mark(binding, reference, at)
                  def restore(at: Instant): IO[Either[ConnectionError, Unit]] =
                    confirm(lock) *> unmark(binding, reference, at)
                  def publish(next: SecretReference, expires: Instant, at: Instant): IO[Either[ConnectionError, Unit]] =
                    confirm(lock) *> publishVersion(binding, reference, next, expires, at)
                use(slot)

  private def resolve[K](lease: RedeemedExecutionLease, target: SelectedResource[K], provider: ProviderId): IO[Option[ConnectionId]] =
    tenantProgram(lease.tenant):
      sql"""select c.id from connections c join resources r
             on r.tenant_id=c.tenant_id and r.connection_id=c.id
             where r.tenant_id=${lease.tenant.toString}::uuid and r.id=${lease.resource.toString}::uuid
               and r.kind=${target.kind.wire} and r.external_id=${target.externalId.value}
               and lower(c.provider)=${provider.value}""".query[UUID].option.map:
        _.flatMap(id => ConnectionId.parse(id.toString).toOption)

  private def load[K](lease: RedeemedExecutionLease, target: SelectedResource[K], provider: ProviderId, connection: ConnectionId)
      : IO[Option[(SecretReference, Option[Instant])]] =
    tenantProgram(lease.tenant):
      sql"""select cr.secret_reference, cr.expires_at from credential_references cr
             join connections c on c.tenant_id=cr.tenant_id and c.id=cr.connection_id
             join resources r on r.tenant_id=c.tenant_id and r.connection_id=c.id
             where c.tenant_id=${lease.tenant.toString}::uuid and c.id=${connection.toString}::uuid
               and c.status='ACTIVE' and lower(c.provider)=${provider.value}
               and cr.credential_type='OAUTH_REFRESHABLE'
               and cr.expires_at is not distinct from c.token_expires_at
               and r.id=${lease.resource.toString}::uuid and r.kind=${target.kind.wire}
               and r.external_id=${target.externalId.value}
               and (r.connection_root or exists (
                 select 1 from connection_resources selected where selected.tenant_id=r.tenant_id
                   and selected.connection_id=c.id and selected.resource_id=r.id and selected.deselected_at is null))
             for update of cr""".query[(String, Option[Instant])].option.map:
        _.flatMap((reference, expires) => SecretReference.parse(reference).map(_ -> expires))

  private def mark(binding: SecretBinding, expected: SecretReference, at: Instant): IO[Either[ConnectionError, Unit]] =
    tenantProgram(binding.tenant):
      lockReference(binding, expected).flatMap:
        case false => ConnectionError.InvalidState.asLeft[Unit].pure[ConnectionIO]
        case true =>
          sql"""update connections set status='NEEDS_REAUTH', updated_at=$at
                 where tenant_id=${binding.tenant.toString}::uuid and id=${binding.connection.toString}::uuid
                   and status='ACTIVE'""".update.run.map:
            case 1 => Right(())
            case _ => Left(ConnectionError.InvalidState)

  private def lockReference(binding: SecretBinding, expected: SecretReference): ConnectionIO[Boolean] =
    sql"""select secret_reference from credential_references
           where tenant_id=${binding.tenant.toString}::uuid and connection_id=${binding.connection.toString}::uuid
             and credential_type='OAUTH_REFRESHABLE' for update""".query[String].option.map(_.contains(expected.value))

  private def unmark(binding: SecretBinding, expected: SecretReference, at: Instant): IO[Either[ConnectionError, Unit]] =
    tenantProgram(binding.tenant):
      lockReference(binding, expected).flatMap:
        case false => ConnectionError.InvalidState.asLeft[Unit].pure[ConnectionIO]
        case true =>
          sql"""update connections set status='ACTIVE', updated_at=$at
                 where tenant_id=${binding.tenant.toString}::uuid and id=${binding.connection.toString}::uuid
                   and status='NEEDS_REAUTH'""".update.run.map:
            case 1 => Right(())
            case _ => Left(ConnectionError.InvalidState)

  private def publishVersion(binding: SecretBinding, expected: SecretReference, next: SecretReference, expires: Instant, at: Instant)
      : IO[Either[ConnectionError, Unit]] =
    tenantProgram(binding.tenant):
      lockReference(binding, expected).flatMap:
        case false => ConnectionError.InvalidState.asLeft[Unit].pure[ConnectionIO]
        case true =>
          sql"""update connections set status='ACTIVE', token_expires_at=$expires, updated_at=$at
                 where tenant_id=${binding.tenant.toString}::uuid and id=${binding.connection.toString}::uuid
                   and status='NEEDS_REAUTH'""".update.run.flatMap:
            case 0 => ConnectionError.InvalidState.asLeft[Unit].pure[ConnectionIO]
            case _ =>
              sql"""update credential_references set secret_reference=${next.value}, expires_at=$expires
                     where tenant_id=${binding.tenant.toString}::uuid and connection_id=${binding.connection.toString}::uuid
                       and secret_reference=${expected.value} and credential_type='OAUTH_REFRESHABLE'""".update.run.flatMap:
                case 1 => ().asRight[ConnectionError].pure[ConnectionIO]
                case _ => new IllegalStateException("OAuth reference publication failed").raiseError[ConnectionIO, Either[ConnectionError, Unit]]

  private final case class Held(connection: JdbcConnection, key: Long)

  private def held(tenant: TenantId, connection: ConnectionId): Resource[IO, Held] =
    val bytes = MessageDigest.getInstance("SHA-256").digest(
      s"hallpass-oauth-refresh:${tenant.toString}:${connection.toString}".getBytes(charset.StandardCharsets.US_ASCII)
    )
    val key = ByteBuffer.wrap(bytes).getLong
    Resource.make(IO.blocking:
      val session = locks.getConnection()
      try
        val settings = session.prepareStatement("select set_config('lock_timeout', '10s', false)")
        try settings.execute()
        finally settings.close()
        val statement = session.prepareStatement("select pg_advisory_lock(?)")
        try
          statement.setLong(1, key)
          statement.execute()
        finally statement.close()
        Held(session, key)
      catch
        case NonFatal(_) =>
          locks.evictConnection(session)
          throw ProviderExecutionException(ProviderError.ConnectionUnavailable)
    )(release)

  private def confirm(lock: Held): IO[Unit] = IO.blocking:
    val statement = lock.connection.prepareStatement(
      """select exists(select 1 from pg_locks where locktype='advisory' and pid=pg_backend_pid()
           and classid::bigint=((?::bigint >> 32) & 4294967295) and objid::bigint=(?::bigint & 4294967295)
           and objsubid=1 and mode='ExclusiveLock' and granted)"""
    )
    try
      statement.setLong(1, lock.key)
      statement.setLong(2, lock.key)
      val result = statement.executeQuery()
      try
        if !result.next() || !result.getBoolean(1) then throw ProviderExecutionException(ProviderError.ConnectionUnavailable)
      finally result.close()
    finally statement.close()

  private def release(lock: Held): IO[Unit] = IO.blocking:
    val unlocked =
      try
        val statement = lock.connection.prepareStatement("select pg_advisory_unlock(?)")
        try
          statement.setLong(1, lock.key)
          val result = statement.executeQuery()
          try result.next() && result.getBoolean(1)
          finally result.close()
        finally statement.close()
      catch case NonFatal(_) => false
    if unlocked then lock.connection.close() else locks.evictConnection(lock.connection)
  .handleError(_ => ())

object PostgresOAuthRefreshRepository:
  def resource(database: DatabaseConfig, xa: Transactor[IO]): Resource[IO, PostgresOAuthRefreshRepository] =
    PostgresDatabase.gateDataSource(database, 8, 10000, 20).map(new PostgresOAuthRefreshRepository(xa, _))
