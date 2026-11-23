package run.hallpass.adapters.postgres

import java.util.UUID
import cats.effect.IO
import cats.syntax.all.*
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.adapters.secrets.{KeyEncryptionService, ProviderSecretRows, StoredProviderSecret, WrappedDataKey}
import run.hallpass.application.*
import run.hallpass.kernel.*

/** Envelope ciphertext in `provider_secrets`, always under the owning tenant's RLS context. A row that does not decode
  * is an explicit failure, never "no secret". */
final class PostgresProviderSecrets(xa: Transactor[IO]) extends ProviderSecretRows:
  private def tenantProgram[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(xa)

  def insert(tenant: TenantId, reference: SecretReference, row: StoredProviderSecret): IO[Unit] =
    tenantProgram(tenant):
      sql"""insert into provider_secrets (tenant_id, reference, connection_id, key_name, wrapped_key, nonce, ciphertext)
            values (${tenant.toString}::uuid, ${reference.value}, ${row.connection.toString}::uuid, ${row.keyName},
                    ${row.wrappedKey.value}, ${row.nonce}, ${row.ciphertext})""".update.run.void

  def find(tenant: TenantId, reference: SecretReference): IO[Option[StoredProviderSecret]] =
    tenantProgram(tenant):
      sql"""select connection_id, key_name, wrapped_key, nonce, ciphertext from provider_secrets
            where tenant_id = ${tenant.toString}::uuid and reference = ${reference.value}"""
        .query[(UUID, String, String, Array[Byte], Array[Byte])]
        .option
    .flatMap:
      case None => IO.pure(None)
      case Some((connection, keyName, wrapped, nonce, ciphertext)) =>
        IO.fromEither(
          ConnectionId.parse(connection.toString)
            .leftMap(_ => IllegalStateException("provider secret connection identifier is invalid"))
            .map(id => Some(StoredProviderSecret(id, keyName, WrappedDataKey.fromStored(wrapped), nonce, ciphertext)))
        )

  def delete(tenant: TenantId, reference: SecretReference): IO[Unit] =
    tenantProgram(tenant):
      sql"delete from provider_secrets where tenant_id = ${tenant.toString}::uuid and reference = ${reference.value}".update.run.void

/** Outcome of one rewrap run. `failed` secrets keep their previous wrapped key, which stays decryptable until the
  * operator raises the key's minimum decryption version. */
final case class RewrapReport(tenants: Int, rewrapped: Int, alreadyCurrent: Int, failed: Int)

/** Key rotation for envelope-encrypted secrets, run by the owner (`HallpassRewrapSecretsMain`) after the key-encryption
  * key is rotated in the key service. Data keys are re-encrypted under the newest key version by the key service
  * itself (rewrap), so no data key or secret is ever decrypted into this process.
  *
  * Tenants are enumerated from the identity directory: every provisioned tenant has a membership row (active or
  * removed), and the owner cannot list `tenants` itself without a tenant context under forced RLS. Each update is
  * conditional on the wrapped key it read, so a concurrent change is left alone rather than overwritten. */
object ProviderSecretRewrap:
  def run(config: DatabaseConfig, keys: KeyEncryptionService): IO[RewrapReport] =
    PostgresDatabase.ownerResource(config).use(run(_, keys))

  def run(xa: Transactor[IO], keys: KeyEncryptionService): IO[RewrapReport] =
    sql"select distinct tenant_id from directory_tenant_memberships order by tenant_id"
      .query[UUID].to[Vector].transact(xa)
      .flatMap: tenantIds =>
        tenantIds
          .flatMap(id => TenantId.parse(id.toString).toOption)
          .traverse(tenant => rewrapTenant(xa, keys, tenant))
          .map: reports =>
            reports.foldLeft(RewrapReport(tenantIds.size, 0, 0, 0)): (total, next) =>
              total.copy(
                rewrapped = total.rewrapped + next.rewrapped,
                alreadyCurrent = total.alreadyCurrent + next.alreadyCurrent,
                failed = total.failed + next.failed
              )

  private def rewrapTenant(xa: Transactor[IO], keys: KeyEncryptionService, tenant: TenantId): IO[RewrapReport] =
    val rows = (TenantSession.establish(tenant) *>
      sql"""select reference, wrapped_key from provider_secrets
            where tenant_id = ${tenant.toString}::uuid and key_name = ${keys.keyName} order by reference"""
        .query[(String, String)].to[Vector]).transact(xa)
    rows.flatMap: secrets =>
      secrets
        .traverse: (reference, stored) =>
          val wrapped = WrappedDataKey.fromStored(stored)
          keys.current(wrapped).flatMap:
            case Right(true) => IO.pure(RewrapReport(0, 0, 1, 0))
            case Left(_)     => IO.pure(RewrapReport(0, 0, 0, 1))
            case Right(false) =>
              keys.rewrap(wrapped, tenant).flatMap:
                case Left(_) => IO.pure(RewrapReport(0, 0, 0, 1))
                case Right(next) =>
                  (TenantSession.establish(tenant) *>
                    sql"""update provider_secrets set wrapped_key = ${next.value}, rewrapped_at = now()
                          where tenant_id = ${tenant.toString}::uuid and reference = $reference and wrapped_key = $stored"""
                      .update.run).transact(xa)
                    .map(updated => if updated == 1 then RewrapReport(0, 1, 0, 0) else RewrapReport(0, 0, 0, 1))
        .map(_.foldLeft(RewrapReport(0, 0, 0, 0))((a, b) =>
          RewrapReport(0, a.rewrapped + b.rewrapped, a.alreadyCurrent + b.alreadyCurrent, a.failed + b.failed)
        ))
