package run.hallpass.adapters.secrets

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}
import cats.effect.IO
import cats.syntax.all.*
import run.hallpass.application.*
import run.hallpass.kernel.{ConnectionId, TenantId}

/** One envelope-encrypted secret as stored. `ciphertext` includes the GCM tag. */
final case class StoredProviderSecret(
    connection: ConnectionId,
    keyName: String,
    wrappedKey: WrappedDataKey,
    nonce: Array[Byte],
    ciphertext: Array[Byte]
)

/** Tenant-scoped persistence for envelope ciphertext. Implementations establish the tenant context for every call. */
trait ProviderSecretRows:
  def insert(tenant: TenantId, reference: SecretReference, row: StoredProviderSecret): IO[Unit]
  def find(tenant: TenantId, reference: SecretReference): IO[Option[StoredProviderSecret]]
  def delete(tenant: TenantId, reference: SecretReference): IO[Unit]

/** Raised by `put` when the key service cannot protect a new secret. The caller creates no connection. */
final case class SecretStoreUnavailable() extends RuntimeException("the provider secret store is unavailable")

/** Production `SecretStore`: envelope encryption with a KMS-wrapped, per-secret data key.
  *
  * `put` generates a random AES-256 data key and a random 96-bit nonce, encrypts the secret with AES-GCM using
  * associated data that binds it to (tenant, connection, reference), wraps the data key under the tenant's derived
  * key-encryption key, and stores only the wrapped key, nonce, and ciphertext. `get` reverses this. Every plaintext
  * byte array this class owns (secret, data key, associated data) is zeroed on success and failure.
  *
  * Failure is closed and never retried here: a key-service outage is `Unavailable` (the executor records
  * `CONNECTION_UNAVAILABLE`), and any authentication failure is `DecryptionFailed`. */
final class EnvelopeSecretStore(keys: KeyEncryptionService, rows: ProviderSecretRows) extends SecretStore[IO]:
  import EnvelopeSecretStore.*
  private val random = SecureRandom()

  def put(binding: SecretBinding, secret: ProviderSecret): IO[SecretReference] =
    IO.delay:
      val dataKey = Array.ofDim[Byte](DataKeyBytes)
      val nonce = Array.ofDim[Byte](NonceBytes)
      random.nextBytes(dataKey)
      random.nextBytes(nonce)
      (SecretReference.random(), dataKey, nonce)
    .flatMap: (reference, dataKey, nonce) =>
      val encrypted = IO.blocking:
        var plaintext = Array.emptyByteArray
        var aad = Array.emptyByteArray
        try
          plaintext = ProviderSecret.bytes(secret)
          aad = ProviderSecretAad.bytes(binding, reference)
          val cipher = Cipher.getInstance(Transformation)
          cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(dataKey, "AES"), GCMParameterSpec(TagBits, nonce))
          cipher.updateAAD(aad)
          cipher.doFinal(plaintext)
        finally
          java.util.Arrays.fill(plaintext, 0.toByte)
          java.util.Arrays.fill(aad, 0.toByte)
      (encrypted, keys.wrap(dataKey, binding.tenant)).tupled
        .guarantee(IO.delay(java.util.Arrays.fill(dataKey, 0.toByte)))
        .flatMap:
          case (_, Left(_)) => IO.raiseError(SecretStoreUnavailable())
          case (ciphertext, Right(wrapped)) =>
            rows
              .insert(binding.tenant, reference, StoredProviderSecret(binding.connection, keys.keyName, wrapped, nonce, ciphertext))
              .as(reference)

  def get(binding: SecretBinding, reference: SecretReference): IO[Either[SecretStoreError, ProviderSecret]] =
    rows.find(binding.tenant, reference).attempt.flatMap:
      case Left(_)     => IO.pure(Left(SecretStoreError.Unavailable))
      case Right(None) => IO.pure(Left(SecretStoreError.NotFound))
      // The row names its own connection; a reference presented for another connection is not that secret.
      case Right(Some(row)) if row.connection != binding.connection => IO.pure(Left(SecretStoreError.NotFound))
      case Right(Some(row)) =>
        keys.unwrap(row.wrappedKey, binding.tenant).flatMap:
          case Left(KeyServiceError.Unavailable) => IO.pure(Left(SecretStoreError.Unavailable))
          case Left(KeyServiceError.Rejected)    => IO.pure(Left(SecretStoreError.DecryptionFailed))
          case Right(dataKey) =>
            IO.blocking:
              var aad = Array.emptyByteArray
              var plaintext = Array.emptyByteArray
              try
                if dataKey.length != DataKeyBytes then Left(SecretStoreError.DecryptionFailed)
                else
                  aad = ProviderSecretAad.bytes(binding, reference)
                  val cipher = Cipher.getInstance(Transformation)
                  cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(dataKey, "AES"), GCMParameterSpec(TagBits, row.nonce))
                  cipher.updateAAD(aad)
                  plaintext = cipher.doFinal(row.ciphertext)
                  Right(ProviderSecret.fromBytes(plaintext))
              catch case _: java.security.GeneralSecurityException => Left(SecretStoreError.DecryptionFailed)
              finally
                java.util.Arrays.fill(dataKey, 0.toByte)
                java.util.Arrays.fill(aad, 0.toByte)
                java.util.Arrays.fill(plaintext, 0.toByte)

  def delete(binding: SecretBinding, reference: SecretReference): IO[Unit] = rows.delete(binding.tenant, reference)

object EnvelopeSecretStore:
  private val Transformation = "AES/GCM/NoPadding"
  private val DataKeyBytes = 32
  private val NonceBytes = 12
  private val TagBits = 128
