package run.hallpass.adapters.secrets

import java.nio.file.{Files, Path, StandardOpenOption}
import java.nio.file.attribute.PosixFilePermissions
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.{Cipher, SecretKey}
import javax.crypto.spec.{GCMParameterSpec, SecretKeySpec}
import cats.effect.IO
import run.hallpass.application.*

/** Development-only file store. It deliberately does not generate, persist, or rotate a master key: production must use
  * a KMS-backed SecretStore implementation. The mounted directory and injected key belong only to the server process;
  * PostgreSQL receives the opaque reference returned here.
  */
final class LocalEncryptedSecretStore private (root: Path, key: SecretKey) extends SecretStore[IO]:
  private val random = SecureRandom()
  private val NonceLength = 12
  private val TagBits = 128

  def put(binding: SecretBinding, secret: ProviderSecret): IO[SecretReference] = IO.blocking:
    Files.createDirectories(root)
    setPrivateDirectory(root)
    val reference = SecretReference.random()
    val nonce = Array.ofDim[Byte](NonceLength)
    random.nextBytes(nonce)
    var plaintext = Array.emptyByteArray
    var encrypted = Array.emptyByteArray
    var payload = Array.emptyByteArray
    var aad = Array.emptyByteArray
    try
      val cipher = Cipher.getInstance("AES/GCM/NoPadding")
      cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TagBits, nonce))
      // Binding the ciphertext to its tenant, connection, and reference prevents moving a secret file elsewhere.
      aad = ProviderSecretAad.bytes(binding, reference)
      cipher.updateAAD(aad)
      plaintext = ProviderSecret.bytes(secret)
      encrypted = cipher.doFinal(plaintext)
      payload = nonce ++ encrypted
      val file = pathFor(reference).getOrElse(throw IllegalArgumentException("generated invalid secret reference"))
      Files.write(file, payload, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
      setPrivateFile(file)
      reference
    finally
      java.util.Arrays.fill(plaintext, 0.toByte)
      java.util.Arrays.fill(encrypted, 0.toByte)
      java.util.Arrays.fill(payload, 0.toByte)
      java.util.Arrays.fill(aad, 0.toByte)
      java.util.Arrays.fill(nonce, 0.toByte)

  def get(binding: SecretBinding, reference: SecretReference): IO[Either[SecretStoreError, ProviderSecret]] = IO.blocking:
    pathFor(reference) match
      case None                                     => Left(SecretStoreError.MalformedReference)
      case Some(file) if !Files.isRegularFile(file) => Left(SecretStoreError.NotFound)
      case Some(file)                               =>
        var stored = Array.emptyByteArray
        var nonce = Array.emptyByteArray
        var ciphertext = Array.emptyByteArray
        var aad = Array.emptyByteArray
        var plaintext = Array.emptyByteArray
        try
          stored = Files.readAllBytes(file)
          if stored.length <= NonceLength then Left(SecretStoreError.DecryptionFailed)
          else
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            nonce = stored.take(NonceLength)
            ciphertext = stored.drop(NonceLength)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TagBits, nonce))
            aad = ProviderSecretAad.bytes(binding, reference)
            cipher.updateAAD(aad)
            plaintext = cipher.doFinal(ciphertext)
            Right(ProviderSecret.fromBytes(plaintext))
        catch case _: Exception => Left(SecretStoreError.DecryptionFailed)
        finally
          java.util.Arrays.fill(stored, 0.toByte)
          java.util.Arrays.fill(nonce, 0.toByte)
          java.util.Arrays.fill(ciphertext, 0.toByte)
          java.util.Arrays.fill(aad, 0.toByte)
          java.util.Arrays.fill(plaintext, 0.toByte)

  def delete(binding: SecretBinding, reference: SecretReference): IO[Unit] = IO.blocking:
    pathFor(reference).foreach(Files.deleteIfExists)
    ()

  private def pathFor(reference: SecretReference): Option[Path] =
    // parse guarantees the filename has no separators, and normalize guards the boundary defensively.
    SecretReference
      .parse(reference.value)
      .map: valid =>
        val candidate = root.resolve(valid.value).normalize()
        if !candidate.startsWith(root) then throw IllegalArgumentException("invalid secret reference")
        candidate

  private def setPrivateDirectory(path: Path): Unit =
    try Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
    catch case _: UnsupportedOperationException => ()
  private def setPrivateFile(path: Path): Unit =
    try Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
    catch case _: UnsupportedOperationException => ()

object LocalEncryptedSecretStore:
  def create(root: Path, encodedMasterKey: String): Either[String, LocalEncryptedSecretStore] =
    try
      val bytes = Base64.getDecoder.decode(encodedMasterKey)
      Either.cond(
        bytes.length == 32,
        new LocalEncryptedSecretStore(root.toAbsolutePath.normalize(), SecretKeySpec(bytes, "AES")),
        "secret master key must be a base64-encoded 32-byte key"
      )
    catch case _: IllegalArgumentException => Left("secret master key must be base64")
