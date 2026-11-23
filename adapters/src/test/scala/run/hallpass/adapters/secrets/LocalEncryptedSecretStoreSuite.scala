package run.hallpass.adapters.secrets

import java.nio.file.Files
import java.util.Base64
import cats.effect.IO
import munit.CatsEffectSuite
import run.hallpass.application.*

final class LocalEncryptedSecretStoreSuite extends CatsEffectSuite:
  private val key = Base64.getEncoder.encodeToString(Array.tabulate[Byte](32)(_.toByte))
  private val binding = SecretBinding(run.hallpass.kernel.TenantId.random(), run.hallpass.kernel.ConnectionId.random())

  test("round trips a secret without storing plaintext") {
    val root = Files.createTempDirectory("hallpass-secrets-")
    val store = LocalEncryptedSecretStore.create(root, key).toOption.get
    val secret = ProviderSecret.fromUtf8("xoxb-sensitive-token")
    for
      reference <- store.put(binding, secret)
      restored <- store.get(binding, reference)
      contents <- IO.blocking(Files.readAllBytes(root.resolve(reference.value)))
    yield
      assertEquals(
        restored.map(value => new String(ProviderSecret.bytes(value), java.nio.charset.StandardCharsets.UTF_8)),
        Right("xoxb-sensitive-token")
      )
      assert(!new String(contents, java.nio.charset.StandardCharsets.ISO_8859_1).contains("xoxb-sensitive-token"))
  }

  test("ciphertext cannot be moved to another secret reference") {
    val root = Files.createTempDirectory("hallpass-secrets-")
    val store = LocalEncryptedSecretStore.create(root, key).toOption.get
    for
      first <- store.put(binding, ProviderSecret.fromUtf8("one"))
      second <- store.put(binding, ProviderSecret.fromUtf8("two"))
      _ <- IO.blocking(
        Files.copy(
          root.resolve(first.value),
          root.resolve(second.value),
          java.nio.file.StandardCopyOption.REPLACE_EXISTING
        )
      )
      restored <- store.get(binding, second)
    yield assertEquals(restored, Left(SecretStoreError.DecryptionFailed))
  }

  test("ciphertext is bound to its tenant and connection") {
    val root = Files.createTempDirectory("hallpass-secrets-")
    val store = LocalEncryptedSecretStore.create(root, key).toOption.get
    for
      reference <- store.put(binding, ProviderSecret.fromUtf8("bound"))
      otherTenant <- store.get(binding.copy(tenant = run.hallpass.kernel.TenantId.random()), reference)
      otherConnection <- store.get(binding.copy(connection = run.hallpass.kernel.ConnectionId.random()), reference)
    yield
      assertEquals(otherTenant, Left(SecretStoreError.DecryptionFailed))
      assertEquals(otherConnection, Left(SecretStoreError.DecryptionFailed))
  }

  test("rejects malformed and incorrectly sized master keys") {
    assert(LocalEncryptedSecretStore.create(java.nio.file.Path.of("/tmp"), "not-base64").isLeft)
    assert(
      LocalEncryptedSecretStore
        .create(java.nio.file.Path.of("/tmp"), Base64.getEncoder.encodeToString(Array[Byte](1)))
        .isLeft
    )
  }
