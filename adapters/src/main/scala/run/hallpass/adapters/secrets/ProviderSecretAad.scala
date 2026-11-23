package run.hallpass.adapters.secrets

import java.nio.charset.StandardCharsets
import run.hallpass.application.{SecretBinding, SecretReference}

/** Associated data for provider-secret ciphertext. A ciphertext decrypts only under the tenant, connection, and
  * reference it was written for, so copying a row or file to another tenant or connection fails authentication. */
private[secrets] object ProviderSecretAad:
  def bytes(binding: SecretBinding, reference: SecretReference): Array[Byte] =
    s"authai.provider-secret.v1|${binding.tenant}|${binding.connection}|${reference.value}".getBytes(StandardCharsets.US_ASCII)
