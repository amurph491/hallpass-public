package run.hallpass.adapters.security

import java.nio.charset.StandardCharsets
import run.hallpass.application.*
import run.hallpass.kernel.TenantId
import cats.effect.IO
import munit.CatsEffectSuite

final class AgentCredentialVerifierSuite extends CatsEffectSuite:
  private val tenant = TenantId.parse("10000000-0000-4000-8000-000000000001").toOption.get
  private val anotherTenant = TenantId.parse("20000000-0000-4000-8000-000000000002").toOption.get

  private def key(id: String, fill: Byte): AgentCredentialHmacKey =
    AgentCredentialHmacKey.fromBytes(id, Array.fill(32)(fill)).toOption.get

  private def verifier(active: String, keys: AgentCredentialHmacKey*): AgentCredentialHmacSha256 =
    AgentCredentialHmacSha256(AgentCredentialKeyRing.from(active, keys).toOption.get)

  test("issues an ac1 credential with a 32-byte tenant-bound HMAC verifier") {
    val crypto = verifier("agent-credential-v2", key("agent-credential-v2", 2))
    for
      generated <- crypto.issue(tenant)
      wire = String(PresentedAgentCredential.canonicalBytes(generated.credential), StandardCharsets.US_ASCII)
      valid <- crypto.matches(tenant, generated.credential, generated.verifier, generated.verifierMetadata)
      wrongTenant <- crypto.matches(anotherTenant, generated.credential, generated.verifier, generated.verifierMetadata)
    yield
      assert(wire.matches("ac1\\.[A-Za-z0-9_-]{16}\\.[A-Za-z0-9_-]{43}"))
      assertEquals(generated.selector.value.length, 16)
      assertEquals(StoredAgentCredentialVerifier.bytes(generated.verifier).length, 32)
      assertEquals(generated.verifierMetadata, CredentialVerifierMetadata(CredentialVerifierAlgorithm.HmacSha256, "agent-credential-v2"))
      assert(valid)
      assert(!wrongTenant)
  }

  test("retained old key IDs verify existing credentials while the active key issues new credentials") {
    val oldKey = key("agent-credential-v1", 1)
    val currentKey = key("agent-credential-v2", 2)
    val oldCrypto = verifier("agent-credential-v1", oldKey)
    val rotatedCrypto = verifier("agent-credential-v2", oldKey, currentKey)
    for
      oldCredential <- oldCrypto.issue(tenant)
      oldMatches <- rotatedCrypto.matches(tenant, oldCredential.credential, oldCredential.verifier, oldCredential.verifierMetadata)
      newCredential <- rotatedCrypto.issue(tenant)
    yield
      assert(oldMatches)
      assertEquals(newCredential.verifierMetadata.keyId, "agent-credential-v2")
  }

  test("unknown key IDs and wrong credentials fail closed, and malformed verifier bytes are rejected") {
    val crypto = verifier("agent-credential-v1", key("agent-credential-v1", 1))
    val altered = PresentedAgentCredential.parse("ac1.aaaaaaaaaaaaaaaa.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").toOption.get
    assert(StoredAgentCredentialVerifier.fromBytes(Array.fill(31)(1.toByte)).isLeft)
    for
      generated <- crypto.issue(tenant)
      unknownKey <- crypto.matches(
        tenant,
        generated.credential,
        generated.verifier,
        CredentialVerifierMetadata(CredentialVerifierAlgorithm.HmacSha256, "not-configured")
      )
      wrongCredential <- crypto.matches(tenant, altered, generated.verifier, generated.verifierMetadata)
    yield
      assert(!unknownKey)
      assert(!wrongCredential)
  }

  test("key configuration validates key strength, IDs, duplicate IDs, and active-key selection without disclosing keys") {
    val good = key("agent-credential-v1", 1)
    assert(AgentCredentialHmacKey.fromBytes("bad key", Array.fill(32)(1.toByte)).isLeft)
    assert(AgentCredentialHmacKey.fromBytes("agent-credential-v1", Array.fill(31)(1.toByte)).isLeft)
    assert(AgentCredentialKeyRing.from("agent-credential-v1", Seq(good, good)).isLeft)
    assert(AgentCredentialKeyRing.from("not-configured", Seq(good)).isLeft)
    assert(!good.toString.contains("\u0001"))
    assert(good.toString.contains("<redacted>"))
  }
