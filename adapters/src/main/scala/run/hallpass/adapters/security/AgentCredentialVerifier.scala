package run.hallpass.adapters.security

import java.nio.charset.StandardCharsets
import java.security.{MessageDigest, SecureRandom}
import java.util.{Arrays, Base64}
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import cats.effect.IO
import run.hallpass.application.*
import run.hallpass.kernel.TenantId

/** Configuration failures are deliberately safe to expose, and never contain key material. */
enum AgentCredentialKeyConfigurationError:
  case InvalidKeyId, KeyTooShort, DuplicateKeyId, UnknownActiveKey

/**
  * A server-only HMAC key. The value has no accessor and is redacted from diagnostic output.
  *
  * Key IDs are durable metadata, so an old ID may remain in a key ring while credentials issued
  * with it are still valid. Operators should include their own version in the ID (for example,
  * `agent-credential-v2`).
  */
final class AgentCredentialHmacKey private[security] (
    val id: String,
    private[security] val secret: SecretKeySpec
):
  override def toString: String = s"AgentCredentialHmacKey(id=$id, secret=<redacted>)"

object AgentCredentialHmacKey:
  private val KeyIdPattern = "[A-Za-z0-9][A-Za-z0-9._-]{0,127}"
  private val MinimumKeyBytes = 32

  def fromBytes(id: String, keyBytes: Array[Byte]): Either[AgentCredentialKeyConfigurationError, AgentCredentialHmacKey] =
    if !id.matches(KeyIdPattern) then Left(AgentCredentialKeyConfigurationError.InvalidKeyId)
    else if keyBytes.length < MinimumKeyBytes then Left(AgentCredentialKeyConfigurationError.KeyTooShort)
    else Right(new AgentCredentialHmacKey(id, SecretKeySpec(keyBytes.clone(), "HmacSHA256")))

/**
  * Server-side key configuration. The active key is used for issuance; all configured keys are
  * retained for verification, allowing explicit key rotation without silently accepting unknown
  * key IDs.
  */
final class AgentCredentialKeyRing private (
    val activeKeyId: String,
    private val keysById: Map[String, AgentCredentialHmacKey]
):
  private[security] def keyFor(id: String): Option[AgentCredentialHmacKey] = keysById.get(id)

  override def toString: String =
    s"AgentCredentialKeyRing(activeKeyId=$activeKeyId, keyIds=${keysById.keys.toVector.sorted.mkString("[", ",", "]")})"

object AgentCredentialKeyRing:
  def from(
      activeKeyId: String,
      keys: Seq[AgentCredentialHmacKey]
  ): Either[AgentCredentialKeyConfigurationError, AgentCredentialKeyRing] =
    val keyIds = keys.map(_.id)
    if keyIds.distinct.size != keyIds.size then Left(AgentCredentialKeyConfigurationError.DuplicateKeyId)
    else
      val indexed = keys.map(key => key.id -> key).toMap
      if !indexed.contains(activeKeyId) then Left(AgentCredentialKeyConfigurationError.UnknownActiveKey)
      else Right(new AgentCredentialKeyRing(activeKeyId, indexed))

/**
  * Issues and verifies local agent credentials with domain-separated HMAC-SHA-256 verifiers.
  *
  * The HMAC input binds the full canonical bearer credential to the trusted tenant selected by
  * server configuration. It is intentionally independent of OAuth token hashing and has no JSON
  * or persistence concerns.
  */
final class AgentCredentialHmacSha256 private (
    keys: AgentCredentialKeyRing,
    random: SecureRandom
) extends AgentCredentialIssuer[IO], AgentCredentialVerifier[IO]:
  import AgentCredentialHmacSha256.*

  override def issue(tenant: TenantId): IO[GeneratedAgentCredential] = IO.blocking:
    val selectorBytes = Array.ofDim[Byte](SelectorBytes)
    val secretBytes = Array.ofDim[Byte](SecretBytes)
    var verifierBytes = Array.emptyByteArray
    try
      random.nextBytes(selectorBytes)
      random.nextBytes(secretBytes)
      val selector = Base64.getUrlEncoder.withoutPadding.encodeToString(selectorBytes)
      val secret = Base64.getUrlEncoder.withoutPadding.encodeToString(secretBytes)
      val presented = PresentedAgentCredential
        .parse(s"ac1.$selector.$secret")
        .fold(error => throw IllegalStateException(s"generated invalid agent credential: $error"), identity)
      val activeKey = keys.keyFor(keys.activeKeyId).getOrElse(
        throw IllegalStateException("active agent credential HMAC key is unavailable")
      )
      verifierBytes = hmac(tenant, presented, activeKey)
      val stored = StoredAgentCredentialVerifier
        .fromBytes(verifierBytes)
        .fold(error => throw IllegalStateException(s"generated invalid agent credential verifier: $error"), identity)
      GeneratedAgentCredential.issue(
        AgentCredentialId.random(),
        presented,
        stored,
        CredentialVerifierMetadata(CredentialVerifierAlgorithm.HmacSha256, activeKey.id)
      )
    finally
      Arrays.fill(selectorBytes, 0.toByte)
      Arrays.fill(secretBytes, 0.toByte)
      Arrays.fill(verifierBytes, 0.toByte)

  override def matches(
      tenant: TenantId,
      presented: PresentedAgentCredential,
      stored: StoredAgentCredentialVerifier,
      metadata: CredentialVerifierMetadata
  ): IO[Boolean] = IO.blocking:
    if metadata.algorithm != CredentialVerifierAlgorithm.HmacSha256 then false
    else
      keys.keyFor(metadata.keyId) match
        case None => false // Unknown or retired-without-retention keys fail closed.
        case Some(key) =>
          val actual = StoredAgentCredentialVerifier.bytes(stored)
          var expected = Array.emptyByteArray
          try
            // The database schema and issuer both require a 32-byte HMAC-SHA-256 verifier.
            actual.length == VerifierBytes && {
              expected = hmac(tenant, presented, key)
              MessageDigest.isEqual(expected, actual)
            }
          finally
            Arrays.fill(actual, 0.toByte)
            Arrays.fill(expected, 0.toByte)

  private def hmac(
      tenant: TenantId,
      presented: PresentedAgentCredential,
      key: AgentCredentialHmacKey
  ): Array[Byte] =
    val tenantBytes = tenant.toString.getBytes(StandardCharsets.US_ASCII)
    val credentialBytes = PresentedAgentCredential.canonicalBytes(presented)
    try
      val mac = Mac.getInstance("HmacSHA256")
      mac.init(key.secret)
      mac.update(DomainSeparator)
      mac.update(Separator)
      mac.update(tenantBytes)
      mac.update(Separator)
      mac.doFinal(credentialBytes)
    finally
      Arrays.fill(tenantBytes, 0.toByte)
      Arrays.fill(credentialBytes, 0.toByte)

object AgentCredentialHmacSha256:
  private val SelectorBytes = 12
  private val SecretBytes = 32
  private val VerifierBytes = 32
  private val DomainSeparator = "authai.agent-credential-verifier.v1".getBytes(StandardCharsets.US_ASCII)
  private val Separator = 0.toByte

  def apply(keys: AgentCredentialKeyRing): AgentCredentialHmacSha256 =
    new AgentCredentialHmacSha256(keys, SecureRandom())
