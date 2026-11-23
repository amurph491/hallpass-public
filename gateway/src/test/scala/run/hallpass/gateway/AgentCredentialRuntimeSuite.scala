package run.hallpass.gateway

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.util.Base64
import munit.FunSuite

final class AgentCredentialRuntimeSuite extends FunSuite:
  private val encodedKey = Base64.getEncoder.encodeToString(Array.fill[Byte](32)(7))

  test("missing credential verifier configuration fails closed") {
    assertEquals(
      AgentCredentialRuntimeConfig.fromEnvironment(Map.empty),
      Left(AgentCredentialRuntimeConfigError.MissingKeyConfiguration)
    )
  }

  test("loads a protected key file before any environment key material") {
    val file = Files.createTempFile("hallpass-agent-credential-", ".keys")
    try
      Files.writeString(
        file,
        s"""active_key_id=agent-credential-v2
           |key.agent-credential-v2=$encodedKey
           |key.agent-credential-v1=$encodedKey
           |""".stripMargin,
        StandardCharsets.UTF_8
      )
      val loaded = AgentCredentialRuntimeConfig.fromEnvironment(
        Map(
          "HALLPASS_AGENT_CREDENTIAL_KEYS_FILE" -> file.toString,
          "HALLPASS_AGENT_CREDENTIAL_ACTIVE_KEY_ID" -> "incorrect",
          "HALLPASS_AGENT_CREDENTIAL_HMAC_KEYS" -> "incorrect:not-a-key"
        )
      )
      assert(loaded.isRight)
      val rendered = loaded.toOption.get.toString
      assert(rendered.contains("agent-credential-v2"))
      assert(!rendered.contains(encodedKey))
    finally Files.deleteIfExists(file)
  }

  test("unknown active key fails closed") {
    assertEquals(
      AgentCredentialRuntimeConfig.fromEnvironment(
        Map(
          "HALLPASS_AGENT_CREDENTIAL_ACTIVE_KEY_ID" -> "agent-credential-v2",
          "HALLPASS_AGENT_CREDENTIAL_HMAC_KEYS" -> s"agent-credential-v1:$encodedKey"
        )
      ),
      Left(AgentCredentialRuntimeConfigError.UnknownActiveKey)
    )
  }

  test("short key material fails closed without echoing it") {
    val shortKey = Base64.getEncoder.encodeToString(Array.fill[Byte](31)(1))
    val loaded = AgentCredentialRuntimeConfig.fromEnvironment(
      Map(
        "HALLPASS_AGENT_CREDENTIAL_ACTIVE_KEY_ID" -> "agent-credential-v1",
        "HALLPASS_AGENT_CREDENTIAL_HMAC_KEYS" -> s"agent-credential-v1:$shortKey"
      )
    )
    assertEquals(loaded, Left(AgentCredentialRuntimeConfigError.KeyTooShort))
    assert(!loaded.toString.contains(shortKey))
  }

  test("non-canonical base64 key material fails closed") {
    assertEquals(
      AgentCredentialRuntimeConfig.fromEnvironment(
        Map(
          "HALLPASS_AGENT_CREDENTIAL_ACTIVE_KEY_ID" -> "agent-credential-v1",
          "HALLPASS_AGENT_CREDENTIAL_HMAC_KEYS" -> "agent-credential-v1:not base64"
        )
      ),
      Left(AgentCredentialRuntimeConfigError.InvalidKeyEncoding)
    )
  }
