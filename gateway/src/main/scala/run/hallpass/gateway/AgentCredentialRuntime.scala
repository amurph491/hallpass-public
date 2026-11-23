package run.hallpass.gateway

import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.util.Base64
import cats.effect.IO
import cats.syntax.all.*
import run.hallpass.adapters.postgres.PostgresAgentCredentials
import run.hallpass.adapters.security.{AgentCredentialHmacKey, AgentCredentialHmacSha256, AgentCredentialKeyRing}
import run.hallpass.application.{AgentAuthenticator, AgentCredentialRoutes, AgentEnrollmentService}

/** Safe startup failures for the server-only agent credential verifier configuration. */
private[gateway] enum AgentCredentialRuntimeConfigError:
  case MissingKeyConfiguration
  case UnableToReadKeyFile
  case InvalidConfiguration
  case DuplicateKeyId
  case InvalidKeyId
  case InvalidKeyEncoding
  case KeyTooShort
  case UnknownActiveKey

/**
  * HMAC verifier configuration loaded by the server, never by the local bridge.
  *
  * Its string representation intentionally contains only durable key identifiers. The active
  * key signs newly enrolled credentials; retained keys verify existing credentials during an
  * explicit rotation window.
  */
private[gateway] final class AgentCredentialRuntimeConfig private (
    val keyRing: AgentCredentialKeyRing
):
  override def toString: String = s"AgentCredentialRuntimeConfig($keyRing)"

private[gateway] object AgentCredentialRuntimeConfig:
  private val KeyFile = "HALLPASS_AGENT_CREDENTIAL_KEYS_FILE"
  private val ActiveKeyId = "HALLPASS_AGENT_CREDENTIAL_ACTIVE_KEY_ID"
  private val KeyValues = "HALLPASS_AGENT_CREDENTIAL_HMAC_KEYS"

  /**
    * Loads a protected key file when configured. Direct environment configuration exists for
    * managed secret injection, but the file form is preferred for ordinary local operation.
    *
    * File format (one entry per line):
    *   active_key_id=agent-credential-v2
    *   key.agent-credential-v2=BASE64_ENCODED_KEY
    *   key.agent-credential-v1=BASE64_ENCODED_RETAINED_KEY
    *
    * The environment alternative uses `HALLPASS_AGENT_CREDENTIAL_ACTIVE_KEY_ID` plus a comma
    * separated `HALLPASS_AGENT_CREDENTIAL_HMAC_KEYS` value of `key-id:BASE64_ENCODED_KEY` pairs.
    * No raw configuration value is included in errors or diagnostic output.
    */
  def fromEnvironment(
      environment: Map[String, String] = sys.env
  ): Either[AgentCredentialRuntimeConfigError, AgentCredentialRuntimeConfig] =
    environment.get(KeyFile).map(_.trim).filter(_.nonEmpty) match
      case Some(file) =>
        Either
          .catchNonFatal(Files.readString(Path.of(file), StandardCharsets.UTF_8))
          .left
          .map(_ => AgentCredentialRuntimeConfigError.UnableToReadKeyFile)
          .flatMap(parseFile)
      case None => parseEnvironment(environment)

  private def parseFile(value: String): Either[AgentCredentialRuntimeConfigError, AgentCredentialRuntimeConfig] =
    val entries = value.linesIterator.toVector.map(_.stripSuffix("\r")).filterNot: line =>
      line.isEmpty || line.startsWith("#")
    val parsed = entries.traverse: line =>
      line.split("=", 2).toList match
        case name :: encoded :: Nil if name.nonEmpty && encoded.nonEmpty && name == name.trim && encoded == encoded.trim =>
          Right(name -> encoded)
        case _ => Left(AgentCredentialRuntimeConfigError.InvalidConfiguration)
    parsed.flatMap: values =>
      if values.map(_._1).distinct.size != values.size then Left(AgentCredentialRuntimeConfigError.InvalidConfiguration)
      else
        val fields = values.toMap
        fields.get("active_key_id") match
          case None => Left(AgentCredentialRuntimeConfigError.InvalidConfiguration)
          case Some(active) =>
            val unknown = fields.keys.exists(name => name != "active_key_id" && !name.startsWith("key."))
            if unknown then Left(AgentCredentialRuntimeConfigError.InvalidConfiguration)
            else build(active, fields.toVector.collect { case (name, encoded) if name.startsWith("key.") => name.drop(4) -> encoded })

  private def parseEnvironment(
      environment: Map[String, String]
  ): Either[AgentCredentialRuntimeConfigError, AgentCredentialRuntimeConfig] =
    val active = environment.get(ActiveKeyId).filter(strictValue)
    val encodedKeys = environment.get(KeyValues).filter(strictValue)
    (active, encodedKeys) match
      case (None, None) => Left(AgentCredentialRuntimeConfigError.MissingKeyConfiguration)
      case (Some(activeKey), Some(keyValues)) =>
        keyValues.split(",", -1).toVector.traverse: entry =>
          entry.split(":", 2).toList match
            case keyId :: encoded :: Nil if strictValue(keyId) && strictValue(encoded) => Right(keyId -> encoded)
            case _ => Left(AgentCredentialRuntimeConfigError.InvalidConfiguration)
        .flatMap(build(activeKey, _))
      case _ => Left(AgentCredentialRuntimeConfigError.InvalidConfiguration)

  private def strictValue(value: String): Boolean = value.nonEmpty && value == value.trim

  private def build(
      activeKeyId: String,
      encodedKeys: Vector[(String, String)]
  ): Either[AgentCredentialRuntimeConfigError, AgentCredentialRuntimeConfig] =
    if !strictValue(activeKeyId) || encodedKeys.isEmpty then Left(AgentCredentialRuntimeConfigError.InvalidConfiguration)
    else if encodedKeys.map(_._1).distinct.size != encodedKeys.size then Left(AgentCredentialRuntimeConfigError.DuplicateKeyId)
    else
      encodedKeys
        .traverse: (id, encoded) =>
          decodeKey(encoded).flatMap: bytes =>
            AgentCredentialHmacKey.fromBytes(id, bytes).left.map:
              case run.hallpass.adapters.security.AgentCredentialKeyConfigurationError.InvalidKeyId =>
                AgentCredentialRuntimeConfigError.InvalidKeyId
              case run.hallpass.adapters.security.AgentCredentialKeyConfigurationError.KeyTooShort =>
                AgentCredentialRuntimeConfigError.KeyTooShort
              case _ => AgentCredentialRuntimeConfigError.InvalidConfiguration
        .flatMap: keys =>
          AgentCredentialKeyRing.from(activeKeyId, keys).left.map:
            case run.hallpass.adapters.security.AgentCredentialKeyConfigurationError.UnknownActiveKey =>
              AgentCredentialRuntimeConfigError.UnknownActiveKey
            case run.hallpass.adapters.security.AgentCredentialKeyConfigurationError.DuplicateKeyId =>
              AgentCredentialRuntimeConfigError.DuplicateKeyId
            case _ => AgentCredentialRuntimeConfigError.InvalidConfiguration
        .map(new AgentCredentialRuntimeConfig(_))

  private def decodeKey(value: String): Either[AgentCredentialRuntimeConfigError, Array[Byte]] =
    try
      val decoded = Base64.getDecoder.decode(value)
      if Base64.getEncoder.encodeToString(decoded) == value then Right(decoded)
      else Left(AgentCredentialRuntimeConfigError.InvalidKeyEncoding)
    catch case _: IllegalArgumentException => Left(AgentCredentialRuntimeConfigError.InvalidKeyEncoding)

/** Internal composition passed to the HTTP edge. Neither service accepts a tenant: authentication routes the
  * credential's selector through the directory, and enrollment takes the authenticated human's tenant. */
private[gateway] final case class AgentCredentialServices(
    authenticator: AgentAuthenticator[IO],
    enrollment: AgentEnrollmentService[IO]
)

private[gateway] object AgentCredentialServices:
  def compose(
      config: AgentCredentialRuntimeConfig,
      credentials: PostgresAgentCredentials,
      routes: AgentCredentialRoutes[IO]
  ): AgentCredentialServices =
    val verifier = AgentCredentialHmacSha256(config.keyRing)
    AgentCredentialServices(
      new AgentAuthenticator[IO](routes, credentials, verifier),
      new AgentEnrollmentService[IO](credentials, verifier)
    )
