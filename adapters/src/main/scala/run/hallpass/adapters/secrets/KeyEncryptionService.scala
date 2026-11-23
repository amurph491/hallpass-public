package run.hallpass.adapters.secrets

import java.net.URI
import java.net.http.{HttpClient, HttpRequest}
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Path}
import java.util.Base64
import scala.concurrent.duration.*
import scala.util.Try
import cats.effect.{IO, Ref}
import run.hallpass.adapters.http.BoundedHttpResponse
import io.circe.Json
import io.circe.parser.parse
import run.hallpass.kernel.TenantId

/** A data key wrapped by a key-encryption service. The value is opaque to Hallpass and names the key version it used. */
final case class WrappedDataKey private (value: String):
  override def toString: String = "WrappedDataKey(<opaque>)"
object WrappedDataKey:
  private[secrets] def issued(value: String): WrappedDataKey = WrappedDataKey(value)

  /** A wrapped key read back from storage. It is only ever passed to the key service, which authenticates it. */
  def fromStored(value: String): WrappedDataKey = WrappedDataKey(value)

enum KeyServiceError:
  /** The service could not be reached or answered unusably. Callers fail closed; nothing retries in a loop. */
  case Unavailable

  /** The service refused the operation: a wrong context (tenant), a tampered value, or an unacceptable key policy. */
  case Rejected

/** Envelope-encryption key service: wraps and unwraps per-secret data keys under a key-encryption key that never leaves
  * the service. Each operation is bound to a tenant, so a wrapped key copied to another tenant cannot be unwrapped. */
trait KeyEncryptionService:
  /** Stable name of the key-encryption key, stored with each secret. */
  def keyName: String
  def wrap(dataKey: Array[Byte], tenant: TenantId): IO[Either[KeyServiceError, WrappedDataKey]]
  def unwrap(wrapped: WrappedDataKey, tenant: TenantId): IO[Either[KeyServiceError, Array[Byte]]]

  /** Re-encrypts under the newest key version without exposing the data key. */
  def rewrap(wrapped: WrappedDataKey, tenant: TenantId): IO[Either[KeyServiceError, WrappedDataKey]]

  /** Whether `wrapped` already uses the newest key version. Unavailable when the version cannot be determined. */
  def current(wrapped: WrappedDataKey): IO[Either[KeyServiceError, Boolean]]

/** Vault (or OpenBao) Transit configuration. The token is read from a file on every call, so an agent sink can rotate
  * it without a restart. */
final class VaultTransitConfig private (
    val address: URI,
    val tokenFile: Path,
    val mount: String,
    val key: String,
    val namespace: Option[String]
):
  override def toString: String = s"VaultTransitConfig(address=$address, mount=$mount, key=$key, token=<file>)"

object VaultTransitConfig:
  private val Name = "[A-Za-z0-9][A-Za-z0-9_.-]{0,127}".r
  private val MountPath = "[A-Za-z0-9][A-Za-z0-9_./-]{0,127}".r

  def from(
      address: String,
      tokenFile: String,
      mount: String,
      key: String,
      namespace: Option[String],
      requireHttps: Boolean
  ): Either[String, VaultTransitConfig] =
    for
      uri <- Try(URI.create(address.stripSuffix("/"))).toOption
        .filter(uri =>
          uri.isAbsolute && uri.getHost != null && Option(uri.getRawPath).forall(_.isEmpty) && uri.getRawQuery == null &&
            (uri.getScheme == "https" || (!requireHttps && uri.getScheme == "http"))
        )
        .toRight(if requireHttps then "the Vault address must be an https URL without a path" else "the Vault address must be an http(s) URL without a path")
      _ <- Either.cond(tokenFile.trim.nonEmpty, (), "a Vault token file is required")
      _ <- Either.cond(MountPath.matches(mount) && !mount.contains(".."), (), "the Vault transit mount path is invalid")
      _ <- Either.cond(Name.matches(key), (), "the Vault transit key name is invalid")
      _ <- Either.cond(namespace.forall(value => MountPath.matches(value) && !value.contains("..")), (), "the Vault namespace is invalid")
    yield VaultTransitConfig(uri, Path.of(tokenFile.trim), mount.stripSuffix("/"), key, namespace)

/** Vault Transit as the key-encryption service.
  *
  * The transit key must be `aes256-gcm96` and created with `derived=true`. Each call passes the tenant ID as the
  * derivation context, so Vault derives a per-tenant key and a wrapped key from one tenant fails authentication under
  * another. The key policy is verified before the first wrap and cached; a non-derived key or another type is refused,
  * so a misconfigured key can never protect new secrets. */
final class VaultTransitKeyEncryption private (
    config: VaultTransitConfig,
    http: HttpClient,
    verified: Ref[IO, Boolean],
    timeout: FiniteDuration
) extends KeyEncryptionService:
  import VaultTransitKeyEncryption.*

  val keyName: String = s"vault-transit:${config.mount}/${config.key}"

  def wrap(dataKey: Array[Byte], tenant: TenantId): IO[Either[KeyServiceError, WrappedDataKey]] =
    verifiedPolicy.flatMap:
      case Left(error) => IO.pure(Left(error))
      case Right(()) =>
        val plaintext = Base64.getEncoder.encodeToString(dataKey)
        post(s"encrypt/${config.key}", Json.obj("plaintext" -> Json.fromString(plaintext), "context" -> context(tenant)))
          .map(_.flatMap(ciphertext))

  def unwrap(wrapped: WrappedDataKey, tenant: TenantId): IO[Either[KeyServiceError, Array[Byte]]] =
    post(s"decrypt/${config.key}", Json.obj("ciphertext" -> Json.fromString(wrapped.value), "context" -> context(tenant)))
      .map(_.flatMap: data =>
        data.hcursor.get[String]("plaintext").toOption
          .flatMap(value => Try(Base64.getDecoder.decode(value)).toOption)
          .toRight(KeyServiceError.Unavailable)
      )

  def rewrap(wrapped: WrappedDataKey, tenant: TenantId): IO[Either[KeyServiceError, WrappedDataKey]] =
    post(s"rewrap/${config.key}", Json.obj("ciphertext" -> Json.fromString(wrapped.value), "context" -> context(tenant)))
      .map(_.flatMap(ciphertext))

  def current(wrapped: WrappedDataKey): IO[Either[KeyServiceError, Boolean]] =
    keyInfo.map(_.flatMap: info =>
      (version(wrapped), info.hcursor.get[Int]("latest_version").toOption) match
        case (Some(used), Some(latest)) => Right(used >= latest)
        case _                          => Left(KeyServiceError.Unavailable)
    )

  private def verifiedPolicy: IO[Either[KeyServiceError, Unit]] =
    verified.get.flatMap:
      case true => IO.pure(Right(()))
      case false =>
        keyInfo.flatMap:
          case Left(error) => IO.pure(Left(error))
          case Right(info) =>
            val cursor = info.hcursor
            val acceptable = cursor.get[String]("type").contains("aes256-gcm96") &&
              cursor.get[Boolean]("derived").contains(true) &&
              cursor.get[Boolean]("supports_encryption").contains(true)
            if acceptable then verified.set(true).as(Right(())) else IO.pure(Left(KeyServiceError.Rejected))

  private def keyInfo: IO[Either[KeyServiceError, Json]] = send("GET", s"keys/${config.key}", None)

  private def post(operation: String, body: Json): IO[Either[KeyServiceError, Json]] = send("POST", operation, Some(body))

  /** One bounded request. Vault answers 400 when it refuses the data itself (for example an authentication failure under
    * the wrong tenant context), which is `Rejected`. Everything else that is not 200 (a bad or expired token, a missing
    * key, throttling, 5xx), transport errors, timeouts, and a missing token file are `Unavailable`. Redirects are never
    * followed. */
  private def send(method: String, operation: String, body: Option[Json]): IO[Either[KeyServiceError, Json]] =
    IO.blocking:
      val token = Files.readString(config.tokenFile, StandardCharsets.UTF_8).trim
      if token.isEmpty then throw IllegalStateException("empty Vault token")
      val builder = HttpRequest
        .newBuilder(URI.create(s"${config.address}/v1/${config.mount}/$operation"))
        .timeout(java.time.Duration.ofMillis(timeout.toMillis))
        .header("X-Vault-Token", token)
        .header("Accept", "application/json")
      config.namespace.foreach(builder.header("X-Vault-Namespace", _))
      val request = body match
        case Some(json) => builder.header("Content-Type", "application/json").method(method, HttpRequest.BodyPublishers.ofString(json.noSpaces))
        case None       => builder.method(method, HttpRequest.BodyPublishers.noBody())
      request.build()
    .flatMap(request => BoundedHttpResponse.send(http, request, MaximumResponseBytes, timeout))
    .attempt
    .map:
      case Right(response) if response.statusCode() == 200 =>
        parse(String(response.body(), StandardCharsets.UTF_8)).toOption.flatMap(_.hcursor.downField("data").focus).toRight(KeyServiceError.Unavailable)
      case Right(response) if response.statusCode() == 400 => Left(KeyServiceError.Rejected)
      case _ => Left(KeyServiceError.Unavailable)

object VaultTransitKeyEncryption:
  private val MaximumResponseBytes = 64 * 1024
  private val Version = "^vault:v([0-9]{1,9}):".r.unanchored

  def create(config: VaultTransitConfig, timeout: FiniteDuration = 5.seconds): IO[VaultTransitKeyEncryption] =
    Ref.of[IO, Boolean](false).map: verified =>
      val http = HttpClient
        .newBuilder()
        .connectTimeout(java.time.Duration.ofSeconds(5))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build()
      VaultTransitKeyEncryption(config, http, verified, timeout)

  private def context(tenant: TenantId): Json =
    Json.fromString(Base64.getEncoder.encodeToString(s"authai-tenant:$tenant".getBytes(StandardCharsets.US_ASCII)))

  private def ciphertext(data: Json): Either[KeyServiceError, WrappedDataKey] =
    data.hcursor.get[String]("ciphertext").toOption
      .filter(value => value.startsWith("vault:v") && value.length <= 4096)
      .map(WrappedDataKey.issued)
      .toRight(KeyServiceError.Unavailable)

  private[secrets] def version(wrapped: WrappedDataKey): Option[Int] =
    wrapped.value match
      case Version(number) => number.toIntOption
      case _               => None
