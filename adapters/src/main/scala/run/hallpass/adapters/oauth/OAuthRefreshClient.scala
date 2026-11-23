package run.hallpass.adapters.oauth

import java.io.InputStream
import java.net.URI
import java.net.URLEncoder
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.nio.charset.StandardCharsets
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import cats.effect.{IO, Resource}
import scala.concurrent.duration.*
import io.circe.parser.parse
import run.hallpass.application.*

final class OAuthRefreshClient private (
    endpoint: URI,
    clientId: String,
    clientSecret: String,
    clock: Clock[IO],
    connectTimeout: java.time.Duration,
    requestTimeout: java.time.Duration
) extends OAuthTokenRefresher, AutoCloseable:
  private val http = HttpClient
    .newBuilder()
    .connectTimeout(connectTimeout)
    .followRedirects(HttpClient.Redirect.NEVER)
    .build()

  def refresh(tokens: OAuthTokens): IO[Either[OAuthRefreshError, OAuthTokens]] =
    tokens.refreshToken match
      case Some(refreshToken) if validToken(refreshToken) => refreshWithToken(tokens, refreshToken)
      case _ => IO.pure(Left(OAuthRefreshError.InvalidResponse))

  private def refreshWithToken(tokens: OAuthTokens, refreshToken: String): IO[Either[OAuthRefreshError, OAuthTokens]] =
    val body = form(Vector(
      "grant_type" -> "refresh_token",
      "refresh_token" -> refreshToken,
      "client_id" -> clientId,
      "client_secret" -> clientSecret
    ))
    val request = HttpRequest.newBuilder(endpoint)
      .timeout(requestTimeout)
      .header("Accept", "application/json")
      .header("Content-Type", "application/x-www-form-urlencoded")
      .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
      .build()
    send(request).timeoutTo(requestTimeout.toMillis.millis, IO.raiseError(java.util.concurrent.TimeoutException())).attempt.flatMap:
      case Left(failure) if OAuthRefreshClient.notSent(failure) => IO.pure(Left(OAuthRefreshError.NotSent))
      case Left(_) => IO.pure(Left(OAuthRefreshError.Unavailable))
      case Right((status, bytes)) =>
        val parsed = try
          if status == 200 then decodeResponse(bytes, tokens.refreshToken)
          else if status >= 400 && status < 500 then Left(OAuthRefreshError.Rejected)
          else Left(OAuthRefreshError.Unavailable)
        finally java.util.Arrays.fill(bytes, 0.toByte)
        parsed match
          case Left(error) => IO.pure(Left(error))
          case Right((access, refresh, lifetime)) =>
            clock.now.attempt.map:
              case Left(_) => Left(OAuthRefreshError.Unavailable)
              case Right(receivedAt) =>
                scala.util.Try(receivedAt.plusSeconds(lifetime)).toOption
                  .flatMap(expiresAt => OAuthTokens.from(access, refresh, expiresAt))
                  .toRight(OAuthRefreshError.InvalidResponse)

  def close(): Unit = http.close()

  private def send(request: HttpRequest): IO[(Int, Array[Byte])] =
    IO.interruptibleMany(http.send(request, HttpResponse.BodyHandlers.ofInputStream())).flatMap: response =>
      Resource.make(IO.pure(response.body()))(stream => IO.interruptibleMany(stream.close()).handleError(_ => ())).use: stream =>
        IO.interruptibleMany(OAuthRefreshClient.readBounded(stream, OAuthRefreshClient.MaximumResponseBytes)).map(response.statusCode() -> _)

  private def decodeResponse(
      bytes: Array[Byte],
      oldRefreshToken: Option[String]
  ): Either[OAuthRefreshError, (String, Option[String], Long)] =
    val decoded = scala.util.Try(
      StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString
    ).toOption
    decoded.flatMap(parse(_).toOption).flatMap: json =>
      json.asObject.flatMap: fields =>
        val access = fields("access_token").flatMap(_.asString).filter(validToken)
        val tokenType = fields("token_type").flatMap(_.asString).filter(_.equalsIgnoreCase("Bearer"))
        val refresh = fields("refresh_token") match
          case None => Some(oldRefreshToken)
          case Some(value) => value.asString.filter(validToken).map(Some(_))
        val lifetime = fields("expires_in").flatMap(_.asNumber).flatMap(_.toLong)
          .filter(seconds => seconds > 0 && seconds <= OAuthRefreshClient.MaximumLifetimeSeconds)
        for
          _ <- Option.when(!fields.contains("error"))(())
          accessToken <- access
          _ <- tokenType
          refreshToken <- refresh
          expiresIn <- lifetime
        yield (accessToken, refreshToken, expiresIn)
    .toRight(OAuthRefreshError.InvalidResponse)

  private def validToken(value: String): Boolean =
    value.nonEmpty && value.forall(character => !character.isWhitespace && !Character.isISOControl(character))

  private def form(fields: Vector[(String, String)]): String =
    fields.map((key, value) => encode(key) + "=" + encode(value)).mkString("&")

  private def encode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8)

object OAuthRefreshClient:
  /** Failures that occur before any request byte can reach the endpoint: connection refused, connect timeout, or an
    * unresolvable host. A read timeout or reset after connecting is not included; the provider may have acted. */
  private[oauth] def notSent(failure: Throwable): Boolean =
    Iterator.iterate(failure)(_.getCause).takeWhile(_ != null).take(8).exists:
      case _: java.net.http.HttpConnectTimeoutException => true
      case _: java.net.ConnectException                  => true
      case _: java.net.UnknownHostException              => true
      case _: java.nio.channels.UnresolvedAddressException => true
      case _                                             => false

  val MaximumResponseBytes = 64 * 1024
  val MaximumLifetimeSeconds = 365L * 24 * 60 * 60
  private val DefaultConnectTimeout = java.time.Duration.ofSeconds(3)
  private val DefaultRequestTimeout = java.time.Duration.ofSeconds(10)

  /** Client secret never appears in rendering; clients are always constructed here with redirects disabled. */
  final class Config private (
      private[oauth] val endpoint: URI,
      private[oauth] val clientId: String,
      private[oauth] val clientSecret: String,
      private[oauth] val allowHttpLoopback: Boolean
  ):
    override def toString: String = "OAuthRefreshClient.Config(<redacted>)"

  object Config:
    def from(
        endpoint: URI,
        clientId: String,
        clientSecret: String,
        allowHttpLoopback: Boolean = false
    ): Either[String, Config] =
      val safeEndpoint = endpoint != null && endpoint.getHost != null && endpoint.getUserInfo == null &&
        endpoint.getFragment == null && endpoint.getQuery == null
      val scheme = Option(endpoint).flatMap(uri => Option(uri.getScheme)).getOrElse("")
      val secure = safeEndpoint && scheme.equalsIgnoreCase("https")
      val loopback = safeEndpoint && scheme.equalsIgnoreCase("http") && allowHttpLoopback && numericLoopback(endpoint.getHost)
      Either.cond(safeEndpoint && (secure || loopback) && Option(clientId).exists(_.nonEmpty) && Option(clientSecret).exists(_.nonEmpty),
        new Config(endpoint, clientId, clientSecret, allowHttpLoopback), "invalid OAuth token endpoint configuration")

    private def numericLoopback(host: String): Boolean =
      host == "::1" || host.equalsIgnoreCase("[::1]") ||
        host.matches("127(?:\\.[0-9]{1,3}){3}") && host.split('.').forall(part => part.toInt <= 255)

  def create(
      config: Config,
      clock: Clock[IO],
      connectTimeout: java.time.Duration = DefaultConnectTimeout,
      requestTimeout: java.time.Duration = DefaultRequestTimeout
  ): OAuthRefreshClient =
    require(!connectTimeout.isNegative && !connectTimeout.isZero && connectTimeout.compareTo(java.time.Duration.ofSeconds(10)) <= 0)
    require(!requestTimeout.isNegative && !requestTimeout.isZero && requestTimeout.compareTo(java.time.Duration.ofSeconds(30)) <= 0)
    new OAuthRefreshClient(config.endpoint, config.clientId, config.clientSecret, clock, connectTimeout, requestTimeout)

  def resource(
      config: Config,
      clock: Clock[IO],
      connectTimeout: java.time.Duration = DefaultConnectTimeout,
      requestTimeout: java.time.Duration = DefaultRequestTimeout
  ): Resource[IO, OAuthRefreshClient] =
    Resource.fromAutoCloseable(IO.delay(create(config, clock, connectTimeout, requestTimeout)))

  private def readBounded(stream: InputStream, maximum: Int): Array[Byte] =
    val output = Array.ofDim[Byte](maximum)
    val chunk = Array.ofDim[Byte](8192)
    var total = 0
    try
      var count = stream.read(chunk)
      while count >= 0 do
        if count > maximum - total then throw IllegalStateException("OAuth response exceeds the size limit")
        System.arraycopy(chunk, 0, output, total, count)
        total += count
        java.util.Arrays.fill(chunk, 0, count, 0.toByte)
        count = stream.read(chunk)
      java.util.Arrays.copyOf(output, total)
    finally
      java.util.Arrays.fill(chunk, 0.toByte)
      java.util.Arrays.fill(output, 0.toByte)
