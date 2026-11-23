package run.hallpass.adapters.linear

import java.net.ConnectException
import java.net.http.{HttpClient, HttpRequest, HttpTimeoutException}
import java.nio.ByteBuffer
import java.nio.charset.{CodingErrorAction, StandardCharsets}
import java.time.Duration
import scala.concurrent.duration.*
import cats.effect.IO
import io.circe.Json
import io.circe.parser.parse
import run.hallpass.adapters.http.BoundedHttpResponse

enum LinearApiError:
  case Unauthorized, Forbidden, RateLimited, Rejected, Timeout, InvalidResponse, OutcomeUnknown

/** Fixed GraphQL documents only: there is no query passthrough. One POST per call, bounded response (1 MiB), no
  * redirects, no retries. `bearer` is an access token and never appears in an error or exception message. A response
  * with a non-empty `errors` array is `Rejected` (or `Unauthorized`/`Forbidden` when every error's
  * `extensions.type` says so), and `data` is returned only when there are no errors. */
final class LinearGraphQl(endpoints: LinearEndpoints, http: HttpClient, requestTimeout: Duration = Duration.ofSeconds(10)):
  def execute(bearer: String, document: LinearDocument, variables: Json): IO[Either[LinearApiError, Json]] =
    IO.delay:
      HttpRequest.newBuilder(endpoints.graphql)
        .timeout(requestTimeout)
        .header("Authorization", "Bearer " + bearer)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .header("User-Agent", "hallpass")
        .POST(HttpRequest.BodyPublishers.ofString(
          Json.obj("query" -> Json.fromString(document.text), "variables" -> variables).noSpaces,
          StandardCharsets.UTF_8))
        .build()
    .attempt.flatMap:
      // An unusable header value (never expected: tokens are validated) is refused without a request or its text.
      case Left(_) => IO.pure(Left(LinearApiError.Rejected))
      case Right(request) =>
        BoundedHttpResponse.send(http, request, LinearGraphQl.MaximumResponseBytes, requestTimeout.toMillis.millis).attempt.map:
          case Left(error) => Left(if document.isMutation then LinearApiError.OutcomeUnknown else LinearGraphQl.classify(error))
          case Right(response) =>
            val bytes = response.body()
            try
              val status = response.statusCode()
              val outcome = LinearGraphQl.interpret(status, bytes)
              if document.isMutation && (status == 408 || status >= 500) then Left(LinearApiError.OutcomeUnknown)
              else if document.isMutation && status == 200 && outcome == Left(LinearApiError.Rejected) then
                // GraphQL can report field errors after the mutation has committed.
                Left(LinearApiError.OutcomeUnknown)
              else outcome
            finally java.util.Arrays.fill(bytes, 0.toByte)

object LinearGraphQl:
  val MaximumResponseBytes: Int = 1024 * 1024
  private val SizeLimitMessage = "HTTP response exceeds the size limit"

  /** Failure messages are discarded: they can carry request detail. */
  private def classify(error: Throwable): LinearApiError =
    val chain = Iterator.iterate(error)(_.getCause).takeWhile(_ != null).take(8).toVector
    if chain.exists(e =>
        e.isInstanceOf[HttpTimeoutException] || e.isInstanceOf[ConnectException] ||
          e.isInstanceOf[java.util.concurrent.TimeoutException])
    then LinearApiError.Timeout
    else if chain.exists(e => e.isInstanceOf[IllegalStateException] && e.getMessage == SizeLimitMessage) then
      LinearApiError.InvalidResponse
    else LinearApiError.Rejected

  private def decodeObject(bytes: Array[Byte]): Option[io.circe.JsonObject] =
    scala.util.Try(
      StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString
    ).toOption.flatMap(parse(_).toOption).flatMap(_.asObject)

  /** Linear reports `extensions.type` ("authentication error") and `extensions.code` ("AUTHENTICATION_ERROR"). */
  private def tags(error: Json): Set[String] =
    val extensions = error.asObject.flatMap(_("extensions")).flatMap(_.asObject)
    Set("type", "code").flatMap: key =>
      extensions.flatMap(_(key)).flatMap(_.asString).map(_.trim.toLowerCase.replace(' ', '_'))

  private def interpret(status: Int, bytes: Array[Byte]): Either[LinearApiError, Json] =
    // Status is checked here, so the JDK redirect policy cannot matter: any 3xx is Rejected.
    status match
      case 401 => Left(LinearApiError.Unauthorized)
      case 403 => Left(LinearApiError.Forbidden)
      case 429 => Left(LinearApiError.RateLimited)
      case 200 =>
        decodeObject(bytes).toRight(LinearApiError.InvalidResponse).flatMap(fromBody)
      case 400 =>
        // Linear signals rate limiting with 400 and a RATELIMITED error.
        val limited = decodeObject(bytes).flatMap(_("errors")).flatMap(_.asArray).exists(_.exists(tags(_).contains("ratelimited")))
        Left(if limited then LinearApiError.RateLimited else LinearApiError.Rejected)
      case other if other >= 200 && other < 300 => Left(LinearApiError.InvalidResponse)
      case _ => Left(LinearApiError.Rejected)

  private def fromBody(body: io.circe.JsonObject): Either[LinearApiError, Json] =
    body("errors") match
      case Some(errors) if !errors.isNull =>
        errors.asArray match
          case None => Left(LinearApiError.InvalidResponse)
          case Some(items) if items.nonEmpty =>
            val all = items.map(tags)
            Left(
              if all.exists(_.contains("ratelimited")) then LinearApiError.RateLimited
              else if all.forall(_.contains("authentication_error")) then LinearApiError.Unauthorized
              else if all.forall(_.contains("forbidden")) then LinearApiError.Forbidden
              else LinearApiError.Rejected
            )
          case Some(_) => data(body)
      case _ => data(body)

  private def data(body: io.circe.JsonObject): Either[LinearApiError, Json] =
    body("data").filter(_.isObject).toRight(LinearApiError.InvalidResponse)

/** A fixed, code-defined GraphQL document. Construct only from string literals in this package. */
final case class LinearDocument private[linear] (text: String, isMutation: Boolean = false)
