package run.hallpass.adapters.google

import java.net.URI
import java.net.URLEncoder
import java.net.http.{HttpClient, HttpRequest}
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.TimeUnit
import scala.concurrent.duration.FiniteDuration
import cats.effect.IO
import io.circe.{Json, parser}
import run.hallpass.adapters.http.BoundedHttpResponse
import run.hallpass.application.*

/** Authenticated Drive `GET` requests. The path is built only from the target's external ID, never from an argument
  * string, and the returned metadata id must equal it. A 3xx is `Rejected` (redirects are never followed here), no
  * request is retried, and no failure carries a body, a URL, or the token. */
private[google] final class GoogleRestClient(endpoints: GoogleEndpoints, http: HttpClient, requestTimeout: Duration):
  private def fileUrl(target: SelectedResource[Google.DriveFile], suffix: String): Either[ProviderError, URI] =
    DriveFileId.fromExternal(target.externalId) match
      case None     => Left(ProviderError.Rejected)
      case Some(id) =>
        Right(URI.create(endpoints.driveApi.toString.stripSuffix("/") + "/drive/v3/files/" + id.value + suffix))

  /** Metadata GET; the result's `id` is verified against the target. */
  def metadata(target: SelectedResource[Google.DriveFile], access: GoogleAccess, fields: String): IO[Json] =
    bytes(target, access, "?fields=" + URLEncoder.encode(fields, StandardCharsets.UTF_8)).flatMap: body =>
      parser.parse(String(body, StandardCharsets.UTF_8)) match
        case Right(json) if json.hcursor.get[String]("id").toOption.contains(target.externalId.value) => IO.pure(json)
        case _                                                                                       => fail(ProviderError.InvalidResponse)

  /** Content GET; `suffix` is a fixed literal chosen by the caller (export path or `?alt=media`). */
  def content(target: SelectedResource[Google.DriveFile], access: GoogleAccess, suffix: String): IO[Array[Byte]] =
    bytes(target, access, suffix)

  private def fail[A](error: ProviderError): IO[A] = IO.raiseError(ProviderExecutionException(error))

  private def bytes(target: SelectedResource[Google.DriveFile], access: GoogleAccess, suffix: String): IO[Array[Byte]] =
    fileUrl(target, suffix) match
      case Left(error) => fail(error)
      case Right(uri)  =>
        val request = HttpRequest
          .newBuilder(uri)
          .timeout(requestTimeout)
          .header("Authorization", "Bearer " + access.accessToken)
          .header("Accept-Encoding", "identity")
          .header("User-Agent", "hallpass")
          .GET()
          .build()
        BoundedHttpResponse
          .send(http, request, GoogleRestClient.MaximumBodyBytes, FiniteDuration(requestTimeout.toNanos, TimeUnit.NANOSECONDS))
          .handleErrorWith(error => IO.raiseError(GoogleRestClient.classify(error)))
          .flatMap: response =>
            val status = response.statusCode()
            if status == 401 || status == 403 then fail(ProviderError.AuthenticationFailed)
            else if status / 100 != 2 then fail(ProviderError.Rejected)
            else IO.pure(response.body())

private[google] object GoogleRestClient:
  val MaximumBodyBytes: Int = 512 * 1024
  val GetFields: String = "id,name,mimeType,modifiedTime,size,webViewLink,owners(displayName),trashed"

  private def classify(error: Throwable): ProviderExecutionException =
    val root = error match
      case wrapped: java.util.concurrent.CompletionException if wrapped.getCause != null => wrapped.getCause
      case other                                                                         => other
    root match
      case _: java.net.http.HttpTimeoutException | _: java.net.ConnectException | _: java.util.concurrent.TimeoutException =>
        ProviderExecutionException.withSafeCause(ProviderError.Timeout, root)
      case _: IllegalStateException if Option(root.getMessage).exists(_.contains("size limit")) =>
        ProviderExecutionException(ProviderError.InvalidResponse)
      case _ => ProviderExecutionException(ProviderError.Rejected)
