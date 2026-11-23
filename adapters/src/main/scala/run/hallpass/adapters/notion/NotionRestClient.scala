package run.hallpass.adapters.notion

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

/** One authenticated Notion REST request, shared by every operation.
  *
  * The request path is built from the selected page's external ID (a normalized [[NotionId]]) and never from an
  * argument string. If the target's external ID is not a Notion ID, nothing is sent. Redirects are never followed (a
  * 3xx is `Rejected`), a write is sent once and never retried, and no failure carries a response body, a URL, or the
  * token.
  */
private[notion] final class NotionRestClient(endpoints: NotionEndpoints, http: HttpClient, requestTimeout: Duration):
  /** `path` is a fixed literal containing [[NotionRestClient.PageMarker]], replaced by the target's normalized ID. */
  def get(
      target: SelectedResource[Notion.Page],
      access: NotionAccess,
      path: String,
      query: Vector[(String, String)]
  ): IO[Json] =
    val queryText =
      if query.isEmpty then ""
      else query.map((name, value) => name + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8)).mkString("?", "&", "")
    execute(target, access, path + queryText, None, _.GET())

  /** One `PATCH` with a JSON body; the status must be exactly `expected`. */
  def patch(
      target: SelectedResource[Notion.Page],
      access: NotionAccess,
      path: String,
      body: Json,
      expected: Int
  ): IO[Json] =
    execute(
      target,
      access,
      path,
      Some(expected),
      _.header("Content-Type", "application/json")
        .method("PATCH", HttpRequest.BodyPublishers.ofString(body.noSpaces, StandardCharsets.UTF_8))
    )

  private def execute(
      target: SelectedResource[Notion.Page],
      access: NotionAccess,
      pathAndQuery: String,
      expected: Option[Int],
      method: HttpRequest.Builder => HttpRequest.Builder
  ): IO[Json] =
    NotionId.fromExternal(target.externalId) match
      case None => IO.raiseError(ProviderExecutionException(ProviderError.Rejected))
      case Some(page) =>
        val base = endpoints.api.toString.stripSuffix("/")
        val builder = HttpRequest
          .newBuilder(URI.create(base + pathAndQuery.replace(NotionRestClient.PageMarker, page.value)))
          .timeout(requestTimeout)
          .header("Authorization", "Bearer " + access.accessToken)
          .header("Notion-Version", Notion.ApiVersion)
          .header("User-Agent", "hallpass")
          .header("Accept-Encoding", "identity")
        val request = method(builder).build()
        BoundedHttpResponse
          .send(http, request, NotionRestClient.MaximumBodyBytes, FiniteDuration(requestTimeout.toNanos, TimeUnit.NANOSECONDS))
          .handleErrorWith(error =>
            IO.raiseError(if expected.nonEmpty then ProviderExecutionException(ProviderError.OutcomeUnknown)
              else NotionRestClient.classify(error)))
          .flatMap: response =>
            val status = response.statusCode()
            if status == 401 || status == 403 then IO.raiseError(ProviderExecutionException(ProviderError.AuthenticationFailed))
            else if expected.nonEmpty && (status == 408 || status >= 500) then
              IO.raiseError(ProviderExecutionException(ProviderError.OutcomeUnknown))
            else if status / 100 != 2 then IO.raiseError(ProviderExecutionException(ProviderError.Rejected))
            else if expected.exists(_ != status) then IO.raiseError(ProviderExecutionException(ProviderError.InvalidResponse))
            else
              parser.parse(String(response.body(), StandardCharsets.UTF_8)) match
                case Right(json) => IO.pure(json)
                case Left(_)     => IO.raiseError(ProviderExecutionException(ProviderError.InvalidResponse))

private[notion] object NotionRestClient:
  val MaximumBodyBytes: Int = 1024 * 1024
  /** Replaced by the target's normalized ID. Callers pass fixed literals containing it, never argument text. */
  val PageMarker = "{page}"

  private def classify(error: Throwable): ProviderExecutionException =
    val root = error match
      case wrapped: java.util.concurrent.CompletionException if wrapped.getCause != null => wrapped.getCause
      case other                                                                         => other
    root match
      case _: java.net.http.HttpTimeoutException | _: java.net.ConnectException | _: java.util.concurrent.TimeoutException =>
        // These JDK transport exceptions carry no request headers, so the cause is safe to retain.
        ProviderExecutionException.withSafeCause(ProviderError.Timeout, root)
      case _: IllegalStateException if Option(root.getMessage).exists(_.contains("size limit")) =>
        ProviderExecutionException(ProviderError.InvalidResponse)
      case _ => ProviderExecutionException(ProviderError.Rejected)
