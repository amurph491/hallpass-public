package run.hallpass.adapters.github

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

/** One authenticated GitHub REST request (`GET` for reads, `POST` for writes), shared by every operation.
  *
  * The request path is built from `token.repository.fullName`, which GitHub reported for the authorized repository ID,
  * and never from an argument string. Before any request is built, the token's repository ID must equal the
  * authorized target's external ID; otherwise nothing is sent. Redirects are never followed by this code (a 3xx is
  * `Rejected`), and no failure carries a response body, a URL, or the token.
  */
private[github] final class GitHubRestClient(
    endpoints: GitHubEndpoints,
    http: HttpClient,
    requestTimeout: Duration
):
  /** `pathSuffix` is a fixed literal beginning with `/` (appended after `/repos/{fullName}`); `query` values are
    * typed, validated values that are URL-encoded here. */
  def get(
      target: SelectedResource[GitHub.Repository],
      token: GitHubInstallationToken,
      pathSuffix: String,
      query: Vector[(String, String)]
  ): IO[Json] =
    val queryText =
      if query.isEmpty then ""
      else query.map((name, value) => name + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8)).mkString("?", "&", "")
    execute(target, token, pathSuffix + queryText, None, _.GET())

  /** One `POST` with a JSON body. The status must be exactly `expected` (a 2xx with any other code is
    * `InvalidResponse`); the executor treats an invalid write response as an unknown outcome. The request is sent
    * once and never retried, because a retried write may duplicate. */
  def post(
      target: SelectedResource[GitHub.Repository],
      token: GitHubInstallationToken,
      pathSuffix: String,
      body: Json,
      expected: Int
  ): IO[Json] =
    execute(
      target,
      token,
      pathSuffix,
      Some(expected),
      _.header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(body.noSpaces, StandardCharsets.UTF_8))
    )

  private def execute(
      target: SelectedResource[GitHub.Repository],
      token: GitHubInstallationToken,
      pathAndQuery: String,
      expected: Option[Int],
      method: HttpRequest.Builder => HttpRequest.Builder
  ): IO[Json] =
    if !GitHubRepositoryId.fromExternal(target.externalId).contains(token.repository.id) then
      IO.raiseError(ProviderExecutionException(ProviderError.Rejected))
    else
      val base = endpoints.api.toString.stripSuffix("/")
      val builder = HttpRequest
        .newBuilder(URI.create(s"$base/repos/${token.repository.fullName.value}$pathAndQuery"))
        .timeout(requestTimeout)
        .header("Authorization", "Bearer " + token.raw)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "hallpass")
        .header("Accept-Encoding", "identity")
      val request = method(builder).build()
      BoundedHttpResponse
        .send(http, request, GitHubRestClient.MaximumBodyBytes, FiniteDuration(requestTimeout.toNanos, TimeUnit.NANOSECONDS))
        .handleErrorWith: error =>
          // Once a POST was submitted, a reset or truncated response cannot prove the write did not commit.
          val classified = GitHubRestClient.classify(error)
          IO.raiseError(if expected.nonEmpty then ProviderExecutionException(ProviderError.OutcomeUnknown) else classified)
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

private[github] object GitHubRestClient:
  val MaximumBodyBytes: Int = 1024 * 1024

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
