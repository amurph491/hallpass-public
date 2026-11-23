package run.hallpass.adapters.hubspot

import java.net.URI
import java.net.http.{HttpClient, HttpRequest}
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.TimeUnit
import scala.concurrent.duration.FiniteDuration
import cats.effect.IO
import io.circe.{Json, parser}
import run.hallpass.adapters.http.BoundedHttpResponse
import run.hallpass.application.*

/** One authenticated HubSpot CRM request, shared by every operation.
  *
  * The object type in the path is the target's external ID, never an argument. A client is told which object type its
  * operation addresses and refuses any other target before sending anything. Redirects are never followed (a 3xx is
  * `Rejected`), the update is sent once and never retried, and no failure carries a response body, a URL, or the token.
  */
private[hubspot] final class HubSpotRestClient(endpoints: HubSpotEndpoints, http: HttpClient, requestTimeout: Duration):
  def get(
      target: SelectedResource[HubSpot.ObjectType],
      expectedType: ExternalId,
      access: HubSpotAccess,
      record: HubSpotRecordId,
      properties: Vector[HubSpotPropertyName]
  ): IO[Json] =
    val query = if properties.isEmpty then "" else "?properties=" + properties.map(_.value).mkString(",")
    execute(target, expectedType, access, record, query, false, _.GET())

  /** One `PATCH` with a JSON body; the status must be exactly 200. */
  def patch(
      target: SelectedResource[HubSpot.ObjectType],
      expectedType: ExternalId,
      access: HubSpotAccess,
      record: HubSpotRecordId,
      body: Json
  ): IO[Json] =
    execute(
      target,
      expectedType,
      access,
      record,
      "",
      true,
      _.header("Content-Type", "application/json")
        .method("PATCH", HttpRequest.BodyPublishers.ofString(body.noSpaces, StandardCharsets.UTF_8))
    )

  private def execute(
      target: SelectedResource[HubSpot.ObjectType],
      expectedType: ExternalId,
      access: HubSpotAccess,
      record: HubSpotRecordId,
      query: String,
      write: Boolean,
      method: HttpRequest.Builder => HttpRequest.Builder
  ): IO[Json] =
    val selected = HubSpotObjectRef.parse(target.externalId.value).filter: ref =>
      (target.kind eq HubSpot.objectType) && ref.objectType == expectedType &&
        target.scope.path.drop(1).headOption.exists(_.externalId == ref.portal)
    selected match
      case None => IO.raiseError(ProviderExecutionException(ProviderError.Rejected))
      case Some(ref) =>
        val base = endpoints.api.toString.stripSuffix("/")
        // The type and portal are checked against the selected resource; an argument never builds the provider path.
        val objectType = ref.objectType.value
        val uri = URI.create(base + "/crm/v3/objects/" + objectType + "/" + record.value + query)
        val builder = HttpRequest
          .newBuilder(uri)
          .timeout(requestTimeout)
          .header("Authorization", "Bearer " + access.accessToken)
          .header("User-Agent", "hallpass")
          .header("Accept-Encoding", "identity")
        val request = method(builder).build()
        BoundedHttpResponse
          .send(http, request, HubSpotRestClient.MaximumBodyBytes, FiniteDuration(requestTimeout.toNanos, TimeUnit.NANOSECONDS))
          .handleErrorWith(error => IO.raiseError(HubSpotRestClient.classify(error, write)))
          .flatMap: response =>
            val status = response.statusCode()
            if status == 401 || status == 403 then IO.raiseError(ProviderExecutionException(ProviderError.AuthenticationFailed))
            else if write && status >= 500 then IO.raiseError(ProviderExecutionException(ProviderError.OutcomeUnknown))
            else if (write && status != 200) || (!write && status / 100 != 2) then
              IO.raiseError(ProviderExecutionException(if status / 100 == 2 then ProviderError.InvalidResponse else ProviderError.Rejected))
            else
              parser.parse(String(response.body(), StandardCharsets.UTF_8)) match
                case Right(json) => IO.pure(json)
                case Left(_)     => IO.raiseError(ProviderExecutionException(ProviderError.InvalidResponse))

private[hubspot] object HubSpotRestClient:
  val MaximumBodyBytes: Int = 1024 * 1024
  private def classify(error: Throwable, write: Boolean): ProviderExecutionException =
    val root = error match
      case wrapped: java.util.concurrent.CompletionException if wrapped.getCause != null => wrapped.getCause
      case other                                                                         => other
    root match
      case _: java.io.IOException | _: java.util.concurrent.TimeoutException if write =>
        // A response may have been lost after HubSpot applied the PATCH. Keep its outcome unknown and never retry.
        ProviderExecutionException(ProviderError.OutcomeUnknown)
      case _: java.net.http.HttpTimeoutException | _: java.net.ConnectException | _: java.util.concurrent.TimeoutException =>
        // These JDK transport exceptions carry no request headers, so the cause is safe to retain.
        ProviderExecutionException.withSafeCause(ProviderError.Timeout, root)
      case _: IllegalStateException if Option(root.getMessage).exists(_.contains("size limit")) =>
        ProviderExecutionException(ProviderError.InvalidResponse)
      case _ => ProviderExecutionException(ProviderError.Rejected)
