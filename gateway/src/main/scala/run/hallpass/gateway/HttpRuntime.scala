package run.hallpass.gateway

import java.net.URI
import java.nio.charset.StandardCharsets
import scala.concurrent.duration.*
import cats.effect.{IO, Ref, Resource as EffectResource}
import cats.syntax.all.*
import com.comcast.ip4s.{Host, Port}
import com.sun.net.httpserver.Headers
import fs2.Stream
import io.circe.Json
import org.http4s.{Header, HttpApp, Method, Request, Response, Status, Headers as Http4sHeaders}
import org.http4s.ember.server.EmberServerBuilder
import org.http4s.server.Server
import org.typelevel.ci.CIString
import org.typelevel.log4cats.LoggerFactory
import org.typelevel.log4cats.noop.NoOpFactory
import run.hallpass.application.{CounterMetric, HistogramMetric, SafeAttribute, Telemetry, TraceSpan}

/** Protocol-neutral view of an HTTP request passed to the existing edge handlers.
  *
  * The body is read up to `limit + 1` bytes, so a handler can detect an oversized request without the runtime buffering
  * an unbounded body. Headers use the JDK `Headers` type the handlers already validate, with case-insensitive names.
  */
private[gateway] final case class EdgeRequest(
    method: String,
    uri: URI,
    headers: Headers,
    body: Array[Byte],
    peer: Option[java.net.InetAddress] = None
):
  def path: String = uri.getPath

/** Telemetry for one listener: which listener it is, and how to turn a path into a literal route template. */
private[gateway] final case class HttpObservation(
    telemetry: Telemetry,
    listener: SafeAttribute.Label,
    route: String => SafeAttribute.Label
)

private[gateway] object HttpObservation:
  val none: HttpObservation = HttpObservation(Telemetry.noop, SafeAttribute.Label.of("unobserved"), _ => SafeAttribute.Label.of("other"))

/** Bounded, safe limits for one listener. */
private[gateway] final case class HttpListenerSettings(
    requestTimeout: FiniteDuration,
    idleTimeout: FiniteDuration,
    headerReceiveTimeout: FiniteDuration,
    shutdownTimeout: FiniteDuration,
    maxConnections: Int,
    maxHeaderBytes: Int,
    maxBodyBytes: Int
)

private[gateway] object HttpListenerSettings:
  /** Longer than the executor's own bounds (gate acquisition 10 s + Slack request 10 s) so the deadline is a backstop
    * rather than the normal way an execution ends. */
  val default: HttpListenerSettings = HttpListenerSettings(
    requestTimeout = 30.seconds,
    idleTimeout = 60.seconds,
    headerReceiveTimeout = 5.seconds,
    shutdownTimeout = 35.seconds,
    maxConnections = 512,
    maxHeaderBytes = 16 * 1024,
    maxBodyBytes = 16 * 1024
  )

  /** After in-flight requests finish, idle keep-alive sockets are closed within this grace. Ember's own graceful
    * shutdown would otherwise hold every idle connection open for the whole shutdown timeout. */
  val IdleConnectionCloseGrace: FiniteDuration = 1.second

/** Readiness, drain, and in-flight state shared by both listeners of one process.
  *
  * Draining fails readiness and marks responses `Connection: close`, but requests are still served until the load
  * balancer stops routing. Shutdown then waits for tracked in-flight requests (bounded), not for idle sockets. Checks
  * carry safe component names only, never error text. */
private[gateway] final class ServerLifecycle private (
    draining: Ref[IO, Boolean],
    inFlight: Ref[IO, Int],
    checks: Vector[ServerLifecycle.ReadinessCheck]
):
  def beginDraining: IO[Unit] = draining.set(true)
  def isDraining: IO[Boolean] = draining.get

  /** Counts `request` as in flight from start until it completes, fails, or is cancelled. */
  def track[A](request: IO[A]): IO[A] =
    IO.uncancelable(poll => inFlight.update(_ + 1) *> poll(request).guarantee(inFlight.update(_ - 1)))

  def inFlightCount: IO[Int] = inFlight.get

  /** Waits until no request is in flight, or `timeout` elapses. Returns whether the process became idle. */
  def awaitIdle(timeout: FiniteDuration): IO[Boolean] =
    def loop: IO[Unit] = inFlight.get.flatMap(count => IO.unlessA(count == 0)(IO.sleep(20.millis) *> loop))
    loop.as(true).timeoutTo(timeout, IO.pure(false))

  def readiness: IO[Either[Vector[String], Unit]] =
    draining.get.flatMap:
      case true => IO.pure(Left(Vector("draining")))
      case false =>
        checks
          .parTraverse: check =>
            check.healthy.timeoutTo(ServerLifecycle.CheckTimeout, IO.pure(false)).handleError(_ => false).map(check.name -> _)
          .map: results =>
            val failing = results.collect { case (name, false) => name }
            Either.cond(failing.isEmpty, (), failing)

private[gateway] object ServerLifecycle:
  final case class ReadinessCheck(name: String, healthy: IO[Boolean])
  val CheckTimeout: FiniteDuration = 2.seconds

  def create(checks: Vector[ReadinessCheck]): IO[ServerLifecycle] =
    (Ref.of[IO, Boolean](false), Ref.of[IO, Int](0)).mapN(new ServerLifecycle(_, _, checks))

/** Serves an edge handler on http4s Ember.
  *
  * Ember provides bounded connections and header-receive and idle timeouts. Each request additionally has a deadline;
  * when it elapses the handler is cancelled and the client receives 504. Cancellation is safe for execution: the
  * executor makes provider dispatch and its audit record uncancelable, so a deadline cannot erase the outcome of a
  * request already sent to a provider.
  *
  * On release, the listener first waits (up to `shutdownTimeout`) for tracked in-flight requests, then stops Ember with
  * a short grace so idle keep-alive sockets do not hold shutdown open.
  */
private[gateway] object HttpRuntime:
  val LivePath = "/health/live"
  val ReadyPath = "/health/ready"

  private given LoggerFactory[IO] = NoOpFactory[IO]

  def serve(
      host: String,
      port: Int,
      settings: HttpListenerSettings,
      lifecycle: ServerLifecycle,
      handler: EdgeRequest => IO[DemoApiResponse],
      observation: HttpObservation = HttpObservation.none
  ): EffectResource[IO, Server] =
    for
      parsedHost <- EffectResource.eval(IO.fromOption(Host.fromString(host))(IllegalArgumentException("invalid bind host")))
      parsedPort <- EffectResource.eval(IO.fromOption(Port.fromInt(port))(IllegalArgumentException("invalid port")))
      server <- EmberServerBuilder
        .default[IO]
        .withHost(parsedHost)
        .withPort(parsedPort)
        .withHttpApp(app(settings, lifecycle, handler, observation))
        .withIdleTimeout(settings.idleTimeout)
        .withRequestHeaderReceiveTimeout(settings.headerReceiveTimeout)
        .withShutdownTimeout(HttpListenerSettings.IdleConnectionCloseGrace)
        .withMaxConnections(settings.maxConnections)
        .withMaxHeaderSize(settings.maxHeaderBytes)
        .withErrorHandler(_ => IO.pure(render(Method.GET, internalError)))
        .build
      // Acquired after the server, so it is released first: in-flight requests finish before Ember stops.
      _ <- EffectResource.onFinalize(lifecycle.awaitIdle(settings.shutdownTimeout).void)
    yield server

  private[gateway] def app(
      settings: HttpListenerSettings,
      lifecycle: ServerLifecycle,
      handler: EdgeRequest => IO[DemoApiResponse],
      observation: HttpObservation = HttpObservation.none
  ): HttpApp[IO] =
    HttpApp[IO]: request =>
      (request.method, request.uri.path.renderString) match
        case (Method.GET, LivePath) => IO.pure(render(request.method, json(200, "status" -> "live")))
        case (Method.GET, ReadyPath) =>
          lifecycle.readiness.map:
            case Right(_) => render(request.method, json(200, "status" -> "ready"))
            case Left(failing) =>
              render(
                request.method,
                DemoApiResponse(
                  503,
                  Json.obj(
                    "status" -> Json.fromString("not_ready"),
                    "failing" -> Json.arr(failing.map(Json.fromString)*)
                  ),
                  NoStore
                )
              )
        case _ =>
          // Only the method and a literal route template are recorded; never the URL, headers, or body.
          val attributes = Vector(
            SafeAttribute.listener(observation.listener),
            SafeAttribute.method(RouteTemplates.method(request.method.name)),
            SafeAttribute.route(observation.route(request.uri.path.renderString))
          )
          lifecycle.track:
            (
              IO.monotonic.flatMap: started =>
                observation.telemetry
                  .span(TraceSpan.HttpRequest, attributes*)(
                    toEdge(request, settings.maxBodyBytes)
                      .flatMap(handler)
                      .timeoutTo(settings.requestTimeout, IO.pure(timedOut))
                  )
                  .handleError(_ => internalError)
                  .flatTap: response =>
                    IO.monotonic.flatMap: finished =>
                      val measured = attributes :+ SafeAttribute.statusClass(RouteTemplates.statusClass(response.status))
                      observation.telemetry.increment(CounterMetric.HttpRequests, measured*) *>
                        observation.telemetry.record(HistogramMetric.HttpRequestDuration, (finished - started).toNanos / 1e9, measured*)
              ,
              lifecycle.isDraining
            ).mapN: (response, draining) =>
              // While draining, ask clients to reconnect elsewhere instead of reusing this connection.
              val closing = if draining then response.copy(headers = response.headers.updated("Connection", "close")) else response
              render(request.method, closing)

  private def toEdge(request: Request[IO], maxBodyBytes: Int): IO[EdgeRequest] =
    request.body.take(maxBodyBytes.toLong + 1).compile.to(Array).map: body =>
      val headers = new Headers()
      request.headers.headers.foreach(header => headers.add(header.name.toString, header.value))
      EdgeRequest(
        request.method.name,
        URI.create(request.uri.renderString),
        headers,
        body,
        request.remote.map(_.host.toInetAddress)
      )

  private val NoStore = Map("Cache-Control" -> "no-store")

  private def json(status: Int, field: (String, String)): DemoApiResponse =
    DemoApiResponse(status, Json.obj(field._1 -> Json.fromString(field._2)), NoStore)

  private def error(status: Int, code: String, message: String): DemoApiResponse =
    DemoApiResponse(
      status,
      Json.obj("error" -> Json.fromString(code), "message" -> Json.fromString(message)),
      NoStore
    )

  private[gateway] val timedOut: DemoApiResponse = error(504, "gateway_timeout", "The request did not complete in time.")
  private[gateway] val internalError: DemoApiResponse =
    error(500, "internal_error", "The request could not be processed.")

  private def render(method: Method, response: DemoApiResponse): Response[IO] =
    val status = Status.fromInt(response.status).getOrElse(Status.InternalServerError)
    val bytes =
      if method == Method.HEAD || !status.isEntityAllowed then Array.emptyByteArray
      else response.body.noSpaces.getBytes(StandardCharsets.UTF_8)
    val entityHeaders =
      if !status.isEntityAllowed then Nil
      else
        List(
          Header.Raw(CIString("Content-Type"), "application/json; charset=utf-8"),
          Header.Raw(CIString("Content-Length"), bytes.length.toString)
        )
    val headers = entityHeaders ++ response.headers.toList.map((name, value) => Header.Raw(CIString(name), value)) ++
      response.cookies.toList.map(cookie => Header.Raw(CIString("Set-Cookie"), cookie))
    Response[IO](status = status, headers = Http4sHeaders(headers), body = Stream.emits(bytes))
