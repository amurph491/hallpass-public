package run.hallpass.gateway

import java.net.URI
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import scala.concurrent.duration.*
import cats.effect.{Deferred, IO, Ref, Resource as EffectResource}
import cats.syntax.all.*
import io.circe.Json
import io.circe.parser.parse
import munit.CatsEffectSuite

final class HttpRuntimeSuite extends CatsEffectSuite:
  private val client = HttpClient.newHttpClient()

  private def serve(
      handler: EdgeRequest => IO[DemoApiResponse],
      settings: HttpListenerSettings = HttpListenerSettings.default,
      checks: Vector[ServerLifecycle.ReadinessCheck] = Vector.empty
  ): EffectResource[IO, (URI, ServerLifecycle)] =
    for
      lifecycle <- EffectResource.eval(ServerLifecycle.create(checks))
      server <- HttpRuntime.serve("127.0.0.1", 0, settings, lifecycle, handler)
    yield URI.create(s"http://127.0.0.1:${server.address.getPort}") -> lifecycle

  private def get(base: URI, path: String): IO[HttpResponse[String]] =
    IO.blocking(client.send(HttpRequest.newBuilder(base.resolve(path)).GET().build(), HttpResponse.BodyHandlers.ofString()))

  private def post(base: URI, path: String, body: String): IO[HttpResponse[String]] =
    IO.blocking(
      client.send(
        HttpRequest.newBuilder(base.resolve(path)).POST(HttpRequest.BodyPublishers.ofString(body)).build(),
        HttpResponse.BodyHandlers.ofString()
      )
    )

  private def ok(value: String) = DemoApiResponse(200, Json.obj("value" -> Json.fromString(value)))

  test("requests are served concurrently rather than on one dispatch thread") {
    Deferred[IO, Unit].flatMap: bothArrived =>
      Ref.of[IO, Int](0).flatMap: arrived =>
        val handler = (_: EdgeRequest) =>
          arrived.updateAndGet(_ + 1).flatMap(count => bothArrived.complete(()).whenA(count == 2)) *>
            bothArrived.get.timeout(5.seconds).as(ok("both"))
        serve(handler).use: (base, _) =>
          (get(base, "/a"), get(base, "/b")).parTupled.map: (first, second) =>
            assertEquals(first.statusCode(), 200)
            assertEquals(second.statusCode(), 200)
  }

  test("a request deadline cancels the handler and returns 504") {
    Deferred[IO, Unit].flatMap: cancelled =>
      val handler = (_: EdgeRequest) => IO.never[DemoApiResponse].onCancel(cancelled.complete(()).void)
      serve(handler, HttpListenerSettings.default.copy(requestTimeout = 200.millis)).use: (base, _) =>
        for
          response <- get(base, "/slow")
          _ <- cancelled.get.timeout(5.seconds)
        yield
          assertEquals(response.statusCode(), 504)
          assertEquals(parse(response.body()).flatMap(_.hcursor.get[String]("error")), Right("gateway_timeout"))
  }

  test("the handler sees at most limit + 1 body bytes, headers, and the raw URI") {
    Ref.of[IO, Option[EdgeRequest]](None).flatMap: seen =>
      val handler = (request: EdgeRequest) => seen.set(Some(request)).as(ok("seen"))
      serve(handler, HttpListenerSettings.default.copy(maxBodyBytes = 8)).use: (base, _) =>
        for
          _ <- post(base, "/api/thing?x=1", "0123456789abcdef")
          request <- seen.get.map(_.get)
        yield
          assertEquals(request.method, "POST")
          assertEquals(request.path, "/api/thing")
          assertEquals(request.uri.getRawQuery, "x=1")
          assertEquals(request.body.length, 9)
          assert(Option(request.headers.getFirst("Host")).exists(_.startsWith("127.0.0.1:")))
  }

  test("liveness is unconditional; readiness reports failing components and draining") {
    Ref.of[IO, Boolean](true).flatMap: databaseUp =>
      val checks = Vector(
        ServerLifecycle.ReadinessCheck("database", databaseUp.get),
        ServerLifecycle.ReadinessCheck("tenant_gate", IO.raiseError(RuntimeException("secret detail")))
      )
      serve(_ => IO.pure(ok("unused")), checks = checks).use: (base, lifecycle) =>
        for
          live <- get(base, HttpRuntime.LivePath)
          failingGate <- get(base, HttpRuntime.ReadyPath)
          _ <- databaseUp.set(false)
          bothFailing <- get(base, HttpRuntime.ReadyPath)
          _ <- lifecycle.beginDraining
          draining <- get(base, HttpRuntime.ReadyPath)
          stillServing <- get(base, "/work")
        yield
          assertEquals(live.statusCode(), 200)
          assertEquals(failingGate.statusCode(), 503)
          assertEquals(
            parse(failingGate.body()).flatMap(_.hcursor.get[Vector[String]]("failing")),
            Right(Vector("tenant_gate"))
          )
          assert(!failingGate.body().contains("secret detail"))
          assertEquals(
            parse(bothFailing.body()).flatMap(_.hcursor.get[Vector[String]]("failing")),
            Right(Vector("database", "tenant_gate"))
          )
          assertEquals(parse(draining.body()).flatMap(_.hcursor.get[Vector[String]]("failing")), Right(Vector("draining")))
          assertEquals(stillServing.statusCode(), 200)
  }

  test("a readiness check that hangs is bounded and reported as failing") {
    val checks = Vector(ServerLifecycle.ReadinessCheck("database", IO.never))
    serve(_ => IO.pure(ok("unused")), checks = checks).use: (base, _) =>
      get(base, HttpRuntime.ReadyPath).map(response => assertEquals(response.statusCode(), 503))
  }

  test("handler failures return a generic 500 without internal detail") {
    serve(_ => IO.raiseError(RuntimeException("xoxb-should-not-leak"))).use: (base, _) =>
      get(base, "/boom").map: response =>
        assertEquals(response.statusCode(), 500)
        assert(!response.body().contains("xoxb"))
  }

  test("bodiless statuses send no entity and response headers are preserved") {
    serve(_ => IO.pure(DemoApiResponse(204, Json.obj(), Map("Cache-Control" -> "no-store")))).use: (base, _) =>
      get(base, "/empty").map: response =>
        assertEquals(response.statusCode(), 204)
        assertEquals(response.body(), "")
        assertEquals(response.headers().firstValue("Cache-Control").orElse(""), "no-store")
  }

  test("idle keep-alive connections do not hold shutdown open for the shutdown timeout") {
    for
      allocated <- serve(_ => IO.pure(ok("keep-alive"))).allocated
      ((base, _), release) = allocated
      _ <- get(base, "/one") *> get(base, "/two")
      started <- IO.monotonic
      _ <- release
      elapsed <- IO.monotonic.map(_ - started)
    yield assert(elapsed < 5.seconds, s"shutdown waited $elapsed for idle connections")
  }

  test("an in-flight wait is bounded by the shutdown timeout") {
    for
      started <- Deferred[IO, Unit]
      allocated <- serve(
        _ => started.complete(()) *> IO.never[DemoApiResponse],
        HttpListenerSettings.default.copy(shutdownTimeout = 500.millis)
      ).allocated
      ((base, lifecycle), release) = allocated
      stuck <- get(base, "/stuck").attempt.start
      _ <- started.get
      inFlight <- lifecycle.inFlightCount
      beganRelease <- IO.monotonic
      _ <- release
      elapsed <- IO.monotonic.map(_ - beganRelease)
      _ <- stuck.cancel
    yield
      assertEquals(inFlight, 1)
      assert(elapsed < 5.seconds, s"shutdown was not bounded: $elapsed")
  }

  test("responses served while draining ask the client to close the connection") {
    import org.http4s.{Method, Request, Uri}
    for
      lifecycle <- ServerLifecycle.create(Vector.empty)
      app = HttpRuntime.app(HttpListenerSettings.default, lifecycle, _ => IO.pure(ok("draining")))
      before <- app.run(Request[IO](Method.GET, Uri.unsafeFromString("/work")))
      _ <- lifecycle.beginDraining
      after <- app.run(Request[IO](Method.GET, Uri.unsafeFromString("/work")))
      count <- lifecycle.inFlightCount
    yield
      assertEquals(before.headers.get(org.typelevel.ci.CIString("Connection")), None)
      assertEquals(after.headers.get(org.typelevel.ci.CIString("Connection")).map(_.head.value), Some("close"))
      assertEquals(after.status.code, 200)
      assertEquals(count, 0)
  }

  test("releasing the server waits for an in-flight request to complete") {
    for
      started <- Deferred[IO, Unit]
      finish <- Deferred[IO, Unit]
      handler = (_: EdgeRequest) => started.complete(()) *> finish.get.as(ok("finished"))
      allocated <- serve(handler).allocated
      ((base, _), release) = allocated
      inFlight <- get(base, "/in-flight").start
      _ <- started.get
      shutdown <- release.start
      _ <- IO.sleep(200.millis)
      _ <- finish.complete(())
      response <- inFlight.joinWithNever
      _ <- shutdown.joinWithNever
    yield
      assertEquals(response.statusCode(), 200)
      assertEquals(parse(response.body()).flatMap(_.hcursor.get[String]("value")), Right("finished"))
  }
