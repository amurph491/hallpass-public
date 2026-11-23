package run.hallpass.adapters.linear

import java.net.{InetSocketAddress, URI}
import java.net.http.HttpClient
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference
import scala.jdk.CollectionConverters.*
import cats.effect.{IO, Resource}
import com.sun.net.httpserver.{HttpExchange, HttpServer}
import io.circe.Json
import io.circe.parser.parse
import munit.CatsEffectSuite

final class LinearGraphQlSuite extends CatsEffectSuite:
  private val token = "lin_oauth_secret_token_value"
  private val document = LinearDocument("query Probe($id: String!) { issue(id: $id) { id } }")

  private final case class Recorded(method: String, headers: Map[String, String], body: String)
  private final case class Reply(status: Int, body: String, headers: Map[String, String] = Map.empty, delayMillis: Long = 0, truncate: Boolean = false)
  private final class Fake(val endpoint: URI, val requests: AtomicReference[Vector[Recorded]])

  private def server(handler: Recorded => Reply): Resource[IO, Fake] =
    Resource.make(IO.blocking:
      val requests = AtomicReference(Vector.empty[Recorded])
      val http = HttpServer.create(InetSocketAddress(java.net.InetAddress.getLoopbackAddress, 0), 0)
      http.setExecutor(Executors.newCachedThreadPool())
      http.createContext("/", (exchange: HttpExchange) =>
        val body = String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)
        val headers = exchange.getRequestHeaders.asScala.map((k, v) => k.toLowerCase -> v.asScala.mkString(",")).toMap
        val recorded = Recorded(exchange.getRequestMethod, headers, body)
        requests.updateAndGet(_ :+ recorded)
        val reply = handler(recorded)
        if reply.delayMillis > 0 then Thread.sleep(reply.delayMillis)
        reply.headers.foreach((k, v) => exchange.getResponseHeaders.add(k, v))
        val bytes = reply.body.getBytes(StandardCharsets.UTF_8)
        scala.util.Try:
          exchange.sendResponseHeaders(reply.status, if bytes.isEmpty then -1 else bytes.length.toLong + (if reply.truncate then 10L else 0L))
          if bytes.nonEmpty then exchange.getResponseBody.write(bytes)
        exchange.close()
      )
      http.start()
      (http, Fake(URI.create(s"http://127.0.0.1:${http.getAddress.getPort}/graphql"), requests))
    )((http, _) => IO.blocking(http.stop(0)).void).map(_._2)

  private def api(fake: Fake, timeout: Duration = Duration.ofSeconds(5)) =
    val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    LinearGraphQl(LinearEndpoints(fake.endpoint, fake.endpoint, fake.endpoint), http, timeout)

  private def run(reply: Reply): IO[Either[LinearApiError, Json]] =
    server(_ => reply).use(fake => api(fake).execute(token, document, Json.obj()))

  private def errorBody(extension: String) =
    s"""{"errors":[{"message":"x","extensions":{$extension}}],"data":null}"""

  test("sends the fixed document, variables, and headers as one POST") {
    server(_ => Reply(200, """{"data":{"issue":{"id":"1"}}}""")).use: fake =>
      api(fake).execute(token, document, Json.obj("id" -> Json.fromString("abc"))).map: result =>
        assertEquals(result, Right(Json.obj("issue" -> Json.obj("id" -> Json.fromString("1")))))
        val request = fake.requests.get.head
        assertEquals(request.method, "POST")
        assertEquals(request.headers("authorization"), "Bearer " + token)
        assertEquals(request.headers("content-type"), "application/json")
        assertEquals(request.headers("accept"), "application/json")
        assertEquals(request.headers("user-agent"), "hallpass")
        val body = parse(request.body).toOption.get.asObject.get
        assertEquals(body("query"), Some(Json.fromString(document.text)))
        assertEquals(body("variables"), Some(Json.obj("id" -> Json.fromString("abc"))))
        assertEquals(fake.requests.get.size, 1)
  }

  private val table: Vector[(String, Reply, LinearApiError)] = Vector(
    ("401 status", Reply(401, "{}"), LinearApiError.Unauthorized),
    ("403 status", Reply(403, "{}"), LinearApiError.Forbidden),
    ("429 status", Reply(429, "{}"), LinearApiError.RateLimited),
    ("400 RATELIMITED code", Reply(400, errorBody(""""code":"RATELIMITED"""")), LinearApiError.RateLimited),
    ("400 ratelimited type", Reply(400, errorBody(""""type":"ratelimited"""")), LinearApiError.RateLimited),
    ("400 other", Reply(400, errorBody(""""code":"INVALID"""")), LinearApiError.Rejected),
    ("400 not json", Reply(400, "nope"), LinearApiError.Rejected),
    ("500 status", Reply(500, "{}"), LinearApiError.Rejected),
    ("404 status", Reply(404, "{}"), LinearApiError.Rejected),
    ("302 not followed", Reply(302, "", Map("Location" -> "http://127.0.0.1:1/elsewhere")), LinearApiError.Rejected),
    ("204 success status", Reply(204, ""), LinearApiError.InvalidResponse),
    ("200 authentication error code", Reply(200, errorBody(""""code":"AUTHENTICATION_ERROR"""")), LinearApiError.Unauthorized),
    ("200 authentication error type", Reply(200, errorBody(""""type":"authentication error"""")), LinearApiError.Unauthorized),
    ("200 forbidden type", Reply(200, errorBody(""""type":"forbidden"""")), LinearApiError.Forbidden),
    ("200 forbidden code", Reply(200, errorBody(""""code":"FORBIDDEN"""")), LinearApiError.Forbidden),
    ("200 ratelimited error", Reply(200, errorBody(""""code":"RATELIMITED"""")), LinearApiError.RateLimited),
    ("200 other error", Reply(200, errorBody(""""code":"BAD_USER_INPUT"""")), LinearApiError.Rejected),
    ("200 error without extensions", Reply(200, """{"errors":[{"message":"x"}],"data":{}}"""), LinearApiError.Rejected),
    (
      "200 mixed errors",
      Reply(200, """{"errors":[{"extensions":{"code":"FORBIDDEN"}},{"extensions":{"code":"OTHER"}}],"data":{}}"""),
      LinearApiError.Rejected
    ),
    ("200 errors with data", Reply(200, """{"errors":[{"message":"x"}],"data":{"a":1}}"""), LinearApiError.Rejected),
    ("200 errors not an array", Reply(200, """{"errors":"x","data":{}}"""), LinearApiError.InvalidResponse),
    ("200 not json", Reply(200, "<html>"), LinearApiError.InvalidResponse),
    ("200 non-object body", Reply(200, "[1]"), LinearApiError.InvalidResponse),
    ("200 data missing", Reply(200, "{}"), LinearApiError.InvalidResponse),
    ("200 data null", Reply(200, """{"data":null}"""), LinearApiError.InvalidResponse),
    ("200 data not an object", Reply(200, """{"data":[1]}"""), LinearApiError.InvalidResponse),
    ("oversize body", Reply(200, "{\"data\":{\"a\":\"" + "x" * (LinearGraphQl.MaximumResponseBytes + 10) + "\"}}"), LinearApiError.InvalidResponse)
  )

  table.foreach: (name, reply, expected) =>
    test(s"classifies: $name") {
      run(reply).map(result => assertEquals(result, Left(expected)))
    }

  test("empty errors array with an object data succeeds") {
    run(Reply(200, """{"errors":[],"data":{"a":1}}""")).map(result =>
      assertEquals(result, Right(Json.obj("a" -> Json.fromInt(1)))))
  }

  test("a slow response is a timeout") {
    server(_ => Reply(200, "{\"data\":{}}", delayMillis = 1500)).use: fake =>
      api(fake, Duration.ofMillis(200)).execute(token, document, Json.obj()).map: result =>
        assertEquals(result, Left(LinearApiError.Timeout))
  }

  test("a refused connection is a timeout") {
    val dead = LinearEndpoints(URI.create("http://127.0.0.1:1/"), URI.create("http://127.0.0.1:1/"), URI.create("http://127.0.0.1:1/graphql"))
    LinearGraphQl(dead, HttpClient.newHttpClient(), Duration.ofSeconds(2)).execute(token, document, Json.obj()).map: result =>
      assertEquals(result, Left(LinearApiError.Timeout))
  }

  test("an unusable bearer is refused without a request") {
    server(_ => Reply(200, "{}")).use: fake =>
      api(fake).execute("bad\ntoken", document, Json.obj()).map: result =>
        assertEquals(result, Left(LinearApiError.Rejected))
        assertEquals(fake.requests.get.size, 0)
  }

  Vector(
    Reply(500, "{}"),
    Reply(408, "{}"),
    Reply(200, """{"errors":[{"message":"failed after commit"}],"data":{"issueCreate":null}}"""),
    Reply(200, """{"data":{}}""", truncate = true)
  ).zipWithIndex.foreach: (reply, index) =>
    test(s"a submitted mutation with an ambiguous response has an unknown outcome ($index), without retry") {
      server(_ => reply).use: fake =>
        api(fake).execute(token, LinearDocuments.create, Json.obj()).map: result =>
          assertEquals(result, Left(LinearApiError.OutcomeUnknown))
          assertEquals(fake.requests.get.size, 1)
    }
