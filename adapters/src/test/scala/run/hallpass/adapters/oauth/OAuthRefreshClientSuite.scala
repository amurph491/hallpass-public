package run.hallpass.adapters.oauth

import java.net.InetSocketAddress
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}
import scala.concurrent.duration.*
import com.sun.net.httpserver.HttpServer
import cats.effect.{IO, Resource}
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.application.*

final class OAuthRefreshClientSuite extends CatsEffectSuite:
  private val receivedAt = Instant.parse("2026-01-02T03:04:05Z")
  private val oldTokens = OAuthTokens.from("old-access-secret", Some("old-refresh-secret"), receivedAt).get

  test("posts the standard refresh form, accepts rotation, and derives expiry after response") {
    val body = """{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600}"""
    withServer(200, body).use: (endpoint, count, requestBody) =>
      val client = refreshClient(endpoint)
      client.refresh(oldTokens).map: result =>
        assertEquals(result.map(_.accessToken), Right("new-access"))
        assertEquals(result.map(_.refreshToken), Right(Some("new-refresh")))
        assertEquals(result.map(_.expiresAt), Right(receivedAt.plusSeconds(3600)))
        assertEquals(count.get(), 1)
        val fields = parseForm(requestBody.get())
        assertEquals(fields.get("grant_type"), Some("refresh_token"))
        assertEquals(fields.get("refresh_token"), Some("old-refresh-secret"))
        assertEquals(fields.get("client_id"), Some("client-id"))
        assertEquals(fields.get("client_secret"), Some("client-secret"))
  }

  test("preserves the previous refresh token when a successful response omits it") {
    withServer(200, """{"access_token":"new-access","token_type":"Bearer","expires_in":60}""").use:
      (endpoint, _, _) =>
        refreshClient(endpoint).refresh(oldTokens).map: result =>
          assertEquals(result.map(_.refreshToken), Right(Some("old-refresh-secret")))
  }

  test("does not send a request when no refresh token is stored") {
    val withoutRefresh = OAuthTokens.from("old-access", None, receivedAt).get
    withServer(200, "{}").use: (endpoint, count, _) =>
      refreshClient(endpoint).refresh(withoutRefresh).map: result =>
        assertEquals(result, Left(OAuthRefreshError.InvalidResponse))
        assertEquals(count.get(), 0)
  }

  test("rejects a nominal success response that also contains an OAuth error") {
    val body = """{"access_token":"new-access","refresh_token":"new-refresh","token_type":"Bearer","expires_in":3600,"error":"invalid_grant"}"""
    withServer(200, body).use: (endpoint, _, _) =>
      refreshClient(endpoint).refresh(oldTokens).map(result => assertEquals(result, Left(OAuthRefreshError.InvalidResponse)))
  }

  test("maps token rejection without exposing response content or credentials") {
    withServer(400, """{"error":"invalid_grant","error_description":"old-refresh-secret client-secret"}""").use:
      (endpoint, _, _) =>
        val config = clientConfig(endpoint)
        val renderedConfig = config.toString
        refreshClient(endpoint).refresh(oldTokens).map: result =>
          assertEquals(result, Left(OAuthRefreshError.Rejected))
          assert(!renderedConfig.contains("client-secret"))
          assert(!result.toString.contains("old-refresh-secret"))
          assert(!result.toString.contains("client-secret"))
  }

  test("rejects malformed JSON and missing access token") {
    val malformed = withServer(200, "not-json")
    val missing = withServer(200, """{"token_type":"Bearer","expires_in":30}""")
    malformed.use((endpoint, _, _) => refreshClient(endpoint).refresh(oldTokens).map(r => assertEquals(r, Left(OAuthRefreshError.InvalidResponse)))) *>
      missing.use((endpoint, _, _) => refreshClient(endpoint).refresh(oldTokens).map(r => assertEquals(r, Left(OAuthRefreshError.InvalidResponse))))
  }

  test("rejects missing, non-Bearer, nonintegral, nonpositive, and excessive expiry") {
    val cases = Vector(
      """{"access_token":"x","token_type":"Bearer"}""",
      """{"access_token":"x","token_type":"MAC","expires_in":10}""",
      """{"access_token":"x","token_type":"Bearer","expires_in":1.5}""",
      """{"access_token":"x","token_type":"Bearer","expires_in":0}""",
      s"""{"access_token":"x","token_type":"Bearer","expires_in":${OAuthRefreshClient.MaximumLifetimeSeconds + 1}}"""
    )
    cases.traverse: body =>
      withServer(200, body).use: (endpoint, _, _) =>
        refreshClient(endpoint).refresh(oldTokens).map(result => assertEquals(result, Left(OAuthRefreshError.InvalidResponse)))
  }

  test("does not follow redirects") {
    withServer(302, "", redirect = Some("/followed")).use: (endpoint, count, _) =>
      refreshClient(endpoint).refresh(oldTokens).map: result =>
        assertEquals(result, Left(OAuthRefreshError.Unavailable))
        assertEquals(count.get(), 1)
  }

  test("bounds response size") {
    val oversized = "x" * (OAuthRefreshClient.MaximumResponseBytes + 1)
    withServer(200, oversized).use: (endpoint, _, _) =>
      refreshClient(endpoint).refresh(oldTokens).map(result => assertEquals(result, Left(OAuthRefreshError.Unavailable)))
  }

  test("bounds a response body that stalls after headers") {
    val body = """{"access_token":"new-access","token_type":"Bearer","expires_in":60}"""
    withServer(200, body, bodyDelay = 500.millis).use: (endpoint, _, _) =>
      OAuthRefreshClient
        .create(clientConfig(endpoint), run.hallpass.application.Clock.fixed(receivedAt), requestTimeout = java.time.Duration.ofMillis(100))
        .refresh(oldTokens)
        .map(result => assertEquals(result, Left(OAuthRefreshError.Unavailable)))
  }

  test("configuration requires HTTPS except explicit numeric loopback HTTP and redacts secret rendering") {
    val https = OAuthRefreshClient.Config.from(URI.create("https://tokens.example.test/token"), "client-id", "client-secret")
    val insecureRemote = OAuthRefreshClient.Config.from(URI.create("http://tokens.example.test/token"), "client-id", "client-secret", allowHttpLoopback = true)
    val loopbackDenied = OAuthRefreshClient.Config.from(URI.create("http://127.0.0.1/token"), "client-id", "client-secret")
    val loopbackAllowed = OAuthRefreshClient.Config.from(URI.create("http://127.0.0.1/token"), "client-id", "client-secret", allowHttpLoopback = true)
    assert(https.isRight)
    assert(insecureRemote.isLeft)
    assert(loopbackDenied.isLeft)
    assert(loopbackAllowed.toOption.exists(!_.toString.contains("client-secret")))
  }

  test("token codec round trips exact fields and rejects malformed or unexpected fields") {
    val codec = new OAuthTokenJsonCodec
    val original = OAuthTokens.from("access-value", Some("refresh-value"), receivedAt).get
    val decoded = codec.decode(codec.encode(original))
    val missing = codec.decode(ProviderSecret.fromUtf8("""{"access_token":"a"}"""))
    val extra = codec.decode(ProviderSecret.fromUtf8("""{"access_token":"a","expires_at":"2026-01-02T03:04:05Z","extra":"x"}"""))
    val malformed = codec.decode(ProviderSecret.fromUtf8("not-json"))
    assertEquals(decoded.map(t => (t.accessToken, t.refreshToken, t.expiresAt)), Right(("access-value", Some("refresh-value"), receivedAt)))
    assertEquals(missing, Left(ConnectionError.MissingCredential))
    assertEquals(extra, Left(ConnectionError.MissingCredential))
    assertEquals(malformed, Left(ConnectionError.MissingCredential))
    assert(!codec.toString.contains("access-value"))
  }

  private def refreshClient(endpoint: URI): OAuthRefreshClient =
    OAuthRefreshClient.create(clientConfig(endpoint), run.hallpass.application.Clock.fixed(receivedAt))

  private def clientConfig(endpoint: URI): OAuthRefreshClient.Config =
    OAuthRefreshClient.Config.from(endpoint, "client-id", "client-secret", allowHttpLoopback = true).fold(message => fail(message), identity)

  private def withServer(
      status: Int,
      response: String,
      redirect: Option[String] = None,
      bodyDelay: FiniteDuration = Duration.Zero
  ): Resource[IO, (URI, AtomicInteger, AtomicReference[String])] =
    Resource.make(IO.blocking:
      val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
      val count = new AtomicInteger(0)
      val requestBody = new AtomicReference("")
      server.createContext("/token", exchange =>
        count.incrementAndGet()
        requestBody.set(new String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8))
        redirect match
          case Some(location) =>
            exchange.getResponseHeaders.add("Location", location)
            exchange.sendResponseHeaders(status, -1)
          case None =>
            val bytes = response.getBytes(StandardCharsets.UTF_8)
            exchange.sendResponseHeaders(status, bytes.length)
            val out = exchange.getResponseBody
            try
              if bodyDelay > Duration.Zero then Thread.sleep(bodyDelay.toMillis)
              out.write(bytes)
            finally out.close()
      )
      server.start()
      (server, URI.create(s"http://127.0.0.1:${server.getAddress.getPort}/token"), count, requestBody)
    )((server, _, _, _) => IO.blocking(server.stop(0))).map((_, endpoint, count, body) => (endpoint, count, body))

  private def parseForm(value: String): Map[String, String] =
    value.split('&').toVector.map: pair =>
      val parts = pair.split("=", 2)
      URLDecoder.decode(parts(0), StandardCharsets.UTF_8) -> URLDecoder.decode(parts.lift(1).getOrElse(""), StandardCharsets.UTF_8)
    .toMap
