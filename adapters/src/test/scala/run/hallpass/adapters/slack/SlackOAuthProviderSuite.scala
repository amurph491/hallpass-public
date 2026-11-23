package run.hallpass.adapters.slack

import java.net.URI
import java.net.http.HttpClient
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicReference
import com.sun.net.httpserver.HttpServer
import cats.effect.{IO, Resource}
import munit.CatsEffectSuite
import run.hallpass.application.*

final class SlackOAuthProviderSuite extends CatsEffectSuite:
  private val config = SlackOAuthConfig(
    "client-id",
    "client-secret",
    URI.create("http://localhost:3000/api/oauth/slack/callback"),
    Vector("search:read")
  )
  private val state = OAuthState.parse("a" * 43).getOrElse(fail("state"))

  test("requests Slack search permission as a user scope, not a bot scope") {
    val provider = new SlackOAuthProvider(config)
    provider
      .authorizationUri(state, None)
      .map: uri =>
        val query = Option(uri.getRawQuery).getOrElse("")
        val parameters = query.split('&').toSet
        assert(parameters.contains("user_scope=search%3Aread"))
        assert(!parameters.contains("scope=search%3Aread"))
  }

  test("stores the OAuth user token rather than the root bot token") {
    val body =
      """{"ok":true,"access_token":"xoxb-bot-token","authed_user":{"id":"U123","access_token":"xoxp-user-token"},"team":{"id":"T123","name":"Workspace"}}"""
    withTokenServer(body).use: endpoint =>
      val provider = new SlackOAuthProvider(
        config,
        HttpClient.newHttpClient(),
        URI.create("https://example.test/authorize"),
        endpoint
      )
      provider
        .exchange(OAuthCallback(state, "callback-code"), None)
        .map: result =>
          assertEquals(
            result.map(grant => new String(ProviderSecret.bytes(grant.secret), StandardCharsets.UTF_8)),
            Right("xoxp-user-token")
          )
          assertEquals(result.map(_.externalAccountId.value), Right("T123"))
          assertEquals(result.map(_.rootExternalId.value), Right("T123"))
          assertEquals(result.map(_.accountLabel), Right(Some("U123")))
  }

  test("rejects a user token response without a stable workspace ID") {
    val body =
      """{"ok":true,"authed_user":{"id":"U123","access_token":"xoxp-user-token"},"team":{"name":"Workspace"}}"""
    withTokenServer(body).use: endpoint =>
      new SlackOAuthProvider(config, HttpClient.newHttpClient(), URI.create("https://example.test/authorize"), endpoint)
        .exchange(OAuthCallback(state, "callback-code"), None)
        .map(result => assertEquals(result, Left(OAuthError.InvalidProviderResponse)))
  }

  test("rejects an OAuth response without a user token") {
    val body = """{"ok":true,"access_token":"xoxb-bot-token","authed_user":{"id":"U123"}}"""
    withTokenServer(body).use: endpoint =>
      val provider = new SlackOAuthProvider(
        config,
        HttpClient.newHttpClient(),
        URI.create("https://example.test/authorize"),
        endpoint
      )
      provider
        .exchange(OAuthCallback(state, "callback-code"), None)
        .map: result =>
          assertEquals(result, Left(OAuthError.InvalidProviderResponse))
  }

  test("rejects Slack responses that report nested provider errors") {
    val body =
      """{"ok":true,"error_description":"authorization failed","response_metadata":{"messages":["invalid_code"]}}"""
    withTokenServer(body).use: endpoint =>
      new SlackOAuthProvider(config, HttpClient.newHttpClient(), URI.create("https://example.test/authorize"), endpoint)
        .exchange(OAuthCallback(state, "callback-code"), None)
        .map(result => assertEquals(result, Left(OAuthError.ProviderRejected)))
  }

  test("rejects an oversized token response without reading it into memory") {
    val body = """{"ok":true,"padding":"""" + ("x" * (70 * 1024)) + """"}"""
    withTokenServer(body).use: endpoint =>
      new SlackOAuthProvider(config, HttpClient.newHttpClient(), URI.create("https://example.test/authorize"), endpoint)
        .exchange(OAuthCallback(state, "callback-code"), None)
        .map(result => assertEquals(result, Left(OAuthError.ProviderRejected)))
  }

  test("Slack is a single-root connector that never reads its credential for discovery") {
    val provider = new SlackOAuthProvider(config)
    assert(provider.singleActiveRoot)
    assert(!provider.usesPkce)
    assertEquals(provider.resourceDiscovery, None)
  }

  private def withTokenServer(body: String): Resource[IO, URI] =
    Resource
      .make(IO.blocking:
        val server = HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext(
          "/",
          exchange =>
            val bytes = body.getBytes(StandardCharsets.UTF_8)
            exchange.sendResponseHeaders(200, bytes.length)
            val output = exchange.getResponseBody
            try output.write(bytes)
            finally output.close()
        )
        server.start()
        server)(server => IO.blocking(server.stop(0)).void)
      .map(server => URI.create(s"http://127.0.0.1:${server.getAddress.getPort}/"))
