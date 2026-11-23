package run.hallpass.adapters.hubspot

import java.net.{InetSocketAddress, URI, URLDecoder}
import java.net.http.HttpClient
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.time.Instant
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference
import scala.jdk.CollectionConverters.*
import cats.effect.{IO, Resource}
import com.sun.net.httpserver.{HttpExchange, HttpServer}
import munit.CatsEffectSuite
import run.hallpass.adapters.oauth.OAuthTokenJsonCodec
import run.hallpass.application.*
import run.hallpass.kernel.{ConnectionId, ResourceId}

final class HubSpotConnectorSuite extends CatsEffectSuite:
  private val now = Instant.parse("2026-03-04T05:06:07Z")
  private val clientSecretValue = "client-secret-value-123"
  private val accessValue = "hs_access_token_value_abc"
  private val refreshValue = "hs_refresh_token_value_xyz"
  private val codeValue = "authorization-code-value-789"
  private val state = OAuthState.parse("a" * 43).get
  private val verifier = PkceVerifier.generate(SecureRandom())
  private val redirect = URI.create("https://hallpass.example/oauth/callback")
  private val clock = new Clock[IO]:
    def now: IO[Instant] = IO.pure(HubSpotConnectorSuite.this.now)
  private val secrets = Vector(accessValue, refreshValue, clientSecretValue, codeValue)

  private final case class Recorded(method: String, path: String, headers: Map[String, String], body: String)
  private final case class Reply(status: Int, body: String, headers: Map[String, String] = Map.empty, delayMillis: Long = 0)
  private final class Fake(val base: URI, val requests: AtomicReference[Vector[Recorded]]):
    def endpoints = HubSpotEndpoints(base.resolve("/oauth/authorize"), base)
    def tokenRequests = requests.get.filter(_.path == "/oauth/v1/token")
    def metadataRequests = requests.get.filter(_.path.startsWith("/oauth/v1/access-tokens/"))

  private def server(handler: Recorded => Reply): Resource[IO, Fake] =
    Resource.make(IO.blocking:
      val requests = AtomicReference(Vector.empty[Recorded])
      val http = HttpServer.create(InetSocketAddress(java.net.InetAddress.getLoopbackAddress, 0), 0)
      http.setExecutor(Executors.newCachedThreadPool())
      http.createContext("/", (exchange: HttpExchange) =>
        val body = String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)
        val headers = exchange.getRequestHeaders.asScala.map((k, v) => k.toLowerCase -> v.asScala.mkString(",")).toMap
        val recorded = Recorded(exchange.getRequestMethod, exchange.getRequestURI.getPath, headers, body)
        requests.updateAndGet(_ :+ recorded)
        val reply = handler(recorded)
        if reply.delayMillis > 0 then Thread.sleep(reply.delayMillis)
        reply.headers.foreach((k, v) => exchange.getResponseHeaders.add(k, v))
        val bytes = reply.body.getBytes(StandardCharsets.UTF_8)
        scala.util.Try:
          exchange.sendResponseHeaders(reply.status, if bytes.isEmpty then -1 else bytes.length.toLong)
          if bytes.nonEmpty then exchange.getResponseBody.write(bytes)
        exchange.close()
      )
      http.start()
      (http, Fake(URI.create(s"http://127.0.0.1:${http.getAddress.getPort}"), requests))
    )((http, _) => IO.blocking(http.stop(0)).void).map(_._2)

  private def connector(fake: Fake): HubSpotConnector =
    val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    HubSpotConnector(HubSpotOAuthClient("client-id-1", clientSecretValue), fake.endpoints, http, clock, redirect)

  private def tokenBody(
      access: String = accessValue,
      refresh: Option[String] = Some(refreshValue),
      expiresIn: Option[String] = Some("1800")
  ) =
    Vector(
      Some(s""""access_token":"$access""""),
      Some(""""token_type":"bearer""""),
      refresh.map(r => s""""refresh_token":"$r""""),
      expiresIn.map(e => s""""expires_in":$e""")
    ).flatten.mkString("{", ",", "}")

  private val allScopes = HubSpot.Scopes.map(s => s""""$s"""").mkString("[", ",", "]")

  private def metadata(
      hubId: String = "44332211",
      scopes: String = allScopes,
      domain: String = "acme.example",
      user: String = "alex@acme.example"
  ) =
    s"""{"token":"x","user":"$user","hub_domain":"$domain","scopes":$scopes,"hub_id":$hubId,"app_id":1,"expires_in":1700,"user_id":9,"token_type":"access"}"""

  private def happy(r: Recorded): Reply =
    if r.path == "/oauth/v1/token" then Reply(200, tokenBody()) else Reply(200, metadata())

  private val callback = OAuthCallback(state, codeValue)

  private def formFields(body: String): Map[String, String] =
    body.split('&').map(_.split("=", 2)).map(p => URLDecoder.decode(p(0), "UTF-8") -> URLDecoder.decode(p(1), "UTF-8")).toMap

  private def assertNoSecrets(text: String): Unit =
    secrets.foreach(s => assert(!text.contains(s), "a credential appeared in rendered output"))

  test("authorization URL carries client, redirect, space-separated scopes, and state, and no PKCE") {
    server(happy).use: fake =>
      connector(fake).authorizationUri(state, None).map: uri =>
        assertEquals(uri.getPath, "/oauth/authorize")
        assertEquals(
          formFields(uri.getRawQuery),
          Map(
            "client_id" -> "client-id-1",
            "redirect_uri" -> redirect.toString,
            "scope" -> HubSpot.Scopes.mkString(" "),
            "state" -> state.value
          )
        )
        assert(!uri.toString.contains(clientSecretValue))
  }

  test("the connector does not use PKCE and refuses a verifier") {
    server(happy).use: fake =>
      val c = connector(fake)
      assert(!c.usesPkce)
      assert(!c.singleActiveRoot)
      c.authorizationUri(state, Some(verifier)).attempt.flatMap: r =>
        assert(r.left.exists(_.isInstanceOf[IllegalStateException]))
        c.exchange(callback, Some(verifier)).map: result =>
          assertEquals(result, Left(OAuthError.InvalidState))
          assertEquals(fake.requests.get.size, 0)
  }

  test("exchange sends the documented token form and the metadata request carries no secret body") {
    server(happy).use: fake =>
      connector(fake).exchange(callback, None).map: result =>
        assert(result.isRight)
        val token = fake.tokenRequests.head
        assertEquals(token.method, "POST")
        assertEquals(token.headers("content-type"), "application/x-www-form-urlencoded")
        assertEquals(
          formFields(token.body),
          Map(
            "grant_type" -> "authorization_code",
            "client_id" -> "client-id-1",
            "client_secret" -> clientSecretValue,
            "redirect_uri" -> redirect.toString,
            "code" -> codeValue
          )
        )
        assert(token.headers.values.forall(v => !v.contains(clientSecretValue)))
        val meta = fake.metadataRequests
        assertEquals(meta.size, 1)
        assertEquals(meta.head.method, "GET")
        assertEquals(meta.head.path, "/oauth/v1/access-tokens/" + accessValue)
        assert(!meta.head.body.contains(clientSecretValue) && !meta.head.body.contains(codeValue))
  }

  test("exchange builds the grant from the numeric portal ID") {
    server(happy).use: fake =>
      connector(fake).exchange(callback, None).map: result =>
        val grant = result.toOption.get
        assertEquals(grant.externalAccountId.value, "44332211")
        assertEquals(grant.rootExternalId.value, "44332211")
        assertEquals(grant.rootDisplayName, "acme.example")
        assertEquals(grant.workspaceLabel, Some("acme.example"))
        assertEquals(grant.accountLabel, Some("alex@acme.example"))
        val expected = now.plusSeconds(1800)
        assertEquals(grant.expiresAt, Some(expected))
        val tokens = OAuthTokenJsonCodec().decode(grant.secret).toOption.get
        assertEquals(tokens.accessToken, accessValue)
        assertEquals(tokens.refreshToken, Some(refreshValue))
        assertEquals(tokens.expiresAt, expected)
  }

  test("a missing domain falls back to a portal-ID label, never a domain-derived identity") {
    server(r =>
      if r.path == "/oauth/v1/token" then Reply(200, tokenBody())
      else Reply(200, s"""{"hub_id":77,"scopes":$allScopes}""")
    ).use: fake =>
      connector(fake).exchange(callback, None).map: result =>
        val grant = result.toOption.get
        assertEquals(grant.rootExternalId.value, "77")
        assertEquals(grant.rootDisplayName, "HubSpot portal 77")
        assertEquals(grant.accountLabel, None)
  }

  test("extra granted scopes are accepted") {
    val more = HubSpot.Scopes.map(s => s""""$s"""").appended(""""crm.objects.owners.read"""").mkString("[", ",", "]")
    server(r => if r.path == "/oauth/v1/token" then Reply(200, tokenBody()) else Reply(200, metadata(scopes = more))).use: fake =>
      connector(fake).exchange(callback, None).map(result => assert(result.isRight))
  }

  private def rejectsToken(name: String, reply: Reply, expected: OAuthError) =
    test(s"exchange fails closed: $name") {
      server(r => if r.path == "/oauth/v1/token" then reply else Reply(200, metadata())).use: fake =>
        connector(fake).exchange(callback, None).map: result =>
          assertEquals(result, Left(expected))
          assertEquals(fake.metadataRequests.size, 0)
          assertNoSecrets(result.toString)
    }

  rejectsToken("missing refresh_token", Reply(200, tokenBody(refresh = None)), OAuthError.InvalidProviderResponse)
  rejectsToken("missing expires_in", Reply(200, tokenBody(expiresIn = None)), OAuthError.InvalidProviderResponse)
  rejectsToken("zero expires_in", Reply(200, tokenBody(expiresIn = Some("0"))), OAuthError.InvalidProviderResponse)
  rejectsToken("negative expires_in", Reply(200, tokenBody(expiresIn = Some("-5"))), OAuthError.InvalidProviderResponse)
  rejectsToken("expires_in over one day", Reply(200, tokenBody(expiresIn = Some("86401"))), OAuthError.InvalidProviderResponse)
  rejectsToken("string expires_in", Reply(200, tokenBody(expiresIn = Some("\"100\""))), OAuthError.InvalidProviderResponse)
  rejectsToken("token with whitespace", Reply(200, tokenBody(access = "bad token")), OAuthError.InvalidProviderResponse)
  rejectsToken("error field present", Reply(200, """{"error":"invalid_grant"}"""), OAuthError.InvalidProviderResponse)
  rejectsToken("wrong token type", Reply(200, tokenBody().replace("bearer", "mac")), OAuthError.InvalidProviderResponse)
  rejectsToken("not json", Reply(200, "<html>"), OAuthError.InvalidProviderResponse)
  rejectsToken("400 from the token endpoint", Reply(400, """{"status":"BAD_AUTH_CODE"}"""), OAuthError.ProviderRejected)
  rejectsToken("500 from the token endpoint", Reply(500, ""), OAuthError.ProviderRejected)
  rejectsToken("redirect is not followed", Reply(302, "", Map("Location" -> "http://127.0.0.1:1/x")), OAuthError.ProviderRejected)
  rejectsToken(
    "oversize token response",
    Reply(200, tokenBody(access = "a" * (HubSpotConnector.MaximumTokenResponseBytes + 10))),
    OAuthError.ProviderRejected
  )

  private def rejectsMetadata(name: String, reply: Reply, expected: OAuthError) =
    test(s"exchange fails closed on token metadata: $name") {
      server(r => if r.path == "/oauth/v1/token" then Reply(200, tokenBody()) else reply).use: fake =>
        connector(fake).exchange(callback, None).map: result =>
          assertEquals(result, Left(expected))
          assertEquals(fake.tokenRequests.size, 1)
          assertEquals(fake.metadataRequests.size, 1)
          assertNoSecrets(result.toString)
    }

  rejectsMetadata("a missing required scope", Reply(200, metadata(scopes = """["oauth","crm.objects.contacts.read"]""")), OAuthError.ProviderRejected)
  rejectsMetadata("no scopes", Reply(200, metadata(scopes = "[]")), OAuthError.ProviderRejected)
  rejectsMetadata("non-string scopes", Reply(200, metadata(scopes = "[1,2]")), OAuthError.InvalidProviderResponse)
  rejectsMetadata("domain as hub_id", Reply(200, metadata(hubId = "\"acme.example\"")), OAuthError.InvalidProviderResponse)
  rejectsMetadata("string hub_id", Reply(200, metadata(hubId = "\"123\"")), OAuthError.InvalidProviderResponse)
  rejectsMetadata("zero hub_id", Reply(200, metadata(hubId = "0")), OAuthError.InvalidProviderResponse)
  rejectsMetadata("negative hub_id", Reply(200, metadata(hubId = "-4")), OAuthError.InvalidProviderResponse)
  rejectsMetadata("fractional hub_id", Reply(200, metadata(hubId = "1.5")), OAuthError.InvalidProviderResponse)
  rejectsMetadata("missing hub_id", Reply(200, s"""{"scopes":$allScopes}"""), OAuthError.InvalidProviderResponse)
  rejectsMetadata("not json", Reply(200, "nope"), OAuthError.InvalidProviderResponse)
  rejectsMetadata("401", Reply(401, "{}"), OAuthError.ProviderRejected)
  rejectsMetadata("302", Reply(302, "", Map("Location" -> "http://127.0.0.1:1/x")), OAuthError.ProviderRejected)
  rejectsMetadata("oversize", Reply(200, "{\"x\":\"" + "x" * (HubSpotConnector.MaximumIdentityResponseBytes + 10) + "\"}"), OAuthError.ProviderRejected)

  test("an unreachable provider is a rejection with no credential in the error") {
    val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    val endpoints = HubSpotEndpoints(URI.create("http://127.0.0.1:1/a"), URI.create("http://127.0.0.1:1"))
    HubSpotConnector(HubSpotOAuthClient("client-id-1", clientSecretValue), endpoints, http, clock, redirect)
      .exchange(callback, None).map: result =>
        assertEquals(result, Left(OAuthError.ProviderRejected))
        assertNoSecrets(result.toString)
  }

  test("the connector and client render no credential") {
    assertNoSecrets(HubSpotOAuthClient("client-id-1", clientSecretValue).toString)
    server(happy).use(fake => IO(assertNoSecrets(connector(fake).toString)))
  }

  private def root(kind: String = HubSpot.portal.wire) =
    ConnectionResource(ResourceId.random(), ConnectionId.random(), kind, ExternalId.parse("44332211").get, "acme", ResourceId.random(), None, None)

  private val secret = OAuthTokenJsonCodec().encode(OAuthTokens.from(accessValue, Some(refreshValue), now.plusSeconds(600)).get)

  test("discovery offers portal-qualified contacts and deals under the portal, without any request") {
    server(happy).use: fake =>
      val discovery = connector(fake).resourceDiscovery.get
      discovery.selectableResources(secret, root()).map: result =>
        val found = result.toOption.get
        assertEquals(found.map(_.externalId.value).toSet, Set("44332211:contacts", "44332211:deals"))
        assertEquals(found.size, 2)
        assert(found.forall(r => (r.kind eq HubSpot.objectType) && r.parentExternalId.value == "44332211"))
        assertEquals(fake.requests.get.size, 0)
  }

  test("discovery rejects a root whose external ID is not a valid HubSpot portal ID") {
    server(happy).use: fake =>
      val invalidPortal = root().copy(externalId = ExternalId.parse("acme.example").get)
      connector(fake).resourceDiscovery.get.selectableResources(secret, invalidPortal).map: result =>
        assertEquals(result, Left(OAuthError.InvalidState))
        assertEquals(fake.requests.get.size, 0)
  }

  test("discovery on a non-portal root is InvalidState") {
    server(happy).use: fake =>
      connector(fake).resourceDiscovery.get.selectableResources(secret, root(HubSpot.objectType.wire)).map: result =>
        assertEquals(result, Left(OAuthError.InvalidState))
        assertEquals(fake.requests.get.size, 0)
  }
