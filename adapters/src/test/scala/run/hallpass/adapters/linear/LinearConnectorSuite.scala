package run.hallpass.adapters.linear

import java.net.{InetSocketAddress, URI, URLDecoder}
import java.net.http.HttpClient
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.time.{Duration, Instant}
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference
import scala.jdk.CollectionConverters.*
import cats.effect.{IO, Resource}
import com.sun.net.httpserver.{HttpExchange, HttpServer}
import io.circe.Json
import io.circe.parser.parse
import munit.CatsEffectSuite
import run.hallpass.adapters.oauth.OAuthTokenJsonCodec
import run.hallpass.application.*
import run.hallpass.kernel.{ConnectionId, ResourceId}

final class LinearConnectorSuite extends CatsEffectSuite:
  private val now = Instant.parse("2026-03-04T05:06:07Z")
  private val clientSecretValue = "client-secret-value-123"
  private val accessValue = "lin_access_token_value_abc"
  private val refreshValue = "lin_refresh_token_value_xyz"
  private val codeValue = "authorization-code-value-789"
  private val orgId = "11111111-2222-3333-4444-555555555555"
  private val state = OAuthState.parse("a" * 43).get
  private val verifier = PkceVerifier.generate(SecureRandom())
  private val redirect = URI.create("https://hallpass.example/oauth/callback")
  private val clock = new Clock[IO]:
    def now: IO[Instant] = IO.pure(LinearConnectorSuite.this.now)
  private val secrets = Vector(accessValue, refreshValue, clientSecretValue, codeValue, verifier.value)

  private final case class Recorded(method: String, path: String, headers: Map[String, String], body: String)
  private final case class Reply(status: Int, body: String, headers: Map[String, String] = Map.empty, delayMillis: Long = 0)
  private final class Fake(val base: URI, val requests: AtomicReference[Vector[Recorded]]):
    def endpoints = LinearEndpoints(base.resolve("/oauth/authorize"), base.resolve("/oauth/token"), base.resolve("/graphql"))
    def tokenRequests = requests.get.filter(_.path == "/oauth/token")
    def graphqlRequests = requests.get.filter(_.path == "/graphql")

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

  private def connector(fake: Fake, timeout: Duration = Duration.ofSeconds(5)): LinearConnector =
    val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    val endpoints = fake.endpoints
    LinearConnector(LinearOAuthClient("client-id-1", clientSecretValue), endpoints, LinearGraphQl(endpoints, http, timeout), http, clock, redirect)

  private def tokenBody(
      access: String = accessValue,
      refresh: Option[String] = Some(refreshValue),
      expiresIn: Option[String] = Some("86399")
  ) =
    val fields = Vector(
      Some(s""""access_token":"$access""""),
      Some(""""token_type":"Bearer""""),
      refresh.map(r => s""""refresh_token":"$r""""),
      expiresIn.map(e => s""""expires_in":$e""")
    ).flatten
    fields.mkString("{", ",", "}")

  private def identityBody(id: String = orgId, org: String = "Acme", viewer: String = "Alex") =
    s"""{"data":{"viewer":{"id":"v1","name":"$viewer"},"organization":{"id":"$id","name":"$org","urlKey":"acme"}}}"""

  private def happy(r: Recorded): Reply =
    if r.path == "/oauth/token" then Reply(200, tokenBody()) else Reply(200, identityBody())

  private val callback = OAuthCallback(state, codeValue)

  private def formFields(body: String): Map[String, String] =
    body.split('&').map(_.split("=", 2)).map(p => URLDecoder.decode(p(0), "UTF-8") -> URLDecoder.decode(p(1), "UTF-8")).toMap

  private def assertNoSecrets(text: String): Unit =
    secrets.foreach(s => assert(!text.contains(s), "a credential appeared in rendered output"))

  // ---- authorization URL

  test("authorization URL carries the PKCE challenge, S256, scopes, and state") {
    server(happy).use: fake =>
      connector(fake).authorizationUri(state, Some(verifier)).map: uri =>
        assertEquals(uri.getPath, "/oauth/authorize")
        val params = formFields(uri.getRawQuery)
        assertEquals(
          params,
          Map(
            "client_id" -> "client-id-1",
            "redirect_uri" -> redirect.toString,
            "response_type" -> "code",
            "scope" -> "read,write",
            "state" -> state.value,
            "code_challenge" -> verifier.challenge,
            "code_challenge_method" -> "S256",
            "prompt" -> "consent"
          )
        )
        assert(!uri.toString.contains(verifier.value))
        assert(!uri.toString.contains(clientSecretValue))
  }

  test("authorization URL without a challenge is a programming error") {
    server(happy).use: fake =>
      val c = connector(fake)
      c.authorizationUri(state, None).attempt.flatMap: result =>
        assert(result.left.exists(_.isInstanceOf[IllegalStateException]))
        c.authorizationUri(state).attempt.map(r => assert(r.left.exists(_.isInstanceOf[IllegalStateException])))
  }

  test("the connector requires PKCE") {
    server(happy).use(fake => IO(assert(connector(fake).usesPkce)))
  }

  // ---- exchange

  test("exchange without a verifier is InvalidState and sends nothing") {
    server(happy).use: fake =>
      connector(fake).exchange(callback, None).map: result =>
        assertEquals(result, Left(OAuthError.InvalidState))
        assertEquals(fake.requests.get.size, 0)
  }

  test("the verifier-less exchange overload is InvalidState") {
    server(happy).use: fake =>
      connector(fake).exchange(callback).map: result =>
        assertEquals(result, Left(OAuthError.InvalidState))
        assertEquals(fake.requests.get.size, 0)
  }

  test("exchange sends the verifier and client secret only in the token request body") {
    server(happy).use: fake =>
      connector(fake).exchange(callback, Some(verifier)).map: result =>
        assert(result.isRight)
        val token = fake.tokenRequests.head
        assertEquals(token.method, "POST")
        assertEquals(token.headers("content-type"), "application/x-www-form-urlencoded")
        assertEquals(
          formFields(token.body),
          Map(
            "grant_type" -> "authorization_code",
            "code" -> codeValue,
            "redirect_uri" -> redirect.toString,
            "client_id" -> "client-id-1",
            "client_secret" -> clientSecretValue,
            "code_verifier" -> verifier.value
          )
        )
        assert(token.headers.values.forall(v => !v.contains(clientSecretValue) && !v.contains(verifier.value)))
        val graphql = fake.graphqlRequests
        assertEquals(graphql.size, 1)
        assertEquals(graphql.head.headers("authorization"), "Bearer " + accessValue)
        assert(!graphql.head.body.contains(clientSecretValue) && !graphql.head.body.contains(verifier.value))
        assert(!graphql.head.body.contains(codeValue))
  }

  test("exchange builds the full grant") {
    server(happy).use: fake =>
      connector(fake).exchange(callback, Some(verifier)).map: result =>
        val grant = result.toOption.get
        assertEquals(grant.externalAccountId.value, orgId)
        assertEquals(grant.rootExternalId.value, orgId)
        assertEquals(grant.rootDisplayName, "Acme")
        assertEquals(grant.workspaceLabel, Some("Acme"))
        assertEquals(grant.accountLabel, Some("Alex"))
        val expected = now.plusSeconds(86399)
        assertEquals(grant.expiresAt, Some(expected))
        val tokens = OAuthTokenJsonCodec().decode(grant.secret).toOption.get
        assertEquals(tokens.accessToken, accessValue)
        assertEquals(tokens.refreshToken, Some(refreshValue))
        assertEquals(tokens.expiresAt, expected)
  }

  test("exchange without a viewer name leaves the account label empty") {
    server(r =>
      if r.path == "/oauth/token" then Reply(200, tokenBody())
      else Reply(200, s"""{"data":{"viewer":{"id":"v"},"organization":{"id":"$orgId","name":"Acme"}}}""")
    ).use: fake =>
      connector(fake).exchange(callback, Some(verifier)).map: result =>
        assertEquals(result.toOption.get.accountLabel, None)
  }

  private def rejectsToken(name: String, reply: Reply, expected: OAuthError) =
    test(s"exchange fails closed: $name") {
      server(r => if r.path == "/oauth/token" then reply else Reply(200, identityBody())).use: fake =>
        connector(fake).exchange(callback, Some(verifier)).map: result =>
          assertEquals(result, Left(expected))
          assertEquals(fake.graphqlRequests.size, 0)
          assertNoSecrets(result.toString)
    }

  rejectsToken("missing refresh_token", Reply(200, tokenBody(refresh = None)), OAuthError.InvalidProviderResponse)
  rejectsToken("missing expires_in", Reply(200, tokenBody(expiresIn = None)), OAuthError.InvalidProviderResponse)
  rejectsToken("zero expires_in", Reply(200, tokenBody(expiresIn = Some("0"))), OAuthError.InvalidProviderResponse)
  rejectsToken("negative expires_in", Reply(200, tokenBody(expiresIn = Some("-5"))), OAuthError.InvalidProviderResponse)
  rejectsToken("expires_in over one year", Reply(200, tokenBody(expiresIn = Some("31622401"))), OAuthError.InvalidProviderResponse)
  rejectsToken("string expires_in", Reply(200, tokenBody(expiresIn = Some("\"100\""))), OAuthError.InvalidProviderResponse)
  rejectsToken("token with whitespace", Reply(200, tokenBody(access = "bad token")), OAuthError.InvalidProviderResponse)
  rejectsToken("error field present", Reply(200, """{"error":"invalid_grant"}"""), OAuthError.InvalidProviderResponse)
  rejectsToken("wrong token type", Reply(200, tokenBody().replace("Bearer", "MAC")), OAuthError.InvalidProviderResponse)
  rejectsToken("not json", Reply(200, "<html>"), OAuthError.InvalidProviderResponse)
  rejectsToken("401 from the token endpoint", Reply(401, """{"error":"invalid_client"}"""), OAuthError.ProviderRejected)
  rejectsToken("400 from the token endpoint", Reply(400, """{"error":"invalid_grant"}"""), OAuthError.ProviderRejected)
  rejectsToken("500 from the token endpoint", Reply(500, ""), OAuthError.ProviderRejected)
  rejectsToken("redirect is not followed", Reply(302, "", Map("Location" -> "http://127.0.0.1:1/x")), OAuthError.ProviderRejected)
  rejectsToken(
    "oversize token response",
    Reply(200, tokenBody(access = "a" * (LinearConnector.MaximumTokenResponseBytes + 10))),
    OAuthError.ProviderRejected
  )

  test("exchange fails closed when the organization query times out") {
    server(r => if r.path == "/oauth/token" then Reply(200, tokenBody()) else Reply(200, identityBody(), delayMillis = 1500)).use: fake =>
      connector(fake, Duration.ofMillis(200)).exchange(callback, Some(verifier)).map: result =>
        assertEquals(result, Left(OAuthError.ProviderRejected))
  }

  private def rejectsIdentity(name: String, reply: Reply, expected: OAuthError) =
    test(s"exchange fails closed on the organization query: $name") {
      server(r => if r.path == "/oauth/token" then Reply(200, tokenBody()) else reply).use: fake =>
        connector(fake).exchange(callback, Some(verifier)).map: result =>
          assertEquals(result, Left(expected))
          assertNoSecrets(result.toString)
    }

  rejectsIdentity("bad organization id", Reply(200, identityBody(id = "not-a-uuid")), OAuthError.InvalidProviderResponse)
  rejectsIdentity("upper-case organization id", Reply(200, identityBody(id = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE")), OAuthError.InvalidProviderResponse)
  rejectsIdentity("blank organization name", Reply(200, identityBody(org = "   ")), OAuthError.InvalidProviderResponse)
  rejectsIdentity("long organization name", Reply(200, identityBody(org = "n" * 201)), OAuthError.InvalidProviderResponse)
  rejectsIdentity("control character in name", Reply(200, identityBody(org = "a\\u0007b")), OAuthError.InvalidProviderResponse)
  rejectsIdentity("missing organization", Reply(200, """{"data":{"viewer":{"id":"v"}}}"""), OAuthError.InvalidProviderResponse)
  rejectsIdentity("graphql errors", Reply(200, """{"errors":[{"message":"x"}],"data":null}"""), OAuthError.ProviderRejected)
  rejectsIdentity("graphql 401", Reply(401, "{}"), OAuthError.ProviderRejected)
  rejectsIdentity("graphql 302", Reply(302, "", Map("Location" -> "http://127.0.0.1:1/x")), OAuthError.ProviderRejected)
  rejectsIdentity("oversize graphql", Reply(200, "{\"data\":{\"x\":\"" + "x" * (1024 * 1024 + 10) + "\"}}"), OAuthError.InvalidProviderResponse)

  test("errors and the connector render no credential") {
    val client = LinearOAuthClient("client-id-1", clientSecretValue)
    assertNoSecrets(client.toString)
    server(happy).use: fake =>
      val rendered = connector(fake).toString + verifier.toString
      IO(assertNoSecrets(rendered))
  }

  // ---- selectable resources

  private def team(i: Int, name: String = null) =
    val id = f"00000000-0000-0000-0000-$i%012d"
    s"""{"id":"$id","name":"${Option(name).getOrElse(s"Team $i")}","key":"K$i"}"""

  private def page(nodes: Seq[String], more: Boolean, cursor: String = "c") =
    s"""{"data":{"teams":{"nodes":[${nodes.mkString(",")}],"pageInfo":{"hasNextPage":$more,"endCursor":"$cursor"}}}}"""

  private def storedSecret(expiresAt: Instant = now.plusSeconds(600)) =
    OAuthTokenJsonCodec().encode(OAuthTokens.from(accessValue, Some(refreshValue), expiresAt).get)

  private def root(kind: String = Linear.organization.wire) =
    ConnectionResource(ResourceId.random(), ConnectionId.random(), kind, ExternalId.parse(orgId).get, "Acme", ResourceId.random(), None, None)

  test("lists teams sorted by display name with the organization as parent") {
    server(_ => Reply(200, page(Vector(team(2, "Zeta"), team(1, "Alpha"), team(3, "Alpha")), more = false))).use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        val teams = result.toOption.get
        assertEquals(teams.map(_.displayName), Vector("Alpha (K1)", "Alpha (K3)", "Zeta (K2)"))
        assert(teams.forall(t => t.kind eq Linear.team))
        assert(teams.forall(_.parentExternalId.value == orgId))
        assertEquals(teams.head.externalId.value, "00000000-0000-0000-0000-000000000001")
        val request = fake.graphqlRequests.head
        assertEquals(request.headers("authorization"), "Bearer " + accessValue)
        val variables = parse(request.body).toOption.get.hcursor.downField("variables")
        assertEquals(variables.get[Int]("first"), Right(100))
        assertEquals(variables.get[Option[String]]("after"), Right(None))
  }

  test("duplicate team IDs are listed once") {
    server(_ => Reply(200, page(Vector(team(1), team(1)), more = false))).use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        assertEquals(result.toOption.get.size, 1)
  }

  test("follows the cursor across pages") {
    server: r =>
      val after = parse(r.body).toOption.get.hcursor.downField("variables").get[Option[String]]("after").toOption.flatten
      after match
        case None => Reply(200, page(Vector(team(1), team(2)), more = true, "cursor-1"))
        case Some("cursor-1") => Reply(200, page(Vector(team(3)), more = false))
        case Some(_) => Reply(500, "")
    .use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        assertEquals(result.toOption.get.size, 3)
        assertEquals(fake.graphqlRequests.size, 2)
  }

  test("pagination stops at 1,000 teams") {
    val counter = java.util.concurrent.atomic.AtomicInteger(0)
    server: _ =>
      val start = counter.getAndAdd(100)
      Reply(200, page((start until start + 100).map(team(_)), more = true, s"c$start"))
    .use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        assertEquals(result.toOption.get.size, 1000)
        assertEquals(fake.graphqlRequests.size, 10)
  }

  test("a repeated cursor is an invalid response, not a loop") {
    server(_ => Reply(200, page(Vector(team(1)), more = true, "same"))).use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        assertEquals(result, Left(OAuthError.InvalidProviderResponse))
        assertEquals(fake.graphqlRequests.size, 2)
  }

  test("a malformed team makes the listing invalid") {
    val bad = """{"id":"nope","name":"X","key":"K"}"""
    server(_ => Reply(200, page(Vector(team(1), bad), more = false))).use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        assertEquals(result, Left(OAuthError.InvalidProviderResponse))
  }

  test("an expired stored token is rejected without a request") {
    server(_ => Reply(200, page(Vector(team(1)), more = false))).use: fake =>
      connector(fake).selectableResources(storedSecret(now), root()).map: result =>
        assertEquals(result, Left(OAuthError.ProviderRejected))
        assertEquals(fake.requests.get.size, 0)
  }

  test("a token expiring in the future is used") {
    server(_ => Reply(200, page(Vector(team(1)), more = false))).use: fake =>
      connector(fake).selectableResources(storedSecret(now.plusSeconds(1)), root()).map(result => assert(result.isRight))
  }

  test("the wrong root kind is InvalidState without a request") {
    server(_ => Reply(200, page(Vector(team(1)), more = false))).use: fake =>
      connector(fake).selectableResources(storedSecret(), root(Linear.team.wire)).map: result =>
        assertEquals(result, Left(OAuthError.InvalidState))
        assertEquals(fake.requests.get.size, 0)
  }

  test("a malformed stored secret is InvalidState without a request") {
    server(_ => Reply(200, page(Vector(team(1)), more = false))).use: fake =>
      connector(fake).selectableResources(ProviderSecret.fromUtf8("not json"), root()).map: result =>
        assertEquals(result, Left(OAuthError.InvalidState))
        assertEquals(fake.requests.get.size, 0)
  }

  test("a listing failure carries no credential") {
    server(_ => Reply(401, "{}")).use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        assertEquals(result, Left(OAuthError.ProviderRejected))
        assertNoSecrets(result.toString)
  }
