package run.hallpass.adapters.github

import java.net.http.HttpClient
import java.net.{InetSocketAddress, URI, URLDecoder}
import java.nio.charset.StandardCharsets
import java.time.{Duration, Instant}
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference
import scala.jdk.CollectionConverters.*
import cats.effect.{IO, Resource}
import com.sun.net.httpserver.{HttpExchange, HttpServer}
import io.circe.Json
import io.circe.parser.parse
import munit.CatsEffectSuite
import run.hallpass.application.Clock

final class GitHubAppClientSuite extends CatsEffectSuite:
  private val now = Instant.parse("2026-03-04T05:06:07Z")
  private val clientSecretValue = "client-secret-value-123"
  private val userTokenValue = "ghu_user_token_value"
  private val installTokenValue = "ghs_installation_token_value"
  private val keyPair =
    val generator = java.security.KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048)
    generator.generateKeyPair()
  private val secrets = GitHubAppSecrets(keyPair.getPrivate.asInstanceOf[java.security.interfaces.RSAPrivateKey], clientSecretValue)
  private val registration = GitHubAppRegistration(42L, "Iv1.client", "hallpass-app")
  private val installationId = GitHubInstallationId.from(777L).get

  private final case class Recorded(method: String, uri: String, headers: Map[String, String], body: String)
  private final case class Reply(status: Int, body: String, headers: Map[String, String] = Map.empty, delayMillis: Long = 0)

  private final class Fake(val endpoint: URI, val requests: AtomicReference[Vector[Recorded]])

  private def server(handler: Recorded => Reply): Resource[IO, Fake] =
    Resource.make(IO.blocking:
      val requests = AtomicReference(Vector.empty[Recorded])
      val http = HttpServer.create(InetSocketAddress(java.net.InetAddress.getLoopbackAddress, 0), 0)
      http.setExecutor(Executors.newCachedThreadPool())
      http.createContext("/", (exchange: HttpExchange) =>
        val body = String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)
        val headers = exchange.getRequestHeaders.asScala.map((k, v) => k.toLowerCase -> v.asScala.mkString(",")).toMap
        val recorded = Recorded(exchange.getRequestMethod, exchange.getRequestURI.toString, headers, body)
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

  private val clock = new Clock[IO]:
    def now: IO[Instant] = IO.pure(GitHubAppClientSuite.this.now)

  private def client(fake: Fake, timeout: Duration = Duration.ofSeconds(5)): GitHubAppClient =
    val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    GitHubAppClient(registration, secrets, GitHubEndpoints(fake.endpoint, fake.endpoint), http, clock, timeout)

  private def mintedToken(raw: String = installTokenValue) =
    MintedInstallationToken(raw, now.plusSeconds(3600), Vector.empty, Map.empty)

  private def repoName(i: Int) = s"org/repo-$i"
  private def reposJson(range: Range): String =
    Json.obj("repositories" -> Json.fromValues(range.map(i =>
      Json.obj("id" -> Json.fromLong(i.toLong), "full_name" -> Json.fromString(repoName(i)))))).noSpaces

  private def parseForm(body: String): Map[String, String] =
    body.split("&").map(_.split("=", 2)).map(a => URLDecoder.decode(a(0), "UTF-8") -> URLDecoder.decode(a(1), "UTF-8")).toMap

  private val tokenBody =
    s"""{"token":"$installTokenValue","expires_at":"2026-03-04T06:06:07Z","permissions":{"issues":"read","metadata":"read"},
       |"repositories":[{"id":11,"full_name":"org/alpha"},{"id":12,"full_name":"org/beta"}]}""".stripMargin

  private val mint = (c: GitHubAppClient) =>
    c.installationToken(installationId, Some(Vector(GitHubRepositoryId.from(11).get, GitHubRepositoryId.from(12).get)),
      Set(GitHubPermission.IssuesRead, GitHubPermission.MetadataRead))

  // ---- installationToken ----

  test("installation token mint sends the exact JSON body and App JWT, and decodes the response") {
    server(_ => Reply(201, tokenBody)).use: fake =>
      mint(client(fake)).map: result =>
        val minted = result.toOption.get
        assertEquals(minted.raw, installTokenValue)
        assertEquals(minted.expiresAt, Instant.parse("2026-03-04T06:06:07Z"))
        assertEquals(minted.permissions, Map("issues" -> "read", "metadata" -> "read"))
        assertEquals(minted.repositories.map(r => r.id.value -> r.fullName.value), Vector(11L -> "org/alpha", 12L -> "org/beta"))
        val request = fake.requests.get().head
        assertEquals(request.method, "POST")
        assertEquals(request.uri, "/app/installations/777/access_tokens")
        assertEquals(parse(request.body), Right(parse("""{"permissions":{"issues":"read","metadata":"read"},"repository_ids":[11,12]}""").toOption.get))
        assertEquals(request.headers.get("accept"), Some("application/vnd.github+json"))
        assertEquals(request.headers.get("x-github-api-version"), Some("2022-11-28"))
        assertEquals(request.headers.get("user-agent"), Some("hallpass"))
        assertEquals(request.headers.get("accept-encoding"), Some("identity"))
        val bearer = request.headers("authorization").stripPrefix("Bearer ")
        assertEquals(bearer.count(_ == '.'), 2)
  }

  test("installation token mint without a repository set omits repository_ids and tolerates absent repositories") {
    server(_ => Reply(201, """{"token":"tok","expires_at":"2026-03-04T06:06:07Z","permissions":{"metadata":"read"}}""")).use: fake =>
      client(fake).installationToken(installationId, None, Set(GitHubPermission.MetadataRead)).map: result =>
        assertEquals(result.toOption.get.repositories, Vector.empty)
        assertEquals(parse(fake.requests.get().head.body).toOption.get, parse("""{"permissions":{"metadata":"read"}}""").toOption.get)
  }

  test("installation token mint refuses empty, contradictory, or empty-repository requests without sending anything") {
    server(_ => Reply(201, tokenBody)).use: fake =>
      val c = client(fake)
      for
        a <- c.installationToken(installationId, None, Set.empty)
        b <- c.installationToken(installationId, None, Set(GitHubPermission.IssuesRead, GitHubPermission.IssuesWrite))
        d <- c.installationToken(installationId, Some(Vector.empty), Set(GitHubPermission.IssuesRead))
      yield
        assertEquals(Vector(a, b, d).map(_.left.toOption), Vector.fill(3)(Some(GitHubApiError.Rejected)))
        assertEquals(fake.requests.get().size, 0)
  }

  test("installation token response must have a clean token, valid repositories, and a 201 status") {
    val bad = Vector(
      """{"token":"has space","expires_at":"2026-03-04T06:06:07Z","permissions":{}}""",
      """{"token":"","expires_at":"2026-03-04T06:06:07Z","permissions":{}}""",
      """{"token":"a\nb","expires_at":"2026-03-04T06:06:07Z","permissions":{}}""",
      """{"token":"tok","expires_at":"yesterday","permissions":{}}""",
      """{"token":"tok","expires_at":"2026-03-04T06:06:07Z"}""",
      """{"token":"tok","expires_at":"2026-03-04T06:06:07Z","permissions":{"issues":1}}""",
      """{"token":"tok","expires_at":"2026-03-04T06:06:07Z","permissions":{},"repositories":[{"id":1,"full_name":"../etc"}]}""",
      """{"token":"tok","expires_at":"2026-03-04T06:06:07Z","permissions":{},"repositories":[{"id":0,"full_name":"org/a"}]}""",
      """{"token":"tok","expires_at":"2026-03-04T06:06:07Z","permissions":{},"repositories":[{"id":"x","full_name":"org/a"}]}"""
    )
    bad.foldLeft(IO.unit): (acc, body) =>
      acc *> server(_ => Reply(201, body)).use: fake =>
        mint(client(fake)).map(r => assertEquals(r.left.toOption, Some(GitHubApiError.InvalidResponse), body))
    .flatMap(_ => server(_ => Reply(200, tokenBody)).use(fake =>
      mint(client(fake)).map(r => assertEquals(r.left.toOption, Some(GitHubApiError.InvalidResponse)))))
  }

  // ---- installation ----

  test("installation lookup decodes the account and sends an App JWT") {
    server(_ => Reply(200, """{"id":777,"account":{"id":9,"login":"octo-org","type":"Organization"}}""")).use: fake =>
      client(fake).installation(installationId).map: result =>
        assertEquals(result, Right(GitHubInstallationAccount(installationId, 9L, "octo-org", "Organization")))
        val request = fake.requests.get().head
        assertEquals(request.method, "GET")
        assertEquals(request.uri, "/app/installations/777")
        assert(request.headers("authorization").startsWith("Bearer "))
  }

  test("installation lookup rejects an id mismatch and missing account fields") {
    val cases = Vector(
      """{"id":778,"account":{"id":9,"login":"o","type":"User"}}""",
      """{"id":777}""",
      """{"id":777,"account":{"id":9,"login":"","type":"User"}}"""
    )
    cases.foldLeft(IO.unit): (acc, body) =>
      acc *> server(_ => Reply(200, body)).use: fake =>
        client(fake).installation(installationId).map(r => assertEquals(r.left.toOption, Some(GitHubApiError.InvalidResponse), body))
  }

  // ---- installationRepositories ----

  test("installation repositories follow pages of 100 with the installation token") {
    val handler = (r: Recorded) =>
      if r.uri.endsWith("page=1") then Reply(200, reposJson(1 to 100)) else Reply(200, reposJson(101 to 150))
    server(handler).use: fake =>
      client(fake).installationRepositories(mintedToken(), 1000).map: result =>
        assertEquals(result.toOption.get.size, 150)
        assertEquals(result.toOption.get.last.fullName.value, repoName(150))
        val requests = fake.requests.get()
        assertEquals(requests.map(_.uri), Vector("/installation/repositories?per_page=100&page=1", "/installation/repositories?per_page=100&page=2"))
        assertEquals(requests.map(_.headers("authorization")).distinct, Vector(s"Bearer $installTokenValue"))
  }

  test("installation repositories truncate at the limit without fetching more pages") {
    server(_ => Reply(200, reposJson(1 to 100))).use: fake =>
      client(fake).installationRepositories(mintedToken(), 30).map: result =>
        assertEquals(result.toOption.get.size, 30)
        assertEquals(fake.requests.get().size, 1)
  }

  test("installation repositories reject a non-positive limit before any request") {
    server(_ => Reply(200, reposJson(1 to 1))).use: fake =>
      client(fake).installationRepositories(mintedToken(), 0).map: result =>
        assertEquals(result.left.toOption, Some(GitHubApiError.Rejected))
        assertEquals(fake.requests.get().size, 0)
  }

  // ---- exchangeUserCode ----

  test("user code exchange posts the client secret only in the form body and decodes the token") {
    server(_ => Reply(200, s"""{"access_token":"$userTokenValue","token_type":"bearer"}""")).use: fake =>
      client(fake).exchangeUserCode("the-code", URI.create("https://hallpass.example/cb?x=1")).map: result =>
        assertEquals(result.toOption.get.raw, userTokenValue)
        val request = fake.requests.get().head
        assertEquals(request.method, "POST")
        assertEquals(request.uri, "/login/oauth/access_token")
        assertEquals(request.headers.get("accept"), Some("application/json"))
        assertEquals(parseForm(request.body), Map(
          "client_id" -> "Iv1.client", "client_secret" -> clientSecretValue, "code" -> "the-code",
          "redirect_uri" -> "https://hallpass.example/cb?x=1"))
        assert(!request.uri.contains(clientSecretValue))
        assert(request.headers.values.forall(!_.contains(clientSecretValue)))
  }

  test("user code exchange treats an error field in a 200 response as rejected") {
    server(_ => Reply(200, """{"error":"bad_verification_code","error_description":"nope"}""")).use: fake =>
      client(fake).exchangeUserCode("c", URI.create("https://a.example/cb")).map: result =>
        assertEquals(result.left.toOption, Some(GitHubApiError.Rejected))
  }

  test("user code exchange rejects a missing or malformed access token") {
    Vector("""{"token_type":"bearer"}""", """{"access_token":"has space"}""").foldLeft(IO.unit): (acc, body) =>
      acc *> server(_ => Reply(200, body)).use: fake =>
        client(fake).exchangeUserCode("c", URI.create("https://a.example/cb")).map: result =>
          assertEquals(result.left.toOption, Some(GitHubApiError.InvalidResponse))
  }

  // ---- userCanAccessInstallation ----

  private def installationsJson(range: Range): String =
    Json.obj("installations" -> Json.fromValues(range.map(i => Json.obj("id" -> Json.fromLong(i.toLong))))).noSpaces

  test("user installation check finds the installation on a later page") {
    val handler = (r: Recorded) =>
      if r.uri.endsWith("page=1") then Reply(200, installationsJson(1 to 100)) else Reply(200, installationsJson(700 to 800))
    server(handler).use: fake =>
      client(fake).userCanAccessInstallation(GitHubUserToken(userTokenValue), installationId).map: result =>
        assertEquals(result, Right(true))
        assertEquals(fake.requests.get().map(_.uri), Vector("/user/installations?per_page=100&page=1", "/user/installations?per_page=100&page=2"))
        assertEquals(fake.requests.get().head.headers("authorization"), s"Bearer $userTokenValue")
  }

  test("user installation check is false after a short page and bounded by MaximumUserPages") {
    server(_ => Reply(200, installationsJson(1 to 5))).use: fake =>
      client(fake).userCanAccessInstallation(GitHubUserToken(userTokenValue), installationId).map: result =>
        assertEquals(result, Right(false))
        assertEquals(fake.requests.get().size, 1)
    .flatMap(_ => server(_ => Reply(200, installationsJson(1 to 100))).use: fake =>
      client(fake).userCanAccessInstallation(GitHubUserToken(userTokenValue), installationId).map: result =>
        assertEquals(result, Right(false))
        assertEquals(fake.requests.get().size, GitHubAppClient.MaximumUserPages))
  }

  // ---- failures ----

  private val statusCases = Vector(
    (401, Map.empty[String, String], GitHubApiError.Unauthorized),
    (403, Map.empty[String, String], GitHubApiError.Forbidden),
    (403, Map("x-ratelimit-remaining" -> "0"), GitHubApiError.RateLimited),
    (403, Map("x-ratelimit-remaining" -> "12"), GitHubApiError.Forbidden),
    (429, Map.empty[String, String], GitHubApiError.RateLimited),
    (404, Map.empty[String, String], GitHubApiError.NotFound),
    (500, Map.empty[String, String], GitHubApiError.Rejected),
    (422, Map.empty[String, String], GitHubApiError.Rejected)
  )

  statusCases.foreach: (status, headers, expected) =>
    test(s"status $status with headers ${headers.keys.mkString(",")} maps to $expected") {
      server(_ => Reply(status, s"""{"message":"$installTokenValue $clientSecretValue"}""", headers)).use: fake =>
        mint(client(fake)).map: result =>
          assertEquals(result.left.toOption, Some(expected))
          assert(!result.toString.contains(installTokenValue))
          assert(!result.toString.contains(clientSecretValue))
    }

  test("a redirect is rejected and its Location is never followed") {
    val handler = (r: Recorded) =>
      if r.uri.startsWith("/elsewhere") then Reply(200, tokenBody)
      else Reply(302, "", Map("Location" -> "/elsewhere"))
    server(handler).use: fake =>
      mint(client(fake)).map: result =>
        assertEquals(result.left.toOption, Some(GitHubApiError.Rejected))
        assertEquals(fake.requests.get().size, 1)
  }

  test("redirect status is rejected even if the client was built to follow redirects") {
    val handler = (r: Recorded) => Reply(307, "", Map("Location" -> "/elsewhere"))
    server(handler).use: fake =>
      val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
      val c = GitHubAppClient(registration, secrets, GitHubEndpoints(fake.endpoint, fake.endpoint), http, clock)
      c.installation(installationId).map(r => assertEquals(r.left.toOption, Some(GitHubApiError.Rejected)))
  }

  test("an oversized body is an InvalidResponse") {
    val big = "{\"pad\":\"" + "a" * (GitHubAppClient.MaximumResponseBytes + 10) + "\"}"
    server(_ => Reply(201, big)).use: fake =>
      mint(client(fake)).map(r => assertEquals(r.left.toOption, Some(GitHubApiError.InvalidResponse)))
  }

  test("malformed and non-object JSON are InvalidResponse") {
    Vector("not json", "[1,2]", "", "{\"token\":").foldLeft(IO.unit): (acc, body) =>
      acc *> server(_ => Reply(201, body)).use: fake =>
        mint(client(fake)).map(r => assertEquals(r.left.toOption, Some(GitHubApiError.InvalidResponse), body))
  }

  test("a server slower than the request timeout yields Timeout and is not retried") {
    server(_ => Reply(201, tokenBody, delayMillis = 2000)).use: fake =>
      mint(client(fake, Duration.ofMillis(300))).map: result =>
        assertEquals(result.left.toOption, Some(GitHubApiError.Timeout))
        assertEquals(fake.requests.get().size, 1)
  }

  test("a refused connection yields Timeout or Rejected without leaking details") {
    val dead = Fake(URI.create("http://127.0.0.1:1"), AtomicReference(Vector.empty))
    mint(client(dead)).map: result =>
      assert(result.left.toOption.exists(e => e == GitHubApiError.Timeout || e == GitHubApiError.Rejected))
      assert(!result.toString.contains("127.0.0.1"))
  }

  test("tokens, secrets, and errors never render credential values") {
    assertEquals(mintedToken().toString, "MintedInstallationToken(<redacted>)")
    assertEquals(GitHubUserToken(userTokenValue).toString, "GitHubUserToken(<redacted>)")
    assertEquals(secrets.toString, "GitHubAppSecrets(<redacted>)")
    val rendered = GitHubApiError.values.map(_.toString).mkString(" ")
    Vector(installTokenValue, userTokenValue, clientSecretValue).foreach(v => assert(!rendered.contains(v)))
    assert(!mintedToken().toString.contains(installTokenValue))
    assert(!GitHubUserToken(userTokenValue).toString.contains(userTokenValue))
    assert(!secrets.toString.contains(clientSecretValue))
  }

  test("error responses from every operation leak no credential through the result") {
    server(_ => Reply(401, s"""{"message":"$userTokenValue $installTokenValue $clientSecretValue"}""")).use: fake =>
      val c = client(fake)
      for
        a <- c.installation(installationId)
        b <- c.installationRepositories(mintedToken(), 10)
        d <- c.exchangeUserCode("code", URI.create("https://a.example/cb"))
        e <- c.userCanAccessInstallation(GitHubUserToken(userTokenValue), installationId)
      yield
        val rendered = Vector(a, b, d, e).map(_.toString).mkString
        Vector(userTokenValue, installTokenValue, clientSecretValue).foreach(v => assert(!rendered.contains(v)))
        assertEquals(Vector(a.left.toOption, b.left.toOption, d.left.toOption, e.left.toOption), Vector.fill(4)(Some(GitHubApiError.Unauthorized)))
  }
