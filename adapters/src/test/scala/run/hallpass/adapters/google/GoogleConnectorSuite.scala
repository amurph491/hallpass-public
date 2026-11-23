package run.hallpass.adapters.google

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

final class GoogleConnectorSuite extends CatsEffectSuite:
  private val now = Instant.parse("2026-03-04T05:06:07Z")
  private val clientSecretValue = "client-secret-value-123"
  private val accessValue = "ya29.access_token_value_abc"
  private val refreshValue = "1//refresh_token_value_xyz"
  private val codeValue = "authorization-code-value-789"
  private val subject = "110169484474386276334"
  private val driveFile = "https://www.googleapis.com/auth/drive.file"
  private val state = OAuthState.parse("a" * 43).get
  private val verifier = PkceVerifier.generate(SecureRandom())
  private val redirect = URI.create("https://hallpass.example/oauth/callback")
  private val clock = new Clock[IO]:
    def now: IO[Instant] = IO.pure(GoogleConnectorSuite.this.now)
  private val secrets = Vector(accessValue, refreshValue, clientSecretValue, codeValue, verifier.value)

  private final case class Recorded(method: String, path: String, query: String, headers: Map[String, String], body: String)
  private final case class Reply(status: Int, body: String, headers: Map[String, String] = Map.empty, delayMillis: Long = 0)
  private final class Fake(val base: URI, val requests: AtomicReference[Vector[Recorded]]):
    def endpoints = GoogleEndpoints(base.resolve("/o/oauth2/v2/auth"), base.resolve("/token"), base.resolve("/v1/userinfo"), base)
    def tokenRequests = requests.get.filter(_.path == "/token")
    def userinfoRequests = requests.get.filter(_.path == "/v1/userinfo")
    def listRequests = requests.get.filter(_.path == "/drive/v3/files")

  private def server(handler: Recorded => Reply): Resource[IO, Fake] =
    Resource.make(IO.blocking:
      val requests = AtomicReference(Vector.empty[Recorded])
      val http = HttpServer.create(InetSocketAddress(java.net.InetAddress.getLoopbackAddress, 0), 0)
      http.setExecutor(Executors.newCachedThreadPool())
      http.createContext("/", (exchange: HttpExchange) =>
        val body = String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)
        val headers = exchange.getRequestHeaders.asScala.map((k, v) => k.toLowerCase -> v.asScala.mkString(",")).toMap
        val recorded = Recorded(
          exchange.getRequestMethod, exchange.getRequestURI.getPath, Option(exchange.getRequestURI.getRawQuery).getOrElse(""), headers, body
        )
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

  private def connector(fake: Fake, fileLimit: Int = 1000, gmailSend: Boolean = false): GoogleConnector =
    val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    GoogleConnector(GoogleOAuthClient("client-id-1.apps", clientSecretValue, None, None), fake.endpoints, http, clock, redirect, fileLimit, gmailSend)

  private def tokenBody(
      access: String = accessValue,
      refresh: Option[String] = Some(refreshValue),
      expiresIn: Option[String] = Some("3599"),
      scope: Option[String] = Some(s"openid $driveFile")
  ) =
    val fields = Vector(
      Some(s""""access_token":"$access""""),
      Some(""""token_type":"Bearer""""),
      refresh.map(r => s""""refresh_token":"$r""""),
      expiresIn.map(e => s""""expires_in":$e"""),
      scope.map(s => s""""scope":"$s"""")
    ).flatten
    fields.mkString("{", ",", "}")

  private def identityBody(sub: String = subject, email: String = "alex@example.com") =
    s"""{"sub":"$sub","email":"$email","email_verified":true}"""

  private def happy(r: Recorded): Reply =
    if r.path == "/token" then Reply(200, tokenBody()) else Reply(200, identityBody())

  private val callback = OAuthCallback(state, codeValue)

  private def formFields(body: String): Map[String, String] =
    body.split('&').map(_.split("=", 2)).map(p => URLDecoder.decode(p(0), "UTF-8") -> URLDecoder.decode(p(1), "UTF-8")).toMap

  private def assertNoSecrets(text: String): Unit =
    secrets.foreach(s => assert(!text.contains(s), "a credential appeared in rendered output"))

  // ---- authorization URL

  test("authorization URL carries PKCE S256, drive.file scope, offline access, and state") {
    server(happy).use: fake =>
      connector(fake).authorizationUri(state, Some(verifier)).map: uri =>
        assertEquals(uri.getPath, "/o/oauth2/v2/auth")
        assertEquals(
          formFields(uri.getRawQuery),
          Map(
            "client_id" -> "client-id-1.apps",
            "redirect_uri" -> redirect.toString,
            "response_type" -> "code",
            "scope" -> s"openid email $driveFile",
            "state" -> state.value,
            "code_challenge" -> verifier.challenge,
            "code_challenge_method" -> "S256",
            "access_type" -> "offline",
            "prompt" -> "consent",
            "include_granted_scopes" -> "false"
          )
        )
        assert(!uri.toString.contains(verifier.value))
        assert(!uri.toString.contains(clientSecretValue))
  }

  test("the requested scopes never include a broader Drive scope") {
    assertEquals(Google.DriveScopes.filter(_.contains("/auth/drive")), Vector(driveFile))
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
        assertEquals(token.query, "")
        assertEquals(
          formFields(token.body),
          Map(
            "grant_type" -> "authorization_code",
            "code" -> codeValue,
            "redirect_uri" -> redirect.toString,
            "client_id" -> "client-id-1.apps",
            "client_secret" -> clientSecretValue,
            "code_verifier" -> verifier.value
          )
        )
        assert(token.headers.values.forall(v => !v.contains(clientSecretValue) && !v.contains(verifier.value)))
        val userinfo = fake.userinfoRequests
        assertEquals(userinfo.size, 1)
        assertEquals(userinfo.head.method, "GET")
        assertEquals(userinfo.head.headers("authorization"), "Bearer " + accessValue)
        assertEquals(userinfo.head.query, "")
        assert(!userinfo.head.body.contains(clientSecretValue) && !userinfo.head.body.contains(codeValue))
  }

  test("exchange builds the full grant, keyed by sub") {
    server(happy).use: fake =>
      connector(fake).exchange(callback, Some(verifier)).map: result =>
        val grant = result.toOption.get
        assertEquals(grant.externalAccountId.value, subject)
        assertEquals(grant.rootExternalId.value, subject)
        assertEquals(grant.rootDisplayName, "alex@example.com")
        assertEquals(grant.accountLabel, Some("alex@example.com"))
        val expected = now.plusSeconds(3599)
        assertEquals(grant.expiresAt, Some(expected))
        val tokens = OAuthTokenJsonCodec().decode(grant.secret).toOption.get
        assertEquals(tokens.accessToken, accessValue)
        assertEquals(tokens.refreshToken, Some(refreshValue))
        assertEquals(tokens.expiresAt, expected)
  }

  test("a changed email does not change the account identity") {
    server(r => if r.path == "/token" then Reply(200, tokenBody()) else Reply(200, identityBody(email = "renamed@example.com"))).use: fake =>
      connector(fake).exchange(callback, Some(verifier)).map: result =>
        val grant = result.toOption.get
        assertEquals(grant.rootExternalId.value, subject)
        assertEquals(grant.rootDisplayName, "renamed@example.com")
  }

  test("a missing or malformed email falls back to the default label") {
    val bodies = Vector(s"""{"sub":"$subject"}""", s"""{"sub":"$subject","email":"  "}""", s"""{"sub":"$subject","email":"a\\u0007b"}""")
    bodies.foldLeft(IO.unit): (previous, body) =>
      previous *> server(r => if r.path == "/token" then Reply(200, tokenBody()) else Reply(200, body)).use: fake =>
        connector(fake).exchange(callback, Some(verifier)).map: result =>
          val grant = result.toOption.get
          assertEquals(grant.rootDisplayName, "Google account")
          assertEquals(grant.accountLabel, Some("Google account"))
  }

  private def rejectsToken(name: String, reply: Reply, expected: OAuthError) =
    test(s"exchange fails closed: $name") {
      server(r => if r.path == "/token" then reply else Reply(200, identityBody())).use: fake =>
        connector(fake).exchange(callback, Some(verifier)).map: result =>
          assertEquals(result, Left(expected))
          assertEquals(fake.userinfoRequests.size, 0)
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
  rejectsToken("wrong token type", Reply(200, tokenBody().replace("Bearer", "MAC")), OAuthError.InvalidProviderResponse)
  rejectsToken("not json", Reply(200, "<html>"), OAuthError.InvalidProviderResponse)
  rejectsToken("missing scope", Reply(200, tokenBody(scope = None)), OAuthError.InvalidProviderResponse)
  rejectsToken("401 from the token endpoint", Reply(401, """{"error":"invalid_client"}"""), OAuthError.ProviderRejected)
  rejectsToken("400 from the token endpoint", Reply(400, """{"error":"invalid_grant"}"""), OAuthError.ProviderRejected)
  rejectsToken("500 from the token endpoint", Reply(500, ""), OAuthError.ProviderRejected)
  rejectsToken("redirect is not followed", Reply(302, "", Map("Location" -> "http://127.0.0.1:1/x")), OAuthError.ProviderRejected)
  rejectsToken(
    "oversize token response",
    Reply(200, tokenBody(access = "a" * (GoogleConnector.MaximumTokenResponseBytes + 10))),
    OAuthError.ProviderRejected
  )

  // An over-broad consent never becomes a connection.
  private val driveScope = "https://www.googleapis.com/auth/drive"
  Vector(
    "drive" -> s"openid $driveFile $driveScope",
    "drive.readonly" -> s"openid $driveFile https://www.googleapis.com/auth/drive.readonly",
    "drive.metadata" -> s"openid $driveFile https://www.googleapis.com/auth/drive.metadata",
    "drive.metadata.readonly" -> s"openid $driveFile https://www.googleapis.com/auth/drive.metadata.readonly",
    "drive.appdata" -> s"openid $driveFile https://www.googleapis.com/auth/drive.appdata",
    "drive without drive.file" -> s"openid $driveScope",
    "no drive.file" -> "openid email",
    "empty scope" -> "",
    "drive.file lookalike" -> "openid https://www.googleapis.com/auth/drive.filex"
  ).foreach: (name, scope) =>
    rejectsToken(s"granted scope $name", Reply(200, tokenBody(scope = Some(scope))), OAuthError.ProviderRejected)

  test("extra non-Drive scopes alongside drive.file are accepted") {
    server(r =>
      if r.path == "/token" then Reply(200, tokenBody(scope = Some(s"openid email $driveFile https://www.googleapis.com/auth/userinfo.email")))
      else Reply(200, identityBody())
    ).use: fake =>
      connector(fake).exchange(callback, Some(verifier)).map(result => assert(result.isRight))
  }

  test("exchange fails closed when the userinfo request times out") {
    val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    server(r => if r.path == "/token" then Reply(200, tokenBody()) else Reply(200, identityBody(), delayMillis = 12000)).use: fake =>
      val c = GoogleConnector(GoogleOAuthClient("client-id-1.apps", clientSecretValue, None, None), fake.endpoints, http, clock, redirect)
      c.exchange(callback, Some(verifier)).map(result => assertEquals(result, Left(OAuthError.ProviderRejected)))
  }

  private def rejectsIdentity(name: String, reply: Reply, expected: OAuthError) =
    test(s"exchange fails closed on userinfo: $name") {
      server(r => if r.path == "/token" then Reply(200, tokenBody()) else reply).use: fake =>
        connector(fake).exchange(callback, Some(verifier)).map: result =>
          assertEquals(result, Left(expected))
          assertNoSecrets(result.toString)
    }

  rejectsIdentity("missing sub", Reply(200, """{"email":"a@example.com"}"""), OAuthError.InvalidProviderResponse)
  rejectsIdentity("email only", Reply(200, """{"email":"a@example.com","email_verified":true}"""), OAuthError.InvalidProviderResponse)
  rejectsIdentity("numeric sub", Reply(200, s"""{"sub":$subject}"""), OAuthError.InvalidProviderResponse)
  rejectsIdentity("empty sub", Reply(200, identityBody(sub = "")), OAuthError.InvalidProviderResponse)
  rejectsIdentity("overlong sub", Reply(200, identityBody(sub = "1" * 256)), OAuthError.InvalidProviderResponse)
  rejectsIdentity("not json", Reply(200, "nope"), OAuthError.InvalidProviderResponse)
  rejectsIdentity("401", Reply(401, "{}"), OAuthError.ProviderRejected)
  rejectsIdentity("302", Reply(302, "", Map("Location" -> "http://127.0.0.1:1/x")), OAuthError.ProviderRejected)
  rejectsIdentity("oversize", Reply(200, "{\"sub\":\"" + "x" * (GoogleConnector.MaximumIdentityResponseBytes + 10) + "\"}"), OAuthError.ProviderRejected)

  test("errors and the connector render no credential") {
    val client = GoogleOAuthClient("client-id-1.apps", clientSecretValue, None, None)
    assertNoSecrets(client.toString)
    server(happy).use: fake =>
      val rendered = connector(fake).toString + verifier.toString
      IO(assertNoSecrets(rendered))
  }

  // ---- selectable resources

  private def file(i: Int, name: String = null, trashed: Boolean = false) =
    val id = f"file$i%012d"
    s"""{"id":"$id","name":"${Option(name).getOrElse(s"File $i")}","mimeType":"text/plain","trashed":$trashed}"""

  private def page(nodes: Seq[String], next: Option[String] = None) =
    val token = next.fold("")(n => s""","nextPageToken":"$n"""")
    s"""{"files":[${nodes.mkString(",")}]$token}"""

  private def storedSecret() =
    ProviderSecret.fromUtf8(accessValue)

  private def root(kind: String = Google.account.wire) =
    ConnectionResource(ResourceId.random(), ConnectionId.random(), kind, ExternalId.parse(subject).get, "Account", ResourceId.random(), None, None)

  test("lists files sorted by name, parented to the account, with the bearer token and fixed query") {
    server(_ => Reply(200, page(Vector(file(2, "Zeta"), file(1, "Alpha"))))).use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        val files = result.toOption.get
        assertEquals(files.map(_.displayName), Vector("Alpha", "Zeta"))
        assert(files.forall(f => f.kind eq Google.driveFile))
        assert(files.forall(_.parentExternalId.value == subject))
        assertEquals(files.head.externalId.value, "file000000000001")
        val request = fake.listRequests.head
        assertEquals(request.method, "GET")
        assertEquals(request.headers("authorization"), "Bearer " + accessValue)
        val query = formFields(request.query)
        assertEquals(query("pageSize"), "100")
        assertEquals(query("q"), "trashed=false")
        assertEquals(query("fields"), "nextPageToken,files(id,name,mimeType,trashed)")
        assert(!query.contains("pageToken"))
  }

  test("a trashed file is not selectable and duplicate IDs are listed once") {
    server(_ => Reply(200, page(Vector(file(1), file(1), file(2, trashed = true))))).use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        assertEquals(result.toOption.get.map(_.externalId.value), Vector("file000000000001"))
  }

  test("an odd file name is sanitized rather than failing the listing") {
    val long = "n" * 300
    server(_ => Reply(200, page(Vector(file(1, "a\\u0007b"), file(2, "   "), file(3, long))))).use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        val names = result.toOption.get.map(_.displayName)
        assert(names.contains("a b"))
        assert(names.contains("Untitled"))
        assert(names.contains("n" * 200))
  }

  test("follows nextPageToken across pages") {
    server: r =>
      formFields(r.query).get("pageToken") match
        case None => Reply(200, page(Vector(file(1), file(2)), Some("cursor-1")))
        case Some("cursor-1") => Reply(200, page(Vector(file(3))))
        case Some(_) => Reply(500, "")
    .use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        assertEquals(result.toOption.get.size, 3)
        assertEquals(fake.listRequests.size, 2)
  }

  test("pagination stops at the file limit") {
    val counter = java.util.concurrent.atomic.AtomicInteger(0)
    server: _ =>
      val start = counter.getAndAdd(100)
      Reply(200, page((start until start + 100).map(file(_)), Some(s"c$start")))
    .use: fake =>
      connector(fake, fileLimit = 250).selectableResources(storedSecret(), root()).map: result =>
        assertEquals(result.toOption.get.size, 250)
        assertEquals(fake.listRequests.size, 3)
  }

  test("a repeated page token is an invalid response, not a loop") {
    server(_ => Reply(200, page(Vector(file(1)), Some("same")))).use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        assertEquals(result, Left(OAuthError.InvalidProviderResponse))
        assertEquals(fake.listRequests.size, 2)
  }

  test("a malformed file ID makes the listing invalid") {
    val bad = """{"id":"x y","name":"X","mimeType":"text/plain"}"""
    server(_ => Reply(200, page(Vector(file(1), bad)))).use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        assertEquals(result, Left(OAuthError.InvalidProviderResponse))
  }

  test("a body without a files array is an invalid response") {
    server(_ => Reply(200, "{}")).use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        assertEquals(result, Left(OAuthError.InvalidProviderResponse))
  }

  test("the wrong root kind is InvalidState without a request") {
    server(_ => Reply(200, page(Vector(file(1))))).use: fake =>
      connector(fake).selectableResources(storedSecret(), root(Google.driveFile.wire)).map: result =>
        assertEquals(result, Left(OAuthError.InvalidState))
        assertEquals(fake.requests.get.size, 0)
  }

  test("a malformed access token is InvalidState without a request") {
    server(_ => Reply(200, page(Vector(file(1))))).use: fake =>
      connector(fake).selectableResources(ProviderSecret.fromUtf8("not json"), root()).map: result =>
        assertEquals(result, Left(OAuthError.InvalidState))
        assertEquals(fake.requests.get.size, 0)
  }

  test("listing failures are rejections that carry no credential, and redirects are not followed") {
    val replies = Vector(Reply(401, "{}"), Reply(500, ""), Reply(302, "", Map("Location" -> "http://127.0.0.1:1/x")))
    replies.foldLeft(IO.unit): (previous, reply) =>
      previous *> server(_ => reply).use: fake =>
        connector(fake).selectableResources(storedSecret(), root()).map: result =>
          assertEquals(result, Left(OAuthError.ProviderRejected))
          assertNoSecrets(result.toString)
          assertEquals(fake.listRequests.size, 1)
  }

  test("an unparsable listing is an invalid response") {
    server(_ => Reply(200, "<html>")).use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        assertEquals(result, Left(OAuthError.InvalidProviderResponse))
  }

  // ---- Gmail send -----------------------------------------------------------------------------------------

  private val gmailSend = "https://www.googleapis.com/auth/gmail.send"

  test("with Gmail send enabled the authorization URL also requests gmail.send, and only that Gmail scope") {
    server(happy).use: fake =>
      connector(fake, gmailSend = true).authorizationUri(state, Some(verifier)).map: uri =>
        val scope = formFields(uri.getRawQuery)("scope")
        assertEquals(scope, s"openid email $driveFile $gmailSend")
        assertEquals(scope.split(" ").filter(_.contains("mail")).toSet, Set("email", gmailSend))
  }

  test("without Gmail send the authorization URL never requests a Gmail scope") {
    server(happy).use: fake =>
      connector(fake).authorizationUri(state, Some(verifier)).map: uri =>
        assert(!formFields(uri.getRawQuery)("scope").contains("gmail"))
  }

  test("with Gmail send enabled a grant of drive.file and gmail.send is accepted") {
    server(r =>
      if r.path == "/token" then Reply(200, tokenBody(scope = Some(s"openid email $driveFile $gmailSend")))
      else Reply(200, identityBody())
    ).use: fake =>
      connector(fake, gmailSend = true).exchange(callback, Some(verifier)).map(result => assert(result.isRight))
  }

  Vector(
    "full mailbox" -> "https://mail.google.com/",
    "gmail.readonly" -> "https://www.googleapis.com/auth/gmail.readonly",
    "gmail.modify" -> "https://www.googleapis.com/auth/gmail.modify",
    "gmail.compose" -> "https://www.googleapis.com/auth/gmail.compose",
    "gmail.metadata" -> "https://www.googleapis.com/auth/gmail.metadata",
    "gmail.send lookalike" -> "https://www.googleapis.com/auth/gmail.sendx"
  ).foreach: (name, extra) =>
    test(s"with Gmail send enabled a broader Gmail grant is refused: $name") {
      server(r =>
        if r.path == "/token" then Reply(200, tokenBody(scope = Some(s"openid $driveFile $gmailSend $extra")))
        else Reply(200, identityBody())
      ).use: fake =>
        connector(fake, gmailSend = true).exchange(callback, Some(verifier)).map: result =>
          assertEquals(result, Left(OAuthError.ProviderRejected))
          assertEquals(fake.userinfoRequests.size, 0)
    }

  Vector("gmail.send" -> gmailSend, "full mailbox" -> "https://mail.google.com/", "gmail.readonly" -> "https://www.googleapis.com/auth/gmail.readonly")
    .foreach: (name, extra) =>
      test(s"without Gmail send any granted Gmail scope is refused: $name") {
        server(r =>
          if r.path == "/token" then Reply(200, tokenBody(scope = Some(s"openid $driveFile $extra")))
          else Reply(200, identityBody())
        ).use: fake =>
          connector(fake).exchange(callback, Some(verifier)).map: result =>
            assertEquals(result, Left(OAuthError.ProviderRejected))
            assertEquals(fake.userinfoRequests.size, 0)
      }

  test("with Gmail send enabled discovery also offers the account's mailbox without another request") {
    server(_ => Reply(200, page(Vector(file(1, "Alpha"))))).use: fake =>
      connector(fake, gmailSend = true).selectableResources(storedSecret(), root()).map: result =>
        val offered = result.toOption.get
        assertEquals(offered.size, 2)
        val mailbox = offered.filter(_.kind eq Google.mailbox)
        assertEquals(mailbox.size, 1)
        assertEquals(mailbox.head.externalId.value, subject)
        assertEquals(mailbox.head.parentExternalId.value, subject)
        assertEquals(mailbox.head.displayName, "Mailbox (send) \u2014 Account")
        assertEquals(fake.requests.get.size, 1, "the mailbox needs no provider request")
  }

  test("without Gmail send discovery offers no mailbox") {
    server(_ => Reply(200, page(Vector(file(1, "Alpha"))))).use: fake =>
      connector(fake).selectableResources(storedSecret(), root()).map: result =>
        assert(result.toOption.get.forall(_.kind eq Google.driveFile))
  }
