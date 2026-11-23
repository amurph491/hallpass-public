package run.hallpass.adapters.notion

import java.net.http.HttpClient
import java.net.{InetSocketAddress, URI, URLDecoder}
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference
import scala.jdk.CollectionConverters.*
import cats.effect.{IO, Resource}
import com.sun.net.httpserver.{HttpExchange, HttpServer}
import io.circe.Json
import io.circe.parser.parse
import munit.CatsEffectSuite
import run.hallpass.application.*
import run.hallpass.kernel.{ConnectionId, ResourceId}

final class NotionConnectorSuite extends CatsEffectSuite:
  private val clientId = "notion-client-id"
  private val clientSecretValue = "notion-client-secret-value-123"
  private val accessValue = "secret_accessTokenValue_abc"
  private val refreshValue = "refreshTokenValue_xyz"
  private val workspaceUuid = "11111111-2222-4333-8444-555555555555"
  private val botUuid = "99999999-8888-4777-8666-555555555555"
  private val redirect = URI.create("https://hallpass.example/oauth/callback")
  private val state = OAuthState.parse("a" * 43).get
  private val secretTexts = Vector(accessValue, refreshValue, clientSecretValue, "the-code-value")

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

  private def connector(fake: Fake, pageLimit: Int = 1000): NotionConnector =
    val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
    NotionConnector(
      NotionOAuthClient(clientId, clientSecretValue),
      NotionEndpoints(fake.endpoint.resolve("/v1/oauth/authorize"), fake.endpoint),
      http,
      redirect,
      pageLimit
    )

  private def withConnector[A](handler: Recorded => Reply, pageLimit: Int = 1000)(use: (NotionConnector, Fake) => IO[A]): IO[A] =
    server(handler).use(fake => use(connector(fake, pageLimit), fake))

  private val callback = OAuthCallback(state, "the-code-value")

  private def tokenBody(extra: Vector[(String, Json)] = Vector.empty, drop: Set[String] = Set.empty): String =
    val base = Vector(
      "access_token" -> Json.fromString(accessValue),
      "token_type" -> Json.fromString("bearer"),
      "refresh_token" -> Json.fromString(refreshValue),
      "bot_id" -> Json.fromString(botUuid),
      "workspace_id" -> Json.fromString(workspaceUuid),
      "workspace_name" -> Json.fromString("Acme  Workspace"),
      "owner" -> Json.obj("type" -> Json.fromString("user"), "user" -> Json.obj("name" -> Json.fromString("Alex")))
    ).filterNot((k, _) => drop(k))
    val overridden = base.filterNot((k, _) => extra.exists(_._1 == k)) ++ extra
    Json.fromFields(overridden).noSpaces

  private def ok(body: String) = Reply(200, body)

  private def assertNoSecret(value: Any): Unit =
    val text = value.toString
    secretTexts.foreach(secret => assert(!text.contains(secret), "secret text leaked"))

  private def exchangeFails(reply: Reply, expected: OAuthError) =
    withConnector(_ => reply): (c, _) =>
      c.exchange(callback).map: result =>
        assertEquals(result.map(_ => ()), Left(expected))
        assertNoSecret(result)

  private def root(workspace: String = workspaceUuid, kind: String = Notion.workspace.wire) =
    ConnectionResource(
      ResourceId.random(), ConnectionId.random(), kind, ExternalId.parse(workspace).get, "Acme", ResourceId.random(), None, None
    )

  private def secret(workspace: String = workspaceUuid) =
    NotionTokenRecord.encode(
      NotionTokenRecord.from(accessValue, Some(refreshValue), NotionId.parse(botUuid).get, NotionId.parse(workspace).get).get
    )

  private def page(id: String, title: Option[String], extra: Vector[(String, Json)] = Vector.empty): Json =
    val titleProperty = title.fold(Vector.empty[(String, Json)]): text =>
      Vector("Name" -> Json.obj(
        "id" -> Json.fromString("title"),
        "type" -> Json.fromString("title"),
        "title" -> Json.arr(Json.obj("plain_text" -> Json.fromString(text)))
      ))
    Json.fromFields(Vector(
      "object" -> Json.fromString("page"),
      "id" -> Json.fromString(id),
      "properties" -> Json.fromFields(Vector("Tags" -> Json.obj("type" -> Json.fromString("rich_text"))) ++ titleProperty)
    ) ++ extra)

  private def pid(n: Int) = f"aaaaaaaa-bbbb-4ccc-8ddd-$n%012d"

  private def searchReply(pages: Vector[Json], next: Option[String] = None) =
    ok(Json.obj(
      "object" -> Json.fromString("list"),
      "results" -> Json.fromValues(pages),
      "next_cursor" -> next.fold(Json.Null)(Json.fromString),
      "has_more" -> Json.fromBoolean(next.isDefined)
    ).noSpaces)

  // Authorization URL

  test("authorization URI carries the client, redirect, response type, owner=user, and state") {
    withConnector(_ => ok("{}")): (c, fake) =>
      c.authorizationUri(state).map: uri =>
        assertEquals(uri.getPath, "/v1/oauth/authorize")
        val params = uri.getRawQuery.split("&").map(_.split("=", 2)).map(a => a(0) -> URLDecoder.decode(a(1), "UTF-8")).toMap
        assertEquals(
          params,
          Map(
            "client_id" -> clientId,
            "redirect_uri" -> redirect.toString,
            "response_type" -> "code",
            "owner" -> "user",
            "state" -> state.value
          )
        )
        assert(uri.getRawQuery.contains("redirect_uri=https%3A%2F%2Fhallpass.example%2Foauth%2Fcallback"))
        assert(!uri.toString.contains(clientSecretValue))
        assertEquals(fake.requests.get.size, 0)
  }

  // Exchange

  test("exchange uses Basic auth, the JSON body, and the Notion headers, and builds the full grant") {
    withConnector(_ => ok(tokenBody())): (c, fake) =>
      c.exchange(callback).map: result =>
        val grant = result.fold(error => fail(s"expected a grant, got $error"), identity)
        val request = fake.requests.get.head
        assertEquals(request.method, "POST")
        assertEquals(request.uri, "/v1/oauth/token")
        val basic = request.headers("authorization")
        assert(basic.startsWith("Basic "))
        assertEquals(String(Base64.getDecoder.decode(basic.stripPrefix("Basic ")), StandardCharsets.UTF_8), s"$clientId:$clientSecretValue")
        assertEquals(request.headers("notion-version"), Notion.ApiVersion)
        assertEquals(request.headers("content-type"), "application/json")
        assertEquals(request.headers("user-agent"), "hallpass")
        assertEquals(request.headers("accept-encoding"), "identity")
        assertEquals(
          parse(request.body),
          Right(Json.obj(
            "grant_type" -> Json.fromString("authorization_code"),
            "code" -> Json.fromString("the-code-value"),
            "redirect_uri" -> Json.fromString(redirect.toString)
          ))
        )
        assert(!request.body.contains(clientSecretValue))
        val record = NotionTokenRecord.decode(grant.secret).fold(error => fail(s"undecodable record: $error"), identity)
        assertEquals(record.accessToken, accessValue)
        assertEquals(record.refreshToken, Some(refreshValue))
        assertEquals(record.botId.value, botUuid)
        assertEquals(record.workspaceId.value, workspaceUuid)
        assertEquals(grant.externalAccountId.value, workspaceUuid)
        assertEquals(grant.rootExternalId.value, workspaceUuid)
        assertEquals(grant.rootDisplayName, "Acme  Workspace")
        assertEquals(grant.workspaceLabel, Some("Acme  Workspace"))
        assertEquals(grant.accountLabel, Some("Alex"))
        assertEquals(grant.expiresAt, None)
        assertEquals(connector(fake).credentialType, "NOTION_OAUTH")
        assertNoSecret(grant.toString)
  }

  test("a null refresh token is kept as None; an absent name falls back and a 32-hex workspace is normalized") {
    val body = tokenBody(
      extra = Vector(
        "refresh_token" -> Json.Null,
        "workspace_id" -> Json.fromString(workspaceUuid.replace("-", "").toUpperCase)
      ),
      drop = Set("workspace_name", "owner")
    )
    withConnector(_ => ok(body)): (c, _) =>
      c.exchange(callback).map: result =>
        val grant = result.fold(error => fail(s"expected a grant, got $error"), identity)
        assertEquals(NotionTokenRecord.decode(grant.secret).toOption.flatMap(_.refreshToken), None)
        assertEquals(grant.rootExternalId.value, workspaceUuid)
        assertEquals(grant.rootDisplayName, "Notion workspace")
        assertEquals(grant.workspaceLabel, Some("Notion workspace"))
        assertEquals(grant.accountLabel, None)
  }

  test("a missing refresh_token field is accepted") {
    withConnector(_ => ok(tokenBody(drop = Set("refresh_token")))): (c, _) =>
      c.exchange(callback).map: result =>
        assert(result.isRight)
  }

  test("a missing access_token, bot_id, or workspace_id is an invalid response") {
    Vector("access_token", "bot_id", "workspace_id").foldLeft(IO.unit): (previous, field) =>
      previous *> exchangeFails(ok(tokenBody(drop = Set(field))), OAuthError.InvalidProviderResponse)
  }

  test("non-UUID bot and workspace IDs, a non-string access token, and a whitespace token are invalid") {
    val bodies = Vector(
      tokenBody(extra = Vector("workspace_id" -> Json.fromString("Acme"))),
      tokenBody(extra = Vector("bot_id" -> Json.fromString("not-a-uuid"))),
      tokenBody(extra = Vector("access_token" -> Json.fromInt(5))),
      tokenBody(extra = Vector("access_token" -> Json.fromString("has space"))),
      tokenBody(extra = Vector("refresh_token" -> Json.fromInt(5)))
    )
    bodies.foldLeft(IO.unit): (previous, body) =>
      previous *> exchangeFails(ok(body), OAuthError.InvalidProviderResponse)
  }

  test("malformed and non-object bodies are invalid responses") {
    Vector("not json", "[]", "\"x\"", "").foldLeft(IO.unit): (previous, body) =>
      previous *> exchangeFails(ok(body), OAuthError.InvalidProviderResponse)
  }

  test("an error field in a 200 response is a provider rejection") {
    exchangeFails(ok("""{"error":"invalid_grant","error_description":"the-code-value"}"""), OAuthError.ProviderRejected)
  }

  test("400, 401, 403, and 500 are provider rejections without secret text") {
    Vector(400, 401, 403, 500).foldLeft(IO.unit): (previous, status) =>
      previous *> exchangeFails(
        Reply(status, s"""{"error":"x","detail":"$accessValue $clientSecretValue"}"""),
        OAuthError.ProviderRejected
      )
  }

  test("a 302 is not followed and is a rejection") {
    withConnector(r => if r.uri == "/v1/oauth/token" then Reply(302, "", Map("Location" -> "/elsewhere")) else ok(tokenBody())): (c, fake) =>
      c.exchange(callback).map: result =>
        assertEquals(result.map(_ => ()), Left(OAuthError.ProviderRejected))
        assertEquals(fake.requests.get.map(_.uri), Vector("/v1/oauth/token"))
  }

  test("a 201 success status other than 200 is a rejection") {
    exchangeFails(Reply(201, tokenBody()), OAuthError.ProviderRejected)
  }

  test("a response larger than 1 MiB is an invalid response") {
    val oversized = tokenBody(extra = Vector("padding" -> Json.fromString("x" * (NotionConnector.MaximumResponseBytes + 10))))
    exchangeFails(ok(oversized), OAuthError.InvalidProviderResponse)
  }

  test("a stalled provider times out as a rejection without secret text") {
    withConnector(_ => Reply(200, tokenBody(), delayMillis = 11000)): (c, _) =>
      c.exchange(callback).map: result =>
        assertEquals(result.map(_ => ()), Left(OAuthError.ProviderRejected))
        assertNoSecret(result)
  }

  test("an unreachable provider is a rejection and is not retried") {
    val closed = server(_ => ok("{}")).use(fake => IO.pure(fake.endpoint))
    closed.flatMap: endpoint =>
      val http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()
      val c = NotionConnector(
        NotionOAuthClient(clientId, clientSecretValue),
        NotionEndpoints(endpoint.resolve("/v1/oauth/authorize"), endpoint),
        http,
        redirect
      )
      c.exchange(callback).map: result =>
        assertEquals(result.map(_ => ()), Left(OAuthError.ProviderRejected))
        assertNoSecret(result)
  }

  test("a failed exchange makes exactly one request") {
    withConnector(_ => Reply(500, "{}")): (c, fake) =>
      c.exchange(callback).map: _ =>
        assertEquals(fake.requests.get.size, 1)
  }

  // Selectable pages

  test("search sends the bearer token, version header, filter, and page size, and lists pages by title") {
    val pages = Vector(page(pid(2), Some("Beta")), page(pid(1), Some("Alpha")))
    withConnector(_ => searchReply(pages)): (c, fake) =>
      c.selectableResources(secret(), root()).map: result =>
        val found = result.fold(error => fail(s"expected pages, got $error"), identity)
        assertEquals(found.map(_.displayName), Vector("Alpha", "Beta"))
        assertEquals(found.map(_.externalId.value), Vector(pid(1), pid(2)))
        assert(found.forall(_.kind eq Notion.page))
        assert(found.forall(_.parentExternalId.value == workspaceUuid))
        val request = fake.requests.get.head
        assertEquals(request.method, "POST")
        assertEquals(request.uri, "/v1/search")
        assertEquals(request.headers("authorization"), "Bearer " + accessValue)
        assertEquals(request.headers("notion-version"), Notion.ApiVersion)
        assertEquals(request.headers("accept-encoding"), "identity")
        assertEquals(request.headers("user-agent"), "hallpass")
        assertEquals(
          parse(request.body),
          Right(Json.obj(
            "filter" -> Json.obj("property" -> Json.fromString("object"), "value" -> Json.fromString("page")),
            "page_size" -> Json.fromInt(100)
          ))
        )
  }

  test("search follows next_cursor, de-duplicates by ID, and sorts across pages") {
    val handler = (request: Recorded) =>
      if request.body.contains("start_cursor") then searchReply(Vector(page(pid(1), Some("Alpha")), page(pid(3), Some("Charlie"))))
      else searchReply(Vector(page(pid(2), Some("Beta")), page(pid(3), Some("Charlie"))), Some("cursor-1"))
    withConnector(handler): (c, fake) =>
      c.selectableResources(secret(), root()).map: result =>
        assertEquals(result.map(_.map(_.displayName)), Right(Vector("Alpha", "Beta", "Charlie")))
        val bodies = fake.requests.get.map(r => parse(r.body).toOption.get)
        assertEquals(bodies.size, 2)
        assertEquals(bodies(1).hcursor.get[String]("start_cursor"), Right("cursor-1"))
  }

  test("search stops at the page limit") {
    withConnector(
      request => searchReply(Vector(page(pid(request.body.length), Some("P"))), Some("more-" + request.body.length)),
      pageLimit = 3
    ): (c, fake) =>
      c.selectableResources(secret(), root()).map: result =>
        assert(result.isRight)
        assertEquals(fake.requests.get.size, 3)
  }

  test("a repeated cursor is an invalid response rather than a loop") {
    withConnector(_ => searchReply(Vector(page(pid(1), Some("A"))), Some("same"))): (c, fake) =>
      c.selectableResources(secret(), root()).map: result =>
        assertEquals(result.map(_ => ()), Left(OAuthError.InvalidProviderResponse))
        assertEquals(fake.requests.get.size, 2)
  }

  test("has_more without a cursor is an invalid response") {
    withConnector(_ => ok("""{"results":[],"next_cursor":null,"has_more":true}""")): (c, _) =>
      c.selectableResources(secret(), root()).map: result =>
        assertEquals(result.map(_ => ()), Left(OAuthError.InvalidProviderResponse))
  }

  test("archived and trashed pages are skipped") {
    val pages = Vector(
      page(pid(1), Some("Live")),
      page(pid(2), Some("Archived"), Vector("archived" -> Json.True)),
      page(pid(3), Some("Trashed"), Vector("in_trash" -> Json.True)),
      page(pid(4), Some("IsArchived"), Vector("is_archived" -> Json.True)),
      page(pid(5), Some("Restored"), Vector("archived" -> Json.False, "in_trash" -> Json.False))
    )
    withConnector(_ => searchReply(pages)): (c, _) =>
      c.selectableResources(secret(), root()).map: result =>
        assertEquals(result.map(_.map(_.displayName)), Right(Vector("Live", "Restored")))
  }

  test("titles are concatenated plain_text of the title-typed property, trimmed, collapsed, capped, and defaulted") {
    val multi = Json.obj(
      "object" -> Json.fromString("page"),
      "id" -> Json.fromString(pid(1)),
      "properties" -> Json.obj(
        "Other" -> Json.obj("type" -> Json.fromString("rich_text"), "rich_text" -> Json.arr(Json.obj("plain_text" -> Json.fromString("WRONG")))),
        "Name" -> Json.obj(
          "type" -> Json.fromString("title"),
          "title" -> Json.arr(
            Json.obj("plain_text" -> Json.fromString("  Hello ")),
            Json.obj("plain_text" -> Json.fromString("\n  big\tworld  "))
          )
        )
      )
    )
    val pages = Vector(
      multi,
      page(pid(2), Some("   ")),
      page(pid(3), None),
      page(pid(4), Some("x" * 500)),
      Json.obj("object" -> Json.fromString("page"), "id" -> Json.fromString(pid(5)))
    )
    withConnector(_ => searchReply(pages)): (c, _) =>
      c.selectableResources(secret(), root()).map: result =>
        val titles = result.fold(error => fail(s"expected pages, got $error"), _.map(r => r.externalId.value -> r.displayName).toMap)
        assertEquals(titles(pid(1)), "Hello big world")
        assertEquals(titles(pid(2)), "Untitled")
        assertEquals(titles(pid(3)), "Untitled")
        assertEquals(titles(pid(4)), "x" * 200)
        assertEquals(titles(pid(5)), "Untitled")
  }

  test("a result with a non-UUID ID is an invalid response") {
    withConnector(_ => searchReply(Vector(page("not-a-uuid", Some("A"))))): (c, _) =>
      c.selectableResources(secret(), root()).map: result =>
        assertEquals(result.map(_ => ()), Left(OAuthError.InvalidProviderResponse))
  }

  test("search 401, 500, a 302, and an oversize body are errors without secret text") {
    val replies = Vector(
      Reply(401, accessValue) -> OAuthError.ProviderRejected,
      Reply(500, "{}") -> OAuthError.ProviderRejected,
      Reply(302, "", Map("Location" -> "/x")) -> OAuthError.ProviderRejected,
      ok("x" * (NotionConnector.MaximumResponseBytes + 10)) -> OAuthError.InvalidProviderResponse,
      ok("not json") -> OAuthError.InvalidProviderResponse
    )
    replies.foldLeft(IO.unit): (previous, entry) =>
      previous *> withConnector(_ => entry._1): (c, fake) =>
        c.selectableResources(secret(), root()).map: result =>
          assertEquals(result.map(_ => ()), Left(entry._2))
          assertEquals(fake.requests.get.size, 1)
          assertNoSecret(result)
  }

  test("a record for another workspace is refused before any request") {
    withConnector(_ => searchReply(Vector.empty)): (c, fake) =>
      c.selectableResources(secret("11111111-2222-4333-8444-666666666666"), root()).map: result =>
        assertEquals(result.map(_ => ()), Left(OAuthError.InvalidState))
        assertEquals(fake.requests.get.size, 0)
  }

  test("a root of the wrong kind is refused before any request") {
    withConnector(_ => searchReply(Vector.empty)): (c, fake) =>
      c.selectableResources(secret(), root(kind = Notion.page.wire)).map: result =>
        assertEquals(result.map(_ => ()), Left(OAuthError.InvalidState))
        assertEquals(fake.requests.get.size, 0)
  }

  test("a malformed stored record is refused before any request") {
    withConnector(_ => searchReply(Vector.empty)): (c, fake) =>
      c.selectableResources(ProviderSecret.fromUtf8("""{"access_token":"x"}"""), root()).map: result =>
        assertEquals(result.map(_ => ()), Left(OAuthError.InvalidState))
        assertEquals(fake.requests.get.size, 0)
  }
