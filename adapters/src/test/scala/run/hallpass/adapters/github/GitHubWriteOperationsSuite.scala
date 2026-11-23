package run.hallpass.adapters.github

import java.net.{InetSocketAddress, URI}
import java.net.http.HttpClient
import java.nio.charset.StandardCharsets
import java.time.{Duration, Instant}
import java.util.concurrent.atomic.AtomicReference
import scala.jdk.CollectionConverters.*
import com.sun.net.httpserver.HttpServer
import cats.effect.{IO, Resource as CatsResource}
import cats.syntax.all.*
import io.circe.Json
import io.circe.parser.parse
import munit.CatsEffectSuite
import run.hallpass.application.*

final class GitHubWriteOperationsSuite extends CatsEffectSuite:
  private val tokenText = "ghs_supersecrettokenvalue"
  private val repoId = 424242L
  private val repoIdText = "424242"
  private val fullName = GitHubRepositoryName.parse("octo-org/hello.world").getOrElse(fail("name"))
  private val summary = GitHubRepositorySummary(GitHubRepositoryId.from(repoId).getOrElse(fail("id")), fullName)
  private val token = GitHubInstallationToken(tokenText, summary, Instant.parse("2026-09-01T13:00:00Z"))
  private val target = GitHubReadTestSupport.repositoryTarget(repoIdText)
  private val repository = GitHubRepositoryId.from(repoId).getOrElse(fail("id"))

  private val repoField = "repository_id" -> Json.fromString(repoIdText)
  private def args(fields: (String, Json)*): Json = Json.obj(fields*)
  private def str(value: String): Json = Json.fromString(value)
  private def decode(fields: (String, Json)*) = GitHubIssuesCreateOperation.decode(args(fields*))
  private def invalid(field: String) = Left(ArgumentError.InvalidField(field))

  private final case class Captured(method: String, path: String, headers: Map[String, String], body: String)
  private final class Fake(val captured: AtomicReference[Vector[Captured]], val uri: URI)

  private val createdJson = """{"number":12,"html_url":"https://github.com/octo-org/hello.world/issues/12","title":"x"}"""

  private def withServer(
      statusCode: Int = 201,
      response: String = createdJson,
      delayMillis: Long = 0,
      location: Option[String] = None,
      truncateResponse: Boolean = false
  ): CatsResource[IO, Fake] =
    CatsResource
      .make(IO.blocking:
        val captured = new AtomicReference(Vector.empty[Captured])
        val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext(
          "/",
          exchange =>
            val headers = exchange.getRequestHeaders.asScala.map((n, v) => n.toLowerCase -> v.asScala.mkString(",")).toMap
            val body = String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)
            captured.updateAndGet(_ :+ Captured(exchange.getRequestMethod, exchange.getRequestURI.toString, headers, body))
            if delayMillis > 0 then Thread.sleep(delayMillis)
            location.foreach(exchange.getResponseHeaders.add("Location", _))
            val bytes = response.getBytes(StandardCharsets.UTF_8)
            try
              exchange.sendResponseHeaders(statusCode, bytes.length + (if truncateResponse then 16 else 0))
              val output = exchange.getResponseBody
              try output.write(bytes)
              finally output.close()
            catch case _: java.io.IOException => ()
            finally exchange.close()
        )
        server.start()
        (captured, server))((_, server) => IO.blocking(server.stop(0)))
      .map((captured, server) => new Fake(captured, URI.create(s"http://127.0.0.1:${server.getAddress.getPort}")))

  private def client(uri: URI, timeout: Duration = Duration.ofSeconds(2)) =
    GitHubIssueCreateClient(GitHubRestClient(GitHubEndpoints(uri, uri), HttpClient.newHttpClient(), timeout))

  private val input = GitHubIssueCreateInput(repository, "A title", Some("A body"))

  private def providerError[A](io: IO[A]): IO[ProviderError] =
    io.attempt.map:
      case Left(error: ProviderExecutionException) =>
        assert(!String.valueOf(error.getMessage).contains(tokenText))
        error.error
      case other => fail(s"expected a provider error, received $other")

  private def statusError(status: Int, response: String = "{}", location: Option[String] = None) =
    withServer(status, response, location = location).use(server => providerError(client(server.uri).dispatch(target, input, token)))

  // ---- descriptor ------------------------------------------------------------------------------------------------
  test("the descriptor is the WRITE operation on GitHub.Issue.Create, distinct from the read capability") {
    val d = GitHubIssuesCreateOperation
    assertEquals(d.id.value, "github.issues.create@1")
    assertEquals(d.tool.value, "github_issues_create")
    assertEquals(d.capability.value, "GitHub.Issue.Create")
    assertNotEquals(d.capability, GitHubIssuesGetOperation.capability)
    assertNotEquals(d.capability, GitHubIssuesListOperation.capability)
    assertEquals(d.action, run.hallpass.kernel.Action.Write)
    assertEquals(d.target.wire, "github.repository")
    assertEquals(d.targetArgument, Some("repository_id"))
    assertEquals(d.audience, GitHubExecutorAudience.local)
  }

  // ---- decoding --------------------------------------------------------------------------------------------------
  test("decode accepts title with and without body, trimming the title") {
    assertEquals(decode(repoField, "title" -> str("Hello")), Right(GitHubIssueCreateInput(repository, "Hello", None)))
    assertEquals(decode(repoField, "title" -> str("  Hello  "), "body" -> str("b")), Right(GitHubIssueCreateInput(repository, "Hello", Some("b"))))
    assertEquals(decode(repoField, "title" -> str("t"), "body" -> Json.Null), Right(GitHubIssueCreateInput(repository, "t", None)))
  }

  test("title is required and bounded to 1 to 256 characters after trimming") {
    assertEquals(decode(repoField), Left(ArgumentError.MissingField("title")))
    assertEquals(decode(repoField, "title" -> str("")), invalid("title"))
    assertEquals(decode(repoField, "title" -> str("   \t ")), invalid("title"))
    assertEquals(decode(repoField, "title" -> Json.fromInt(1)), invalid("title"))
    assertEquals(decode(repoField, "title" -> Json.Null), invalid("title"))
    assert(decode(repoField, "title" -> str("a" * 256)).isRight)
    assert(decode(repoField, "title" -> str(" " + "a" * 256 + " ")).isRight)
    assertEquals(decode(repoField, "title" -> str("a" * 257)), invalid("title"))
  }

  test("title refuses ISO control characters") {
    assertEquals(decode(repoField, "title" -> str("a\nb")), invalid("title"))
    assertEquals(decode(repoField, "title" -> str("a\u0000b")), invalid("title"))
    assertEquals(decode(repoField, "title" -> str("a\tb")), invalid("title"))
    assertEquals(decode(repoField, "title" -> str("a\u009fb")), invalid("title"))
  }

  test("body is at most 65,536 characters; only newline, carriage return, and tab are allowed controls") {
    assert(decode(repoField, "title" -> str("t"), "body" -> str("x" * 65536)).isRight)
    assertEquals(decode(repoField, "title" -> str("t"), "body" -> str("x" * 65537)), invalid("body"))
    assert(decode(repoField, "title" -> str("t"), "body" -> str("a\nb\r\nc\td")).isRight)
    assertEquals(decode(repoField, "title" -> str("t"), "body" -> str("a\u0000b")), invalid("body"))
    assertEquals(decode(repoField, "title" -> str("t"), "body" -> str("a\u001bb")), invalid("body"))
    assertEquals(decode(repoField, "title" -> str("t"), "body" -> Json.fromInt(1)), invalid("body"))
    assertEquals(decode(repoField, "title" -> str("t"), "body" -> Json.True), invalid("body"))
  }

  test("decode rejects unknown fields and non-objects") {
    assertEquals(decode(repoField, "title" -> str("t"), "labels" -> Json.arr()), Left(ArgumentError.UnexpectedField))
    assertEquals(decode(repoField, "title" -> str("t"), "assignees" -> Json.arr()), Left(ArgumentError.UnexpectedField))
    assertEquals(GitHubIssuesCreateOperation.decode(Json.arr()), Left(ArgumentError.NotAnObject))
    assertEquals(GitHubIssuesCreateOperation.decode(Json.obj()), Left(ArgumentError.MissingField("repository_id")))
  }

  test("repository_id must be a decimal string without leading zeros") {
    def repo(value: Json) = decode("repository_id" -> value, "title" -> str("t"))
    assertEquals(repo(Json.fromLong(repoId)), invalid("repository_id"))
    assertEquals(repo(str("0123")), invalid("repository_id"))
    assertEquals(repo(str("")), invalid("repository_id"))
    assertEquals(repo(str("0")), invalid("repository_id"))
    assertEquals(repo(str("octo-org/hello")), invalid("repository_id"))
    assertEquals(repo(Json.Null), invalid("repository_id"))
  }

  test("locate selects the repository by its external ID and facts are empty") {
    GitHubIssuesCreateOperation.locate(input) match
      case ResourceLocator.Selected(ref) => assertEquals(ref.id.value, repoIdText)
      case other                         => fail(s"unexpected locator $other")
  }

  test("input schema is a closed object requiring repository_id and title") {
    val cursor = GitHubIssuesCreateOperation.inputSchema.hcursor
    assertEquals(cursor.get[Boolean]("additionalProperties"), Right(false))
    assertEquals(cursor.downField("required").as[List[String]], Right(List("repository_id", "title")))
    assertEquals(cursor.downField("properties").downField("repository_id").get[String]("pattern"), Right("^[1-9][0-9]{0,18}$"))
  }

  test("canonical form is the exact values sent, with a null body when absent") {
    val withBody = GitHubIssuesCreateOperation.decode(args(repoField, "title" -> str(" T "), "body" -> str("B"))).getOrElse(fail("decode"))
    val trimmed = GitHubIssuesCreateOperation.decode(args(repoField, "title" -> str("T"), "body" -> str("B"))).getOrElse(fail("decode"))
    val noBody = GitHubIssuesCreateOperation.decode(args(repoField, "title" -> str("T"))).getOrElse(fail("decode"))
    val explicitNull = GitHubIssuesCreateOperation.decode(args(repoField, "title" -> str("T"), "body" -> Json.Null)).getOrElse(fail("decode"))
    assertEquals(GitHubIssuesCreateOperation.canonical(withBody), GitHubIssuesCreateOperation.canonical(trimmed))
    assertEquals(
      GitHubIssuesCreateOperation.canonical(noBody),
      Json.obj("repository_id" -> str(repoIdText), "title" -> str("T"), "body" -> Json.Null)
    )
    assertEquals(GitHubIssuesCreateOperation.canonical(noBody), GitHubIssuesCreateOperation.canonical(explicitNull))
    assertNotEquals(GitHubIssuesCreateOperation.canonical(noBody), GitHubIssuesCreateOperation.canonical(trimmed))
    assertNotEquals(GitHubIssuesCreateOperation.canonical(trimmed), GitHubIssuesCreateOperation.canonical(trimmed.copy(title = "U")))
    assertNotEquals(
      GitHubIssuesCreateOperation.canonical(trimmed),
      GitHubIssuesCreateOperation.canonical(trimmed.copy(repository = GitHubRepositoryId.from(1).getOrElse(fail("id"))))
    )
  }

  // ---- registry --------------------------------------------------------------------------------------------------
  private object StubApp extends GitHubAppApi:
    def installationToken(i: GitHubInstallationId, r: Option[Vector[GitHubRepositoryId]], p: Set[GitHubPermission]) = IO.raiseError(IllegalStateException("unused"))
    def installation(id: GitHubInstallationId) = IO.raiseError(IllegalStateException("unused"))
    def installationRepositories(t: MintedInstallationToken, limit: Int) = IO.raiseError(IllegalStateException("unused"))
    def exchangeUserCode(code: String, redirectUri: URI) = IO.raiseError(IllegalStateException("unused"))
    def userCanAccessInstallation(user: GitHubUserToken, installation: GitHubInstallationId) = IO.raiseError(IllegalStateException("unused"))

  private object StubConnections extends ProviderConnectionResolver:
    def activeConnectionFor[K](lease: RedeemedExecutionLease, target: SelectedResource[K], provider: ProviderId, credentialType: String) =
      IO.pure(Left(ConnectionError.InvalidState))

  test("reads and writes register together with unique ids and tools") {
    val registration = GitHubAppRegistration(1L, "Iv1.abc", "hallpass")
    val http = HttpClient.newHttpClient()
    val reads = GitHubReadOperations.all(registration, StubConnections, StubApp, GitHubEndpoints.DotCom, http)
    val writes = GitHubWriteOperations.all(registration, StubConnections, StubApp, GitHubEndpoints.DotCom, http)
    assertEquals(writes.map(_.descriptor.id.value), Vector("github.issues.create@1"))
    val registry = OperationRegistry.from(reads ++ writes).getOrElse(fail("registry"))
    assertEquals(registry.all.size, 5)
    assertEquals((reads ++ writes).map(_.descriptor.tool.value).toSet.size, 5)
    assertEquals((reads ++ writes).map(_.descriptor.id.value).toSet.size, 5)
  }

  // ---- client ----------------------------------------------------------------------------------------------------
  test("the client posts to the path built from the token's repository name with the exact JSON body and headers") {
    withServer().use: server =>
      client(server.uri).dispatch(target, input, token).map: result =>
        assertEquals(server.captured.get.size, 1)
        val request = server.captured.get.head
        assertEquals(request.method, "POST")
        assertEquals(request.path, "/repos/octo-org/hello.world/issues")
        assertEquals(parse(request.body), Right(Json.obj("title" -> str("A title"), "body" -> str("A body"))))
        assertEquals(request.headers.get("authorization"), Some("Bearer " + tokenText))
        assertEquals(request.headers.get("content-type"), Some("application/json"))
        assertEquals(request.headers.get("accept"), Some("application/vnd.github+json"))
        assertEquals(request.headers.get("x-github-api-version"), Some("2022-11-28"))
        assertEquals(request.headers.get("user-agent"), Some("hallpass"))
        assertEquals(request.headers.get("accept-encoding"), Some("identity"))
        assertEquals(result.content, "Created issue #12: https://github.com/octo-org/hello.world/issues/12")
        assert(!result.content.contains(tokenText))
  }

  test("an absent body is omitted from the request") {
    withServer().use: server =>
      client(server.uri).dispatch(target, input.copy(body = None), token).map: _ =>
        assertEquals(parse(server.captured.get.head.body), Right(Json.obj("title" -> str("A title"))))
  }

  test("a token for a different repository ID is refused before any request") {
    val other = GitHubInstallationToken(tokenText, summary.copy(id = GitHubRepositoryId.from(999).getOrElse(fail("id"))), Instant.EPOCH)
    withServer().use: server =>
      providerError(client(server.uri).dispatch(target, input, other)).map: error =>
        assertEquals(error, ProviderError.Rejected)
        assert(server.captured.get.isEmpty, "no request may be sent")
  }

  test("a 200 is InvalidResponse, since only 201 means the issue was created") {
    statusError(200, createdJson).map(assertEquals(_, ProviderError.InvalidResponse))
  }

  test("a 201 without a number or URL is InvalidResponse") {
    for
      noNumber <- statusError(201, """{"html_url":"https://x"}""")
      noUrl <- statusError(201, """{"number":3}""")
      malformed <- statusError(201, "{not json")
    yield
      assertEquals(noNumber, ProviderError.InvalidResponse)
      assertEquals(noUrl, ProviderError.InvalidResponse)
      assertEquals(malformed, ProviderError.InvalidResponse)
  }

  test("definitive refusals stay rejected, but a server error after a write has an unknown outcome") {
    for
      unauthorized <- statusError(401)
      forbidden <- statusError(403)
      missing <- statusError(404)
      gone <- statusError(410)
      unprocessable <- statusError(422)
      broken <- statusError(500)
      moved <- statusError(302, location = Some("http://127.0.0.1:1/elsewhere"))
    yield
      assertEquals(unauthorized, ProviderError.AuthenticationFailed)
      assertEquals(forbidden, ProviderError.AuthenticationFailed)
      assertEquals(missing, ProviderError.Rejected)
      assertEquals(gone, ProviderError.Rejected)
      assertEquals(unprocessable, ProviderError.Rejected)
      assertEquals(broken, ProviderError.OutcomeUnknown)
      assertEquals(moved, ProviderError.Rejected)
  }

  test("a redirect is not followed and the write is sent once") {
    withServer(302, location = Some("http://127.0.0.1:1/elsewhere")).use: server =>
      providerError(client(server.uri).dispatch(target, input, token)).map: error =>
        assertEquals(error, ProviderError.Rejected)
        assertEquals(server.captured.get.size, 1)
  }

  test("an oversized write response has an unknown outcome") {
    withServer(response = "a" * (1024 * 1024 + 1)).use: server =>
      providerError(client(server.uri).dispatch(target, input, token)).map(assertEquals(_, ProviderError.OutcomeUnknown))
  }

  test("a timeout has an unknown outcome and the write was received exactly once, never retried") {
    withServer(delayMillis = 1500).use: server =>
      providerError(client(server.uri, Duration.ofMillis(200)).dispatch(target, input, token)).flatMap: error =>
        IO.sleep(scala.concurrent.duration.DurationInt(1800).millis).map: _ =>
          assertEquals(error, ProviderError.OutcomeUnknown)
          assertEquals(server.captured.get.size, 1)
  }

  test("a transport failure is conservatively an unknown write outcome") {
    providerError(client(URI.create("http://127.0.0.1:1")).dispatch(target, input, token)).map(assertEquals(_, ProviderError.OutcomeUnknown))
  }

  test("the token never appears in a result or in the token's text form") {
    withServer().use: server =>
      client(server.uri).dispatch(target, input, token).map: result =>
        assert(!result.content.contains(tokenText))
        assert(!token.toString.contains(tokenText))
  }

  test("a response truncated after the provider accepts the write is unknown and is never retried") {
    withServer(truncateResponse = true).use: server =>
      providerError(client(server.uri).dispatch(target, input, token)).map: error =>
        assertEquals(error, ProviderError.OutcomeUnknown)
        assertEquals(server.captured.get.size, 1)
  }

  test("gateway failures and request timeouts cannot prove that a submitted write was rejected") {
    List(408, 502, 503, 504).traverse_ : status =>
      withServer(status).use: server =>
        providerError(client(server.uri).dispatch(target, input, token)).map: error =>
          assertEquals(error, ProviderError.OutcomeUnknown)
          assertEquals(server.captured.get.size, 1)
  }
