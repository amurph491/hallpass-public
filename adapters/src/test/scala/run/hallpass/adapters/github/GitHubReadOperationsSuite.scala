package run.hallpass.application:
  import run.hallpass.adapters.github.GitHub
  import run.hallpass.kernel.*
  import run.hallpass.kernel.authorization.*

  /** Test-only access to `SelectedResource.trusted`, which is `private[application]`. */
  object GitHubReadTestSupport:
    private val tenant = TenantId.random()

    def repositoryTarget(externalId: String): SelectedResource[GitHub.Repository] =
      val repository = Resource(ResourceId.random(), tenant, ResourceType.Repository, None, externalId, None)
      SelectedResource.trusted(
        GitHub.repository,
        ExternalId.parse(externalId).getOrElse(throw IllegalStateException("external id")),
        ResourceScope.fromPath(Vector(repository)).getOrElse(throw IllegalStateException("scope"))
      )

package run.hallpass.adapters.github:
  import java.net.{InetSocketAddress, URI}
  import java.net.http.HttpClient
  import java.nio.charset.StandardCharsets
  import java.time.{Duration, Instant}
  import java.util.concurrent.atomic.AtomicReference
  import scala.jdk.CollectionConverters.*
  import com.sun.net.httpserver.HttpServer
  import cats.effect.{IO, Resource as CatsResource}
  import io.circe.Json
  import io.circe.parser.parse
  import munit.CatsEffectSuite
  import run.hallpass.application.*

  final class GitHubReadOperationsSuite extends CatsEffectSuite:
    private val tokenText = "ghs_supersecrettokenvalue"
    private val repoId = 424242L
    private val repoIdText = "424242"
    private val fullName = GitHubRepositoryName.parse("octo-org/hello.world").getOrElse(fail("name"))
    private val summary = GitHubRepositorySummary(GitHubRepositoryId.from(repoId).getOrElse(fail("id")), fullName)
    private val token = GitHubInstallationToken(tokenText, summary, Instant.parse("2026-09-01T13:00:00Z"))
    private val target = GitHubReadTestSupport.repositoryTarget(repoIdText)
    private val repository = GitHubRepositoryId.from(repoId).getOrElse(fail("id"))

    private def json(text: String): Json = parse(text).getOrElse(fail("json"))
    private val repoField = "repository_id" -> Json.fromString(repoIdText)
    private def args(fields: (String, Json)*): Json = Json.obj(fields*)

    private final case class Captured(method: String, path: String, headers: Map[String, String])
    private final class Fake(val captured: AtomicReference[Vector[Captured]], val uri: URI)

    private def withServer(
        statusCode: Int = 200,
        response: Array[Byte] = "[]".getBytes(StandardCharsets.UTF_8),
        delayMillis: Long = 0,
        location: Option[String] = None
    ): CatsResource[IO, Fake] =
      CatsResource
        .make(IO.blocking:
          val captured = new AtomicReference(Vector.empty[Captured])
          val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
          server.createContext(
            "/",
            exchange =>
              val headers = exchange.getRequestHeaders.asScala.map((n, v) => n.toLowerCase -> v.asScala.mkString(",")).toMap
              captured.updateAndGet(_ :+ Captured(exchange.getRequestMethod, exchange.getRequestURI.toString, headers))
              if delayMillis > 0 then Thread.sleep(delayMillis)
              location.foreach(exchange.getResponseHeaders.add("Location", _))
              try
                exchange.sendResponseHeaders(statusCode, response.length)
                val output = exchange.getResponseBody
                try output.write(response)
                finally output.close()
              catch case _: java.io.IOException => ()
          )
          server.start()
          (captured, server))((_, server) => IO.blocking(server.stop(0)))
        .map((captured, server) => new Fake(captured, URI.create(s"http://127.0.0.1:${server.getAddress.getPort}")))

    private def bytes(value: String): Array[Byte] = value.getBytes(StandardCharsets.UTF_8)

    private def rest(uri: URI, timeout: Duration = Duration.ofSeconds(2)) =
      GitHubRestClient(GitHubEndpoints(uri, uri), HttpClient.newHttpClient(), timeout)

    private def listClient(uri: URI, pulls: Boolean = false) =
      GitHubReadClient[GitHubListInput](
        rest(uri),
        in => (if pulls then "/pulls" else "/issues", Vector("state" -> in.state.wire, "per_page" -> in.limit.toString)),
        if pulls then GitHubRender.pullList else GitHubRender.issueList
      )
    private def getClient(uri: URI, pulls: Boolean = false, timeout: Duration = Duration.ofSeconds(2)) =
      GitHubReadClient[GitHubItemInput](
        rest(uri, timeout),
        in => ((if pulls then "/pulls/" else "/issues/") + in.number, Vector.empty),
        if pulls then GitHubRender.pull else GitHubRender.issue
      )
    private val listInput = GitHubListInput(repository, GitHubItemState.Open, 20)
    private val itemInput = GitHubItemInput(repository, 7)

    private def providerError[A](io: IO[A]): IO[ProviderError] =
      io.attempt.map:
        case Left(error: ProviderExecutionException) =>
          assert(!String.valueOf(error.getMessage).contains(tokenText))
          error.error
        case other => fail(s"expected a provider error, received $other")

    private val issueJson =
      """{"number":7,"title":"Broken\nthing","state":"open","user":{"login":"alex"},
        |"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-02T00:00:00Z",
        |"labels":[{"name":"bug"},{"name":"p1"}],"html_url":"https://github.com/octo-org/hello.world/issues/7","body":"BODY"}""".stripMargin

    // ---- decoding ------------------------------------------------------------------------------------------------
    test("list decode fills defaults and accepts explicit values") {
      assertEquals(GitHubIssuesListOperation.decode(args(repoField)), Right(GitHubListInput(repository, GitHubItemState.Open, 20)))
      assertEquals(
        GitHubPullsListOperation.decode(args(repoField, "state" -> Json.fromString("all"), "limit" -> Json.fromInt(50))),
        Right(GitHubListInput(repository, GitHubItemState.All, 50))
      )
    }

    test("get decode reads repository and number") {
      assertEquals(GitHubIssuesGetOperation.decode(args(repoField, "number" -> Json.fromInt(2147483647))), Right(GitHubItemInput(repository, Int.MaxValue)))
      assertEquals(GitHubPullsGetOperation.decode(args(repoField, "number" -> Json.fromInt(1))), Right(GitHubItemInput(repository, 1)))
    }

    test("canonical form is equal for defaulted and explicit defaults, and differs for different inputs") {
      val defaulted = GitHubIssuesListOperation.decode(args(repoField)).getOrElse(fail("decode"))
      val explicit =
        GitHubIssuesListOperation.decode(args(repoField, "state" -> Json.fromString("open"), "limit" -> Json.fromInt(20))).getOrElse(fail("decode"))
      val other = defaulted.copy(limit = 21)
      assertEquals(GitHubIssuesListOperation.canonical(defaulted), GitHubIssuesListOperation.canonical(explicit))
      assertNotEquals(GitHubIssuesListOperation.canonical(defaulted), GitHubIssuesListOperation.canonical(other))
      assertNotEquals(
        GitHubIssuesListOperation.canonical(defaulted),
        GitHubIssuesListOperation.canonical(defaulted.copy(repository = GitHubRepositoryId.from(1).getOrElse(fail("id"))))
      )
      assertNotEquals(
        GitHubIssuesGetOperation.canonical(itemInput),
        GitHubIssuesGetOperation.canonical(itemInput.copy(number = 8))
      )
    }

    test("locate selects the repository by its external ID, and facts are empty") {
      GitHubIssuesGetOperation.locate(itemInput) match
        case ResourceLocator.Selected(ref) => assertEquals(ref.id.value, repoIdText)
        case other                         => fail(s"unexpected locator $other")
      assertEquals(GitHubIssuesGetOperation.targetArgument, Some("repository_id"))
    }

    test("decode rejects unknown fields, non-objects, and missing fields") {
      assertEquals(GitHubIssuesListOperation.decode(args(repoField, "extra" -> Json.True)), Left(ArgumentError.UnexpectedField))
      assertEquals(GitHubIssuesGetOperation.decode(args(repoField, "number" -> Json.fromInt(1), "state" -> Json.fromString("open"))), Left(ArgumentError.UnexpectedField))
      assertEquals(GitHubIssuesListOperation.decode(Json.arr()), Left(ArgumentError.NotAnObject))
      assertEquals(GitHubIssuesListOperation.decode(Json.obj()), Left(ArgumentError.MissingField("repository_id")))
      assertEquals(GitHubPullsGetOperation.decode(args(repoField)), Left(ArgumentError.MissingField("number")))
    }

    test("repository_id must be a decimal string without leading zeros") {
      def repo(value: Json) = GitHubIssuesListOperation.decode(args("repository_id" -> value))
      val invalid = Left(ArgumentError.InvalidField("repository_id"))
      assertEquals(repo(Json.fromLong(repoId)), invalid)
      assertEquals(repo(Json.fromString("0123")), invalid)
      assertEquals(repo(Json.fromString("")), invalid)
      assertEquals(repo(Json.fromString("0")), invalid)
      assertEquals(repo(Json.fromString("-5")), invalid)
      assertEquals(repo(Json.fromString("octo-org/hello")), invalid)
      assertEquals(repo(Json.Null), invalid)
    }

    test("number must be an integer from 1 to 2147483647") {
      def number(value: Json) = GitHubIssuesGetOperation.decode(args(repoField, "number" -> value))
      val invalid = Left(ArgumentError.InvalidField("number"))
      assertEquals(number(Json.fromInt(0)), invalid)
      assertEquals(number(Json.fromInt(-1)), invalid)
      assertEquals(number(Json.fromLong(2147483648L)), invalid)
      assertEquals(number(Json.fromString("7")), invalid)
      assertEquals(number(json("1.5")), invalid)
      assertEquals(number(json("7.0")), invalid)
    }

    test("limit must be 1 to 50 and state one of open, closed, all") {
      def decode(field: (String, Json)) = GitHubPullsListOperation.decode(args(repoField, field))
      assertEquals(decode("limit" -> Json.fromInt(0)), Left(ArgumentError.InvalidField("limit")))
      assertEquals(decode("limit" -> Json.fromInt(51)), Left(ArgumentError.InvalidField("limit")))
      assertEquals(decode("limit" -> Json.fromString("5")), Left(ArgumentError.InvalidField("limit")))
      assertEquals(decode("state" -> Json.fromString("merged")), Left(ArgumentError.InvalidField("state")))
      assertEquals(decode("state" -> Json.fromString("OPEN")), Left(ArgumentError.InvalidField("state")))
      assertEquals(decode("state" -> Json.fromInt(1)), Left(ArgumentError.InvalidField("state")))
    }

    test("input schemas are closed objects with a string repository_id") {
      List(GitHubIssuesListOperation.inputSchema, GitHubIssuesGetOperation.inputSchema, GitHubPullsListOperation.inputSchema, GitHubPullsGetOperation.inputSchema)
        .foreach: schema =>
          val cursor = schema.hcursor
          assertEquals(cursor.get[Boolean]("additionalProperties"), Right(false))
          assert(cursor.downField("required").as[List[String]].exists(_.contains("repository_id")))
          val repo = cursor.downField("properties").downField("repository_id")
          assertEquals(repo.get[String]("type"), Right("string"))
          assertEquals(repo.get[String]("pattern"), Right("^[1-9][0-9]{0,18}$"))
          assert(repo.focus.exists(_.isObject))
    }

    // ---- registry ------------------------------------------------------------------------------------------------
    private object StubApp extends GitHubAppApi:
      def installationToken(i: GitHubInstallationId, r: Option[Vector[GitHubRepositoryId]], p: Set[GitHubPermission]) = IO.raiseError(IllegalStateException("unused"))
      def installation(id: GitHubInstallationId) = IO.raiseError(IllegalStateException("unused"))
      def installationRepositories(t: MintedInstallationToken, limit: Int) = IO.raiseError(IllegalStateException("unused"))
      def exchangeUserCode(code: String, redirectUri: URI) = IO.raiseError(IllegalStateException("unused"))
      def userCanAccessInstallation(user: GitHubUserToken, installation: GitHubInstallationId) = IO.raiseError(IllegalStateException("unused"))

    private object StubConnections extends ProviderConnectionResolver:
      def activeConnectionFor[K](lease: RedeemedExecutionLease, target: SelectedResource[K], provider: ProviderId, credentialType: String) =
        IO.pure(Left(ConnectionError.InvalidState))

    test("all builds four operations that register with unique ids and tools on the GitHub repository kind") {
      val operations = GitHubReadOperations.all(
        GitHubAppRegistration(1L, "Iv1.abc", "hallpass"),
        StubConnections,
        StubApp,
        GitHubEndpoints.DotCom,
        HttpClient.newHttpClient()
      )
      assertEquals(operations.size, 4)
      val registry = OperationRegistry.from(operations).getOrElse(fail("registry"))
      assertEquals(
        operations.map(_.descriptor.id.value).toSet,
        Set("github.issues.list@1", "github.issues.get@1", "github.pulls.list@1", "github.pulls.get@1")
      )
      assertEquals(
        operations.map(_.descriptor.tool.value).toSet,
        Set("github_issues_list", "github_issues_get", "github_pulls_list", "github_pulls_get")
      )
      assert(operations.forall(_.descriptor.target.wire == "github.repository"))
      assertEquals(registry.all.size, 4)
    }

    // ---- clients -------------------------------------------------------------------------------------------------
    test("each client requests the exact path built from the token's repository name, with the required headers") {
      val cases = List(
        ("/repos/octo-org/hello.world/issues?state=open&per_page=20", (uri: URI) => listClient(uri).dispatch(target, listInput, token)),
        ("/repos/octo-org/hello.world/issues/7", (uri: URI) => getClient(uri).dispatch(target, itemInput, token)),
        ("/repos/octo-org/hello.world/pulls?state=open&per_page=20", (uri: URI) => listClient(uri, pulls = true).dispatch(target, listInput, token)),
        ("/repos/octo-org/hello.world/pulls/7", (uri: URI) => getClient(uri, pulls = true).dispatch(target, itemInput, token))
      )
      cases.foldLeft(IO.unit): (previous, expected) =>
        previous *> withServer(response = bytes(if expected._1.contains("?") then "[]" else issueJson)).use: server =>
          expected._2(server.uri).map: _ =>
            val request = server.captured.get.head
            assertEquals(request.method, "GET")
            assertEquals(request.path, expected._1)
            assertEquals(request.headers.get("authorization"), Some("Bearer " + tokenText))
            assertEquals(request.headers.get("accept"), Some("application/vnd.github+json"))
            assertEquals(request.headers.get("x-github-api-version"), Some("2022-11-28"))
            assertEquals(request.headers.get("user-agent"), Some("hallpass"))
            assertEquals(request.headers.get("accept-encoding"), Some("identity"))
            assert(!request.path.contains(tokenText))
    }

    test("the query reflects the decoded state and limit") {
      withServer().use: server =>
        listClient(server.uri).dispatch(target, GitHubListInput(repository, GitHubItemState.All, 5), token).map: _ =>
          assertEquals(server.captured.get.head.path, "/repos/octo-org/hello.world/issues?state=all&per_page=5")
    }

    test("a token for a different repository ID is refused before any request") {
      val other = GitHubInstallationToken(tokenText, summary.copy(id = GitHubRepositoryId.from(999).getOrElse(fail("id"))), Instant.EPOCH)
      withServer().use: server =>
        providerError(listClient(server.uri).dispatch(target, listInput, other)).map: error =>
          assertEquals(error, ProviderError.Rejected)
          assert(server.captured.get.isEmpty, "no request may be sent")
    }

    test("the issue list drops pull requests and renders the expected fields") {
      val body =
        s"""[$issueJson,
           |{"number":8,"title":"A PR","state":"open","pull_request":{"url":"x"},"user":{"login":"bob"}}]""".stripMargin
      withServer(response = bytes(body)).use: server =>
        listClient(server.uri).dispatch(target, listInput, token).map: result =>
          val lines = result.content.split("\n").toList
          assertEquals(lines.size, 1)
          assertEquals(
            lines.head,
            "#7 [open] Broken thing | by alex | created 2026-01-01T00:00:00Z | updated 2026-01-02T00:00:00Z | labels bug,p1 | https://github.com/octo-org/hello.world/issues/7"
          )
          assert(!result.content.contains(tokenText))
    }

    test("the pull list keeps every item") {
      val body = """[{"number":8,"title":"A PR","state":"closed","user":{"login":"bob"}}]"""
      withServer(response = bytes(body)).use: server =>
        listClient(server.uri, pulls = true).dispatch(target, listInput, token).map: result =>
          assert(result.content.startsWith("#8 [closed] A PR | by bob"))
    }

    test("get renders the body and truncates it to 8,000 characters") {
      val long = "x" * 20000
      val body = issueJson.replace("\"BODY\"", "\"" + long + "\"")
      withServer(response = bytes(body)).use: server =>
        getClient(server.uri).dispatch(target, itemInput, token).map: result =>
          assert(result.content.contains("number: 7"))
          assert(result.content.contains("author: alex"))
          assert(result.content.contains("labels: bug,p1"))
          assert(result.content.contains("x" * 8000 + "...[truncated]"))
          assert(!result.content.contains("x" * 8001))
    }

    test("pull get renders head, base, draft, and merged") {
      val body = """{"number":7,"title":"T","state":"closed","user":{"login":"a"},"head":{"ref":"feature"},"base":{"ref":"main"},"draft":false,"merged":true,"body":null}"""
      withServer(response = bytes(body)).use: server =>
        getClient(server.uri, pulls = true).dispatch(target, itemInput, token).map: result =>
          List("head: feature", "base: main", "draft: false", "merged: true").foreach(l => assert(result.content.contains(l), l))
    }

    test("a pull request answered by the issue endpoint is Rejected") {
      withServer(response = bytes(issueJson.replace("\"body\"", "\"pull_request\":{},\"body\""))).use: server =>
        providerError(getClient(server.uri).dispatch(target, itemInput, token)).map(assertEquals(_, ProviderError.Rejected))
    }

    test("a long list is capped at 60,000 characters") {
      val item = (n: Int) => s"""{"number":$n,"title":"${"t" * 500}","state":"open","user":{"login":"a"},"labels":[${(1 to 20).map(i => "{\"name\":\"" + "l" * 900 + "\"}").mkString(",")}]}"""
      val body = (1 to 50).map(item).mkString("[", ",", "]")
      withServer(response = bytes(body)).use: server =>
        listClient(server.uri).dispatch(target, listInput, token).map: result =>
          assert(result.content.length <= GitHubRender.ContentLimit + 20, result.content.length.toString)
    }

    // ---- error mapping -------------------------------------------------------------------------------------------
    private def statusError(status: Int, body: String = "{}", location: Option[String] = None) =
      withServer(status, bytes(body), location = location).use(server => providerError(getClient(server.uri).dispatch(target, itemInput, token)))

    test("401 and 403 are AuthenticationFailed; 404, 500, and 3xx are Rejected") {
      for
        unauthorized <- statusError(401)
        forbidden <- statusError(403)
        missing <- statusError(404)
        broken <- statusError(500)
        moved <- statusError(302, location = Some("http://127.0.0.1:1/elsewhere"))
      yield
        assertEquals(unauthorized, ProviderError.AuthenticationFailed)
        assertEquals(forbidden, ProviderError.AuthenticationFailed)
        assertEquals(missing, ProviderError.Rejected)
        assertEquals(broken, ProviderError.Rejected)
        assertEquals(moved, ProviderError.Rejected)
    }

    test("a redirect is not followed") {
      withServer(302, location = Some("http://127.0.0.1:1/elsewhere")).use: server =>
        providerError(getClient(server.uri).dispatch(target, itemInput, token)).map: error =>
          assertEquals(error, ProviderError.Rejected)
          assertEquals(server.captured.get.size, 1)
    }

    test("malformed JSON and unexpected shapes are InvalidResponse") {
      for
        malformed <- statusError(200, "{not json")
        wrongShape <- withServer(response = bytes("{}")).use(s => providerError(listClient(s.uri).dispatch(target, listInput, token)))
        noNumber <- statusError(200, """{"title":"x"}""")
      yield
        assertEquals(malformed, ProviderError.InvalidResponse)
        assertEquals(wrongShape, ProviderError.InvalidResponse)
        assertEquals(noNumber, ProviderError.InvalidResponse)
    }

    test("a response over 1 MiB is InvalidResponse") {
      withServer(response = Array.fill(1024 * 1024 + 1)('a'.toByte)).use: server =>
        providerError(getClient(server.uri).dispatch(target, itemInput, token)).map(assertEquals(_, ProviderError.InvalidResponse))
    }

    test("a slow response is Timeout") {
      withServer(delayMillis = 1500).use: server =>
        providerError(getClient(server.uri, timeout = Duration.ofMillis(200)).dispatch(target, itemInput, token))
          .map(assertEquals(_, ProviderError.Timeout))
    }

    test("an unreachable endpoint is Timeout") {
      providerError(getClient(URI.create("http://127.0.0.1:1")).dispatch(target, itemInput, token))
        .map(assertEquals(_, ProviderError.Timeout))
    }

    test("a token never appears in a result or an exception message") {
      withServer(response = bytes(issueJson)).use: server =>
        getClient(server.uri).dispatch(target, itemInput, token).map: result =>
          assert(!result.content.contains(tokenText))
          assert(!token.toString.contains(tokenText))
    }
