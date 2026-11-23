package run.hallpass.application:
  import run.hallpass.adapters.linear.Linear
  import run.hallpass.kernel.*
  import run.hallpass.kernel.authorization.*
  import run.hallpass.kernel.authorization.*

  /** Test-only access to `SelectedResource.trusted`, which is `private[application]`. */
  object LinearOperationsTestSupport:
    private val tenant = TenantId.random()

    def teamTarget(externalId: String): SelectedResource[Linear.Team] =
      val team = Resource(ResourceId.random(), tenant, ResourceType.Team, None, externalId, None)
      SelectedResource.trusted(
        Linear.team,
        ExternalId.parse(externalId).getOrElse(throw IllegalStateException("external id")),
        ResourceScope.fromPath(Vector(team)).getOrElse(throw IllegalStateException("scope"))
      )

package run.hallpass.adapters.linear:
  import java.net.URI
  import java.net.http.HttpClient
  import java.util.UUID
  import java.util.concurrent.atomic.AtomicReference
  import cats.effect.IO
  import cats.syntax.all.*
  import io.circe.Json
  import io.circe.parser.parse
  import munit.CatsEffectSuite
  import run.hallpass.application.*
  import run.hallpass.kernel.*
  import run.hallpass.kernel.authorization.*

  final class LinearOperationsSuite extends CatsEffectSuite:
    private val tokenText = "lin_oauth_supersecrettokenvalue"
    private val teamText = "11111111-1111-4111-8111-111111111111"
    private val otherTeamText = "22222222-2222-4222-8222-222222222222"
    private val issueUuid = "33333333-3333-4333-8333-333333333333"
    private val key = UUID.fromString("44444444-4444-4444-8444-444444444444")
    private val team = LinearId.parse(teamText).getOrElse(fail("team"))
    private val target = LinearOperationsTestSupport.teamTarget(teamText)
    private val access = LinearAccess(tokenText, key)

    private def json(text: String): Json = parse(text).getOrElse(fail("json"))
    private val teamField = "team_id" -> Json.fromString(teamText)
    private def args(fields: (String, Json)*): Json = Json.obj(fields*)

    private final case class Call(bearer: String, document: LinearDocument, variables: Json)

    private final class Stub(response: IO[Either[LinearApiError, Json]]):
      val calls = new AtomicReference(Vector.empty[Call])
      val execute: LinearExecute = (bearer, document, variables) =>
        IO.delay(calls.updateAndGet(_ :+ Call(bearer, document, variables))) *> response

    private def stub(data: String) = Stub(IO.pure(Right(json(data))))
    private def failing(error: LinearApiError) = Stub(IO.pure(Left(error)))

    private def providerError(io: IO[ToolResult]): IO[ProviderError] =
      io.attempt.map:
        case Left(ProviderExecutionException(error)) => error
        case other                                   => fail(s"expected a provider failure, got $other")

    // ---- decode -------------------------------------------------------------------------------------------------
    test("list decodes team_id and limit with a default, and refuses invalid values") {
      val op = LinearIssuesListOperation
      assertEquals(op.decode(args(teamField)), Right(LinearListInput(team, 20)))
      assertEquals(op.decode(args(teamField, "limit" -> Json.fromInt(1))), Right(LinearListInput(team, 1)))
      assertEquals(op.decode(args(teamField, "limit" -> Json.fromInt(50))), Right(LinearListInput(team, 50)))
      assertEquals(op.decode(args(teamField, "limit" -> Json.fromInt(0))), Left(ArgumentError.InvalidField("limit")))
      assertEquals(op.decode(args(teamField, "limit" -> Json.fromInt(51))), Left(ArgumentError.InvalidField("limit")))
      assertEquals(op.decode(args(teamField, "limit" -> Json.fromString("5"))), Left(ArgumentError.InvalidField("limit")))
      assertEquals(op.decode(args(teamField, "limit" -> Json.fromDoubleOrNull(5.5))), Left(ArgumentError.InvalidField("limit")))
      assertEquals(op.decode(args()), Left(ArgumentError.MissingField("team_id")))
      assertEquals(op.decode(args("team_id" -> Json.fromString("ENG"))), Left(ArgumentError.InvalidField("team_id")))
      assertEquals(op.decode(args("team_id" -> Json.fromString("AAAAAAAA-1111-4111-8111-111111111111"))), Left(ArgumentError.InvalidField("team_id")))
      assertEquals(op.decode(args("team_id" -> Json.fromInt(1))), Left(ArgumentError.InvalidField("team_id")))
      assertEquals(op.decode(Json.fromString("x")), Left(ArgumentError.NotAnObject))
      assertEquals(op.decode(args(teamField, "extra" -> Json.True)), Left(ArgumentError.UnexpectedField))
    }

    test("get accepts an issue UUID or an identifier and refuses anything else") {
      val op = LinearIssuesGetOperation
      def issue(value: String) = op.decode(args(teamField, "issue_id" -> Json.fromString(value)))
      assertEquals(issue(issueUuid), Right(LinearGetInput(team, LinearIssueRef.Id(LinearId.parse(issueUuid).get))))
      assertEquals(issue("ENG-123"), Right(LinearGetInput(team, LinearIssueRef.Identifier("ENG-123"))))
      assertEquals(issue("A1B2C3D4E5-999999999"), Right(LinearGetInput(team, LinearIssueRef.Identifier("A1B2C3D4E5-999999999"))))
      List("eng-123", "ENG-0", "ENG-01", "ENG123", "-1", "1ENG-1", "ABCDEFGHIJK-1", "ENG-1234567890", "ENG-1 ", "", "ENG-1\n")
        .foreach(bad => assertEquals(issue(bad), Left(ArgumentError.InvalidField("issue_id")), bad))
      assertEquals(op.decode(args(teamField)), Left(ArgumentError.MissingField("issue_id")))
      assertEquals(op.decode(args("issue_id" -> Json.fromString("ENG-1"))), Left(ArgumentError.MissingField("team_id")))
      assertEquals(
        op.decode(args(teamField, "issue_id" -> Json.fromString("ENG-1"), "limit" -> Json.fromInt(1))),
        Left(ArgumentError.UnexpectedField)
      )
    }

    test("create trims the title, bounds it, and refuses control characters; description is optional and bounded") {
      val op = LinearIssuesCreateOperation
      def create(fields: (String, Json)*) = op.decode(args(teamField +: fields*))
      def title(value: String) = create("title" -> Json.fromString(value))
      assertEquals(title("  Fix it  "), Right(LinearCreateInput(team, "Fix it", None)))
      assertEquals(title("a" * 256).map(_.title.length), Right(256))
      assertEquals(title("a" * 257), Left(ArgumentError.InvalidField("title")))
      assertEquals(title("   "), Left(ArgumentError.InvalidField("title")))
      assertEquals(title(""), Left(ArgumentError.InvalidField("title")))
      assertEquals(title("a\nb"), Left(ArgumentError.InvalidField("title")))
      assertEquals(title("a\u0000b"), Left(ArgumentError.InvalidField("title")))
      assertEquals(title("a\tb"), Left(ArgumentError.InvalidField("title")))
      assertEquals(create(), Left(ArgumentError.MissingField("title")))
      assertEquals(create("title" -> Json.fromInt(1)), Left(ArgumentError.InvalidField("title")))
      def description(value: String) = create("title" -> Json.fromString("t"), "description" -> Json.fromString(value))
      assertEquals(description("line1\r\nline2\tend"), Right(LinearCreateInput(team, "t", Some("line1\r\nline2\tend"))))
      assertEquals(description("a" * 65536).map(_.description.map(_.length)), Right(Some(65536)))
      assertEquals(description("a" * 65537), Left(ArgumentError.InvalidField("description")))
      assertEquals(description("a\u0007b"), Left(ArgumentError.InvalidField("description")))
      assertEquals(description("a\u001bb"), Left(ArgumentError.InvalidField("description")))
      assertEquals(
        create("title" -> Json.fromString("t"), "description" -> Json.fromInt(1)),
        Left(ArgumentError.InvalidField("description"))
      )
      assertEquals(
        create("title" -> Json.fromString("t"), "labels" -> Json.True),
        Left(ArgumentError.UnexpectedField)
      )
    }

    // ---- descriptors ---------------------------------------------------------------------------------------------
    test("descriptors carry the contract table and locate the decoded team") {
      val table = List(
        (LinearIssuesListOperation.id.value, LinearIssuesListOperation.tool.value, LinearIssuesListOperation.capability.value, LinearIssuesListOperation.action),
        (LinearIssuesGetOperation.id.value, LinearIssuesGetOperation.tool.value, LinearIssuesGetOperation.capability.value, LinearIssuesGetOperation.action),
        (LinearIssuesCreateOperation.id.value, LinearIssuesCreateOperation.tool.value, LinearIssuesCreateOperation.capability.value, LinearIssuesCreateOperation.action)
      )
      assertEquals(table.map(_._1), List("linear.issues.list@1", "linear.issues.get@1", "linear.issues.create@1"))
      assertEquals(table.map(_._2), List("linear_issues_list", "linear_issues_get", "linear_issues_create"))
      assertEquals(table.map(_._3), List("Linear.Issue.Read", "Linear.Issue.Read", "Linear.Issue.Create"))
      assertEquals(table.map(_._4), List(Action.Read, Action.Read, Action.Write))
      assert(LinearIssuesListOperation.target eq Linear.team)
      assertEquals(LinearIssuesListOperation.audience, LinearExecutorAudience.local)
      assertEquals(LinearIssuesGetOperation.targetArgument, Some("team_id"))
      assertEquals(LinearIssuesCreateOperation.targetArgument, Some("team_id"))
      assertEquals(LinearIssuesListOperation.facts(LinearListInput(team, 1)), AuthorizationContext.empty)
      LinearIssuesListOperation.locate(LinearListInput(team, 1)) match
        case ResourceLocator.Selected(ref) => assertEquals(ref.id.value, teamText)
        case _                             => fail("expected Selected")
    }

    test("canonical forms fill defaults, and differ when dispatch would differ") {
      val list = LinearIssuesListOperation
      assertEquals(
        list.decode(args(teamField)).map(list.canonical),
        list.decode(args(teamField, "limit" -> Json.fromInt(20))).map(list.canonical)
      )
      assertNotEquals(
        list.decode(args(teamField)).map(list.canonical),
        list.decode(args(teamField, "limit" -> Json.fromInt(21))).map(list.canonical)
      )
      assertNotEquals(
        list.decode(args(teamField)).map(list.canonical),
        list.decode(args("team_id" -> Json.fromString(otherTeamText))).map(list.canonical)
      )
      val get = LinearIssuesGetOperation
      def getCanon(issue: String) = get.decode(args(teamField, "issue_id" -> Json.fromString(issue))).map(get.canonical)
      assertEquals(getCanon("ENG-1"), getCanon("ENG-1"))
      assertNotEquals(getCanon("ENG-1"), getCanon("ENG-2"))
      val create = LinearIssuesCreateOperation
      def createCanon(fields: (String, Json)*) = create.decode(args(teamField +: fields*)).map(create.canonical)
      assertEquals(createCanon("title" -> Json.fromString(" t ")), createCanon("title" -> Json.fromString("t")))
      assertNotEquals(createCanon("title" -> Json.fromString("t")), createCanon("title" -> Json.fromString("u")))
      assertNotEquals(
        createCanon("title" -> Json.fromString("t")),
        createCanon("title" -> Json.fromString("t"), "description" -> Json.fromString("d"))
      )
      assertNotEquals(
        createCanon("title" -> Json.fromString("t"), "description" -> Json.fromString("")),
        createCanon("title" -> Json.fromString("t"))
      )
    }

    // ---- clients -------------------------------------------------------------------------------------------------
    private val listData =
      s"""{"team":{"id":"$teamText","issues":{"nodes":[
         |{"id":"i1","identifier":"ENG-1","title":"First\\nissue","url":"https://linear.app/x/issue/ENG-1","updatedAt":"2026-09-01T00:00:00.000Z","priority":2,"state":{"name":"Todo"},"assignee":{"name":"Alex"}},
         |{"id":"i2","identifier":"ENG-2","title":"Second","url":"https://linear.app/x/issue/ENG-2","updatedAt":"2026-09-02T00:00:00.000Z","priority":0,"state":{"name":"Done"},"assignee":null}
         |]}}}""".stripMargin

    private def getData(teamId: String, description: String = "Body text") =
      s"""{"issue":{"id":"$issueUuid","identifier":"ENG-7","title":"Bug","description":${Json.fromString(description)},"url":"https://linear.app/x/issue/ENG-7","createdAt":"2026-08-01T00:00:00.000Z","updatedAt":"2026-09-01T00:00:00.000Z","priority":1,"state":{"name":"In Progress"},"assignee":{"name":"Alex"},"team":{"id":"$teamId"}}}"""

    private def createData(issueId: String, success: Boolean = true) =
      s"""{"issueCreate":{"success":$success,"issue":{"id":"$issueId","identifier":"ENG-9","url":"https://linear.app/x/issue/ENG-9"}}}"""

    test("list sends the fixed document, the target's team ID and limit, and the bearer token") {
      val s = stub(listData)
      LinearIssuesListClient(s.execute).dispatch(target, LinearListInput(team, 7), access).map: result =>
        val call = s.calls.get.head
        assertEquals(s.calls.get.size, 1)
        assertEquals(call.bearer, tokenText)
        assertEquals(call.document, LinearDocuments.list)
        assertEquals(
          call.document.text,
          "query($team: String!, $first: Int!) { team(id: $team) { id issues(first: $first, orderBy: updatedAt) { nodes { id identifier title url updatedAt priority state { name } assignee { name } } } } }"
        )
        assertEquals(call.variables, Json.obj("team" -> Json.fromString(teamText), "first" -> Json.fromInt(7)))
        assertEquals(
          result.content,
          "ENG-1 [Todo] First issue | Alex | 2026-09-01T00:00:00.000Z | https://linear.app/x/issue/ENG-1\n" +
            "ENG-2 [Done] Second | unassigned | 2026-09-02T00:00:00.000Z | https://linear.app/x/issue/ENG-2"
        )
        assert(!result.content.contains(tokenText))
    }

    test("the provider request is built from the authorized target, not from the argument") {
      val s = stub(s"""{"team":{"id":"$otherTeamText","issues":{"nodes":[]}}}""")
      val otherTarget = LinearOperationsTestSupport.teamTarget(otherTeamText)
      LinearIssuesListClient(s.execute).dispatch(otherTarget, LinearListInput(team, 5), access).map: _ =>
        assertEquals(s.calls.get.head.variables.hcursor.get[String]("team"), Right(otherTeamText))
    }

    test("list refuses a team whose ID is not the authorized team, with no content") {
      val s = stub(s"""{"team":{"id":"$otherTeamText","issues":{"nodes":[{"identifier":"X-1"}]}}}""")
      providerError(LinearIssuesListClient(s.execute).dispatch(target, LinearListInput(team, 5), access))
        .assertEquals(ProviderError.Rejected)
    }

    test("list refuses a missing team and malformed nodes") {
      for
        a <- providerError(LinearIssuesListClient(stub("""{"team":null}""").execute).dispatch(target, LinearListInput(team, 5), access))
        b <- providerError(LinearIssuesListClient(stub(s"""{"team":{"id":"$teamText","issues":{"nodes":[{"title":"no identifier"}]}}}""").execute).dispatch(target, LinearListInput(team, 5), access))
        c <- providerError(LinearIssuesListClient(stub(s"""{"team":{"id":"$teamText"}}""").execute).dispatch(target, LinearListInput(team, 5), access))
      yield
        assertEquals(a, ProviderError.Rejected)
        assertEquals(b, ProviderError.InvalidResponse)
        assertEquals(c, ProviderError.InvalidResponse)
    }

    test("list output is capped at 60,000 characters") {
      val nodes = (1 to 50).map(i => s"""{"identifier":"ENG-$i","title":"${"t" * 400}","url":"${"u" * 1500}","updatedAt":"x","state":{"name":"s"}}""")
      val s = stub(s"""{"team":{"id":"$teamText","issues":{"nodes":[${nodes.mkString(",")}]}}}""")
      LinearIssuesListClient(s.execute).dispatch(target, LinearListInput(team, 50), access).map: result =>
        assert(result.content.length <= 60000 + 20, result.content.length)
        assert(result.content.endsWith("...[truncated]"))
    }

    test("get sends the fixed document with the issue reference and renders the issue") {
      val ids = List(LinearIssueRef.Identifier("ENG-7") -> "ENG-7", LinearIssueRef.Id(LinearId.parse(issueUuid).get) -> issueUuid)
      ids.foldLeft(IO.unit): (previous, entry) =>
        previous *> {
          val s = stub(getData(teamText))
          LinearIssuesGetClient(s.execute).dispatch(target, LinearGetInput(team, entry._1), access).map: result =>
            val call = s.calls.get.head
            assertEquals(call.bearer, tokenText)
            assertEquals(call.document, LinearDocuments.get)
            assertEquals(
              call.document.text,
              "query($id: String!) { issue(id: $id) { id identifier title description url createdAt updatedAt priority state { name } assignee { name } team { id } } }"
            )
            assertEquals(call.variables, Json.obj("id" -> Json.fromString(entry._2)))
            assertEquals(
              result.content,
              Vector(
                "identifier: ENG-7",
                "title: Bug",
                "state: In Progress",
                "assignee: Alex",
                "priority: 1",
                "created_at: 2026-08-01T00:00:00.000Z",
                "updated_at: 2026-09-01T00:00:00.000Z",
                "url: https://linear.app/x/issue/ENG-7",
                "description:",
                "Body text"
              ).mkString("\n")
            )
        }
    }

    test("get refuses an issue from another team and returns no content") {
      val s = stub(getData(otherTeamText, description = "TOP SECRET OTHER TEAM BODY"))
      LinearIssuesGetClient(s.execute)
        .dispatch(target, LinearGetInput(team, LinearIssueRef.Identifier("ENG-7")), access)
        .attempt
        .map:
          case Left(ProviderExecutionException(error)) =>
            assertEquals(error, ProviderError.Rejected)
            assert(!String.valueOf(error).contains("SECRET"))
          case other => fail(s"expected Rejected, got $other")
    }

    test("get refuses a missing issue, and an answer without a team") {
      for
        a <- providerError(LinearIssuesGetClient(stub("""{"issue":null}""").execute).dispatch(target, LinearGetInput(team, LinearIssueRef.Identifier("ENG-7")), access))
        b <- providerError(LinearIssuesGetClient(stub("""{"issue":{"id":"x","identifier":"ENG-7","title":"t"}}""").execute).dispatch(target, LinearGetInput(team, LinearIssueRef.Identifier("ENG-7")), access))
      yield
        assertEquals(a, ProviderError.Rejected)
        assertEquals(b, ProviderError.InvalidResponse)
    }

    test("get truncates the description at 8,000 characters") {
      val s = stub(getData(teamText, description = "d" * 20000))
      LinearIssuesGetClient(s.execute).dispatch(target, LinearGetInput(team, LinearIssueRef.Identifier("ENG-7")), access).map: result =>
        assert(result.content.endsWith("d" * 8000 + "...[truncated]"))
        assert(!result.content.contains("d" * 8001))
    }

    test("create sends id = operationKey, the target's team, the title, and the description, exactly once") {
      val s = stub(createData(key.toString))
      LinearIssuesCreateClient(s.execute)
        .dispatch(target, LinearCreateInput(team, "Fix it", Some("Details")), access)
        .map: result =>
          assertEquals(s.calls.get.size, 1)
          val call = s.calls.get.head
          assertEquals(call.bearer, tokenText)
          assertEquals(call.document, LinearDocuments.create)
          assertEquals(
            call.document.text,
            "mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }"
          )
          assertEquals(
            call.variables,
            Json.obj(
              "input" -> Json.obj(
                "id" -> Json.fromString(key.toString),
                "teamId" -> Json.fromString(teamText),
                "title" -> Json.fromString("Fix it"),
                "description" -> Json.fromString("Details")
              )
            )
          )
          assertEquals(result.content, "Created issue ENG-9: https://linear.app/x/issue/ENG-9")
    }

    test("create omits an absent description and builds teamId from the target, not the argument") {
      val s = stub(createData(key.toString))
      val otherTarget = LinearOperationsTestSupport.teamTarget(otherTeamText)
      LinearIssuesCreateClient(s.execute).dispatch(otherTarget, LinearCreateInput(team, "t", None), access).map: _ =>
        val input = s.calls.get.head.variables.hcursor.downField("input")
        assertEquals(input.get[String]("teamId"), Right(otherTeamText))
        assert(input.downField("description").failed)
    }

    test("the operation key is derived per lease and distinct keys are sent for distinct accesses") {
      val s = stub(createData(UUID.fromString("55555555-5555-4555-8555-555555555555").toString))
      LinearIssuesCreateClient(s.execute)
        .dispatch(target, LinearCreateInput(team, "t", None), LinearAccess(tokenText, UUID.fromString("55555555-5555-4555-8555-555555555555")))
        .map: _ =>
          assertEquals(
            s.calls.get.head.variables.hcursor.downField("input").get[String]("id"),
            Right("55555555-5555-4555-8555-555555555555")
          )
    }

    test("create refuses a different issue id, success=false, and a missing issue") {
      def run(data: String) =
        providerError(LinearIssuesCreateClient(stub(data).execute).dispatch(target, LinearCreateInput(team, "t", None), access))
      for
        a <- run(createData(UUID.randomUUID().toString))
        b <- run(createData(key.toString, success = false))
        c <- run("""{"issueCreate":{"success":true,"issue":null}}""")
        d <- run("""{"issueCreate":null}""")
      yield
        assertEquals(List(a, b, c, d), List.fill(4)(ProviderError.InvalidResponse))
    }

    // ---- errors ---------------------------------------------------------------------------------------------------
    test("GraphQL errors map to provider errors on every operation; a create timeout is a Timeout, never retried") {
      val expected = List(
        LinearApiError.Unauthorized -> ProviderError.AuthenticationFailed,
        LinearApiError.Forbidden -> ProviderError.AuthenticationFailed,
        LinearApiError.RateLimited -> ProviderError.Rejected,
        LinearApiError.Rejected -> ProviderError.Rejected,
        LinearApiError.Timeout -> ProviderError.Timeout,
        LinearApiError.InvalidResponse -> ProviderError.InvalidResponse
      )
      expected.foldLeft(IO.unit): (previous, entry) =>
        previous *> {
          val (error, mapped) = entry
          val list = failing(error)
          val get = failing(error)
          val create = failing(error)
          for
            a <- providerError(LinearIssuesListClient(list.execute).dispatch(target, LinearListInput(team, 5), access))
            b <- providerError(LinearIssuesGetClient(get.execute).dispatch(target, LinearGetInput(team, LinearIssueRef.Identifier("ENG-1")), access))
            c <- providerError(LinearIssuesCreateClient(create.execute).dispatch(target, LinearCreateInput(team, "t", None), access))
          yield
            assertEquals(List(a, b, c), List.fill(3)(mapped))
            assertEquals(List(list, get, create).map(_.calls.get.size), List(1, 1, 1))
        }
    }

    test("infrastructure failures of the GraphQL function stay failed effects") {
      val boom = IllegalStateException("boom")
      val execute: LinearExecute = (_, _, _) => IO.raiseError(boom)
      LinearIssuesCreateClient(execute).dispatch(target, LinearCreateInput(team, "t", None), access).attempt.map: result =>
        assertEquals(result.left.toOption.map(_.getMessage), Some("boom"))
    }

    test("the access token never appears in a result, an error, or the access description") {
      val s = stub(listData)
      val results = LinearIssuesListClient(s.execute).dispatch(target, LinearListInput(team, 5), access)
      val failures = LinearApiError.values.toList.traverse_(error =>
        LinearIssuesCreateClient(failing(error).execute).dispatch(target, LinearCreateInput(team, "t", None), access).attempt.map:
          case Left(e) =>
            assert(!String.valueOf(e).contains(tokenText))
            assert(!String.valueOf(e.getMessage).contains(tokenText))
          case Right(_) => fail("expected failure")
      )
      results.map(r => assert(!r.content.contains(tokenText))) *> failures.map: _ =>
        assert(!access.toString.contains(tokenText))
        assertEquals(access.toString, "LinearAccess(<redacted>)")
    }

    // ---- registry ------------------------------------------------------------------------------------------------
    private object StubOAuth extends CredentialStrategy[Linear.Team, OAuthTokens]:
      def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[Linear.Team]) =
        IO.pure(Left(ConnectionError.InvalidState))

    test("all builds three operations that register with unique ids and tools on the Linear team kind") {
      val endpoints = LinearEndpoints.Production
      val operations = LinearOperations.all(LinearCredentials(StubOAuth), LinearGraphQl(endpoints, HttpClient.newHttpClient()))
      assertEquals(operations.size, 3)
      val registry = OperationRegistry.from(operations).getOrElse(fail("registry"))
      assertEquals(operations.map(_.descriptor.id.value).toSet, Set("linear.issues.list@1", "linear.issues.get@1", "linear.issues.create@1"))
      assertEquals(operations.map(_.descriptor.tool.value).toSet, Set("linear_issues_list", "linear_issues_get", "linear_issues_create"))
      assert(operations.forall(_.descriptor.target.wire == "linear.team"))
      assertEquals(registry.all.size, 3)
    }
