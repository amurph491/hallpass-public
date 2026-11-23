package run.hallpass.application:
  import run.hallpass.adapters.notion.Notion
  import run.hallpass.kernel.*
  import run.hallpass.kernel.authorization.*

  /** Test-only access to `SelectedResource.trusted`, which is `private[application]`. */
  object NotionTestSupport:
    private val tenant = TenantId.random()

    def pageTarget(externalId: String): SelectedResource[Notion.Page] =
      val page = Resource(ResourceId.random(), tenant, ResourceType.Document, None, externalId, None)
      SelectedResource.trusted(
        Notion.page,
        ExternalId.parse(externalId).getOrElse(throw IllegalStateException("external id")),
        ResourceScope.fromPath(Vector(page)).getOrElse(throw IllegalStateException("scope"))
      )

package run.hallpass.adapters.notion:
  import java.net.{InetSocketAddress, URI}
  import java.net.http.HttpClient
  import java.nio.charset.StandardCharsets
  import java.time.Duration
  import java.util.concurrent.atomic.AtomicReference
  import scala.jdk.CollectionConverters.*
  import com.sun.net.httpserver.HttpServer
  import cats.effect.{IO, Resource as CatsResource}
  import io.circe.Json
  import io.circe.parser.parse
  import munit.CatsEffectSuite
  import run.hallpass.application.*

  final class NotionOperationsSuite extends CatsEffectSuite:
    private val tokenText = "secret_notiontokenvalue"
    private val hyphenated = "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
    private val compact = "0a1b2c3d4e5f4a6b8c7d9e0f1a2b3c4d"
    private val otherId = "11111111-2222-4333-8444-555555555555"
    private val access = NotionAccess(tokenText)
    private val target = NotionTestSupport.pageTarget(hyphenated)
    private val page = NotionId.parse(hyphenated).getOrElse(fail("id"))

    private def str(value: String): Json = Json.fromString(value)
    private def args(fields: (String, Json)*): Json = Json.obj(fields*)
    private def invalid(field: String) = Left(ArgumentError.InvalidField(field))
    private val pageField = "page_id" -> str(hyphenated)

    private def getArgs(fields: (String, Json)*) = NotionPagesGetOperation.decode(args(fields*))
    private def listArgs(fields: (String, Json)*) = NotionBlocksChildrenListOperation.decode(args(fields*))
    private def appendArgs(fields: (String, Json)*) = NotionBlocksAppendOperation.decode(args(fields*))

    private final case class Captured(method: String, path: String, headers: Map[String, String], body: String)
    private final class Fake(val captured: AtomicReference[Vector[Captured]], val uri: URI)

    private def withServer(
        statusCode: Int = 200,
        response: String = "{}",
        delayMillis: Long = 0,
        location: Option[String] = None,
        truncate: Boolean = false
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
                exchange.sendResponseHeaders(statusCode, bytes.length.toLong + (if truncate then 10L else 0L))
                val output = exchange.getResponseBody
                try output.write(bytes)
                finally output.close()
              catch case _: java.io.IOException => ()
          )
          server.start()
          (captured, server))((_, server) => IO.blocking(server.stop(0)))
        .map((captured, server) => new Fake(captured, URI.create(s"http://127.0.0.1:${server.getAddress.getPort}")))

    private def rest(uri: URI, timeout: Duration = Duration.ofSeconds(2)) =
      NotionRestClient(NotionEndpoints(uri, uri), HttpClient.newHttpClient(), timeout)

    private def providerError[A](io: IO[A]): IO[ProviderError] =
      io.attempt.map:
        case Left(error: ProviderExecutionException) =>
          assert(!String.valueOf(error.getMessage).contains(tokenText))
          error.error
        case other => fail(s"expected a provider error, received $other")

    private def pageJson(id: String = hyphenated, properties: String = "{}") =
      s"""{"object":"page","id":"$id","url":"https://www.notion.so/Plan","last_edited_time":"2026-09-30T10:00:00.000Z","archived":false,"properties":$properties}"""

    private def getPage(status: Int, response: String, location: Option[String] = None) =
      withServer(status, response, location = location).use: server =>
        providerError(NotionPagesGetClient(rest(server.uri)).dispatch(target, NotionPageInput(page), access))

    private val appendInput = NotionAppendInput(page, Vector("First", "Second line\nstill second"))
    private def appendStatus(status: Int, response: String = """{"object":"list","results":[]}""") =
      withServer(status, response).use: server =>
        providerError(NotionAppendClient(rest(server.uri)).dispatch(target, appendInput, access))

    // ---- descriptors ----------------------------------------------------------------------------------------------
    test("descriptors carry the contract ids, tools, capabilities, actions, audience, and target argument") {
      val table = Vector(
        (NotionPagesGetOperation, "notion.pages.get@1", "notion_pages_get", "Notion.Page.Read", run.hallpass.kernel.Action.Read),
        (NotionBlocksChildrenListOperation, "notion.blocks.children.list@1", "notion_blocks_children_list", "Notion.Page.Read", run.hallpass.kernel.Action.Read),
        (NotionBlocksAppendOperation, "notion.blocks.append@1", "notion_blocks_append", "Notion.Page.Append", run.hallpass.kernel.Action.Write)
      )
      table.foreach: (d, id, tool, capability, action) =>
        assertEquals(d.id.value, id)
        assertEquals(d.tool.value, tool)
        assertEquals(d.capability.value, capability)
        assertEquals(d.action, action)
        assertEquals(d.target.wire, "notion.page")
        assertEquals(d.audience, NotionExecutorAudience.local)
        assertEquals(d.targetArgument, Some("page_id"))
    }

    test("input schemas are closed objects requiring page_id") {
      Vector(NotionPagesGetOperation.inputSchema, NotionBlocksChildrenListOperation.inputSchema, NotionBlocksAppendOperation.inputSchema)
        .foreach: schema =>
          assertEquals(schema.hcursor.get[Boolean]("additionalProperties"), Right(false))
          assert(schema.hcursor.downField("required").as[List[String]].exists(_.contains("page_id")))
      assertEquals(NotionBlocksAppendOperation.inputSchema.hcursor.downField("required").as[List[String]], Right(List("page_id", "paragraphs")))
    }

    // ---- decoding -------------------------------------------------------------------------------------------------
    test("page_id in hyphenated, compact, and upper-case forms normalizes to the same input") {
      val expected = Right(NotionPageInput(page))
      assertEquals(getArgs("page_id" -> str(hyphenated)), expected)
      assertEquals(getArgs("page_id" -> str(compact)), expected)
      assertEquals(getArgs("page_id" -> str(compact.toUpperCase)), expected)
      assertEquals(listArgs("page_id" -> str(compact)).map(_.page), Right(page))
      assertEquals(appendArgs("page_id" -> str(compact), "paragraphs" -> Json.arr(str("x"))).map(_.page), Right(page))
    }

    test("page_id must be a UUID string") {
      Vector(
        Json.fromInt(1), Json.Null, str(""), str("not-a-uuid"), str(hyphenated.dropRight(1)), str(hyphenated + "0"),
        str("0a1b2c3d4e5f-4a6b-8c7d-9e0f1a2b3c4d"), str("../" + compact), str(compact + "/children"), str(" " + hyphenated)
      ).foreach(value => assertEquals(getArgs("page_id" -> value), invalid("page_id")))
      assertEquals(getArgs(), Left(ArgumentError.MissingField("page_id")))
    }

    test("decode rejects unknown fields and non-objects on every operation") {
      assertEquals(getArgs(pageField, "extra" -> str("x")), Left(ArgumentError.UnexpectedField))
      assertEquals(listArgs(pageField, "limit" -> Json.fromInt(1)), Left(ArgumentError.UnexpectedField))
      assertEquals(appendArgs(pageField, "paragraphs" -> Json.arr(str("x")), "parent" -> str("y")), Left(ArgumentError.UnexpectedField))
      assertEquals(NotionPagesGetOperation.decode(Json.arr()), Left(ArgumentError.NotAnObject))
      assertEquals(NotionBlocksChildrenListOperation.decode(str("x")), Left(ArgumentError.NotAnObject))
      assertEquals(NotionBlocksAppendOperation.decode(Json.Null), Left(ArgumentError.NotAnObject))
    }

    test("children.list defaults page_size to 50 and no cursor") {
      assertEquals(listArgs(pageField), Right(NotionChildrenInput(page, None, 50)))
      assertEquals(listArgs(pageField, "start_cursor" -> Json.Null), Right(NotionChildrenInput(page, None, 50)))
    }

    test("page_size is a JSON integer from 1 to 100") {
      assertEquals(listArgs(pageField, "page_size" -> Json.fromInt(1)).map(_.pageSize), Right(1))
      assertEquals(listArgs(pageField, "page_size" -> Json.fromInt(100)).map(_.pageSize), Right(100))
      Vector(Json.fromInt(0), Json.fromInt(101), Json.fromInt(-1), Json.fromDoubleOrNull(1.5), str("5"), Json.Null, Json.True)
        .foreach(value => assertEquals(listArgs(pageField, "page_size" -> value), invalid("page_size")))
    }

    test("start_cursor is 1 to 256 printable characters") {
      assertEquals(listArgs(pageField, "start_cursor" -> str("a" * 256)).map(_.startCursor), Right(Some("a" * 256)))
      assertEquals(listArgs(pageField, "start_cursor" -> str("abc-123_DEF=")).map(_.startCursor), Right(Some("abc-123_DEF=")))
      Vector(str(""), str("a" * 257), str("a b"), str("a\nb"), str("a\u0000b"), str("café"), Json.fromInt(3), Json.True)
        .foreach(value => assertEquals(listArgs(pageField, "start_cursor" -> value), invalid("start_cursor")))
    }

    test("paragraphs: 1 to 20 strings of 1 to 2,000 characters") {
      def p(values: Json*) = appendArgs(pageField, "paragraphs" -> Json.arr(values*))
      assertEquals(p(str("a")).map(_.paragraphs), Right(Vector("a")))
      assert(p(Vector.fill(20)(str("x"))*).isRight)
      assertEquals(p(Vector.fill(21)(str("x"))*), invalid("paragraphs"))
      assertEquals(p(), invalid("paragraphs"))
      assert(p(str("x" * 2000)).isRight)
      assertEquals(p(str("x" * 2001)), invalid("paragraphs"))
      assertEquals(p(str("ok"), str("")), invalid("paragraphs"))
      assertEquals(p(str("ok"), Json.fromInt(1)), invalid("paragraphs"))
      assertEquals(p(str("ok"), Json.Null), invalid("paragraphs"))
      assertEquals(appendArgs(pageField), Left(ArgumentError.MissingField("paragraphs")))
      assertEquals(appendArgs(pageField, "paragraphs" -> str("x")), invalid("paragraphs"))
      assertEquals(appendArgs(pageField, "paragraphs" -> Json.Null), invalid("paragraphs"))
    }

    test("paragraphs allow newline only as a control character") {
      def p(value: String) = appendArgs(pageField, "paragraphs" -> Json.arr(str(value)))
      assert(p("a\nb").isRight)
      Vector("a\tb", "a\rb", "a\u0000b", "a\u001bb", "a\u009fb").foreach(v => assertEquals(p(v), invalid("paragraphs")))
    }

    test("locate selects the page by its normalized external ID and facts are empty") {
      val inputs = Vector(
        NotionPagesGetOperation.locate(NotionPageInput(page)),
        NotionBlocksChildrenListOperation.locate(NotionChildrenInput(page, None, 50)),
        NotionBlocksAppendOperation.locate(appendInput)
      )
      inputs.foreach:
        case ResourceLocator.Selected(ref) => assertEquals(ref.id.value, hyphenated)
        case other                         => fail(s"unexpected locator $other")
      assertEquals(NotionPagesGetOperation.facts(NotionPageInput(page)), run.hallpass.kernel.AuthorizationContext.empty)
    }

    // ---- canonical ------------------------------------------------------------------------------------------------
    test("canonical form is identical for both ID forms and defaults, and differs for different content") {
      val fromCompact = getArgs("page_id" -> str(compact)).getOrElse(fail("decode"))
      val fromHyphen = getArgs("page_id" -> str(hyphenated)).getOrElse(fail("decode"))
      assertEquals(NotionPagesGetOperation.canonical(fromCompact), NotionPagesGetOperation.canonical(fromHyphen))
      assertNotEquals(
        NotionPagesGetOperation.canonical(fromHyphen),
        NotionPagesGetOperation.canonical(NotionPageInput(NotionId.parse(otherId).getOrElse(fail("id"))))
      )

      val omitted = listArgs(pageField).getOrElse(fail("decode"))
      val explicit = listArgs("page_id" -> str(compact), "page_size" -> Json.fromInt(50), "start_cursor" -> Json.Null).getOrElse(fail("decode"))
      assertEquals(NotionBlocksChildrenListOperation.canonical(omitted), NotionBlocksChildrenListOperation.canonical(explicit))
      assertNotEquals(NotionBlocksChildrenListOperation.canonical(omitted), NotionBlocksChildrenListOperation.canonical(omitted.copy(pageSize = 10)))
      assertNotEquals(NotionBlocksChildrenListOperation.canonical(omitted), NotionBlocksChildrenListOperation.canonical(omitted.copy(startCursor = Some("c"))))

      def append(id: String, ps: String*) = appendArgs("page_id" -> str(id), "paragraphs" -> Json.arr(ps.map(str)*)).getOrElse(fail("decode"))
      assertEquals(NotionBlocksAppendOperation.canonical(append(compact, "a", "b")), NotionBlocksAppendOperation.canonical(append(hyphenated, "a", "b")))
      assertNotEquals(NotionBlocksAppendOperation.canonical(append(hyphenated, "a", "b")), NotionBlocksAppendOperation.canonical(append(hyphenated, "a", "c")))
      assertNotEquals(NotionBlocksAppendOperation.canonical(append(hyphenated, "a", "b")), NotionBlocksAppendOperation.canonical(append(hyphenated, "b", "a")))
      assertNotEquals(NotionBlocksAppendOperation.canonical(append(hyphenated, "ab")), NotionBlocksAppendOperation.canonical(append(hyphenated, "a", "b")))
    }

    test("append canonical form is exactly the page and the paragraphs that are sent") {
      withServer().use: server =>
        NotionAppendClient(rest(server.uri)).dispatch(target, appendInput, access).map: _ =>
          val canonical = NotionBlocksAppendOperation.canonical(appendInput)
          val sent = parse(server.captured.get.head.body).getOrElse(fail("body")).hcursor
          val sentTexts = sent.downField("children").as[Vector[Json]].getOrElse(fail("children"))
            .map(_.hcursor.downField("paragraph").downField("rich_text").downN(0).downField("text").get[String]("content").getOrElse(fail("content")))
          assertEquals(canonical.hcursor.get[Vector[String]]("paragraphs"), Right(sentTexts))
          assertEquals(canonical.hcursor.get[String]("page_id"), Right(hyphenated))
    }

    // ---- registry -------------------------------------------------------------------------------------------------
    private object StubConnections extends ProviderConnectionResolver:
      def activeConnectionFor[K](lease: RedeemedExecutionLease, target: SelectedResource[K], provider: ProviderId, credentialType: String) =
        IO.pure(Left(ConnectionError.InvalidState))

    test("all() registers three operations with unique ids and tools") {
      val operations = NotionOperations.all(NotionCredentials(StubConnections), NotionEndpoints.Production, HttpClient.newHttpClient())
      assertEquals(
        operations.map(_.descriptor.id.value),
        Vector("notion.pages.get@1", "notion.blocks.children.list@1", "notion.blocks.append@1")
      )
      assertEquals(operations.map(_.descriptor.tool.value).toSet.size, 3)
      val registry = OperationRegistry.from(operations).getOrElse(fail("registry"))
      assertEquals(registry.all.size, 3)
    }

    // ---- pages.get ------------------------------------------------------------------------------------------------
    test("pages.get sends GET to the path built from the target with the contract headers") {
      val argumentOnly = getArgs("page_id" -> str(compact)).getOrElse(fail("decode"))
      assertEquals(argumentOnly.page, page)
      withServer(response = pageJson()).use: server =>
        NotionPagesGetClient(rest(server.uri)).dispatch(target, argumentOnly, access).map: result =>
          assertEquals(server.captured.get.size, 1)
          val request = server.captured.get.head
          assertEquals(request.method, "GET")
          assertEquals(request.path, s"/v1/pages/$hyphenated")
          assertEquals(request.headers.get("authorization"), Some("Bearer " + tokenText))
          assertEquals(request.headers.get("notion-version"), Some(Notion.ApiVersion))
          assertEquals(request.headers.get("accept-encoding"), Some("identity"))
          assertEquals(request.headers.get("user-agent"), Some("hallpass"))
          assert(!result.content.contains(tokenText))
    }

    test("the request path uses the target, not the argument, even if they differ") {
      val other = NotionPageInput(NotionId.parse(otherId).getOrElse(fail("id")))
      withServer(response = pageJson()).use: server =>
        NotionPagesGetClient(rest(server.uri)).dispatch(target, other, access).map: _ =>
          assertEquals(server.captured.get.head.path, s"/v1/pages/$hyphenated")
    }

    test("a target whose external ID is not a Notion ID is refused before any request") {
      val bad = NotionTestSupport.pageTarget("not-a-notion-id")
      withServer(response = pageJson()).use: server =>
        providerError(NotionPagesGetClient(rest(server.uri)).dispatch(bad, NotionPageInput(page), access)).map: error =>
          assertEquals(error, ProviderError.Rejected)
          assert(server.captured.get.isEmpty)
    }

    test("a returned page whose id differs from the target is Rejected; the 32-hex form of the target is accepted") {
      for
        mismatch <- getPage(200, pageJson(id = otherId))
        missing <- getPage(200, """{"object":"page","url":"u"}""")
        accepted <- withServer(response = pageJson(id = compact)).use: server =>
          NotionPagesGetClient(rest(server.uri)).dispatch(target, NotionPageInput(page), access)
      yield
        assertEquals(mismatch, ProviderError.Rejected)
        assertEquals(missing, ProviderError.Rejected)
        assert(accepted.content.startsWith("title:"))
    }

    test("pages.get renders title, url, last edited time, archived, and simple properties") {
      val properties =
        """{"Name":{"id":"t","type":"title","title":[{"plain_text":"Quarterly "},{"plain_text":"plan"}]},
          |"Notes":{"type":"rich_text","rich_text":[{"plain_text":"hello"}]},
          |"Status":{"type":"select","select":{"name":"Doing"}},
          |"Empty":{"type":"select","select":null},
          |"Tags":{"type":"multi_select","multi_select":[{"name":"a"},{"name":"b"}]},
          |"Points":{"type":"number","number":3.5},
          |"Done":{"type":"checkbox","checkbox":true},
          |"When":{"type":"date","date":{"start":"2026-10-01","end":"2026-10-02"}},
          |"Link":{"type":"url","url":"https://example.com"},
          |"Mail":{"type":"email","email":"a@example.com"},
          |"Owner":{"type":"people","people":[{"id":"x"}]}}""".stripMargin
      withServer(response = pageJson(properties = properties)).use: server =>
        NotionPagesGetClient(rest(server.uri)).dispatch(target, NotionPageInput(page), access).map: result =>
          val lines = result.content.linesIterator.toVector
          assertEquals(lines.take(5), Vector(
            "title: Quarterly plan",
            "url: https://www.notion.so/Plan",
            "last_edited_time: 2026-09-30T10:00:00.000Z",
            "archived: false",
            "properties:"
          ))
          Vector(
            "Name: Quarterly plan", "Notes: hello", "Status: Doing", "Empty: ", "Tags: a,b", "Points: 3.5", "Done: true",
            "When: 2026-10-01 -> 2026-10-02", "Link: https://example.com", "Mail: a@example.com", "Owner: [people]"
          ).foreach(expected => assert(lines.exists(_.trim == expected.trim), s"missing $expected in ${result.content}"))
    }

    test("pages.get output is capped at 60,000 characters") {
      val long = "x" * 100
      val properties = (0 until 90).map(i => s""""P$i":{"type":"rich_text","rich_text":[{"plain_text":"$long"}]}""").mkString("{", ",", "}")
      val rendered = NotionRender.page(parse(pageJson(properties = properties)).getOrElse(fail("json")))
      assert(rendered.exists(_.length <= 60100))
      val huge = Json.obj("id" -> str(hyphenated), "properties" -> Json.obj((0 until 100).map(i => s"P$i" -> Json.obj("type" -> str("rich_text"), "rich_text" -> Json.arr(Json.obj("plain_text" -> str("y" * 5000)))))*))
      assert(NotionRender.page(huge).exists(_.length <= 60100))
    }

    // ---- children.list --------------------------------------------------------------------------------------------
    private val childrenJson =
      """{"object":"list","has_more":true,"next_cursor":"cur-2","results":[
        |{"type":"paragraph","paragraph":{"rich_text":[{"plain_text":"Hello "},{"plain_text":"world"}]}},
        |{"type":"heading_1","heading_1":{"rich_text":[{"plain_text":"Title"}]}},
        |{"type":"to_do","to_do":{"rich_text":[{"plain_text":"task"}],"checked":false}},
        |{"type":"child_page","child_page":{"title":"Sub page"}},
        |{"type":"child_database","child_database":{"title":"Tasks"}},
        |{"type":"image","image":{}},
        |{"type":"paragraph","paragraph":{"rich_text":[{"plain_text":"two\nlines"}]}}]}""".stripMargin

    test("children.list sends GET with page_size and an encoded cursor, built from the target") {
      val input = listArgs("page_id" -> str(compact), "page_size" -> Json.fromInt(7), "start_cursor" -> str("a+b=c&d")).getOrElse(fail("decode"))
      withServer(response = childrenJson).use: server =>
        NotionChildrenListClient(rest(server.uri)).dispatch(target, input, access).map: result =>
          val request = server.captured.get.head
          assertEquals(request.method, "GET")
          assertEquals(request.path, s"/v1/blocks/$hyphenated/children?page_size=7&start_cursor=a%2Bb%3Dc%26d")
          assertEquals(request.headers.get("authorization"), Some("Bearer " + tokenText))
          assertEquals(request.headers.get("notion-version"), Some(Notion.ApiVersion))
          assertEquals(request.headers.get("accept-encoding"), Some("identity"))
          assertEquals(request.headers.get("user-agent"), Some("hallpass"))
          assert(!result.content.contains(tokenText))
    }

    test("children.list omits start_cursor when absent and renders one line per block") {
      withServer(response = childrenJson).use: server =>
        NotionChildrenListClient(rest(server.uri)).dispatch(target, NotionChildrenInput(page, None, 50), access).map: result =>
          assertEquals(server.captured.get.head.path, s"/v1/blocks/$hyphenated/children?page_size=50")
          assertEquals(
            result.content.linesIterator.toVector,
            Vector(
              "paragraph: Hello world", "heading_1: Title", "to_do: task", "[child_page] Sub page", "[child_database] Tasks",
              "[image]", "paragraph: two lines", "next_cursor: cur-2"
            )
          )
    }

    test("children.list prints no next_cursor when there is no more") {
      val json = """{"has_more":false,"next_cursor":null,"results":[{"type":"divider","divider":{}}]}"""
      withServer(response = json).use: server =>
        NotionChildrenListClient(rest(server.uri)).dispatch(target, NotionChildrenInput(page, None, 50), access)
          .map(result => assertEquals(result.content, "[divider]"))
    }

    test("children.list rejects a response without results or with a typeless block") {
      for
        noResults <- withServer(response = "{}").use(s => providerError(NotionChildrenListClient(rest(s.uri)).dispatch(target, NotionChildrenInput(page, None, 50), access)))
        typeless <- withServer(response = """{"results":[{"id":"x"}]}""").use(s => providerError(NotionChildrenListClient(rest(s.uri)).dispatch(target, NotionChildrenInput(page, None, 50), access)))
      yield
        assertEquals(noResults, ProviderError.InvalidResponse)
        assertEquals(typeless, ProviderError.InvalidResponse)
    }

    test("children.list output is capped at 60,000 characters") {
      val block = Json.obj("type" -> str("paragraph"), "paragraph" -> Json.obj("rich_text" -> Json.arr(Json.obj("plain_text" -> str("z" * 1500)))))
      val json = Json.obj("results" -> Json.arr(Vector.fill(100)(block)*))
      val rendered = NotionRender.children(json).getOrElse(fail("render"))
      assert(rendered.length <= 60000 + "\n...[truncated]".length)
      assert(rendered.endsWith("...[truncated]"))
      val long = Json.obj("results" -> Json.arr(Json.obj("type" -> str("paragraph"), "paragraph" -> Json.obj("rich_text" -> Json.arr(Json.obj("plain_text" -> str("q" * 10000)))))))
      assert(NotionRender.children(long).exists(_.length < 2100))
    }

    // ---- append ---------------------------------------------------------------------------------------------------
    test("append sends one PATCH with exactly the decoded paragraphs as plain paragraph blocks") {
      val input = appendArgs("page_id" -> str(compact), "paragraphs" -> Json.arr(str("First"), str("Second line\nstill second"), str("<b>[link](http://x) @mention</b>")))
        .getOrElse(fail("decode"))
      withServer().use: server =>
        NotionAppendClient(rest(server.uri)).dispatch(target, input, access).map: result =>
          assertEquals(server.captured.get.size, 1)
          val request = server.captured.get.head
          assertEquals(request.method, "PATCH")
          assertEquals(request.path, s"/v1/blocks/$hyphenated/children")
          assertEquals(request.headers.get("content-type"), Some("application/json"))
          assertEquals(request.headers.get("authorization"), Some("Bearer " + tokenText))
          assertEquals(request.headers.get("notion-version"), Some(Notion.ApiVersion))
          assertEquals(request.headers.get("accept-encoding"), Some("identity"))
          assertEquals(request.headers.get("user-agent"), Some("hallpass"))
          def block(text: String) = Json.obj(
            "object" -> str("block"),
            "type" -> str("paragraph"),
            "paragraph" -> Json.obj("rich_text" -> Json.arr(Json.obj("type" -> str("text"), "text" -> Json.obj("content" -> str(text)))))
          )
          assertEquals(
            parse(request.body),
            Right(Json.obj("children" -> Json.arr(block("First"), block("Second line\nstill second"), block("<b>[link](http://x) @mention</b>"))))
          )
          assertEquals(result.content, s"Appended 3 paragraph(s) to $hyphenated")
          assert(!result.content.contains(tokenText))
    }

    test("append requires exactly 200; any other 2xx is InvalidResponse, and bad JSON is InvalidResponse") {
      for
        created <- appendStatus(201)
        accepted <- appendStatus(204, "")
        malformed <- appendStatus(200, "{not json")
      yield
        assertEquals(created, ProviderError.InvalidResponse)
        assertEquals(accepted, ProviderError.InvalidResponse)
        assertEquals(malformed, ProviderError.InvalidResponse)
    }

    test("append timeout has an unknown outcome and the write was received exactly once, never retried") {
      withServer(delayMillis = 1500).use: server =>
        providerError(NotionAppendClient(rest(server.uri, Duration.ofMillis(200))).dispatch(target, appendInput, access)).flatMap: error =>
          IO.sleep(scala.concurrent.duration.DurationInt(1800).millis).map: _ =>
            assertEquals(error, ProviderError.OutcomeUnknown)
            assertEquals(server.captured.get.size, 1)
    }

    test("a redirect on append is Rejected, not followed, and the write is sent once") {
      withServer(302, location = Some("http://127.0.0.1:1/elsewhere")).use: server =>
        providerError(NotionAppendClient(rest(server.uri)).dispatch(target, appendInput, access)).map: error =>
          assertEquals(error, ProviderError.Rejected)
          assertEquals(server.captured.get.size, 1)
    }

    // ---- error mapping --------------------------------------------------------------------------------------------
    test("status codes map to provider errors for reads") {
      for
        unauthorized <- getPage(401, "{}")
        forbidden <- getPage(403, "{}")
        missing <- getPage(404, "{}")
        bad <- getPage(400, "{}")
        conflict <- getPage(409, "{}")
        limited <- getPage(429, "{}")
        broken <- getPage(500, "{}")
        moved <- getPage(302, "{}", location = Some("http://127.0.0.1:1/elsewhere"))
        malformed <- getPage(200, "{not json")
      yield
        assertEquals(unauthorized, ProviderError.AuthenticationFailed)
        assertEquals(forbidden, ProviderError.AuthenticationFailed)
        assertEquals(missing, ProviderError.Rejected)
        assertEquals(bad, ProviderError.Rejected)
        assertEquals(conflict, ProviderError.Rejected)
        assertEquals(limited, ProviderError.Rejected)
        assertEquals(broken, ProviderError.Rejected)
        assertEquals(moved, ProviderError.Rejected)
        assertEquals(malformed, ProviderError.InvalidResponse)
    }

    test("status codes map to provider errors for append") {
      for
        unauthorized <- appendStatus(401)
        forbidden <- appendStatus(403)
        missing <- appendStatus(404)
        bad <- appendStatus(400)
        conflict <- appendStatus(409)
        limited <- appendStatus(429)
        broken <- appendStatus(503)
      yield
        assertEquals(unauthorized, ProviderError.AuthenticationFailed)
        assertEquals(forbidden, ProviderError.AuthenticationFailed)
        assertEquals(List(missing, bad, conflict, limited).distinct, List(ProviderError.Rejected))
        assertEquals(broken, ProviderError.OutcomeUnknown)
    }

    test("a response over 1 MiB is InvalidResponse") {
      withServer(response = "a" * (1024 * 1024 + 1)).use: server =>
        providerError(NotionPagesGetClient(rest(server.uri)).dispatch(target, NotionPageInput(page), access))
          .map(assertEquals(_, ProviderError.InvalidResponse))
    }

    test("a read timeout and an unreachable endpoint are Timeout") {
      for
        slow <- withServer(response = pageJson(), delayMillis = 1000).use: server =>
          providerError(NotionPagesGetClient(rest(server.uri, Duration.ofMillis(200))).dispatch(target, NotionPageInput(page), access))
        unreachable <- providerError(NotionPagesGetClient(rest(URI.create("http://127.0.0.1:1"))).dispatch(target, NotionPageInput(page), access))
      yield
        assertEquals(slow, ProviderError.Timeout)
        assertEquals(unreachable, ProviderError.Timeout)
    }

    test("the token never appears in a result, an error, or the access object's text form") {
      assert(!access.toString.contains(tokenText))
      withServer(response = pageJson(), statusCode = 200).use: server =>
        NotionPagesGetClient(rest(server.uri)).dispatch(target, NotionPageInput(page), access).map: result =>
          assert(!result.content.contains(tokenText))
    }

    Vector(408, 500, 502, 504).foreach: status =>
      test(s"append HTTP $status has an unknown outcome and is sent once") {
        withServer(status).use: server =>
          providerError(NotionAppendClient(rest(server.uri)).dispatch(target, appendInput, access)).map: error =>
            assertEquals(error, ProviderError.OutcomeUnknown)
            assertEquals(server.captured.get.size, 1)
      }

    test("a truncated response after append has an unknown outcome and is never retried") {
      withServer(truncate = true).use: server =>
        providerError(NotionAppendClient(rest(server.uri)).dispatch(target, appendInput, access)).map: error =>
          assertEquals(error, ProviderError.OutcomeUnknown)
          assertEquals(server.captured.get.size, 1)
    }
