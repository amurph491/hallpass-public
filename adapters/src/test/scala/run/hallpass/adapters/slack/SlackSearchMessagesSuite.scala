package run.hallpass.application:
  import java.time.{Duration, Instant}
  import cats.effect.IO
  import run.hallpass.adapters.slack.{Slack, SlackSearchMessagesOperation}
  import run.hallpass.kernel.*
  import run.hallpass.kernel.authorization.*

  /** Test-only access to values whose constructors are `private[application]`. Declared in this package so the Slack
    * adapter tests can exercise the client and credential strategy without widening any production visibility. */
  object SlackSearchTestSupport:
    private val tenant = TenantId.random()
    private val agentId = AgentId.random()
    private val issuedAt = Instant.parse("2026-09-01T12:00:00Z")
    private val workspace = Resource(ResourceId.random(), tenant, ResourceType.Provider, None, "slack-workspace", None)

    val target: SelectedResource[Slack.Workspace] =
      SelectedResource.trusted(
        Slack.workspace,
        ExternalId.parse("T0TEST").getOrElse(throw IllegalStateException("external id")),
        ResourceScope.fromPath(Vector(workspace)).getOrElse(throw IllegalStateException("scope"))
      )

    /** A genuinely redeemed lease for the workspace target, issued through the broker. */
    def redeemedLease(query: SearchQuery): IO[RedeemedExecutionLease] =
      val descriptor = SlackSearchMessagesOperation
      val agent = Principal.Agent(agentId)
      val request = AuthorizationRequest(
        AuthorizationRequestId.random(),
        tenant,
        IdentityChain.direct(agent),
        target.scope,
        descriptor.capability,
        descriptor.action,
        AuthorizationContext.empty
      )
      val policies = Policies(
        Vector(
          Policy(
            PolicyId.random(),
            PolicyVersion.from(1).getOrElse(throw IllegalStateException("version")),
            NonEmptySet.one(
              PolicyStatement(agent, workspace.id, NonEmptySet.one(descriptor.action), None, Constraints.empty, Effect.Allow)
            )
          )
        )
      )
      val capability = AuthorizationEngine.authorize(policies, request, Vector.empty, issuedAt) match
        case AuthorizationResult.Authorized(value) => value
        case other                                 => throw IllegalStateException(s"expected authorization, got $other")
      val metadata = ExecutionAuditMetadata.authenticatedInvocation(
        AuthenticatedAgentContext.authenticated(
          tenant,
          agentId,
          AgentCredentialId.random(),
          issuedAt,
          UnverifiedExecutionClaims.empty
        ),
        ExecutionAuditCorrelationId.parse("slack-search-suite").getOrElse(throw IllegalStateException("correlation")),
        ResourceId.random(),
        CatalogCapabilityId.parse("00000000-0000-4000-8000-000000000001").getOrElse(throw IllegalStateException("id")),
        InvocationBinding.of(tenant, agentId, descriptor, target, query)
      )
      for
        store <- InMemoryExecutionLeaseStore.create(Clock.fixed(issuedAt), InMemoryExecutionLeaseStore.DefaultPruneInterval, 10)
        audit <- InMemoryExecutionAuditRecorder.create
        broker = new InMemoryCredentialBroker(store, Clock.fixed(issuedAt), Duration.ofSeconds(60), audit)
        lease <- broker.issueLease(capability, request.id, descriptor.audience, metadata)
        redeemed <- store.redeem(lease.id, descriptor.audience, issuedAt)
        result <- redeemed match
          case LeaseRedemption.Redeemed(value) => IO.pure(value)
          case other                           => IO.raiseError(IllegalStateException(s"redemption failed: $other"))
      yield result

package run.hallpass.adapters.slack:
  import java.net.{InetSocketAddress, URI, URLEncoder}
  import java.net.http.HttpClient
  import java.nio.charset.StandardCharsets
  import java.time.Duration
  import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}
  import scala.jdk.CollectionConverters.*
  import com.sun.net.httpserver.HttpServer
  import cats.effect.{IO, Resource as CatsResource}
  import io.circe.Json
  import io.circe.parser.parse
  import munit.CatsEffectSuite
  import run.hallpass.application.*
  import run.hallpass.kernel.*

  final class SlackSearchMessagesSuite extends CatsEffectSuite:
    private val tokenText = "xoxp-test-token"
    private val token = SlackAccessToken.parse(tokenText).getOrElse(fail("token"))
    private val target = SlackSearchTestSupport.target
    private def query(value: String): SearchQuery = SearchQuery.parse(value).getOrElse(fail("query"))
    private val emptyResult = """{"ok":true,"messages":{"matches":[]}}"""

    private final case class Captured(method: String, path: String, headers: Map[String, String], body: String)

    private final class FakeSlack(val captured: AtomicReference[Vector[Captured]], val uri: URI)

    private def withServer(
        statusCode: Int = 200,
        response: String = emptyResult,
        delayMillis: Long = 0
    ): CatsResource[IO, FakeSlack] =
      CatsResource
        .make(IO.blocking:
          val captured = new AtomicReference(Vector.empty[Captured])
          val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
          server.createContext(
            "/",
            exchange =>
              val body = new String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)
              val headers = exchange.getRequestHeaders.asScala.map((name, values) => name.toLowerCase -> values.asScala.mkString(",")).toMap
              captured.updateAndGet(_ :+ Captured(exchange.getRequestMethod, exchange.getRequestURI.toString, headers, body))
              if delayMillis > 0 then Thread.sleep(delayMillis)
              val bytes = response.getBytes(StandardCharsets.UTF_8)
              try
                exchange.sendResponseHeaders(statusCode, bytes.length)
                val output = exchange.getResponseBody
                try output.write(bytes)
                finally output.close()
              catch case _: java.io.IOException => () // the client timed out and went away
          )
          server.start()
          (captured, server))((_, server) => IO.blocking(server.stop(0)))
        .map: (captured, server) =>
          new FakeSlack(captured, URI.create(s"http://127.0.0.1:${server.getAddress.getPort}/api/search.messages"))

    private def client(uri: URI, timeout: Duration = Duration.ofSeconds(2)) =
      new SlackSearchMessagesClient(uri, HttpClient.newHttpClient(), timeout)

    private def dispatchError(statusCode: Int, response: String): IO[Option[ProviderError]] =
      withServer(statusCode, response).use: slack =>
        client(slack.uri).dispatch(target, query("roadmap"), token).attempt.map:
          case Left(error: ProviderExecutionException) => Some(error.error)
          case other                                   => fail(s"expected a provider error, received $other")

    // ---- SlackSearchMessagesClient ---------------------------------------------------------------------------------
    test("a successful search renders each message with channel, timestamp, and author") {
      val response =
        """{"ok":true,"messages":{"matches":[
          |{"channel":{"id":"C1"},"ts":"1.0","text":"hello","username":"alex"},
          |{"channel_id":"C2","ts":"2.0","text":"no author"}]}}""".stripMargin
      withServer(response = response).use: slack =>
        client(slack.uri).dispatch(target, query("roadmap"), token).map: result =>
          assertEquals(result, ToolResult("C1 1.0 alex: hello\nC2 2.0 unknown: no author"))
    }

    test("a response without messages renders an empty result") {
      withServer(response = """{"ok":true}""").use: slack =>
        client(slack.uri).dispatch(target, query("roadmap"), token).map: result =>
          assertEquals(result, ToolResult(""))
    }

    test("channel.id is read when channel_id is absent, and channel_id wins when both are present") {
      val response =
        """{"ok":true,"messages":{"matches":[
          |{"channel_id":"CFLAT","channel":{"id":"CNESTED"},"ts":"1.0","text":"both"},
          |{"channel":{"id":"CNESTED"},"ts":"2.0","text":"nested only"}]}}""".stripMargin
      withServer(response = response).use: slack =>
        client(slack.uri).dispatch(target, query("roadmap"), token).map: result =>
          assertEquals(result, ToolResult("CFLAT 1.0 unknown: both\nCNESTED 2.0 unknown: nested only"))
    }

    test("the token travels only in the Authorization header and the body is only the url-encoded query") {
      val text = "from:alex roadmap & plan=2026 100%"
      withServer().use: slack =>
        for
          _ <- client(slack.uri).dispatch(target, query(text), token)
          requests = slack.captured.get
        yield
          assertEquals(requests.size, 1)
          val request = requests.head
          assertEquals(request.method, "POST")
          assertEquals(request.path, "/api/search.messages")
          assertEquals(request.headers.get("authorization"), Some("Bearer " + tokenText))
          assertEquals(request.headers.get("content-type"), Some("application/x-www-form-urlencoded"))
          assertEquals(request.body, "query=" + URLEncoder.encode(text, StandardCharsets.UTF_8))
          assert(!request.body.contains(tokenText), "the token must not be in the body")
          assert(!request.path.contains(tokenText), "the token must not be in the URL")
          val elsewhere = request.headers - "authorization"
          assert(!elsewhere.values.exists(_.contains(tokenText)), s"the token leaked into another header: ${elsewhere.keys}")
    }

    test("401 and 403 are AuthenticationFailed") {
      for
        unauthorized <- dispatchError(401, """{"ok":false,"error":"invalid_auth"}""")
        forbidden <- dispatchError(403, """{"ok":false}""")
      yield
        assertEquals(unauthorized, Some(ProviderError.AuthenticationFailed))
        assertEquals(forbidden, Some(ProviderError.AuthenticationFailed))
    }

    test("other non-2xx statuses are Rejected") {
      List(400, 404, 429, 500, 503).foldLeft(IO.unit): (previous, status) =>
        previous *> dispatchError(status, emptyResult).map(assertEquals(_, Some(ProviderError.Rejected), s"status $status"))
    }

    test("ok=false in a 2xx response is Rejected") {
      dispatchError(200, """{"ok":false,"error":"missing_scope"}""").map(assertEquals(_, Some(ProviderError.Rejected)))
    }

    test("an unparseable or malformed body is InvalidResponse") {
      for
        notJson <- dispatchError(200, "<html>gateway</html>")
        noOk <- dispatchError(200, """{"messages":{"matches":[]}}""")
        badMatch <- dispatchError(200, """{"ok":true,"messages":{"matches":[{"text":"no channel or ts"}]}}""")
      yield
        assertEquals(notJson, Some(ProviderError.InvalidResponse))
        assertEquals(noOk, Some(ProviderError.InvalidResponse))
        assertEquals(badMatch, Some(ProviderError.InvalidResponse))
    }

    test("a response slower than the request timeout is Timeout") {
      withServer(delayMillis = 1500).use: slack =>
        client(slack.uri, Duration.ofMillis(200)).dispatch(target, query("roadmap"), token).attempt.map:
          case Left(error: ProviderExecutionException) => assertEquals(error.error, ProviderError.Timeout)
          case other                                   => fail(s"expected a timeout, received $other")
    }

    test("an unreachable endpoint is Timeout") {
      client(URI.create("http://127.0.0.1:1/api/search.messages"), Duration.ofMillis(500))
        .dispatch(target, query("roadmap"), token)
        .attempt
        .map:
          case Left(error: ProviderExecutionException) => assertEquals(error.error, ProviderError.Timeout)
          case other                                   => fail(s"expected a timeout, received $other")
    }

    test("a failing provider call never renders the token in its error") {
      withServer(401, """{"ok":false}""").use: slack =>
        client(slack.uri).dispatch(target, query("roadmap"), token).attempt.map: outcome =>
          val error = outcome.left.getOrElse(fail("expected a failure"))
          val rendered = error.toString + Option(error.getMessage).getOrElse("") + error.getSuppressed.mkString
          assert(!rendered.contains(tokenText))
          assertEquals(token.toString, "SlackAccessToken(<redacted>)")
    }

    // ---- SlackSearchMessagesOperation ------------------------------------------------------------------------------
    private def decoded(json: String): Either[ArgumentError, String] =
      SlackSearchMessagesOperation.decode(parse(json).getOrElse(fail("json"))).map(_.value)

    test("decode accepts exactly {\"query\": string}") {
      assertEquals(decoded("""{"query":"roadmap"}"""), Right("roadmap"))
      assertEquals(decoded("""{"query":"from:alex in:#general"}"""), Right("from:alex in:#general"))
      assertEquals(decoded(Json.obj("query" -> Json.fromString("x" * 1000)).noSpaces), Right("x" * 1000))
    }

    test("decode rejects a non-object") {
      List("\"roadmap\"", "[\"roadmap\"]", "42", "null", "true").foreach: json =>
        assertEquals(decoded(json), Left(ArgumentError.NotAnObject), json)
    }

    test("decode rejects any extra field") {
      assertEquals(decoded("""{"query":"roadmap","count":5}"""), Left(ArgumentError.UnexpectedField))
      assertEquals(decoded("""{"query":"roadmap","query2":"x"}"""), Left(ArgumentError.UnexpectedField))
      assertEquals(decoded("""{"count":5}"""), Left(ArgumentError.UnexpectedField))
    }

    test("decode reports a missing query") {
      assertEquals(decoded("{}"), Left(ArgumentError.MissingField("query")))
    }

    test("decode rejects a blank, oversized, or non-string query") {
      val invalid = Left(ArgumentError.InvalidField("query"))
      assertEquals(decoded("""{"query":""}"""), invalid)
      assertEquals(decoded("""{"query":"   "}"""), invalid)
      assertEquals(decoded(Json.obj("query" -> Json.fromString("x" * 1001)).noSpaces), invalid)
      assertEquals(decoded("""{"query":123}"""), invalid)
      assertEquals(decoded("""{"query":null}"""), invalid)
      assertEquals(decoded("""{"query":["roadmap"]}"""), invalid)
      assertEquals(decoded("""{"query":{"text":"roadmap"}}"""), invalid)
    }

    test("canonical input is stable, key-complete, and distinct for distinct queries") {
      val a = SlackSearchMessagesOperation.canonical(query("roadmap"))
      assertEquals(a, Json.obj("query" -> Json.fromString("roadmap")))
      assertEquals(a, SlackSearchMessagesOperation.canonical(query("roadmap")))
      assertNotEquals(a, SlackSearchMessagesOperation.canonical(query("roadmap ")))
      assertNotEquals(a, SlackSearchMessagesOperation.canonical(query("Roadmap")))
    }

    test("the operation is workspace-rooted: it locates the connection root and supplies no constraint facts") {
      assertEquals(SlackSearchMessagesOperation.locate(query("roadmap")), ResourceLocator.ConnectionRoot[Slack.Workspace]())
      assertEquals(SlackSearchMessagesOperation.facts(query("roadmap")), run.hallpass.kernel.AuthorizationContext.empty)
    }

    // ---- SlackConnectionCredentials --------------------------------------------------------------------------------
    private def resolverReturning(
        result: Either[ConnectionError, ProviderSecret],
        calls: AtomicInteger = new AtomicInteger(0)
    ): ConnectionResolver[IO] = new ConnectionResolver[IO]:
      def activeConnectionFor(lease: RedeemedExecutionLease): IO[Either[ConnectionError, ResolvedConnection]] =
        IO(calls.incrementAndGet()) *> IO.pure(
          result.map: secret =>
            val now = java.time.Instant.parse("2026-09-01T12:00:00Z")
            ResolvedConnection(
              Connection(ConnectionId.random(), ResourceId.random(), "slack", ConnectionStatus.Active, None, None, None, now, now),
              secret
            )
        )

    private def credentialsFor(result: Either[ConnectionError, ProviderSecret]): IO[Either[ConnectionError, SlackAccessToken]] =
      for
        lease <- SlackSearchTestSupport.redeemedLease(query("roadmap"))
        outcome <- SlackConnectionCredentials(resolverReturning(result)).credentialFor(lease, target)
      yield outcome

    test("a stored secret that is not a valid token is MissingCredential") {
      for
        empty <- credentialsFor(Right(ProviderSecret.fromUtf8("")))
        spaced <- credentialsFor(Right(ProviderSecret.fromUtf8("xoxp test")))
        newline <- credentialsFor(Right(ProviderSecret.fromUtf8("xoxp-test\n")))
        invalidUtf8 <- credentialsFor(Right(ProviderSecret.fromBytes(Array(0xff, 0x20, 0xfe).map(_.toByte))))
      yield
        assertEquals(empty.left.toOption, Some(ConnectionError.MissingCredential))
        assertEquals(spaced.left.toOption, Some(ConnectionError.MissingCredential))
        assertEquals(newline.left.toOption, Some(ConnectionError.MissingCredential))
        assertEquals(invalidUtf8.left.toOption, Some(ConnectionError.MissingCredential))
    }

    test("a connection failure from the resolver passes through unchanged") {
      ConnectionError.values.toVector.foldLeft(IO.unit): (previous, error) =>
        previous *> credentialsFor(Left(error)).map(outcome => assertEquals(outcome.left.toOption, Some(error)))
    }

    test("a valid stored secret yields a token that renders redacted and authenticates the request") {
      withServer().use: slack =>
        for
          outcome <- credentialsFor(Right(ProviderSecret.fromUtf8(tokenText)))
          resolved = outcome.getOrElse(fail(s"expected a token, received $outcome"))
          _ <- client(slack.uri).dispatch(target, query("roadmap"), resolved)
        yield
          assertEquals(resolved.toString, "SlackAccessToken(<redacted>)")
          assertEquals(slack.captured.get.head.headers.get("authorization"), Some("Bearer " + tokenText))
    }

    test("the credential strategy resolves the connection once per call") {
      val calls = new AtomicInteger(0)
      for
        lease <- SlackSearchTestSupport.redeemedLease(query("roadmap"))
        _ <- SlackConnectionCredentials(resolverReturning(Right(ProviderSecret.fromUtf8(tokenText)), calls))
          .credentialFor(lease, target)
      yield assertEquals(calls.get, 1)
    }
