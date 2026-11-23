package run.hallpass.gateway

import java.net.URI
import java.util.Base64
import java.nio.charset.StandardCharsets
import java.time.Instant
import com.sun.net.httpserver.Headers
import cats.effect.IO
import cats.effect.kernel.Ref
import cats.syntax.all.*
import munit.CatsEffectSuite
import io.circe.Json
import run.hallpass.adapters.slack.{Slack, SlackAccessToken, SlackExecutorAudience, SlackSearchMessagesOperation}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*
import run.hallpass.kernel.authorization.AuthorizedCapability.*

final class AgentApiSuite extends CatsEffectSuite:
  private val slackReadKey = CapabilityKey.parse("Slack.Message.Read").getOrElse(fail("capability key"))
  private val tenant = TenantId.random()
  private val agentId = AgentId.random()
  private val credentialId = AgentCredentialId.random()
  private val selector = AgentCredentialSelector.parse("abcdefghijklmnop").getOrElse(fail("selector"))
  private val credential = "ac1.abcdefghijklmnop.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  private val now = Instant.parse("2026-09-20T12:00:00Z")
  private val SlackCallPath = AgentApi.callPath("slack_search_messages")

  test("authentication reads the injected clock on execution and rejects exact credential expiry") {
    val expiresAt = now.plusSeconds(60)
    for
      time <- Ref.of[IO, Instant](now)
      observed <- Ref.of[IO, Vector[Instant]](Vector.empty)
      clock = new Clock[IO]:
        def now = time.get
      repository = new AgentCredentialAuthenticationRepository[IO]:
        def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) =
          observed.update(_ :+ at).as(
            if at.isBefore(expiresAt) then Right(stored(agentId, selector, 1))
            else Left(AgentCredentialLookupError.Expired)
          )
        def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
      verifier = new AgentCredentialVerifier[IO]:
        def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) = IO.pure(true)
      pending = identityCall(apiWithRepository(repository, verifier, clock), credential)
      before <- observed.get
      _ <- time.set(expiresAt)
      expired <- pending
      _ <- time.set(expiresAt.minusNanos(1))
      active <- pending
      checked <- observed.get
    yield
      assertEquals(before, Vector.empty)
      assertEquals(expired.status, 401)
      assertEquals(active.status, 200)
      assertEquals(checked, Vector(expiresAt, expiresAt.minusNanos(1)))
  }

  test("agent routes reject missing bearer authentication before tool access") {
    val repository = new Credentials
    api(repository)
      .handle("GET", AgentApi.ToolsPath, headers(), URI.create("http://127.0.0.1:8081" + AgentApi.ToolsPath), Array.emptyByteArray)
      .map: response =>
        assertEquals(response.status, 401)
        assertEquals(response.headers.get("Cache-Control"), Some("no-store"))
        assertEquals(repository.lookups, 0)
  }

  test("identity rejects missing and malformed bearer credentials before lookup") {
    val repository = new Credentials
    val agentApi = api(repository)
    val uri = URI.create("http://127.0.0.1:8081" + AgentApi.IdentityPath)

    for
      missing <- agentApi.handle("GET", AgentApi.IdentityPath, headers(), uri, Array.emptyByteArray)
      malformed <- agentApi.handle("GET", AgentApi.IdentityPath, headers("Authorization" -> "Bearer malformed"), uri, Array.emptyByteArray)
    yield
      assertEquals(missing.status, 401)
      assertEquals(malformed.status, 401)
      assertEquals(repository.lookups, 0)
      assertEquals(missing.headers.get("Cache-Control"), Some("no-store"))
  }

  test("identity returns only the authenticated agent ID without consulting authority") {
    val repository = new Credentials
    identityCall(api(repository), credential).map: response =>
      assertEquals(response.status, 200)
      assertEquals(response.body, io.circe.Json.obj("agentId" -> io.circe.Json.fromString(agentId.toString)))
      assertEquals(response.body.asObject.map(_.keys.toSet), Some(Set("agentId")))
      assertEquals(response.headers.get("Cache-Control"), Some("no-store"))
      assertEquals(repository.lookups, 1)
  }

  test("identity is selected by each credential and cannot select another agent") {
    val agentA = AgentId.random()
    val agentB = AgentId.random()
    val selectorA = AgentCredentialSelector.parse("identitycredentialA1").getOrElse(fail("selector A"))
    val selectorB = AgentCredentialSelector.parse("identitycredentialB2").getOrElse(fail("selector B"))
    val credentialA = credentialFor(selectorA.value, 8)
    val credentialB = credentialFor(selectorB.value, 9)
    val repository = new MultiAgentCredentials(Vector(stored(agentA, selectorA, 8), stored(agentB, selectorB, 9)))
    val api = apiWithRepository(repository, new AgentCredentialVerifier[IO]:
      def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) = IO.pure(true)
    )

    for
      responseA <- identityCall(api, credentialA)
      responseB <- identityCall(api, credentialB)
    yield
      assertEquals(responseA.body.hcursor.get[String]("agentId").toOption, Some(agentA.toString))
      assertEquals(responseB.body.hcursor.get[String]("agentId").toOption, Some(agentB.toString))
  }

  test("identity rejects a wrong secret and revoked credential without disclosing an ID") {
    val badVerifier = new AgentCredentialVerifier[IO]:
      def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) = IO.pure(false)
    val revokedRepository = new AgentCredentialAuthenticationRepository[IO]:
      def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) = IO.pure(Left(AgentCredentialLookupError.Revoked))
      def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
    val expiredRepository = new AgentCredentialAuthenticationRepository[IO]:
      def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) = IO.pure(Left(AgentCredentialLookupError.Expired))
      def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
    val acceptingVerifier = new AgentCredentialVerifier[IO]:
      def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) = IO.pure(true)

    for
      wrong <- identityCall(apiWithRepository(new Credentials, badVerifier), credential)
      revoked <- identityCall(apiWithRepository(revokedRepository, acceptingVerifier), credential)
      expired <- identityCall(apiWithRepository(expiredRepository, acceptingVerifier), credential)
    yield
      assertEquals(wrong.status, 401)
      assertEquals(wrong.body.hcursor.get[String]("error").toOption, Some("authentication_required"))
      assertEquals(wrong.body.hcursor.get[String]("agentId").toOption, None)
      assertEquals(revoked.status, 401)
      assertEquals(revoked.body.hcursor.get[String]("agentId").toOption, None)
      assertEquals(expired.status, 401)
      assertEquals(expired.body.hcursor.get[String]("agentId").toOption, None)
  }

  test("identity maps authentication infrastructure failures to service unavailable") {
    val repository = new AgentCredentialAuthenticationRepository[IO]:
      def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) = IO.raiseError[Either[AgentCredentialLookupError, StoredAgentCredential]](IllegalStateException("database unavailable"))
      def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))

    identityCall(apiWithRepository(repository, new AgentCredentialVerifier[IO]:
      def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) = IO.pure(true)
    ), credential).map: response =>
      assertEquals(response.status, 503)
      assertEquals(response.body.hcursor.get[String]("agentId").toOption, None)
  }

  test("the agent listener does not dispatch admin routes") {
    val repository = new Credentials
    api(repository)
      .handle("GET", "/api/agents", headers(), URI.create("http://127.0.0.1:8081/api/agents"), Array.emptyByteArray)
      .map: response =>
        assertEquals(response.status, 404)
        assertEquals(repository.lookups, 0)
  }

  test("tool discovery returns service unavailable when authority persistence fails") {
    val authority = authorityOf((_, _, _) => IO.pure(Left(AuthorityLoadError.PersistenceFailure)))

    pipeline(authority).flatMap: pipeline =>
      val agentApi = apiWithTools(new MultiAgentCredentials(Vector(stored(agentId, selector, 3))), pipeline.tools)
      agentApi
        .handle("GET", AgentApi.ToolsPath, headers("Authorization" -> s"Bearer $credential"), URI.create("http://127.0.0.1:8081" + AgentApi.ToolsPath), Array.emptyByteArray)
        .map: response =>
          assertEquals(response.status, 503)
          assertEquals(response.body.hcursor.get[String]("error").toOption, Some("service_unavailable"))
          assertEquals(response.body.hcursor.downField("tools").focus, None, "no partial list on a discovery failure")
  }

  test("unmapped agent calls return 403 without issuing a lease or reaching the provider") {
    val selector = AgentCredentialSelector.parse("abcdefghijklmnop").getOrElse(fail("selector"))
    val presented = credentialFor(selector.value, 3)
    val authority = authorityOf((_, _, _) => IO.pure(Left(AuthorityLoadError.UnmappedTool)))

    for
      pipeline <- pipeline(authority)
      api = apiWithTools(new MultiAgentCredentials(Vector(stored(agentId, selector, 3))), pipeline.tools)
      response <- call(api, presented)
      audit <- pipeline.audit.recorded
    yield
      assertEquals(response.status, 403)
      assertEquals(response.body.hcursor.get[String]("error").toOption, Some("authorization_denied"))
      assertEquals(pipeline.broker.requestIds, Vector.empty)
      assertEquals(pipeline.client.dispatches, Vector.empty)
      assertEquals(audit, Vector.empty)
  }

  test("authenticated calls require strict JSON and never accept identity fields") {
    val repository = new Credentials
    val authority = authorityOf((_, _, _) => IO.raiseError(AssertionError("an invalid body must not load authority")))
    pipeline(authority).flatMap: pipeline =>
      api(repository, Some(pipeline.tools))
        .handle(
          "POST",
          SlackCallPath,
          headers("Authorization" -> s"Bearer $credential", "Content-Type" -> "application/json"),
          URI.create("http://127.0.0.1:8081" + SlackCallPath),
          "{\"query\":\"roadmap\",\"agentId\":\"attacker\"}".getBytes(StandardCharsets.UTF_8)
        )
        .map: response =>
          assertEquals(response.status, 400)
          assertEquals(response.body.hcursor.get[String]("error").toOption, Some("invalid_request"))
          assertEquals(response.headers.get("Cache-Control"), Some("no-store"))
          assertEquals(repository.lookups, 1)
          assertEquals(pipeline.broker.requestIds, Vector.empty)
          assertEquals(pipeline.client.dispatches, Vector.empty)
  }

  test("malformed, non-object, incomplete, oversized, and mistyped bodies never reach authorization or the provider") {
    val repository = new Credentials
    val authority = authorityOf((_, _, _) => IO.raiseError(AssertionError("an invalid body must not load authority")))
    def post(agentApi: AgentApi, contentType: String, body: Array[Byte]) =
      agentApi.handle(
        "POST",
        SlackCallPath,
        headers("Authorization" -> s"Bearer $credential", "Content-Type" -> contentType),
        URI.create("http://127.0.0.1:8081" + SlackCallPath),
        body
      )
    def text(value: String) = value.getBytes(StandardCharsets.UTF_8)
    pipeline(authority).flatMap: pipeline =>
      val agentApi = api(repository, Some(pipeline.tools))
      for
        notJson <- post(agentApi, "application/json", text("not json"))
        array <- post(agentApi, "application/json", text("[]"))
        empty <- post(agentApi, "application/json", text("{}"))
        blank <- post(agentApi, "application/json", text("{\"query\":\"  \"}"))
        number <- post(agentApi, "application/json", text("{\"query\":7}"))
        oversized <- post(agentApi, "application/json", Array.fill[Byte](AgentApi.MaximumBodyBytes + 1)('a'.toByte))
        wrongType <- post(agentApi, "text/plain", text("{\"query\":\"roadmap\"}"))
      yield
        assertEquals(Vector(notJson, array, empty, blank, number).map(_.status), Vector.fill(5)(400))
        assertEquals(oversized.status, 413)
        assertEquals(wrongType.status, 415)
        assertEquals(pipeline.broker.requestIds, Vector.empty)
        assertEquals(pipeline.client.dispatches, Vector.empty)
  }

  test("the isolated listener has no management or legacy execution routes") {
    val repository = new Credentials
    api(repository)
      .handle(
        "POST",
        "/api/agents/00000000-0000-4000-8000-000000000000/tools/slack_search_messages/call",
        headers(),
        URI.create("http://127.0.0.1:8081/api/agents/00000000-0000-4000-8000-000000000000/tools/slack_search_messages/call"),
        Array.emptyByteArray
      )
      .map: response =>
        assertEquals(response.status, 404)
        assertEquals(repository.lookups, 0)
  }

  test("an authorized call whose provider connection is missing or unreadable is 424, never a generic outage") {
    val agent = AgentId.random()
    val human: Principal.Human = Principal.Human(UserId.random())
    val resource = Resource(ResourceId.random(), tenant, ResourceType.Account, None, "slack-workspace", None)
    val descriptor = CapabilityDescriptor(resource.id, Action.Read, slackReadKey)
    val capability = CatalogCapability("10000000-0000-4000-8000-000000000010", "Slack.Message.Read", descriptor)
    val policy = Policies(Vector(Policy(
      PolicyId.random(),
      PolicyVersion.from(1).getOrElse(fail("policy version")),
      NonEmptySet.one(PolicyStatement(human, resource.id, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow))
    )))
    val grant = delegation(human, agent, descriptor)
    val authority = authorityOf: (_, _, _) =>
      IO.pure(Right(AuthoritySnapshot(ResourceScope.fromPath(Vector(resource)).getOrElse(throw new AssertionError("scope")), capability, policy, Vector(grant), Some(ResourceId.random()))))
    def credentialsFailingWith(error: ConnectionError) = new CredentialStrategy[Slack.Workspace, SlackAccessToken]:
      def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[Slack.Workspace]) = IO.pure(Left(error))
    def respond(
        client: RecordingSlackClient = new RecordingSlackClient,
        credentials: CredentialStrategy[Slack.Workspace, SlackAccessToken] = staticCredentials
    ) =
      pipeline(authority, resource, client = client, credentials = credentials).flatMap: pipeline =>
        call(apiWithTools(new MultiAgentCredentials(Vector(stored(agent, selector, 3))), pipeline.tools), credential)
          .map(response => (response, pipeline))
    for
      missing <- respond(credentials = credentialsFailingWith(ConnectionError.NotFound))
      unreadable <- respond(credentials = credentialsFailingWith(ConnectionError.MissingCredential))
      disabled <- respond(credentials = credentialsFailingWith(ConnectionError.Disabled))
      authRejected <- respond(client = new RecordingSlackClient(Some(ProviderExecutionException(ProviderError.AuthenticationFailed))))
      upstream <- respond(client = new RecordingSlackClient(Some(ProviderExecutionException(ProviderError.Rejected))))
      unknown <- respond(client = new RecordingSlackClient(Some(ProviderExecutionException(ProviderError.OutcomeUnknown))))
      healthy <- respond()
    yield
      assertEquals(unknown._1.status, 502)
      assertEquals(unknown._1.body.hcursor.get[String]("error").toOption, Some("outcome_unknown"))
      assertEquals(missing._1.status, 424)
      assertEquals(missing._1.body.hcursor.get[String]("error").toOption, Some("connection_unavailable"))
      assertEquals(unreadable._1.status, 424)
      assertEquals(disabled._1.status, 424)
      // No provider request is sent when the connection cannot supply a credential.
      assertEquals(Vector(missing, unreadable, disabled).flatMap(_._2.client.dispatches), Vector.empty)
      assertEquals(authRejected._1.status, 503, "a provider authentication failure stays a generic outage")
      assertEquals(upstream._1.status, 503, "other provider failures stay a generic outage")
      assertEquals(healthy._1.status, 200)
      assertEquals(healthy._2.client.dispatches.size, 1)
  }

  test("three authenticated agents share one trusted tool while grant revocation stays isolated") {
    val agentA = AgentId.random()
    val agentB = AgentId.random()
    val agentC = AgentId.random()
    val selectorA = AgentCredentialSelector.parse("codexcredential01").getOrElse(fail("selector A"))
    val selectorB = AgentCredentialSelector.parse("claudecodecred02").getOrElse(fail("selector B"))
    val selectorC = AgentCredentialSelector.parse("antigravitycred03").getOrElse(fail("selector C"))
    val credentialA = credentialFor(selectorA.value, 3)
    val credentialB = credentialFor(selectorB.value, 4)
    val credentialC = credentialFor(selectorC.value, 5)
    val human: Principal.Human = Principal.Human(UserId.random())
    val resource = Resource(ResourceId.random(), tenant, ResourceType.Account, None, "shared-slack-workspace", None)
    val descriptor = CapabilityDescriptor(resource.id, Action.Read, slackReadKey)
    val capability = CatalogCapability("10000000-0000-4000-8000-000000000010", "Slack.Message.Read", descriptor)
    val trustedToolId = ResourceId.random()
    val policy = Policies(Vector(Policy(
      PolicyId.random(),
      PolicyVersion.from(1).getOrElse(fail("policy version")),
      NonEmptySet.one(PolicyStatement(human, resource.id, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow))
    )))
    val delegationA = delegation(human, agentA, descriptor)
    val delegationB = delegation(human, agentB, descriptor)
    val delegationC = delegation(human, agentC, descriptor)

    for
      activeDelegations <- Ref.of[IO, Vector[Delegation]](Vector(delegationA, delegationB, delegationC))
      authorityCalls <- Ref.of[IO, Vector[Principal]](Vector.empty)
      repository = new MultiAgentCredentials(Vector(stored(agentA, selectorA, 3), stored(agentB, selectorB, 4), stored(agentC, selectorC, 5)))
      authority = authorityOf: (_, principal, externalTool) =>
        authorityCalls.update(_ :+ principal).flatMap: _ =>
          if externalTool != "slack_search_messages" then IO.pure(Left(AuthorityLoadError.UnmappedTool))
          else activeDelegations.get.map(ds => Right(AuthoritySnapshot(ResourceScope.fromPath(Vector(resource)).getOrElse(throw new AssertionError("scope")), capability, policy, ds.filter(_.grantee == principal), Some(trustedToolId))))
      pipeline <- pipeline(authority, resource)
      broker = pipeline.broker
      api = apiWithTools(repository, pipeline.tools)
      discoverA <- api.handle("GET", AgentApi.ToolsPath, headers("Authorization" -> s"Bearer $credentialA"), URI.create("http://127.0.0.1:8081" + AgentApi.ToolsPath), Array.emptyByteArray)
      discoverB <- api.handle("GET", AgentApi.ToolsPath, headers("Authorization" -> s"Bearer $credentialB"), URI.create("http://127.0.0.1:8081" + AgentApi.ToolsPath), Array.emptyByteArray)
      discoverC <- api.handle("GET", AgentApi.ToolsPath, headers("Authorization" -> s"Bearer $credentialC"), URI.create("http://127.0.0.1:8081" + AgentApi.ToolsPath), Array.emptyByteArray)
      _ <- activeDelegations.update(_.map(value => if value.id == delegationA.id then value.copy(revokedAt = Some(now.plusSeconds(1))) else value))
      discoverAAfterRevoke <- api.handle("GET", AgentApi.ToolsPath, headers("Authorization" -> s"Bearer $credentialA"), URI.create("http://127.0.0.1:8081" + AgentApi.ToolsPath), Array.emptyByteArray)
      deniedA <- call(api, credentialA)
      leasesAfterDeniedA = broker.requestIds.size
      executionsAfterDeniedA = pipeline.client.dispatches.size
      allowedB <- call(api, credentialB)
      allowedC <- call(api, credentialC)
      seen <- authorityCalls.get
      audit <- pipeline.audit.recorded
    yield
      assertEquals(discoverA.body.hcursor.downField("tools").focus.flatMap(_.asArray).map(_.size), Some(1))
      assertEquals(discoverB.body.hcursor.downField("tools").focus.flatMap(_.asArray).map(_.size), Some(1))
      assertEquals(discoverC.body.hcursor.downField("tools").focus.flatMap(_.asArray).map(_.size), Some(1))
      assertEquals(discoverAAfterRevoke.body.hcursor.downField("tools").focus.flatMap(_.asArray).map(_.size), Some(0))
      assertEquals(deniedA.status, 403)
      assertEquals(leasesAfterDeniedA, 0)
      assertEquals(executionsAfterDeniedA, 0)
      assertEquals(allowedB.status, 200)
      assertEquals(allowedC.status, 200)
      assertEquals(seen.toSet, Set(Principal.Agent(agentA), Principal.Agent(agentB), Principal.Agent(agentC)))
      assertEquals(broker.requestIds.size, 2)
      assertEquals(pipeline.client.dispatches.size, 2)
      val executed = audit.collect { case ExecutionAuditEvent.ExecutionCompleted(context, _) => (context.agentId, context.tenant) }
      assertEquals(executed, Vector((agentB, tenant), (agentC, tenant)))
  }

  // ---- Generic operation routing ----

  /** A second operation over the same Slack workspace kind, so the registry holds two tools. Its decoder accepts any
    * JSON object; it exists to show that the legacy bare-body alias is scoped to `slack_search_messages`. */
  private object EchoOperation extends OperationDescriptor[Json, Slack.Workspace]:
    val id: OperationId = OperationId.parse("fake.echo@1").getOrElse(throw AssertionError("operation id"))
    val tool: ExternalToolId = ExternalToolId.parse("fake_echo").getOrElse(throw AssertionError("tool id"))
    val description: String = "Echo an object."
    val capability: CapabilityKey = slackReadKey
    val action: Action = Action.Read
    val target: ResourceKind[Slack.Workspace] = Slack.workspace
    val audience: ExecutorAudience = SlackExecutorAudience.local
    val inputSchema: Json = Json.obj("type" -> Json.fromString("object"))
    def decode(arguments: Json): Either[ArgumentError, Json] = arguments.asObject.as(arguments).toRight(ArgumentError.NotAnObject)
    def locate(input: Json): ResourceLocator[Slack.Workspace] = ResourceLocator.ConnectionRoot()
    def facts(input: Json): AuthorizationContext = AuthorizationContext.empty
    def canonical(input: Json): Json = input

  private final class EchoClient extends ProviderOperationClient[Json, Slack.Workspace, SlackAccessToken]:
    var dispatches = Vector.empty[Json]
    def dispatch(target: SelectedResource[Slack.Workspace], input: Json, credential: SlackAccessToken) =
      IO.delay { dispatches = dispatches :+ input }.as(ToolResult("echoed"))

  private final class CountingJournal extends AuthorizationJournal[IO]:
    var rows = 0
    def record(t: TenantId, event: AuthorizationEvent) = IO.delay { rows = rows + 1 }
    def recent(t: TenantId, limit: Int) = IO.pure(Vector.empty)

  private final class AuthorityLoads:
    var count = 0

  /** A fully authorized agent over the shared Slack workspace, counting every authority load. */
  private def grantedAuthority(agent: AgentId, loads: AuthorityLoads, effect: Effect = Effect.Allow): (Resource, AuthorityRepository[IO]) =
    val human: Principal.Human = Principal.Human(UserId.random())
    val resource = Resource(ResourceId.random(), tenant, ResourceType.Account, None, "slack-workspace", None)
    val descriptor = CapabilityDescriptor(resource.id, Action.Read, slackReadKey)
    val capability = CatalogCapability("10000000-0000-4000-8000-000000000010", "Slack.Message.Read", descriptor)
    val policy = Policies(Vector(Policy(
      PolicyId.random(),
      PolicyVersion.from(1).getOrElse(fail("policy version")),
      NonEmptySet.one(PolicyStatement(human, resource.id, NonEmptySet.one(Action.Read), None, Constraints.empty, effect))
    )))
    val grant = delegation(human, agent, descriptor)
    resource -> authorityOf: (_, _, _) =>
      IO.delay { loads.count = loads.count + 1 } *>
        IO.pure(Right(AuthoritySnapshot(ResourceScope.fromPath(Vector(resource)).getOrElse(throw AssertionError("scope")), capability, policy, Vector(grant), Some(ResourceId.random()))))

  private def post(api: AgentApi, path: String, body: String, bearer: Option[String] = Some(credential), contentType: String = "application/json") =
    api.handle(
      "POST",
      path,
      headers((bearer.map(value => "Authorization" -> s"Bearer $value").toList :+ ("Content-Type" -> contentType))*),
      URI.create("http://127.0.0.1:8081" + path),
      body.getBytes(StandardCharsets.UTF_8)
    )

  private final class TwoToolFixture(
      val api: AgentApi,
      val pipeline: Pipeline,
      val echo: EchoClient,
      val loads: AuthorityLoads,
      val journal: CountingJournal
  )

  private def twoToolFixture: IO[TwoToolFixture] =
    val loads = AuthorityLoads()
    val journal = CountingJournal()
    val echo = EchoClient()
    val (resource, authority) = grantedAuthority(agentId, loads)
    pipeline(
      authority,
      resource,
      journal = journal,
      extraOperations = Vector(RegisteredOperation(EchoOperation, echo, staticCredentials))
    ).map: pipeline =>
      TwoToolFixture(apiWithTools(new MultiAgentCredentials(Vector(stored(agentId, selector, 3))), pipeline.tools), pipeline, echo, loads, journal)

  private val bearer3 = credentialFor(selector.value, 3)

  test("tool listing returns every visible operation with its name, description, and input schema, in registry order") {
    twoToolFixture.flatMap: fixture =>
      fixture.api
        .handle("GET", AgentApi.ToolsPath, headers("Authorization" -> s"Bearer $bearer3"), URI.create("http://127.0.0.1:8081" + AgentApi.ToolsPath), Array.emptyByteArray)
        .map: response =>
          assertEquals(response.status, 200)
          assertEquals(response.headers.get("Cache-Control"), Some("no-store"))
          assertEquals(
            response.body,
            Json.obj(
              "tools" -> Json.arr(
                Json.obj(
                  "name" -> Json.fromString("fake_echo"),
                  "description" -> Json.fromString(EchoOperation.description),
                  "inputSchema" -> EchoOperation.inputSchema
                ),
                Json.obj(
                  "name" -> Json.fromString("slack_search_messages"),
                  "description" -> Json.fromString(SlackSearchMessagesOperation.description),
                  "inputSchema" -> SlackSearchMessagesOperation.inputSchema
                )
              )
            )
          )
          assertEquals(SlackSearchMessagesOperation.description, "Search messages in the configured Slack workspace.")
  }

  test("the arguments envelope succeeds on the generic call path for each operation") {
    twoToolFixture.flatMap: fixture =>
      for
        slack <- post(fixture.api, AgentApi.callPath("slack_search_messages"), """{"arguments":{"query":"x"}}""", Some(bearer3))
        echo <- post(fixture.api, AgentApi.callPath("fake_echo"), """{"arguments":{"hello":"world"}}""", Some(bearer3))
      yield
        assertEquals(slack.status, 200)
        assertEquals(slack.body.hcursor.get[String]("content").toOption, Some("sanitized"))
        assert(slack.body.hcursor.get[String]("correlationId").isRight)
        assertEquals(fixture.pipeline.client.dispatches.map(_.value), Vector("x"))
        assertEquals(echo.status, 200)
        assertEquals(fixture.echo.dispatches, Vector(Json.obj("hello" -> Json.fromString("world"))))
  }

  test("the legacy bare body is still accepted for slack_search_messages only") {
    twoToolFixture.flatMap: fixture =>
      for
        slack <- post(fixture.api, AgentApi.callPath("slack_search_messages"), """{"query":"x"}""", Some(bearer3))
        echoBare <- post(fixture.api, AgentApi.callPath("fake_echo"), """{"hello":"world"}""", Some(bearer3))
        echoEmpty <- post(fixture.api, AgentApi.callPath("fake_echo"), "{}", Some(bearer3))
      yield
        assertEquals(slack.status, 200)
        assertEquals(fixture.pipeline.client.dispatches.map(_.value), Vector("x"))
        assertEquals(echoBare.status, 400)
        assertEquals(echoEmpty.status, 400)
        assertEquals(echoBare.body.hcursor.get[String]("error").toOption, Some("invalid_request"))
        assertEquals(fixture.echo.dispatches, Vector.empty)
  }

  test("an unknown tool name is 404 after authentication, with no authority load or journal row") {
    twoToolFixture.flatMap: fixture =>
      for
        unknown <- post(fixture.api, AgentApi.callPath("not_a_tool"), """{"arguments":{}}""", Some(bearer3))
        // A syntactically valid name differing only by case is a different, unknown tool.
        upper <- post(fixture.api, AgentApi.callPath("SLACK_SEARCH_MESSAGES"), """{"arguments":{"query":"x"}}""", Some(bearer3))
        audit <- fixture.pipeline.audit.recorded
      yield
        assertEquals(unknown.status, 404)
        assertEquals(unknown.body.hcursor.get[String]("error").toOption, Some("not_found"))
        assertEquals(upper.status, 404)
        assertEquals(fixture.loads.count, 0)
        assertEquals(fixture.journal.rows, 0)
        assertEquals(fixture.pipeline.broker.requestIds, Vector.empty)
        assertEquals(fixture.pipeline.client.dispatches, Vector.empty)
        assertEquals(audit, Vector.empty)
  }

  test("an unauthenticated call to an unknown tool name is 401, not 404") {
    twoToolFixture.flatMap: fixture =>
      for
        missing <- post(fixture.api, AgentApi.callPath("not_a_tool"), """{"arguments":{}}""", None)
        malformed <- post(fixture.api, AgentApi.callPath("not_a_tool"), """{"arguments":{}}""", Some("malformed"))
      yield
        assertEquals(missing.status, 401)
        assertEquals(malformed.status, 401)
        assertEquals(fixture.loads.count, 0)
  }

  test("tool names that could smuggle another path or exceed the grammar are 404 before authentication") {
    val repository = new Credentials
    val authority = authorityOf((_, _, _) => IO.raiseError(AssertionError("a malformed route must not load authority")))
    pipeline(authority).flatMap: pipeline =>
      val agentApi = api(repository, Some(pipeline.tools))
      val paths = Vector(
        "/api/agent/tools/a/b/call",
        "/api/agent/tools/slack_search_messages/extra/call",
        "/api/agent/tools/../identity/call",
        "/api/agent/tools/../call",
        "/api/agent/tools/./call",
        "/api/agent/tools/%2Fslack_search_messages/call",
        "/api/agent/tools/slack%5Fsearch%5Fmessages/call",
        "/api/agent/tools/slack_search_messages%2F..%2Fx/call",
        "/api/agent/tools/slack-search-messages/call",
        "/api/agent/tools/slack.search/call",
        "/api/agent/tools/slack search/call",
        "/api/agent/tools//call",
        "/api/agent/tools/call",
        "/api/agent/tools/" + "a" * 65 + "/call",
        "/api/agent/tools/été/call",
        "/api/agent/tools/٣/call",
        "/api/agent/tools/slack_search_messages/call/",
        "/api/agent/tools/slack_search_messages"
      )
      paths
        .traverse: path =>
          agentApi
            .handle("POST", path, headers("Authorization" -> s"Bearer $credential", "Content-Type" -> "application/json"), URI.create("http://127.0.0.1:8081/x"), """{"arguments":{}}""".getBytes(StandardCharsets.UTF_8))
            .map(path -> _)
        .map: responses =>
          responses.foreach: (path, response) =>
            assertEquals(response.status, 404, s"path $path")
            assertEquals(response.body.hcursor.get[String]("error").toOption, Some("not_found"), s"path $path")
          assertEquals(repository.lookups, 0)
          assertEquals(pipeline.client.dispatches, Vector.empty)
  }

  test("a 64-character tool name is routed and unknown, while the route refuses every name outside the grammar") {
    twoToolFixture.flatMap: fixture =>
      post(fixture.api, AgentApi.callPath("a" * 64), """{"arguments":{}}""", Some(bearer3)).map: response =>
        assertEquals(response.status, 404)
        assertEquals(fixture.loads.count, 0)
        assertEquals(AgentApi.CallRoute.unapply(AgentApi.callPath("a" * 64)).map(_.value), Some("a" * 64))
        assertEquals(AgentApi.CallRoute.unapply(AgentApi.callPath("a" * 65)), None)
  }

  test("the call envelope accepts only a single arguments key; every other shape is 400 before authorization") {
    twoToolFixture.flatMap: fixture =>
      val shapes = Vector(
        """{"arguments":{"query":"x"},"extra":1}""",
        """{"arguments":{"query":"x"},"agentId":"attacker"}""",
        """{"arguments":"not-object"}""",
        """{"arguments":null}""",
        """{"arguments":[]}""",
        """[]""",
        "\"text\"",
        "7",
        "null",
        "true",
        "not json"
      )
      shapes
        .traverse(shape => post(fixture.api, AgentApi.callPath("slack_search_messages"), shape, Some(bearer3)).map(shape -> _))
        .map: responses =>
          responses.foreach: (shape, response) =>
            assertEquals(response.status, 400, s"body $shape")
            assertEquals(response.body.hcursor.get[String]("error").toOption, Some("invalid_request"), s"body $shape")
            assertEquals(response.body.hcursor.get[String]("message").toOption, Some("The request body or arguments are invalid."))
          assertEquals(fixture.loads.count, 0)
          assertEquals(fixture.journal.rows, 0)
          assertEquals(fixture.pipeline.broker.requestIds, Vector.empty)
          assertEquals(fixture.pipeline.client.dispatches, Vector.empty)
  }

  test("an arguments envelope is never mixed with the legacy alias and oversized or mistyped bodies keep their status") {
    twoToolFixture.flatMap: fixture =>
      for
        mixed <- post(fixture.api, AgentApi.callPath("slack_search_messages"), """{"query":"x","arguments":{"query":"y"}}""", Some(bearer3))
        oversized <- post(fixture.api, AgentApi.callPath("slack_search_messages"), "a" * (AgentApi.MaximumBodyBytes + 1), Some(bearer3))
        wrongType <- post(fixture.api, AgentApi.callPath("slack_search_messages"), """{"arguments":{"query":"x"}}""", Some(bearer3), "text/plain")
      yield
        assertEquals(mixed.status, 400)
        assertEquals(oversized.status, 413)
        assertEquals(wrongType.status, 415)
        assertEquals(fixture.pipeline.client.dispatches, Vector.empty)
  }

  /** Records what the service asks of the approval store, so the edge's pass-through is observable. */
  private final class SpyApprovals extends ApprovalStore:
    val created = new java.util.concurrent.ConcurrentLinkedQueue[ApprovalRecord]()
    val found = new java.util.concurrent.ConcurrentLinkedQueue[ApprovalId]()
    def create(record: ApprovalRecord) = IO.delay(created.add(record)).void
    def find(tenant: TenantId, id: ApprovalId) = IO.delay(found.add(id)).as(None)
    def pendingFor(tenant: TenantId, approver: Principal.Human, at: Instant, limit: Int) = IO.pure(Vector.empty)
    def decide(tenant: TenantId, id: ApprovalId, approver: Principal.Human, approve: Boolean, at: Instant) =
      IO.pure(Left(ApprovalDecisionError.NotFound))
    def consume(tenant: TenantId, id: ApprovalId, agent: AgentId, binding: ApprovalBinding, request: AuthorizationRequestId, at: Instant) =
      IO.pure(false)

  private def approvalFixture(store: ApprovalStore): IO[TwoToolFixture] =
    val loads = AuthorityLoads()
    val journal = CountingJournal()
    val (resource, authority) = grantedAuthority(agentId, loads, Effect.RequireApproval)
    pipeline(authority, resource, journal = journal, approvals = store).map: pipeline =>
      TwoToolFixture(apiWithTools(new MultiAgentCredentials(Vector(stored(agentId, selector, 3))), pipeline.tools), pipeline, EchoClient(), loads, journal)

  private val slackBody = """{"query":"x"}"""

  test("approval required with a recorded approval is 409 with its ID and expiry") {
    val spy = SpyApprovals()
    approvalFixture(spy).flatMap: fixture =>
      post(fixture.api, SlackCallPath, s"""{"arguments":$slackBody}""", Some(bearer3)).map: response =>
        assertEquals(response.status, 409)
        val body = response.body.hcursor
        assertEquals(body.get[String]("error"), Right("approval_required"))
        assert(body.get[String]("message").exists(_.nonEmpty))
        assertEquals(spy.created.size, 1)
        val record = spy.created.peek()
        assertEquals(body.get[String]("approval_id"), Right(record.id.toString))
        assertEquals(body.get[String]("expires_at"), Right(record.expiresAt.toString))
        assertEquals(fixture.pipeline.client.dispatches, Vector.empty)
  }

  test("approval required without a recorded approval is 409 with no ID or expiry") {
    approvalFixture(ApprovalStore.unavailable).flatMap: fixture =>
      post(fixture.api, SlackCallPath, s"""{"arguments":$slackBody}""", Some(bearer3)).map: response =>
        assertEquals(response.status, 409)
        assertEquals(response.body.hcursor.get[String]("error"), Right("approval_required"))
        assertEquals(response.body.asObject.map(_.keys.toSet), Some(Set("error", "message")))
  }

  test("a presented approval_id reaches the service, and one that grants nothing is 403 without saying why") {
    val spy = SpyApprovals()
    val id = ApprovalId.random()
    approvalFixture(spy).flatMap: fixture =>
      post(fixture.api, SlackCallPath, s"""{"arguments":$slackBody,"approval_id":"$id"}""", Some(bearer3)).map: response =>
        assertEquals(response.status, 403)
        assertEquals(response.body.hcursor.get[String]("error"), Right("authorization_denied"))
        assertEquals(scala.jdk.CollectionConverters.CollectionHasAsScala(spy.found).asScala.toVector, Vector(id))
        assert(spy.created.isEmpty, "a presented approval never falls back to requesting a new one")
        assertEquals(fixture.pipeline.client.dispatches, Vector.empty)
  }

  test("a malformed approval_id is 400 before the service is called") {
    val spy = SpyApprovals()
    approvalFixture(spy).flatMap: fixture =>
      Vector("\"not-a-uuid\"", "42", "null", "\"\"", "{}", "\"" + "A" * 36 + "\"").traverse: value =>
        post(fixture.api, SlackCallPath, s"""{"arguments":$slackBody,"approval_id":$value}""", Some(bearer3)).map(value -> _)
      .map: responses =>
        responses.foreach: (value, response) =>
          assertEquals(response.status, 400, s"approval_id $value")
          assertEquals(response.body.hcursor.get[String]("error"), Right("invalid_request"))
        assertEquals(fixture.loads.count, 0)
        assert(spy.found.isEmpty && spy.created.isEmpty)
  }

  test("telemetry route templates never contain a concrete tool name") {
    assertEquals(RouteTemplates.agent(AgentApi.callPath("slack_search_messages")).toString, "/api/agent/tools/{name}/call")
    assertEquals(RouteTemplates.agent(AgentApi.callPath("anything_else")).toString, "/api/agent/tools/{name}/call")
    assertEquals(RouteTemplates.agent("/api/agent/tools/a/b/call").toString, "other")
    assertEquals(RouteTemplates.agent("/api/agent/tools/%2F/call").toString, "other")
    assertEquals(RouteTemplates.agent("/api/agent/tools").toString, "/api/agent/tools")
  }

  /** Every test credential belongs to `tenant`; routing is covered by AgentAuthenticationSuite and the directory suite. */
  private val routedToTenant: AgentCredentialRoutes[IO] = _ => IO.pure(Right(Some(tenant)))

  private def identityCall(api: AgentApi, credential: String) =
    api.handle(
      "GET",
      AgentApi.IdentityPath,
      headers("Authorization" -> s"Bearer $credential"),
      URI.create("http://127.0.0.1:8081" + AgentApi.IdentityPath),
      Array.emptyByteArray
    )

  private def apiWithRepository(
      repository: AgentCredentialAuthenticationRepository[IO],
      verifier: AgentCredentialVerifier[IO],
      clock: Clock[IO] = Clock.system
  ): AgentApi =
    val authenticator = new AgentAuthenticator[IO](routedToTenant, repository, verifier)
    val credentials = AgentCredentialServices(authenticator, null.asInstanceOf[AgentEnrollmentService[IO]])
    AgentApi(AgentApiDependencies(credentials, None), clock)

  private def api(repository: Credentials, tools: Option[AgentToolService] = None): AgentApi =
    val authenticator = new AgentAuthenticator[IO](routedToTenant, repository, new AgentCredentialVerifier[IO]:
      def matches(
          trusted: TenantId,
          presented: PresentedAgentCredential,
          verifier: StoredAgentCredentialVerifier,
          metadata: CredentialVerifierMetadata
      ): IO[Boolean] = IO.pure(true)
    )
    val credentials = AgentCredentialServices(authenticator, null.asInstanceOf[AgentEnrollmentService[IO]])
    AgentApi(AgentApiDependencies(credentials, tools))

  private final class Credentials extends AgentCredentialAuthenticationRepository[IO]:
    var lookups = 0
    private val stored = new StoredAgentCredential(
      tenant,
      credentialId,
      agentId,
      selector,
      StoredAgentCredentialVerifier.fromBytes(Array.fill(32)(1.toByte)).getOrElse(fail("verifier")),
      CredentialVerifierMetadata(CredentialVerifierAlgorithm.HmacSha256, "test-key"),
      now,
      None,
      None,
      None
    )

    def credentialForAuthentication(
        trusted: TenantId,
        requested: AgentCredentialSelector,
        at: Instant
    ): IO[Either[AgentCredentialLookupError, StoredAgentCredential]] =
      lookups = lookups + 1
      IO.pure(Right(stored))

    def recordSuccessfulAuthentication(
        trusted: TenantId,
        id: AgentCredentialId,
        at: Instant
    ): IO[Either[AgentCredentialUseError, Unit]] = IO.pure(Right(()))

  private def apiWithTools(repository: MultiAgentCredentials, tools: AgentToolService): AgentApi =
    val authenticator = new AgentAuthenticator[IO](routedToTenant, repository, new AgentCredentialVerifier[IO]:
      def matches(trusted: TenantId, presented: PresentedAgentCredential, verifier: StoredAgentCredentialVerifier, metadata: CredentialVerifierMetadata): IO[Boolean] = IO.pure(true)
    )
    val credentials = AgentCredentialServices(authenticator, null.asInstanceOf[AgentEnrollmentService[IO]])
    AgentApi(AgentApiDependencies(credentials, Some(tools)))

  private def call(api: AgentApi, credential: String) =
    api.handle("POST", SlackCallPath, headers("Authorization" -> s"Bearer $credential", "Content-Type" -> "application/json"), URI.create("http://127.0.0.1:8081" + SlackCallPath), "{\"arguments\":{\"query\":\"roadmap\"}}".getBytes(StandardCharsets.UTF_8))

  private def credentialFor(selector: String, seed: Int): String =
    s"ac1.$selector.${Base64.getUrlEncoder.withoutPadding.encodeToString(Array.fill[Byte](32)(seed.toByte))}"

  private def stored(agent: AgentId, selector: AgentCredentialSelector, seed: Int) =
    new StoredAgentCredential(tenant, AgentCredentialId.random(), agent, selector, StoredAgentCredentialVerifier.fromBytes(Array.fill[Byte](32)(seed.toByte)).getOrElse(fail("verifier")), CredentialVerifierMetadata(CredentialVerifierAlgorithm.HmacSha256, "test-key"), now, None, None, None)

  private def delegation(grantor: Principal.Human, grantee: AgentId, descriptor: CapabilityDescriptor) =
    Delegation(DelegationId.random(), grantor, Principal.Agent(grantee), None, NonEmptySet.one(descriptor), Constraints.empty, Instant.EPOCH, None, None)

  private final class MultiAgentCredentials(values: Vector[StoredAgentCredential]) extends AgentCredentialAuthenticationRepository[IO]:
    def credentialForAuthentication(trusted: TenantId, requested: AgentCredentialSelector, at: Instant) =
      IO.pure(values.find(_.selector == requested).toRight(AgentCredentialLookupError.Unknown))
    def recordSuccessfulAuthentication(trusted: TenantId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))

  private val slackResource = Resource(ResourceId.random(), tenant, ResourceType.Account, None, "slack-workspace", None)

  /** Serves the same answer to scoped and unscoped loads: the suite's resource catalog is a single root. */
  private def authorityOf(
      load: (TenantId, Principal, String) => IO[Either[AuthorityLoadError, AuthoritySnapshot]]
  ): AuthorityRepository[IO] =
    new AuthorityRepository[IO]:
      def snapshotFor(t: TenantId, principal: Principal, externalTool: String) = load(t, principal, externalTool)
      def snapshotWithin(t: TenantId, principal: Principal, externalTool: String, scope: ResourceScope) =
        load(t, principal, externalTool)

  /** A catalog whose only root is `resource`; nothing below it is selected. */
  private def catalogOf(resource: Resource): ResourceCatalog =
    val scope = ResourceScope.fromPath(Vector(resource)).getOrElse(throw AssertionError("scope"))
    val externalId = ExternalId.parse(resource.externalId).getOrElse(throw AssertionError("external id"))
    new ResourceCatalog:
      def rootScope(t: TenantId, root: ResourceKind[?]) = IO.pure(Option.when(t == resource.tenant)(externalId -> scope))
      def selectedScope(t: TenantId, kind: ResourceKind[?], id: ExternalId) = IO.pure(None)
      def currentScope(t: TenantId, id: ResourceId) = IO.pure(Option.when(id == resource.id)(scope))

  private final class RecordingSlackClient(failure: Option[Throwable] = None)
      extends ProviderOperationClient[SearchQuery, Slack.Workspace, SlackAccessToken]:
    var dispatches = Vector.empty[SearchQuery]
    def dispatch(target: SelectedResource[Slack.Workspace], input: SearchQuery, credential: SlackAccessToken) =
      IO.delay { dispatches = dispatches :+ input } *> failure.fold(IO.pure(ToolResult("sanitized")))(IO.raiseError)

  private val staticCredentials: CredentialStrategy[Slack.Workspace, SlackAccessToken] =
    new CredentialStrategy[Slack.Workspace, SlackAccessToken]:
      def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[Slack.Workspace]) =
        IO.pure(SlackAccessToken.parse("xoxb-agent-api-suite").left.map(_ => ConnectionError.MissingCredential))

  private val noJournal: AuthorizationJournal[IO] = new AuthorizationJournal[IO]:
    def record(t: TenantId, event: AuthorizationEvent) = IO.unit
    def recent(t: TenantId, limit: Int) = IO.pure(Vector.empty)

  /** Issues real leases (so the store, binding, and audit context are the production ones) and remembers each request. */
  private final class RecordingBroker(delegate: CredentialBroker[IO]) extends CredentialBroker[IO]:
    var requestIds = Vector.empty[AuthorizationRequestId]
    def issueLease(authorized: AuthorizedCapability, requestId: AuthorizationRequestId, audience: ExecutorAudience, auditMetadata: ExecutionAuditMetadata) =
      IO.delay { requestIds = requestIds :+ requestId } *> delegate.issueLease(authorized, requestId, audience, auditMetadata)

  private object AllowCurrentState extends LeaseAuthorityValidator[IO]:
    def validate(lease: RedeemedExecutionLease, at: Instant) = IO.pure(Right(()))

  private final class Pipeline(
      val tools: AgentToolService,
      val broker: RecordingBroker,
      val client: RecordingSlackClient,
      val audit: InMemoryExecutionAuditRecorder
  )

  /** The production pipeline over the Slack search operation, with only the provider edges faked. */
  private def pipeline(
      authority: AuthorityRepository[IO],
      resource: Resource = slackResource,
      journal: AuthorizationJournal[IO] = noJournal,
      client: RecordingSlackClient = new RecordingSlackClient,
      credentials: CredentialStrategy[Slack.Workspace, SlackAccessToken] = staticCredentials,
      extraOperations: Vector[RegisteredOperation[?, ?, ?]] = Vector.empty,
      approvals: ApprovalStore = ApprovalStore.unavailable
  ): IO[Pipeline] =
    for
      store <- InMemoryExecutionLeaseStore.create
      audit <- InMemoryExecutionAuditRecorder.create
      gate <- SingleProcessTenantExecutionMutationGate.create
      broker = new RecordingBroker(InMemoryCredentialBroker(store, Clock.system, java.time.Duration.ofSeconds(60), audit))
      registry <- IO.fromEither(
        OperationRegistry
          .from(Vector(RegisteredOperation(SlackSearchMessagesOperation, client, credentials)) ++ extraOperations)
          .leftMap(error => IllegalStateException(s"invalid operation registry: $error"))
      )
      executor = ProviderExecutionService(store, Clock.system, audit, AllowCurrentState, gate)
    yield Pipeline(
      AgentToolService(registry, ResourceResolver(catalogOf(resource)), authority, journal, broker, executor, approvals = approvals),
      broker,
      client,
      audit
    )

  private def headers(values: (String, String)*): Headers =
    val result = new Headers()
    values.foreach { case (name, value) => result.add(name, value) }
    result
