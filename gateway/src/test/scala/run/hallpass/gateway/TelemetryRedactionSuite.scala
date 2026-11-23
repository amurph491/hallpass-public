package run.hallpass.gateway

import java.time.Instant
import java.util.Base64
import scala.jdk.CollectionConverters.*
import cats.effect.IO
import cats.syntax.all.*
import munit.CatsEffectSuite
import org.http4s.{Header, Headers as Http4sHeaders, Method, Request, Uri}
import org.typelevel.ci.CIString
import org.typelevel.otel4s.oteljava.testkit.OtelJavaTestkit
import run.hallpass.adapters.slack.{Slack, SlackAccessToken, SlackSearchMessagesOperation}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Drives real secrets through the HTTP runtime and the instrumented services, exports every span and metric to an
  * in-memory OpenTelemetry SDK, and checks that no secret appears anywhere in the exported telemetry. */
final class TelemetryRedactionSuite extends CatsEffectSuite:
  private val slackReadKey = CapabilityKey.parse("Slack.Message.Read").getOrElse(fail("capability key"))
  private val tenant = TenantId.random()
  private val now = Instant.parse("2026-09-28T12:00:00Z")
  private val selector = AgentCredentialSelector.parse("redactionselect1").getOrElse(fail("selector"))
  private val bearer = s"ac1.${selector.value}.${Base64.getUrlEncoder.withoutPadding.encodeToString(Array.fill[Byte](32)(9))}"
  private val bearerSecret = bearer.split('.').last
  private val providerToken = "xoxb-provider-token-must-not-leak-7731"
  private val oauthCode = "oauth-code-must-not-leak-5521"
  private val oauthState = "Z" * 43
  private val searchTerm = "confidential-merger-plans"

  private val secrets = Vector(bearer, bearerSecret, selector.value, providerToken, oauthCode, oauthState, searchTerm)

  /** Every attribute key the application may emit. Anything else would mean a new, unreviewed attribute. */
  private val allowedKeys = Set(
    "hallpass.tenant.id", "hallpass.agent.id", "hallpass.request.id", "hallpass.tool", "hallpass.outcome",
    "hallpass.reason", "hallpass.source", "hallpass.kind", "hallpass.gate.mode", "hallpass.listener", "http.route",
    "http.request.method", "http.response.status_class", "error.type"
  )

  test("no bearer credential, provider token, OAuth code or state, or request text reaches spans or metrics") {
    OtelJavaTestkit.inMemory[IO]().use: testkit =>
      for
        tracer <- testkit.tracerProvider.get("redaction-test")
        meter <- testkit.meterProvider.get("redaction-test")
        telemetry <- OtelTelemetry.instruments(tracer, meter)
        lifecycle <- ServerLifecycle.create(Vector.empty)
        gate <- SingleProcessTenantExecutionMutationGate.create.map(Instrumented.gate(_, telemetry))
        agentApi <- agentApiWith(telemetry, gate)
        agentApp = HttpRuntime.app(
          HttpListenerSettings.default,
          lifecycle,
          request => agentApi.handle(request.method, request.path, request.headers, request.uri, request.body),
          HttpObservation(telemetry, SafeAttribute.Label.of("agent"), RouteTemplates.agent)
        )
        managementApp = HttpRuntime.app(
          HttpListenerSettings.default,
          lifecycle,
          _ => IO.pure(DemoApiResponse(303, io.circe.Json.obj(), Map("Location" -> "/admin"))),
          HttpObservation(telemetry, SafeAttribute.Label.of("management"), RouteTemplates.management)
        )
        call <- agentApp.run(
          Request[IO](
            Method.POST,
            Uri.unsafeFromString(AgentApi.callPath("slack_search_messages")),
            headers = Http4sHeaders(Header.Raw(CIString("Authorization"), s"Bearer $bearer"))
          ).withEntity(s"""{"arguments":{"query":"$searchTerm"}}""")
            // withEntity sets text/plain; replace it rather than adding a second Content-Type.
            .putHeaders(Header.Raw(CIString("Content-Type"), "application/json"))
        )
        rejected <- agentApp.run(
          Request[IO](
            Method.GET,
            Uri.unsafeFromString(s"${AgentApi.ToolsPath}?token=$providerToken"),
            headers = Http4sHeaders(Header.Raw(CIString("Authorization"), s"Bearer $bearer"))
          )
        )
        _ <- managementApp.run(
          Request[IO](Method.GET, Uri.unsafeFromString(s"/api/oauth/slack/callback?code=$oauthCode&state=$oauthState"))
        )
        _ <- managementApp.run(Request[IO](Method.GET, Uri.unsafeFromString(s"/api/unknown/$providerToken")))
        // Secret store failures are counted by kind only.
        store = Instrumented.secretStore(failingStore, telemetry)
        _ <- store.get(SecretBinding(tenant, ConnectionId.random()), SecretReference.random())
        spans <- testkit.finishedSpans
        metrics <- testkit.collectMetrics
      yield
        assertEquals(call.status.code, 200)
        assertEquals(rejected.status.code, 401)
        val spanText = spans.flatMap: span =>
          span.getName +: (span.getAttributes.asMap.asScala.toVector.map((key, value) => s"${key.getKey}=$value") ++
            span.getEvents.asScala.toVector.map(_.toString))
        val metricPoints = metrics.flatMap(_.getData.getPoints.asScala.toVector)
        val metricText = metricPoints.flatMap(_.getAttributes.asMap.asScala.toVector.map((key, value) => s"${key.getKey}=$value"))
        val everything = (spanText ++ metricText).mkString("\n")
        secrets.foreach(secret => assert(!everything.contains(secret), s"telemetry contains a secret: $secret"))
        val keys = spans.flatMap(_.getAttributes.asMap.asScala.keys.map(_.getKey)) ++
          metricPoints.flatMap(_.getAttributes.asMap.asScala.keys.map(_.getKey))
        assertEquals(keys.toSet -- allowedKeys, Set.empty[String], "unreviewed telemetry attribute keys")
        // The test is only meaningful if the instrumented path actually ran.
        val names = spans.map(_.getName).toSet
        Vector(
          TraceSpan.HttpRequest, TraceSpan.AgentAuthentication, TraceSpan.AuthorityLoad, TraceSpan.PolicyEvaluation,
          TraceSpan.DecisionRecord, TraceSpan.LeaseIssue, TraceSpan.GateWait
        ).foreach(span => assert(names.contains(span.name), s"missing span ${span.name}: $names"))
        assert(everything.contains("http.route=/api/oauth/{provider}/callback"), "the callback is recorded by template")
        assert(everything.contains("http.route=/api/agent/tools/{name}/call"), "agent calls are recorded by template")
        assert(everything.contains("http.route=other"), "unknown paths are recorded as other")
        assert(everything.contains("hallpass.kind=decryption_failed"), "secret store failures are counted by kind")
  }

  test("the Google Picker configuration route is recorded by its literal template") {
    assertEquals(RouteTemplates.management("/api/connections/google/picker-config").value, "/api/connections/google/picker-config")
    assertEquals(RouteTemplates.management("/api/connections/google/picker-config/x").value, "other")
  }

  test("approval routes are recorded by template, never by approval ID") {
    val id = java.util.UUID.randomUUID().toString
    assertEquals(RouteTemplates.management("/api/approvals").value, "/api/approvals")
    assertEquals(RouteTemplates.management(s"/api/approvals/$id/approve").value, "/api/approvals/{id}/approve")
    assertEquals(RouteTemplates.management(s"/api/approvals/$id/deny").value, "/api/approvals/{id}/deny")
    assertEquals(RouteTemplates.management(s"/api/approvals/$id/other").value, "other")
    assertEquals(RouteTemplates.management(s"/api/approvals/$id").value, "other")
  }

  test("telemetry labels accept only literals and code-defined enum names") {
    val errors = compileErrors("""
      val fromRequest: String = "anything"
      run.hallpass.application.SafeAttribute.Label.of(fromRequest)
    """)
    assert(errors.contains("expression cannot be a constant") || errors.contains("constant"), errors)
    assertEquals(SafeAttribute.Label.of(DenialReason.InactiveDelegation(DelegationId.random())).value, "inactive_delegation")
    assertEquals(SafeAttribute.Label.of(SecretStoreError.DecryptionFailed).value, "decryption_failed")
    assert(compileErrors("""new run.hallpass.application.SafeAttribute("k", "v")""").nonEmpty, "SafeAttribute has no public constructor")
  }

  private val failingStore: SecretStore[IO] = new SecretStore[IO]:
    def put(binding: SecretBinding, secret: ProviderSecret) = IO.raiseError(IllegalStateException(providerToken))
    def get(binding: SecretBinding, reference: SecretReference) = IO.pure(Left(SecretStoreError.DecryptionFailed))
    def delete(binding: SecretBinding, reference: SecretReference) = IO.unit

  /** An agent API whose one agent holds a delegated read on a Slack resource, with a gated executor that returns a
    * provider token in its result. */
  private def agentApiWith(telemetry: Telemetry, gate: TenantExecutionMutationGate[IO]): IO[AgentApi] =
    val agent = AgentId.random()
    val human: Principal.Human = Principal.Human(UserId.random())
    val resource = Resource(ResourceId.random(), tenant, ResourceType.Account, None, "slack", None)
    val descriptor = CapabilityDescriptor(resource.id, Action.Read, slackReadKey)
    val capability = CatalogCapability("10000000-0000-4000-8000-000000000010", "Slack.Message.Read", descriptor)
    val policy = Policies(Vector(Policy(
      PolicyId.random(),
      PolicyVersion.from(1).getOrElse(fail("policy version")),
      NonEmptySet.one(PolicyStatement(human, resource.id, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow))
    )))
    val delegation =
      Delegation(DelegationId.random(), human, Principal.Agent(agent), None, NonEmptySet.one(descriptor), Constraints.empty, Instant.EPOCH, None, None)
    val scope = ResourceScope.fromPath(Vector(resource)).getOrElse(throw new AssertionError("scope"))
    val snapshot = IO.pure(Right(AuthoritySnapshot(scope, capability, policy, Vector(delegation), Some(ResourceId.random()))))
    val authority = new AuthorityRepository[IO]:
      def snapshotFor(t: TenantId, principal: Principal, externalTool: String) = snapshot
      def snapshotWithin(t: TenantId, principal: Principal, externalTool: String, within: ResourceScope) = snapshot
    val catalog = new ResourceCatalog:
      def rootScope(t: TenantId, root: ResourceKind[?]) =
        IO.pure(Some(ExternalId.parse("slack").getOrElse(throw new AssertionError("external id")) -> scope))
      def selectedScope(t: TenantId, kind: ResourceKind[?], externalId: ExternalId) = IO.pure(None)
      def currentScope(t: TenantId, id: ResourceId) = IO.pure(Some(scope))
    val journal = Instrumented.journal(
      new AuthorizationJournal[IO]:
        def record(t: TenantId, event: AuthorizationEvent) = IO.unit
        def recent(t: TenantId, limit: Int) = IO.pure(Vector.empty)
      ,
      telemetry
    )
    val client = new ProviderOperationClient[SearchQuery, Slack.Workspace, SlackAccessToken]:
      def dispatch(target: SelectedResource[Slack.Workspace], input: SearchQuery, credential: SlackAccessToken) =
        IO.pure(ToolResult(s"result with $providerToken"))
    val credentials = new CredentialStrategy[Slack.Workspace, SlackAccessToken]:
      def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[Slack.Workspace]) =
        IO.pure(SlackAccessToken.parse(providerToken).left.map(_ => ConnectionError.MissingCredential))
    val currentState = new LeaseAuthorityValidator[IO]:
      def validate(lease: RedeemedExecutionLease, at: Instant) = IO.pure(Right(()))
    val toolsProgram = for
      store <- InMemoryExecutionLeaseStore.create
      audit <- InMemoryExecutionAuditRecorder.create
      registry <- IO.fromEither(
        OperationRegistry
          .from(Vector(RegisteredOperation(SlackSearchMessagesOperation, client, credentials)))
          .leftMap(error => IllegalStateException(error.toString))
      )
      broker = InMemoryCredentialBroker(store, Clock.system, java.time.Duration.ofSeconds(60), audit)
      executor = ProviderExecutionService(store, Clock.system, audit, currentState, gate, telemetry)
    yield AgentToolService(registry, ResourceResolver(catalog), authority, journal, broker, executor, telemetry)
    val stored = new StoredAgentCredential(
      tenant, AgentCredentialId.random(), agent, selector,
      StoredAgentCredentialVerifier.fromBytes(Array.fill[Byte](32)(9)).getOrElse(fail("verifier")),
      CredentialVerifierMetadata(CredentialVerifierAlgorithm.HmacSha256, "test-key"), now, None, None, None
    )
    val repository = new AgentCredentialAuthenticationRepository[IO]:
      def credentialForAuthentication(t: TenantId, s: AgentCredentialSelector, at: Instant) = IO.pure(Right(stored))
      def recordSuccessfulAuthentication(t: TenantId, id: AgentCredentialId, at: Instant) = IO.pure(Right(()))
    val authenticator = new AgentAuthenticator[IO](_ => IO.pure(Right(Some(tenant))), repository, new AgentCredentialVerifier[IO]:
      def matches(t: TenantId, p: PresentedAgentCredential, v: StoredAgentCredentialVerifier, m: CredentialVerifierMetadata) = IO.pure(true)
    )
    toolsProgram.map(tools =>
      AgentApi(AgentApiDependencies(AgentCredentialServices(authenticator, null.asInstanceOf[AgentEnrollmentService[IO]]), Some(tools)), telemetry = telemetry)
    )
