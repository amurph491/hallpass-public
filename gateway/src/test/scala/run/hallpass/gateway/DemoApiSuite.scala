package run.hallpass.gateway

import io.circe.Json

import java.nio.charset.StandardCharsets
import java.time.Instant
import java.util.{Base64, UUID}
import cats.effect.IO
import cats.effect.kernel.Ref
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*
import run.hallpass.kernel.authorization.AuthorizedCapability.*

final class DemoApiSuite extends CatsEffectSuite:
  private val slackReadKey = CapabilityKey.parse("Slack.Message.Read").getOrElse(fail("capability key"))
  private def json(value: String) = value.getBytes(StandardCharsets.UTF_8)

  test("revocation reads time after the tenant mutation gate is acquired") {
    val beforeGate = Instant.parse("2026-09-27T12:00:00Z")
    val afterGate = beforeGate.plusSeconds(30)
    for
      time <- Ref.of[IO, Instant](beforeGate)
      clock = new Clock[IO]:
        def now = time.get
      gate = new TenantExecutionMutationGate[IO]:
        def withinExecution[A](tenant: TenantId)(operation: ExecutionGatePermit[IO] => IO[A]): IO[A] =
          IO.raiseError(IllegalStateException("no execution in this test"))
        def withinMutation[A](tenant: TenantId)(operation: IO[A]): IO[A] = time.set(afterGate) *> operation
      pair <- fixture(gateOverride = Some(gate), clock = clock)
      (api, state) = pair
      created <- api.handle("POST", "/api/agents", json("{\"name\":\"Clock agent\"}"))
      agentId = created.body.hcursor.get[String]("id").getOrElse(fail("agent"))
      grant <- api.handle("POST", "/api/delegations", json(s"{\"agentId\":\"$agentId\",\"capabilityId\":\"${state.capability.id}\",\"resourceId\":\"${state.resource.id}\"}"))
      delegationId = grant.body.hcursor.get[String]("id").getOrElse(fail("delegation"))
      _ <- time.set(beforeGate)
      pending = api.handle("POST", s"/api/delegations/$delegationId/revoke", Array.emptyByteArray)
      unchanged <- time.get
      revoked <- pending
    yield
      assertEquals(unchanged, beforeGate)
      assertEquals(revoked.status, 200)
      assertEquals(revoked.body.hcursor.get[String]("revokedAt"), Right(afterGate.toString))
  }

  test("file-backed OAuth secrets are enabled only for development, and production needs Vault Transit over https") {
    val environment = Map(
      "HALLPASS_SLACK_CLIENT_ID" -> "client-id",
      "HALLPASS_SLACK_CLIENT_SECRET" -> "client-secret",
      "HALLPASS_SLACK_REDIRECT_URI" -> "http://localhost:3000/api/oauth/slack/callback",
      "HALLPASS_SECRET_MASTER_KEY" -> java.util.Base64.getEncoder.encodeToString(Array.fill[Byte](32)(7)),
      "HALLPASS_SECRET_DIRECTORY" -> java.nio.file.Files.createTempDirectory("hallpass-secrets-").toString
    )
    val vault = Map(
      "HALLPASS_SECRET_STORE" -> "vault-transit",
      "HALLPASS_VAULT_ADDR" -> "https://vault.example.test:8200",
      "HALLPASS_VAULT_TOKEN_FILE" -> "/run/secrets/vault-token"
    )
    def store(values: Map[String, String]) = OAuthRuntime.fromEnvironment(values).map(_.map(_.store.getClass.getSimpleName))
    assertEquals(store(environment.updated("HALLPASS_ENV", "development")), Right(Some("Local")))
    assertEquals(
      OAuthRuntime.fromEnvironment(environment.updated("HALLPASS_ENV", "production")).map(_.isDefined),
      Left("HALLPASS_ENV=production cannot use LocalEncryptedSecretStore; set HALLPASS_SECRET_STORE=vault-transit")
    )
    val slackOnly = environment -- Set("HALLPASS_SECRET_MASTER_KEY", "HALLPASS_SECRET_DIRECTORY")
    assertEquals(store(slackOnly ++ vault + ("HALLPASS_ENV" -> "production")), Right(Some("VaultTransit")))
    assert(store(slackOnly ++ vault + ("HALLPASS_ENV" -> "production") + ("HALLPASS_VAULT_ADDR" -> "http://vault:8200")).isLeft)
    assert(store(slackOnly ++ vault + ("HALLPASS_SECRET_STORE" -> "plaintext")).isLeft)
    // Slack is off only when its client ID is unset. A half-configured Slack refuses startup instead of disabling itself.
    assertEquals(OAuthRuntime.fromEnvironment(Map("HALLPASS_ENV" -> "production")).map(_.isDefined), Right(false))
    assert(OAuthRuntime.fromEnvironment(Map("HALLPASS_ENV" -> "development", "HALLPASS_SLACK_CLIENT_ID" -> "client-id")).isLeft)
  }

  test("production requires the multi-instance tenant gate") {
    assertEquals(TenantGateRuntime.fromEnvironment(Map.empty), Right(TenantGateRuntime.Selection.SingleProcess))
    assert(TenantGateRuntime.fromEnvironment(Map("HALLPASS_ENV" -> "production")).isLeft)
    assert(
      TenantGateRuntime
        .fromEnvironment(Map("HALLPASS_ENV" -> "production", "HALLPASS_TENANT_GATE" -> "single-process"))
        .isLeft
    )
    assert(TenantGateRuntime.fromEnvironment(Map("HALLPASS_TENANT_GATE" -> "redis")).isLeft)
    assert(
      TenantGateRuntime
        .fromEnvironment(Map("HALLPASS_ENV" -> "production", "HALLPASS_TENANT_GATE" -> "postgres"))
        .exists(_.isInstanceOf[TenantGateRuntime.Selection.Postgres])
    )
  }

  test("an uncoordinated authority mutation is refused with 503 and changes nothing") {
    val unavailable = new TenantExecutionMutationGate[IO]:
      def withinExecution[A](tenant: TenantId)(operation: ExecutionGatePermit[IO] => IO[A]): IO[A] =
        IO.raiseError(TenantGateException(TenantGateFailure.CoordinatorUnavailable))
      def withinMutation[A](tenant: TenantId)(operation: IO[A]): IO[A] =
        IO.raiseError(TenantGateException(TenantGateFailure.CoordinatorUnavailable))
    fixture(gateOverride = Some(unavailable)).flatMap: (api, state) =>
      for
        created <- api.handle("POST", "/api/agents", json("{\"name\":\"Local Codex\"}"))
        agentId = created.body.hcursor.get[String]("id").toOption.get
        granted <- api.handle(
          "POST",
          "/api/delegations",
          json(s"{\"agentId\":\"$agentId\",\"capabilityId\":\"${state.capability.id}\",\"resourceId\":\"${state.resource.id}\"}")
        )
        listed <- api.handle("GET", "/api/delegations", Array.emptyByteArray)
      yield
        assertEquals(granted.status, 503)
        assertEquals(granted.body.hcursor.get[String]("error"), Right("service_unavailable"))
        assertEquals(listed.body.hcursor.downField("delegations").values.map(_.size), Some(0))
  }

  test("delegation constraints are validated strictly, passed through, and listed in the wire shape") {
    fixture().flatMap: (api, state) =>
      def body(agentId: String, constraints: String) =
        json(s"""{"agentId":"$agentId","capabilityId":"${state.capability.id}","resourceId":"${state.resource.id}","constraints":$constraints}""")
      val invalid = Vector(
        "null",
        "[]",
        """{"other":{}}""",
        """{"value_in":[]}""",
        Json.obj("value_in" -> Json.obj("k.a" -> Json.arr(
          (1 to 200).map(i => Json.fromString("x" * 500 + i.toString))*
        ))).noSpaces,
        """{"value_in":{"Bad Key":["a"]}}""",
        """{"value_in":{"k.a":[]}}""",
        """{"value_in":{"k.a":["a","a"]}}""",
        """{"value_in":{"k.a":[1]}}""",
        """{"value_in":{"k.a":["a"]},"x":1}""",
        s"""{"value_in":{"k.a":[${(1 to 201).map(i => "\"v" + i + "\"").mkString(",")}]}}""",
        s"""{"value_in":{${(1 to 21).map(i => "\"k" + i + "\":[\"a\"]").mkString(",")}}}"""
      )
      for
        created <- api.handle("POST", "/api/agents", json("{\"name\":\"Local Codex\"}"))
        agentId = created.body.hcursor.get[String]("id").toOption.get
        rejected <- invalid.traverse(c => api.handle("POST", "/api/delegations", body(agentId, c)))
        none <- api.handle("GET", "/api/delegations", Array.emptyByteArray)
        accepted <- api.handle("POST", "/api/delegations", body(agentId, """{"value_in":{"k.b":["y","x"],"k.a":["z"]}}"""))
        listed <- api.handle("GET", "/api/delegations", Array.emptyByteArray)
      yield
        assertEquals(rejected.map(_.status), Vector.fill(invalid.size)(400))
        assertEquals(none.body.hcursor.downField("delegations").values.map(_.size), Some(0))
        assertEquals(accepted.status, 201)
        val expected = io.circe.parser.parse("""{"value_in":{"k.a":["z"],"k.b":["x","y"]}}""").toOption.get
        assertEquals(accepted.body.hcursor.downField("constraints").focus, Some(expected))
        assertEquals(listed.body.hcursor.downField("delegations").downArray.downField("constraints").focus, Some(expected))
  }

  test("a grant without the connection resource it covers is refused; there is no provider-wide default") {
    fixture().flatMap: (api, state) =>
      for
        created <- api.handle("POST", "/api/agents", json("{\"name\":\"Local Codex\"}"))
        agentId = created.body.hcursor.get[String]("id").toOption.get
        missing <- api.handle("POST", "/api/delegations", json(s"{\"agentId\":\"$agentId\",\"capabilityId\":\"${state.capability.id}\"}"))
        listed <- api.handle("GET", "/api/delegations", Array.emptyByteArray)
      yield
        assertEquals(missing.status, 400)
        assertEquals(listed.body.hcursor.downField("delegations").values.map(_.size), Some(0))
  }

  test("creates and lists durable agents through edge DTOs") {
    fixture().flatMap: pair =>
      val api = pair._1
      for
        bad <- api.handle("POST", "/api/agents", json("{\"name\":\"  \"}"))
        created <- api.handle("POST", "/api/agents", json("{\"name\":\"Local Codex\",\"description\":\"local\"}"))
        listed <- api.handle("GET", "/api/agents", Array.emptyByteArray)
      yield
        assertEquals(bad.status, 400)
        assertEquals(created.status, 201)
        assertEquals(created.body.hcursor.get[String]("name"), Right("Local Codex"))
        assertEquals(listed.body.hcursor.downField("agents").downN(0).get[String]("name"), Right("Local Codex"))
  }

  test("a control-plane grant allows and revocation immediately denies") {
    fixture().flatMap: pair =>
      val (api, state) = pair
      for
        created <- api.handle("POST", "/api/agents", json("{\"name\":\"Local Codex\"}"))
        agentId = created.body.hcursor.get[String]("id").toOption.get
        before <- api.handle(
          "POST",
          "/api/authorization/check",
          json(s"{\"agentId\":\"$agentId\",\"tool\":\"slack_search_messages\"}")
        )
        grant <- api.handle(
          "POST",
          "/api/delegations",
          json(s"{\"agentId\":\"$agentId\",\"capabilityId\":\"${state.capability.id}\",\"resourceId\":\"${state.resource.id}\"}")
        )
        delegationId = grant.body.hcursor.get[String]("id").toOption.get
        allowed <- api.handle(
          "POST",
          "/api/authorization/check",
          json(s"{\"agentId\":\"$agentId\",\"tool\":\"slack_search_messages\"}")
        )
        revoked <- api.handle("POST", s"/api/delegations/$delegationId/revoke", Array.emptyByteArray)
        denied <- api.handle(
          "POST",
          "/api/authorization/check",
          json(s"{\"agentId\":\"$agentId\",\"tool\":\"slack_search_messages\"}")
        )
        decisions <- api.handle("GET", "/api/authorization/decisions", Array.emptyByteArray)
      yield
        assertEquals(before.body.hcursor.get[String]("outcome"), Right("denied"))
        assertEquals(before.body.hcursor.get[String]("authorizationSource"), Right("HUMAN_PREVIEW"))
        assertEquals(grant.status, 201)
        assertEquals(allowed.body.hcursor.get[String]("outcome"), Right("allowed"))
        assertEquals(allowed.body.hcursor.get[String]("authorizationSource"), Right("HUMAN_PREVIEW"))
        assertEquals(revoked.body.hcursor.get[String]("status"), Right("revoked"))
        assertEquals(denied.body.hcursor.get[String]("reason"), Right("inactive_delegation"))
        assertEquals(denied.body.hcursor.get[String]("authorizationSource"), Right("HUMAN_PREVIEW"))
        assertEquals(decisions.body.hcursor.downField("decisions").focus.flatMap(_.asArray).map(_.size), Some(3))
        assertEquals(
          decisions.body.hcursor.downField("decisions").downN(0).get[String]("authorizationSource"),
          Right("HUMAN_PREVIEW")
        )
  }

  test("completion summary is tenant and agent scoped, validates inputs, and preserves failures") {
    for
      observed <- Ref.of[IO, Vector[(TenantId, Option[AgentId])]](Vector.empty)
      unavailable <- Ref.of[IO, Boolean](false)
      agent = AgentId.random()
      history = new ExecutionHistory[IO]:
        def hasCompletedExecution(tenant: TenantId, selected: Option[AgentId]): IO[Boolean] =
          observed.update(_ :+ (tenant -> selected)) *> unavailable.get.flatMap:
            case true => IO.raiseError(RuntimeException("unavailable"))
            case false => IO.pure(selected.forall(_ == agent))
        def recent(tenant: TenantId, agent: Option[AgentId], limit: Int) = IO.raiseError[Vector[ExecutionHistoryEntry]](RuntimeException("must not read recent history"))
        def page(tenant: TenantId, agent: Option[AgentId], limit: Int, cursor: Option[ExecutionHistoryCursor]) = IO.raiseError[ExecutionHistoryPage](RuntimeException("must not read a page"))
        def forRequest(tenant: TenantId, agent: Option[AgentId], request: AuthorizationRequestId, limit: Int, cursor: Option[ExecutionHistoryCursor]) = IO.raiseError[ExecutionHistoryPage](RuntimeException("must not read a request"))
      pair <- fixture(Some(history))
      completed <- pair._1.handle("GET", "/api/executions/summary", Array.emptyByteArray, Map("agentId" -> agent.toString))
      other <- pair._1.handle("GET", "/api/executions/summary", Array.emptyByteArray, Map("agentId" -> AgentId.random().toString))
      workspace <- pair._1.handle("GET", "/api/executions/summary", Array.emptyByteArray)
      invalid <- pair._1.handle("GET", "/api/executions/summary", Array.emptyByteArray, Map("agentId" -> "invalid"))
      injected <- pair._1.handle("GET", "/api/executions/summary", Array.emptyByteArray, Map("tenantId" -> TenantId.random().toString))
      _ <- unavailable.set(true)
      failure <- pair._1.handle("GET", "/api/executions/summary", Array.emptyByteArray)
      missing <- fixture().flatMap(_._1.handle("GET", "/api/executions/summary", Array.emptyByteArray))
      calls <- observed.get
    yield
      assertEquals(completed.body.hcursor.get[Boolean]("hasCompletedExecution"), Right(true))
      assertEquals(other.body.hcursor.get[Boolean]("hasCompletedExecution"), Right(false))
      assertEquals(workspace.body.hcursor.get[Boolean]("hasCompletedExecution"), Right(true))
      assertEquals(invalid.status, 400)
      assertEquals(injected.status, 400)
      assertEquals(failure.status, 503)
      assertEquals(missing.status, 503)
      assertEquals(calls.size, 4)
      assert(calls.forall(_._1 == pair._2.tenant))
      assertEquals(calls.head._2, Some(agent))
  }

  test("execution history is bounded, agent-filtered, and credential-free") {
    for
      calls <- Ref.of[IO, Vector[(TenantId, Option[AgentId], Int, Option[ExecutionHistoryCursor])]](Vector.empty)
      agent = AgentId.random()
      encodedCursor = Base64.getUrlEncoder.withoutPadding.encodeToString(
        s"2026-09-22T10:00:00Z|${UUID.randomUUID()}".getBytes(StandardCharsets.UTF_8)
      )
      entry = ExecutionHistoryEntry(
        AuthorizationRequestId.random(),
        ExecutionAuditCorrelationId.parse("history-test").get,
        agent,
        ExternalToolId.parse("slack_search_messages").get,
        "Slack.Message.Read",
        ExecutionHistoryEventKind.ExecutionCompleted,
        ExecutionHistoryOutcome.Completed,
        Instant.parse("2026-09-23T12:00:00Z")
      )
      history = new ExecutionHistory[IO]:
        def hasCompletedExecution(tenant: TenantId, selected: Option[AgentId]) = IO.pure(selected.forall(_ == agent))
        def recent(tenant: TenantId, selected: Option[AgentId], limit: Int): IO[Vector[ExecutionHistoryEntry]] =
          IO.pure(Vector(entry).filter(value => selected.forall(_ == value.agentId)))
        def page(tenant: TenantId, selected: Option[AgentId], limit: Int, cursor: Option[ExecutionHistoryCursor]) =
          calls.update(_ :+ ((tenant, selected, limit, cursor))).as(
            ExecutionHistoryPage(Vector(entry).filter(value => selected.forall(_ == value.agentId)), None)
          )
        def forRequest(
            tenant: TenantId,
            selected: Option[AgentId],
            request: AuthorizationRequestId,
            limit: Int,
            cursor: Option[ExecutionHistoryCursor]
        ) = IO.pure(ExecutionHistoryPage(
          Vector(entry).filter(value => value.requestId == request && selected.forall(_ == value.agentId)).take(limit),
          None
        ))
      pair <- fixture(Some(history))
      api = pair._1
      good <- api.handle("GET", "/api/executions", Array.emptyByteArray, Map("agentId" -> agent.toString, "limit" -> "5"))
      continued <- api.handle("GET", "/api/executions", Array.emptyByteArray, Map("agentId" -> agent.toString, "limit" -> "3", "cursor" -> encodedCursor))
      detail <- api.handle("GET", s"/api/executions/${entry.requestId}", Array.emptyByteArray, Map("agentId" -> agent.toString, "limit" -> "1"))
      missingDetail <- api.handle("GET", s"/api/executions/${AuthorizationRequestId.random()}", Array.emptyByteArray)
      invalidCursor <- api.handle("GET", "/api/executions", Array.emptyByteArray, Map("cursor" -> "invalid"))
      other <- api.handle("GET", "/api/executions", Array.emptyByteArray, Map("agentId" -> AgentId.random().toString))
      invalid <- api.handle("GET", "/api/executions", Array.emptyByteArray, Map("agentId" -> "not-an-id"))
      excessive <- api.handle("GET", "/api/executions", Array.emptyByteArray, Map("limit" -> "101"))
      unexpected <- api.handle("GET", "/api/executions", Array.emptyByteArray, Map("tenantId" -> TenantId.random().toString))
      observed <- calls.get
    yield
      assertEquals(good.status, 200)
      assertEquals(continued.status, 200)
      assertEquals(good.body.hcursor.downField("executions").downN(0).get[String]("agentId"), Right(agent.toString))
      assertEquals(good.body.hcursor.downField("executions").downN(0).get[String]("eventKind"), Right("EXECUTION_COMPLETED"))
      assertEquals(good.body.hcursor.downField("executions").downN(0).get[String]("safeOutcome"), Right("COMPLETED"))
      assertEquals(good.body.hcursor.downField("executions").focus.flatMap(_.asArray).map(_.size), Some(1))
      assertEquals(detail.status, 200)
      assertEquals(detail.body.hcursor.downField("events").focus.flatMap(_.asArray).map(_.size), Some(1))
      assertEquals(missingDetail.status, 404)
      assertEquals(invalidCursor.status, 400)
      assertEquals(other.body.hcursor.downField("executions").focus.flatMap(_.asArray).map(_.size), Some(0))
      assertEquals(invalid.status, 400)
      assertEquals(excessive.status, 400)
      assertEquals(unexpected.status, 400)
      assertEquals(observed.map(_._3), Vector(5, 3, 50))
      assert(observed(1)._4.nonEmpty)
      assertEquals(observed.map(_._1).distinct, Vector(pair._2.tenant))
      assert(!good.body.noSpaces.contains("credential"))
  }

  test("unknown tools and malformed identifiers fail closed") {
    fixture().flatMap: pair =>
      val api = pair._1
      for
        created <- api.handle("POST", "/api/agents", json("{\"name\":\"Local Codex\"}"))
        agentId = created.body.hcursor.get[String]("id").toOption.get
        unknown <- api.handle(
          "POST",
          "/api/authorization/check",
          json(s"{\"agentId\":\"$agentId\",\"tool\":\"unknown\"}")
        )
        malformed <- api.handle(
          "POST",
          "/api/authorization/check",
          json("{\"agentId\":\"not-a-uuid\",\"tool\":\"slack_search_messages\"}")
        )
      yield
        assertEquals(unknown.body.hcursor.get[String]("reason"), Right("unmapped_tool"))
        assertEquals(malformed.status, 400)
  }

  private final class State(
      val tenant: TenantId,
      val human: Principal.Human,
      val resource: Resource,
      val capability: CatalogCapability,
      val policy: Policy,
      agentsRef: Ref[IO, Vector[Agent]],
      delegationsRef: Ref[IO, Vector[Delegation]],
      eventsRef: Ref[IO, Vector[AuthorizationEvent]]
  ) extends AgentRepository[IO],
        AuthorityRepository[IO],
        DelegationRepository[IO],
        AuthorizationJournal[IO],
        ControlPlaneCatalog[IO]:
    def create(t: TenantId, request: CreateAgent) =
      val value = Agent(AgentId.random(), request.name, request.description, Instant.now())
      agentsRef.update(_ :+ value).as(Right(value))
    def find(t: TenantId, id: AgentId) = agentsRef.get.map(_.find(_.id == id))
    def list(t: TenantId) = agentsRef.get
    def resources(t: TenantId) = IO.pure(Vector(CatalogResource(resource, "Demo Slack workspace", Some("slack"))))
    def capabilities(t: TenantId) = IO.pure(Vector(capability))
    def tools(t: TenantId) = IO.pure(
      Vector(
        CatalogTool(
          "slack_search_messages",
          "Search Slack messages",
          resource.id,
          Some(capability),
          Some("PROVIDER_DEFINED"),
          true
        )
      )
    )
    def snapshotFor(t: TenantId, principal: Principal, tool: String) = if tool != "slack_search_messages" then
      IO.pure(Left(AuthorityLoadError.UnmappedTool))
    else
      delegationsRef.get.map(ds =>
        Right(AuthoritySnapshot(ResourceScope.fromPath(Vector(resource)).getOrElse(throw new AssertionError("scope")), capability, Policies(Vector(policy)), ds.filter(_.grantee == principal)))
      )
    def snapshotWithin(t: TenantId, principal: Principal, tool: String, scope: ResourceScope) =
      snapshotFor(t, principal, tool)
    def create(t: TenantId, request: CreateDelegation) =
      val value = Delegation(
        DelegationId.random(),
        request.grantor,
        request.grantee,
        None,
        NonEmptySet.one(CapabilityDescriptor(request.resource, request.action, slackReadKey)),
        request.constraints,
        Instant.now(),
        request.expiresAt,
        None
      )
      delegationsRef.update(_ :+ value).as(Right(value))
    def revoke(t: TenantId, id: DelegationId, at: Instant) = delegationsRef.modify: values =>
      values.find(_.id == id) match
        case None        => values -> Left(DelegationError.NotFound)
        case Some(value) =>
          val revoked = value.copy(revokedAt = Some(at))
          values.map(item => if item.id == id then revoked else item) -> Right(revoked)
    def listForGrantee(t: TenantId, grantee: Principal) = delegationsRef.get.map(_.filter(_.grantee == grantee))
    def record(t: TenantId, event: AuthorizationEvent) = eventsRef.update(event +: _)
    def recent(t: TenantId, limit: Int) = eventsRef.get.map(_.take(limit).map(toRecord))
    private def toRecord(event: AuthorizationEvent) =
      val (outcome, reason, policyId, version, ids) = event.result match
        case AuthorizationResult.Authorized(value) =>
          (
            RecordedOutcome.Allow,
            "authorized",
            Some(value.evidence.policyId),
            Some(value.evidence.policyVersion),
            value.evidence.delegationIds
          )
        case AuthorizationResult.Denied(value) => (RecordedOutcome.Deny, value.toString, None, None, Vector.empty)
        case AuthorizationResult.ApprovalRequired(value) =>
          (
            RecordedOutcome.RequireApproval,
            "approval_required",
            Some(value.policyId),
            Some(value.policyVersion),
            Vector.empty
          )
      AuthorizationRecord(
        event.requestId,
        event.principal,
        event.tool,
        event.resource,
        event.capability.map(_.action),
        event.capability.map(_.capability),
        outcome,
        reason,
        policyId,
        version,
        ids,
        event.correlationId,
        event.occurredAt,
        Some(event.authorizationSource)
      )

  private val approvalBinding = ApprovalBinding.parse("a" * 64).getOrElse(fail("binding"))
  private val approvalNow = Instant.parse("2030-01-01T00:00:00Z")

  private def approvalRecord(state: State, approver: Principal.Human, expiresAt: Instant = approvalNow.plusSeconds(900)) =
    ApprovalRecord(
      ApprovalId.random(), state.tenant, AgentId.random(), approver,
      OperationId.parse("github.issues_create@1").getOrElse(fail("operation")),
      ExternalToolId.parse("github_issues_create").getOrElse(fail("tool")),
      approvalBinding, "10000000-0000-4000-8000-000000000010",
      CapabilityDescriptor(state.resource.id, Action.Read, slackReadKey),
      state.policy.id, state.policy.version,
      io.circe.Json.obj("title" -> io.circe.Json.fromString("Fix it")),
      approvalNow, expiresAt, ApprovalStatus.Pending, None, None
    )

  private def humanUuid(human: Principal.Human): String = human match
    case Principal.Human(id) => id.toString

  /** Decides like the durable store: only the record's approver, once, before expiry. Records every `decide` call. */
  private final class FakeApprovals(records: Ref[IO, Vector[ApprovalRecord]], val calls: Ref[IO, Vector[(Principal.Human, Boolean, Instant)]])
      extends ApprovalStore:
    def create(record: ApprovalRecord) = records.update(_ :+ record)
    def find(tenant: TenantId, id: ApprovalId) = records.get.map(_.find(_.id == id))
    def pendingFor(tenant: TenantId, approver: Principal.Human, at: Instant, limit: Int) =
      records.get.map(_.filter(r => r.tenant == tenant && r.approver == approver && r.status == ApprovalStatus.Pending && r.expiresAt.isAfter(at)))
    def decide(tenant: TenantId, id: ApprovalId, approver: Principal.Human, approve: Boolean, at: Instant) =
      calls.update(_ :+ ((approver, approve, at))) *> records.get.flatMap: all =>
        all.find(r => r.id == id && r.tenant == tenant) match
          case None => IO.pure(Left(ApprovalDecisionError.NotFound))
          case Some(r) if r.approver != approver => IO.pure(Left(ApprovalDecisionError.NotApprover))
          case Some(r) if r.status != ApprovalStatus.Pending => IO.pure(Left(ApprovalDecisionError.AlreadyDecided))
          case Some(r) if !at.isBefore(r.expiresAt) => IO.pure(Left(ApprovalDecisionError.Expired))
          case Some(r) =>
            val decided = r.copy(status = if approve then ApprovalStatus.Approved else ApprovalStatus.Denied, decidedAt = Some(at))
            records.update(_.map(x => if x.id == id then decided else x)).as(Right(decided))
    def consume(tenant: TenantId, id: ApprovalId, agent: AgentId, binding: ApprovalBinding, request: AuthorizationRequestId, at: Instant) =
      IO.pure(false)

  private def approvalFixture(
      seed: State => Vector[ApprovalRecord]
  ): IO[(ScopedApi, State, FakeApprovals, Vector[ApprovalRecord])] =
    for
      records <- Ref.of[IO, Vector[ApprovalRecord]](Vector.empty)
      calls <- Ref.of[IO, Vector[(Principal.Human, Boolean, Instant)]](Vector.empty)
      store = FakeApprovals(records, calls)
      clock = new Clock[IO]:
        def now = IO.pure(approvalNow)
      pair <- fixture(clock = clock, approvals = Some(ApprovalService(store)))
      (api, state) = pair
      seeded = seed(state)
      _ <- records.set(seeded)
    yield (api, state, store, seeded)

  test("admin approval routes answer 503 when approvals are not configured") {
    for
      pair <- fixture()
      (api, _) = pair
      list <- api.handle("GET", "/api/approvals", Array.emptyByteArray)
      approve <- api.handle("POST", s"/api/approvals/${UUID.randomUUID()}/approve", Array.emptyByteArray)
    yield
      assertEquals(list.status, 503)
      assertEquals(approve.status, 503)
  }

  test("GET /api/approvals lists only the session human's pending approvals with the typed preview") {
    for
      fx <- approvalFixture(state => Vector(
        approvalRecord(state, state.human),
        approvalRecord(state, Principal.Human(UserId.random())),
        approvalRecord(state, state.human, expiresAt = approvalNow.minusSeconds(1))
      ))
      (api, state, _, seeded) = fx
      response <- api.handle("GET", "/api/approvals", Array.emptyByteArray)
    yield
      assertEquals(response.status, 200)
      val listed = response.body.hcursor.downField("approvals").values.getOrElse(fail("approvals")).toVector
      assertEquals(listed.size, 1)
      val item = listed.head.hcursor
      assertEquals(item.get[String]("id"), Right(seeded.head.id.toString))
      assertEquals(item.get[String]("tool"), Right("github_issues_create"))
      assertEquals(item.get[String]("operation"), Right("github.issues_create@1"))
      assertEquals(item.get[String]("agentId"), Right(seeded.head.agent.toString))
      assertEquals(item.get[String]("capability"), Right("Slack.Message.Read"))
      assertEquals(item.get[String]("action"), Right("read"))
      assertEquals(item.get[String]("resourceId"), Right(state.resource.id.toString))
      assertEquals(item.get[io.circe.Json]("preview"), Right(io.circe.Json.obj("title" -> io.circe.Json.fromString("Fix it"))))
      assertEquals(item.get[String]("requestedAt"), Right(approvalNow.toString))
      assertEquals(item.get[String]("expiresAt"), Right(approvalNow.plusSeconds(900).toString))
  }

  private val pickerConfig = GooglePickerConfig("client-1.apps.googleusercontent.com", "picker-key-1", "123456789012")

  test("the Picker configuration is the public Picker settings and nothing else") {
    fixture(googlePicker = Some(pickerConfig)).flatMap: (api, _) =>
      api.handle("GET", "/api/connections/google/picker-config", Array.emptyByteArray).map: response =>
        assertEquals(response.status, 200)
        assertEquals(
          response.body,
          io.circe.Json.obj(
            "clientId" -> io.circe.Json.fromString("client-1.apps.googleusercontent.com"),
            "apiKey" -> io.circe.Json.fromString("picker-key-1"),
            "appId" -> io.circe.Json.fromString("123456789012"),
            "scope" -> io.circe.Json.fromString("https://www.googleapis.com/auth/drive.file")
          )
        )
        assertEquals(response.body.asObject.map(_.keys.toSet), Some(Set("clientId", "apiKey", "appId", "scope")))
  }

  test("the Picker configuration is 404 when Google is not configured with a Picker key") {
    fixture().flatMap: (api, _) =>
      api.handle("GET", "/api/connections/google/picker-config", Array.emptyByteArray).map(response => assertEquals(response.status, 404))
  }

  test("the Picker configuration answers GET only") {
    fixture(googlePicker = Some(pickerConfig)).flatMap: (api, _) =>
      List("POST", "PUT", "DELETE").traverse(method => api.handle(method, "/api/connections/google/picker-config", Array.emptyByteArray)).map:
        responses => assertEquals(responses.map(_.status), List(404, 404, 404))
  }

  test("the Picker configuration needs both the Picker key and the project number") {
    def selection(key: Option[String], app: Option[String]) =
      GoogleRuntime.Selection(
        run.hallpass.adapters.google.GoogleOAuthClient("client-1", "secret-sentinel-1", key, app),
        run.hallpass.adapters.google.GoogleEndpoints.Production,
        java.net.URI.create("http://localhost:3000/cb")
      )
    assertEquals(GooglePickerConfig.from(selection(Some("k"), Some("1"))), Some(GooglePickerConfig("client-1", "k", "1")))
    assertEquals(GooglePickerConfig.from(selection(Some("k"), None)), None)
    assertEquals(GooglePickerConfig.from(selection(None, Some("1"))), None)
    assert(!GooglePickerConfig("client-1", "k", "1").json.noSpaces.contains("secret-sentinel-1"))
  }

  test("approve and deny decide as the session human and return the record") {
    for
      fx <- approvalFixture(state => Vector(approvalRecord(state, state.human), approvalRecord(state, state.human)))
      (api, state, store, seeded) = fx
      approved <- api.handle("POST", s"/api/approvals/${seeded(0).id}/approve", Array.emptyByteArray)
      denied <- api.handle("POST", s"/api/approvals/${seeded(1).id}/deny", Array.emptyByteArray)
      calls <- store.calls.get
    yield
      assertEquals(approved.status, 200)
      assertEquals(approved.body.hcursor.get[String]("status"), Right("APPROVED"))
      assertEquals(approved.body.hcursor.get[String]("id"), Right(seeded(0).id.toString))
      assertEquals(denied.status, 200)
      assertEquals(denied.body.hcursor.get[String]("status"), Right("DENIED"))
      assertEquals(calls.map(c => c._1 -> c._2), Vector(state.human -> true, state.human -> false))
  }

  test("a decision maps each error and an approver named in the body changes nothing") {
    for
      fx <- approvalFixture(state => Vector(
        approvalRecord(state, state.human),
        approvalRecord(state, Principal.Human(UserId.random())),
        approvalRecord(state, state.human, expiresAt = approvalNow)
      ))
      (api, state, store, seeded) = fx
      missing <- api.handle("POST", s"/api/approvals/${UUID.randomUUID()}/approve", Array.emptyByteArray)
      // The body claims to be the record's approver; only the session decides.
      notApprover <- api.handle(
        "POST", s"/api/approvals/${seeded(1).id}/approve",
        json(s"""{"approver":"${humanUuid(seeded(1).approver)}"}""")
      )
      expired <- api.handle("POST", s"/api/approvals/${seeded(2).id}/approve", Array.emptyByteArray)
      first <- api.handle("POST", s"/api/approvals/${seeded(0).id}/approve", Array.emptyByteArray)
      again <- api.handle("POST", s"/api/approvals/${seeded(0).id}/deny", Array.emptyByteArray)
      malformed <- api.handle("POST", "/api/approvals/not-an-id/approve", Array.emptyByteArray)
      calls <- store.calls.get
    yield
      assertEquals(missing.status, 404)
      assertEquals(notApprover.status, 403)
      assertEquals(expired.status, 410)
      assertEquals(first.status, 200)
      assertEquals(again.status, 409)
      assertEquals(malformed.status, 404)
      assert(calls.forall(_._1 == state.human), "the approver is always the session's human")
  }

  test("a decision runs under the tenant mutation gate and reads time inside it") {
    val afterGate = approvalNow.plusSeconds(30)
    for
      entered <- Ref.of[IO, Vector[TenantId]](Vector.empty)
      time <- Ref.of[IO, Instant](approvalNow)
      gate = new TenantExecutionMutationGate[IO]:
        def withinExecution[A](tenant: TenantId)(operation: ExecutionGatePermit[IO] => IO[A]): IO[A] =
          IO.raiseError(IllegalStateException("no execution in this test"))
        def withinMutation[A](tenant: TenantId)(operation: IO[A]): IO[A] =
          entered.update(_ :+ tenant) *> time.set(afterGate) *> operation
      records <- Ref.of[IO, Vector[ApprovalRecord]](Vector.empty)
      calls <- Ref.of[IO, Vector[(Principal.Human, Boolean, Instant)]](Vector.empty)
      store = FakeApprovals(records, calls)
      clock = new Clock[IO]:
        def now = time.get
      pair <- fixture(gateOverride = Some(gate), clock = clock, approvals = Some(ApprovalService(store)))
      (api, state) = pair
      record = approvalRecord(state, state.human, expiresAt = approvalNow.plusSeconds(3600))
      _ <- records.set(Vector(record))
      decided <- api.handle("POST", s"/api/approvals/${record.id}/approve", Array.emptyByteArray)
      listed <- api.handle("GET", "/api/approvals", Array.emptyByteArray)
      gated <- entered.get
      recorded <- calls.get
    yield
      assertEquals(decided.status, 200)
      assertEquals(listed.status, 200)
      assertEquals(gated, Vector(state.tenant), "only the decision takes the gate, once, for the session's tenant")
      assertEquals(recorded.map(_._3), Vector(afterGate))
  }

  private def fixture(
      history: Option[ExecutionHistory[IO]] = None,
      gateOverride: Option[TenantExecutionMutationGate[IO]] = None,
      clock: Clock[IO] = Clock.system,
      approvals: Option[ApprovalService] = None,
      googlePicker: Option[GooglePickerConfig] = None
  ): IO[(ScopedApi, State)] = for
    agents <- Ref.of[IO, Vector[Agent]](Vector.empty)
    delegations <- Ref.of[IO, Vector[Delegation]](Vector.empty)
    events <- Ref.of[IO, Vector[AuthorizationEvent]](Vector.empty)
    tenant = TenantId.random()
    human = (Principal.Human(UserId.random()): Principal.Human)
    resource = Resource(ResourceId.random(), tenant, ResourceType.Provider, None, "workspace", None)
    descriptor = CapabilityDescriptor(resource.id, Action.Read, slackReadKey)
    capability = CatalogCapability("10000000-0000-4000-8000-000000000010", "Slack.Message.Read", descriptor)
    policy = Policy(
      PolicyId.random(),
      PolicyVersion.from(1).get,
      NonEmptySet.one(
        PolicyStatement(human, resource.id, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow)
      )
    )
    state = State(tenant, human, resource, capability, policy, agents, delegations, events)
    gate <- gateOverride.fold(SingleProcessTenantExecutionMutationGate.create.widen[TenantExecutionMutationGate[IO]])(IO.pure)
    now <- clock.now
    context <- HumanAuthenticator[IO](singleMembership(tenant, human))
      .authenticate(member, tenant, now)
      .map(_.getOrElse(fail("expected an authenticated administrator")))
  yield ScopedApi(DemoApi(state, state, state, state, state, mutationGate = gate, executionHistory = history, clock = clock, approvals = approvals, googlePicker = googlePicker), context) -> state

  private val member = DirectoryUserId.random()

  private def singleMembership(tenant: TenantId, human: Principal.Human): HumanDirectory[IO] = new HumanDirectory[IO]:
    def userFor(identity: ExternalIdentity) = IO.pure(Right(Some(member)))
    def activeMemberships(user: DirectoryUserId) =
      IO.pure(Right(Vector(TenantMembership(member, tenant, human, MembershipRole.Admin))))

  /** The DemoApi as one authenticated administrator sees it. */
  private final class ScopedApi(api: DemoApi, context: AuthenticatedHuman):
    private val session = SessionToken.generate(java.security.SecureRandom()).oauthBinding
    def handle(method: String, path: String, body: Array[Byte], query: Map[String, String] = Map.empty): IO[DemoApiResponse] =
      api.handle(method, path, body, query)(using context, session)
