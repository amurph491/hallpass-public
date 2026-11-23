package run.hallpass.application

import java.sql.DriverManager
import java.time.Instant
import cats.effect.IO
import cats.syntax.all.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import scala.compiletime.uninitialized
import run.hallpass.adapters.postgres.*
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

final class PostgresExecutionAuditSuite extends CatsEffectSuite:
  private val slackReadKey = CapabilityKey.parse("Slack.Message.Read").getOrElse(fail("capability key"))
  private var container: PostgreSQLContainer[?] = uninitialized
  private var config: DatabaseConfig = uninitialized
  private var dockerAvailable = false

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      val admin = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
      try
        val statement = admin.createStatement()
        statement.execute("create role hallpass login password 'test-password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute("grant connect on database test to hallpass")
        statement.execute("grant usage, create on schema public to hallpass")
      finally admin.close()
      config = DatabaseConfig
        .fromEnvironment(
          Map(
            "HALLPASS_DB_URL" -> container.getJdbcUrl,
            "HALLPASS_DB_USER" -> "hallpass",
            "HALLPASS_DB_PASSWORD" -> "test-password"
          )
        )
        .toOption
        .get

  override def afterAll(): Unit = if dockerAvailable then container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  test("execution audit persists ordered tenant-scoped evidence at supplied event time") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      val repository = PostgresControlPlane(xa)
      val tenant = DemoBootstrap.Tenant.toString
      val human = DemoBootstrap.Human.id.toString
      val resource = DemoBootstrap.SlackResource
      val tool = ResourceId.parse("10000000-0000-4000-8000-000000000012").toOption.get
      val capability = CatalogCapabilityId.parse("10000000-0000-4000-8000-000000000010").getOrElse(fail("capability"))
      val policy = PolicyId.parse("10000000-0000-4000-8000-000000000014").toOption.get
      val credential = AgentCredentialId.parse("40000000-0000-4000-8000-000000000102").toOption.get
      val request = AuthorizationRequestId.parse("40000000-0000-4000-8000-000000000101").toOption.get
      val service = ServiceId.parse("40000000-0000-4000-8000-000000000103").toOption.get
      val firstDelegation = DelegationId.parse("40000000-0000-4000-8000-000000000104").toOption.get
      val secondDelegation = DelegationId.parse("40000000-0000-4000-8000-000000000105").toOption.get
      val correlation = ExecutionAuditCorrelationId.parse("execution-audit-adapter").getOrElse(fail("correlation"))
      val audience = ExecutorAudience.parse("test.audit.executor").getOrElse(fail("audience"))
      val occurredAt = Instant.parse("2026-09-20T10:11:12Z")
      val policyVersion = PolicyVersion.from(1).getOrElse(fail("policy version"))
      for
        _ <- DemoBootstrap.run(xa)
        agent <- repository
          .create(DemoBootstrap.Tenant, CreateAgent("Audit adapter agent", None))
          .flatMap(_.fold(_ => IO.raiseError(RuntimeException("agent creation failed")), IO.pure))
        _ <- setupEvidence(xa, tenant, human, agent.id.toString, resource.toString, credential, request, service, firstDelegation, secondDelegation, correlation, occurredAt)
        evidence = AuthorizationEvidence(
          policy,
          policyVersion,
          Vector(firstDelegation, secondDelegation),
          CapabilityDescriptor(resource, Action.Read, slackReadKey)
        )
        first = Delegation(
          firstDelegation,
          DemoBootstrap.Human,
          Principal.Service(service),
          None,
          NonEmptySet.one(CapabilityDescriptor(resource, Action.Read, slackReadKey)),
          Constraints.empty,
          Instant.EPOCH,
          None,
          None
        )
        second = Delegation(
          secondDelegation,
          Principal.Service(service),
          Principal.Agent(agent.id),
          Some(firstDelegation),
          NonEmptySet.one(CapabilityDescriptor(resource, Action.Read, slackReadKey)),
          Constraints.empty,
          Instant.EPOCH,
          None,
          None
        )
        requestModel = AuthorizationRequest(
          request,
          DemoBootstrap.Tenant,
          IdentityChain(Principal.Agent(agent.id), Vector(firstDelegation, secondDelegation), None, ExecutionContext.LocalProcess),
          ResourceScope.fromPath(Vector(Resource(resource, DemoBootstrap.Tenant, ResourceType.Provider, None, "Slack", None))).getOrElse(fail("scope")),
          slackReadKey,
          Action.Read,
          AuthorizationContext.empty
        )
        capabilityProof = AuthorizationEngine.authorize(
          Policies(Vector(Policy(
            policy,
            policyVersion,
            NonEmptySet.one(PolicyStatement(DemoBootstrap.Human, resource, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow))
          ))),
          requestModel,
          Vector(first, second),
          occurredAt
        ) match
          case AuthorizationResult.Authorized(value) => value
          case other                                 => fail(s"expected authorized capability, received $other")
        lease = ExecutionLease
          .issueForBroker(capabilityProof, request, audience, occurredAt, occurredAt.plusSeconds(60))
          .fold(error => fail(s"lease issuance failed: $error"), identity)
        authenticated = AuthenticatedAgentContext.authenticated(
          DemoBootstrap.Tenant,
          agent.id,
          credential,
          occurredAt,
          UnverifiedExecutionClaims.empty
        )
        context = ExecutionAuditContext
          .fromLease(
            lease,
            ExecutionAuditMetadata.authenticatedInvocation(
              authenticated,
              correlation,
              tool,
              capability,
              InvocationBinding.compute(
                DemoBootstrap.Tenant,
                agent.id,
                OperationId.parse("slack.search.messages@1").getOrElse(fail("operation id")),
                slackReadKey,
                Action.Read,
                resource,
                run.hallpass.adapters.slack.Slack.workspace,
                ExternalId.parse("slack-workspace").getOrElse(fail("external ID")),
                io.circe.Json.obj("query" -> io.circe.Json.fromString("roadmap"))
              )
            )
          )
          .fold(error => fail(s"audit context failed: $error"), identity)
        audit = PostgresExecutionAudit(xa)
        _ <- audit.record(ExecutionAuditEvent.LeaseIssued(context, occurredAt))
        incomplete <- audit.hasCompletedExecution(DemoBootstrap.Tenant, Some(agent.id))
        _ <- audit
          .record(
            ExecutionAuditEvent.ExecutionCompleted(
              context,
              occurredAt.plusSeconds(1)
            )
          )
        persisted <- (TenantSession.establish(DemoBootstrap.Tenant) *>
          sql"""select correlation_id, agent_principal_id, tool_id, capability_id, resource_id, action,
                       policy_id, policy_version, agent_credential_id, event_kind, safe_outcome, occurred_at
                  from execution_audit_events where authorization_request_id=${request.toString}::uuid
                    and event_kind = 'LEASE_ISSUED'"""
            .query[(String, java.util.UUID, java.util.UUID, java.util.UUID, java.util.UUID, String, java.util.UUID, Int, Option[java.util.UUID], String, String, Instant)]
            .unique).transact(xa)
        orderedDelegations <- (TenantSession.establish(DemoBootstrap.Tenant) *>
          sql"""select d.delegation_id from execution_audit_event_delegations d
                  join execution_audit_events e on e.tenant_id = d.tenant_id and e.id = d.execution_audit_event_id
                  where e.event_kind = 'LEASE_ISSUED'
                  order by d.delegation_position asc""".query[java.util.UUID].to[Vector]).transact(xa)
        visibleEvents <- (TenantSession.establish(DemoBootstrap.Tenant) *>
          sql"select count(*) from execution_audit_events".query[Long].unique).transact(xa)
        invisibleWithoutTenant <- sql"select count(*) from execution_audit_events".query[Long].unique.transact(xa)
        firstPage <- audit.page(DemoBootstrap.Tenant, Some(agent.id), 1, None)
        secondPage <- audit.page(DemoBootstrap.Tenant, Some(agent.id), 1, firstPage.nextCursor)
        requestPage1 <- audit.forRequest(DemoBootstrap.Tenant, Some(agent.id), request, 1, None)
        requestPage2 <- audit.forRequest(DemoBootstrap.Tenant, Some(agent.id), request, 1, requestPage1.nextCursor)
        requestHistoryWrongTenant <- audit.forRequest(TenantId.random(), None, request, 10, None)
        requestHistoryWrongAgent <- audit.forRequest(DemoBootstrap.Tenant, Some(AgentId.random()), request, 10, None)
        history <- audit.recent(DemoBootstrap.Tenant, Some(agent.id), 10)
        allHistory <- audit.recent(DemoBootstrap.Tenant, None, 10)
        wrongTenant <- audit.recent(TenantId.random(), None, 10)
        otherAgent <- repository
          .create(DemoBootstrap.Tenant, CreateAgent("Other audit agent", None))
          .flatMap(_.fold(_ => IO.raiseError(RuntimeException("other agent creation failed")), IO.pure))
        otherHistory <- audit.recent(DemoBootstrap.Tenant, Some(otherAgent.id), 10)
        _ <- (2 to 103).toVector.traverse_(offset => audit.record(ExecutionAuditEvent.LeaseIssued(context, occurredAt.plusSeconds(offset.toLong))))
        recentWindow <- audit.recent(DemoBootstrap.Tenant, Some(agent.id), 100)
        completed <- audit.hasCompletedExecution(DemoBootstrap.Tenant, Some(agent.id))
        completedWorkspace <- audit.hasCompletedExecution(DemoBootstrap.Tenant)
        completedOtherAgent <- audit.hasCompletedExecution(DemoBootstrap.Tenant, Some(otherAgent.id))
        completedOtherTenant <- audit.hasCompletedExecution(TenantId.random())
      yield
        assertEquals(incomplete, false)
        assertEquals(completed, true)
        assertEquals(completedWorkspace, true)
        assertEquals(completedOtherAgent, false)
        assertEquals(completedOtherTenant, false)
        assert(!recentWindow.exists(_.eventKind == ExecutionHistoryEventKind.ExecutionCompleted))
        assertEquals(firstPage.entries.map(_.eventKind), Vector(ExecutionHistoryEventKind.ExecutionCompleted))
        assert(firstPage.nextCursor.nonEmpty)
        assertEquals(secondPage.entries.map(_.eventKind), Vector(ExecutionHistoryEventKind.LeaseIssued))
        assertEquals(secondPage.nextCursor, None)
        assertEquals(requestPage1.entries.map(_.eventKind), Vector(ExecutionHistoryEventKind.LeaseIssued))
        assert(requestPage1.nextCursor.nonEmpty)
        assertEquals(requestPage2.entries.map(_.eventKind), Vector(ExecutionHistoryEventKind.ExecutionCompleted))
        assertEquals(requestPage2.nextCursor, None)
        assertEquals(requestHistoryWrongTenant.entries, Vector.empty)
        assertEquals(requestHistoryWrongAgent.entries, Vector.empty)
        assertEquals(history.map(_.eventKind), Vector(ExecutionHistoryEventKind.ExecutionCompleted, ExecutionHistoryEventKind.LeaseIssued))
        assertEquals(history.map(_.safeOutcome), Vector(ExecutionHistoryOutcome.Completed, ExecutionHistoryOutcome.Issued))
        assertEquals(history.map(_.tool.value).distinct, Vector("slack_search_messages"))
        assertEquals(history.map(_.capability).distinct, Vector("Slack.Message.Read"))
        assertEquals(history.map(_.agentId).distinct, Vector(agent.id))
        assertEquals(allHistory, history)
        assertEquals(wrongTenant, Vector.empty)
        assertEquals(otherHistory, Vector.empty)
        assertEquals(persisted._1, correlation.value)
        assertEquals(persisted._2.toString, agent.id.toString)
        assertEquals(persisted._3.toString, tool.toString)
        assertEquals(persisted._4.toString, capability.value.toString)
        assertEquals(persisted._5.toString, resource.toString)
        assertEquals(persisted._6, "READ")
        assertEquals(persisted._7.toString, policy.toString)
        assertEquals(persisted._8, 1)
        assertEquals(persisted._9.map(_.toString), Some(credential.toString))
        assertEquals(persisted._10, "LEASE_ISSUED")
        assertEquals(persisted._11, "ISSUED")
        assertEquals(persisted._12, occurredAt)
        assertEquals(orderedDelegations.map(_.toString), Vector(firstDelegation.toString, secondDelegation.toString))
        assertEquals(visibleEvents, 2L)
        assertEquals(invisibleWithoutTenant, 0L)
  }

  private def setupEvidence(
      xa: org.typelevel.doobie.Transactor[IO],
      tenant: String,
      human: String,
      agent: String,
      resource: String,
      credential: AgentCredentialId,
      request: AuthorizationRequestId,
      service: ServiceId,
      firstDelegation: DelegationId,
      secondDelegation: DelegationId,
      correlation: ExecutionAuditCorrelationId,
      at: Instant
  ): IO[Unit] =
    (TenantSession.establish(DemoBootstrap.Tenant) *> (for
      _ <- sql"insert into principals(id, tenant_id, kind) values (${service.toString}::uuid, $tenant::uuid, 'SERVICE')".update.run
      _ <- sql"""insert into agent_credentials(
                    id, tenant_id, agent_principal_id, selector, verifier, verifier_algorithm, verifier_key_id
                  ) values (
                    ${credential.toString}::uuid, $tenant::uuid, $agent::uuid, 'AuditAdapterCred01',
                    decode(repeat('ab', 32), 'hex'), 'HMAC_SHA256_V1', 'local-test-v1'
                  )""".update.run
      _ <- sql"""insert into authorization_requests(
                    id, tenant_id, subject_principal_id, resource_id, action, correlation_id
                  ) values (
                    ${request.toString}::uuid, $tenant::uuid, $agent::uuid, $resource::uuid, 'READ', ${correlation.value}
                  )""".update.run
      _ <- sql"""insert into delegations(
                    id, tenant_id, grantor_principal_id, grantee_principal_id, valid_from
                  ) values (
                    ${firstDelegation.toString}::uuid, $tenant::uuid, $human::uuid, ${service.toString}::uuid, $at
                  )""".update.run
      _ <- sql"""insert into delegations(
                    id, tenant_id, grantor_principal_id, grantee_principal_id, parent_delegation_id, valid_from
                  ) values (
                    ${secondDelegation.toString}::uuid, $tenant::uuid, ${service.toString}::uuid, $agent::uuid,
                    ${firstDelegation.toString}::uuid, $at
                  )""".update.run
    yield ())).transact(xa)
