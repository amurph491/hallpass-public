package run.hallpass.adapters.postgres

import java.sql.DriverManager
import java.time.Instant
import cats.effect.IO
import cats.syntax.all.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.implicits.javatimedrivernative.*
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import scala.compiletime.uninitialized
import run.hallpass.application.*
import run.hallpass.kernel.*

final class ExecutionAuditSchemaSuite extends CatsEffectSuite:
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

  test("execution evidence enforces tenant-correlated typed lifecycle metadata") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      val repository = PostgresControlPlane(xa)
      val tenant = DemoBootstrap.Tenant.toString
      val human = DemoBootstrap.Human.id.toString
      val resource = DemoBootstrap.SlackResource.toString
      val tool = "10000000-0000-4000-8000-000000000012"
      val capability = "10000000-0000-4000-8000-000000000010"
      val policy = "10000000-0000-4000-8000-000000000014"
      val request = "40000000-0000-4000-8000-000000000001"
      val credential = "40000000-0000-4000-8000-000000000002"
      val delegation = "40000000-0000-4000-8000-000000000003"
      val event = "40000000-0000-4000-8000-000000000004"
      val correlation = "execution-audit-evidence"
      val now = Instant.now()
      for
        _ <- DemoBootstrap.run(xa)
        agent <- repository
          .create(DemoBootstrap.Tenant, CreateAgent("Execution audit agent", None))
          .flatMap(_.fold(_ => IO.raiseError(RuntimeException("agent creation failed")), IO.pure))
        agentId = agent.id.toString
        _ <- (TenantSession.establish(DemoBootstrap.Tenant) *> (for
          _ <-
            sql"""insert into agent_credentials(
              id, tenant_id, agent_principal_id, selector, verifier, verifier_algorithm, verifier_key_id
            ) values (
              $credential::uuid, $tenant::uuid, $agentId::uuid, 'AuditCredential000',
              decode(repeat('ef', 32), 'hex'), 'HMAC_SHA256_V1', 'local-test-v1'
            )""".update.run
          _ <-
            sql"""insert into authorization_requests(
              id, tenant_id, subject_principal_id, resource_id, action, correlation_id
            ) values ($request::uuid, $tenant::uuid, $agentId::uuid, $resource::uuid, 'READ', $correlation)""".update.run
          _ <-
            sql"""insert into delegations(
              id, tenant_id, grantor_principal_id, grantee_principal_id, valid_from
            ) values ($delegation::uuid, $tenant::uuid, $human::uuid, $agentId::uuid, $now)""".update.run
          _ <-
            sql"""insert into execution_audit_events(
              id, tenant_id, authorization_request_id, correlation_id, agent_principal_id,
              tool_id, capability_id, resource_id, action, policy_id, policy_version,
              agent_credential_id, event_kind, safe_outcome, occurred_at
            ) values (
              $event::uuid, $tenant::uuid, $request::uuid, $correlation, $agentId::uuid,
              $tool::uuid, $capability::uuid, $resource::uuid, 'READ', $policy::uuid, 1,
              $credential::uuid, 'LEASE_ISSUED', 'ISSUED', $now
            )""".update.run
          _ <-
            sql"""insert into execution_audit_event_delegations(
              tenant_id, execution_audit_event_id, delegation_position, delegation_id
            ) values ($tenant::uuid, $event::uuid, 0, $delegation::uuid)""".update.run
        yield ())).transact(xa)
        delegationCount <- (TenantSession.establish(DemoBootstrap.Tenant) *>
          sql"select count(*) from execution_audit_event_delegations".query[Long].unique).transact(xa)
        withoutContext <- sql"select count(*) from execution_audit_events".query[Long].unique.transact(xa)
        mismatchedCorrelation <- (TenantSession.establish(DemoBootstrap.Tenant) *>
          sql"""insert into execution_audit_events(
            id, tenant_id, authorization_request_id, correlation_id, agent_principal_id,
            tool_id, capability_id, resource_id, action, event_kind, safe_outcome, occurred_at
          ) values (
            '40000000-0000-4000-8000-000000000005'::uuid, $tenant::uuid, $request::uuid,
            'different-correlation', $agentId::uuid, $tool::uuid, $capability::uuid,
            $resource::uuid, 'READ', 'LEASE_ISSUED', 'ISSUED', $now
          )""".update.run).attempt.transact(xa)
        invalidOutcome <- (TenantSession.establish(DemoBootstrap.Tenant) *>
          sql"""insert into execution_audit_events(
            id, tenant_id, authorization_request_id, correlation_id, agent_principal_id,
            tool_id, capability_id, resource_id, action, event_kind, safe_outcome, occurred_at
          ) values (
            '40000000-0000-4000-8000-000000000006'::uuid, $tenant::uuid, $request::uuid,
            $correlation, $agentId::uuid, $tool::uuid, $capability::uuid, $resource::uuid,
            'READ', 'LEASE_ISSUED', 'COMPLETED', $now
          )""".update.run).attempt.transact(xa)
        insertKind = (id: String, kind: String, outcome: String) =>
          (TenantSession.establish(DemoBootstrap.Tenant) *>
            sql"""insert into execution_audit_events(
              id, tenant_id, authorization_request_id, correlation_id, agent_principal_id,
              tool_id, capability_id, resource_id, action, event_kind, safe_outcome, occurred_at
            ) values (
              $id::uuid, $tenant::uuid, $request::uuid, $correlation, $agentId::uuid, $tool::uuid,
              $capability::uuid, $resource::uuid, 'READ', $kind, $outcome, $now
            )""".update.run).attempt.transact(xa)
        coordination <- insertKind(
          "40000000-0000-4000-8000-000000000007",
          "COORDINATION_UNAVAILABLE",
          "DENIED_COORDINATION_UNAVAILABLE"
        )
        coordinationAsUnknown <- insertKind("40000000-0000-4000-8000-000000000008", "COORDINATION_UNAVAILABLE", "UNKNOWN")
        unknownAsCoordination <- insertKind(
          "40000000-0000-4000-8000-000000000009",
          "COMPLETION_UNKNOWN",
          "DENIED_COORDINATION_UNAVAILABLE"
        )
        unlistedKind <- insertKind("40000000-0000-4000-8000-00000000000a", "PROVIDER_TEXT", "UNKNOWN")
      yield
        assertEquals(delegationCount, 1L)
        assertEquals(withoutContext, 0L)
        assert(mismatchedCorrelation.isLeft)
        assert(invalidOutcome.isLeft)
        assertEquals(coordination, Right(1))
        assert(coordinationAsUnknown.isLeft)
        assert(unknownAsCoordination.isLeft)
        assert(unlistedKind.isLeft)
}
