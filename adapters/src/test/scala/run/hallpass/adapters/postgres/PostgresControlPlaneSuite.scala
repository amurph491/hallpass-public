package run.hallpass.adapters.postgres

import java.sql.DriverManager
import java.time.Instant
import cats.effect.IO
import cats.effect.kernel.Ref
import cats.syntax.all.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import munit.CatsEffectSuite
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.DockerClientFactory
import scala.compiletime.uninitialized
import run.hallpass.adapters.security.{AgentCredentialHmacKey, AgentCredentialKeyRing, AgentCredentialHmacSha256}
import io.circe.Json
import run.hallpass.adapters.slack.{Slack, SlackAccessToken, SlackSearchMessagesOperation}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

final class PostgresControlPlaneSuite extends CatsEffectSuite:
  private var container: PostgreSQLContainer[?] = uninitialized
  private var config: DatabaseConfig = uninitialized
  private var dockerAvailable = false
  private val session = SessionToken.generate(java.security.SecureRandom()).oauthBinding

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      val admin = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
      try
        val statement = admin.createStatement()
        statement.execute(
          "create role hallpass login password 'test-password' nosuperuser nocreatedb nocreaterole noreplication"
        )
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

  /** The Slack search operation pointed at a tool the tenant catalog has never mapped. */
  private final class MissingToolOperation extends OperationDescriptor[SearchQuery, Slack.Workspace]:
    val id: OperationId = OperationId.parse("slack.missing.tool@1").getOrElse(fail("operation id"))
    val tool: ExternalToolId = ExternalToolId.parse("missing_external_tool").getOrElse(fail("tool"))
    def description: String = SlackSearchMessagesOperation.description
    def capability: CapabilityKey = SlackSearchMessagesOperation.capability
    def action: Action = SlackSearchMessagesOperation.action
    def target: ResourceKind[Slack.Workspace] = SlackSearchMessagesOperation.target
    def audience: ExecutorAudience = SlackSearchMessagesOperation.audience
    def inputSchema: Json = SlackSearchMessagesOperation.inputSchema
    def decode(arguments: Json) = SlackSearchMessagesOperation.decode(arguments)
    def locate(input: SearchQuery) = SlackSearchMessagesOperation.locate(input)
    def facts(input: SearchQuery) = SlackSearchMessagesOperation.facts(input)
    def canonical(input: SearchQuery) = SlackSearchMessagesOperation.canonical(input)

  test("bootstrap is idempotent and agent records round trip through typed IDs") {
    requireDocker()
    PostgresDatabase
      .resource(config)
      .use: xa =>
        val repository = PostgresControlPlane(xa)
        for
          _ <- DemoBootstrap.run(xa) *> DemoBootstrap.run(xa)
          created <- repository.create(DemoBootstrap.Tenant, CreateAgent("Local Codex", Some("local demo")))
          agents <- repository.list(DemoBootstrap.Tenant)
          found <- created.fold(_ => IO.pure(None), value => repository.find(DemoBootstrap.Tenant, value.id))
        yield
          assert(created.isRight)
          assertEquals(agents.map(_.name), Vector("Local Codex"))
          assertEquals(found.map(_.name), Some("Local Codex"))
  }

  test("unmapped agent tool calls persist a tenant-scoped denial without a resource or action") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      val repository = PostgresControlPlane(xa)
      val journal = repository
      val credentialRepository = PostgresAgentCredentials(xa)
      val key = AgentCredentialHmacKey.fromBytes("integration-test", Array.fill[Byte](32)(17)).toOption.get
      val keyRing = AgentCredentialKeyRing.from("integration-test", Seq(key)).toOption.get
      val credentialCrypto = AgentCredentialHmacSha256(keyRing)
      val directory = PostgresIdentityDirectory(xa)
      val authenticator = AgentAuthenticator[IO](directory, credentialRepository, credentialCrypto)
      val enrollment = AgentEnrollmentService(credentialRepository, credentialCrypto)
      val enrollmentRequest = AgentCredentialEnrollmentRequest.from(Some("unmapped tool test"), None).toOption.get
      val broker = new CredentialBroker[IO]:
        def issueLease(
            authorized: AuthorizedCapability,
            requestId: AuthorizationRequestId,
            audience: ExecutorAudience,
            auditMetadata: ExecutionAuditMetadata
        ) = IO.raiseError[ExecutionLease](IllegalStateException("unmapped tool must not issue a lease"))
      val missingOperation = new MissingToolOperation
      val unusedClient = new ProviderOperationClient[SearchQuery, Slack.Workspace, SlackAccessToken]:
        def dispatch(target: SelectedResource[Slack.Workspace], input: SearchQuery, credential: SlackAccessToken) =
          IO.raiseError[ToolResult](IllegalStateException("unmapped tool must not execute"))
      val unusedCredentials = new CredentialStrategy[Slack.Workspace, SlackAccessToken]:
        def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[Slack.Workspace]) =
          IO.raiseError(IllegalStateException("unmapped tool must not resolve a credential"))
      val unusedAuthority = new LeaseAuthorityValidator[IO]:
        def validate(lease: RedeemedExecutionLease, now: Instant) =
          IO.raiseError(IllegalStateException("unmapped tool must not revalidate a lease"))
      val service = for
        leases <- InMemoryExecutionLeaseStore.create
        audit <- InMemoryExecutionAuditRecorder.create
        gate <- SingleProcessTenantExecutionMutationGate.create
        registry <- IO.fromEither(
          OperationRegistry
            .from(Vector(RegisteredOperation(missingOperation, unusedClient, unusedCredentials)))
            .leftMap(error => IllegalStateException(error.toString))
        )
        executor = ProviderExecutionService(leases, Clock.system, audit, unusedAuthority, gate)
      yield AgentToolService(registry, ResourceResolver(repository), repository, journal, broker, executor)
      for
        _ <- DemoBootstrap.run(xa)
        _ <- SlackConnectionFixture.ensure(xa, Instant.parse("2026-09-24T12:00:00Z"))
        administrator <- HumanAuthenticator[IO](directory)
          .authenticate(DemoBootstrap.AdministratorUser, DemoBootstrap.Tenant, Instant.parse("2026-09-24T12:00:00Z"))
          .flatMap(result => IO.fromEither(result.leftMap(error => RuntimeException(error.toString))))
        created <- repository.create(DemoBootstrap.Tenant, CreateAgent("Unmapped tool agent", None))
        agent <- IO.fromEither(created.leftMap(error => RuntimeException(error.toString)))
        disclosure <- enrollment.enroll(administrator, agent.id, enrollmentRequest, Instant.parse("2026-09-24T12:00:00Z"))
          .flatMap(_.fold(error => IO.raiseError(RuntimeException(error.toString)), IO.pure))
        authenticated <- authenticator.authenticate(
          disclosure.credential,
          UnverifiedExecutionClaims.empty,
          Instant.parse("2026-09-24T12:00:00Z")
        ).map(_.fold(error => throw RuntimeException(error.toString), identity))
        tools <- service
        outcome <- tools.execute(
          authenticated,
          missingOperation.id,
          Json.obj("query" -> Json.fromString("roadmap")),
          Instant.parse("2026-09-24T12:00:00Z")
        )
        snapshot = outcome match
          case AgentToolExecutionResult.Denied(value, DenialReason.UnmappedTool) => value
          case other => fail(s"expected an unmapped-tool denial, received $other")
        persisted <- (TenantSession.establish(DemoBootstrap.Tenant) *>
          sql"""select r.tenant_id, r.resource_id, r.action, d.outcome, d.reason_code, r.authorization_source
                   from authorization_requests r join authorization_decisions d
                     on d.tenant_id=r.tenant_id and d.request_id=r.id
                  where r.id=${snapshot.requestId.toString}::uuid"""
            .query[(java.util.UUID, Option[java.util.UUID], Option[String], String, String, Option[String])]
            .unique).transact(xa)
      yield
        assertEquals(persisted._1.toString, DemoBootstrap.Tenant.toString)
        assertEquals(persisted._2, None)
        assertEquals(persisted._3, None)
        assertEquals(persisted._4, "DENY")
        assertEquals(persisted._5, "UnmappedTool")
        assertEquals(persisted._6, Some("AGENT_CALL"))

  }

  test("bootstrap's canonical policy JSON authorizes its bound owner") {
    requireDocker()
    PostgresDatabase
      .resource(config)
      .use: xa =>
        val repository = PostgresControlPlane(xa)
        val service = DynamicAuthorizationService[IO](repository, repository)
        for
          _ <- DemoBootstrap.run(xa)
          persistedPolicies <- (TenantSession.establish(DemoBootstrap.Tenant) *>
            sql"""select p.id, p.version, p.definition::text
                     from policies p join policy_bindings b on b.tenant_id=p.tenant_id and b.policy_id=p.id
                    where p.tenant_id=${DemoBootstrap.Tenant.toString}::uuid and p.status='ACTIVE'
                      and b.subject_principal_id=${DemoBootstrap.Human.id.toString}::uuid
                      and b.resource_id=${DemoBootstrap.SlackResource.toString}::uuid
                    order by b.priority desc, p.id asc"""
              .query[(java.util.UUID, Int, String)]
              .to[Vector]).transact(xa)
          snapshot <- repository.snapshotFor(
            DemoBootstrap.Tenant,
            DemoBootstrap.Human,
            "slack_search_messages"
          )
          result <- service.authorize(
            DemoBootstrap.Tenant,
            DemoBootstrap.Human,
            "slack_search_messages",
            "bootstrap-owner-policy",
            Instant.now()
          )
        yield
          snapshot match
            case Right(value) =>
              assertEquals(value.policies.values.size, 1)
              assertEquals(value.policies.values.head.statements.toSet.head.effect, Effect.Allow)
            case Left(error) => fail(s"bootstrap owner policy could not load: $error; rows=$persistedPolicies")
          result match
            case _: AuthorizationResult.Authorized => ()
            case unexpected                        => fail(s"bootstrap owner policy was not authorized: $unexpected")
  }

  test("UI-style grant changes authorization and revocation changes it back immediately") {
    requireDocker()
    PostgresDatabase
      .resource(config)
      .use: xa =>
        val repository = PostgresControlPlane(xa)
        val service = DynamicAuthorizationService[IO](repository, repository)
        for
          _ <- DemoBootstrap.run(xa)
          agent <- repository
            .create(DemoBootstrap.Tenant, CreateAgent("Revocation Agent", None))
            .flatMap(_.fold(_ => IO.raiseError(RuntimeException("agent create failed")), IO.pure))
          capabilities <- repository.capabilities(DemoBootstrap.Tenant)
          read = capabilities.find(_.name == "Slack.Message.Read").get
          slack <- SlackConnectionFixture.ensure(xa, Instant.now())
          before <- service.authorize(
            DemoBootstrap.Tenant,
            Principal.Agent(agent.id),
            "slack_search_messages",
            "before-grant",
            Instant.now()
          )
          grant <- repository
            .create(
              DemoBootstrap.Tenant,
              CreateDelegation(
                DemoBootstrap.Human,
                Principal.Agent(agent.id),
                read.id,
                slack.resource,
                read.descriptor.action,
                None
              )
            )
            .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"grant failed: $error")), IO.pure))
          allowed <- service.authorize(
            DemoBootstrap.Tenant,
            Principal.Agent(agent.id),
            "slack_search_messages",
            "allowed",
            Instant.now()
          )
          _ <- repository
            .revoke(DemoBootstrap.Tenant, grant.id, Instant.now())
            .flatMap(_.fold(_ => IO.raiseError(RuntimeException("revoke failed")), IO.pure))
          denied <- service.authorize(
            DemoBootstrap.Tenant,
            Principal.Agent(agent.id),
            "slack_search_messages",
            "revoked",
            Instant.now()
          )
          history <- repository.recent(DemoBootstrap.Tenant, 10)
        yield
          assertEquals(before, AuthorizationResult.Denied(DenialReason.NoMatchingAuthority))
          assert(allowed.isInstanceOf[AuthorizationResult.Authorized])
          assertEquals(denied, AuthorizationResult.Denied(DenialReason.InactiveDelegation(grant.id)))
          assertEquals(history.take(3).map(_.correlationId), Vector("revoked", "allowed", "before-grant"))
          assertEquals(history.take(3).map(_.authorizationSource), Vector.fill(3)(Some(AuthorizationSource.HumanPreview)))
  }

  test("RLS hides tenant data when context is missing or mismatched") {
    requireDocker()
    PostgresDatabase
      .resource(config)
      .use: xa =>
        for
          _ <- DemoBootstrap.run(xa)
          withoutContext <- sql"select count(*) from resources".query[Long].unique.transact(xa)
          otherTenant = TenantId.random()
          mismatched <- (TenantSession.establish(otherTenant) *> sql"select count(*) from resources".query[Long].unique)
            .transact(xa)
        yield
          assertEquals(withoutContext, 0L)
          assertEquals(mismatched, 0L)
  }

  test("agent credential schema enforces tenant subtype, verifier, and live-credential invariants") {
    requireDocker()
    PostgresDatabase
      .resource(config)
      .use: xa =>
        val repository = PostgresControlPlane(xa)
        val tenant = DemoBootstrap.Tenant.toString
        val human = DemoBootstrap.Human.id.toString
        val credentialOne = "30000000-0000-4000-8000-000000000001"
        val credentialTwo = "30000000-0000-4000-8000-000000000002"
        for
          _ <- DemoBootstrap.run(xa)
          agent <- repository
            .create(DemoBootstrap.Tenant, CreateAgent("Credential Agent", None))
            .flatMap(_.fold(_ => IO.raiseError(RuntimeException("agent create failed")), IO.pure))
          agentId = agent.id.toString
          insert =
            sql"""insert into agent_credentials(
              id, tenant_id, agent_principal_id, selector, verifier,
              verifier_algorithm, verifier_key_id, issued_by_human_principal_id
            ) values (
              $credentialOne::uuid, $tenant::uuid, $agentId::uuid, 'Abcdefghijklmnop', decode(repeat('ab', 32), 'hex'),
              'HMAC_SHA256_V1', 'local-v1', $human::uuid
            )""".update.run
          _ <- (TenantSession.establish(DemoBootstrap.Tenant) *> insert).transact(xa)
          duplicate <- (TenantSession.establish(DemoBootstrap.Tenant) *>
            sql"""insert into agent_credentials(
              id, tenant_id, agent_principal_id, selector, verifier, verifier_algorithm, verifier_key_id
            ) values (
              $credentialTwo::uuid, $tenant::uuid, $agentId::uuid, 'Pponmlkjihgfedcb', decode(repeat('cd', 32), 'hex'),
              'HMAC_SHA256_V1', 'local-v1'
            )""".update.run).attempt.transact(xa)
          withoutContext <- sql"select count(*) from agent_credentials".query[Long].unique.transact(xa)
        yield
          assert(duplicate.isLeft)
          assertEquals(withoutContext, 0L)
  }

  test("OAuth states are persisted per tenant, expire, and can only be consumed once") {
    requireDocker()
    PostgresDatabase
      .resource(config)
      .use: xa =>
        val states = new PostgresOAuthStateRepository(xa)
        val now = Instant.now()
        val usable = OAuthState.parse("a" * 43).get
        val expiring = OAuthState.parse("b" * 43).get
        for
          _ <- DemoBootstrap.run(xa)
          _ <- states.create(DemoBootstrap.Tenant, DemoBootstrap.SlackResource, usable, session, now.plusSeconds(60))
          first <- states.consume(DemoBootstrap.Tenant, usable, session, now)
          replay <- states.consume(DemoBootstrap.Tenant, usable, session, now)
          _ <- states.create(DemoBootstrap.Tenant, DemoBootstrap.SlackResource, expiring, session, now.plusSeconds(60))
          expired <- states.consume(DemoBootstrap.Tenant, expiring, session, now.plusSeconds(61))
          purged <- states.purgeExpired(DemoBootstrap.Tenant, now.plusSeconds(7200))
        yield
          assertEquals(first, Right(DemoBootstrap.SlackResource))
          assertEquals(replay, Left(OAuthError.StateAlreadyUsed))
          assertEquals(expired, Left(OAuthError.ExpiredState))
          assertEquals(purged, 2L)
  }

  test("OAuth state completes only in the browser session that started it") {
    requireDocker()
    PostgresDatabase
      .resource(config)
      .use: xa =>
        val states = new PostgresOAuthStateRepository(xa)
        val now = Instant.now()
        val usable = OAuthState.parse("d" * 43).get
        val otherSession = SessionToken.generate(java.security.SecureRandom()).oauthBinding
        for
          _ <- DemoBootstrap.run(xa)
          _ <- states.create(DemoBootstrap.Tenant, DemoBootstrap.SlackResource, usable, session, now.plusSeconds(60))
          foreign <- states.consume(DemoBootstrap.Tenant, usable, otherSession, now)
          owner <- states.consume(DemoBootstrap.Tenant, usable, session, now)
        yield
          assertEquals(foreign, Left(OAuthError.InvalidState))
          assertEquals(owner, Right(DemoBootstrap.SlackResource), "another session's attempt must not consume the state")
  }

  test("OAuth state concurrent consumption allows exactly one consumer") {
    requireDocker()
    PostgresDatabase
      .resource(config)
      .use: xa =>
        val states = new PostgresOAuthStateRepository(xa)
        val now = Instant.now()
        val usable = OAuthState.parse("c" * 43).get
        for
          _ <- DemoBootstrap.run(xa)
          _ <- states.create(DemoBootstrap.Tenant, DemoBootstrap.SlackResource, usable, session, now.plusSeconds(60))
          results <- List.fill(2)(states.consume(DemoBootstrap.Tenant, usable, session, now)).parSequence
        yield
          assertEquals(results.count(_.isRight), 1)
          assertEquals(results.count(_ == Left(OAuthError.StateAlreadyUsed)), 1)
  }

  test("expired OAuth connections are not resolved for credential retrieval") {
    requireDocker()
    PostgresDatabase
      .resource(config)
      .use: xa =>
        val connections = new PostgresConnectionRepository(xa)
        val now = Instant.now()
        val expired = Connection(
          ConnectionId.random(),
          DemoBootstrap.SlackResource,
          "SLACK",
          ConnectionStatus.Active,
          Some("expired-account"),
          Some("Expired workspace"),
          Some(now.minusSeconds(1)),
          now.minusSeconds(2),
          now
        )
        for
          _ <- DemoBootstrap.run(xa)
          _ <- connections.create(DemoBootstrap.Tenant, expired, SecretReference.random())
          found <- connections.findForResource(DemoBootstrap.Tenant, DemoBootstrap.SlackResource)
        yield assertEquals(found, None)
  }

  test("untrusted suggested mappings never resolve for authorization") {
    requireDocker()
    PostgresDatabase
      .resource(config)
      .use: xa =>
        val repository = PostgresControlPlane(xa)
        val tenant = DemoBootstrap.Tenant.toString
        val tool = "20000000-0000-4000-8000-000000000001"
        val capability = "10000000-0000-4000-8000-000000000010"
        val resource = DemoBootstrap.SlackResource.toString
        for
          _ <- DemoBootstrap.run(xa)
          _ <- (TenantSession.establish(DemoBootstrap.Tenant) *> (for
            _ <-
              sql"insert into resources(id,tenant_id,resource_type,name,parent_resource_id,external_id) values ($tool::uuid,$tenant::uuid,'TOOL','Suggested tool',$resource::uuid,'suggested_tool')".update.run
            _ <-
              sql"insert into tools(tenant_id,resource_id,protocol) values ($tenant::uuid,$tool::uuid,'MCP')".update.run
            _ <-
              sql"insert into tool_capability_mappings(tenant_id,tool_id,capability_id,mapping_source,trusted) values ($tenant::uuid,$tool::uuid,$capability::uuid,'AUTHAI_SUGGESTED',false)".update.run
          yield ())).transact(xa)
          snapshot <- repository.snapshotFor(DemoBootstrap.Tenant, DemoBootstrap.Human, "suggested_tool")
        yield assertEquals(snapshot, Left(AuthorityLoadError.UnmappedTool))
  }

  test("multiple trusted mappings fail closed instead of selecting an arbitrary capability") {
    requireDocker()
    PostgresDatabase
      .resource(config)
      .use: xa =>
        val repository = PostgresControlPlane(xa)
        val tenant = DemoBootstrap.Tenant.toString
        val resource = DemoBootstrap.SlackResource.toString
        val extraCapability = "20000000-0000-4000-8000-000000000002"
        val searchTool = "10000000-0000-4000-8000-000000000012"
        for
          _ <- DemoBootstrap.run(xa)
          _ <- (TenantSession.establish(DemoBootstrap.Tenant) *>
            sql"""insert into capabilities(id, tenant_id, namespace, name, action, resource_id)
                   values ($extraCapability::uuid, $tenant::uuid, 'Slack.Message', 'AlternativeRead', 'READ', $resource::uuid)""".update.run *>
            sql"""insert into tool_capability_mappings(tenant_id, tool_id, capability_id, mapping_source, trusted)
                   values ($tenant::uuid, $searchTool::uuid, $extraCapability::uuid, 'CUSTOMER_DEFINED', true)""".update.run
          ).transact(xa)
          snapshot <- repository.snapshotFor(DemoBootstrap.Tenant, DemoBootstrap.Human, "slack_search_messages")
        yield assertEquals(snapshot, Left(AuthorityLoadError.AmbiguousMapping))
  }

  test("agent and delegation creation read injected time on every execution") {
    requireDocker()
    val at = Instant.parse("2026-09-27T12:00:00Z")
    PostgresDatabase.resource(config).use: xa =>
      for
        _ <- DemoBootstrap.run(xa)
        time <- Ref.of[IO, Instant](at.minusSeconds(60))
        clock = new Clock[IO]:
          def now = time.get
        repository = PostgresControlPlane(xa, clock)
        pendingAgent = repository.create(DemoBootstrap.Tenant, CreateAgent("Injected clock agent", None))
        _ <- time.set(at)
        first <- pendingAgent.flatMap(value => IO.fromEither(value.leftMap(error => RuntimeException(error.toString))))
        _ <- time.set(at.plusSeconds(60))
        second <- pendingAgent.flatMap(value => IO.fromEither(value.leftMap(error => RuntimeException(error.toString))))
        found <- repository.find(DemoBootstrap.Tenant, first.id)
        capabilities <- repository.capabilities(DemoBootstrap.Tenant)
        read = capabilities.find(_.name == "Slack.Message.Read").getOrElse(fail("read capability"))
        slack <- SlackConnectionFixture.ensure(xa, at)
        pendingDelegation = repository.create(DemoBootstrap.Tenant, CreateDelegation(
          DemoBootstrap.Human, Principal.Agent(first.id), read.id, slack.resource, read.descriptor.action, None))
        _ <- time.set(at.plusSeconds(120))
        delegation <- pendingDelegation.flatMap(value => IO.fromEither(value.leftMap(error => RuntimeException(error.toString))))
        _ <- time.set(at.plusSeconds(180))
        nextDelegation <- pendingDelegation.flatMap(value => IO.fromEither(value.leftMap(error => RuntimeException(error.toString))))
      yield
        assertEquals(first.createdAt, at)
        assertEquals(found.map(_.createdAt), Some(at))
        assertEquals(second.createdAt, at.plusSeconds(60))
        assertNotEquals(first.id, second.id)
        assertEquals(delegation.validFrom, at.plusSeconds(120))
        assertEquals(nextDelegation.validFrom, at.plusSeconds(180))
        assertNotEquals(delegation.id, nextDelegation.id)
  }
