package run.hallpass.adapters.postgres

import java.sql.{DriverManager, SQLException}
import java.time.Instant
import java.util.UUID
import cats.effect.IO
import cats.syntax.all.*
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import scala.compiletime.uninitialized
import run.hallpass.adapters.slack.Slack
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Persistence coverage for capability identity: the kernel's `CapabilityKey` is derived only from trusted
  * catalog rows (`capabilities.namespace || '.' || capabilities.name`), so two capabilities on the same resource and
  * action stay distinct authority. Every test provisions its own tenant, so catalog and policy edits cannot leak
  * between tests. */
final class PostgresCapabilityIdentitySuite extends CatsEffectSuite:
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

  private val slackReadKey = CapabilityKey.parse("Slack.Message.Read").getOrElse(fail("capability key"))
  private val slackExportKey = CapabilityKey.parse("Slack.Message.Export").getOrElse(fail("capability key"))
  private val searchTool = "slack_search_messages"

  /** A freshly provisioned tenant with its identifiers, so tests can edit its catalog and policies. */
  private final case class Fixture(ids: ProvisioningIds, human: Principal.Human, root: ResourceId):
    def tenant: TenantId = ids.tenant
    def resource: ResourceId = ids.slackResource
    def readCapability: String = ids.readCapability.toString
    def readPolicy: String = ids.readPolicy.toString

  private def provision(xa: Transactor[IO]): IO[Fixture] =
    val ids = ProvisioningIds.random()
    val subject = UUID.randomUUID().toString
    val request = TenantProvisioningRequest
      .from(
        "Capability identity",
        s"capability-${subject.take(8)}",
        ExternalIdentity.from("https://idp.example.com", subject).toOption.get
      )
      .toOption
      .get
    // Grants name a connection root, never the provider's catalog resource, so every fixture connects one workspace.
    val connections = PostgresConnectionRepository(xa)
    val workspace = ExternalId.parse("T-IDENTITY").getOrElse(fail("workspace ID"))
    val connection = ConnectionId.random()
    val at = Instant.parse("2026-01-01T00:00:00Z")
    for
      provisioned <- TenantProvisioning.program(request, ids).transact(xa)
      owner = provisioned.administratorPrincipal
      _ <- connections.reserve(ids.tenant, connection, "SLACK", owner, at)
      activated <- connections.activateReserved(
        ids.tenant,
        connection,
        ConnectionActivation(
          owner, workspace, None, Some("Identity workspace"), None, "SLACK_OAUTH", SecretReference.random(),
          Slack.workspace, workspace, "Identity workspace", None, singleActiveRoot = true
        ),
        at
      )
      saved <- IO.fromEither(activated.leftMap(error => RuntimeException(s"connection activation failed: $error")))
    yield Fixture(ids, owner, saved.resource)

  private def inTenant[A](fixture: Fixture)(program: ConnectionIO[A]): ConnectionIO[A] =
    TenantSession.establish(fixture.tenant) *> program

  private def setPolicyDefinition(xa: Transactor[IO], fixture: Fixture, definition: String): IO[Unit] =
    inTenant(fixture)(
      sql"""update policies set definition=$definition::jsonb
             where tenant_id=${fixture.tenant.toString}::uuid and id=${fixture.readPolicy}::uuid""".update.run
    ).transact(xa).flatMap(rows => IO(assertEquals(rows, 1)))

  private def createAgent(repository: PostgresControlPlane, fixture: Fixture, name: String): IO[AgentId] =
    repository
      .create(fixture.tenant, CreateAgent(name, None))
      .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"agent create failed: $error")), agent => IO.pure(agent.id)))

  private def grantRead(repository: PostgresControlPlane, fixture: Fixture, agent: AgentId): IO[Delegation] =
    repository
      .create(
        fixture.tenant,
        CreateDelegation(fixture.human, Principal.Agent(agent), fixture.readCapability, fixture.root, Action.Read, None)
      )
      .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"grant failed: $error")), IO.pure))

  /** Adds a trusted `slack_export_messages` tool mapped to a second capability with the same resource and action. */
  private def addExportCapability(xa: Transactor[IO], fixture: Fixture): IO[Unit] =
    val tenant = fixture.tenant.toString
    val resource = fixture.resource.toString
    val capability = UUID.randomUUID().toString
    val tool = UUID.randomUUID().toString
    inTenant(fixture)(for
      _ <-
        sql"""insert into capabilities(id, tenant_id, namespace, name, action, resource_id)
               values ($capability::uuid, $tenant::uuid, 'Slack.Message', 'Export', 'READ', $resource::uuid)""".update.run
      _ <-
        sql"""insert into resources(id, tenant_id, resource_type, name, provider, parent_resource_id, external_id)
               values ($tool::uuid, $tenant::uuid, 'TOOL', 'Export Slack messages', 'slack', $resource::uuid, 'slack_export_messages')""".update.run
      _ <- sql"insert into tools(tenant_id, resource_id, protocol) values ($tenant::uuid, $tool::uuid, 'MCP')".update.run
      _ <-
        sql"""insert into tool_capability_mappings(tenant_id, tool_id, capability_id, mapping_source, trusted)
               values ($tenant::uuid, $tool::uuid, $capability::uuid, 'PROVIDER_DEFINED', true)""".update.run
    yield ()).transact(xa)

  private def authorizeAt(
      service: DynamicAuthorizationService[IO],
      fixture: Fixture,
      agent: AgentId,
      tool: String,
      correlation: String
  ): IO[AuthorizationResult] =
    service.authorize(fixture.tenant, Principal.Agent(agent), tool, correlation, Instant.now())

  test("a delegation loaded through snapshotFor carries the catalog key of its stored capability_id") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      val repository = PostgresControlPlane(xa)
      for
        fixture <- provision(xa)
        agent <- createAgent(repository, fixture, "Key loading agent")
        delegationId = UUID.randomUUID().toString
        // Insert the delegation rows directly so the key can only come from capability_id, not from the request path.
        _ <- inTenant(fixture)(for
          _ <-
            sql"""insert into delegations(id, tenant_id, grantor_principal_id, grantee_principal_id, valid_from)
                   values ($delegationId::uuid, ${fixture.tenant.toString}::uuid, ${fixture.human.id.toString}::uuid,
                           ${agent.toString}::uuid, ${Instant.EPOCH})""".update.run
          _ <-
            sql"""insert into delegated_capabilities(tenant_id, delegation_id, capability_id, resource_id, actions)
                   values (${fixture.tenant.toString}::uuid, $delegationId::uuid, ${fixture.readCapability}::uuid,
                           ${fixture.root.toString}::uuid, ARRAY['READ']::text[])""".update.run
        yield ()).transact(xa)
        snapshot <- repository.snapshotFor(fixture.tenant, Principal.Agent(agent), searchTool)
      yield snapshot match
        case Right(value) =>
          // The catalog capability sits on the provider resource; the delegation names the connection root.
          assertEquals(value.capability.descriptor, CapabilityDescriptor(fixture.resource, Action.Read, slackReadKey))
          assertEquals(value.delegations.map(_.id.toString), Vector(delegationId))
          assertEquals(
            value.delegations.flatMap(_.capabilities.toSet),
            Vector(CapabilityDescriptor(fixture.root, Action.Read, slackReadKey))
          )
        case Left(error) => fail(s"snapshot did not load: $error")
  }

  test("a policy with a capability allowlist containing the key still authorizes the Slack search tool") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      val repository = PostgresControlPlane(xa)
      val service = DynamicAuthorizationService[IO](repository, repository)
      for
        fixture <- provision(xa)
        _ <- setPolicyDefinition(xa, fixture, """{"action":"READ","effect":"ALLOW","capabilities":["Slack.Message.Read"]}""")
        agent <- createAgent(repository, fixture, "Allowlisted agent")
        _ <- grantRead(repository, fixture, agent)
        snapshot <- repository.snapshotFor(fixture.tenant, Principal.Agent(agent), searchTool)
        result <- authorizeAt(service, fixture, agent, searchTool, "allowlist-includes-key")
      yield
        snapshot match
          case Right(value) =>
            val statements = value.policies.values.flatMap(_.statements.toSet)
            assertEquals(statements.map(_.capabilities.map(_.toSet)), Vector(Some(Set(slackReadKey))))
          case Left(error) => fail(s"snapshot did not load: $error")
        assert(result.isInstanceOf[AuthorizationResult.Authorized], s"expected authorization, received $result")
  }

  test("a policy allowlist that excludes the requested key does not authorize") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      val repository = PostgresControlPlane(xa)
      val service = DynamicAuthorizationService[IO](repository, repository)
      for
        fixture <- provision(xa)
        agent <- createAgent(repository, fixture, "Excluded agent")
        _ <- grantRead(repository, fixture, agent)
        // Authorized baseline: the unrestricted owner policy plus the grant allow the search tool.
        baseline <- authorizeAt(service, fixture, agent, searchTool, "allowlist-baseline")
        _ <- setPolicyDefinition(xa, fixture, """{"action":"READ","effect":"ALLOW","capabilities":["Slack.Message.Export"]}""")
        excluded <- authorizeAt(service, fixture, agent, searchTool, "allowlist-excludes-key")
      yield
        assert(baseline.isInstanceOf[AuthorizationResult.Authorized], s"baseline must authorize, received $baseline")
        assertEquals(excluded, AuthorizationResult.Denied(DenialReason.NoMatchingAuthority))
  }

  test("a delegation of Slack.Message.Read does not authorize a different capability with the same resource and action") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      val repository = PostgresControlPlane(xa)
      val service = DynamicAuthorizationService[IO](repository, repository)
      for
        fixture <- provision(xa)
        _ <- addExportCapability(xa, fixture)
        agent <- createAgent(repository, fixture, "Read-only agent")
        _ <- grantRead(repository, fixture, agent)
        readResult <- authorizeAt(service, fixture, agent, searchTool, "key-separation-read")
        exportSnapshot <- repository.snapshotFor(fixture.tenant, Principal.Agent(agent), "slack_export_messages")
        exportResult <- authorizeAt(service, fixture, agent, "slack_export_messages", "key-separation-export")
      yield
        assert(readResult.isInstanceOf[AuthorizationResult.Authorized], s"the granted key must authorize: $readResult")
        exportSnapshot match
          case Right(value) =>
            assertEquals(value.capability.descriptor.capability, slackExportKey)
            assertEquals(value.capability.descriptor.action, Action.Read)
            assertEquals(value.capability.descriptor.resource, fixture.resource)
            // The delegation is looked up by the tool's capability_id, so the Read grant is never loaded for Export.
            assertEquals(value.delegations, Vector.empty)
          case Left(error) => fail(s"export snapshot did not load: $error")
        // NoMatchingAuthority, not InvalidDelegationChain: the loader returns no delegation for the Export
        // capability_id (the Read grant is on a different capability row), so the request carries an empty claimed
        // chain and the agent is its own root. No policy binds the agent, so the kernel finds no applicable authority.
        // The owner's action-level READ policy is not consulted for the agent, and a grant of Read never widens into
        // the sibling key even though resource and action are identical.
        assertEquals(exportResult, AuthorizationResult.Denied(DenialReason.NoMatchingAuthority))
  }

  test("policy definitions with an empty, malformed, or non-string allowlist, or an unknown field, fail to load") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      val repository = PostgresControlPlane(xa)
      val invalid = Vector(
        """{"action":"READ","effect":"ALLOW","capabilities":[]}""",
        """{"action":"READ","effect":"ALLOW","capabilities":["bad key"]}""",
        """{"action":"READ","effect":"ALLOW","capabilities":[1]}""",
        """{"action":"READ","effect":"ALLOW","capabilities":"Slack.Message.Read"}""",
        """{"action":"READ","effect":"ALLOW","unknown":true}"""
      )
      for
        fixture <- provision(xa)
        baseline <- repository.snapshotFor(fixture.tenant, fixture.human, searchTool)
        results <- invalid.traverse: definition =>
          setPolicyDefinition(xa, fixture, definition) *>
            repository.snapshotFor(fixture.tenant, fixture.human, searchTool).map(definition -> _)
      yield
        assert(baseline.isRight, s"the unmodified policy must load, received $baseline")
        results.foreach: (definition, result) =>
          assertEquals(result, Left(AuthorityLoadError.InvalidStoredAuthority), definition)
  }

  test("the authorization journal round trips capability key and action, distinguishing keys on one resource and action") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      val repository = PostgresControlPlane(xa)
      val at = Instant.parse("2026-09-30T12:00:00Z")
      def event(
          requestId: AuthorizationRequestId,
          principal: Principal,
          capability: Option[CapabilityDescriptor],
          fixture: Fixture,
          offset: Long,
          correlation: String
      ) = AuthorizationEvent(
        requestId,
        principal,
        searchTool,
        capability.map(_.resource),
        capability,
        AuthorizationResult.Denied(DenialReason.NoMatchingAuthority),
        correlation,
        at.plusSeconds(offset),
        AuthorizationSource.AgentCall
      )
      for
        fixture <- provision(xa)
        agent <- createAgent(repository, fixture, "Journal agent")
        principal = Principal.Agent(agent)
        readRequest = AuthorizationRequestId.random()
        exportRequest = AuthorizationRequestId.random()
        unmappedRequest = AuthorizationRequestId.random()
        read = CapabilityDescriptor(fixture.resource, Action.Read, slackReadKey)
        exported = CapabilityDescriptor(fixture.resource, Action.Read, slackExportKey)
        _ <- repository.record(fixture.tenant, event(readRequest, principal, Some(read), fixture, 0, "journal-read"))
        _ <- repository.record(fixture.tenant, event(exportRequest, principal, Some(exported), fixture, 1, "journal-export"))
        _ <- repository.record(fixture.tenant, event(unmappedRequest, principal, None, fixture, 2, "journal-unmapped"))
        history <- repository.recent(fixture.tenant, 10)
        byRequest = history.map(record => record.requestId -> record).toMap
      yield
        assertEquals(history.map(_.correlationId), Vector("journal-unmapped", "journal-export", "journal-read"))
        val readRecord = byRequest(readRequest)
        assertEquals(readRecord.resource, Some(fixture.resource))
        assertEquals(readRecord.action, Some(Action.Read))
        assertEquals(readRecord.capability, Some(slackReadKey))
        val exportRecord = byRequest(exportRequest)
        assertEquals(exportRecord.resource, Some(fixture.resource))
        assertEquals(exportRecord.action, Some(Action.Read))
        assertEquals(exportRecord.capability, Some(slackExportKey))
        val unmappedRecord = byRequest(unmappedRequest)
        assertEquals((unmappedRecord.resource, unmappedRecord.action, unmappedRecord.capability), (None, None, None))
  }

  private def insertCapability(
      xa: Transactor[IO],
      fixture: Fixture,
      namespace: String,
      name: String,
      action: Option[String],
      resource: Option[String]
  ): IO[Either[Throwable, Int]] =
    inTenant(fixture)(
      sql"""insert into capabilities(id, tenant_id, namespace, name, action, resource_id)
             values (${UUID.randomUUID().toString}::uuid, ${fixture.tenant.toString}::uuid, $namespace, $name,
                     $action, ${resource}::uuid)""".update.run
    ).attempt.transact(xa)

  private def sqlState(result: Either[Throwable, Int]): Option[String] = result.left.toOption.flatMap:
    case error: SQLException => Option(error.getSQLState)
    case _                   => None

  test("V16 rejects a capability with a malformed key, a null action, or a null resource, and accepts a well-formed one") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      for
        fixture <- provision(xa)
        resource = Some(fixture.resource.toString)
        valid <- insertCapability(xa, fixture, "Slack.Message", "Archive", Some("READ"), resource)
        badKey <- insertCapability(xa, fixture, "slack", "read", Some("READ"), resource)
        twoSegments <- insertCapability(xa, fixture, "Slack", "Message", Some("READ"), resource)
        nullAction <- insertCapability(xa, fixture, "Slack.Message", "NoAction", None, resource)
        nullResource <- insertCapability(xa, fixture, "Slack.Message", "NoResource", Some("READ"), None)
      yield
        assertEquals(valid, Right(1))
        // 23514 = check_violation (capabilities_key_format); 23502 = not_null_violation.
        assertEquals(sqlState(badKey), Some("23514"))
        assert(badKey.left.exists(_.getMessage.contains("capabilities_key_format")), s"unexpected failure: $badKey")
        assertEquals(sqlState(twoSegments), Some("23514"))
        assertEquals(sqlState(nullAction), Some("23502"))
        assert(nullAction.left.exists(_.getMessage.contains("\"action\"")), s"unexpected failure: $nullAction")
        assertEquals(sqlState(nullResource), Some("23502"))
        assert(nullResource.left.exists(_.getMessage.contains("\"resource_id\"")), s"unexpected failure: $nullResource")
  }
