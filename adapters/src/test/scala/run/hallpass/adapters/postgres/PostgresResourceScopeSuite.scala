package run.hallpass.adapters.postgres

import java.sql.DriverManager
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

/** Persistence coverage for resource scope: a resource's scope is its trusted catalog
  * ancestry, read from `resources.parent_resource_id`. A grant on an ancestor covers its descendants, never the other
  * way round and never a sibling, and a corrupt stored path fails closed. Every test provisions its own tenant.
  *
  * The catalog tree built here is: root (the tenant's Slack provider) with children A and B, and A1 under A. A tool
  * is mapped on a resource by parenting the tool on it and mapping a capability whose `resource_id` is that resource.
  * The runtime role owns the schema in this in-process setup, so catalog rows are inserted through the tenant session
  * like the sibling suites do. */
final class PostgresResourceScopeSuite extends CatsEffectSuite:
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

  private val rootTool = "slack_search_messages"
  private val channelTool = "channel_a_read"
  private val threadTool = "thread_a1_read"

  /** A freshly provisioned tenant with the identifiers of its owner policy, root resource, and root capability. */
  private final case class Fixture(ids: ProvisioningIds, human: Principal.Human):
    def tenant: TenantId = ids.tenant
    def root: ResourceId = ids.slackResource
    def rootCapability: String = ids.readCapability.toString
    def readPolicy: String = ids.readPolicy.toString
    def readBinding: String = ids.readBinding.toString

  /** A provisioned tenant plus children A and B of the root and A1 under A. Tools `channel_a_read` and
    * `thread_a1_read` are mapped on A and A1; the provisioned `slack_search_messages` is mapped on the root. */
  private final case class Tree(
      base: Fixture,
      a: ResourceId,
      b: ResourceId,
      a1: ResourceId,
      capabilityA: String,
      capabilityB: String,
      capabilityA1: String
  ):
    def tenant: TenantId = base.tenant
    def root: ResourceId = base.root

  private def provision(xa: Transactor[IO]): IO[Fixture] =
    val ids = ProvisioningIds.random()
    val subject = UUID.randomUUID().toString
    val request = TenantProvisioningRequest
      .from(
        "Resource scope",
        s"scope-${subject.take(8)}",
        ExternalIdentity.from("https://idp.example.com", subject).toOption.get
      )
      .toOption
      .get
    TenantProvisioning.program(request, ids).transact(xa).map(provisioned => Fixture(ids, provisioned.administratorPrincipal))

  private def inTenant[A](tenant: TenantId)(program: ConnectionIO[A]): ConnectionIO[A] =
    TenantSession.establish(tenant) *> program

  private def addResource(
      tenant: TenantId,
      id: ResourceId,
      resourceType: String,
      parent: ResourceId,
      externalId: String
  ): ConnectionIO[Int] =
    sql"""insert into resources(id, tenant_id, resource_type, name, provider, parent_resource_id, external_id)
           values (${id.toString}::uuid, ${tenant.toString}::uuid, $resourceType, $externalId, 'slack',
                   ${parent.toString}::uuid, $externalId)""".update.run

  private def addCapability(
      tenant: TenantId,
      id: String,
      namespace: String,
      name: String,
      resource: ResourceId
  ): ConnectionIO[Int] =
    sql"""insert into capabilities(id, tenant_id, namespace, name, action, resource_id)
           values ($id::uuid, ${tenant.toString}::uuid, $namespace, $name, 'READ', ${resource.toString}::uuid)""".update.run

  /** A trusted tool parented on `parent`, so the authorization resource is `parent`. */
  private def addTool(tenant: TenantId, externalId: String, parent: ResourceId, capability: String): ConnectionIO[Unit] =
    val tool = ResourceId.random()
    for
      _ <- addResource(tenant, tool, "TOOL", parent, externalId)
      _ <- sql"insert into tools(tenant_id, resource_id, protocol) values (${tenant.toString}::uuid, ${tool.toString}::uuid, 'MCP')".update.run
      _ <-
        sql"""insert into tool_capability_mappings(tenant_id, tool_id, capability_id, mapping_source, trusted)
               values (${tenant.toString}::uuid, ${tool.toString}::uuid, $capability::uuid, 'PROVIDER_DEFINED', true)""".update.run
    yield ()

  private def buildTree(xa: Transactor[IO]): IO[Tree] =
    for
      fixture <- provision(xa)
      tree = Tree(
        fixture,
        ResourceId.random(),
        ResourceId.random(),
        ResourceId.random(),
        UUID.randomUUID().toString,
        UUID.randomUUID().toString,
        UUID.randomUUID().toString
      )
      _ <- inTenant(fixture.tenant)(for
        _ <- addResource(fixture.tenant, tree.a, "CHANNEL", fixture.root, "channel-a")
        _ <- addResource(fixture.tenant, tree.b, "CHANNEL", fixture.root, "channel-b")
        _ <- addResource(fixture.tenant, tree.a1, "CHANNEL", tree.a, "channel-a1")
        _ <- addCapability(fixture.tenant, tree.capabilityA, "Slack.Channel", "Read", tree.a)
        _ <- addCapability(fixture.tenant, tree.capabilityB, "Slack.Channel", "Peek", tree.b)
        _ <- addCapability(fixture.tenant, tree.capabilityA1, "Slack.Thread", "Read", tree.a1)
        _ <- addTool(fixture.tenant, channelTool, tree.a, tree.capabilityA)
        _ <- addTool(fixture.tenant, threadTool, tree.a1, tree.capabilityA1)
      yield ()).transact(xa)
    yield tree

  private def createAgent(repository: PostgresControlPlane, tenant: TenantId, name: String): IO[AgentId] =
    repository
      .create(tenant, CreateAgent(name, None))
      .flatMap(_.fold(error => IO.raiseError(RuntimeException(s"agent create failed: $error")), agent => IO.pure(agent.id)))

  /** Stores an owner delegation whose single grant names `capability` on `resource`. It is inserted directly so the
    * grant's resource can differ from the capability's own resource, which `create` does not offer. */
  private def grant(xa: Transactor[IO], tree: Tree, agent: AgentId, capability: String, resource: ResourceId): IO[Unit] =
    val id = UUID.randomUUID().toString
    inTenant(tree.tenant)(for
      _ <-
        sql"""insert into delegations(id, tenant_id, grantor_principal_id, grantee_principal_id, valid_from)
               values ($id::uuid, ${tree.tenant.toString}::uuid, ${tree.base.human.id.toString}::uuid,
                       ${agent.toString}::uuid, ${Instant.EPOCH})""".update.run
      _ <-
        sql"""insert into delegated_capabilities(tenant_id, delegation_id, capability_id, resource_id, actions)
               values (${tree.tenant.toString}::uuid, $id::uuid, $capability::uuid, ${resource.toString}::uuid,
                       ARRAY['READ']::text[])""".update.run
    yield ()).transact(xa)

  /** An extra ACTIVE owner policy with the given effect, bound to `resource`. */
  private def addOwnerPolicy(xa: Transactor[IO], tree: Tree, effect: String, resource: ResourceId): IO[Unit] =
    val policy = UUID.randomUUID().toString
    val definition = s"""{"action":"READ","effect":"$effect"}"""
    inTenant(tree.tenant)(for
      _ <-
        sql"""insert into policies(id, tenant_id, name, version, status, definition, created_by)
               values ($policy::uuid, ${tree.tenant.toString}::uuid, $effect, 1, 'ACTIVE', $definition::jsonb,
                       ${tree.base.human.id.toString}::uuid)""".update.run
      _ <-
        sql"""insert into policy_bindings(id, tenant_id, policy_id, subject_principal_id, resource_id)
               values (${UUID.randomUUID().toString}::uuid, ${tree.tenant.toString}::uuid, $policy::uuid,
                       ${tree.base.human.id.toString}::uuid, ${resource.toString}::uuid)""".update.run
    yield ()).transact(xa)

  /** Rebinds the provisioned owner ALLOW policy to another resource. */
  private def moveOwnerBinding(xa: Transactor[IO], tree: Tree, resource: ResourceId): IO[Unit] =
    inTenant(tree.tenant)(
      sql"""update policy_bindings set resource_id=${resource.toString}::uuid
             where tenant_id=${tree.tenant.toString}::uuid and id=${tree.base.readBinding}::uuid""".update.run
    ).transact(xa).flatMap(rows => IO(assertEquals(rows, 1)))

  private def setOwnerPolicyDefinition(xa: Transactor[IO], tree: Tree, definition: String): IO[Unit] =
    inTenant(tree.tenant)(
      sql"""update policies set definition=$definition::jsonb
             where tenant_id=${tree.tenant.toString}::uuid and id=${tree.base.readPolicy}::uuid""".update.run
    ).transact(xa).flatMap(rows => IO(assertEquals(rows, 1)))

  private def authorizeAt(
      service: DynamicAuthorizationService[IO],
      tree: Tree,
      agent: AgentId,
      tool: String
  ): IO[AuthorizationResult] =
    service.authorize(tree.tenant, Principal.Agent(agent), tool, s"scope-$tool", Instant.now())

  private def assertAuthorized(result: AuthorizationResult, clue: String): Unit =
    assert(result.isInstanceOf[AuthorizationResult.Authorized], s"$clue: expected authorization, received $result")

  private def assertNoAuthority(result: AuthorizationResult, clue: String): Unit =
    assertEquals(result, AuthorizationResult.Denied(DenialReason.NoMatchingAuthority), clue)

  private def withTree[A](
      body: (Transactor[IO], PostgresControlPlane, DynamicAuthorizationService[IO], Tree) => IO[A]
  ): IO[A] =
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      val repository = PostgresControlPlane(xa)
      val service = DynamicAuthorizationService[IO](repository, repository)
      buildTree(xa).flatMap(tree => body(xa, repository, service, tree))

  private def pathOf(result: Either[AuthorityLoadError, AuthoritySnapshot]): Vector[ResourceId] =
    result.fold(error => fail(s"snapshot did not load: $error"), _.scope.path.map(_.id))

  // ---- positive ----------------------------------------------------------------------------------------------

  test("an owner policy on the root and a delegation on child A cover tools mapped on A and grandchild A1") {
    withTree: (xa, repository, service, tree) =>
      for
        agent <- createAgent(repository, tree.tenant, "Child grant agent")
        _ <- grant(xa, tree, agent, tree.capabilityA, tree.a)
        _ <- grant(xa, tree, agent, tree.capabilityA1, tree.a)
        onA <- authorizeAt(service, tree, agent, channelTool)
        onA1 <- authorizeAt(service, tree, agent, threadTool)
        snapshot <- repository.snapshotFor(tree.tenant, Principal.Agent(agent), threadTool)
      yield
        assertAuthorized(onA, "tool mapped on child A")
        assertAuthorized(onA1, "tool mapped on grandchild A1")
        snapshot match
          case Right(value) =>
            // The owner policy is bound to the root, and its statement keeps that binding's resource.
            assertEquals(value.policies.values.flatMap(_.statements.toSet).map(_.resource), Vector(tree.root))
          case Left(error) => fail(s"snapshot did not load: $error")
  }

  test("a delegation granted on child A authorizes a tool mapped on grandchild A1") {
    withTree: (xa, repository, service, tree) =>
      for
        agent <- createAgent(repository, tree.tenant, "Child grant agent")
        _ <- grant(xa, tree, agent, tree.capabilityA1, tree.a)
        onA1 <- authorizeAt(service, tree, agent, threadTool)
      yield assertAuthorized(onA1, "grant on A over a tool mapped on A1")
  }

  test("snapshotFor carries the scope path from the target to the root with the exact catalog IDs") {
    withTree: (xa, repository, _, tree) =>
      for
        agent <- createAgent(repository, tree.tenant, "Path agent")
        _ <- grant(xa, tree, agent, tree.capabilityA1, tree.root)
        _ <- grant(xa, tree, agent, tree.capabilityA, tree.root)
        _ <- grant(xa, tree, agent, tree.base.rootCapability, tree.root)
        grandchild <- repository.snapshotFor(tree.tenant, Principal.Agent(agent), threadTool)
        child <- repository.snapshotFor(tree.tenant, Principal.Agent(agent), channelTool)
        root <- repository.snapshotFor(tree.tenant, Principal.Agent(agent), rootTool)
      yield
        assertEquals(pathOf(grandchild), Vector(tree.a1, tree.a, tree.root))
        assertEquals(pathOf(child), Vector(tree.a, tree.root))
        assertEquals(pathOf(root), Vector(tree.root))
        assertEquals(grandchild.map(_.resource.id), Right(tree.a1))
  }

  // ---- negative ----------------------------------------------------------------------------------------------

  test("a delegation granted on sibling B does not authorize a tool mapped on A") {
    withTree: (xa, repository, service, tree) =>
      for
        allowed <- createAgent(repository, tree.tenant, "Grant on A agent")
        sibling <- createAgent(repository, tree.tenant, "Grant on B agent")
        _ <- grant(xa, tree, allowed, tree.capabilityA, tree.a)
        _ <- grant(xa, tree, sibling, tree.capabilityA, tree.b)
        baseline <- authorizeAt(service, tree, allowed, channelTool)
        outcome <- authorizeAt(service, tree, sibling, channelTool)
      yield
        assertAuthorized(baseline, "grant on A itself")
        assertNoAuthority(outcome, "grant on sibling B")
  }

  test("a delegation granted on grandchild A1 does not authorize a tool mapped on its ancestor A") {
    withTree: (xa, repository, service, tree) =>
      for
        allowed <- createAgent(repository, tree.tenant, "Grant on A agent")
        narrow <- createAgent(repository, tree.tenant, "Grant on A1 agent")
        _ <- grant(xa, tree, allowed, tree.capabilityA, tree.a)
        _ <- grant(xa, tree, narrow, tree.capabilityA, tree.a1)
        baseline <- authorizeAt(service, tree, allowed, channelTool)
        outcome <- authorizeAt(service, tree, narrow, channelTool)
      yield
        assertAuthorized(baseline, "grant on A itself")
        assertNoAuthority(outcome, "grant on a descendant over an ancestor-mapped tool")
  }

  test("a delegation stored on the provider's catalog resource confers nothing, even beneath it") {
    withTree: (xa, repository, service, tree) =>
      for
        allowed <- createAgent(repository, tree.tenant, "Grant on A agent")
        providerWide <- createAgent(repository, tree.tenant, "Provider-wide grant agent")
        _ <- grant(xa, tree, allowed, tree.capabilityA, tree.a)
        _ <- grant(xa, tree, providerWide, tree.capabilityA, tree.root)
        _ <- grant(xa, tree, providerWide, tree.base.rootCapability, tree.root)
        baseline <- authorizeAt(service, tree, allowed, channelTool)
        onChild <- authorizeAt(service, tree, providerWide, channelTool)
        onRoot <- authorizeAt(service, tree, providerWide, rootTool)
      yield
        assertAuthorized(baseline, "grant on A itself")
        assertNoAuthority(onChild, "a provider-wide grant over a child")
        assertNoAuthority(onRoot, "a provider-wide grant over the provider resource")
  }

  test("a DENY policy bound to the root blocks an ALLOW bound to child A") {
    withTree: (xa, repository, service, tree) =>
      for
        agent <- createAgent(repository, tree.tenant, "Denied agent")
        _ <- grant(xa, tree, agent, tree.capabilityA1, tree.a)
        // The only ALLOW is bound to child A, so the baseline shows that a descendant-bound policy authorizes.
        _ <- moveOwnerBinding(xa, tree, tree.a)
        baseline <- authorizeAt(service, tree, agent, threadTool)
        _ <- addOwnerPolicy(xa, tree, "DENY", tree.root)
        outcome <- authorizeAt(service, tree, agent, threadTool)
      yield
        assertAuthorized(baseline, "ALLOW bound to A")
        outcome match
          case AuthorizationResult.Denied(DenialReason.ExplicitDeny(_, _)) => ()
          case other => fail(s"expected an explicit deny from the root policy, received $other")
  }

  test("a stored parent cycle makes snapshotFor fail closed") {
    withTree: (xa, repository, _, tree) =>
      for
        agent <- createAgent(repository, tree.tenant, "Cycle agent")
        _ <- grant(xa, tree, agent, tree.capabilityA1, tree.root)
        baseline <- repository.snapshotFor(tree.tenant, Principal.Agent(agent), threadTool)
        // A becomes A1's child as well as its parent: A1 -> A -> A1 -> ...
        rows <- inTenant(tree.tenant)(
          sql"""update resources set parent_resource_id=${tree.a1.toString}::uuid
                 where tenant_id=${tree.tenant.toString}::uuid and id=${tree.a.toString}::uuid""".update.run
        ).transact(xa)
        outcome <- repository.snapshotFor(tree.tenant, Principal.Agent(agent), threadTool)
      yield
        assert(baseline.isRight, s"baseline must load, received $baseline")
        assertEquals(rows, 1)
        assertEquals(outcome.map(_ => ()), Left(AuthorityLoadError.InvalidStoredAuthority))
  }

  test("a stored path deeper than the kernel maximum makes snapshotFor fail closed") {
    withTree: (xa, repository, _, tree) =>
      // levels(0) is the root at depth 1; a target at depth MaximumDepth is valid and one level deeper is not.
      val levels = tree.root +: Vector.fill(ResourceScope.MaximumDepth)(ResourceId.random())
      val atLimit = levels(ResourceScope.MaximumDepth - 1)
      val overLimit = levels(ResourceScope.MaximumDepth)
      val limitCapability = UUID.randomUUID().toString
      val overCapability = UUID.randomUUID().toString
      for
        agent <- createAgent(repository, tree.tenant, "Deep agent")
        _ <- inTenant(tree.tenant)(for
          _ <- levels.zip(levels.tail).zipWithIndex.traverse_ { case ((parent, id), index) =>
            addResource(tree.tenant, id, "CHANNEL", parent, s"level-${index + 2}")
          }
          _ <- addCapability(tree.tenant, limitCapability, "Slack.Deep", "AtLimit", atLimit)
          _ <- addCapability(tree.tenant, overCapability, "Slack.Deep", "OverLimit", overLimit)
          _ <- addTool(tree.tenant, "deep_at_limit", atLimit, limitCapability)
          _ <- addTool(tree.tenant, "deep_over_limit", overLimit, overCapability)
        yield ()).transact(xa)
        _ <- grant(xa, tree, agent, limitCapability, tree.root)
        _ <- grant(xa, tree, agent, overCapability, tree.root)
        within <- repository.snapshotFor(tree.tenant, Principal.Agent(agent), "deep_at_limit")
        beyond <- repository.snapshotFor(tree.tenant, Principal.Agent(agent), "deep_over_limit")
      yield
        assertEquals(within.map(_.scope.path.size), Right(ResourceScope.MaximumDepth))
        assertEquals(beyond.map(_ => ()), Left(AuthorityLoadError.InvalidStoredAuthority))
  }

  test("delegation create is refused when the only owner policy for the scope is a DENY") {
    withTree: (xa, repository, _, tree) =>
      for
        agent <- createAgent(repository, tree.tenant, "Grantee agent")
        request = CreateDelegation(tree.base.human, Principal.Agent(agent), tree.capabilityA, tree.a, Action.Read, None)
        // Baseline: the owner policy is bound to the root, an ancestor of A, so the owner may delegate on A.
        baseline <- repository.create(tree.tenant, request)
        _ <- setOwnerPolicyDefinition(xa, tree, """{"action":"READ","effect":"DENY"}""")
        outcome <- repository.create(tree.tenant, request)
      yield
        assert(baseline.isRight, s"baseline must create, received $baseline")
        assertEquals(outcome.map(_ => ()), Left(DelegationError.GrantorLacksAuthority))
  }

  test("delegation create is refused when the grantor has no policy on any ancestor of the resource") {
    withTree: (xa, repository, _, tree) =>
      for
        agent <- createAgent(repository, tree.tenant, "Grantee agent")
        request = CreateDelegation(tree.base.human, Principal.Agent(agent), tree.capabilityA1, tree.a1, Action.Read, None)
        baseline <- repository.create(tree.tenant, request)
        // The only owner policy now sits on sibling B, which is not on A1's path to the root.
        _ <- moveOwnerBinding(xa, tree, tree.b)
        outcome <- repository.create(tree.tenant, request)
      yield
        assert(baseline.isRight, s"baseline must create, received $baseline")
        assertEquals(outcome.map(_ => ()), Left(DelegationError.GrantorLacksAuthority))
  }

  // ---- resource catalog and scoped authority loading ---------------------------------------------------

  private sealed trait UnprovisionedAccount
  private val unprovisionedKind: ResourceKind[UnprovisionedAccount] = ResourceKind.root[UnprovisionedAccount](
    "othervendor.account",
    ProviderId.parse("othervendor").getOrElse(fail("provider id")),
    ResourceType.Account,
    Custody.Workspace
  )

  private def scopeOf(repository: PostgresControlPlane, tenant: TenantId, resource: ResourceId): IO[ResourceScope] =
    repository
      .currentScope(tenant, resource)
      .flatMap(IO.fromOption(_)(RuntimeException(s"resource $resource has no current scope")))

  test("rootScope returns the provisioned Slack provider resource and a one-element scope") {
    withTree: (xa, repository, _, tree) =>
      repository.rootScope(tree.tenant, Slack.workspace).map:
        case Some((externalId, scope)) =>
          // The tree adds children below the root; the root scope still contains only the root itself.
          assertEquals(externalId, ExternalId.parse("slack-workspace").getOrElse(fail("external id")))
          assertEquals(scope.path.map(_.id), Vector(tree.root))
          assertEquals(scope.target.externalId, "slack-workspace")
          assertEquals(scope.target.resourceType, ResourceType.Provider)
          assertEquals(scope.tenant, tree.tenant)
        case None => fail("expected the provisioned Slack root")
  }

  test("rootScope returns None for a provider with no provisioned root, and for a tenant with no resources") {
    withTree: (xa, repository, _, tree) =>
      for
        unprovisioned <- repository.rootScope(tree.tenant, unprovisionedKind)
        otherTenant <- repository.rootScope(TenantId.random(), Slack.workspace)
      yield
        assertEquals(unprovisioned, None)
        assertEquals(otherTenant, None)
  }

  test("rootScope does not return another tenant's root") {
    withTree: (xa, repository, _, first) =>
      for
        second <- buildTree(xa)
        inFirst <- repository.rootScope(first.tenant, Slack.workspace)
        inSecond <- repository.rootScope(second.tenant, Slack.workspace)
      yield
        assertEquals(inFirst.map(_._2.path.map(_.id)), Some(Vector(first.root)))
        assertEquals(inSecond.map(_._2.path.map(_.id)), Some(Vector(second.root)))
        assertNotEquals(first.root, second.root)
  }

  test("selectedScope is None for every resource until selection is stored") {
    withTree: (xa, repository, _, tree) =>
      repository
        .selectedScope(tree.tenant, Slack.workspace, ExternalId.parse("slack-workspace").getOrElse(fail("external id")))
        .map(assertEquals(_, None))
  }

  test("currentScope returns the exact catalog ancestry of a resource, and None for an unknown resource") {
    withTree: (xa, repository, _, tree) =>
      for
        a1 <- repository.currentScope(tree.tenant, tree.a1)
        root <- repository.currentScope(tree.tenant, tree.root)
        unknown <- repository.currentScope(tree.tenant, ResourceId.random())
      yield
        assertEquals(a1.map(_.path.map(_.id)), Some(Vector(tree.a1, tree.a, tree.root)))
        assertEquals(root.map(_.path.map(_.id)), Some(Vector(tree.root)))
        assertEquals(unknown, None)
  }

  test("currentScope does not resolve a resource that belongs to another tenant") {
    withTree: (xa, repository, _, first) =>
      for
        second <- buildTree(xa)
        crossTenant <- repository.currentScope(first.tenant, second.a)
        own <- repository.currentScope(second.tenant, second.a)
      yield
        assertEquals(crossTenant, None)
        assert(own.isDefined, "the resource resolves inside its own tenant")
  }

  test("snapshotWithin loads authority in a scope that covers the mapped resource, and reports that scope") {
    withTree: (xa, repository, _, tree) =>
      for
        agent <- createAgent(repository, tree.tenant, "Scoped agent")
        _ <- grant(xa, tree, agent, tree.capabilityA, tree.root)
        ownScope <- scopeOf(repository, tree.tenant, tree.a)
        descendantScope <- scopeOf(repository, tree.tenant, tree.a1)
        atMapped <- repository.snapshotWithin(tree.tenant, Principal.Agent(agent), channelTool, ownScope)
        // A resource below the mapped one is covered: the mapping applies to everything beneath its resource.
        atDescendant <- repository.snapshotWithin(tree.tenant, Principal.Agent(agent), channelTool, descendantScope)
      yield
        assertEquals(atMapped.map(_.scope.path.map(_.id)), Right(Vector(tree.a, tree.root)))
        assertEquals(atDescendant.map(_.scope.path.map(_.id)), Right(Vector(tree.a1, tree.a, tree.root)))
  }

  test("snapshotWithin refuses a scope that does not cover the mapped resource") {
    withTree: (xa, repository, _, tree) =>
      for
        agent <- createAgent(repository, tree.tenant, "Mismatched scope agent")
        _ <- grant(xa, tree, agent, tree.capabilityA, tree.root)
        siblingScope <- scopeOf(repository, tree.tenant, tree.b)
        rootScope <- scopeOf(repository, tree.tenant, tree.root)
        baseline <- scopeOf(repository, tree.tenant, tree.a).flatMap(scope =>
          repository.snapshotWithin(tree.tenant, Principal.Agent(agent), channelTool, scope)
        )
        sibling <- repository.snapshotWithin(tree.tenant, Principal.Agent(agent), channelTool, siblingScope)
        // A scope that ends at the root does not cover a tool mapped on a child: authority never flows upward.
        ancestor <- repository.snapshotWithin(tree.tenant, Principal.Agent(agent), channelTool, rootScope)
      yield
        assert(baseline.isRight, s"baseline must load, received $baseline")
        assertEquals(sibling.map(_ => ()), Left(AuthorityLoadError.InvalidStoredAuthority))
        assertEquals(ancestor.map(_ => ()), Left(AuthorityLoadError.InvalidStoredAuthority))
  }

  test("snapshotWithin refuses a scope that belongs to another tenant") {
    withTree: (xa, repository, _, first) =>
      for
        second <- buildTree(xa)
        agent <- createAgent(repository, first.tenant, "Cross-tenant scope agent")
        _ <- grant(xa, first, agent, first.base.rootCapability, first.root)
        foreignRoot <- scopeOf(repository, second.tenant, second.root)
        ownRoot <- scopeOf(repository, first.tenant, first.root)
        baseline <- repository.snapshotWithin(first.tenant, Principal.Agent(agent), rootTool, ownRoot)
        foreign <- repository.snapshotWithin(first.tenant, Principal.Agent(agent), rootTool, foreignRoot)
      yield
        assert(baseline.isRight, s"baseline must load, received $baseline")
        assertEquals(foreign.map(_ => ()), Left(AuthorityLoadError.InvalidStoredAuthority))
  }

  test("snapshotWithin keeps an unmapped tool unmapped") {
    withTree: (xa, repository, _, tree) =>
      for
        agent <- createAgent(repository, tree.tenant, "Unmapped agent")
        rootScope <- scopeOf(repository, tree.tenant, tree.root)
        outcome <- repository.snapshotWithin(tree.tenant, Principal.Agent(agent), "no_such_tool", rootScope)
      yield assertEquals(outcome.map(_ => ()), Left(AuthorityLoadError.UnmappedTool))
  }
