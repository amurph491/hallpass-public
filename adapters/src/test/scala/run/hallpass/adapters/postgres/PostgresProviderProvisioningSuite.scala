package run.hallpass.adapters.postgres

import java.sql.DriverManager
import java.util.UUID
import scala.compiletime.uninitialized
import cats.effect.IO
import cats.effect.unsafe.implicits.global
import cats.syntax.all.*
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.application.*
import run.hallpass.kernel.*

/** GitHub catalog provisioning, for new tenants (including the development fixture) and for existing tenants, run as
  * the schema owner against PostgreSQL 18. */
final class PostgresProviderProvisioningSuite extends CatsEffectSuite:
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(180, "s")
  private val Owner = "authai_owner"
  private val App = "authai_app"
  private val Password = "test-password"
  private var container: PostgreSQLContainer[?] = uninitialized
  private var dockerAvailable = false
  private var ownerXa: Transactor[IO] = uninitialized
  private var release: IO[Unit] = IO.unit
  private val runtimeRole = RuntimeRole.parse(App).toOption.get

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      val admin = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
      try
        val statement = admin.createStatement()
        statement.execute(s"create role $Owner login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"create role $App login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"grant connect on database test to $Owner, $App")
        statement.execute("revoke create on schema public from public")
        statement.execute(s"grant usage, create on schema public to $Owner")
        statement.execute(s"grant usage on schema public to $App")
      finally admin.close()
      val setup = for
        _ <- PostgresDatabase.migrateAsOwner(config(Owner), runtimeRole)
        owner <- PostgresDatabase.resource(config(Owner)).allocated
      yield owner
      val (owner, releaseOwner) = setup.unsafeRunSync()
      ownerXa = owner
      release = releaseOwner

  override def afterAll(): Unit =
    if dockerAvailable then
      release.unsafeRunSync()
      container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  private def config(user: String): DatabaseConfig =
    DatabaseConfig
      .fromEnvironment(Map("HALLPASS_DB_URL" -> container.getJdbcUrl, "HALLPASS_DB_USER" -> user, "HALLPASS_DB_PASSWORD" -> Password))
      .toOption
      .get

  private def provision(): IO[(ProvisionedTenant, String)] =
    val slug = s"prov-${UUID.randomUUID().toString.take(8)}"
    val request = TenantProvisioningRequest
      .from("Provisioning fixture", slug, ExternalIdentity.from("urn:hallpass:provisioning-test", UUID.randomUUID().toString).toOption.get)
      .toOption
      .get
    TenantProvisioning.provision(ownerXa, request).map(_ -> slug)

  private def inTenant[A](tenant: TenantId)(query: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> query).transact(ownerXa)

  private final case class CatalogCounts(
      providers: Long, capabilities: Long, tools: Long, trustedMappings: Long, policies: Long, bindings: Long, resources: Long
  )

  private def counts(tenant: TenantId): IO[CatalogCounts] = inTenant(tenant):
    for
      providers <- sql"select count(*) from resources where resource_type='PROVIDER' and provider='github'".query[Long].unique
      capabilities <- sql"select count(*) from capabilities where namespace like 'GitHub.%'".query[Long].unique
      tools <- sql"select count(*) from resources where resource_type='TOOL' and provider='github'".query[Long].unique
      mappings <- sql"""select count(*) from tool_capability_mappings m join resources r on r.tenant_id=m.tenant_id and r.id=m.tool_id
                         where r.provider='github' and m.trusted and m.mapping_source='PROVIDER_DEFINED'""".query[Long].unique
      policies <- sql"select count(*) from policies where name like 'GitHub%'".query[Long].unique
      bindings <- sql"""select count(*) from policy_bindings b join policies p on p.tenant_id=b.tenant_id and p.id=b.policy_id
                         where p.name like 'GitHub%'""".query[Long].unique
      resources <- sql"select count(*) from resources".query[Long].unique
    yield CatalogCounts(providers, capabilities, tools, mappings, policies, bindings, resources)

  private def stripGitHub(tenant: TenantId): IO[Unit] = inTenant(tenant):
    for
      _ <- sql"delete from policy_bindings where policy_id in (select id from policies where name like 'GitHub%')".update.run
      _ <- sql"delete from policies where name like 'GitHub%'".update.run
      _ <- sql"delete from tool_capability_mappings where capability_id in (select id from capabilities where namespace like 'GitHub.%')".update.run
      _ <- sql"delete from tools where resource_id in (select id from resources where provider='github' and resource_type='TOOL')".update.run
      _ <- sql"delete from capabilities where namespace like 'GitHub.%'".update.run
      _ <- sql"delete from resources where provider='github' and resource_type='TOOL'".update.run
      _ <- sql"delete from resources where provider='github' and resource_type='PROVIDER'".update.run
    yield ()

  /** Reverts a tenant to the read-only GitHub catalog. */
  private def stripCreate(tenant: TenantId): IO[Unit] = inTenant(tenant):
    for
      _ <- sql"delete from policy_bindings where policy_id in (select id from policies where name='GitHub write owner authority')".update.run
      _ <- sql"delete from policies where name='GitHub write owner authority'".update.run
      _ <- sql"delete from tool_capability_mappings where capability_id in (select id from capabilities where namespace='GitHub.Issue' and name='Create')".update.run
      _ <- sql"delete from tools where resource_id in (select id from resources where provider='github' and external_id='github_issues_create')".update.run
      _ <- sql"delete from resources where provider='github' and external_id='github_issues_create'".update.run
      _ <- sql"delete from capabilities where namespace='GitHub.Issue' and name='Create'".update.run
    yield ()

  /** An additional member of an existing tenant, as an owner would have added through the directory. */
  private def addMember(tenant: TenantId, role: String, status: String): IO[UserId] =
    val principal = UserId.random()
    val user = UUID.randomUUID()
    (TenantSession.establish(tenant) *> (
      sql"insert into principals(id,tenant_id,kind) values (${principal.toString}::uuid,${tenant.toString}::uuid,'HUMAN')".update.run *>
        sql"insert into human_identities(tenant_id,principal_id) values (${tenant.toString}::uuid,${principal.toString}::uuid)".update.run *>
        sql"insert into directory_users(id,status) values ($user::uuid,'ACTIVE')".update.run *>
        sql"""insert into directory_tenant_memberships(tenant_id,user_id,human_principal_id,role,status,removed_at)
              values (${tenant.toString}::uuid,$user::uuid,${principal.toString}::uuid,$role,$status,
                      case when $status = 'REMOVED' then now() else null end)""".update.run
    )).transact(ownerXa).as(principal)

  test("a newly provisioned tenant has the GitHub catalog, trusted mappings, and READ and WRITE owner policies, neither requiring approval") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, _) = provisioned
      found <- counts(tenant.tenant)
      mappings <- inTenant(tenant.tenant)(
        sql"""select r.external_id, c.namespace || '.' || c.name, c.action
                from tool_capability_mappings m
                join resources r on r.tenant_id=m.tenant_id and r.id=m.tool_id
                join capabilities c on c.tenant_id=m.tenant_id and c.id=m.capability_id
               where r.provider='github' and m.trusted and m.mapping_source='PROVIDER_DEFINED'
               order by r.external_id""".query[(String, String, String)].to[Vector]
      )
      policy <- inTenant(tenant.tenant)(
        sql"""select p.name, p.definition::text, b.subject_principal_id, rs.provider
                from policies p
                join policy_bindings b on b.tenant_id=p.tenant_id and b.policy_id=p.id
                join resources rs on rs.tenant_id=b.tenant_id and rs.id=b.resource_id
               where rs.provider='github' order by p.name""".query[(String, String, UUID, String)].to[Vector]
      )
    yield
      assertEquals(
        found.copy(resources = 0),
        CatalogCounts(providers = 1, capabilities = 3, tools = 5, trustedMappings = 5, policies = 2, bindings = 2, resources = 0)
      )
      assertEquals(
        mappings,
        Vector(
          ("github_issues_create", "GitHub.Issue.Create", "WRITE"),
          ("github_issues_get", "GitHub.Issue.Read", "READ"),
          ("github_issues_list", "GitHub.Issue.Read", "READ"),
          ("github_pulls_get", "GitHub.PullRequest.Read", "READ"),
          ("github_pulls_list", "GitHub.PullRequest.Read", "READ")
        )
      )
      val administrator = UUID.fromString(tenant.administratorPrincipal.id.toString)
      assertEquals(
        policy.map(row => (row._1, row._3, row._4)),
        Vector(("GitHub read owner authority", administrator, "github"), ("GitHub write owner authority", administrator, "github"))
      )
      assertEquals(io.circe.parser.parse(policy(0)._2), io.circe.parser.parse("""{"action":"READ","effect":"ALLOW"}"""))
      assertEquals(io.circe.parser.parse(policy(1)._2), io.circe.parser.parse("""{"action":"WRITE","effect":"ALLOW"}"""))
  }

  test("the development fixture converges on one GitHub catalog however often it runs") {
    requireDocker()
    for
      _ <- DemoBootstrap.run(ownerXa)
      first <- counts(DemoBootstrap.Tenant)
      _ <- DemoBootstrap.run(ownerXa)
      second <- counts(DemoBootstrap.Tenant)
    yield
      assertEquals(first.providers, 1L)
      assertEquals((first.capabilities, first.tools, first.policies, first.bindings), (3L, 5L, 2L, 2L))
      assertEquals(second, first)
  }

  test("adding GitHub to an existing tenant binds every active administrator and is idempotent") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, slug) = provisioned
      secondAdmin <- addMember(tenant.tenant, "ADMIN", "ACTIVE")
      _ <- addMember(tenant.tenant, "MEMBER", "ACTIVE")
      _ <- addMember(tenant.tenant, "ADMIN", "REMOVED")
      _ <- stripGitHub(tenant.tenant)
      empty <- counts(tenant.tenant)
      first <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.GitHub)
      afterFirst <- counts(tenant.tenant)
      second <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.GitHub)
      afterSecond <- counts(tenant.tenant)
      bound <- inTenant(tenant.tenant)(
        sql"""select b.subject_principal_id from policy_bindings b join policies p on p.tenant_id=b.tenant_id and p.id=b.policy_id
               where p.name='GitHub read owner authority'""".query[UUID].to[Vector]
      )
      writeBound <- inTenant(tenant.tenant)(
        sql"""select b.subject_principal_id from policy_bindings b join policies p on p.tenant_id=b.tenant_id and p.id=b.policy_id
               where p.name='GitHub write owner authority'""".query[UUID].to[Vector]
      )
      nonAllow <- inTenant(tenant.tenant)(sql"select count(*) from policies where name like 'GitHub%' and definition->>'effect' <> 'ALLOW'".query[Long].unique)
    yield
      assertEquals((empty.providers, empty.policies, empty.bindings), (0L, 0L, 0L))
      assertEquals(first.map(result => (result.tenant, result.administrators, result.written)), Some((tenant.tenant, 2, true)))
      assertEquals(afterFirst.copy(resources = 0), CatalogCounts(1, 3, 5, 5, 2, 4, 0))
      assertEquals(
        bound.toSet,
        Set(UUID.fromString(tenant.administratorPrincipal.id.toString), UUID.fromString(secondAdmin.toString))
      )
      assertEquals(second.map(result => (result.administrators, result.written)), Some((2, false)))
      assertEquals(afterSecond, afterFirst, "a second run must change nothing")
      assertEquals(writeBound.toSet, bound.toSet)
      assertEquals(nonAllow, 0L, "GitHub owner policies allow outright; none requires approval")
  }

  test("adding GitHub to a tenant that has only the read catalog adds the create rows, and a second run is a no-op") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, slug) = provisioned
      secondAdmin <- addMember(tenant.tenant, "ADMIN", "ACTIVE")
      _ <- stripCreate(tenant.tenant)
      readOnly <- counts(tenant.tenant)
      first <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.GitHub)
      afterFirst <- counts(tenant.tenant)
      second <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.GitHub)
      afterSecond <- counts(tenant.tenant)
      create <- inTenant(tenant.tenant)(
        sql"""select p.definition::text, b.subject_principal_id
                from policies p join policy_bindings b on b.tenant_id=p.tenant_id and b.policy_id=p.id
               where p.name='GitHub write owner authority'""".query[(String, UUID)].to[Vector]
      )
      mapping <- inTenant(tenant.tenant)(
        sql"""select c.namespace || '.' || c.name, c.action, m.trusted, m.mapping_source
                from tool_capability_mappings m
                join resources r on r.tenant_id=m.tenant_id and r.id=m.tool_id
                join capabilities c on c.tenant_id=m.tenant_id and c.id=m.capability_id
               where r.external_id='github_issues_create'""".query[(String, String, Boolean, String)].to[Vector]
      )
    yield
      assertEquals(readOnly.copy(resources = 0), CatalogCounts(1, 2, 4, 4, 1, 1, 0))
      assertEquals(first.map(_.written), Some(true))
      assertEquals(afterFirst.copy(resources = 0), CatalogCounts(1, 3, 5, 5, 2, 4, 0))
      assertEquals(afterFirst.resources, readOnly.resources + 1, "only the create tool resource is new")
      assertEquals(second.map(_.written), Some(false))
      assertEquals(afterSecond, afterFirst, "a second run must change nothing")
      assertEquals(mapping, Vector(("GitHub.Issue.Create", "WRITE", true, "PROVIDER_DEFINED")))
      assertEquals(create.map(_._2).toSet, Set(UUID.fromString(tenant.administratorPrincipal.id.toString), UUID.fromString(secondAdmin.toString)))
      assert(create.forall(row => io.circe.parser.parse(row._1) == io.circe.parser.parse("""{"action":"WRITE","effect":"ALLOW"}""")))
  }

  test("an unknown slug or provider writes nothing") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, _) = provisioned
      _ <- stripGitHub(tenant.tenant)
      before <- counts(tenant.tenant)
      missing <- ProviderCatalogProvisioning.addToExisting(ownerXa, s"missing-${UUID.randomUUID().toString.take(8)}", ExistingTenantProvider.GitHub)
      after <- counts(tenant.tenant)
    yield
      assertEquals(missing, None)
      assertEquals(after, before)
      assertEquals(ExistingTenantProvider.parse("slack"), None)
      assertEquals(ExistingTenantProvider.parse("github"), Some(ExistingTenantProvider.GitHub))
  }

  test("the runtime role cannot provision a catalog") {
    requireDocker()
    PostgresDatabase.resourceWithSchema(config(App), MigrationMode.External).use: (runtime, _) =>
      for
        provisioned <- provision()
        (tenant, _) = provisioned
        _ <- stripGitHub(tenant.tenant)
        attempt <- (TenantSession.establish(tenant.tenant) *> ProviderCatalogProvisioning
          .github(tenant.tenant, List(tenant.administratorPrincipal.id), GitHubCatalogIds.random())).transact(runtime).attempt
        after <- counts(tenant.tenant)
      yield
        assert(attempt.isLeft, "the runtime role must not be able to insert catalog rows")
        assertEquals(after.providers, 0L)
  }

  // ---- Linear ---------------------------------------------------------------------------------------------------------

  private def linearCounts(tenant: TenantId): IO[CatalogCounts] = inTenant(tenant):
    for
      providers <- sql"select count(*) from resources where resource_type='PROVIDER' and provider='linear'".query[Long].unique
      capabilities <- sql"select count(*) from capabilities where namespace like 'Linear.%'".query[Long].unique
      tools <- sql"select count(*) from resources where resource_type='TOOL' and provider='linear'".query[Long].unique
      mappings <- sql"""select count(*) from tool_capability_mappings m join resources r on r.tenant_id=m.tenant_id and r.id=m.tool_id
                         where r.provider='linear' and m.trusted and m.mapping_source='PROVIDER_DEFINED'""".query[Long].unique
      policies <- sql"select count(*) from policies where name like 'Linear%'".query[Long].unique
      bindings <- sql"""select count(*) from policy_bindings b join policies p on p.tenant_id=b.tenant_id and p.id=b.policy_id
                         where p.name like 'Linear%'""".query[Long].unique
    yield CatalogCounts(providers, capabilities, tools, mappings, policies, bindings, 0)

  private def stripLinear(tenant: TenantId): IO[Unit] = inTenant(tenant):
    for
      _ <- sql"delete from policy_bindings where policy_id in (select id from policies where name like 'Linear%')".update.run
      _ <- sql"delete from policies where name like 'Linear%'".update.run
      _ <- sql"delete from tool_capability_mappings where capability_id in (select id from capabilities where namespace like 'Linear.%')".update.run
      _ <- sql"delete from tools where resource_id in (select id from resources where provider='linear' and resource_type='TOOL')".update.run
      _ <- sql"delete from capabilities where namespace like 'Linear.%'".update.run
      _ <- sql"delete from resources where provider='linear' and resource_type='TOOL'".update.run
      _ <- sql"delete from resources where provider='linear' and resource_type='PROVIDER'".update.run
    yield ()

  test("a newly provisioned tenant has the Linear catalog, trusted mappings, and READ and WRITE owner policies, neither requiring approval") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, _) = provisioned
      found <- linearCounts(tenant.tenant)
      provider <- inTenant(tenant.tenant)(
        sql"select name, external_id from resources where resource_type='PROVIDER' and provider='linear'".query[(String, Option[String])].to[Vector]
      )
      mappings <- inTenant(tenant.tenant)(
        sql"""select r.external_id, c.namespace || '.' || c.name, c.action
                from tool_capability_mappings m
                join resources r on r.tenant_id=m.tenant_id and r.id=m.tool_id
                join capabilities c on c.tenant_id=m.tenant_id and c.id=m.capability_id
               where r.provider='linear' and m.trusted and m.mapping_source='PROVIDER_DEFINED'
               order by r.external_id""".query[(String, String, String)].to[Vector]
      )
      policy <- inTenant(tenant.tenant)(
        sql"""select p.name, p.definition::text, b.subject_principal_id, rs.provider
                from policies p
                join policy_bindings b on b.tenant_id=p.tenant_id and b.policy_id=p.id
                join resources rs on rs.tenant_id=b.tenant_id and rs.id=b.resource_id
               where rs.provider='linear' order by p.name""".query[(String, String, UUID, String)].to[Vector]
      )
    yield
      assertEquals(found, CatalogCounts(providers = 1, capabilities = 2, tools = 3, trustedMappings = 3, policies = 2, bindings = 2, resources = 0))
      assertEquals(provider, Vector(("Linear", Some("linear"))))
      assertEquals(
        mappings,
        Vector(
          ("linear_issues_create", "Linear.Issue.Create", "WRITE"),
          ("linear_issues_get", "Linear.Issue.Read", "READ"),
          ("linear_issues_list", "Linear.Issue.Read", "READ")
        )
      )
      val administrator = UUID.fromString(tenant.administratorPrincipal.id.toString)
      assertEquals(
        policy.map(row => (row._1, row._3, row._4)),
        Vector(("Linear read owner authority", administrator, "linear"), ("Linear write owner authority", administrator, "linear"))
      )
      assertEquals(io.circe.parser.parse(policy(0)._2), io.circe.parser.parse("""{"action":"READ","effect":"ALLOW"}"""))
      assertEquals(io.circe.parser.parse(policy(1)._2), io.circe.parser.parse("""{"action":"WRITE","effect":"ALLOW"}"""))
  }

  test("the development fixture converges on one Linear catalog however often it runs") {
    requireDocker()
    for
      _ <- DemoBootstrap.run(ownerXa)
      first <- linearCounts(DemoBootstrap.Tenant)
      _ <- DemoBootstrap.run(ownerXa)
      second <- linearCounts(DemoBootstrap.Tenant)
    yield
      assertEquals(first, CatalogCounts(1, 2, 3, 3, 2, 2, 0))
      assertEquals(second, first)
  }

  test("adding Linear to an existing tenant binds every active administrator, is idempotent, and leaves GitHub untouched") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, slug) = provisioned
      secondAdmin <- addMember(tenant.tenant, "ADMIN", "ACTIVE")
      _ <- addMember(tenant.tenant, "MEMBER", "ACTIVE")
      _ <- addMember(tenant.tenant, "ADMIN", "REMOVED")
      _ <- stripLinear(tenant.tenant)
      githubBefore <- counts(tenant.tenant)
      empty <- linearCounts(tenant.tenant)
      first <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.Linear)
      afterFirst <- linearCounts(tenant.tenant)
      second <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.Linear)
      afterSecond <- linearCounts(tenant.tenant)
      githubAfter <- counts(tenant.tenant)
      bound <- inTenant(tenant.tenant)(
        sql"""select b.subject_principal_id from policy_bindings b join policies p on p.tenant_id=b.tenant_id and p.id=b.policy_id
               where p.name='Linear write owner authority'""".query[UUID].to[Vector]
      )
    yield
      assertEquals((empty.providers, empty.policies, empty.bindings), (0L, 0L, 0L))
      assertEquals(first.map(result => (result.tenant, result.administrators, result.written)), Some((tenant.tenant, 2, true)))
      assertEquals(afterFirst, CatalogCounts(1, 2, 3, 3, 2, 4, 0))
      assertEquals(second.map(result => (result.administrators, result.written)), Some((2, false)))
      assertEquals(afterSecond, afterFirst, "a second run must change nothing")
      assertEquals(githubAfter.copy(resources = 0), githubBefore.copy(resources = 0))
      assertEquals(bound.toSet, Set(UUID.fromString(tenant.administratorPrincipal.id.toString), UUID.fromString(secondAdmin.toString)))
  }

  test("adding Linear to a tenant that lacks only the create rows adds exactly those rows") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, slug) = provisioned
      _ <- inTenant(tenant.tenant):
        for
          _ <- sql"delete from policy_bindings where policy_id in (select id from policies where name='Linear write owner authority')".update.run
          _ <- sql"delete from policies where name='Linear write owner authority'".update.run
          _ <- sql"delete from tool_capability_mappings where capability_id in (select id from capabilities where namespace='Linear.Issue' and name='Create')".update.run
          _ <- sql"delete from tools where resource_id in (select id from resources where provider='linear' and external_id='linear_issues_create')".update.run
          _ <- sql"delete from resources where provider='linear' and external_id='linear_issues_create'".update.run
          _ <- sql"delete from capabilities where namespace='Linear.Issue' and name='Create'".update.run
        yield ()
      readOnly <- linearCounts(tenant.tenant)
      first <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.Linear)
      afterFirst <- linearCounts(tenant.tenant)
      second <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.Linear)
      afterSecond <- linearCounts(tenant.tenant)
    yield
      assertEquals(readOnly, CatalogCounts(1, 1, 2, 2, 1, 1, 0))
      assertEquals(first.map(_.written), Some(true))
      assertEquals(afterFirst, CatalogCounts(1, 2, 3, 3, 2, 2, 0))
      assertEquals(second.map(_.written), Some(false))
      assertEquals(afterSecond, afterFirst)
  }

  // ---- Notion ---------------------------------------------------------------------------------------------------------

  private def notionCounts(tenant: TenantId): IO[CatalogCounts] = inTenant(tenant):
    for
      providers <- sql"select count(*) from resources where resource_type='PROVIDER' and provider='notion'".query[Long].unique
      capabilities <- sql"select count(*) from capabilities where namespace like 'Notion.%'".query[Long].unique
      tools <- sql"select count(*) from resources where resource_type='TOOL' and provider='notion'".query[Long].unique
      mappings <- sql"""select count(*) from tool_capability_mappings m join resources r on r.tenant_id=m.tenant_id and r.id=m.tool_id
                         where r.provider='notion' and m.trusted and m.mapping_source='PROVIDER_DEFINED'""".query[Long].unique
      policies <- sql"select count(*) from policies where name like 'Notion%'".query[Long].unique
      bindings <- sql"""select count(*) from policy_bindings b join policies p on p.tenant_id=b.tenant_id and p.id=b.policy_id
                         where p.name like 'Notion%'""".query[Long].unique
    yield CatalogCounts(providers, capabilities, tools, mappings, policies, bindings, 0)

  private def stripNotion(tenant: TenantId): IO[Unit] = inTenant(tenant):
    for
      _ <- sql"delete from policy_bindings where policy_id in (select id from policies where name like 'Notion%')".update.run
      _ <- sql"delete from policies where name like 'Notion%'".update.run
      _ <- sql"delete from tool_capability_mappings where capability_id in (select id from capabilities where namespace like 'Notion.%')".update.run
      _ <- sql"delete from tools where resource_id in (select id from resources where provider='notion' and resource_type='TOOL')".update.run
      _ <- sql"delete from capabilities where namespace like 'Notion.%'".update.run
      _ <- sql"delete from resources where provider='notion' and resource_type='TOOL'".update.run
      _ <- sql"delete from resources where provider='notion' and resource_type='PROVIDER'".update.run
    yield ()

  test("a newly provisioned tenant has the Notion catalog, trusted mappings, and a READ owner policy and an approval-gated WRITE owner policy") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, _) = provisioned
      found <- notionCounts(tenant.tenant)
      provider <- inTenant(tenant.tenant)(
        sql"select name, external_id from resources where resource_type='PROVIDER' and provider='notion'".query[(String, Option[String])].to[Vector]
      )
      mappings <- inTenant(tenant.tenant)(
        sql"""select r.external_id, c.namespace || '.' || c.name, c.action
                from tool_capability_mappings m
                join resources r on r.tenant_id=m.tenant_id and r.id=m.tool_id
                join capabilities c on c.tenant_id=m.tenant_id and c.id=m.capability_id
               where r.provider='notion' and m.trusted and m.mapping_source='PROVIDER_DEFINED'
               order by r.external_id""".query[(String, String, String)].to[Vector]
      )
      policy <- inTenant(tenant.tenant)(
        sql"""select p.name, p.definition::text, b.subject_principal_id, rs.provider
                from policies p
                join policy_bindings b on b.tenant_id=p.tenant_id and b.policy_id=p.id
                join resources rs on rs.tenant_id=b.tenant_id and rs.id=b.resource_id
               where rs.provider='notion' order by p.name""".query[(String, String, UUID, String)].to[Vector]
      )
    yield
      assertEquals(found, CatalogCounts(providers = 1, capabilities = 2, tools = 3, trustedMappings = 3, policies = 2, bindings = 2, resources = 0))
      assertEquals(provider, Vector(("Notion", Some("notion"))))
      assertEquals(
        mappings,
        Vector(
          ("notion_blocks_append", "Notion.Page.Append", "WRITE"),
          ("notion_blocks_children_list", "Notion.Page.Read", "READ"),
          ("notion_pages_get", "Notion.Page.Read", "READ")
        )
      )
      val administrator = UUID.fromString(tenant.administratorPrincipal.id.toString)
      assertEquals(
        policy.map(row => (row._1, row._3, row._4)),
        Vector(("Notion append owner authority", administrator, "notion"), ("Notion read owner authority", administrator, "notion"))
      )
      assertEquals(io.circe.parser.parse(policy(1)._2), io.circe.parser.parse("""{"action":"READ","effect":"ALLOW"}"""))
      assertEquals(io.circe.parser.parse(policy(0)._2), io.circe.parser.parse("""{"action":"WRITE","effect":"REQUIRE_APPROVAL"}"""))
  }

  test("the development fixture converges on one Notion catalog however often it runs") {
    requireDocker()
    for
      _ <- DemoBootstrap.run(ownerXa)
      first <- notionCounts(DemoBootstrap.Tenant)
      _ <- DemoBootstrap.run(ownerXa)
      second <- notionCounts(DemoBootstrap.Tenant)
    yield
      assertEquals(first, CatalogCounts(1, 2, 3, 3, 2, 2, 0))
      assertEquals(second, first)
  }

  test("adding Notion to an existing tenant binds every active administrator, is idempotent, and leaves GitHub untouched") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, slug) = provisioned
      secondAdmin <- addMember(tenant.tenant, "ADMIN", "ACTIVE")
      _ <- addMember(tenant.tenant, "MEMBER", "ACTIVE")
      _ <- addMember(tenant.tenant, "ADMIN", "REMOVED")
      _ <- stripNotion(tenant.tenant)
      githubBefore <- counts(tenant.tenant)
      empty <- notionCounts(tenant.tenant)
      first <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.Notion)
      afterFirst <- notionCounts(tenant.tenant)
      second <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.Notion)
      afterSecond <- notionCounts(tenant.tenant)
      githubAfter <- counts(tenant.tenant)
      bound <- inTenant(tenant.tenant)(
        sql"""select b.subject_principal_id from policy_bindings b join policies p on p.tenant_id=b.tenant_id and p.id=b.policy_id
               where p.name='Notion append owner authority'""".query[UUID].to[Vector]
      )
    yield
      assertEquals((empty.providers, empty.policies, empty.bindings), (0L, 0L, 0L))
      assertEquals(first.map(result => (result.tenant, result.administrators, result.written)), Some((tenant.tenant, 2, true)))
      assertEquals(afterFirst, CatalogCounts(1, 2, 3, 3, 2, 4, 0))
      assertEquals(second.map(result => (result.administrators, result.written)), Some((2, false)))
      assertEquals(afterSecond, afterFirst, "a second run must change nothing")
      assertEquals(githubAfter.copy(resources = 0), githubBefore.copy(resources = 0))
      assertEquals(bound.toSet, Set(UUID.fromString(tenant.administratorPrincipal.id.toString), UUID.fromString(secondAdmin.toString)))
  }

  test("adding Notion to a tenant that lacks only the append rows adds exactly those rows") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, slug) = provisioned
      _ <- inTenant(tenant.tenant):
        for
          _ <- sql"delete from policy_bindings where policy_id in (select id from policies where name='Notion append owner authority')".update.run
          _ <- sql"delete from policies where name='Notion append owner authority'".update.run
          _ <- sql"delete from tool_capability_mappings where capability_id in (select id from capabilities where namespace='Notion.Page' and name='Append')".update.run
          _ <- sql"delete from tools where resource_id in (select id from resources where provider='notion' and external_id='notion_blocks_append')".update.run
          _ <- sql"delete from resources where provider='notion' and external_id='notion_blocks_append'".update.run
          _ <- sql"delete from capabilities where namespace='Notion.Page' and name='Append'".update.run
        yield ()
      readOnly <- notionCounts(tenant.tenant)
      first <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.Notion)
      afterFirst <- notionCounts(tenant.tenant)
      second <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.Notion)
      afterSecond <- notionCounts(tenant.tenant)
    yield
      assertEquals(readOnly, CatalogCounts(1, 1, 2, 2, 1, 1, 0))
      assertEquals(first.map(_.written), Some(true))
      assertEquals(afterFirst, CatalogCounts(1, 2, 3, 3, 2, 2, 0))
      assertEquals(second.map(_.written), Some(false))
      assertEquals(afterSecond, afterFirst)
  }

  // ---- HubSpot ---------------------------------------------------------------------------------------------------------

  private def hubspotCounts(tenant: TenantId): IO[CatalogCounts] = inTenant(tenant):
    for
      providers <- sql"select count(*) from resources where resource_type='PROVIDER' and provider='hubspot'".query[Long].unique
      capabilities <- sql"select count(*) from capabilities where namespace like 'HubSpot.%'".query[Long].unique
      tools <- sql"select count(*) from resources where resource_type='TOOL' and provider='hubspot'".query[Long].unique
      mappings <- sql"""select count(*) from tool_capability_mappings m join resources r on r.tenant_id=m.tenant_id and r.id=m.tool_id
                         where r.provider='hubspot' and m.trusted and m.mapping_source='PROVIDER_DEFINED'""".query[Long].unique
      policies <- sql"select count(*) from policies where name like 'HubSpot%'".query[Long].unique
      bindings <- sql"""select count(*) from policy_bindings b join policies p on p.tenant_id=b.tenant_id and p.id=b.policy_id
                         where p.name like 'HubSpot%'""".query[Long].unique
    yield CatalogCounts(providers, capabilities, tools, mappings, policies, bindings, 0)

  private def stripHubSpot(tenant: TenantId): IO[Unit] = inTenant(tenant):
    for
      _ <- sql"delete from policy_bindings where policy_id in (select id from policies where name like 'HubSpot%')".update.run
      _ <- sql"delete from policies where name like 'HubSpot%'".update.run
      _ <- sql"delete from tool_capability_mappings where capability_id in (select id from capabilities where namespace like 'HubSpot.%')".update.run
      _ <- sql"delete from tools where resource_id in (select id from resources where provider='hubspot' and resource_type='TOOL')".update.run
      _ <- sql"delete from capabilities where namespace like 'HubSpot.%'".update.run
      _ <- sql"delete from resources where provider='hubspot' and resource_type='TOOL'".update.run
      _ <- sql"delete from resources where provider='hubspot' and resource_type='PROVIDER'".update.run
    yield ()

  test("a newly provisioned tenant has the HubSpot catalog, trusted mappings, and a READ owner policy and an approval-gated update owner policy") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, _) = provisioned
      found <- hubspotCounts(tenant.tenant)
      provider <- inTenant(tenant.tenant)(
        sql"select name, external_id from resources where resource_type='PROVIDER' and provider='hubspot'".query[(String, Option[String])].to[Vector]
      )
      mappings <- inTenant(tenant.tenant)(
        sql"""select r.external_id, c.namespace || '.' || c.name, c.action
                from tool_capability_mappings m
                join resources r on r.tenant_id=m.tenant_id and r.id=m.tool_id
                join capabilities c on c.tenant_id=m.tenant_id and c.id=m.capability_id
               where r.provider='hubspot' and m.trusted and m.mapping_source='PROVIDER_DEFINED'
               order by r.external_id""".query[(String, String, String)].to[Vector]
      )
      policy <- inTenant(tenant.tenant)(
        sql"""select p.name, p.definition::text, b.subject_principal_id, rs.provider
                from policies p
                join policy_bindings b on b.tenant_id=p.tenant_id and b.policy_id=p.id
                join resources rs on rs.tenant_id=b.tenant_id and rs.id=b.resource_id
               where rs.provider='hubspot' order by p.name""".query[(String, String, UUID, String)].to[Vector]
      )
    yield
      assertEquals(found, CatalogCounts(providers = 1, capabilities = 3, tools = 3, trustedMappings = 3, policies = 2, bindings = 2, resources = 0))
      assertEquals(provider, Vector(("HubSpot", Some("hubspot"))))
      assertEquals(
        mappings,
        Vector(
          ("hubspot_contacts_get", "HubSpot.Contact.Read", "READ"),
          ("hubspot_deals_get", "HubSpot.Deal.Read", "READ"),
          ("hubspot_deals_update_properties", "HubSpot.Deal.Update", "WRITE")
        )
      )
      val administrator = UUID.fromString(tenant.administratorPrincipal.id.toString)
      assertEquals(
        policy.map(row => (row._1, row._3, row._4)),
        Vector(("HubSpot deal update owner authority", administrator, "hubspot"), ("HubSpot read owner authority", administrator, "hubspot"))
      )
      assertEquals(io.circe.parser.parse(policy(1)._2), io.circe.parser.parse("""{"action":"READ","effect":"ALLOW"}"""))
      assertEquals(io.circe.parser.parse(policy(0)._2), io.circe.parser.parse("""{"action":"WRITE","effect":"REQUIRE_APPROVAL"}"""))
  }

  test("the development fixture converges on one HubSpot catalog however often it runs") {
    requireDocker()
    for
      _ <- DemoBootstrap.run(ownerXa)
      first <- hubspotCounts(DemoBootstrap.Tenant)
      _ <- DemoBootstrap.run(ownerXa)
      second <- hubspotCounts(DemoBootstrap.Tenant)
    yield
      assertEquals(first, CatalogCounts(1, 3, 3, 3, 2, 2, 0))
      assertEquals(second, first)
  }

  test("adding HubSpot to an existing tenant binds every active administrator, is idempotent, and leaves GitHub untouched") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, slug) = provisioned
      secondAdmin <- addMember(tenant.tenant, "ADMIN", "ACTIVE")
      _ <- addMember(tenant.tenant, "MEMBER", "ACTIVE")
      _ <- addMember(tenant.tenant, "ADMIN", "REMOVED")
      _ <- stripHubSpot(tenant.tenant)
      githubBefore <- counts(tenant.tenant)
      empty <- hubspotCounts(tenant.tenant)
      first <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.HubSpot)
      afterFirst <- hubspotCounts(tenant.tenant)
      second <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.HubSpot)
      afterSecond <- hubspotCounts(tenant.tenant)
      githubAfter <- counts(tenant.tenant)
      bound <- inTenant(tenant.tenant)(
        sql"""select b.subject_principal_id from policy_bindings b join policies p on p.tenant_id=b.tenant_id and p.id=b.policy_id
               where p.name='HubSpot deal update owner authority'""".query[UUID].to[Vector]
      )
    yield
      assertEquals((empty.providers, empty.policies, empty.bindings), (0L, 0L, 0L))
      assertEquals(first.map(result => (result.tenant, result.administrators, result.written)), Some((tenant.tenant, 2, true)))
      assertEquals(afterFirst, CatalogCounts(1, 3, 3, 3, 2, 4, 0))
      assertEquals(second.map(result => (result.administrators, result.written)), Some((2, false)))
      assertEquals(afterSecond, afterFirst, "a second run must change nothing")
      assertEquals(githubAfter.copy(resources = 0), githubBefore.copy(resources = 0))
      assertEquals(bound.toSet, Set(UUID.fromString(tenant.administratorPrincipal.id.toString), UUID.fromString(secondAdmin.toString)))
  }

  // ---- Google ---------------------------------------------------------------------------------------------------------

  private def googleCounts(tenant: TenantId): IO[CatalogCounts] = inTenant(tenant):
    for
      providers <- sql"select count(*) from resources where resource_type='PROVIDER' and provider='google'".query[Long].unique
      capabilities <- sql"select count(*) from capabilities where namespace like 'Google.%'".query[Long].unique
      tools <- sql"select count(*) from resources where resource_type='TOOL' and provider='google'".query[Long].unique
      mappings <- sql"""select count(*) from tool_capability_mappings m join resources r on r.tenant_id=m.tenant_id and r.id=m.tool_id
                         where r.provider='google' and m.trusted and m.mapping_source='PROVIDER_DEFINED'""".query[Long].unique
      policies <- sql"select count(*) from policies where name like 'Google%' or name like 'Gmail%'".query[Long].unique
      bindings <- sql"""select count(*) from policy_bindings b join policies p on p.tenant_id=b.tenant_id and p.id=b.policy_id
                         where p.name like 'Google%' or p.name like 'Gmail%'""".query[Long].unique
    yield CatalogCounts(providers, capabilities, tools, mappings, policies, bindings, 0)

  private def stripGoogle(tenant: TenantId): IO[Unit] = inTenant(tenant):
    for
      _ <- sql"delete from policy_bindings where policy_id in (select id from policies where name like 'Google%' or name like 'Gmail%')".update.run
      _ <- sql"delete from policies where name like 'Google%' or name like 'Gmail%'".update.run
      _ <- sql"delete from tool_capability_mappings where capability_id in (select id from capabilities where namespace like 'Google.%')".update.run
      _ <- sql"delete from tools where resource_id in (select id from resources where provider='google' and resource_type='TOOL')".update.run
      _ <- sql"delete from capabilities where namespace like 'Google.%'".update.run
      _ <- sql"delete from resources where provider='google' and resource_type='TOOL'".update.run
      _ <- sql"delete from resources where provider='google' and resource_type='PROVIDER'".update.run
    yield ()

  test("a newly provisioned tenant has the Google catalog, trusted mappings, and a READ owner policy") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, _) = provisioned
      found <- googleCounts(tenant.tenant)
      provider <- inTenant(tenant.tenant)(
        sql"select name, external_id from resources where resource_type='PROVIDER' and provider='google'".query[(String, Option[String])].to[Vector]
      )
      mappings <- inTenant(tenant.tenant)(
        sql"""select r.external_id, c.namespace || '.' || c.name, c.action
                from tool_capability_mappings m
                join resources r on r.tenant_id=m.tenant_id and r.id=m.tool_id
                join capabilities c on c.tenant_id=m.tenant_id and c.id=m.capability_id
               where r.provider='google' and m.trusted and m.mapping_source='PROVIDER_DEFINED'
               order by r.external_id""".query[(String, String, String)].to[Vector]
      )
      policy <- inTenant(tenant.tenant)(
        sql"""select p.name, p.definition::text, b.subject_principal_id, rs.provider
                from policies p
                join policy_bindings b on b.tenant_id=p.tenant_id and b.policy_id=p.id
                join resources rs on rs.tenant_id=b.tenant_id and rs.id=b.resource_id
               where rs.provider='google' order by p.name""".query[(String, String, UUID, String)].to[Vector]
      )
    yield
      assertEquals(found, CatalogCounts(providers = 1, capabilities = 2, tools = 3, trustedMappings = 3, policies = 2, bindings = 2, resources = 0))
      assertEquals(provider, Vector(("Google", Some("google"))))
      assertEquals(
        mappings,
        Vector(
          ("drive_files_export_text", "Google.DriveFile.Read", "READ"),
          ("drive_files_get", "Google.DriveFile.Read", "READ"),
          ("gmail_messages_send", "Google.Mail.Send", "WRITE")
        )
      )
      val administrator = UUID.fromString(tenant.administratorPrincipal.id.toString)
      assertEquals(
        policy.map(row => (row._1, row._3, row._4)),
        Vector(("Gmail send owner authority", administrator, "google"), ("Google Drive read owner authority", administrator, "google"))
      )
      assertEquals(io.circe.parser.parse(policy(0)._2), io.circe.parser.parse("""{"action":"WRITE","effect":"REQUIRE_APPROVAL"}"""))
      assertEquals(io.circe.parser.parse(policy(1)._2), io.circe.parser.parse("""{"action":"READ","effect":"ALLOW"}"""))
  }

  test("the development fixture converges on one Google catalog however often it runs") {
    requireDocker()
    for
      _ <- DemoBootstrap.run(ownerXa)
      first <- googleCounts(DemoBootstrap.Tenant)
      _ <- DemoBootstrap.run(ownerXa)
      second <- googleCounts(DemoBootstrap.Tenant)
    yield
      assertEquals(first, CatalogCounts(1, 2, 3, 3, 2, 2, 0))
      assertEquals(second, first)
  }

  test("adding Google to an existing tenant binds every active administrator, is idempotent, and leaves GitHub untouched") {
    requireDocker()
    for
      provisioned <- provision()
      (tenant, slug) = provisioned
      secondAdmin <- addMember(tenant.tenant, "ADMIN", "ACTIVE")
      _ <- addMember(tenant.tenant, "MEMBER", "ACTIVE")
      _ <- addMember(tenant.tenant, "ADMIN", "REMOVED")
      _ <- stripGoogle(tenant.tenant)
      githubBefore <- counts(tenant.tenant)
      empty <- googleCounts(tenant.tenant)
      first <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.Google)
      afterFirst <- googleCounts(tenant.tenant)
      second <- ProviderCatalogProvisioning.addToExisting(ownerXa, slug, ExistingTenantProvider.Google)
      afterSecond <- googleCounts(tenant.tenant)
      githubAfter <- counts(tenant.tenant)
      bound <- inTenant(tenant.tenant)(
        sql"""select b.subject_principal_id from policy_bindings b join policies p on p.tenant_id=b.tenant_id and p.id=b.policy_id
               where p.name='Google Drive read owner authority'""".query[UUID].to[Vector]
      )
    yield
      assertEquals((empty.providers, empty.policies, empty.bindings), (0L, 0L, 0L))
      assertEquals(first.map(result => (result.tenant, result.administrators, result.written)), Some((tenant.tenant, 2, true)))
      assertEquals(afterFirst, CatalogCounts(1, 2, 3, 3, 2, 4, 0))
      assertEquals(second.map(result => (result.administrators, result.written)), Some((2, false)))
      assertEquals(afterSecond, afterFirst, "a second run must change nothing")
      assertEquals(githubAfter.copy(resources = 0), githubBefore.copy(resources = 0))
      assertEquals(bound.toSet, Set(UUID.fromString(tenant.administratorPrincipal.id.toString), UUID.fromString(secondAdmin.toString)))
  }

  test("provider names parse to the providers that can be added to an existing tenant") {
    assertEquals(ExistingTenantProvider.parse("linear"), Some(ExistingTenantProvider.Linear))
    assertEquals(ExistingTenantProvider.parse("Linear"), None)
    assertEquals(ExistingTenantProvider.parse("notion"), Some(ExistingTenantProvider.Notion))
    assertEquals(ExistingTenantProvider.parse("Notion"), None)
    assertEquals(ExistingTenantProvider.parse("google"), Some(ExistingTenantProvider.Google))
    assertEquals(ExistingTenantProvider.parse("Google"), None)
    assertEquals(ExistingTenantProvider.parse("hubspot"), Some(ExistingTenantProvider.HubSpot))
    assertEquals(ExistingTenantProvider.parse("HubSpot"), None)
    assertEquals(ExistingTenantProvider.parse("github"), Some(ExistingTenantProvider.GitHub))
  }
