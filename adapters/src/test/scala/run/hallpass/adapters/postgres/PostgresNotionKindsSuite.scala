package run.hallpass.adapters.postgres

import java.sql.DriverManager
import java.time.Instant
import java.util.UUID
import scala.compiletime.uninitialized
import cats.effect.IO
import cats.effect.unsafe.implicits.global
import cats.syntax.all.*
import munit.CatsEffectSuite
import org.postgresql.util.PSQLException
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.application.*
import run.hallpass.kernel.*

/** The Notion resource kinds registered by V25: their shape, how the runtime role may place them under an active Linear
  * connection, and how a page round-trips through the control plane's scope loading. The schema is migrated by a
  * separate owner role and served to a non-owner runtime role, as in production. */
final class PostgresNotionKindsSuite extends CatsEffectSuite:
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(180, "s")
  private val Owner = "authai_owner"
  private val App = "authai_app"
  private val Password = "test-password"
  private var container: PostgreSQLContainer[?] = uninitialized
  private var dockerAvailable = false
  private var ownerXa: Transactor[IO] = uninitialized
  private var runtimeXa: Transactor[IO] = uninitialized
  private var release: IO[Unit] = IO.unit
  private val runtimeRole = RuntimeRole.parse(App).toOption.get
  private val now = Instant.parse("2026-09-30T12:00:00Z")

  private sealed trait NWorkspace
  private sealed trait NPage
  private val notion = ProviderId.parse("notion").getOrElse(fail("provider"))
  private val workspace: ResourceKind[NWorkspace] =
    ResourceKind.root[NWorkspace]("notion.workspace", notion, ResourceType.Account, Custody.Workspace)
  private val page: ResourceKind[NPage] = ResourceKind.child[NPage, NWorkspace]("notion.page", ResourceType.Document)(using workspace)

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
        runtime <- PostgresDatabase.resourceWithSchema(config(App), MigrationMode.External).allocated
      yield (owner, runtime)
      val ((owner, releaseOwner), ((runtime, _), releaseRuntime)) = setup.unsafeRunSync()
      ownerXa = owner
      runtimeXa = runtime
      release = releaseRuntime *> releaseOwner

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

  private def ownerTx[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(ownerXa)

  private def runtimeTx[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(runtimeXa)

  private def provision(): IO[(ProvisioningIds, Principal.Human)] =
    val ids = ProvisioningIds.random()
    val subject = UUID.randomUUID().toString
    val request = TenantProvisioningRequest
      .from("Notion kinds", s"nk-${subject.take(8)}", ExternalIdentity.from("https://idp.example.com", subject).toOption.get)
      .toOption
      .get
    TenantProvisioning.program(request, ids).transact(ownerXa).map(provisioned => ids -> provisioned.administratorPrincipal)

  private def activeConnection(tenant: TenantId, admin: UserId, providerName: String): IO[ConnectionId] =
    val id = ConnectionId.random()
    ownerTx(tenant):
      sql"""insert into connections (id, tenant_id, provider, status, owner_principal_id)
             values (${id.toString}::uuid, ${tenant.toString}::uuid, $providerName, 'ACTIVE', ${admin.toString}::uuid)""".update.run.as(id)

  private def insertResource(
      tenant: TenantId,
      resourceType: String,
      kind: String,
      connection: ConnectionId,
      parent: ResourceId,
      externalId: String,
      providerName: String
  ): ConnectionIO[Int] =
    sql"""insert into resources (id, tenant_id, resource_type, name, provider, parent_resource_id, external_id, kind, connection_id)
           values (${UUID.randomUUID().toString}::uuid, ${tenant.toString}::uuid, $resourceType, $externalId, $providerName,
                   ${parent.toString}::uuid, $externalId, $kind, ${connection.toString}::uuid)""".update.run

  private def refused[A](attempt: IO[A], fragment: String): IO[Unit] =
    attempt.attempt.map:
      case Right(value) => fail(s"expected a refusal containing '$fragment' but the statement succeeded: $value")
      case Left(failure: PSQLException) =>
        assertEquals(failure.getSQLState, "23514", failure.getMessage)
        assert(failure.getMessage.contains(fragment), s"expected '$fragment' in: ${failure.getMessage}")
      case Left(failure) => throw failure

  private def ext(value: String): ExternalId = ExternalId.parse(value).getOrElse(fail(s"external id $value"))

  private def okOrFail[A](result: IO[Either[ConnectionResourceError, A]]): IO[A] =
    result.flatMap:
      case Right(value) => IO.pure(value)
      case Left(error)  => IO.raiseError(AssertionError(s"expected success, received $error"))

  test("V25 registers notion.workspace as a workspace account root and notion.page as its DOCUMENT child") {
    requireDocker()
    sql"""select wire, provider, parent_wire, resource_type, custody from resource_kinds
           where provider='notion' order by wire"""
      .query[(String, String, Option[String], String, Option[String])]
      .to[Vector]
      .transact(ownerXa)
      .map: kinds =>
        assertEquals(
          kinds,
          Vector(
            ("notion.page", "notion", Some("notion.workspace"), "DOCUMENT", None),
            ("notion.workspace", "notion", None, "ACCOUNT", Some("WORKSPACE"))
          )
        )
  }

  test("under an active Notion connection the runtime role inserts a workspace root and a page under it") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "NOTION")
      rootRows <- runtimeTx(ids.tenant)(
        insertResource(ids.tenant, "ACCOUNT", "notion.workspace", connection, ids.notion.resource, "ws-1", "notion")
      )
      rootId <- runtimeTx(ids.tenant)(
        sql"select id from resources where tenant_id=${ids.tenant.toString}::uuid and kind='notion.workspace'".query[UUID].unique
      )
      pageRows <- runtimeTx(ids.tenant)(
        insertResource(
          ids.tenant, "DOCUMENT", "notion.page", connection, ResourceId.parse(rootId.toString).toOption.get, "page-1", "notion"
        )
      )
    yield assertEquals((rootRows, pageRows), (1, 1))
  }

  test("a page directly under the Notion catalog resource is refused") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "NOTION")
      _ <- refused(
        runtimeTx(ids.tenant)(insertResource(ids.tenant, "DOCUMENT", "notion.page", connection, ids.notion.resource, "page-x", "notion")),
        "a selected resource must be under its registered parent kind in the same connection"
      )
    yield ()
  }

  test("a page under a GitHub connection is refused") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "GITHUB")
      _ <- refused(
        runtimeTx(ids.tenant)(insertResource(ids.tenant, "DOCUMENT", "notion.page", connection, ids.github.resource, "page-y", "github")),
        "resource kind is not registered for the connection's provider"
      )
    yield ()
  }

  test("a Notion page round-trips through scope loading as ResourceType.Document") {
    requireDocker()
    val resources = PostgresConnectionResources(runtimeXa)
    val catalog = PostgresControlPlane(runtimeXa)
    for
      provisioned <- provision()
      (ids, human) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "NOTION")
      root <- okOrFail(resources.createRoot(ids.tenant, connection, workspace, ext("ws-rt"), "Acme", None))
      selected <- okOrFail(resources.select(ids.tenant, connection, page, ext("page-rt"), "Roadmap", root.id, human, now))
      scope <- catalog.selectedScope(ids.tenant, page, ext("page-rt"))
      targets <- catalog.discoveryTargets(ids.tenant, page)
      current <- catalog.currentScope(ids.tenant, selected.id)
    yield
      val found = scope.getOrElse(fail("the selected page has no scope"))
      assertEquals(found.target.resourceType, ResourceType.Document)
      assertEquals(found.target.id, selected.id)
      assertEquals(found.path.map(_.resourceType), Vector(ResourceType.Document, ResourceType.Account, ResourceType.Provider))
      assertEquals(found.path.last.id, ids.notion.resource)
      assertEquals(targets.map(t => (t.scope.target.id, t.displayName)), Vector((selected.id, "Roadmap")))
      assertEquals(current.map(_.target.resourceType), Some(ResourceType.Document))
  }

  private def insertCredential(tenant: TenantId, connection: ConnectionId, credentialType: String): ConnectionIO[Int] =
    sql"""insert into credential_references (tenant_id, connection_id, secret_reference, credential_type)
           values (${tenant.toString}::uuid, ${connection.toString}::uuid, 'ref-1', $credentialType)""".update.run

  test("a NOTION_OAUTH credential reference is accepted") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "NOTION")
      rows <- runtimeTx(ids.tenant)(insertCredential(ids.tenant, connection, "NOTION_OAUTH"))
    yield assertEquals(rows, 1)
  }

  test("an unknown credential type is still refused") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "NOTION")
      _ <- refused(runtimeTx(ids.tenant)(insertCredential(ids.tenant, connection, "NOTION_PASSWORD")), "credential_references_type_check")
    yield ()
  }
