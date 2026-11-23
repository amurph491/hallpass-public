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

/** The Linear resource kinds registered by V23: their shape, how the runtime role may place them under an active Linear
  * connection, and how a team round-trips through the control plane's scope loading. The schema is migrated by a
  * separate owner role and served to a non-owner runtime role, as in production. */
final class PostgresLinearKindsSuite extends CatsEffectSuite:
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

  private sealed trait LOrganization
  private sealed trait LTeam
  private val linear = ProviderId.parse("linear").getOrElse(fail("provider"))
  private val organization: ResourceKind[LOrganization] =
    ResourceKind.root[LOrganization]("linear.organization", linear, ResourceType.Account, Custody.Workspace)
  private val team: ResourceKind[LTeam] = ResourceKind.child[LTeam, LOrganization]("linear.team", ResourceType.Team)(using organization)

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
      .from("Linear kinds", s"lk-${subject.take(8)}", ExternalIdentity.from("https://idp.example.com", subject).toOption.get)
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

  test("V23 registers linear.organization as a workspace account root and linear.team as its TEAM child") {
    requireDocker()
    sql"""select wire, provider, parent_wire, resource_type, custody from resource_kinds
           where provider='linear' order by wire"""
      .query[(String, String, Option[String], String, Option[String])]
      .to[Vector]
      .transact(ownerXa)
      .map: kinds =>
        assertEquals(
          kinds,
          Vector(
            ("linear.organization", "linear", None, "ACCOUNT", Some("WORKSPACE")),
            ("linear.team", "linear", Some("linear.organization"), "TEAM", None)
          )
        )
  }

  test("under an active Linear connection the runtime role inserts an organization root and a team under it") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "LINEAR")
      rootRows <- runtimeTx(ids.tenant)(
        insertResource(ids.tenant, "ACCOUNT", "linear.organization", connection, ids.linear.resource, "org-1", "linear")
      )
      rootId <- runtimeTx(ids.tenant)(
        sql"select id from resources where tenant_id=${ids.tenant.toString}::uuid and kind='linear.organization'".query[UUID].unique
      )
      teamRows <- runtimeTx(ids.tenant)(
        insertResource(
          ids.tenant, "TEAM", "linear.team", connection, ResourceId.parse(rootId.toString).toOption.get, "team-1", "linear"
        )
      )
    yield assertEquals((rootRows, teamRows), (1, 1))
  }

  test("a team directly under the Linear catalog resource is refused") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "LINEAR")
      _ <- refused(
        runtimeTx(ids.tenant)(insertResource(ids.tenant, "TEAM", "linear.team", connection, ids.linear.resource, "team-x", "linear")),
        "a selected resource must be under its registered parent kind in the same connection"
      )
    yield ()
  }

  test("a team under a GitHub connection is refused") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "GITHUB")
      _ <- refused(
        runtimeTx(ids.tenant)(insertResource(ids.tenant, "TEAM", "linear.team", connection, ids.github.resource, "team-y", "github")),
        "resource kind is not registered for the connection's provider"
      )
    yield ()
  }

  test("a Linear team round-trips through scope loading as ResourceType.Team") {
    requireDocker()
    val resources = PostgresConnectionResources(runtimeXa)
    val catalog = PostgresControlPlane(runtimeXa)
    for
      provisioned <- provision()
      (ids, human) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "LINEAR")
      root <- okOrFail(resources.createRoot(ids.tenant, connection, organization, ext("org-rt"), "Acme", None))
      selected <- okOrFail(resources.select(ids.tenant, connection, team, ext("team-rt"), "Platform", root.id, human, now))
      scope <- catalog.selectedScope(ids.tenant, team, ext("team-rt"))
      targets <- catalog.discoveryTargets(ids.tenant, team)
      current <- catalog.currentScope(ids.tenant, selected.id)
    yield
      val found = scope.getOrElse(fail("the selected team has no scope"))
      assertEquals(found.target.resourceType, ResourceType.Team)
      assertEquals(found.target.id, selected.id)
      assertEquals(found.path.map(_.resourceType), Vector(ResourceType.Team, ResourceType.Account, ResourceType.Provider))
      assertEquals(found.path.last.id, ids.linear.resource)
      assertEquals(targets.map(t => (t.scope.target.id, t.displayName)), Vector((selected.id, "Platform")))
      assertEquals(current.map(_.target.resourceType), Some(ResourceType.Team))
  }
