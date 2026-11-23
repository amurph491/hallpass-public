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
import run.hallpass.adapters.hubspot.HubSpotObjectRef.*

/** The HubSpot resource kinds registered by V28: their shape, how the runtime role may place a portal root and a CRM
  * object type under it, and how an object type round-trips through the control plane's scope loading as a CUSTOM
  * resource. The schema is migrated by a separate owner role and served to a non-owner runtime role, as in production. */
final class PostgresHubSpotKindsSuite extends CatsEffectSuite:
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

  private val portal: ResourceKind[run.hallpass.adapters.hubspot.HubSpot.Portal] = run.hallpass.adapters.hubspot.HubSpot.portal
  private val objectType: ResourceKind[run.hallpass.adapters.hubspot.HubSpot.ObjectType] = run.hallpass.adapters.hubspot.HubSpot.objectType

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
      .from("HubSpot kinds", s"nk-${subject.take(8)}", ExternalIdentity.from("https://idp.example.com", subject).toOption.get)
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

  test("V28 registers hubspot.portal as a WORKSPACE account root and hubspot.object_type as its CUSTOM child") {
    requireDocker()
    sql"""select wire, provider, parent_wire, resource_type, custody from resource_kinds
           where provider='hubspot' order by wire"""
      .query[(String, String, Option[String], String, Option[String])]
      .to[Vector]
      .transact(ownerXa)
      .map: kinds =>
        assertEquals(
          kinds,
          Vector(
            ("hubspot.object_type", "hubspot", Some("hubspot.portal"), "CUSTOM", None),
            ("hubspot.portal", "hubspot", None, "ACCOUNT", Some("WORKSPACE"))
          )
        )
  }

  test("under an active HubSpot connection the runtime role inserts a portal root and an object type under it") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "HUBSPOT")
      rootRows <- runtimeTx(ids.tenant)(
        insertResource(ids.tenant, "ACCOUNT", "hubspot.portal", connection, ids.hubspot.resource, "12345", "hubspot")
      )
      rootId <- runtimeTx(ids.tenant)(
        sql"select id from resources where tenant_id=${ids.tenant.toString}::uuid and kind='hubspot.portal'".query[UUID].unique
      )
      typeRows <- runtimeTx(ids.tenant)(
        insertResource(
          ids.tenant, "CUSTOM", "hubspot.object_type", connection, ResourceId.parse(rootId.toString).toOption.get, "deals", "hubspot"
        )
      )
    yield assertEquals((rootRows, typeRows), (1, 1))
  }

  test("an object type directly under the HubSpot catalog resource is refused") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "HUBSPOT")
      _ <- refused(
        runtimeTx(ids.tenant)(insertResource(ids.tenant, "CUSTOM", "hubspot.object_type", connection, ids.hubspot.resource, "deals", "hubspot")),
        "a selected resource must be under its registered parent kind in the same connection"
      )
    yield ()
  }

  test("an object type under a GitHub connection is refused") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "GITHUB")
      _ <- refused(
        runtimeTx(ids.tenant)(insertResource(ids.tenant, "CUSTOM", "hubspot.object_type", connection, ids.github.resource, "deals", "github")),
        "resource kind is not registered for the connection's provider"
      )
    yield ()
  }

  test("an object type registered with the wrong resource type is refused") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "HUBSPOT")
      _ <- runtimeTx(ids.tenant)(insertResource(ids.tenant, "ACCOUNT", "hubspot.portal", connection, ids.hubspot.resource, "12345", "hubspot"))
      rootId <- runtimeTx(ids.tenant)(
        sql"select id from resources where tenant_id=${ids.tenant.toString}::uuid and kind='hubspot.portal'".query[UUID].unique
      )
      _ <- refused(
        runtimeTx(ids.tenant)(
          insertResource(ids.tenant, "DOCUMENT", "hubspot.object_type", connection, ResourceId.parse(rootId.toString).toOption.get, "deals", "hubspot")
        ),
        "resource type does not match its registered kind"
      )
    yield ()
  }

  test("a HubSpot object type round-trips through scope loading as ResourceType.Custom") {
    requireDocker()
    val resources = PostgresConnectionResources(runtimeXa)
    val catalog = PostgresControlPlane(runtimeXa)
    for
      provisioned <- provision()
      (ids, human) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "HUBSPOT")
      root <- okOrFail(resources.createRoot(ids.tenant, connection, portal, ext("12345"), "Acme portal", None))
      selected <- okOrFail(resources.select(ids.tenant, connection, objectType, ext("deals"), "Deals", root.id, human, now))
      scope <- catalog.selectedScope(ids.tenant, objectType, ext("deals"))
      targets <- catalog.discoveryTargets(ids.tenant, objectType)
      current <- catalog.currentScope(ids.tenant, selected.id)
    yield
      val found = scope.getOrElse(fail("the selected object type has no scope"))
      assertEquals(found.target.resourceType, ResourceType.Custom)
      assertEquals(found.target.id, selected.id)
      assertEquals(found.path.map(_.resourceType), Vector(ResourceType.Custom, ResourceType.Account, ResourceType.Provider))
      assertEquals(found.path.last.id, ids.hubspot.resource)
      assertEquals(targets.map(t => (t.scope.target.id, t.displayName)), Vector((selected.id, "Deals")))
      assertEquals(current.map(_.target.resourceType), Some(ResourceType.Custom))
  }

  test("portal-qualified object selections resolve to their own connected portal") {
    requireDocker()
    val resources = PostgresConnectionResources(runtimeXa)
    val catalog = PostgresControlPlane(runtimeXa)
    val refA = run.hallpass.adapters.hubspot.HubSpotObjectRef.forPortal(ext("12345"), ext("deals")).get
    val refB = run.hallpass.adapters.hubspot.HubSpotObjectRef.forPortal(ext("67890"), ext("deals")).get
    for
      provisioned <- provision()
      (ids, human) = provisioned
      connectionA <- activeConnection(ids.tenant, ids.administratorPrincipal, "HUBSPOT")
      connectionB <- activeConnection(ids.tenant, ids.administratorPrincipal, "HUBSPOT")
      rootA <- okOrFail(resources.createRoot(ids.tenant, connectionA, portal, ext("12345"), "Portal A", None))
      rootB <- okOrFail(resources.createRoot(ids.tenant, connectionB, portal, ext("67890"), "Portal B", None))
      selectedA <- okOrFail(resources.select(ids.tenant, connectionA, objectType, refA.externalId, "Deals", rootA.id, human, now))
      selectedB <- okOrFail(resources.select(ids.tenant, connectionB, objectType, refB.externalId, "Deals", rootB.id, human, now))
      scopeA <- catalog.selectedScope(ids.tenant, objectType, refA.externalId)
      scopeB <- catalog.selectedScope(ids.tenant, objectType, refB.externalId)
    yield
      assertEquals(refA.value, "12345:deals")
      assertEquals(refB.value, "67890:deals")
      assertNotEquals(refA.value, refB.value)
      assertEquals(scopeA.map(_.target.id), Some(selectedA.id))
      assertEquals(scopeB.map(_.target.id), Some(selectedB.id))
      assertEquals(scopeA.flatMap(_.path.lift(1)).map(_.id), Some(rootA.id))
      assertEquals(scopeB.flatMap(_.path.lift(1)).map(_.id), Some(rootB.id))
  }
