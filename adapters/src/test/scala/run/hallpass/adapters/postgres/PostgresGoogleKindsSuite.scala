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

/** The Google resource kinds registered by V26: their shape, how the runtime role may place a personal account root and
  * a Drive file under it, and how a file round-trips through the control plane's scope loading. The schema is migrated by a
  * separate owner role and served to a non-owner runtime role, as in production. */
final class PostgresGoogleKindsSuite extends CatsEffectSuite:
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

  private val account: ResourceKind[run.hallpass.adapters.google.Google.Account] = run.hallpass.adapters.google.Google.account
  private val driveFile: ResourceKind[run.hallpass.adapters.google.Google.DriveFile] = run.hallpass.adapters.google.Google.driveFile

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
      .from("Google kinds", s"gk-${subject.take(8)}", ExternalIdentity.from("https://idp.example.com", subject).toOption.get)
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


  private def insertResource(
      tenant: TenantId,
      resourceType: String,
      kind: String,
      connection: ConnectionId,
      parent: UUID,
      externalId: String,
      custodian: Option[UUID]
  ): ConnectionIO[Int] =
    sql"""insert into resources (id, tenant_id, resource_type, name, provider, parent_resource_id, external_id, kind, connection_id,
                                  custodian_principal_id)
           values (${UUID.randomUUID().toString}::uuid, ${tenant.toString}::uuid, $resourceType, $externalId, 'google',
                   $parent::uuid, $externalId, $kind, ${connection.toString}::uuid, $custodian::uuid)""".update.run

  private def principalUuid(user: UserId): UUID = UUID.fromString(user.toString)

  private def anotherHuman(tenant: TenantId): IO[UUID] =
    val principal = UUID.randomUUID()
    ownerTx(tenant)(
      sql"insert into principals(id,tenant_id,kind) values ($principal::uuid,${tenant.toString}::uuid,'HUMAN')".update.run *>
        sql"insert into human_identities(tenant_id,principal_id) values (${tenant.toString}::uuid,$principal::uuid)".update.run
    ).as(principal)

  private def accountRoot(tenant: TenantId, connection: ConnectionId, parent: ResourceId, custodian: Option[UUID], external: String): IO[Int] =
    runtimeTx(tenant)(insertResource(tenant, "ACCOUNT", "google.account", connection, UUID.fromString(parent.toString), external, custodian))

  private def accountId(tenant: TenantId): IO[UUID] =
    runtimeTx(tenant)(sql"select id from resources where tenant_id=${tenant.toString}::uuid and kind='google.account'".query[UUID].unique)

  test("V26 registers google.account as a PERSONAL account root and google.drive_file as its DOCUMENT child") {
    requireDocker()
    sql"""select wire, provider, parent_wire, resource_type, custody from resource_kinds
           where provider='google' order by wire"""
      .query[(String, String, Option[String], String, Option[String])]
      .to[Vector]
      .transact(ownerXa)
      .map: kinds =>
        assertEquals(
          kinds,
          Vector(
            ("google.account", "google", None, "ACCOUNT", Some("PERSONAL")),
            ("google.drive_file", "google", Some("google.account"), "DOCUMENT", None),
            ("google.mailbox", "google", Some("google.account"), "CHANNEL", None)
          )
        )
  }

  test("the runtime role inserts an account root custodied by the connection's owner, and a file under it with the same custodian") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      owner = principalUuid(ids.administratorPrincipal)
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "GOOGLE")
      rootRows <- accountRoot(ids.tenant, connection, ids.google.resource, Some(owner), "sub-1")
      rootId <- accountId(ids.tenant)
      fileRows <- runtimeTx(ids.tenant)(insertResource(ids.tenant, "DOCUMENT", "google.drive_file", connection, rootId, "file-aaaaaaaaaa", Some(owner)))
    yield assertEquals((rootRows, fileRows), (1, 1))
  }

  test("an account root without a custodian is refused") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "GOOGLE")
      _ <- refused(
        accountRoot(ids.tenant, connection, ids.google.resource, None, "sub-2"),
        "a personal root's custodian is the human who owns the connection"
      )
    yield ()
  }

  test("an account root custodied by another principal is refused") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      other <- anotherHuman(ids.tenant)
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "GOOGLE")
      _ <- refused(
        accountRoot(ids.tenant, connection, ids.google.resource, Some(other), "sub-3"),
        "a personal root's custodian is the human who owns the connection"
      )
    yield ()
  }

  test("a Drive file under the account refuses a different custodian") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      owner = principalUuid(ids.administratorPrincipal)
      other <- anotherHuman(ids.tenant)
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "GOOGLE")
      _ <- accountRoot(ids.tenant, connection, ids.google.resource, Some(owner), "sub-4")
      rootId <- accountId(ids.tenant)
      _ <- refused(
        runtimeTx(ids.tenant)(insertResource(ids.tenant, "DOCUMENT", "google.drive_file", connection, rootId, "file-bbbbbbbbbb", Some(other))),
        "a selected resource inherits its parent's custody"
      )
    yield ()
  }

  test("a Drive file directly under the Google catalog resource is refused") {
    requireDocker()
    for
      provisioned <- provision()
      (ids, _) = provisioned
      owner = principalUuid(ids.administratorPrincipal)
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "GOOGLE")
      _ <- refused(
        runtimeTx(ids.tenant)(
          insertResource(ids.tenant, "DOCUMENT", "google.drive_file", connection, UUID.fromString(ids.google.resource.toString), "file-cccccccccc", Some(owner))
        ),
        "a selected resource must be under its registered parent kind in the same connection"
      )
    yield ()
  }

  test("a Drive file round-trips through scope loading as ResourceType.Document with the owner as custodian") {
    requireDocker()
    val resources = PostgresConnectionResources(runtimeXa)
    val catalog = PostgresControlPlane(runtimeXa)
    for
      provisioned <- provision()
      (ids, human) = provisioned
      connection <- activeConnection(ids.tenant, ids.administratorPrincipal, "GOOGLE")
      root <- okOrFail(resources.createRoot(ids.tenant, connection, account, ext("sub-rt"), "Alex", Some(ids.administratorPrincipal)))
      selected <- okOrFail(resources.select(ids.tenant, connection, driveFile, ext("file-roundtrip1"), "Plan.txt", root.id, human, now))
      scope <- catalog.selectedScope(ids.tenant, driveFile, ext("file-roundtrip1"))
    yield
      val found = scope.getOrElse(fail("the selected file has no scope"))
      assertEquals(found.target.resourceType, ResourceType.Document)
      assertEquals(found.target.id, selected.id)
      assertEquals(found.custodian, Some(human))
  }
