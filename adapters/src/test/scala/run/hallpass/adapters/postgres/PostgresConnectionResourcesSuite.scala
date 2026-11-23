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
import org.typelevel.doobie.implicits.javatimedrivernative.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.adapters.slack.Slack
import run.hallpass.application.*
import run.hallpass.kernel.*

/** Runtime resource hierarchy over V17: the insert trigger, selections, and the selection-aware
  * catalog.
  *
  * The schema is migrated by a separate owner role and served to the application as a non-owner runtime role in
  * external mode, because in-process mode makes the runtime role the owner and the owner-only rule for catalog rows
  * could not be observed. Everything the application does runs as the runtime role. The owner only provisions tenants,
  * provider catalog resources, connections, and principals, which the runtime role cannot (or need not) create.
  *
  * The resource kinds below are test-only and registered globally once, as the owner. */
final class PostgresConnectionResourcesSuite extends CatsEffectSuite:
  private var container: PostgreSQLContainer[?] = uninitialized
  private var dockerAvailable = false
  private var ownerXa: Transactor[IO] = uninitialized
  private var runtimeXa: Transactor[IO] = uninitialized
  private var releaseTransactors: IO[Unit] = IO.unit
  private val Owner = "authai_owner"
  private val App = "authai_app"
  private val Password = "test-password"
  private val runtimeRole = RuntimeRole.parse(App).toOption.get

  // ---- test-only resource kinds -------------------------------------------------------------------------------------

  private sealed trait TAccount
  private sealed trait TItem
  private sealed trait TPart
  private sealed trait TMailbox
  private sealed trait TMail
  private sealed trait TOther
  private val provider = ProviderId.parse("test").getOrElse(fail("provider"))
  private val account: ResourceKind[TAccount] =
    ResourceKind.root[TAccount]("test.account", provider, ResourceType.Account, Custody.Workspace)
  private val item: ResourceKind[TItem] = ResourceKind.child[TItem, TAccount]("test.item", ResourceType.Repository)(using account)
  private val part: ResourceKind[TPart] = ResourceKind.child[TPart, TItem]("test.part", ResourceType.Document)(using item)
  private val mailbox: ResourceKind[TMailbox] =
    ResourceKind.root[TMailbox]("test.mailbox", provider, ResourceType.Account, Custody.Personal)
  private val mail: ResourceKind[TMail] = ResourceKind.child[TMail, TMailbox]("test.mail", ResourceType.Document)(using mailbox)
  private val other: ResourceKind[TOther] = ResourceKind.root[TOther](
    "other.thing",
    ProviderId.parse("other").getOrElse(fail("provider")),
    ResourceType.Account,
    Custody.Workspace
  )

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
        _ <- registerKinds(owner._1)
      yield (owner, runtime)
      val ((owner, releaseOwner), ((runtime, _), releaseRuntime)) = setup.unsafeRunSync()
      ownerXa = owner
      runtimeXa = runtime
      releaseTransactors = releaseRuntime *> releaseOwner

  override def afterAll(): Unit =
    if dockerAvailable then
      releaseTransactors.unsafeRunSync()
      container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  private def config(user: String): DatabaseConfig =
    DatabaseConfig
      .fromEnvironment(
        Map("HALLPASS_DB_URL" -> container.getJdbcUrl, "HALLPASS_DB_USER" -> user, "HALLPASS_DB_PASSWORD" -> Password)
      )
      .toOption
      .get

  private def registerKinds(xa: Transactor[IO]): IO[Unit] =
    val kinds = Vector(
      ("test.account", "test", None, "ACCOUNT", Some("WORKSPACE")),
      ("test.item", "test", Some("test.account"), "REPOSITORY", None),
      ("test.part", "test", Some("test.item"), "DOCUMENT", None),
      ("test.mailbox", "test", None, "ACCOUNT", Some("PERSONAL")),
      ("test.mail", "test", Some("test.mailbox"), "DOCUMENT", None),
      ("other.thing", "other", None, "ACCOUNT", Some("WORKSPACE"))
    )
    kinds.traverse_ : (wire, providerName, parent, resourceType, custody) =>
      sql"""insert into resource_kinds (wire, provider, parent_wire, resource_type, custody)
             values ($wire, $providerName, $parent, $resourceType, $custody)""".update.run.transact(xa).void

  // ---- fixtures and helpers -----------------------------------------------------------------------------------------

  /** A freshly provisioned tenant, with a `test` provider catalog resource, a second human, and an agent principal. */
  private final case class Fixture(
      ids: ProvisioningIds,
      testCatalog: ResourceId,
      otherHuman: UserId,
      agent: AgentId
  ):
    def tenant: TenantId = ids.tenant
    def admin: UserId = ids.administratorPrincipal
    def slackCatalog: ResourceId = ids.slackResource

  private def ownerTx[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(ownerXa)

  private def runtimeTx[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(runtimeXa)

  private def fixture(): IO[Fixture] =
    val ids = ProvisioningIds.random()
    val subject = UUID.randomUUID().toString
    val request = TenantProvisioningRequest
      .from("Connection resources", s"cr-${subject.take(8)}", ExternalIdentity.from("https://idp.example.com", subject).toOption.get)
      .toOption
      .get
    val built = Fixture(ids, ResourceId.random(), UserId.random(), AgentId.random())
    for
      _ <- TenantProvisioning.program(request, ids).transact(ownerXa)
      _ <- ownerTx(built.tenant):
        for
          _ <- sql"insert into principals (id, tenant_id, kind) values (${built.otherHuman.toString}::uuid, ${built.tenant.toString}::uuid, 'HUMAN')".update.run
          _ <- sql"insert into principals (id, tenant_id, kind) values (${built.agent.toString}::uuid, ${built.tenant.toString}::uuid, 'AGENT')".update.run
          _ <- sql"""insert into resources (id, tenant_id, resource_type, name, provider, external_id)
                     values (${built.testCatalog.toString}::uuid, ${built.tenant.toString}::uuid, 'PROVIDER', 'Test catalog', 'test', 'test-catalog')""".update.run
        yield ()
    yield built

  private def connection(
      f: Fixture,
      owner: Option[String],
      providerName: String = "TEST",
      status: String = "ACTIVE"
  ): IO[ConnectionId] =
    val id = ConnectionId.random()
    ownerTx(f.tenant):
      sql"""insert into connections (id, tenant_id, provider, status, owner_principal_id)
             values (${id.toString}::uuid, ${f.tenant.toString}::uuid, $providerName, $status, $owner::uuid)""".update.run.as(id)

  private def ext(value: String): ExternalId = ExternalId.parse(value).getOrElse(fail(s"external id $value"))

  private val t0 = Instant.parse("2026-01-01T00:00:00Z")
  private val t1 = t0.plusSeconds(60)
  private val t2 = t0.plusSeconds(120)
  private val t3 = t0.plusSeconds(180)

  private def repository = PostgresConnectionResources(runtimeXa)
  private def catalog = PostgresControlPlane(runtimeXa)

  private def ok[A](result: IO[Either[ConnectionResourceError, A]]): IO[A] =
    result.flatMap:
      case Right(value) => IO.pure(value)
      case Left(error)  => IO.raiseError(AssertionError(s"expected success, received $error"))

  /** Runtime inserts a connection-scoped resource row directly, to exercise the trigger rather than the repository. */
  private def insertResource(
      tenant: TenantId,
      id: UUID,
      resourceType: String,
      kind: Option[String],
      connection: Option[ConnectionId],
      parent: Option[ResourceId],
      custodian: Option[String],
      externalId: String,
      connectionRoot: Boolean = false,
      providerName: String = "test"
  ): ConnectionIO[Int] =
    sql"""insert into resources (id, tenant_id, resource_type, name, provider, parent_resource_id, external_id,
                                  kind, connection_id, custodian_principal_id, connection_root)
           values (${id.toString}::uuid, ${tenant.toString}::uuid, $resourceType, $externalId, $providerName,
                   ${parent.map(_.toString)}::uuid, $externalId, $kind, ${connection.map(_.toString)}::uuid,
                   $custodian::uuid, $connectionRoot)""".update.run

  private def asRuntime(f: Fixture)(
      resourceType: String,
      kind: Option[String],
      connection: Option[ConnectionId],
      parent: Option[ResourceId],
      custodian: Option[String],
      externalId: String = "ext"
  ): IO[Int] =
    runtimeTx(f.tenant)(
      insertResource(f.tenant, UUID.randomUUID(), resourceType, kind, connection, parent, custodian, externalId)
    )

  private def refused[A](attempt: IO[A], sqlState: String, fragment: String): IO[Unit] =
    attempt.attempt.map:
      case Right(value) => fail(s"expected a refusal containing '$fragment' but the statement succeeded: $value")
      case Left(failure: PSQLException) =>
        assertEquals(failure.getSQLState, sqlState, failure.getMessage)
        assert(failure.getMessage.contains(fragment), s"expected '$fragment' in: ${failure.getMessage}")
      case Left(failure) => throw failure

  private def count(tenant: TenantId, query: Fragment): IO[Int] =
    runtimeTx(tenant)(query.query[Int].unique)

  private def openRoot(f: Fixture, kind: ResourceKind[?], connection: ConnectionId, externalId: String): IO[ConnectionResource] =
    val custodian = Option.when(kind.custody == Custody.Personal)(f.admin)
    ok(repository.createRoot(f.tenant, connection, kind, ext(externalId), s"Root $externalId", custodian))

  private def human(id: UserId): Principal.Human = Principal.Human(id)

  // ---- insert trigger: what the runtime role may create -------------------------------------------------------------

  test("the runtime role cannot insert a catalog resource, which only the owner provisions") {
    requireDocker()
    for
      f <- fixture()
      _ <- refused(
        runtimeTx(f.tenant)(
          insertResource(f.tenant, UUID.randomUUID(), "PROVIDER", None, None, None, None, "rogue-catalog")
        ),
        "42501",
        "catalog resources are provisioned by the owner"
      )
      // A catalog resource with a custodian is not a thing at all.
      _ <- refused(
        runtimeTx(f.tenant)(
          insertResource(f.tenant, UUID.randomUUID(), "PROVIDER", None, None, None, Some(f.admin.toString), "rogue-custody")
        ),
        "23514",
        "a catalog resource has no custodian"
      )
      owned <- count(f.tenant, sql"select count(*) from resources where tenant_id=${f.tenant.toString}::uuid and kind is null and external_id like 'rogue%'")
    yield assertEquals(owned, 0)
  }

  test("resource type must be the registered kind's, and PROVIDER, TOOL, or an unregistered kind is refused") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      _ <- List("PROVIDER", "TOOL", "REPOSITORY", "CHANNEL").traverse_ : resourceType =>
        refused(
          asRuntime(f)(resourceType, Some("test.account"), Some(c), Some(f.testCatalog), None),
          "23514",
          "resource type does not match its registered kind"
        )
      _ <- refused(
        asRuntime(f)("ACCOUNT", Some("test.unregistered"), Some(c), Some(f.testCatalog), None),
        "23514",
        "resource type does not match its registered kind"
      )
      accepted <- asRuntime(f)("ACCOUNT", Some("test.account"), Some(c), Some(f.testCatalog), None, "good")
    yield assertEquals(accepted, 1)
  }

  test("resources are added only under an existing, active connection") {
    requireDocker()
    for
      f <- fixture()
      disabled <- connection(f, Some(f.admin.toString), status = "DISABLED")
      failed <- connection(f, Some(f.admin.toString), status = "ERROR")
      connecting <- connection(f, Some(f.admin.toString), status = "CONNECTING")
      _ <- List(disabled, failed, connecting, ConnectionId.random()).traverse_ : c =>
        refused(
          asRuntime(f)("ACCOUNT", Some("test.account"), Some(c), Some(f.testCatalog), None),
          "23514",
          "resources are added only under an active connection"
        )
    yield ()
  }

  test("a kind registered for another provider is refused on this connection") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      _ <- refused(
        asRuntime(f)("ACCOUNT", Some("other.thing"), Some(c), Some(f.testCatalog), None),
        "23514",
        "resource kind is not registered for the connection's provider"
      )
      // The provider name compares case-insensitively: 'TEST' and 'test' are the same provider.
      lower <- connection(f, Some(f.admin.toString), providerName = "test")
      accepted <- asRuntime(f)("ACCOUNT", Some("test.account"), Some(lower), Some(f.testCatalog), None)
    yield assertEquals(accepted, 1)
  }

  test("a connection root must sit directly under its provider's catalog resource, once per connection") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      c2 <- connection(f, Some(f.admin.toString))
      fragment = "a connection root must be under its provider's catalog resource"
      // Another provider's catalog resource, no parent, and a non-catalog parent are all refused.
      _ <- refused(asRuntime(f)("ACCOUNT", Some("test.account"), Some(c), Some(f.slackCatalog), None), "23514", fragment)
      _ <- refused(asRuntime(f)("ACCOUNT", Some("test.account"), Some(c), None, None), "23514", fragment)
      _ <- refused(asRuntime(f)("ACCOUNT", Some("test.account"), Some(c), Some(ResourceId.random()), None), "23514", fragment)
      root2 <- openRoot(f, account, c2, "acct-2")
      _ <- refused(asRuntime(f)("ACCOUNT", Some("test.account"), Some(c), Some(root2.id), None), "23514", fragment)
      first <- asRuntime(f)("ACCOUNT", Some("test.account"), Some(c), Some(f.testCatalog), None, "acct-1")
      _ <- refused(
        asRuntime(f)("ACCOUNT", Some("test.account"), Some(c), Some(f.testCatalog), None, "acct-1b"),
        "23505",
        "resources_one_root_per_connection_idx"
      )
    yield assertEquals(first, 1)
  }

  test("a workspace root has no custodian, and a personal root's custodian is exactly the owning human") {
    requireDocker()
    for
      f <- fixture()
      owned <- connection(f, Some(f.admin.toString))
      agentOwned <- connection(f, Some(f.agent.toString))
      unowned <- connection(f, None)
      _ <- refused(
        asRuntime(f)("ACCOUNT", Some("test.account"), Some(owned), Some(f.testCatalog), Some(f.admin.toString)),
        "23514",
        "a workspace root has no custodian"
      )
      personal = "a personal root's custodian is the human who owns the connection"
      // Not the connection owner.
      _ <- refused(asRuntime(f)("ACCOUNT", Some("test.mailbox"), Some(owned), Some(f.testCatalog), Some(f.otherHuman.toString)), "23514", personal)
      // No custodian.
      _ <- refused(asRuntime(f)("ACCOUNT", Some("test.mailbox"), Some(owned), Some(f.testCatalog), None), "23514", personal)
      // An agent is not a human, even when it owns the connection and is named custodian.
      _ <- refused(asRuntime(f)("ACCOUNT", Some("test.mailbox"), Some(agentOwned), Some(f.testCatalog), Some(f.agent.toString)), "23514", personal)
      // A connection with no owner has no human to be custodian.
      _ <- refused(asRuntime(f)("ACCOUNT", Some("test.mailbox"), Some(unowned), Some(f.testCatalog), Some(f.admin.toString)), "23514", personal)
      accepted <- asRuntime(f)("ACCOUNT", Some("test.mailbox"), Some(owned), Some(f.testCatalog), Some(f.admin.toString), "box")
      stored <- runtimeTx(f.tenant)(
        sql"select custodian_principal_id::text from resources where tenant_id=${f.tenant.toString}::uuid and external_id='box'"
          .query[String]
          .unique
      )
    yield
      assertEquals(accepted, 1)
      assertEquals(stored, f.admin.toString)
  }

  test("a child sits under its registered parent kind in the same connection and inherits custody exactly") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      c2 <- connection(f, Some(f.admin.toString))
      root <- openRoot(f, account, c, "acct")
      root2 <- openRoot(f, account, c2, "acct-other")
      cBox <- connection(f, Some(f.admin.toString))
      box <- openRoot(f, mailbox, cBox, "box")
      placement = "a selected resource must be under its registered parent kind in the same connection"
      // A part belongs under an item, not directly under the account root.
      _ <- refused(asRuntime(f)("DOCUMENT", Some("test.part"), Some(c), Some(root.id), None), "23514", placement)
      // The right parent kind in another connection.
      _ <- refused(asRuntime(f)("REPOSITORY", Some("test.item"), Some(c), Some(root2.id), None), "23514", placement)
      // A parent that does not exist, and the catalog resource as parent.
      _ <- refused(asRuntime(f)("REPOSITORY", Some("test.item"), Some(c), Some(ResourceId.random()), None), "23514", placement)
      _ <- refused(asRuntime(f)("REPOSITORY", Some("test.item"), Some(c), Some(f.testCatalog), None), "23514", placement)
      inherits = "a selected resource inherits its parent's custody"
      // A workspace child may not claim a custodian.
      _ <- refused(asRuntime(f)("REPOSITORY", Some("test.item"), Some(c), Some(root.id), Some(f.admin.toString)), "23514", inherits)
      // A personal child must carry exactly its parent's custodian: none and another human are both refused.
      _ <- refused(asRuntime(f)("DOCUMENT", Some("test.mail"), Some(box.connection), Some(box.id), None), "23514", inherits)
      _ <- refused(asRuntime(f)("DOCUMENT", Some("test.mail"), Some(box.connection), Some(box.id), Some(f.otherHuman.toString)), "23514", inherits)
      fine <- asRuntime(f)("DOCUMENT", Some("test.mail"), Some(box.connection), Some(box.id), Some(f.admin.toString), "mail-1")
      child <- asRuntime(f)("REPOSITORY", Some("test.item"), Some(c), Some(root.id), None, "item-1")
    yield
      assertEquals(fine, 1)
      assertEquals(child, 1)
  }

  test("connection_root is set by the trigger: a forged flag on a child is cleared, and a root gets it") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      root <- openRoot(f, account, c, "acct")
      childId = UUID.randomUUID()
      _ <- runtimeTx(f.tenant)(
        insertResource(f.tenant, childId, "REPOSITORY", Some("test.item"), Some(c), Some(root.id), None, "forged", connectionRoot = true)
      )
      c2 <- connection(f, Some(f.admin.toString))
      second = UUID.randomUUID()
      _ <- runtimeTx(f.tenant)(
        insertResource(f.tenant, second, "ACCOUNT", Some("test.account"), Some(c2), Some(f.testCatalog), None, "unflagged", connectionRoot = false)
      )
      flags <- runtimeTx(f.tenant)(
        sql"select external_id, connection_root from resources where tenant_id=${f.tenant.toString}::uuid and external_id in ('forged','unflagged','acct') order by external_id"
          .query[(String, Boolean)]
          .to[Vector]
      )
    yield assertEquals(flags, Vector("acct" -> true, "forged" -> false, "unflagged" -> true))
  }

  // ---- selections ---------------------------------------------------------------------------------------------------

  test("select, deselect, and reselect keep one resource row and a selection history") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      root <- openRoot(f, account, c, "acct")
      first <- ok(repository.select(f.tenant, c, item, ext("repo-1"), "Repo 1", root.id, human(f.admin), t1))
      listed <- repository.listFor(f.tenant, c)
      closed <- repository.deselect(f.tenant, first.id, t2)
      afterClose <- repository.listFor(f.tenant, c)
      closedAgain <- repository.deselect(f.tenant, first.id, t3)
      again <- ok(repository.select(f.tenant, c, item, ext("repo-1"), "Repo 1 renamed", root.id, human(f.admin), t3))
      afterReselect <- repository.listFor(f.tenant, c)
      rows <- count(f.tenant, sql"select count(*) from resources where tenant_id=${f.tenant.toString}::uuid and external_id='repo-1'")
      history <- runtimeTx(f.tenant)(
        sql"select selected_at, deselected_at from connection_resources where tenant_id=${f.tenant.toString}::uuid and resource_id=${first.id.toString}::uuid order by selected_at"
          .query[(Instant, Option[Instant])]
          .to[Vector]
      )
    yield
      assertEquals(first.selectedAt, Some(t1))
      assertEquals(first.parent, root.id)
      assertEquals(first.kind, "test.item")
      assertEquals(first.custodian, None)
      assertEquals(listed.map(_.id), Vector(root.id, first.id))
      assertEquals(listed.map(_.selectedAt), Vector(None, Some(t1)))
      assertEquals(closed, Right(()))
      assertEquals(afterClose.map(_.id), Vector(root.id))
      assertEquals(closedAgain, Left(ConnectionResourceError.NotFound))
      // The resource row is reused, with its original name, and the history keeps both selections.
      assertEquals(again.id, first.id)
      assertEquals(again.displayName, "Repo 1")
      assertEquals(afterReselect.map(_.id), Vector(root.id, first.id))
      assertEquals(rows, 1)
      assertEquals(history, Vector(t1 -> Some(t2), t3 -> None))
  }

  test("a resource already open is AlreadySelected, in this connection and in a second connection") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      c2 <- connection(f, Some(f.admin.toString))
      root <- openRoot(f, account, c, "acct")
      root2 <- openRoot(f, account, c2, "acct-2")
      _ <- ok(repository.select(f.tenant, c, item, ext("shared-repo"), "Shared", root.id, human(f.admin), t1))
      duplicate <- repository.select(f.tenant, c, item, ext("shared-repo"), "Shared", root.id, human(f.admin), t2)
      elsewhere <- repository.select(f.tenant, c2, item, ext("shared-repo"), "Shared", root2.id, human(f.admin), t2)
      leaked <- count(f.tenant, sql"select count(*) from resources where tenant_id=${f.tenant.toString}::uuid and connection_id=${c2.toString}::uuid and kind='test.item'")
      listed2 <- repository.listFor(f.tenant, c2)
    yield
      assertEquals(duplicate, Left(ConnectionResourceError.AlreadySelected))
      assertEquals(elsewhere, Left(ConnectionResourceError.AlreadySelected))
      // The refused selection rolled back its own resource row.
      assertEquals(leaked, 0)
      assertEquals(listed2.map(_.id), Vector(root2.id))
  }

  test("once the first connection releases it, a second connection can select the same external resource") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      c2 <- connection(f, Some(f.admin.toString))
      root <- openRoot(f, account, c, "acct")
      root2 <- openRoot(f, account, c2, "acct-2")
      first <- ok(repository.select(f.tenant, c, item, ext("moving"), "Moving", root.id, human(f.admin), t1))
      _ <- ok(repository.deselect(f.tenant, first.id, t2))
      second <- ok(repository.select(f.tenant, c2, item, ext("moving"), "Moving", root2.id, human(f.admin), t3))
      scope <- catalog.selectedScope(f.tenant, item, ext("moving"))
    yield
      assertNotEquals(second.id, first.id)
      // Only the open one is addressable, so the external ID resolves to the second connection's row.
      assertEquals(scope.map(_.target.id), Some(second.id))
  }

  test("deselection is one-way: a second close or a reopen is refused by the trigger") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      root <- openRoot(f, account, c, "acct")
      chosen <- ok(repository.select(f.tenant, c, item, ext("repo"), "Repo", root.id, human(f.admin), t1))
      _ <- ok(repository.deselect(f.tenant, chosen.id, t2))
      closeAgain = sql"update connection_resources set deselected_at=${t3} where tenant_id=${f.tenant.toString}::uuid and resource_id=${chosen.id.toString}::uuid".update.run
      reopen = sql"update connection_resources set deselected_at=null where tenant_id=${f.tenant.toString}::uuid and resource_id=${chosen.id.toString}::uuid".update.run
      _ <- refused(runtimeTx(f.tenant)(closeAgain), "23514", "a selection can only be closed, once")
      _ <- refused(runtimeTx(f.tenant)(reopen), "23514", "a selection can only be closed, once")
      still <- count(f.tenant, sql"select count(*) from connection_resources where tenant_id=${f.tenant.toString}::uuid and resource_id=${chosen.id.toString}::uuid and deselected_at=$t2")
      // An open selection cannot be closed before it was opened.
      open <- ok(repository.select(f.tenant, c, item, ext("repo"), "Repo", root.id, human(f.admin), t3))
      early <- repository.deselect(f.tenant, open.id, t0)
      stillOpen <- count(f.tenant, sql"select count(*) from connection_resources where tenant_id=${f.tenant.toString}::uuid and resource_id=${open.id.toString}::uuid and deselected_at is null")
    yield
      assertEquals(still, 1)
      // The table's own check refuses it; the repository reports an unexplained failure, never a success.
      assertEquals(early, Left(ConnectionResourceError.PersistenceFailure))
      assertEquals(stillOpen, 1)
  }

  test("the runtime role can update only deselected_at on a selection, and delete nothing") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      root <- openRoot(f, account, c, "acct")
      chosen <- ok(repository.select(f.tenant, c, item, ext("repo"), "Repo", root.id, human(f.admin), t1))
      where = fr"where tenant_id=${f.tenant.toString}::uuid and resource_id=${chosen.id.toString}::uuid"
      _ <- refused(runtimeTx(f.tenant)((fr"update connection_resources set selected_by=${f.otherHuman.toString}::uuid" ++ where).update.run), "42501", "permission denied")
      _ <- refused(runtimeTx(f.tenant)((fr"update connection_resources set external_id='other'" ++ where).update.run), "42501", "permission denied")
      _ <- refused(runtimeTx(f.tenant)((fr"update connection_resources set selected_at=$t3" ++ where).update.run), "42501", "permission denied")
      _ <- refused(runtimeTx(f.tenant)((fr"delete from connection_resources" ++ where).update.run), "42501", "permission denied")
      // Resources are insert-only too.
      _ <- refused(runtimeTx(f.tenant)(sql"update resources set name='renamed' where tenant_id=${f.tenant.toString}::uuid and id=${chosen.id.toString}::uuid".update.run), "42501", "permission denied")
      _ <- refused(runtimeTx(f.tenant)(sql"delete from resources where tenant_id=${f.tenant.toString}::uuid and id=${chosen.id.toString}::uuid".update.run), "42501", "permission denied")
      remaining <- count(f.tenant, sql"select count(*) from connection_resources where tenant_id=${f.tenant.toString}::uuid and resource_id=${chosen.id.toString}::uuid and deselected_at is null")
    yield assertEquals(remaining, 1)
  }

  test("another tenant's context sees and changes nothing, and cannot insert for this tenant") {
    requireDocker()
    for
      a <- fixture()
      b <- fixture()
      c <- connection(a, Some(a.admin.toString))
      root <- openRoot(a, account, c, "acct")
      chosen <- ok(repository.select(a.tenant, c, item, ext("repo"), "Repo", root.id, human(a.admin), t1))
      seenSelections <- count(b.tenant, sql"select count(*) from connection_resources")
      seenResources <- count(b.tenant, sql"select count(*) from resources where kind is not null")
      updated <- runtimeTx(b.tenant)(sql"update connection_resources set deselected_at=$t2".update.run)
      _ <- refused(
        runtimeTx(b.tenant)(
          sql"""insert into connection_resources (tenant_id, connection_id, resource_id, kind, external_id, selected_by, selected_at)
                 values (${a.tenant.toString}::uuid, ${c.toString}::uuid, ${chosen.id.toString}::uuid, 'test.item', 'repo',
                         ${a.admin.toString}::uuid, $t3)""".update.run
        ),
        "42501",
        "row-level security"
      )
      crossResource <- runtimeTx(b.tenant)(
        insertResource(a.tenant, UUID.randomUUID(), "REPOSITORY", Some("test.item"), Some(c), Some(root.id), None, "intruder")
      ).attempt
      deselected <- repository.deselect(b.tenant, chosen.id, t2)
      listedByB <- repository.listFor(b.tenant, c)
      stillOpen <- count(a.tenant, sql"select count(*) from connection_resources where deselected_at is null")
      intruders <- count(a.tenant, sql"select count(*) from resources where external_id='intruder'")
    yield
      assertEquals(seenSelections, 0)
      assertEquals(seenResources, 0)
      assertEquals(updated, 0)
      assert(crossResource.isLeft, "a resource row for another tenant must be refused")
      assertEquals(deselected, Left(ConnectionResourceError.NotFound))
      assertEquals(listedByB, Vector.empty)
      assertEquals(stillOpen, 1)
      assertEquals(intruders, 0)
  }

  test("a selection must name a resource of its own connection, kind, and external ID") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      c2 <- connection(f, Some(f.admin.toString))
      root <- openRoot(f, account, c, "acct")
      _ <- openRoot(f, account, c2, "acct-2")
      chosen <- ok(repository.select(f.tenant, c, item, ext("repo"), "Repo", root.id, human(f.admin), t1))
      _ <- ok(repository.deselect(f.tenant, chosen.id, t2))
      insertSelection = (connection: ConnectionId, kind: String, externalId: String) =>
        sql"""insert into connection_resources (tenant_id, connection_id, resource_id, kind, external_id, selected_by, selected_at)
               values (${f.tenant.toString}::uuid, ${connection.toString}::uuid, ${chosen.id.toString}::uuid, $kind, $externalId,
                       ${f.admin.toString}::uuid, $t3)""".update.run
      _ <- refused(runtimeTx(f.tenant)(insertSelection(c2, "test.item", "repo")), "23503", "violates foreign key constraint")
      _ <- refused(runtimeTx(f.tenant)(insertSelection(c, "test.part", "repo")), "23503", "violates foreign key constraint")
      _ <- refused(runtimeTx(f.tenant)(insertSelection(c, "test.item", "different")), "23503", "violates foreign key constraint")
    yield ()
  }

  // ---- repository error mapping -------------------------------------------------------------------------------------

  test("the repository maps the trigger's refusals to explicit errors") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      disabled <- connection(f, Some(f.admin.toString), status = "DISABLED")
      root <- openRoot(f, account, c, "acct")
      cWorkspace <- connection(f, Some(f.admin.toString))
      cPersonalOther <- connection(f, Some(f.admin.toString))
      cPersonalNone <- connection(f, Some(f.admin.toString))
      cChild <- connection(f, Some(f.admin.toString))
      repo = repository
      inactive <- repo.createRoot(f.tenant, disabled, account, ext("acct-d"), "Disabled", None)
      foreignKind <- repo.createRoot(f.tenant, c, other, ext("thing"), "Other", None)
      secondRoot <- repo.createRoot(f.tenant, c, account, ext("acct-2"), "Second", None)
      workspaceCustody <- repo.createRoot(f.tenant, cWorkspace, account, ext("acct-c"), "Custody", Some(f.admin))
      personalOther <- repo.createRoot(f.tenant, cPersonalOther, mailbox, ext("box-o"), "Box", Some(f.otherHuman))
      personalNone <- repo.createRoot(f.tenant, cPersonalNone, mailbox, ext("box-n"), "Box", None)
      childAsRoot <- repo.createRoot(f.tenant, cChild, item, ext("item-r"), "Item", None)
      rootAsChild <- repo.select(f.tenant, c, account, ext("acct-x"), "Account", root.id, human(f.admin), t1)
      wrongParent <- repo.select(f.tenant, c, part, ext("part"), "Part", root.id, human(f.admin), t1)
      missingParent <- repo.select(f.tenant, c, item, ext("repo"), "Repo", ResourceId.random(), human(f.admin), t1)
      selected <- ok(repo.select(f.tenant, c, item, ext("repo"), "Repo", root.id, human(f.admin), t1))
      _ <- ok(repo.deselect(f.tenant, selected.id, t2))
      // The row exists and its connection is later disabled: a reselect is still refused, not silently reopened.
      _ <- ownerTx(f.tenant)(sql"update connections set status='DISABLED' where tenant_id=${f.tenant.toString}::uuid and id=${c.toString}::uuid".update.run)
      reselect <- repo.select(f.tenant, c, item, ext("repo"), "Repo", root.id, human(f.admin), t3)
      unknownDeselect <- repo.deselect(f.tenant, ResourceId.random(), t3)
    yield
      assertEquals(inactive.map(_ => ()), Left(ConnectionResourceError.ConnectionUnavailable))
      assertEquals(foreignKind.map(_ => ()), Left(ConnectionResourceError.ConnectionUnavailable))
      assertEquals(secondRoot.map(_ => ()), Left(ConnectionResourceError.AlreadySelected))
      assertEquals(workspaceCustody.map(_ => ()), Left(ConnectionResourceError.InvalidCustody))
      assertEquals(personalOther.map(_ => ()), Left(ConnectionResourceError.InvalidCustody))
      assertEquals(personalNone.map(_ => ()), Left(ConnectionResourceError.InvalidCustody))
      assertEquals(childAsRoot.map(_ => ()), Left(ConnectionResourceError.InvalidPlacement))
      assertEquals(rootAsChild.map(_ => ()), Left(ConnectionResourceError.InvalidPlacement))
      assertEquals(wrongParent.map(_ => ()), Left(ConnectionResourceError.InvalidPlacement))
      assertEquals(missingParent.map(_ => ()), Left(ConnectionResourceError.InvalidPlacement))
      assertEquals(reselect.map(_ => ()), Left(ConnectionResourceError.ConnectionUnavailable))
      assertEquals(unknownDeselect, Left(ConnectionResourceError.NotFound))
  }

  test("a root for a provider with no catalog resource in the tenant has no place") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString), providerName = "OTHER")
      result <- repository.createRoot(f.tenant, c, other, ext("thing"), "Other", None)
    yield assertEquals(result.map(_ => ()), Left(ConnectionResourceError.InvalidPlacement))
  }

  test("a personal root and its children carry the owner as custodian") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      box <- ok(repository.createRoot(f.tenant, c, mailbox, ext("box"), "Mailbox", Some(f.admin)))
      message <- ok(repository.select(f.tenant, c, mail, ext("m-1"), "Message", box.id, human(f.admin), t1))
      listed <- repository.listFor(f.tenant, c)
    yield
      assertEquals(box.custodian, Some(f.admin))
      assertEquals(message.custodian, Some(f.admin))
      assertEquals(listed.map(_.custodian), Vector(Some(f.admin), Some(f.admin)))
  }

  // ---- selection-aware catalog --------------------------------------------------------------------------------------

  test("rootScope prefers a connection root to the catalog fallback, and falls back without one") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      before <- catalog.rootScope(f.tenant, account)
      root <- openRoot(f, account, c, "acct")
      after <- catalog.rootScope(f.tenant, account)
    yield
      assertEquals(before.map(_._1), Some(ext("test-catalog")))
      assertEquals(before.map(_._2.path.map(_.id)), Some(Vector(f.testCatalog)))
      assertEquals(after.map(_._1), Some(ext("acct")))
      assertEquals(after.map(_._2.path.map(_.id)), Some(Vector(root.id, f.testCatalog)))
      assertEquals(after.map(_._2.target.resourceType), Some(ResourceType.Account))
      assertEquals(after.flatMap(_._2.custodian), None)
  }

  test("rootScope is None with two active roots, ignores a disabled connection's root, and never falls back once roots exist") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      c2 <- connection(f, Some(f.admin.toString))
      first <- openRoot(f, account, c, "acct-1")
      _ <- openRoot(f, account, c2, "acct-2")
      two <- catalog.rootScope(f.tenant, account)
      _ <- runtimeTx(f.tenant)(sql"update connections set status='DISABLED' where tenant_id=${f.tenant.toString}::uuid and id=${c2.toString}::uuid".update.run)
      one <- catalog.rootScope(f.tenant, account)
      _ <- runtimeTx(f.tenant)(sql"update connections set status='DISABLED' where tenant_id=${f.tenant.toString}::uuid and id=${c.toString}::uuid".update.run)
      none <- catalog.rootScope(f.tenant, account)
    yield
      assertEquals(two, None)
      assertEquals(one.map(_._2.target.id), Some(first.id))
      // A kind whose roots are all disconnected resolves to nothing: disconnection behaves like revocation. Only a kind
      // that has never had a root falls back to the catalog resource.
      assertEquals(none, None)
  }

  test("a personal kind with no root never falls back to the catalog resource") {
    requireDocker()
    for
      f <- fixture()
      scope <- catalog.rootScope(f.tenant, mailbox)
    yield assertEquals(scope, None)
  }

  test("rootScope of a personal root carries the owner as custodian") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      box <- openRoot(f, mailbox, c, "box")
      scope <- catalog.rootScope(f.tenant, mailbox)
    yield
      assertEquals(scope.map(_._2.target.id), Some(box.id))
      assertEquals(scope.flatMap(_._2.custodian), Some(Principal.Human(f.admin)))
  }

  test("selectedScope and currentScope return the path while selected, and None after deselection") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      root <- openRoot(f, account, c, "acct")
      unselected <- catalog.selectedScope(f.tenant, item, ext("repo"))
      chosen <- ok(repository.select(f.tenant, c, item, ext("repo"), "Repo", root.id, human(f.admin), t1))
      bySelected <- catalog.selectedScope(f.tenant, item, ext("repo"))
      byCurrent <- catalog.currentScope(f.tenant, chosen.id)
      wrongKind <- catalog.selectedScope(f.tenant, part, ext("repo"))
      rootByKind <- catalog.selectedScope(f.tenant, account, ext("acct"))
      _ <- ok(repository.deselect(f.tenant, chosen.id, t2))
      afterSelected <- catalog.selectedScope(f.tenant, item, ext("repo"))
      afterCurrent <- catalog.currentScope(f.tenant, chosen.id)
      rootStill <- catalog.currentScope(f.tenant, root.id)
    yield
      val path = Vector(chosen.id, root.id, f.testCatalog)
      assertEquals(unselected, None)
      assertEquals(bySelected.map(_.path.map(_.id)), Some(path))
      assertEquals(byCurrent.map(_.path.map(_.id)), Some(path))
      assertEquals(bySelected.map(_.target.externalId), Some("repo"))
      assertEquals(bySelected.map(_.target.resourceType), Some(ResourceType.Repository))
      assertEquals(wrongKind, None)
      // A root is addressable while its connection is active, with no selection row of its own.
      assertEquals(rootByKind.map(_.target.id), Some(root.id))
      assertEquals(afterSelected, None)
      assertEquals(afterCurrent, None)
      assertEquals(rootStill.map(_.target.id), Some(root.id))
  }

  test("disabling the connection makes every resource under it unaddressable, catalog resources excepted") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      root <- openRoot(f, account, c, "acct")
      chosen <- ok(repository.select(f.tenant, c, item, ext("repo"), "Repo", root.id, human(f.admin), t1))
      before <- catalog.currentScope(f.tenant, chosen.id)
      _ <- runtimeTx(f.tenant)(sql"update connections set status='DISABLED' where tenant_id=${f.tenant.toString}::uuid and id=${c.toString}::uuid".update.run)
      item_ <- catalog.currentScope(f.tenant, chosen.id)
      selectedItem <- catalog.selectedScope(f.tenant, item, ext("repo"))
      rootScope <- catalog.currentScope(f.tenant, root.id)
      rootByKind <- catalog.selectedScope(f.tenant, account, ext("acct"))
      provider <- catalog.currentScope(f.tenant, f.testCatalog)
      slack <- catalog.currentScope(f.tenant, f.slackCatalog)
    yield
      assert(before.nonEmpty)
      assertEquals(item_, None)
      assertEquals(selectedItem, None)
      assertEquals(rootScope, None)
      assertEquals(rootByKind, None)
      assertEquals(provider.map(_.path.map(_.id)), Some(Vector(f.testCatalog)))
      assertEquals(slack.map(_.path.map(_.id)), Some(Vector(f.slackCatalog)))
  }

  test("a closed ancestor selection makes its descendants unaddressable, though their own selections stay open") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      root <- openRoot(f, account, c, "acct")
      repo <- ok(repository.select(f.tenant, c, item, ext("repo"), "Repo", root.id, human(f.admin), t1))
      file <- ok(repository.select(f.tenant, c, part, ext("file"), "File", repo.id, human(f.admin), t1))
      open <- catalog.selectedScope(f.tenant, part, ext("file"))
      _ <- ok(repository.deselect(f.tenant, repo.id, t2))
      byKind <- catalog.selectedScope(f.tenant, part, ext("file"))
      byId <- catalog.currentScope(f.tenant, file.id)
      _ <- ok(repository.select(f.tenant, c, item, ext("repo"), "Repo", root.id, human(f.admin), t3))
      reopened <- catalog.selectedScope(f.tenant, part, ext("file"))
    yield
      assertEquals(open.map(_.path.map(_.id)), Some(Vector(file.id, repo.id, root.id, f.testCatalog)))
      assertEquals(byKind, None)
      assertEquals(byId, None)
      // Selecting the ancestor again restores the path: the descendant's own selection never closed.
      assertEquals(reopened.map(_.target.id), Some(file.id))
  }

  test("a personal child's scope carries the owner as custodian") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      box <- openRoot(f, mailbox, c, "box")
      message <- ok(repository.select(f.tenant, c, mail, ext("m-1"), "Message", box.id, human(f.admin), t1))
      scope <- catalog.selectedScope(f.tenant, mail, ext("m-1"))
    yield
      assertEquals(scope.flatMap(_.custodian), Some(Principal.Human(f.admin)))
      assertEquals(scope.map(_.path.map(_.id)), Some(Vector(message.id, box.id, f.testCatalog)))
  }

  test("a custodian that is not a human makes the scope invalid and unaddressable (fail closed)") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      corrupt = UUID.randomUUID()
      // The insert trigger cannot produce this state, so it is forged by the owner with the trigger off, in one
      // transaction that restores it.
      _ <- ownerTx(f.tenant)(
        for
          _ <- sql"alter table resources disable trigger resources_insert_check".update.run
          _ <- insertResource(f.tenant, corrupt, "ACCOUNT", Some("test.mailbox"), Some(c), Some(f.testCatalog), Some(f.agent.toString), "box", connectionRoot = true)
          _ <- sql"alter table resources enable trigger resources_insert_check".update.run
        yield ()
      )
      current <- catalog.currentScope(f.tenant, ResourceId.parse(corrupt.toString).toOption.get)
      root <- catalog.rootScope(f.tenant, mailbox)
    yield
      assertEquals(current, None)
      assertEquals(root, None)
  }

  test("the existing Slack catalog fallback still resolves and Slack selections stay empty") {
    requireDocker()
    for
      f <- fixture()
      root <- catalog.rootScope(f.tenant, Slack.workspace)
      selected <- catalog.selectedScope(f.tenant, Slack.workspace, ext("slack-workspace"))
      current <- catalog.currentScope(f.tenant, f.slackCatalog)
      unknown <- catalog.currentScope(f.tenant, ResourceId.random())
    yield
      assertEquals(root.map(_._1), Some(ext("slack-workspace")))
      assertEquals(root.map(_._2.path.map(_.id)), Some(Vector(f.slackCatalog)))
      assertEquals(selected, None)
      assertEquals(current.map(_.target.id), Some(f.slackCatalog))
      assertEquals(unknown, None)
  }

  test("OAuth intended connections must exist in the state's tenant") {
    requireDocker()
    def state(f: Fixture, intended: Option[ConnectionId]): IO[Int] =
      val hash = Array.fill[Byte](32)(1)
      runtimeTx(f.tenant)(
        sql"""insert into oauth_states (tenant_id, state_hash, provider, resource_id, expires_at, intended_connection_id, session_binding)
               values (${f.tenant.toString}::uuid, $hash, 'SLACK', ${f.slackCatalog.toString}::uuid,
                       current_timestamp + interval '5 minutes', ${intended.map(_.toString)}::uuid, $hash)""".update.run
      )
    for
      f <- fixture()
      foreign <- fixture()
      own <- connection(f, Some(f.admin.toString))
      other <- connection(foreign, Some(foreign.admin.toString))
      _ <- refused(state(f, Some(other)), "23503", "oauth_states_intended_connection_fk")
      _ <- refused(state(f, Some(ConnectionId.random())), "23503", "oauth_states_intended_connection_fk")
      accepted <- state(f, Some(own))
      nullFixture <- fixture()
      noIntended <- state(nullFixture, None)
    yield
      assertEquals(accepted, 1)
      assertEquals(noIntended, 1)
  }

  test("active account uniqueness normalizes provider casing and permits a disconnected predecessor") {
    requireDocker()
    def accountConnection(f: Fixture, providerName: String, status: String = "ACTIVE"): IO[Int] =
      val id = ConnectionId.random()
      runtimeTx(f.tenant)(
        sql"""insert into connections (id, tenant_id, provider, status, external_account_id)
               values (${id.toString}::uuid, ${f.tenant.toString}::uuid, $providerName, $status, 'account-1')""".update.run
      )
    for
      f <- fixture()
      foreign <- fixture()
      inactive <- accountConnection(f, "TEST", "DISABLED")
      active <- accountConnection(f, "test")
      _ <- refused(accountConnection(f, "TEST"), "23505", "connections_active_account_idx")
      isolated <- accountConnection(foreign, "TEST")
    yield
      assertEquals(inactive, 1)
      assertEquals(active, 1)
      assertEquals(isolated, 1)
  }

  test("discovery enumerates only currently addressable selected targets of the requested kind") {
    requireDocker()
    for
      f <- fixture()
      c <- connection(f, Some(f.admin.toString))
      root <- openRoot(f, account, c, "acct")
      first <- ok(repository.select(f.tenant, c, item, ext("item-1"), "First", root.id, human(f.admin), t0))
      second <- ok(repository.select(f.tenant, c, item, ext("item-2"), "Second", root.id, human(f.admin), t0))
      nested <- ok(repository.select(f.tenant, c, part, ext("part-1"), "Part", first.id, human(f.admin), t0))
      before <- catalog.discoveryScopes(f.tenant, item)
      _ <- ok(repository.deselect(f.tenant, first.id, t1))
      after <- catalog.discoveryScopes(f.tenant, item)
      belowClosed <- catalog.discoveryScopes(f.tenant, part)
      _ <- runtimeTx(f.tenant)(sql"update connections set status='DISABLED' where tenant_id=${f.tenant.toString}::uuid and id=${c.toString}::uuid".update.run)
      disconnected <- catalog.discoveryScopes(f.tenant, item)
      foreign <- catalog.discoveryScopes(TenantId.random(), item)
    yield
      assertEquals(before.map(_.target.id).toSet, Set(first.id, second.id))
      assertEquals(after.map(_.target.id), Vector(second.id))
      assertEquals(belowClosed, Vector.empty)
      assertEquals(disconnected, Vector.empty)
      assertEquals(foreign, Vector.empty)
  }

  // ---- single-transaction activation ------------------------------------------------------------------------------------

  private def connections = PostgresConnectionRepository(runtimeXa)

  private def activation(
      f: Fixture,
      externalId: String,
      kind: ResourceKind[?] = account,
      singleActiveRoot: Boolean = true,
      owner: Option[UserId] = None
  ): ConnectionActivation =
    ConnectionActivation(
      human(owner.getOrElse(f.admin)), ext(externalId), None, Some(s"Workspace $externalId"), None, "SLACK_OAUTH",
      SecretReference.random(), kind, ext(externalId), s"Root $externalId", None, singleActiveRoot
    )

  private def reserved(f: Fixture, providerName: String = "TEST"): IO[ConnectionId] =
    val id = ConnectionId.random()
    connections.reserve(f.tenant, id, providerName, human(f.admin), t0).as(id)

  private def statusOf(f: Fixture, id: ConnectionId): IO[String] =
    runtimeTx(f.tenant)(
      sql"select status from connections where tenant_id=${f.tenant.toString}::uuid and id=${id.toString}::uuid"
        .query[String].unique
    )

  private def credentialRows(f: Fixture, id: ConnectionId): IO[Int] =
    count(f.tenant, fr"select count(*)::int from credential_references where connection_id=${id.toString}::uuid")

  test("activation publishes the connection, its credential reference, and its verified root together") {
    requireDocker()
    for
      f <- fixture()
      id <- reserved(f)
      result <- connections.activateReserved(f.tenant, id, activation(f, "acct-1"), t1)
      listed <- repository.listFor(f.tenant, id)
      references <- credentialRows(f, id)
      status <- statusOf(f, id)
    yield
      val connection = result.getOrElse(fail(s"activation failed: $result"))
      assertEquals(status, "ACTIVE")
      assertEquals(references, 1)
      assertEquals(listed.map(_.id), Vector(connection.resource))
      assertEquals(listed.map(_.parent), Vector(f.testCatalog))
      assertEquals(connection.externalAccountId, Some("acct-1"))
  }

  test("a refused root rolls the whole activation back: the reservation stays CONNECTING with no credential") {
    requireDocker()
    for
      f <- fixture()
      // The `other` provider has no catalog resource in this tenant, so the trigger refuses its root.
      id <- reserved(f, providerName = "OTHER")
      result <- connections.activateReserved(f.tenant, id, activation(f, "thing", kind = other), t1)
      status <- statusOf(f, id)
      references <- credentialRows(f, id)
      roots <- count(f.tenant, fr"select count(*)::int from resources where connection_id=${id.toString}::uuid")
    yield
      assertEquals(result.map(_ => ()), Left(ConnectionActivationError.InvalidPlacement))
      assertEquals(status, "CONNECTING")
      assertEquals(references, 0)
      assertEquals(roots, 0)
  }

  test("a single-root provider refuses a second active root of the same kind; a multi-root provider allows it") {
    requireDocker()
    for
      f <- fixture()
      first <- reserved(f)
      _ <- connections.activateReserved(f.tenant, first, activation(f, "acct-1"), t1)
      second <- reserved(f)
      refused <- connections.activateReserved(f.tenant, second, activation(f, "acct-2"), t1)
      secondStatus <- statusOf(f, second)
      third <- reserved(f)
      allowed <- connections.activateReserved(f.tenant, third, activation(f, "acct-3", singleActiveRoot = false), t1)
    yield
      assertEquals(refused.map(_ => ()), Left(ConnectionActivationError.RootKindInUse))
      assertEquals(secondStatus, "CONNECTING")
      assert(allowed.isRight, s"a provider with argument-addressed roots may connect several accounts: $allowed")
  }

  test("an account already connected is refused before any write") {
    requireDocker()
    for
      f <- fixture()
      first <- reserved(f)
      _ <- connections.activateReserved(f.tenant, first, activation(f, "acct-1", singleActiveRoot = false), t1)
      second <- reserved(f)
      result <- connections.activateReserved(f.tenant, second, activation(f, "acct-1", singleActiveRoot = false), t1)
      references <- credentialRows(f, second)
    yield
      assertEquals(result.map(_ => ()), Left(ConnectionActivationError.AccountAlreadyConnected))
      assertEquals(references, 0)
  }

  test("only the human who reserved a connection can activate it, and only once") {
    requireDocker()
    for
      f <- fixture()
      id <- reserved(f)
      stranger <- connections.activateReserved(f.tenant, id, activation(f, "acct-1", owner = Some(f.otherHuman)), t1)
      first <- connections.activateReserved(f.tenant, id, activation(f, "acct-1"), t1)
      again <- connections.activateReserved(f.tenant, id, activation(f, "acct-1"), t1)
      failedAfterActivation <- connections.failReserved(f.tenant, id, t2)
      status <- statusOf(f, id)
    yield
      assertEquals(stranger.map(_ => ()), Left(ConnectionActivationError.NotReserved))
      assert(first.isRight)
      assertEquals(again.map(_ => ()), Left(ConnectionActivationError.NotReserved))
      // Cleanup after a committed activation is a no-op, so it can never fail a live connection.
      assertEquals(failedAfterActivation, false)
      assertEquals(status, "ACTIVE")
  }

  test("a selection replacement is refused once the connection is no longer active") {
    requireDocker()
    for
      f <- fixture()
      id <- reserved(f)
      _ <- connections.activateReserved(f.tenant, id, activation(f, "acct-1", singleActiveRoot = false), t1)
      _ <- runtimeTx(f.tenant)(
        sql"update connections set status='DISABLED' where tenant_id=${f.tenant.toString}::uuid and id=${id.toString}::uuid".update.run
      )
      result <- repository.replaceSelection(
        f.tenant, id, human(f.admin), Vector(SelectableProviderResource(item, ext("repo-1"), "Repo", ext("acct-1"))), t2
      )
    yield assertEquals(result.map(_ => ()), Left(ConnectionResourceError.ConnectionUnavailable))
  }

  // ---- grant placement -----------------------------------------------------------------------------------------------

  test("a grant must name a connection resource of the capability's own provider, never the catalog resource") {
    requireDocker()
    for
      f <- fixture()
      slack <- reserved(f, providerName = "SLACK")
      activated <- connections.activateReserved(
        f.tenant, slack, activation(f, "T-SLACK").copy(rootKind = Slack.workspace), t1
      )
      slackRoot = activated.getOrElse(fail(s"slack activation failed: $activated")).resource
      other <- reserved(f)
      testRoot <- connections.activateReserved(f.tenant, other, activation(f, "acct-1", singleActiveRoot = false), t1)
        .map(_.getOrElse(fail("test activation failed")).resource)
      read = f.ids.readCapability.toString
      onCatalog <- catalog.create(f.tenant, CreateDelegation(human(f.admin), Principal.Agent(f.agent), read, f.slackCatalog, Action.Read, None))
      crossProvider <- catalog.create(f.tenant, CreateDelegation(human(f.admin), Principal.Agent(f.agent), read, testRoot, Action.Read, None))
      onRoot <- catalog.create(f.tenant, CreateDelegation(human(f.admin), Principal.Agent(f.agent), read, slackRoot, Action.Read, None))
    yield
      assertEquals(onCatalog.map(_ => ()), Left(DelegationError.InvalidRequest))
      assertEquals(crossProvider.map(_ => ()), Left(DelegationError.InvalidRequest))
      assert(onRoot.isRight, s"a grant on the provider's connection root is the authorized baseline: $onRoot")
  }

  test("disconnecting closes the connection's selections, so a later connection can select the same resources") {
    requireDocker()
    for
      f <- fixture()
      first <- reserved(f)
      _ <- connections.activateReserved(f.tenant, first, activation(f, "acct-1", singleActiveRoot = false), t1)
      root <- repository.listFor(f.tenant, first).map(_.head)
      _ <- ok(repository.select(f.tenant, first, item, ext("repo-1"), "Repo", root.id, human(f.admin), t1))
      disabled <- connections.disable(f.tenant, first)
      open <- count(f.tenant, fr"select count(*)::int from connection_resources where connection_id=${first.toString}::uuid and deselected_at is null")
      second <- reserved(f)
      _ <- connections.activateReserved(f.tenant, second, activation(f, "acct-1", singleActiveRoot = false), t2)
      secondRoot <- repository.listFor(f.tenant, second).map(_.head)
      reselected <- repository.select(f.tenant, second, item, ext("repo-1"), "Repo", secondRoot.id, human(f.admin), t2)
    yield
      assertEquals(disabled, Right(()))
      assertEquals(open, 0)
      assert(reselected.isRight, s"the released resource can be selected again: $reselected")
  }
