package run.hallpass.adapters.postgres

import java.sql.DriverManager
import scala.compiletime.uninitialized
import cats.effect.{IO, Resource}
import cats.syntax.all.*
import munit.CatsEffectSuite
import org.flywaydb.core.Flyway
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.util.transactor.Transactor
import run.hallpass.kernel.TenantId

/** Catalog-driven checks of the production database shape: a migration-owner role and a separate runtime role.
  *
  * The checks enumerate the live catalog rather than a hand-written table list, so a new table, policy, foreign key,
  * or grant that breaks tenant isolation fails here without anyone remembering to add a test. */
final class PostgresSchemaInvariantsSuite extends CatsEffectSuite:
  // The first test in the suite migrates a fresh container, which is slow while other suites start theirs.
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(120, "s")
  private var container: PostgreSQLContainer[?] = uninitialized
  private var dockerAvailable = false
  private val Owner = "authai_owner"
  private val App = "authai_app"
  private val Password = "test-password"
  private val runtimeRole = RuntimeRole.parse(App).toOption.get

  /** Global reference data shared by every tenant. It contains no tenant information; the runtime role may only read
    * it, and tenant tables may reference it. `models` holds execution-context model identities (provider, name,
    * version), which are not tenant-owned. */
  private val GlobalReferenceTables = Set("models", "resource_kinds")

  /** The identity directory: pre-tenant routing data (users, external identities, memberships, credential routes) and
    * pre-tenant browser state (login attempts, sessions, their audit events, and break-glass grants). It
    * is not tenant-scoped by policy; instead the runtime role has no privileges on it and reaches it only through the
    * SECURITY DEFINER routing functions (see PostgresIdentityDirectorySuite). */
  private val DirectoryTables = Set(
    "directory_users",
    "directory_external_identities",
    "directory_tenant_memberships",
    "directory_agent_credential_routes",
    "directory_login_attempts",
    "directory_sessions",
    "directory_break_glass_grants",
    "directory_session_events",
    "directory_agent_authentication_failures",
    "directory_agent_authentication_rejections",
    "directory_connection_account_claims"
  )

  /** Tables deliberately outside tenant ownership. Adding one requires an explicit decision here. */
  private val NonTenantTables = Set("flyway_schema_history") ++ GlobalReferenceTables ++ DirectoryTables

  /** The runtime role's intended privileges: the specification that `afterMigrate.sql` implements. */
  private val MutableState = Set("SELECT", "INSERT", "UPDATE")
  private val InsertOnly = Set("SELECT", "INSERT")
  /** Provisioned by the owner (HallpassProvisionMain); the API only reads them. */
  private val Provisioned = Set("SELECT")
  private val ExpectedPrivileges: Map[String, Set[String]] = Map(
    "agent_credentials" -> MutableState,
    "connections" -> MutableState,
    "delegations" -> MutableState,
    "oauth_states" -> Set("SELECT", "INSERT", "UPDATE", "DELETE"),
    // Envelope ciphertext: never updated at runtime (the owner-run rewrap job does that).
    "provider_secrets" -> Set("SELECT", "INSERT", "DELETE"),
    "tenants" -> Provisioned,
    "principals" -> InsertOnly,
    "human_identities" -> Provisioned,
    "agents" -> InsertOnly,
    // Catalog rows are provisioned by the owner; the insert trigger admits only connection-scoped rows at runtime.
    "resources" -> InsertOnly,
    // Closing a selection is a column-level UPDATE of deselected_at, checked below.
    "connection_resources" -> InsertOnly,
    // Decision and consumption are column-level UPDATEs, checked below.
    "approvals" -> InsertOnly,
    "resource_kinds" -> Set("SELECT"),
    "tools" -> Provisioned,
    "capabilities" -> Provisioned,
    "tool_capability_mappings" -> Provisioned,
    "credential_references" -> InsertOnly,
    "policies" -> Provisioned,
    "policy_bindings" -> Provisioned,
    "delegated_capabilities" -> InsertOnly,
    "authorization_requests" -> InsertOnly,
    "authorization_decisions" -> InsertOnly,
    "audit_events" -> InsertOnly,
    "execution_audit_events" -> InsertOnly,
    "execution_audit_event_delegations" -> InsertOnly,
    "models" -> Set("SELECT"),
    "flyway_schema_history" -> Set("SELECT")
  ) ++ DirectoryTables.map(_ -> Set.empty[String])
  private val AppendOnlyEvidence =
    Vector("authorization_requests", "authorization_decisions", "audit_events", "execution_audit_events", "execution_audit_event_delegations")

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      superuser("test"): statement =>
        statement.execute(s"create role $Owner login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"create role $App login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"create role hallpass_member login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"grant $Owner to hallpass_member")
        statement.execute("create role hallpass_privileged nologin superuser")
        statement.execute("create role hallpass_bypass nologin bypassrls")
        statement.execute(s"create role hallpass_bypass_member login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute("grant hallpass_bypass to hallpass_bypass_member")
        statement.execute("create database behind")
        statement.execute(s"grant connect on database test to $Owner, $App, hallpass_member, hallpass_bypass_member")
        statement.execute(s"grant connect on database behind to $Owner, $App")
      Vector("test", "behind").foreach: database =>
        superuser(database): statement =>
          statement.execute("revoke create on schema public from public")
          statement.execute(s"grant usage, create on schema public to $Owner")
          statement.execute(s"grant usage on schema public to $App")
          if database == "test" then statement.execute("grant usage on schema public to hallpass_bypass_member")

  override def afterAll(): Unit = if dockerAvailable then container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  private def superuser(database: String)(use: java.sql.Statement => Unit): Unit =
    val url = container.getJdbcUrl.replace("/test?", s"/$database?").replace("/test", s"/$database")
    val connection = DriverManager.getConnection(url, container.getUsername, container.getPassword)
    try use(connection.createStatement())
    finally connection.close()

  private def config(user: String, database: String = "test", password: String = Password): DatabaseConfig =
    val url = container.getJdbcUrl.replace("/test?", s"/$database?").replace("/test", s"/$database")
    DatabaseConfig
      .fromEnvironment(Map("HALLPASS_DB_URL" -> url, "HALLPASS_DB_USER" -> user, "HALLPASS_DB_PASSWORD" -> password))
      .toOption
      .get

  /** Migrated by the owner job, seeded by the owner, and served by the runtime role in external mode. */
  private lazy val prepared: IO[Unit] =
    PostgresDatabase.migrateAsOwner(config(Owner), runtimeRole) *>
      PostgresDatabase.resource(config(Owner)).use(DemoBootstrap.run)

  private def asRuntimeRole[A](program: Transactor[IO] => IO[A]): IO[A] =
    prepared *> PostgresDatabase.resourceWithSchema(config(App), MigrationMode.External).use((xa, _) => program(xa))

  private def asOwner[A](program: Transactor[IO] => IO[A]): IO[A] =
    prepared *> PostgresDatabase.resource(config(Owner)).use(program)

  private def tables(xa: Transactor[IO]): IO[Vector[String]] =
    sql"""select table_name from information_schema.tables
          where table_schema = 'public' and table_type = 'BASE TABLE' order by table_name"""
      .query[String].to[Vector].transact(xa)

  private def tenantOwnedTables(xa: Transactor[IO]): IO[Vector[String]] =
    tables(xa).map(_.filterNot(NonTenantTables.contains))

  test("every table is tenant-owned or explicitly allowlisted") {
    requireDocker()
    asOwner: xa =>
      sql"""select t.table_name from information_schema.tables t
            where t.table_schema = 'public' and t.table_type = 'BASE TABLE' and t.table_name <> 'tenants'
              and not exists (
                select 1 from information_schema.columns c
                where c.table_schema = 'public' and c.table_name = t.table_name and c.column_name = 'tenant_id'
              )"""
        .query[String].to[Vector].transact(xa)
        .map: withoutTenant =>
          // Directory tables may carry tenant_id (memberships, routes) yet are classified as directory, not tenant-owned.
          assertEquals(withoutTenant.toSet -- DirectoryTables, NonTenantTables -- DirectoryTables)
  }

  test("row-level security is enabled, forced, and scoped only by the transaction tenant on every tenant table") {
    requireDocker()
    asOwner: xa =>
      for
        owned <- tenantOwnedTables(xa)
        flags <- sql"""select c.relname, c.relrowsecurity, c.relforcerowsecurity
                       from pg_class c join pg_namespace n on n.oid = c.relnamespace
                       where n.nspname = 'public' and c.relkind = 'r'"""
          .query[(String, Boolean, Boolean)].to[Vector].transact(xa)
        policies <- sql"""select tablename, permissive, cmd, coalesce(qual, ''), coalesce(with_check, '')
                          from pg_policies where schemaname = 'public'"""
          .query[(String, String, String, String, String)].to[Vector].transact(xa)
      yield
        val flagsByTable = flags.map((name, enabled, forced) => name -> (enabled, forced)).toMap
        val notForced = owned.filterNot(table => flagsByTable.get(table).contains((true, true)))
        assertEquals(notForced, Vector.empty, "tables without enabled and forced RLS")
        val withoutPolicy = owned.filterNot(table => policies.exists(_._1 == table))
        assertEquals(withoutPolicy, Vector.empty, "tenant tables without a policy")
        val scoped = (expression: String) => expression.contains("current_setting('authai.tenant_id'::text, true)")
        val unsafe = policies.filterNot: (_, permissive, command, visibility, check) =>
          permissive == "PERMISSIVE" && command == "ALL" && scoped(visibility) && scoped(check)
        assertEquals(unsafe, Vector.empty, "policies that are not tenant-scoped for every command")
  }

  test("every foreign key between tenant-owned tables carries tenant_id on both sides") {
    requireDocker()
    asOwner: xa =>
      sql"""select con.conname, src.relname, dst.relname,
                   (select string_agg(a.attname::text, ',' order by k.position)
                      from unnest(con.conkey) with ordinality k(attnum, position)
                      join pg_attribute a on a.attrelid = con.conrelid and a.attnum = k.attnum),
                   (select string_agg(a.attname::text, ',' order by k.position)
                      from unnest(con.confkey) with ordinality k(attnum, position)
                      join pg_attribute a on a.attrelid = con.confrelid and a.attnum = k.attnum)
            from pg_constraint con
            join pg_class src on src.oid = con.conrelid
            join pg_class dst on dst.oid = con.confrelid
            join pg_namespace n on n.oid = src.relnamespace
            where con.contype = 'f' and n.nspname = 'public'"""
        .query[(String, String, String, String, String)].to[Vector].transact(xa)
        .map(_.map((name, source, target, sourceColumns, targetColumns) =>
          (name, source, target, sourceColumns.split(',').toList, targetColumns.split(',').toList)
        ))
        .map: foreignKeys =>
          val violations = foreignKeys.filterNot: (_, source, target, sourceColumns, targetColumns) =>
            if target == "tenants" then sourceColumns == List("tenant_id") && targetColumns == List("id")
            else if GlobalReferenceTables.contains(target) then true
            // Only the directory may reference its own global rows (users); tenant tables never point into it.
            else if DirectoryTables.contains(target) then DirectoryTables.contains(source)
            else sourceColumns.zip(targetColumns).contains("tenant_id" -> "tenant_id")
          assertEquals(violations.map(_._1), Vector.empty, s"foreign keys that can cross tenants: $violations")
  }

  test("the runtime role cannot bypass RLS, alter the schema, or exceed its privilege matrix") {
    requireDocker()
    asOwner: xa =>
      for
        allTables <- tables(xa)
        role <- sql"""select rolsuper, rolbypassrls, has_schema_privilege(oid, 'public', 'CREATE'),
                             exists(select 1 from pg_class c where c.relowner = r.oid)
                      from pg_roles r where rolname = $App"""
          .query[(Boolean, Boolean, Boolean, Boolean)].unique.transact(xa)
        granted <- allTables.traverse: table =>
          Vector("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")
            .traverse: privilege =>
              sql"select has_table_privilege($App, ${"public." + table}, $privilege)"
                .query[Boolean].unique.transact(xa).map(privilege -> _)
            .map(results => table -> results.collect { case (privilege, true) => privilege }.toSet)
      yield
        assertEquals(role, (false, false, false, false), "runtime role must not be superuser, BYPASSRLS, able to create, or an owner")
        assertEquals(allTables.toSet -- ExpectedPrivileges.keySet, Set.empty, "tables missing from the privilege matrix")
        GlobalReferenceTables.foreach: table =>
          assertEquals(ExpectedPrivileges(table), Set("SELECT"), s"global reference table $table must be read-only at runtime")
        assertEquals(granted.toMap, ExpectedPrivileges.filter((table, _) => allTables.contains(table)))
  }

  /** Column-level UPDATE grants do not appear as table privileges, so they are pinned separately. The relation name is
    * built from each row's own schema: PostgreSQL may evaluate the privilege functions before the `table_schema`
    * filter, and a hard-coded `public.` prefix then names catalog tables (such as `pg_statistic`) that do not exist
    * there. */
  private val ExpectedColumnUpdates: Set[(String, String)] = Set(
    "connection_resources" -> "deselected_at",
    "approvals" -> "status",
    "approvals" -> "decided_by",
    "approvals" -> "decided_at",
    "approvals" -> "consumed_at",
    "approvals" -> "consumed_request_id",
    "credential_references" -> "secret_reference",
    "credential_references" -> "expires_at"
  )

  test("the runtime role can update only the columns in its column matrix beyond its table-level UPDATE grants") {
    requireDocker()
    asOwner: xa =>
      sql"""select c.table_name, c.column_name from information_schema.columns c
            where c.table_schema = 'public'
              and has_column_privilege($App, format('%I.%I', c.table_schema, c.table_name), c.column_name, 'UPDATE')
              and not has_table_privilege($App, format('%I.%I', c.table_schema, c.table_name), 'UPDATE')"""
        .query[(String, String)].to[Vector].transact(xa)
        .map(columns => assertEquals(columns.toSet, ExpectedColumnUpdates))
  }

  test("without a tenant context, or in another tenant's, the runtime role reads and changes nothing") {
    requireDocker()
    asRuntimeRole: xa =>
      def count(table: String, tenant: Option[String]): IO[Long] =
        (tenant.traverse_(value => sql"select set_config('authai.tenant_id', $value, true)".query[String].unique) *>
          (fr"select count(*) from" ++ Fragment.const(table)).query[Long].unique).transact(xa)
      def updated(table: String): IO[Either[Throwable, Int]] =
        (fr"update" ++ Fragment.const(table) ++ fr"set tenant_id = tenant_id").update.run.transact(xa).attempt
      for
        owned <- tenantOwnedTables(xa)
        withoutContext <- owned.traverse(table => count(table, None).map(table -> _))
        otherTenant <- owned.traverse(table => count(table, Some(TenantId.random().toString)).map(table -> _))
        ownTenant <- count("tenants", Some(DemoBootstrap.Tenant.toString))
        ownCatalog <- count("capabilities", Some(DemoBootstrap.Tenant.toString))
        updates <- ExpectedPrivileges.collect { case (table, privileges) if privileges("UPDATE") => table }.toVector.traverse(updated)
        malformed <- (sql"select set_config('authai.tenant_id', 'not-a-uuid', true)".query[String].unique *>
          sql"select count(*) from agents".query[Long].unique).transact(xa).attempt
      yield
        assertEquals(withoutContext.filter(_._2 != 0), Vector.empty, "rows visible without a tenant context")
        assertEquals(otherTenant.filter(_._2 != 0), Vector.empty, "rows visible from another tenant")
        assertEquals(ownTenant, 1L)
        assert(ownCatalog > 0, "the seeded tenant's own rows must remain visible")
        assert(updates.forall(_ == Right(0)), s"updates without context changed rows: $updates")
        assert(malformed.isLeft, "a malformed tenant context must fail, not return rows")
  }

  test("the runtime role cannot write rows for a tenant other than its transaction tenant") {
    requireDocker()
    asRuntimeRole: xa =>
      val foreign = TenantId.random().toString
      def insertPrincipal(context: Option[String]): IO[Either[Throwable, Int]] =
        (context.traverse_(value => sql"select set_config('authai.tenant_id', $value, true)".query[String].unique) *>
          sql"insert into principals(id, tenant_id, kind) values (gen_random_uuid(), $foreign::uuid, 'AGENT')".update.run)
          .transact(xa)
          .attempt
      for
        withoutContext <- insertPrincipal(None)
        mismatched <- insertPrincipal(Some(DemoBootstrap.Tenant.toString))
        tenant <- (sql"select set_config('authai.tenant_id', $foreign, true)".query[String].unique *>
          sql"insert into tenants(id, name, slug) values ($foreign::uuid, 'Foreign', ${"foreign-" + foreign.take(8)})".update.run)
          .transact(xa)
          .attempt
      yield
        assert(withoutContext.isLeft, "insert without a tenant context must be rejected")
        assert(mismatched.isLeft, "insert for another tenant must be rejected by the policy check")
        assert(
          tenant.left.exists { case error: java.sql.SQLException => error.getSQLState == "42501"; case _ => false },
          s"the runtime role must not be able to create tenants: $tenant"
        )
  }

  test("append-only evidence cannot be updated or deleted by the runtime role") {
    requireDocker()
    asRuntimeRole: xa =>
      AppendOnlyEvidence
        .traverse: table =>
          val tenantContext = sql"select set_config('authai.tenant_id', ${DemoBootstrap.Tenant.toString}, true)".query[String].unique
          (
            (tenantContext *> (fr"update" ++ Fragment.const(table) ++ fr"set tenant_id = tenant_id").update.run).transact(xa).attempt,
            (tenantContext *> (fr"delete from" ++ Fragment.const(table)).update.run).transact(xa).attempt
          ).mapN((update, delete) => (table, update, delete))
        .map: results =>
          def denied(result: Either[Throwable, Int]) = result match
            case Left(error: java.sql.SQLException) => error.getSQLState == "42501"
            case _                                  => false
          val permitted = results.filterNot((_, update, delete) => denied(update) && denied(delete))
          assertEquals(permitted.map(_._1), Vector.empty, "evidence tables that the runtime role can alter")
  }

  test("external mode refuses a role that owns the schema") {
    requireDocker()
    prepared *>
      PostgresDatabase.resourceWithSchema(config(Owner), MigrationMode.External).use(_ => IO.unit).attempt.map:
        case Left(DatabaseSafetyException(message)) => assert(message.contains("ownership of schema objects"), message)
        case other                                  => fail(s"expected an ownership refusal, received $other")
  }

  test("a runtime role that inherits the migration owner is refused before migration and API startup") {
    requireDocker()
    for
      migration <- PostgresDatabase.migrateAsOwner(config(Owner), RuntimeRole.parse("hallpass_member").toOption.get).attempt
      _ <- prepared
      startup <- PostgresDatabase.resourceWithSchema(config("hallpass_member"), MigrationMode.External).use(_ => IO.unit).attempt
    yield
      assert(migration.left.exists {
        case DatabaseSafetyException(message) => message.contains("member of the migration owner role")
        case _                                => false
      }, s"migration job accepted an inherited owner: $migration")
      assert(startup.left.exists {
        case DatabaseSafetyException(message) => message.contains("ownership of schema objects")
        case _                                => false
      }, s"API accepted an inherited owner: $startup")
  }

  test("a runtime role that can assume a BYPASSRLS role is refused by the migration job and at startup") {
    requireDocker()
    val member = RuntimeRole.parse("hallpass_bypass_member").toOption.get
    for
      migration <- PostgresDatabase.migrateAsOwner(config(Owner), member).attempt
      _ <- prepared
      // Enough to pass schema validation, so the refusal comes from the role check.
      _ <- IO.blocking(superuser("test")(_.execute("grant select on flyway_schema_history to hallpass_bypass_member")))
      startup <- PostgresDatabase.resourceWithSchema(config("hallpass_bypass_member"), MigrationMode.External).use(_ => IO.unit).attempt
    yield
      assert(migration.left.exists {
        case DatabaseSafetyException(message) => message.contains("member of a role that does")
        case _                                => false
      }, s"migration job accepted a runtime role that can assume BYPASSRLS: $migration")
      assert(startup.left.exists {
        case DatabaseSafetyException(message) => message.contains("member of a superuser or BYPASSRLS role")
        case _                                => false
      }, s"API accepted a runtime role that can assume BYPASSRLS: $startup")
  }

  test("external mode refuses a schema that is behind this release") {
    requireDocker()
    val behind = config(Owner, database = "behind")
    IO.blocking(
      Flyway
        .configure()
        .dataSource(behind.jdbcUrl, behind.user, behind.password.orNull)
        .locations("classpath:db/migration")
        .placeholders(java.util.Map.of("runtime_role", App))
        .target("10")
        .load()
        .migrate()
    ) *>
      PostgresDatabase.resourceWithSchema(config(App, database = "behind"), MigrationMode.External).use(_ => IO.unit).attempt.map:
        case Left(DatabaseSafetyException(message)) => assert(message.contains("run the migration job"), message)
        case other                                  => fail(s"expected a schema refusal, received $other")
  }

  test("the migration job refuses unsafe role combinations before migrating") {
    requireDocker()
    def refusal(database: DatabaseConfig, role: String): IO[String] =
      PostgresDatabase.migrateAsOwner(database, RuntimeRole.parse(role).toOption.get).attempt.map:
        case Left(DatabaseSafetyException(message)) => message
        case other                                  => fail(s"expected a migration refusal, received $other")
    for
      sameRole <- refusal(config(Owner), Owner)
      missing <- refusal(config(Owner), "hallpass_missing")
      privilegedRuntime <- refusal(config(Owner), "hallpass_privileged")
      privilegedOwner <- refusal(config(container.getUsername, password = container.getPassword), App)
    yield
      assert(sameRole.contains("must be different"), sameRole)
      assert(missing.contains("does not exist"), missing)
      assert(privilegedRuntime.contains("runtime role is a superuser"), privilegedRuntime)
      assert(privilegedOwner.contains("migration role is a superuser"), privilegedOwner)
  }

  test("re-running the migration job revokes privileges granted outside it") {
    requireDocker()
    for
      _ <- prepared
      _ <- IO.blocking(superuser("test")(_.execute(s"grant delete, truncate on agents to $App")))
      _ <- PostgresDatabase.migrateAsOwner(config(Owner), runtimeRole)
      remaining <- asOwner: xa =>
        sql"select has_table_privilege($App, 'public.agents', 'DELETE') or has_table_privilege($App, 'public.agents', 'TRUNCATE')"
          .query[Boolean].unique.transact(xa)
    yield assert(!remaining, "stray privileges survived the migration job")
  }
