package run.hallpass.adapters.postgres

import cats.effect.{IO, Resource}
import cats.syntax.all.*
import com.zaxxer.hikari.{HikariConfig, HikariDataSource}
import org.typelevel.doobie.hikari.HikariTransactor
import org.typelevel.doobie.ConnectionIO
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.util.transactor.Transactor
import org.flywaydb.core.Flyway
import org.flywaydb.core.api.{MigrationState, MigrationVersion}
import run.hallpass.kernel.TenantId

/** Edge configuration only. Passwords are accepted from the process environment and are never represented in the
  * authorization kernel or logged here.
  */
final case class DatabaseConfig private (
    jdbcUrl: String,
    user: String,
    password: Option[String],
    maximumPoolSize: Int
)

object DatabaseConfig:
  private val UrlKey = "HALLPASS_DB_URL"
  private val UserKey = "HALLPASS_DB_USER"
  private val PasswordKey = "HALLPASS_DB_PASSWORD"
  private val PoolSizeKey = "HALLPASS_DB_MAX_POOL_SIZE"

  def fromEnvironment(environment: Map[String, String] = sys.env): Either[String, DatabaseConfig] =
    for
      url <- required(environment, UrlKey)
      user <- required(environment, UserKey)
      poolSize <- environment
        .get(PoolSizeKey)
        .fold[Either[String, Int]](Right(8)): raw =>
          raw.toIntOption.filter(size => size >= 1 && size <= 64).toRight(s"$PoolSizeKey must be between 1 and 64")
      password <- optionalSecret(environment, PasswordKey)
    yield DatabaseConfig(url, user, password, poolSize)

  private def required(environment: Map[String, String], key: String): Either[String, String] =
    environment.get(key).map(_.trim).filter(_.nonEmpty).toRight(s"Missing required environment variable: $key")

  /** Prefer a mounted secret file so passwords are not present in the container environment. */
  private def optionalSecret(environment: Map[String, String], key: String): Either[String, Option[String]] =
    environment.get(s"${key}_FILE").map(_.trim).filter(_.nonEmpty) match
      case Some(path) =>
        Either
          .catchNonFatal(java.nio.file.Files.readString(java.nio.file.Path.of(path)).trim)
          .left
          .map(_ => s"Unable to read ${key}_FILE")
          .flatMap(value => Either.cond(value.nonEmpty, Some(value), s"${key}_FILE is empty"))
      case None => Right(environment.get(key).map(_.trim).filter(_.nonEmpty))

/** A Flyway schema version string such as `11`. */
final case class SchemaVersion(value: String):
  private[postgres] def migrationVersion: MigrationVersion = MigrationVersion.fromVersion(value)

/** The PostgreSQL role the API connects as. It is interpolated into grant statements, so only plain lower-case
  * identifiers are accepted. */
final case class RuntimeRole private (value: String)
object RuntimeRole:
  private val Pattern = "[a-z_][a-z0-9_]{0,62}".r
  def parse(value: String): Either[String, RuntimeRole] =
    value match
      case Pattern() => Right(RuntimeRole(value))
      case _         => Left("runtime role must be a lower-case PostgreSQL identifier")

/** Who applies schema migrations.
  *
  * `InProcess` is the local development shape: the API role migrates and therefore owns the schema. `External` is the
  * production shape: a separate owner role migrates in a one-shot job, and the API role only verifies the schema and
  * holds the DML grants the `afterMigrate` callback gives it. */
enum MigrationMode:
  case InProcess
  case External

object MigrationMode:
  val EnvironmentKey = "HALLPASS_DB_MIGRATIONS"
  def fromEnvironment(environment: Map[String, String]): Either[String, MigrationMode] =
    environment.get(EnvironmentKey).map(_.trim.toLowerCase).filter(_.nonEmpty) match
      case None | Some("in-process") => Right(InProcess)
      case Some("external")          => Right(External)
      case Some(_)                   => Left(s"$EnvironmentKey must be in-process or external")

/** Startup refusal for an unsafe runtime role or schema. Messages are operator-facing and contain no secrets. */
final case class DatabaseSafetyException(message: String) extends RuntimeException(message)

/** Owns infrastructure lifecycle and validates the database schema and role before the application accepts requests.
  */
object PostgresDatabase:
  private val Locations = "classpath:db/migration"

  def resource(config: DatabaseConfig): Resource[IO, Transactor[IO]] =
    resourceWithSchema(config).map(_._1)

  /** In-process mode, as used by local development and most integration tests. */
  def resourceWithSchema(config: DatabaseConfig): Resource[IO, (Transactor[IO], SchemaVersion)] =
    resourceWithSchema(config, MigrationMode.InProcess)

  /** Returns the schema version this code requires, which readiness keeps checking.
    *
    * In-process mode migrates first, granting to the connecting role itself. External mode never migrates. It refuses
    * to start if the schema is behind this code or has been changed, and if the role could alter the schema or bypass
    * row-level security. */
  def resourceWithSchema(
      config: DatabaseConfig,
      mode: MigrationMode
  ): Resource[IO, (Transactor[IO], SchemaVersion)] =
    for
      version <- Resource.eval(mode match
        case MigrationMode.InProcess =>
          IO.fromEither(RuntimeRole.parse(config.user).leftMap(DatabaseSafetyException(_)))
            .flatMap(role => migrate(config, role))
        case MigrationMode.External => verifySchema(config)
      )
      transactor <- HikariTransactor.fromHikariConfig[IO](hikariConfig(config))
      _ <- Resource.eval(verifyRuntimeRole(transactor, mode))
    yield (transactor, version)

  private def flyway(config: DatabaseConfig, runtimeRole: RuntimeRole): Flyway =
    Flyway
      .configure()
      .dataSource(config.jdbcUrl, config.user, config.password.orNull)
      .locations(Locations)
      .placeholders(java.util.Map.of("runtime_role", runtimeRole.value))
      .load()

  /** Applies pending migrations as `config.user`, then the `afterMigrate` callback converges the runtime role's grants.
    * Returns the version this code requires. */
  def migrate(config: DatabaseConfig, runtimeRole: RuntimeRole): IO[SchemaVersion] =
    IO.blocking:
      val migrator = flyway(config, runtimeRole)
      migrator.migrate()
      requiredVersion(migrator)

  /** The migration job: applies migrations as a dedicated owner role and grants the separate runtime role.
    *
    * Refuses when the owner and runtime role are the same, when either is a superuser or has BYPASSRLS, or when the
    * runtime role does not exist. Nothing is migrated unless every check passes. */
  def migrateAsOwner(config: DatabaseConfig, runtimeRole: RuntimeRole): IO[SchemaVersion] =
    val preflight =
      HikariTransactor
        .fromHikariConfig[IO]:
          val single = hikariConfig(config)
          single.setMaximumPoolSize(1)
          single.setPoolName("hallpass-migration-preflight")
          single
        .use: transactor =>
          sql"""select
                  (select rolsuper or rolbypassrls from pg_roles where rolname = current_user),
                  (select r.rolsuper or r.rolbypassrls or exists(
                            select 1 from pg_roles p
                            where p.oid <> r.oid and (p.rolsuper or p.rolbypassrls) and pg_has_role(r.oid, p.oid, 'MEMBER'))
                     from pg_roles r where r.rolname = ${runtimeRole.value}),
                  coalesce((select pg_has_role(r.oid, current_user, 'MEMBER')
                            from pg_roles r where r.rolname = ${runtimeRole.value}), false)"""
            .query[(Boolean, Option[Boolean], Boolean)]
            .unique
            .transact(transactor)
      .flatMap: (ownerPrivileged, runtimePrivileged, runtimeMemberOfOwner) =>
        val problems = Vector(
          Option.when(config.user == runtimeRole.value)(
            "the migration role and the runtime role must be different roles"
          ),
          Option.when(ownerPrivileged)("the migration role is a superuser or has BYPASSRLS"),
          Option.when(runtimePrivileged.isEmpty)("the runtime role does not exist"),
          Option.when(runtimePrivileged.contains(true))(
            "the runtime role is a superuser, has BYPASSRLS, or is a member of a role that does"
          ),
          Option.when(runtimeMemberOfOwner)("the runtime role is a member of the migration owner role")
        ).flatten
        IO.raiseUnless(problems.isEmpty)(DatabaseSafetyException(s"refusing to migrate: ${problems.mkString("; ")}"))
    preflight *> migrate(config, runtimeRole)

  /** For operator jobs that run as the schema owner against an already-migrated schema, such as tenant provisioning.
    * It never migrates, and it refuses a schema that does not match this release. */
  private[postgres] def ownerResource(config: DatabaseConfig): Resource[IO, Transactor[IO]] =
    Resource.eval(verifySchema(config)) *> HikariTransactor.fromHikariConfig[IO](hikariConfig(config))

  /** Read-only check for external mode. Validation fails on pending (not yet applied) migrations and on checksum
    * changes; a newer schema from a later release is accepted, as expand/contract migrations require. */
  private[postgres] def verifySchema(config: DatabaseConfig): IO[SchemaVersion] =
    IO.fromEither(RuntimeRole.parse(config.user).leftMap(DatabaseSafetyException(_))).flatMap: role =>
      IO.blocking:
        val verifier = flyway(config, role)
        val validation = verifier.validateWithResult()
        if !validation.validationSuccessful then
          throw DatabaseSafetyException(
            "database schema does not match this release; run the migration job before starting the API"
          )
        requiredVersion(verifier)

  /** The newest versioned migration shipped with this code. */
  private def requiredVersion(migrator: Flyway): SchemaVersion =
    migrator
      .info()
      .all()
      .toVector
      .filter(info => info.getVersion != null && info.getState != MigrationState.FUTURE_SUCCESS)
      .map(_.getVersion)
      .maxOption
      .map(version => SchemaVersion(version.getVersion))
      .getOrElse(throw DatabaseSafetyException("no versioned migrations are available"))

  /** The role serving traffic must never bypass RLS, directly or through a role it can assume. In external mode it must
    * also be unable to alter the schema: an owner could `ALTER TABLE ... NO FORCE ROW LEVEL SECURITY`. */
  private def verifyRuntimeRole(transactor: Transactor[IO], mode: MigrationMode): IO[Unit] =
    sql"""select r.rolsuper,
                 r.rolbypassrls,
                 exists(
                   select 1 from pg_roles p
                   where p.oid <> r.oid and (p.rolsuper or p.rolbypassrls) and pg_has_role(r.oid, p.oid, 'MEMBER')
                 ),
                 exists(
                   select 1 from pg_class c join pg_namespace n on n.oid = c.relnamespace
                   where n.nspname = 'public'
                     and (c.relowner = r.oid or pg_has_role(r.oid, c.relowner, 'MEMBER'))
                 ),
                 has_schema_privilege(r.oid, 'public', 'CREATE')
          from pg_roles r where r.rolname = current_user"""
      .query[(Boolean, Boolean, Boolean, Boolean, Boolean)]
      .unique
      .transact(transactor)
      .flatMap: (superuser, bypassesRls, privilegedMembership, ownsObjects, canCreate) =>
        val problems =
          Vector(
            Option.when(superuser)("the database role is a superuser"),
            Option.when(bypassesRls)("the database role has BYPASSRLS"),
            Option.when(privilegedMembership)(
              "the database role is a member of a superuser or BYPASSRLS role and could SET ROLE to it"
            ),
            Option.when(mode == MigrationMode.External && ownsObjects)(
              "the runtime role owns or can assume ownership of schema objects; use a separate migration owner role"
            ),
            Option.when(mode == MigrationMode.External && canCreate)(
              "the runtime role can create objects in schema public"
            )
          ).flatten
        IO.raiseUnless(problems.isEmpty)(
          DatabaseSafetyException(s"refusing to serve with an unsafe database role: ${problems.mkString("; ")}")
        )

  /** True only if PostgreSQL answers and its latest successful versioned migration is at least `required`. A newer
    * schema is expected briefly during a rolling deploy, so it does not fail readiness. Never throws. */
  def schemaAtLeast(transactor: Transactor[IO], required: SchemaVersion): IO[Boolean] =
    sql"""select version from flyway_schema_history
           where success and version is not null"""
      .query[String]
      .to[Vector]
      .transact(transactor)
      .map(_.map(MigrationVersion.fromVersion).maxOption.exists(_.compareTo(required.migrationVersion) >= 0))
      .handleError(_ => false)

  /** A separate pool for tenant-gate sessions. Gate connections hold a session-level advisory lock across a whole
    * critical section, so they must never compete with (or deadlock against) the repository pool used inside it.
    * Its size bounds the number of concurrent gated critical sections in this process. */
  private[postgres] def gateDataSource(
      config: DatabaseConfig,
      maximumPoolSize: Int,
      connectionTimeoutMillis: Long,
      socketTimeoutSeconds: Int
  ): Resource[IO, HikariDataSource] =
    Resource.fromAutoCloseable(IO.blocking:
      val hikari = HikariConfig()
      hikari.setJdbcUrl(config.jdbcUrl)
      hikari.setUsername(config.user)
      config.password.foreach(hikari.setPassword)
      hikari.setMaximumPoolSize(maximumPoolSize)
      hikari.setMinimumIdle(0)
      hikari.setPoolName("hallpass-tenant-gate")
      // Session-level advisory locks outlive transactions; autocommit keeps no transaction open while one is held.
      hikari.setAutoCommit(true)
      hikari.setConnectionTimeout(math.max(250L, connectionTimeoutMillis))
      // Bounds every blocking read, so a partitioned gate session cannot hang an ownership check indefinitely.
      hikari.addDataSourceProperty("socketTimeout", socketTimeoutSeconds.toString)
      hikari.addDataSourceProperty("tcpKeepAlive", "true")
      HikariDataSource(hikari)
    )

  private def hikariConfig(config: DatabaseConfig): HikariConfig =
    val hikari = HikariConfig()
    hikari.setJdbcUrl(config.jdbcUrl)
    hikari.setUsername(config.user)
    config.password.foreach(hikari.setPassword)
    hikari.setMaximumPoolSize(config.maximumPoolSize)
    hikari.setPoolName("hallpass-postgres")
    hikari.setAutoCommit(false)
    hikari

/** Establishes the RLS tenant for the current transaction. Repository programs should compose this as their first
  * operation; `isLocal = true` ensures the setting disappears at transaction end and cannot leak through the pool.
  */
object TenantSession:
  def establish(tenantId: TenantId): ConnectionIO[Unit] =
    sql"select set_config('authai.tenant_id', ${tenantId.toString}, true)".query[String].unique.void
