package run.hallpass.gateway

import cats.effect.{ExitCode, IO, IOApp}
import cats.syntax.all.*
import run.hallpass.adapters.postgres.{DatabaseConfig, DatabaseSafetyException, PostgresDatabase, RuntimeRole}

/** One-shot migration job for deployments that run the API with `HALLPASS_DB_MIGRATIONS=external`.
  *
  * It connects as the schema owner (`HALLPASS_DB_USER`), applies pending migrations, and converges the runtime role's
  * grants (`HALLPASS_DB_RUNTIME_ROLE`). Run it to completion before starting or rolling API instances. It exits non-zero
  * without migrating if the roles are unsafe. */
object HallpassMigrateMain extends IOApp:
  val RuntimeRoleKey = "HALLPASS_DB_RUNTIME_ROLE"

  private[gateway] def configFromEnvironment(
      environment: Map[String, String]
  ): Either[String, (DatabaseConfig, RuntimeRole)] =
    for
      database <- DatabaseConfig.fromEnvironment(environment)
      rawRole <- environment.get(RuntimeRoleKey).map(_.trim).filter(_.nonEmpty).toRight(s"$RuntimeRoleKey is required")
      role <- RuntimeRole.parse(rawRole).leftMap(error => s"$RuntimeRoleKey is invalid: $error")
    yield database -> role

  def run(args: List[String]): IO[ExitCode] =
    configFromEnvironment(sys.env) match
      case Left(error) => IO.consoleForIO.errorln(error).as(ExitCode.Error)
      case Right((database, role)) =>
        PostgresDatabase
          .migrateAsOwner(database, role)
          .flatMap(version => IO.println(s"Schema is at version ${version.value}; runtime role grants converged."))
          .as(ExitCode.Success)
          .recoverWith:
            case refusal: DatabaseSafetyException => IO.consoleForIO.errorln(refusal.message).as(ExitCode.Error)
