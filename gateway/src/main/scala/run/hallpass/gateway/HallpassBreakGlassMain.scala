package run.hallpass.gateway

import java.time.Duration
import cats.effect.{ExitCode, IO, IOApp}
import cats.syntax.all.*
import run.hallpass.adapters.postgres.{BreakGlass, BreakGlassError, BreakGlassRequest, DatabaseConfig, DatabaseSafetyException}
import run.hallpass.application.{BreakGlassGrantId, ExternalIdentity}
import run.hallpass.kernel.TenantId

/** One-shot operator job for audited, time-boxed emergency administrator access. It runs as the schema owner
  * (`HALLPASS_DB_USER`, like `HallpassMigrateMain`); the API's runtime role cannot grant elevation.
  *
  * The person still signs in through the identity provider: there is no break-glass login. The grant makes their role
  * ADMIN in one tenant for at most four hours and adds no policy or delegation, so it can contain (revoke credentials
  * and delegations, disconnect providers) but cannot create authority.
  *
  * {{{
  * HallpassBreakGlassMain grant --tenant <tenant-id> --issuer https://idp.example.com --subject 00u1abcd \
  *   --minutes 60 --operator "alex (on-call)" --reason "INC-123: tenant administrators locked out"
  * HallpassBreakGlassMain revoke --grant <grant-id>
  * }}} */
object HallpassBreakGlassMain extends IOApp:
  private val Usage =
    """usage:
      |  HallpassBreakGlassMain grant --tenant <tenant-id> --issuer <issuer> --subject <subject> --minutes <1-240> --operator <name> --reason <reason>
      |  HallpassBreakGlassMain revoke --grant <grant-id>""".stripMargin

  enum Command:
    case Grant(request: BreakGlassRequest)
    case Revoke(grant: BreakGlassGrantId)

  private[gateway] def commandFromArguments(args: List[String]): Either[String, Command] =
    def options(remaining: List[String], parsed: Map[String, String]): Either[String, Map[String, String]] =
      remaining match
        case Nil => Right(parsed)
        case flag :: value :: rest if flag.startsWith("--") && !parsed.contains(flag) => options(rest, parsed.updated(flag, value))
        case _ => Left(Usage)
    args match
      case "grant" :: rest =>
        for
          parsed <- options(rest, Map.empty)
          _ <- Either.cond(parsed.keySet == Set("--tenant", "--issuer", "--subject", "--minutes", "--operator", "--reason"), (), Usage)
          tenant <- TenantId.parse(parsed("--tenant")).leftMap(_ => "The tenant must be a tenant ID.")
          person <- ExternalIdentity.from(parsed("--issuer"), parsed("--subject")).leftMap(error => s"The identity is invalid: $error")
          minutes <- parsed("--minutes").toLongOption.toRight("--minutes must be a number")
          request <- BreakGlassRequest
            .from(tenant, person, parsed("--reason"), parsed("--operator"), Duration.ofMinutes(minutes))
            .leftMap(error => s"The break-glass request is invalid: $error")
        yield Command.Grant(request)
      case "revoke" :: rest =>
        for
          parsed <- options(rest, Map.empty)
          _ <- Either.cond(parsed.keySet == Set("--grant"), (), Usage)
          grant <- BreakGlassGrantId.parse(parsed("--grant")).leftMap(_ => "The grant must be a grant ID.")
        yield Command.Revoke(grant)
      case _ => Left(Usage)

  def run(args: List[String]): IO[ExitCode] =
    (DatabaseConfig.fromEnvironment(sys.env), commandFromArguments(args)).tupled match
      case Left(error) => IO.consoleForIO.errorln(error).as(ExitCode.Error)
      case Right((database, command)) =>
        val outcome = command match
          case Command.Grant(request) =>
            BreakGlass.grant(database, request).flatMap:
              case Right(grant) =>
                IO.println(s"Granted break-glass ${grant.id.value} to user ${grant.user} in tenant ${request.tenant} until ${grant.expiresAt}.")
                  .as(ExitCode.Success)
              case Left(BreakGlassError.UnknownUser) =>
                IO.consoleForIO.errorln("No active directory user is linked to that identity; nothing was granted.").as(ExitCode.Error)
              case Left(BreakGlassError.UnknownTenant) =>
                IO.consoleForIO.errorln("The tenant does not exist; nothing was granted.").as(ExitCode.Error)
          case Command.Revoke(grant) =>
            BreakGlass.revoke(database, grant).flatMap:
              case true  => IO.println(s"Revoked break-glass ${grant.value}.").as(ExitCode.Success)
              case false => IO.consoleForIO.errorln("No active grant has that ID; nothing was changed.").as(ExitCode.Error)
        outcome.recoverWith:
          case refusal: DatabaseSafetyException => IO.consoleForIO.errorln(refusal.message).as(ExitCode.Error)
