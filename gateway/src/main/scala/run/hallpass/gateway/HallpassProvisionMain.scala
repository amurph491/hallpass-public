package run.hallpass.gateway

import cats.effect.{ExitCode, IO, IOApp}
import cats.syntax.all.*
import run.hallpass.adapters.postgres.{DatabaseConfig, DatabaseSafetyException, ExistingTenantProvider, ProviderCatalogProvisioning, TenantProvisioning, TenantProvisioningRequest}
import run.hallpass.application.ExternalIdentity

/** One-shot operator job that creates a tenant. The API cannot: its runtime role only reads tenants, the provider
  * catalog, and policies, and it has no access to the identity directory.
  *
  * It connects as the schema owner (`HALLPASS_DB_USER`, the same role as `HallpassMigrateMain`) and, in one transaction,
  * creates the tenant, the Slack provider catalog, the first administrator's human principal with owner policies, and
  * that administrator's directory user and membership. The administrator is named by their identity-provider account
  * (issuer and subject), which OIDC login resolves.
  *
  * {{{
  * HallpassProvisionMain --name "Example Corp" --slug example \
  *   --admin-issuer https://idp.example.com --admin-subject 00u1abcd
  * }}}
  *
  * The second form adds a provider catalog to a tenant that already exists, as the owner and idempotently. Its
  * owner policies allow administrator reads and provider-specific writes; Notion append requires approval.
  * `github`, `linear`, `notion`, `google` and `hubspot` are accepted; HubSpot deal updates require approval.
  *
  * {{{
  * HallpassProvisionMain --tenant-slug example --provider github
  * }}} */
object HallpassProvisionMain extends IOApp:
  private val Usage =
    "usage: HallpassProvisionMain --name <tenant name> --slug <tenant-slug> --admin-issuer <issuer> --admin-subject <subject>\n" +
      "   or: HallpassProvisionMain --tenant-slug <tenant-slug> --provider <github|linear|notion|google|hubspot>"

  /** Adds a provider catalog to an existing tenant. */
  private[gateway] final case class AddProviderRequest(slug: String, provider: ExistingTenantProvider)

  private def optionMap(remaining: List[String], parsed: Map[String, String]): Either[String, Map[String, String]] =
    remaining match
      case Nil                                                                       => Right(parsed)
      case flag :: value :: rest if flag.startsWith("--") && !parsed.contains(flag) => optionMap(rest, parsed.updated(flag, value))
      case _                                                                         => Left(Usage)

  private[gateway] def addProviderFromArguments(args: List[String]): Either[String, AddProviderRequest] =
    for
      parsed <- optionMap(args, Map.empty)
      _ <- Either.cond(parsed.keySet == Set("--tenant-slug", "--provider"), (), Usage)
      provider <- ExistingTenantProvider.parse(parsed("--provider")).toRight(Usage)
    yield AddProviderRequest(parsed("--tenant-slug"), provider)

  private[gateway] def requestFromArguments(args: List[String]): Either[String, TenantProvisioningRequest] =
    def options(remaining: List[String], parsed: Map[String, String]): Either[String, Map[String, String]] =
      remaining match
        case Nil                                                => Right(parsed)
        case flag :: value :: rest if flag.startsWith("--") && !parsed.contains(flag) => options(rest, parsed.updated(flag, value))
        case _                                                  => Left(Usage)
    for
      parsed <- options(args, Map.empty)
      _ <- Either.cond(parsed.keySet == Set("--name", "--slug", "--admin-issuer", "--admin-subject"), (), Usage)
      administrator <- ExternalIdentity
        .from(parsed("--admin-issuer"), parsed("--admin-subject"))
        .leftMap(error => s"The administrator identity is invalid: $error")
      request <- TenantProvisioningRequest
        .from(parsed("--name"), parsed("--slug"), administrator)
        .leftMap(error => s"The tenant is invalid: $error")
    yield request

  def run(args: List[String]): IO[ExitCode] =
    if args.contains("--tenant-slug") then addProvider(args) else createTenant(args)

  private def addProvider(args: List[String]): IO[ExitCode] =
    (DatabaseConfig.fromEnvironment(sys.env), addProviderFromArguments(args)).tupled match
      case Left(error) => IO.consoleForIO.errorln(error).as(ExitCode.Error)
      case Right((database, request)) =>
        ProviderCatalogProvisioning
          .addToExisting(database, request.slug, request.provider)
          .flatMap:
            case None =>
              IO.consoleForIO.errorln(s"No tenant with slug ${request.slug} exists; nothing was changed.").as(ExitCode.Error)
            case Some(added) =>
              IO.println(
                if added.written then
                  s"Added the ${request.provider} catalog to tenant ${added.tenant} (${request.slug}); Owner policies bound to ${added.administrators} administrator(s)."
                else s"Tenant ${added.tenant} (${request.slug}) already has the ${request.provider} catalog; nothing was changed."
              ).as(ExitCode.Success)
          .recoverWith:
            case refusal: DatabaseSafetyException => IO.consoleForIO.errorln(refusal.message).as(ExitCode.Error)

  private def createTenant(args: List[String]): IO[ExitCode] =
    (DatabaseConfig.fromEnvironment(sys.env), requestFromArguments(args)).tupled match
      case Left(error) => IO.consoleForIO.errorln(error).as(ExitCode.Error)
      case Right((database, request)) =>
        TenantProvisioning
          .provision(database, request)
          .flatMap: provisioned =>
            IO.println(
              s"Provisioned tenant ${provisioned.tenant} (${request.slug}); administrator user ${provisioned.administrator}, principal ${provisioned.administratorPrincipal.id}."
            )
          .as(ExitCode.Success)
          .recoverWith:
            case refusal: DatabaseSafetyException => IO.consoleForIO.errorln(refusal.message).as(ExitCode.Error)
            case duplicate: java.sql.SQLException if duplicate.getSQLState == "23505" =>
              IO.consoleForIO.errorln(s"A tenant with slug ${request.slug} already exists; nothing was changed.").as(ExitCode.Error)
