package run.hallpass.gateway

import scala.concurrent.duration.*

/** The deployment profile. It is required so a missing variable can never silently select development behavior. */
enum RuntimeProfile:
  case Development
  case Production

object RuntimeProfile:
  val EnvironmentKey = "HALLPASS_ENV"

  def fromEnvironment(environment: Map[String, String] = sys.env): Either[String, RuntimeProfile] =
    environment.get(EnvironmentKey).map(_.trim.toLowerCase) match
      case Some("development") => Right(Development)
      case Some("production")  => Right(Production)
      case Some(_)             => Left(s"$EnvironmentKey must be development or production")
      case None                => Left(s"$EnvironmentKey is required and must be development or production")

  extension (profile: RuntimeProfile)
    /** Time between failing readiness and closing listeners, so a load balancer stops routing before shutdown. */
    def defaultDrainDelay: FiniteDuration = profile match
      case Development => Duration.Zero
      case Production  => 10.seconds

/** Components that are acceptable for a local single-tenant demo but unsafe for production traffic. Descriptions are
  * operator-facing. */
enum DevelopmentOnlyComponent(val description: String):
  case DemoCatalogSeed
      extends DevelopmentOnlyComponent(
        "demo tenant seeding at startup (in-process migrations); provision tenants with HallpassProvisionMain"
      )
  case AdminBootstrapSecret
      extends DevelopmentOnlyComponent(
        "shared bootstrap-header admin login as the development identity; unset HALLPASS_ADMIN_BOOTSTRAP(_FILE) and sign in with OIDC (HALLPASS_OIDC_ISSUER)"
      )
  case InProcessMigrations
      extends DevelopmentOnlyComponent(
        "schema migrations run by the API under its runtime role; run HallpassMigrateMain as a separate owner role and set HALLPASS_DB_MIGRATIONS=external"
      )
  case LocalEncryptedSecretStore
      extends DevelopmentOnlyComponent(
        "file-backed LocalEncryptedSecretStore; set HALLPASS_SECRET_STORE=vault-transit and remove HALLPASS_SECRET_DIRECTORY and HALLPASS_SECRET_MASTER_KEY(_FILE)"
      )
  case SingleProcessTenantGate
      extends DevelopmentOnlyComponent(
        "single-process tenant gate; set HALLPASS_TENANT_GATE=postgres to coordinate multiple instances"
      )
  case ProviderEndpointOverride
      extends DevelopmentOnlyComponent(
        "overridden provider endpoint (HALLPASS_SLACK_SEARCH_URL, HALLPASS_GITHUB_API_URL, HALLPASS_GITHUB_WEB_URL, HALLPASS_LINEAR_AUTHORIZE_URL, HALLPASS_LINEAR_EXCHANGE_URL, HALLPASS_LINEAR_GRAPHQL_URL, HALLPASS_NOTION_AUTHORIZE_URL, HALLPASS_NOTION_API_URL, HALLPASS_GOOGLE_AUTHORIZE_URL, HALLPASS_GOOGLE_EXCHANGE_URL, HALLPASS_GOOGLE_USERINFO_URL, HALLPASS_GOOGLE_DRIVE_API_URL, HALLPASS_HUBSPOT_AUTHORIZE_URL or HALLPASS_HUBSPOT_API_URL); production sends provider tokens and App JWTs only to Slack, github.com, Linear, Notion, Google and HubSpot"
      )
  case LoopbackAgentListener
      extends DevelopmentOnlyComponent(
        "agent listener bound to loopback; production serves it behind an ingress (HALLPASS_AGENT_HTTP_BIND_HOST=0.0.0.0)"
      )

/** Capabilities a production deployment needs. Configurable ones are unmet until configured. Structural ones are
  * capabilities this release does not have at all; production stays refused until none remain. */
enum MissingProductionRequirement(val description: String):
  case KmsSecretStore
      extends MissingProductionRequirement(
        "a KMS-backed provider secret store; set HALLPASS_SECRET_STORE=vault-transit with HALLPASS_VAULT_ADDR, HALLPASS_VAULT_TOKEN_FILE, and a derived aes256-gcm96 transit key"
      )
  case Observability
      extends MissingProductionRequirement(
        "OpenTelemetry export; set OTEL_EXPORTER_OTLP_ENDPOINT to an https collector and load deploy/observability/alerts.yaml"
      )
  case TrustedProxyCount
      extends MissingProductionRequirement(
        "an explicit HALLPASS_TRUSTED_PROXY_COUNT: the number of proxies in front of the agent listener that append X-Forwarded-For (1 behind the example ingress, 0 if none)"
      )
  case AgentPublicUrl
      extends MissingProductionRequirement(
        "an explicit HALLPASS_AGENT_PUBLIC_URL: the https URL client machines use to reach the agent API (for example https://agents.example.com); the admin UI puts it in setup commands"
      )

object MissingProductionRequirement:
  /** Capabilities not built yet. There are none, and production starts once every configurable requirement is met. */
  val structural: Vector[MissingProductionRequirement] = Vector.empty

/** Refuses to start a production profile while any development-only component is in use or a production requirement
  * is unmet.
  *
  * This is a pure function of configuration so each refusal is testable without starting a server. Structural
  * requirements list capabilities that must exist before production may start. */
object ProductionGuard:
  def missingRequirements(environment: Map[String, String]): Vector[MissingProductionRequirement] =
    Option.unless(environment.get("HALLPASS_SECRET_STORE").exists(_.trim.equalsIgnoreCase("vault-transit")))(
      MissingProductionRequirement.KmsSecretStore
    ).toVector ++
      Option.unless(environment.get(TelemetryRuntime.EndpointKey).exists(_.trim.toLowerCase.startsWith("https://")))(
        MissingProductionRequirement.Observability
      ) ++
      // Wrong in either direction is harmful (throttling the whole ingress, or trusting forged headers), so production
      // must state it rather than inherit the development default.
      Option.unless(environment.get(ClientAddress.TrustedProxiesKey).exists(_.trim.nonEmpty))(
        MissingProductionRequirement.TrustedProxyCount
      ) ++
      // There is no correct default: loopback works only on the server's own machine, and every setup command the UI
      // renders would point clients at it. The value's syntax is checked when the server configuration is parsed.
      Option.unless(environment.get(AgentPublicUrl.Key).exists(_.trim.nonEmpty))(
        MissingProductionRequirement.AgentPublicUrl
      ) ++ MissingProductionRequirement.structural

  def componentsInUse(environment: Map[String, String]): Vector[DevelopmentOnlyComponent] =
    def present(key: String) = environment.get(key).exists(_.trim.nonEmpty)
    val bootstrap = Option.when(present("HALLPASS_ADMIN_BOOTSTRAP") || present("HALLPASS_ADMIN_BOOTSTRAP_FILE"))(
      DevelopmentOnlyComponent.AdminBootstrapSecret
    )
    // In-process mode is also the only mode that seeds the demo tenant (see DemoRepositories.resource).
    val migrations =
      if environment.get("HALLPASS_DB_MIGRATIONS").exists(_.trim.equalsIgnoreCase("external")) then Vector.empty
      else Vector(DevelopmentOnlyComponent.InProcessMigrations, DevelopmentOnlyComponent.DemoCatalogSeed)
    val secretStore = Option.when(
      present("HALLPASS_SECRET_DIRECTORY") || present("HALLPASS_SECRET_MASTER_KEY") || present("HALLPASS_SECRET_MASTER_KEY_FILE") ||
        environment.get("HALLPASS_SECRET_STORE").exists(_.trim.equalsIgnoreCase("local"))
    )(DevelopmentOnlyComponent.LocalEncryptedSecretStore)
    val gate = Option.unless(environment.get("HALLPASS_TENANT_GATE").exists(_.trim.equalsIgnoreCase("postgres")))(
      DevelopmentOnlyComponent.SingleProcessTenantGate
    )
    val agentBinding = Option.unless(environment.get("HALLPASS_AGENT_HTTP_BIND_HOST").exists(_.trim == "0.0.0.0"))(
      DevelopmentOnlyComponent.LoopbackAgentListener
    )
    val providerEndpoint = Option.when(present("HALLPASS_SLACK_SEARCH_URL") || present(GitHubRuntime.ApiUrlKey) || present(GitHubRuntime.WebUrlKey) || LinearRuntime.EndpointOverrideKeys.exists(present) || NotionRuntime.EndpointOverrideKeys.exists(present) || GoogleRuntime.EndpointOverrideKeys.exists(present) || HubSpotRuntime.EndpointOverrideKeys.exists(present))(DevelopmentOnlyComponent.ProviderEndpointOverride)
    bootstrap.toVector ++ migrations ++ secretStore ++ gate ++ agentBinding ++ providerEndpoint

  def check(profile: RuntimeProfile, environment: Map[String, String]): Either[String, Unit] =
    profile match
      case RuntimeProfile.Development => Right(())
      case RuntimeProfile.Production =>
        val components = componentsInUse(environment)
        val missing = missingRequirements(environment)
        Either.cond(
          components.isEmpty && missing.isEmpty,
          (),
          (Vector("HALLPASS_ENV=production refused:") ++
            Option.when(components.nonEmpty)("development-only components are in use:") ++
            components.map(component => s"  - ${component.description}") ++
            Option.when(missing.nonEmpty)("production requirements are not met:") ++
            missing.map(requirement => s"  - ${requirement.description}")).mkString("\n")
        )
