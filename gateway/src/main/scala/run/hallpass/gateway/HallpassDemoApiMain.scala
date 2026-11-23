package run.hallpass.gateway

import java.net.URI
import java.net.http.HttpClient
import scala.concurrent.duration.*
import cats.effect.{ExitCode, IO, IOApp, Resource as EffectResource}
import cats.syntax.all.*
import run.hallpass.adapters.postgres.{
  DatabaseConfig,
  DatabaseSafetyException,
  DemoBootstrap,
  DemoRepositories,
  MigrationMode,
  RepositoryConnectionResolver,
  RepositoryProviderConnectionResolver
}
import run.hallpass.adapters.notion.{NotionConnector, NotionCredentials, NotionOperations}
import run.hallpass.adapters.hubspot.{HubSpot, HubSpotConnector, HubSpotCredentials, HubSpotOperations}
import run.hallpass.adapters.google.{GmailCredentials, GmailOperations, Google, GoogleConnector, GoogleDriveCredentials, GoogleDriveOperations}
import run.hallpass.adapters.linear.{Linear, LinearConnector, LinearCredentials, LinearGraphQl, LinearOperations}
import run.hallpass.adapters.oauth.{OAuthRefreshClient, OAuthTokenJsonCodec}
import run.hallpass.adapters.github.{GitHubAppClient, GitHubConnector, GitHubReadOperations, GitHubWriteOperations}
import run.hallpass.adapters.oidc.OidcIdentityProvider
import run.hallpass.adapters.secrets.{EnvelopeSecretStore, VaultTransitKeyEncryption}
import run.hallpass.adapters.slack.{
  SlackOperations,
  SlackSearchMessagesClient
}
import run.hallpass.application.*
import run.hallpass.kernel.*

/** Startup configuration parsed before any resource is acquired. Every value is validated and redacted-by-design. */
private[gateway] final case class ServerConfig(
    profile: RuntimeProfile,
    database: DatabaseConfig,
    agentCredentials: AgentCredentialRuntimeConfig,
    admin: AdminHttpAuthentication.RuntimeConfig,
    agentBinding: AgentHttpServer.Binding,
    agentPort: Int,
    agentPublicUrl: AgentPublicUrl,
    trustedProxies: Int,
    gate: TenantGateRuntime.Selection,
    migrations: MigrationMode,
    managementPort: Int,
    drainDelay: FiniteDuration,
    oauth: Option[OAuthRuntime.Selection],
    github: Option[GitHubRuntime.Selection],
    linear: Option[LinearRuntime.Selection],
    notion: Option[NotionRuntime.Selection],
    google: Option[GoogleRuntime.Selection],
    hubspot: Option[HubSpotRuntime.Selection],
    /** Present when any provider is configured. Slack's selection carries its own; GitHub alone reads the same keys. */
    secretStore: Option[OAuthRuntime.StoreSelection],
    telemetry: TelemetryRuntime.Selection
)

private[gateway] object ServerConfig:
  def fromEnvironment(args: List[String], environment: Map[String, String] = sys.env): Either[String, ServerConfig] =
    for
      profile <- RuntimeProfile.fromEnvironment(environment)
      _ <- ProductionGuard.check(profile, environment)
      database <- DatabaseConfig.fromEnvironment(environment)
      agentCredentials <- AgentCredentialRuntimeConfig
        .fromEnvironment(environment)
        .left
        .map(error => s"Agent credential configuration is invalid: $error")
      admin <- AdminHttpAuthentication.RuntimeConfig
        .fromEnvironment(environment)
        .left
        .map(error => s"Admin session configuration is invalid: $error")
      agentBinding <- AgentHttpServer.Binding
        .fromEnvironment(environment)
        .left
        .map(error => s"Agent HTTP listener configuration is invalid: $error")
      agentPort <- environment.get("HALLPASS_AGENT_HTTP_PORT").map(_.trim).filter(_.nonEmpty) match
        case None      => Right(AgentHttpServer.DefaultPort)
        case Some(raw) => raw.toIntOption.filter(port => port >= 1 && port <= 65535).toRight("HALLPASS_AGENT_HTTP_PORT must be 1-65535")
      agentPublicUrl <- AgentPublicUrl.fromEnvironment(environment, profile, agentPort)
      trustedProxies <- ClientAddress.fromEnvironment(environment)
      gate <- TenantGateRuntime.fromEnvironment(environment).left.map(error => s"Tenant gate configuration is invalid: $error")
      migrations <- MigrationMode.fromEnvironment(environment)
      managementPort <- args.headOption match
        case None      => Right(8080)
        case Some(raw) => raw.toIntOption.filter(port => port >= 1 && port <= 65535).toRight("port must be 1-65535")
      drainDelay <- drainDelay(profile, environment)
      oauth <- OAuthRuntime.fromEnvironment(environment).left.map(error => s"Slack OAuth configuration is invalid: $error")
      github <- GitHubRuntime.fromEnvironment(environment).left.map(error => s"GitHub App configuration is invalid: $error")
      linear <- LinearRuntime.fromEnvironment(environment).left.map(error => s"Linear OAuth configuration is invalid: $error")
      notion <- NotionRuntime.fromEnvironment(environment).left.map(error => s"Notion OAuth configuration is invalid: $error")
      google <- GoogleRuntime.fromEnvironment(environment).left.map(error => s"Google Drive configuration is invalid: $error")
      hubspot <- HubSpotRuntime.fromEnvironment(environment).left.map(error => s"HubSpot OAuth configuration is invalid: $error")
      secretStore <- oauth match
        case Some(slack) => Right(Some(slack.store))
        case None if github.nonEmpty || linear.nonEmpty || notion.nonEmpty || google.nonEmpty || hubspot.nonEmpty => OAuthRuntime.storeFromEnvironment(environment).map(Some(_))
        case None => Right(None)
      telemetry <- TelemetryRuntime.fromEnvironment(environment).left.map(error => s"Telemetry configuration is invalid: $error")
    yield ServerConfig(profile, database, agentCredentials, admin, agentBinding, agentPort, agentPublicUrl, trustedProxies, gate, migrations, managementPort, drainDelay, oauth, github, linear, notion, google, hubspot, secretStore, telemetry)

  def drainDelay(profile: RuntimeProfile, environment: Map[String, String]): Either[String, FiniteDuration] =
    environment.get("HALLPASS_SHUTDOWN_DRAIN_DELAY_MS").map(_.trim).filter(_.nonEmpty) match
      case None => Right(profile.defaultDrainDelay)
      case Some(raw) =>
        raw.toLongOption
          .filter(value => value >= 0 && value <= 120000)
          .map(_.millis)
          .toRight("HALLPASS_SHUTDOWN_DRAIN_DELAY_MS must be between 0 and 120000")

/** Imperative shell for the management and agent listeners.
  *
  * Shutdown order is the reverse of acquisition: readiness fails and the drain delay elapses first, then each listener
  * stops accepting and waits for in-flight requests, and only then are the gate and database pools closed. */
object HallpassDemoApiMain extends IOApp:
  /** Configuration and database-safety refusals are operator-facing and already redacted, so they are printed without
    * a stack trace. */
  def run(args: List[String]): IO[ExitCode] =
    ServerConfig.fromEnvironment(args) match
      case Left(error) => IO.consoleForIO.errorln(error).as(ExitCode.Error)
      case Right(config) =>
        server(config).useForever.recoverWith:
          case refusal: DatabaseSafetyException => IO.consoleForIO.errorln(refusal.message).as(ExitCode.Error)

  private[gateway] def server(config: ServerConfig): EffectResource[IO, Unit] =
    for
      telemetry <- TelemetryRuntime.resource(config.telemetry)
      repositories <- DemoRepositories.resource(config.database, config.migrations)
      identityProvider <- EffectResource.eval(config.admin.oidc.traverse(OidcIdentityProvider.create(_)))
      humans = new HumanAuthenticator[IO](repositories.directory)
      adminAuthentication = AdminHttpAuthentication.create(
        config.admin,
        HumanLogin(
          identityProvider,
          repositories.browserSessions,
          repositories.browserSessions,
          humans,
          config.admin.policy,
          telemetry = telemetry
        ),
        repositories.browserSessions,
        humans,
        DemoBootstrap.DevelopmentAdministrator,
        telemetry = telemetry
      )
      (rawGate, gateChecks) <- TenantGateRuntime.resource(config.gate, config.database)
      gate = Instrumented.gate(rawGate, telemetry)
      limiter <- EffectResource.eval(FailedAuthenticationLimiter.create())
      recentRejections <- EffectResource.eval(RecentAgentRejections.create())
      // Refreshable providers share one refresh single-flight repository (its own lock pool), each with a bounded
      // token client for its own endpoint and client.
      refreshRepository <- Option.when(config.linear.nonEmpty || config.google.nonEmpty || config.hubspot.nonEmpty)(()).traverse(_ => repositories.oauthRefresh)
      linearRefresh <- (config.linear, refreshRepository).tupled.traverse: (linear, repository) =>
        refreshClient("Linear", linear.endpoints.token, linear.client.clientId, linear.client.secretForRefresh, config.profile)
          .map(repository -> _)
      googleRefresh <- (config.google, refreshRepository).tupled.traverse: (google, repository) =>
        refreshClient("Google", google.endpoints.token, google.client.clientId, google.client.secretForRefresh, config.profile)
          .map(repository -> _)
      hubspotRefresh <- (config.hubspot, refreshRepository).tupled.traverse: (hubspot, repository) =>
        refreshClient("HubSpot", hubspot.endpoints.token, hubspot.client.clientId, hubspot.client.secretForRefresh, config.profile)
          .map(repository -> _)
      (api, agentApi) <- EffectResource.eval(
        services(config, repositories, gate, telemetry, limiter, recentRejections, linearRefresh, googleRefresh, hubspotRefresh)
      )
      lifecycle <- EffectResource.eval(
        ServerLifecycle.create(ServerLifecycle.ReadinessCheck("database", repositories.schemaReady) +: gateChecks)
      )
      _ <- DemoHttpServer.resource(
        api,
        adminAuthentication,
        repositories.controlPlane,
        config.agentPublicUrl,
        config.managementPort,
        lifecycle = Some(lifecycle),
        telemetry = telemetry
      )
      _ <- AgentHttpServer.resource(
        agentApi,
        port = config.agentPort,
        binding = config.agentBinding,
        lifecycle = Some(lifecycle),
        telemetry = telemetry
      )
      _ <- EffectResource.onFinalize(lifecycle.beginDraining *> IO.sleep(config.drainDelay))
    yield ()

  private def services(
      config: ServerConfig,
      repositories: DemoRepositories,
      gate: TenantExecutionMutationGate[IO],
      telemetry: Telemetry,
      limiter: FailedAuthenticationLimiter,
      recentRejections: RecentAgentRejections,
      linearRefresh: Option[(OAuthRefreshRepository, OAuthTokenRefresher)],
      googleRefresh: Option[(OAuthRefreshRepository, OAuthTokenRefresher)],
      hubspotRefresh: Option[(OAuthRefreshRepository, OAuthTokenRefresher)]
  ): IO[(DemoApi, AgentApi)] =
    val repository = repositories.controlPlane
    // Every decision (agent calls and human previews) and every execution audit event is counted and traced.
    val journal = Instrumented.journal(repository, telemetry)
    val executionAudit = Instrumented.executionAudit(repositories.executionAudit, telemetry)
    val protection = (limiter: FailedAuthenticationLimiter) =>
      AgentAuthenticationProtection(
        Some(limiter),
        repositories.agentAuthenticationLockout,
        config.trustedProxies,
        Some(recentRejections)
      )
    val connectionRepository = repositories.connections
    val agentCredentials = AgentCredentialServices.compose(
      config.agentCredentials,
      repositories.agentCredentials,
      repositories.directory
    )
    config.secretStore match
      case None =>
        IO.pure(
          DemoApi(
            repository,
            repository,
            repository,
            journal,
            repository,
            connectionRepository,
            agentCredentialServices = Some(agentCredentials),
            mutationGate = gate,
            executionHistory = Some(repositories.executionAudit)
          ) -> AgentApi(AgentApiDependencies(agentCredentials, None, protection(limiter)), telemetry = telemetry)
        )
      case Some(selection) =>
        // Never follow a redirect: provider clients attach bearer credentials, and a followed redirect would replay
        // them to another origin before any status check runs.
        val httpClient = HttpClient.newBuilder()
          .connectTimeout(java.time.Duration.ofSeconds(5))
          .followRedirects(HttpClient.Redirect.NEVER)
          .build()
        for
          secrets <- secretStore(selection, repositories).map(Instrumented.secretStore(_, telemetry))
          leases <- InMemoryExecutionLeaseStore.create
          authority = new DurableLeaseAuthorityValidator(
            new CurrentStateExecutionRevalidator(repositories.agentCredentials, repository, repository, repository)
          )
          executor = new ProviderExecutionService(leases, Clock.system, executionAudit, authority, gate, telemetry)
          connections = Instrumented.connectionResolver(new RepositoryConnectionResolver(connectionRepository, secrets), telemetry)
          providerConnections = repositories.providerConnections(secrets)
          slack = config.oauth.map: slack =>
            (slack.provider: ProviderConnector) ->
              Vector(SlackOperations.searchMessages(new SlackSearchMessagesClient(slack.searchEndpoint, httpClient), connections))
          github = config.github.map: github =>
            val app = new GitHubAppClient(github.registration, github.secrets, github.endpoints, httpClient, Clock.system)
            (new GitHubConnector(github.registration, app, github.endpoints, github.redirectUri): ProviderConnector) ->
              (GitHubReadOperations.all(github.registration, providerConnections, app, github.endpoints, httpClient) ++
                GitHubWriteOperations.all(github.registration, providerConnections, app, github.endpoints, httpClient))
          linear = (config.linear, linearRefresh).tupled.map: (linear, refresh) =>
            val graphql = new LinearGraphQl(linear.endpoints, httpClient)
            val oauth = new RefreshableOAuth[Linear.Team](
              ProviderId.Linear, refresh._1, secrets, new OAuthTokenJsonCodec, refresh._2, Clock.system, RefreshTokenRotation.Rotating
            )
            (new LinearConnector(linear.client, linear.endpoints, graphql, httpClient, Clock.system, linear.redirectUri): ProviderConnector) ->
              LinearOperations.all(new LinearCredentials(oauth), graphql)
          notion = config.notion.map: notion =>
            (new NotionConnector(notion.client, notion.endpoints, httpClient, notion.redirectUri): ProviderConnector) ->
              NotionOperations.all(new NotionCredentials(providerConnections), notion.endpoints, httpClient)
          google = (config.google, googleRefresh).tupled.map: (google, refresh) =>
            val oauth = new RefreshableOAuth[Google.DriveFile](
              ProviderId.Google, refresh._1, secrets, new OAuthTokenJsonCodec, refresh._2, Clock.system, RefreshTokenRotation.NonRotating
            )
            // Gmail send is opt-in per deployment; the mailbox has its own strategy over the same refresh
            // repository and token client, so refresh stays single-flight per connection.
            val gmail =
              if !google.gmailSend then Vector.empty
              else
                val mailboxOAuth = new RefreshableOAuth[Google.Mailbox](
                  ProviderId.Google, refresh._1, secrets, new OAuthTokenJsonCodec, refresh._2, Clock.system, RefreshTokenRotation.NonRotating
                )
                GmailOperations.all(new GmailCredentials(mailboxOAuth), google.endpoints, httpClient)
            (new GoogleConnector(google.client, google.endpoints, httpClient, Clock.system, google.redirectUri, gmailSend = google.gmailSend): ProviderConnector) ->
              (GoogleDriveOperations.all(new GoogleDriveCredentials(oauth), google.endpoints, httpClient) ++ gmail)
          hubspot = (config.hubspot, hubspotRefresh).tupled.map: (hubspot, refresh) =>
            // HubSpot documents no refresh-token rotation; NonRotating keeps the stored refresh token.
            val oauth = new RefreshableOAuth[HubSpot.ObjectType](
              ProviderId.HubSpot, refresh._1, secrets, new OAuthTokenJsonCodec, refresh._2, Clock.system, RefreshTokenRotation.NonRotating
            )
            (new HubSpotConnector(hubspot.client, hubspot.endpoints, httpClient, Clock.system, hubspot.redirectUri): ProviderConnector) ->
              HubSpotOperations.all(new HubSpotCredentials(oauth), hubspot.endpoints, httpClient)
          providers = slack.toVector ++ github.toVector ++ linear.toVector ++ notion.toVector ++ google.toVector ++ hubspot.toVector
          registry <- IO.fromEither(
            OperationRegistry
              .from(providers.flatMap(_._2))
              .leftMap(error => IllegalStateException(s"invalid operation registry: $error"))
          )
          connectors = providers.map(_._1)
          oauth = new OAuthConnectionService(
            repositories.oauthStates,
            connectionRepository,
            secrets,
            repositories.connectionResources,
            connectors,
            tokenCodec = Some(new _root_.run.hallpass.adapters.oauth.OAuthTokenJsonCodec)
          )
          broker = new InMemoryCredentialBroker(
            leases,
            Clock.system,
            java.time.Duration.ofMinutes(1),
            executionAudit
          )
          agentTools = AgentToolService(
            registry, ResourceResolver(repository), repository, journal, broker, executor, telemetry, repositories.approvals
          )
        yield DemoApi(
          repository,
          repository,
          repository,
          journal,
          repository,
          connectionRepository,
          Some(oauth),
          Some(agentCredentials),
          gate,
          Some(repositories.executionAudit),
          approvals = Some(ApprovalService(repositories.approvals)),
          googlePicker = config.google.flatMap(GooglePickerConfig.from)
        ) -> AgentApi(AgentApiDependencies(agentCredentials, Some(agentTools), protection(limiter)), telemetry = telemetry)

  private def refreshClient(
      name: String,
      endpoint: URI,
      clientId: String,
      secret: String,
      profile: RuntimeProfile
  ): EffectResource[IO, OAuthRefreshClient] =
    EffectResource
      .eval(IO.fromEither(
        OAuthRefreshClient.Config
          .from(endpoint, clientId, secret, allowHttpLoopback = profile != RuntimeProfile.Production)
          .leftMap(_ => IllegalStateException(s"$name token endpoint must be https (or numeric loopback in development)"))
      ))
      .flatMap(OAuthRefreshClient.resource(_, Clock.system))

  /** The development file store, or envelope encryption with Vault Transit wrapping each data key. */
  private def secretStore(selection: OAuthRuntime.StoreSelection, repositories: DemoRepositories): IO[SecretStore[IO]] =
    selection match
      case OAuthRuntime.StoreSelection.Local(store) => IO.pure(store)
      case OAuthRuntime.StoreSelection.VaultTransit(vault) =>
        VaultTransitKeyEncryption.create(vault).map(keys => EnvelopeSecretStore(keys, repositories.providerSecrets))
