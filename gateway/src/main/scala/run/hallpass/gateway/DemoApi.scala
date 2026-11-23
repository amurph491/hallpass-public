package run.hallpass.gateway

import java.net.URI
import java.net.http.HttpClient
import java.time.Instant
import java.util.UUID
import org.http4s.server.Server
import cats.effect.{IO, Resource as EffectResource}
import cats.syntax.all.*
import io.circe.{Json, JsonObject}
import io.circe.parser.parse
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*
import run.hallpass.adapters.postgres.{
  DatabaseConfig,
  DemoBootstrap,
  PostgresTenantExecutionMutationGate,
  PostgresTenantGateConfig,
  PostgresControlPlane,
  DemoRepositories,
  RepositoryConnectionResolver
}
import run.hallpass.adapters.secrets.{LocalEncryptedSecretStore, VaultTransitConfig}
import run.hallpass.adapters.slack.{SlackCapabilityCatalog, SlackOAuthConfig, SlackOAuthProvider}

/** `cookies` holds complete `Set-Cookie` values; a response may set several, which a header map cannot hold. */
private[gateway] final case class DemoApiResponse(
    status: Int,
    body: Json,
    headers: Map[String, String] = Map.empty,
    cookies: Vector[String] = Vector.empty
)

/** Browser-visible Google Picker configuration. Everything here is public by design (the OAuth client ID, the
  * referrer-restricted Picker API key, the Cloud project number); it carries no client secret and no token. */
private[gateway] final case class GooglePickerConfig(clientId: String, apiKey: String, appId: String):
  def json: Json = Json.obj(
    "clientId" -> Json.fromString(clientId),
    "apiKey" -> Json.fromString(apiKey),
    "appId" -> Json.fromString(appId),
    "scope" -> Json.fromString(GooglePickerConfig.Scope)
  )

private[gateway] object GooglePickerConfig:
  val Scope = "https://www.googleapis.com/auth/drive.file"
  /** Present only when both the Picker API key and the project number are configured. */
  def from(selection: GoogleRuntime.Selection): Option[GooglePickerConfig] =
    for
      key <- selection.client.pickerApiKey
      app <- selection.client.appId
    yield GooglePickerConfig(selection.client.clientId, key, app)

/** Validates edge DTOs and delegates typed decisions to the application layer.
  *
  * Every operation takes the request's [[AuthenticatedHuman]]; the tenant and acting principal come only from it. */
private[gateway] final class DemoApi(
    agents: AgentRepository[IO],
    authority: AuthorityRepository[IO],
    delegations: DelegationRepository[IO],
    journal: AuthorizationJournal[IO],
    catalog: ControlPlaneCatalog[IO],
  connections: ConnectionRepository[IO] = ConnectionRepository.unavailable,
  oauth: Option[OAuthConnectionService] = None,
  // Kept inside the gateway package until the separate agent HTTP boundary consumes it.
  agentCredentialServices: Option[AgentCredentialServices] = None,
  mutationGate: TenantExecutionMutationGate[IO],
  executionHistory: Option[ExecutionHistory[IO]] = None,
  clock: Clock[IO] = Clock.system,
  approvals: Option[ApprovalService] = None,
  googlePicker: Option[GooglePickerConfig] = None
):
  import DemoApi.*
  private val authorization = DynamicAuthorizationService[IO](authority, journal)

  /** Authority-changing operations hold the tenant gate exclusively through commit. If the gate is unavailable the
    * mutation never starts, so the caller receives a retryable failure rather than a partial change. */
  private def mutating(operation: IO[DemoApiResponse])(using context: AuthenticatedHuman): IO[DemoApiResponse] =
    mutationGate
      .withinMutation(context.tenant)(operation)
      .recover:
        case TenantGateException(_) =>
          error(503, "service_unavailable", "The change could not be coordinated. Try again.")

  def handle(method: String, path: String, body: Array[Byte], query: Map[String, String] = Map.empty)(using
      context: AuthenticatedHuman,
      session: OAuthSessionBinding
  ): IO[DemoApiResponse] = (method, path) match
    case ("GET", "/health")     => IO.pure(ok(Json.obj("status" -> Json.fromString("ok"))))
    case ("GET", "/api/agents") =>
      agents.list(context.tenant).map(v => ok(Json.obj("agents" -> Json.arr(v.map(agentJson)*))))
    case ("POST", "/api/agents")   => createAgent(body)
    case ("GET", CredentialCollectionPath(id))  => listAgentCredentials(id)
    case ("POST", CredentialCollectionPath(id)) => enrollAgentCredential(id, body)
    case ("POST", CredentialActionPath(agentId, credentialId, "revoke")) => revokeAgentCredential(agentId, credentialId)
    case ("POST", CredentialActionPath(agentId, credentialId, "rotate")) => rotateAgentCredential(agentId, credentialId, body)
    case ("GET", "/api/resources") =>
      catalog.resources(context.tenant).map(v => ok(Json.obj("resources" -> Json.arr(v.map(resourceJson)*))))
    case ("GET", "/api/capabilities") =>
      catalog.capabilities(context.tenant).map(v => ok(Json.obj("capabilities" -> Json.arr(v.map(capabilityJson)*))))
    case ("GET", "/api/tools") =>
      catalog.tools(context.tenant).map(v => ok(Json.obj("tools" -> Json.arr(v.map(toolJson)*))))
    case ("GET", "/api/delegations") => listDelegations
    case ("GET", "/api/connections") =>
      connections.list(context.tenant).map(v => ok(Json.obj("connections" -> Json.arr(v.map(connectionJson)*))))
    case ("GET", "/api/connections/google/picker-config") =>
      IO.pure(googlePicker match
        case Some(picker) => ok(picker.json)
        case None => error(404, "not_found", "Google Picker is not configured."))
    case ("POST", ConnectionStartPath(provider)) => startProviderOAuth(provider)
    case ("POST", "/api/connections/slack/start")  => startProviderOAuth("slack")
    case ("GET", ConnectionResourcesPath(id)) => readConnectionResources(id)
    case ("PUT", ConnectionResourcesPath(id)) => updateConnectionResources(id, body)
    case ("POST", DisconnectPath(id))              => disconnect(id)
    case ("POST", ReauthorizePath(id))             => reauthorizeConnection(id)
    case ("POST", "/api/delegations")              => createDelegation(body)
    case ("POST", RevokePath(id))                  => revokeDelegation(id)
    case ("POST", LegacyExecuteSlackSearchPath(_)) => IO.pure(legacyExecutionNotFound)
    case ("POST", "/api/authorization/check")      => authorizationCheck(body)
    case ("GET", "/api/authorization/decisions")   =>
      journal.recent(context.tenant, 50).map(v => ok(Json.obj("decisions" -> Json.arr(v.map(recordJson)*))))
    case ("GET", "/api/approvals") => listApprovals
    case ("POST", ApprovalDecisionPath(id, decision)) => decideApproval(id, decision == "approve")
    case ("GET", "/api/executions/summary") => executionSummary(query)
    case ("GET", "/api/executions") => listExecutions(query)
    case ("GET", path) if path.startsWith("/api/executions/") => getExecution(path.stripPrefix("/api/executions/"), query)
    case _ => IO.pure(error(404, "not_found", "The requested control-plane endpoint does not exist."))

  private def executionSummary(query: Map[String, String])(using context: AuthenticatedHuman): IO[DemoApiResponse] =
    val parsed =
      if !query.keySet.subsetOf(Set("agentId")) then None
      else query.get("agentId") match
        case None => Some(None)
        case Some(value) => AgentId.parse(value).toOption.map(Some(_))
    parsed match
      case None => IO.pure(error(400, "invalid_request", "A valid agent ID is required."))
      case Some(agent) => executionHistory match
        case None => IO.pure(error(503, "service_unavailable", "Execution history is unavailable."))
        case Some(history) =>
          history.hasCompletedExecution(context.tenant, agent)
            .map(completed => ok(Json.obj("hasCompletedExecution" -> Json.fromBoolean(completed))))
            .handleError(_ => error(503, "service_unavailable", "Execution history is unavailable."))

  private def listExecutions(query: Map[String, String])(using context: AuthenticatedHuman): IO[DemoApiResponse] =
    val parsed =
      if !query.keySet.subsetOf(Set("agentId", "limit", "cursor")) then None
      else
        for
          agent <- query.get("agentId") match
            case None => Some(None)
            case Some(value) => AgentId.parse(value).toOption.map(Some(_))
          limit <- query.get("limit") match
            case None => Some(50)
            case Some(value) => value.toIntOption.filter(number => number >= 1 && number <= 100)
          cursor <- query.get("cursor") match
            case None => Some(None)
            case Some(value) => ExecutionHistoryCursor.parse(value).map(Some(_))
        yield (agent, limit, cursor)
    parsed match
      case None => IO.pure(error(400, "invalid_request", "A valid agent ID, limit, and cursor are required."))
      case Some((agent, limit, cursor)) =>
        executionHistory match
          case None => IO.pure(error(503, "service_unavailable", "Execution history is unavailable."))
          case Some(history) =>
            history.page(context.tenant, agent, limit, cursor)
              .map(page => ok(Json.obj(
                "executions" -> Json.arr(page.entries.map(executionJson)*),
                "nextCursor" -> page.nextCursor.fold(Json.Null)(value => Json.fromString(value.encode))
              )))
              .handleError(_ => error(503, "service_unavailable", "Execution history is unavailable."))

  private def getExecution(rawId: String, query: Map[String, String])(using context: AuthenticatedHuman): IO[DemoApiResponse] =
    val parsed =
      if rawId.contains("/") || !query.keySet.subsetOf(Set("agentId", "limit", "cursor")) then None
      else
        for
          requestId <- AuthorizationRequestId.parse(rawId).toOption
          agent <- query.get("agentId") match
            case None => Some(None)
            case Some(value) => AgentId.parse(value).toOption.map(Some(_))
          limit <- query.get("limit") match
            case None => Some(50)
            case Some(value) => value.toIntOption.filter(number => number >= 1 && number <= 100)
          cursor <- query.get("cursor") match
            case None => Some(None)
            case Some(value) => ExecutionHistoryCursor.parse(value).map(Some(_))
        yield (requestId, agent, limit, cursor)
    parsed match
      case None => IO.pure(error(400, "invalid_request", "A valid request ID, agent ID, limit, and cursor are required."))
      case Some((requestId, agent, limit, cursor)) =>
        executionHistory match
          case None => IO.pure(error(503, "service_unavailable", "Execution history is unavailable."))
          case Some(history) =>
            history.forRequest(context.tenant, agent, requestId, limit, cursor).map: page =>
              if page.entries.isEmpty && cursor.isEmpty then error(404, "not_found", "The execution does not exist.")
              else ok(Json.obj(
                "requestId" -> Json.fromString(requestId.toString),
                "events" -> Json.arr(page.entries.map(executionJson)*),
                "nextCursor" -> page.nextCursor.fold(Json.Null)(value => Json.fromString(value.encode))
              ))
            .handleError(_ => error(503, "service_unavailable", "Execution history is unavailable."))

  private def executionJson(value: ExecutionHistoryEntry): Json = Json.obj(
    "requestId" -> Json.fromString(value.requestId.toString),
    "correlationId" -> Json.fromString(value.correlationId.value),
    "agentId" -> Json.fromString(value.agentId.toString),
    "tool" -> Json.fromString(value.tool.value),
    "capability" -> Json.fromString(value.capability),
    "eventKind" -> Json.fromString(value.eventKind.wire),
    "safeOutcome" -> Json.fromString(value.safeOutcome.wire),
    "occurredAt" -> Json.fromString(value.occurredAt.toString),
    "authorizationSource" -> value.authorizationSource.fold(Json.Null)(source => Json.fromString(source.wire))
  )

  /** The Slack OAuth callback completes only in the session, and therefore the tenant, that started it. */
  def handleCallback(providerName: String, query: Map[String, String])(using
      context: AuthenticatedHuman,
      session: OAuthSessionBinding
  ): IO[DemoApiResponse] =
    (for
      state <- query.get("state").flatMap(OAuthState.parse).toRight(())
      code <- query.get("code").map(_.trim).filter(value => value.nonEmpty && value.length <= 4096).toRight(())
      parameters <- DemoApi.callbackParameters(oauth.fold(Set.empty[String])(_.callbackParameters(providerName)), query)
    yield OAuthCallback(state, code, parameters)) match
      case Left(_)         => IO.pure(error(400, "invalid_callback", "The OAuth callback is invalid."))
      case Right(callback) =>
        oauth.filter(_.supportsProvider(providerName)).fold(IO.pure(error(503, "oauth_not_configured", "The provider connection is not configured on this server."))):
          service =>
            // The provider exchange runs outside the tenant gate; the service takes the gate only to publish.
            clock.now.flatMap(now =>
              service.completeConnection(providerName, context.tenant, context.principal, session, callback, mutationGate, now)
            )
              .recover:
                case TenantGateException(_) => Left(OAuthError.ProviderRejected)
              .map:
                case Right(connection) =>
                  // The browser returns to a fixed UI route. No OAuth callback value or credential metadata enters it.
                  DemoApiResponse(303, Json.obj(), Map("Location" -> "/admin#connections"))
                case Left(_) =>
                  DemoApiResponse(303, Json.obj(), Map("Location" -> "/admin#connections"))

  private def startProviderOAuth(providerName: String)(using context: AuthenticatedHuman, session: OAuthSessionBinding): IO[DemoApiResponse] =
    oauth.filter(_.supportsProvider(providerName)).fold(IO.pure(error(503, "oauth_not_configured", "The provider connection is not configured on this server."))): service =>
      val providerResource = providerName.toLowerCase
      catalog.resources(context.tenant).flatMap: available =>
        available.find(resource => resource.resource.resourceType == ResourceType.Provider && resource.provider.exists(_.equalsIgnoreCase(providerResource))) match
          case None => IO.pure(error(409, "provider_not_provisioned", "This provider is not provisioned for this workspace."))
          case Some(resource) =>
            mutating:
              clock.now.flatMap(now => service.startConnection(providerName, context.tenant, resource.resource.id, context.principal, session, now))
                .map:
                  case Right(uri) => ok(Json.obj("authorizationUrl" -> Json.fromString(uri.toString)))
                  case Left(_) => error(503, "connection_unavailable", "The provider connection could not be started.")

  /** Reconnects a connection whose credential needs reauthorization, keeping its grants and selections. */
  private def reauthorizeConnection(rawId: String)(using context: AuthenticatedHuman, session: OAuthSessionBinding): IO[DemoApiResponse] =
    (ConnectionId.parse(rawId).toOption, oauth) match
      case (None, _) => IO.pure(error(400, "invalid_id", "A valid connection ID is required."))
      case (_, None) => IO.pure(error(503, "oauth_not_configured", "The provider connection is not configured on this server."))
      case (Some(id), Some(service)) =>
        clock.now.flatMap(now => service.startReauthorization(context.tenant, id, context.principal, session, now)).map:
          case Right(uri) => ok(Json.obj("authorizationUrl" -> Json.fromString(uri.toString)))
          case Left(_)    => error(409, "connection_unavailable", "This connection does not need to be reconnected.")

  private def readConnectionResources(rawId: String)(using context: AuthenticatedHuman): IO[DemoApiResponse] =
    ConnectionId.parse(rawId) match
      case Left(_) => IO.pure(error(400, "invalid_id", "A valid connection ID is required."))
      case Right(id) => oauth match
        case None => IO.pure(error(503, "connection_unavailable", "Connection management is unavailable."))
        case Some(service) => service.connectionResources(context.tenant, id).map:
          case Left(_) => error(404, "not_found", "The connection does not exist or is unavailable.")
          case Right(listing) => ok(connectionResourcesJson(listing))

  private def updateConnectionResources(rawId: String, body: Array[Byte])(using context: AuthenticatedHuman): IO[DemoApiResponse] =
    val requested = parseObject(body).toOption.filter(_.keys.toSet == Set("resources"))
      .flatMap(value => value("resources")).flatMap(_.asArray)
      .flatMap(values => values.traverse(_.asString).filter(_.forall(_.length <= 600)))
    (ConnectionId.parse(rawId).toOption, requested) match
      case (None, _) => IO.pure(error(400, "invalid_id", "A valid connection ID is required."))
      case (_, None) => IO.pure(error(400, "invalid_request", "A resources array of selection keys is required."))
      case (Some(id), Some(keys)) => oauth match
        case None => IO.pure(error(503, "connection_unavailable", "Connection management is unavailable."))
        case Some(service) =>
          // Discovery runs outside the tenant gate; the service takes the gate only to replace the selection.
          service.replaceResources(context.tenant, context.principal, id, keys.toVector, mutationGate)
              .map:
                case Right(_) => DemoApiResponse(204, Json.obj())
                case Left(ConnectionResourceError.InvalidPlacement) => error(400, "invalid_selection", "One or more resources are not selectable for this connection.")
                case Left(ConnectionResourceError.NotFound) => error(404, "not_found", "The connection or selected resource does not exist.")
                case Left(_) => error(409, "connection_unavailable", "The connection selection could not be changed.")
              .recover:
                case TenantGateException(_) =>
                  error(503, "service_unavailable", "The change could not be coordinated. Try again.")

  private def disconnect(rawId: String)(using context: AuthenticatedHuman): IO[DemoApiResponse] = ConnectionId.parse(rawId) match
    case Left(_)   => IO.pure(error(400, "invalid_id", "A valid connection ID is required."))
    case Right(id) =>
      mutating:
        connections.disable(context.tenant, id)
        .map:
          case Right(_)                       => DemoApiResponse(204, Json.obj())
          case Left(ConnectionError.NotFound) => error(404, "not_found", "The connection does not exist.")
          case Left(_) => error(500, "persistence_error", "The connection could not be disconnected.")

  private def createAgent(body: Array[Byte])(using context: AuthenticatedHuman): IO[DemoApiResponse] = parseObject(body) match
    case Left(response) => IO.pure(response)
    case Right(value)   =>
      value("name").flatMap(_.asString).map(_.trim).filter(_.nonEmpty) match
        case None       => IO.pure(error(400, "invalid_request", "A non-empty agent name is required."))
        case Some(name) =>
          agents
            .create(context.tenant, CreateAgent(name, value("description").flatMap(_.asString)))
            .map:
              case Right(agent)                 => DemoApiResponse(201, agentJson(agent))
              case Left(AgentError.InvalidName) => error(400, "invalid_request", "A non-empty agent name is required.")
              case Left(_)                      => error(500, "persistence_error", "The agent could not be created.")

  private def listAgentCredentials(rawAgentId: String)(using context: AuthenticatedHuman): IO[DemoApiResponse] =
    withAgentCredentials(rawAgentId): (agentId, service) =>
      agents.find(context.tenant, agentId).flatMap:
        case None => IO.pure(error(404, "not_found", "The agent does not exist."))
        case Some(_) =>
          service.enrollment.metadataFor(context, agentId).map: values =>
            ok(Json.obj("credentials" -> Json.arr(values.map(agentCredentialMetadataJson)*)))

  private def enrollAgentCredential(rawAgentId: String, body: Array[Byte])(using context: AuthenticatedHuman): IO[DemoApiResponse] =
    withAgentCredentials(rawAgentId): (agentId, service) =>
      credentialRequest(body) match
        case Left(response) => IO.pure(response)
        case Right(request) =>
          mutating:
            clock.now.flatMap(now => service.enrollment.enroll(context, agentId, request, now)).map:
              case Right(disclosure) => createdDisclosure(disclosure)
              case Left(error)       => enrollmentError(error)

  private def revokeAgentCredential(rawAgentId: String, rawCredentialId: String)(using context: AuthenticatedHuman): IO[DemoApiResponse] =
    withAgentCredentialId(rawAgentId, rawCredentialId): (agentId, credentialId, service) =>
      mutating:
        clock.now.flatMap(now => service.enrollment.revoke(context, agentId, credentialId, now)).map:
          case Right(_) => DemoApiResponse(204, Json.obj(), Map("Cache-Control" -> "no-store"))
          case Left(error) => enrollmentError(error)

  private def rotateAgentCredential(
      rawAgentId: String,
      rawCredentialId: String,
      body: Array[Byte]
  )(using context: AuthenticatedHuman): IO[DemoApiResponse] =
    withAgentCredentialId(rawAgentId, rawCredentialId): (agentId, credentialId, service) =>
      credentialRequest(body) match
        case Left(response) => IO.pure(response)
        case Right(request) =>
          mutating:
            clock.now.flatMap(now => service.enrollment.rotate(context, agentId, credentialId, request, now)).map:
              case Right(disclosure) => createdDisclosure(disclosure)
              case Left(error)       => enrollmentError(error)

  private def withAgentCredentials(
      rawAgentId: String
  )(
      next: (AgentId, AgentCredentialServices) => IO[DemoApiResponse]
  ): IO[DemoApiResponse] =
    (AgentId.parse(rawAgentId), agentCredentialServices) match
      case (Left(_), _)       => IO.pure(error(400, "invalid_id", "A valid agent ID is required."))
      case (_, None)          => IO.pure(error(503, "service_unavailable", "Agent credential enrollment is unavailable."))
      case (Right(agent), Some(service)) => next(agent, service)

  private def withAgentCredentialId(
      rawAgentId: String,
      rawCredentialId: String
  )(
      next: (AgentId, AgentCredentialId, AgentCredentialServices) => IO[DemoApiResponse]
  ): IO[DemoApiResponse] =
    (AgentId.parse(rawAgentId), AgentCredentialId.parse(rawCredentialId), agentCredentialServices) match
      case (Left(_), _, _) => IO.pure(error(400, "invalid_id", "A valid agent ID is required."))
      case (_, Left(_), _) => IO.pure(error(400, "invalid_id", "A valid credential ID is required."))
      case (_, _, None)    => IO.pure(error(503, "service_unavailable", "Agent credential enrollment is unavailable."))
      case (Right(agent), Right(credential), Some(service)) => next(agent, credential, service)

  private def credentialRequest(body: Array[Byte]): Either[DemoApiResponse, AgentCredentialEnrollmentRequest] =
    parseObject(body).flatMap: value =>
      if !(value.keys.toSet subsetOf Set("expiresAt")) then Left(error(400, "invalid_request", "Only an optional expiresAt field is accepted."))
      else
        val expiry = value("expiresAt") match
          case None => Right(None)
          case Some(json) if json.isNull => Right(None)
          case Some(json) => json.asString.flatMap(parseInstant).toRight(error(400, "invalid_request", "expiresAt must be an ISO-8601 timestamp.")).map(Some(_))
        expiry
        .flatMap: expiry =>
          AgentCredentialEnrollmentRequest.from(None, expiry).leftMap(_ => error(400, "invalid_request", "The credential request is not valid."))

  private def createdDisclosure(disclosure: OneTimeAgentCredentialDisclosure): DemoApiResponse =
    val bytes = PresentedAgentCredential.canonicalBytes(disclosure.credential)
    try
      DemoApiResponse(
        201,
        agentCredentialMetadataJson(disclosure.metadata).deepMerge(Json.obj("credential" -> Json.fromString(String(bytes, java.nio.charset.StandardCharsets.UTF_8)))),
        Map("Cache-Control" -> "no-store", "Referrer-Policy" -> "no-referrer")
      )
    finally java.util.Arrays.fill(bytes, 0.toByte)

  private def enrollmentError(outcome: AgentEnrollmentError): DemoApiResponse = outcome match
    case AgentEnrollmentError.AgentNotFound | AgentEnrollmentError.CredentialNotFound =>
      error(404, "not_found", "The requested agent credential does not exist.")
    case AgentEnrollmentError.ExistingActiveCredential =>
      error(409, "active_credential_exists", "The agent already has an active bridge credential. Rotate it explicitly.")
    case AgentEnrollmentError.InvalidRequest(_) => error(400, "invalid_request", "The credential request is not valid.")
    case AgentEnrollmentError.PersistenceFailure => error(503, "service_unavailable", "Agent credential enrollment is unavailable.")

  private def listDelegations(using context: AuthenticatedHuman): IO[DemoApiResponse] = for
    allAgents <- agents.list(context.tenant)
    capabilities <- catalog.capabilities(context.tenant)
    values <- allAgents.traverse(a => delegations.listForGrantee(context.tenant, Principal.Agent(a.id))).map(_.flatten)
    now <- clock.now
  yield ok(Json.obj("delegations" -> Json.arr(values.map(delegationJson(_, capabilities, now))*)))

  private def createDelegation(body: Array[Byte])(using context: AuthenticatedHuman): IO[DemoApiResponse] = parseObject(body) match
    case Left(response) => IO.pure(response)
    case Right(value)   =>
      val decoded = for
        rawAgent <- value("agentId").flatMap(_.asString).toRight("agentId")
        agentId <- AgentId.parse(rawAgent).leftMap(_ => "agentId")
        capabilityId <- value("capabilityId").flatMap(_.asString).filter(isUuid).toRight("capabilityId")
        // A grant names the connection root or selected resource it covers. There is no provider-wide default: the
        // provider's catalog resource would cover every current and future connection.
        resource <- value("resourceId").flatMap(_.asString).flatMap(raw => ResourceId.parse(raw).toOption)
          .toRight("resourceId")
        expires <- value("expiresAt")
          .filterNot(_.isNull)
          .traverse(json => json.asString.flatMap(parseInstant).toRight("expiresAt"))
        constraints <- value("constraints") match
          case None => Right(Constraints.empty)
          case Some(json) => DelegationConstraintsJson.decode(json).leftMap(_ => "constraints")
      yield (agentId, capabilityId, resource, expires, constraints)
      decoded match
        case Left(field) => IO.pure(error(400, "invalid_request", s"A valid $field is required."))
        case Right((agentId, capabilityId, selectedResource, expiresAt, constraints)) =>
          for
            agent <- agents.find(context.tenant, agentId)
            capabilities <- catalog.capabilities(context.tenant)
            response <- ((agent, capabilities.find(_.id == capabilityId)) match
              case (Some(_), Some(capability)) =>
                val request = CreateDelegation(
                  context.principal,
                  Principal.Agent(agentId),
                  capability.id,
                  selectedResource,
                  capability.descriptor.action,
                  expiresAt,
                  constraints
                )
                mutating:
                  clock.now.flatMap: now =>
                    delegations.create(context.tenant, request)
                    .map:
                      case Right(created) => DemoApiResponse(201, delegationJson(created, capabilities, now))
                      case Left(DelegationError.GrantorLacksAuthority) =>
                        error(403, "authority_escalation", "The owner lacks authority to delegate this capability.")
                      case Left(DelegationError.InvalidRequest) =>
                        error(400, "invalid_request", "The delegation is not valid.")
                      case Left(_) => error(500, "persistence_error", "The delegation could not be created.")
              case _ => IO.pure(error(404, "not_found", "The agent or capability does not exist."))
            )
          yield response

  private val approvalsUnavailable = error(503, "service_unavailable", "Approvals are unavailable.")

  private def listApprovals(using context: AuthenticatedHuman): IO[DemoApiResponse] =
    approvals match
      case None => IO.pure(approvalsUnavailable)
      case Some(service) =>
        clock.now
          .flatMap(now => service.pending(context, now))
          .map(records => ok(Json.obj("approvals" -> Json.arr(records.map(approvalJson)*))))
          .handleError(_ => approvalsUnavailable)

  /** The approver is the session's human; nothing in the request names one. Deciding is an authority mutation: it runs
    * under the tenant gate, and the time is read after the gate is held. */
  private def decideApproval(rawId: String, approve: Boolean)(using context: AuthenticatedHuman): IO[DemoApiResponse] =
    approvals match
      case None => IO.pure(approvalsUnavailable)
      case Some(service) =>
        ApprovalId.parse(rawId.toLowerCase) match
          case Left(_) => IO.pure(error(400, "invalid_id", "A valid approval ID is required."))
          case Right(id) =>
            mutating:
              clock.now.flatMap(now => service.decide(context, id, approve, now)).map:
                case Right(record) => ok(approvalJson(record))
                case Left(ApprovalDecisionError.NotFound) => error(404, "not_found", "The approval does not exist.")
                case Left(ApprovalDecisionError.NotApprover) => error(403, "not_approver", "Only the approver of this request may decide it.")
                case Left(ApprovalDecisionError.AlreadyDecided) => error(409, "already_decided", "The approval was already decided.")
                case Left(ApprovalDecisionError.Expired) => error(410, "expired", "The approval has expired.")

  private def revokeDelegation(rawId: String)(using context: AuthenticatedHuman): IO[DemoApiResponse] = DelegationId.parse(rawId) match
    case Left(_)   => IO.pure(error(400, "invalid_id", "A valid delegation ID is required."))
    case Right(id) =>
      catalog
        .capabilities(context.tenant)
        .flatMap: capabilities =>
          mutating:
            clock.now.flatMap: now =>
              delegations.revoke(context.tenant, id, now)
              .map:
                case Right(value)                         => ok(delegationJson(value, capabilities, now))
                case Left(DelegationError.NotFound)       => error(404, "not_found", "The delegation does not exist.")
                case Left(DelegationError.AlreadyRevoked) =>
                  error(409, "already_revoked", "The delegation is already revoked.")
                case Left(_) => error(500, "persistence_error", "The delegation could not be revoked.")

  private def authorizationCheck(body: Array[Byte])(using context: AuthenticatedHuman): IO[DemoApiResponse] = parseObject(body) match
    case Left(response) => IO.pure(response)
    case Right(value)   =>
      val decoded = for
        rawAgent <- value("agentId").flatMap(_.asString).toRight("agentId")
        agentId <- AgentId.parse(rawAgent).leftMap(_ => "agentId")
        tool <- value("tool").flatMap(_.asString).map(_.trim).filter(_.nonEmpty).toRight("tool")
      yield agentId -> tool
      decoded match
        case Left(field)            => IO.pure(error(400, "invalid_request", s"A valid $field is required."))
        case Right((agentId, tool)) =>
          agents
            .find(context.tenant, agentId)
            .flatMap:
              case None    => IO.pure(error(404, "not_found", "The agent does not exist."))
              case Some(_) =>
                val correlationId = UUID.randomUUID().toString
                clock.now.flatMap(now => authorization.authorize(context.tenant, Principal.Agent(agentId), tool, correlationId, now))
                  .map(r => ok(decisionJson(r, correlationId)))

  private def parseObject(body: Array[Byte]): Either[DemoApiResponse, JsonObject] =
    parse(String(body, java.nio.charset.StandardCharsets.UTF_8))
      .leftMap(_ => error(400, "invalid_json", "A JSON object is required."))
      .flatMap(_.asObject.toRight(error(400, "invalid_json", "A JSON object is required.")))

private[gateway] object DemoApi:
  private val RevokePath = "^/api/delegations/([0-9a-fA-F-]{36})/revoke$".r
  /** Only provider-declared callback parameters cross the edge, each non-empty, at most 256 printable ASCII characters.
    * A declared parameter with any other value rejects the callback. They remain untrusted input. */
  private[gateway] def callbackParameters(declared: Set[String], query: Map[String, String]): Either[Unit, Map[String, String]] =
    declared.toVector.traverse: name =>
      query.get(name) match
        case None => Right(None)
        case Some(value) if value.nonEmpty && value.length <= 256 && value.forall(c => c > ' ' && c < '\u007f') =>
          Right(Some(name -> value))
        case Some(_) => Left(())
    .map(_.flatten.toMap)

  private val ApprovalDecisionPath = "^/api/approvals/([0-9a-fA-F-]{36})/(approve|deny)$".r
  private def approvalJson(record: ApprovalRecord) = Json.obj(
    "id" -> Json.fromString(record.id.toString),
    "tool" -> Json.fromString(record.tool.value),
    "operation" -> Json.fromString(record.operation.value),
    "agentId" -> Json.fromString(record.agent.toString),
    "capability" -> Json.fromString(record.requiredCapability.capability.value),
    "action" -> Json.fromString(actionWire(record.requiredCapability.action)),
    "resourceId" -> Json.fromString(record.requiredCapability.resource.toString),
    // Typed canonical input, rendered by the UI; it never carries a credential.
    "preview" -> record.preview,
    "status" -> Json.fromString(record.status.toString.toUpperCase),
    "requestedAt" -> Json.fromString(record.requestedAt.toString),
    "expiresAt" -> Json.fromString(record.expiresAt.toString),
    "decidedAt" -> record.decidedAt.fold(Json.Null)(at => Json.fromString(at.toString))
  )
  private val DisconnectPath = "^/api/connections/([0-9a-fA-F-]{36})/disconnect$".r
  private val ReauthorizePath = "^/api/connections/([0-9a-fA-F-]{36})/reauthorize$".r
  private val ConnectionStartPath = "^/api/connections/([a-z][a-z0-9]{1,31})/start$".r
  private val ConnectionResourcesPath = "^/api/connections/([0-9a-fA-F-]{36})/resources$".r
  private[gateway] val OAuthCallbackPath = "^/api/oauth/([a-z][a-z0-9]{1,31})/callback$".r
  private val CredentialCollectionPath = "^/api/agents/([0-9a-fA-F-]{36})/credentials$".r
  private val CredentialActionPath = "^/api/agents/([0-9a-fA-F-]{36})/credentials/([0-9a-fA-F-]{36})/(revoke|rotate)$".r
  private val LegacyExecuteSlackSearchPath = "^/api/agents/([0-9a-fA-F-]{36})/tools/slack_search_messages/call$".r
  private val legacyExecutionNotFound = DemoApiResponse(
    404,
    Json.obj("error" -> Json.fromString("not_found"), "message" -> Json.fromString("The requested control-plane endpoint does not exist.")),
    Map("Cache-Control" -> "no-store")
  )
  private def ok(body: Json) = DemoApiResponse(200, body)
  private def error(status: Int, code: String, message: String) =
    DemoApiResponse(status, Json.obj("error" -> Json.fromString(code), "message" -> Json.fromString(message)))
  private[gateway] def errorResponse(status: Int, code: String, message: String): DemoApiResponse = error(status, code, message)
  private def isUuid(value: String) =
    Either.catchNonFatal(UUID.fromString(value)).exists(_.toString.equalsIgnoreCase(value))
  private def parseInstant(value: String) = Either.catchNonFatal(Instant.parse(value)).toOption
  private def principalId(value: Principal) = value match
    case Principal.Human(id)   => id.toString
    case Principal.Agent(id)   => id.toString
    case Principal.Service(id) => id.toString
  private def actionWire(value: Action) = value.toString.toLowerCase
  private def agentJson(v: Agent) = Json.obj(
    "id" -> Json.fromString(v.id.toString),
    "name" -> Json.fromString(v.name),
    "description" -> v.description.fold(Json.Null)(Json.fromString),
    "createdAt" -> Json.fromString(v.createdAt.toString)
  )
  private def resourceJson(v: CatalogResource) = Json.obj(
    "id" -> Json.fromString(v.resource.id.toString),
    "name" -> Json.fromString(v.name),
    "type" -> Json.fromString(v.resource.resourceType.toString.toLowerCase),
    "provider" -> v.provider.fold(Json.Null)(Json.fromString),
    "externalId" -> Json.fromString(v.resource.externalId)
  )
  private def capabilityJson(v: CatalogCapability) = Json.obj(
    "id" -> Json.fromString(v.id),
    "name" -> Json.fromString(v.name),
    "resourceId" -> Json.fromString(v.descriptor.resource.toString),
    "action" -> Json.fromString(actionWire(v.descriptor.action))
  )
  private def toolJson(v: CatalogTool) = Json.obj(
    "name" -> Json.fromString(v.name),
    "label" -> Json.fromString(v.label),
    "resourceId" -> Json.fromString(v.resource.toString),
    "mapping" -> v.capability.fold(Json.Null)(c =>
      Json.obj(
        "capabilityId" -> Json.fromString(c.id),
        "capability" -> Json.fromString(c.name),
        "action" -> Json.fromString(actionWire(c.descriptor.action)),
        "source" -> v.mappingSource.fold(Json.Null)(Json.fromString),
        "trusted" -> Json.fromBoolean(v.trusted)
      )
    )
  )
  private def connectionJson(v: Connection) = Json.obj(
    "id" -> Json.fromString(v.id.toString),
    "resourceId" -> Json.fromString(v.resource.toString),
    "provider" -> Json.fromString(v.provider),
    "status" -> Json.fromString(if v.status == ConnectionStatus.NeedsReauth then "needs_reauth" else v.status.toString.toLowerCase),
    "accountLabel" -> v.accountLabel.fold(Json.Null)(Json.fromString),
    "externalAccountId" -> v.externalAccountId.fold(Json.Null)(Json.fromString),
    "workspaceLabel" -> v.workspaceLabel.fold(Json.Null)(Json.fromString),
    "expiresAt" -> v.expiresAt.fold(Json.Null)(x => Json.fromString(x.toString)),
    "createdAt" -> Json.fromString(v.createdAt.toString),
    "updatedAt" -> Json.fromString(v.updatedAt.toString)
  )
  private def connectionResourcesJson(value: ConnectionResourceListing) = Json.obj(
    "resources" -> Json.arr(value.current.map(resource => Json.obj(
      "id" -> Json.fromString(resource.id.toString),
      "kind" -> Json.fromString(resource.kind),
      "externalId" -> Json.fromString(resource.externalId.value),
      "name" -> Json.fromString(resource.displayName),
      "selectedAt" -> resource.selectedAt.fold(Json.Null)(at => Json.fromString(at.toString)),
      "root" -> Json.fromBoolean(resource.selectedAt.isEmpty)
    ))*),
    "available" -> Json.arr(value.available.map(resource => Json.obj(
      "selectionKey" -> Json.fromString(resource.selectionKey),
      "kind" -> Json.fromString(resource.kind.wire),
      "externalId" -> Json.fromString(resource.externalId.value),
      "name" -> Json.fromString(resource.displayName)
    ))*)
  )
  private def agentCredentialMetadataJson(value: AgentCredentialMetadata): Json = Json.obj(
    "credentialId" -> Json.fromString(value.id.toString),
    "prefix" -> Json.fromString(value.selector.value),
    "createdAt" -> Json.fromString(value.createdAt.toString),
    "expiresAt" -> value.expiresAt.fold(Json.Null)(at => Json.fromString(at.toString)),
    "revokedAt" -> value.revokedAt.fold(Json.Null)(at => Json.fromString(at.toString)),
    "lastUsedAt" -> value.lastUsedAt.fold(Json.Null)(at => Json.fromString(at.toString)),
    "label" -> value.label.fold(Json.Null)(Json.fromString)
  )
  private def delegationJson(v: Delegation, capabilities: Vector[CatalogCapability], now: Instant) =
    val descriptor = v.capabilities.toSet.head
    val capability = capabilities.find(c =>
      c.descriptor.capability == descriptor.capability && c.descriptor.action == descriptor.action
    )
    Json.obj(
      "id" -> Json.fromString(v.id.toString),
      "grantorId" -> Json.fromString(principalId(v.grantor)),
      "granteeId" -> Json.fromString(principalId(v.grantee)),
      "capabilityId" -> capability.fold(Json.Null)(c => Json.fromString(c.id)),
      "capability" -> capability.fold(Json.fromString("Unknown capability"))(c => Json.fromString(c.name)),
      "resourceId" -> Json.fromString(descriptor.resource.toString),
      "action" -> Json.fromString(actionWire(descriptor.action)),
      "constraints" -> DelegationConstraintsJson.render(v.constraints),
      "validFrom" -> Json.fromString(v.validFrom.toString),
      "expiresAt" -> v.expiresAt.fold(Json.Null)(x => Json.fromString(x.toString)),
      "revokedAt" -> v.revokedAt.fold(Json.Null)(x => Json.fromString(x.toString)),
      "status" -> Json.fromString(
        if v.revokedAt.nonEmpty then "revoked"
        else if v.expiresAt.exists(at => !at.isAfter(now)) then "expired"
        else "active"
      )
    )
  private def decisionJson(result: AuthorizationResult, correlationId: String) = result match
    case AuthorizationResult.Authorized(capability) =>
      Json.obj(
        "outcome" -> Json.fromString("allowed"),
        "authorizationSource" -> Json.fromString(AuthorizationSource.HumanPreview.wire),
        "reason" -> Json.fromString("authorized"),
        "message" -> Json.fromString("The delegated capability and owner policy allow this action."),
        "correlationId" -> Json.fromString(correlationId),
        "evidence" -> evidenceJson(
          capability.evidence.policyId,
          capability.evidence.policyVersion,
          capability.evidence.delegationIds,
          capability.evidence.requiredCapability
        )
      )
    case AuthorizationResult.Denied(reason) =>
      Json.obj(
        "outcome" -> Json.fromString("denied"),
        "authorizationSource" -> Json.fromString(AuthorizationSource.HumanPreview.wire),
        "reason" -> Json.fromString(denialCode(reason)),
        "message" -> Json.fromString(denialMessage(reason)),
        "correlationId" -> Json.fromString(correlationId)
      )
    case AuthorizationResult.ApprovalRequired(request) =>
      Json.obj(
        "outcome" -> Json.fromString("approval_required"),
        "authorizationSource" -> Json.fromString(AuthorizationSource.HumanPreview.wire),
        "reason" -> Json.fromString("approval_required"),
        "message" -> Json.fromString("An approval policy applies before this action can proceed."),
        "correlationId" -> Json.fromString(correlationId),
        "evidence" -> evidenceJson(
          request.policyId,
          request.policyVersion,
          Vector.empty,
          request.requiredCapability
        )
      )
  private def evidenceJson(
      policyId: PolicyId,
      version: PolicyVersion,
      ids: Vector[DelegationId],
      required: CapabilityDescriptor
  ) = Json.obj(
    "policyId" -> Json.fromString(policyId.toString),
    "policyVersion" -> Json.fromString(version.toString),
    "delegationIds" -> Json.arr(ids.map(x => Json.fromString(x.toString))*),
    "resourceId" -> Json.fromString(required.resource.toString),
    "action" -> Json.fromString(actionWire(required.action)),
    "capability" -> Json.fromString(required.capability.value)
  )
  private def recordJson(v: AuthorizationRecord) = Json.obj(
    "requestId" -> Json.fromString(v.requestId.toString),
    "principalId" -> Json.fromString(principalId(v.principal)),
    "tool" -> Json.fromString(v.tool),
    "resourceId" -> v.resource.fold(Json.Null)(x => Json.fromString(x.toString)),
    "action" -> v.action.fold(Json.Null)(x => Json.fromString(actionWire(x))),
    "capability" -> v.capability.fold(Json.Null)(x => Json.fromString(x.value)),
    "outcome" -> Json.fromString(v.outcome.toString.toLowerCase),
    "reason" -> Json.fromString(v.reason),
    "policyId" -> v.policyId.fold(Json.Null)(x => Json.fromString(x.toString)),
    "policyVersion" -> v.policyVersion.fold(Json.Null)(x => Json.fromString(x.toString)),
    "delegationIds" -> Json.arr(v.delegationIds.map(x => Json.fromString(x.toString))*),
    "correlationId" -> Json.fromString(v.correlationId),
    "decidedAt" -> Json.fromString(v.occurredAt.toString),
    "authorizationSource" -> v.authorizationSource.fold(Json.Null)(source => Json.fromString(source.wire))
  )
  private def denialCode(r: DenialReason) = r match
    case DenialReason.UnmappedTool                         => "unmapped_tool"
    case DenialReason.TenantMismatch                       => "tenant_mismatch"
    case DenialReason.ResourceNotSelected                  => "resource_not_selected"
    case DenialReason.CustodianMismatch                    => "custodian_mismatch"
    case DenialReason.InvalidDelegationChain               => "invalid_delegation_chain"
    case DenialReason.InactiveDelegation(_)                => "inactive_delegation"
    case DenialReason.CapabilityNotDelegated(_)            => "capability_not_delegated"
    case DenialReason.DelegationConstraintsNotSatisfied(_) => "delegation_constraints_not_satisfied"
    case DenialReason.ExplicitDeny(_, _)                   => "explicit_deny"
    case DenialReason.NoMatchingAuthority                  => "no_matching_authority"
    case DenialReason.ApprovalMismatch                     => "approval_mismatch"
  private def denialMessage(r: DenialReason) = r match
    case DenialReason.UnmappedTool              => "This tool has no trusted capability mapping, so it is denied."
    case DenialReason.InactiveDelegation(_)     => "The delegation is expired or revoked."
    case DenialReason.CapabilityNotDelegated(_) => "The agent was not delegated the required capability."
    case DenialReason.NoMatchingAuthority       => "No applicable policy grants this action."
    case DenialReason.ResourceNotSelected       => "The resource is not selected under an active connection."
    case DenialReason.CustodianMismatch         => "Only the resource's custodian can authorize access to it."
    case DenialReason.ApprovalMismatch          => "The approval does not cover this exact request, or it has expired."
    case _                                      => "Authorization was denied."

object DemoHttpServer:
  /** The management listener binds every interface inside its container; Compose publishes it only through the UI. */
  val BindHost = "0.0.0.0"
  val MethodsPath = "/api/auth/methods"
  val OidcStartPath = "/api/auth/oidc/start"
  val OidcCallbackPath = AdminHttpAuthentication.RuntimeConfig.CallbackPath
  val SessionPath = "/api/session"
  val SessionTenantPath = "/api/session/tenant"
  val LogoutPath = "/api/session/logout"

  def resource(
      api: DemoApi,
      authentication: AdminHttpAuthentication,
      tenantNames: TenantNames,
      agentPublicUrl: AgentPublicUrl,
      port: Int,
      settings: HttpListenerSettings = HttpListenerSettings.default,
      lifecycle: Option[ServerLifecycle] = None,
      telemetry: Telemetry = Telemetry.noop
  ): EffectResource[IO, Server] =
    EffectResource
      .eval(lifecycle.fold(ServerLifecycle.create(Vector.empty))(IO.pure))
      .flatMap: current =>
        HttpRuntime.serve(
          BindHost,
          port,
          settings,
          current,
          request =>
            managementResponse(api, authentication, tenantNames, agentPublicUrl, request).map: response =>
              if request.path.startsWith("/api/") then response.copy(headers = response.headers.updated("Cache-Control", "no-store"))
              else response,
          HttpObservation(telemetry, SafeAttribute.Label.of("management"), RouteTemplates.management)
        )

  private[gateway] def managementResponse(
      api: DemoApi,
      authentication: AdminHttpAuthentication,
      tenantNames: TenantNames,
      agentPublicUrl: AgentPublicUrl,
      request: EdgeRequest
  ): IO[DemoApiResponse] =
    val method = request.method
    val path = request.path
    val query = queryParams(request.uri.getRawQuery)
    (method, path) match
      case ("GET", "/health") => IO.pure(DemoApiResponse(200, Json.obj("status" -> Json.fromString("ok"))))
      case ("GET", MethodsPath) =>
        IO.pure(DemoApiResponse(200, Json.obj(
          "oidc" -> Json.fromBoolean(authentication.oidcEnabled),
          "developmentBootstrap" -> Json.fromBoolean(authentication.bootstrapEnabled)
        )))
      case ("POST", AdminHttpAuthentication.BootstrapPath) =>
        authentication.bootstrapSession(request.headers).map:
          case Right(session) =>
            DemoApiResponse(
              201,
              Json.obj("csrfToken" -> Json.fromString(session.token.csrfToken)),
              Map("Cache-Control" -> "no-store", "Referrer-Policy" -> "no-referrer"),
              Vector(authentication.cookies.session(session.token))
            )
          case Left(AdminHttpAuthentication.Rejection.LoginUnavailable) => notFound
          case Left(rejection) => adminRejection(rejection)
      case ("GET", OidcStartPath) =>
        authentication.startLogin(request.headers).map:
          case Right(redirect) =>
            DemoApiResponse(
              302,
              Json.obj(),
              Map("Location" -> redirect.authorizationUri.toString, "Referrer-Policy" -> "no-referrer"),
              Vector(authentication.cookies.login(redirect.binding))
            )
          case Left(LoginFailure.NotConfigured) => notFound
          case Left(failure)                    => loginFailed(authentication, failure)
      case ("GET", OidcCallbackPath) =>
        authentication.completeLogin(request.headers, query).map:
          case Right(session) =>
            // The browser returns to a fixed route. No callback parameter is reflected into it.
            DemoApiResponse(
              303,
              Json.obj(),
              Map("Location" -> "/admin", "Referrer-Policy" -> "no-referrer"),
              Vector(authentication.cookies.session(session.token), authentication.cookies.clearLogin)
            )
          case Left(LoginFailure.NotConfigured) => notFound
          case Left(failure)                    => loginFailed(authentication, failure)
      case ("GET", SessionPath) =>
        authentication.session(method, request.headers).flatMap:
          case Left(rejection) => IO.pure(adminRejection(rejection))
          case Right(browser)  => sessionView(authentication, tenantNames, agentPublicUrl, browser)
      case ("POST", SessionTenantPath) =>
        authentication.session(method, request.headers).flatMap:
          case Left(rejection) => IO.pure(adminRejection(rejection))
          case Right(browser) =>
            requestedTenant(request.body) match
              case None => IO.pure(DemoApi.errorResponse(400, "invalid_request", "A valid tenantId is required."))
              case Some(tenant) =>
                authentication.selectTenant(browser, tenant).map:
                  case Right(())       => DemoApiResponse(204, Json.obj())
                  case Left(rejection) => adminRejection(rejection)
      case ("POST", LogoutPath) =>
        authentication.session(method, request.headers).flatMap:
          // An already-ended session still clears the cookie.
          case Left(AdminHttpAuthentication.Rejection.MissingSession) =>
            IO.pure(DemoApiResponse(204, Json.obj(), cookies = Vector(authentication.cookies.clearSession)))
          case Left(rejection) => IO.pure(adminRejection(rejection))
          case Right(browser) =>
            authentication.logout(browser).map:
              case Right(())       => DemoApiResponse(204, Json.obj(), cookies = Vector(authentication.cookies.clearSession))
              case Left(rejection) => adminRejection(rejection)
      case _ =>
        authentication.authorize(method, request.headers).flatMap:
          case Left(rejection) => IO.pure(adminRejection(rejection))
          case Right((human, _)) if human.role != MembershipRole.Admin =>
            IO.pure(
              DemoApiResponse(
                403,
                Json.obj(
                  "error" -> Json.fromString("administrator_required"),
                  "message" -> Json.fromString("The control plane requires an administrator membership.")
                ),
                Map("Cache-Control" -> "no-store")
              )
            )
          case Right((human, browser)) =>
            given AuthenticatedHuman = human
            given OAuthSessionBinding = browser.token.oauthBinding
            // The OAuth callback is a safe-method navigation, so it needs the session but no CSRF header. The
            // single-use state is bound to the session's tenant and to the session itself.
            (method, path) match
              case ("GET", DemoApi.OAuthCallbackPath(provider)) => api.handleCallback(provider, query)
              case _ => api.handle(method, path, request.body, query)

  /** The signed-in person, the CSRF token for this session, the tenants they may select, and the public agent API
    * address to show in setup commands. The selected tenant is
    * reported only while the membership in it is current. */
  private def sessionView(
      authentication: AdminHttpAuthentication,
      tenantNames: TenantNames,
      agentPublicUrl: AgentPublicUrl,
      browser: AdminHttpAuthentication.BrowserSession
  ): IO[DemoApiResponse] =
    authentication.memberships(browser.live.user).flatMap:
      case Left(rejection) => IO.pure(adminRejection(rejection))
      case Right(memberships) =>
        memberships
          .traverse(membership => tenantNames.nameOf(membership.tenant).map(membership -> _))
          .map: named =>
            def membershipJson(membership: TenantMembership, name: Option[String]) = Json.obj(
              "tenantId" -> Json.fromString(membership.tenant.toString),
              "name" -> name.fold(Json.Null)(Json.fromString),
              "role" -> Json.fromString(membership.role.toString.toUpperCase),
              "breakGlass" -> Json.fromBoolean(membership.breakGlass.nonEmpty)
            )
            val selected = browser.live.tenant.flatMap(tenant => named.find(_._1.tenant == tenant))
            DemoApiResponse(
              200,
              Json.obj(
                "csrfToken" -> Json.fromString(browser.token.csrfToken),
                "userId" -> Json.fromString(browser.live.user.toString),
                "tenant" -> selected.fold(Json.Null)(membershipJson.tupled),
                "memberships" -> Json.arr(named.map(membershipJson.tupled)*),
                // Display only: where setup commands point a client machine. It grants and selects nothing.
                "agentApiUrl" -> Json.fromString(agentPublicUrl.value)
              ),
              Map("Cache-Control" -> "no-store")
            )
        .handleError(_ => adminRejection(AdminHttpAuthentication.Rejection.Unavailable))

  private def requestedTenant(body: Array[Byte]): Option[TenantId] =
    parse(String(body, java.nio.charset.StandardCharsets.UTF_8)).toOption
      .flatMap(_.asObject)
      .filter(_.keys.toSet == Set("tenantId"))
      .flatMap(_("tenantId").flatMap(_.asString))
      .flatMap(TenantId.parse(_).toOption)

  private val notFound: DemoApiResponse =
    DemoApi.errorResponse(404, "not_found", "The requested control-plane endpoint does not exist.")

  /** Login failures return to the sign-in page with a coarse reason and never reflect provider parameters. */
  private def loginFailed(authentication: AdminHttpAuthentication, failure: LoginFailure): DemoApiResponse =
    val reason = failure match
      case LoginFailure.Unavailable | LoginFailure.TooManyPendingLogins => "unavailable"
      case LoginFailure.UnknownIdentity | LoginFailure.NoMembership     => "no_access"
      case _                                                            => "failed"
    DemoApiResponse(
      303,
      Json.obj(),
      Map("Location" -> s"/?login=$reason", "Referrer-Policy" -> "no-referrer"),
      Vector(authentication.cookies.clearLogin)
    )

  private def adminRejection(rejection: AdminHttpAuthentication.Rejection): DemoApiResponse =
    import AdminHttpAuthentication.Rejection
    val (status, code) = rejection match
      case Rejection.InvalidBootstrap | Rejection.MissingSession | Rejection.AgentAuthenticationNotAccepted |
          Rejection.MembershipInactive => 401 -> "authentication_required"
      case Rejection.NoMembership            => 403 -> "membership_required"
      case Rejection.TenantSelectionRequired => 403 -> "tenant_selection_required"
      case Rejection.InvalidCsrf             => 403 -> "csrf_rejected"
      case Rejection.OriginRejected          => 403 -> "origin_rejected"
      case Rejection.LoginUnavailable        => 404 -> "not_found"
      case Rejection.Unavailable             => 503 -> "service_unavailable"
    val message =
      if status == 503 then "Management authentication is temporarily unavailable." else "Management authentication is required."
    DemoApiResponse(status, Json.obj("error" -> Json.fromString(code), "message" -> Json.fromString(message)), Map("Cache-Control" -> "no-store"))

  private def queryParams(raw: String | Null): Map[String, String] = Option(raw).toVector
    .flatMap(_.split("&").toVector)
    .flatMap: entry =>
      entry.split("=", 2).toList match
        case key :: value :: Nil =>
          Some(
            java.net.URLDecoder.decode(key, java.nio.charset.StandardCharsets.UTF_8) -> java.net.URLDecoder
              .decode(value, java.nio.charset.StandardCharsets.UTF_8)
          )
        case _ => None
    .toMap

/** Selects the tenant gate at the composition root. Production must use the multi-instance PostgreSQL gate. */
private[gateway] object TenantGateRuntime:
  enum Selection:
    case SingleProcess
    case Postgres(config: PostgresTenantGateConfig)

  def fromEnvironment(environment: Map[String, String] = sys.env): Either[String, Selection] =
    val production = environment.get("HALLPASS_ENV").exists(_.trim.equalsIgnoreCase("production"))
    environment.get("HALLPASS_TENANT_GATE").map(_.trim.toLowerCase).filter(_.nonEmpty) match
      case Some("postgres") => PostgresTenantGateConfig.fromEnvironment(environment).map(Selection.Postgres(_))
      case None | Some("single-process") if production =>
        Left("HALLPASS_ENV=production requires HALLPASS_TENANT_GATE=postgres; the single-process gate cannot coordinate instances")
      case None | Some("single-process") => Right(Selection.SingleProcess)
      case Some(_) => Left("HALLPASS_TENANT_GATE must be postgres or single-process")

  /** The gate plus the readiness checks it contributes. */
  def resource(
      selection: Selection,
      database: DatabaseConfig
  ): EffectResource[IO, (TenantExecutionMutationGate[IO], Vector[ServerLifecycle.ReadinessCheck])] =
    selection match
      case Selection.SingleProcess =>
        EffectResource.eval(SingleProcessTenantExecutionMutationGate.create).map(_ -> Vector.empty)
      case Selection.Postgres(config) =>
        PostgresTenantExecutionMutationGate
          .resource(database, config)
          .map(gate => gate -> Vector(ServerLifecycle.ReadinessCheck("tenant_gate", gate.healthy)))

/** Slack OAuth and the provider secret store, selected at startup.
  *
  * Slack is off when `HALLPASS_SLACK_CLIENT_ID` is unset. Once it is set, every other setting must be valid: an invalid
  * secret store or Slack setting refuses startup instead of silently disabling Slack.
  *
  * `HALLPASS_SECRET_STORE` chooses the store:
  *   - `vault-transit` (production): envelope encryption, data keys wrapped by Vault Transit (see [[VaultTransitConfig]]);
  *   - `local` (development only, and the default when unset): `LocalEncryptedSecretStore`. */
private[gateway] object OAuthRuntime:
  enum StoreSelection:
    case Local(store: LocalEncryptedSecretStore)
    case VaultTransit(config: VaultTransitConfig)

  /** `searchEndpoint` is Slack's search API. It can be overridden only in development (for a local fake provider);
    * `ProductionGuard` refuses the override, because it decides where provider tokens are sent. */
  final case class Selection(provider: SlackOAuthProvider, store: StoreSelection, searchEndpoint: URI)

  val DefaultSearchEndpoint: URI = URI.create("https://slack.com/api/search.messages")
  val SearchEndpointKey = "HALLPASS_SLACK_SEARCH_URL"

  def fromEnvironment(environment: Map[String, String] = sys.env): Either[String, Option[Selection]] =
    environment.get("HALLPASS_SLACK_CLIENT_ID").map(_.trim).filter(_.nonEmpty) match
      case None => Right(None)
      case Some(clientId) =>
        for
          clientSecret <- requiredSecret(environment, "HALLPASS_SLACK_CLIENT_SECRET")
          redirect <- required(environment, "HALLPASS_SLACK_REDIRECT_URI").flatMap(value =>
            Either.catchNonFatal(URI.create(value)).left.map(_ => "HALLPASS_SLACK_REDIRECT_URI must be a URI")
          )
          store <- storeFromEnvironment(environment)
          endpoint <- environment.get(SearchEndpointKey).map(_.trim).filter(_.nonEmpty) match
            case None => Right(DefaultSearchEndpoint)
            case Some(raw) =>
              Either
                .catchNonFatal(URI.create(raw))
                .toOption
                .filter(uri => uri.isAbsolute && uri.getHost != null && (uri.getScheme == "http" || uri.getScheme == "https"))
                .toRight(s"$SearchEndpointKey must be an absolute http(s) URL")
        yield Some(Selection(new SlackOAuthProvider(SlackOAuthConfig(clientId, clientSecret, redirect, Vector("search:read"))), store, endpoint))

  def storeFromEnvironment(environment: Map[String, String]): Either[String, StoreSelection] =
    val production = environment.get("HALLPASS_ENV").exists(_.trim.equalsIgnoreCase("production"))
    environment.get("HALLPASS_SECRET_STORE").map(_.trim.toLowerCase).filter(_.nonEmpty) match
      case Some("vault-transit") =>
        VaultTransitConfig
          .from(
            required(environment, "HALLPASS_VAULT_ADDR").getOrElse(""),
            environment.get("HALLPASS_VAULT_TOKEN_FILE").getOrElse(""),
            environment.get("HALLPASS_VAULT_TRANSIT_MOUNT").map(_.trim).filter(_.nonEmpty).getOrElse("transit"),
            environment.get("HALLPASS_VAULT_TRANSIT_KEY").map(_.trim).filter(_.nonEmpty).getOrElse("hallpass-provider-secrets"),
            environment.get("HALLPASS_VAULT_NAMESPACE").map(_.trim).filter(_.nonEmpty),
            requireHttps = production
          )
          .map(StoreSelection.VaultTransit(_))
          .left.map(error => s"Vault Transit secret store configuration is invalid: $error")
      case None | Some("local") =>
        if production then
          Left("HALLPASS_ENV=production cannot use LocalEncryptedSecretStore; set HALLPASS_SECRET_STORE=vault-transit")
        else
          for
            masterKey <- requiredSecret(environment, "HALLPASS_SECRET_MASTER_KEY")
            directory <- required(environment, "HALLPASS_SECRET_DIRECTORY")
            store <- LocalEncryptedSecretStore.create(java.nio.file.Path.of(directory), masterKey)
          yield StoreSelection.Local(store)
      case Some(_) => Left("HALLPASS_SECRET_STORE must be vault-transit or local")

  private def required(environment: Map[String, String], key: String): Either[String, String] =
    environment.get(key).map(_.trim).filter(_.nonEmpty).toRight(s"Missing $key")
  private def requiredSecret(environment: Map[String, String], key: String): Either[String, String] =
    environment.get(s"${key}_FILE").map(_.trim).filter(_.nonEmpty) match
      case Some(path) =>
        Either
          .catchNonFatal(java.nio.file.Files.readString(java.nio.file.Path.of(path)).trim)
          .left
          .map(_ => s"Unable to read ${key}_FILE")
          .flatMap(value => Either.cond(value.nonEmpty, value, s"${key}_FILE is empty"))
      case None => required(environment, key)
