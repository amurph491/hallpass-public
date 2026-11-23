package run.hallpass.gateway

import run.hallpass.application.SafeAttribute.Label

/** Route templates for telemetry. Every template is a literal; identifiers in the path become `{id}`, and anything
  * unrecognized is `other`. The raw path and query (which can carry OAuth codes and state) never reach telemetry. */
private[gateway] object RouteTemplates:
  private val Id = "[0-9a-fA-F-]{36}"
  private val AgentCredentials = s"^/api/agents/$Id/credentials$$".r
  private val AgentCredentialAction = s"^/api/agents/$Id/credentials/$Id/(revoke|rotate)$$".r
  private val DelegationRevoke = s"^/api/delegations/$Id/revoke$$".r
  private val ConnectionDisconnect = s"^/api/connections/$Id/disconnect$$".r
  private val ConnectionResources = s"^/api/connections/$Id/resources$$".r
  private val ConnectionReauthorize = s"^/api/connections/$Id/reauthorize$$".r
  private val ConnectionStart = "^/api/connections/[a-z][a-z0-9]{1,31}/start$".r
  private val OAuthCallback = "^/api/oauth/[a-z][a-z0-9]{1,31}/callback$".r
  private val ApprovalDecision = s"^/api/approvals/$Id/(approve|deny)$$".r
  private val Execution = s"^/api/executions/$Id$$".r

  def health(path: String): Option[Label] = path match
    case "/health/live"  => Some(Label.of("/health/live"))
    case "/health/ready" => Some(Label.of("/health/ready"))
    case _               => None

  def management(path: String): Label = health(path).getOrElse(path match
    case "/health"                     => Label.of("/health")
    case "/api/admin/session"          => Label.of("/api/admin/session")
    case "/api/auth/methods"           => Label.of("/api/auth/methods")
    case "/api/auth/oidc/start"        => Label.of("/api/auth/oidc/start")
    case "/api/auth/oidc/callback"     => Label.of("/api/auth/oidc/callback")
    case "/api/session"                => Label.of("/api/session")
    case "/api/session/tenant"         => Label.of("/api/session/tenant")
    case "/api/session/logout"         => Label.of("/api/session/logout")
    case "/api/agents"                 => Label.of("/api/agents")
    case "/api/resources"              => Label.of("/api/resources")
    case "/api/capabilities"           => Label.of("/api/capabilities")
    case "/api/tools"                  => Label.of("/api/tools")
    case "/api/delegations"            => Label.of("/api/delegations")
    case "/api/connections"            => Label.of("/api/connections")
    case "/api/connections/google/picker-config" => Label.of("/api/connections/google/picker-config")
    case ConnectionStart()              => Label.of("/api/connections/{provider}/start")
    case OAuthCallback()                => Label.of("/api/oauth/{provider}/callback")
    case "/api/authorization/check"    => Label.of("/api/authorization/check")
    case "/api/authorization/decisions" => Label.of("/api/authorization/decisions")
    case "/api/executions/summary"     => Label.of("/api/executions/summary")
    case "/api/executions"             => Label.of("/api/executions")
    case AgentCredentials()            => Label.of("/api/agents/{id}/credentials")
    case AgentCredentialAction(_)      => Label.of("/api/agents/{id}/credentials/{id}/action")
    case DelegationRevoke()            => Label.of("/api/delegations/{id}/revoke")
    case ConnectionDisconnect()        => Label.of("/api/connections/{id}/disconnect")
    case ConnectionResources()         => Label.of("/api/connections/{id}/resources")
    case ConnectionReauthorize()       => Label.of("/api/connections/{id}/reauthorize")
    case "/api/approvals"              => Label.of("/api/approvals")
    case ApprovalDecision("approve")   => Label.of("/api/approvals/{id}/approve")
    case ApprovalDecision("deny")      => Label.of("/api/approvals/{id}/deny")
    case Execution()                   => Label.of("/api/executions/{id}")
    case _                             => Label.of("other")
  )

  def agent(path: String): Label = health(path).getOrElse(path match
    case "/api/agent/identity"                          => Label.of("/api/agent/identity")
    case "/api/agent/tools"                             => Label.of("/api/agent/tools")
    // The concrete tool name never reaches telemetry: only the template does.
    case AgentApi.CallRoute(_)                          => Label.of("/api/agent/tools/{name}/call")
    case _                                              => Label.of("other")
  )

  def method(value: String): Label = value match
    case "GET"     => Label.of("get")
    case "HEAD"    => Label.of("head")
    case "POST"    => Label.of("post")
    case "PUT"     => Label.of("put")
    case "PATCH"   => Label.of("patch")
    case "DELETE"  => Label.of("delete")
    case "OPTIONS" => Label.of("options")
    case _         => Label.of("other")

  def statusClass(status: Int): Label = status / 100 match
    case 1 => Label.of("1xx")
    case 2 => Label.of("2xx")
    case 3 => Label.of("3xx")
    case 4 => Label.of("4xx")
    case _ => Label.of("5xx")
