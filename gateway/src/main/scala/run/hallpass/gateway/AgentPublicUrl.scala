package run.hallpass.gateway

import java.net.URI
import scala.util.Try

/** The address a client machine uses to reach the agent API, as the administrator's browser should display it in
  * setup commands. It is display configuration only: it names where a bridge sends its agent credential and is never
  * used to select a tenant, authenticate, or authorize anything.
  *
  * It follows the same rule as the bridge's endpoint (`BridgeConfig`): `https` to one exact host, or `http` to a
  * numeric loopback address, with an optional port and no user info, path, query, or fragment. A value the bridge would
  * refuse is refused here, so the UI never renders a command that cannot work. The stored form is `scheme://authority`
  * with no trailing slash. */
final class AgentPublicUrl private (val value: String):
  override def toString: String = value
  override def equals(other: Any): Boolean = other match
    case that: AgentPublicUrl => that.value == value
    case _                    => false
  override def hashCode: Int = value.hashCode

object AgentPublicUrl:
  val Key = "HALLPASS_AGENT_PUBLIC_URL"

  /** Parses the endpoint rule. Production additionally requires `https`, because a loopback address cannot be reached
    * from the machines an administrator is configuring. */
  def parse(raw: String, production: Boolean): Either[String, AgentPublicUrl] =
    val invalid = Left(
      s"$Key must be https://HOST[:PORT], or http://127.0.0.1[:PORT] for local development, with no path, query, or user info"
    )
    Try(URI.create(raw.trim)).toOption match
      case None => invalid
      case Some(uri) =>
        val path = uri.getRawPath
        val wellFormed =
          uri.isAbsolute && !uri.isOpaque && uri.getHost != null && uri.getUserInfo == null && uri.getRawQuery == null &&
            uri.getRawFragment == null && (path == null || path.isEmpty || path == "/") &&
            (uri.getPort == -1 || (uri.getPort > 0 && uri.getPort <= 65535))
        val host = Option(uri.getHost).map(_.toLowerCase)
        (Option(uri.getScheme).map(_.toLowerCase), host) match
          case (Some("https"), Some(name)) if wellFormed && isHostName(name) =>
            Right(new AgentPublicUrl(s"https://${authority(name, uri.getPort)}"))
          case (Some("http"), Some(name)) if wellFormed && isLoopbackLiteral(name) =>
            if production then Left(s"$Key must be an https URL in production")
            else Right(new AgentPublicUrl(s"http://${authority(name, uri.getPort)}"))
          case _ => invalid

  /** Production must state its public agent URL: the default address only works on the machine running the server, so
    * a default would render setup commands that fail everywhere else. Development derives it from the agent port. */
  def fromEnvironment(
      environment: Map[String, String],
      profile: RuntimeProfile,
      agentPort: Int
  ): Either[String, AgentPublicUrl] =
    val production = profile == RuntimeProfile.Production
    environment.get(Key).map(_.trim).filter(_.nonEmpty) match
      case Some(raw) => parse(raw, production)
      case None if production => Left(s"$Key is required in production")
      case None => parse(s"http://127.0.0.1:$agentPort", production = false)

  /** A DNS name with at least two labels, or a bracketed IPv6 literal. */
  private def isHostName(host: String): Boolean =
    val label = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    host.length <= 253 && (host.matches(s"$label(\\.$label)+") || host.startsWith("["))

  /** `127.x.y.z` or `[::1]`, checked syntactically so validation never performs a DNS lookup. */
  private def isLoopbackLiteral(host: String): Boolean =
    val octets = host.split("\\.", -1)
    (octets.length == 4 && octets.head == "127" && octets.forall(part => part.matches("\\d{1,3}") && part.toInt <= 255)) ||
    host == "[::1]"

  private def authority(host: String, port: Int): String =
    if port == -1 then host else s"$host:$port"
