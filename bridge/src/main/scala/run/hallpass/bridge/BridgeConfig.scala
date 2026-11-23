package run.hallpass.bridge

import java.net.{Inet6Address, InetAddress, URI}
import java.util.Locale
import java.nio.charset.StandardCharsets
import java.nio.file.attribute.{PosixFileAttributeView, PosixFilePermission}
import java.nio.file.{Files, LinkOption, Path}
import scala.jdk.CollectionConverters.*

enum BridgeConfigError:
  case MissingCredential, MultipleCredentials, InvalidCredential, InvalidEndpoint, CredentialFileUnavailable, CredentialFileNotProtected,
    CredentialEndpointMismatch

/** A bridge bearer is intentionally opaque at this boundary: diagnostics must never render it. */
final class BridgeCredential private[bridge] (private[bridge] val value: String):
  override def toString: String = "BridgeCredential(<redacted>)"

object BridgeCredential:
  private val WireFormat = "ac1\\.[A-Za-z0-9_-]{16,32}\\.[A-Za-z0-9_-]{43}".r

  def parse(value: String): Either[BridgeConfigError, BridgeCredential] =
    value match
      case WireFormat() => Right(new BridgeCredential(value))
      case _            => Left(BridgeConfigError.InvalidCredential)

final case class BridgeConfig private (endpoint: URI, credential: BridgeCredential)

object BridgeConfig:
  private val EndpointVariable = "HALLPASS_AGENT_API_URL"
  private val CredentialVariable = "HALLPASS_AGENT_CREDENTIAL"
  private val CredentialFileVariable = "HALLPASS_AGENT_CREDENTIAL_FILE"
  private val MaximumCredentialFileBytes = 4096L

  private val ProfileHeader = "hallpass-agent-profile/1"

  /** A credential file written before profiles existed was verified only against the local default endpoint. */
  private val LegacyEndpoint = "http://127.0.0.1:8081"

  /** A credential, and the endpoint it is bound to when it came from a profile file. An environment credential carries
    * no binding: whoever sets both variables chose that pairing explicitly. */
  private final case class LoadedCredential(credential: BridgeCredential, boundEndpoint: Option[URI])

  /** Only environment variables and an owner-readable POSIX file are configuration sources.
    *
    * A credential file binds its credential to one endpoint, and the bridge refuses to pair it with any other, whatever
    * a client registration says: a rotated credential must not be sent to the server an older registration names. */
  def fromEnvironment(environment: Map[String, String]): Either[BridgeConfigError, BridgeConfig] =
    for
      endpoint <- environment.get(EndpointVariable).toRight(BridgeConfigError.InvalidEndpoint).flatMap(parseEndpoint)
      loaded <- loadCredential(environment)
      _ <- Either.cond(
        loaded.boundEndpoint.forall(_.toString == endpoint.toString),
        (),
        BridgeConfigError.CredentialEndpointMismatch
      )
    yield BridgeConfig(endpoint, loaded.credential)

  def load(): Either[BridgeConfigError, BridgeConfig] = fromEnvironment(sys.env)

  private def loadCredential(environment: Map[String, String]): Either[BridgeConfigError, LoadedCredential] =
    (environment.get(CredentialVariable), environment.get(CredentialFileVariable)) match
      case (Some(_), Some(_))  => Left(BridgeConfigError.MultipleCredentials)
      case (Some(value), None) => BridgeCredential.parse(value).map(LoadedCredential(_, None))
      case (None, Some(path))  => credentialFromProtectedFile(Path.of(path))
      case (None, None)        => Left(BridgeConfigError.MissingCredential)

  private def parseCredentialFile(content: String): Either[BridgeConfigError, LoadedCredential] =
    val trimmed = content.trim
    if trimmed.startsWith("ac1.") then
      for
        credential <- BridgeCredential.parse(trimmed)
        bound <- parseEndpoint(LegacyEndpoint)
      yield LoadedCredential(credential, Some(bound))
    else if !content.endsWith("\n") || content.contains("\r") then Left(BridgeConfigError.InvalidCredential)
    else
      content.stripSuffix("\n").split("\n", -1).toList match
        case List(ProfileHeader, endpointLine, credentialLine)
            if endpointLine.startsWith("endpoint=") && credentialLine.startsWith("credential=") =>
          val endpointText = endpointLine.stripPrefix("endpoint=")
          for
            bound <- parseEndpoint(endpointText)
            _ <- Either.cond(bound.toString == endpointText, (), BridgeConfigError.InvalidEndpoint) // must already be canonical
            credential <- BridgeCredential.parse(credentialLine.stripPrefix("credential="))
          yield LoadedCredential(credential, Some(bound))
        case _ => Left(BridgeConfigError.InvalidCredential)

  private def credentialFromProtectedFile(path: Path): Either[BridgeConfigError, LoadedCredential] =
    try
      val view = Files.getFileAttributeView(path, classOf[PosixFileAttributeView], LinkOption.NOFOLLOW_LINKS)
      if view == null || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path) then
        Left(BridgeConfigError.CredentialFileNotProtected)
      else if view.readAttributes().permissions().asScala.exists(permission =>
          permission == PosixFilePermission.GROUP_READ || permission == PosixFilePermission.GROUP_WRITE ||
            permission == PosixFilePermission.GROUP_EXECUTE || permission == PosixFilePermission.OTHERS_READ ||
            permission == PosixFilePermission.OTHERS_WRITE || permission == PosixFilePermission.OTHERS_EXECUTE
        ) then Left(BridgeConfigError.CredentialFileNotProtected)
      else if Files.size(path) > MaximumCredentialFileBytes then Left(BridgeConfigError.InvalidCredential)
      else parseCredentialFile(Files.readString(path, StandardCharsets.UTF_8))
    catch case _: Exception => Left(BridgeConfigError.CredentialFileUnavailable)

  /** Where the bridge sends its bearer credential, so it is deliberately narrow:
    *   - `http` only to a numeric loopback address (the local stack);
    *   - `https` to one exact host (the hosted agent endpoint), verified by the JDK's default certificate and hostname
    *     checks. The client never follows redirects, so the bearer cannot be steered to another host.
    * No path, user info, query, or fragment is accepted. The result is the one canonical form every Hallpass
    * component uses (bridge/tests/endpoint_vectors.json): `scheme://host[:port]` with a lowercase host, a compressed
    * bracketed IPv6 literal, and no port that is the scheme's default. */
  private def parseEndpoint(value: String): Either[BridgeConfigError, URI] =
    try
      val uri = URI.create(value)
      val validPath = uri.getRawPath == null || uri.getRawPath.isEmpty || uri.getRawPath == "/"
      val wellFormed =
        uri.isAbsolute && !uri.isOpaque && uri.getHost != null && uri.getUserInfo == null && uri.getRawQuery == null &&
          uri.getRawFragment == null && validPath && (uri.getPort == -1 || (uri.getPort > 0 && uri.getPort <= 65535))
      val scheme = uri.getScheme
      val canonicalHost = if wellFormed && hasCanonicalPortSyntax(uri) then canonicalHostOf(uri.getHost) else None
      (scheme, canonicalHost) match
        case ("http", Some(host)) if isLoopbackLiteral(host) => Right(canonicalUri(scheme, host, uri.getPort, defaultPort = 80))
        case ("https", Some(host)) if isHostName(host)       => Right(canonicalUri(scheme, host, uri.getPort, defaultPort = 443))
        case _                                               => Left(BridgeConfigError.InvalidEndpoint)
    catch case _: Exception => Left(BridgeConfigError.InvalidEndpoint)

  /** Java's URI parser accepts an empty port (`host:`) and unbounded leading zeros; the shared rule allows neither. */
  private def hasCanonicalPortSyntax(uri: URI): Boolean =
    val authority = uri.getRawAuthority
    val hostEnd =
      if authority.startsWith("[") then authority.indexOf(']') + 1
      else if authority.contains(":") then authority.indexOf(':')
      else authority.length
    val remainder = authority.substring(hostEnd)
    remainder.isEmpty ||
    (remainder.startsWith(":") && remainder.length >= 2 && remainder.length <= 6 && remainder.tail.forall(digit => digit >= '0' && digit <= '9'))

  private val StrictIpv4 = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3}"

  private def canonicalUri(scheme: String, host: String, port: Int, defaultPort: Int): URI =
    val authority = if host.contains(":") then s"[$host]" else host
    URI.create(if port == -1 || port == defaultPort then s"$scheme://$authority" else s"$scheme://$authority:$port")

  /** Lowercase host; an IPv6 literal is returned unbracketed in RFC 5952 form. None for spellings that are not accepted
    * (zones, IPv4-embedded forms), which keeps one textual form per address. */
  private def canonicalHostOf(rawHost: String): Option[String] =
    if rawHost.startsWith("[") then compressIpv6(rawHost.stripPrefix("[").stripSuffix("]").toLowerCase(Locale.ROOT))
    else if rawHost.forall(character => character.isDigit || character == '.') then
      Option.when(rawHost.matches(StrictIpv4))(rawHost) // a numeric host must be a real dotted quad, spelled once
    else Some(rawHost.toLowerCase(Locale.ROOT))

  private def compressIpv6(text: String): Option[String] =
    if !text.contains(":") || !text.forall(character => character == ':' || Character.digit(character, 16) >= 0) then None
    else
      // The text is only hex digits and colons, so this parses a literal and never resolves a name.
      InetAddress.getByName(text) match
        case address: Inet6Address =>
          val bytes = address.getAddress
          val groups = Vector.tabulate(8)(index => ((bytes(2 * index) & 0xff) << 8) | (bytes(2 * index + 1) & 0xff))
          val longestRun = (8 to 2 by -1).iterator
            .flatMap(length => (0 to 8 - length).iterator.find(start => groups.slice(start, start + length).forall(_ == 0)).map(_ -> length))
            .nextOption()
          def render(parts: Vector[Int]) = parts.map(_.toHexString).mkString(":")
          Some(longestRun match
            case None                => render(groups)
            case Some((start, size)) => s"${render(groups.take(start))}::${render(groups.drop(start + size))}"
          )
        case _ => None // Java folds IPv4-mapped addresses into IPv4; they are not accepted here

  /** A DNS name with at least two labels, or an IPv6 literal. */
  private def isHostName(host: String): Boolean =
    val label = "[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
    host.length <= 253 && (host.matches(s"$label(\\.$label)+") || host.contains(":"))

  private def isLoopbackLiteral(host: String): Boolean =
    if host.contains(":") then host == "::1"
    else host.forall(character => character.isDigit || character == '.') && InetAddress.getByName(host).isLoopbackAddress
