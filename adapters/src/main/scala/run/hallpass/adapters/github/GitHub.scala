package run.hallpass.adapters.github

import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.interfaces.RSAPrivateKey
import java.time.Instant
import io.circe.{Json, parser}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** GitHub's resource topology.
  *
  * The connection root is a GitHub App installation on an organization or user account (Workspace custody). An
  * administrator selects repositories under it. External IDs are GitHub's numeric IDs, never names.
  */
object GitHub:
  sealed trait Installation
  sealed trait Repository

  given installation: ResourceKind[Installation] =
    ResourceKind.root("github.installation", ProviderId.GitHub, ResourceType.Account, Custody.Workspace)
  given repository: ResourceKind[Repository] =
    ResourceKind.child[Repository, Installation]("github.repository", ResourceType.Repository)

  /** `credential_references.credential_type` for an installation connection. The stored "secret" is a
    * [[GitHubInstallationRecord]]: it names the installation, and holds no token. */
  val CredentialType = "GITHUB_APP_INSTALLATION"

/** Adapter registration; the kernel sees only the opaque ExecutorAudience value. */
object GitHubExecutorAudience:
  val local: ExecutorAudience =
    ExecutorAudience.parse("hallpass.local.github").getOrElse(throw IllegalStateException("static executor audience is invalid"))

/** GitHub's numeric installation ID. */
opaque type GitHubInstallationId = Long
object GitHubInstallationId:
  def parse(value: String): Option[GitHubInstallationId] = positiveId(value)
  def from(value: Long): Option[GitHubInstallationId] = Option.when(value > 0)(value)
  extension (value: GitHubInstallationId)
    def value: Long = value
    def externalId: ExternalId = ExternalId.parse(value.toString).get

/** GitHub's numeric repository ID: the repository's external ID in Hallpass. It survives renames and transfers. */
opaque type GitHubRepositoryId = Long
object GitHubRepositoryId:
  def parse(value: String): Option[GitHubRepositoryId] = positiveId(value)
  def from(value: Long): Option[GitHubRepositoryId] = Option.when(value > 0)(value)
  def fromExternal(value: ExternalId): Option[GitHubRepositoryId] = parse(value.value)
  extension (value: GitHubRepositoryId)
    def value: Long = value
    def externalId: ExternalId = ExternalId.parse(value.toString).get

private def positiveId(value: String): Option[Long] =
  Option.when(value.nonEmpty && value.length <= 19 && value.forall(_.isDigit) && !value.startsWith("0"))(value)
    .flatMap(_.toLongOption)
    .filter(_ > 0)

/** `owner/name`, as GitHub reports it for a repository ID. Used to build REST paths only after GitHub itself returned
  * it for the authorized repository ID (in the narrowed token's repository list); never taken from agent arguments. */
opaque type GitHubRepositoryName = String
object GitHubRepositoryName:
  private val Pattern = "[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}".r
  def parse(value: String): Option[GitHubRepositoryName] =
    Option.when(Pattern.matches(value) && !value.endsWith("/.") && !value.endsWith("/.."))(value)
  extension (value: GitHubRepositoryName) def value: String = value

/** One repository GitHub reports for an installation or a narrowed token. */
final case class GitHubRepositorySummary(id: GitHubRepositoryId, fullName: GitHubRepositoryName)

/** The account an installation is on. `accountType` is GitHub's `Organization` or `User`. */
final case class GitHubInstallationAccount(
    installation: GitHubInstallationId,
    accountId: Long,
    login: String,
    accountType: String
)

/** A repository permission an installation token is narrowed to. Each operation declares the minimum it needs;
  * `metadata: read` is implied by GitHub for every token. */
enum GitHubPermission(val name: String, val level: String):
  case MetadataRead extends GitHubPermission("metadata", "read")
  case IssuesRead extends GitHubPermission("issues", "read")
  case IssuesWrite extends GitHubPermission("issues", "write")
  case PullRequestsRead extends GitHubPermission("pull_requests", "read")

/** Where the GitHub API and web flow live. Only `github.com` is built; overrides exist for a local
  * fake provider in development and are refused in production, because they decide where tokens are sent. */
final case class GitHubEndpoints(api: URI, web: URI)
object GitHubEndpoints:
  val DotCom: GitHubEndpoints = GitHubEndpoints(URI.create("https://api.github.com"), URI.create("https://github.com"))

/** Hallpass's platform-owned GitHub App on github.com. The private key and client secret are held separately in
  * [[GitHubAppSecrets]]; nothing here is secret. */
final case class GitHubAppRegistration(appId: Long, clientId: String, slug: String):
  require(appId > 0, "GitHub App ID must be positive")
  require(clientId.matches("[A-Za-z0-9._-]{1,64}"), "GitHub client ID is invalid")
  require(slug.matches("[a-z0-9][a-z0-9-]{0,99}"), "GitHub App slug is invalid")
  /** Stored in each connection's installation record, so a later multi-registration server can tell them apart. */
  def registrationKey: String = s"platform:github.com:$appId"

/** The App's private key (the only credential that can mint installation tokens) and its OAuth client secret. Loaded
  * from mounted files at startup and never rendered. */
final class GitHubAppSecrets(private[github] val privateKey: RSAPrivateKey, private[github] val clientSecret: String):
  override def toString: String = "GitHubAppSecrets(<redacted>)"

/** What a GitHub connection stores through the secret store. It is not secret, but storing it there keeps the usual
  * rule that execution needs an ACTIVE connection with a current credential reference, and binds the connection to
  * one installation of one registration. */
final case class GitHubInstallationRecord(registration: String, installation: GitHubInstallationId)
object GitHubInstallationRecord:
  def encode(record: GitHubInstallationRecord): ProviderSecret =
    ProviderSecret.fromUtf8(
      Json.obj(
        "registration" -> Json.fromString(record.registration),
        "installation_id" -> Json.fromLong(record.installation.value)
      ).noSpaces
    )

  def decode(secret: ProviderSecret): Either[ConnectionError, GitHubInstallationRecord] =
    val text = String(ProviderSecret.bytes(secret), StandardCharsets.UTF_8)
    (for
      json <- parser.parse(text).toOption
      cursor = json.hcursor
      registration <- cursor.get[String]("registration").toOption
      installation <- cursor.get[Long]("installation_id").toOption.flatMap(GitHubInstallationId.from)
    yield GitHubInstallationRecord(registration, installation)).toRight(ConnectionError.InvalidState)

/** A minted installation token. Executor-private: it never leaves the credential strategy and provider client. */
final class MintedInstallationToken private[github] (
    private[github] val raw: String,
    val expiresAt: Instant,
    /** The repositories GitHub says the token can reach. For a narrowed token this is exactly the requested set. */
    val repositories: Vector[GitHubRepositorySummary],
    /** The permissions GitHub granted, by name and level. */
    val permissions: Map[String, String]
):
  override def toString: String = "MintedInstallationToken(<redacted>)"

/** A GitHub user-to-server token, used only during the install callback to verify the installer can access the
  * installation. It is discarded after verification and never stored. */
final class GitHubUserToken private[github] (private[github] val raw: String):
  override def toString: String = "GitHubUserToken(<redacted>)"

/** The credential a GitHub operation dispatches with: a token narrowed to one repository, and that repository's
  * name as GitHub reported it for the authorized ID. */
final class GitHubInstallationToken private[github] (
    private[github] val raw: String,
    val repository: GitHubRepositorySummary,
    val expiresAt: Instant
):
  override def toString: String = "GitHubInstallationToken(<redacted>)"

/** Credential-free GitHub API failure categories. No response body or token ever appears in one. */
enum GitHubApiError:
  case Unauthorized, Forbidden, NotFound, RateLimited, Rejected, Timeout, InvalidResponse
