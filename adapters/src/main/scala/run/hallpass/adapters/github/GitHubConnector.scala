package run.hallpass.adapters.github

import java.net.URI
import cats.effect.IO
import run.hallpass.application.*

/** The GitHub App connection flow.
  *
  * Start sends the administrator to `{web}/apps/{slug}/installations/new?state=…`. With "Request user authorization
  * (OAuth) during installation" enabled, GitHub returns to the callback with `code`, `installation_id`, and
  * `setup_action`. The exchange then verifies, in order, and fails closed at each step:
  *   1. `installation_id` is present and numeric (it is untrusted input);
  *   2. the code exchanges for a user-to-server token;
  *   3. that user can access the installation (`GET /user/installations`), so an administrator cannot bind an
  *      installation they cannot see; the user token is then discarded, never stored;
  *   4. the App can read the installation (`GET /app/installations/{id}`), which names its account.
  *
  * The grant stores a [[GitHubInstallationRecord]] (no token). The external account ID is
  * `github.com:installation:{id}`, which the V22 directory claim keeps unique across tenants. The root is the
  * installation (external ID: the installation ID), labelled with the account login.
  *
  * `selectableResources` mints a metadata-only token for the whole installation and lists its repositories (bounded by
  * `repositoryLimit`). The stored record must name this registration and the root's installation.
  */
final class GitHubConnector(
    registration: GitHubAppRegistration,
    app: GitHubAppApi,
    endpoints: GitHubEndpoints,
    val redirectUri: URI,
    repositoryLimit: Int = 1000
) extends ProviderConnector:
  val provider: ProviderId = ProviderId.GitHub
  val rootKind: ResourceKind[?] = GitHub.installation
  val credentialType: String = GitHub.CredentialType
  override val callbackParameters: Set[String] = Set("installation_id", "setup_action")

  val singleActiveRoot = false
  val usesPkce = false
  val resourceDiscovery: Option[ResourceDiscovery] = Some(new ResourceDiscovery:
    def selectableResources(credential: ProviderSecret, root: ConnectionResource) =
      GitHubConnector.this.selectableResources(credential, root)
  )
  def authorizationUri(state: OAuthState, pkce: Option[PkceVerifier]): IO[URI] = authorizationUri(state)
  def exchange(callback: OAuthCallback, pkce: Option[PkceVerifier]): IO[Either[OAuthError, OAuthGrant]] = exchange(callback)

  def authorizationUri(state: OAuthState): IO[URI] = IO.delay:
    val base = endpoints.web.toString.stripSuffix("/")
    URI.create(s"$base/apps/${encode(registration.slug)}/installations/new?state=${encode(state.value)}")

  def exchange(callback: OAuthCallback): IO[Either[OAuthError, OAuthGrant]] =
    val installation = callback.parameters.get("installation_id").flatMap(GitHubInstallationId.parse)
    val action = callback.parameters.get("setup_action")
    installation match
      case None => IO.pure(Left(OAuthError.InvalidProviderResponse))
      case Some(_) if action.exists(value => value != "install" && value != "update") =>
        // "request" means an organization member asked for approval; nothing is installed yet.
        IO.pure(Left(OAuthError.ProviderRejected))
      case Some(id) => verify(callback, id)

  private def verify(callback: OAuthCallback, id: GitHubInstallationId): IO[Either[OAuthError, OAuthGrant]] =
    call(app.exchangeUserCode(callback.code, redirectUri)).flatMap:
      case Left(error) => IO.pure(Left(error))
      case Right(user) =>
        call(app.userCanAccessInstallation(user, id)).flatMap:
          case Left(error)  => IO.pure(Left(error))
          case Right(false) => IO.pure(Left(OAuthError.ProviderRejected))
          case Right(true) =>
            call(app.installation(id)).map:
              case Left(error)    => Left(error)
              case Right(account) => grant(id, account)

  private def grant(id: GitHubInstallationId, account: GitHubInstallationAccount): Either[OAuthError, OAuthGrant] =
    val login = account.login
    val validLogin = login.trim.nonEmpty && login.length <= 100 && !login.exists(Character.isISOControl(_))
    if !validLogin || account.installation.value != id.value then Left(OAuthError.InvalidProviderResponse)
    else
      Right(
        OAuthGrant(
          secret = GitHubInstallationRecord.encode(GitHubInstallationRecord(registration.registrationKey, id)),
          externalAccountId = GitHubConnector.externalAccountId(id),
          rootExternalId = id.externalId,
          rootDisplayName = login,
          accountLabel = Some(login),
          workspaceLabel = Some(account.accountType),
          expiresAt = None
        )
      )

  def selectableResources(
      credential: ProviderSecret,
      root: ConnectionResource
  ): IO[Either[OAuthError, Vector[SelectableProviderResource]]] =
    GitHubInstallationRecord.decode(credential) match
      case Left(_) => IO.pure(Left(OAuthError.InvalidState))
      case Right(record)
          if record.registration != registration.registrationKey ||
            root.kind != GitHub.installation.wire ||
            root.externalId != record.installation.externalId =>
        IO.pure(Left(OAuthError.InvalidState))
      case Right(record) =>
        call(app.installationToken(record.installation, None, Set(GitHubPermission.MetadataRead))).flatMap:
          case Left(error) => IO.pure(Left(error))
          case Right(token) =>
            call(app.installationRepositories(token, repositoryLimit)).map:
              case Left(error) => Left(error)
              case Right(repositories) =>
                Right(
                  repositories
                    .distinctBy(_.id.value)
                    .map(repo =>
                      SelectableProviderResource(
                        GitHub.repository,
                        repo.id.externalId,
                        repo.fullName.value,
                        root.externalId
                      )
                    )
                    .sortBy(_.displayName)
                )

  /** Any API failure, including an unexpected exception, is an opaque rejection; no message escapes. */
  private def call[A](effect: IO[Either[GitHubApiError, A]]): IO[Either[OAuthError, A]] =
    effect.attempt.map:
      case Right(Right(value)) => Right(value)
      case _                   => Left(OAuthError.ProviderRejected)

  private def encode(value: String): String =
    java.net.URLEncoder.encode(value, java.nio.charset.StandardCharsets.UTF_8).replace("+", "%20")

object GitHubConnector:
  def externalAccountId(installation: GitHubInstallationId): ExternalId =
    ExternalId.parse(s"github.com:installation:${installation.value}").get
