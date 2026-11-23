package run.hallpass.adapters.github

import cats.effect.IO
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Mints an installation token for one redeemed lease, narrowed to the lease's one repository and to the operation's
  * minimum permissions.
  *
  * In order, failing closed at each step, and only ever called by the executor after redemption and revalidation:
  *   1. the target must be the lease's resource in the lease's tenant;
  *   2. the connection is resolved server-side from that resource: ACTIVE, GitHub, an installation credential;
  *   3. the stored record must name this server's registration and the installation that is the target's trusted
  *      connection root in the catalog;
  *   4. GitHub mints a token for `repository_ids = [target]` and the declared permissions only;
  *   5. GitHub's answer must be exactly that one repository, with no permission beyond those requested.
  *
  * The repository name in the result comes from GitHub's answer for the authorized ID, so the provider request is built
  * from the authorized resource rather than from an argument string. A repository removed from the installation on
  * GitHub fails at step 4 or 5. Nothing is cached: every call mints.
  */
final class GitHubInstallationCredentials(
    registration: GitHubAppRegistration,
    connections: ProviderConnectionResolver,
    app: GitHubAppApi,
    permissions: Set[GitHubPermission]
) extends CredentialStrategy[GitHub.Repository, GitHubInstallationToken]:
  require(permissions.nonEmpty, "an operation must declare its GitHub permissions")

  def credentialFor(
      lease: RedeemedExecutionLease,
      target: SelectedResource[GitHub.Repository]
  ): IO[Either[ConnectionError, GitHubInstallationToken]] =
    if lease.tenant != target.tenant || lease.resource != target.resource || !(target.kind eq GitHub.repository) then
      IO.pure(Left(ConnectionError.InvalidState))
    else
      (GitHubRepositoryId.fromExternal(target.externalId), installationRootOf(target)) match
        case (None, _) | (_, None) => IO.pure(Left(ConnectionError.InvalidState))
        case (Some(repository), Some(rootInstallation)) =>
          connections.activeConnectionFor(lease, target, ProviderId.GitHub, GitHub.CredentialType).flatMap:
            case Left(error) => IO.pure(Left(error))
            case Right(resolved) =>
              GitHubInstallationRecord.decode(resolved.secret) match
                case Left(error) => IO.pure(Left(error))
                case Right(record)
                    if record.registration != registration.registrationKey || record.installation != rootInstallation =>
                  IO.pure(Left(ConnectionError.InvalidState))
                case Right(record) =>
                  app.installationToken(record.installation, Some(Vector(repository)), permissions).map:
                    case Left(_) => Left(ConnectionError.MissingCredential)
                    case Right(minted) => narrowed(minted, repository)

  /** The installation that is the target's connection root in the trusted catalog scope. */
  private def installationRootOf(target: SelectedResource[GitHub.Repository]): Option[GitHubInstallationId] =
    target.scope.path match
      case Vector(_, root, _) if root.resourceType == GitHub.installation.resourceType =>
        GitHubInstallationId.parse(root.externalId)
      case _ => None

  /** GitHub must confirm the narrowing: exactly the one requested repository, and only requested permissions. */
  private def narrowed(
      minted: MintedInstallationToken,
      repository: GitHubRepositoryId
  ): Either[ConnectionError, GitHubInstallationToken] =
    val requested = permissions.map(permission => permission.name -> permission.level).toMap + ("metadata" -> "read")
    val withinPermissions = minted.permissions.forall((name, level) => requested.get(name).contains(level))
    minted.repositories match
      case Vector(only) if only.id == repository && withinPermissions =>
        Right(GitHubInstallationToken(minted.raw, only, minted.expiresAt))
      case _ => Left(ConnectionError.InvalidState)
