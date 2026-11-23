package run.hallpass.application

import java.time.Instant
import java.util.UUID
import run.hallpass.kernel.*
import cats.Monad
import cats.syntax.all.*

/** A person's global directory identity. It is distinct from the tenant-owned human principal ([[UserId]]) that
  * authority attaches to: one directory user can be a member of several tenants, with a different principal in each. */
opaque type DirectoryUserId = UUID
object DirectoryUserId:
  def random(): DirectoryUserId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, DirectoryUserId] = CanonicalUuid.parse(value)

private[application] object CanonicalUuid:
  private val Pattern = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}".r
  def parse(value: String): Either[IdentifierParseError, UUID] =
    value match
      case Pattern() => Right(UUID.fromString(value))
      case _         => Left(IdentifierParseError.InvalidUuid)

enum ExternalIdentityError:
  case InvalidIssuer, InvalidSubject

/** An identity-provider account: the provider's issuer and its stable subject for the person. Constructing one proves
  * nothing. Only a login authenticator that has verified the provider's assertion may resolve it to a user. */
final case class ExternalIdentity private (issuer: String, subject: String)
object ExternalIdentity:
  def from(issuer: String, subject: String): Either[ExternalIdentityError, ExternalIdentity] =
    if !valid(issuer, 512) then Left(ExternalIdentityError.InvalidIssuer)
    else if !valid(subject, 255) then Left(ExternalIdentityError.InvalidSubject)
    else Right(ExternalIdentity(issuer, subject))

  private def valid(value: String, maximum: Int): Boolean =
    value.nonEmpty && value.length <= maximum && value == value.trim && value.forall(character => !Character.isISOControl(character))

enum MembershipRole:
  case Admin, Member

/** An operator-granted, time-boxed elevation to [[MembershipRole.Admin]] in one tenant. */
opaque type BreakGlassGrantId = UUID
object BreakGlassGrantId:
  def random(): BreakGlassGrantId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, BreakGlassGrantId] = CanonicalUuid.parse(value)
  extension (id: BreakGlassGrantId) def value: UUID = id

/** An active membership as reported by the directory: which tenant, which principal in it, and which role.
  *
  * `breakGlass` is set when the role is Admin only because of an active break-glass grant. Elevation changes the role,
  * never the principal's policies or delegations, so it cannot create authority. */
final case class TenantMembership(
    user: DirectoryUserId,
    tenant: TenantId,
    principal: Principal.Human,
    role: MembershipRole,
    breakGlass: Option[BreakGlassGrantId] = None
)

enum DirectoryError:
  case Unavailable

/** Pre-tenant routing for agent credentials. The answer is a candidate, not authentication: the credential is still
  * verified inside the candidate tenant, with a verifier bound to that tenant. */
trait AgentCredentialRoutes[F[_]]:
  def candidateTenant(selector: AgentCredentialSelector): F[Either[DirectoryError, Option[TenantId]]]

/** Pre-tenant lookups for people. Disabled users and removed memberships are simply absent. */
trait HumanDirectory[F[_]]:
  def userFor(identity: ExternalIdentity): F[Either[DirectoryError, Option[DirectoryUserId]]]
  def activeMemberships(user: DirectoryUserId): F[Either[DirectoryError, Vector[TenantMembership]]]

/** The authenticated caller of one request. Only authenticators construct these, and the tenant always comes from
  * verified server state (a verified credential or a current membership), never from request input. */
sealed trait RequestContext:
  def tenant: TenantId

/** Authentication result for an agent. Its constructor is private so HTTP DTOs cannot manufacture an identity. */
final class AuthenticatedAgentContext private (
    val tenant: TenantId,
    private val authenticatedAgentId: AgentId,
    val credentialId: AgentCredentialId,
    val authenticatedAt: Instant,
    val unverifiedClaims: UnverifiedExecutionClaims
) extends RequestContext:
  val principal: Principal.Agent = Principal.Agent(authenticatedAgentId)
  def agentId: AgentId = authenticatedAgentId
  override def toString: String =
    s"AuthenticatedAgentContext(tenant=$tenant, principal=$principal, credentialId=$credentialId, authenticatedAt=$authenticatedAt)"

object AuthenticatedAgentContext:
  /** Reserved for the authenticator boundary after verification and successful last-used recording. */
  private[application] def authenticated(
      tenant: TenantId,
      agentId: AgentId,
      credentialId: AgentCredentialId,
      authenticatedAt: Instant,
      unverifiedClaims: UnverifiedExecutionClaims
  ): AuthenticatedAgentContext =
    new AuthenticatedAgentContext(tenant, agentId, credentialId, authenticatedAt, unverifiedClaims)

/** A person acting in one tenant through a membership that was active when this request was authenticated. */
final class AuthenticatedHuman private (val membership: TenantMembership, val authenticatedAt: Instant)
    extends RequestContext:
  def tenant: TenantId = membership.tenant
  def principal: Principal.Human = membership.principal
  def user: DirectoryUserId = membership.user
  def role: MembershipRole = membership.role
  def breakGlass: Option[BreakGlassGrantId] = membership.breakGlass
  override def toString: String =
    s"AuthenticatedHuman(tenant=$tenant, principal=$principal, user=$user, role=$role, breakGlass=$breakGlass, authenticatedAt=$authenticatedAt)"

object AuthenticatedHuman:
  private[application] def authenticated(membership: TenantMembership, at: Instant): AuthenticatedHuman =
    new AuthenticatedHuman(membership, at)

enum HumanAuthenticationError:
  case UnknownIdentity, NoActiveMembership, Unavailable

/** Turns a login (a verified external identity) into a user, and a session (user plus selected tenant) into an
  * [[AuthenticatedHuman]]. Membership is rechecked on every call, so disabling a user or removing a membership takes
  * effect on that user's next request. */
final class HumanAuthenticator[F[_]](directory: HumanDirectory[F])(using F: Monad[F]):
  /** Call only after the login flow has verified the identity-provider assertion for `identity`. */
  def userFor(identity: ExternalIdentity): F[Either[HumanAuthenticationError, DirectoryUserId]] =
    directory.userFor(identity).map:
      case Left(DirectoryError.Unavailable) => Left(HumanAuthenticationError.Unavailable)
      case Right(None)                      => Left(HumanAuthenticationError.UnknownIdentity)
      case Right(Some(user))                => Right(user)

  def memberships(user: DirectoryUserId): F[Either[HumanAuthenticationError, Vector[TenantMembership]]] =
    directory.activeMemberships(user).map(_.leftMap(_ => HumanAuthenticationError.Unavailable))

  def authenticate(
      user: DirectoryUserId,
      tenant: TenantId,
      at: Instant
  ): F[Either[HumanAuthenticationError, AuthenticatedHuman]] =
    memberships(user).map:
      case Left(error) => Left(error)
      case Right(current) =>
        // The directory is queried by user; the tenant filter here is exact, so a membership for another tenant can
        // never stand in for the session's tenant.
        current.filter(membership => membership.user == user && membership.tenant == tenant) match
          case Vector(membership) => Right(AuthenticatedHuman.authenticated(membership, at))
          case _                  => Left(HumanAuthenticationError.NoActiveMembership)
