package run.hallpass.adapters.linear

import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.UUID
import cats.effect.IO
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Linear's resource topology: the organization is the connection root (Workspace custody), and
  * administrators select teams under it. Issues are addressed by argument and authorized at their team. External IDs
  * are Linear's UUIDs, never names or team keys. */
object Linear:
  sealed trait Organization
  sealed trait Team

  given organization: ResourceKind[Organization] =
    ResourceKind.root("linear.organization", ProviderId.Linear, ResourceType.Account, Custody.Workspace)
  given team: ResourceKind[Team] = ResourceKind.child[Team, Organization]("linear.team", ResourceType.Team)

  /** Linear access tokens expire and are refreshed through the insert-only rotation. */
  val CredentialType = "OAUTH_REFRESHABLE"

object LinearExecutorAudience:
  val local: ExecutorAudience =
    ExecutorAudience.parse("hallpass.local.linear").getOrElse(throw IllegalStateException("static executor audience is invalid"))

/** Where Linear's OAuth and GraphQL endpoints live. Overrides exist only for a local fake and are refused in
  * production, because they decide where tokens are sent. */
final case class LinearEndpoints(authorize: URI, token: URI, graphql: URI)
object LinearEndpoints:
  val Production: LinearEndpoints = LinearEndpoints(
    URI.create("https://linear.app/oauth/authorize"),
    URI.create("https://api.linear.app/oauth/token"),
    URI.create("https://api.linear.app/graphql")
  )

/** The OAuth application's client ID (not secret) and client secret (from a mounted file, never rendered). */
final class LinearOAuthClient(val clientId: String, private[linear] val clientSecret: String):
  require(clientId.matches("[A-Za-z0-9._-]{1,128}"), "Linear client ID is invalid")
  override def toString: String = s"LinearOAuthClient($clientId, <redacted>)"
  /** For the shared refresh client, which runs inside the executor only. */
  def secretForRefresh: String = clientSecret

/** A Linear UUID: organizations, teams, and issues. */
opaque type LinearId = String
object LinearId:
  private val Pattern = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}".r
  def parse(value: String): Option[LinearId] = Option.when(Pattern.matches(value))(value)
  def fromExternal(value: ExternalId): Option[LinearId] = parse(value.value)
  extension (value: LinearId)
    def value: String = value
    def externalId: ExternalId = ExternalId.parse(value).get

/** What a Linear operation dispatches with. Executor-private. `operationKey` is derived from the redeemed lease, so
  * a create carries one stable client-chosen ID (Linear `issueCreate(input: {id})`) per authorized invocation. */
final class LinearAccess private[linear] (private[linear] val accessToken: String, val operationKey: UUID):
  override def toString: String = "LinearAccess(<redacted>)"

object LinearAccess:
  def operationKey(lease: RedeemedExecutionLease): UUID =
    UUID.nameUUIDFromBytes(s"hallpass.linear.operation:${lease.id}".getBytes(StandardCharsets.UTF_8))

/** Refreshable OAuth for the lease's team, plus the lease-derived operation key. Refresh, single flight, and
  * rotation are entirely RefreshableOAuth's; this adds nothing that could widen access. */
final class LinearCredentials(oauth: CredentialStrategy[Linear.Team, OAuthTokens])
    extends CredentialStrategy[Linear.Team, LinearAccess]:
  def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[Linear.Team]): IO[Either[ConnectionError, LinearAccess]] =
    if lease.tenant != target.tenant || lease.resource != target.resource || !(target.kind eq Linear.team) then
      IO.pure(Left(ConnectionError.InvalidState))
    else oauth.credentialFor(lease, target).map(_.map(tokens => LinearAccess(tokens.accessToken, LinearAccess.operationKey(lease))))
