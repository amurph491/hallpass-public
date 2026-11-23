package run.hallpass.application

import java.net.URI
import java.time.Instant
import cats.effect.IO
import run.hallpass.kernel.{ConnectionId, ResourceId, TenantId}

opaque type OAuthState = String
object OAuthState:
  def parse(value: String): Option[OAuthState] =
    Option.when(value.matches("[A-Za-z0-9_-]{43,256}"))(value)
  extension (value: OAuthState) def value: String = value

final case class OAuthCallback(state: OAuthState, code: String, parameters: Map[String, String] = Map.empty)
final case class OAuthGrant(
    secret: ProviderSecret,
    /** Stable provider account key, never a display name. */
    externalAccountId: ExternalId,
    /** Stable external identity for the provider's connection root. */
    rootExternalId: ExternalId,
    rootDisplayName: String,
    accountLabel: Option[String],
    workspaceLabel: Option[String],
    expiresAt: Option[Instant]
)
object OAuthGrant:
  /** Credential type for connections whose stored secret is an [[OAuthTokens]] record refreshed by
    * [[RefreshableOAuth]]. */
  val RefreshableCredentialType = "OAUTH_REFRESHABLE"

  /** The grant of a refreshable connector. The stored secret is the codec's encoding of `tokens`, and the connection
    * and reference expiry is the tokens' own (microsecond-truncated) expiry, so the refresh strategy's equality check
    * between stored metadata and the decoded secret holds from the first use. */
  def refreshable(
      tokens: OAuthTokens,
      codec: OAuthTokenCodec,
      externalAccountId: ExternalId,
      rootExternalId: ExternalId,
      rootDisplayName: String,
      accountLabel: Option[String],
      workspaceLabel: Option[String]
  ): OAuthGrant =
    OAuthGrant(
      codec.encode(tokens), externalAccountId, rootExternalId, rootDisplayName, accountLabel, workspaceLabel,
      Some(tokens.expiresAt)
    )

enum OAuthError:
  case InvalidState, ExpiredState, StateAlreadyUsed, ProviderRejected, InvalidProviderResponse
  /** The provider account is already connected in this tenant. */
  case AccountAlreadyConnected
  /** The provider supports one active connection per tenant, and one is active. */
  case ProviderAlreadyConnected
  /** A reauthorization signed in to a different provider account than the connection's. */
  case AccountMismatch

trait OAuthStateRepository[F[_]]:
  def create(
      tenant: TenantId,
      resource: ResourceId,
      state: OAuthState,
      session: OAuthSessionBinding,
      expiresAt: Instant
  ): F[Unit]

  /** Atomically consumes state, returning its bound resource only once, and only to the session that created it. */
  def consume(
      tenant: TenantId,
      state: OAuthState,
      session: OAuthSessionBinding,
      now: Instant
  ): F[Either[OAuthError, ResourceId]]

  /** Removes expired and already-consumed state. This is lifecycle housekeeping, never authorization. */
  def purgeExpired(tenant: TenantId, now: Instant): F[Long]

  /** Provider connection state. Every binding is persisted: the provider, the reserved connection, a digest of the
    * server's fixed redirect URI, and (for PKCE) a secret-store reference to the verifier, never the verifier itself. */
  def createBound(
      tenant: TenantId,
      resource: ResourceId,
      provider: ProviderId,
      intendedConnection: ConnectionId,
      redirectBinding: Array[Byte],
      pkceVerifier: Option[SecretReference],
      state: OAuthState,
      session: OAuthSessionBinding,
      expiresAt: Instant
  ): F[Unit]

  /** Consumes state once, only for the same session, provider, and redirect binding. */
  def consumeBound(
      tenant: TenantId,
      provider: ProviderId,
      redirectBinding: Array[Byte],
      state: OAuthState,
      session: OAuthSessionBinding,
      now: Instant
  ): F[Either[OAuthError, OAuthStateBinding]]

final case class OAuthStateBinding(
    resource: ResourceId,
    provider: ProviderId,
    connection: ConnectionId,
    pkceVerifier: Option[SecretReference]
)

/** A provider integration's management-side OAuth edge. Callbacks and grants never cross into the kernel. */
trait ProviderConnector:
  /** Only these bounded callback parameters reach this connector; each remains untrusted. */
  def callbackParameters: Set[String] = Set.empty
  def provider: ProviderId
  def rootKind: ResourceKind[?]
  /** Fixed callback configured by the server. It is hashed into state and never accepted from a browser request. */
  def redirectUri: URI
  def credentialType: String
  /** True when this provider's operations address the connection root without an argument. A second active root of
    * the same kind would then be ambiguous, so activation refuses it. */
  def singleActiveRoot: Boolean
  /** True when the provider supports RFC 7636 PKCE with S256. The verifier is then generated per connection attempt. */
  def usesPkce: Boolean
  def authorizationUri(state: OAuthState, pkce: Option[PkceVerifier]): IO[URI]
  def exchange(callback: OAuthCallback, pkce: Option[PkceVerifier]): IO[Either[OAuthError, OAuthGrant]]
  /** Child resources an administrator may select, or `None` when the connector authorizes only at its root. With
    * `None`, connection management never reads the stored provider credential. */
  def resourceDiscovery: Option[ResourceDiscovery]

/** Management-side listing of selectable children. This is the one use of a stored provider credential outside the
  * trusted executor: it runs only from an authenticated administrator route, outside the tenant mutation gate, and
  * its result is a candidate list that the selection step re-checks. It never grants authority. */
trait ResourceDiscovery:
  def selectableResources(
      credential: ProviderSecret,
      root: ConnectionResource
  ): IO[Either[OAuthError, Vector[SelectableProviderResource]]]

final case class SelectableProviderResource(
    kind: ResourceKind[?],
    externalId: ExternalId,
    displayName: String,
    parentExternalId: ExternalId
):
  /** Management edge key; never used for authorization or provider dispatch. */
  def selectionKey: String = s"${kind.wire}|${externalId.value}"
