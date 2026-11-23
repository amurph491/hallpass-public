package run.hallpass.application

import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.{MessageDigest, SecureRandom}
import java.time.{Duration, Instant}
import java.util.Base64
import cats.effect.IO
import cats.syntax.all.*
import run.hallpass.kernel.*

/** Orchestrates provider connections at the imperative edge. Neither grants nor secrets enter the authorization kernel
  * or ordinary PostgreSQL columns.
  *
  * Provider network calls (token exchange, resource discovery) run outside the tenant mutation gate, so a slow or
  * stalled provider cannot block executions or other mutations. Only the database publication that changes authority
  * (activating a connection, replacing a selection) runs inside the gate, and it re-checks current state there.
  */
final class OAuthConnectionService(
    states: OAuthStateRepository[IO],
    connections: ConnectionRepository[IO],
    secrets: SecretStore[IO],
    resources: ConnectionResourceRepository,
    connectors: Vector[ProviderConnector],
    clock: Clock[IO] = Clock.system,
    stateTtl: Duration = Duration.ofMinutes(10),
    tokenCodec: Option[OAuthTokenCodec] = None
):
  require(!stateTtl.isNegative && !stateTtl.isZero, "OAuth state TTL must be positive")
  private val random = SecureRandom()
  private val byProvider: Map[String, ProviderConnector] = connectors.map(value => value.provider.value -> value).toMap
  require(byProvider.size == connectors.size, "each provider has one connector")

  def supportsProvider(value: String): Boolean = byProvider.contains(value.toLowerCase)

  def callbackParameters(value: String): Set[String] =
    byProvider.get(value.toLowerCase).fold(Set.empty)(_.callbackParameters)

  /** Reserves a connection ID and binds it, the provider, the fixed redirect, the session, and (with PKCE) a stored
    * verifier into single-use state, so a callback cannot substitute a different intended connection. */
  def startConnection(
      providerName: String,
      tenant: TenantId,
      catalogResource: ResourceId,
      owner: Principal.Human,
      session: OAuthSessionBinding,
      now: Instant
  ): IO[Either[OAuthError, URI]] =
    byProvider.get(providerName.toLowerCase) match
      case None => IO.pure(Left(OAuthError.ProviderRejected))
      case Some(connector) =>
        for
          id <- IO.delay(ConnectionId.random())
          state <- freshState
          verifier <- IO.delay(Option.when(connector.usesPkce)(PkceVerifier.generate(random)))
          reserved <- connections.reserve(tenant, id, connector.provider.value.toUpperCase, owner, now).attempt
          result <- reserved match
            case Left(_) => IO.pure(Left(OAuthError.ProviderRejected))
            case Right(_) =>
              val binding = SecretBinding(tenant, id)
              val stored = verifier.traverse(value => secrets.put(binding, ProviderSecret.fromUtf8(value.value)))
              stored.attempt.flatMap:
                case Left(_) => connections.failReserved(tenant, id, now).as(Left(OAuthError.ProviderRejected))
                case Right(verifierReference) =>
                  (states.purgeExpired(tenant, now).void *>
                    states.createBound(
                      tenant, catalogResource, connector.provider, id, redirectDigest(connector.redirectUri),
                      verifierReference, state, session, now.plus(stateTtl)
                    ) *>
                    connector.authorizationUri(state, verifier)).attempt.flatMap:
                    case Right(uri) => IO.pure(Right(uri))
                    case Left(_) =>
                      verifierReference.traverse_(reference => secrets.delete(binding, reference).attempt) *>
                        connections.failReserved(tenant, id, now).as(Left(OAuthError.ProviderRejected))
        yield result

  /** Starts reauthorizing a connection whose credential needs it. The existing connection ID is bound into state, so
    * the callback can only replace this connection's credential, and only for the same provider account. */
  def startReauthorization(
      tenant: TenantId,
      id: ConnectionId,
      owner: Principal.Human,
      session: OAuthSessionBinding,
      now: Instant
  ): IO[Either[OAuthError, URI]] =
    connections.list(tenant).flatMap: all =>
      all.find(connection => connection.id == id && connection.status == ConnectionStatus.NeedsReauth)
        .flatMap(connection => byProvider.get(connection.provider.toLowerCase).map(connection -> _)) match
        case None => IO.pure(Left(OAuthError.InvalidState))
        case Some((connection, connector)) =>
          for
            state <- freshState
            verifier <- IO.delay(Option.when(connector.usesPkce)(PkceVerifier.generate(random)))
            binding = SecretBinding(tenant, id)
            stored <- verifier.traverse(value => secrets.put(binding, ProviderSecret.fromUtf8(value.value))).attempt
            result <- stored match
              case Left(_) => IO.pure(Left(OAuthError.ProviderRejected))
              case Right(verifierReference) =>
                (states.purgeExpired(tenant, now).void *>
                  states.createBound(
                    tenant, connection.resource, connector.provider, id, redirectDigest(connector.redirectUri),
                    verifierReference, state, session, now.plus(stateTtl)
                  ) *>
                  connector.authorizationUri(state, verifier)).attempt.flatMap:
                  case Right(uri) => IO.pure(Right(uri))
                  case Left(_) =>
                    verifierReference.traverse_(reference => secrets.delete(binding, reference).attempt)
                      .as(Left(OAuthError.ProviderRejected))
          yield result

  /** Completes a connection. State consumption, the provider exchange, and credential storage happen outside the
    * gate; activation (connection, credential reference, and verified root in one transaction) happens inside it.
    * A successful connection is rooted at the provider-verified account and grants no agent authority. */
  def completeConnection(
      providerName: String,
      tenant: TenantId,
      owner: Principal.Human,
      session: OAuthSessionBinding,
      callback: OAuthCallback,
      gate: TenantExecutionMutationGate[IO],
      now: Instant
  ): IO[Either[OAuthError, Connection]] =
    byProvider.get(providerName.toLowerCase) match
      case None => IO.pure(Left(OAuthError.ProviderRejected))
      case Some(connector) =>
        states.purgeExpired(tenant, now).void *>
          states.consumeBound(tenant, connector.provider, redirectDigest(connector.redirectUri), callback.state, session, now)
            .flatMap:
              case Left(error) => IO.pure(Left(error))
              case Right(binding) =>
                val failed = (error: OAuthError) => connections.failReserved(tenant, binding.connection, now).as(Left(error))
                val reauthorizing = connections.list(tenant).map(_.exists(connection =>
                  connection.id == binding.connection && connection.status == ConnectionStatus.NeedsReauth
                ))
                verifierFor(connector, tenant, binding).flatMap:
                  case Left(error) => failed(error)
                  case Right(verifier) =>
                    connector.exchange(callback, verifier).flatMap:
                      case Left(error) => failed(error)
                      case Right(grant) =>
                        reauthorizing.flatMap:
                          case true  => replaceCredential(connector, tenant, owner, binding.connection, grant, gate)
                          case false => store(connector, tenant, owner, binding.connection, grant, gate)

  /** Loads the stored PKCE verifier once and deletes it, whatever the outcome of the exchange. */
  private def verifierFor(
      connector: ProviderConnector,
      tenant: TenantId,
      binding: OAuthStateBinding
  ): IO[Either[OAuthError, Option[PkceVerifier]]] =
    val secretBinding = SecretBinding(tenant, binding.connection)
    (connector.usesPkce, binding.pkceVerifier) match
      case (false, None) => IO.pure(Right(None))
      case (false, Some(reference)) =>
        secrets.delete(secretBinding, reference).attempt.as(Left(OAuthError.InvalidState))
      case (true, None) => IO.pure(Left(OAuthError.InvalidState))
      case (true, Some(reference)) =>
        secrets
          .get(secretBinding, reference)
          .map(_.toOption.flatMap(secret =>
            PkceVerifier.parse(new String(ProviderSecret.bytes(secret), StandardCharsets.US_ASCII))
          ).toRight(OAuthError.InvalidState).map(Some(_)))
          .guarantee(secrets.delete(secretBinding, reference).attempt.void)

  private def store(
      connector: ProviderConnector,
      tenant: TenantId,
      owner: Principal.Human,
      connection: ConnectionId,
      grant: OAuthGrant,
      gate: TenantExecutionMutationGate[IO]
  ): IO[Either[OAuthError, Connection]] =
    val secretBinding = SecretBinding(tenant, connection)
    secrets.put(secretBinding, grant.secret).attempt.flatMap:
      case Left(_) =>
        clock.now.flatMap(at => connections.failReserved(tenant, connection, at)).as(Left(OAuthError.ProviderRejected))
      case Right(reference) =>
        val activation = ConnectionActivation(
          owner,
          grant.externalAccountId,
          grant.accountLabel,
          grant.workspaceLabel,
          grant.expiresAt,
          connector.credentialType,
          reference,
          connector.rootKind,
          grant.rootExternalId,
          grant.rootDisplayName,
          connector.rootKind.custody match
            case Custody.Personal  => Some(owner.id)
            case Custody.Workspace => None
          ,
          connector.singleActiveRoot
        )
        // Only a reservation that is still CONNECTING is failed and its credential deleted. If the activation
        // committed and a later read failed, the connection is ACTIVE and its credential must stay.
        val cleanup = clock.now.flatMap(at => connections.failReserved(tenant, connection, at)).flatMap: failed =>
          secrets.delete(secretBinding, reference).attempt.void.whenA(failed)
        gate
          .withinMutation(tenant):
            clock.now.flatMap(at => connections.activateReserved(tenant, connection, activation, at))
          .onCancel(cleanup.attempt.void)
          .attempt
          .flatMap:
            case Right(Right(created)) => IO.pure(Right(created))
            case Right(Left(error))    => cleanup.as(Left(activationError(error)))
            case Left(failure)         => cleanup.attempt *> IO.raiseError(failure)

  /** Reauthorization: store the new credential outside the gate, swap the reference inside it, then delete the
    * superseded credential. A refused swap deletes only the new credential; the connection stays NEEDS_REAUTH. */
  private def replaceCredential(
      connector: ProviderConnector,
      tenant: TenantId,
      by: Principal.Human,
      connection: ConnectionId,
      grant: OAuthGrant,
      gate: TenantExecutionMutationGate[IO]
  ): IO[Either[OAuthError, Connection]] =
    val secretBinding = SecretBinding(tenant, connection)
    secrets.put(secretBinding, grant.secret).attempt.flatMap:
      case Left(_) => IO.pure(Left(OAuthError.ProviderRejected))
      case Right(reference) =>
        val reauthorization = ConnectionReauthorization(
          by, grant.externalAccountId, grant.rootExternalId, grant.expiresAt, connector.credentialType, reference
        )
        val discard = secrets.delete(secretBinding, reference).attempt.void
        gate
          .withinMutation(tenant):
            clock.now.flatMap(at => connections.reauthorize(tenant, connection, reauthorization, at))
          .attempt
          .flatMap:
            case Right(Right(previous)) =>
              secrets.delete(secretBinding, previous).attempt *>
                connections.list(tenant).map(_.find(_.id == connection).toRight(OAuthError.InvalidState))
            case Right(Left(error)) => discard.as(Left(activationError(error)))
            // The swap may have committed; the new credential may be live, so it is kept.
            case Left(failure) => IO.raiseError(failure)

  private def activationError(error: ConnectionActivationError): OAuthError = error match
    case ConnectionActivationError.AccountAlreadyConnected => OAuthError.AccountAlreadyConnected
    case ConnectionActivationError.RootKindInUse           => OAuthError.ProviderAlreadyConnected
    case ConnectionActivationError.NotReserved             => OAuthError.InvalidState
    case ConnectionActivationError.InvalidPlacement        => OAuthError.ProviderRejected
    case ConnectionActivationError.AccountMismatch         => OAuthError.AccountMismatch

  private def freshState: IO[OAuthState] = IO.delay:
    val raw = Array.ofDim[Byte](32)
    random.nextBytes(raw)
    OAuthState
      .parse(Base64.getUrlEncoder.withoutPadding.encodeToString(raw))
      .getOrElse(throw IllegalStateException("generated invalid OAuth state"))

  private def redirectDigest(uri: URI): Array[Byte] =
    MessageDigest.getInstance("SHA-256").digest(uri.toString.getBytes(StandardCharsets.UTF_8))

  /** Management discovery, outside the gate. The connection ID comes from the authenticated admin route. A stored
    * credential is read only when the connector lists selectable children, and only for that fixed listing. */
  def connectionResources(tenant: TenantId, id: ConnectionId): IO[Either[OAuthError, ConnectionResourceListing]] =
    connections.list(tenant).flatMap: all =>
      all.find(_.id == id).flatMap(connection => byProvider.get(connection.provider.toLowerCase).map(connection -> _)) match
        case None => IO.pure(Left(OAuthError.InvalidState))
        case Some((connection, _)) if connection.status != ConnectionStatus.Active => IO.pure(Left(OAuthError.InvalidState))
        case Some((_, connector)) =>
          resources.listFor(tenant, id).flatMap: current =>
            current.find(_.kind == connector.rootKind.wire) match
              case None => IO.pure(Left(OAuthError.InvalidState))
              case Some(root) =>
                connector.resourceDiscovery match
                  case None => IO.pure(Right(ConnectionResourceListing(current, Vector.empty)))
                  case Some(discovery) =>
                    connections.secretReference(tenant, id).flatMap:
                      case None => IO.pure(Left(OAuthError.ProviderRejected))
                      case Some(reference) =>
                        secrets.get(SecretBinding(tenant, id), reference).flatMap:
                          case Left(_) => IO.pure(Left(OAuthError.ProviderRejected))
                          case Right(secret) =>
                            discoveryCredential(connector, secret).flatMap:
                              case Left(error) => IO.pure(Left(error))
                              case Right(credential) =>
                                discovery.selectableResources(credential, root).map(_.map(ConnectionResourceListing(current, _)))

  /** The credential discovery may use. A refreshable record yields only its unexpired access token: the refresh token
    * never leaves the executor, and management never refreshes. An expired access token is refused; the next agent
    * call refreshes it, or the administrator reconnects. */
  private def discoveryCredential(connector: ProviderConnector, stored: ProviderSecret): IO[Either[OAuthError, ProviderSecret]] =
    if connector.credentialType != OAuthGrant.RefreshableCredentialType then IO.pure(Right(stored))
    else
      tokenCodec match
        case None => IO.pure(Left(OAuthError.ProviderRejected))
        case Some(codec) =>
          clock.now.map: now =>
            codec.decode(stored) match
              case Right(tokens) if tokens.expiresAt.isAfter(now) => Right(ProviderSecret.fromUtf8(tokens.accessToken))
              case _                                             => Left(OAuthError.ProviderRejected)

  /** Selection changes addressability, an authority mutation. The provider listing that validates the request runs
    * outside the gate; the replacement runs inside it, and the repository re-checks that the connection is active. */
  def replaceResources(
      tenant: TenantId,
      owner: Principal.Human,
      id: ConnectionId,
      requestedIds: Vector[String],
      gate: TenantExecutionMutationGate[IO]
  ): IO[Either[ConnectionResourceError, Vector[ConnectionResource]]] =
    if requestedIds.distinct.size != requestedIds.size then IO.pure(Left(ConnectionResourceError.AlreadySelected))
    else
      connectionResources(tenant, id).flatMap:
        case Left(_) => IO.pure(Left(ConnectionResourceError.ConnectionUnavailable))
        case Right(listing) =>
          val wanted = requestedIds.toSet
          if !wanted.subsetOf(listing.available.map(_.selectionKey).toSet) then
            IO.pure(Left(ConnectionResourceError.InvalidPlacement))
          else
            val selected = listing.available.filter(item => wanted.contains(item.selectionKey))
            gate.withinMutation(tenant):
              clock.now.flatMap(at => resources.replaceSelection(tenant, id, owner, selected, at))
