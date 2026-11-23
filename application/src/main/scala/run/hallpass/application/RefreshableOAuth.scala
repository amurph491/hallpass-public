package run.hallpass.application

import cats.effect.IO
import cats.syntax.all.*
import scala.concurrent.duration.*
import run.hallpass.kernel.*

/** Refresh is reachable only through the redeemed-lease credential strategy inside the executor's shared gate.
  * The durable pre-call marker is deliberately conservative: ambiguous rotation requires reconnecting, never retry.
  */
final class RefreshableOAuth[K](
    provider: ProviderId,
    repository: OAuthRefreshRepository,
    secrets: SecretStore[IO],
    codec: OAuthTokenCodec,
    refresher: OAuthTokenRefresher,
    clock: Clock[IO],
    rotation: RefreshTokenRotation,
    refreshSkew: FiniteDuration = 60.seconds
) extends CredentialStrategy[K, OAuthTokens]:
  require(refreshSkew >= Duration.Zero && refreshSkew <= 5.minutes)

  def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[K]): IO[Either[ConnectionError, OAuthTokens]] =
    if lease.tenant != target.tenant || lease.resource != target.resource || target.kind.provider != provider then
      IO.pure(Left(ConnectionError.InvalidState))
    else
      repository.withCredential(lease, target, provider): slot =>
        secrets.get(slot.binding, slot.reference).flatMap:
          case Left(_) => IO.pure(Left(ConnectionError.MissingCredential))
          case Right(secret) =>
            IO.delay(codec.decode(secret)).flatMap:
              case Left(error) => IO.pure(Left(error))
              case Right(tokens) if !slot.expiresAt.contains(tokens.expiresAt) =>
                IO.pure(Left(ConnectionError.InvalidState))
              case Right(tokens) =>
                clock.now.flatMap: now =>
                  if tokens.expiresAt.isAfter(now.plusMillis(refreshSkew.toMillis)) then IO.pure(Right(tokens))
                  else
                    slot.requireReauthorization(now).flatMap:
                      case Left(error) => IO.pure(Left(error))
                      case Right(_) if tokens.refreshToken.isEmpty => IO.pure(Left(ConnectionError.MissingCredential))
                      // Once the marker commits, a crash cannot cause an automatic reuse of a possibly consumed token.
                      // Exchange, storage, and publication are each bounded, so the segment runs uncancelable: a
                      // request deadline must not discard a token the provider has already rotated.
                      case Right(_) => IO.uncancelable(_ => exchange(slot, tokens))
      .handleErrorWith(_ => IO.raiseError(ProviderExecutionException(ProviderError.ConnectionUnavailable)))

  private def exchange(slot: LockedOAuthCredential, tokens: OAuthTokens): IO[Either[ConnectionError, OAuthTokens]] =
    refresher.refresh(tokens).attempt.flatMap:
      case Right(Right(next)) => store(slot, next)
      case outcome =>
        // The old refresh token provably survives a request that was never sent, and, for a non-rotating provider,
        // any answer short of an explicit rejection. Only then is the marker cleared; this call still fails.
        val survives = outcome match
          case Right(Left(OAuthRefreshError.NotSent)) => true
          case Right(Left(OAuthRefreshError.Rejected)) => false
          case _ => rotation == RefreshTokenRotation.NonRotating
        val restored =
          if survives then clock.now.flatMap(slot.restore).attempt.void else IO.unit
        restored.as(Left(ConnectionError.MissingCredential))

  private def store(slot: LockedOAuthCredential, next: OAuthTokens): IO[Either[ConnectionError, OAuthTokens]] =
    clock.now.flatMap: at =>
      if !next.expiresAt.isAfter(at.plusMillis(refreshSkew.toMillis)) || next.refreshToken.isEmpty then
        IO.pure(Left(ConnectionError.InvalidState))
      else
        secrets.put(slot.binding, codec.encode(next)).attempt.flatMap:
          case Left(_) => IO.pure(Left(ConnectionError.PersistenceFailure))
          case Right(reference) =>
            clock.now.flatMap: publicationAt =>
              if !next.expiresAt.isAfter(publicationAt.plusMillis(refreshSkew.toMillis)) then
                IO.pure(Left(ConnectionError.InvalidState))
              else
                slot.publish(reference, next.expiresAt, publicationAt).attempt.flatMap:
                  // Do not delete a replacement after an ambiguous commit. It may be the live pointer.
                  case Left(_) => IO.pure(Left(ConnectionError.PersistenceFailure))
                  case Right(Left(error)) => IO.pure(Left(error))
                  case Right(Right(_)) => secrets.delete(slot.binding, slot.reference).attempt.as(Right(next))
