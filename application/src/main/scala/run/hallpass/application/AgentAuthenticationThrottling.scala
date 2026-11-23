package run.hallpass.application

import java.net.InetAddress
import java.security.SecureRandom
import java.util.{Arrays, HexFormat}
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import scala.concurrent.duration.*
import cats.effect.{IO, Ref, Resource}
import cats.syntax.all.*

/** Why an agent credential presentation was rejected, as recorded in the rejection audit. Never contains bearer
  * material. */
enum AgentRejectionReason:
  case MalformedCredential, UnroutedCredential, UnknownCredential, ExpiredCredential, RevokedCredential, WrongSecret
  case CredentialNoLongerActive, InvalidStoredCredential, Locked

object AgentRejectionReason:
  def of(rejection: AgentCredentialRejection): AgentRejectionReason = rejection match
    case AgentCredentialRejection.UnroutedCredential       => UnroutedCredential
    case AgentCredentialRejection.UnknownCredential        => UnknownCredential
    case AgentCredentialRejection.ExpiredCredential        => ExpiredCredential
    case AgentCredentialRejection.RevokedCredential        => RevokedCredential
    case AgentCredentialRejection.WrongSecret              => WrongSecret
    case AgentCredentialRejection.CredentialNoLongerActive => CredentialNoLongerActive
    case AgentCredentialRejection.InvalidStoredCredential  => InvalidStoredCredential

/** Durable, cross-instance lockout of one credential selector after repeated wrong-secret attempts, and the audit of
  * rejected presentations.
  *
  * Only wrong-secret failures count toward a lockout: they are the only failures that target a real credential. A
  * locked selector is rejected before verification with the same 401 as any other rejection, so lockout does not
  * reveal which selectors exist. Implementations store a digest of the selector, never the selector or secret. */
trait AgentAuthenticationLockout:
  def isLocked(selector: AgentCredentialSelector): IO[Either[DirectoryError, Boolean]]
  def recordRejection(
      selector: Option[AgentCredentialSelector],
      reason: AgentRejectionReason,
      client: Option[InetAddress]
  ): IO[Either[DirectoryError, Unit]]

object AgentAuthenticationLockout:
  /** For compositions without the directory (tests of other behavior). Production always uses the durable one. */
  val disabled: AgentAuthenticationLockout = new AgentAuthenticationLockout:
    def isLocked(selector: AgentCredentialSelector): IO[Either[DirectoryError, Boolean]] = IO.pure(Right(false))
    def recordRejection(
        selector: Option[AgentCredentialSelector],
        reason: AgentRejectionReason,
        client: Option[InetAddress]
    ): IO[Either[DirectoryError, Unit]] = IO.pure(Right(()))

/** A per-instance failed-authentication budget. Each attempt reserves one token atomically before authentication;
  * success or an infrastructure failure refunds it, while rejection or cancellation consumes it. Pending attempts
  * also bound concurrency: time cannot refill reserved tokens. A shared address can have at most `capacity` concurrent
  * authentications, and successful calls cost no lasting budget.
  *
  * Memory is bounded. Only fully recovered clients with no pending attempts may be evicted. When the table is full
  * of active clients, new addresses are throttled rather than resetting an offender's budget or losing a reservation.
  * Each instance has its own budget; the durable selector lockout is the fleet-wide control. */
final class FailedAuthenticationLimiter private (
    buckets: Ref[IO, Map[InetAddress, FailedAuthenticationLimiter.Bucket]],
    capacity: Int,
    refillEvery: FiniteDuration,
    maximumClients: Int,
    now: IO[FiniteDuration]
):
  import FailedAuthenticationLimiter.{Attempt, Bucket}

  /** The resource releases pending admission on every exit. Only an authenticated success or infrastructure failure
    * should call `refund`; a canceled request spends its token so cancellation cannot bypass the budget. */
  def admit(client: InetAddress): Resource[IO, Either[FiniteDuration, Attempt]] =
    Resource.eval(Ref.of[IO, Boolean](false)).flatMap: refunded =>
      Resource.make(reserve(client).map(_.map(_ => Attempt(refunded.set(true))))):
        case Left(_) => IO.unit
        case Right(_) => refunded.get.flatMap(settle(client, _))

  private def reserve(client: InetAddress): IO[Either[FiniteDuration, Unit]] =
    now.flatMap: at =>
      buckets.modify: current =>
        val retained =
          if current.contains(client) || current.size < maximumClients then current
          else current.filter((_, bucket) => bucket.pending > 0 || refilled(bucket, at).tokens < capacity)
        if !retained.contains(client) && retained.size >= maximumClients then retained -> Left(refillEvery)
        else
          val bucket = retained.get(client).map(refilled(_, at)).getOrElse(Bucket(capacity.toDouble, 0, at))
          if bucket.tokens < 1 || bucket.pending >= capacity then
            val wait = math.max(1L, math.ceil((1 - bucket.tokens) * refillEvery.toNanos).toLong).nanos
            retained.updated(client, bucket) -> Left(wait)
          else
            retained.updated(client, bucket.copy(tokens = bucket.tokens - 1, pending = bucket.pending + 1)) -> Right(())

  private def settle(client: InetAddress, refund: Boolean): IO[Unit] =
    now.flatMap: at =>
      buckets.update: current =>
        // A bucket with a pending reservation cannot be evicted.
        val bucket = refilled(current(client), at)
        val pending = bucket.pending - 1
        val tokens = math.min((capacity - pending).toDouble, bucket.tokens + (if refund then 1 else 0))
        current.updated(client, bucket.copy(tokens = tokens, pending = pending))

  private def refilled(bucket: Bucket, at: FiniteDuration): Bucket =
    val earned = math.max(0L, (at - bucket.updatedAt).toNanos).toDouble / refillEvery.toNanos
    bucket.copy(tokens = math.min((capacity - bucket.pending).toDouble, bucket.tokens + earned),
      updatedAt = if at > bucket.updatedAt then at else bucket.updatedAt)

object FailedAuthenticationLimiter:
  private[application] final case class Bucket(tokens: Double, pending: Int, updatedAt: FiniteDuration)

  final class Attempt private[application] (val refund: IO[Unit])

  /** 20 failures in a burst, then one more every 3 seconds (20 a minute sustained). */
  def create(
      capacity: Int = 20,
      refillEvery: FiniteDuration = 3.seconds,
      maximumClients: Int = 100000,
      now: IO[FiniteDuration] = IO.monotonic
  ): IO[FailedAuthenticationLimiter] =
    require(capacity >= 1 && refillEvery > Duration.Zero && maximumClients >= 1)
    Ref.of[IO, Map[InetAddress, Bucket]](Map.empty).map(FailedAuthenticationLimiter(_, capacity, refillEvery, maximumClients, now))

/** A bounded, per-instance memory of bearer credentials that were rejected for a reason that cannot become false for
  * that exact bearer. A client that keeps presenting one (a stale bridge after a revocation) is answered from this
  * table with the same 401 as any other rejection, before the address budget, the lockout store, credential
  * verification, or the rejection audit, so it stops draining the budget its neighbours behind a shared address
  * depend on.
  *
  * The table can only turn a request into a rejection. It never authenticates: a hit skips verification, and a miss
  * changes nothing. Its key is an HMAC-SHA-256 of the entire presented bearer (selector and secret) under a random
  * key generated when the instance starts and never persisted or exposed, so a different secret for the same selector
  * is a different key and still spends the budget and counts toward the durable selector lockout, and a memory dump
  * of the table holds neither the bearer, the secret, nor an unkeyed hash of them.
  *
  * Only rejections that are terminal for the bearer are remembered, and the set is fixed by an exhaustive match on
  * [[AgentCredentialRejection]] so a new rejection must be classified deliberately. `Locked` is not an
  * [[AgentCredentialRejection]] (a lockout is temporary), `InvalidStoredCredential` is excluded (an operator repair
  * can make the credential valid), and unavailability and success never reach `remember`.
  *
  * The TTL slides: each hit extends it, so a client polling at least once per TTL never costs budget again. Memory is
  * bounded. When full, expired entries are dropped first; if it is still full the rejection is simply not remembered
  * and that client keeps spending budget. Every remembered rejection spent a budget token first, so filling the table
  * with random bearers is limited to what the address budgets allow. Entries live only in this process, so an
  * instance restart (which is also how its verification key ring changes) starts empty. */
final class RecentAgentRejections private (
    table: Ref[IO, Map[String, FiniteDuration]],
    key: SecretKeySpec,
    ttl: FiniteDuration,
    maximumEntries: Int,
    now: IO[FiniteDuration]
):
  /** True when this exact bearer was recently rejected for a terminal reason. A hit refreshes its TTL. */
  def isRecentlyRejected(presented: PresentedAgentCredential): IO[Boolean] =
    (digest(presented), now).tupled.flatMap: (id, at) =>
      table.modify: current =>
        current.get(id) match
          case Some(expiresAt) if expiresAt > at => current.updated(id, at + ttl) -> true
          case Some(_)                            => current.removed(id) -> false
          case None                               => current -> false

  /** Remembers a rejection if it is terminal for the bearer. Returns whether the bearer is now in the table. */
  def remember(presented: PresentedAgentCredential, rejection: AgentCredentialRejection): IO[Boolean] =
    if !RecentAgentRejections.terminal(rejection) then IO.pure(false)
    else
      (digest(presented), now).tupled.flatMap: (id, at) =>
        table.modify: current =>
          if current.contains(id) then current.updated(id, at + ttl) -> true
          else
            val live = if current.size < maximumEntries then current else current.filter((_, expiresAt) => expiresAt > at)
            if live.size >= maximumEntries then live -> false
            else live.updated(id, at + ttl) -> true

  /** HMAC-SHA-256 over at most a few hundred bytes takes about a microsecond and performs no I/O, so it runs on
    * `IO.delay`: a thread hop through `IO.blocking` would cost more than the work on the path whose purpose is to be
    * cheap. A `Mac` is not thread-safe, so each call creates its own. The bearer bytes are a fresh copy and are zeroed. */
  private def digest(presented: PresentedAgentCredential): IO[String] =
    IO.delay:
      val bearer = PresentedAgentCredential.canonicalBytes(presented)
      try
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(key)
        HexFormat.of.formatHex(mac.doFinal(bearer))
      finally Arrays.fill(bearer, 0.toByte)

object RecentAgentRejections:
  val DefaultTtl: FiniteDuration = 10.minutes
  val DefaultMaximumEntries: Int = 10000

  /** Rejections that cannot become false for the exact bearer presented:
    *  - Unrouted, Unknown: a credential's selector and secret are generated together, server side, at enrollment, and
    *    the bearer is disclosed only after that transaction commits; no route or row can later appear for it.
    *  - Expired, Revoked: `expires_at` is never updated, and `revoked_at` is only ever set (`coalesce`), never
    *    cleared. A revoked credential is terminal and cannot be rotated. Rotation issues a new bearer.
    *  - WrongSecret: the stored verifier and its key id are immutable. The one way a wrong secret could later match is
    *    a verification key missing from this instance's key ring, which is fixed by restarting the instance and so
    *    also clears this table.
    *  - CredentialNoLongerActive: the credential was revoked or expired between lookup and use. */
  private[application] def terminal(rejection: AgentCredentialRejection): Boolean = rejection match
    case AgentCredentialRejection.UnroutedCredential | AgentCredentialRejection.UnknownCredential |
        AgentCredentialRejection.ExpiredCredential | AgentCredentialRejection.RevokedCredential |
        AgentCredentialRejection.WrongSecret | AgentCredentialRejection.CredentialNoLongerActive => true
    case AgentCredentialRejection.InvalidStoredCredential => false

  /** Ten minutes, up to 10,000 bearers. The digest key is 256 random bits from a `SecureRandom`, generated here. */
  def create(
      ttl: FiniteDuration = DefaultTtl,
      maximumEntries: Int = DefaultMaximumEntries,
      now: IO[FiniteDuration] = IO.monotonic
  ): IO[RecentAgentRejections] =
    require(ttl > Duration.Zero && maximumEntries >= 1)
    IO.blocking:
      val bytes = Array.ofDim[Byte](32)
      try
        SecureRandom().nextBytes(bytes)
        SecretKeySpec(bytes, "HmacSHA256")
      finally Arrays.fill(bytes, 0.toByte)
    .flatMap(key => Ref.of[IO, Map[String, FiniteDuration]](Map.empty).map(RecentAgentRejections(_, key, ttl, maximumEntries, now)))
