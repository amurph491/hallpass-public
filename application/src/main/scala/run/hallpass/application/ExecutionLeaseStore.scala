package run.hallpass.application

import java.time.Instant

import cats.effect.IO
import cats.effect.Ref
import run.hallpass.kernel.ExecutionLeaseId
import run.hallpass.kernel.authorization.ExecutionLease
import run.hallpass.kernel.authorization.ExecutionLeaseValidationError
import run.hallpass.kernel.authorization.ExecutorAudience

/** Proof that a lease has been atomically redeemed by its intended executor. Credential-facing ports require this value
  * rather than an issued lease or connection identifier.
  */
opaque type RedeemedExecutionLease = (ExecutionLease, ExecutionAuditContext)
object RedeemedExecutionLease:
  private[application] def from(lease: ExecutionLease, context: ExecutionAuditContext): RedeemedExecutionLease =
    (lease, context)
  extension (lease: RedeemedExecutionLease)
    def id: ExecutionLeaseId = ExecutionLease.id(lease._1)
    def authorizationRequestId = ExecutionLease.authorizationRequestId(lease._1)
    def tenant = ExecutionLease.tenant(lease._1)
    def principal = ExecutionLease.principal(lease._1)
    def resource = ExecutionLease.resource(lease._1)
    def capability = ExecutionLease.capability(lease._1)
    def action = ExecutionLease.action(lease._1)
    def evidence = ExecutionLease.evidence(lease._1)
    def audience = ExecutionLease.audience(lease._1)
    def expiresAt = ExecutionLease.expiresAt(lease._1)
    def auditContext: ExecutionAuditContext = lease._2

/** Records the result of attempting to redeem an execution lease.
  *
  * A caller receives the lease only after this store has atomically marked it as redeemed. All other outcomes
  * deliberately provide no authority material.
  */
enum LeaseRedemption:
  case Redeemed(lease: RedeemedExecutionLease)
  case Unknown
  case Expired
  case AlreadyRedeemed
  case WrongAudience

/** Application boundary for the mutable, single-use state of execution leases.
  *
  * The kernel owns the immutable lease. Implementations of this interface own lifecycle state such as whether that
  * lease has already been redeemed.
  */
trait ExecutionLeaseStore[F[_]]:
  def issue(lease: ExecutionLease, context: ExecutionAuditContext): F[Unit]

  def redeem(
      id: ExecutionLeaseId,
      audience: ExecutorAudience,
      now: Instant
  ): F[LeaseRedemption]

/** In-process implementation of [[ExecutionLeaseStore]].
  *
  * It is correct with several API instances only because a lease is issued and redeemed within one request on one
  * instance and its ID never leaves the process: a lease presented to another instance's store is `Unknown` and fails
  * closed. Splitting issuance and execution across processes requires a shared atomic store instead.
  *
  * `Ref.modify` makes the check-and-mark transition one atomic operation. An existing entry is never replaced by
  * `issue`: a repeated ID must not reset a redeemed lease and thereby make it executable again.
  *
  * Memory is bounded. Entries past expiry are pruned, at most once per `pruneInterval`, during `issue`; after expiry a
  * redemption is denied whether or not the entry remains, so pruning never grants authority. If the live-entry count
  * still reaches `maximumEntries`, issuance fails closed instead of growing without bound.
  */
final class InMemoryExecutionLeaseStore private (
    state: Ref[IO, InMemoryExecutionLeaseStore.State],
    clock: Clock[IO],
    pruneInterval: java.time.Duration,
    maximumEntries: Int
) extends ExecutionLeaseStore[IO]:
  import InMemoryExecutionLeaseStore.{LeaseState, State}

  def issue(lease: ExecutionLease, context: ExecutionAuditContext): IO[Unit] =
    clock.now.flatMap: now =>
      state
        .modify: current =>
          val pruned =
            if now.isBefore(current.nextPruneAt) then current
            else
              State(
                current.leases.filter((_, entry) => now.isBefore(entry.lease.expiresAt)),
                now.plus(pruneInterval)
              )
          if pruned.leases.contains(lease.id) then (pruned, Right(()))
          else if pruned.leases.size >= maximumEntries then (pruned, Left(ExecutionLeaseStoreFull()))
          else (pruned.copy(leases = pruned.leases.updated(lease.id, LeaseState(lease, context, redeemed = false))), Right(()))
        .flatMap(IO.fromEither)

  def redeem(
      id: ExecutionLeaseId,
      audience: ExecutorAudience,
      now: Instant
  ): IO[LeaseRedemption] =
    state.modify: current =>
      current.leases.get(id) match
        case None        => (current, LeaseRedemption.Unknown)
        case Some(entry) =>
          entry.lease.validateFor(audience, now) match
            case Left(ExecutionLeaseValidationError.Expired) =>
              (current, LeaseRedemption.Expired)
            case Left(ExecutionLeaseValidationError.WrongAudience) =>
              (current, LeaseRedemption.WrongAudience)
            case Right(_) if entry.redeemed =>
              (current, LeaseRedemption.AlreadyRedeemed)
            case Right(lease) =>
              val redeemed = entry.copy(redeemed = true)
              (
                current.copy(leases = current.leases.updated(id, redeemed)),
                LeaseRedemption.Redeemed(RedeemedExecutionLease.from(lease, entry.context))
              )

  /** Entries currently retained, for bounded-memory tests and diagnostics. */
  def size: IO[Int] = state.get.map(_.leases.size)

/** Issuance refused because the in-process store is at capacity. No lease is created, so nothing can execute. */
final case class ExecutionLeaseStoreFull() extends RuntimeException("execution lease store is at capacity")

object InMemoryExecutionLeaseStore:
  private final case class LeaseState(lease: ExecutionLease, context: ExecutionAuditContext, redeemed: Boolean)
  private final case class State(leases: Map[ExecutionLeaseId, LeaseState], nextPruneAt: Instant)

  val DefaultPruneInterval: java.time.Duration = java.time.Duration.ofSeconds(10)
  val DefaultMaximumEntries: Int = 100000

  def create: IO[InMemoryExecutionLeaseStore] = create(Clock.system, DefaultPruneInterval, DefaultMaximumEntries)

  def create(
      clock: Clock[IO],
      pruneInterval: java.time.Duration,
      maximumEntries: Int
  ): IO[InMemoryExecutionLeaseStore] =
    IO.raiseUnless(maximumEntries >= 1 && !pruneInterval.isNegative)(
      IllegalArgumentException("lease store bounds must be positive")
    ) *>
      Ref
        .of[IO, State](State(Map.empty, Instant.MIN))
        .map(new InMemoryExecutionLeaseStore(_, clock, pruneInterval, maximumEntries))
