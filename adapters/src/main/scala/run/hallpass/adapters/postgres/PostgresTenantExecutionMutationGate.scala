package run.hallpass.adapters.postgres

import java.sql.{Connection, SQLException}
import java.util.UUID
import scala.concurrent.duration.*
import scala.util.control.NonFatal
import cats.effect.{IO, Resource}
import com.zaxxer.hikari.HikariDataSource
import run.hallpass.application.*
import run.hallpass.kernel.TenantId

/** Safe, bounded settings for the multi-instance tenant gate. */
final case class PostgresTenantGateConfig private (
    maximumPoolSize: Int,
    acquisitionTimeout: FiniteDuration,
    connectionLossDetection: FiniteDuration
)

object PostgresTenantGateConfig:
  val default: PostgresTenantGateConfig = PostgresTenantGateConfig(16, 10.seconds, 15.seconds)

  def from(
      maximumPoolSize: Int,
      acquisitionTimeout: FiniteDuration,
      connectionLossDetection: FiniteDuration = default.connectionLossDetection
  ): Either[String, PostgresTenantGateConfig] =
    if maximumPoolSize < 1 || maximumPoolSize > 256 then Left("tenant gate pool size must be between 1 and 256")
    else if acquisitionTimeout < 250.millis || acquisitionTimeout > 5.minutes then
      Left("tenant gate acquisition timeout must be between 250ms and 5 minutes")
    else if connectionLossDetection < 3.seconds || connectionLossDetection > 10.minutes then
      Left("tenant gate connection-loss detection must be between 3 seconds and 10 minutes")
    else Right(PostgresTenantGateConfig(maximumPoolSize, acquisitionTimeout, connectionLossDetection))

  def fromEnvironment(environment: Map[String, String] = sys.env): Either[String, PostgresTenantGateConfig] =
    for
      poolSize <- environment.get("HALLPASS_TENANT_GATE_POOL_SIZE").map(_.trim).filter(_.nonEmpty) match
        case None      => Right(default.maximumPoolSize)
        case Some(raw) => raw.toIntOption.toRight("HALLPASS_TENANT_GATE_POOL_SIZE must be an integer")
      timeout <- environment.get("HALLPASS_TENANT_GATE_ACQUIRE_TIMEOUT_MS").map(_.trim).filter(_.nonEmpty) match
        case None      => Right(default.acquisitionTimeout)
        case Some(raw) => raw.toLongOption.map(_.millis).toRight("HALLPASS_TENANT_GATE_ACQUIRE_TIMEOUT_MS must be an integer")
      config <- from(poolSize, timeout)
    yield config

/** Multi-instance readers–writer tenant gate backed by PostgreSQL session-level advisory locks.
  *
  * Executions hold `pg_advisory_lock_shared`; authority mutations hold `pg_advisory_lock`. Each critical section owns
  * one dedicated connection from the gate pool for its whole duration, and the lock lives exactly as long as that
  * server session.
  *
  * Writer preference (revocation cannot be starved) relies on PostgreSQL's heavyweight lock queue rather than on an
  * application-level fairness mechanism. In `LockAcquire`/`LockCheckConflicts` (src/backend/storage/lmgr/lock.c), a
  * new request whose mode conflicts with the *wait mask* of an already-queued request must wait even if it is
  * compatible with every granted holder. `ShareLock` conflicts with a waiting `ExclusiveLock`, so a queued mutation
  * blocks every shared request that arrives after it, and `ProcLockWakeup` grants waiters in queue order. The one
  * exception (`ProcSleep` lets a requester jump ahead of waiters when it *already holds* a lock on the same object that
  * those waiters conflict with) cannot occur here: a gate session holds at most one gate lock and each acquisition
  * uses a fresh critical section on its own connection. `PostgresTenantExecutionMutationGateSuite` checks this with a
  * continuous stream of overlapping shared holders and asserts that a mutation completes within a fixed bound.
  *
  * Failure model: PostgreSQL releases a lock only when it is unlocked or the owning session ends. A holder that crashes
  * cannot dispatch. For a holder that is partitioned from the database, the server ends the session after TCP
  * keepalive / user-timeout detection, which is configured per gate session. `confirmHeld` proves from `pg_locks`, on
  * that same session, that the lock is still granted. The executor calls it immediately before dispatch, so the
  * unfenced window is only from that proof to the request leaving the process. An external provider cannot be fenced,
  * so this window is bounded and documented rather than zero.
  *
  * A connection is returned to the pool only after PostgreSQL confirms the unlock. On any doubt it is evicted, which
  * closes the session and releases every lock it could hold.
  */
final class PostgresTenantExecutionMutationGate private (
    dataSource: HikariDataSource,
    config: PostgresTenantGateConfig
) extends TenantExecutionMutationGate[IO]:
  import PostgresTenantExecutionMutationGate.*

  def withinExecution[A](tenant: TenantId)(operation: ExecutionGatePermit[IO] => IO[A]): IO[A] =
    held(tenant, LockMode.Shared).use(lock => operation(lock.permit))

  def withinMutation[A](tenant: TenantId)(operation: IO[A]): IO[A] =
    held(tenant, LockMode.Exclusive).use(_ => operation)

  /** Readiness probe: the gate pool can hand out a live session. Takes no lock and never throws. */
  def healthy: IO[Boolean] =
    IO.blocking:
      val connection = dataSource.getConnection()
      try connection.isValid(2)
      finally connection.close()
    .handleError(_ => false)

  /** Acquisition is uncancelable but bounded by the pool wait plus `lock_timeout`, both within `acquisitionTimeout`;
    * release always runs, including on error and cancellation. */
  private def held(tenant: TenantId, mode: LockMode): Resource[IO, HeldLock] =
    Resource.make(acquire(LockKey.of(tenant), mode))(release)

  private def acquire(key: LockKey, mode: LockMode): IO[HeldLock] =
    IO.blocking:
      val started = System.nanoTime()
      val connection =
        try dataSource.getConnection()
        catch case NonFatal(_) => throw TenantGateException(TenantGateFailure.CoordinatorUnavailable)
      try
        val remaining = config.acquisitionTimeout.toMillis - (System.nanoTime() - started) / 1000000L
        if remaining <= 0 then throw TenantGateException(TenantGateFailure.AcquisitionTimedOut)
        configureSession(connection, remaining)
        val statement = connection.prepareStatement(s"select ${mode.lockFunction}(?, ?)")
        try
          statement.setInt(1, key.classId)
          statement.setInt(2, key.objectId)
          statement.execute()
        finally statement.close()
        HeldLock(connection, key, mode)
      catch
        case error: TenantGateException =>
          evict(connection)
          throw error
        case error: SQLException if error.getSQLState == LockNotAvailable || error.getSQLState == QueryCanceled =>
          evict(connection)
          throw TenantGateException(TenantGateFailure.AcquisitionTimedOut)
        case NonFatal(_) =>
          evict(connection)
          throw TenantGateException(TenantGateFailure.CoordinatorUnavailable)

  /** Session settings are reapplied on every acquisition because pooled sessions are reused. */
  private def configureSession(connection: Connection, lockTimeoutMillis: Long): Unit =
    val detectionSeconds = math.max(3L, config.connectionLossDetection.toSeconds)
    val idle = math.max(1L, detectionSeconds / 3)
    val count = 5L
    val interval = math.max(1L, (detectionSeconds - idle) / count)
    val statement = connection.prepareStatement(
      """select set_config('lock_timeout', ?, false),
        |       set_config('tcp_keepalives_idle', ?, false),
        |       set_config('tcp_keepalives_interval', ?, false),
        |       set_config('tcp_keepalives_count', ?, false),
        |       set_config('tcp_user_timeout', ?, false)""".stripMargin
    )
    try
      statement.setString(1, s"${math.max(1L, lockTimeoutMillis)}ms")
      statement.setString(2, idle.toString)
      statement.setString(3, interval.toString)
      statement.setString(4, count.toString)
      statement.setString(5, (detectionSeconds * 1000L).toString)
      statement.execute()
    finally statement.close()

  private def release(lock: HeldLock): IO[Unit] =
    IO.blocking:
      val unlocked =
        try
          val statement = lock.connection.prepareStatement(s"select ${lock.mode.unlockFunction}(?, ?)")
          try
            statement.setInt(1, lock.key.classId)
            statement.setInt(2, lock.key.objectId)
            val result = statement.executeQuery()
            try result.next() && result.getBoolean(1)
            finally result.close()
          finally statement.close()
        catch case NonFatal(_) => false
      if unlocked then
        try lock.connection.close()
        catch case NonFatal(_) => ()
      else evict(lock.connection)
    .handleError(_ => ())

  private def evict(connection: Connection): Unit =
    try dataSource.evictConnection(connection)
    catch
      case NonFatal(_) =>
        try connection.close()
        catch case NonFatal(_) => ()

  private final case class HeldLock(connection: Connection, key: LockKey, mode: LockMode):
    val permit: ExecutionGatePermit[IO] = new ExecutionGatePermit[IO]:
      def confirmHeld: IO[Unit] =
        IO.blocking(stillGranted(connection, key, mode))
          .handleError(_ => false)
          .flatMap(granted => IO.raiseUnless(granted)(TenantGateException(TenantGateFailure.OwnershipLost)))

  private def stillGranted(connection: Connection, key: LockKey, mode: LockMode): Boolean =
    val statement = connection.prepareStatement(
      """select exists(
        |  select 1 from pg_locks
        |  where locktype = 'advisory'
        |    and pid = pg_backend_pid()
        |    and classid::text = ?
        |    and objid::text = ?
        |    and objsubid = 2
        |    and mode = ?
        |    and granted
        |)""".stripMargin
    )
    try
      statement.setString(1, Integer.toUnsignedString(key.classId))
      statement.setString(2, Integer.toUnsignedString(key.objectId))
      statement.setString(3, mode.pgLocksMode)
      val result = statement.executeQuery()
      try result.next() && result.getBoolean(1)
      finally result.close()
    finally statement.close()

object PostgresTenantExecutionMutationGate:
  private val LockNotAvailable = "55P03"
  private val QueryCanceled = "57014"

  private[postgres] enum LockMode(val lockFunction: String, val unlockFunction: String, val pgLocksMode: String):
    case Shared extends LockMode("pg_advisory_lock_shared", "pg_advisory_unlock_shared", "ShareLock")
    case Exclusive extends LockMode("pg_advisory_lock", "pg_advisory_unlock", "ExclusiveLock")

  /** A 64-bit tenant key in the two-int advisory key space (`objsubid = 2` in `pg_locks`).
    *
    * The two-int space is reserved for the tenant gate. Flyway uses the single-bigint space (`objsubid = 1`), which
    * PostgreSQL keeps distinct. The key folds the UUID's two 64-bit halves together; a random (v4) UUID has 122 random
    * bits, so the key is uniform over 2^64 and a collision between unrelated tenants is negligible (below 1e-7 even at
    * one million tenants). A collision would only over-serialize the two tenants; it never lets an execution run
    * concurrently with a mutation in its own tenant. */
  private[postgres] final case class LockKey(classId: Int, objectId: Int)
  private[postgres] object LockKey:
    def of(tenant: TenantId): LockKey =
      val uuid = UUID.fromString(tenant.toString)
      val folded = uuid.getMostSignificantBits ^ uuid.getLeastSignificantBits
      LockKey((folded >>> 32).toInt, folded.toInt)

  def resource(
      database: DatabaseConfig,
      config: PostgresTenantGateConfig = PostgresTenantGateConfig.default
  ): Resource[IO, PostgresTenantExecutionMutationGate] =
    val socketTimeoutSeconds =
      (config.acquisitionTimeout + config.connectionLossDetection).toSeconds.toInt + 5
    PostgresDatabase
      .gateDataSource(database, config.maximumPoolSize, config.acquisitionTimeout.toMillis, socketTimeoutSeconds)
      .map(new PostgresTenantExecutionMutationGate(_, config))
