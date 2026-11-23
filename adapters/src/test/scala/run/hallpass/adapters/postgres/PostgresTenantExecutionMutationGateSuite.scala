package run.hallpass.adapters.postgres

import java.sql.DriverManager
import scala.compiletime.uninitialized
import scala.concurrent.duration.*
import cats.effect.{Deferred, IO, Ref, Resource}
import cats.syntax.all.*
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import run.hallpass.application.*
import run.hallpass.kernel.TenantId

/** Two independently pooled gates stand in for two API instances sharing one PostgreSQL. */
final class PostgresTenantExecutionMutationGateSuite extends CatsEffectSuite:
  override val munitIOTimeout: Duration = 90.seconds

  private var container: PostgreSQLContainer[?] = uninitialized
  private var dockerAvailable = false

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      admin: statement =>
        statement.execute("create role hallpass login password 'test-password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute("grant connect on database test to hallpass")
        statement.execute("create role hallpass_outage login password 'test-password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute("grant connect on database test to hallpass_outage")

  override def afterAll(): Unit = if dockerAvailable then container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  private def admin[A](use: java.sql.Statement => A): A =
    val connection = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
    try use(connection.createStatement())
    finally connection.close()

  private def databaseConfig(user: String = "hallpass"): DatabaseConfig =
    DatabaseConfig
      .fromEnvironment(
        Map("HALLPASS_DB_URL" -> container.getJdbcUrl, "HALLPASS_DB_USER" -> user, "HALLPASS_DB_PASSWORD" -> "test-password")
      )
      .toOption
      .get

  private def gate(
      timeout: FiniteDuration = 5.seconds,
      poolSize: Int = 8,
      user: String = "hallpass"
  ): Resource[IO, PostgresTenantExecutionMutationGate] =
    PostgresTenantExecutionMutationGate.resource(
      databaseConfig(user),
      PostgresTenantGateConfig.from(poolSize, timeout).toOption.get
    )

  private def instances = (gate(), gate()).tupled

  /** Counts Hallpass gate locks, granted or waiting, across all sessions. */
  private def gateLocks(granted: Boolean): IO[Int] = IO.blocking:
    admin: statement =>
      val result = statement.executeQuery(
        s"select count(*) from pg_locks where locktype = 'advisory' and objsubid = 2 and granted = $granted"
      )
      result.next()
      result.getInt(1)

  private def eventually(condition: IO[Boolean]): IO[Unit] =
    condition.flatMap:
      case true  => IO.unit
      case false => IO.sleep(20.millis) *> eventually(condition)
    .timeout(10.seconds)

  test("executions on different instances hold the same tenant gate concurrently") {
    requireDocker()
    instances.use: (a, b) =>
      val tenant = TenantId.random()
      for
        both <- Deferred[IO, Unit]
        inside <- Ref.of[IO, Int](0)
        enter = (g: PostgresTenantExecutionMutationGate) =>
          g.withinExecution(tenant): permit =>
            permit.confirmHeld *>
              inside.updateAndGet(_ + 1).flatMap(count => both.complete(()).whenA(count == 2)) *>
              both.get.timeout(5.seconds)
        _ <- (enter(a), enter(b)).parTupled
        remaining <- gateLocks(granted = true)
      yield assertEquals(remaining, 0)
  }

  test("a mutation on one instance waits for an execution on another; the next execution observes it") {
    requireDocker()
    instances.use: (a, b) =>
      val tenant = TenantId.random()
      for
        executing <- Deferred[IO, Unit]
        finish <- Deferred[IO, Unit]
        log <- Ref.of[IO, Vector[String]](Vector.empty)
        execution <- a.withinExecution(tenant)(_ => executing.complete(()) *> finish.get *> log.update(_ :+ "execution")).start
        _ <- executing.get
        mutation <- b.withinMutation(tenant)(log.update(_ :+ "revocation committed")).start
        _ <- eventually(gateLocks(granted = false).map(_ == 1))
        whileExecuting <- log.get
        _ <- finish.complete(())
        _ <- execution.joinWithNever *> mutation.joinWithNever
        _ <- a.withinExecution(tenant)(_ => log.update(_ :+ "next execution"))
        finalLog <- log.get
      yield
        assertEquals(whileExecuting, Vector.empty)
        assertEquals(finalLog, Vector("execution", "revocation committed", "next execution"))
  }

  test("a queued mutation blocks executions that arrive after it, on any instance") {
    requireDocker()
    instances.use: (a, b) =>
      val tenant = TenantId.random()
      for
        executing <- Deferred[IO, Unit]
        finish <- Deferred[IO, Unit]
        log <- Ref.of[IO, Vector[String]](Vector.empty)
        first <- a.withinExecution(tenant)(_ => executing.complete(()) *> finish.get).start
        _ <- executing.get
        mutation <- b.withinMutation(tenant)(log.update(_ :+ "mutation")).start
        _ <- eventually(gateLocks(granted = false).map(_ == 1))
        late <- a.withinExecution(tenant)(_ => log.update(_ :+ "late execution")).start
        _ <- eventually(gateLocks(granted = false).map(_ == 2))
        whileQueued <- log.get
        _ <- finish.complete(())
        _ <- first.joinWithNever *> mutation.joinWithNever *> late.joinWithNever
        finalLog <- log.get
      yield
        assertEquals(whileQueued, Vector.empty)
        assertEquals(finalLog, Vector("mutation", "late execution"))
  }

  test("contended acquisition fails closed within its bound and leaves no lock behind") {
    requireDocker()
    (gate(), gate(timeout = 500.millis)).tupled.use: (holder, contender) =>
      val tenant = TenantId.random()
      for
        // Open the contender's pooled session first, so the 500 ms bound measures lock contention rather than a cold
        // connection to the test database (which, on a loaded machine, fails closed as CoordinatorUnavailable instead).
        warm <- contender.healthy
        _ = assert(warm, "the contender's pool connects")
        holding <- Deferred[IO, Unit]
        release <- Deferred[IO, Unit]
        held <- holder.withinMutation(tenant)(holding.complete(()) *> release.get).start
        _ <- holding.get
        ran <- Ref.of[IO, Boolean](false)
        started <- IO.monotonic
        outcome <- contender.withinExecution(tenant)(_ => ran.set(true)).attempt
        elapsed <- IO.monotonic.map(_ - started)
        _ <- release.complete(()) *> held.joinWithNever
        executed <- ran.get
        _ <- contender.withinExecution(tenant)(_ => ran.set(true))
        remaining <- gateLocks(granted = true)
      yield
        assertEquals(outcome, Left(TenantGateException(TenantGateFailure.AcquisitionTimedOut)))
        assert(!executed)
        assert(elapsed < 5.seconds, s"acquisition was not bounded: $elapsed")
        assertEquals(remaining, 0)
  }

  test("a holder whose session is terminated cannot prove ownership and does not dispatch") {
    requireDocker()
    instances.use: (a, b) =>
      val tenant = TenantId.random()
      for
        holding <- Deferred[IO, Unit]
        terminated <- Deferred[IO, Unit]
        dispatched <- Ref.of[IO, Boolean](false)
        execution <- a
          .withinExecution(tenant): permit =>
            holding.complete(()) *> terminated.get *> permit.confirmHeld *> dispatched.set(true)
          .attempt
          .start
        _ <- holding.get
        // Simulates coordinator-side loss of the holder (network partition detected, failover, or operator action).
        _ <- IO.blocking:
          admin: statement =>
            statement.execute(
              "select pg_terminate_backend(pid) from pg_locks where locktype = 'advisory' and objsubid = 2"
            )
        // The lock is gone, so a mutation on another instance proceeds without waiting for the stale holder.
        _ <- b.withinMutation(tenant)(IO.unit).timeout(5.seconds)
        _ <- terminated.complete(())
        outcome <- execution.joinWithNever
        didDispatch <- dispatched.get
        // The evicted connection is replaced and the gate keeps working.
        _ <- a.withinExecution(tenant)(_.confirmHeld)
      yield
        assertEquals(outcome, Left(TenantGateException(TenantGateFailure.OwnershipLost)))
        assert(!didDispatch)
  }

  test("a mutation is not starved by a continuous stream of overlapping executions on both instances") {
    requireDocker()
    (gate(poolSize = 8), gate(poolSize = 8)).tupled.use: (a, b) =>
      val tenant = TenantId.random()
      for
        stop <- Ref.of[IO, Boolean](false)
        executions <- Ref.of[IO, Int](0)
        // Six overlapping 40 ms holders keep the shared lock continuously granted: without writer preference, an
        // exclusive request would wait until the stream stops.
        reader = (g: PostgresTenantExecutionMutationGate, offset: FiniteDuration) =>
          IO.sleep(offset) *>
            (g.withinExecution(tenant)(_ => IO.sleep(40.millis)) *> executions.update(_ + 1))
              .whileM_(stop.get.map(!_))
        // Warm a pooled session for the mutation so the measured wait is lock queueing, not connection setup.
        _ <- b.withinMutation(tenant)(IO.unit)
        readers <- List(a, b, a, b, a, b).zipWithIndex
          .traverse((g, index) => reader(g, (index * 7).millis).start)
        // Wait for a steady overlapping stream rather than a fixed delay, which is load-sensitive.
        _ <- eventually(executions.get.map(_ >= 12))
        beforeMutation <- executions.get
        started <- IO.monotonic
        _ <- b.withinMutation(tenant)(IO.unit)
        elapsed <- IO.monotonic.map(_ - started)
        _ <- IO.sleep(200.millis)
        afterMutation <- executions.get
        _ <- stop.set(true)
        _ <- readers.traverse_(_.joinWithNever)
      yield
        assert(beforeMutation > 0, "the shared stream never started")
        assert(elapsed < 1.second, s"mutation waited $elapsed behind a continuous shared stream")
        assert(afterMutation > beforeMutation, "executions did not resume after the mutation")
  }

  test("distinct tenants map to distinct 64-bit keys in the reserved two-int space") {
    val keys = Vector.fill(10000)(PostgresTenantExecutionMutationGate.LockKey.of(TenantId.random()))
    assertEquals(keys.distinct.size, keys.size)
    assert(keys.map(_.classId).distinct.size > 1, "class IDs must carry tenant entropy, not a constant namespace")
  }

  test("tenants do not block each other") {
    requireDocker()
    instances.use: (a, b) =>
      val tenant = TenantId.random()
      val other = TenantId.random()
      for
        holding <- Deferred[IO, Unit]
        release <- Deferred[IO, Unit]
        held <- a.withinMutation(tenant)(holding.complete(()) *> release.get).start
        _ <- holding.get
        _ <- b.withinExecution(other)(_.confirmHeld).timeout(5.seconds)
        _ <- b.withinMutation(other)(IO.unit).timeout(5.seconds)
        _ <- release.complete(()) *> held.joinWithNever
      yield ()
  }

  test("cancellation and failure release the lock, and pooled sessions retain no locks") {
    requireDocker()
    gate(poolSize = 2).use: g =>
      val tenant = TenantId.random()
      for
        started <- Deferred[IO, Unit]
        cancelled <- g.withinExecution(tenant)(_ => started.complete(()) *> IO.never[Unit]).start
        _ <- started.get *> cancelled.cancel
        _ <- g.withinMutation(tenant)(IO.raiseError[Unit](RuntimeException("mutation failed"))).attempt
        _ <- (1 to 20).toList.traverse_(_ => g.withinExecution(tenant)(_ => IO.unit) *> g.withinMutation(tenant)(IO.unit))
        remaining <- gateLocks(granted = true)
        _ <- g.withinMutation(tenant)(IO.unit).timeout(5.seconds)
      yield assertEquals(remaining, 0)
  }

  test("an unreachable coordinator fails closed before the operation starts") {
    requireDocker()
    gate(timeout = 1.second, user = "hallpass_outage").use: g =>
      val tenant = TenantId.random()
      for
        _ <- g.withinExecution(tenant)(_.confirmHeld)
        _ <- IO.blocking:
          admin: statement =>
            statement.execute("alter role hallpass_outage nologin")
            statement.execute("select pg_terminate_backend(pid) from pg_stat_activity where usename = 'hallpass_outage'")
        ran <- Ref.of[IO, Boolean](false)
        outcome <- g.withinExecution(tenant)(_ => ran.set(true)).attempt
        executed <- ran.get
        _ <- IO.blocking(admin(_.execute("alter role hallpass_outage login")))
      yield
        assertEquals(outcome, Left(TenantGateException(TenantGateFailure.CoordinatorUnavailable)))
        assert(!executed)
  }

  test("configuration bounds are enforced") {
    assert(PostgresTenantGateConfig.from(0, 1.second).isLeft)
    assert(PostgresTenantGateConfig.from(8, 10.millis).isLeft)
    assert(PostgresTenantGateConfig.from(8, 1.second, 1.second).isLeft)
    assert(PostgresTenantGateConfig.fromEnvironment(Map("HALLPASS_TENANT_GATE_POOL_SIZE" -> "many")).isLeft)
    assertEquals(PostgresTenantGateConfig.fromEnvironment(Map.empty), Right(PostgresTenantGateConfig.default))
  }
