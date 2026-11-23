package run.hallpass.application

import scala.concurrent.duration.*
import cats.effect.{Deferred, IO, Ref}
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.kernel.TenantId

final class SingleProcessTenantExecutionMutationGateSuite extends CatsEffectSuite:
  private val tenant = TenantId.random()

  test("executions in one tenant hold the gate concurrently") {
    for
      gate <- SingleProcessTenantExecutionMutationGate.create
      bothInside <- Deferred[IO, Unit]
      inside <- Ref.of[IO, Int](0)
      enter = gate.withinExecution(tenant): _ =>
        inside.updateAndGet(_ + 1).flatMap(count => bothInside.complete(()).whenA(count == 2)) *>
          bothInside.get.timeout(2.seconds)
      _ <- (enter, enter).parTupled
    yield ()
  }

  test("a mutation waits for an in-flight execution and later executions observe it") {
    for
      gate <- SingleProcessTenantExecutionMutationGate.create
      executing <- Deferred[IO, Unit]
      finishExecution <- Deferred[IO, Unit]
      log <- Ref.of[IO, Vector[String]](Vector.empty)
      execution <- gate
        .withinExecution(tenant)(_ => executing.complete(()) *> finishExecution.get *> log.update(_ :+ "execution"))
        .start
      _ <- executing.get
      mutation <- gate.withinMutation(tenant)(log.update(_ :+ "mutation")).start
      _ <- IO.sleep(100.millis)
      beforeRelease <- log.get
      _ <- finishExecution.complete(())
      _ <- execution.joinWithNever *> mutation.joinWithNever
      _ <- gate.withinExecution(tenant)(_ => log.update(_ :+ "next execution"))
      finalLog <- log.get
    yield
      assertEquals(beforeRelease, Vector.empty)
      assertEquals(finalLog, Vector("execution", "mutation", "next execution"))
  }

  test("a queued mutation blocks executions that arrive after it") {
    for
      gate <- SingleProcessTenantExecutionMutationGate.create
      executing <- Deferred[IO, Unit]
      finishFirst <- Deferred[IO, Unit]
      log <- Ref.of[IO, Vector[String]](Vector.empty)
      first <- gate.withinExecution(tenant)(_ => executing.complete(()) *> finishFirst.get).start
      _ <- executing.get
      mutation <- gate.withinMutation(tenant)(log.update(_ :+ "mutation")).start
      _ <- IO.sleep(50.millis)
      late <- gate.withinExecution(tenant)(_ => log.update(_ :+ "late execution")).start
      _ <- IO.sleep(100.millis)
      whileQueued <- log.get
      _ <- finishFirst.complete(())
      _ <- first.joinWithNever *> mutation.joinWithNever *> late.joinWithNever
      finalLog <- log.get
    yield
      assertEquals(whileQueued, Vector.empty)
      assertEquals(finalLog, Vector("mutation", "late execution"))
  }

  test("acquisition is bounded and fails closed with a typed error") {
    for
      gate <- SingleProcessTenantExecutionMutationGate.create(4, 100.millis)
      holding <- Deferred[IO, Unit]
      release <- Deferred[IO, Unit]
      holder <- gate.withinMutation(tenant)(holding.complete(()) *> release.get).start
      _ <- holding.get
      ran <- Ref.of[IO, Boolean](false)
      outcome <- gate.withinExecution(tenant)(_ => ran.set(true)).attempt
      _ <- release.complete(()) *> holder.joinWithNever
      executed <- ran.get
    yield
      assertEquals(outcome, Left(TenantGateException(TenantGateFailure.AcquisitionTimedOut)))
      assert(!executed)
  }

  test("tenants are isolated") {
    val other = TenantId.random()
    for
      gate <- SingleProcessTenantExecutionMutationGate.create(4, 200.millis)
      holding <- Deferred[IO, Unit]
      release <- Deferred[IO, Unit]
      holder <- gate.withinMutation(tenant)(holding.complete(()) *> release.get).start
      _ <- holding.get
      _ <- gate.withinExecution(other)(_ => IO.unit)
      _ <- gate.withinMutation(other)(IO.unit)
      _ <- release.complete(()) *> holder.joinWithNever
    yield ()
  }

  test("cancellation and failure release the gate") {
    for
      gate <- SingleProcessTenantExecutionMutationGate.create(4, 500.millis)
      started <- Deferred[IO, Unit]
      cancelled <- gate.withinExecution(tenant)(_ => started.complete(()) *> IO.never[Unit]).start
      _ <- started.get *> cancelled.cancel
      _ <- gate.withinMutation(tenant)(IO.raiseError[Unit](RuntimeException("mutation failed"))).attempt
      _ <- gate.withinMutation(tenant)(IO.unit)
    yield ()
  }

  test("a non-positive concurrency bound is rejected") {
    SingleProcessTenantExecutionMutationGate.create(0, 1.second).attempt.map(result => assert(result.isLeft))
  }
