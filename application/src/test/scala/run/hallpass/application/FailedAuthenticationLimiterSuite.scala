package run.hallpass.application

import java.net.InetAddress
import scala.concurrent.duration.*
import cats.effect.{Deferred, IO, Ref}
import cats.syntax.all.*
import munit.CatsEffectSuite

final class FailedAuthenticationLimiterSuite extends CatsEffectSuite:
  private val attacker = InetAddress.getByName("192.0.2.10")
  private val neighbour = InetAddress.getByName("192.0.2.11")

  private def limiter(time: Ref[IO, FiniteDuration], maximumClients: Int = 100) =
    FailedAuthenticationLimiter.create(capacity = 3, refillEvery = 10.seconds, maximumClients = maximumClients, now = time.get)

  private def attempt(limits: FailedAuthenticationLimiter, client: InetAddress, refund: Boolean = false) =
    limits.admit(client).use(_.traverse(permit => if refund then permit.refund else IO.unit))

  test("a client is blocked once its failure budget is spent, and only that client") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      limits <- limiter(time)
      _ <- attempt(limits, attacker).replicateA_(2)
      third <- attempt(limits, attacker)
      fourth <- attempt(limits, attacker)
      other <- attempt(limits, neighbour)
    yield
      assertEquals(third, Right(()))
      assertEquals(fourth, Left(10.seconds), "one token takes one refill interval")
      assertEquals(other, Right(()))
  }

  test("time refills the budget, never beyond its capacity") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      limits <- limiter(time)
      _ <- attempt(limits, attacker).replicateA_(3)
      _ <- time.set(5.seconds)
      halfway <- attempt(limits, attacker)
      _ <- time.set(10.seconds)
      refilled <- attempt(limits, attacker)
      _ <- time.set(10.hours)
      afterLongIdle <- attempt(limits, attacker).replicateA(4)
    yield
      assertEquals(halfway, Left(5.seconds))
      assertEquals(refilled, Right(()))
      assertEquals(afterLongIdle, List(Right(()), Right(()), Right(()), Left(10.seconds)), "a long idle period restores at most the full burst")
  }

  test("memory stays bounded, dropping only recovered clients and never resetting active budgets") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      limits <- limiter(time, maximumClients = 2)
      _ <- attempt(limits, InetAddress.getByName("198.51.100.1"))
      _ <- time.set(100.seconds)
      _ <- attempt(limits, attacker).replicateA_(3)
      recoveredEvicted <- attempt(limits, neighbour)
      overflow <- attempt(limits, InetAddress.getByName("198.51.100.2"))
      stillBlocked <- attempt(limits, attacker)
    yield
      assertEquals(recoveredEvicted, Right(()))
      assertEquals(overflow, Left(10.seconds), "new clients cannot evict an active budget when the table is full")
      assertEquals(stillBlocked, Left(10.seconds))
  }

  test("parallel attempts reserve atomically and pending tokens cannot refill") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      limits <- limiter(time)
      entered <- Deferred[IO, Unit]
      release <- Deferred[IO, Unit]
      count <- Ref.of[IO, Int](0)
      pending <- (1 to 3).toList.parTraverse(_ => limits.admit(attacker).use:
        case Left(_) => IO.raiseError(AssertionError("initial burst should be admitted"))
        case Right(_) => count.updateAndGet(_ + 1).flatMap(n => entered.complete(()).void.whenA(n == 3)) *> release.get
      ).start
      _ <- entered.get.timeout(2.seconds)
      blocked <- (1 to 40).toList.parTraverse(_ => attempt(limits, attacker))
      _ <- time.set(10.hours)
      whilePending <- attempt(limits, attacker)
      _ <- release.complete(())
      _ <- pending.joinWithNever
      afterFailures <- attempt(limits, attacker)
    yield
      assert(blocked.forall(_.isLeft))
      assert(whilePending.isLeft, "elapsed time cannot create extra pending authentications")
      assertEquals(afterFailures, Left(10.seconds))
  }

  test("successful attempts refund exactly once, even if refund is called twice") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      limits <- limiter(time)
      _ <- limits.admit(attacker).use(_.traverse_(permit => permit.refund *> permit.refund)).replicateA_(20)
      burst <- attempt(limits, attacker).replicateA(4)
    yield assertEquals(burst, List(Right(()), Right(()), Right(()), Left(10.seconds)))
  }

  test("cancellation releases pending admission but consumes the token") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      limits <- FailedAuthenticationLimiter.create(capacity = 1, refillEvery = 10.seconds, now = time.get)
      entered <- Deferred[IO, Unit]
      fiber <- limits.admit(attacker).use(_ => entered.complete(()) *> IO.never[Unit]).start
      _ <- entered.get
      _ <- fiber.cancel
      canceled <- attempt(limits, attacker)
      _ <- time.set(10.seconds)
      next <- attempt(limits, attacker, refund = true)
      again <- attempt(limits, attacker, refund = true)
    yield
      assertEquals(canceled, Left(10.seconds))
      assertEquals(next, Right(()))
      assertEquals(again, Right(()), "a canceled reservation must not leak pending admission")
  }

  test("rejection reasons map one to one from credential rejections") {
    assertEquals(
      AgentCredentialRejection.values.map(AgentRejectionReason.of).toSet.size,
      AgentCredentialRejection.values.length
    )
  }
