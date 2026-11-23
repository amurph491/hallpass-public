package run.hallpass.bridge

import munit.FunSuite
import scala.concurrent.duration.*

final class RefreshPolicySuite extends FunSuite:
  import RefreshOutcome.*

  /** Feeds the outcomes through the policy with a fixed jitter sample, returning each chosen delay and the final state. */
  private def run(outcomes: Seq[RefreshOutcome], jitter: Double = 0.0): (Vector[FiniteDuration], RefreshState) =
    outcomes.foldLeft((Vector.empty[FiniteDuration], RefreshState.initial)):
      case ((delays, state), outcome) =>
        val (delay, next) = RefreshPolicy.next(state, outcome, jitter)
        (delays :+ delay, next)

  test("a reachable API is polled at the base interval and stays healthy") {
    val (delays, state) = run(Seq.fill(3)(Reachable))
    assertEquals(delays, Vector.fill(3)(1.second))
    assertEquals(state, RefreshState.initial)
  }

  test("unauthorized backs off from 5s, doubling to a 5 minute cap") {
    val (delays, state) = run(Seq.fill(9)(Unauthorized))
    assertEquals(delays, Vector(5, 10, 20, 40, 80, 160, 300, 300, 300).map(_.seconds))
    assertEquals(state, RefreshState(RefreshHealth.Unauthorized, 9))
  }

  test("other unavailability backs off from 2s, doubling to a 60s cap") {
    val (delays, state) = run(Seq.fill(8)(Unavailable))
    assertEquals(delays, Vector(2, 4, 8, 16, 32, 60, 60, 60).map(_.seconds))
    assertEquals(state.health, RefreshHealth.Unavailable)
  }

  test("rate limiting without a hint backs off from 5s to a 5 minute cap") {
    val (delays, _) = run(Seq.fill(8)(RateLimited(None)))
    assertEquals(delays, Vector(5, 10, 20, 40, 80, 160, 300, 300).map(_.seconds))
  }

  test("rate limiting with a hint waits exactly the hint without jitter, and never less with it") {
    assertEquals(run(Seq(RateLimited(Some(17.seconds))))._1, Vector(17.seconds))
    for sample <- Seq(0.0, 0.25, 0.5, 0.999) do
      val (delay, _) = RefreshPolicy.next(RefreshState.initial, RateLimited(Some(30.seconds)), sample)
      assert(delay >= 30.seconds && delay <= 36.seconds, s"delay $delay for sample $sample")
  }

  test("a hint is bounded to 1s..5 minutes even if the client did not bound it") {
    assertEquals(run(Seq(RateLimited(Some(Duration.Zero))))._1, Vector(1.second))
    assertEquals(run(Seq(RateLimited(Some(1.hour))))._1, Vector(5.minutes))
  }

  test("success resets the backoff, so the next failure starts from the beginning again") {
    val (delays, state) = run(Seq(Unauthorized, Unauthorized, Unauthorized, Reachable, Unauthorized))
    assertEquals(delays, Vector(5.seconds, 10.seconds, 20.seconds, 1.second, 5.seconds))
    assertEquals(state, RefreshState(RefreshHealth.Unauthorized, 1))
  }

  test("a different kind of failure restarts the doubling for the new kind") {
    val (delays, _) = run(Seq(Unavailable, Unavailable, Unavailable, Unauthorized, Unauthorized, Unavailable))
    assertEquals(delays, Vector(2, 4, 8, 5, 10, 2).map(_.seconds))
  }

  test("jitter only lengthens a delay by at most 20 percent and never passes the cap") {
    val (first, _) = RefreshPolicy.next(RefreshState.initial, Unauthorized, 0.5)
    assertEquals(first, 5500.millis)
    val (top, _) = RefreshPolicy.next(RefreshState.initial, Unauthorized, 1.0)
    assertEquals(top, 6.seconds)
    val (capped, _) = run(Seq.fill(12)(Unauthorized), jitter = 0.99)
    assertEquals(capped.last, 5.minutes)
    val (unavailable, _) = run(Seq.fill(12)(Unavailable), jitter = 0.99)
    assertEquals(unavailable.last, 60.seconds)
  }

  test("out-of-range and non-finite jitter samples are clamped") {
    assertEquals(RefreshPolicy.next(RefreshState.initial, Unauthorized, -3.0)._1, 5.seconds)
    assertEquals(RefreshPolicy.next(RefreshState.initial, Unauthorized, 42.0)._1, 6.seconds)
    assertEquals(RefreshPolicy.next(RefreshState.initial, Unauthorized, Double.NaN)._1, 5.seconds)
  }

  test("failure counts saturate rather than overflow the shift") {
    val saturated = RefreshState(RefreshHealth.Unavailable, 1000)
    assertEquals(RefreshPolicy.next(saturated, Unavailable, 0.0), (60.seconds, saturated))
  }

  test("a client error maps to the outcome that drives its schedule") {
    assertEquals(RefreshOutcome.of(Right(Vector.empty)), Reachable)
    assertEquals(RefreshOutcome.of(Left(AgentApiError.Unauthorized)), Unauthorized)
    assertEquals(RefreshOutcome.of(Left(AgentApiError.RateLimited(Some(3.seconds)))), RateLimited(Some(3.seconds)))
    for error <- Seq(AgentApiError.Unavailable, AgentApiError.TimedOut, AgentApiError.InvalidResponse, AgentApiError.ResponseTooLarge) do
      assertEquals(RefreshOutcome.of(Left(error)), Unavailable)
  }

  test("only a change of health produces a one-line transition message") {
    import RefreshHealth.*
    assertEquals(RefreshPolicy.transition(Healthy, Healthy), None)
    assertEquals(RefreshPolicy.transition(Unauthorized, Unauthorized), None)
    for from <- RefreshHealth.values; to <- RefreshHealth.values if from != to do
      val line = RefreshPolicy.transition(from, to).getOrElse(fail(s"no line for $from -> $to"))
      assert(!line.contains('\n') && !line.contains("ac1."), line)
    assert(RefreshPolicy.transition(Healthy, Unauthorized).exists(_.contains("hallpass doctor")))
  }
