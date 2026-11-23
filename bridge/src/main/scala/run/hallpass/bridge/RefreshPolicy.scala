package run.hallpass.bridge

import scala.concurrent.duration.*

/** What one tool-list poll told the bridge, reduced to the distinctions that change how soon to poll again. */
enum RefreshOutcome:
  /** The agent API answered with a well-formed tool list. The list may be empty. */
  case Reachable
  /** The API rejected the credential. A revoked or unknown credential does not recover within a session. */
  case Unauthorized
  case RateLimited(retryAfter: Option[FiniteDuration])
  /** Timeouts, 5xx, connection errors, and any response the bridge cannot interpret. */
  case Unavailable

object RefreshOutcome:
  def of(poll: Either[AgentApiError, Vector[AgentTool]]): RefreshOutcome =
    poll match
      case Right(_)                                => Reachable
      case Left(AgentApiError.Unauthorized)        => Unauthorized
      case Left(AgentApiError.RateLimited(after))  => RateLimited(after)
      case Left(_)                                 => Unavailable

/** Coarse health, used to decide when a state change is worth one stderr line. */
enum RefreshHealth:
  case Healthy, Unauthorized, RateLimited, Unavailable

/** `failures` counts consecutive polls with the same failing health, and is zero while healthy. */
final case class RefreshState(health: RefreshHealth, failures: Int)

object RefreshState:
  val initial: RefreshState = RefreshState(RefreshHealth.Healthy, 0)

/**
  * When to poll the agent API for the tool list again. This is scheduling only: tool visibility is a UX hint and every
  * call is independently authenticated and authorized by the server, so a failure always hides the tool and no delay
  * here can grant or extend authority.
  *
  * | outcome                         | next delay                                   | cap        |
  * |---------------------------------|----------------------------------------------|------------|
  * | reachable                       | 1s, and the backoff resets                   |            |
  * | unauthorized (401)              | 5s, doubling per consecutive 401             | 5 minutes  |
  * | rate limited with `Retry-After` | the hinted delay (already in [1s, 5 minutes]) | 5 minutes  |
  * | rate limited without a hint     | 5s, doubling per consecutive 429             | 5 minutes  |
  * | unavailable (timeout, 5xx, ...) | 2s, doubling per consecutive failure         | 60s        |
  *
  * Failing delays get up to 20% extra, scaled by an injected unit-interval sample, so bridges that failed together do
  * not retry together. Jitter only lengthens a delay, so "at least the server's hint" holds, and no delay exceeds its
  * cap. A change of failure kind restarts the doubling for the new kind.
  */
object RefreshPolicy:
  val HealthyInterval: FiniteDuration = 1.second
  val UnauthorizedStart: FiniteDuration = 5.seconds
  val UnauthorizedCap: FiniteDuration = 5.minutes
  val RateLimitedStart: FiniteDuration = 5.seconds
  val RateLimitedCap: FiniteDuration = 5.minutes
  val UnavailableStart: FiniteDuration = 2.seconds
  val UnavailableCap: FiniteDuration = 60.seconds
  val MaximumJitterFraction: Double = 0.2

  /** `jitter` is a sample from [0, 1); values outside that range are clamped. */
  def next(state: RefreshState, outcome: RefreshOutcome, jitter: Double): (FiniteDuration, RefreshState) =
    outcome match
      case RefreshOutcome.Reachable =>
        (HealthyInterval, RefreshState.initial)
      case RefreshOutcome.Unauthorized =>
        backoff(state, RefreshHealth.Unauthorized, UnauthorizedStart, UnauthorizedCap, jitter)
      case RefreshOutcome.RateLimited(None) =>
        backoff(state, RefreshHealth.RateLimited, RateLimitedStart, RateLimitedCap, jitter)
      case RefreshOutcome.RateLimited(Some(hint)) =>
        val failed = failing(state, RefreshHealth.RateLimited)
        (lengthen(hint.max(RetryAfter.Minimum), RateLimitedCap, jitter), failed)
      case RefreshOutcome.Unavailable =>
        backoff(state, RefreshHealth.Unavailable, UnavailableStart, UnavailableCap, jitter)

  /** The one-line stderr message for entering `to` from `from`, or nothing when the health did not change. */
  def transition(from: RefreshHealth, to: RefreshHealth): Option[String] =
    Option.when(from != to):
      to match
        case RefreshHealth.Healthy =>
          "Hallpass agent API is reachable again; tool visibility follows the agent's current authority."
        case RefreshHealth.Unauthorized =>
          "Hallpass rejected this agent's credential (revoked, expired, or unknown); the tool is hidden and the bridge " +
            "will poll less often. Run `hallpass doctor --client <client> --agent <agent>`, then restart the client " +
            "after importing a valid credential."
        case RefreshHealth.RateLimited =>
          "Hallpass agent API is rate limiting this bridge; the tool is hidden and the bridge is backing off."
        case RefreshHealth.Unavailable =>
          "Hallpass agent API is unavailable; the tool is hidden and the bridge is backing off."

  private def backoff(
      state: RefreshState,
      health: RefreshHealth,
      start: FiniteDuration,
      cap: FiniteDuration,
      jitter: Double
  ): (FiniteDuration, RefreshState) =
    val failed = failing(state, health)
    // Doubling stops mattering long before the shift could overflow.
    val doubled = start * (1L << math.min(failed.failures - 1, 20))
    (lengthen(doubled.min(cap), cap, jitter), failed)

  private def failing(state: RefreshState, health: RefreshHealth): RefreshState =
    val previous = if state.health == health then state.failures else 0
    RefreshState(health, math.min(previous + 1, 1000))

  private def lengthen(delay: FiniteDuration, cap: FiniteDuration, jitter: Double): FiniteDuration =
    val sample = if jitter.isNaN then 0.0 else math.max(0.0, math.min(1.0, jitter))
    val jittered = FiniteDuration(math.round(delay.toNanos * (1.0 + MaximumJitterFraction * sample)), NANOSECONDS)
    jittered.min(cap)
