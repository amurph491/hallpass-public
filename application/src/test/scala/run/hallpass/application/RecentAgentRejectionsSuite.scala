package run.hallpass.application

import java.util.Base64
import scala.concurrent.duration.*
import cats.effect.{IO, Ref}
import cats.syntax.all.*
import munit.CatsEffectSuite

final class RecentAgentRejectionsSuite extends CatsEffectSuite:
  private def secret(seed: Int): String = Base64.getUrlEncoder.withoutPadding.encodeToString(Array.fill[Byte](32)(seed.toByte))

  private def bearer(selector: String = "recentselector001", seed: Int = 1): PresentedAgentCredential =
    PresentedAgentCredential.parse(s"ac1.$selector.${secret(seed)}").getOrElse(fail("credential"))

  private def cache(time: Ref[IO, FiniteDuration], maximumEntries: Int = 100) =
    RecentAgentRejections.create(ttl = 10.minutes, maximumEntries = maximumEntries, now = time.get)

  test("a remembered bearer is recognized, and a never-seen bearer is not") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      recent <- cache(time)
      before <- recent.isRecentlyRejected(bearer())
      stored <- recent.remember(bearer(), AgentCredentialRejection.RevokedCredential)
      after <- recent.isRecentlyRejected(bearer())
    yield
      assert(!before)
      assert(stored)
      assert(after)
  }

  test("a different secret for the same selector, and a different selector, are independent") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      recent <- cache(time)
      _ <- recent.remember(bearer(seed = 1), AgentCredentialRejection.WrongSecret)
      sameSelector <- recent.isRecentlyRejected(bearer(seed = 2))
      otherSelector <- recent.isRecentlyRejected(bearer(selector = "recentselector002", seed = 1))
      same <- recent.isRecentlyRejected(bearer(seed = 1))
    yield
      assert(!sameSelector, "guessing another secret must not be answered from the table")
      assert(!otherSelector)
      assert(same)
  }

  test("entries expire after the TTL, exactly at the boundary, and each hit slides it") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      recent <- cache(time)
      _ <- recent.remember(bearer(), AgentCredentialRejection.UnknownCredential)
      _ <- time.set(10.minutes - 1.nano)
      justBefore <- recent.isRecentlyRejected(bearer())
      _ <- time.set(20.minutes - 2.nanos)
      slidJustBefore <- recent.isRecentlyRejected(bearer())
      _ <- time.set(30.minutes - 2.nanos)
      expired <- recent.isRecentlyRejected(bearer())
    yield
      assert(justBefore)
      assert(slidJustBefore, "each hit refreshes the TTL")
      assert(!expired, "an entry not seen for a full TTL is gone")
  }

  test("a client polling more often than the TTL is never forgotten, and one that goes silent is") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      recent <- cache(time)
      _ <- recent.remember(bearer(), AgentCredentialRejection.UnroutedCredential)
      polls <- (1 to 30).toList.traverse: _ =>
        time.update(_ + 9.minutes) *> recent.isRecentlyRejected(bearer())
      _ <- time.update(_ + 10.minutes)
      afterSilence <- recent.isRecentlyRejected(bearer())
    yield
      assert(polls.forall(identity))
      assert(!afterSilence)
  }

  test("remembering again refreshes the TTL rather than adding a second entry") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      recent <- cache(time, maximumEntries = 1)
      _ <- recent.remember(bearer(), AgentCredentialRejection.RevokedCredential)
      _ <- time.set(9.minutes)
      again <- recent.remember(bearer(), AgentCredentialRejection.RevokedCredential)
      _ <- time.set(18.minutes)
      alive <- recent.isRecentlyRejected(bearer())
    yield
      assert(again, "the bearer is already present, so a full table is not a reason to refuse it")
      assert(alive)
  }

  test("a full table of live entries refuses new ones, and keeps the existing ones") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      recent <- cache(time, maximumEntries = 2)
      first <- recent.remember(bearer(seed = 1), AgentCredentialRejection.RevokedCredential)
      second <- recent.remember(bearer(seed = 2), AgentCredentialRejection.RevokedCredential)
      third <- recent.remember(bearer(seed = 3), AgentCredentialRejection.RevokedCredential)
      thirdKnown <- recent.isRecentlyRejected(bearer(seed = 3))
      firstKnown <- recent.isRecentlyRejected(bearer(seed = 1))
      secondKnown <- recent.isRecentlyRejected(bearer(seed = 2))
    yield
      assertEquals((first, second, third), (true, true, false))
      assert(!thirdKnown, "the client whose entry was refused falls back to spending budget")
      assert(firstKnown && secondKnown)
  }

  test("expired entries are dropped first, so a table full of a dead entry accepts a new one") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      recent <- cache(time, maximumEntries = 2)
      _ <- recent.remember(bearer(seed = 1), AgentCredentialRejection.RevokedCredential)
      _ <- time.set(5.minutes)
      _ <- recent.remember(bearer(seed = 2), AgentCredentialRejection.RevokedCredential)
      // The first entry expires at 10 minutes; the second is live until 15 minutes.
      _ <- time.set(10.minutes)
      third <- recent.remember(bearer(seed = 3), AgentCredentialRejection.RevokedCredential)
      firstKnown <- recent.isRecentlyRejected(bearer(seed = 1))
      secondKnown <- recent.isRecentlyRejected(bearer(seed = 2))
      thirdKnown <- recent.isRecentlyRejected(bearer(seed = 3))
      // Both remaining entries are live, so a fourth is refused.
      fourth <- recent.remember(bearer(seed = 4), AgentCredentialRejection.RevokedCredential)
    yield
      assert(third)
      assert(!firstKnown)
      assert(secondKnown && thirdKnown)
      assert(!fourth)
  }

  test("only rejections that cannot become valid for the bearer are remembered") {
    val expected = Map(
      AgentCredentialRejection.UnroutedCredential -> true,
      AgentCredentialRejection.UnknownCredential -> true,
      AgentCredentialRejection.ExpiredCredential -> true,
      AgentCredentialRejection.RevokedCredential -> true,
      AgentCredentialRejection.WrongSecret -> true,
      AgentCredentialRejection.CredentialNoLongerActive -> true,
      // An operator repair of the stored row can make this credential valid.
      AgentCredentialRejection.InvalidStoredCredential -> false
    )
    assertEquals(AgentCredentialRejection.values.toSet, expected.keySet, "every rejection is classified here")
    expected.toList.traverse_ : (rejection, cached) =>
      for
        time <- Ref.of[IO, FiniteDuration](0.seconds)
        recent <- cache(time)
        stored <- recent.remember(bearer(), rejection)
        known <- recent.isRecentlyRejected(bearer())
      yield
        assertEquals(stored, cached, rejection.toString)
        assertEquals(known, cached, rejection.toString)
  }

  test("each instance uses its own random key, so one instance's table means nothing to another") {
    for
      time <- Ref.of[IO, FiniteDuration](0.seconds)
      one <- cache(time)
      two <- cache(time)
      _ <- one.remember(bearer(), AgentCredentialRejection.RevokedCredential)
      known <- two.isRecentlyRejected(bearer())
    yield assert(!known)
  }
