package run.hallpass.adapters.slack

import munit.FunSuite

final class SlackAccessTokenSuite extends FunSuite:
  test("token rendering is redacted") {
    val secret = "xoxb-not-for-output"
    val token = SlackAccessToken.parse(secret).getOrElse(fail("valid token"))
    assertEquals(token.toString, "SlackAccessToken(<redacted>)")
    assert(!token.toString.contains(secret))
  }

  test("missing or whitespace-containing tokens are rejected") {
    assertEquals(SlackAccessToken.parse(""), Left(SlackAccessToken.ValidationError.Missing))
    assertEquals(SlackAccessToken.parse("xoxb value"), Left(SlackAccessToken.ValidationError.ContainsWhitespace))
  }
