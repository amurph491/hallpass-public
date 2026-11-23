package run.hallpass.gateway

import java.net.URI
import com.sun.net.httpserver.Headers
import munit.FunSuite

final class AgentHttpAuthenticationSuite extends FunSuite:
  private val credential = "ac1.abcdefghijklmnop.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  private val requestUri = URI.create("http://127.0.0.1:8081/api/agent/tools")

  test("parses exactly one canonical bearer credential") {
    val parsed = AgentHttpAuthentication.parse(headers("Authorization" -> s"Bearer $credential"), requestUri)

    assert(parsed.isRight)
    assertEquals(parsed.toOption.map(_.selector.value), Some("abcdefghijklmnop"))
  }

  test("the parsed credential remains redacted") {
    val parsed = AgentHttpAuthentication.parse(headers("Authorization" -> s"Bearer $credential"), requestUri).toOption.get

    assertEquals(parsed.toString, "PresentedAgentCredential(<redacted>)")
    assert(!parsed.toString.contains(credential))
  }

  test("rejects missing, repeated, and comma-folded authorization values") {
    assertEquals(
      AgentHttpAuthentication.parse(headers(), requestUri),
      Left(AgentHttpAuthentication.Rejection.MissingAuthorization)
    )
    assertEquals(
      AgentHttpAuthentication.parse(
        headers("Authorization" -> s"Bearer $credential", "Authorization" -> s"Bearer $credential"),
        requestUri
      ),
      Left(AgentHttpAuthentication.Rejection.MultipleAuthorizationValues)
    )
    assertEquals(
      AgentHttpAuthentication.parse(headers("Authorization" -> s"Bearer $credential, Bearer $credential"), requestUri),
      Left(AgentHttpAuthentication.Rejection.InvalidAuthorization)
    )
  }

  test("rejects blank, wrong-scheme, and non-canonical whitespace forms") {
    val invalid = Vector(
      "",
      "Basic abc",
      s"bearer $credential",
      s"Bearer  $credential",
      s"Bearer\t$credential",
      s" Bearer $credential",
      s"Bearer $credential "
    )

    invalid.foreach: value =>
      assertEquals(
        AgentHttpAuthentication.parse(headers("Authorization" -> value), requestUri),
        Left(AgentHttpAuthentication.Rejection.InvalidAuthorization),
        value
      )
  }

  test("rejects oversized authorization headers and bearer credentials") {
    val oversizedHeader = "Bearer " + "a" * (AgentHttpAuthentication.MaxAuthorizationHeaderBytes + 1)
    val oversizedCredential = "Bearer " + "a" * (AgentHttpAuthentication.MaxBearerCredentialBytes + 1)

    assertEquals(
      AgentHttpAuthentication.parse(headers("Authorization" -> oversizedHeader), requestUri),
      Left(AgentHttpAuthentication.Rejection.AuthorizationTooLarge)
    )
    assertEquals(
      AgentHttpAuthentication.parse(headers("Authorization" -> oversizedCredential), requestUri),
      Left(AgentHttpAuthentication.Rejection.BearerCredentialTooLarge)
    )
  }

  test("rejects query and cookie authentication channels without inspecting their values") {
    assertEquals(
      AgentHttpAuthentication.parse(headers("Authorization" -> s"Bearer $credential"), URI.create(s"$requestUri?token=ignored")),
      Left(AgentHttpAuthentication.Rejection.QueryNotAllowed)
    )
    assertEquals(
      AgentHttpAuthentication.parse(headers("Authorization" -> s"Bearer $credential", "Cookie" -> "session=ignored"), requestUri),
      Left(AgentHttpAuthentication.Rejection.CookieNotAllowed)
    )
  }

  private def headers(values: (String, String)*): Headers =
    val result = new Headers()
    values.foreach { case (name, value) => result.add(name, value) }
    result
