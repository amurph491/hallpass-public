package run.hallpass.gateway

import munit.FunSuite

final class AgentPublicUrlSuite extends FunSuite:
  private def parsed(raw: String, production: Boolean = false): Either[String, String] =
    AgentPublicUrl.parse(raw, production).map(_.value)

  test("https accepts one exact host with an optional port and normalizes to scheme and authority") {
    assertEquals(parsed("https://agents.example.com"), Right("https://agents.example.com"))
    assertEquals(parsed("https://agents.example.com/"), Right("https://agents.example.com"))
    assertEquals(parsed("https://hallpass-sandbox.tail1234.ts.net:8443"), Right("https://hallpass-sandbox.tail1234.ts.net:8443"))
    assertEquals(parsed("  HTTPS://Agents.Example.COM:443 "), Right("https://agents.example.com:443"))
  }

  test("http is accepted only for a numeric loopback address, and never in production") {
    assertEquals(parsed("http://127.0.0.1:8081"), Right("http://127.0.0.1:8081"))
    assertEquals(parsed("http://127.0.0.1"), Right("http://127.0.0.1"))
    assertEquals(parsed("http://[::1]:8081"), Right("http://[::1]:8081"))
    assert(parsed("http://localhost:8081").isLeft, "localhost is a name, not a numeric loopback address")
    assert(parsed("http://192.168.1.10:8081").isLeft)
    assert(parsed("http://127.0.0.256:8081").isLeft)
    assert(parsed("http://agents.example.com").isLeft)
    assert(parsed("http://127.0.0.1:8081", production = true).isLeft)
    assert(parsed("https://agents.example.com", production = true).isRight)
  }

  test("paths, queries, fragments, user info, bad ports, and other schemes are refused") {
    val refused = Vector(
      "", "agents.example.com", "ftp://agents.example.com", "https://agents.example.com/api",
      "https://agents.example.com/?a=b", "https://agents.example.com/#x", "https://user@agents.example.com",
      "https://user:secret@agents.example.com", "https://agents.example.com:0", "https://agents.example.com:70000",
      "https://localhost", "https://bad_host.example.com", "https://", "https://agents example.com", "javascript:alert(1)"
    )
    refused.foreach(raw => assert(parsed(raw).isLeft, s"expected refusal of '$raw'"))
  }

  test("a refusal names the setting and never echoes the rejected value") {
    val refusal = parsed("https://user:hunter2@agents.example.com")
    assert(refusal.left.exists(_.contains(AgentPublicUrl.Key)), refusal.toString)
    assert(!refusal.left.exists(_.contains("hunter2")), refusal.toString)
  }

  test("development defaults to loopback on the agent port; production must state the URL") {
    def fromEnv(entries: Map[String, String], profile: RuntimeProfile, port: Int) =
      AgentPublicUrl.fromEnvironment(entries, profile, port).map(_.value)
    assertEquals(fromEnv(Map.empty, RuntimeProfile.Development, 9091), Right("http://127.0.0.1:9091"))
    assertEquals(fromEnv(Map(AgentPublicUrl.Key -> " "), RuntimeProfile.Development, 8081), Right("http://127.0.0.1:8081"))
    assertEquals(
      fromEnv(Map(AgentPublicUrl.Key -> "https://agents.example.com"), RuntimeProfile.Development, 8081),
      Right("https://agents.example.com")
    )
    val missing = fromEnv(Map.empty, RuntimeProfile.Production, 8081)
    assert(missing.left.exists(_.contains(AgentPublicUrl.Key)), missing.toString)
    val invalid = fromEnv(Map(AgentPublicUrl.Key -> "https://agents.example.com/x"), RuntimeProfile.Development, 8081)
    assert(invalid.left.exists(message => message.contains(AgentPublicUrl.Key) && message.contains("no path")), invalid.toString)
  }
