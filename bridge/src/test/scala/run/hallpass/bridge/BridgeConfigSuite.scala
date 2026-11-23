package run.hallpass.bridge

import java.nio.charset.StandardCharsets
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.{Files, Path}
import munit.FunSuite

final class BridgeConfigSuite extends FunSuite:
  private val credential = "ac1.abcdefghijklmnop.abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"

  private def environment(endpoint: String) = Map(
    "HALLPASS_AGENT_API_URL" -> endpoint,
    "HALLPASS_AGENT_CREDENTIAL" -> credential
  )

  test("accepts numeric IPv4 loopback endpoints") {
    val config = BridgeConfig.fromEnvironment(environment("http://127.0.0.1:8081/")).toOption
    assertEquals(config.map(_.endpoint.toString), Some("http://127.0.0.1:8081"))
  }

  test("rejects hostname endpoints so the bridge bearer has a fixed loopback destination") {
    assertEquals(BridgeConfig.fromEnvironment(environment("http://localhost:8081")), Left(BridgeConfigError.InvalidEndpoint))
  }

  test("rejects non-loopback endpoints over plain http") {
    assertEquals(BridgeConfig.fromEnvironment(environment("http://192.0.2.1:8081")), Left(BridgeConfigError.InvalidEndpoint))
    assertEquals(BridgeConfig.fromEnvironment(environment("http://agents.example.com")), Left(BridgeConfigError.InvalidEndpoint))
  }

  test("accepts a hosted https endpoint, normalized to scheme and authority") {
    val config = BridgeConfig.fromEnvironment(environment("https://agents.hallpass.example.com/")).toOption
    assertEquals(config.map(_.endpoint.toString), Some("https://agents.hallpass.example.com"))
    val withPort = BridgeConfig.fromEnvironment(environment("https://agents.hallpass.example.com:8443")).toOption
    assertEquals(withPort.map(_.endpoint.toString), Some("https://agents.hallpass.example.com:8443"))
  }

  test("rejects hosted endpoints that could redirect the bearer or carry extra routing") {
    Vector(
      "https://agents.example.com/api/agent",
      "https://user:pass@agents.example.com",
      "https://agents.example.com?next=https://evil.example",
      "https://agents.example.com#fragment",
      "https://localhost",
      "ftp://agents.example.com",
      "https://agents..example.com",
      "https://-agents.example.com"
    ).foreach: endpoint =>
      assertEquals(BridgeConfig.fromEnvironment(environment(endpoint)), Left(BridgeConfigError.InvalidEndpoint), endpoint)
  }

  test("endpoint rule matches the vectors shared with the Python CLI (bridge/tests/endpoint_vectors.json)") {
    // sbt runs bridge tests from the bridge project directory; also accept the repository root.
    val path = Vector(Path.of("tests", "endpoint_vectors.json"), Path.of("bridge", "tests", "endpoint_vectors.json"))
      .find(Files.isRegularFile(_))
      .getOrElse(fail("endpoint_vectors.json not found relative to the working directory"))
    val vectors = io.circe.parser
      .parse(Files.readString(path, StandardCharsets.UTF_8))
      .flatMap(_.as[Vector[EndpointVector]])
      .fold(error => fail(s"unreadable endpoint vectors: $error"), identity)
    assert(vectors.size >= 50, "the shared vector set must stay substantial")
    assert(vectors.exists(_.expected.isDefined) && vectors.exists(_.expected.isEmpty), "vectors must cover accept and reject")
    val disagreements = vectors.flatMap: vector =>
      val actual = BridgeConfig.fromEnvironment(environment(vector.input)).toOption.map(_.endpoint.toString)
      Option.when(actual != vector.expected)(s"input=${vector.input}: expected ${vector.expected}, bridge ${actual}")
    assertEquals(disagreements, Vector.empty[String])
  }

  private def credentialFileEnvironment(endpoint: String, content: String) =
    val file = Files.createTempFile("hallpass-profile-", ".credential", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))
    file.toFile.deleteOnExit()
    Files.writeString(file, content, StandardCharsets.US_ASCII)
    Map("HALLPASS_AGENT_API_URL" -> endpoint, "HALLPASS_AGENT_CREDENTIAL_FILE" -> file.toString)

  private def profile(endpoint: String) = s"hallpass-agent-profile/1\nendpoint=$endpoint\ncredential=$credential\n"

  test("a profile credential file is accepted only with the endpoint it is bound to") {
    val config = BridgeConfig.fromEnvironment(credentialFileEnvironment("https://agents.hallpass.example.com", profile("https://agents.hallpass.example.com")))
    assertEquals(config.toOption.map(_.endpoint.toString), Some("https://agents.hallpass.example.com"))
  }

  test("an old client registration cannot pair a rotated credential with the previous server") {
    // Rotation replaced the profile (bound to the new server); the registration still names the old one.
    val stale = credentialFileEnvironment("https://previous.hallpass.example.com", profile("https://agents.hallpass.example.com"))
    assertEquals(BridgeConfig.fromEnvironment(stale), Left(BridgeConfigError.CredentialEndpointMismatch))
    val local = credentialFileEnvironment("http://127.0.0.1:8081", profile("https://agents.hallpass.example.com"))
    assertEquals(BridgeConfig.fromEnvironment(local), Left(BridgeConfigError.CredentialEndpointMismatch))
  }

  test("binding compares canonical endpoints, so spelling differences neither bypass nor break it") {
    val spelled = credentialFileEnvironment("HTTPS://x".toLowerCase.replace("x", "Agents.Hallpass.Example.com:443/"), profile("https://agents.hallpass.example.com"))
    assertEquals(BridgeConfig.fromEnvironment(spelled).toOption.map(_.endpoint.toString), Some("https://agents.hallpass.example.com"))
  }

  test("a bare credential file from before profiles is bound to the local default endpoint only") {
    val local = credentialFileEnvironment("http://127.0.0.1:8081", credential + "\n")
    assert(BridgeConfig.fromEnvironment(local).isRight)
    val elsewhere = credentialFileEnvironment("https://agents.hallpass.example.com", credential + "\n")
    assertEquals(BridgeConfig.fromEnvironment(elsewhere), Left(BridgeConfigError.CredentialEndpointMismatch))
    val otherPort = credentialFileEnvironment("http://127.0.0.1:9000", credential + "\n")
    assertEquals(BridgeConfig.fromEnvironment(otherPort), Left(BridgeConfigError.CredentialEndpointMismatch))
  }

  test("malformed profiles are rejected rather than read leniently") {
    val endpoint = "https://agents.hallpass.example.com"
    Vector(
      profile(endpoint).stripSuffix("\n"),
      profile(endpoint) + "extra\n",
      profile(endpoint).replace("profile/1", "profile/2"),
      s"hallpass-agent-profile/1\ncredential=$credential\nendpoint=$endpoint\n",
      profile("https://agents.hallpass.example.com:443"), // stored endpoints must already be canonical
      profile("https://agents.hallpass.example.com/"),
      profile("http://evil.example.com"),
      s"hallpass-agent-profile/1\nendpoint=$endpoint\ncredential=ac1.short\n"
    ).foreach: content =>
      assert(BridgeConfig.fromEnvironment(credentialFileEnvironment(endpoint, content)).isLeft, content)
  }

  test("an environment credential carries no binding") {
    assert(BridgeConfig.fromEnvironment(environment("https://agents.hallpass.example.com")).isRight)
  }

  private final case class EndpointVector(input: String, expected: Option[String])

  private given io.circe.Decoder[EndpointVector] =
    io.circe.Decoder.forProduct2("input", "expected")(EndpointVector.apply)
