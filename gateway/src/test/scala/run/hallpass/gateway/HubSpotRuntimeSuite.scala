package run.hallpass.gateway

import java.nio.file.{Files, Path}
import munit.FunSuite
import run.hallpass.adapters.hubspot.HubSpotEndpoints

class HubSpotRuntimeSuite extends FunSuite:
  private val secretContents = "HUBSPOT-SECRET-sentinel-42de"

  private def write(content: String): Path =
    val path = Files.createTempFile("hubspot-runtime", ".txt")
    Files.writeString(path, content)
    path.toFile.deleteOnExit()
    path

  private def env(overrides: (String, String)*): Map[String, String] =
    Map(
      "HALLPASS_HUBSPOT_CLIENT_ID" -> "hubspot-client-1",
      "HALLPASS_HUBSPOT_REDIRECT_URI" -> "http://localhost:3000/api/oauth/hubspot/callback",
      "HALLPASS_HUBSPOT_CLIENT_SECRET_FILE" -> write(secretContents).toString
    ) ++ overrides

  private def failure(environment: Map[String, String]): String =
    HubSpotRuntime.fromEnvironment(environment).fold(identity, _ => fail("expected a configuration error"))

  test("HubSpot is off when the client ID is unset or blank") {
    assertEquals(HubSpotRuntime.fromEnvironment(Map.empty), Right(None))
    assertEquals(HubSpotRuntime.fromEnvironment(Map("HALLPASS_HUBSPOT_CLIENT_ID" -> "  ")), Right(None))
    assertEquals(HubSpotRuntime.fromEnvironment(Map("HALLPASS_HUBSPOT_CLIENT_ID" -> "")), Right(None))
  }

  test("a complete configuration selects the production endpoints") {
    val selection = HubSpotRuntime.fromEnvironment(env()).toOption.flatten.getOrElse(fail("expected a selection"))
    assertEquals(selection.client.clientId, "hubspot-client-1")
    assert(!selection.client.toString.contains(secretContents))
    assertEquals(selection.endpoints, HubSpotEndpoints.Production)
    assertEquals(selection.redirectUri.getPath, "/api/oauth/hubspot/callback")
  }

  test("each missing or invalid required value refuses startup") {
    List("HALLPASS_HUBSPOT_REDIRECT_URI", "HALLPASS_HUBSPOT_CLIENT_SECRET_FILE").foreach(key => assert(failure(env() - key).contains(key), key))
    assert(failure(env("HALLPASS_HUBSPOT_CLIENT_ID" -> "bad id")).contains("HALLPASS_HUBSPOT_CLIENT_ID"))
    assert(HubSpotRuntime.fromEnvironment(env("HALLPASS_HUBSPOT_REDIRECT_URI" -> "/relative")).isLeft)
    assert(HubSpotRuntime.fromEnvironment(env("HALLPASS_HUBSPOT_REDIRECT_URI" -> "ftp://localhost/cb")).isLeft)
  }

  test("the environment-variable form of the secret is refused without echoing it") {
    val message = failure(env("HALLPASS_HUBSPOT_CLIENT_SECRET" -> "value-sentinel-77"))
    assert(message.contains("HALLPASS_HUBSPOT_CLIENT_SECRET"))
    assert(!message.contains("value-sentinel-77"))
  }

  test("unreadable and empty secret files are errors") {
    assertEquals(failure(env("HALLPASS_HUBSPOT_CLIENT_SECRET_FILE" -> "/nonexistent/secret")), "Unable to read HALLPASS_HUBSPOT_CLIENT_SECRET_FILE")
    assertEquals(failure(env("HALLPASS_HUBSPOT_CLIENT_SECRET_FILE" -> write("  \n").toString)), "HALLPASS_HUBSPOT_CLIENT_SECRET_FILE is empty")
    assertEquals(failure(env("HALLPASS_HUBSPOT_CLIENT_SECRET_FILE" -> write("").toString)), "HALLPASS_HUBSPOT_CLIENT_SECRET_FILE is empty")
  }

  test("errors never contain the secret file contents") {
    List(env("HALLPASS_HUBSPOT_CLIENT_ID" -> "bad id"), env("HALLPASS_HUBSPOT_REDIRECT_URI" -> "/relative"), env("HALLPASS_HUBSPOT_API_URL" -> "nope"))
      .foreach(environment => assert(!failure(environment).contains(secretContents)))
  }

  test("endpoint overrides must be absolute http(s) URLs with a host, and the token endpoint derives from the API URL") {
    val selection = HubSpotRuntime
      .fromEnvironment(env("HALLPASS_HUBSPOT_AUTHORIZE_URL" -> "http://localhost:9000/a", "HALLPASS_HUBSPOT_API_URL" -> "http://localhost:9000"))
      .toOption.flatten.getOrElse(fail("expected a selection"))
    assertEquals(selection.endpoints.authorize.toString, "http://localhost:9000/a")
    assertEquals(selection.endpoints.api.toString, "http://localhost:9000")
    assertEquals(selection.endpoints.token.toString, "http://localhost:9000/oauth/v1/token")
    HubSpotRuntime.EndpointOverrideKeys.foreach { key =>
      List("not a url", "/relative", "file:///etc/passwd", "http://").foreach(bad => assert(failure(env(key -> bad)).contains(key), s"$key $bad"))
    }
  }

  test("no endpoint override key contains TOKEN, so the Compose secret scan stays meaningful") {
    HubSpotRuntime.EndpointOverrideKeys.foreach(key => assert(!key.contains("TOKEN"), key))
  }

  test("production requires an https redirect URI") {
    assert(failure(env("HALLPASS_ENV" -> "production")).contains("https"))
    assert(HubSpotRuntime.fromEnvironment(env("HALLPASS_ENV" -> "production", "HALLPASS_HUBSPOT_REDIRECT_URI" -> "https://admin.example.com/api/oauth/hubspot/callback")).isRight)
    assert(HubSpotRuntime.fromEnvironment(env("HALLPASS_ENV" -> "development")).isRight)
  }
