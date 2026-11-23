package run.hallpass.gateway

import java.nio.file.{Files, Path}
import munit.FunSuite
import run.hallpass.adapters.linear.LinearEndpoints

class LinearRuntimeSuite extends FunSuite:
  private val secretContents = "LINEAR-SECRET-sentinel-42de"

  private def write(content: String): Path =
    val path = Files.createTempFile("linear-runtime", ".txt")
    Files.writeString(path, content)
    path.toFile.deleteOnExit()
    path

  private def env(overrides: (String, String)*): Map[String, String] =
    Map(
      "HALLPASS_LINEAR_CLIENT_ID" -> "linear-client-1",
      "HALLPASS_LINEAR_REDIRECT_URI" -> "http://localhost:3000/api/oauth/linear/callback",
      "HALLPASS_LINEAR_CLIENT_SECRET_FILE" -> write(secretContents).toString
    ) ++ overrides

  private def failure(environment: Map[String, String]): String =
    LinearRuntime.fromEnvironment(environment).fold(identity, _ => fail("expected a configuration error"))

  test("Linear is off when the client ID is unset or blank") {
    assertEquals(LinearRuntime.fromEnvironment(Map.empty), Right(None))
    assertEquals(LinearRuntime.fromEnvironment(Map("HALLPASS_LINEAR_CLIENT_ID" -> "  ")), Right(None))
    assertEquals(LinearRuntime.fromEnvironment(Map("HALLPASS_LINEAR_CLIENT_ID" -> "")), Right(None))
  }

  test("a complete configuration selects the production endpoints") {
    val selection = LinearRuntime.fromEnvironment(env()).toOption.flatten.getOrElse(fail("expected a selection"))
    assertEquals(selection.client.clientId, "linear-client-1")
    assertEquals(selection.client.secretForRefresh, secretContents)
    assertEquals(selection.endpoints, LinearEndpoints.Production)
    assertEquals(selection.redirectUri.getPath, "/api/oauth/linear/callback")
  }

  test("each missing or invalid required value refuses startup") {
    List("HALLPASS_LINEAR_REDIRECT_URI", "HALLPASS_LINEAR_CLIENT_SECRET_FILE").foreach(key => assert(failure(env() - key).contains(key), key))
    assert(failure(env("HALLPASS_LINEAR_CLIENT_ID" -> "bad id")).contains("HALLPASS_LINEAR_CLIENT_ID"))
    assert(LinearRuntime.fromEnvironment(env("HALLPASS_LINEAR_REDIRECT_URI" -> "/relative")).isLeft)
    assert(LinearRuntime.fromEnvironment(env("HALLPASS_LINEAR_REDIRECT_URI" -> "ftp://localhost/cb")).isLeft)
  }

  test("the environment-variable form of the secret is refused without echoing it") {
    val message = failure(env("HALLPASS_LINEAR_CLIENT_SECRET" -> "value-sentinel-77"))
    assert(message.contains("HALLPASS_LINEAR_CLIENT_SECRET"))
    assert(!message.contains("value-sentinel-77"))
  }

  test("unreadable and empty secret files are errors") {
    assertEquals(failure(env("HALLPASS_LINEAR_CLIENT_SECRET_FILE" -> "/nonexistent/secret")), "Unable to read HALLPASS_LINEAR_CLIENT_SECRET_FILE")
    assertEquals(failure(env("HALLPASS_LINEAR_CLIENT_SECRET_FILE" -> write("  \n").toString)), "HALLPASS_LINEAR_CLIENT_SECRET_FILE is empty")
    assertEquals(failure(env("HALLPASS_LINEAR_CLIENT_SECRET_FILE" -> write("").toString)), "HALLPASS_LINEAR_CLIENT_SECRET_FILE is empty")
  }

  test("errors never contain the secret file contents") {
    List(env("HALLPASS_LINEAR_CLIENT_ID" -> "bad id"), env("HALLPASS_LINEAR_REDIRECT_URI" -> "/relative"), env("HALLPASS_LINEAR_EXCHANGE_URL" -> "nope"))
      .foreach(environment => assert(!failure(environment).contains(secretContents)))
  }

  test("endpoint overrides must be absolute http(s) URLs with a host") {
    val selection = LinearRuntime
      .fromEnvironment(env("HALLPASS_LINEAR_AUTHORIZE_URL" -> "http://localhost:9000/a", "HALLPASS_LINEAR_EXCHANGE_URL" -> "http://localhost:9000/t", "HALLPASS_LINEAR_GRAPHQL_URL" -> "http://localhost:9000/g"))
      .toOption.flatten.getOrElse(fail("expected a selection"))
    assertEquals(selection.endpoints.authorize.toString, "http://localhost:9000/a")
    assertEquals(selection.endpoints.token.toString, "http://localhost:9000/t")
    assertEquals(selection.endpoints.graphql.toString, "http://localhost:9000/g")
    LinearRuntime.EndpointOverrideKeys.foreach { key =>
      List("not a url", "/relative", "file:///etc/passwd", "http://").foreach(bad => assert(failure(env(key -> bad)).contains(key), s"$key $bad"))
    }
  }

  test("production requires an https redirect URI") {
    assert(failure(env("HALLPASS_ENV" -> "production")).contains("https"))
    assert(LinearRuntime.fromEnvironment(env("HALLPASS_ENV" -> "production", "HALLPASS_LINEAR_REDIRECT_URI" -> "https://admin.example.com/api/oauth/linear/callback")).isRight)
    assert(LinearRuntime.fromEnvironment(env("HALLPASS_ENV" -> "development")).isRight)
  }
