package run.hallpass.gateway

import java.nio.file.{Files, Path}
import munit.FunSuite
import run.hallpass.adapters.notion.NotionEndpoints

class NotionRuntimeSuite extends FunSuite:
  private val secretContents = "NOTION-SECRET-sentinel-42de"

  private def write(content: String): Path =
    val path = Files.createTempFile("notion-runtime", ".txt")
    Files.writeString(path, content)
    path.toFile.deleteOnExit()
    path

  private def env(overrides: (String, String)*): Map[String, String] =
    Map(
      "HALLPASS_NOTION_CLIENT_ID" -> "notion-client-1",
      "HALLPASS_NOTION_REDIRECT_URI" -> "http://localhost:3000/api/oauth/notion/callback",
      "HALLPASS_NOTION_CLIENT_SECRET_FILE" -> write(secretContents).toString
    ) ++ overrides

  private def failure(environment: Map[String, String]): String =
    NotionRuntime.fromEnvironment(environment).fold(identity, _ => fail("expected a configuration error"))

  test("Notion is off when the client ID is unset or blank") {
    assertEquals(NotionRuntime.fromEnvironment(Map.empty), Right(None))
    assertEquals(NotionRuntime.fromEnvironment(Map("HALLPASS_NOTION_CLIENT_ID" -> "  ")), Right(None))
    assertEquals(NotionRuntime.fromEnvironment(Map("HALLPASS_NOTION_CLIENT_ID" -> "")), Right(None))
  }

  test("a complete configuration selects the production endpoints") {
    val selection = NotionRuntime.fromEnvironment(env()).toOption.flatten.getOrElse(fail("expected a selection"))
    assertEquals(selection.client.clientId, "notion-client-1")
    assert(!selection.client.toString.contains(secretContents))
    assertEquals(selection.endpoints, NotionEndpoints.Production)
    assertEquals(selection.redirectUri.getPath, "/api/oauth/notion/callback")
  }

  test("each missing or invalid required value refuses startup") {
    List("HALLPASS_NOTION_REDIRECT_URI", "HALLPASS_NOTION_CLIENT_SECRET_FILE").foreach(key => assert(failure(env() - key).contains(key), key))
    assert(failure(env("HALLPASS_NOTION_CLIENT_ID" -> "bad id")).contains("HALLPASS_NOTION_CLIENT_ID"))
    assert(NotionRuntime.fromEnvironment(env("HALLPASS_NOTION_REDIRECT_URI" -> "/relative")).isLeft)
    assert(NotionRuntime.fromEnvironment(env("HALLPASS_NOTION_REDIRECT_URI" -> "ftp://localhost/cb")).isLeft)
  }

  test("the environment-variable form of the secret is refused without echoing it") {
    val message = failure(env("HALLPASS_NOTION_CLIENT_SECRET" -> "value-sentinel-77"))
    assert(message.contains("HALLPASS_NOTION_CLIENT_SECRET"))
    assert(!message.contains("value-sentinel-77"))
  }

  test("unreadable and empty secret files are errors") {
    assertEquals(failure(env("HALLPASS_NOTION_CLIENT_SECRET_FILE" -> "/nonexistent/secret")), "Unable to read HALLPASS_NOTION_CLIENT_SECRET_FILE")
    assertEquals(failure(env("HALLPASS_NOTION_CLIENT_SECRET_FILE" -> write("  \n").toString)), "HALLPASS_NOTION_CLIENT_SECRET_FILE is empty")
    assertEquals(failure(env("HALLPASS_NOTION_CLIENT_SECRET_FILE" -> write("").toString)), "HALLPASS_NOTION_CLIENT_SECRET_FILE is empty")
  }

  test("errors never contain the secret file contents") {
    List(env("HALLPASS_NOTION_CLIENT_ID" -> "bad id"), env("HALLPASS_NOTION_REDIRECT_URI" -> "/relative"), env("HALLPASS_NOTION_API_URL" -> "nope"))
      .foreach(environment => assert(!failure(environment).contains(secretContents)))
  }

  test("endpoint overrides must be absolute http(s) URLs with a host") {
    val selection = NotionRuntime
      .fromEnvironment(env("HALLPASS_NOTION_AUTHORIZE_URL" -> "http://localhost:9000/a", "HALLPASS_NOTION_API_URL" -> "http://localhost:9000/api"))
      .toOption.flatten.getOrElse(fail("expected a selection"))
    assertEquals(selection.endpoints.authorize.toString, "http://localhost:9000/a")
    assertEquals(selection.endpoints.api.toString, "http://localhost:9000/api")
    NotionRuntime.EndpointOverrideKeys.foreach { key =>
      List("not a url", "/relative", "file:///etc/passwd", "http://").foreach(bad => assert(failure(env(key -> bad)).contains(key), s"$key $bad"))
    }
  }

  test("production requires an https redirect URI") {
    assert(failure(env("HALLPASS_ENV" -> "production")).contains("https"))
    assert(NotionRuntime.fromEnvironment(env("HALLPASS_ENV" -> "production", "HALLPASS_NOTION_REDIRECT_URI" -> "https://admin.example.com/api/oauth/notion/callback")).isRight)
    assert(NotionRuntime.fromEnvironment(env("HALLPASS_ENV" -> "development")).isRight)
  }
