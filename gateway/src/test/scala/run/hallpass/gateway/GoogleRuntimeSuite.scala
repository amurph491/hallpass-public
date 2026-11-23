package run.hallpass.gateway

import java.nio.file.{Files, Path}
import munit.FunSuite
import run.hallpass.adapters.google.GoogleEndpoints

class GoogleRuntimeSuite extends FunSuite:
  private val secretContents = "GOOGLE-SECRET-sentinel-42de"

  private def write(content: String): Path =
    val path = Files.createTempFile("google-runtime", ".txt")
    Files.writeString(path, content)
    path.toFile.deleteOnExit()
    path

  private def env(overrides: (String, String)*): Map[String, String] =
    Map(
      "HALLPASS_GOOGLE_DRIVE_CLIENT_ID" -> "google-client-1",
      "HALLPASS_GOOGLE_DRIVE_REDIRECT_URI" -> "http://localhost:3000/api/oauth/google/callback",
      "HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET_FILE" -> write(secretContents).toString
    ) ++ overrides

  private def failure(environment: Map[String, String]): String =
    GoogleRuntime.fromEnvironment(environment).fold(identity, _ => fail("expected a configuration error"))

  test("Google Drive is off when the client ID is unset or blank") {
    assertEquals(GoogleRuntime.fromEnvironment(Map.empty), Right(None))
    assertEquals(GoogleRuntime.fromEnvironment(Map("HALLPASS_GOOGLE_DRIVE_CLIENT_ID" -> "  ")), Right(None))
    assertEquals(GoogleRuntime.fromEnvironment(Map("HALLPASS_GOOGLE_DRIVE_CLIENT_ID" -> "")), Right(None))
  }

  test("a complete configuration selects the production endpoints") {
    val selection = GoogleRuntime.fromEnvironment(env()).toOption.flatten.getOrElse(fail("expected a selection"))
    assertEquals(selection.client.clientId, "google-client-1")
    assert(!selection.client.toString.contains(secretContents))
    assertEquals(selection.endpoints, GoogleEndpoints.Production)
    assertEquals(selection.redirectUri.getPath, "/api/oauth/google/callback")
  }

  test("each missing or invalid required value refuses startup") {
    List("HALLPASS_GOOGLE_DRIVE_REDIRECT_URI", "HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET_FILE").foreach(key => assert(failure(env() - key).contains(key), key))
    assert(failure(env("HALLPASS_GOOGLE_DRIVE_CLIENT_ID" -> "bad id")).contains("HALLPASS_GOOGLE_DRIVE_CLIENT_ID"))
    assert(GoogleRuntime.fromEnvironment(env("HALLPASS_GOOGLE_DRIVE_REDIRECT_URI" -> "/relative")).isLeft)
    assert(GoogleRuntime.fromEnvironment(env("HALLPASS_GOOGLE_DRIVE_REDIRECT_URI" -> "ftp://localhost/cb")).isLeft)
  }

  test("the environment-variable form of the secret is refused without echoing it") {
    val message = failure(env("HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET" -> "value-sentinel-77"))
    assert(message.contains("HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET"))
    assert(!message.contains("value-sentinel-77"))
  }

  test("unreadable and empty secret files are errors") {
    assertEquals(failure(env("HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET_FILE" -> "/nonexistent/secret")), "Unable to read HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET_FILE")
    assertEquals(failure(env("HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET_FILE" -> write("  \n").toString)), "HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET_FILE is empty")
    assertEquals(failure(env("HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET_FILE" -> write("").toString)), "HALLPASS_GOOGLE_DRIVE_CLIENT_SECRET_FILE is empty")
  }

  test("errors never contain the secret file contents") {
    List(env("HALLPASS_GOOGLE_DRIVE_CLIENT_ID" -> "bad id"), env("HALLPASS_GOOGLE_DRIVE_REDIRECT_URI" -> "/relative"), env("HALLPASS_GOOGLE_DRIVE_API_URL" -> "nope"))
      .foreach(environment => assert(!failure(environment).contains(secretContents)))
  }

  test("endpoint overrides must be absolute http(s) URLs with a host") {
    val selection = GoogleRuntime
      .fromEnvironment(
        env(
          "HALLPASS_GOOGLE_AUTHORIZE_URL" -> "http://localhost:9000/a",
          "HALLPASS_GOOGLE_EXCHANGE_URL" -> "http://localhost:9000/t",
          "HALLPASS_GOOGLE_USERINFO_URL" -> "http://localhost:9000/u",
          "HALLPASS_GOOGLE_DRIVE_API_URL" -> "http://localhost:9000/d"
        )
      )
      .toOption.flatten.getOrElse(fail("expected a selection"))
    assertEquals(selection.endpoints.authorize.toString, "http://localhost:9000/a")
    assertEquals(selection.endpoints.token.toString, "http://localhost:9000/t")
    assertEquals(selection.endpoints.userinfo.toString, "http://localhost:9000/u")
    assertEquals(selection.endpoints.driveApi.toString, "http://localhost:9000/d")
    GoogleRuntime.EndpointOverrideKeys.foreach { key =>
      List("not a url", "/relative", "file:///etc/passwd", "http://").foreach(bad => assert(failure(env(key -> bad)).contains(key), s"$key $bad"))
    }
  }

  test("no endpoint override key contains TOKEN, so the Compose secret scan stays meaningful") {
    GoogleRuntime.EndpointOverrideKeys.foreach(key => assert(!key.contains("TOKEN"), key))
  }

  test("the Picker settings are optional, browser-visible, and validated") {
    val without = GoogleRuntime.fromEnvironment(env()).toOption.flatten.getOrElse(fail("expected a selection"))
    assertEquals((without.client.pickerApiKey, without.client.appId), (None, None))
    val picker = GoogleRuntime
      .fromEnvironment(env("HALLPASS_GOOGLE_PICKER_API_KEY" -> "AIzaSyExample-key_1", "HALLPASS_GOOGLE_PICKER_APP_ID" -> "123456789012"))
      .toOption.flatten.getOrElse(fail("expected a selection"))
    assertEquals(picker.client.pickerApiKey, Some("AIzaSyExample-key_1"))
    assertEquals(picker.client.appId, Some("123456789012"))
    assert(failure(env("HALLPASS_GOOGLE_PICKER_APP_ID" -> "12ab")).contains("HALLPASS_GOOGLE_PICKER_APP_ID"))
    assert(failure(env("HALLPASS_GOOGLE_PICKER_API_KEY" -> "bad key")).contains("HALLPASS_GOOGLE_PICKER_API_KEY"))
  }

  test("production requires an https redirect URI") {
    assert(failure(env("HALLPASS_ENV" -> "production")).contains("https"))
    assert(GoogleRuntime.fromEnvironment(env("HALLPASS_ENV" -> "production", "HALLPASS_GOOGLE_DRIVE_REDIRECT_URI" -> "https://admin.example.com/api/oauth/google/callback")).isRight)
    assert(GoogleRuntime.fromEnvironment(env("HALLPASS_ENV" -> "development")).isRight)
  }

  test("Gmail send is off by default and when false") {
    assertEquals(GoogleRuntime.fromEnvironment(env()).toOption.flatten.map(_.gmailSend), Some(false))
    assertEquals(GoogleRuntime.fromEnvironment(env("HALLPASS_GOOGLE_GMAIL_SEND_ENABLED" -> "false")).toOption.flatten.map(_.gmailSend), Some(false))
    assertEquals(GoogleRuntime.fromEnvironment(env("HALLPASS_GOOGLE_GMAIL_SEND_ENABLED" -> "")).toOption.flatten.map(_.gmailSend), Some(false))
  }

  test("Gmail send is enabled only by the exact value true") {
    assertEquals(GoogleRuntime.fromEnvironment(env("HALLPASS_GOOGLE_GMAIL_SEND_ENABLED" -> "true")).toOption.flatten.map(_.gmailSend), Some(true))
  }

  test("any other Gmail send value refuses startup, naming the setting and not the value") {
    Vector("TRUE", "yes", "1", "on", "enabled").foreach: value =>
      val message = failure(env("HALLPASS_GOOGLE_GMAIL_SEND_ENABLED" -> value))
      assert(message.contains("HALLPASS_GOOGLE_GMAIL_SEND_ENABLED"), message)
      assert(!message.contains(value), message)
  }
