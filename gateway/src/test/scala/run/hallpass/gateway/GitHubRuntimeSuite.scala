package run.hallpass.gateway

import java.nio.file.{Files, Path}
import java.security.interfaces.RSAPrivateKey
import munit.FunSuite

class GitHubRuntimeSuite extends FunSuite:
  private val keyContents = "PEM-CONTENTS-sentinel-7f3a"
  private val secretContents = "CLIENT-SECRET-sentinel-91bc"

  // The suite never exercises real PEM parsing; a JDK-generated key stands in for a successful parse.
  private lazy val rsaKey: RSAPrivateKey =
    val generator = java.security.KeyPairGenerator.getInstance("RSA")
    generator.initialize(2048)
    generator.generateKeyPair().getPrivate.asInstanceOf[RSAPrivateKey]
  private val acceptKey: String => Either[String, RSAPrivateKey] = _ => Right(rsaKey)
  private val rejectKey: String => Either[String, RSAPrivateKey] = text => Left(s"bad key $text")

  private def write(content: String): Path =
    val path = Files.createTempFile("github-runtime", ".txt")
    Files.writeString(path, content)
    path.toFile.deleteOnExit()
    path

  private def env(overrides: (String, String)*): Map[String, String] =
    Map(
      "HALLPASS_GITHUB_APP_ID" -> "12345",
      "HALLPASS_GITHUB_CLIENT_ID" -> "Iv1.abcdef",
      "HALLPASS_GITHUB_APP_SLUG" -> "hallpass-dev",
      "HALLPASS_GITHUB_REDIRECT_URI" -> "http://localhost:3000/api/oauth/github/callback",
      "HALLPASS_GITHUB_PRIVATE_KEY_FILE" -> write(keyContents).toString,
      "HALLPASS_GITHUB_CLIENT_SECRET_FILE" -> write(secretContents).toString
    ) ++ overrides

  private def load(environment: Map[String, String], parse: String => Either[String, RSAPrivateKey] = acceptKey) =
    GitHubRuntime.fromEnvironment(environment, parse)

  private def failure(environment: Map[String, String], parse: String => Either[String, RSAPrivateKey] = acceptKey): String =
    load(environment, parse).fold(identity, _ => fail("expected a configuration error"))

  test("GitHub is off when the app ID is unset or blank") {
    assertEquals(load(Map.empty), Right(None))
    assertEquals(load(Map("HALLPASS_GITHUB_APP_ID" -> "  ")), Right(None))
    assertEquals(load(Map("HALLPASS_GITHUB_APP_ID" -> "")), Right(None))
  }

  test("a complete configuration selects github.com endpoints and the registration") {
    val selection = load(env()).toOption.flatten.getOrElse(fail("expected a selection"))
    assertEquals(selection.registration.appId, 12345L)
    assertEquals(selection.registration.slug, "hallpass-dev")
    assertEquals(selection.endpoints, run.hallpass.adapters.github.GitHubEndpoints.DotCom)
    assertEquals(selection.redirectUri.getPath, "/api/oauth/github/callback")
  }

  test("each missing or invalid required value refuses startup") {
    List("HALLPASS_GITHUB_CLIENT_ID", "HALLPASS_GITHUB_APP_SLUG", "HALLPASS_GITHUB_REDIRECT_URI", "HALLPASS_GITHUB_PRIVATE_KEY_FILE", "HALLPASS_GITHUB_CLIENT_SECRET_FILE")
      .foreach(key => assert(failure(env() - key).contains(key), key))
    List("abc", "0", "-4").foreach(id => assert(failure(env("HALLPASS_GITHUB_APP_ID" -> id)).contains("HALLPASS_GITHUB_APP_ID"), id))
    assert(load(env("HALLPASS_GITHUB_APP_SLUG" -> "Bad Slug!")).isLeft)
    assert(load(env("HALLPASS_GITHUB_CLIENT_ID" -> "bad id")).isLeft)
    assert(load(env("HALLPASS_GITHUB_REDIRECT_URI" -> "/relative")).isLeft)
    assert(load(env("HALLPASS_GITHUB_REDIRECT_URI" -> "ftp://localhost/cb")).isLeft)
  }

  test("environment-variable forms of the secrets are refused") {
    List("HALLPASS_GITHUB_PRIVATE_KEY", "HALLPASS_GITHUB_CLIENT_SECRET").foreach { key =>
      val message = failure(env(key -> "value-sentinel-55"))
      assert(message.contains(key))
      assert(!message.contains("value-sentinel-55"))
    }
  }

  test("unreadable and empty secret files are errors") {
    assertEquals(failure(env("HALLPASS_GITHUB_PRIVATE_KEY_FILE" -> "/nonexistent/key.pem")), "Unable to read HALLPASS_GITHUB_PRIVATE_KEY_FILE")
    assertEquals(failure(env("HALLPASS_GITHUB_CLIENT_SECRET_FILE" -> "/nonexistent/secret")), "Unable to read HALLPASS_GITHUB_CLIENT_SECRET_FILE")
    assertEquals(failure(env("HALLPASS_GITHUB_PRIVATE_KEY_FILE" -> write("  \n").toString)), "HALLPASS_GITHUB_PRIVATE_KEY_FILE is empty")
    assertEquals(failure(env("HALLPASS_GITHUB_CLIENT_SECRET_FILE" -> write("").toString)), "HALLPASS_GITHUB_CLIENT_SECRET_FILE is empty")
  }

  test("errors never contain secret file contents, including a rejected key") {
    val parseFailure = failure(env(), rejectKey)
    assert(parseFailure.contains("HALLPASS_GITHUB_PRIVATE_KEY_FILE"))
    List(keyContents, secretContents).foreach(secret => assert(!parseFailure.contains(secret)))
    val other = failure(env("HALLPASS_GITHUB_APP_SLUG" -> "Bad Slug!"))
    List(keyContents, secretContents).foreach(secret => assert(!other.contains(secret)))
  }

  test("endpoint overrides must be absolute http(s) URLs with a host") {
    val selection = load(env("HALLPASS_GITHUB_API_URL" -> "http://localhost:9000", "HALLPASS_GITHUB_WEB_URL" -> "http://localhost:9001"))
      .toOption.flatten.getOrElse(fail("expected a selection"))
    assertEquals(selection.endpoints.api.toString, "http://localhost:9000")
    assertEquals(selection.endpoints.web.toString, "http://localhost:9001")
    List(GitHubRuntime.ApiUrlKey, GitHubRuntime.WebUrlKey).foreach { key =>
      List("not a url", "/relative", "file:///etc/passwd", "http://").foreach(bad =>
        assert(failure(env(key -> bad)).contains(key), s"$key $bad")
      )
    }
  }

  test("production requires an https redirect URI") {
    assert(failure(env("HALLPASS_ENV" -> "production")).contains("https"))
    assert(load(env("HALLPASS_ENV" -> "production", "HALLPASS_GITHUB_REDIRECT_URI" -> "https://admin.example.com/api/oauth/github/callback")).isRight)
    assert(load(env("HALLPASS_ENV" -> "development")).isRight)
  }
