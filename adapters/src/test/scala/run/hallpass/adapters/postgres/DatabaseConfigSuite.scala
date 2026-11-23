package run.hallpass.adapters.postgres

import munit.FunSuite

final class DatabaseConfigSuite extends FunSuite:
  test("requires an explicit database URL and user") {
    assertEquals(
      DatabaseConfig.fromEnvironment(Map.empty),
      Left("Missing required environment variable: HALLPASS_DB_URL")
    )
    assertEquals(
      DatabaseConfig.fromEnvironment(Map("HALLPASS_DB_URL" -> "jdbc:postgresql://db/authai")),
      Left("Missing required environment variable: HALLPASS_DB_USER")
    )
  }

  test("rejects unsafe pool sizes without exposing password values") {
    val environment = Map(
      "HALLPASS_DB_URL" -> "jdbc:postgresql://db/authai",
      "HALLPASS_DB_USER" -> "hallpass",
      "HALLPASS_DB_PASSWORD" -> "do-not-render",
      "HALLPASS_DB_MAX_POOL_SIZE" -> "0"
    )
    assertEquals(DatabaseConfig.fromEnvironment(environment), Left("HALLPASS_DB_MAX_POOL_SIZE must be between 1 and 64"))
  }

  test("accepts passwordless local configuration") {
    val result = DatabaseConfig.fromEnvironment(
      Map(
        "HALLPASS_DB_URL" -> "jdbc:postgresql://db/authai",
        "HALLPASS_DB_USER" -> "hallpass"
      )
    )
    assert(result.isRight)
  }
