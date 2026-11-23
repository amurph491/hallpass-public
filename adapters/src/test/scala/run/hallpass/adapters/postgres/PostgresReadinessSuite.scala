package run.hallpass.adapters.postgres

import java.sql.DriverManager
import scala.compiletime.uninitialized
import scala.concurrent.duration.*
import cats.effect.IO
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer

final class PostgresReadinessSuite extends CatsEffectSuite:
  private var container: PostgreSQLContainer[?] = uninitialized
  private var dockerAvailable = false

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      val admin = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
      try
        val statement = admin.createStatement()
        statement.execute("create role hallpass login password 'test-password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute("grant connect on database test to hallpass")
        statement.execute("grant usage, create on schema public to hallpass")
      finally admin.close()

  override def afterAll(): Unit = if dockerAvailable then container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  private def config: DatabaseConfig =
    DatabaseConfig
      .fromEnvironment(
        Map("HALLPASS_DB_URL" -> container.getJdbcUrl, "HALLPASS_DB_USER" -> "hallpass", "HALLPASS_DB_PASSWORD" -> "test-password")
      )
      .toOption
      .get

  test("readiness requires at least the schema version this code needs, and tolerates a newer one") {
    requireDocker()
    PostgresDatabase.resourceWithSchema(config).use: (xa, version) =>
      for
        current <- PostgresDatabase.schemaAtLeast(xa, version)
        olderCode <- PostgresDatabase.schemaAtLeast(xa, SchemaVersion("1"))
        newerCode <- PostgresDatabase.schemaAtLeast(xa, SchemaVersion("999"))
      yield
        assert(version.value.toIntOption.exists(_ >= 11), s"unexpected schema version $version")
        assert(current)
        assert(olderCode, "an older release must stay ready against a newer schema during a rolling deploy")
        assert(!newerCode)
  }

  test("repository readiness reflects the schema version") {
    requireDocker()
    DemoRepositories.resource(config).use(repositories => repositories.schemaReady.map(assert(_)))
  }

  test("the tenant gate pool reports health without taking a lock") {
    requireDocker()
    PostgresTenantExecutionMutationGate
      .resource(config, PostgresTenantGateConfig.from(2, 1.second).toOption.get)
      .use(gate => gate.healthy.map(assert(_)))
  }
