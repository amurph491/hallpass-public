package run.hallpass.adapters.postgres

import java.sql.DriverManager
import java.time.Instant
import cats.effect.IO
import cats.syntax.all.*
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import scala.compiletime.uninitialized
import run.hallpass.application.*
import run.hallpass.kernel.*

final class PostgresAgentCredentialsSuite extends CatsEffectSuite:
  private var container: PostgreSQLContainer[?] = uninitialized
  private var config: DatabaseConfig = uninitialized
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
      config = DatabaseConfig
        .fromEnvironment(
          Map(
            "HALLPASS_DB_URL" -> container.getJdbcUrl,
            "HALLPASS_DB_USER" -> "hallpass",
            "HALLPASS_DB_PASSWORD" -> "test-password"
          )
        )
        .toOption
        .get

  override def afterAll(): Unit = if dockerAvailable then container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  private def credential(selector: String): GeneratedAgentCredential =
    val presented = PresentedAgentCredential.parse(s"ac1.$selector.${"A" * 43}").toOption.get
    val verifier = StoredAgentCredentialVerifier.fromBytes(Array.fill(32)(3.toByte)).toOption.get
    GeneratedAgentCredential.issue(
      AgentCredentialId.random(),
      presented,
      verifier,
      CredentialVerifierMetadata(CredentialVerifierAlgorithm.HmacSha256, "local-test-v1")
    )

  private val request = AgentCredentialEnrollmentRequest.from(Some("local Codex"), None).toOption.get

  test("credential lifecycle is tenant-scoped, revocation is idempotent, and active inserts fail closed") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      val agents = PostgresControlPlane(xa)
      val credentials = new PostgresAgentCredentials(xa)
      val now = Instant.now()
      val first = credential("credentialselector01")
      val second = credential("credentialselector02")
      for
        _ <- DemoBootstrap.run(xa)
        agent <- agents.create(DemoBootstrap.Tenant, CreateAgent("Credential lifecycle", None)).flatMap(_.fold(
          _ => IO.raiseError(RuntimeException("agent creation failed")),
          IO.pure
        ))
        enrolled <- credentials.enroll(DemoBootstrap.Tenant, agent.id, first, request, DemoBootstrap.Human, now)
        duplicate <- credentials.enroll(DemoBootstrap.Tenant, agent.id, second, request, DemoBootstrap.Human, now)
        lookedUp <- credentials.credentialForAuthentication(DemoBootstrap.Tenant, first.selector, now)
        used <- credentials.recordSuccessfulAuthentication(DemoBootstrap.Tenant, first.credentialId, now.plusSeconds(1))
        metadataBeforeRevoke <- credentials.metadataFor(DemoBootstrap.Tenant, agent.id)
        revoked <- credentials.revoke(DemoBootstrap.Tenant, agent.id, first.credentialId, now.plusSeconds(2))
        revokedAgain <- credentials.revoke(DemoBootstrap.Tenant, agent.id, first.credentialId, now.plusSeconds(3))
        afterRevoke <- credentials.credentialForAuthentication(DemoBootstrap.Tenant, first.selector, now.plusSeconds(4))
        useAfterRevoke <- credentials.recordSuccessfulAuthentication(DemoBootstrap.Tenant, first.credentialId, now.plusSeconds(4))
        revokedRotation <- credentials.rotate(
          DemoBootstrap.Tenant,
          agent.id,
          first.credentialId,
          second,
          request,
          DemoBootstrap.Human,
          now.plusSeconds(5)
        )
      yield
        assert(enrolled.isRight)
        assertEquals(duplicate, Left(AgentEnrollmentError.ExistingActiveCredential))
        assert(lookedUp.isRight)
        assertEquals(used, Right(()))
        assertEquals(metadataBeforeRevoke.map(_.label), Vector(Some("local Codex")))
        assertEquals(revoked, Right(()))
        assertEquals(revokedAgain, Right(()))
        assertEquals(afterRevoke, Left(AgentCredentialLookupError.Revoked))
        assertEquals(useAfterRevoke, Left(AgentCredentialUseError.NoLongerActive))
        assertEquals(revokedRotation, Left(AgentEnrollmentError.CredentialNotFound))
  }

  test("rotation locks and replaces only an owned credential") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      val agents = PostgresControlPlane(xa)
      val credentials = new PostgresAgentCredentials(xa)
      val now = Instant.now()
      val original = credential("credentialselector03")
      val replacement = credential("credentialselector04")
      for
        _ <- DemoBootstrap.run(xa)
        owner <- agents.create(DemoBootstrap.Tenant, CreateAgent("Credential owner", None)).flatMap(_.fold(
          _ => IO.raiseError(RuntimeException("owner creation failed")), IO.pure
        ))
        other <- agents.create(DemoBootstrap.Tenant, CreateAgent("Credential other", None)).flatMap(_.fold(
          _ => IO.raiseError(RuntimeException("other creation failed")), IO.pure
        ))
        _ <- credentials.enroll(DemoBootstrap.Tenant, owner.id, original, request, DemoBootstrap.Human, now)
        foreignRotation <- credentials.rotate(DemoBootstrap.Tenant, other.id, original.credentialId, replacement, request, DemoBootstrap.Human, now.plusSeconds(1))
        rotated <- credentials.rotate(DemoBootstrap.Tenant, owner.id, original.credentialId, replacement, request, DemoBootstrap.Human, now.plusSeconds(2))
        oldCredential <- credentials.credentialForAuthentication(DemoBootstrap.Tenant, original.selector, now.plusSeconds(3))
        newCredential <- credentials.credentialForAuthentication(DemoBootstrap.Tenant, replacement.selector, now.plusSeconds(3))
        foreignRevoke <- credentials.revoke(DemoBootstrap.Tenant, other.id, replacement.credentialId, now.plusSeconds(4))
      yield
        assertEquals(foreignRotation, Left(AgentEnrollmentError.CredentialNotFound))
        assert(rotated.isRight)
        assertEquals(oldCredential, Left(AgentCredentialLookupError.Revoked))
        assert(newCredential.isRight)
        assertEquals(foreignRevoke, Left(AgentEnrollmentError.CredentialNotFound))
  }
