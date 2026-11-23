package run.hallpass.adapters.postgres

import java.net.InetAddress
import java.sql.DriverManager
import java.util.UUID
import scala.compiletime.uninitialized
import cats.effect.IO
import cats.syntax.all.*
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.util.transactor.Transactor
import run.hallpass.application.*

/** Durable agent-selector lockout and the rejection audit, as the split runtime role. The owner inspects rows and moves
  * clocks backwards, standing in for time passing. */
final class PostgresAgentAuthenticationLockoutSuite extends CatsEffectSuite:
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(120, "s")
  private var container: PostgreSQLContainer[?] = uninitialized
  private var dockerAvailable = false
  private val Owner = "authai_owner"
  private val App = "authai_app"
  private val Password = "test-password"
  private val client = Some(InetAddress.getByName("203.0.113.7"))

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      val connection = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
      try
        val statement = connection.createStatement()
        statement.execute(s"create role $Owner login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"create role $App login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"grant connect on database test to $Owner, $App")
        statement.execute("revoke create on schema public from public")
        statement.execute(s"grant usage, create on schema public to $Owner")
        statement.execute(s"grant usage on schema public to $App")
      finally connection.close()

  override def afterAll(): Unit = if dockerAvailable then container.stop()

  private def config(user: String): DatabaseConfig =
    DatabaseConfig
      .fromEnvironment(Map("HALLPASS_DB_URL" -> container.getJdbcUrl, "HALLPASS_DB_USER" -> user, "HALLPASS_DB_PASSWORD" -> Password))
      .toOption
      .get

  private lazy val prepared: IO[Unit] =
    PostgresDatabase.migrateAsOwner(config(Owner), RuntimeRole.parse(App).toOption.get).void

  private def asOwner[A](program: Transactor[IO] => IO[A]): IO[A] =
    prepared *> PostgresDatabase.ownerResource(config(Owner)).use(program)

  private def asRuntimeRole[A](program: PostgresAgentAuthenticationLockout => IO[A]): IO[A] =
    prepared *> PostgresDatabase.resourceWithSchema(config(App), MigrationMode.External).use((xa, _) => program(PostgresAgentAuthenticationLockout(xa)))

  private def selector(): AgentCredentialSelector =
    AgentCredentialSelector.parse(UUID.randomUUID().toString.replace("-", "").take(20)).getOrElse(fail("selector"))

  private def wrongSecrets(lockout: PostgresAgentAuthenticationLockout, value: AgentCredentialSelector, times: Int): IO[Unit] =
    lockout.recordRejection(Some(value), AgentRejectionReason.WrongSecret, client).replicateA_(times)

  test("ten wrong secrets lock a selector for every instance; nine do not") {
    assume(dockerAvailable, "Docker is required")
    val (nine, ten) = (selector(), selector())
    asRuntimeRole: lockout =>
      for
        _ <- wrongSecrets(lockout, nine, 9)
        _ <- wrongSecrets(lockout, ten, 10)
        states <- (lockout.isLocked(nine), lockout.isLocked(ten)).tupled
      yield assertEquals(states, (Right(false), Right(true)))
  }

  test("only wrong secrets count toward a lockout") {
    assume(dockerAvailable, "Docker is required")
    val value = selector()
    asRuntimeRole: lockout =>
      for
        _ <- Vector(AgentRejectionReason.UnknownCredential, AgentRejectionReason.ExpiredCredential, AgentRejectionReason.RevokedCredential)
          .traverse_(reason => lockout.recordRejection(Some(value), reason, client).replicateA_(10))
        locked <- lockout.isLocked(value)
      yield assertEquals(locked, Right(false))
  }

  test("a lock expires, and failures outside the 15-minute window start a new count") {
    assume(dockerAvailable, "Docker is required")
    val (expiring, windowed) = (selector(), selector())
    for
      _ <- asRuntimeRole(lockout => wrongSecrets(lockout, expiring, 10) *> wrongSecrets(lockout, windowed, 9))
      _ <- asOwner(xa =>
        (sql"""update directory_agent_authentication_failures set locked_until = now() - interval '1 second'
               where selector_digest = ${PostgresAgentAuthenticationLockout.digest(expiring)}""".update.run *>
          sql"""update directory_agent_authentication_failures set window_started_at = now() - interval '16 minutes'
                where selector_digest = ${PostgresAgentAuthenticationLockout.digest(windowed)}""".update.run).transact(xa)
      )
      states <- asRuntimeRole(lockout => wrongSecrets(lockout, windowed, 1) *> (lockout.isLocked(expiring), lockout.isLocked(windowed)).tupled)
      count <- asOwner(xa =>
        sql"select failures from directory_agent_authentication_failures where selector_digest = ${PostgresAgentAuthenticationLockout.digest(windowed)}"
          .query[Int].unique.transact(xa)
      )
    yield
      assertEquals(states, (Right(false), Right(false)))
      assertEquals(count, 1, "the tenth failure outside the window starts a new count")
  }

  test("rejections are audited with a selector digest and the client address, never the selector") {
    assume(dockerAvailable, "Docker is required")
    val value = selector()
    for
      _ <- asRuntimeRole(lockout =>
        lockout.recordRejection(Some(value), AgentRejectionReason.WrongSecret, client) *>
          lockout.recordRejection(None, AgentRejectionReason.MalformedCredential, None)
      )
      rows <- asOwner(xa =>
        sql"""select reason, encode(selector_digest, 'hex'), host(client_address)
              from directory_agent_authentication_rejections order by id desc limit 2"""
          .query[(String, Option[String], Option[String])].to[Vector].transact(xa)
      )
      columns <- asOwner(xa =>
        sql"""select string_agg(column_name, ',' order by column_name) from information_schema.columns
              where table_name = 'directory_agent_authentication_rejections'"""
          .query[String].unique.transact(xa)
      )
    yield
      assertEquals(rows.map(_._1), Vector("MALFORMED_CREDENTIAL", "WRONG_SECRET"))
      assertEquals(rows(1)._3, Some("203.0.113.7"))
      assert(rows(1)._2.exists(_.length == 64))
      assert(!rows.toString.contains(value.value), "the selector itself is never stored")
      assertEquals(columns, "client_address,id,occurred_at,reason,selector_digest")
  }

  test("every rejection reason is accepted by the audit's vocabulary") {
    assume(dockerAvailable, "Docker is required")
    asRuntimeRole: lockout =>
      AgentRejectionReason.values.toVector
        .traverse(reason => lockout.recordRejection(Some(selector()), reason, client))
        .map(results => assertEquals(results.filter(_.isLeft), Vector.empty))
  }
