package run.hallpass.adapters.postgres

import java.time.Instant
import cats.effect.IO
import cats.syntax.all.*
import org.typelevel.doobie.Transactor
import run.hallpass.adapters.slack.Slack
import run.hallpass.application.*
import run.hallpass.kernel.*

/** Exercises the same reservation and single-transaction activation used by connection management. */
private[postgres] object SlackConnectionFixture:
  def create(
      xa: Transactor[IO],
      connection: ConnectionId,
      reference: SecretReference,
      at: Instant
  ): IO[Connection] =
    val connections = PostgresConnectionRepository(xa)
    val external = ExternalId.parse("T123").getOrElse(throw IllegalStateException("invalid fixture account"))
    for
      _ <- connections.reserve(DemoBootstrap.Tenant, connection, "SLACK", DemoBootstrap.Human, at)
      activated <- connections.activateReserved(
        DemoBootstrap.Tenant,
        connection,
        ConnectionActivation(
          DemoBootstrap.Human, external, Some("Demo account"), Some("Shared demo workspace"), None, "SLACK_OAUTH",
          reference, Slack.workspace, external, "Shared demo workspace", None, singleActiveRoot = true
        ),
        at
      )
      saved <- IO.fromEither(activated.leftMap(error => RuntimeException(s"connection activation failed: $error")))
    yield saved

  /** The demo tenant's active Slack connection, created once. Grants name its root; suites that share one database
    * reuse it, since a second active workspace would be refused. */
  def ensure(xa: Transactor[IO], at: Instant): IO[Connection] =
    PostgresConnectionRepository(xa).list(DemoBootstrap.Tenant).flatMap: all =>
      all.find(connection => connection.externalAccountId.contains("T123") && connection.status == ConnectionStatus.Active) match
        case Some(existing) => IO.pure(existing)
        case None           => create(xa, ConnectionId.random(), SecretReference.random(), at)
