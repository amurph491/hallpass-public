package run.hallpass.adapters.postgres

import java.net.InetAddress
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import cats.effect.IO
import cats.syntax.all.*
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import run.hallpass.application.*

/** Durable selector lockout and rejection audit through the V15 directory functions. Only a digest of the selector is
  * sent; database failures are `DirectoryError.Unavailable`, never "not locked". */
final class PostgresAgentAuthenticationLockout(xa: Transactor[IO]) extends AgentAuthenticationLockout:
  import PostgresAgentAuthenticationLockout.*

  def isLocked(selector: AgentCredentialSelector): IO[Either[DirectoryError, Boolean]] =
    sql"select authai_agent_selector_locked(${digest(selector)})"
      .query[Boolean]
      .unique
      .transact(xa)
      .map(Right(_))
      .handleError(_ => Left(DirectoryError.Unavailable))

  def recordRejection(
      selector: Option[AgentCredentialSelector],
      reason: AgentRejectionReason,
      client: Option[InetAddress]
  ): IO[Either[DirectoryError, Unit]] =
    sql"""select count(*) from authai_record_agent_authentication_rejection(
            ${selector.map(digest)}, ${wire(reason)}, ${client.map(_.getHostAddress)}::inet)"""
      .query[Long]
      .unique
      .transact(xa)
      .as(Right(()))
      .handleError(_ => Left(DirectoryError.Unavailable))

object PostgresAgentAuthenticationLockout:
  /** Domain-separated so the digest cannot be confused with any other stored hash. */
  private[postgres] def digest(selector: AgentCredentialSelector): Array[Byte] =
    val hash = MessageDigest.getInstance("SHA-256")
    hash.update("authai.agent-selector.v1".getBytes(StandardCharsets.US_ASCII))
    hash.update(0.toByte)
    hash.digest(selector.value.getBytes(StandardCharsets.US_ASCII))

  private[postgres] def wire(reason: AgentRejectionReason): String =
    reason.toString.replaceAll("([a-z])([A-Z])", "$1_$2").toUpperCase
