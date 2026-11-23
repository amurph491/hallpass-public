package run.hallpass.bridge

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Instant
import cats.effect.{IO, Ref}
import cats.syntax.all.*
import io.circe.Json
import io.circe.parser.parse
import scala.concurrent.duration.*

/** An approval the server created for one exact call, as the server reported it. */
private[bridge] final case class PendingApproval(id: String, expiresAt: Option[Instant])

/** The bridge's memory of approvals it has been told about, so that the model's identical retry carries the
  * `approval_id`. It is only a convenience: the server binds an approval to the exact invocation and agent, so a wrong
  * or stale ID is a denial, never authority. Entries are keyed by a digest of the tool and its canonical arguments,
  * so an ID is never sent for different arguments. The table is bounded and entries expire. */
private[bridge] final class ApprovalMemory private (now: IO[Instant], state: Ref[IO, ApprovalMemory.State]):
  import ApprovalMemory.*

  def recall(key: String): IO[Option[String]] =
    now.flatMap: at =>
      state.modify: current =>
        current.entries.get(key) match
          case Some(entry) if entry.expiresAt.isAfter(at) => (current, Some(entry.id))
          case Some(_) => (current.copy(entries = current.entries - key), None)
          case None => (current, None)

  def remember(key: String, pending: PendingApproval): IO[Unit] =
    now.flatMap: at =>
      val deadline = pending.expiresAt.fold(at.plusMillis(MaximumLifetime.toMillis))(
        expiry => Seq(expiry, at.plusMillis(MaximumLifetime.toMillis)).min
      )
      state.update: current =>
        val live = current.entries.filter((_, entry) => entry.expiresAt.isAfter(at)) - key
        val room = if live.size >= MaximumEntries then live - live.minBy(_._2.sequence)._1 else live
        State(room + (key -> Entry(pending.id, deadline, current.next)), current.next + 1)

  def forget(key: String): IO[Unit] = state.update(current => current.copy(entries = current.entries - key))

private[bridge] object ApprovalMemory:
  val MaximumEntries = 64
  val MaximumLifetime: FiniteDuration = 30.minutes

  private final case class Entry(id: String, expiresAt: Instant, sequence: Long)
  private final case class State(entries: Map[String, Entry], next: Long)

  def create(now: IO[Instant]): IO[ApprovalMemory] =
    Ref.of[IO, State](State(Map.empty, 0L)).map(new ApprovalMemory(now, _))

  private val IdPattern = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}".r

  /** SHA-256 of the tool name and the compact JSON of the arguments with object keys sorted at every level. */
  def keyOf(tool: String, arguments: Json): String =
    val text = tool + "\u0000" + canonical(arguments).noSpaces
    MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)).map("%02x".format(_)).mkString

  private def canonical(json: Json): Json =
    json.arrayOrObject(
      json,
      values => Json.fromValues(values.map(canonical)),
      fields => Json.fromFields(fields.toVector.sortBy(_._1).map((key, value) => key -> canonical(value)))
    )

  /** The `approval_id` of a 409 `approval_required` body. The server's value is untrusted: only a well-formed ID is kept. */
  def pendingApproval(body: Array[Byte]): Option[PendingApproval] =
    for
      json <- parse(new String(body, StandardCharsets.UTF_8)).toOption
      fields <- json.asObject
      id <- fields("approval_id").flatMap(_.asString).filter(IdPattern.matches)
      expiresAt = fields("expires_at").flatMap(_.asString).flatMap(text => scala.util.Try(Instant.parse(text)).toOption)
    yield PendingApproval(id, expiresAt)
