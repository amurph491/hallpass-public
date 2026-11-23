package run.hallpass.adapters.google

import java.net.URI
import java.net.http.{HttpClient, HttpRequest}
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.TimeUnit
import scala.concurrent.duration.FiniteDuration
import cats.effect.IO
import io.circe.{Json, JsonObject, parser}
import run.hallpass.adapters.http.BoundedHttpResponse
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Gmail send, the only irreversible external-communication operation. Fixed contract:
  *
  * | operation               | tool                  | capability         | action |
  * |-------------------------|-----------------------|--------------------|--------|
  * | `gmail.messages.send@1` | `gmail_messages_send` | `Google.Mail.Send` | WRITE  |
  *
  * Targets `Google.mailbox`; `targetArgument` is `mailbox` (the mailbox's external ID, the account `sub`); `locate` is
  * `Selected(mailbox)`. Arguments: `to` (1–50 addresses), optional `cc` and `bcc` (each 0–50), all parsed by
  * EmailAddress.parse (no display names); total distinct recipients 1–100; `subject` (1–200 characters, no control
  * characters at all — so no header injection); `body` (plain text, 1–100,000 characters; CR, LF and TAB allowed,
  * other control characters refused). Unknown fields refused.
  * Facts: `AuthorizationContext.withFacts(Map.empty, Map(Google.RecipientsFact -> <the distinct union of to, cc,
  * bcc>))`, so a grant can be limited to specific recipients (ValueIn), and approval (owner policy
  * REQUIRE_APPROVAL) binds the exact recipients, subject, and body.
  * Canonical: `{mailbox, to, cc, bcc, subject, body}` with each address list deduplicated and sorted — exactly what the
  * message carries.
  * Dispatch: build an RFC 5322 message with only `To`, `Cc` (when non-empty), `Bcc` (when non-empty), `Subject`
  * (RFC 2047 encoded-word when non-ASCII), `MIME-Version: 1.0`, `Content-Type: text/plain; charset=UTF-8`,
  * `Content-Transfer-Encoding: base64` headers and the base64 body. Bcc: Google documents that messages.send sends to
  * "the recipients in the To, Cc, and Bcc headers", so a Bcc header IS written (when non-empty) or those recipients
  * would not receive the message; it is placed before the MIME headers (Gmail ignores addressing headers that follow
  * them). Gmail removes Bcc from the copies it delivers (standard Bcc semantics; Google's reference pages do not spell
  * this out, so it is unverified against the live API) and keeps it in the sender's Sent copy. Long address lists are
  * folded one address per line. POST `{gmailApi}/gmail/v1/users/me/messages/send` with `{"raw": base64url(message)}`;
  * expect 200 with an `id`; result `Sent message <id> to N recipient(s)`. Sent once, never retried: a timeout (or any
  * transport failure after the request is issued) is ProviderError.Timeout, which the executor records as an unknown
  * outcome — the model is told not to retry. A 401/403 is AuthenticationFailed; any 3xx (never followed), 400,
  * 429 and other non-2xx statuses below 500 are Rejected; a 5xx is OutcomeUnknown. A 2xx other than 200, malformed
  * JSON, a missing or malformed `id`, or an oversized (64 KiB) response is InvalidResponse.
  */
object GmailOperations:
  def all(
      credentials: GmailCredentials,
      endpoints: GoogleEndpoints,
      http: HttpClient,
      requestTimeout: Duration = Duration.ofSeconds(15)
  ): Vector[RegisteredOperation[?, ?, ?]] =
    Vector(RegisteredOperation(GmailMessagesSendOperation, GmailSendClient(endpoints, http, requestTimeout), credentials))

/** The validated arguments of a send: exactly what the message carries. Each address list is already deduplicated and
  * sorted; `subject` is trimmed and free of control characters. */
final case class GmailSendInput(
    mailbox: ExternalId,
    to: Vector[EmailAddress],
    cc: Vector[EmailAddress],
    bcc: Vector[EmailAddress],
    subject: String,
    body: String
):
  /** The distinct union of To, Cc, and Bcc. */
  def recipients: Set[EmailAddress] = (to ++ cc ++ bcc).toSet

object GmailMessagesSendOperation extends OperationDescriptor[GmailSendInput, Google.Mailbox]:
  private val PerList = 50
  private val TotalRecipients = 100
  private val SubjectMaximum = 200
  private val BodyMaximum = 100000
  private val MailboxPattern = "[A-Za-z0-9._-]{1,255}".r

  val id: OperationId = OperationId.parse("gmail.messages.send@1").getOrElse(throw IllegalStateException("static operation is invalid"))
  val tool: ExternalToolId = ExternalToolId.parse("gmail_messages_send").getOrElse(throw IllegalStateException("static tool is invalid"))
  val capability: CapabilityKey = CapabilityKey.parse("Google.Mail.Send").getOrElse(throw IllegalStateException("static capability is invalid"))
  val description: String =
    "Send one plain-text email from the user's selected Gmail mailbox. This is irreversible and is never retried. " +
      "Give 1 to 50 `to` addresses and optionally `cc` and `bcc` (at most 50 each, 100 distinct recipients in all), " +
      "plain addresses only (no display names), a subject (1 to 200 characters), and a body (up to 100,000 characters)."
  val action: Action = Action.Write
  val target: ResourceKind[Google.Mailbox] = Google.mailbox
  val audience: ExecutorAudience = GoogleExecutorAudience.gmail

  private def text(value: String): Json = Json.fromString(value)
  private def addresses(description: String, minimum: Int): Json = Json.obj(
    "type" -> text("array"),
    "items" -> Json.obj("type" -> text("string")),
    "minItems" -> Json.fromInt(minimum),
    "maxItems" -> Json.fromInt(PerList),
    "description" -> text(description)
  )
  val inputSchema: Json = Json.obj(
    "type" -> text("object"),
    "properties" -> Json.obj(
      "mailbox" -> Json.obj("type" -> text("string"), "description" -> text("The selected Gmail mailbox ID")),
      "to" -> addresses("Recipient addresses (1 to 50)", 1),
      "cc" -> addresses("Cc addresses", 0),
      "bcc" -> addresses("Bcc addresses", 0),
      "subject" -> Json.obj("type" -> text("string"), "minLength" -> Json.fromInt(1), "maxLength" -> Json.fromInt(SubjectMaximum)),
      "body" -> Json.obj("type" -> text("string"), "minLength" -> Json.fromInt(1), "maxLength" -> Json.fromInt(BodyMaximum))
    ),
    "required" -> Json.arr(Vector("mailbox", "to", "subject", "body").map(text)*),
    "additionalProperties" -> Json.False
  )
  override def targetArgument: Option[String] = Some("mailbox")

  private def list(fields: JsonObject, name: String, required: Boolean): Either[ArgumentError, Vector[EmailAddress]] =
    fields(name) match
      case None | Some(Json.Null) if !required => Right(Vector.empty)
      case None                                => Left(ArgumentError.MissingField(name))
      case Some(value)                         =>
        val invalid = ArgumentError.InvalidField(name)
        value.asArray.toRight(invalid).flatMap: items =>
          if items.length > PerList || (required && items.isEmpty) then Left(invalid)
          else
            val parsed = items.map(item => item.asString.flatMap(EmailAddress.parse))
            if parsed.exists(_.isEmpty) then Left(invalid)
            else Right(parsed.flatten.distinct.sortBy(_.value))

  private def textField(fields: JsonObject, name: String): Either[ArgumentError, String] =
    fields(name) match
      case None        => Left(ArgumentError.MissingField(name))
      case Some(value) => value.asString.toRight(ArgumentError.InvalidField(name))

  /** Strict: exactly `mailbox`, `to`, `subject`, `body` (required) and `cc`, `bcc` (optional). */
  def decode(arguments: Json): Either[ArgumentError, GmailSendInput] =
    arguments.asObject.toRight(ArgumentError.NotAnObject).flatMap: fields =>
      if !fields.keys.forall(Set("mailbox", "to", "cc", "bcc", "subject", "body").contains) then Left(ArgumentError.UnexpectedField)
      else
        for
          mailboxText <- textField(fields, "mailbox")
          mailbox <- Option
            .when(MailboxPattern.matches(mailboxText))(mailboxText)
            .flatMap(ExternalId.parse)
            .toRight(ArgumentError.InvalidField("mailbox"))
          to <- list(fields, "to", required = true)
          cc <- list(fields, "cc", required = false)
          bcc <- list(fields, "bcc", required = false)
          _ <- Either.cond((to ++ cc ++ bcc).distinct.length <= TotalRecipients, (), ArgumentError.InvalidField("to"))
          subjectText <- textField(fields, "subject")
          subject = subjectText.trim
          _ <- Either.cond(
            subject.nonEmpty && subject.codePointCount(0, subject.length) <= SubjectMaximum && !subject.exists(Character.isISOControl),
            (),
            ArgumentError.InvalidField("subject")
          )
          body <- textField(fields, "body")
          _ <- Either.cond(
            body.nonEmpty && body.codePointCount(0, body.length) <= BodyMaximum &&
              body.forall(c => !Character.isISOControl(c) || c == '\n' || c == '\r' || c == '\t'),
            (),
            ArgumentError.InvalidField("body")
          )
        yield GmailSendInput(mailbox, to, cc, bcc, subject, body)

  def locate(input: GmailSendInput): ResourceLocator[Google.Mailbox] =
    ResourceLocator.Selected(ExternalRef[Google.Mailbox](input.mailbox))

  def facts(input: GmailSendInput): AuthorizationContext =
    AuthorizationContext.withFacts(Map.empty, Map(Google.RecipientsFact -> input.recipients.map(a => ContextValue(a.value))))

  def canonical(input: GmailSendInput): Json =
    def strings(values: Vector[EmailAddress]) = Json.arr(values.map(a => Json.fromString(a.value))*)
    Json.obj(
      "mailbox" -> Json.fromString(input.mailbox.value),
      "to" -> strings(input.to),
      "cc" -> strings(input.cc),
      "bcc" -> strings(input.bcc),
      "subject" -> Json.fromString(input.subject),
      "body" -> Json.fromString(input.body)
    )

/** Builds the RFC 5322 message from typed values only: addresses are `EmailAddress`, the subject has no control
  * characters, and the body is base64, so no argument text can introduce a header. */
private[google] object GmailMimeMessage:
  private val Crlf = "\r\n"

  private def addressHeader(name: String, values: Vector[EmailAddress]): Option[String] =
    Option.when(values.nonEmpty)(name + ": " + values.map(_.value).mkString("," + Crlf + " "))

  /** Plain ASCII is sent as is (unless it could be mistaken for an encoded word); anything else is RFC 2047 `B`
    * encoded-words of at most 45 UTF-8 bytes each, folded onto continuation lines. */
  def subjectHeader(subject: String): String =
    if subject.forall(c => c < 0x80) && !subject.contains("=?") then "Subject: " + subject
    else
      val words = scala.collection.mutable.ArrayBuffer.empty[String]
      val chunk = new java.lang.StringBuilder
      var size = 0
      def flush(): Unit =
        if chunk.length > 0 then
          val encoded = java.util.Base64.getEncoder.encodeToString(chunk.toString.getBytes(StandardCharsets.UTF_8))
          words += "=?UTF-8?B?" + encoded + "?="
          chunk.setLength(0)
          size = 0
      subject.codePoints().forEach: cp =>
        val width = new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8).length
        if size + width > 45 then flush()
        chunk.appendCodePoint(cp)
        size += width
      flush()
      "Subject: " + words.mkString(Crlf + " ")

  def build(input: GmailSendInput): Array[Byte] =
    val headers = Vector(
      addressHeader("To", input.to),
      addressHeader("Cc", input.cc),
      addressHeader("Bcc", input.bcc),
      Some(subjectHeader(input.subject)),
      Some("MIME-Version: 1.0"),
      Some("Content-Type: text/plain; charset=UTF-8"),
      Some("Content-Transfer-Encoding: base64")
    ).flatten
    val encodedBody = java.util.Base64
      .getMimeEncoder(76, Crlf.getBytes(StandardCharsets.US_ASCII))
      .encodeToString(input.body.getBytes(StandardCharsets.UTF_8))
    (headers.mkString(Crlf) + Crlf + Crlf + encodedBody + Crlf).getBytes(StandardCharsets.US_ASCII)

/** Sends one message with a single request and never retries. Every transport failure after the request is issued is
  * `Timeout` (outcome unknown); a 5xx is `OutcomeUnknown`; a 3xx is `Rejected` and not followed. No failure carries
  * a body, URL, or token. */
private[google] final class GmailSendClient(endpoints: GoogleEndpoints, http: HttpClient, requestTimeout: Duration)
    extends ProviderOperationClient[GmailSendInput, Google.Mailbox, GmailAccess]:
  private val MaximumBodyBytes = 64 * 1024
  private val MessageId = "[A-Za-z0-9_-]{1,100}".r

  private def fail[A](error: ProviderError): IO[A] = IO.raiseError(ProviderExecutionException(error))

  private def classify(error: Throwable): ProviderExecutionException =
    val root = error match
      case wrapped: java.util.concurrent.CompletionException if wrapped.getCause != null => wrapped.getCause
      case other                                                                         => other
    root match
      case _: IllegalStateException if Option(root.getMessage).exists(_.contains("size limit")) =>
        ProviderExecutionException(ProviderError.InvalidResponse)
      case _: java.io.IOException | _: java.util.concurrent.TimeoutException =>
        ProviderExecutionException.withSafeCause(ProviderError.Timeout, root)
      case _ => ProviderExecutionException(ProviderError.Rejected)

  def dispatch(target: SelectedResource[Google.Mailbox], input: GmailSendInput, access: GmailAccess): IO[ToolResult] =
    if !(target.kind eq Google.mailbox) then fail(ProviderError.Rejected)
    else
      val raw = java.util.Base64.getUrlEncoder.withoutPadding.encodeToString(GmailMimeMessage.build(input))
      val request = HttpRequest
        .newBuilder(URI.create(endpoints.gmailApi.toString.stripSuffix("/") + "/gmail/v1/users/me/messages/send"))
        .timeout(requestTimeout)
        .header("Authorization", "Bearer " + access.accessToken)
        .header("Content-Type", "application/json")
        .header("Accept-Encoding", "identity")
        .header("User-Agent", "hallpass")
        .POST(HttpRequest.BodyPublishers.ofString(Json.obj("raw" -> Json.fromString(raw)).noSpaces, StandardCharsets.UTF_8))
        .build()
      BoundedHttpResponse
        .send(http, request, MaximumBodyBytes, FiniteDuration(requestTimeout.toNanos, TimeUnit.NANOSECONDS))
        .handleErrorWith(error => IO.raiseError(classify(error)))
        .flatMap: response =>
          val status = response.statusCode()
          if status == 401 || status == 403 then fail(ProviderError.AuthenticationFailed)
          else if status >= 500 then fail(ProviderError.OutcomeUnknown)
          else if status / 100 != 2 then fail(ProviderError.Rejected)
          else if status != 200 then fail(ProviderError.InvalidResponse)
          else
            parser.parse(String(response.body(), StandardCharsets.UTF_8)).toOption.flatMap(_.hcursor.get[String]("id").toOption) match
              case Some(id) if MessageId.matches(id) =>
                IO.pure(ToolResult(s"Sent message $id to ${input.recipients.size} recipient(s)"))
              case _ => fail(ProviderError.InvalidResponse)
