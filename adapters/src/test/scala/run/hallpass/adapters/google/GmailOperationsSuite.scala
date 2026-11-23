package run.hallpass.application:
  import run.hallpass.adapters.google.Google
  import run.hallpass.kernel.*

  /** Test-only access to `SelectedResource.trusted`, which is `private[application]`. */
  object GmailTestSupport:
    private val tenant = TenantId.random()

    def target[K](kind: ResourceKind[K], resourceType: ResourceType, externalId: String): SelectedResource[K] =
      val resource = Resource(ResourceId.random(), tenant, resourceType, None, externalId, None)
      SelectedResource.trusted(
        kind,
        ExternalId.parse(externalId).getOrElse(throw IllegalStateException("external id")),
        ResourceScope.fromPath(Vector(resource)).getOrElse(throw IllegalStateException("scope"))
      )

    def mailbox(externalId: String): SelectedResource[Google.Mailbox] = target(Google.mailbox, ResourceType.Channel, externalId)
    def account(externalId: String): SelectedResource[Google.Account] = target(Google.account, ResourceType.Account, externalId)

package run.hallpass.adapters.google:
  import java.net.{InetSocketAddress, URI}
  import java.net.http.HttpClient
  import java.nio.charset.StandardCharsets
  import java.time.Duration
  import java.util.concurrent.atomic.AtomicReference
  import scala.jdk.CollectionConverters.*
  import com.sun.net.httpserver.HttpServer
  import cats.effect.{IO, Resource as CatsResource}
  import cats.syntax.all.*
  import io.circe.{Json, parser}
  import munit.CatsEffectSuite
  import run.hallpass.application.*
  import run.hallpass.kernel.*

  final class GmailOperationsSuite extends CatsEffectSuite:
    private val tokenText = "ya29.supersecretgmailtoken"
    private val mailboxId = "112233445566778899"
    private val target = GmailTestSupport.mailbox(mailboxId)
    private val access = GmailAccess(tokenText)
    private val op = GmailMessagesSendOperation

    private def addr(value: String): EmailAddress = EmailAddress.parse(value).getOrElse(fail(s"address $value"))
    private def text(value: String): Json = Json.fromString(value)
    private def strings(values: String*): Json = Json.arr(values.map(text)*)

    private def args(
        to: Json = strings("a@example.com"),
        cc: Option[Json] = None,
        bcc: Option[Json] = None,
        subject: Json = text("Hello"),
        body: Json = text("Body"),
        extra: Seq[(String, Json)] = Nil
    ): Json =
      Json.obj(
        (Vector("mailbox" -> text(mailboxId), "to" -> to, "subject" -> subject, "body" -> body) ++
          cc.map("cc" -> _) ++ bcc.map("bcc" -> _) ++ extra)*
      )

    private def decoded(json: Json): GmailSendInput = op.decode(json).getOrElse(fail(s"decode failed for $json"))
    private def invalid(json: Json, field: String): Unit = assertEquals(op.decode(json), Left(ArgumentError.InvalidField(field)))

    // ---- fake server ---------------------------------------------------------------------------------------------
    private final case class Captured(method: String, path: String, headers: Map[String, String], body: String)
    private final case class Reply(status: Int, body: Array[Byte], location: Option[String] = None, delayMillis: Long = 0)
    private final class Fake(val captured: AtomicReference[Vector[Captured]], val uri: URI)

    private def ok(id: String = "18c0ffee12345"): Reply = Reply(200, s"""{"id":"$id","threadId":"t1"}""".getBytes(StandardCharsets.UTF_8))

    private def withServer(replies: Reply*): CatsResource[IO, Fake] =
      CatsResource
        .make(IO.blocking:
          val captured = new AtomicReference(Vector.empty[Captured])
          val counter = new java.util.concurrent.atomic.AtomicInteger(0)
          val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
          server.createContext(
            "/",
            exchange =>
              val headers = exchange.getRequestHeaders.asScala.map((n, v) => n.toLowerCase -> v.asScala.mkString(",")).toMap
              val body = String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)
              captured.updateAndGet(_ :+ Captured(exchange.getRequestMethod, exchange.getRequestURI.getRawPath, headers, body))
              val reply = replies(math.min(counter.getAndIncrement(), replies.length - 1))
              if reply.delayMillis > 0 then Thread.sleep(reply.delayMillis)
              reply.location.foreach(exchange.getResponseHeaders.add("Location", _))
              try
                exchange.sendResponseHeaders(reply.status, reply.body.length)
                val output = exchange.getResponseBody
                try output.write(reply.body)
                finally output.close()
              catch case _: java.io.IOException => ()
          )
          server.start()
          (captured, server))((_, server) => IO.blocking(server.stop(0)))
        .map((captured, server) => new Fake(captured, URI.create(s"http://127.0.0.1:${server.getAddress.getPort}")))

    private def client(uri: URI, timeout: Duration = Duration.ofSeconds(2)) =
      GmailSendClient(GoogleEndpoints(uri, uri, uri, uri, uri), HttpClient.newHttpClient(), timeout)

    private def providerError[A](io: IO[A]): IO[ProviderError] =
      io.attempt.map:
        case Left(error: ProviderExecutionException) =>
          assert(!String.valueOf(error.getMessage).contains(tokenText))
          assert(!String.valueOf(error.getCause).contains(tokenText))
          error.error
        case other => fail(s"expected a provider error, received $other")

    // ---- raw message parsing (independent of the builder) --------------------------------------------------------
    private final case class Parsed(headers: Vector[(String, String)], body: String, rawHeaderBlock: String):
      def all(name: String): Vector[String] = headers.filter(_._1.equalsIgnoreCase(name)).map(_._2)
      def one(name: String): String = all(name) match
        case Vector(single) => single
        case other          => fail(s"expected one $name header, found ${other.size}")

    private def rfc2047(value: String): String =
      val word = "=\\?UTF-8\\?B\\?([A-Za-z0-9+/=]+)\\?=".r
      val pieces = value.split("\r\n ").toVector
      pieces.map:
        case word(encoded) => String(java.util.Base64.getDecoder.decode(encoded), StandardCharsets.UTF_8)
        case other         => other
      .mkString

    private def parseRaw(captured: Captured): Parsed =
      val raw = parser.parse(captured.body).toOption.flatMap(_.hcursor.get[String]("raw").toOption).getOrElse(fail("no raw"))
      assert(raw.matches("[A-Za-z0-9_-]+"), "raw must be base64url")
      val message = String(java.util.Base64.getUrlDecoder.decode(raw), StandardCharsets.US_ASCII)
      val split = message.indexOf("\r\n\r\n")
      assert(split > 0)
      val block = message.substring(0, split)
      assert(!block.contains("\n") || block.split("\r\n").forall(_.nonEmpty))
      // unfold: a line starting with a space continues the previous header
      val lines = block.split("\r\n").toVector
      assert(lines.forall(l => !l.contains('\r') && !l.contains('\n')))
      val folded = lines.foldLeft(Vector.empty[String]): (acc, line) =>
        if line.startsWith(" ") then acc.init :+ (acc.last + "\r\n" + line) else acc :+ line
      val headers = folded.map: line =>
        val colon = line.indexOf(':')
        line.substring(0, colon) -> line.substring(colon + 1).stripPrefix(" ")
      val encodedBody = message.substring(split + 4)
      Parsed(headers, String(java.util.Base64.getMimeDecoder.decode(encodedBody), StandardCharsets.UTF_8), block)

    private def addrList(value: String): Vector[String] = value.split("," + "\r\n ").toVector.map(_.trim)

    private def sendOnce(input: GmailSendInput): IO[(ToolResult, Captured)] =
      withServer(ok()).use: fake =>
        client(fake.uri).dispatch(target, input, access).map(r => (r, fake.captured.get.head))

    // ---- decoding ------------------------------------------------------------------------------------------------
    test("decode accepts the minimal send and normalizes, sorts, and dedupes each list") {
      val input = decoded(args(to = strings("b@Example.com", " a@example.com ", "B@EXAMPLE.COM"), cc = Some(strings("z@x.io", "c@x.io"))))
      assertEquals(input.to.map(_.value), Vector("a@example.com", "b@example.com"))
      assertEquals(input.cc.map(_.value), Vector("c@x.io", "z@x.io"))
      assertEquals(input.bcc, Vector.empty)
      assertEquals(input.mailbox.value, mailboxId)
    }

    test("decode accepts null cc and bcc as empty") {
      val input = decoded(args(cc = Some(Json.Null), bcc = Some(Json.Null)))
      assertEquals((input.cc, input.bcc), (Vector.empty, Vector.empty))
    }

    test("decode refuses display names, comments, groups, control characters, and non-strings in any list") {
      val bad = Seq(
        "Alex <a@example.com>", "\"Alex\" <a@example.com>", "a@example.com (Alex)", "<a@example.com>", "a@example.com, b@example.com",
        "a@example.com\r\nBcc: evil@example.com", "a@example.com\nX: y", "a@exa mple.com", "a@", "@example.com", "a", "", "a@example", "a@é.com",
      )
      bad.foreach: value =>
        invalid(args(to = strings(value)), "to")
        invalid(args(cc = Some(strings(value))), "cc")
        invalid(args(bcc = Some(strings(value))), "bcc")
      invalid(args(to = Json.arr(Json.fromInt(1))), "to")
      invalid(args(to = text("a@example.com")), "to")
      invalid(args(cc = Some(text("a@example.com"))), "cc")
    }

    test("edge whitespace and control characters are stripped by EmailAddress.parse, so only the clean address can be sent") {
      assertEquals(decoded(args(to = strings("a@example.com\u0000", "\r\nA@example.com\n"))).to.map(_.value), Vector("a@example.com"))
    }

    test("decode requires a non-empty to and enforces 0/50/51 per list") {
      def n(count: Int, prefix: String): Json = strings((1 to count).map(i => s"$prefix$i@example.com")*)
      assertEquals(op.decode(args(to = strings())), Left(ArgumentError.InvalidField("to")))
      assertEquals(op.decode(Json.obj("mailbox" -> text(mailboxId), "subject" -> text("s"), "body" -> text("b"))), Left(ArgumentError.MissingField("to")))
      assert(op.decode(args(to = n(50, "t"))).isRight)
      invalid(args(to = n(51, "t")), "to")
      assert(op.decode(args(cc = Some(n(50, "c")), bcc = Some(strings()))).isRight)
      invalid(args(cc = Some(n(51, "c"))), "cc")
      invalid(args(bcc = Some(n(51, "b"))), "bcc")
      // 51 identical addresses is still 51 entries
      invalid(args(to = strings(Seq.fill(51)("same@example.com")*)), "to")
    }

    test("decode enforces 100 and 101 distinct recipients in total, duplicates across lists counted once") {
      def n(from: Int, to: Int, prefix: String) = strings((from to to).map(i => s"$prefix$i@example.com")*)
      assert(op.decode(args(to = n(1, 50, "t"), cc = Some(n(1, 50, "c")))).isRight)
      invalid(args(to = n(1, 50, "t"), cc = Some(n(1, 50, "c")), bcc = Some(n(1, 1, "b"))), "to")
      // overlap does not count twice: 50 + 50 distinct + 50 repeats of the to list
      assert(op.decode(args(to = n(1, 50, "t"), cc = Some(n(1, 50, "c")), bcc = Some(n(1, 50, "t")))).isRight)
      val d = decoded(args(to = strings("a@example.com"), cc = Some(strings("a@example.com")), bcc = Some(strings("A@example.com"))))
      assertEquals(d.recipients, Set(addr("a@example.com")))
    }

    test("decode refuses unknown fields, bad shapes, and a bad mailbox") {
      assertEquals(op.decode(text("x")), Left(ArgumentError.NotAnObject))
      assertEquals(op.decode(args(extra = Seq("reply_to" -> text("a@example.com")))), Left(ArgumentError.UnexpectedField))
      assertEquals(op.decode(args(extra = Seq("headers" -> Json.obj()))), Left(ArgumentError.UnexpectedField))
      assertEquals(op.decode(Json.obj("to" -> strings("a@example.com"), "subject" -> text("s"), "body" -> text("b"))), Left(ArgumentError.MissingField("mailbox")))
      Seq("../me", "a b", "", "x/y", "a" * 256).foreach: bad =>
        assertEquals(
          op.decode(Json.obj("mailbox" -> text(bad), "to" -> strings("a@example.com"), "subject" -> text("s"), "body" -> text("b"))),
          Left(ArgumentError.InvalidField("mailbox"))
        )
    }

    test("decode refuses a subject with CR, LF, or any other control character, or an empty or oversized one") {
      Seq("a\rb", "a\nb", "a\r\nBcc: x@example.com", "a\tb", "a\u0000b", "a\u001bb", "a\u007fb", "a\u0085b", "\u009f").foreach: subject =>
        invalid(args(subject = text(subject)), "subject")
      invalid(args(subject = text("")), "subject")
      invalid(args(subject = text("   ")), "subject")
      invalid(args(subject = Json.fromInt(1)), "subject")
      assert(op.decode(args(subject = text("s" * 200))).isRight)
      invalid(args(subject = text("s" * 201)), "subject")
      assertEquals(decoded(args(subject = text("  padded  "))).subject, "padded")
    }

    test("decode accepts CR, LF, and TAB in the body and refuses other control characters and bad sizes") {
      assertEquals(decoded(args(body = text("a\r\nb\tc\n"))).body, "a\r\nb\tc\n")
      Seq("a\u0000b", "a\u001bb", "a\u007fb", "a\u0085b", "a\u0008b").foreach: body =>
        invalid(args(body = text(body)), "body")
      invalid(args(body = text("")), "body")
      invalid(args(body = Json.Null), "body")
      assert(op.decode(args(body = text("b" * 100000))).isRight)
      invalid(args(body = text("b" * 100001)), "body")
    }

    test("descriptor carries the contract table, target argument, and locator") {
      assertEquals(op.id.value, "gmail.messages.send@1")
      assertEquals(op.tool.value, "gmail_messages_send")
      assertEquals(op.capability.value, "Google.Mail.Send")
      assertEquals(op.action, run.hallpass.kernel.Action.Write)
      assertEquals(op.audience, GoogleExecutorAudience.gmail)
      assertEquals(op.targetArgument, Some("mailbox"))
      assert(op.target eq Google.mailbox)
      op.locate(decoded(args())) match
        case ResourceLocator.Selected(ref) => assertEquals(ref.id.value, mailboxId)
        case other                         => fail(s"unexpected locator $other")
    }

    // ---- facts and canonical -------------------------------------------------------------------------------------
    test("facts are exactly the distinct recipient union") {
      val input = decoded(args(to = strings("A@x.io", "b@x.io"), cc = Some(strings("b@x.io", "c@x.io")), bcc = Some(strings("d@x.io", "a@x.io"))))
      val facts = op.facts(input)
      assertEquals(facts.values, Map.empty[ContextKey, ContextValue])
      assertEquals(facts.facts.keySet, Set(Google.RecipientsFact))
      assertEquals(facts.facts(Google.RecipientsFact).map(_.value), Set("a@x.io", "b@x.io", "c@x.io", "d@x.io"))
      assert(facts.complete)
    }

    test("canonical is sorted, deduplicated, and differs with any field") {
      val input = decoded(args(to = strings("b@x.io", "a@x.io", "b@x.io"), cc = Some(strings("c@x.io")), subject = text("Hi"), body = text("Yo")))
      assertEquals(
        op.canonical(input),
        Json.obj(
          "mailbox" -> text(mailboxId),
          "to" -> strings("a@x.io", "b@x.io"),
          "cc" -> strings("c@x.io"),
          "bcc" -> strings(),
          "subject" -> text("Hi"),
          "body" -> text("Yo")
        )
      )
      assertEquals(op.canonical(input), op.canonical(decoded(args(to = strings("a@x.io", "b@x.io"), cc = Some(strings("C@x.io")), subject = text("Hi"), body = text("Yo")))))
      // moving a recipient between lists changes the canonical form
      assertNotEquals(
        op.canonical(decoded(args(to = strings("a@x.io"), cc = Some(strings("b@x.io"))))),
        op.canonical(decoded(args(to = strings("a@x.io"), bcc = Some(strings("b@x.io")))))
      )
      assertNotEquals(op.canonical(decoded(args(body = text("a")))), op.canonical(decoded(args(body = text("b")))))
    }

    // ---- dispatch ------------------------------------------------------------------------------------------------
    test("dispatch sends one POST to the fixed path with the token only in Authorization, and the message equals the canonical input") {
      val input = decoded(
        args(
          to = strings("B@x.io", "a@x.io"),
          cc = Some(strings("c@x.io")),
          bcc = Some(strings("d@x.io", "a@x.io")),
          subject = text("Quarterly plan"),
          body = text("Line one\r\nLine two\ttabbed\n" + "long ".repeat(100))
        )
      )
      sendOnce(input).map: (result, request) =>
        assertEquals(result.content, "Sent message 18c0ffee12345 to 4 recipient(s)")
        assertEquals(request.method, "POST")
        assertEquals(request.path, "/gmail/v1/users/me/messages/send")
        assertEquals(request.headers("authorization"), "Bearer " + tokenText)
        assertEquals(request.headers("content-type"), "application/json")
        assert(!request.body.contains(tokenText))
        assertEquals(parser.parse(request.body).toOption.flatMap(_.asObject).map(_.keys.toSet), Some(Set("raw")))
        val message = parseRaw(request)
        assertEquals(message.headers.map(_._1), Vector("To", "Cc", "Bcc", "Subject", "MIME-Version", "Content-Type", "Content-Transfer-Encoding"))
        assertEquals(addrList(message.one("To")), input.to.map(_.value))
        assertEquals(addrList(message.one("Cc")), input.cc.map(_.value))
        assertEquals(addrList(message.one("Bcc")), input.bcc.map(_.value))
        assertEquals(message.one("Subject"), "Quarterly plan")
        assertEquals(message.one("MIME-Version"), "1.0")
        assertEquals(message.one("Content-Type"), "text/plain; charset=UTF-8")
        assertEquals(message.one("Content-Transfer-Encoding"), "base64")
        assertEquals(message.body, input.body)
        assert(!message.rawHeaderBlock.contains(tokenText))
    }

    test("Cc and Bcc headers are omitted when empty, and Bcc goes before the MIME headers when present") {
      sendOnce(decoded(args())).map: (_, request) =>
        val message = parseRaw(request)
        assertEquals(message.headers.map(_._1), Vector("To", "Subject", "MIME-Version", "Content-Type", "Content-Transfer-Encoding"))
      >> sendOnce(decoded(args(bcc = Some(strings("hidden@x.io"))))).map: (_, request) =>
        val names = parseRaw(request).headers.map(_._1)
        assert(names.indexOf("Bcc") >= 0 && names.indexOf("Bcc") < names.indexOf("MIME-Version"), names.toString)
    }

    test("a non-ASCII subject is sent as RFC 2047 encoded words and decodes to the canonical subject") {
      val subject = "Café ☃ 日本語 " + "😀".repeat(30) + " end"
      sendOnce(decoded(args(subject = text(subject)))).map: (_, request) =>
        val message = parseRaw(request)
        val header = message.one("Subject")
        assert(header.contains("=?UTF-8?B?"))
        assert(header.forall(c => c < 0x80))
        header.split("\r\n").foreach(line => assert(line.length + (if line eq header.split("\r\n").head then 9 else 0) <= 78, line))
        assertEquals(rfc2047(header), subject)
    }

    test("an ASCII subject that looks like an encoded word is encoded, and a plain one is not") {
      sendOnce(decoded(args(subject = text("=?UTF-8?B?aGk=?=")))).map: (_, request) =>
        assertEquals(rfc2047(parseRaw(request).one("Subject")), "=?UTF-8?B?aGk=?=")
        assert(parseRaw(request).one("Subject").startsWith("=?UTF-8?B?"))
    }

    test("a body that looks like headers cannot add a header") {
      val body = "x\r\nBcc: evil@example.com\r\n\r\nTo: evil@example.com"
      sendOnce(decoded(args(body = text(body)))).map: (_, request) =>
        val message = parseRaw(request)
        assertEquals(message.body, body)
        assertEquals(message.all("Bcc"), Vector.empty)
        assertEquals(addrList(message.one("To")), Vector("a@example.com"))
    }

    test("a 50-address list is folded so that no header line exceeds 998 characters") {
      val many = (1 to 50).map(i => s"${"x" * 60}$i@${"d" * 50}.example.com")
      sendOnce(decoded(args(to = strings(many*)))).map: (_, request) =>
        val message = parseRaw(request)
        message.rawHeaderBlock.split("\r\n").foreach(line => assert(line.length <= 998))
        assertEquals(addrList(message.one("To")).toSet, many.toSet)
    }

    test("an id with unexpected characters, a missing id, malformed JSON, a non-200 2xx, or an oversized body is InvalidResponse") {
      def run(reply: Reply) = withServer(reply).use(fake => providerError(client(fake.uri).dispatch(target, decoded(args()), access)))
      for
        a <- run(Reply(200, """{"id":"abc def\nx"}""".getBytes(StandardCharsets.UTF_8)))
        b <- run(Reply(200, """{"threadId":"t"}""".getBytes(StandardCharsets.UTF_8)))
        c <- run(Reply(200, "not json".getBytes(StandardCharsets.UTF_8)))
        d <- run(Reply(204, Array.emptyByteArray))
        e <- run(Reply(200, ("{\"id\":\"" + "a" * 70000 + "\"}").getBytes(StandardCharsets.UTF_8)))
      yield assertEquals(Vector(a, b, c, d, e), Vector.fill(5)(ProviderError.InvalidResponse))
    }

    test("status codes map to provider errors and nothing is retried") {
      val cases = Vector(
        401 -> ProviderError.AuthenticationFailed,
        403 -> ProviderError.AuthenticationFailed,
        400 -> ProviderError.Rejected,
        429 -> ProviderError.Rejected,
        500 -> ProviderError.OutcomeUnknown,
        502 -> ProviderError.OutcomeUnknown,
        503 -> ProviderError.OutcomeUnknown,
        504 -> ProviderError.OutcomeUnknown
      )
      cases.traverse_ { case (status, expected) =>
        withServer(Reply(status, s"""{"error":"$tokenText"}""".getBytes(StandardCharsets.UTF_8))).use: fake =>
          providerError(client(fake.uri).dispatch(target, decoded(args()), access)).map: error =>
            assertEquals(error, expected, s"status $status")
            assertEquals(fake.captured.get.size, 1, s"status $status")
      }
    }

    test("a 3xx is Rejected, is not followed, and sends exactly once") {
      Vector(301, 302, 303, 307, 308).traverse_ { status =>
        withServer(Reply(status, Array.emptyByteArray, location = Some("/elsewhere")), ok()).use: fake =>
          providerError(client(fake.uri).dispatch(target, decoded(args()), access)).map: error =>
            assertEquals(error, ProviderError.Rejected, s"status $status")
            assertEquals(fake.captured.get.map(_.path), Vector("/gmail/v1/users/me/messages/send"))
      }
    }

    test("a timeout is Timeout and the message was sent exactly once") {
      withServer(Reply(200, """{"id":"abc"}""".getBytes(StandardCharsets.UTF_8), delayMillis = 1500)).use: fake =>
        providerError(client(fake.uri, Duration.ofMillis(300)).dispatch(target, decoded(args()), access)).flatMap: error =>
          IO.sleep(scala.concurrent.duration.DurationInt(2).seconds).map: _ =>
            assertEquals(error, ProviderError.Timeout)
            assertEquals(fake.captured.get.size, 1)
    }

    test("a connection that is closed without a response is Timeout (unknown outcome), never retried") {
      CatsResource
        .make(IO.blocking:
          val count = new java.util.concurrent.atomic.AtomicInteger(0)
          val socket = new java.net.ServerSocket(0, 5, java.net.InetAddress.getLoopbackAddress)
          val thread = new Thread(() =>
            try
              while true do
                val connection = socket.accept()
                count.incrementAndGet()
                connection.getInputStream.read()
                connection.close()
            catch case _: java.io.IOException => ()
          )
          thread.setDaemon(true)
          thread.start()
          (socket, count))((socket, _) => IO.blocking(socket.close()))
        .use: (socket, count) =>
          val uri = URI.create(s"http://127.0.0.1:${socket.getLocalPort}")
          providerError(client(uri).dispatch(target, decoded(args()), access)).map: error =>
            assertEquals(error, ProviderError.Timeout)
            assertEquals(count.get, 1)
    }

    test("a target of another kind is refused before any request") {
      withServer(ok()).use: fake =>
        val wrong = GmailTestSupport.account(mailboxId).asInstanceOf[SelectedResource[Google.Mailbox]]
        providerError(client(fake.uri).dispatch(wrong, decoded(args()), access)).map: error =>
          assertEquals(error, ProviderError.Rejected)
          assertEquals(fake.captured.get, Vector.empty)
    }

    test("the request path never depends on the target or arguments") {
      val other = GmailTestSupport.mailbox("998877")
      withServer(ok()).use: fake =>
        client(fake.uri).dispatch(other, decoded(args()), access).map: _ =>
          assertEquals(fake.captured.get.map(_.path), Vector("/gmail/v1/users/me/messages/send"))
    }

    test("the token never appears in a result, a failure, or toString") {
      assert(!access.toString.contains(tokenText))
      sendOnce(decoded(args())).map: (result, _) =>
        assert(!result.content.contains(tokenText))
    }

    // ---- registry ------------------------------------------------------------------------------------------------
    test("all() registers the send operation in a registry") {
      val oauth = new CredentialStrategy[Google.Mailbox, OAuthTokens]:
        def credentialFor(lease: RedeemedExecutionLease, t: SelectedResource[Google.Mailbox]) =
          IO.pure(Left(ConnectionError.InvalidState))
      val operations = GmailOperations.all(GmailCredentials(oauth), GoogleEndpoints.Production, HttpClient.newHttpClient())
      assertEquals(operations.map(_.descriptor.id.value), Vector("gmail.messages.send@1"))
      val registry = OperationRegistry.from(operations)
      assert(registry.isRight, registry.toString)
      assert(registry.toOption.get.findByTool(GmailMessagesSendOperation.tool).isDefined)
    }
