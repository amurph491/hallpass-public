package run.hallpass.application:
  import run.hallpass.adapters.google.Google
  import run.hallpass.kernel.*
  import run.hallpass.kernel.*

  /** Test-only access to `SelectedResource.trusted`, which is `private[application]`. */
  object GoogleDriveTestSupport:
    private val tenant = TenantId.random()

    def fileTarget(externalId: String): SelectedResource[Google.DriveFile] =
      val file = Resource(ResourceId.random(), tenant, ResourceType.Document, None, externalId, None)
      SelectedResource.trusted(
        Google.driveFile,
        ExternalId.parse(externalId).getOrElse(throw IllegalStateException("external id")),
        ResourceScope.fromPath(Vector(file)).getOrElse(throw IllegalStateException("scope"))
      )

package run.hallpass.adapters.google:
  import java.net.{InetSocketAddress, URI}
  import java.net.http.HttpClient
  import java.nio.charset.StandardCharsets
  import java.time.Duration
  import java.util.concurrent.atomic.AtomicReference
  import scala.jdk.CollectionConverters.*
  import com.sun.net.httpserver.HttpServer
  import cats.effect.{IO, Resource as CatsResource}
  import io.circe.Json
  import munit.CatsEffectSuite
  import run.hallpass.application.*
  import run.hallpass.kernel.*

  final class GoogleDriveOperationsSuite extends CatsEffectSuite:
    private val tokenText = "ya29.supersecretaccesstoken"
    private val fileIdText = "1AbCdEfGhIjKlMnOp"
    private val fileId = DriveFileId.parse(fileIdText).getOrElse(fail("id"))
    private val target = GoogleDriveTestSupport.fileTarget(fileIdText)
    private val access = GoogleAccess(tokenText)
    private val input = DriveFileInput(fileId)
    private val docMime = "application/vnd.google-apps.document"
    private val sheetMime = "application/vnd.google-apps.spreadsheet"

    private def bytes(value: String): Array[Byte] = value.getBytes(StandardCharsets.UTF_8)
    private def meta(mime: String, id: String = fileIdText): String = s"""{"id":"$id","mimeType":"$mime"}"""

    private final case class Captured(path: String, query: String, headers: Map[String, String])
    private final case class Reply(status: Int, body: Array[Byte], location: Option[String] = None, delayMillis: Long = 0)
    private final class Fake(val captured: AtomicReference[Vector[Captured]], val uri: URI)

    /** `replies` are served in request order; the last one repeats. */
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
              captured.updateAndGet(_ :+ Captured(exchange.getRequestURI.getPath, String.valueOf(exchange.getRequestURI.getQuery), headers))
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

    private def rest(uri: URI, timeout: Duration = Duration.ofSeconds(2)) =
      GoogleRestClient(GoogleEndpoints(uri, uri, uri, uri), HttpClient.newHttpClient(), timeout)

    private def get(uri: URI, timeout: Duration = Duration.ofSeconds(2)) = GoogleDriveGetClient(rest(uri, timeout))
    private def export_(uri: URI) = GoogleDriveExportClient(rest(uri))

    private def providerError[A](io: IO[A]): IO[ProviderError] =
      io.attempt.map:
        case Left(error: ProviderExecutionException) =>
          assert(!String.valueOf(error.getMessage).contains(tokenText))
          error.error
        case other => fail(s"expected a provider error, received $other")

    private val metaJson =
      """{"id":"1AbCdEfGhIjKlMnOp","name":"Plan\nQ4","mimeType":"application/pdf","modifiedTime":"2026-01-02T00:00:00Z",
        |"size":"1234","webViewLink":"https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/view","owners":[{"displayName":"Alex"},{"displayName":"Sam"}],"trashed":false}""".stripMargin

    // ---- decoding ------------------------------------------------------------------------------------------------
    private val descriptors = Vector(GoogleDriveFilesGetOperation, GoogleDriveExportTextOperation)

    test("decode accepts a well-formed file_id") {
      descriptors.foreach(d => assertEquals(d.decode(Json.obj("file_id" -> Json.fromString(fileIdText))), Right(input)))
    }

    test("decode refuses bad shapes, unknown fields, and malformed ids") {
      descriptors.foreach: d =>
        assertEquals(d.decode(Json.fromString("x")), Left(ArgumentError.NotAnObject))
        assertEquals(d.decode(Json.obj()), Left(ArgumentError.MissingField("file_id")))
        assertEquals(
          d.decode(Json.obj("file_id" -> Json.fromString(fileIdText), "extra" -> Json.True)),
          Left(ArgumentError.UnexpectedField)
        )
        assertEquals(d.decode(Json.obj("file_id" -> Json.fromInt(5))), Left(ArgumentError.InvalidField("file_id")))
        assertEquals(d.decode(Json.obj("file_id" -> Json.fromString("short"))), Left(ArgumentError.InvalidField("file_id")))
        assertEquals(d.decode(Json.obj("file_id" -> Json.fromString("../../etc/passwd00"))), Left(ArgumentError.InvalidField("file_id")))
        assertEquals(d.decode(Json.obj("file_id" -> Json.fromString(fileIdText + "?x=1"))), Left(ArgumentError.InvalidField("file_id")))
    }

    test("descriptors carry the contract table") {
      assertEquals(GoogleDriveFilesGetOperation.id.value, "drive.files.get@1")
      assertEquals(GoogleDriveExportTextOperation.id.value, "drive.files.export_text@1")
      assertEquals(GoogleDriveFilesGetOperation.tool.value, "drive_files_get")
      assertEquals(GoogleDriveExportTextOperation.tool.value, "drive_files_export_text")
      descriptors.foreach: d =>
        assertEquals(d.capability.value, "Google.DriveFile.Read")
        assertEquals(d.action, run.hallpass.kernel.Action.Read)
        assertEquals(d.audience, GoogleExecutorAudience.drive)
        assertEquals(d.targetArgument, Some("file_id"))
        assert(d.target eq Google.driveFile)
        assertEquals(d.facts(input), AuthorizationContext.empty)
        d.locate(input) match
          case ResourceLocator.Selected(ref) => assertEquals(ref.id.value, fileIdText)
          case other                         => fail(s"unexpected locator $other")
    }

    test("canonical form is {file_id} and differs per file") {
      val other = DriveFileInput(DriveFileId.parse("ZyXwVuTsRqPoNmLk").getOrElse(fail("id")))
      descriptors.foreach: d =>
        assertEquals(d.canonical(input), Json.obj("file_id" -> Json.fromString(fileIdText)))
        assertNotEquals(d.canonical(input), d.canonical(other))
    }

    // ---- get -----------------------------------------------------------------------------------------------------
    test("get builds its path from the target, sends the fixed headers, and renders the metadata") {
      withServer(Reply(200, bytes(metaJson))).use: fake =>
        get(fake.uri).dispatch(target, input, access).map: result =>
          val request = fake.captured.get.head
          assertEquals(request.path, s"/drive/v3/files/$fileIdText")
          assert(request.query.contains("fields=id,name,mimeType,modifiedTime,size,webViewLink,owners(displayName),trashed"))
          assertEquals(request.headers.get("authorization"), Some("Bearer " + tokenText))
          assertEquals(request.headers.get("accept-encoding"), Some("identity"))
          assertEquals(request.headers.get("user-agent"), Some("hallpass"))
          assertEquals(fake.captured.get.size, 1)
          val text = result.content
          assert(text.contains("name: Plan Q4"))
          assert(text.contains("mimeType: application/pdf"))
          assert(text.contains("modifiedTime: 2026-01-02T00:00:00Z"))
          assert(text.contains("size: 1234"))
          assert(text.contains("owners: Alex,Sam"))
          assert(text.contains("webViewLink: https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/view"))
          assert(text.contains("trashed: false"))
          assert(!text.contains(tokenText))
    }

    test("the request path ignores the argument string and uses the target's external ID") {
      val spoof = DriveFileInput(DriveFileId.parse("SpoofedFileId0000").getOrElse(fail("id")))
      withServer(Reply(200, bytes(metaJson))).use: fake =>
        get(fake.uri).dispatch(target, spoof, access).map: _ =>
          assertEquals(fake.captured.get.head.path, s"/drive/v3/files/$fileIdText")
    }

    test("get rejects a response whose id is not the target's") {
      withServer(Reply(200, bytes(metaJson.replace(fileIdText, "OtherFileId00000")))).use: fake =>
        providerError(get(fake.uri).dispatch(target, input, access)).map(assertEquals(_, ProviderError.InvalidResponse))
    }

    test("get rejects malformed JSON and a response without a name") {
      withServer(Reply(200, bytes("not json"))).use: fake =>
        providerError(get(fake.uri).dispatch(target, input, access)).map(assertEquals(_, ProviderError.InvalidResponse))
      >> withServer(Reply(200, bytes(meta("application/pdf")))).use: fake =>
        providerError(get(fake.uri).dispatch(target, input, access)).map(assertEquals(_, ProviderError.InvalidResponse))
    }

    // ---- export_text ---------------------------------------------------------------------------------------------
    test("a Google Doc is exported as text/plain after a metadata request") {
      withServer(Reply(200, bytes(meta(docMime))), Reply(200, bytes("hello doc"))).use: fake =>
        export_(fake.uri).dispatch(target, input, access).map: result =>
          assertEquals(result.content, "hello doc")
          val requests = fake.captured.get
          assertEquals(requests.size, 2)
          assertEquals(requests(0).path, s"/drive/v3/files/$fileIdText")
          assert(requests(0).query.startsWith("fields="))
          assertEquals(requests(1).path, s"/drive/v3/files/$fileIdText/export")
          assertEquals(requests(1).query, "mimeType=text/plain")
          requests.foreach(r => assertEquals(r.headers.get("authorization"), Some("Bearer " + tokenText)))
    }

    test("a Google Sheet is exported as text/csv") {
      withServer(Reply(200, bytes(meta(sheetMime))), Reply(200, bytes("a,b\n1,2"))).use: fake =>
        export_(fake.uri).dispatch(target, input, access).map: result =>
          assertEquals(result.content, "a,b\n1,2")
          assertEquals(fake.captured.get()(1).path, s"/drive/v3/files/$fileIdText/export")
          assertEquals(fake.captured.get()(1).query, "mimeType=text/csv")
    }

    test("a text/ file is read with alt=media") {
      withServer(Reply(200, bytes(meta("text/markdown"))), Reply(200, bytes("# hi"))).use: fake =>
        export_(fake.uri).dispatch(target, input, access).map: result =>
          assertEquals(result.content, "# hi")
          assertEquals(fake.captured.get()(1).path, s"/drive/v3/files/$fileIdText")
          assertEquals(fake.captured.get()(1).query, "alt=media")
    }

    test("PDF and image types are Rejected after only the metadata request") {
      List("application/pdf", "image/png", "application/vnd.google-apps.folder").foldLeft(IO.unit): (acc, mime) =>
        acc >> withServer(Reply(200, bytes(meta(mime))), Reply(200, bytes("SHOULD NOT BE READ"))).use: fake =>
          providerError(export_(fake.uri).dispatch(target, input, access)).map: error =>
            assertEquals(error, ProviderError.Rejected)
            assertEquals(fake.captured.get.size, 1)
    }

    test("export refuses metadata for another id and metadata without a mime type") {
      withServer(Reply(200, bytes(meta(docMime, "OtherFileId00000")))).use: fake =>
        providerError(export_(fake.uri).dispatch(target, input, access)).map: error =>
          assertEquals(error, ProviderError.InvalidResponse)
          assertEquals(fake.captured.get.size, 1)
      >> withServer(Reply(200, bytes(s"""{"id":"$fileIdText"}"""))).use: fake =>
        providerError(export_(fake.uri).dispatch(target, input, access)).map(assertEquals(_, ProviderError.InvalidResponse))
    }

    test("a body over 512 KiB is InvalidResponse") {
      val big = Array.fill(512 * 1024 + 1)('a'.toByte)
      withServer(Reply(200, bytes(meta(docMime))), Reply(200, big)).use: fake =>
        providerError(export_(fake.uri).dispatch(target, input, access)).map(assertEquals(_, ProviderError.InvalidResponse))
    }

    test("a body of exactly 512 KiB is accepted and the text is truncated to 60,000 characters") {
      val max = Array.fill(512 * 1024)('a'.toByte)
      withServer(Reply(200, bytes(meta(docMime))), Reply(200, max)).use: fake =>
        export_(fake.uri).dispatch(target, input, access).map: result =>
          assert(result.content.startsWith("a" * 60000))
          assertEquals(result.content, "a" * 60000 + "\n...[truncated]")
    }

    test("text at the limit is returned whole, and invalid UTF-8 is replaced") {
      withServer(Reply(200, bytes(meta(docMime))), Reply(200, Array.fill(60000)('b'.toByte))).use: fake =>
        export_(fake.uri).dispatch(target, input, access).map(result => assertEquals(result.content, "b" * 60000))
      >> withServer(Reply(200, bytes(meta(docMime))), Reply(200, Array[Byte]('o'.toByte, 0xff.toByte, 'k'.toByte))).use: fake =>
        export_(fake.uri).dispatch(target, input, access).map(result => assertEquals(result.content, "o�k"))
    }

    // ---- errors --------------------------------------------------------------------------------------------------
    test("statuses map to provider errors on both requests") {
      val expected = List(
        401 -> ProviderError.AuthenticationFailed,
        403 -> ProviderError.AuthenticationFailed,
        404 -> ProviderError.Rejected,
        400 -> ProviderError.Rejected,
        429 -> ProviderError.Rejected,
        500 -> ProviderError.Rejected
      )
      expected.foldLeft(IO.unit): (acc, entry) =>
        val (status, error) = entry
        acc >> withServer(Reply(status, bytes("""{"error":"detail with ya29.supersecretaccesstoken"}"""))).use: fake =>
          providerError(get(fake.uri).dispatch(target, input, access)).map(assertEquals(_, error)) >>
            providerError(export_(fake.uri).dispatch(target, input, access)).map(assertEquals(_, error))
    }

    test("content request errors map after a good metadata request") {
      withServer(Reply(200, bytes(meta(docMime))), Reply(403, Array.emptyByteArray)).use: fake =>
        providerError(export_(fake.uri).dispatch(target, input, access)).map(assertEquals(_, ProviderError.AuthenticationFailed))
    }

    test("a 3xx is not followed and is Rejected") {
      withServer(Reply(302, Array.emptyByteArray, location = Some("/elsewhere")), Reply(200, bytes(metaJson))).use: fake =>
        providerError(get(fake.uri).dispatch(target, input, access)).map: error =>
          assertEquals(error, ProviderError.Rejected)
          assertEquals(fake.captured.get.size, 1)
      >> withServer(Reply(200, bytes(meta("text/plain"))), Reply(307, Array.emptyByteArray, location = Some("/media"))).use: fake =>
        providerError(export_(fake.uri).dispatch(target, input, access)).map: error =>
          assertEquals(error, ProviderError.Rejected)
          assertEquals(fake.captured.get.size, 2)
    }

    test("a slow response is a Timeout and is not retried") {
      withServer(Reply(200, bytes(metaJson), delayMillis = 1500)).use: fake =>
        providerError(get(fake.uri, Duration.ofMillis(200)).dispatch(target, input, access)).map: error =>
          assertEquals(error, ProviderError.Timeout)
          assertEquals(fake.captured.get.size, 1)
    }

    test("an unreachable endpoint fails without leaking the token") {
      providerError(get(URI.create("http://127.0.0.1:1")).dispatch(target, input, access)).map: error =>
        assert(error == ProviderError.Timeout || error == ProviderError.Rejected)
    }

    test("the access token never appears in results or the access object's string form") {
      assert(!access.toString.contains(tokenText))
      withServer(Reply(200, bytes(metaJson))).use: fake =>
        get(fake.uri).dispatch(target, input, access).map(result => assert(!result.content.contains(tokenText)))
    }

    // ---- registry ------------------------------------------------------------------------------------------------
    test("all() registers both operations in a registry") {
      val oauth = new CredentialStrategy[Google.DriveFile, OAuthTokens]:
        def credentialFor(lease: RedeemedExecutionLease, t: SelectedResource[Google.DriveFile]) =
          IO.pure(Left(ConnectionError.InvalidState))
      val operations =
        GoogleDriveOperations.all(GoogleDriveCredentials(oauth), GoogleEndpoints.Production, HttpClient.newHttpClient())
      assertEquals(operations.map(_.descriptor.id.value).toSet, Set("drive.files.get@1", "drive.files.export_text@1"))
      val registry = OperationRegistry.from(operations)
      assert(registry.isRight, registry.toString)
      assert(registry.toOption.get.findByTool(GoogleDriveFilesGetOperation.tool).isDefined)
      assert(registry.toOption.get.findByTool(GoogleDriveExportTextOperation.tool).isDefined)
    }
