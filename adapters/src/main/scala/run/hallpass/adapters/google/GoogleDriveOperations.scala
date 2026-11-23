package run.hallpass.adapters.google

import java.net.http.HttpClient
import java.time.Duration
import cats.effect.IO
import io.circe.Json
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Drive operations. Fixed contract:
  *
  * | operation                    | tool                      | capability            | action |
  * |------------------------------|---------------------------|-----------------------|--------|
  * | `drive.files.get@1`          | `drive_files_get`         | `Google.DriveFile.Read` | READ |
  * | `drive.files.export_text@1`  | `drive_files_export_text` | `Google.DriveFile.Read` | READ |
  *
  * Both target `Google.driveFile` and take `file_id` (`targetArgument`); `locate` is `Selected(file_id)`.
  * get: metadata only — GET `{driveApi}/drive/v3/files/{id}?fields=id,name,mimeType,modifiedTime,size,webViewLink,
  * owners(displayName),trashed`; the returned id must equal the target. export_text: for Google Docs
  * (`application/vnd.google-apps.document`) GET `/drive/v3/files/{id}/export?mimeType=text/plain`; for Sheets export
  * `text/csv`; for plain-text (`text/` media type) files GET `/drive/v3/files/{id}?alt=media`; any other type is Rejected without a
  * content request. The body is read through BoundedHttpResponse with a 512 KiB cap (larger → InvalidResponse) and
  * returned as text truncated to 60,000 characters. Paths use the target's external ID only.
  *
  * Both operations take exactly `file_id` (unknown fields are refused). The text result ends with `\n...[truncated]`
  * when it was cut at 60,000 characters. Requests are sent once, never retried. This code never follows redirects: a
  * 3xx answer (Google may redirect `alt=media`) is `Rejected`; the supplied `HttpClient` must not be configured to
  * follow redirects either. A 401 or 403 is `AuthenticationFailed`; 400, 404, 429 and every other non-2xx status are
  * `Rejected`; a timeout is `Timeout`; malformed JSON, an id other than the target's, or an oversized body is
  * `InvalidResponse`.
  */
object GoogleDriveOperations:
  def all(
      credentials: GoogleDriveCredentials,
      endpoints: GoogleEndpoints,
      http: HttpClient,
      requestTimeout: Duration = Duration.ofSeconds(15)
  ): Vector[RegisteredOperation[?, ?, ?]] =
    val rest = GoogleRestClient(endpoints, http, requestTimeout)
    Vector(
      RegisteredOperation(GoogleDriveFilesGetOperation, GoogleDriveGetClient(rest), credentials),
      RegisteredOperation(GoogleDriveExportTextOperation, GoogleDriveExportClient(rest), credentials)
    )

final case class DriveFileInput(file: DriveFileId)

private def staticId(value: String): OperationId =
  OperationId.parse(value).getOrElse(throw IllegalStateException("static operation is invalid"))
private def staticTool(value: String): ExternalToolId =
  ExternalToolId.parse(value).getOrElse(throw IllegalStateException("static tool is invalid"))
private def staticCapability(value: String): CapabilityKey =
  CapabilityKey.parse(value).getOrElse(throw IllegalStateException("static capability is invalid"))

private[google] abstract class GoogleDriveDescriptor(operationId: String, toolName: String, val description: String)
    extends OperationDescriptor[DriveFileInput, Google.DriveFile]:
  private val Field = "file_id"
  val id: OperationId = staticId(operationId)
  val tool: ExternalToolId = staticTool(toolName)
  val capability: CapabilityKey = staticCapability("Google.DriveFile.Read")
  val action: Action = Action.Read
  val target: ResourceKind[Google.DriveFile] = Google.driveFile
  val audience: ExecutorAudience = GoogleExecutorAudience.drive
  val inputSchema: Json = Json.obj(
    "type" -> Json.fromString("object"),
    "properties" -> Json.obj(
      Field -> Json.obj(
        "type" -> Json.fromString("string"),
        "pattern" -> Json.fromString("^[A-Za-z0-9_-]{10,200}$"),
        "description" -> Json.fromString("Google Drive file ID")
      )
    ),
    "required" -> Json.arr(Json.fromString(Field)),
    "additionalProperties" -> Json.False
  )
  override def targetArgument: Option[String] = Some(Field)

  /** Strict: an object with exactly `file_id`, a JSON string that is a well-formed Drive file ID. */
  def decode(arguments: Json): Either[ArgumentError, DriveFileInput] =
    arguments.asObject.toRight(ArgumentError.NotAnObject).flatMap: obj =>
      if !obj.keys.forall(_ == Field) then Left(ArgumentError.UnexpectedField)
      else
        obj(Field) match
          case None        => Left(ArgumentError.MissingField(Field))
          case Some(value) =>
            value.asString.flatMap(DriveFileId.parse).map(DriveFileInput(_)).toRight(ArgumentError.InvalidField(Field))

  def locate(input: DriveFileInput): ResourceLocator[Google.DriveFile] =
    ResourceLocator.Selected(ExternalRef[Google.DriveFile](input.file.externalId))
  def facts(input: DriveFileInput): AuthorizationContext = AuthorizationContext.empty
  def canonical(input: DriveFileInput): Json = Json.obj("file_id" -> Json.fromString(input.file.value))

object GoogleDriveFilesGetOperation
    extends GoogleDriveDescriptor(
      "drive.files.get@1",
      "drive_files_get",
      "Get metadata for one Google Drive file the user selected: name, type, modified time, size, owners, link, and trashed state."
    )

object GoogleDriveExportTextOperation
    extends GoogleDriveDescriptor(
      "drive.files.export_text@1",
      "drive_files_export_text",
      "Read one selected Google Drive file as text: Google Docs as plain text, Google Sheets as CSV, and plain-text files as they are (truncated to 60,000 characters). Other file types are refused."
    )

private[google] final class GoogleDriveGetClient(rest: GoogleRestClient)
    extends ProviderOperationClient[DriveFileInput, Google.DriveFile, GoogleAccess]:
  def dispatch(target: SelectedResource[Google.DriveFile], input: DriveFileInput, access: GoogleAccess): IO[ToolResult] =
    rest.metadata(target, access, GoogleRestClient.GetFields).map(GoogleDriveRender.metadata).flatMap:
      case Right(text) => IO.pure(ToolResult(text))
      case Left(error) => IO.raiseError(ProviderExecutionException(error))

private[google] final class GoogleDriveExportClient(rest: GoogleRestClient)
    extends ProviderOperationClient[DriveFileInput, Google.DriveFile, GoogleAccess]:
  def dispatch(target: SelectedResource[Google.DriveFile], input: DriveFileInput, access: GoogleAccess): IO[ToolResult] =
    rest.metadata(target, access, "id,mimeType").flatMap: json =>
      json.hcursor.get[String]("mimeType").toOption match
        case None           => IO.raiseError(ProviderExecutionException(ProviderError.InvalidResponse))
        case Some(mimeType) =>
          GoogleDriveRender.contentPath(mimeType) match
            case None       => IO.raiseError(ProviderExecutionException(ProviderError.Rejected))
            case Some(path) =>
              rest.content(target, access, path).map(bytes => ToolResult(GoogleDriveRender.text(bytes)))

private[google] object GoogleDriveRender:
  val TextLimit = 60000
  private def flat(value: String): String = value.replaceAll("\\s+", " ").trim
  private def field(cursor: io.circe.ACursor, name: String): Option[String] =
    cursor.get[Option[String]](name).toOption.flatten

  /** The content request's path suffix, or `None` for a type that is not read as text. */
  def contentPath(mimeType: String): Option[String] = mimeType match
    case "application/vnd.google-apps.document"               => Some("/export?mimeType=text%2Fplain")
    case "application/vnd.google-apps.spreadsheet"            => Some("/export?mimeType=text%2Fcsv")
    case other if other.regionMatches(true, 0, "text/", 0, 5) => Some("?alt=media")
    case _                                                    => None

  def text(bytes: Array[Byte]): String =
    val decoded = String(bytes, java.nio.charset.StandardCharsets.UTF_8)
    if decoded.length <= TextLimit then decoded
    else
      val cut = if Character.isHighSurrogate(decoded.charAt(TextLimit - 1)) then TextLimit - 1 else TextLimit
      decoded.take(cut) + "\n...[truncated]"

  def metadata(json: Json): Either[ProviderError, String] =
    val cursor = json.hcursor
    val owners = cursor.downField("owners").focus.flatMap(_.asArray).getOrElse(Vector.empty)
      .flatMap(_.hcursor.get[Option[String]]("displayName").toOption.flatten).map(flat).mkString(",")
    field(cursor, "name") match
      case None       => Left(ProviderError.InvalidResponse)
      case Some(name) =>
        Right(
          Vector(
            "name: " + flat(name),
            "mimeType: " + field(cursor, "mimeType").getOrElse("unknown"),
            "modifiedTime: " + field(cursor, "modifiedTime").getOrElse("unknown"),
            "size: " + field(cursor, "size").getOrElse("unknown"),
            "owners: " + owners,
            "webViewLink: " + field(cursor, "webViewLink").getOrElse(""),
            "trashed: " + cursor.get[Option[Boolean]]("trashed").toOption.flatten.getOrElse(false)
          ).mkString("\n")
        )
