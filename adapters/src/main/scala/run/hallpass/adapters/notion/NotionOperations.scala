package run.hallpass.adapters.notion

import java.net.http.HttpClient
import java.time.Duration
import cats.effect.IO
import io.circe.{ACursor, Json, JsonObject}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Notion's operations. Fixed contract:
  *
  * | operation                       | tool                          | capability            | action |
  * |---------------------------------|-------------------------------|-----------------------|--------|
  * | `notion.pages.get@1`            | `notion_pages_get`            | `Notion.Page.Read`    | READ   |
  * | `notion.blocks.children.list@1` | `notion_blocks_children_list` | `Notion.Page.Read`    | READ   |
  * | `notion.blocks.append@1`        | `notion_blocks_append`        | `Notion.Page.Append`  | WRITE  |
  *
  * Every operation targets `Notion.page` and takes `page_id` (a Notion page UUID, hyphenated or 32-hex;
  * `targetArgument`); `locate` is `Selected(page_id)` using the normalized hyphenated form. children.list: optional
  * `start_cursor` (Notion cursor string, at most 256 printable characters) and `page_size` (1–100, default 50); it lists
  * only the selected page's direct children. append: required `paragraphs`, 1–20 strings, each 1–2,000 characters,
  * no control characters except newline; each becomes one paragraph block with plain rich text (no links, no
  * mentions). The provider request path always uses the target's external ID, never the argument string. Owner policy
  * for append is REQUIRE_APPROVAL, so the approver sees the exact paragraphs.
  */
object NotionOperations:
  def all(
      credentials: NotionCredentials,
      endpoints: NotionEndpoints,
      http: HttpClient,
      requestTimeout: Duration = Duration.ofSeconds(10)
  ): Vector[RegisteredOperation[?, ?, ?]] =
    val rest = NotionRestClient(endpoints, http, requestTimeout)
    Vector(
      RegisteredOperation(NotionPagesGetOperation, NotionPagesGetClient(rest), credentials),
      RegisteredOperation(NotionBlocksChildrenListOperation, NotionChildrenListClient(rest), credentials),
      RegisteredOperation(NotionBlocksAppendOperation, NotionAppendClient(rest), credentials)
    )

final case class NotionPageInput(page: NotionId)
final case class NotionChildrenInput(page: NotionId, startCursor: Option[String], pageSize: Int)
final case class NotionAppendInput(page: NotionId, paragraphs: Vector[String])

private[notion] object NotionArguments:
  val PageField = "page_id"
  val DefaultPageSize = 50
  val MaximumPageSize = 100
  val CursorMaximum = 256
  val ParagraphsMaximum = 20
  val ParagraphMaximum = 2000

  private def text(value: String): Json = Json.fromString(value)

  val pageSchema: Json = Json.obj(
    "type" -> text("string"),
    "pattern" -> text("^[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}$"),
    "description" -> text("Notion page ID (UUID, with or without hyphens)")
  )

  def schema(properties: Vector[(String, Json)], required: Vector[String]): Json = Json.obj(
    "type" -> text("object"),
    "properties" -> Json.obj(properties*),
    "required" -> Json.arr(required.map(text)*),
    "additionalProperties" -> Json.False
  )

  def fields(arguments: Json, allowed: Set[String]): Either[ArgumentError, JsonObject] =
    arguments.asObject.toRight(ArgumentError.NotAnObject).flatMap: obj =>
      Either.cond(obj.keys.forall(allowed.contains), obj, ArgumentError.UnexpectedField)

  /** A UUID string in either canonical form; `NotionId.parse` accepts nothing else. */
  def page(fields: JsonObject): Either[ArgumentError, NotionId] =
    fields(PageField) match
      case None        => Left(ArgumentError.MissingField(PageField))
      case Some(value) => value.asString.flatMap(NotionId.parse).toRight(ArgumentError.InvalidField(PageField))

  private def integer(value: Json): Option[Int] =
    value.asNumber.filter(_.toString.forall(_.isDigit)).flatMap(_.toInt)

  /** Absent or JSON `null` is no cursor. Otherwise 1 to 256 printable ASCII characters without spaces. */
  def cursor(fields: JsonObject): Either[ArgumentError, Option[String]] =
    fields("start_cursor") match
      case None | Some(Json.Null) => Right(None)
      case Some(value)            =>
        value.asString
          .filter(c => c.nonEmpty && c.length <= CursorMaximum && c.forall(ch => ch >= 0x21 && ch <= 0x7e))
          .map(Some(_))
          .toRight(ArgumentError.InvalidField("start_cursor"))

  def pageSize(fields: JsonObject): Either[ArgumentError, Int] =
    fields("page_size") match
      case None        => Right(DefaultPageSize)
      case Some(value) =>
        integer(value).filter(n => n >= 1 && n <= MaximumPageSize).toRight(ArgumentError.InvalidField("page_size"))

  /** Newline is the only permitted control character; every string is 1 to 2,000 characters. */
  def paragraphs(fields: JsonObject): Either[ArgumentError, Vector[String]] =
    def valid(p: String): Boolean =
      val length = p.codePointCount(0, p.length)
      length >= 1 && length <= ParagraphMaximum && p.forall(c => !Character.isISOControl(c) || c == '\n')
    fields("paragraphs") match
      case None        => Left(ArgumentError.MissingField("paragraphs"))
      case Some(value) =>
        value.asArray
          .filter(items => items.nonEmpty && items.size <= ParagraphsMaximum)
          .flatMap: items =>
            val strings = items.flatMap(_.asString)
            Option.when(strings.size == items.size)(strings)
          .filter(_.forall(valid))
          .toRight(ArgumentError.InvalidField("paragraphs"))

private def staticId(value: String): OperationId =
  OperationId.parse(value).getOrElse(throw IllegalStateException("static operation is invalid"))
private def staticTool(value: String): ExternalToolId =
  ExternalToolId.parse(value).getOrElse(throw IllegalStateException("static tool is invalid"))
private def staticCapability(value: String): CapabilityKey =
  CapabilityKey.parse(value).getOrElse(throw IllegalStateException("static capability is invalid"))

private def locatePage(page: NotionId): ResourceLocator[Notion.Page] =
  ResourceLocator.Selected(ExternalRef[Notion.Page](page.externalId))

object NotionPagesGetOperation extends OperationDescriptor[NotionPageInput, Notion.Page]:
  val id: OperationId = staticId("notion.pages.get@1")
  val tool: ExternalToolId = staticTool("notion_pages_get")
  val capability: CapabilityKey = staticCapability("Notion.Page.Read")
  val description: String =
    "Get one selected Notion page: title, URL, last edited time, archived state, and its simple property values."
  val action: Action = Action.Read
  val target: ResourceKind[Notion.Page] = Notion.page
  val audience: ExecutorAudience = NotionExecutorAudience.local
  val inputSchema: Json =
    NotionArguments.schema(Vector(NotionArguments.PageField -> NotionArguments.pageSchema), Vector(NotionArguments.PageField))
  override def targetArgument: Option[String] = Some(NotionArguments.PageField)

  def decode(arguments: Json): Either[ArgumentError, NotionPageInput] =
    NotionArguments.fields(arguments, Set(NotionArguments.PageField)).flatMap(f => NotionArguments.page(f).map(NotionPageInput(_)))
  def locate(input: NotionPageInput): ResourceLocator[Notion.Page] = locatePage(input.page)
  def facts(input: NotionPageInput): AuthorizationContext = AuthorizationContext.empty
  def canonical(input: NotionPageInput): Json = Json.obj("page_id" -> Json.fromString(input.page.value))

object NotionBlocksChildrenListOperation extends OperationDescriptor[NotionChildrenInput, Notion.Page]:
  val id: OperationId = staticId("notion.blocks.children.list@1")
  val tool: ExternalToolId = staticTool("notion_blocks_children_list")
  val capability: CapabilityKey = staticCapability("Notion.Page.Read")
  val description: String =
    "List the direct child blocks of a selected Notion page (type and plain text, one line per block). Pass start_cursor from a previous result's next_cursor to continue."
  val action: Action = Action.Read
  val target: ResourceKind[Notion.Page] = Notion.page
  val audience: ExecutorAudience = NotionExecutorAudience.local
  val inputSchema: Json = NotionArguments.schema(
    Vector(
      NotionArguments.PageField -> NotionArguments.pageSchema,
      "start_cursor" -> Json.obj(
        "type" -> Json.fromString("string"),
        "maxLength" -> Json.fromInt(NotionArguments.CursorMaximum),
        "description" -> Json.fromString("Cursor from a previous result (optional)")
      ),
      "page_size" -> Json.obj(
        "type" -> Json.fromString("integer"),
        "minimum" -> Json.fromInt(1),
        "maximum" -> Json.fromInt(NotionArguments.MaximumPageSize),
        "default" -> Json.fromInt(NotionArguments.DefaultPageSize),
        "description" -> Json.fromString("Maximum number of blocks to return")
      )
    ),
    Vector(NotionArguments.PageField)
  )
  override def targetArgument: Option[String] = Some(NotionArguments.PageField)

  def decode(arguments: Json): Either[ArgumentError, NotionChildrenInput] =
    NotionArguments.fields(arguments, Set(NotionArguments.PageField, "start_cursor", "page_size")).flatMap: f =>
      for
        page <- NotionArguments.page(f)
        cursor <- NotionArguments.cursor(f)
        size <- NotionArguments.pageSize(f)
      yield NotionChildrenInput(page, cursor, size)
  def locate(input: NotionChildrenInput): ResourceLocator[Notion.Page] = locatePage(input.page)
  def facts(input: NotionChildrenInput): AuthorizationContext = AuthorizationContext.empty
  /** Defaults are filled in, so omitted and explicit defaults bind identically. */
  def canonical(input: NotionChildrenInput): Json = Json.obj(
    "page_id" -> Json.fromString(input.page.value),
    "start_cursor" -> input.startCursor.fold(Json.Null)(Json.fromString),
    "page_size" -> Json.fromInt(input.pageSize)
  )

object NotionBlocksAppendOperation extends OperationDescriptor[NotionAppendInput, Notion.Page]:
  val id: OperationId = staticId("notion.blocks.append@1")
  val tool: ExternalToolId = staticTool("notion_blocks_append")
  val capability: CapabilityKey = staticCapability("Notion.Page.Append")
  val description: String =
    "Append plain-text paragraphs to the end of a selected Notion page (1 to 20 paragraphs of 1 to 2,000 characters). Links, mentions, and formatting are not supported."
  val action: Action = Action.Write
  val target: ResourceKind[Notion.Page] = Notion.page
  val audience: ExecutorAudience = NotionExecutorAudience.local
  val inputSchema: Json = NotionArguments.schema(
    Vector(
      NotionArguments.PageField -> NotionArguments.pageSchema,
      "paragraphs" -> Json.obj(
        "type" -> Json.fromString("array"),
        "minItems" -> Json.fromInt(1),
        "maxItems" -> Json.fromInt(NotionArguments.ParagraphsMaximum),
        "items" -> Json.obj(
          "type" -> Json.fromString("string"),
          "minLength" -> Json.fromInt(1),
          "maxLength" -> Json.fromInt(NotionArguments.ParagraphMaximum)
        ),
        "description" -> Json.fromString("Paragraph texts, appended in order")
      )
    ),
    Vector(NotionArguments.PageField, "paragraphs")
  )
  override def targetArgument: Option[String] = Some(NotionArguments.PageField)

  def decode(arguments: Json): Either[ArgumentError, NotionAppendInput] =
    NotionArguments.fields(arguments, Set(NotionArguments.PageField, "paragraphs")).flatMap: f =>
      for
        page <- NotionArguments.page(f)
        paragraphs <- NotionArguments.paragraphs(f)
      yield NotionAppendInput(page, paragraphs)
  def locate(input: NotionAppendInput): ResourceLocator[Notion.Page] = locatePage(input.page)
  def facts(input: NotionAppendInput): AuthorizationContext = AuthorizationContext.empty
  /** Exactly what is sent: the page and the ordered paragraph texts, so the approver's preview equals the dispatch. */
  def canonical(input: NotionAppendInput): Json = Json.obj(
    "page_id" -> Json.fromString(input.page.value),
    "paragraphs" -> Json.arr(input.paragraphs.map(Json.fromString)*)
  )

private def failWith(error: ProviderError): IO[ToolResult] = IO.raiseError(ProviderExecutionException(error))

/** The page response must describe the selected page; anything else is `Rejected`. */
private[notion] final class NotionPagesGetClient(rest: NotionRestClient)
    extends ProviderOperationClient[NotionPageInput, Notion.Page, NotionAccess]:
  def dispatch(target: SelectedResource[Notion.Page], input: NotionPageInput, access: NotionAccess): IO[ToolResult] =
    rest.get(target, access, "/v1/pages/" + NotionRestClient.PageMarker, Vector.empty).flatMap: json =>
      val returned = json.hcursor.get[String]("id").toOption.flatMap(NotionId.parse)
      if !NotionId.fromExternal(target.externalId).exists(returned.contains) then failWith(ProviderError.Rejected)
      else
        NotionRender.page(json) match
          case Right(text) => IO.pure(ToolResult(text))
          case Left(error) => failWith(error)

private[notion] final class NotionChildrenListClient(rest: NotionRestClient)
    extends ProviderOperationClient[NotionChildrenInput, Notion.Page, NotionAccess]:
  def dispatch(target: SelectedResource[Notion.Page], input: NotionChildrenInput, access: NotionAccess): IO[ToolResult] =
    val query = Vector("page_size" -> input.pageSize.toString) ++ input.startCursor.map("start_cursor" -> _)
    rest.get(target, access, "/v1/blocks/" + NotionRestClient.PageMarker + "/children", query).flatMap: json =>
      NotionRender.children(json) match
        case Right(text) => IO.pure(ToolResult(text))
        case Left(error) => failWith(error)

/** Appends with one PATCH, expecting 200, never retried. The body is exactly the decoded paragraphs as plain-text
  * paragraph blocks. */
private[notion] final class NotionAppendClient(rest: NotionRestClient)
    extends ProviderOperationClient[NotionAppendInput, Notion.Page, NotionAccess]:
  def dispatch(target: SelectedResource[Notion.Page], input: NotionAppendInput, access: NotionAccess): IO[ToolResult] =
    val blocks = input.paragraphs.map: p =>
      Json.obj(
        "object" -> Json.fromString("block"),
        "type" -> Json.fromString("paragraph"),
        "paragraph" -> Json.obj(
          "rich_text" -> Json.arr(
            Json.obj("type" -> Json.fromString("text"), "text" -> Json.obj("content" -> Json.fromString(p)))
          )
        )
      )
    val body = Json.obj("children" -> Json.arr(blocks*))
    rest.patch(target, access, "/v1/blocks/" + NotionRestClient.PageMarker + "/children", body, expected = 200).map: _ =>
      ToolResult(s"Appended ${input.paragraphs.size} paragraph(s) to ${NotionId.fromExternal(target.externalId).fold("")(_.value)}")

/** Plain-text rendering, capped at 60,000 characters. Provider content is data and never interpreted. */
private[notion] object NotionRender:
  val ContentLimit = 60000
  private val TitleLimit = 500
  private val LineLimit = 2000
  private val PropertyLimit = 100
  private val ValueLimit = 500

  private def flat(value: String): String = value.replaceAll("\\s+", " ").trim
  private def cap(value: String, limit: Int): String =
    if value.length <= limit then value else value.take(limit) + "...[truncated]"
  private def capped(value: String): String =
    if value.length <= ContentLimit then value else value.take(ContentLimit) + "\n...[truncated]"
  private def str(cursor: ACursor, field: String): Option[String] = cursor.get[Option[String]](field).toOption.flatten

  private def richText(json: Json): String =
    json.asArray.getOrElse(Vector.empty).map: item =>
      val c = item.hcursor
      str(c, "plain_text").orElse(str(c.downField("text"), "content")).getOrElse("")
    .mkString

  private def named(json: Json): Option[String] = str(json.hcursor, "name")

  private def scalar(kind: String, value: ACursor): Option[String] =
    val focus = value.focus
    kind match
      case "title" | "rich_text" => focus.map(richText)
      case "select"              => focus.map(j => if j.isNull then "" else named(j).getOrElse(""))
      case "multi_select"        => focus.map(_.asArray.getOrElse(Vector.empty).flatMap(named).mkString(","))
      case "number"              => focus.map(j => j.asNumber.fold("")(_.toString))
      case "checkbox"            => focus.flatMap(_.asBoolean).map(_.toString)
      case "date" =>
        focus.map: j =>
          val c = j.hcursor
          (str(c, "start"), str(c, "end")) match
            case (Some(s), Some(e)) => s"$s -> $e"
            case (Some(s), None)    => s
            case _                  => ""
      case "url" | "email" => focus.map(j => j.asString.getOrElse(""))
      case _               => None

  private def property(name: String, value: Json): String =
    val cursor = value.hcursor
    val kind = str(cursor, "type").getOrElse("unknown")
    val rendered = scalar(kind, cursor.downField(kind)).map(v => cap(flat(v), ValueLimit)).getOrElse(s"[$kind]")
    s"${cap(flat(name), TitleLimit)}: $rendered"

  def page(json: Json): Either[ProviderError, String] =
    val cursor = json.hcursor
    json.asObject.toRight(ProviderError.InvalidResponse).map: _ =>
      val properties = cursor.downField("properties").focus.flatMap(_.asObject).map(_.toVector).getOrElse(Vector.empty)
      val title = properties
        .find((_, v) => str(v.hcursor, "type").contains("title"))
        .map((_, v) => richText(v.hcursor.downField("title").focus.getOrElse(Json.Null)))
        .getOrElse("")
      val head = Vector(
        "title: " + cap(flat(title), TitleLimit),
        "url: " + str(cursor, "url").getOrElse(""),
        "last_edited_time: " + str(cursor, "last_edited_time").getOrElse("unknown"),
        "archived: " + cursor.get[Option[Boolean]]("archived").toOption.flatten.getOrElse(false),
        "properties:"
      )
      capped((head ++ properties.take(PropertyLimit).map((n, v) => "  " + property(n, v))).mkString("\n"))

  private val TextLike = Set(
    "paragraph", "heading_1", "heading_2", "heading_3", "bulleted_list_item", "numbered_list_item", "to_do", "quote",
    "callout", "toggle", "code"
  )

  private def blockLine(block: Json): Option[String] =
    val cursor = block.hcursor
    str(cursor, "type").map: kind =>
      val body = cursor.downField(kind)
      val line =
        if TextLike.contains(kind) then s"$kind: ${flat(richText(body.downField("rich_text").focus.getOrElse(Json.Null)))}"
        else if kind == "child_page" then "[child_page] " + flat(str(body, "title").getOrElse(""))
        else if kind == "child_database" then "[child_database] " + flat(str(body, "title").getOrElse(""))
        else s"[$kind]"
      cap(line, LineLimit)

  def children(json: Json): Either[ProviderError, String] =
    val cursor = json.hcursor
    cursor.downField("results").focus.flatMap(_.asArray).toRight(ProviderError.InvalidResponse).flatMap: blocks =>
      val lines = blocks.map(blockLine)
      if lines.exists(_.isEmpty) then Left(ProviderError.InvalidResponse)
      else
        val more = cursor.get[Option[Boolean]]("has_more").toOption.flatten.getOrElse(false)
        val next = if more then str(cursor, "next_cursor").map("next_cursor: " + _).toVector else Vector.empty
        Right(capped((lines.flatten ++ next).mkString("\n")))
