package run.hallpass.adapters.linear

import cats.effect.IO
import io.circe.{ACursor, Json, JsonObject}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Linear's operations. Fixed contract:
  *
  * | operation               | tool                  | capability          | action |
  * |-------------------------|-----------------------|---------------------|--------|
  * | `linear.issues.list@1`  | `linear_issues_list`  | `Linear.Issue.Read`   | READ   |
  * | `linear.issues.get@1`   | `linear_issues_get`   | `Linear.Issue.Read`   | READ   |
  * | `linear.issues.create@1`| `linear_issues_create`| `Linear.Issue.Create` | WRITE  |
  *
  * Every operation targets `Linear.team` and takes `team_id` (a Linear team UUID string; `targetArgument`); `locate`
  * is `Selected(team_id)`. list: optional `limit` (1–50, default 20). get: required `issue_id` (a Linear issue UUID or
  * an identifier such as `ENG-123`); the fetched issue's team must be the authorized team, else `Rejected` and
  * nothing is returned. create: required `title` (1–256 characters after trimming, no control characters), optional
  * `description` (Markdown, at most 65,536 characters); sends `issueCreate(input: {id: access.operationKey, teamId:
  * <authorized team ID from the SelectedResource>, title, description})`.
  */
object LinearOperations:
  def all(credentials: LinearCredentials, graphql: LinearGraphQl): Vector[RegisteredOperation[?, ?, ?]] =
    val execute: LinearExecute = graphql.execute
    Vector(
      RegisteredOperation(LinearIssuesListOperation, LinearIssuesListClient(execute), credentials),
      RegisteredOperation(LinearIssuesGetOperation, LinearIssuesGetClient(execute), credentials),
      RegisteredOperation(LinearIssuesCreateOperation, LinearIssuesCreateClient(execute), credentials)
    )

/** One GraphQL call: bearer, fixed document, variables. `LinearGraphQl.execute` in production; a stub in tests. */
private[linear] type LinearExecute = (String, LinearDocument, Json) => IO[Either[LinearApiError, Json]]

/** An issue is addressed by its UUID or its identifier (`ENG-123`). Both are untrusted until the fetched issue's team
  * is compared with the authorized team. */
enum LinearIssueRef:
  case Id(id: LinearId)
  case Identifier(value: String)

object LinearIssueRef:
  private val IdentifierPattern = "[A-Z][A-Z0-9]{0,9}-[1-9][0-9]{0,8}".r
  def parse(value: String): Option[LinearIssueRef] =
    LinearId.parse(value).map(Id(_)).orElse(Option.when(IdentifierPattern.matches(value))(Identifier(value)))
  extension (ref: LinearIssueRef)
    def wire: String = ref match
      case Id(id)         => id.value
      case Identifier(v)  => v

final case class LinearListInput(team: LinearId, limit: Int)
final case class LinearGetInput(team: LinearId, issue: LinearIssueRef)
final case class LinearCreateInput(team: LinearId, title: String, description: Option[String])

private[linear] object LinearArguments:
  val TeamField = "team_id"
  val DefaultLimit = 20
  val MaximumLimit = 50
  val TitleMaximum = 256
  val DescriptionMaximum = 65536

  private def text(value: String): Json = Json.fromString(value)

  val teamSchema: Json = Json.obj(
    "type" -> text("string"),
    "pattern" -> text("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    "description" -> text("Linear team ID (UUID)")
  )

  def schema(properties: Vector[(String, Json)], required: Vector[String]): Json = Json.obj(
    "type" -> text("object"),
    "properties" -> Json.obj(properties*),
    "required" -> Json.arr(required.map(text)*),
    "additionalProperties" -> Json.False
  )

  private def integer(value: Json): Option[Int] =
    value.asNumber.filter(_.toString.forall(_.isDigit)).flatMap(_.toInt)

  def fields(arguments: Json, allowed: Set[String]): Either[ArgumentError, JsonObject] =
    arguments.asObject.toRight(ArgumentError.NotAnObject).flatMap: obj =>
      Either.cond(obj.keys.forall(allowed.contains), obj, ArgumentError.UnexpectedField)

  def team(fields: JsonObject): Either[ArgumentError, LinearId] =
    fields(TeamField) match
      case None        => Left(ArgumentError.MissingField(TeamField))
      case Some(value) => value.asString.flatMap(LinearId.parse).toRight(ArgumentError.InvalidField(TeamField))

  def limit(fields: JsonObject): Either[ArgumentError, Int] =
    fields("limit") match
      case None        => Right(DefaultLimit)
      case Some(value) =>
        integer(value).filter(n => n >= 1 && n <= MaximumLimit).toRight(ArgumentError.InvalidField("limit"))

  def issue(fields: JsonObject): Either[ArgumentError, LinearIssueRef] =
    fields("issue_id") match
      case None        => Left(ArgumentError.MissingField("issue_id"))
      case Some(value) => value.asString.flatMap(LinearIssueRef.parse).toRight(ArgumentError.InvalidField("issue_id"))

  /** Trimmed, 1 to 256 characters, no control characters. */
  def title(fields: JsonObject): Either[ArgumentError, String] =
    fields("title") match
      case None        => Left(ArgumentError.MissingField("title"))
      case Some(value) =>
        value.asString.map(_.trim)
          .filter(t => t.nonEmpty && t.length <= TitleMaximum && !t.exists(Character.isISOControl(_)))
          .toRight(ArgumentError.InvalidField("title"))

  /** Optional; at most 65,536 characters; control characters other than newline, carriage return, and tab refused. */
  def description(fields: JsonObject): Either[ArgumentError, Option[String]] =
    fields("description") match
      case None        => Right(None)
      case Some(value) =>
        value.asString
          .filter(d =>
            d.length <= DescriptionMaximum &&
              d.forall(c => !Character.isISOControl(c) || c == '\n' || c == '\r' || c == '\t')
          )
          .map(Some(_)).toRight(ArgumentError.InvalidField("description"))

  val limitProperty: (String, Json) = "limit" -> Json.obj(
    "type" -> text("integer"),
    "minimum" -> Json.fromInt(1),
    "maximum" -> Json.fromInt(MaximumLimit),
    "default" -> Json.fromInt(DefaultLimit),
    "description" -> text("Maximum number of issues to return")
  )

private def staticId(value: String): OperationId =
  OperationId.parse(value).getOrElse(throw IllegalStateException("static operation is invalid"))
private def staticTool(value: String): ExternalToolId =
  ExternalToolId.parse(value).getOrElse(throw IllegalStateException("static tool is invalid"))
private def staticCapability(value: String): CapabilityKey =
  CapabilityKey.parse(value).getOrElse(throw IllegalStateException("static capability is invalid"))

private[linear] abstract class LinearDescriptor[In](
    operationId: String,
    toolName: String,
    capabilityKey: String,
    val action: Action,
    val description: String
) extends OperationDescriptor[In, Linear.Team]:
  val id: OperationId = staticId(operationId)
  val tool: ExternalToolId = staticTool(toolName)
  val capability: CapabilityKey = staticCapability(capabilityKey)
  val target: ResourceKind[Linear.Team] = Linear.team
  val audience: ExecutorAudience = LinearExecutorAudience.local
  override def targetArgument: Option[String] = Some(LinearArguments.TeamField)
  protected def team(input: In): LinearId
  def locate(input: In): ResourceLocator[Linear.Team] =
    ResourceLocator.Selected(ExternalRef[Linear.Team](team(input).externalId))
  def facts(input: In): AuthorizationContext = AuthorizationContext.empty

object LinearIssuesListOperation
    extends LinearDescriptor[LinearListInput](
      "linear.issues.list@1",
      "linear_issues_list",
      "Linear.Issue.Read",
      Action.Read,
      "List recent issues in a selected Linear team: identifier, state, title, assignee, update time, and URL."
    ):
  val inputSchema: Json = LinearArguments.schema(
    Vector(LinearArguments.TeamField -> LinearArguments.teamSchema, LinearArguments.limitProperty),
    Vector(LinearArguments.TeamField)
  )
  protected def team(input: LinearListInput): LinearId = input.team
  def decode(arguments: Json): Either[ArgumentError, LinearListInput] =
    LinearArguments.fields(arguments, Set(LinearArguments.TeamField, "limit")).flatMap: fields =>
      for
        team <- LinearArguments.team(fields)
        limit <- LinearArguments.limit(fields)
      yield LinearListInput(team, limit)
  def canonical(input: LinearListInput): Json = Json.obj(
    "team_id" -> Json.fromString(input.team.value),
    "limit" -> Json.fromInt(input.limit)
  )

object LinearIssuesGetOperation
    extends LinearDescriptor[LinearGetInput](
      "linear.issues.get@1",
      "linear_issues_get",
      "Linear.Issue.Read",
      Action.Read,
      "Get one issue in a selected Linear team, including its description (truncated to 8,000 characters)."
    ):
  val inputSchema: Json = LinearArguments.schema(
    Vector(
      LinearArguments.TeamField -> LinearArguments.teamSchema,
      "issue_id" -> Json.obj(
        "type" -> Json.fromString("string"),
        "description" -> Json.fromString("Linear issue UUID or identifier such as ENG-123")
      )
    ),
    Vector(LinearArguments.TeamField, "issue_id")
  )
  protected def team(input: LinearGetInput): LinearId = input.team
  def decode(arguments: Json): Either[ArgumentError, LinearGetInput] =
    LinearArguments.fields(arguments, Set(LinearArguments.TeamField, "issue_id")).flatMap: fields =>
      for
        team <- LinearArguments.team(fields)
        issue <- LinearArguments.issue(fields)
      yield LinearGetInput(team, issue)
  def canonical(input: LinearGetInput): Json = Json.obj(
    "team_id" -> Json.fromString(input.team.value),
    "issue_id" -> Json.fromString(input.issue.wire)
  )

object LinearIssuesCreateOperation
    extends LinearDescriptor[LinearCreateInput](
      "linear.issues.create@1",
      "linear_issues_create",
      "Linear.Issue.Create",
      Action.Write,
      "Create an issue in a selected Linear team from a title and an optional Markdown description."
    ):
  val inputSchema: Json = LinearArguments.schema(
    Vector(
      LinearArguments.TeamField -> LinearArguments.teamSchema,
      "title" -> Json.obj(
        "type" -> Json.fromString("string"),
        "minLength" -> Json.fromInt(1),
        "maxLength" -> Json.fromInt(LinearArguments.TitleMaximum),
        "description" -> Json.fromString("Issue title")
      ),
      "description" -> Json.obj(
        "type" -> Json.fromString("string"),
        "maxLength" -> Json.fromInt(LinearArguments.DescriptionMaximum),
        "description" -> Json.fromString("Issue description (Markdown)")
      )
    ),
    Vector(LinearArguments.TeamField, "title")
  )
  protected def team(input: LinearCreateInput): LinearId = input.team
  def decode(arguments: Json): Either[ArgumentError, LinearCreateInput] =
    LinearArguments.fields(arguments, Set(LinearArguments.TeamField, "title", "description")).flatMap: fields =>
      for
        team <- LinearArguments.team(fields)
        title <- LinearArguments.title(fields)
        description <- LinearArguments.description(fields)
      yield LinearCreateInput(team, title, description)
  def canonical(input: LinearCreateInput): Json = Json.obj(
    "team_id" -> Json.fromString(input.team.value),
    "title" -> Json.fromString(input.title),
    "description" -> input.description.fold(Json.Null)(Json.fromString)
  )

private[linear] object LinearDocuments:
  val list: LinearDocument = LinearDocument(
    "query($team: String!, $first: Int!) { team(id: $team) { id issues(first: $first, orderBy: updatedAt) { nodes { id identifier title url updatedAt priority state { name } assignee { name } } } } }"
  )
  val get: LinearDocument = LinearDocument(
    "query($id: String!) { issue(id: $id) { id identifier title description url createdAt updatedAt priority state { name } assignee { name } team { id } } }"
  )
  val create: LinearDocument = LinearDocument(
    "mutation($input: IssueCreateInput!) { issueCreate(input: $input) { success issue { id identifier url } } }",
    isMutation = true
  )

private[linear] object LinearClientSupport:
  def providerError(error: LinearApiError): ProviderError = error match
    case LinearApiError.Unauthorized | LinearApiError.Forbidden => ProviderError.AuthenticationFailed
    case LinearApiError.RateLimited | LinearApiError.Rejected   => ProviderError.Rejected
    case LinearApiError.Timeout                                 => ProviderError.Timeout
    case LinearApiError.InvalidResponse                         => ProviderError.InvalidResponse
    case LinearApiError.OutcomeUnknown                          => ProviderError.OutcomeUnknown

  /** Runs one document, then renders. Every failure is a credential-free `ProviderExecutionException`. */
  def run(
      execute: LinearExecute,
      access: LinearAccess,
      document: LinearDocument,
      variables: Json,
      render: Json => Either[ProviderError, String]
  ): IO[ToolResult] =
    execute(access.accessToken, document, variables).flatMap:
      case Left(error) => IO.raiseError(ProviderExecutionException(providerError(error)))
      case Right(data) =>
        render(data) match
          case Right(content) => IO.pure(ToolResult(content))
          case Left(error)    => IO.raiseError(ProviderExecutionException(error))

private[linear] final class LinearIssuesListClient(execute: LinearExecute)
    extends ProviderOperationClient[LinearListInput, Linear.Team, LinearAccess]:
  def dispatch(target: SelectedResource[Linear.Team], input: LinearListInput, access: LinearAccess): IO[ToolResult] =
    val team = target.externalId.value
    LinearClientSupport.run(
      execute,
      access,
      LinearDocuments.list,
      Json.obj("team" -> Json.fromString(team), "first" -> Json.fromInt(input.limit)),
      LinearRender.list(team)
    )

private[linear] final class LinearIssuesGetClient(execute: LinearExecute)
    extends ProviderOperationClient[LinearGetInput, Linear.Team, LinearAccess]:
  def dispatch(target: SelectedResource[Linear.Team], input: LinearGetInput, access: LinearAccess): IO[ToolResult] =
    LinearClientSupport.run(
      execute,
      access,
      LinearDocuments.get,
      Json.obj("id" -> Json.fromString(input.issue.wire)),
      LinearRender.issue(target.externalId.value)
    )

/** Sends exactly once, never retried. The issue ID is the lease-derived operation key, and a timeout is raised as
  * `ProviderError.Timeout` so the executor records an unknown outcome. */
private[linear] final class LinearIssuesCreateClient(execute: LinearExecute)
    extends ProviderOperationClient[LinearCreateInput, Linear.Team, LinearAccess]:
  def dispatch(target: SelectedResource[Linear.Team], input: LinearCreateInput, access: LinearAccess): IO[ToolResult] =
    val key = access.operationKey.toString
    val fields = Vector(
      "id" -> Json.fromString(key),
      "teamId" -> Json.fromString(target.externalId.value),
      "title" -> Json.fromString(input.title)
    ) ++ input.description.map(d => "description" -> Json.fromString(d))
    LinearClientSupport.run(
      execute,
      access,
      LinearDocuments.create,
      Json.obj("input" -> Json.obj(fields*)),
      LinearRender.created(key)
    )

/** Plain-text rendering of provider data, capped at 60,000 characters. */
private[linear] object LinearRender:
  val BodyLimit = 8000
  val ContentLimit = 60000
  private val TitleLimit = 500

  private def text(cursor: ACursor, field: String): Option[String] =
    cursor.get[Option[String]](field).toOption.flatten
  private def flat(value: String): String = value.replaceAll("\\s+", " ").trim
  private def cap(value: String, limit: Int): String =
    if value.length <= limit then value else value.take(limit) + "...[truncated]"
  private def capped(value: String): String =
    if value.length <= ContentLimit then value else value.take(ContentLimit) + "\n...[truncated]"
  private def nested(cursor: ACursor, parent: String, field: String): Option[String] =
    text(cursor.downField(parent), field)

  private def line(item: Json): Option[String] =
    val c = item.hcursor
    text(c, "identifier").map: identifier =>
      s"${flat(identifier)} [${nested(c, "state", "name").map(flat).getOrElse("unknown")}] " +
        cap(flat(text(c, "title").getOrElse("")), TitleLimit) +
        " | " + nested(c, "assignee", "name").map(flat).getOrElse("unassigned") +
        " | " + text(c, "updatedAt").map(flat).getOrElse("unknown") +
        " | " + text(c, "url").map(flat).getOrElse("")

  def list(authorizedTeam: String)(data: Json): Either[ProviderError, String] =
    val team = data.hcursor.downField("team")
    if text(team, "id").contains(authorizedTeam) then
      team.downField("issues").downField("nodes").focus.flatMap(_.asArray) match
        case None        => Left(ProviderError.InvalidResponse)
        case Some(nodes) =>
          val lines = nodes.map(line)
          if lines.exists(_.isEmpty) then Left(ProviderError.InvalidResponse)
          else Right(capped(lines.flatten.mkString("\n")))
    else Left(ProviderError.Rejected)

  /** An issue outside the authorized team (or none) is `Rejected` and nothing is rendered. */
  def issue(authorizedTeam: String)(data: Json): Either[ProviderError, String] =
    val c = data.hcursor.downField("issue")
    if c.focus.forall(_.isNull) then Left(ProviderError.Rejected)
    else if nested(c, "team", "id").contains(authorizedTeam) then
      text(c, "identifier") match
        case None             => Left(ProviderError.InvalidResponse)
        case Some(identifier) =>
          val head = Vector(
            s"identifier: ${flat(identifier)}",
            "title: " + cap(flat(text(c, "title").getOrElse("")), TitleLimit),
            "state: " + nested(c, "state", "name").map(flat).getOrElse("unknown"),
            "assignee: " + nested(c, "assignee", "name").map(flat).getOrElse("unassigned"),
            "priority: " + c.get[Option[Int]]("priority").toOption.flatten.fold("unknown")(_.toString),
            "created_at: " + text(c, "createdAt").map(flat).getOrElse("unknown"),
            "updated_at: " + text(c, "updatedAt").map(flat).getOrElse("unknown"),
            "url: " + text(c, "url").map(flat).getOrElse("")
          )
          Right(capped((head :+ "description:" :+ cap(text(c, "description").getOrElse(""), BodyLimit)).mkString("\n")))
    else if nested(c, "team", "id").isEmpty then Left(ProviderError.InvalidResponse)
    else Left(ProviderError.Rejected)

  def created(operationKey: String)(data: Json): Either[ProviderError, String] =
    val c = data.hcursor.downField("issueCreate")
    val issue = c.downField("issue")
    if c.get[Boolean]("success") == Right(true) && text(issue, "id").contains(operationKey) then
      Right(
        capped(
          s"Created issue ${text(issue, "identifier").map(flat).getOrElse("unknown")}: ${text(issue, "url").map(flat).getOrElse("")}"
        )
      )
    else Left(ProviderError.InvalidResponse)
