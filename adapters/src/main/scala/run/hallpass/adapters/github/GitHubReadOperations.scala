package run.hallpass.adapters.github

import java.net.http.HttpClient
import java.time.Duration
import cats.effect.IO
import io.circe.{ACursor, Json, JsonObject}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** GitHub's read operations: issues and pull requests in one selected repository.
  *
  * Fixed contract (the catalog provisioning and tests depend on it):
  *
  * | operation                | tool                | capability             | action | permission         |
  * |--------------------------|---------------------|------------------------|--------|--------------------|
  * | `github.issues.list@1`   | `github_issues_list`| `GitHub.Issue.Read`    | READ   | issues: read       |
  * | `github.issues.get@1`    | `github_issues_get` | `GitHub.Issue.Read`    | READ   | issues: read       |
  * | `github.pulls.list@1`    | `github_pulls_list` | `GitHub.PullRequest.Read` | READ | pull_requests: read |
  * | `github.pulls.get@1`     | `github_pulls_get`  | `GitHub.PullRequest.Read` | READ | pull_requests: read |
  *
  * Arguments: `repository_id` (required; GitHub's numeric repository ID as a decimal string) on every operation; the
  * list operations accept optional `state` (`open`, `closed`, `all`; default `open`) and `limit` (1–50, default 20);
  * the get operations require `number` (a positive integer). Every descriptor's `targetArgument` is `repository_id`
  * and `locate` is `Selected(ExternalRef[GitHub.Repository](repository_id))`.
  *
  * Results are compact plain text (see [[GitHubRender]]), capped at 60,000 characters. Provider content is data and is
  * never interpreted. The issue list drops pull requests after GitHub applies `per_page`, so it may return fewer
  * than `limit` items.
  */
object GitHubReadOperations:
  def all(
      registration: GitHubAppRegistration,
      connections: ProviderConnectionResolver,
      app: GitHubAppApi,
      endpoints: GitHubEndpoints,
      http: HttpClient,
      requestTimeout: Duration = Duration.ofSeconds(10)
  ): Vector[RegisteredOperation[?, ?, ?]] =
    val rest = GitHubRestClient(endpoints, http, requestTimeout)
    def credentials(permission: GitHubPermission) =
      GitHubInstallationCredentials(registration, connections, app, Set(permission))
    Vector(
      RegisteredOperation(
        GitHubIssuesListOperation,
        GitHubReadClient[GitHubListInput](rest, in => ("/issues", listQuery(in)), GitHubRender.issueList),
        credentials(GitHubPermission.IssuesRead)
      ),
      RegisteredOperation(
        GitHubIssuesGetOperation,
        GitHubReadClient[GitHubItemInput](rest, in => (s"/issues/${in.number}", Vector.empty), GitHubRender.issue),
        credentials(GitHubPermission.IssuesRead)
      ),
      RegisteredOperation(
        GitHubPullsListOperation,
        GitHubReadClient[GitHubListInput](rest, in => ("/pulls", listQuery(in)), GitHubRender.pullList),
        credentials(GitHubPermission.PullRequestsRead)
      ),
      RegisteredOperation(
        GitHubPullsGetOperation,
        GitHubReadClient[GitHubItemInput](rest, in => (s"/pulls/${in.number}", Vector.empty), GitHubRender.pull),
        credentials(GitHubPermission.PullRequestsRead)
      )
    )

  private def listQuery(input: GitHubListInput): Vector[(String, String)] =
    Vector("state" -> input.state.wire, "per_page" -> input.limit.toString)

enum GitHubItemState(val wire: String):
  case Open extends GitHubItemState("open")
  case Closed extends GitHubItemState("closed")
  case All extends GitHubItemState("all")

object GitHubItemState:
  def parse(value: String): Option[GitHubItemState] = GitHubItemState.values.find(_.wire == value)

final case class GitHubListInput(repository: GitHubRepositoryId, state: GitHubItemState, limit: Int)
final case class GitHubItemInput(repository: GitHubRepositoryId, number: Int)

private[github] object GitHubArguments:
  val DefaultLimit = 20
  val MaximumLimit = 50
  val RepositoryField = "repository_id"

  private def text(value: String): Json = Json.fromString(value)

  val repositorySchema: Json = Json.obj(
    "type" -> text("string"),
    "pattern" -> text("^[1-9][0-9]{0,18}$"),
    "description" -> text("GitHub repository ID")
  )

  def schema(properties: Vector[(String, Json)], required: Vector[String]): Json = Json.obj(
    "type" -> text("object"),
    "properties" -> Json.obj(properties*),
    "required" -> Json.arr(required.map(text)*),
    "additionalProperties" -> Json.False
  )

  private def integer(value: Json): Option[Int] =
    value.asNumber.filter(_.toString.forall(_.isDigit)).flatMap(_.toInt)

  /** Rejects non-objects and unknown fields. */
  def fields(arguments: Json, allowed: Set[String]): Either[ArgumentError, JsonObject] =
    arguments.asObject.toRight(ArgumentError.NotAnObject).flatMap: obj =>
      Either.cond(obj.keys.forall(allowed.contains), obj, ArgumentError.UnexpectedField)

  /** `repository_id` is a JSON string of decimal digits, never a JSON number. */
  def repository(fields: JsonObject): Either[ArgumentError, GitHubRepositoryId] =
    fields(RepositoryField) match
      case None        => Left(ArgumentError.MissingField(RepositoryField))
      case Some(value) =>
        value.asString.flatMap(GitHubRepositoryId.parse).toRight(ArgumentError.InvalidField(RepositoryField))

  def number(fields: JsonObject): Either[ArgumentError, Int] =
    fields("number") match
      case None        => Left(ArgumentError.MissingField("number"))
      case Some(value) => integer(value).filter(_ >= 1).toRight(ArgumentError.InvalidField("number"))

  def state(fields: JsonObject): Either[ArgumentError, GitHubItemState] =
    fields("state") match
      case None        => Right(GitHubItemState.Open)
      case Some(value) => value.asString.flatMap(GitHubItemState.parse).toRight(ArgumentError.InvalidField("state"))

  def limit(fields: JsonObject): Either[ArgumentError, Int] =
    fields("limit") match
      case None        => Right(DefaultLimit)
      case Some(value) =>
        integer(value).filter(n => n >= 1 && n <= MaximumLimit).toRight(ArgumentError.InvalidField("limit"))

  val listProperties: Vector[(String, Json)] = Vector(
    RepositoryField -> repositorySchema,
    "state" -> Json.obj(
      "type" -> text("string"),
      "enum" -> Json.arr(GitHubItemState.values.toVector.map(s => text(s.wire))*),
      "default" -> text("open"),
      "description" -> text("Which items to list")
    ),
    "limit" -> Json.obj(
      "type" -> text("integer"),
      "minimum" -> Json.fromInt(1),
      "maximum" -> Json.fromInt(MaximumLimit),
      "default" -> Json.fromInt(DefaultLimit),
      "description" -> text("Maximum number of items to return")
    )
  )

  def numberProperty(description: String): (String, Json) =
    "number" -> Json.obj(
      "type" -> text("integer"),
      "minimum" -> Json.fromInt(1),
      "maximum" -> Json.fromInt(Int.MaxValue),
      "description" -> text(description)
    )

private def staticId(value: String): OperationId =
  OperationId.parse(value).getOrElse(throw IllegalStateException("static operation is invalid"))
private def staticTool(value: String): ExternalToolId =
  ExternalToolId.parse(value).getOrElse(throw IllegalStateException("static tool is invalid"))
private def staticCapability(value: String): CapabilityKey =
  CapabilityKey.parse(value).getOrElse(throw IllegalStateException("static capability is invalid"))

private[github] abstract class GitHubListDescriptor(
    operationId: String,
    toolName: String,
    capabilityKey: String,
    val description: String
) extends OperationDescriptor[GitHubListInput, GitHub.Repository]:
  val id: OperationId = staticId(operationId)
  val tool: ExternalToolId = staticTool(toolName)
  val capability: CapabilityKey = staticCapability(capabilityKey)
  val action: Action = Action.Read
  val target: ResourceKind[GitHub.Repository] = GitHub.repository
  val audience: ExecutorAudience = GitHubExecutorAudience.local
  val inputSchema: Json = GitHubArguments.schema(GitHubArguments.listProperties, Vector(GitHubArguments.RepositoryField))
  override def targetArgument: Option[String] = Some(GitHubArguments.RepositoryField)

  /** Strict: an object with `repository_id` (required), `state` and `limit` (optional, defaulted); nothing else. */
  def decode(arguments: Json): Either[ArgumentError, GitHubListInput] =
    GitHubArguments.fields(arguments, Set(GitHubArguments.RepositoryField, "state", "limit")).flatMap: fields =>
      for
        repository <- GitHubArguments.repository(fields)
        state <- GitHubArguments.state(fields)
        limit <- GitHubArguments.limit(fields)
      yield GitHubListInput(repository, state, limit)

  def locate(input: GitHubListInput): ResourceLocator[GitHub.Repository] =
    ResourceLocator.Selected(ExternalRef[GitHub.Repository](input.repository.externalId))
  def facts(input: GitHubListInput): AuthorizationContext = AuthorizationContext.empty
  /** Defaults are filled in, so omitted and explicit defaults bind identically. */
  def canonical(input: GitHubListInput): Json = Json.obj(
    "repository_id" -> Json.fromString(input.repository.value.toString),
    "state" -> Json.fromString(input.state.wire),
    "limit" -> Json.fromInt(input.limit)
  )

private[github] abstract class GitHubGetDescriptor(
    operationId: String,
    toolName: String,
    capabilityKey: String,
    val description: String,
    numberDescription: String
) extends OperationDescriptor[GitHubItemInput, GitHub.Repository]:
  val id: OperationId = staticId(operationId)
  val tool: ExternalToolId = staticTool(toolName)
  val capability: CapabilityKey = staticCapability(capabilityKey)
  val action: Action = Action.Read
  val target: ResourceKind[GitHub.Repository] = GitHub.repository
  val audience: ExecutorAudience = GitHubExecutorAudience.local
  val inputSchema: Json = GitHubArguments.schema(
    Vector(GitHubArguments.RepositoryField -> GitHubArguments.repositorySchema, GitHubArguments.numberProperty(numberDescription)),
    Vector(GitHubArguments.RepositoryField, "number")
  )
  override def targetArgument: Option[String] = Some(GitHubArguments.RepositoryField)

  /** Strict: an object with exactly `repository_id` and `number` (a JSON integer, 1 to 2147483647). */
  def decode(arguments: Json): Either[ArgumentError, GitHubItemInput] =
    GitHubArguments.fields(arguments, Set(GitHubArguments.RepositoryField, "number")).flatMap: fields =>
      for
        repository <- GitHubArguments.repository(fields)
        number <- GitHubArguments.number(fields)
      yield GitHubItemInput(repository, number)

  def locate(input: GitHubItemInput): ResourceLocator[GitHub.Repository] =
    ResourceLocator.Selected(ExternalRef[GitHub.Repository](input.repository.externalId))
  def facts(input: GitHubItemInput): AuthorizationContext = AuthorizationContext.empty
  def canonical(input: GitHubItemInput): Json = Json.obj(
    "repository_id" -> Json.fromString(input.repository.value.toString),
    "number" -> Json.fromInt(input.number)
  )

object GitHubIssuesListOperation
    extends GitHubListDescriptor(
      "github.issues.list@1",
      "github_issues_list",
      "GitHub.Issue.Read",
      "List issues (not pull requests) in a selected GitHub repository: number, title, state, author, dates, labels, and URL."
    )

object GitHubIssuesGetOperation
    extends GitHubGetDescriptor(
      "github.issues.get@1",
      "github_issues_get",
      "GitHub.Issue.Read",
      "Get one issue in a selected GitHub repository, including its body (truncated to 8,000 characters).",
      "Issue number"
    )

object GitHubPullsListOperation
    extends GitHubListDescriptor(
      "github.pulls.list@1",
      "github_pulls_list",
      "GitHub.PullRequest.Read",
      "List pull requests in a selected GitHub repository: number, title, state, author, dates, labels, and URL."
    )

object GitHubPullsGetOperation
    extends GitHubGetDescriptor(
      "github.pulls.get@1",
      "github_pulls_get",
      "GitHub.PullRequest.Read",
      "Get one pull request in a selected GitHub repository, including its body (truncated to 8,000 characters), branches, draft and merged state.",
      "Pull request number"
    )

/** Sends one read request through the shared REST helper and renders the answer. `request` yields the fixed path
  * suffix and typed query for the decoded input; the repository part of the path comes only from the token. */
private[github] final class GitHubReadClient[In](
    rest: GitHubRestClient,
    request: In => (String, Vector[(String, String)]),
    render: Json => Either[ProviderError, String]
) extends ProviderOperationClient[In, GitHub.Repository, GitHubInstallationToken]:
  def dispatch(target: SelectedResource[GitHub.Repository], input: In, token: GitHubInstallationToken): IO[ToolResult] =
    val (suffix, query) = request(input)
    rest.get(target, token, suffix, query).flatMap: json =>
      render(json) match
        case Right(text) => IO.pure(ToolResult(text))
        case Left(error) => IO.raiseError(ProviderExecutionException(error))

/** Plain-text rendering. Lists: one line per item (`#number [state] title | by login | created | updated | labels |
  * url`). Gets: the same fields as `key: value` lines, then the body (at most 8,000 characters), and for pull requests
  * the head and base refs, draft, and merged. Titles and bodies are provider data, shown verbatim (whitespace in
  * titles collapsed). The whole result is capped at 60,000 characters. */
private[github] object GitHubRender:
  val BodyLimit = 8000
  val ContentLimit = 60000
  private val TitleLimit = 500
  private val LabelLimit = 20

  private def text(cursor: ACursor, field: String): Option[String] = cursor.get[Option[String]](field).toOption.flatten
  private def flat(value: String): String = value.replaceAll("\\s+", " ").trim
  private def cap(value: String, limit: Int): String =
    if value.length <= limit then value else value.take(limit) + "...[truncated]"

  private def labels(cursor: ACursor): String =
    cursor.downField("labels").focus.flatMap(_.asArray).getOrElse(Vector.empty)
      .flatMap(label => label.asString.orElse(label.hcursor.get[Option[String]]("name").toOption.flatten))
      .take(LabelLimit).map(flat).mkString(",")

  private def common(cursor: ACursor): Option[(Int, String)] =
    for
      number <- cursor.get[Int]("number").toOption
      state <- text(cursor, "state")
    yield (number, state)

  private def line(item: Json): Option[String] =
    val cursor = item.hcursor
    common(cursor).map: (number, state) =>
      Vector(
        s"#$number [$state] ${cap(flat(text(cursor, "title").getOrElse("")), TitleLimit)}",
        "by " + text(cursor.downField("user"), "login").getOrElse("unknown"),
        "created " + text(cursor, "created_at").getOrElse("unknown"),
        "updated " + text(cursor, "updated_at").getOrElse("unknown"),
        "labels " + labels(cursor),
        text(cursor, "html_url").getOrElse("")
      ).mkString(" | ")

  private def capped(value: String): String =
    if value.length <= ContentLimit then value else value.take(ContentLimit) + "\n...[truncated]"

  private def list(json: Json, keep: Json => Boolean): Either[ProviderError, String] =
    json.asArray.toRight(ProviderError.InvalidResponse).flatMap: items =>
      val lines = items.filter(keep).map(item => line(item))
      if lines.exists(_.isEmpty) then Left(ProviderError.InvalidResponse) else Right(capped(lines.flatten.mkString("\n")))

  private def isPullRequest(item: Json): Boolean = item.asObject.exists(_.contains("pull_request"))

  val issueList: Json => Either[ProviderError, String] = json => list(json, item => !isPullRequest(item))
  val pullList: Json => Either[ProviderError, String] = json => list(json, _ => true)

  private def detail(json: Json, extra: ACursor => Vector[String]): Either[ProviderError, String] =
    val cursor = json.hcursor
    common(cursor).toRight(ProviderError.InvalidResponse).map: (number, state) =>
      val head = Vector(
        s"number: $number",
        s"title: ${cap(flat(text(cursor, "title").getOrElse("")), TitleLimit)}",
        s"state: $state",
        "author: " + text(cursor.downField("user"), "login").getOrElse("unknown"),
        "created_at: " + text(cursor, "created_at").getOrElse("unknown"),
        "updated_at: " + text(cursor, "updated_at").getOrElse("unknown"),
        "labels: " + labels(cursor),
        "html_url: " + text(cursor, "html_url").getOrElse("")
      ) ++ extra(cursor)
      capped((head :+ "body:" :+ cap(text(cursor, "body").getOrElse(""), BodyLimit)).mkString("\n"))

  /** An issue endpoint answers for pull requests too; a pull request is not an issue, so it is `Rejected`. */
  val issue: Json => Either[ProviderError, String] = json =>
    if isPullRequest(json) then Left(ProviderError.Rejected) else detail(json, _ => Vector.empty)

  val pull: Json => Either[ProviderError, String] = json =>
    detail(
      json,
      cursor =>
        Vector(
          "head: " + text(cursor.downField("head"), "ref").getOrElse("unknown"),
          "base: " + text(cursor.downField("base"), "ref").getOrElse("unknown"),
          "draft: " + cursor.get[Option[Boolean]]("draft").toOption.flatten.getOrElse(false),
          "merged: " + cursor.get[Option[Boolean]]("merged").toOption.flatten.getOrElse(false)
        )
    )
