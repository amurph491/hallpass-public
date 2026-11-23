package run.hallpass.adapters.github

import java.net.http.HttpClient
import java.time.Duration
import cats.effect.IO
import io.circe.{Json, JsonObject}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** GitHub's write operations.
  *
  * | operation               | tool                  | capability            | action | permission    |
  * |-------------------------|-----------------------|-----------------------|--------|---------------|
  * | `github.issues.create@1`| `github_issues_create`| `GitHub.Issue.Create` | WRITE  | issues: write |
  *
  * `GitHub.Issue.Create` is a different capability from `GitHub.Issue.Read`, so a read grant never authorizes a
  * create. The request path is built from the token's repository full name, never from an argument. A write is sent
  * once and never retried; a timeout surfaces as `ProviderError.Timeout`, which the executor records as an unknown
  * outcome for a non-read action.
  */
object GitHubWriteOperations:
  def all(
      registration: GitHubAppRegistration,
      connections: ProviderConnectionResolver,
      app: GitHubAppApi,
      endpoints: GitHubEndpoints,
      http: HttpClient,
      requestTimeout: Duration = Duration.ofSeconds(10)
  ): Vector[RegisteredOperation[?, ?, ?]] =
    val rest = GitHubRestClient(endpoints, http, requestTimeout)
    Vector(
      RegisteredOperation(
        GitHubIssuesCreateOperation,
        GitHubIssueCreateClient(rest),
        GitHubInstallationCredentials(registration, connections, app, Set(GitHubPermission.IssuesWrite))
      )
    )

/** The validated arguments of an issue creation: exactly the values that are sent. `title` is already trimmed. */
final case class GitHubIssueCreateInput(repository: GitHubRepositoryId, title: String, body: Option[String])

private[github] object GitHubIssueArguments:
  val TitleMaximum = 256
  val BodyMaximum = 65536

  def title(fields: JsonObject): Either[ArgumentError, String] =
    fields("title") match
      case None        => Left(ArgumentError.MissingField("title"))
      case Some(value) =>
        value.asString
          .map(_.trim)
          .filter: title =>
            title.nonEmpty && title.codePointCount(0, title.length) <= TitleMaximum && !title.exists(Character.isISOControl)
          .toRight(ArgumentError.InvalidField("title"))

  /** Absent or JSON `null` is no body. Newline, carriage return, and tab are the only permitted control characters. */
  def body(fields: JsonObject): Either[ArgumentError, Option[String]] =
    fields("body") match
      case None | Some(Json.Null) => Right(None)
      case Some(value)            =>
        value.asString
          .filter: body =>
            body.codePointCount(0, body.length) <= BodyMaximum &&
              body.forall(c => !Character.isISOControl(c) || c == '\n' || c == '\r' || c == '\t')
          .map(Some(_))
          .toRight(ArgumentError.InvalidField("body"))

object GitHubIssuesCreateOperation extends OperationDescriptor[GitHubIssueCreateInput, GitHub.Repository]:
  private def text(value: String): Json = Json.fromString(value)

  val id: OperationId = OperationId.parse("github.issues.create@1").getOrElse(throw IllegalStateException("static operation is invalid"))
  val tool: ExternalToolId = ExternalToolId.parse("github_issues_create").getOrElse(throw IllegalStateException("static tool is invalid"))
  val capability: CapabilityKey = CapabilityKey.parse("GitHub.Issue.Create").getOrElse(throw IllegalStateException("static capability is invalid"))
  val description: String =
    "Create an issue in a selected GitHub repository. The title is required (1 to 256 characters); the body is optional (at most 65,536 characters)."
  val action: Action = Action.Write
  val target: ResourceKind[GitHub.Repository] = GitHub.repository
  val audience: ExecutorAudience = GitHubExecutorAudience.local
  val inputSchema: Json = GitHubArguments.schema(
    Vector(
      GitHubArguments.RepositoryField -> GitHubArguments.repositorySchema,
      "title" -> Json.obj(
        "type" -> text("string"),
        "minLength" -> Json.fromInt(1),
        "maxLength" -> Json.fromInt(GitHubIssueArguments.TitleMaximum),
        "description" -> text("Issue title")
      ),
      "body" -> Json.obj(
        "type" -> text("string"),
        "maxLength" -> Json.fromInt(GitHubIssueArguments.BodyMaximum),
        "description" -> text("Issue body (optional)")
      )
    ),
    Vector(GitHubArguments.RepositoryField, "title")
  )
  override def targetArgument: Option[String] = Some(GitHubArguments.RepositoryField)

  /** Strict: an object with `repository_id` and `title` (required) and `body` (optional); nothing else. */
  def decode(arguments: Json): Either[ArgumentError, GitHubIssueCreateInput] =
    GitHubArguments.fields(arguments, Set(GitHubArguments.RepositoryField, "title", "body")).flatMap: fields =>
      for
        repository <- GitHubArguments.repository(fields)
        title <- GitHubIssueArguments.title(fields)
        body <- GitHubIssueArguments.body(fields)
      yield GitHubIssueCreateInput(repository, title, body)

  def locate(input: GitHubIssueCreateInput): ResourceLocator[GitHub.Repository] =
    ResourceLocator.Selected(ExternalRef[GitHub.Repository](input.repository.externalId))
  def facts(input: GitHubIssueCreateInput): AuthorizationContext = AuthorizationContext.empty

  /** The exact values sent; an absent body is `null`. */
  def canonical(input: GitHubIssueCreateInput): Json = Json.obj(
    "repository_id" -> Json.fromString(input.repository.value.toString),
    "title" -> Json.fromString(input.title),
    "body" -> input.body.fold(Json.Null)(Json.fromString)
  )

/** Creates one issue with a single request, expecting 201. The path comes from the token's repository. */
private[github] final class GitHubIssueCreateClient(rest: GitHubRestClient)
    extends ProviderOperationClient[GitHubIssueCreateInput, GitHub.Repository, GitHubInstallationToken]:
  def dispatch(
      target: SelectedResource[GitHub.Repository],
      input: GitHubIssueCreateInput,
      token: GitHubInstallationToken
  ): IO[ToolResult] =
    val body = Json.obj(Vector("title" -> Json.fromString(input.title)) ++ input.body.map(b => "body" -> Json.fromString(b))*)
    rest.post(target, token, "/issues", body, expected = 201).flatMap: json =>
      val cursor = json.hcursor
      (cursor.get[Int]("number").toOption.filter(_ >= 1), cursor.get[String]("html_url").toOption.filter(_.nonEmpty)) match
        case (Some(number), Some(url)) => IO.pure(ToolResult(s"Created issue #$number: $url"))
        case _                         => IO.raiseError(ProviderExecutionException(ProviderError.InvalidResponse))
