package run.hallpass.application

import cats.effect.IO
import io.circe.Json
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** A fictional provider used to exercise the generic operation pipeline without any real provider adapter. */
object PipelineProvider:
  val id: ProviderId = ProviderId.parse("testprov").getOrElse(throw IllegalStateException("provider id"))

  sealed trait Workspace
  sealed trait Item
  sealed trait Mailbox

  /** A workspace-custody connection root. */
  given workspace: ResourceKind[Workspace] =
    ResourceKind.root("testprov.workspace", id, ResourceType.Provider, Custody.Workspace)

  /** A kind selected beneath the workspace. */
  given item: ResourceKind[Item] = ResourceKind.child[Item, Workspace]("testprov.item", ResourceType.Repository)

  /** A personal-custody connection root, such as one person's mailbox. */
  given mailbox: ResourceKind[Mailbox] =
    ResourceKind.root("testprov.mailbox", id, ResourceType.Account, Custody.Personal)

  val audience: ExecutorAudience = ExecutorAudience.parse("hallpass.test.provider").getOrElse(throw IllegalStateException("audience"))

  def operationId(value: String): OperationId =
    OperationId.parse(value).getOrElse(throw IllegalStateException(s"operation id $value"))
  def toolId(value: String): ExternalToolId =
    ExternalToolId.parse(value).getOrElse(throw IllegalStateException(s"tool id $value"))
  def capabilityKey(value: String): CapabilityKey =
    CapabilityKey.parse(value).getOrElse(throw IllegalStateException(s"capability key $value"))
  def externalId(value: String): ExternalId =
    ExternalId.parse(value).getOrElse(throw IllegalStateException(s"external id $value"))

/** A query operation over any resource kind. The input is a [[SearchQuery]] decoded from `{"query": ...}`. */
final class PipelineOperation[K](
    val id: OperationId,
    val tool: ExternalToolId,
    val target: ResourceKind[K],
    locator: ResourceLocator[K],
    val capability: CapabilityKey = PipelineProvider.capabilityKey("Test.Message.Read"),
    val action: Action = Action.Read
) extends OperationDescriptor[SearchQuery, K]:
  val description: String = "test operation"
  val audience: ExecutorAudience = PipelineProvider.audience
  val inputSchema: Json = Json.obj("type" -> Json.fromString("object"))

  def decode(arguments: Json): Either[ArgumentError, SearchQuery] =
    arguments.asObject.toRight(ArgumentError.NotAnObject).flatMap: fields =>
      if fields.keys.exists(_ != "query") then Left(ArgumentError.UnexpectedField)
      else
        fields("query") match
          case None        => Left(ArgumentError.MissingField("query"))
          case Some(value) =>
            value.asString.flatMap(SearchQuery.parse(_).toOption).toRight(ArgumentError.InvalidField("query"))

  def locate(input: SearchQuery): ResourceLocator[K] = locator
  def facts(input: SearchQuery): AuthorizationContext = AuthorizationContext.empty
  def canonical(input: SearchQuery): Json = Json.obj("query" -> Json.fromString(input.value))

/** A client that records every dispatch and returns a fixed result; its credential type is `Unit`. */
final class PipelineClient[K](result: ToolResult = ToolResult("provider-result"))
    extends ProviderOperationClient[SearchQuery, K, Unit]:
  var dispatches = Vector.empty[(SelectedResource[K], SearchQuery)]
  def dispatch(target: SelectedResource[K], input: SearchQuery, credential: Unit): IO[ToolResult] =
    IO.delay:
      dispatches = dispatches :+ (target -> input)
      result

/** A credential strategy that records every resolution request. */
final class PipelineCredentials[K](result: Either[ConnectionError, Unit] = Right(()))
    extends CredentialStrategy[K, Unit]:
  var resolutions = Vector.empty[ExecutionLeaseId]
  def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[K]): IO[Either[ConnectionError, Unit]] =
    IO.delay:
      resolutions = resolutions :+ lease.id
      result

object PipelineFixtures:
  /** A registered operation with throwaway client and credentials, for registry-shape tests. */
  def registered[K](descriptor: OperationDescriptor[SearchQuery, K]): RegisteredOperation[SearchQuery, K, Unit] =
    RegisteredOperation(descriptor, PipelineClient[K](), PipelineCredentials[K]())
