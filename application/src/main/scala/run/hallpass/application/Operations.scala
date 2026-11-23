package run.hallpass.application

import cats.effect.IO
import io.circe.Json
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** A provider's stable Hallpass name. It matches `resources.provider` on the provider's catalog resource. */
opaque type ProviderId = String
object ProviderId:
  private val Pattern = "[a-z][a-z0-9]{1,31}".r
  def parse(value: String): Option[ProviderId] = Option.when(Pattern.matches(value))(value)
  val Slack: ProviderId = "slack"
  val GitHub: ProviderId = "github"
  val Linear: ProviderId = "linear"
  val Notion: ProviderId = "notion"
  val Google: ProviderId = "google"
  val HubSpot: ProviderId = "hubspot"
  extension (value: ProviderId) def value: String = value

/** A provider's stable identifier for a resource, such as a numeric repository ID. Never a display name. */
opaque type ExternalId = String
object ExternalId:
  val MaximumLength = 256
  def parse(value: String): Option[ExternalId] =
    Option.when(
      value.nonEmpty && value.length <= MaximumLength &&
        value.forall(character => !Character.isISOControl(character) && !character.isWhitespace)
    )(value)
  extension (value: ExternalId) def value: String = value

/** A versioned operation identity, such as `slack.search.messages@1`. A changed contract is a new version. */
opaque type OperationId = String
object OperationId:
  private val Pattern = "[a-z][a-z0-9_]*(\\.[a-z][a-z0-9_]*){1,4}@[1-9][0-9]{0,3}".r
  def parse(value: String): Option[OperationId] = Option.when(Pattern.matches(value))(value)
  extension (value: OperationId) def value: String = value

/** Who a connection root belongs to. Personal roots carry one human's credentials, so only that human can be the root
  * of authority for anything beneath them. */
enum Custody:
  case Workspace, Personal

/** The value-level declaration of a provider resource kind `K`, given once per phantom tag.
  *
  * A child kind can only be declared from a given parent kind, so a topology cannot name an undeclared parent. Custody
  * is declared on roots and inherited below them.
  */
final class ResourceKind[K] private (
    /** The persisted name, such as `github.repository`. */
    val wire: String,
    val provider: ProviderId,
    /** The kernel's coarse, protocol-neutral class. */
    val resourceType: ResourceType,
    val parent: Option[ResourceKind[?]],
    declaredCustody: Option[Custody]
):
  def isRoot: Boolean = parent.isEmpty
  def custody: Custody = parent.fold(declaredCustody.getOrElse(Custody.Workspace))(_.custody)
  /** This kind and its ancestors, nearest first. */
  def lineage: Vector[ResourceKind[?]] = this +: parent.fold(Vector.empty)(_.lineage)
  override def toString: String = s"ResourceKind($wire)"

object ResourceKind:
  private val WirePattern = "[a-z][a-z0-9]*(\\.[a-z][a-z0-9_]*)+".r

  def root[K](wire: String, provider: ProviderId, resourceType: ResourceType, custody: Custody): ResourceKind[K] =
    require(validWire(wire, provider), s"invalid resource kind name for provider ${provider.value}")
    new ResourceKind(wire, provider, resourceType, None, Some(custody))

  def child[K, P](wire: String, resourceType: ResourceType)(using parent: ResourceKind[P]): ResourceKind[K] =
    require(validWire(wire, parent.provider), s"invalid resource kind name for provider ${parent.provider.value}")
    new ResourceKind(wire, parent.provider, resourceType, Some(parent), None)

  private def validWire(wire: String, provider: ProviderId): Boolean =
    WirePattern.matches(wire) && wire.startsWith(provider.value + ".")

/** A provider's stable identifier for a resource of kind `K`. Mixing kinds is a compile error. */
final case class ExternalRef[K](id: ExternalId)(using val kind: ResourceKind[K])

/** Where an operation acts, extracted from its typed input. Untrusted until the [[ResourceResolver]] resolves it. */
enum ResourceLocator[K]:
  /** The connection's root, for example one person's mailbox. */
  case ConnectionRoot()
  /** One resource the administrator selected, for example one repository. */
  case Selected(ref: ExternalRef[K])

/** A resource that the [[ResourceResolver]] found in this tenant's catalog, with its trusted scope. Its constructor is
  * private to the application layer, so dispatch cannot be handed a resource that was not resolved, and the provider
  * request is built from this value rather than from an argument string.
  */
opaque type SelectedResource[K] = SelectedResource.Data[K]
object SelectedResource:
  private[application] final case class Data[K](kind: ResourceKind[K], externalId: ExternalId, scope: ResourceScope)

  private[application] def trusted[K](
      kind: ResourceKind[K],
      externalId: ExternalId,
      scope: ResourceScope
  ): SelectedResource[K] = Data(kind, externalId, scope)

  extension [K](value: SelectedResource[K])
    def kind: ResourceKind[K] = value.kind
    def externalId: ExternalId = value.externalId
    def scope: ResourceScope = value.scope
    def resource: ResourceId = value.scope.target.id
    def tenant: TenantId = value.scope.tenant

/** Why agent-supplied arguments were rejected. Field names come from the operation's own schema, never from input. An
  * argument error carries no authority: it is answered before resolution, authorization, or journaling. */
enum ArgumentError:
  case NotAnObject
  case UnexpectedField
  case MissingField(name: String)
  case InvalidField(name: String)

/** A versioned, code-defined operation contract. `In` is its typed input and `K` the kind of resource it acts on.
  *
  * The capability and action here must agree with the tenant's trusted catalog mapping for `tool`; a disagreement
  * denies the call.
  */
trait OperationDescriptor[In, K]:
  def id: OperationId
  /** The catalog tool whose trusted mapping supplies the capability's authority. */
  def tool: ExternalToolId
  def description: String
  def capability: CapabilityKey
  def action: Action
  def target: ResourceKind[K]
  def audience: ExecutorAudience
  /** The agent-visible argument contract. A display aid only: `decode` is authoritative. */
  def inputSchema: Json
  def decode(arguments: Json): Either[ArgumentError, In]
  /** The argument field that names the target resource's external ID, for operations whose target is a selected
    * child. Discovery uses it only to annotate the agent-visible schema with the targets the agent may currently
    * address; `locate` remains authoritative. */
  def targetArgument: Option[String] = None
  def locate(input: In): ResourceLocator[K]
  /** Valued facts for constraints. */
  def facts(input: In): AuthorizationContext
  /** The canonical form of the input that the invocation binding digests. It must be deterministic for equal inputs
    * and distinct for inputs that would dispatch differently. */
  def canonical(input: In): Json

/** Resolves the provider credential for one redeemed lease. `C` is an adapter-private credential type that never
  * leaves the executor. Implementations resolve the connection server-side from the authorized resource; they never
  * accept a connection ID from a request. */
trait CredentialStrategy[K, C]:
  def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[K]): IO[Either[ConnectionError, C]]

/** Sends one operation to the provider. Failures are raised as [[ProviderExecutionException]] and never carry
  * credentials or provider payloads. */
trait ProviderOperationClient[In, K, C]:
  def dispatch(target: SelectedResource[K], input: In, credential: C): IO[ToolResult]

/** A descriptor with the client and credential strategy that serve it. Declaring them together makes `In`, `K`, and
  * `C` line up at compile time, so a client cannot be paired with another provider's credential type. */
final case class RegisteredOperation[In, K, C](
    descriptor: OperationDescriptor[In, K],
    client: ProviderOperationClient[In, K, C],
    credentials: CredentialStrategy[K, C]
)

enum OperationRegistryError:
  case DuplicateOperation(id: OperationId)
  case DuplicateTool(tool: ExternalToolId)
  /** Two distinct kind declarations share a wire name. */
  case ConflictingKind(wire: String)
  /** A kind's lineage names a different provider from its root. */
  case MixedProviderLineage(wire: String)

/** The code-defined set of operations this server can execute. */
final class OperationRegistry private (operations: Vector[RegisteredOperation[?, ?, ?]]):
  private val byId = operations.map(operation => operation.descriptor.id -> operation).toMap
  private val byTool = operations.map(operation => operation.descriptor.tool -> operation).toMap
  def find(id: OperationId): Option[RegisteredOperation[?, ?, ?]] = byId.get(id)
  /** Tool names are unique in a registry, so an agent-visible name selects at most one operation. */
  def findByTool(tool: ExternalToolId): Option[RegisteredOperation[?, ?, ?]] = byTool.get(tool)
  def all: Vector[RegisteredOperation[?, ?, ?]] = operations

object OperationRegistry:
  def from(operations: Vector[RegisteredOperation[?, ?, ?]]): Either[OperationRegistryError, OperationRegistry] =
    val descriptors = operations.map(_.descriptor)
    val kinds = descriptors.flatMap(_.target.lineage)
    descriptors.groupBy(_.id).collectFirst { case (id, found) if found.size > 1 => OperationRegistryError.DuplicateOperation(id) }
      .orElse(
        descriptors.groupBy(_.tool).collectFirst { case (tool, found) if found.size > 1 => OperationRegistryError.DuplicateTool(tool) }
      )
      .orElse(
        kinds.groupBy(_.wire).collectFirst:
          case (wire, found) if found.exists(kind => !(kind eq found.head)) => OperationRegistryError.ConflictingKind(wire)
      )
      .orElse(
        kinds.collectFirst:
          case kind if kind.lineage.exists(_.provider != kind.provider) => OperationRegistryError.MixedProviderLineage(kind.wire)
      )
      .toLeft(new OperationRegistry(operations))

/** A credential-free provider execution failure category. */
enum ProviderError:
  /** The connection is missing, disabled, or its secret cannot be read. Nothing was sent to the provider. */
  case ConnectionUnavailable
  /** Current authority no longer matches the lease. Nothing was sent to the provider. */
  case AuthorityRevoked
  /** The redeemed lease does not bind this exact invocation. Nothing was sent to the provider. */
  case BindingMismatch
  case AuthenticationFailed
  case Rejected
  case Timeout
  case InvalidResponse
  /** The provider may have completed, but completion evidence could not be recorded. Never retry. */
  case OutcomeUnknown

/** Raised by provider clients and the execution lifecycle. Only causes classified as safe are retained. */
final class ProviderExecutionException private (val error: ProviderError, cause: Throwable | Null)
    extends RuntimeException(error.toString, cause)

object ProviderExecutionException:
  def apply(error: ProviderError): ProviderExecutionException = new ProviderExecutionException(error, null)
  /** For causes known not to carry request details, such as JDK connect and timeout exceptions. */
  def withSafeCause(error: ProviderError, cause: Throwable): ProviderExecutionException =
    new ProviderExecutionException(error, cause)
  def unapply(value: ProviderExecutionException): Some[ProviderError] = Some(value.error)
