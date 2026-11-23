package run.hallpass.application

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.HexFormat
import io.circe.{Json, Printer}
import run.hallpass.kernel.*

/** A SHA-256 digest, as 64 lower-case hex characters. */
opaque type InvocationDigest = String
object InvocationDigest:
  private[application] def sha256(bytes: Array[Byte]): InvocationDigest =
    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))
  extension (value: InvocationDigest) def value: String = value

/** Binds a lease to one exact invocation: who, which operation version, which capability and action, which resolved
  * resource, its provider kind and external ID, and the canonical typed input.
  *
  * The broker stores it with the lease's audit context. At redemption the executor recomputes it from the input and
  * target it is about to dispatch, and refuses to resolve a credential when the two differ. Approvals and a
  * future external decision point sign the same value.
  */
final case class InvocationBinding private (
    operation: OperationId,
    resource: ResourceId,
    externalId: ExternalId,
    digest: InvocationDigest
)

object InvocationBinding:
  private val Version = 2
  private val printer = Printer.noSpaces.copy(sortKeys = true, dropNullValues = false)

  def compute(
      tenant: TenantId,
      agent: AgentId,
      operation: OperationId,
      capability: CapabilityKey,
      action: Action,
      resource: ResourceId,
      kind: ResourceKind[?],
      externalId: ExternalId,
      canonicalInput: Json
  ): InvocationBinding =
    // A JSON object printed with sorted keys and no whitespace: field boundaries are unambiguous and equal inputs
    // produce equal bytes.
    val document = Json.obj(
      "v" -> Json.fromInt(Version),
      "tenant" -> Json.fromString(tenant.toString),
      "agent" -> Json.fromString(agent.toString),
      "operation" -> Json.fromString(operation.value),
      "capability" -> Json.fromString(capability.value),
      "action" -> Json.fromString(action.toString),
      "resource" -> Json.fromString(resource.toString),
      "provider" -> Json.fromString(kind.provider.value),
      "kind" -> Json.fromString(kind.wire),
      "externalId" -> Json.fromString(externalId.value),
      "input" -> canonicalInput
    )
    val bytes = printer.print(document).getBytes(StandardCharsets.UTF_8)
    InvocationBinding(operation, resource, externalId, InvocationDigest.sha256(bytes))

  /** The binding for a typed input against its resolved target. */
  def of[In, K](
      tenant: TenantId,
      agent: AgentId,
      descriptor: OperationDescriptor[In, K],
      target: SelectedResource[K],
      input: In
  ): InvocationBinding =
    compute(
      tenant,
      agent,
      descriptor.id,
      descriptor.capability,
      descriptor.action,
      target.resource,
      target.kind,
      target.externalId,
      descriptor.canonical(input)
    )
