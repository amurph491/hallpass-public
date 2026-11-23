package run.hallpass.kernel

import java.util.UUID

enum IdentifierParseError:
  case InvalidUuid

private[kernel] def parseUuid(value: String): Either[IdentifierParseError, UUID] =
  val canonicalUuid = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}".r
  value match
    case canonicalUuid() => Right(UUID.fromString(value))
    case _               => Left(IdentifierParseError.InvalidUuid)

opaque type TenantId = UUID
object TenantId:
  def random(): TenantId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, TenantId] = parseUuid(value)

opaque type UserId = UUID
object UserId:
  def random(): UserId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, UserId] = parseUuid(value)

opaque type AgentId = UUID
object AgentId:
  def random(): AgentId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, AgentId] = parseUuid(value)

opaque type ServiceId = UUID
object ServiceId:
  def random(): ServiceId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, ServiceId] = parseUuid(value)

opaque type ModelId = UUID
object ModelId:
  def random(): ModelId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, ModelId] = parseUuid(value)

opaque type ResourceId = UUID
object ResourceId:
  def random(): ResourceId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, ResourceId] = parseUuid(value)

opaque type PolicyId = UUID
object PolicyId:
  def random(): PolicyId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, PolicyId] = parseUuid(value)

opaque type DelegationId = UUID
object DelegationId:
  def random(): DelegationId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, DelegationId] = parseUuid(value)

opaque type AuthorizationRequestId = UUID
object AuthorizationRequestId:
  def random(): AuthorizationRequestId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, AuthorizationRequestId] = parseUuid(value)

opaque type ExecutionLeaseId = UUID
object ExecutionLeaseId:
  def random(): ExecutionLeaseId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, ExecutionLeaseId] = parseUuid(value)

/** Distinct from both an authorization resource and a provider credential. */
opaque type ConnectionId = UUID
object ConnectionId:
  def random(): ConnectionId = UUID.randomUUID()
  def parse(value: String): Either[IdentifierParseError, ConnectionId] = parseUuid(value)
