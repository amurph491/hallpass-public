package run.hallpass.kernel.authorization

import java.time.Instant
import run.hallpass.kernel.*

/** A protocol-neutral identity for a trusted execution surface. */
opaque type ExecutorAudience = String
object ExecutorAudience:
  def parse(value: String): Option[ExecutorAudience] =
    Option.when(value.nonEmpty && value.forall(c => c.isLetterOrDigit || c == '.' || c == '-' || c == '_'))(value)

enum ExecutionLeaseIssuanceError:
  case InvalidValidityWindow

enum ExecutionLeaseValidationError:
  case Expired
  case WrongAudience

/** Immutable evidence that one authorized capability may be exercised by one trusted executor during a bounded window.
  * It is not a provider credential.
  *
  * The representation and issuance constructor are private. The only public issuance path requires an
  * [[AuthorizedCapability]], whose constructor is restricted to the authorization kernel.
  */
opaque type ExecutionLease = ExecutionLease.Data

object ExecutionLease:
  private[authorization] final case class Data(
      id: ExecutionLeaseId,
      authorizationRequestId: AuthorizationRequestId,
      tenant: TenantId,
      principal: Principal,
      resource: ResourceId,
      capability: CapabilityKey,
      action: Action,
      evidence: AuthorizationEvidence,
      audience: ExecutorAudience,
      issuedAt: Instant,
      expiresAt: Instant
  )

  /** The broker is the only application service that should invoke this factory. A lease remains non-executable until
    * it is registered by an application lease store.
    */
  def issueForBroker(
      capability: AuthorizedCapability,
      authorizationRequestId: AuthorizationRequestId,
      audience: ExecutorAudience,
      issuedAt: Instant,
      expiresAt: Instant
  ): Either[ExecutionLeaseIssuanceError, ExecutionLease] =
    Either.cond(
      expiresAt.isAfter(issuedAt),
      Data(
        id = ExecutionLeaseId.random(),
        authorizationRequestId = authorizationRequestId,
        tenant = capability.tenant,
        principal = capability.principal,
        resource = capability.resource,
        capability = capability.capability,
        action = capability.action,
        evidence = capability.evidence,
        audience = audience,
        issuedAt = issuedAt,
        expiresAt = expiresAt
      ),
      ExecutionLeaseIssuanceError.InvalidValidityWindow
    )

  extension (lease: ExecutionLease)
    def id: ExecutionLeaseId = lease.id
    def authorizationRequestId: AuthorizationRequestId = lease.authorizationRequestId
    def tenant: TenantId = lease.tenant
    def principal: Principal = lease.principal
    def resource: ResourceId = lease.resource
    def capability: CapabilityKey = lease.capability
    def action: Action = lease.action
    def evidence: AuthorizationEvidence = lease.evidence
    def audience: ExecutorAudience = lease.audience
    def issuedAt: Instant = lease.issuedAt
    def expiresAt: Instant = lease.expiresAt

    /** Validates immutable lease claims. Single-use tracking is intentionally an application concern because it
      * requires mutable, atomic storage.
      */
    def validateFor(audience: ExecutorAudience, now: Instant): Either[ExecutionLeaseValidationError, ExecutionLease] =
      if !now.isBefore(lease.expiresAt) then Left(ExecutionLeaseValidationError.Expired)
      else if lease.audience != audience then Left(ExecutionLeaseValidationError.WrongAudience)
      else Right(lease)
