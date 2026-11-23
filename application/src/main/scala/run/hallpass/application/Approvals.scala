package run.hallpass.application

import java.time.Instant
import cats.effect.IO
import io.circe.Json
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

enum ApprovalStatus:
  case Pending, Approved, Denied

/** One invocation awaiting, or having received, a human decision. `preview` is the operation's canonical typed
  * input: what the approver is shown and exactly what the binding digests. */
final case class ApprovalRecord(
    id: ApprovalId,
    tenant: TenantId,
    agent: AgentId,
    approver: Principal.Human,
    operation: OperationId,
    tool: ExternalToolId,
    binding: ApprovalBinding,
    /** The catalog capability row (`capabilities.id`). */
    catalogCapability: String,
    requiredCapability: CapabilityDescriptor,
    policyId: PolicyId,
    policyVersion: PolicyVersion,
    preview: Json,
    requestedAt: Instant,
    expiresAt: Instant,
    status: ApprovalStatus,
    decidedAt: Option[Instant],
    consumedAt: Option[Instant]
):
  /** The kernel's view of an APPROVED, unconsumed record. Anything else grants nothing. */
  def granted: Option[GrantedApproval] =
    Option.when(status == ApprovalStatus.Approved && consumedAt.isEmpty)(
      GrantedApproval(id, tenant, Principal.Agent(agent), approver, binding, requiredCapability, policyId, policyVersion, expiresAt)
    )

enum ApprovalDecisionError:
  case NotFound
  /** Only the invocation's root of authority may decide it; an agent never can. */
  case NotApprover
  case AlreadyDecided
  case Expired

/** Durable approvals. Implementations scope every call to the tenant (RLS) and never delete a row. */
trait ApprovalStore:
  def create(record: ApprovalRecord): IO[Unit]
  def find(tenant: TenantId, id: ApprovalId): IO[Option[ApprovalRecord]]
  /** Undecided, unexpired approvals the human may decide, newest first, at most `limit`. */
  def pendingFor(tenant: TenantId, approver: Principal.Human, at: Instant, limit: Int): IO[Vector[ApprovalRecord]]
  /** Decides a PENDING, unexpired approval once, only as its approver. */
  def decide(
      tenant: TenantId,
      id: ApprovalId,
      approver: Principal.Human,
      approve: Boolean,
      at: Instant
  ): IO[Either[ApprovalDecisionError, ApprovalRecord]]
  /** Atomically consumes an APPROVED, unconsumed, unexpired approval for exactly this agent and binding. `false` when
    * any condition fails, including a concurrent consumer winning. */
  def consume(
      tenant: TenantId,
      id: ApprovalId,
      agent: AgentId,
      binding: ApprovalBinding,
      request: AuthorizationRequestId,
      at: Instant
  ): IO[Boolean]

object ApprovalStore:
  /** For deployments and tests without approvals: a required approval cannot be requested, so it stays a plain
    * `approval_required` with no ID, and no approval can be presented. */
  val unavailable: ApprovalStore = new ApprovalStore:
    def create(record: ApprovalRecord) = IO.raiseError(UnsupportedOperationException("approvals unavailable"))
    def find(tenant: TenantId, id: ApprovalId) = IO.pure(None)
    def pendingFor(tenant: TenantId, approver: Principal.Human, at: Instant, limit: Int) = IO.pure(Vector.empty)
    def decide(tenant: TenantId, id: ApprovalId, approver: Principal.Human, approve: Boolean, at: Instant) =
      IO.pure(Left(ApprovalDecisionError.NotFound))
    def consume(tenant: TenantId, id: ApprovalId, agent: AgentId, binding: ApprovalBinding, request: AuthorizationRequestId, at: Instant) =
      IO.pure(false)

/** The approver's side. Deciding is an authority mutation: callers hold the tenant mutation gate and read `at` after
  * acquiring it. The browser context supplies the human; nothing in a request names the approver. */
final class ApprovalService(store: ApprovalStore):
  def pending(context: AuthenticatedHuman, at: Instant): IO[Vector[ApprovalRecord]] =
    store.pendingFor(context.tenant, context.principal, at, 100)

  def decide(context: AuthenticatedHuman, id: ApprovalId, approve: Boolean, at: Instant): IO[Either[ApprovalDecisionError, ApprovalRecord]] =
    store.decide(context.tenant, id, context.principal, approve, at)
