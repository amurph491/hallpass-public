package run.hallpass.adapters.postgres

import java.time.Instant
import java.util.UUID
import cats.ApplicativeThrow
import cats.effect.IO
import cats.syntax.all.*
import io.circe.parser
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.implicits.javatimedrivernative.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Durable single-use approvals, over V24.
  *
  * Every statement runs after `TenantSession.establish`, so forced row-level security scopes it. The V24 trigger and the
  * runtime role's column-limited UPDATE are the defense in depth; the guarantees are stated here too, in SQL:
  *
  *  - a decision is a conditional UPDATE of a PENDING, unexpired row, made only after the row is locked and its
  *    approver compared;
  *  - consumption is one conditional UPDATE ... RETURNING, so of any number of concurrent consumers exactly one wins;
  *  - nothing is deleted;
  *  - a stored row that cannot be decoded fails the effect. It is never reported as absent, pending or granted.
  *
  * The record's `tool` (the catalog tool the agent called) is display metadata only, never consulted for authority.
  */
final class PostgresApprovalStore(xa: Transactor[IO]) extends ApprovalStore:
  import PostgresApprovalStore.*

  private def tenantProgram[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(xa)

  def create(record: ApprovalRecord): IO[Unit] =
    val tenant = record.tenant.toString
    tenantProgram(record.tenant):
      // Selecting from `capabilities` ties the stored action and capability to the catalog row, in this tenant: a row
      // that does not match inserts nothing, which is refused below.
      sql"""insert into approvals (id, tenant_id, agent_principal_id, approver_principal_id, operation_id, tool_name,
                                    binding_digest, capability_id, action, resource_id, policy_id, policy_version, preview, requested_at,
                                    expires_at, status)
             select ${record.id.toString}::uuid, c.tenant_id, ${record.agent.toString}::uuid,
                    ${record.approver.id.toString}::uuid, ${record.operation.value}, ${record.tool.value},
                    ${record.binding.value}, c.id,
                    c.action, ${record.requiredCapability.resource.toString}::uuid, ${record.policyId.toString}::uuid,
                    ${policyVersionInt(record.policyVersion)}, ${record.preview.noSpaces}::jsonb, ${record.requestedAt},
                    ${record.expiresAt}, 'PENDING'
               from capabilities c
              where c.tenant_id = $tenant::uuid and c.id = ${record.catalogCapability}::uuid
                and c.namespace || '.' || c.name = ${record.requiredCapability.capability.value}
                and c.action = ${actionWire(record.requiredCapability.action)}""".update.run.flatMap:
        case 1 => ().pure[ConnectionIO]
        case _ => fail("approval capability does not match the tenant's catalog")

  def find(tenant: TenantId, id: ApprovalId): IO[Option[ApprovalRecord]] =
    tenantProgram(tenant):
      selectById(tenant, id, forUpdate = false).flatMap(_.traverse(decode))

  def pendingFor(tenant: TenantId, approver: Principal.Human, at: Instant, limit: Int): IO[Vector[ApprovalRecord]] =
    if limit <= 0 then IO.pure(Vector.empty)
    else
      tenantProgram(tenant):
        (selectFragment ++
          fr"""where a.tenant_id = ${tenant.toString}::uuid and a.status = 'PENDING' and a.expires_at > $at
                 and a.approver_principal_id = ${approver.id.toString}::uuid
               order by a.requested_at desc, a.id limit $limit""")
          .query[Row].to[Vector].flatMap(_.traverse(decode))

  def decide(
      tenant: TenantId,
      id: ApprovalId,
      approver: Principal.Human,
      approve: Boolean,
      at: Instant
  ): IO[Either[ApprovalDecisionError, ApprovalRecord]] =
    val status = if approve then "APPROVED" else "DENIED"
    tenantProgram(tenant):
      // The row lock serializes concurrent deciders, so the checks below and the update see one state.
      selectById(tenant, id, forUpdate = true).flatMap:
        case None => ApprovalDecisionError.NotFound.asLeft[ApprovalRecord].pure[ConnectionIO]
        case Some(raw) =>
          decode(raw).flatMap: record =>
            if record.approver != approver then ApprovalDecisionError.NotApprover.asLeft[ApprovalRecord].pure[ConnectionIO]
            else if record.status != ApprovalStatus.Pending then ApprovalDecisionError.AlreadyDecided.asLeft[ApprovalRecord].pure[ConnectionIO]
            else if !record.expiresAt.isAfter(at) then ApprovalDecisionError.Expired.asLeft[ApprovalRecord].pure[ConnectionIO]
            else
              sql"""update approvals set status = $status, decided_by = ${approver.id.toString}::uuid, decided_at = $at
                     where tenant_id = ${tenant.toString}::uuid and id = ${id.toString}::uuid
                       and approver_principal_id = ${approver.id.toString}::uuid
                       and status = 'PENDING' and expires_at > $at and requested_at <= $at""".update.run.flatMap:
                case 1 =>
                  selectById(tenant, id, forUpdate = false).flatMap:
                    case Some(updated) => decode(updated).map(_.asRight[ApprovalDecisionError])
                    case None          => fail("approval vanished after a decision")
                case _ =>
                  // The row is locked, so this is a decision time before the request: not a state to report.
                  fail("approval decision could not be recorded")

  def consume(
      tenant: TenantId,
      id: ApprovalId,
      agent: AgentId,
      binding: ApprovalBinding,
      request: AuthorizationRequestId,
      at: Instant
  ): IO[Boolean] =
    tenantProgram(tenant):
      sql"""update approvals set consumed_at = $at, consumed_request_id = ${request.toString}::uuid
             where tenant_id = ${tenant.toString}::uuid and id = ${id.toString}::uuid
               and status = 'APPROVED' and consumed_at is null and expires_at > $at and decided_at <= $at
               and agent_principal_id = ${agent.toString}::uuid and binding_digest = ${binding.value}
         returning id""".query[UUID].to[Vector].map(_.sizeIs == 1)

  private def selectById(tenant: TenantId, id: ApprovalId, forUpdate: Boolean): ConnectionIO[Option[Row]] =
    val lock = if forUpdate then fr"for update of a" else Fragment.empty
    (selectFragment ++ fr"where a.tenant_id = ${tenant.toString}::uuid and a.id = ${id.toString}::uuid" ++ lock)
      .query[Row].option

object PostgresApprovalStore:
  private type Row = (
      UUID, UUID, UUID, String, String, UUID, String, UUID, UUID, Int, String, Instant, Instant, String, Option[Instant],
      Option[Instant], String, String, UUID, String
  )

  private val selectFragment: Fragment =
    fr"""select a.id, a.agent_principal_id, a.approver_principal_id, a.operation_id, a.binding_digest, a.capability_id,
                a.action, a.resource_id, a.policy_id, a.policy_version, a.preview::text, a.requested_at, a.expires_at,
                a.status, a.decided_at, a.consumed_at, c.namespace || '.' || c.name, c.action, a.tenant_id, a.tool_name
           from approvals a
           join capabilities c on c.tenant_id = a.tenant_id and c.id = a.capability_id"""

  private def fail[A](message: String): ConnectionIO[A] =
    ApplicativeThrow[ConnectionIO].raiseError(IllegalStateException(message))

  private def actionWire(action: Action): String = action.toString.toUpperCase
  private def actionFromWire(value: String): Option[Action] = Action.values.find(actionWire(_) == value)
  private def policyVersionInt(version: PolicyVersion): Int = version.toString.toInt

  private def decode(row: Row): ConnectionIO[ApprovalRecord] =
    decodeRow(row).fold(_ => fail("invalid stored approval"), _.pure[ConnectionIO])

  private def decodeRow(row: Row): Either[String, ApprovalRecord] =
    val (id, agent, approver, operation, binding, capabilityId, action, resource, policy, version, preview, requestedAt,
      expiresAt, status, decidedAt, consumedAt, capabilityKey, catalogAction, tenantUuid, toolName) = row
    for
      approvalId <- ApprovalId.parse(id.toString).leftMap(_.getMessage)
      tenant <- TenantId.parse(tenantUuid.toString).leftMap(_.toString)
      agentId <- AgentId.parse(agent.toString).leftMap(_.toString)
      human <- UserId.parse(approver.toString).leftMap(_.toString)
      operationId <- OperationId.parse(operation).toRight("operation")
      tool <- ExternalToolId.parse(toolName).toRight("tool")
      digest <- ApprovalBinding.parse(binding).toRight("binding")
      parsedAction <- actionFromWire(action).toRight("action")
      _ <- Either.cond(catalogAction == action, (), "capability action differs from the approval's")
      resourceId <- ResourceId.parse(resource.toString).leftMap(_.toString)
      key <- CapabilityKey.parse(capabilityKey).leftMap(_.toString)
      policyId <- PolicyId.parse(policy.toString).leftMap(_.toString)
      policyVersion <- PolicyVersion.from(version).toRight("policy version")
      json <- parser.parse(preview).leftMap(_.message)
      parsedStatus <- status match
        case "PENDING"  => Right(ApprovalStatus.Pending)
        case "APPROVED" => Right(ApprovalStatus.Approved)
        case "DENIED"   => Right(ApprovalStatus.Denied)
        case _          => Left("status")
    yield ApprovalRecord(
      approvalId, tenant, agentId, Principal.Human(human), operationId, tool, digest, capabilityId.toString,
      CapabilityDescriptor(resourceId, parsedAction, key), policyId, policyVersion, json, requestedAt, expiresAt,
      parsedStatus, decidedAt, consumedAt
    )
