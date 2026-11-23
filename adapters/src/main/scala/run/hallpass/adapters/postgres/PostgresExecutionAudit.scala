package run.hallpass.adapters.postgres

import java.time.Instant
import java.util.UUID
import cats.effect.IO
import cats.syntax.all.*
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.implicits.javatimedrivernative.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.application.*
import run.hallpass.kernel.*

/** Safe failure categories exposed by the durable execution-evidence boundary. */
enum ExecutionAuditPersistenceError:
  case ContextlessRedemptionDenial
  case LegacyContextNotDurable
  case PersistenceFailure

/** Never includes database error detail, request content, or credential material. */
final case class ExecutionAuditPersistenceException(error: ExecutionAuditPersistenceError)
    extends RuntimeException(error.toString)

/**
  * PostgreSQL append-only execution evidence store.
  *
  * A lifecycle row and its ordered delegation evidence are written inside one tenant-scoped transaction. The adapter
  * accepts only complete, authenticated-agent lifecycle contexts. Contextless redemption failures intentionally fail
  * closed, because V8 cannot safely attribute them to a tenant, request, or agent.
  */
final class PostgresExecutionAudit(xa: Transactor[IO]) extends ExecutionAudit[IO], ExecutionHistory[IO]:
  def record(event: ExecutionAuditEvent): IO[Unit] =
    rowFor(event) match
      case Left(error) => IO.raiseError(ExecutionAuditPersistenceException(error))
      case Right(row) =>
        (TenantSession.establish(row.tenant) *> insert(row)).transact(xa).handleErrorWith: _ =>
          IO.raiseError(ExecutionAuditPersistenceException(ExecutionAuditPersistenceError.PersistenceFailure))

  def hasCompletedExecution(tenant: TenantId, agent: Option[AgentId] = None): IO[Boolean] =
    val agentFilter = agent.fold(Fragment.empty)(id => fr"and agent_principal_id = ${id.toString}::uuid")
    (TenantSession.establish(tenant) *>
      (fr"""select exists(
              select 1 from execution_audit_events
              where tenant_id = ${tenant.toString}::uuid and event_kind = 'EXECUTION_COMPLETED'
            """ ++ agentFilter ++ fr")").query[Boolean].unique)
      .transact(xa)
      .handleErrorWith(_ => IO.raiseError(ExecutionAuditPersistenceException(ExecutionAuditPersistenceError.PersistenceFailure)))

  def recent(tenant: TenantId, agent: Option[AgentId], limit: Int): IO[Vector[ExecutionHistoryEntry]] =
    page(tenant, agent, limit, None).map(_.entries)

  override def page(
      tenant: TenantId,
      agent: Option[AgentId],
      limit: Int,
      cursor: Option[ExecutionHistoryCursor]
  ): IO[ExecutionHistoryPage] =
    if limit < 1 || limit > 100 then
      IO.raiseError(ExecutionAuditPersistenceException(ExecutionAuditPersistenceError.PersistenceFailure))
    else
      val agentFilter = agent.fold(Fragment.empty)(id => fr"and e.agent_principal_id = ${id.toString}::uuid")
      val cursorFilter = cursor.fold(Fragment.empty)(value =>
        fr"and (e.occurred_at, e.id) < (${value.occurredAt}, ${value.eventId})"
      )
      val query =
        fr"""select e.id, e.authorization_request_id, e.correlation_id, e.agent_principal_id,
                     tr.external_id, c.namespace || '.' || c.name, e.event_kind, e.safe_outcome, e.occurred_at,
                     ar.authorization_source
              from execution_audit_events e
              join resources tr on tr.tenant_id = e.tenant_id and tr.id = e.tool_id
              join capabilities c on c.tenant_id = e.tenant_id and c.id = e.capability_id
              join authorization_requests ar on ar.tenant_id=e.tenant_id and ar.id=e.authorization_request_id
              where e.tenant_id = ${tenant.toString}::uuid""" ++ agentFilter ++ cursorFilter ++
          fr"order by e.occurred_at desc, e.id desc limit ${limit + 1}"
      (TenantSession.establish(tenant) *>
        query.query[(UUID, UUID, String, UUID, String, String, String, String, Instant, Option[String])].to[Vector])
        .transact(xa)
        .flatMap: rows =>
          rows.traverse(decodeHistoryRow) match
            case None => IO.raiseError(ExecutionAuditPersistenceException(ExecutionAuditPersistenceError.PersistenceFailure))
            case Some(decoded) =>
              val hasMore = decoded.size > limit
              val entries = decoded.take(limit)
              val nextCursor = if hasMore then entries.lastOption.flatMap(_.cursor) else None
              IO.pure(ExecutionHistoryPage(entries, nextCursor))
        .handleErrorWith(_ => IO.raiseError(
          ExecutionAuditPersistenceException(ExecutionAuditPersistenceError.PersistenceFailure)
        ))

  override def forRequest(
      tenant: TenantId,
      agent: Option[AgentId],
      requestId: AuthorizationRequestId,
      limit: Int,
      cursor: Option[ExecutionHistoryCursor]
  ): IO[ExecutionHistoryPage] =
    if limit < 1 || limit > 100 then
      IO.raiseError(ExecutionAuditPersistenceException(ExecutionAuditPersistenceError.PersistenceFailure))
    else
      val agentFilter = agent.fold(Fragment.empty)(id => fr"and e.agent_principal_id = ${id.toString}::uuid")
      val cursorFilter = cursor.fold(Fragment.empty)(value =>
        fr"and (e.occurred_at, e.id) > (${value.occurredAt}, ${value.eventId})"
      )
      val query =
        fr"""select e.id, e.authorization_request_id, e.correlation_id, e.agent_principal_id,
                   tr.external_id, c.namespace || '.' || c.name, e.event_kind, e.safe_outcome, e.occurred_at,
                   ar.authorization_source
            from execution_audit_events e
            join resources tr on tr.tenant_id = e.tenant_id and tr.id = e.tool_id
            join capabilities c on c.tenant_id = e.tenant_id and c.id = e.capability_id
            join authorization_requests ar on ar.tenant_id=e.tenant_id and ar.id=e.authorization_request_id
            where e.tenant_id = ${tenant.toString}::uuid
              and e.authorization_request_id = ${requestId.toString}::uuid""" ++ agentFilter ++ cursorFilter ++
          fr"order by e.occurred_at, e.id limit ${limit + 1}"
      (TenantSession.establish(tenant) *>
        query.query[(UUID, UUID, String, UUID, String, String, String, String, Instant, Option[String])].to[Vector])
        .transact(xa)
        .flatMap: rows =>
          rows.traverse(decodeHistoryRow) match
            case None => IO.raiseError(ExecutionAuditPersistenceException(ExecutionAuditPersistenceError.PersistenceFailure))
            case Some(decoded) =>
              val hasMore = decoded.size > limit
              val entries = decoded.take(limit)
              val nextCursor = if hasMore then entries.lastOption.flatMap(_.cursor) else None
              IO.pure(ExecutionHistoryPage(entries, nextCursor))
        .handleErrorWith(_ => IO.raiseError(
          ExecutionAuditPersistenceException(ExecutionAuditPersistenceError.PersistenceFailure)
        ))

  private def decodeHistoryRow(
      row: (UUID, UUID, String, UUID, String, String, String, String, Instant, Option[String])
  ): Option[ExecutionHistoryEntry] =
    for
      cursor <- Some(ExecutionHistoryCursor.fromStored(row._9, row._1))
      request <- AuthorizationRequestId.parse(row._2.toString).toOption
      correlation <- ExecutionAuditCorrelationId.parse(row._3)
      agent <- AgentId.parse(row._4.toString).toOption
      tool <- ExternalToolId.parse(row._5)
      kind <- ExecutionHistoryEventKind.fromWire(row._7)
      outcome <- ExecutionHistoryOutcome.fromWire(row._8)
      if row._6.nonEmpty
      source <- row._10.traverse(AuthorizationSource.fromWire)
      if row._10.isEmpty || source.nonEmpty
    yield ExecutionHistoryEntry(request, correlation, agent, tool, row._6, kind, outcome, row._9, Some(cursor), source)

  private def insert(row: AuditRow): ConnectionIO[Unit] =
    for
      _ <- sql"""insert into execution_audit_events(
                  id, tenant_id, authorization_request_id, correlation_id, agent_principal_id,
                  tool_id, capability_id, resource_id, action, policy_id, policy_version,
                  agent_credential_id, event_kind, safe_outcome, occurred_at
                ) values (
                  ${row.id.toString}::uuid, ${row.tenant.toString}::uuid, ${row.requestId.toString}::uuid,
                  ${row.correlationId}, ${row.agentId.toString}::uuid, ${row.toolId.toString}::uuid,
                  ${row.capabilityId}::uuid, ${row.resourceId.toString}::uuid, ${row.action},
                  ${row.policyId.toString}::uuid, ${row.policyVersion}, ${row.agentCredentialId}::uuid,
                  ${row.eventKind}, ${row.safeOutcome}, ${row.occurredAt}
                )""".update.run
      _ <- row.delegationIds.zipWithIndex.traverse_ { case (delegationId, position) =>
        sql"""insert into execution_audit_event_delegations(
                    tenant_id, execution_audit_event_id, delegation_position, delegation_id
                  ) values (
                    ${row.tenant.toString}::uuid, ${row.id.toString}::uuid, $position, ${delegationId.toString}::uuid
                  )""".update.run
      }
    yield ()

  private def rowFor(event: ExecutionAuditEvent): Either[ExecutionAuditPersistenceError, AuditRow] =
    event match
      case ExecutionAuditEvent.LeaseIssued(context: AuthenticatedExecutionAuditContext, occurredAt) =>
        rowFrom(context, "LEASE_ISSUED", "ISSUED", occurredAt)
      case ExecutionAuditEvent.LeaseRedeemed(context: AuthenticatedExecutionAuditContext, occurredAt) =>
        rowFrom(context, "LEASE_REDEEMED", "REDEEMED", occurredAt)
      case ExecutionAuditEvent.ExecutionCompleted(context: AuthenticatedExecutionAuditContext, occurredAt) =>
        rowFrom(context, "EXECUTION_COMPLETED", "COMPLETED", occurredAt)
      case ExecutionAuditEvent.ExecutionFailed(context: AuthenticatedExecutionAuditContext, outcome, occurredAt) =>
        outcome match
          case ExecutionFailure.AuthorityRevoked =>
            rowFrom(context, "AUTHORITY_CHANGED", "DENIED_AUTHORITY_CHANGED", occurredAt)
          case ExecutionFailure.ConnectionUnavailable =>
            rowFrom(context, "CONNECTION_UNAVAILABLE", "DENIED_CONNECTION_UNAVAILABLE", occurredAt)
          case ExecutionFailure.ProviderRejected =>
            rowFrom(context, "PROVIDER_REJECTED", "FAILED_PROVIDER_REJECTED", occurredAt)
          case ExecutionFailure.ProviderUnavailable =>
            rowFrom(context, "PROVIDER_UNAVAILABLE", "FAILED_PROVIDER_UNAVAILABLE", occurredAt)
          case ExecutionFailure.Unexpected =>
            rowFrom(context, "COMPLETION_UNKNOWN", "UNKNOWN", occurredAt)
          case ExecutionFailure.CompletionUnknown =>
            rowFrom(context, "COMPLETION_UNKNOWN", "UNKNOWN", occurredAt)
          case ExecutionFailure.CoordinationUnavailable =>
            rowFrom(context, "COORDINATION_UNAVAILABLE", "DENIED_COORDINATION_UNAVAILABLE", occurredAt)
      case ExecutionAuditEvent.RedemptionDenied(_, _, outcome, occurredAt, Some(context: AuthenticatedExecutionAuditContext)) =>
        val safeOutcome = outcome match
          case LeaseRedemptionDenial.UnknownLease => "DENIED_UNKNOWN_LEASE"
          case LeaseRedemptionDenial.Expired => "DENIED_EXPIRED"
          case LeaseRedemptionDenial.AlreadyRedeemed => "DENIED_ALREADY_REDEEMED"
          case LeaseRedemptionDenial.WrongAudience => "DENIED_WRONG_AUDIENCE"
        rowFrom(context, "REDEMPTION_DENIED", safeOutcome, occurredAt)
      case ExecutionAuditEvent.RedemptionDenied(_, _, _, _, None) =>
        Left(ExecutionAuditPersistenceError.ContextlessRedemptionDenial)
      case _ => Left(ExecutionAuditPersistenceError.LegacyContextNotDurable)

  private def rowFrom(
      context: AuthenticatedExecutionAuditContext,
      eventKind: String,
      safeOutcome: String,
      occurredAt: Instant
  ): Either[ExecutionAuditPersistenceError, AuditRow] =
    Right(
      AuditRow(
        UUID.randomUUID(),
        context.tenant,
        context.authorizationRequestId,
        context.correlationId.value,
        context.agentId,
        context.toolId,
        context.capabilityId.value.toString,
        context.evidence.requiredCapability.resource,
        actionWire(context.evidence.requiredCapability.action),
        context.evidence.policyId,
        context.evidence.policyVersion.toString.toInt,
        context.agentCredentialId.toString,
        eventKind,
        safeOutcome,
        occurredAt,
        context.evidence.delegationIds
      )
    )

  private def actionWire(action: Action): String = action.toString.toUpperCase

private final case class AuditRow(
    id: UUID,
    tenant: TenantId,
    requestId: AuthorizationRequestId,
    correlationId: String,
    agentId: AgentId,
    toolId: ResourceId,
    capabilityId: String,
    resourceId: ResourceId,
    action: String,
    policyId: PolicyId,
    policyVersion: Int,
    agentCredentialId: String,
    eventKind: String,
    safeOutcome: String,
    occurredAt: Instant,
    delegationIds: Vector[DelegationId]
)
