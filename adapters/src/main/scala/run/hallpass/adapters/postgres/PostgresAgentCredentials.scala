package run.hallpass.adapters.postgres

import java.sql.SQLException
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

/** PostgreSQL lifecycle store for local agent credentials. Plaintext bearer credentials never cross this boundary:
  * only their verifier and safe lifecycle metadata are persisted.
  */
final class PostgresAgentCredentials(xa: Transactor[IO])
    extends AgentCredentialAuthenticationRepository[IO],
      AgentCredentialCurrentStateRepository[IO],
      AgentCredentialEnrollmentRepository[IO]:

  private def tenantProgram[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(xa)

  def credentialForAuthentication(
      tenant: TenantId,
      selector: AgentCredentialSelector,
      at: Instant
  ): IO[Either[AgentCredentialLookupError, StoredAgentCredential]] =
    tenantProgram(tenant):
      sql"""select id, tenant_id, agent_principal_id, selector, verifier, verifier_algorithm, verifier_key_id,
                    created_at, expires_at, revoked_at, last_used_at
               from agent_credentials
              where tenant_id=${tenant.toString}::uuid and selector=${selector.value}"""
        .query[(UUID, UUID, UUID, String, Array[Byte], String, String, Instant, Option[Instant], Option[Instant], Option[Instant])]
        .option
        .map:
          case None => Left(AgentCredentialLookupError.Unknown)
          case Some(raw) =>
            val row = CredentialRow(
              raw._1,
              raw._2,
              raw._3,
              raw._4,
              raw._5,
              raw._6,
              raw._7,
              raw._8,
              raw._9,
              raw._10,
              raw._11
            )
            row.toStored(tenant) match
              case None => Left(AgentCredentialLookupError.InvalidStoredCredential)
              case Some(stored) if stored.revokedAt.nonEmpty => Left(AgentCredentialLookupError.Revoked)
              case Some(stored) if stored.expiresAt.exists(!_.isAfter(at)) => Left(AgentCredentialLookupError.Expired)
              case Some(stored) => Right(stored)
    .handleError(_ => Left(AgentCredentialLookupError.Unavailable))

  def recordSuccessfulAuthentication(
      tenant: TenantId,
      credentialId: AgentCredentialId,
      at: Instant
  ): IO[Either[AgentCredentialUseError, Unit]] =
    tenantProgram(tenant):
      sql"""update agent_credentials set last_used_at=$at
               where tenant_id=${tenant.toString}::uuid and id=${credentialId.toString}::uuid
                 and revoked_at is null and (expires_at is null or expires_at > $at)""".update.run
        .map:
          case 1 => Right(())
          case _ => Left(AgentCredentialUseError.NoLongerActive)
    .handleError(_ => Left(AgentCredentialUseError.Unavailable))

  /** Re-check the server-recorded credential lifecycle at redemption. This is intentionally an ID-only query: the
    * original bearer value is neither retained nor needed after authentication. */
  def ensureActive(
      tenant: TenantId,
      credentialId: AgentCredentialId,
      agentId: AgentId,
      at: Instant
  ): IO[Either[AgentCredentialCurrentStateError, Unit]] =
    tenantProgram(tenant):
      sql"""select exists(
               select 1 from agent_credentials
                where tenant_id=${tenant.toString}::uuid
                  and id=${credentialId.toString}::uuid
                  and agent_principal_id=${agentId.toString}::uuid
                  and revoked_at is null
                  and (expires_at is null or expires_at > $at)
             )""".query[Boolean].unique.map:
        case true  => Right(())
        case false => Left(AgentCredentialCurrentStateError.NoLongerActive)
    .handleError(_ => Left(AgentCredentialCurrentStateError.Unavailable))

  /** The credential insert also writes its selector route (a trigger on `agent_credentials`) in this transaction. A
    * selector that already routes to another tenant fails the whole enrollment. */
  def enroll(
      tenant: TenantId,
      agentId: AgentId,
      generated: GeneratedAgentCredential,
      request: AgentCredentialEnrollmentRequest,
      issuedBy: Principal.Human,
      at: Instant
  ): IO[Either[AgentEnrollmentError, AgentCredentialMetadata]] =
    tenantProgram(tenant):
      agentExists(tenant, agentId).flatMap:
        case false => AgentEnrollmentError.AgentNotFound.asLeft[AgentCredentialMetadata].pure[ConnectionIO]
        case true  => insert(tenant, agentId, generated, request, issuedBy, at).map(_.asRight)
    .attempt
    .map:
      case Right(result) => result
      case Left(error) if isLiveCredentialUniqueness(error) => Left(AgentEnrollmentError.ExistingActiveCredential)
      case Left(_) => Left(AgentEnrollmentError.PersistenceFailure)

  def rotate(
      tenant: TenantId,
      agentId: AgentId,
      previousCredentialId: AgentCredentialId,
      generated: GeneratedAgentCredential,
      request: AgentCredentialEnrollmentRequest,
      issuedBy: Principal.Human,
      at: Instant
  ): IO[Either[AgentEnrollmentError, AgentCredentialMetadata]] =
    tenantProgram(tenant):
      agentExists(tenant, agentId).flatMap:
        case false => AgentEnrollmentError.AgentNotFound.asLeft[AgentCredentialMetadata].pure[ConnectionIO]
        case true =>
          lockOwnedCredential(tenant, agentId, previousCredentialId).flatMap:
            case false => AgentEnrollmentError.CredentialNotFound.asLeft[AgentCredentialMetadata].pure[ConnectionIO]
            case true =>
              // This transaction holds the owned row lock through the replacement insert, so no observer sees
              // a new credential without the prior one being revoked.
              revokeOwned(tenant, agentId, previousCredentialId, at) *>
                insert(tenant, agentId, generated, request, issuedBy, at).map(_.asRight)
    .attempt
    .map:
      case Right(result) => result
      case Left(error) if isLiveCredentialUniqueness(error) => Left(AgentEnrollmentError.ExistingActiveCredential)
      case Left(_) => Left(AgentEnrollmentError.PersistenceFailure)

  /** Revocation removes the selector route in the same transaction, so a revoked credential no longer routes. */
  def revoke(
      tenant: TenantId,
      agentId: AgentId,
      credentialId: AgentCredentialId,
      at: Instant
  ): IO[Either[AgentEnrollmentError, Unit]] =
    tenantProgram(tenant):
      // COALESCE preserves the first revocation instant; updating an already-revoked owned row is intentional.
      sql"""update agent_credentials set revoked_at=coalesce(revoked_at, $at)
               where tenant_id=${tenant.toString}::uuid and agent_principal_id=${agentId.toString}::uuid
                 and id=${credentialId.toString}::uuid""".update.run
        .map:
          case 1 => Right(())
          case _ => Left(AgentEnrollmentError.CredentialNotFound)
    .handleError(_ => Left(AgentEnrollmentError.PersistenceFailure))

  def metadataFor(tenant: TenantId, agentId: AgentId): IO[Vector[AgentCredentialMetadata]] =
    tenantProgram(tenant):
      sql"""select id, agent_principal_id, selector, created_at, expires_at, revoked_at, last_used_at,
                    label, issued_by_human_principal_id
               from agent_credentials
              where tenant_id=${tenant.toString}::uuid and agent_principal_id=${agentId.toString}::uuid
              order by created_at desc"""
        .query[MetadataRow]
        .to[Vector]
        // Corrupt rows are never surfaced as fabricated identifiers or metadata.
        .map(_.flatMap(_.toMetadata))
    .handleError(_ => Vector.empty)

  private def agentExists(tenant: TenantId, agentId: AgentId): ConnectionIO[Boolean] =
    sql"""select exists(
             select 1 from agents
              where tenant_id=${tenant.toString}::uuid and principal_id=${agentId.toString}::uuid
           )""".query[Boolean].unique

  // Rotation is an explicit human-management action: an expired-but-unrevoked credential may be replaced,
  // but a revoked credential is terminal and must never mint a new bearer credential.
  private def lockOwnedCredential(tenant: TenantId, agentId: AgentId, credentialId: AgentCredentialId): ConnectionIO[Boolean] =
    sql"""select id from agent_credentials
             where tenant_id=${tenant.toString}::uuid and agent_principal_id=${agentId.toString}::uuid
               and id=${credentialId.toString}::uuid and revoked_at is null for update"""
      .query[UUID]
      .option
      .map(_.nonEmpty)

  private def revokeOwned(tenant: TenantId, agentId: AgentId, credentialId: AgentCredentialId, at: Instant): ConnectionIO[Unit] =
    sql"""update agent_credentials set revoked_at=coalesce(revoked_at, $at)
             where tenant_id=${tenant.toString}::uuid and agent_principal_id=${agentId.toString}::uuid
               and id=${credentialId.toString}::uuid and revoked_at is null""".update.run.void

  private def insert(
      tenant: TenantId,
      agentId: AgentId,
      generated: GeneratedAgentCredential,
      request: AgentCredentialEnrollmentRequest,
      issuedBy: Principal.Human,
      at: Instant
  ): ConnectionIO[AgentCredentialMetadata] =
    val algorithm = generated.verifierMetadata.algorithm match
      case CredentialVerifierAlgorithm.HmacSha256 => "HMAC_SHA256_V1"
    sql"""insert into agent_credentials(
             id, tenant_id, agent_principal_id, selector, verifier, verifier_algorithm, verifier_key_id,
             label, issued_by_human_principal_id, created_at, expires_at
           ) values (
             ${generated.credentialId.toString}::uuid, ${tenant.toString}::uuid, ${agentId.toString}::uuid,
             ${generated.selector.value}, ${StoredAgentCredentialVerifier.bytes(generated.verifier)}, $algorithm,
             ${generated.verifierMetadata.keyId}, ${request.label}, ${issuedBy.id.toString}::uuid, $at, ${request.expiresAt}
           )""".update.run.as(
      AgentCredentialMetadata(
        generated.credentialId,
        agentId,
        generated.selector,
        at,
        request.expiresAt,
        None,
        None,
        request.label,
        Some(issuedBy.id)
      )
    )

  private def isLiveCredentialUniqueness(error: Throwable): Boolean =
    error match
      case sql: SQLException if sql.getSQLState == "23505" =>
        Option(sql.getMessage).exists(_.contains("agent_credentials_one_unrevoked_per_agent_idx")) ||
          Option(sql.getCause).exists(isLiveCredentialUniqueness)
      case other if other.getCause != null => isLiveCredentialUniqueness(other.getCause)
      case _ => false

  private final case class CredentialRow(
      id: UUID,
      tenantId: UUID,
      agentId: UUID,
      selector: String,
      verifier: Array[Byte],
      algorithm: String,
      keyId: String,
      createdAt: Instant,
      expiresAt: Option[Instant],
      revokedAt: Option[Instant],
      lastUsedAt: Option[Instant]
  ):
    def toStored(expectedTenant: TenantId): Option[StoredAgentCredential] =
      for
        parsedTenant <- TenantId.parse(tenantId.toString).toOption
        _ <- Option.when(parsedTenant == expectedTenant)(())
        credentialId <- AgentCredentialId.parse(id.toString).toOption
        parsedAgentId <- AgentId.parse(agentId.toString).toOption
        parsedSelector <- AgentCredentialSelector.parse(selector).toOption
        parsedVerifier <- StoredAgentCredentialVerifier.fromBytes(verifier).toOption
        parsedAlgorithm <- parseAlgorithm(algorithm)
        _ <- Option.when(validKeyId(keyId))(())
      yield new StoredAgentCredential(
        parsedTenant,
        credentialId,
        parsedAgentId,
        parsedSelector,
        parsedVerifier,
        CredentialVerifierMetadata(parsedAlgorithm, keyId),
        createdAt,
        expiresAt,
        revokedAt,
        lastUsedAt
      )

  private final case class MetadataRow(
      id: UUID,
      agentId: UUID,
      selector: String,
      createdAt: Instant,
      expiresAt: Option[Instant],
      revokedAt: Option[Instant],
      lastUsedAt: Option[Instant],
      label: Option[String],
      issuedBy: Option[UUID]
  ):
    def toMetadata: Option[AgentCredentialMetadata] =
      for
        credentialId <- AgentCredentialId.parse(id.toString).toOption
        parsedAgentId <- AgentId.parse(agentId.toString).toOption
        parsedSelector <- AgentCredentialSelector.parse(selector).toOption
        parsedIssuedBy <- issuedBy.traverse(value => UserId.parse(value.toString).toOption)
      yield AgentCredentialMetadata(
        credentialId,
        parsedAgentId,
        parsedSelector,
        createdAt,
        expiresAt,
        revokedAt,
        lastUsedAt,
        label,
        parsedIssuedBy
      )

  private def parseAlgorithm(value: String): Option[CredentialVerifierAlgorithm] =
    value match
      case "HMAC_SHA256_V1" => Some(CredentialVerifierAlgorithm.HmacSha256)
      case _                => None

  private def validKeyId(value: String): Boolean =
    value.nonEmpty && value.length <= 128 && value == value.trim && value.forall(character => !Character.isISOControl(character))
