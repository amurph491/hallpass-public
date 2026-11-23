package run.hallpass.adapters.postgres

import java.time.Instant
import java.util.UUID
import java.security.MessageDigest
import cats.effect.IO
import cats.syntax.all.*
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.implicits.javatimedrivernative.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.application.*
import run.hallpass.kernel.*

/** Durable connection metadata. All credentials remain in SecretStore. */
final class PostgresConnectionRepository(xa: Transactor[IO]) extends ConnectionRepository[IO]:
  private def tenantProgram[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(xa)

  def create(tenant: TenantId, connection: Connection, secret: SecretReference): IO[Connection] =
    tenantProgram(tenant):
      for
        _ <-
          sql"""insert into connections (id, tenant_id, resource_id, provider, external_account_id, workspace_label, status, token_expires_at, created_at, updated_at)
                     values (${connection.id.toString}::uuid, ${tenant.toString}::uuid, ${connection.resource.toString}::uuid,
                             ${connection.provider}, ${connection.externalAccountId.orElse(connection.accountLabel)}, ${connection.workspaceLabel}, ${statusWire(
              connection.status
            )},
                             ${connection.expiresAt}, ${connection.createdAt}, ${connection.updatedAt})""".update.run
        _ <-
          sql"""insert into credential_references (tenant_id, connection_id, secret_reference, credential_type, expires_at)
                     values (${tenant.toString}::uuid, ${connection.id.toString}::uuid, ${secret.value}, 'SLACK_OAUTH', ${connection.expiresAt})""".update.run
      yield connection

  override def reserve(tenant: TenantId, id: ConnectionId, provider: String, owner: Principal.Human, at: Instant)(using
      cats.ApplicativeError[IO, Throwable]
  ): IO[Unit] =
    tenantProgram(tenant):
      sql"""insert into connections (id, tenant_id, provider, owner_principal_id, status, created_at, updated_at)
             values (${id.toString}::uuid, ${tenant.toString}::uuid, ${provider.toUpperCase}, ${owner.id.toString}::uuid,
                     'CONNECTING', $at, $at)""".update.run.void

  /** One transaction: every check reads first, then every write. A refusal raised by a write (the active external-account index or
    * the resource placement trigger) rolls the whole activation back, so a crash or refusal can never leave an
    * ACTIVE connection without its credential reference or root. */
  override def activateReserved(tenant: TenantId, id: ConnectionId, activation: ConnectionActivation, at: Instant)(using
      cats.Applicative[IO]
  ): IO[Either[ConnectionActivationError, Connection]] =
    val tenantId = tenant.toString
    val connectionId = id.toString
    val kind = activation.rootKind
    val checks: ConnectionIO[Option[ConnectionActivationError]] =
      for
        reserved <-
          sql"""select provider from connections
                 where tenant_id=$tenantId::uuid and id=$connectionId::uuid
                   and owner_principal_id=${activation.owner.id.toString}::uuid and status='CONNECTING'
                 for update""".query[String].option
        accountTaken <-
          sql"""select exists(select 1 from connections
                 where tenant_id=$tenantId::uuid and id <> $connectionId::uuid and status in ('ACTIVE', 'NEEDS_REAUTH')
                   and lower(provider)=${kind.provider.value}
                   and external_account_id=${activation.externalAccountId.value})""".query[Boolean].unique
        rootTaken <-
          if !activation.singleActiveRoot then false.pure[ConnectionIO]
          else
            sql"""select exists(select 1 from resources r join connections c
                     on c.tenant_id=r.tenant_id and c.id=r.connection_id
                   where r.tenant_id=$tenantId::uuid and r.kind=${kind.wire} and r.connection_root
                     and c.status in ('ACTIVE', 'NEEDS_REAUTH') and c.id <> $connectionId::uuid)""".query[Boolean].unique
      yield
        if reserved.forall(_.toLowerCase != kind.provider.value) then Some(ConnectionActivationError.NotReserved)
        else if accountTaken then Some(ConnectionActivationError.AccountAlreadyConnected)
        else if rootTaken then Some(ConnectionActivationError.RootKindInUse)
        else None
    def writes(rootId: ResourceId): ConnectionIO[Unit] =
      for
        _ <- sql"""update connections set external_account_id=${activation.externalAccountId.value},
                          account_label=${activation.accountLabel}, workspace_label=${activation.workspaceLabel},
                          token_expires_at=${activation.expiresAt}, status='ACTIVE', updated_at=$at
                    where tenant_id=$tenantId::uuid and id=$connectionId::uuid and status='CONNECTING'""".update.run
        _ <- sql"""insert into credential_references (tenant_id, connection_id, secret_reference, credential_type, expires_at)
                    values ($tenantId::uuid, $connectionId::uuid, ${activation.secret.value}, ${activation.credentialType},
                            ${activation.expiresAt})""".update.run
        catalog <- PostgresConnectionResources.catalogResource(tenant, kind.provider)
        // Without one catalog parent the trigger refuses the root, which rolls the activation back.
        _ <- sql"""insert into resources (id, tenant_id, resource_type, name, provider, parent_resource_id, external_id,
                                           kind, connection_id, custodian_principal_id)
                    values (${rootId.toString}::uuid, $tenantId::uuid,
                            ${PostgresConnectionResources.resourceTypeWire(kind.resourceType)},
                            ${activation.rootDisplayName}, ${kind.provider.value}, ${catalog.map(_.toString)}::uuid,
                            ${activation.rootExternalId.value}, ${kind.wire}, $connectionId::uuid,
                            ${activation.rootCustodian.map(_.toString)}::uuid)""".update.run
        _ <- sql"""update connections set resource_id=${rootId.toString}::uuid
                    where tenant_id=$tenantId::uuid and id=$connectionId::uuid""".update.run
      yield ()
    def program(rootId: ResourceId): ConnectionIO[Either[ConnectionActivationError, Unit]] =
      checks.flatMap:
        case Some(error) => error.asLeft[Unit].pure[ConnectionIO]
        case None        => writes(rootId).map(_.asRight[ConnectionActivationError])
    IO.delay(ResourceId.random())
      .flatMap(rootId => tenantProgram(tenant)(program(rootId)))
      .recoverWith:
        case failure: java.sql.SQLException =>
          activationRefusal(failure).fold(IO.raiseError(failure))(error => IO.pure(Left(error)))
      .flatMap:
        case Left(error) => IO.pure(Left(error))
        case Right(_) =>
          list(tenant).flatMap: all =>
            IO.fromOption(all.find(_.id == id).map(Right(_)))(IllegalStateException("activated connection is not readable"))

  /** Recognised refusals only: the active external-account index and the resource placement trigger's own messages. Any other
    * database failure, including an unrelated CHECK violation, stays a failed effect. */
  private def activationRefusal(failure: java.sql.SQLException): Option[ConnectionActivationError] =
    val constraint = failure match
      case server: org.postgresql.util.PSQLException =>
        Option(server.getServerErrorMessage).flatMap(message => Option(message.getConstraint))
      case _ => None
    if failure.getSQLState == "23505" && constraint.contains("connections_active_account_idx") then
      Some(ConnectionActivationError.AccountAlreadyConnected)
    else
      PostgresConnectionResources.refusal(failure) match
        case ConnectionResourceError.InvalidPlacement | ConnectionResourceError.InvalidCustody |
            ConnectionResourceError.ConnectionUnavailable =>
          Some(ConnectionActivationError.InvalidPlacement)
        case _ => None

  /** One transaction under the caller's mutation gate. Every check reads first: the connection needs reauthorization,
    * the callback proved its account and root, and for a personal root only the custodian may reauthorize. Only the
    * two runtime-updatable reference columns change, and the connection returns to ACTIVE. */
  override def reauthorize(
      tenant: TenantId,
      id: ConnectionId,
      reauthorization: ConnectionReauthorization,
      at: Instant
  )(using cats.Applicative[IO]): IO[Either[ConnectionActivationError, SecretReference]] =
    val tenantId = tenant.toString
    val connectionId = id.toString
    val program: ConnectionIO[Either[ConnectionActivationError, SecretReference]] =
      for
        current <-
          sql"""select c.external_account_id, r.external_id, r.custodian_principal_id, cr.secret_reference
                  from connections c
                  join resources r on r.tenant_id=c.tenant_id and r.id=c.resource_id and r.connection_root
                  join credential_references cr on cr.tenant_id=c.tenant_id and cr.connection_id=c.id
                 where c.tenant_id=$tenantId::uuid and c.id=$connectionId::uuid and c.status='NEEDS_REAUTH'
                   and cr.credential_type=${reauthorization.credentialType}
                 for update of c, cr""".query[(Option[String], String, Option[UUID], String)].option
        result <- current match
          case None => ConnectionActivationError.NotReserved.asLeft[SecretReference].pure[ConnectionIO]
          case Some((account, root, custodian, previous)) =>
            if !account.contains(reauthorization.externalAccountId.value) || root != reauthorization.rootExternalId.value then
              ConnectionActivationError.AccountMismatch.asLeft[SecretReference].pure[ConnectionIO]
            else if custodian.exists(_.toString != reauthorization.by.id.toString) then
              ConnectionActivationError.NotReserved.asLeft[SecretReference].pure[ConnectionIO]
            else
              SecretReference.parse(previous) match
                case None => new IllegalStateException("invalid stored secret reference").raiseError[ConnectionIO, Either[ConnectionActivationError, SecretReference]]
                case Some(old) =>
                  for
                    _ <- sql"""update credential_references set secret_reference=${reauthorization.secret.value},
                                      expires_at=${reauthorization.expiresAt}
                                where tenant_id=$tenantId::uuid and connection_id=$connectionId::uuid
                                  and secret_reference=$previous""".update.run
                    _ <- sql"""update connections set status='ACTIVE', token_expires_at=${reauthorization.expiresAt},
                                      updated_at=$at
                                where tenant_id=$tenantId::uuid and id=$connectionId::uuid
                                  and status='NEEDS_REAUTH'""".update.run
                  yield old.asRight[ConnectionActivationError]
      yield result
    tenantProgram(tenant)(program)

  override def failReserved(tenant: TenantId, id: ConnectionId, at: Instant)(using cats.Applicative[IO]): IO[Boolean] =
    tenantProgram(tenant):
      sql"""update connections set status='ERROR', updated_at=$at
             where tenant_id=${tenant.toString}::uuid and id=${id.toString}::uuid and status='CONNECTING'""".update.run
        .map(_ == 1)

  def findForResource(tenant: TenantId, resource: ResourceId): IO[Option[Connection]] = tenantProgram(tenant):
    sql"""select id, resource_id, provider, status, external_account_id, account_label, workspace_label, token_expires_at, created_at, updated_at
             from connections where tenant_id=${tenant.toString}::uuid and resource_id=${resource.toString}::uuid and status='ACTIVE'
               and (token_expires_at is null or token_expires_at > now())
             order by updated_at desc limit 1"""
      .query[(UUID, UUID, String, String, Option[String], Option[String], Option[String], Option[Instant], Instant, Instant)]
      .option
      .map(_.flatMap(connectionFromRow))

  /** Disables the connection and, in the same transaction, closes its open selections, so its external resources
    * can be selected under a later connection (the open-selection index spans every connection in the tenant). */
  def disable(tenant: TenantId, id: ConnectionId): IO[Either[ConnectionError, Unit]] = tenantProgram(tenant):
    sql"update connections set status='DISABLED', updated_at=now() where tenant_id=${tenant.toString}::uuid and id=${id.toString}::uuid and status <> 'DISABLED'".update.run
      .flatMap:
        case 1 =>
          sql"""update connection_resources set deselected_at=greatest(now(), selected_at)
                 where tenant_id=${tenant.toString}::uuid and connection_id=${id.toString}::uuid and deselected_at is null"""
            .update.run.as(().asRight[ConnectionError])
        case _ => ConnectionError.NotFound.asLeft[Unit].pure[ConnectionIO]

  def list(tenant: TenantId): IO[Vector[Connection]] = tenantProgram(tenant):
    sql"""select id, resource_id, provider, status, external_account_id, account_label, workspace_label, token_expires_at, created_at, updated_at
             from connections where tenant_id=${tenant.toString}::uuid order by updated_at desc"""
      .query[(UUID, Option[UUID], String, String, Option[String], Option[String], Option[String], Option[Instant], Instant, Instant)]
      .to[Vector]
      .map(
        _.flatMap(row =>
          row._2.flatMap(resource =>
            connectionFromRow((row._1, resource, row._3, row._4, row._5, row._6, row._7, row._8, row._9, row._10))
          )
        )
      )

  def secretReference(tenant: TenantId, id: ConnectionId): IO[Option[SecretReference]] = tenantProgram(tenant):
    sql"""select cr.secret_reference from credential_references cr join connections c
             on c.tenant_id=cr.tenant_id and c.id=cr.connection_id
             where c.tenant_id=${tenant.toString}::uuid and c.id=${id.toString}::uuid and c.status='ACTIVE'"""
      .query[String]
      .option
      .map(_.flatMap(SecretReference.parse))

  /** Atomically select the only eligible Slack connection and its unexpired credential reference. The caller may
    * retrieve the secret only after this complete metadata proof has been obtained. */
  private[postgres] def activeSlackConnectionWithReference(
      tenant: TenantId,
      resource: ResourceId,
      at: Instant
  ): IO[Either[ConnectionError, (Connection, SecretReference)]] =
    tenantProgram(tenant):
      sql"""select c.id, c.resource_id, c.provider, c.status, c.external_account_id, c.account_label, c.workspace_label,
                    c.token_expires_at, c.created_at, c.updated_at, cr.secret_reference
               from connections c
               join credential_references cr
                 on cr.tenant_id=c.tenant_id and cr.connection_id=c.id
              where c.tenant_id=${tenant.toString}::uuid
                and c.resource_id=${resource.toString}::uuid
                and c.provider in ('SLACK', 'slack')
                and c.status='ACTIVE'
                and (c.token_expires_at is null or c.token_expires_at > $at)
                and cr.credential_type='SLACK_OAUTH'
                and (cr.expires_at is null or cr.expires_at > $at)"""
        .query[(UUID, UUID, String, String, Option[String], Option[String], Option[String], Option[Instant], Instant, Instant, String)]
        .to[Vector]
        .map:
          case Vector() => Left(ConnectionError.NotFound)
          case Vector(row) =>
            for
              connection <- connectionFromRow((row._1, row._2, row._3, row._4, row._5, row._6, row._7, row._8, row._9, row._10))
                .toRight(ConnectionError.InvalidState)
              reference <- SecretReference.parse(row._11).toRight(ConnectionError.InvalidState)
            yield connection -> reference
          case _ => Left(ConnectionError.Ambiguous)

  private def statusWire(status: ConnectionStatus): String =
    if status == ConnectionStatus.NeedsReauth then "NEEDS_REAUTH" else status.toString.toUpperCase
  private def connectionFromRow(
      row: (UUID, UUID, String, String, Option[String], Option[String], Option[String], Option[Instant], Instant, Instant)
  ): Option[Connection] =
    for
      id <- ConnectionId.parse(row._1.toString).toOption
      resource <- ResourceId.parse(row._2.toString).toOption
    yield Connection(
      id,
      resource,
      row._3,
      (if row._4 == "NEEDS_REAUTH" then ConnectionStatus.NeedsReauth
       else ConnectionStatus.values.find(_.toString.equalsIgnoreCase(row._4)).getOrElse(ConnectionStatus.Error)),
      row._6,
      row._7,
      row._8,
      row._9,
      row._10,
      row._5
    )

/** Resolves exactly the active connection bound to the authorized resource. */
final class RepositoryConnectionResolver(
    connections: PostgresConnectionRepository,
    secrets: SecretStore[IO],
    clock: Clock[IO] = Clock.system
) extends ConnectionResolver[IO]:
  def activeConnectionFor(
      lease: RedeemedExecutionLease
  ): IO[Either[ConnectionError, ResolvedConnection]] =
    clock.now.flatMap: now =>
      connections.activeSlackConnectionWithReference(lease.tenant, lease.resource, now).flatMap:
        case Left(error) => IO.pure(Left(error))
        case Right((connection, reference)) =>
          secrets
            .get(SecretBinding(lease.tenant, connection.id), reference)
            .map(_.left.map(_ => ConnectionError.MissingCredential).map(ResolvedConnection(connection, _)))

/** Resolves the connection that owns a redeemed lease's resource for a provider whose connection root has selected
  * children (for example a GitHub installation and its repositories), then reads its secret.
  *
  * The connection is found from the lease's resource only. Everything must agree or nothing is returned: the
  * resource's kind and external ID equal the target's, its connection is ACTIVE, unexpired, of the provider, and holds
  * a credential reference of the requested type, and the resource is the connection root or an open selection. A
  * mismatch between lease and target is refused before any query, and the secret is read only after the proof. */
final class RepositoryProviderConnectionResolver(
    xa: Transactor[IO],
    secrets: SecretStore[IO],
    clock: Clock[IO] = Clock.system
) extends ProviderConnectionResolver:
  private type Row = (UUID, Option[UUID], String, String, Option[String], Option[String], Option[String], Option[Instant], Instant, Instant, String)

  def activeConnectionFor[K](
      lease: RedeemedExecutionLease,
      target: SelectedResource[K],
      provider: ProviderId,
      credentialType: String
  ): IO[Either[ConnectionError, ResolvedConnection]] =
    if lease.tenant != target.tenant || lease.resource != target.resource || target.kind.provider != provider then
      IO.pure(Left(ConnectionError.InvalidState))
    else
      clock.now.flatMap: now =>
        select(lease, target, provider, credentialType, now).flatMap:
          case Left(error) => IO.pure(Left(error))
          case Right((connection, reference)) =>
            secrets
              .get(SecretBinding(lease.tenant, connection.id), reference)
              .map(_.left.map(_ => ConnectionError.MissingCredential).map(ResolvedConnection(connection, _)))

  private def select[K](
      lease: RedeemedExecutionLease,
      target: SelectedResource[K],
      provider: ProviderId,
      credentialType: String,
      at: Instant
  ): IO[Either[ConnectionError, (Connection, SecretReference)]] =
    (TenantSession.establish(lease.tenant) *>
      sql"""select c.id, c.resource_id, c.provider, c.status, c.external_account_id, c.account_label, c.workspace_label,
                    c.token_expires_at, c.created_at, c.updated_at, cr.secret_reference
               from resources r
               join connections c on c.tenant_id=r.tenant_id and c.id=r.connection_id
               join credential_references cr on cr.tenant_id=c.tenant_id and cr.connection_id=c.id
              where r.tenant_id=${lease.tenant.toString}::uuid and r.id=${lease.resource.toString}::uuid
                and r.kind=${target.kind.wire} and r.external_id=${target.externalId.value}
                and lower(c.provider)=${provider.value}
                and c.status='ACTIVE'
                and (c.token_expires_at is null or c.token_expires_at > $at)
                and cr.credential_type=$credentialType
                and (cr.expires_at is null or cr.expires_at > $at)
                and (r.connection_root or exists (
                  select 1 from connection_resources selected where selected.tenant_id=r.tenant_id
                    and selected.connection_id=c.id and selected.resource_id=r.id and selected.deselected_at is null))"""
        .query[Row]
        .to[Vector]).transact(xa).map:
      case Vector()    => Left(ConnectionError.NotFound)
      case Vector(row) => decode(row).toRight(ConnectionError.InvalidState)
      case _           => Left(ConnectionError.Ambiguous)

  private def decode(row: Row): Option[(Connection, SecretReference)] =
    for
      id <- ConnectionId.parse(row._1.toString).toOption
      root <- row._2.flatMap(value => ResourceId.parse(value.toString).toOption)
      status <- row._4 match
        case "NEEDS_REAUTH" => Some(ConnectionStatus.NeedsReauth)
        case other          => ConnectionStatus.values.find(_.toString.equalsIgnoreCase(other))
      reference <- SecretReference.parse(row._11)
    yield Connection(id, root, row._3, status, row._6, row._7, row._8, row._9, row._10, row._5) -> reference

/** OAuth state is hashed at rest and consumed atomically before token exchange. */
final class PostgresOAuthStateRepository(xa: Transactor[IO]) extends OAuthStateRepository[IO]:
  private def tenantProgram[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(xa)
  private def hash(state: OAuthState): Array[Byte] =
    MessageDigest.getInstance("SHA-256").digest(state.value.getBytes(java.nio.charset.StandardCharsets.US_ASCII))

  def create(
      tenant: TenantId,
      resource: ResourceId,
      state: OAuthState,
      session: OAuthSessionBinding,
      expiresAt: Instant
  ): IO[Unit] =
    tenantProgram(tenant):
      sql"""insert into oauth_states (tenant_id, state_hash, provider, resource_id, session_binding, expires_at)
             values (${tenant.toString}::uuid, ${hash(state)}, 'SLACK', ${resource.toString}::uuid,
                     ${session.digest.toArray}, $expiresAt)""".update.run.void

  override def createBound(
      tenant: TenantId,
      resource: ResourceId,
      provider: ProviderId,
      intendedConnection: ConnectionId,
      redirectBinding: Array[Byte],
      pkceVerifier: Option[SecretReference],
      state: OAuthState,
      session: OAuthSessionBinding,
      expiresAt: Instant
  ): IO[Unit] = tenantProgram(tenant):
    sql"""insert into oauth_states (tenant_id, state_hash, provider, resource_id, session_binding, expires_at,
                                      intended_connection_id, redirect_binding_digest, pkce_verifier_reference)
           values (${tenant.toString}::uuid, ${hash(state)}, ${provider.value.toUpperCase}, ${resource.toString}::uuid,
                   ${session.digest.toArray}, $expiresAt, ${intendedConnection.toString}::uuid, $redirectBinding,
                   ${pkceVerifier.map(_.value)})""".update.run.void

  override def consumeBound(
      tenant: TenantId,
      provider: ProviderId,
      redirectBinding: Array[Byte],
      state: OAuthState,
      session: OAuthSessionBinding,
      now: Instant
  ): IO[Either[OAuthError, OAuthStateBinding]] =
    val stateHash = hash(state)
    tenantProgram(tenant):
      sql"""update oauth_states set consumed_at=$now
             where tenant_id=${tenant.toString}::uuid and state_hash=$stateHash
               and provider=${provider.value.toUpperCase} and redirect_binding_digest=$redirectBinding
               and session_binding=${session.digest.toArray} and consumed_at is null and expires_at > $now
             returning resource_id, intended_connection_id, pkce_verifier_reference"""
        .query[(UUID, Option[UUID], Option[String])]
        .option
        .flatMap:
          case Some((resource, Some(connection), verifier)) =>
            (
              ResourceId.parse(resource.toString).toOption,
              ConnectionId.parse(connection.toString).toOption,
              verifier.traverse(SecretReference.parse)
            ) match
              case (Some(resourceId), Some(connectionId), Some(verifierReference)) =>
                OAuthStateBinding(resourceId, provider, connectionId, verifierReference).asRight[OAuthError].pure[ConnectionIO]
              case _ => OAuthError.InvalidState.asLeft[OAuthStateBinding].pure[ConnectionIO]
          case Some(_) => OAuthError.InvalidState.asLeft[OAuthStateBinding].pure[ConnectionIO]
          case None =>
            sql"""select case
                     when session_binding <> ${session.digest.toArray} then 'invalid'
                     when consumed_at is not null then 'used'
                     when expires_at <= $now then 'expired'
                     else 'invalid'
                   end from oauth_states
                    where tenant_id=${tenant.toString}::uuid and state_hash=$stateHash"""
              .query[String]
              .option
              .map:
                case Some("used") => Left(OAuthError.StateAlreadyUsed)
                case Some("expired") => Left(OAuthError.ExpiredState)
                case _ => Left(OAuthError.InvalidState)

  /** Single-use consumption. The conditional update is the only path to success, so at most one caller wins, and only
    * from the session that created the state. Another session presenting the state gets `InvalidState` and does not
    * consume it.
    *
    * A loser is classified in a second statement. Under READ COMMITTED each statement takes a new snapshot, so that
    * statement sees the winner's committed `consumed_at`. A classification inside the update's own statement would use
    * the pre-update snapshot and misreport a concurrently consumed state as invalid. */
  def consume(
      tenant: TenantId,
      state: OAuthState,
      session: OAuthSessionBinding,
      now: Instant
  ): IO[Either[OAuthError, ResourceId]] =
    val stateHash = hash(state)
    tenantProgram(tenant):
      sql"""update oauth_states set consumed_at=$now
             where tenant_id=${tenant.toString}::uuid and state_hash=$stateHash
               and session_binding=${session.digest.toArray}
               and consumed_at is null and expires_at > $now
             returning resource_id"""
        .query[UUID]
        .option
        .flatMap:
          case Some(resource) =>
            ResourceId.parse(resource.toString).left.map(_ => OAuthError.InvalidState).pure[ConnectionIO]
          case None =>
            sql"""select case
                     when session_binding <> ${session.digest.toArray} then 'invalid'
                     when consumed_at is not null then 'used'
                     when expires_at <= $now then 'expired'
                     else 'invalid'
                   end
                   from oauth_states
                  where tenant_id=${tenant.toString}::uuid and state_hash=$stateHash"""
              .query[String]
              .option
              .map:
                case Some("used")    => Left(OAuthError.StateAlreadyUsed)
                case Some("expired") => Left(OAuthError.ExpiredState)
                case _               => Left(OAuthError.InvalidState)

  def purgeExpired(tenant: TenantId, now: Instant): IO[Long] =
    // State is an unguessable bearer value; deleting consumed records promptly also prevents unbounded growth.
    tenantProgram(tenant):
      sql"""delete from oauth_states
             where tenant_id=${tenant.toString}::uuid and
               (expires_at <= $now - interval '1 hour' or (consumed_at is not null and consumed_at <= $now - interval '1 hour'))""".update.run
        .map(_.toLong)
