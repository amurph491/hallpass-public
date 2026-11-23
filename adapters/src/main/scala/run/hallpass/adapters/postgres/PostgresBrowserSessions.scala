package run.hallpass.adapters.postgres

import java.time.Duration
import java.util.UUID
import cats.effect.IO
import cats.syntax.all.*
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.application.*
import run.hallpass.kernel.*

/** Durable browser sessions and pending OIDC logins, shared by every API instance.
  *
  * Both are pre-tenant (a cookie and an OIDC callback carry no tenant), so they live in the V13 directory tables and are
  * reached only through its `SECURITY DEFINER` functions. Only digests of browser secrets are passed in. The database
  * clock decides every expiry. Database failures are reported as unavailable, never as "no session". */
final class PostgresBrowserSessions(xa: Transactor[IO]) extends SessionStore, LoginAttemptStore:

  def create(
      token: SecretDigest,
      id: SessionId,
      user: DirectoryUserId,
      tenant: Option[TenantId],
      method: LoginMethod,
      policy: SessionPolicy
  ): IO[Either[SessionStoreError, Boolean]] =
    val methodWire = method match
      case LoginMethod.Oidc                 => "OIDC"
      case LoginMethod.DevelopmentBootstrap => "DEVELOPMENT_BOOTSTRAP"
    sql"""select authai_create_session(
            ${token.toArray}, ${id.value}, ${user.toString}::uuid, ${tenant.map(_.toString)}::uuid, $methodWire,
            ${seconds(policy.absoluteLifetime)}, ${seconds(policy.idleTimeout)})"""
      .query[Boolean]
      .unique
      .transact(xa)
      .map(Right(_))
      .handleError(_ => Left(SessionStoreError.Unavailable))

  def resolve(token: SecretDigest): IO[Either[SessionStoreError, Option[LiveSession]]] =
    sql"select session_id, user_id, tenant_id from authai_resolve_session(${token.toArray})"
      .query[(UUID, UUID, Option[UUID])]
      .option
      .transact(xa)
      .map:
        case None => Right(None)
        case Some((session, user, tenant)) =>
          // A row that does not decode is an explicit failure, never "signed out" and never "no tenant selected".
          (for
            parsedUser <- DirectoryUserId.parse(user.toString).toOption
            parsedTenant <- tenant match
              case None        => Some(None)
              case Some(value) => TenantId.parse(value.toString).toOption.map(Some(_))
          yield LiveSession(SessionId.fromUuid(session), parsedUser, parsedTenant)).map(Some(_)).toRight(SessionStoreError.Unavailable)
      .handleError(_ => Left(SessionStoreError.Unavailable))

  def selectTenant(token: SecretDigest, tenant: TenantId): IO[Either[SessionStoreError, Boolean]] =
    sql"select authai_select_session_tenant(${token.toArray}, ${tenant.toString}::uuid)"
      .query[Boolean]
      .unique
      .transact(xa)
      .map(Right(_))
      .handleError(_ => Left(SessionStoreError.Unavailable))

  def revoke(token: SecretDigest): IO[Either[SessionStoreError, Unit]] =
    // The function returns void; counting its single row avoids decoding a void column.
    sql"select count(*) from authai_revoke_session(${token.toArray})"
      .query[Long]
      .unique
      .transact(xa)
      .as(Right(()))
      .handleError(_ => Left(SessionStoreError.Unavailable))

  def begin(
      state: SecretDigest,
      binding: SecretDigest,
      pending: PendingLogin,
      lifetime: Duration
  ): IO[Either[LoginStoreError, Unit]] =
    sql"""select authai_begin_login(${state.toArray}, ${binding.toArray}, ${pending.nonce.value},
            ${pending.verifier.value}, ${seconds(lifetime)})"""
      .query[Boolean]
      .unique
      .transact(xa)
      .map(accepted => Either.cond(accepted, (), LoginStoreError.TooManyPendingLogins))
      .handleError(_ => Left(LoginStoreError.Unavailable))

  def consume(state: SecretDigest, binding: SecretDigest): IO[Either[LoginStoreError, Option[PendingLogin]]] =
    sql"select nonce, code_verifier from authai_consume_login_attempt(${state.toArray}, ${binding.toArray})"
      .query[(String, String)]
      .option
      .transact(xa)
      .map:
        case None => Right(None)
        case Some((nonce, verifier)) =>
          (OidcNonce.parse(nonce), PkceVerifier.parse(verifier)).mapN(PendingLogin(_, _)).map(Some(_)).toRight(LoginStoreError.Unavailable)
      .handleError(_ => Left(LoginStoreError.Unavailable))

  private def seconds(duration: Duration): Int = Math.toIntExact(duration.getSeconds)
