package run.hallpass.application

import java.net.URI
import java.security.SecureRandom
import java.time.Duration
import cats.effect.IO
import run.hallpass.kernel.TenantId

enum LoginFailure:
  case NotConfigured
  case InvalidCallback

  /** Unknown, expired, already used, or started in another browser. */
  case LoginExpired
  case IdentityRejected

  /** The verified account is not linked to an active directory user. There is no just-in-time provisioning. */
  case UnknownIdentity
  case NoMembership
  case TooManyPendingLogins
  case Unavailable

/** A redirect to the identity provider plus the binding cookie the callback must present. */
final case class LoginRedirect(authorizationUri: URI, binding: LoginBinding)

/** A new session. `tenant` is set when the user had exactly one membership; otherwise they select one. */
final case class NewSession(token: SessionToken, tenant: Option[TenantId])

/** Browser login: OIDC authorization code with PKCE, and the development bootstrap login.
  *
  * A login proves who the person is. It never grants authority: the session holds only the directory user and a
  * selected tenant, and every request re-resolves the user's current membership there. */
final class HumanLogin(
    provider: Option[IdentityProvider],
    attempts: LoginAttemptStore,
    sessions: SessionStore,
    humans: HumanAuthenticator[IO],
    policy: SessionPolicy = SessionPolicy.default,
    loginLifetime: Duration = Duration.ofMinutes(10),
    telemetry: Telemetry = Telemetry.noop
):
  private val random = SecureRandom()

  def oidcConfigured: Boolean = provider.nonEmpty

  def start: IO[Either[LoginFailure, LoginRedirect]] =
    provider match
      case None => IO.pure(Left(LoginFailure.NotConfigured))
      case Some(idp) =>
        IO.delay((LoginState.generate(random), LoginBinding.generate(random), OidcNonce.generate(random), PkceVerifier.generate(random)))
          .flatMap: (state, binding, nonce, verifier) =>
            idp.authorizationUri(state, nonce, verifier).flatMap:
              case Left(_) => IO.pure(Left(LoginFailure.Unavailable))
              case Right(uri) =>
                attempts.begin(state.digest, binding.digest, PendingLogin(nonce, verifier), loginLifetime).map:
                  case Left(LoginStoreError.TooManyPendingLogins) => Left(LoginFailure.TooManyPendingLogins)
                  case Left(LoginStoreError.Unavailable)          => Left(LoginFailure.Unavailable)
                  case Right(())                                  => Right(LoginRedirect(uri, binding))

  /** Completes an OIDC callback. The attempt is consumed before the code is redeemed, so a state is usable once, and
    * only with the binding cookie of the browser that started it. */
  def complete(rawState: String, rawCode: String, rawBinding: Option[String]): IO[Either[LoginFailure, NewSession]] =
    telemetry.span(TraceSpan.OidcLogin)(completeOidc(rawState, rawCode, rawBinding)).flatTap(counted(SafeAttribute.Label.of("oidc")))

  private def completeOidc(rawState: String, rawCode: String, rawBinding: Option[String]): IO[Either[LoginFailure, NewSession]] =
    (provider, LoginState.parse(rawState), AuthorizationCode.parse(rawCode), rawBinding.flatMap(LoginBinding.parse)) match
      case (None, _, _, _) => IO.pure(Left(LoginFailure.NotConfigured))
      case (Some(idp), Some(state), Some(code), Some(binding)) =>
        attempts.consume(state.digest, binding.digest).flatMap:
          case Left(_)            => IO.pure(Left(LoginFailure.Unavailable))
          case Right(None)        => IO.pure(Left(LoginFailure.LoginExpired))
          case Right(Some(login)) =>
            idp.verify(code, login).flatMap:
              case Left(IdentityProviderError.Unavailable) => IO.pure(Left(LoginFailure.Unavailable))
              case Left(IdentityProviderError.Rejected)    => IO.pure(Left(LoginFailure.IdentityRejected))
              case Right(identity)                         => open(identity, LoginMethod.Oidc, _ => true)
      case _ => IO.pure(Left(LoginFailure.InvalidCallback))

  /** The development bootstrap login. It signs in as the development identity, which must have exactly one
    * administrator membership. The caller has already checked the bootstrap secret; production never enables it. */
  def developmentSession(identity: ExternalIdentity): IO[Either[LoginFailure, NewSession]] =
    open(identity, LoginMethod.DevelopmentBootstrap, _.role == MembershipRole.Admin)
      .flatTap(counted(SafeAttribute.Label.of("development_bootstrap")))

  private def counted(method: SafeAttribute.Label)(outcome: Either[LoginFailure, NewSession]): IO[Unit] =
    val result = outcome.fold(SafeAttribute.Label.of(_), _ => SafeAttribute.Label.of("succeeded"))
    telemetry.increment(CounterMetric.LoginOutcomes, SafeAttribute.kind(method), SafeAttribute.outcome(result))

  private def open(
      identity: ExternalIdentity,
      method: LoginMethod,
      eligible: TenantMembership => Boolean
  ): IO[Either[LoginFailure, NewSession]] =
    humans.userFor(identity).flatMap:
      case Left(HumanAuthenticationError.Unavailable) => IO.pure(Left(LoginFailure.Unavailable))
      case Left(_)                                    => IO.pure(Left(LoginFailure.UnknownIdentity))
      case Right(user) =>
        humans.memberships(user).flatMap:
          case Left(_) => IO.pure(Left(LoginFailure.Unavailable))
          case Right(current) =>
            current.filter(eligible) match
              case Vector() => IO.pure(Left(LoginFailure.NoMembership))
              case candidates =>
                // Select automatically only when there is no choice to make. The development login requires that.
                val tenant = Option.when(candidates.size == 1)(candidates.head.tenant)
                if method == LoginMethod.DevelopmentBootstrap && tenant.isEmpty then IO.pure(Left(LoginFailure.NoMembership))
                else
                  IO.delay(SessionToken.generate(random)).flatMap: token =>
                    sessions.create(token.lookup, SessionId.random(), user, tenant, method, policy).map:
                      case Right(true)  => Right(NewSession(token, tenant))
                      // The user or membership changed between lookup and creation.
                      case Right(false) => Left(LoginFailure.NoMembership)
                      case Left(_)      => Left(LoginFailure.Unavailable)
