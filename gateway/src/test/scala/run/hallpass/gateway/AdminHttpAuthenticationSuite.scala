package run.hallpass.gateway

import java.net.URI
import com.sun.net.httpserver.Headers
import cats.effect.IO
import cats.effect.kernel.Ref
import java.time.{Duration, Instant}
import cats.syntax.all.*
import io.circe.Json
import munit.CatsEffectSuite
import run.hallpass.application.*
import run.hallpass.kernel.*

final class AdminHttpAuthenticationSuite extends CatsEffectSuite:
  private val bootstrap = "b" * 48
  private val origin = "http://localhost:3000"
  private val host = "localhost:3000"
  private val developmentIdentity = ExternalIdentity.from("urn:hallpass:development", "local-administrator").toOption.get
  private val oidcIdentity = ExternalIdentity.from("https://idp.example.test", "person-1").toOption.get
  private val user = DirectoryUserId.random()
  private val tenant = TenantId.random()
  private val otherTenant = TenantId.random()
  private val principal: Principal.Human = Principal.Human(UserId.random())

  private def headers(values: (String, String)*): Headers =
    val result = new Headers()
    values.foreach { case (name, value) => result.add(name, value) }
    result

  /** The directory as an operator would change it between requests. */
  private final class Directory(
      val users: Ref[IO, Map[ExternalIdentity, DirectoryUserId]],
      val memberships: Ref[IO, Either[DirectoryError, Vector[TenantMembership]]]
  ) extends HumanDirectory[IO]:
    def userFor(identity: ExternalIdentity) = users.get.map(current => Right(current.get(identity)))
    def activeMemberships(value: DirectoryUserId) = memberships.get.map(_.map(_.filter(_.user == value)))
    def active(value: DirectoryUserId): IO[Boolean] = users.get.map(_.values.exists(_ == value))

  private final case class StoredSession(id: SessionId, user: DirectoryUserId, tenant: Option[TenantId], revoked: Boolean)

  /** Mirrors the database functions: sessions need an active user, and a tenant only among current memberships. */
  private final class Sessions(directory: Directory, val state: Ref[IO, Map[SecretDigest, StoredSession]], val down: Ref[IO, Boolean])
      extends SessionStore:
    private def allowed(value: DirectoryUserId, selected: TenantId): IO[Boolean] =
      directory.activeMemberships(value).map(_.exists(_.exists(_.tenant == selected)))
    private def available[A](program: IO[A]): IO[Either[SessionStoreError, A]] =
      down.get.flatMap(if _ then IO.pure(Left(SessionStoreError.Unavailable)) else program.map(Right(_)))
    def create(token: SecretDigest, id: SessionId, value: DirectoryUserId, selected: Option[TenantId], method: LoginMethod, policy: SessionPolicy) =
      available:
        (directory.active(value), selected.traverse(allowed(value, _)).map(_.forall(identity))).tupled.flatMap:
          case (true, true) => state.update(_.updated(token, StoredSession(id, value, selected, false))).as(true)
          case _            => IO.pure(false)
    def resolve(token: SecretDigest) =
      available:
        state.get.map(_.get(token)).flatMap:
          case Some(session) if !session.revoked =>
            directory.active(session.user).map(Option.when(_)(LiveSession(session.id, session.user, session.tenant)))
          case _ => IO.pure(None)
    def selectTenant(token: SecretDigest, selected: TenantId) =
      available:
        state.get.map(_.get(token)).flatMap:
          case Some(session) if !session.revoked =>
            allowed(session.user, selected).flatTap(IO.whenA(_)(state.update(_.updated(token, session.copy(tenant = Some(selected))))))
          case _ => IO.pure(false)
    def revoke(token: SecretDigest) = available(state.update(current => current.get(token).fold(current)(s => current.updated(token, s.copy(revoked = true)))))

  private final class Attempts(val state: Ref[IO, Map[SecretDigest, (SecretDigest, PendingLogin)]]) extends LoginAttemptStore:
    def begin(stateDigest: SecretDigest, binding: SecretDigest, pending: PendingLogin, lifetime: Duration) =
      state.update(_.updated(stateDigest, binding -> pending)).as(Right(()))
    def consume(stateDigest: SecretDigest, binding: SecretDigest) =
      state.modify(current => (current - stateDigest) -> current.get(stateDigest)).map:
        case Some((stored, pending)) if stored.matches(binding) => Right(Some(pending))
        case _                                                  => Right(None)

  /** An identity provider that returns the state in the redirect and checks that the stored nonce comes back. */
  private final class Provider(val outcome: Ref[IO, Either[IdentityProviderError, ExternalIdentity]], val nonces: Ref[IO, Vector[String]])
      extends IdentityProvider:
    def authorizationUri(state: LoginState, nonce: OidcNonce, verifier: PkceVerifier) =
      nonces.update(_ :+ nonce.value).as(Right(URI.create(s"https://idp.example.test/authorize?state=${state.value}&code_challenge=${verifier.challenge}")))
    def verify(code: AuthorizationCode, pending: PendingLogin) =
      nonces.get.flatMap: issued =>
        if issued.contains(pending.nonce.value) then outcome.get else IO.pure(Left(IdentityProviderError.Rejected))

  private final case class Fixture(
      auth: AdminHttpAuthentication,
      directory: Directory,
      sessions: Sessions,
      provider: Provider,
      api: DemoApi
  ):
    def respond(method: String, path: String, requestHeaders: Headers, body: String = ""): IO[DemoApiResponse] =
      DemoHttpServer.managementResponse(api, auth, names, agentPublicUrl, EdgeRequest(method, URI.create(path), requestHeaders, body.getBytes("UTF-8")))

  private val agentPublicUrl = AgentPublicUrl.parse("https://agents.example.test:8443", production = true)
    .fold(error => throw IllegalStateException(error), identity)

  private val names = new TenantNames:
    def nameOf(value: TenantId) = IO.pure(Some(if value == tenant then "Primary" else "Secondary"))

  private def membership(role: MembershipRole = MembershipRole.Admin, in: TenantId = tenant) =
    TenantMembership(user, in, principal, role)

  private def fixture(
      initial: Vector[TenantMembership] = Vector(membership()),
      environment: Map[String, String] = Map("HALLPASS_ADMIN_BOOTSTRAP" -> bootstrap, "HALLPASS_ADMIN_ORIGIN" -> origin),
      clock: Clock[IO] = Clock.system
  ): IO[Fixture] =
    val config = AdminHttpAuthentication.RuntimeConfig
      .fromEnvironment(environment)
      .fold(error => fail(s"expected valid management configuration: $error"), identity)
    for
      users <- Ref.of[IO, Map[ExternalIdentity, DirectoryUserId]](Map(developmentIdentity -> user, oidcIdentity -> user))
      memberships <- Ref.of[IO, Either[DirectoryError, Vector[TenantMembership]]](Right(initial))
      directory = Directory(users, memberships)
      sessions <- (Ref.of[IO, Map[SecretDigest, StoredSession]](Map.empty), Ref.of[IO, Boolean](false)).mapN(Sessions(directory, _, _))
      attempts <- Ref.of[IO, Map[SecretDigest, (SecretDigest, PendingLogin)]](Map.empty).map(Attempts(_))
      provider <- (Ref.of[IO, Either[IdentityProviderError, ExternalIdentity]](Right(oidcIdentity)), Ref.of[IO, Vector[String]](Vector.empty))
        .mapN(Provider(_, _))
      humans = HumanAuthenticator[IO](directory)
      login = HumanLogin(Some(provider), attempts, sessions, humans)
      gate <- SingleProcessTenantExecutionMutationGate.create
    yield Fixture(
      AdminHttpAuthentication.create(config, login, sessions, humans, developmentIdentity, clock),
      directory,
      sessions,
      provider,
      // Repositories are never reached: authorized requests below go to an unknown path, which answers 404.
      DemoApi(null, null, null, null, null, mutationGate = gate)
    )

  private def cookieValue(response: DemoApiResponse, name: String): Option[String] =
    response.cookies.collectFirst { case cookie if cookie.startsWith(s"$name=") => cookie.drop(name.length + 1).takeWhile(_ != ';') }

  private def signIn(f: Fixture): IO[(String, String)] =
    f.respond("POST", AdminHttpAuthentication.BootstrapPath, headers("Host" -> host, "Origin" -> origin, AdminHttpAuthentication.BootstrapHeader -> bootstrap))
      .map: response =>
        assertEquals(response.status, 201)
        val id = cookieValue(response, f.auth.cookies.sessionName).getOrElse(fail("expected a session cookie"))
        id -> response.body.hcursor.get[String]("csrfToken").getOrElse(fail("expected a CSRF token"))

  private def withSession(f: Fixture, id: String, extra: (String, String)*): Headers =
    headers((Vector("Host" -> host, "Origin" -> origin, "Cookie" -> s"${f.auth.cookies.sessionName}=$id") ++ extra)*)

  /** Signed-in control-plane probe: 404 means authorized (the path does not exist); anything else is a rejection. */
  private def probe(f: Fixture, id: String, extra: (String, String)*): IO[(Int, Option[String])] =
    f.respond("POST", "/api/nothing", withSession(f, id, extra*)).map(r => r.status -> r.body.hcursor.get[String]("error").toOption)

  private def oidcLogin(f: Fixture): IO[DemoApiResponse] =
    for
      start <- f.respond("GET", DemoHttpServer.OidcStartPath, headers("Host" -> host))
      binding = cookieValue(start, f.auth.cookies.loginName).getOrElse(fail("expected a login binding cookie"))
      state = start.headers("Location").split("state=")(1).takeWhile(_ != '&')
      callback <- f.respond(
        "GET",
        s"${DemoHttpServer.OidcCallbackPath}?state=$state&code=authorization-code",
        headers("Host" -> host, "Cookie" -> s"${f.auth.cookies.loginName}=$binding")
      )
    yield callback

  test("bootstrap creates a durable session that requires the configured origin and CSRF token") {
    for
      f <- fixture()
      (id, csrf) <- signIn(f)
      allowed <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> csrf)
      missingCsrf <- probe(f, id)
      wrongCsrf <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> ("x" * 43))
      wrongOrigin <- f.respond("GET", "/api/nothing", headers("Host" -> host, "Origin" -> "http://attacker.invalid", "Cookie" -> s"${f.auth.cookies.sessionName}=$id"))
    yield
      assertEquals(allowed, 404 -> Some("not_found"))
      assertEquals(missingCsrf, 403 -> Some("csrf_rejected"))
      assertEquals(wrongCsrf, 403 -> Some("csrf_rejected"))
      assertEquals(wrongOrigin.status, 403)
  }

  test("the session cookie is HttpOnly and Lax, and __Host- and Secure over https") {
    for
      local <- fixture()
      localCookie <- local.respond("POST", AdminHttpAuthentication.BootstrapPath, headers("Host" -> host, "Origin" -> origin, AdminHttpAuthentication.BootstrapHeader -> bootstrap))
      secure <- fixture(environment = Map("HALLPASS_ADMIN_BOOTSTRAP" -> bootstrap, "HALLPASS_ADMIN_ORIGIN" -> "https://admin.example.test"))
      secureCookie <- secure.respond(
        "POST",
        AdminHttpAuthentication.BootstrapPath,
        headers("Host" -> "admin.example.test", "Origin" -> "https://admin.example.test", AdminHttpAuthentication.BootstrapHeader -> bootstrap)
      )
    yield
      val plain = localCookie.cookies.head
      assert(plain.startsWith("hallpass_admin_session=") && plain.contains("HttpOnly") && plain.contains("SameSite=Lax") && !plain.contains("Secure"), plain)
      val hardened = secureCookie.cookies.head
      assert(hardened.startsWith("__Host-hallpass_admin_session=") && hardened.contains("; Secure") && hardened.contains("Path=/"), hardened)
      assert(!hardened.contains("Domain="), hardened)
  }

  test("agent bearer credentials cannot bootstrap or access management routes") {
    for
      f <- fixture()
      (id, csrf) <- signIn(f)
      bootstrapAttempt <- f.auth.bootstrapSession(
        headers("Host" -> host, "Origin" -> origin, AdminHttpAuthentication.BootstrapHeader -> bootstrap, "Authorization" -> "Bearer ac1.not-a-real-token")
      )
      accessAttempt <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> csrf, "Authorization" -> "Bearer ac1.not-a-real-token")
    yield
      assertEquals(bootstrapAttempt.map(_.tenant), Left(AdminHttpAuthentication.Rejection.AgentAuthenticationNotAccepted))
      assertEquals(accessAttempt._1, 401)
  }

  test("the bootstrap login does not exist unless a bootstrap secret is configured") {
    for
      f <- fixture(environment = Map("HALLPASS_OIDC_ISSUER" -> "https://idp.example.test", "HALLPASS_OIDC_CLIENT_ID" -> "hallpass", "HALLPASS_ADMIN_ORIGIN" -> origin))
      attempt <- f.respond("POST", AdminHttpAuthentication.BootstrapPath, headers("Host" -> host, "Origin" -> origin, AdminHttpAuthentication.BootstrapHeader -> bootstrap))
      methods <- f.respond("GET", DemoHttpServer.MethodsPath, headers("Host" -> host))
    yield
      assertEquals(attempt.status, 404)
      assertEquals(attempt.cookies, Vector.empty)
      assertEquals(methods.body, Json.obj("oidc" -> Json.True, "developmentBootstrap" -> Json.False))
  }

  test("a removed membership loses access on the next request") {
    for
      f <- fixture()
      (id, csrf) <- signIn(f)
      before <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> csrf)
      _ <- f.directory.memberships.set(Right(Vector.empty))
      removed <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> csrf)
    yield
      assertEquals(before._1, 404)
      assertEquals(removed, 401 -> Some("authentication_required"))
  }

  test("a disabled user cannot sign in, and a signed-in user who is disabled loses access") {
    for
      f <- fixture()
      (id, csrf) <- signIn(f)
      // The directory omits a disabled user from both lookups, and the session store stops resolving their sessions.
      _ <- f.directory.users.set(Map.empty) *> f.directory.memberships.set(Right(Vector.empty))
      request <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> csrf)
      bootstrapLogin <- f.auth.bootstrapSession(headers("Host" -> host, "Origin" -> origin, AdminHttpAuthentication.BootstrapHeader -> bootstrap))
      oidc <- oidcLogin(f)
    yield
      assertEquals(request._1, 401)
      assertEquals(bootstrapLogin.map(_.tenant), Left(AdminHttpAuthentication.Rejection.NoMembership))
      assertEquals(oidc.headers.get("Location"), Some("/?login=no_access"))
      assertEquals(cookieValue(oidc, f.auth.cookies.sessionName), None)
  }

  test("bootstrap requires exactly one administrator membership") {
    for
      memberOnly <- fixture(Vector(membership(MembershipRole.Member)))
      ambiguous <- fixture(Vector(membership(), membership(in = otherTenant)))
      none <- fixture(Vector.empty)
      results <- Vector(memberOnly, ambiguous, none).traverse(f =>
        f.auth.bootstrapSession(headers("Host" -> host, "Origin" -> origin, AdminHttpAuthentication.BootstrapHeader -> bootstrap)).map(_.map(_.tenant))
      )
    yield assertEquals(results, Vector.fill(3)(Left(AdminHttpAuthentication.Rejection.NoMembership)))
  }

  test("a directory or session-store outage fails closed as unavailable and keeps the session") {
    for
      f <- fixture()
      (id, csrf) <- signIn(f)
      _ <- f.directory.memberships.set(Left(DirectoryError.Unavailable))
      directoryOutage <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> csrf)
      _ <- f.directory.memberships.set(Right(Vector(membership())))
      _ <- f.sessions.down.set(true)
      storeOutage <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> csrf)
      _ <- f.sessions.down.set(false)
      recovered <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> csrf)
    yield
      assertEquals(directoryOutage._1, 503)
      assertEquals(storeOutage._1, 503)
      assertEquals(recovered._1, 404)
  }

  test("members cannot use the control plane, and the Slack OAuth callback requires a session") {
    for
      f <- fixture()
      (id, _) <- signIn(f)
      _ <- f.directory.memberships.set(Right(Vector(membership(MembershipRole.Member))))
      member <- f.respond("GET", "/api/agents", withSession(f, id))
      callback <- f.respond("GET", "/api/oauth/slack/callback?state=x&code=y", headers("Host" -> host))
    yield
      assertEquals(member.status, 403)
      assertEquals(member.body.hcursor.get[String]("error"), Right("administrator_required"))
      assertEquals(callback.status, 401, "the OAuth callback must not bypass the session")
  }

  test("OIDC login binds the callback to the starting browser, creates a session, and selects the only tenant") {
    for
      f <- fixture()
      callback <- oidcLogin(f)
      id = cookieValue(callback, f.auth.cookies.sessionName).getOrElse(fail("expected a session cookie"))
      view <- f.respond("GET", DemoHttpServer.SessionPath, withSession(f, id))
      csrf = view.body.hcursor.get[String]("csrfToken").getOrElse(fail("expected a CSRF token"))
      allowed <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> csrf)
    yield
      assertEquals(callback.status, 303)
      assertEquals(callback.headers.get("Location"), Some("/admin"))
      assert(callback.cookies.exists(_.startsWith(s"${f.auth.cookies.loginName}=;")), "the login binding cookie is cleared")
      assertEquals(view.body.hcursor.downField("tenant").get[String]("tenantId"), Right(tenant.toString))
      assertEquals(view.body.hcursor.downField("tenant").get[String]("name"), Right("Primary"))
      assertEquals(view.body.hcursor.get[String]("agentApiUrl"), Right("https://agents.example.test:8443"))
      assertEquals(allowed._1, 404)
  }

  test("an OIDC callback without the starting browser's binding, or replayed, creates no session") {
    for
      f <- fixture()
      start <- f.respond("GET", DemoHttpServer.OidcStartPath, headers("Host" -> host))
      binding = cookieValue(start, f.auth.cookies.loginName).getOrElse(fail("expected a login binding cookie"))
      state = start.headers("Location").split("state=")(1).takeWhile(_ != '&')
      callbackPath = s"${DemoHttpServer.OidcCallbackPath}?state=$state&code=authorization-code"
      // An attacker's browser has the state (for example from a log) but not the victim's binding cookie. The attempt
      // is consumed, so the victim's own completion fails too: a leaked state cannot be used by anyone.
      foreign <- f.respond("GET", callbackPath, headers("Host" -> host, "Cookie" -> s"${f.auth.cookies.loginName}=${"z" * 43}"))
      replay <- f.respond("GET", callbackPath, headers("Host" -> host, "Cookie" -> s"${f.auth.cookies.loginName}=$binding"))
      missing <- f.respond("GET", callbackPath, headers("Host" -> host))
      stored <- f.sessions.state.get
    yield
      assertEquals(foreign.headers.get("Location"), Some("/?login=failed"))
      assertEquals(replay.headers.get("Location"), Some("/?login=failed"))
      assertEquals(missing.headers.get("Location"), Some("/?login=failed"))
      assert(Vector(foreign, replay, missing).forall(cookieValue(_, f.auth.cookies.sessionName).isEmpty))
      assertEquals(stored, Map.empty)
  }

  test("OIDC rejection, an unknown account, and a provider outage return to sign-in with a coarse reason") {
    for
      f <- fixture()
      _ <- f.provider.outcome.set(Left(IdentityProviderError.Rejected))
      rejected <- oidcLogin(f)
      _ <- f.provider.outcome.set(Right(ExternalIdentity.from("https://idp.example.test", "stranger").toOption.get))
      unknown <- oidcLogin(f)
      _ <- f.provider.outcome.set(Left(IdentityProviderError.Unavailable))
      outage <- oidcLogin(f)
    yield
      assertEquals(rejected.headers.get("Location"), Some("/?login=failed"))
      assertEquals(unknown.headers.get("Location"), Some("/?login=no_access"))
      assertEquals(outage.headers.get("Location"), Some("/?login=unavailable"))
  }

  test("an OAuth error callback, with or without a state, creates no session and clears the login binding") {
    for
      f <- fixture()
      start <- f.respond("GET", DemoHttpServer.OidcStartPath, headers("Host" -> host))
      binding = cookieValue(start, f.auth.cookies.loginName).getOrElse(fail("expected a login binding cookie"))
      state = start.headers("Location").split("state=")(1).takeWhile(_ != '&')
      bound = headers("Host" -> host, "Cookie" -> s"${f.auth.cookies.loginName}=$binding")
      // The person declined consent at Google. The provider's description must not be reflected back.
      denied <- f.respond("GET", s"${DemoHttpServer.OidcCallbackPath}?error=access_denied&error_description=%3Cscript%3E&state=$state", bound)
      stateless <- f.respond("GET", s"${DemoHttpServer.OidcCallbackPath}?error=access_denied", headers("Host" -> host))
      // The error response cleared the binding cookie, so a later code for this state from any browser without it fails.
      unbound <- f.respond("GET", s"${DemoHttpServer.OidcCallbackPath}?state=$state&code=authorization-code", headers("Host" -> host))
      stored <- f.sessions.state.get
    yield
      Vector(denied, stateless, unbound).foreach: response =>
        assertEquals(response.status, 303)
        assertEquals(response.headers.get("Location"), Some("/?login=failed"))
        assertEquals(cookieValue(response, f.auth.cookies.sessionName), None)
      assert(denied.cookies.exists(_.startsWith(s"${f.auth.cookies.loginName}=;")), "the login binding cookie is cleared")
      assertEquals(stored, Map.empty)
  }

  test("a person with several memberships selects a tenant, and only one they belong to") {
    for
      f <- fixture(Vector(membership(), membership(MembershipRole.Member, in = otherTenant)))
      callback <- oidcLogin(f)
      id = cookieValue(callback, f.auth.cookies.sessionName).getOrElse(fail("expected a session cookie"))
      view <- f.respond("GET", DemoHttpServer.SessionPath, withSession(f, id))
      csrf = view.body.hcursor.get[String]("csrfToken").getOrElse(fail("expected a CSRF token"))
      unselected <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> csrf)
      foreign <- f.respond("POST", DemoHttpServer.SessionTenantPath, withSession(f, id, AdminHttpAuthentication.CsrfHeader -> csrf), s"""{"tenantId":"${TenantId.random()}"}""")
      noCsrf <- f.respond("POST", DemoHttpServer.SessionTenantPath, withSession(f, id), s"""{"tenantId":"$tenant"}""")
      selected <- f.respond("POST", DemoHttpServer.SessionTenantPath, withSession(f, id, AdminHttpAuthentication.CsrfHeader -> csrf), s"""{"tenantId":"$tenant"}""")
      allowed <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> csrf)
      memberTenant <- f.respond("POST", DemoHttpServer.SessionTenantPath, withSession(f, id, AdminHttpAuthentication.CsrfHeader -> csrf), s"""{"tenantId":"$otherTenant"}""")
      asMember <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> csrf)
    yield
      assertEquals(view.body.hcursor.downField("tenant").focus, Some(Json.Null))
      assertEquals(view.body.hcursor.downField("memberships").values.map(_.size), Some(2))
      assertEquals(unselected, 403 -> Some("tenant_selection_required"))
      assertEquals(foreign.status, 403)
      assertEquals(noCsrf.status, 403)
      assertEquals(selected.status, 204)
      assertEquals(allowed._1, 404)
      assertEquals(memberTenant.status, 204)
      assertEquals(asMember, 403 -> Some("administrator_required"))
  }

  test("logout revokes the session everywhere and clears the cookie") {
    for
      f <- fixture()
      (id, csrf) <- signIn(f)
      withoutCsrf <- f.respond("POST", DemoHttpServer.LogoutPath, withSession(f, id))
      logout <- f.respond("POST", DemoHttpServer.LogoutPath, withSession(f, id, AdminHttpAuthentication.CsrfHeader -> csrf))
      after <- probe(f, id, AdminHttpAuthentication.CsrfHeader -> csrf)
      again <- f.respond("POST", DemoHttpServer.LogoutPath, withSession(f, id, AdminHttpAuthentication.CsrfHeader -> csrf))
    yield
      assertEquals(withoutCsrf.status, 403)
      assertEquals(logout.status, 204)
      assert(logout.cookies.exists(_.contains("Max-Age=0")))
      assertEquals(after._1, 401)
      assertEquals(again.status, 204)
  }

  test("management login configuration fails closed") {
    import AdminHttpAuthentication.RuntimeConfigError
    def parse(values: (String, String)*) = AdminHttpAuthentication.RuntimeConfig.fromEnvironment(values.toMap).map(_ => ())
    assertEquals(parse(), Left(RuntimeConfigError.NoLoginMethod))
    assertEquals(parse("HALLPASS_ADMIN_BOOTSTRAP" -> "short"), Left(RuntimeConfigError.InvalidBootstrap))
    assertEquals(parse("HALLPASS_ADMIN_BOOTSTRAP" -> ("x" * 48), "HALLPASS_ADMIN_ORIGIN" -> "file:///tmp/not-an-origin"), Left(RuntimeConfigError.InvalidOrigin))
    assert(parse("HALLPASS_OIDC_ISSUER" -> "https://idp.example.test").isLeft, "a client ID is required")
    assertEquals(
      parse("HALLPASS_ENV" -> "production", "HALLPASS_OIDC_ISSUER" -> "https://idp.example.test", "HALLPASS_OIDC_CLIENT_ID" -> "hallpass"),
      Left(RuntimeConfigError.InsecureOrigin)
    )
    assert(
      parse(
        "HALLPASS_ENV" -> "production",
        "HALLPASS_ADMIN_ORIGIN" -> "https://admin.example.test",
        "HALLPASS_OIDC_ISSUER" -> "http://idp.example.test",
        "HALLPASS_OIDC_CLIENT_ID" -> "hallpass"
      ).isLeft,
      "production requires an https issuer"
    )
    assertEquals(
      parse("HALLPASS_ADMIN_BOOTSTRAP" -> ("x" * 48), "HALLPASS_ADMIN_SESSION_IDLE_MINUTES" -> "600", "HALLPASS_ADMIN_SESSION_ABSOLUTE_MINUTES" -> "60").left.map(_.getClass),
      Left(classOf[RuntimeConfigError.InvalidSessionLifetime])
    )
    assertEquals(
      parse("HALLPASS_ENV" -> "production", "HALLPASS_ADMIN_ORIGIN" -> "https://admin.example.test", "HALLPASS_OIDC_ISSUER" -> "https://idp.example.test", "HALLPASS_OIDC_CLIENT_ID" -> "hallpass"),
      Right(())
    )
  }

  test("the injected clock is read when a previously built authorization effect runs") {
    // Session expiry is decided by the database clock (see PostgresBrowserSessionsSuite). The gateway still stamps each
    // authenticated request with the injected clock, read at execution rather than when the effect is built.
    val at = Instant.parse("2026-09-27T12:00:00Z")
    for
      time <- Ref.of[IO, Instant](at)
      clock = new Clock[IO]:
        def now = time.get
      f <- fixture(clock = clock)
      (id, csrf) <- signIn(f)
      pending = f.auth.authorize("POST", withSession(f, id, AdminHttpAuthentication.CsrfHeader -> csrf))
      first <- pending
      _ <- time.set(at.plus(Duration.ofHours(1)))
      second <- pending
    yield
      assertEquals(first.map(_._1.authenticatedAt), Right(at))
      assertEquals(second.map(_._1.authenticatedAt), Right(at.plus(Duration.ofHours(1))))
  }

  test("repeating a login effect yields fresh state, binding, and session secrets") {
    for
      f <- fixture()
      start = f.respond("GET", DemoHttpServer.OidcStartPath, headers("Host" -> host))
      first <- start
      second <- start
      (firstSession, _) <- signIn(f)
      (secondSession, _) <- signIn(f)
    yield
      assertNotEquals(first.headers.get("Location"), second.headers.get("Location"))
      assertNotEquals(cookieValue(first, f.auth.cookies.loginName), cookieValue(second, f.auth.cookies.loginName))
      assertNotEquals(firstSession, secondSession)
  }

