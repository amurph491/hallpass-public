package run.hallpass.adapters.github

import java.net.URI
import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}
import cats.effect.IO
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.application.*
import run.hallpass.kernel.{ConnectionId, ResourceId}

final class GitHubConnectorSuite extends CatsEffectSuite:
  private val UserSecretText = "ghu_stub_user_token_value"
  private val registration = GitHubAppRegistration(42L, "Iv1.client", "hallpass-app")
  private val endpoints = GitHubEndpoints.DotCom
  private val redirect = URI.create("https://hallpass.example/oauth/callback")
  private val state = OAuthState.parse("a" * 43).get
  private val installation = GitHubInstallationId.from(777L).get

  private def userToken = GitHubUserToken(UserSecretText)
  private def minted = MintedInstallationToken("ghs_minted", java.time.Instant.EPOCH, Vector.empty, Map.empty)

  private final class Stub(
      val code: IO[Either[GitHubApiError, GitHubUserToken]] = IO.pure(Right(userToken)),
      val access: IO[Either[GitHubApiError, Boolean]] = IO.pure(Right(true)),
      val lookup: IO[Either[GitHubApiError, GitHubInstallationAccount]] =
        IO.pure(Right(GitHubInstallationAccount(installation, 9L, "acme", "Organization"))),
      val mint: IO[Either[GitHubApiError, MintedInstallationToken]] = IO.pure(Right(minted)),
      val repos: IO[Either[GitHubApiError, Vector[GitHubRepositorySummary]]] = IO.pure(Right(Vector.empty))
  ) extends GitHubAppApi:
    val calls = AtomicInteger(0)
    val lookups = AtomicInteger(0)
    val mintedWith = AtomicReference[(Option[Vector[GitHubRepositoryId]], Set[GitHubPermission])]()
    def installationToken(
        i: GitHubInstallationId,
        r: Option[Vector[GitHubRepositoryId]],
        p: Set[GitHubPermission]
    ): IO[Either[GitHubApiError, MintedInstallationToken]] =
      calls.incrementAndGet(); mintedWith.set((r, p)); mint
    def installation(id: GitHubInstallationId): IO[Either[GitHubApiError, GitHubInstallationAccount]] =
      calls.incrementAndGet(); lookups.incrementAndGet(); lookup
    def installationRepositories(
        token: MintedInstallationToken,
        limit: Int
    ): IO[Either[GitHubApiError, Vector[GitHubRepositorySummary]]] =
      calls.incrementAndGet(); repos
    def exchangeUserCode(c: String, r: URI): IO[Either[GitHubApiError, GitHubUserToken]] =
      calls.incrementAndGet(); code
    def userCanAccessInstallation(u: GitHubUserToken, i: GitHubInstallationId): IO[Either[GitHubApiError, Boolean]] =
      calls.incrementAndGet(); access

  private def connector(stub: Stub) = GitHubConnector(registration, stub, endpoints, redirect)
  private def callback(params: Map[String, String]) = OAuthCallback(state, "the-code", params)
  private def okParams = Map("installation_id" -> "777", "setup_action" -> "install")

  private def repo(id: Long, name: String) =
    GitHubRepositorySummary(GitHubRepositoryId.from(id).get, GitHubRepositoryName.parse(name).get)

  private def root(kind: String = GitHub.installation.wire, external: String = "777") =
    ConnectionResource(
      ResourceId.random(),
      ConnectionId.random(),
      kind,
      ExternalId.parse(external).get,
      "acme",
      ResourceId.random(),
      None,
      None
    )

  private def record(reg: String = registration.registrationKey, id: Long = 777L) =
    GitHubInstallationRecord.encode(GitHubInstallationRecord(reg, GitHubInstallationId.from(id).get))

  private def text(secret: ProviderSecret) = String(ProviderSecret.bytes(secret), "UTF-8")

  test("authorization URL has the install path and the state") {
    connector(Stub()).authorizationUri(state).map: uri =>
      assertEquals(uri.toString, s"https://github.com/apps/hallpass-app/installations/new?state=${"a" * 43}")
  }

  test("authorization URL percent-encodes the state value") {
    val odd = OAuthState.parse("a" * 42 + "-_").get
    connector(Stub()).authorizationUri(odd).map(uri => assert(uri.toString.endsWith("state=" + "a" * 42 + "-_")))
  }

  test("exchange verifies and returns the specified grant without the user token") {
    connector(Stub()).exchange(callback(okParams)).map: result =>
      val grant = result.toOption.get
      assertEquals(
        GitHubInstallationRecord.decode(grant.secret),
        Right(GitHubInstallationRecord(registration.registrationKey, installation))
      )
      assert(!text(grant.secret).contains(UserSecretText))
      assert(!grant.toString.contains(UserSecretText))
      assertEquals(grant.externalAccountId, GitHubConnector.externalAccountId(installation))
      assertEquals(grant.rootExternalId.value, "777")
      assertEquals(grant.rootDisplayName, "acme")
      assertEquals(grant.accountLabel, Some("acme"))
      assertEquals(grant.workspaceLabel, Some("Organization"))
      assertEquals(grant.expiresAt, None)
  }

  test("exchange accepts setup_action=update and an absent setup_action") {
    for
      a <- connector(Stub()).exchange(callback(Map("installation_id" -> "777", "setup_action" -> "update")))
      b <- connector(Stub()).exchange(callback(Map("installation_id" -> "777")))
    yield
      assert(a.isRight)
      assert(b.isRight)
  }

  for bad <- Seq(None, Some("abc"), Some("0"), Some("-5"), Some(""), Some("12 3"), Some("0777")) do
    test(s"exchange refuses installation_id ${bad.fold("missing")(v => s"'$v'")} without calling GitHub") {
      val stub = Stub()
      val params = bad.fold(Map.empty[String, String])(v => Map("installation_id" -> v))
      connector(stub).exchange(callback(params)).map: result =>
        assertEquals(result.left.toOption, Some(OAuthError.InvalidProviderResponse))
        assertEquals(stub.calls.get, 0)
    }

  test("exchange refuses setup_action=request and unknown actions without calling GitHub") {
    val stub = Stub()
    for
      a <- connector(stub).exchange(callback(Map("installation_id" -> "777", "setup_action" -> "request")))
      b <- connector(stub).exchange(callback(Map("installation_id" -> "777", "setup_action" -> "other")))
    yield
      assertEquals(a.left.toOption, Some(OAuthError.ProviderRejected))
      assertEquals(b.left.toOption, Some(OAuthError.ProviderRejected))
      assertEquals(stub.calls.get, 0)
  }

  test("exchange rejects a failed code exchange") {
    val stub = Stub(code = IO.pure(Left(GitHubApiError.Rejected)))
    connector(stub).exchange(callback(okParams)).map: result =>
      assertEquals(result.left.toOption, Some(OAuthError.ProviderRejected))
      assertEquals(stub.calls.get, 1)
  }

  test("exchange rejects an installation the user cannot access and never looks it up") {
    val stub = Stub(access = IO.pure(Right(false)))
    connector(stub).exchange(callback(okParams)).map: result =>
      assertEquals(result.left.toOption, Some(OAuthError.ProviderRejected))
      assertEquals(stub.lookups.get, 0)
  }

  test("exchange rejects a failed access check without looking up the installation") {
    val stub = Stub(access = IO.pure(Left(GitHubApiError.Timeout)))
    connector(stub).exchange(callback(okParams)).map: result =>
      assertEquals(result.left.toOption, Some(OAuthError.ProviderRejected))
      assertEquals(stub.lookups.get, 0)
  }

  test("exchange rejects an installation GitHub cannot find") {
    val stub = Stub(lookup = IO.pure(Left(GitHubApiError.NotFound)))
    connector(stub).exchange(callback(okParams)).map(r => assertEquals(r.left.toOption, Some(OAuthError.ProviderRejected)))
  }

  for (label, login) <- Seq("blank" -> "   ", "empty" -> "", "overlong" -> ("a" * 101), "control character" -> "ac\nme") do
    test(s"exchange rejects a $label account login") {
      val stub = Stub(lookup = IO.pure(Right(GitHubInstallationAccount(installation, 9L, login, "User"))))
      connector(stub).exchange(callback(okParams)).map(r => assertEquals(r.left.toOption, Some(OAuthError.InvalidProviderResponse)))
    }

  test("a throwing app API becomes ProviderRejected and leaks no message") {
    val leak = "ghp_SECRET_LOOKING_MESSAGE"
    val stubs = List(
      Stub(code = IO.raiseError(RuntimeException(leak))),
      Stub(access = IO.raiseError(RuntimeException(leak))),
      Stub(lookup = IO.raiseError(RuntimeException(leak))),
      Stub(code = IO.delay(throw RuntimeException(leak)))
    )
    stubs.traverse_ : stub =>
      connector(stub).exchange(callback(okParams)).map: result =>
        assertEquals(result.left.toOption, Some(OAuthError.ProviderRejected))
        assert(!result.toString.contains(leak))
  }

  test("selectable resources are mapped, deduplicated, and sorted; minted for the installation with metadata only") {
    val stub = Stub(repos =
      IO.pure(Right(Vector(repo(3, "acme/zeta"), repo(1, "acme/alpha"), repo(3, "acme/zeta"), repo(2, "acme/beta"))))
    )
    connector(stub).selectableResources(record(), root()).map: result =>
      val items = result.toOption.get
      assertEquals(items.map(_.displayName), Vector("acme/alpha", "acme/beta", "acme/zeta"))
      assertEquals(items.map(_.externalId.value), Vector("1", "2", "3"))
      assert(items.forall(_.kind eq GitHub.repository))
      assert(items.forall(_.parentExternalId.value == "777"))
      assertEquals(stub.mintedWith.get, (None, Set(GitHubPermission.MetadataRead)))
  }

  private def refused(secret: ProviderSecret, r: ConnectionResource) =
    val stub = Stub(repos = IO.pure(Right(Vector(repo(1, "acme/alpha")))))
    connector(stub).selectableResources(secret, r).map: result =>
      assertEquals(result.left.toOption, Some(OAuthError.InvalidState))
      assertEquals(stub.calls.get, 0)

  test("selectable resources refuse a record for another registration")(refused(record(reg = "platform:github.com:99"), root()))
  test("selectable resources refuse a record for another installation")(refused(record(id = 778L), root()))
  test("selectable resources refuse a root of the wrong kind")(refused(record(), root(kind = "github.repository")))
  test("selectable resources refuse a root with another external ID")(refused(record(), root(external = "778")))
  test("selectable resources refuse a malformed record")(refused(ProviderSecret.fromUtf8("not json"), root()))

  test("selectable resources reject a mint failure and a listing failure") {
    val mintFail = Stub(mint = IO.pure(Left(GitHubApiError.Forbidden)))
    val listFail = Stub(repos = IO.pure(Left(GitHubApiError.RateLimited)))
    for
      a <- connector(mintFail).selectableResources(record(), root())
      b <- connector(listFail).selectableResources(record(), root())
    yield
      assertEquals(a.left.toOption, Some(OAuthError.ProviderRejected))
      assertEquals(b.left.toOption, Some(OAuthError.ProviderRejected))
  }
