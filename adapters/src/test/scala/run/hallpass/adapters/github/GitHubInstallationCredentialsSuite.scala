package run.hallpass.application:
  import java.time.{Duration, Instant}
  import cats.effect.IO
  import io.circe.Json
  import run.hallpass.adapters.github.{GitHub, GitHubExecutorAudience}
  import run.hallpass.kernel.*
  import run.hallpass.kernel.authorization.*

  /** Test-only access to `private[application]` constructors for the GitHub credential strategy suite. */
  object GitHubCredentialsTestSupport:
    val tenant: TenantId = TenantId.random()
    private val agentId = AgentId.random()
    val issuedAt: Instant = Instant.parse("2026-09-01T12:00:00Z")
    val catalog: Resource = Resource(ResourceId.random(), tenant, ResourceType.Provider, None, "github", None)
    val installation: Resource =
      Resource(ResourceId.random(), tenant, ResourceType.Account, Some(catalog.id), "4242", None)
    val repository: Resource =
      Resource(ResourceId.random(), tenant, ResourceType.Repository, Some(installation.id), "1001", None)
    val sibling: Resource =
      Resource(ResourceId.random(), tenant, ResourceType.Repository, Some(installation.id), "1002", None)

    private def selected(resource: Resource): SelectedResource[GitHub.Repository] =
      SelectedResource.trusted(
        GitHub.repository,
        ExternalId.parse(resource.externalId).getOrElse(throw IllegalStateException("external id")),
        ResourceScope.fromPath(Vector(resource, installation, catalog)).getOrElse(throw IllegalStateException("scope"))
      )

    val target: SelectedResource[GitHub.Repository] = selected(repository)
    val siblingTarget: SelectedResource[GitHub.Repository] = selected(sibling)
    /** A scope that skips the installation root: the strategy must not trust it. */
    val rootlessTarget: SelectedResource[GitHub.Repository] =
      val detached = Resource(repository.id, tenant, ResourceType.Repository, Some(catalog.id), "1001", None)
      SelectedResource.trusted(
        GitHub.repository,
        ExternalId.parse("1001").getOrElse(throw IllegalStateException("external id")),
        ResourceScope.fromPath(Vector(detached, catalog)).getOrElse(throw IllegalStateException("scope"))
      )

    private object Descriptor extends OperationDescriptor[Unit, GitHub.Repository]:
      val id: OperationId = OperationId.parse("github.test.read@1").get
      val tool: ExternalToolId = ExternalToolId.parse("github_test_read").get
      val description = "test"
      val capability: CapabilityKey = CapabilityKey.parse("GitHub.Issue.Read").toOption.get
      val action: Action = Action.Read
      val target: ResourceKind[GitHub.Repository] = GitHub.repository
      val audience: ExecutorAudience = GitHubExecutorAudience.local
      val inputSchema: Json = Json.obj("type" -> Json.fromString("object"))
      def decode(arguments: Json) = Right(())
      def locate(input: Unit) = ResourceLocator.Selected(ExternalRef[GitHub.Repository](ExternalId.parse("1001").get))
      def facts(input: Unit) = AuthorizationContext.empty
      def canonical(input: Unit) = Json.obj()

    /** A genuinely redeemed lease for `target`, issued through the broker. */
    def redeemedLease: IO[RedeemedExecutionLease] =
      val agent = Principal.Agent(agentId)
      val request = AuthorizationRequest(
        AuthorizationRequestId.random(),
        tenant,
        IdentityChain.direct(agent),
        target.scope,
        Descriptor.capability,
        Descriptor.action,
        AuthorizationContext.empty
      )
      val policies = Policies(
        Vector(
          Policy(
            PolicyId.random(),
            PolicyVersion.from(1).get,
            NonEmptySet.one(
              PolicyStatement(agent, catalog.id, NonEmptySet.one(Descriptor.action), None, Constraints.empty, Effect.Allow)
            )
          )
        )
      )
      val capability = AuthorizationEngine.authorize(policies, request, Vector.empty, issuedAt) match
        case AuthorizationResult.Authorized(value) => value
        case other                                 => throw IllegalStateException(s"expected authorization, got $other")
      val metadata = ExecutionAuditMetadata.authenticatedInvocation(
        AuthenticatedAgentContext.authenticated(tenant, agentId, AgentCredentialId.random(), issuedAt, UnverifiedExecutionClaims.empty),
        ExecutionAuditCorrelationId.parse("github-credentials-suite").get,
        ResourceId.random(),
        CatalogCapabilityId.parse("00000000-0000-4000-8000-000000000001").get,
        InvocationBinding.of(tenant, agentId, Descriptor, target, ())
      )
      for
        store <- InMemoryExecutionLeaseStore.create(Clock.fixed(issuedAt), InMemoryExecutionLeaseStore.DefaultPruneInterval, 10)
        audit <- InMemoryExecutionAuditRecorder.create
        broker = new InMemoryCredentialBroker(store, Clock.fixed(issuedAt), Duration.ofSeconds(60), audit)
        lease <- broker.issueLease(capability, request.id, Descriptor.audience, metadata)
        redeemed <- store.redeem(lease.id, Descriptor.audience, issuedAt)
        result <- redeemed match
          case LeaseRedemption.Redeemed(value) => IO.pure(value)
          case other                           => IO.raiseError(IllegalStateException(s"redemption failed: $other"))
      yield result

package run.hallpass.adapters.github:
  import java.net.URI
  import java.time.Instant
  import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}
  import cats.effect.IO
  import munit.CatsEffectSuite
  import run.hallpass.application.*
  import run.hallpass.application.GitHubCredentialsTestSupport as Support
  import run.hallpass.kernel.*

  /** The installation-token strategy is the GitHub credential boundary. Every
    * refusal must happen before a token is minted, or discard a token GitHub did not narrow as requested. */
  class GitHubInstallationCredentialsSuite extends CatsEffectSuite:
    private val registration = GitHubAppRegistration(77, "Iv1.testclient", "hallpass-test")
    private val installationId = GitHubInstallationId.parse("4242").get
    private val repositoryId = GitHubRepositoryId.parse("1001").get
    private val tokenText = "ghs_installationTokenValueThatMustNeverLeak"
    private val expiresAt = Instant.parse("2026-09-01T13:00:00Z")

    private def record(registrationKey: String = registration.registrationKey, installation: String = "4242") =
      GitHubInstallationRecord.encode(GitHubInstallationRecord(registrationKey, GitHubInstallationId.parse(installation).get))

    private final class Resolver(result: Either[ConnectionError, ProviderSecret]) extends ProviderConnectionResolver:
      val calls = AtomicInteger(0)
      val requested = AtomicReference[Option[(ProviderId, String)]](None)
      def activeConnectionFor[K](lease: RedeemedExecutionLease, target: SelectedResource[K], provider: ProviderId, credentialType: String) =
        IO.delay:
          calls.incrementAndGet()
          requested.set(Some(provider -> credentialType))
          result.map: secret =>
            ResolvedConnection(
              Connection(
                ConnectionId.random(), target.resource, "GITHUB", ConnectionStatus.Active, None, None, None, Support.issuedAt, Support.issuedAt
              ),
              secret
            )

    private final class App(minted: Either[GitHubApiError, MintedInstallationToken]) extends GitHubAppApi:
      val mints = AtomicInteger(0)
      val request = AtomicReference[Option[(GitHubInstallationId, Option[Vector[GitHubRepositoryId]], Set[GitHubPermission])]](None)
      def installationToken(installation: GitHubInstallationId, repositories: Option[Vector[GitHubRepositoryId]], permissions: Set[GitHubPermission]) =
        IO.delay:
          mints.incrementAndGet()
          request.set(Some((installation, repositories, permissions)))
          minted
      def installation(id: GitHubInstallationId) = IO.raiseError(AssertionError("unexpected installation lookup"))
      def installationRepositories(token: MintedInstallationToken, limit: Int) = IO.raiseError(AssertionError("unexpected listing"))
      def exchangeUserCode(code: String, redirectUri: URI) = IO.raiseError(AssertionError("unexpected user exchange"))
      def userCanAccessInstallation(user: GitHubUserToken, installation: GitHubInstallationId) =
        IO.raiseError(AssertionError("unexpected user check"))

    private def minted(
        repositories: Vector[GitHubRepositorySummary] = Vector(summary(repositoryId)),
        permissions: Map[String, String] = Map("issues" -> "read", "metadata" -> "read")
    ) = MintedInstallationToken(tokenText, expiresAt, repositories, permissions)

    private def summary(id: GitHubRepositoryId, name: String = "octo/hello") =
      GitHubRepositorySummary(id, GitHubRepositoryName.parse(name).get)

    private def strategy(resolver: Resolver, app: App) =
      GitHubInstallationCredentials(registration, resolver, app, Set(GitHubPermission.IssuesRead))

    test("mints a token narrowed to the lease's one repository and the operation's permissions") {
      val resolver = Resolver(Right(record()))
      val app = App(Right(minted()))
      for
        lease <- Support.redeemedLease
        result <- strategy(resolver, app).credentialFor(lease, Support.target)
      yield
        val token = result.fold(error => fail(s"expected a token, got $error"), identity)
        assertEquals(token.repository.id, repositoryId)
        assertEquals(token.repository.fullName.value, "octo/hello")
        assertEquals(app.request.get, Some((installationId, Some(Vector(repositoryId)), Set(GitHubPermission.IssuesRead))))
        assertEquals(resolver.requested.get, Some(ProviderId.GitHub -> GitHub.CredentialType))
        assert(!token.toString.contains(tokenText))
    }

    test("a target other than the lease's resource is refused before any connection lookup or mint") {
      val resolver = Resolver(Right(record()))
      val app = App(Right(minted()))
      for
        lease <- Support.redeemedLease
        result <- strategy(resolver, app).credentialFor(lease, Support.siblingTarget)
      yield
        assertEquals(result.map(_ => ()), Left(ConnectionError.InvalidState))
        assertEquals(resolver.calls.get, 0)
        assertEquals(app.mints.get, 0)
    }

    test("a scope without an installation root is refused before any connection lookup or mint") {
      val resolver = Resolver(Right(record()))
      val app = App(Right(minted()))
      for
        lease <- Support.redeemedLease
        result <- strategy(resolver, app).credentialFor(lease, Support.rootlessTarget)
      yield
        assertEquals(result.map(_ => ()), Left(ConnectionError.InvalidState))
        assertEquals(app.mints.get, 0)
    }

    test("a missing or inactive connection passes through and nothing is minted") {
      val resolver = Resolver(Left(ConnectionError.NotFound))
      val app = App(Right(minted()))
      for
        lease <- Support.redeemedLease
        result <- strategy(resolver, app).credentialFor(lease, Support.target)
      yield
        assertEquals(result.map(_ => ()), Left(ConnectionError.NotFound))
        assertEquals(app.mints.get, 0)
    }

    test("a record for another registration, another installation, or a malformed record mints nothing") {
      val records = Vector(
        record(registrationKey = "platform:github.com:999"),
        record(installation = "4243"),
        ProviderSecret.fromUtf8("""{"installation_id":"4242"}"""),
        ProviderSecret.fromUtf8("not json")
      )
      records.foldLeft(IO.unit): (previous, stored) =>
        previous *> {
          val app = App(Right(minted()))
          for
            lease <- Support.redeemedLease
            result <- strategy(Resolver(Right(stored)), app).credentialFor(lease, Support.target)
          yield
            assertEquals(result.map(_ => ()), Left(ConnectionError.InvalidState))
            assertEquals(app.mints.get, 0)
        }
    }

    test("a token GitHub did not narrow to exactly the authorized repository is discarded") {
      val unnarrowed = Vector(
        Vector.empty,
        Vector(summary(GitHubRepositoryId.parse("1002").get, "octo/other")),
        Vector(summary(repositoryId), summary(GitHubRepositoryId.parse("1002").get, "octo/other"))
      )
      unnarrowed.foldLeft(IO.unit): (previous, repositories) =>
        previous *> Support.redeemedLease.flatMap: lease =>
          strategy(Resolver(Right(record())), App(Right(minted(repositories = repositories))))
            .credentialFor(lease, Support.target)
            .map(result => assertEquals(result.map(_ => ()), Left(ConnectionError.InvalidState)))
    }

    test("a token with a permission beyond those requested is discarded") {
      val broader = Vector(
        Map("issues" -> "write", "metadata" -> "read"),
        Map("issues" -> "read", "contents" -> "write"),
        Map("issues" -> "read", "metadata" -> "write")
      )
      broader.foldLeft(IO.unit): (previous, permissions) =>
        previous *> Support.redeemedLease.flatMap: lease =>
          strategy(Resolver(Right(record())), App(Right(minted(permissions = permissions))))
            .credentialFor(lease, Support.target)
            .map(result => assertEquals(result.map(_ => ()), Left(ConnectionError.InvalidState)))
    }

    test("a mint failure is a missing credential, with no retry") {
      val app = App(Left(GitHubApiError.NotFound))
      for
        lease <- Support.redeemedLease
        result <- strategy(Resolver(Right(record())), app).credentialFor(lease, Support.target)
      yield
        assertEquals(result.map(_ => ()), Left(ConnectionError.MissingCredential))
        assertEquals(app.mints.get, 1)
    }
