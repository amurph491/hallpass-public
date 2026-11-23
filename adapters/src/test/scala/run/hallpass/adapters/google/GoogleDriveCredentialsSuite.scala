package run.hallpass.application:
  import java.time.{Duration, Instant}
  import cats.effect.IO
  import io.circe.Json
  import run.hallpass.adapters.google.{Google, GoogleExecutorAudience}
  import run.hallpass.kernel.*
  import run.hallpass.kernel.authorization.*

  /** Test-only access to `private[application]` constructors for the Google Drive credential strategy suite. The
    * scope's root is a google.account resource under personal custody, held by `human`. */
  object GoogleCredentialsTestSupport:
    val tenant: TenantId = TenantId.random()
    private val human = Principal.Human(UserId.random())
    private val agentId = AgentId.random()
    val issuedAt: Instant = Instant.parse("2026-09-01T12:00:00Z")
    val catalog: Resource = Resource(ResourceId.random(), tenant, ResourceType.Provider, None, "google", None)
    val account: Resource =
      Resource(ResourceId.random(), tenant, ResourceType.Account, Some(catalog.id), "110169484474386276334", Some(human))
    val file: Resource =
      Resource(ResourceId.random(), tenant, ResourceType.Document, Some(account.id), "file000000000001", Some(human))
    val sibling: Resource =
      Resource(ResourceId.random(), tenant, ResourceType.Document, Some(account.id), "file000000000002", Some(human))

    private def selected[K](kind: ResourceKind[K], resource: Resource): SelectedResource[K] =
      SelectedResource.trusted(
        kind,
        ExternalId.parse(resource.externalId).getOrElse(throw IllegalStateException("external id")),
        ResourceScope.fromPath(Vector(resource, account, catalog)).getOrElse(throw IllegalStateException("scope"))
      )

    val target: SelectedResource[Google.DriveFile] = selected(Google.driveFile, file)
    val siblingTarget: SelectedResource[Google.DriveFile] = selected(Google.driveFile, sibling)
    /** Same resource as the lease's, but declared as another kind: the strategy must not trust it. */
    val wrongKindTarget: SelectedResource[Google.DriveFile] =
      SelectedResource.trusted(
        Google.account.asInstanceOf[ResourceKind[Google.DriveFile]],
        ExternalId.parse(file.externalId).getOrElse(throw IllegalStateException("external id")),
        ResourceScope.fromPath(Vector(file, account, catalog)).getOrElse(throw IllegalStateException("scope"))
      )

    private object Descriptor extends OperationDescriptor[Unit, Google.DriveFile]:
      val id: OperationId = OperationId.parse("google.test.read@1").get
      val tool: ExternalToolId = ExternalToolId.parse("google_test_read").get
      val description = "test"
      val capability: CapabilityKey = CapabilityKey.parse("Google.Drive.Read").toOption.get
      val action: Action = Action.Read
      val target: ResourceKind[Google.DriveFile] = Google.driveFile
      val audience: ExecutorAudience = GoogleExecutorAudience.drive
      val inputSchema: Json = Json.obj("type" -> Json.fromString("object"))
      def decode(arguments: Json) = Right(())
      def locate(input: Unit) = ResourceLocator.Selected(ExternalRef[Google.DriveFile](ExternalId.parse("file000000000001").get))
      def facts(input: Unit) = AuthorizationContext.empty
      def canonical(input: Unit) = Json.obj()

    /** A genuinely redeemed lease for `target`, issued through the broker. */
    def redeemedLease: IO[RedeemedExecutionLease] =
      val agent = Principal.Agent(agentId)
      val delegation = Delegation(
        DelegationId.random(),
        human,
        agent,
        None,
        NonEmptySet.one(CapabilityDescriptor(catalog.id, Descriptor.action, Descriptor.capability)),
        Constraints.empty,
        issuedAt.minusSeconds(60),
        Some(issuedAt.plusSeconds(3600)),
        None
      )
      val request = AuthorizationRequest(
        AuthorizationRequestId.random(),
        tenant,
        IdentityChain(agent, Vector(delegation.id), None, ExecutionContext.LocalProcess),
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
              PolicyStatement(human, catalog.id, NonEmptySet.one(Descriptor.action), None, Constraints.empty, Effect.Allow)
            )
          )
        )
      )
      val capability = AuthorizationEngine.authorize(policies, request, Vector(delegation), issuedAt) match
        case AuthorizationResult.Authorized(value) => value
        case other                                 => throw IllegalStateException(s"expected authorization, got $other")
      val metadata = ExecutionAuditMetadata.authenticatedInvocation(
        AuthenticatedAgentContext.authenticated(tenant, agentId, AgentCredentialId.random(), issuedAt, UnverifiedExecutionClaims.empty),
        ExecutionAuditCorrelationId.parse("google-credentials-suite").get,
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

package run.hallpass.adapters.google:
  import java.util.concurrent.atomic.AtomicInteger
  import cats.effect.IO
  import munit.CatsEffectSuite
  import run.hallpass.application.*
  import run.hallpass.application.GoogleCredentialsTestSupport as Support

  /** The Drive credential strategy is the Google credential boundary: every refusal happens before the wrapped
    * refreshable-OAuth strategy runs, so no stored token is read for a target the lease does not name. */
  class GoogleDriveCredentialsSuite extends CatsEffectSuite:
    private val accessValue = "ya29.drive_access_token_that_must_never_leak"

    private final class Wrapped(result: Either[ConnectionError, OAuthTokens]) extends CredentialStrategy[Google.DriveFile, OAuthTokens]:
      val calls = AtomicInteger(0)
      def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[Google.DriveFile]) =
        IO.delay:
          calls.incrementAndGet()
          result

    private def tokens = OAuthTokens.from(accessValue, Some("1//refresh"), Support.issuedAt.plusSeconds(600)).get

    test("maps the refreshed tokens to access for the lease's file") {
      val wrapped = Wrapped(Right(tokens))
      for
        lease <- Support.redeemedLease
        result <- GoogleDriveCredentials(wrapped).credentialFor(lease, Support.target)
      yield
        val access = result.fold(error => fail(s"expected access, got $error"), identity)
        assertEquals(access.accessToken, accessValue)
        assertEquals(wrapped.calls.get, 1)
        assert(!access.toString.contains(accessValue))
    }

    test("a target other than the lease's resource is refused before the wrapped strategy runs") {
      val wrapped = Wrapped(Right(tokens))
      for
        lease <- Support.redeemedLease
        result <- GoogleDriveCredentials(wrapped).credentialFor(lease, Support.siblingTarget)
      yield
        assertEquals(result.map(_ => ()), Left(ConnectionError.InvalidState))
        assertEquals(wrapped.calls.get, 0)
    }

    test("the lease's resource declared as another kind is refused before the wrapped strategy runs") {
      val wrapped = Wrapped(Right(tokens))
      for
        lease <- Support.redeemedLease
        result <- GoogleDriveCredentials(wrapped).credentialFor(lease, Support.wrongKindTarget)
      yield
        assertEquals(result.map(_ => ()), Left(ConnectionError.InvalidState))
        assertEquals(wrapped.calls.get, 0)
    }

    test("wrapped errors pass through unchanged") {
      val errors = Vector(
        ConnectionError.NotFound, ConnectionError.Disabled, ConnectionError.MissingCredential,
        ConnectionError.Ambiguous, ConnectionError.InvalidState, ConnectionError.PersistenceFailure
      )
      errors.foldLeft(IO.unit): (previous, error) =>
        previous *> Support.redeemedLease.flatMap: lease =>
          val wrapped = Wrapped(Left(error))
          GoogleDriveCredentials(wrapped).credentialFor(lease, Support.target).map: result =>
            assertEquals(result.map(_ => ()), Left(error))
            assertEquals(wrapped.calls.get, 1)
    }
