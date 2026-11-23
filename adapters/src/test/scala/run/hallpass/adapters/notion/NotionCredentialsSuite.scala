package run.hallpass.application:
  import java.time.{Duration, Instant}
  import cats.effect.IO
  import io.circe.Json
  import run.hallpass.adapters.notion.{Notion, NotionExecutorAudience}
  import run.hallpass.kernel.*
  import run.hallpass.kernel.authorization.*

  /** Test-only access to `private[application]` constructors for the Notion credential strategy suite. */
  object NotionCredentialsTestSupport:
    val tenant: TenantId = TenantId.random()
    private val agentId = AgentId.random()
    val issuedAt: Instant = Instant.parse("2026-09-01T12:00:00Z")
    val workspaceUuid = "11111111-2222-4333-8444-555555555555"
    val pageUuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    val siblingUuid = "aaaaaaaa-bbbb-4ccc-8ddd-ffffffffffff"
    val catalog: Resource = Resource(ResourceId.random(), tenant, ResourceType.Provider, None, "notion", None)
    val workspace: Resource =
      Resource(ResourceId.random(), tenant, ResourceType.Account, Some(catalog.id), workspaceUuid, None)
    val page: Resource =
      Resource(ResourceId.random(), tenant, ResourceType.Document, Some(workspace.id), pageUuid, None)
    val sibling: Resource =
      Resource(ResourceId.random(), tenant, ResourceType.Document, Some(workspace.id), siblingUuid, None)

    private def external(value: String): ExternalId =
      ExternalId.parse(value).getOrElse(throw IllegalStateException("external id"))

    private def selected(resource: Resource, path: Vector[Resource]): SelectedResource[Notion.Page] =
      SelectedResource.trusted(
        Notion.page,
        external(resource.externalId),
        ResourceScope.fromPath(path).getOrElse(throw IllegalStateException("scope"))
      )

    val target: SelectedResource[Notion.Page] = selected(page, Vector(page, workspace, catalog))
    val siblingTarget: SelectedResource[Notion.Page] = selected(sibling, Vector(sibling, workspace, catalog))
    /** A scope that skips the workspace root: the strategy must not trust it. */
    val rootlessTarget: SelectedResource[Notion.Page] =
      val detached = Resource(page.id, tenant, ResourceType.Document, Some(catalog.id), pageUuid, None)
      selected(detached, Vector(detached, catalog))

    private object Descriptor extends OperationDescriptor[Unit, Notion.Page]:
      val id: OperationId = OperationId.parse("notion.test.read@1").get
      val tool: ExternalToolId = ExternalToolId.parse("notion_test_read").get
      val description = "test"
      val capability: CapabilityKey = CapabilityKey.parse("Notion.Page.Read").toOption.get
      val action: Action = Action.Read
      val target: ResourceKind[Notion.Page] = Notion.page
      val audience: ExecutorAudience = NotionExecutorAudience.local
      val inputSchema: Json = Json.obj("type" -> Json.fromString("object"))
      def decode(arguments: Json) = Right(())
      def locate(input: Unit) = ResourceLocator.Selected(ExternalRef[Notion.Page](external(pageUuid)))
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
        ExecutionAuditCorrelationId.parse("notion-credentials-suite").get,
        ResourceId.random(),
        CatalogCapabilityId.parse("00000000-0000-4000-8000-000000000002").get,
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

package run.hallpass.adapters.notion:
  import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}
  import cats.effect.IO
  import munit.CatsEffectSuite
  import run.hallpass.application.*
  import run.hallpass.application.NotionCredentialsTestSupport as Support
  import run.hallpass.kernel.*

  /** The Notion strategy is the credential boundary: every refusal happens before a token is handed out. */
  class NotionCredentialsSuite extends CatsEffectSuite:
    private val tokenText = "secret_notionAccessTokenThatMustNeverLeak"
    private val botId = NotionId.parse("99999999-8888-4777-8666-555555555555").get
    private val workspaceId = NotionId.parse(Support.workspaceUuid).get

    private def record(workspace: NotionId = workspaceId) =
      NotionTokenRecord.encode(NotionTokenRecord.from(tokenText, Some("refresh_value_x"), botId, workspace).get)

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
                ConnectionId.random(), target.resource, "NOTION", ConnectionStatus.Active, None, None, None, Support.issuedAt, Support.issuedAt
              ),
              secret
            )

    test("resolves the access token for the lease's page with the NOTION_OAUTH credential type") {
      val resolver = Resolver(Right(record()))
      for
        lease <- Support.redeemedLease
        result <- NotionCredentials(resolver).credentialFor(lease, Support.target)
      yield
        val access = result.fold(error => fail(s"expected access, got $error"), identity)
        assertEquals(access.accessToken, tokenText)
        assertEquals(resolver.requested.get, Some(ProviderId.Notion -> Notion.CredentialType))
        assert(!access.toString.contains(tokenText))
    }

    test("a target other than the lease's resource is refused before any connection lookup") {
      val resolver = Resolver(Right(record()))
      for
        lease <- Support.redeemedLease
        result <- NotionCredentials(resolver).credentialFor(lease, Support.siblingTarget)
      yield
        assertEquals(result.map(_ => ()), Left(ConnectionError.InvalidState))
        assertEquals(resolver.calls.get, 0)
    }

    test("a scope without a workspace root is refused before any connection lookup") {
      val resolver = Resolver(Right(record()))
      for
        lease <- Support.redeemedLease
        result <- NotionCredentials(resolver).credentialFor(lease, Support.rootlessTarget)
      yield
        assertEquals(result.map(_ => ()), Left(ConnectionError.InvalidState))
        assertEquals(resolver.calls.get, 0)
    }

    test("a record for another workspace is refused") {
      val other = NotionId.parse("11111111-2222-4333-8444-666666666666").get
      for
        lease <- Support.redeemedLease
        result <- NotionCredentials(Resolver(Right(record(other)))).credentialFor(lease, Support.target)
      yield assertEquals(result.map(_ => ()), Left(ConnectionError.InvalidState))
    }

    test("a malformed stored record is refused") {
      for
        lease <- Support.redeemedLease
        result <- NotionCredentials(Resolver(Right(ProviderSecret.fromUtf8("not json")))).credentialFor(lease, Support.target)
      yield assertEquals(result.map(_ => ()), Left(ConnectionError.InvalidState))
    }

    test("resolver errors pass through unchanged") {
      val errors = Vector(ConnectionError.NotFound, ConnectionError.InvalidState)
      errors.foldLeft(IO.unit): (previous, error) =>
        previous *> Support.redeemedLease.flatMap: lease =>
          val resolver = Resolver(Left(error))
          NotionCredentials(resolver).credentialFor(lease, Support.target).map: result =>
            assertEquals(result.map(_ => ()), Left(error))
            assertEquals(resolver.calls.get, 1)
    }
