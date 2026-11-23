package run.hallpass.application:
  import java.time.{Duration, Instant}
  import cats.effect.IO
  import io.circe.Json
  import run.hallpass.adapters.hubspot.{HubSpot, HubSpotExecutorAudience}
  import run.hallpass.kernel.*
  import run.hallpass.kernel.authorization.*

  /** Test-only access to `private[application]` constructors for the HubSpot Drive credential strategy suite. The
    * scope's root is a hubspot.account resource under personal custody, held by `human`. */
  object HubSpotCredentialsTestSupport:
    val tenant: TenantId = TenantId.random()
    private val human = Principal.Human(UserId.random())
    private val agentId = AgentId.random()
    val issuedAt: Instant = Instant.parse("2026-09-01T12:00:00Z")
    val catalog: Resource = Resource(ResourceId.random(), tenant, ResourceType.Provider, None, "hubspot", None)
    val account: Resource =
      Resource(ResourceId.random(), tenant, ResourceType.Account, Some(catalog.id), "44332211", Some(human))
    val contacts: Resource =
      Resource(ResourceId.random(), tenant, ResourceType.Custom, Some(account.id), "44332211:contacts", Some(human))
    val sibling: Resource =
      Resource(ResourceId.random(), tenant, ResourceType.Custom, Some(account.id), "44332211:deals", Some(human))

    private def selected[K](kind: ResourceKind[K], resource: Resource): SelectedResource[K] =
      SelectedResource.trusted(
        kind,
        ExternalId.parse(resource.externalId).getOrElse(throw IllegalStateException("external id")),
        ResourceScope.fromPath(Vector(resource, account, catalog)).getOrElse(throw IllegalStateException("scope"))
      )

    val target: SelectedResource[HubSpot.ObjectType] = selected(HubSpot.objectType, contacts)
    val siblingTarget: SelectedResource[HubSpot.ObjectType] = selected(HubSpot.objectType, sibling)
    /** Same resource as the lease's, but declared as another kind: the strategy must not trust it. */
    val wrongKindTarget: SelectedResource[HubSpot.ObjectType] =
      SelectedResource.trusted(
        HubSpot.portal.asInstanceOf[ResourceKind[HubSpot.ObjectType]],
        ExternalId.parse(contacts.externalId).getOrElse(throw IllegalStateException("external id")),
        ResourceScope.fromPath(Vector(contacts, account, catalog)).getOrElse(throw IllegalStateException("scope"))
      )

    private object Descriptor extends OperationDescriptor[Unit, HubSpot.ObjectType]:
      val id: OperationId = OperationId.parse("hubspot.test.read@1").get
      val tool: ExternalToolId = ExternalToolId.parse("hubspot_test_read").get
      val description = "test"
      val capability: CapabilityKey = CapabilityKey.parse("HubSpot.Contact.Read").toOption.get
      val action: Action = Action.Read
      val target: ResourceKind[HubSpot.ObjectType] = HubSpot.objectType
      val audience: ExecutorAudience = HubSpotExecutorAudience.local
      val inputSchema: Json = Json.obj("type" -> Json.fromString("object"))
      def decode(arguments: Json) = Right(())
      def locate(input: Unit) = ResourceLocator.Selected(ExternalRef[HubSpot.ObjectType](ExternalId.parse("44332211:contacts").get))
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
        ExecutionAuditCorrelationId.parse("hubspot-credentials-suite").get,
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

package run.hallpass.adapters.hubspot:
  import java.util.concurrent.atomic.AtomicInteger
  import cats.effect.IO
  import munit.CatsEffectSuite
  import run.hallpass.application.*
  import run.hallpass.application.HubSpotCredentialsTestSupport as Support

  /** The HubSpot credential strategy is the HubSpot credential boundary: every refusal happens before the wrapped
    * refreshable-OAuth strategy runs, so no stored token is read for a target the lease does not name. */
  class HubSpotCredentialsSuite extends CatsEffectSuite:
    private val accessValue = "hs_access_token_that_must_never_leak"

    private final class Wrapped(result: Either[ConnectionError, OAuthTokens]) extends CredentialStrategy[HubSpot.ObjectType, OAuthTokens]:
      val calls = AtomicInteger(0)
      def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[HubSpot.ObjectType]) =
        IO.delay:
          calls.incrementAndGet()
          result

    private def tokens = OAuthTokens.from(accessValue, Some("hs_refresh"), Support.issuedAt.plusSeconds(600)).get

    test("maps the refreshed tokens to access for the lease's object type") {
      val wrapped = Wrapped(Right(tokens))
      for
        lease <- Support.redeemedLease
        result <- HubSpotCredentials(wrapped).credentialFor(lease, Support.target)
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
        result <- HubSpotCredentials(wrapped).credentialFor(lease, Support.siblingTarget)
      yield
        assertEquals(result.map(_ => ()), Left(ConnectionError.InvalidState))
        assertEquals(wrapped.calls.get, 0)
    }

    test("the lease's resource declared as another kind is refused before the wrapped strategy runs") {
      val wrapped = Wrapped(Right(tokens))
      for
        lease <- Support.redeemedLease
        result <- HubSpotCredentials(wrapped).credentialFor(lease, Support.wrongKindTarget)
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
          HubSpotCredentials(wrapped).credentialFor(lease, Support.target).map: result =>
            assertEquals(result.map(_ => ()), Left(error))
            assertEquals(wrapped.calls.get, 1)
    }
