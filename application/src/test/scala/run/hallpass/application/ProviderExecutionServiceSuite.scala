package run.hallpass.application

import java.time.{Duration, Instant}
import java.util.concurrent.atomic.{AtomicInteger, AtomicReference}
import scala.concurrent.duration.*
import cats.effect.IO
import cats.effect.kernel.Deferred
import cats.syntax.all.*
import io.circe.Json
import munit.CatsEffectSuite
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Lifecycle coverage for the generic [[ProviderExecutionService]], using a provider-neutral fake operation. Leases are
  * issued through [[InMemoryCredentialBroker]] so the audit context and invocation binding are real. */
final class ProviderExecutionServiceSuite extends CatsEffectSuite:
  // ---- a phantom-kind fake provider --------------------------------------------------------------------------------
  private final case class FakeInput(value: String)
  private sealed trait FakeAccount
  private val fakeProvider = ProviderId.parse("fake").getOrElse(fail("provider"))
  private given accountKind: ResourceKind[FakeAccount] =
    ResourceKind.root[FakeAccount]("fake.account", fakeProvider, ResourceType.Account, Custody.Workspace)

  /** A credential type whose rendering never contains the secret. */
  private final class FakeCredential(val raw: String):
    override def toString: String = "FakeCredential(<redacted>)"

  private val credentialText = "fake-credential-secret"
  private val readKey = CapabilityKey.parse("Fake.Thing.Read").getOrElse(fail("capability key"))
  private val otherKey = CapabilityKey.parse("Fake.Thing.Export").getOrElse(fail("capability key"))
  private val fakeAudience = ExecutorAudience.parse("test.fake.executor").getOrElse(fail("audience"))
  private val otherAudience = ExecutorAudience.parse("test.other.executor").getOrElse(fail("audience"))

  private final case class FakeDescriptor(
      capability: CapabilityKey = readKey,
      action: Action = Action.Read,
      audience: ExecutorAudience = fakeAudience
  ) extends OperationDescriptor[FakeInput, FakeAccount]:
    val id: OperationId = OperationId.parse("fake.thing.read@1").getOrElse(throw IllegalStateException("operation id"))
    val tool: ExternalToolId = ExternalToolId.parse("fake_thing_read").getOrElse(throw IllegalStateException("tool"))
    val description: String = "fake"
    def target: ResourceKind[FakeAccount] = accountKind
    val inputSchema: Json = Json.obj()
    def decode(arguments: Json): Either[ArgumentError, FakeInput] =
      arguments.hcursor.get[String]("value").left.map(_ => ArgumentError.MissingField("value")).map(FakeInput.apply)
    def locate(input: FakeInput): ResourceLocator[FakeAccount] = ResourceLocator.ConnectionRoot()
    def facts(input: FakeInput): AuthorizationContext = AuthorizationContext.empty
    def canonical(input: FakeInput): Json = Json.obj("value" -> Json.fromString(input.value))

  private val descriptor = FakeDescriptor()

  private final class CountingStrategy extends CredentialStrategy[FakeAccount, FakeCredential]:
    val lookups = new AtomicInteger(0)
    @volatile var result: Either[ConnectionError, FakeCredential] = Right(new FakeCredential(credentialText))
    @volatile var onLookup: IO[Unit] = IO.unit
    def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[FakeAccount]) =
      IO(lookups.incrementAndGet()) *> IO.defer(onLookup) *> IO.delay(result)

  private final class CountingClient extends ProviderOperationClient[FakeInput, FakeAccount, FakeCredential]:
    val seen = new AtomicReference(Vector.empty[(SelectedResource[FakeAccount], FakeInput, String)])
    @volatile var respond: IO[ToolResult] = IO.pure(ToolResult("fake-result"))
    def calls: Int = seen.get.size
    def dispatch(target: SelectedResource[FakeAccount], input: FakeInput, credential: FakeCredential) =
      IO(seen.updateAndGet(_ :+ ((target, input, credential.raw)))) *> IO.defer(respond)

  private final class CountingValidator extends LeaseAuthorityValidator[IO]:
    val calls = new AtomicInteger(0)
    @volatile var result: Either[LeaseAuthorityDenial, Unit] = Right(())
    @volatile var onValidate: IO[Unit] = IO.unit
    def validate(lease: RedeemedExecutionLease, now: Instant) =
      IO(calls.incrementAndGet()) *> IO.defer(onValidate) *> IO.delay(result)

  private val heldPermit: ExecutionGatePermit[IO] = new ExecutionGatePermit[IO]:
    def confirmHeld: IO[Unit] = IO.unit

  private def gateWith(permit: ExecutionGatePermit[IO]): TenantExecutionMutationGate[IO] =
    new TenantExecutionMutationGate[IO]:
      def withinExecution[A](tenant: TenantId)(operation: ExecutionGatePermit[IO] => IO[A]): IO[A] = operation(permit)
      def withinMutation[A](tenant: TenantId)(operation: IO[A]): IO[A] = operation

  private val testGate = gateWith(heldPermit)

  // ---- authority fixture --------------------------------------------------------------------------------------------
  private val issuedAt = Instant.parse("2026-09-01T12:00:00Z")
  private val leaseTtl = Duration.ofSeconds(60)
  private val tenant = TenantId.random()
  private val agentId = AgentId.random()
  private val agent = Principal.Agent(agentId)
  private val credentialId = AgentCredentialId.random()
  private val account = Resource(ResourceId.random(), tenant, ResourceType.Account, None, "fake-account", None)
  private val otherAccount = Resource(ResourceId.random(), tenant, ResourceType.Account, None, "other-account", None)
  private val input = FakeInput("roadmap")

  private def targetFor(resource: Resource): SelectedResource[FakeAccount] =
    SelectedResource.trusted(
      accountKind,
      ExternalId.parse(resource.externalId).getOrElse(fail("external id")),
      ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope"))
    )

  private val target = targetFor(account)

  private def authorized(
      resource: Resource,
      key: CapabilityKey,
      action: Action
  ): (AuthorizationRequestId, AuthorizedCapability) =
    val request = AuthorizationRequest(
      AuthorizationRequestId.random(),
      tenant,
      IdentityChain.direct(agent),
      ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope")),
      key,
      action,
      AuthorizationContext.empty
    )
    val policies = Policies(
      Vector(
        Policy(
          PolicyId.random(),
          PolicyVersion.from(1).getOrElse(fail("policy version")),
          NonEmptySet.one(PolicyStatement(agent, resource.id, NonEmptySet.one(action), None, Constraints.empty, Effect.Allow))
        )
      )
    )
    AuthorizationEngine.authorize(policies, request, Vector.empty, issuedAt) match
      case AuthorizationResult.Authorized(capability) => (request.id, capability)
      case other                                      => fail(s"expected authorized capability, received $other")

  /** Mutable fixture: tests may replace the gate, the audit sink, the clock, and the fakes' behavior. */
  private final class Harness(
      val store: InMemoryExecutionLeaseStore,
      val recorder: InMemoryExecutionAuditRecorder,
      val time: AtomicReference[Instant]
  ):
    val clock: Clock[IO] = new Clock[IO]:
      def now: IO[Instant] = IO(time.get)
    val validator = new CountingValidator
    val strategy = new CountingStrategy
    val client = new CountingClient
    @volatile var gate: TenantExecutionMutationGate[IO] = testGate
    @volatile var serviceAudit: ExecutionAudit[IO] = recorder
    private val broker = new InMemoryCredentialBroker(store, clock, leaseTtl, recorder)

    /** Issues a lease whose binding covers `boundInput` against `boundTarget` for `bound`. */
    def issue(
        boundInput: FakeInput = input,
        boundTarget: SelectedResource[FakeAccount] = target,
        bound: FakeDescriptor = descriptor,
        resource: Resource = account
    ): IO[ExecutionLeaseId] =
      val (requestId, capability) = authorized(resource, bound.capability, bound.action)
      val binding = InvocationBinding.of(tenant, agentId, bound, boundTarget, boundInput)
      val metadata = ExecutionAuditMetadata.authenticatedInvocation(
        AuthenticatedAgentContext.authenticated(tenant, agentId, credentialId, issuedAt, UnverifiedExecutionClaims.empty),
        ExecutionAuditCorrelationId.parse("provider-execution-suite").getOrElse(fail("correlation")),
        ResourceId.random(),
        CatalogCapabilityId.parse("00000000-0000-4000-8000-000000000001").getOrElse(fail("catalog capability")),
        binding
      )
      broker.issueLease(capability, requestId, bound.audience, metadata).map(_.id)

    def run(
        leaseId: ExecutionLeaseId,
        runInput: FakeInput = input,
        runTarget: SelectedResource[FakeAccount] = target,
        runDescriptor: FakeDescriptor = descriptor
    ): IO[ToolResult] =
      new ProviderExecutionService(store, clock, serviceAudit, validator, gate)
        .execute(leaseId, RegisteredOperation(runDescriptor, client, strategy), runInput, runTarget)

    def events: IO[Vector[ExecutionAuditEvent]] = recorder.recorded

    def nothingReachedCredentialsOrProvider: Boolean = strategy.lookups.get == 0 && client.calls == 0

  private def harness: IO[Harness] =
    val time = new AtomicReference(issuedAt)
    val clock = new Clock[IO]:
      def now: IO[Instant] = IO(time.get)
    for
      store <- InMemoryExecutionLeaseStore.create(
        clock,
        InMemoryExecutionLeaseStore.DefaultPruneInterval,
        InMemoryExecutionLeaseStore.DefaultMaximumEntries
      )
      recorder <- InMemoryExecutionAuditRecorder.create
    yield new Harness(store, recorder, time)

  private def failures(events: Vector[ExecutionAuditEvent]): Vector[ExecutionFailure] =
    events.collect { case ExecutionAuditEvent.ExecutionFailed(_, outcome, _) => outcome }

  private def denials(events: Vector[ExecutionAuditEvent]): Vector[LeaseRedemptionDenial] =
    events.collect { case ExecutionAuditEvent.RedemptionDenied(_, _, outcome, _, _) => outcome }

  private def redemptionDenial(outcome: Either[Throwable, ToolResult]): Option[LeaseRedemptionDenial] =
    outcome.left.toOption.collect { case LeaseRedemptionException(denial) => denial }

  private def providerError(outcome: Either[Throwable, ToolResult]): Option[ProviderError] = outcome match
    case Left(error: ProviderExecutionException) => Some(error.error)
    case _                                       => None

  private def assertProviderError(outcome: Either[Throwable, ToolResult], expected: ProviderError)(using
      munit.Location
  ): Unit = assertEquals(providerError(outcome), Some(expected), s"unexpected outcome: $outcome")

  // ---- success ------------------------------------------------------------------------------------------------------
  test("a valid lease completes once, records LeaseRedeemed then ExecutionCompleted, and sends the exact input and target") {
    for
      h <- harness
      id <- h.issue()
      result <- h.run(id)
      events <- h.events
    yield
      assertEquals(result, ToolResult("fake-result"))
      assertEquals(h.client.seen.get, Vector((target, input, credentialText)))
      assertEquals(h.strategy.lookups.get, 1)
      assertEquals(h.validator.calls.get, 2)
      val lifecycle = events.collect:
        case _: ExecutionAuditEvent.LeaseIssued        => "issued"
        case _: ExecutionAuditEvent.LeaseRedeemed      => "redeemed"
        case _: ExecutionAuditEvent.ExecutionCompleted => "completed"
      assertEquals(lifecycle, Vector("issued", "redeemed", "completed"))
  }

  test("a lease redeems once: replaying it is denied and dispatches nothing more") {
    for
      h <- harness
      id <- h.issue()
      _ <- h.run(id)
      second <- h.run(id).attempt
      events <- h.events
    yield
      assertEquals(redemptionDenial(second), Some(LeaseRedemptionDenial.AlreadyRedeemed))
      assertEquals(h.client.calls, 1)
      assertEquals(h.strategy.lookups.get, 1)
      assertEquals(denials(events), Vector(LeaseRedemptionDenial.AlreadyRedeemed))
  }

  // ---- redemption denials -------------------------------------------------------------------------------------------
  private def assertRedemptionDenied(
      h: Harness,
      outcome: Either[Throwable, ToolResult],
      expected: LeaseRedemptionDenial
  )(using munit.Location): IO[Unit] =
    h.events.map: events =>
      assertEquals(redemptionDenial(outcome), Some(expected))
      assertEquals(denials(events), Vector(expected))
      assert(h.nothingReachedCredentialsOrProvider, "credential or provider reached after a redemption denial")
      assertEquals(h.validator.calls.get, 0)
      assert(!events.exists(_.isInstanceOf[ExecutionAuditEvent.LeaseRedeemed]))

  test("an unknown lease is denied, recorded, and never reaches credentials or the provider") {
    for
      h <- harness
      outcome <- h.run(ExecutionLeaseId.random()).attempt
      _ <- assertRedemptionDenied(h, outcome, LeaseRedemptionDenial.UnknownLease)
    yield ()
  }

  test("an expired lease is denied, recorded, and never reaches credentials or the provider") {
    for
      h <- harness
      id <- h.issue()
      _ <- IO(h.time.set(issuedAt.plus(leaseTtl).plusSeconds(1)))
      outcome <- h.run(id).attempt
      _ <- assertRedemptionDenied(h, outcome, LeaseRedemptionDenial.Expired)
    yield ()
  }

  test("a lease presented to another audience is denied, recorded, and never reaches credentials or the provider") {
    for
      h <- harness
      id <- h.issue()
      outcome <- h.run(id, runDescriptor = descriptor.copy(audience = otherAudience)).attempt
      _ <- assertRedemptionDenied(h, outcome, LeaseRedemptionDenial.WrongAudience)
    yield ()
  }

  // ---- expiry between redemption and dispatch ----------------------------------------------------------------------
  test("a lease that expires while waiting at the tenant gate is denied before credentials and dispatch") {
    for
      h <- harness
      id <- h.issue()
      _ = h.gate = new TenantExecutionMutationGate[IO]:
        def withinExecution[A](t: TenantId)(operation: ExecutionGatePermit[IO] => IO[A]): IO[A] =
          IO(h.time.set(issuedAt.plus(leaseTtl))) *> operation(heldPermit)
        def withinMutation[A](t: TenantId)(operation: IO[A]): IO[A] = operation
      outcome <- h.run(id).attempt
      events <- h.events
    yield
      assertEquals(redemptionDenial(outcome), Some(LeaseRedemptionDenial.Expired))
      assert(h.nothingReachedCredentialsOrProvider)
      assertEquals(h.validator.calls.get, 0)
      assert(events.exists:
        case ExecutionAuditEvent.RedemptionDenied(_, _, LeaseRedemptionDenial.Expired, _, Some(_)) => true
        case _                                                                                     => false)
  }

  test("a lease that expires during authority validation is checked again before credentials and dispatch") {
    for
      h <- harness
      id <- h.issue()
      _ = h.validator.onValidate = IO(h.time.set(issuedAt.plus(leaseTtl)))
      outcome <- h.run(id).attempt
      events <- h.events
    yield
      assertEquals(redemptionDenial(outcome), Some(LeaseRedemptionDenial.Expired))
      assertEquals(h.validator.calls.get, 1)
      assert(h.nothingReachedCredentialsOrProvider)
      assert(events.exists:
        case ExecutionAuditEvent.RedemptionDenied(_, _, LeaseRedemptionDenial.Expired, _, Some(_)) => true
        case _                                                                                     => false)
  }

  // ---- current authority --------------------------------------------------------------------------------------------
  test("a denied current-state validation is AuthorityRevoked and never reaches credentials or the provider") {
    for
      h <- harness
      id <- h.issue()
      _ = h.validator.result = Left(LeaseAuthorityDenial.CurrentStateChanged)
      outcome <- h.run(id).attempt
      events <- h.events
    yield
      assertProviderError(outcome, ProviderError.AuthorityRevoked)
      assertEquals(failures(events), Vector(ExecutionFailure.AuthorityRevoked))
      assertEquals(h.validator.calls.get, 1)
      assert(h.nothingReachedCredentialsOrProvider)
      assert(!events.exists(_.isInstanceOf[ExecutionAuditEvent.ExecutionCompleted]))
  }

  test("revocation between two calls stops the second before a second credential read or dispatch") {
    for
      h <- harness
      first <- h.issue()
      second <- h.issue()
      ok <- h.run(first)
      _ = h.validator.result = Left(LeaseAuthorityDenial.CurrentStateChanged)
      denied <- h.run(second).attempt
      events <- h.events
    yield
      assertEquals(ok, ToolResult("fake-result"))
      assertProviderError(denied, ProviderError.AuthorityRevoked)
      assertEquals(h.strategy.lookups.get, 1)
      assertEquals(h.client.calls, 1)
      assertEquals(h.validator.calls.get, 3)
      assertEquals(failures(events), Vector(ExecutionFailure.AuthorityRevoked))
  }

  // ---- invocation binding -------------------------------------------------------------------------------------------
  private def assertBindingRefused(h: Harness, outcome: Either[Throwable, ToolResult])(using munit.Location): IO[Unit] =
    h.events.map: events =>
      assertProviderError(outcome, ProviderError.BindingMismatch)
      assertEquals(failures(events), Vector(ExecutionFailure.AuthorityRevoked))
      assertEquals(h.validator.calls.get, 0, "the validator ran before the binding was checked")
      assert(h.nothingReachedCredentialsOrProvider, "credential or provider reached despite a binding mismatch")
      assert(!events.exists(_.isInstanceOf[ExecutionAuditEvent.ExecutionCompleted]))

  test("binding: a different input than the one bound is refused before validation, credentials, and dispatch") {
    for
      h <- harness
      id <- h.issue(boundInput = FakeInput("roadmap"))
      outcome <- h.run(id, runInput = FakeInput("salaries")).attempt
      _ <- assertBindingRefused(h, outcome)
    yield ()
  }

  test("binding: a target for another resource than the one bound is refused before validation, credentials, and dispatch") {
    for
      h <- harness
      id <- h.issue()
      outcome <- h.run(id, runTarget = targetFor(otherAccount)).attempt
      _ <- assertBindingRefused(h, outcome)
    yield ()
  }

  test("binding: changing only the external ID is refused before validation, credentials, and dispatch") {
    val changed = targetFor(account.copy(externalId = "different-account"))
    assertEquals(changed.resource, target.resource)
    for
      h <- harness
      id <- h.issue()
      outcome <- h.run(id, runTarget = changed).attempt
      _ <- assertBindingRefused(h, outcome)
    yield ()
  }

  test("binding: changing only the resource kind is refused before validation, credentials, and dispatch") {
    val otherKind = ResourceKind.root[FakeAccount]("fake.otheraccount", fakeProvider, ResourceType.Account, Custody.Workspace)
    val changed = SelectedResource.trusted(otherKind, target.externalId, target.scope)
    for
      h <- harness
      id <- h.issue()
      outcome <- h.run(id, runTarget = changed).attempt
      _ <- assertBindingRefused(h, outcome)
    yield ()
  }

  test("a catalog external ID change after issuance is denied before credentials and dispatch") {
    val changedScope =
      ResourceScope.fromPath(Vector(account.copy(externalId = "different-account"))).getOrElse(fail("scope"))
    val currentCredentials = new AgentCredentialCurrentStateRepository[IO]:
      def ensureActive(t: TenantId, c: AgentCredentialId, a: AgentId, now: Instant) =
        IO.pure(Right(()))
    val tools = new TrustedToolLookup[IO]:
      def externalToolFor(t: TenantId, tool: ResourceId) = IO.pure(Right(descriptor.tool))
    val resources = new ResourceCatalog:
      def rootScope(t: TenantId, kind: ResourceKind[?]): IO[Option[(ExternalId, ResourceScope)]] =
        IO.raiseError(AssertionError("execution must not resolve roots"))
      def selectedScope(t: TenantId, kind: ResourceKind[?], id: ExternalId): IO[Option[ResourceScope]] =
        IO.raiseError(AssertionError("execution must not resolve selections"))
      def currentScope(t: TenantId, resource: ResourceId): IO[Option[ResourceScope]] =
        IO.pure(Some(changedScope))
    val unusedAuthority = new AuthorityRepository[IO]:
      def snapshotFor(t: TenantId, p: Principal, tool: String): IO[Either[AuthorityLoadError, AuthoritySnapshot]] =
        IO.raiseError(AssertionError("a changed target must stop before authority loading"))
      def snapshotWithin(t: TenantId, p: Principal, tool: String, scope: ResourceScope): IO[Either[AuthorityLoadError, AuthoritySnapshot]] =
        IO.raiseError(AssertionError("a changed target must stop before authority loading"))
    val revalidator = new CurrentStateExecutionRevalidator(currentCredentials, unusedAuthority, tools, resources)
    for
      h <- harness
      id <- h.issue()
      outcome <- new ProviderExecutionService(
        h.store, h.clock, h.recorder, new DurableLeaseAuthorityValidator(revalidator), testGate
      ).execute(id, RegisteredOperation(descriptor, h.client, h.strategy), input, target).attempt
      events <- h.events
    yield
      assertProviderError(outcome, ProviderError.AuthorityRevoked)
      assertEquals(failures(events), Vector(ExecutionFailure.AuthorityRevoked))
      assert(h.nothingReachedCredentialsOrProvider)
  }

  test("binding: a descriptor with another capability is refused before validation, credentials, and dispatch") {
    for
      h <- harness
      id <- h.issue()
      outcome <- h.run(id, runDescriptor = descriptor.copy(capability = otherKey)).attempt
      _ <- assertBindingRefused(h, outcome)
    yield ()
  }

  test("binding: a descriptor with another action is refused before validation, credentials, and dispatch") {
    for
      h <- harness
      id <- h.issue()
      outcome <- h.run(id, runDescriptor = descriptor.copy(action = Action.Write)).attempt
      _ <- assertBindingRefused(h, outcome)
    yield ()
  }

  test("binding: a lease bound to another resource is refused even when the input matches") {
    // The lease is authorized and bound for otherAccount; the caller presents the account target.
    for
      h <- harness
      id <- h.issue(boundTarget = targetFor(otherAccount), resource = otherAccount)
      outcome <- h.run(id, runTarget = target).attempt
      _ <- assertBindingRefused(h, outcome)
    yield ()
  }

  test("binding: a descriptor with another audience cannot redeem the lease at all") {
    // The audience is part of redemption, so this is refused as a wrong-audience redemption before the binding check.
    for
      h <- harness
      id <- h.issue()
      outcome <- h.run(id, runDescriptor = descriptor.copy(audience = otherAudience)).attempt
      _ <- assertRedemptionDenied(h, outcome, LeaseRedemptionDenial.WrongAudience)
    yield ()
  }

  // ---- connection failures ------------------------------------------------------------------------------------------
  test("a credential strategy ConnectionError is ConnectionUnavailable and never dispatches") {
    ConnectionError.values.toVector.traverse_ { error =>
      for
        h <- harness
        id <- h.issue()
        _ = h.strategy.result = Left(error)
        outcome <- h.run(id).attempt
        events <- h.events
        _ <- IO:
          assertProviderError(outcome, ProviderError.ConnectionUnavailable)
          assertEquals(failures(events), Vector(ExecutionFailure.ConnectionUnavailable), s"for $error")
          assertEquals(h.strategy.lookups.get, 1)
          assertEquals(h.client.calls, 0)
      yield ()
    }
  }

  test("a failing credential strategy is an unexpected failure that never dispatches") {
    for
      h <- harness
      id <- h.issue()
      failing = new CredentialStrategy[FakeAccount, FakeCredential]:
        def credentialFor(lease: RedeemedExecutionLease, t: SelectedResource[FakeAccount]) =
          IO.raiseError(IllegalStateException("secret store exploded"))
      outcome <- new ProviderExecutionService(h.store, h.clock, h.recorder, h.validator, testGate)
        .execute(id, RegisteredOperation(descriptor, h.client, failing), input, target)
        .attempt
      events <- h.events
    yield
      assertEquals(outcome.left.toOption.map(_.getMessage), Some("secret store exploded"))
      assertEquals(failures(events), Vector(ExecutionFailure.Unexpected))
      assertEquals(h.client.calls, 0)
  }

  // ---- provider failures --------------------------------------------------------------------------------------------
  private def clientFailureCategory(failure: Throwable): IO[(Either[Throwable, ToolResult], Vector[ExecutionFailure])] =
    for
      h <- harness
      id <- h.issue()
      _ = h.client.respond = IO.raiseError(failure)
      outcome <- h.run(id).attempt
      events <- h.events
    yield (outcome, failures(events))

  test("provider failures map to audit categories and the original error reaches the caller") {
    val cases = List(
      ProviderError.AuthenticationFailed -> ExecutionFailure.ProviderRejected,
      ProviderError.Rejected -> ExecutionFailure.ProviderRejected,
      ProviderError.Timeout -> ExecutionFailure.ProviderUnavailable,
      ProviderError.InvalidResponse -> ExecutionFailure.Unexpected
    )
    cases.traverse_ { (error, category) =>
      clientFailureCategory(ProviderExecutionException(error)).map: (outcome, recorded) =>
        assertProviderError(outcome, error)
        assertEquals(recorded, Vector(category), s"for $error")
    } *> clientFailureCategory(RuntimeException("boom")).map: (outcome, recorded) =>
      assertEquals(outcome.left.toOption.map(_.getMessage), Some("boom"))
      assertEquals(recorded, Vector(ExecutionFailure.Unexpected))
  }

  test("a write that times out is an unknown outcome, never a plain unavailability, and is not retried") {
    val write = descriptor.copy(action = Action.Write)
    for
      h <- harness
      id <- h.issue(bound = write)
      _ = h.client.respond = IO.raiseError(ProviderExecutionException(ProviderError.Timeout))
      outcome <- h.run(id, runDescriptor = write).attempt
      again <- h.run(id, runDescriptor = write).attempt
      events <- h.events
    yield
      assertProviderError(outcome, ProviderError.OutcomeUnknown)
      assertEquals(failures(events), Vector(ExecutionFailure.CompletionUnknown))
      assertEquals(h.client.calls, 1)
      assert(again.isLeft, "a replay must be denied")
  }

  test("a definitive provider rejection of a write keeps its category") {
    val write = descriptor.copy(action = Action.Write)
    for
      h <- harness
      id <- h.issue(bound = write)
      _ = h.client.respond = IO.raiseError(ProviderExecutionException(ProviderError.Rejected))
      outcome <- h.run(id, runDescriptor = write).attempt
      events <- h.events
    yield
      assertProviderError(outcome, ProviderError.Rejected)
      assertEquals(failures(events), Vector(ExecutionFailure.ProviderRejected))
  }

  test("an audit failure while recording a provider failure does not mask it") {
    for
      h <- harness
      id <- h.issue()
      _ = h.client.respond = IO.raiseError(ProviderExecutionException(ProviderError.AuthenticationFailed))
      _ = h.serviceAudit = new ExecutionAudit[IO]:
        def record(event: ExecutionAuditEvent): IO[Unit] = event match
          case _: ExecutionAuditEvent.ExecutionFailed => IO.raiseError(RuntimeException("audit recorder unavailable"))
          case other                                  => h.recorder.record(other)
      outcome <- h.run(id).attempt
    yield assertProviderError(outcome, ProviderError.AuthenticationFailed)
  }

  test("a completion-audit failure after dispatch is OutcomeUnknown and the provider is never retried") {
    for
      h <- harness
      id <- h.issue()
      _ = h.serviceAudit = new ExecutionAudit[IO]:
        def record(event: ExecutionAuditEvent): IO[Unit] = event match
          case _: ExecutionAuditEvent.ExecutionCompleted => IO.raiseError(RuntimeException("completion write failed"))
          case other                                     => h.recorder.record(other)
      outcome <- h.run(id).attempt
      again <- h.run(id).attempt
    yield
      assertProviderError(outcome, ProviderError.OutcomeUnknown)
      assertEquals(h.client.calls, 1)
      assertEquals(h.strategy.lookups.get, 1)
      assert(again.isLeft, "a replay must be denied")
  }

  test("results, errors, and audit events never render the provider credential") {
    for
      ok <- harness
      okId <- ok.issue()
      result <- ok.run(okId)
      okEvents <- ok.events
      bad <- harness
      badId <- bad.issue()
      _ = bad.client.respond = IO.raiseError(ProviderExecutionException(ProviderError.AuthenticationFailed))
      error <- bad.run(badId).attempt
      badEvents <- bad.events
    yield
      val rendered = Vector(okEvents.toString, badEvents.toString, result.toString, error.toString).mkString(" ")
      assert(!rendered.contains(credentialText))
  }

  // ---- coordination -------------------------------------------------------------------------------------------------
  private def unavailableGate(failure: TenantGateFailure): TenantExecutionMutationGate[IO] =
    new TenantExecutionMutationGate[IO]:
      def withinExecution[A](t: TenantId)(operation: ExecutionGatePermit[IO] => IO[A]): IO[A] =
        IO.raiseError(TenantGateException(failure))
      def withinMutation[A](t: TenantId)(operation: IO[A]): IO[A] = operation

  test("gate acquisition timeout or coordinator outage is CoordinationUnavailable with no credential or dispatch") {
    List(TenantGateFailure.AcquisitionTimedOut, TenantGateFailure.CoordinatorUnavailable).traverse_ { failure =>
      for
        h <- harness
        id <- h.issue()
        _ = h.gate = unavailableGate(failure)
        outcome <- h.run(id).attempt
        events <- h.events
        _ <- IO:
          assertEquals(outcome.left.toOption, Some(TenantGateException(failure)))
          assertEquals(failures(events), Vector(ExecutionFailure.CoordinationUnavailable))
          assert(h.nothingReachedCredentialsOrProvider)
          assertEquals(h.validator.calls.get, 0)
          assert(!events.exists(_.isInstanceOf[ExecutionAuditEvent.ExecutionCompleted]))
      yield ()
    }
  }

  test("gate ownership lost at confirmHeld prevents dispatch and is recorded once as CoordinationUnavailable") {
    val lost = new ExecutionGatePermit[IO]:
      def confirmHeld: IO[Unit] = IO.raiseError(TenantGateException(TenantGateFailure.OwnershipLost))
    for
      h <- harness
      id <- h.issue()
      _ = h.gate = gateWith(lost)
      outcome <- h.run(id).attempt
      events <- h.events
    yield
      assertEquals(outcome.left.toOption, Some(TenantGateException(TenantGateFailure.OwnershipLost)))
      assertEquals(h.client.calls, 0)
      assertEquals(failures(events), Vector(ExecutionFailure.CoordinationUnavailable))
  }

  // ---- cancellation -------------------------------------------------------------------------------------------------
  test("cancelling a request after dispatch still waits for the provider call and records its outcome") {
    for
      h <- harness
      id <- h.issue()
      started <- Deferred[IO, Unit]
      _ = h.client.respond = started.complete(()) *> IO.sleep(300.millis).as(ToolResult("slow-result"))
      running <- h.run(id).start
      _ <- started.get.timeout(5.seconds)
      _ <- running.cancel
      events <- h.events
    yield assert(
      events.exists(_.isInstanceOf[ExecutionAuditEvent.ExecutionCompleted]),
      s"dispatched execution lost its outcome on cancellation: $events"
    )
  }

  test("a lease expiring during credential refresh is denied before provider dispatch") {
    for
      h <- harness
      id <- h.issue()
      _ = h.strategy.onLookup = IO(h.time.set(issuedAt.plus(leaseTtl)))
      outcome <- h.run(id).attempt
      events <- h.events
    yield
      assertEquals(redemptionDenial(outcome), Some(LeaseRedemptionDenial.Expired))
      assertEquals(h.strategy.lookups.get, 1)
      assertEquals(h.client.calls, 0)
      assertEquals(denials(events), Vector(LeaseRedemptionDenial.Expired))
  }

  test("lost gate ownership before refresh prevents credential access") {
    val lost = new ExecutionGatePermit[IO]:
      def confirmHeld: IO[Unit] = IO.raiseError(TenantGateException(TenantGateFailure.OwnershipLost))
    for
      h <- harness
      id <- h.issue()
      _ = h.gate = gateWith(lost)
      outcome <- h.run(id).attempt
      events <- h.events
    yield
      assertEquals(outcome.left.toOption, Some(TenantGateException(TenantGateFailure.OwnershipLost)))
      assert(h.nothingReachedCredentialsOrProvider)
      assertEquals(failures(events), Vector(ExecutionFailure.CoordinationUnavailable))
  }

  test("authority expiring during credential refresh is revalidated at the new time before dispatch") {
    val deadline = issuedAt.plusSeconds(10)
    val validations = new AtomicReference(Vector.empty[Instant])
    val temporalValidator = new LeaseAuthorityValidator[IO]:
      def validate(lease: RedeemedExecutionLease, at: Instant): IO[Either[LeaseAuthorityDenial, Unit]] = IO:
        validations.updateAndGet(_ :+ at)
        if at.isBefore(deadline) then Right(()) else Left(LeaseAuthorityDenial.CurrentStateChanged)
    for
      h <- harness
      id <- h.issue()
      _ = h.strategy.onLookup = IO(h.time.set(deadline))
      outcome <- new ProviderExecutionService(h.store, h.clock, h.recorder, temporalValidator, testGate)
        .execute(id, RegisteredOperation(descriptor, h.client, h.strategy), input, target).attempt
      events <- h.events
    yield
      assertProviderError(outcome, ProviderError.AuthorityRevoked)
      assertEquals(validations.get, Vector(issuedAt, deadline))
      assertEquals(h.strategy.lookups.get, 1)
      assertEquals(h.client.calls, 0)
      assertEquals(failures(events), Vector(ExecutionFailure.AuthorityRevoked))
  }

  test("an invalid write response and an explicit unknown outcome are audited as unknown and cannot replay") {
    List(ProviderError.InvalidResponse, ProviderError.OutcomeUnknown).traverse_ : error =>
      val write = descriptor.copy(action = Action.Write)
      for
        h <- harness
        id <- h.issue(bound = write)
        _ = h.client.respond = IO.raiseError(ProviderExecutionException(error))
        outcome <- h.run(id, runDescriptor = write).attempt
        again <- h.run(id, runDescriptor = write).attempt
        events <- h.events
        _ <- IO:
          assertProviderError(outcome, ProviderError.OutcomeUnknown)
          assertEquals(failures(events), Vector(ExecutionFailure.CompletionUnknown))
          assertEquals(redemptionDenial(again), Some(LeaseRedemptionDenial.AlreadyRedeemed))
          assertEquals(h.client.calls, 1)
      yield ()
  }

  test("a credential acquisition timeout before dispatch does not become an unknown write outcome") {
    val write = descriptor.copy(action = Action.Write)
    for
      h <- harness
      id <- h.issue(bound = write)
      _ = h.strategy.onLookup = IO.raiseError(ProviderExecutionException(ProviderError.Timeout))
      outcome <- h.run(id, runDescriptor = write).attempt
      events <- h.events
    yield
      assertProviderError(outcome, ProviderError.Timeout)
      assertEquals(failures(events), Vector(ExecutionFailure.ProviderUnavailable))
      assertEquals(h.client.calls, 0)
  }
