package run.hallpass.application

import java.time.{Duration, Instant}
import cats.effect.{Deferred, IO, Ref}
import cats.effect.std.Semaphore
import cats.syntax.all.*
import io.circe.Json
import munit.CatsEffectSuite
import scala.concurrent.duration.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Exercises OAuth refresh through the same redeemed-lease execution lifecycle used by providers. */
final class OAuthRefreshExecutionSuite extends CatsEffectSuite:
  private final case class Input(value: String)
  private sealed trait Account
  private val provider = ProviderId.parse("sample").getOrElse(fail("provider"))
  private given accountKind: ResourceKind[Account] = ResourceKind.root[Account]("sample.account", provider, ResourceType.Account, Custody.Workspace)
  private val descriptor = new OperationDescriptor[Input, Account]:
    val id = OperationId.parse("sample.account.read@1").getOrElse(fail("operation"))
    val tool = ExternalToolId.parse("sample_read").getOrElse(fail("tool"))
    val description = "sample account read"
    val capability = CapabilityKey.parse("Sample.Account.Read").getOrElse(fail("capability"))
    val action = Action.Read
    def target: ResourceKind[Account] = accountKind
    val audience = ExecutorAudience.parse("test.sample.executor").getOrElse(fail("audience"))
    val inputSchema = Json.obj()
    def decode(arguments: Json): Either[ArgumentError, Input] = Right(Input("report"))
    def locate(input: Input): ResourceLocator[Account] = ResourceLocator.ConnectionRoot()
    def facts(input: Input): AuthorizationContext = AuthorizationContext.empty
    def canonical(input: Input): Json = Json.obj("value" -> Json.fromString(input.value))

  private val now = Instant.parse("2026-09-30T12:00:00Z")
  private val accessToken = "initial-access-token"
  private val refreshToken = "initial-refresh-token"
  private val rotatedAccess = "rotated-access-token"
  private val rotatedRefresh = "rotated-refresh-token"

  private final class Codec extends OAuthTokenCodec:
    def encode(tokens: OAuthTokens): ProviderSecret =
      ProviderSecret.fromUtf8(s"${tokens.accessToken}\n${tokens.refreshToken.getOrElse("")}\n${tokens.expiresAt}")
    def decode(secret: ProviderSecret): Either[ConnectionError, OAuthTokens] =
      String(ProviderSecret.bytes(secret), java.nio.charset.StandardCharsets.UTF_8).split("\\n", -1).toList match
        case access :: refresh :: expiry :: Nil =>
          Either.catchNonFatal(Instant.parse(expiry)).toOption
            .flatMap(at => OAuthTokens.from(access, Option.when(refresh.nonEmpty)(refresh), at))
            .toRight(ConnectionError.InvalidState)
        case _ => Left(ConnectionError.InvalidState)

  private final case class Pointer(reference: SecretReference, expiresAt: Option[Instant], needsReauth: Boolean)

  private final class MemorySecrets(initialReference: SecretReference, initialSecret: ProviderSecret) extends SecretStore[IO]:
    val values = Ref.unsafe[IO, Map[SecretReference, ProviderSecret]](Map(initialReference -> initialSecret))
    val gets = Ref.unsafe[IO, Int](0)
    def put(binding: SecretBinding, secret: ProviderSecret): IO[SecretReference] =
      val reference = SecretReference.random()
      values.update(_.updated(reference, secret)).as(reference)
    def get(binding: SecretBinding, reference: SecretReference): IO[Either[SecretStoreError, ProviderSecret]] =
      gets.update(_ + 1) *> values.get.map(_.get(reference).toRight(SecretStoreError.NotFound))
    def delete(binding: SecretBinding, reference: SecretReference): IO[Unit] = values.update(_ - reference)

  private final class FakeRepository(
      initial: Pointer,
      binding: SecretBinding,
      events: Ref[IO, Vector[String]],
      lock: Semaphore[IO]
  ) extends OAuthRefreshRepository:
    val pointer = Ref.unsafe[IO, Pointer](initial)
    def withCredential[K](lease: RedeemedExecutionLease, target: SelectedResource[K], provider: ProviderId)(use: LockedOAuthCredential => IO[Either[ConnectionError, OAuthTokens]]) =
      lock.permit.use: _ =>
        pointer.get.flatMap: current =>
          if current.needsReauth then IO.pure(Left(ConnectionError.Disabled))
          else
            val slot = new LockedOAuthCredential:
              def binding: SecretBinding = FakeRepository.this.binding
              def reference: SecretReference = current.reference
              def expiresAt: Option[Instant] = current.expiresAt
              def requireReauthorization(at: Instant): IO[Either[ConnectionError, Unit]] =
                events.update(_ :+ "reauthorize") *>
                  pointer.update(_.copy(needsReauth = true)).as(Right(()))
              def restore(at: Instant): IO[Either[ConnectionError, Unit]] =
                events.update(_ :+ "restore") *> pointer.update(_.copy(needsReauth = false)).as(Right(()))
              def publish(reference: SecretReference, expiresAt: Instant, at: Instant): IO[Either[ConnectionError, Unit]] =
                events.update(_ :+ "publish") *>
                  pointer.set(Pointer(reference, Some(expiresAt), needsReauth = false)).as(Right(()))
            use(slot)

  private final class FakeRefresher(
      result: Either[OAuthRefreshError, OAuthTokens],
      repository: FakeRepository,
      events: Ref[IO, Vector[String]],
      executionCount: Ref[IO, Int]
  ) extends OAuthTokenRefresher:
    val calls = Ref.unsafe[IO, Int](0)
    @volatile var effect: IO[Either[OAuthRefreshError, OAuthTokens]] = IO.pure(result)
    def refresh(current: OAuthTokens): IO[Either[OAuthRefreshError, OAuthTokens]] =
      calls.update(_ + 1) *> repository.pointer.get.flatMap: pointer =>
        executionCount.get.flatMap: inside =>
          IO(assert(pointer.needsReauth, "reauthorization marker must commit before refresh endpoint")) *>
            IO(assert(inside > 0, "refresh endpoint must run under the shared execution gate")) *>
            events.update(_ :+ "endpoint") *> IO.defer(effect)

  private final class Client(
      secrets: MemorySecrets,
      repository: FakeRepository,
      events: Ref[IO, Vector[String]],
      executionCount: Ref[IO, Int]
  ) extends ProviderOperationClient[Input, Account, OAuthTokens]:
    val seenRefreshTokens = Ref.unsafe[IO, Vector[Option[String]]](Vector.empty)
    val calls = Ref.unsafe[IO, Int](0)
    def dispatch(target: SelectedResource[Account], input: Input, credential: OAuthTokens): IO[ToolResult] =
      for
        inside <- executionCount.get
        pointer <- repository.pointer.get
        secret <- secrets.values.get.map(_.get(pointer.reference))
        decoded = secret.flatMap(value => new Codec().decode(value).toOption)
        _ <- IO(assert(inside > 0, "provider dispatch must remain under the shared execution gate"))
        _ <- IO(assertEquals(decoded.map(_.refreshToken), Some(credential.refreshToken), "the published secret must be readable before dispatch"))
        _ <- IO(assertEquals(credential.refreshToken, Some(rotatedRefresh)))
        _ <- calls.update(_ + 1) *> seenRefreshTokens.update(_ :+ credential.refreshToken) *> events.update(_ :+ "dispatch")
      yield ToolResult("provider-result")

  private final class Harness(
      val store: InMemoryExecutionLeaseStore,
      val audit: InMemoryExecutionAuditRecorder,
      val secrets: MemorySecrets,
      val repository: FakeRepository,
      val refresher: FakeRefresher,
      val client: Client,
      val validator: Ref[IO, Boolean],
      val executionCount: Ref[IO, Int],
      val events: Ref[IO, Vector[String]],
      val gate: TenantExecutionMutationGate[IO]
  ):
    val clock: Clock[IO] = Clock.fixed(now)
    val credentials = new RefreshableOAuth[Account](provider, repository, secrets, new Codec(), refresher, clock, RefreshTokenRotation.Rotating)
    private val authority = new LeaseAuthorityValidator[IO]:
        def validate(lease: RedeemedExecutionLease, at: Instant): IO[Either[LeaseAuthorityDenial, Unit]] = validator.get.map:
          case true  => Right(())
          case false => Left(LeaseAuthorityDenial.CurrentStateChanged)
    private val executor = new ProviderExecutionService(store, clock, audit, authority, gate)
    def issue(): IO[ExecutionLeaseId] =
      val requestId = AuthorizationRequestId.random()
      val request = AuthorizationRequest(requestId, tenant, IdentityChain.direct(agent), scope, descriptor.capability, descriptor.action, AuthorizationContext.empty)
      val policy = Policy(
        PolicyId.random(), PolicyVersion.from(1).getOrElse(fail("policy version")),
        NonEmptySet.one(PolicyStatement(agent, resource.id, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow))
      )
      val capability = AuthorizationEngine.authorize(Policies(Vector(policy)), request, Vector.empty, now) match
        case AuthorizationResult.Authorized(value) => value
        case other => fail(s"authorization failed: $other")
      val binding = InvocationBinding.of(tenant, agentId, descriptor, target, input)
      val metadata = ExecutionAuditMetadata.authenticatedInvocation(
        AuthenticatedAgentContext.authenticated(tenant, agentId, credentialId, now, UnverifiedExecutionClaims.empty),
        ExecutionAuditCorrelationId.parse("oauth-refresh-execution").getOrElse(fail("correlation")), ResourceId.random(),
        CatalogCapabilityId.parse("00000000-0000-4000-8000-000000000001").getOrElse(fail("catalog capability")), binding
      )
      InMemoryCredentialBroker(store, clock, Duration.ofSeconds(60), audit).issueLease(capability, requestId, descriptor.audience, metadata).map(_.id)
    def run(id: ExecutionLeaseId): IO[ToolResult] =
      executor.execute(id, RegisteredOperation(descriptor, client, credentials), input, target)
    def auditEvents: IO[Vector[ExecutionAuditEvent]] = audit.recorded

  private val tenant = TenantId.random()
  private val agentId = AgentId.random()
  private val agent = Principal.Agent(agentId)
  private val credentialId = AgentCredentialId.random()
  private val resource = Resource(ResourceId.random(), tenant, ResourceType.Account, None, "sample-account", None)
  private val scope = ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope"))
  private val target = SelectedResource.trusted(accountKind, ExternalId.parse(resource.externalId).getOrElse(fail("external id")), scope)
  private val input = Input("report")
  private val oldReference = SecretReference.random()

  private def fixture(refreshResult: Either[OAuthRefreshError, OAuthTokens] = Right(OAuthTokens.from(rotatedAccess, Some(rotatedRefresh), now.plusSeconds(3600)).getOrElse(fail("tokens")))): IO[Harness] =
    val initial = OAuthTokens.from(accessToken, Some(refreshToken), now.plusSeconds(10)).getOrElse(fail("tokens"))
    val codec = new Codec()
    val initialSecret = codec.encode(initial)
    val events = Ref.unsafe[IO, Vector[String]](Vector.empty)
    val executionCount = Ref.unsafe[IO, Int](0)
    val secrets = new MemorySecrets(oldReference, initialSecret)
    val binding = SecretBinding(tenant, ConnectionId.random())
    for
      store <- InMemoryExecutionLeaseStore.create(Clock.fixed(now), Duration.ofSeconds(10), 100)
      audit <- InMemoryExecutionAuditRecorder.create
      pointer = Pointer(oldReference, Some(initial.expiresAt), needsReauth = false)
      lock <- Semaphore[IO](1)
      repository = new FakeRepository(pointer, binding, events, lock)
      validator <- Ref.of[IO, Boolean](true)
      sharedGate <- SingleProcessTenantExecutionMutationGate.create
      trackingGate = new TenantExecutionMutationGate[IO]:
        def withinExecution[A](tenant: TenantId)(operation: ExecutionGatePermit[IO] => IO[A]): IO[A] =
          sharedGate.withinExecution(tenant): permit =>
            executionCount.update(_ + 1) *> operation(new ExecutionGatePermit[IO]:
              def confirmHeld: IO[Unit] = executionCount.get.flatMap(count => IO(assert(count > 0, "gate not held")))
            ).guarantee(executionCount.update(_ - 1))
        def withinMutation[A](tenant: TenantId)(operation: IO[A]): IO[A] = sharedGate.withinMutation(tenant)(operation)
      refresher = new FakeRefresher(refreshResult, repository, events, executionCount)
      client = new Client(secrets, repository, events, executionCount)
    yield new Harness(store, audit, secrets, repository, refresher, client, validator, executionCount, events, trackingGate)

  private def failures(events: Vector[ExecutionAuditEvent]): Vector[ExecutionFailure] =
    events.collect { case ExecutionAuditEvent.ExecutionFailed(_, failure, _) => failure }

  test("refresh is gated, marked before exchange, published before dispatch, and audited to completion") {
    for
      h <- fixture()
      id <- h.issue()
      result <- h.run(id)
      events <- h.auditEvents
      timeline <- h.events.get
      gets <- h.secrets.gets.get
      dispatches <- h.client.calls.get
    yield
      assertEquals(result, ToolResult("provider-result"))
      assert(timeline.indexOf("reauthorize") < timeline.indexOf("endpoint"), timeline.toString)
      assert(timeline.indexOf("endpoint") < timeline.indexOf("publish"), timeline.toString)
      assert(timeline.indexOf("publish") < timeline.indexOf("dispatch"), timeline.toString)
      assertEquals(gets, 1)
      assertEquals(dispatches, 1)
      assertEquals(failures(events), Vector.empty)
      assert(events.exists(_.isInstanceOf[ExecutionAuditEvent.ExecutionCompleted]))
  }

  test("refresh rejection leaves needs-reauth, records one connection failure, and never retries") {
    for
      h <- fixture(Left(OAuthRefreshError.Rejected))
      firstLease <- h.issue()
      first <- h.run(firstLease).attempt
      firstEvents <- h.auditEvents
      pointerAfterFirst <- h.repository.pointer.get
      secondLease <- h.issue()
      second <- h.run(secondLease).attempt
      events <- h.auditEvents
      refreshes <- h.refresher.calls.get
      calls <- h.client.calls.get
    yield
      assert(first.isLeft)
      assert(second.isLeft)
      assert(pointerAfterFirst.needsReauth)
      assertEquals(failures(firstEvents), Vector(ExecutionFailure.ConnectionUnavailable))
      assertEquals(failures(events), Vector(ExecutionFailure.ConnectionUnavailable, ExecutionFailure.ConnectionUnavailable))
      assertEquals(refreshes, 1)
      assertEquals(calls, 0)
  }

  test("revoked authority stops before secret lookup, refresh, and provider dispatch") {
    for
      h <- fixture()
      _ <- h.validator.set(false)
      id <- h.issue()
      result <- h.run(id).attempt
      events <- h.auditEvents
      gets <- h.secrets.gets.get
      refreshes <- h.refresher.calls.get
      calls <- h.client.calls.get
    yield
      assert(result.isLeft)
      assertEquals(failures(events), Vector(ExecutionFailure.AuthorityRevoked))
      assertEquals(gets, 0)
      assertEquals(refreshes, 0)
      assertEquals(calls, 0)
  }

  test("cancellation after the reauthorization marker waits for the bounded exchange, releases gate and lock, and cannot retry refresh") {
    for
      entered <- Deferred[IO, Unit]
      h <- fixture()
      // The exchange is uncancelable and bounded (the real client times out); this one ends unanswered.
      _ = h.refresher.effect =
        entered.complete(()) *> IO.sleep(scala.concurrent.duration.DurationInt(200).millis).as(Left(OAuthRefreshError.Unavailable))
      id <- h.issue()
      fiber <- h.run(id).start
      _ <- entered.get
      _ <- fiber.cancel
      cancelledEvents <- h.auditEvents
      pointer <- h.repository.pointer.get
      mutations <- Ref.of[IO, Int](0)
      _ <- h.gate.withinMutation(tenant)(mutations.update(_ + 1))
      count <- mutations.get
      retryId <- h.issue()
      retry <- h.run(retryId).attempt
      refreshes <- h.refresher.calls.get
      calls <- h.client.calls.get
    yield
      assert(pointer.needsReauth)
      assertEquals(failures(cancelledEvents), Vector(ExecutionFailure.ConnectionUnavailable))
      assertEquals(count, 1)
      assert(retry.isLeft)
      assertEquals(refreshes, 1)
      assertEquals(calls, 0)
  }
