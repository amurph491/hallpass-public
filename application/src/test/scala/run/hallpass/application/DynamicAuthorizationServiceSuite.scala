package run.hallpass.application

import java.time.Instant
import cats.effect.IO
import cats.effect.kernel.Ref
import munit.CatsEffectSuite
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

final class DynamicAuthorizationServiceSuite extends CatsEffectSuite:
  private val slackReadKey = CapabilityKey.parse("Slack.Message.Read").getOrElse(fail("capability key"))
  private val tenant = TenantId.random()
  private val human = Principal.Human(UserId.random())
  private val agent = Principal.Agent(AgentId.random())
  private val resource = Resource(ResourceId.random(), tenant, ResourceType.Provider, None, "workspace", None)
  private val resourceScope = ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope"))
  private val descriptor = CapabilityDescriptor(resource.id, Action.Read, slackReadKey)
  private val capability = CatalogCapability("capability-id", "Slack.Message.Read", descriptor)
  private val policy = Policy(
    PolicyId.random(),
    PolicyVersion.from(1).get,
    NonEmptySet.one(PolicyStatement(human, resource.id, NonEmptySet.one(Action.Read), None, Constraints.empty, Effect.Allow))
  )
  private val active = Delegation(
    DelegationId.random(),
    human,
    agent,
    None,
    NonEmptySet.one(descriptor),
    Constraints.empty,
    Instant.EPOCH,
    None,
    None
  )

  test("durable authority changes and revocation affect the next decision") {
    for
      state <- Ref.of[IO, Option[Delegation]](None)
      events <- Ref.of[IO, Vector[AuthorizationEvent]](Vector.empty)
      authority = new AuthorityRepository[IO]:
        def snapshotFor(t: TenantId, p: Principal, tool: String) = state.get.map: delegation =>
          if tool != "slack_search_messages" then Left(AuthorityLoadError.UnmappedTool)
          else Right(AuthoritySnapshot(resourceScope, capability, Policies(Vector(policy)), delegation.toVector))
        def snapshotWithin(t: TenantId, p: Principal, tool: String, scope: ResourceScope) =
          IO.raiseError(AssertionError("dynamic authorization loads authority at the tool's mapped resource"))
      journal = new AuthorizationJournal[IO]:
        def record(t: TenantId, event: AuthorizationEvent) = events.update(_ :+ event)
        def recent(t: TenantId, limit: Int) = IO.pure(Vector.empty)
      service = DynamicAuthorizationService[IO](authority, journal)
      before <- service.authorize(tenant, agent, "slack_search_messages", "before", Instant.now())
      _ <- state.set(Some(active))
      granted <- service.authorize(tenant, agent, "slack_search_messages", "granted", Instant.now())
      _ <- state.set(Some(active.copy(revokedAt = Some(Instant.now().minusSeconds(1)))))
      revoked <- service.authorize(tenant, agent, "slack_search_messages", "revoked", Instant.now())
      recorded <- events.get
    yield
      assert(before.isInstanceOf[AuthorizationResult.Denied])
      assert(granted.isInstanceOf[AuthorizationResult.Authorized])
      assertEquals(revoked, AuthorizationResult.Denied(DenialReason.InactiveDelegation(active.id)))
      assertEquals(recorded.map(_.correlationId), Vector("before", "granted", "revoked"))
  }

  test("unknown tools fail closed and are journaled without a fabricated capability") {
    for
      recorded <- Ref.of[IO, Option[AuthorizationEvent]](None)
      authority = new AuthorityRepository[IO]:
        def snapshotFor(t: TenantId, p: Principal, tool: String) = IO.pure(Left(AuthorityLoadError.UnmappedTool))
        def snapshotWithin(t: TenantId, p: Principal, tool: String, scope: ResourceScope) =
          IO.raiseError(AssertionError("dynamic authorization loads authority at the tool's mapped resource"))
      journal = new AuthorizationJournal[IO]:
        def record(t: TenantId, event: AuthorizationEvent) = recorded.set(Some(event))
        def recent(t: TenantId, limit: Int) = IO.pure(Vector.empty)
      result <- DynamicAuthorizationService[IO](authority, journal).authorize(
        tenant,
        agent,
        "unknown",
        "corr",
        Instant.now()
      )
      event <- recorded.get
    yield
      assertEquals(result, AuthorizationResult.Denied(DenialReason.UnmappedTool))
      assertEquals(event.flatMap(_.capability), None)
      assertEquals(event.flatMap(_.resource), None)
  }
