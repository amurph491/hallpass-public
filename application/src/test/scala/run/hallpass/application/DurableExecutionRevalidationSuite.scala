package run.hallpass.application

import java.time.Instant

import cats.effect.IO
import cats.syntax.all.*
import io.circe.Json
import munit.CatsEffectSuite
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Regression coverage for the execution-time authority boundary. These checks deliberately exercise the proof
  * created at issuance against freshly loaded state: an authentication result alone must never be sufficient to
  * retrieve a provider credential. */
final class DurableExecutionRevalidationSuite extends CatsEffectSuite:
  private val slackReadKey = CapabilityKey.parse("Slack.Message.Read").getOrElse(fail("capability key"))
  // Same resource and action as slackReadKey, but a distinct catalog capability.
  private val slackExportKey = CapabilityKey.parse("Slack.Message.Export").getOrElse(fail("capability key"))
  private val at = Instant.parse("2026-09-21T12:00:00Z")
  private val tenant = TenantId.random()
  private val agentId = AgentId.random()
  private val agent = Principal.Agent(agentId)
  private val human = Principal.Human(UserId.random())
  private val credentialId = AgentCredentialId.random()
  private val resource = Resource(ResourceId.random(), tenant, ResourceType.Provider, None, "slack-workspace", None)
  private val resourceScope = ResourceScope.fromPath(Vector(resource)).getOrElse(fail("scope"))
  private val descriptor = CapabilityDescriptor(resource.id, Action.Read, slackReadKey)
  private val toolId = ResourceId.random()
  private val capabilityId = CatalogCapabilityId
    .parse("00000000-0000-4000-8000-000000000031")
    .getOrElse(fail("catalog capability ID"))
  private val audience = ExecutorAudience.parse("test.durable.revalidation").getOrElse(fail("audience"))
  private val policyId = PolicyId.random()
  private val delegation = Delegation(
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

  private def policies(version: Int = 1, effect: Effect = Effect.Allow): Policies =
    Policies(
      Vector(
        Policy(
          policyId,
          PolicyVersion.from(version).getOrElse(fail("policy version")),
          NonEmptySet.one(PolicyStatement(human, resource.id, NonEmptySet.one(Action.Read), None, Constraints.empty, effect))
        )
      )
    )

  private def snapshot(
      currentPolicies: Policies = policies(),
      currentDelegations: Vector[Delegation] = Vector(delegation),
      currentToolId: Option[ResourceId] = Some(toolId)
  ): AuthoritySnapshot =
    AuthoritySnapshot(
      resourceScope,
      CatalogCapability(capabilityId.value.toString, "Slack.Message.Read", descriptor),
      currentPolicies,
      currentDelegations,
      currentToolId
    )

  /** The same delegation (same ID, grantor, and grantee) granting a different capability key on the same resource and
    * action. */
  private def delegationFor(key: CapabilityKey): Delegation =
    delegation.copy(capabilities = NonEmptySet.one(CapabilityDescriptor(resource.id, Action.Read, key)))

  private def issuedLease: ExecutionLease = issuedLeaseFor(slackReadKey, AuthorizationRequestId.random())

  private def issuedLeaseFor(key: CapabilityKey, requestId: AuthorizationRequestId): ExecutionLease =
    val keyDelegation = delegationFor(key)
    val request = AuthorizationRequest(
      requestId,
      tenant,
      IdentityChain(agent, Vector(delegation.id), None, ExecutionContext.LocalProcess),
      resourceScope,
      key,
      Action.Read,
      AuthorizationContext.empty
    )
    val capability = AuthorizationEngine.authorize(policies(), request, Vector(keyDelegation), at) match
      case AuthorizationResult.Authorized(value) => value
      case other                                 => fail(s"expected authorization, got $other")
    ExecutionLease
      .issueForBroker(capability, request.id, audience, at, at.plusSeconds(60))
      .fold(error => fail(s"lease issuance failed: $error"), identity)

  private def redeemedLease: RedeemedExecutionLease =
    val lease = issuedLease
    redeemedLeaseWithContextFrom(lease, lease)

  /** Redeems `lease` with an audit context built from `contextLease`, as if the stored evidence disagreed. */
  private def redeemedLeaseWithContextFrom(lease: ExecutionLease, contextLease: ExecutionLease): RedeemedExecutionLease =
    val context = ExecutionAuditContext
      .fromLease(
        contextLease,
        ExecutionAuditMetadata.authenticatedInvocation(
          authenticatedContext(),
          ExecutionAuditCorrelationId.parse("durable-revalidation-suite").getOrElse(fail("correlation")),
          toolId,
          capabilityId,
          binding
        )
      )
      .fold(error => fail(s"audit context failed: $error"), identity)
    RedeemedExecutionLease.from(lease, context)

  private val operation = OperationId.parse("test.revalidation.read@1").getOrElse(fail("operation"))
  private val binding = InvocationBinding.compute(
    tenant,
    agentId,
    operation,
    slackReadKey,
    Action.Read,
    resource.id,
    PipelineProvider.workspace,
    PipelineProvider.externalId(resource.externalId),
    Json.obj("query" -> Json.fromString("roadmap"))
  )

  private final class Credentials(
      result: Either[AgentCredentialCurrentStateError, Unit]
  ) extends AgentCredentialCurrentStateRepository[IO]:
    var calls = Vector.empty[(TenantId, AgentCredentialId, AgentId)]

    def ensureActive(
        checkedTenant: TenantId,
        checkedCredential: AgentCredentialId,
        checkedAgent: AgentId,
        checkedAt: Instant
    ): IO[Either[AgentCredentialCurrentStateError, Unit]] =
      calls = calls :+ (checkedTenant, checkedCredential, checkedAgent)
      IO.pure(result)

  /** Serves `result` for scoped loads, read each time the effect runs. `snapshotFor` is unused by revalidation. */
  private final class Authority(
      result: => Either[AuthorityLoadError, AuthoritySnapshot]
  ) extends AuthorityRepository[IO]:
    var calls = Vector.empty[(TenantId, Principal, String)]
    var scopes = Vector.empty[ResourceScope]

    def snapshotFor(
        checkedTenant: TenantId,
        checkedPrincipal: Principal,
        externalTool: String
    ): IO[Either[AuthorityLoadError, AuthoritySnapshot]] =
      IO.raiseError(AssertionError("revalidation must load authority within the resolved scope"))

    def snapshotWithin(
        checkedTenant: TenantId,
        checkedPrincipal: Principal,
        externalTool: String,
        scope: ResourceScope
    ): IO[Either[AuthorityLoadError, AuthoritySnapshot]] =
      IO.delay:
        calls = calls :+ (checkedTenant, checkedPrincipal, externalTool)
        scopes = scopes :+ scope
        result

  /** The catalog's current answer for the leased resource, read each time the effect runs. */
  private final class Resources(result: => Option[ResourceScope] = Some(resourceScope)) extends ResourceCatalog:
    var currentCalls = Vector.empty[(TenantId, ResourceId)]

    def rootScope(t: TenantId, root: ResourceKind[?]): IO[Option[(ExternalId, ResourceScope)]] =
      IO.raiseError(AssertionError("revalidation must not resolve roots"))
    def selectedScope(t: TenantId, kind: ResourceKind[?], externalId: ExternalId): IO[Option[ResourceScope]] =
      IO.raiseError(AssertionError("revalidation must not resolve selections"))
    def currentScope(t: TenantId, resourceId: ResourceId): IO[Option[ResourceScope]] =
      IO.delay:
        currentCalls = currentCalls :+ (t, resourceId)
        result

  private final class Tools(
      result: Either[AuthorityLoadError, ExternalToolId]
  ) extends TrustedToolLookup[IO]:
    var calls = Vector.empty[(TenantId, ResourceId)]

    def externalToolFor(
        checkedTenant: TenantId,
        checkedTool: ResourceId
    ): IO[Either[AuthorityLoadError, ExternalToolId]] =
      calls = calls :+ (checkedTenant, checkedTool)
      IO.pure(result)

  private val externalTool = ExternalToolId.parse("slack_search_messages").getOrElse(fail("tool"))

  private def authenticatedContext(
      authenticatedTenant: TenantId = tenant,
      authenticatedAgentId: AgentId = agentId
  ): AuthenticatedAgentContext =
    AuthenticatedAgentContext.authenticated(
      authenticatedTenant,
      authenticatedAgentId,
      credentialId,
      at,
      UnverifiedExecutionClaims.empty
    )

  test("unchanged current authority accepts the redeemed proof") {
    val credentials = new Credentials(Right(()))
    val authority = new Authority(Right(snapshot()))
    val tools = new Tools(Right(externalTool))
    new CurrentStateExecutionRevalidator(credentials, authority, tools, new Resources()).revalidate(redeemedLease, at).map: result =>
      assertEquals(result, Right(()))
      assertEquals(authority.calls, Vector((tenant, agent, externalTool.value)))
  }

  test("revalidation reads current state when its effect runs, not when it is constructed") {
    var current = snapshot()
    val credentials = new Credentials(Right(()))
    val authority = new Authority(Right(current))
    val tools = new Tools(Right(externalTool))
    val pending =
      new CurrentStateExecutionRevalidator(credentials, authority, tools, new Resources()).revalidate(redeemedLease, at)
    // A revocation commits after the effect was built but before it runs.
    current = snapshot(currentDelegations = Vector(delegation.copy(revokedAt = Some(at))))
    assertEquals(authority.calls, Vector.empty, "constructing the effect must not read authority")
    pending.map: result =>
      assertEquals(result, Left(DurableExecutionRevalidationDenial.AuthorityChanged))
      assertEquals(authority.calls.size, 1)
  }

  test("a resource that is no longer addressable denies as changed authority without loading authority") {
    val credentials = new Credentials(Right(()))
    val authority = new Authority(Right(snapshot()))
    val tools = new Tools(Right(externalTool))
    val resources = new Resources(None)
    new CurrentStateExecutionRevalidator(credentials, authority, tools, resources)
      .revalidate(redeemedLease, at)
      .map: result =>
        assertEquals(result, Left(DurableExecutionRevalidationDenial.AuthorityChanged))
        assertEquals(resources.currentCalls, Vector((tenant, resource.id)))
        assertEquals(authority.calls, Vector.empty)
  }

  test("authority is loaded within the catalog's current scope for the leased resource") {
    val credentials = new Credentials(Right(()))
    val authority = new Authority(Right(snapshot()))
    val tools = new Tools(Right(externalTool))
    val resources = new Resources()
    new CurrentStateExecutionRevalidator(credentials, authority, tools, resources)
      .revalidate(redeemedLease, at)
      .map: result =>
        assertEquals(result, Right(()))
        assertEquals(authority.scopes, Vector(resourceScope))
  }

  test("a changed external ID on the same resource UUID denies before authority is loaded") {
    val changedScope =
      ResourceScope.fromPath(Vector(resource.copy(externalId = "different-workspace"))).getOrElse(fail("scope"))
    assertEquals(changedScope.target.id, resource.id)
    val credentials = new Credentials(Right(()))
    val authority = new Authority(Right(snapshot()))
    val tools = new Tools(Right(externalTool))
    val resources = new Resources(Some(changedScope))
    new CurrentStateExecutionRevalidator(credentials, authority, tools, resources)
      .revalidate(redeemedLease, at)
      .map: result =>
        assertEquals(result, Left(DurableExecutionRevalidationDenial.AuthorityChanged))
        assertEquals(resources.currentCalls, Vector((tenant, resource.id)))
        assertEquals(authority.calls, Vector.empty)
  }

  test("a scoped authority answer with a different external ID is rejected") {
    val changedScope =
      ResourceScope.fromPath(Vector(resource.copy(externalId = "different-workspace"))).getOrElse(fail("scope"))
    val credentials = new Credentials(Right(()))
    val authority = new Authority(Right(snapshot().copy(scope = changedScope)))
    val tools = new Tools(Right(externalTool))
    new CurrentStateExecutionRevalidator(credentials, authority, tools, new Resources())
      .revalidate(redeemedLease, at)
      .map: result =>
        assertEquals(result, Left(DurableExecutionRevalidationDenial.AuthorityChanged))
        assertEquals(authority.calls.size, 1)
  }

  test("infrastructure failure remains a failed effect and stops subsequent reads") {
    val failure = IllegalStateException("credential repository unavailable")
    val credentials = new AgentCredentialCurrentStateRepository[IO]:
      def ensureActive(t: TenantId, c: AgentCredentialId, a: AgentId, checkedAt: Instant) =
        IO.raiseError[Either[AgentCredentialCurrentStateError, Unit]](failure)
    val authority = new Authority(Right(snapshot()))
    val tools = new Tools(Right(externalTool))
    new CurrentStateExecutionRevalidator(credentials, authority, tools, new Resources()).revalidate(redeemedLease, at).attempt.map: result =>
      assertEquals(result, Left(failure))
      assertEquals(tools.calls, Vector.empty)
      assertEquals(authority.calls, Vector.empty)
  }

  test("a credential revoked after authentication denies before mapping or authority reads") {
    val credentials = new Credentials(Left(AgentCredentialCurrentStateError.NoLongerActive))
    val authority = new Authority(Right(snapshot()))
    val tools = new Tools(Right(externalTool))

    new CurrentStateExecutionRevalidator(credentials, authority, tools, new Resources()).revalidate(redeemedLease, at).map: result =>
      assertEquals(result, Left(DurableExecutionRevalidationDenial.EnrollmentCredentialInactive))
      assertEquals(credentials.calls, Vector((tenant, credentialId, agentId)))
      assertEquals(tools.calls, Vector.empty)
      assertEquals(authority.calls, Vector.empty)
  }

  /** A lease authorized by a consumed human approval under a REQUIRE_APPROVAL policy. */
  private def approvedLease: RedeemedExecutionLease =
    val request = AuthorizationRequest(
      AuthorizationRequestId.random(),
      tenant,
      IdentityChain(agent, Vector(delegation.id), None, ExecutionContext.LocalProcess),
      resourceScope,
      slackReadKey,
      Action.Read,
      AuthorizationContext.empty
    )
    val approvalBinding = ApprovalBinding.parse("a" * 64).getOrElse(fail("binding"))
    val required = AuthorizationEngine.authorize(policies(effect = Effect.RequireApproval), request, Vector(delegation), at) match
      case AuthorizationResult.ApprovalRequired(value) => value
      case other                                       => fail(s"expected approval required, got $other")
    val granted = GrantedApproval(
      ApprovalId.random(), tenant, agent, human.asInstanceOf[Principal.Human], approvalBinding, required.requiredCapability, required.policyId,
      required.policyVersion, at.plusSeconds(600)
    )
    val capability = AuthorizationEngine.authorizeWithApproval(
      policies(effect = Effect.RequireApproval), request, Vector(delegation), approvalBinding, Some(granted), at
    ) match
      case AuthorizationResult.Authorized(value) => value
      case other                                 => fail(s"expected approved authorization, got $other")
    val lease = ExecutionLease
      .issueForBroker(capability, request.id, audience, at, at.plusSeconds(60))
      .fold(error => fail(s"lease issuance failed: $error"), identity)
    redeemedLeaseWithContextFrom(lease, lease)

  test("an approved lease stays valid while the same policy version still requires approval over the same chain") {
    val authority = new Authority(Right(snapshot(currentPolicies = policies(effect = Effect.RequireApproval))))
    new CurrentStateExecutionRevalidator(new Credentials(Right(())), authority, new Tools(Right(externalTool)), new Resources())
      .revalidate(approvedLease, at)
      .map(result => assertEquals(result, Right(())))
  }

  test("an approved lease is invalidated by a new policy version, a revoked delegation, a deny, or an allow") {
    val changedStates = Vector(
      snapshot(currentPolicies = policies(version = 2, effect = Effect.RequireApproval)),
      snapshot(
        currentPolicies = policies(effect = Effect.RequireApproval),
        currentDelegations = Vector(delegation.copy(revokedAt = Some(at.minusSeconds(1))))
      ),
      snapshot(currentPolicies = policies(effect = Effect.Deny)),
      // Even a now-permissive policy changes the evidence: the approved proof no longer describes current authority.
      snapshot(currentPolicies = policies(effect = Effect.Allow))
    )
    changedStates
      .traverse: changed =>
        new CurrentStateExecutionRevalidator(new Credentials(Right(())), new Authority(Right(changed)), new Tools(Right(externalTool)), new Resources())
          .revalidate(approvedLease, at)
      .map(results => assertEquals(results, Vector.fill(4)(Left(DurableExecutionRevalidationDenial.AuthorityChanged))))
  }

  test("a lease without an approval is not revalidated by a policy that now requires approval") {
    val authority = new Authority(Right(snapshot(currentPolicies = policies(effect = Effect.RequireApproval))))
    new CurrentStateExecutionRevalidator(new Credentials(Right(())), authority, new Tools(Right(externalTool)), new Resources())
      .revalidate(redeemedLease, at)
      .map(result => assertEquals(result, Left(DurableExecutionRevalidationDenial.AuthorityChanged)))
  }

  test("a changed mapping, policy version, or delegation proof invalidates the redeemed lease") {
    val revokedDelegation = delegation.copy(revokedAt = Some(at.minusSeconds(1)))
    val changedStates = Vector(
      snapshot(currentToolId = Some(ResourceId.random())),
      snapshot(currentPolicies = policies(version = 2)),
      snapshot(currentDelegations = Vector(revokedDelegation))
    )

    val outcomes = changedStates.map: changed =>
      val credentials = new Credentials(Right(()))
      val authority = new Authority(Right(changed))
      val tools = new Tools(Right(externalTool))
      new CurrentStateExecutionRevalidator(credentials, authority, tools, new Resources()).revalidate(redeemedLease, at)

    outcomes.sequence.map: results =>
      assertEquals(results, Vector.fill(3)(Left(DurableExecutionRevalidationDenial.AuthorityChanged)))
  }

  test("unavailable or unmapped current state fails closed") {
    val unavailableCredentials = new Credentials(Left(AgentCredentialCurrentStateError.Unavailable))
    val unusedAuthority = new Authority(Right(snapshot()))
    val unusedTools = new Tools(Right(externalTool))
    val unavailable = new CurrentStateExecutionRevalidator(unavailableCredentials, unusedAuthority, unusedTools, new Resources())
      .revalidate(redeemedLease, at)

    val activeCredentials = new Credentials(Right(()))
    val authority = new Authority(Right(snapshot()))
    val missingTools = new Tools(Left(AuthorityLoadError.UnmappedTool))
    val unmapped = new CurrentStateExecutionRevalidator(activeCredentials, authority, missingTools, new Resources())
      .revalidate(redeemedLease, at)

    (unavailable, unmapped).mapN: (credentialResult, toolResult) =>
      assertEquals(credentialResult, Left(DurableExecutionRevalidationDenial.AuthorityUnavailable))
      assertEquals(toolResult, Left(DurableExecutionRevalidationDenial.AuthorityChanged))
      assertEquals(unusedTools.calls, Vector.empty)
      assertEquals(unusedAuthority.calls, Vector.empty)
      assertEquals(authority.calls, Vector.empty)
  }

  test("audit proof construction rejects tenant and principal metadata that do not match the issued lease") {
    val lease = issuedLease
    val correlation = ExecutionAuditCorrelationId.parse("audit-proof-rejection").getOrElse(fail("correlation"))
    val wrongTenant = ExecutionAuditContext.fromLease(
      lease,
      ExecutionAuditMetadata.authenticatedInvocation(authenticatedContext(authenticatedTenant = TenantId.random()), correlation, toolId, capabilityId, binding)
    )
    val wrongAgent = ExecutionAuditContext.fromLease(
      lease,
      ExecutionAuditMetadata.authenticatedInvocation(authenticatedContext(authenticatedAgentId = AgentId.random()), correlation, toolId, capabilityId, binding)
    )

    assertEquals(wrongTenant, Left(ExecutionAuditContextError.LeaseTenantDoesNotMatchInvocation))
    assertEquals(wrongAgent, Left(ExecutionAuditContextError.LeasePrincipalDoesNotMatchAuthenticatedAgent))
  }

  test("a lease whose capability key differs from the current snapshot's key is denied as changed authority") {
    // The snapshot is internally consistent and would authorize its own key (Slack.Message.Export) for the same
    // resource, action, tool, and catalog capability ID. Only the key differs from the lease's Slack.Message.Read.
    val exportDescriptor = CapabilityDescriptor(resource.id, Action.Read, slackExportKey)
    val exportSnapshot = AuthoritySnapshot(
      resourceScope,
      CatalogCapability(capabilityId.value.toString, "Slack.Message.Export", exportDescriptor),
      policies(),
      Vector(delegationFor(slackExportKey)),
      Some(toolId)
    )
    val credentials = new Credentials(Right(()))
    val authority = new Authority(Right(exportSnapshot))
    val tools = new Tools(Right(externalTool))
    new CurrentStateExecutionRevalidator(credentials, authority, tools, new Resources()).revalidate(redeemedLease, at).map: result =>
      assertEquals(result, Left(DurableExecutionRevalidationDenial.AuthorityChanged))
      assertEquals(authority.calls.size, 1, "the current snapshot was loaded and compared")
  }

  test("a lease whose capability key differs from its audit-context evidence is denied before any current-state read") {
    val requestId = AuthorizationRequestId.random()
    val lease = issuedLeaseFor(slackReadKey, requestId)
    val contextLease = issuedLeaseFor(slackExportKey, requestId)
    assertEquals(lease.capability, slackReadKey)
    assertEquals(contextLease.capability, slackExportKey)
    assertEquals(lease.action, contextLease.action)
    assertEquals(lease.resource, contextLease.resource)
    val credentials = new Credentials(Right(()))
    val authority = new Authority(Right(snapshot()))
    val tools = new Tools(Right(externalTool))
    new CurrentStateExecutionRevalidator(credentials, authority, tools, new Resources())
      .revalidate(redeemedLeaseWithContextFrom(lease, contextLease), at)
      .map: result =>
        assertEquals(result, Left(DurableExecutionRevalidationDenial.LeaseContextMismatch))
        assertEquals(credentials.calls, Vector.empty)
        assertEquals(tools.calls, Vector.empty)
        assertEquals(authority.calls, Vector.empty)
  }
