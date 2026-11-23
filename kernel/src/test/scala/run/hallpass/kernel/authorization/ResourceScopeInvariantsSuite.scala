package run.hallpass.kernel.authorization

import java.time.Instant
import munit.ScalaCheckSuite
import org.scalacheck.Gen
import org.scalacheck.Prop.forAll
import run.hallpass.kernel.*

/** Trusted containment and personal custody. Every property starts from an authorized baseline, so a restriction
  * cannot pass only because the generated request was already denied.
  *
  * The generated tree is: root → (target's ancestors …) → target, plus a sibling of the target and a child of the
  * target. Grants are placed on some element of the target's path, so they cover the target.
  */
final class ResourceScopeInvariantsSuite extends ScalaCheckSuite:
  private val at = Instant.parse("2026-09-30T12:00:00Z")
  private val key = CapabilityKey.parse("GitHub.Issue.Read").getOrElse(fail("static key"))
  private val version = PolicyVersion.from(1).getOrElse(fail("version"))
  private val effects = Gen.oneOf(Effect.values.toSeq)
  private def nonEmpty[A](values: Set[A]): NonEmptySet[A] =
    NonEmptySet.from(values).getOrElse(fail("generated empty set"))

  private final case class Tree(
      tenant: TenantId,
      /** Target first, root last. */
      path: Vector[Resource],
      sibling: Resource,
      child: Resource
  ):
    def target: Resource = path.head
    def root: Resource = path.last
    def scopeOf(resource: Resource): ResourceScope =
      val chain =
        if resource == child then child +: path
        else if resource == sibling then sibling +: path.tail
        else path.dropWhile(_ != resource)
      ResourceScope.fromPath(chain).getOrElse(fail(s"generated scope for $resource"))
    def all: Vector[Resource] = child +: sibling +: path
    def scopes: ResourceId => Option[ResourceScope] = id => all.find(_.id == id).map(scopeOf)

  private def resource(tenant: TenantId, parent: Option[Resource], custodian: Option[Principal]): Resource =
    Resource(ResourceId.random(), tenant, ResourceType.Repository, parent.map(_.id), "generated", custodian)

  /** Depth of the target's path is 1–(MaximumDepth − 1), leaving room for the target's child. */
  private def trees(custodian: Option[Principal] = None): Gen[Tree] =
    Gen.chooseNum(1, ResourceScope.MaximumDepth - 1).map: depth =>
      val tenant = TenantId.random()
      val root = resource(tenant, None, custodian)
      val rootToTarget = (1 until depth).foldLeft(Vector(root))((built, _) => built :+ resource(tenant, built.lastOption, None))
      val path = rootToTarget.reverse
      val sibling = resource(tenant, path.lift(1), None)
      val child = resource(tenant, path.headOption, None)
      Tree(tenant, path, if depth == 1 then sibling.copy(parent = None) else sibling, child)

  private val human = Principal.Human(UserId.random())
  private val agent = Principal.Agent(AgentId.random())

  private def statement(subject: Principal, on: Resource, effect: Effect = Effect.Allow) =
    PolicyStatement(subject, on.id, NonEmptySet.one(Action.Read), None, Constraints.empty, effect)
  private def policies(statements: PolicyStatement*): Policies =
    Policies(statements.toVector.map(value => Policy(PolicyId.random(), version, NonEmptySet.one(value))))
  private def delegation(grantor: Principal, grantee: Principal, on: Resource, parent: Option[Delegation] = None) =
    Delegation(
      DelegationId.random(),
      grantor,
      grantee,
      parent.map(_.id),
      NonEmptySet.one(CapabilityDescriptor(on.id, Action.Read, key)),
      Constraints.empty,
      at.minusSeconds(60),
      parent.flatMap(_.expiresAt),
      None
    )
  private def request(scope: ResourceScope, subject: Principal, chain: Vector[Delegation]) =
    AuthorizationRequest(
      AuthorizationRequestId.random(),
      scope.tenant,
      IdentityChain(subject, chain.map(_.id), None, ExecutionContext.LocalProcess),
      scope,
      key,
      Action.Read,
      AuthorizationContext.empty
    )
  private def evaluate(policies: Policies, request: AuthorizationRequest, chain: Vector[Delegation]) =
    AuthorizationEngine.evaluate(policies, request, chain, at)
  private def isAllow(decision: AuthorizationDecision) = decision.isInstanceOf[AuthorizationDecision.Allow]

  /** An element of the target's path (the target itself or one of its ancestors). */
  private def onPath(tree: Tree, pick: Int): Resource = tree.path(pick % tree.path.size)

  property("a grant anywhere on the target's path covers the target") {
    forAll(trees(), Gen.chooseNum(0, 64), Gen.chooseNum(0, 64)) { (tree, policyAt, grantAt) =>
      val grant = delegation(human, agent, onPath(tree, grantAt))
      val decision = evaluate(
        policies(statement(human, onPath(tree, policyAt))),
        request(tree.scopeOf(tree.target), agent, Vector(grant)),
        Vector(grant)
      )
      assert(isAllow(decision), decision)
    }
  }

  property("a grant on a sibling never covers the target") {
    forAll(trees(), Gen.chooseNum(0, 64)) { (tree, policyAt) =>
      val scope = tree.scopeOf(tree.target)
      val owner = policies(statement(human, onPath(tree, policyAt)))
      val onTarget = delegation(human, agent, tree.target)
      assert(isAllow(evaluate(owner, request(scope, agent, Vector(onTarget)), Vector(onTarget))))
      val onSibling = delegation(human, agent, tree.sibling)
      assertEquals(
        evaluate(owner, request(scope, agent, Vector(onSibling)), Vector(onSibling)),
        AuthorizationDecision.Deny(DenialReason.CapabilityNotDelegated(onSibling.id))
      )
      // An owner policy on the sibling alone grants nothing on the target either.
      assertEquals(
        evaluate(policies(statement(human, tree.sibling)), request(scope, human, Vector.empty), Vector.empty),
        AuthorizationDecision.Deny(DenialReason.NoMatchingAuthority)
      )
    }
  }

  property("a grant on a child never covers its ancestors") {
    forAll(trees(), Gen.chooseNum(0, 64)) { (tree, requestAt) =>
      val requested = onPath(tree, requestAt)
      val scope = tree.scopeOf(requested)
      val owner = policies(statement(human, tree.root))
      val onRoot = delegation(human, agent, tree.root)
      assert(isAllow(evaluate(owner, request(scope, agent, Vector(onRoot)), Vector(onRoot))))
      val onChild = delegation(human, agent, tree.child)
      assertEquals(
        evaluate(owner, request(scope, agent, Vector(onChild)), Vector(onChild)),
        AuthorizationDecision.Deny(DenialReason.CapabilityNotDelegated(onChild.id))
      )
      assertEquals(
        evaluate(policies(statement(human, tree.child)), request(scope, human, Vector.empty), Vector.empty),
        AuthorizationDecision.Deny(DenialReason.NoMatchingAuthority)
      )
    }
  }

  property("a deny on any ancestor beats an allow on the target, and a deny on the target beats an allow on its root") {
    forAll(trees(), Gen.chooseNum(0, 64), effects) { (tree, denyAt, otherEffect) =>
      val scope = tree.scopeOf(tree.target)
      val allowOnTarget = statement(human, tree.target)
      assert(isAllow(evaluate(policies(allowOnTarget), request(scope, human, Vector.empty), Vector.empty)))
      val denied = evaluate(
        policies(allowOnTarget, statement(human, onPath(tree, denyAt), Effect.Deny), statement(human, tree.root, otherEffect)),
        request(scope, human, Vector.empty),
        Vector.empty
      )
      assert(denied.isInstanceOf[AuthorizationDecision.Deny], denied)
      val targetDeny = evaluate(
        policies(statement(human, tree.root), statement(human, tree.target, Effect.Deny)),
        request(scope, human, Vector.empty),
        Vector.empty
      )
      assert(targetDeny.isInstanceOf[AuthorizationDecision.Deny], targetDeny)
    }
  }

  property("a deny on a sibling or a child never blocks the target") {
    forAll(trees()) { tree =>
      val scope = tree.scopeOf(tree.target)
      val decision = evaluate(
        policies(
          statement(human, tree.root),
          statement(human, tree.sibling, Effect.Deny),
          statement(human, tree.child, Effect.Deny)
        ),
        request(scope, human, Vector.empty),
        Vector.empty
      )
      assert(isAllow(decision), decision)
    }
  }

  property("a child delegation can narrow to a descendant but never widen to an ancestor or a sibling") {
    forAll(trees(), Gen.chooseNum(0, 64)) { (tree, parentAt) =>
      val parentResource = onPath(tree, parentAt)
      val parent = delegation(human, agent, parentResource)
      val service = Principal.Service(ServiceId.random())
      def child(on: Resource) = delegation(agent, service, on, Some(parent))
      val narrowed = child(tree.child)
      assertEquals(Delegation.validateChild(parent, narrowed, tree.scopes), Right(narrowed))
      val same = child(parentResource)
      assertEquals(Delegation.validateChild(parent, same, tree.scopes), Right(same))
      if parentResource != tree.root then
        assertEquals(
          Delegation.validateChild(parent, child(tree.root), tree.scopes),
          Left(DelegationValidationError.CapabilityEscalation)
        )
      if parentResource == tree.target then
        assertEquals(
          Delegation.validateChild(parent, child(tree.sibling), tree.scopes),
          Left(DelegationValidationError.CapabilityEscalation)
        )
      val unknown = child(resource(tree.tenant, Some(tree.target), None))
      assertEquals(
        Delegation.validateChild(parent, unknown, tree.scopes),
        Left(DelegationValidationError.UnknownResource)
      )
      // A scope lookup that answers for a different resource is not trusted.
      assertEquals(
        Delegation.validateChild(parent, narrowed, _ => Some(tree.scopeOf(tree.target))),
        Left(DelegationValidationError.UnknownResource)
      )
    }
  }

  property("another principal's personal resource is never authorized, whatever policies exist") {
    val custodian = Principal.Human(UserId.random())
    forAll(trees(Some(custodian)), Gen.listOf(effects), Gen.chooseNum(0, 64)) { (tree, extraEffects, policyAt) =>
      val scope = tree.scopeOf(tree.target)
      assertEquals(scope.custodian, Some(custodian))
      assert(
        isAllow(evaluate(policies(statement(custodian, tree.root)), request(scope, custodian, Vector.empty), Vector.empty))
      )
      val everything = policies(
        (statement(human, onPath(tree, policyAt)) +: extraEffects.map(effect => statement(human, tree.root, effect)))*
      )
      assertEquals(
        evaluate(everything, request(scope, human, Vector.empty), Vector.empty),
        AuthorizationDecision.Deny(DenialReason.CustodianMismatch)
      )
    }
  }

  property("a delegation from the custodian authorizes, and a chain rooted elsewhere is denied") {
    val custodian = Principal.Human(UserId.random())
    forAll(trees(Some(custodian))) { tree =>
      val scope = tree.scopeOf(tree.target)
      val fromCustodian = delegation(custodian, agent, tree.root)
      assert(
        isAllow(
          evaluate(policies(statement(custodian, tree.root)), request(scope, agent, Vector(fromCustodian)), Vector(fromCustodian))
        )
      )
      val fromOther = delegation(human, agent, tree.root)
      assertEquals(
        evaluate(
          policies(statement(human, tree.root), statement(custodian, tree.root)),
          request(scope, agent, Vector(fromOther)),
          Vector(fromOther)
        ),
        AuthorizationDecision.Deny(DenialReason.CustodianMismatch)
      )
      // The custodian re-delegating through an agent keeps the custodian as the root of authority.
      val service = Principal.Service(ServiceId.random())
      val onward = delegation(agent, service, tree.target, Some(fromCustodian))
      assert(
        isAllow(
          evaluate(
            policies(statement(custodian, tree.root)),
            request(scope, service, Vector(fromCustodian, onward)),
            Vector(fromCustodian, onward)
          )
        )
      )
    }
  }

  property("scope construction rejects broken, cyclic, deep, cross-tenant, and conflicting-custody paths") {
    forAll(trees()) { tree =>
      assertEquals(ResourceScope.fromPath(Vector.empty), Left(ResourceScope.Error.Empty))
      if tree.path.size >= 2 then
        assertEquals(ResourceScope.fromPath(tree.path.reverse), Left(ResourceScope.Error.BrokenParentLink))
        // Dropping the root leaves a path that does not end at a root.
        assertEquals(ResourceScope.fromPath(tree.path.init), Left(ResourceScope.Error.BrokenParentLink))
        val foreign = tree.root.copy(tenant = TenantId.random())
        assertEquals(ResourceScope.fromPath(tree.path.init :+ foreign), Left(ResourceScope.Error.TenantMismatch))
        val otherCustodian = Principal.Human(UserId.random())
        val conflicting = tree.path.updated(0, tree.target.copy(custodian = Some(otherCustodian))).init :+
          tree.root.copy(custodian = Some(human))
        assertEquals(ResourceScope.fromPath(conflicting), Left(ResourceScope.Error.ConflictingCustody))
      assertEquals(ResourceScope.fromPath(tree.target +: tree.path), Left(ResourceScope.Error.Cycle))
      val deep = (1 to ResourceScope.MaximumDepth).foldLeft(Vector(tree.root))((built, _) =>
        built :+ resource(tree.tenant, built.lastOption, None)
      )
      assertEquals(ResourceScope.fromPath(deep.reverse), Left(ResourceScope.Error.TooDeep))
    }
  }

  property("a request whose tenant differs from its scope's tenant is denied") {
    forAll(trees()) { tree =>
      val scope = tree.scopeOf(tree.target)
      val owner = policies(statement(human, tree.root))
      assert(isAllow(evaluate(owner, request(scope, human, Vector.empty), Vector.empty)))
      assertEquals(
        evaluate(owner, request(scope, human, Vector.empty).copy(tenant = TenantId.random()), Vector.empty),
        AuthorizationDecision.Deny(DenialReason.TenantMismatch)
      )
    }
  }
