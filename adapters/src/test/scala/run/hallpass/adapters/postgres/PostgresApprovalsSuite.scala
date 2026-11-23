package run.hallpass.adapters.postgres

import java.sql.DriverManager
import java.time.Instant
import java.util.UUID
import scala.compiletime.uninitialized
import cats.effect.IO
import cats.effect.unsafe.implicits.global
import cats.syntax.all.*
import io.circe.Json
import munit.CatsEffectSuite
import org.postgresql.util.PSQLException
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.implicits.javatimedrivernative.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Durable approvals over V24, served to the application as a non-owner runtime role (external migration mode). The
  * owner only provisions tenants and principals, and forges the states the runtime role cannot reach. */
final class PostgresApprovalsSuite extends CatsEffectSuite:
  private var container: PostgreSQLContainer[?] = uninitialized
  private var dockerAvailable = false
  private var ownerXa: Transactor[IO] = uninitialized
  private var runtimeXa: Transactor[IO] = uninitialized
  private var releaseTransactors: IO[Unit] = IO.unit
  private val Owner = "authai_owner"
  private val App = "authai_app"
  private val Password = "test-password"
  private val runtimeRole = RuntimeRole.parse(App).toOption.get

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      val admin = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
      try
        val statement = admin.createStatement()
        statement.execute(s"create role $Owner login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"create role $App login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"grant connect on database test to $Owner, $App")
        statement.execute("revoke create on schema public from public")
        statement.execute(s"grant usage, create on schema public to $Owner")
        statement.execute(s"grant usage on schema public to $App")
      finally admin.close()
      val setup = for
        _ <- PostgresDatabase.migrateAsOwner(config(Owner), runtimeRole)
        owner <- PostgresDatabase.resource(config(Owner)).allocated
        runtime <- PostgresDatabase.resourceWithSchema(config(App), MigrationMode.External).allocated
      yield (owner, runtime)
      val ((owner, releaseOwner), ((runtime, _), releaseRuntime)) = setup.unsafeRunSync()
      ownerXa = owner
      runtimeXa = runtime
      releaseTransactors = releaseRuntime *> releaseOwner

  override def afterAll(): Unit =
    if dockerAvailable then
      releaseTransactors.unsafeRunSync()
      container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  private def config(user: String): DatabaseConfig =
    DatabaseConfig
      .fromEnvironment(
        Map("HALLPASS_DB_URL" -> container.getJdbcUrl, "HALLPASS_DB_USER" -> user, "HALLPASS_DB_PASSWORD" -> Password)
      )
      .toOption
      .get

  // ---- fixtures -----------------------------------------------------------------------------------------------------

  /** A freshly provisioned tenant (Slack catalog, owner policies), a second human and an agent. */
  private final case class Fixture(ids: ProvisioningIds, otherHuman: UserId, agent: AgentId, otherAgent: AgentId):
    def tenant: TenantId = ids.tenant
    def adminUuid: UUID = UUID.fromString(ids.administratorPrincipal.toString)
    def admin: Principal.Human = Principal.Human(ids.administratorPrincipal)
    def other: Principal.Human = Principal.Human(otherHuman)
    def resource: ResourceId = ids.slackResource
    def capability: UUID = ids.readCapability
    def policy: PolicyId = PolicyId.parse(ids.readPolicy.toString).toOption.get

  private def ownerTx[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(ownerXa)

  private def runtimeTx[A](tenant: TenantId)(program: ConnectionIO[A]): IO[A] =
    (TenantSession.establish(tenant) *> program).transact(runtimeXa)

  private def fixture(): IO[Fixture] =
    val ids = ProvisioningIds.random()
    val subject = UUID.randomUUID().toString
    val request = TenantProvisioningRequest
      .from("Approvals", s"ap-${subject.take(8)}", ExternalIdentity.from("https://idp.example.com", subject).toOption.get)
      .toOption
      .get
    val built = Fixture(ids, UserId.random(), AgentId.random(), AgentId.random())
    for
      _ <- TenantProvisioning.program(request, ids).transact(ownerXa)
      _ <- ownerTx(built.tenant):
        for
          _ <- sql"insert into principals (id, tenant_id, kind) values (${built.otherHuman.toString}::uuid, ${built.tenant.toString}::uuid, 'HUMAN')".update.run
          _ <- sql"insert into principals (id, tenant_id, kind) values (${built.agent.toString}::uuid, ${built.tenant.toString}::uuid, 'AGENT')".update.run
          _ <- sql"insert into principals (id, tenant_id, kind) values (${built.otherAgent.toString}::uuid, ${built.tenant.toString}::uuid, 'AGENT')".update.run
        yield ()
    yield built

  private val t0 = Instant.parse("2026-01-01T00:00:00Z")
  private val expiry = t0.plusSeconds(3600)
  private def store = PostgresApprovalStore(runtimeXa)

  private def digest(): ApprovalBinding =
    ApprovalBinding.parse(UUID.randomUUID().toString.replace("-", "") * 2).getOrElse(fail("binding"))

  private def record(
      f: Fixture,
      approver: Option[Principal.Human] = None,
      requestedAt: Instant = t0,
      expiresAt: Instant = expiry,
      binding: ApprovalBinding = digest()
  ): ApprovalRecord =
    ApprovalRecord(
      id = ApprovalId.random(),
      tenant = f.tenant,
      agent = f.agent,
      approver = approver.getOrElse(f.admin),
      operation = OperationId.parse("slack.search.messages@1").getOrElse(fail("operation")),
      tool = ExternalToolId.parse("slack_search_messages").getOrElse(fail("tool")),
      binding = binding,
      catalogCapability = f.capability.toString,
      requiredCapability = CapabilityDescriptor(
        f.resource,
        Action.Read,
        CapabilityKey.parse("Slack.Message.Read").getOrElse(fail("key"))
      ),
      policyId = f.policy,
      policyVersion = PolicyVersion.from(1).getOrElse(fail("version")),
      preview = Json.obj("query" -> Json.fromString("quarterly numbers")),
      requestedAt = requestedAt,
      expiresAt = expiresAt,
      status = ApprovalStatus.Pending,
      decidedAt = None,
      consumedAt = None
    )

  private def approved(f: Fixture): IO[ApprovalRecord] =
    val pending = record(f)
    store.create(pending) *> store.decide(f.tenant, pending.id, f.admin, approve = true, t0.plusSeconds(10)).flatMap:
      case Right(decided) => IO.pure(decided)
      case Left(error)    => IO.raiseError(AssertionError(s"expected approval, received $error"))

  private def consume(f: Fixture, r: ApprovalRecord, at: Instant = t0.plusSeconds(20)): IO[Boolean] =
    store.consume(f.tenant, r.id, r.agent, r.binding, AuthorizationRequestId.random(), at)

  private def sqlStateOf(attempt: IO[?]): IO[Option[String]] =
    attempt.attempt.map:
      case Right(_)                     => None
      case Left(failure: PSQLException) => Option(failure.getSQLState)
      case Left(failure)                => throw failure

  private def assertRefused(attempt: IO[?], state: String, clue: String): IO[Unit] =
    sqlStateOf(attempt).map(found => assertEquals(found, Some(state), clue))

  private def rowState(f: Fixture, id: ApprovalId): IO[(String, Option[UUID], Boolean)] =
    runtimeTx(f.tenant):
      sql"select status, decided_by, consumed_at is not null from approvals where id = ${id.toString}::uuid"
        .query[(String, Option[UUID], Boolean)].unique

  // ---- store behavior -----------------------------------------------------------------------------------------------

  test("create then find round-trips the record, with the capability built from the catalog row") {
    requireDocker()
    for
      f <- fixture()
      r = record(f)
      _ <- store.create(r)
      found <- store.find(f.tenant, r.id)
    yield assertEquals(found, Some(r))
  }

  test("find reports a missing approval as absent") {
    requireDocker()
    fixture().flatMap(f => store.find(f.tenant, ApprovalId.random())).map(assertEquals(_, None))
  }

  test("create refuses a capability that does not match the tenant's catalog") {
    requireDocker()
    for
      f <- fixture()
      wrongAction = record(f).copy(requiredCapability = record(f).requiredCapability.copy(action = Action.Write))
      wrongKey = record(f).copy(requiredCapability = record(f).requiredCapability.copy(capability = CapabilityKey.parse("Slack.Message.Send").getOrElse(fail("key"))))
      first <- store.create(wrongAction).attempt
      second <- store.create(wrongKey).attempt
    yield
      assert(first.isLeft, "an action that differs from the catalog row must not be stored")
      assert(second.isLeft, "a capability key that differs from the catalog row must not be stored")
  }

  test("pendingFor filters by approver, status, expiry and tenant, newest first") {
    requireDocker()
    for
      f <- fixture()
      older = record(f, requestedAt = t0)
      newer = record(f, requestedAt = t0.plusSeconds(5))
      expired = record(f, requestedAt = t0, expiresAt = t0.plusSeconds(30))
      decided = record(f, requestedAt = t0.plusSeconds(1))
      notMine = record(f, approver = Some(f.other))
      _ <- List(older, newer, expired, decided, notMine).traverse_(store.create)
      _ <- store.decide(f.tenant, decided.id, f.admin, approve = false, t0.plusSeconds(2))
      at = t0.plusSeconds(60)
      mine <- store.pendingFor(f.tenant, f.admin, at, 10)
      theirs <- store.pendingFor(f.tenant, f.other, at, 10)
      limited <- store.pendingFor(f.tenant, f.admin, at, 1)
      zero <- store.pendingFor(f.tenant, f.admin, at, 0)
      elsewhere <- fixture().flatMap(g => store.pendingFor(g.tenant, f.admin, at, 10))
    yield
      assertEquals(mine.map(_.id), Vector(newer.id, older.id))
      assertEquals(theirs.map(_.id), Vector(notMine.id))
      assertEquals(limited.map(_.id), Vector(newer.id))
      assertEquals(zero, Vector.empty)
      assertEquals(elsewhere, Vector.empty)
  }

  test("the approver approves or denies a pending approval once, and the record reflects it") {
    requireDocker()
    for
      f <- fixture()
      yes = record(f)
      no = record(f)
      _ <- List(yes, no).traverse_(store.create)
      approvedResult <- store.decide(f.tenant, yes.id, f.admin, approve = true, t0.plusSeconds(10))
      deniedResult <- store.decide(f.tenant, no.id, f.admin, approve = false, t0.plusSeconds(11))
    yield
      assertEquals(
        approvedResult,
        Right(yes.copy(status = ApprovalStatus.Approved, decidedAt = Some(t0.plusSeconds(10))))
      )
      assertEquals(deniedResult, Right(no.copy(status = ApprovalStatus.Denied, decidedAt = Some(t0.plusSeconds(11)))))
      assertEquals(approvedResult.toOption.flatMap(_.granted.map(_.id)), Some(yes.id))
      assertEquals(deniedResult.toOption.flatMap(_.granted), None)
  }

  test("a non-approver cannot decide: NotApprover, and the row stays pending") {
    requireDocker()
    for
      f <- fixture()
      r = record(f)
      _ <- store.create(r)
      byOther <- store.decide(f.tenant, r.id, f.other, approve = true, t0.plusSeconds(10))
      byAgentless <- store.decide(f.tenant, r.id, f.other, approve = false, t0.plusSeconds(10))
      state <- rowState(f, r.id)
    yield
      assertEquals(byOther, Left(ApprovalDecisionError.NotApprover))
      assertEquals(byAgentless, Left(ApprovalDecisionError.NotApprover))
      assertEquals(state, ("PENDING", None, false))
  }

  test("deciding a missing approval is NotFound, and a decided one is AlreadyDecided") {
    requireDocker()
    for
      f <- fixture()
      r = record(f)
      _ <- store.create(r)
      missing <- store.decide(f.tenant, ApprovalId.random(), f.admin, approve = true, t0.plusSeconds(10))
      first <- store.decide(f.tenant, r.id, f.admin, approve = false, t0.plusSeconds(10))
      again <- store.decide(f.tenant, r.id, f.admin, approve = true, t0.plusSeconds(11))
      state <- rowState(f, r.id)
    yield
      assertEquals(missing, Left(ApprovalDecisionError.NotFound))
      assert(first.isRight)
      assertEquals(again, Left(ApprovalDecisionError.AlreadyDecided))
      assertEquals(state._1, "DENIED")
  }

  test("an expired approval cannot be decided, including exactly at its expiry") {
    requireDocker()
    for
      f <- fixture()
      r = record(f)
      _ <- store.create(r)
      after <- store.decide(f.tenant, r.id, f.admin, approve = true, expiry.plusSeconds(1))
      boundary <- store.decide(f.tenant, r.id, f.admin, approve = true, expiry)
      state <- rowState(f, r.id)
    yield
      assertEquals(after, Left(ApprovalDecisionError.Expired))
      assertEquals(boundary, Left(ApprovalDecisionError.Expired))
      assertEquals(state, ("PENDING", None, false))
  }

  test("concurrent decisions: exactly one wins and the others see AlreadyDecided") {
    requireDocker()
    for
      f <- fixture()
      r = record(f)
      _ <- store.create(r)
      results <- List.fill(4)(store.decide(f.tenant, r.id, f.admin, approve = true, t0.plusSeconds(10))).parSequence
    yield
      assertEquals(results.count(_.isRight), 1)
      assertEquals(results.collect { case Left(error) => error }.distinct, List(ApprovalDecisionError.AlreadyDecided))
  }

  test("consume succeeds once and is then false") {
    requireDocker()
    for
      f <- fixture()
      r <- approved(f)
      first <- consume(f, r)
      second <- consume(f, r)
      found <- store.find(f.tenant, r.id)
    yield
      assert(first)
      assert(!second)
      assertEquals(found.flatMap(_.consumedAt), Some(t0.plusSeconds(20)))
      assertEquals(found.flatMap(_.granted), None, "a consumed approval grants nothing")
  }

  test("consume is false for the wrong agent, wrong binding, a denied, a pending and an expired approval") {
    requireDocker()
    for
      f <- fixture()
      r <- approved(f)
      wrongAgent <- store.consume(f.tenant, r.id, f.otherAgent, r.binding, AuthorizationRequestId.random(), t0.plusSeconds(20))
      wrongBinding <- store.consume(f.tenant, r.id, r.agent, digest(), AuthorizationRequestId.random(), t0.plusSeconds(20))
      atExpiry <- consume(f, r, at = expiry)
      denied = record(f)
      _ <- store.create(denied)
      _ <- store.decide(f.tenant, denied.id, f.admin, approve = false, t0.plusSeconds(10))
      deniedResult <- consume(f, denied)
      pending = record(f)
      _ <- store.create(pending)
      pendingResult <- consume(f, pending)
      missing <- store.consume(f.tenant, ApprovalId.random(), f.agent, digest(), AuthorizationRequestId.random(), t0.plusSeconds(20))
      untouched <- rowState(f, r.id)
      stillWorks <- consume(f, r)
    yield
      assert(!wrongAgent)
      assert(!wrongBinding)
      assert(!atExpiry)
      assert(!deniedResult)
      assert(!pendingResult)
      assert(!missing)
      assertEquals(untouched, ("APPROVED", Some(f.adminUuid), false))
      assert(stillWorks, "failed attempts must not consume the approval")
  }

  test("two concurrent consumers: exactly one wins") {
    requireDocker()
    for
      f <- fixture()
      r <- approved(f)
      results <- List.fill(4)(consume(f, r)).parSequence
      second <- (consume(f, r), consume(f, r)).parTupled
    yield
      assertEquals(results.count(identity), 1)
      assertEquals(second, (false, false))
  }

  test("another tenant cannot find, decide or consume") {
    requireDocker()
    for
      f <- fixture()
      g <- fixture()
      r <- approved(f)
      pending = record(f)
      _ <- store.create(pending)
      found <- store.find(g.tenant, r.id)
      decided <- store.decide(g.tenant, pending.id, f.admin, approve = true, t0.plusSeconds(10))
      consumed <- store.consume(g.tenant, r.id, r.agent, r.binding, AuthorizationRequestId.random(), t0.plusSeconds(20))
      state <- rowState(f, pending.id)
      stillMine <- consume(f, r)
    yield
      assertEquals(found, None)
      assertEquals(decided, Left(ApprovalDecisionError.NotFound))
      assert(!consumed)
      assertEquals(state._1, "PENDING")
      assert(stillMine)
  }

  test("an invalid stored row fails the effect and never grants") {
    requireDocker()
    for
      f <- fixture()
      r <- approved(f)
      // The owner forges an operation ID the application cannot parse, by bypassing the V24 check.
      _ <- ownerTx(f.tenant):
        sql"alter table approvals disable trigger approvals_transition_check".update.run *>
          sql"alter table approvals drop constraint approvals_operation_id_check".update.run *>
          sql"update approvals set operation_id = 'NOT-AN-OPERATION' where id = ${r.id.toString}::uuid".update.run *>
          sql"alter table approvals enable trigger approvals_transition_check".update.run
      found <- store.find(f.tenant, r.id).attempt
      decided <- store.decide(f.tenant, r.id, f.admin, approve = true, t0.plusSeconds(30)).attempt
    yield
      assert(found.isLeft, "an undecodable row must fail find")
      assert(decided.isLeft, "an undecodable row must fail decide")
  }

  // ---- the V24 trigger and grants, from the runtime role --------------------------------------------------------------

  private def insertDirect(f: Fixture, status: String, decidedBy: Option[UUID], capability: UUID, resource: ResourceId, tenant: TenantId, context: Option[TenantId] = None): IO[Int] =
    runtimeTx(context.getOrElse(tenant)):
      sql"""insert into approvals (id, tenant_id, agent_principal_id, approver_principal_id, operation_id, tool_name, binding_digest,
                                    capability_id, action, resource_id, policy_id, policy_version, preview, requested_at,
                                    expires_at, status, decided_by, decided_at)
             values (${UUID.randomUUID().toString}::uuid, ${tenant.toString}::uuid, ${f.agent.toString}::uuid,
                     ${f.ids.administratorPrincipal.toString}::uuid, 'slack.search.messages@1', 'slack_search_messages', ${digest().value},
                     ${capability.toString}::uuid, 'READ', ${resource.toString}::uuid, ${f.ids.readPolicy.toString}::uuid, 1,
                     '{}'::jsonb, $t0, $expiry, $status, ${decidedBy.map(_.toString)}::uuid, ${decidedBy.map(_ => t0.plusSeconds(1))})""".update.run

  test("the trigger refuses a new row that is not pending and unconsumed") {
    requireDocker()
    for
      f <- fixture()
      _ <- assertRefused(
        insertDirect(f, "APPROVED", Some(f.adminUuid), f.capability, f.resource, f.tenant),
        "23514",
        "an approved row must not be insertable"
      )
      _ <- assertRefused(
        runtimeTx(f.tenant)(
          sql"""insert into approvals (id, tenant_id, agent_principal_id, approver_principal_id, operation_id, tool_name, binding_digest,
                                        capability_id, action, resource_id, policy_id, policy_version, preview, requested_at,
                                        expires_at, status, consumed_at, consumed_request_id)
                 values (${UUID.randomUUID().toString}::uuid, ${f.tenant.toString}::uuid, ${f.agent.toString}::uuid,
                         ${f.ids.administratorPrincipal.toString}::uuid, 'slack.search.messages@1', 'slack_search_messages', ${digest().value},
                         ${f.capability.toString}::uuid, 'READ', ${f.resource.toString}::uuid, ${f.ids.readPolicy.toString}::uuid, 1,
                         '{}'::jsonb, $t0, $expiry, 'PENDING', $t0, ${UUID.randomUUID().toString}::uuid)""".update.run
        ),
        "23514",
        "a consumed row must not be insertable"
      )
    yield ()
  }

  test("the trigger makes the request immutable, even for the owner") {
    requireDocker()
    for
      f <- fixture()
      r = record(f)
      _ <- store.create(r)
      binding <- sqlStateOf(ownerTx(f.tenant)(sql"update approvals set binding_digest = ${digest().value} where id = ${r.id.toString}::uuid".update.run))
      preview <- sqlStateOf(ownerTx(f.tenant)(sql"""update approvals set preview = '{"query":"other"}'::jsonb where id = ${r.id.toString}::uuid""".update.run))
      expires <- sqlStateOf(ownerTx(f.tenant)(sql"update approvals set expires_at = ${expiry.plusSeconds(3600)} where id = ${r.id.toString}::uuid".update.run))
      state <- rowState(f, r.id)
    yield
      assertEquals(binding, Some("23514"))
      assertEquals(preview, Some("23514"))
      assertEquals(expires, Some("23514"))
      assertEquals(state, ("PENDING", None, false))
  }

  test("the trigger refuses re-deciding and re-consuming, and consuming a denied row") {
    requireDocker()
    for
      f <- fixture()
      r <- approved(f)
      _ <- consume(f, r)
      redecide <- sqlStateOf(
        runtimeTx(f.tenant)(
          sql"""update approvals set status = 'DENIED' where id = ${r.id.toString}::uuid""".update.run
        )
      )
      reconsume <- sqlStateOf(
        runtimeTx(f.tenant)(
          sql"""update approvals set consumed_at = ${t0.plusSeconds(99)}, consumed_request_id = ${UUID.randomUUID().toString}::uuid
                 where id = ${r.id.toString}::uuid""".update.run
        )
      )
      denied = record(f)
      _ <- store.create(denied)
      _ <- store.decide(f.tenant, denied.id, f.admin, approve = false, t0.plusSeconds(10))
      consumeDenied <- sqlStateOf(
        runtimeTx(f.tenant)(
          sql"""update approvals set consumed_at = ${t0.plusSeconds(20)}, consumed_request_id = ${UUID.randomUUID().toString}::uuid
                 where id = ${denied.id.toString}::uuid""".update.run
        )
      )
      deniedState <- rowState(f, denied.id)
      original <- store.find(f.tenant, r.id)
    yield
      assertEquals(redecide, Some("23514"))
      assertEquals(reconsume, Some("23514"))
      assertEquals(consumeDenied, Some("23514"))
      assertEquals(deniedState, ("DENIED", Some(f.adminUuid), false))
      assertEquals(original.map(_.status), Some(ApprovalStatus.Approved))
      assertEquals(original.flatMap(_.consumedAt), Some(t0.plusSeconds(20)))
  }

  test("the runtime role cannot delete approvals or update columns outside the decision and consumption set") {
    requireDocker()
    for
      f <- fixture()
      r = record(f)
      _ <- store.create(r)
      delete <- sqlStateOf(runtimeTx(f.tenant)(sql"delete from approvals where id = ${r.id.toString}::uuid".update.run))
      binding <- sqlStateOf(runtimeTx(f.tenant)(sql"update approvals set binding_digest = ${digest().value} where id = ${r.id.toString}::uuid".update.run))
      agent <- sqlStateOf(runtimeTx(f.tenant)(sql"update approvals set agent_principal_id = ${f.otherAgent.toString}::uuid where id = ${r.id.toString}::uuid".update.run))
      approver <- sqlStateOf(runtimeTx(f.tenant)(sql"update approvals set approver_principal_id = ${f.otherHuman.toString}::uuid where id = ${r.id.toString}::uuid".update.run))
      expires <- sqlStateOf(runtimeTx(f.tenant)(sql"update approvals set expires_at = ${expiry.plusSeconds(1)} where id = ${r.id.toString}::uuid".update.run))
      truncate <- sqlStateOf(runtimeTx(f.tenant)(sql"truncate approvals".update.run))
      trigger <- sqlStateOf(sql"select authai_check_approval_transition()".query[String].unique.transact(runtimeXa))
      found <- store.find(f.tenant, r.id)
    yield
      List(delete, binding, agent, approver, expires, truncate, trigger).foreach(assertEquals(_, Some("42501")))
      assertEquals(found, Some(r))
  }

  test("foreign keys keep a capability or resource of another tenant out of an approval") {
    requireDocker()
    for
      f <- fixture()
      g <- fixture()
      _ <- assertRefused(
        insertDirect(f, "PENDING", None, g.capability, f.resource, f.tenant),
        "23503",
        "a capability of another tenant must not be referenced"
      )
      _ <- assertRefused(
        insertDirect(f, "PENDING", None, f.capability, g.resource, f.tenant),
        "23503",
        "a resource of another tenant must not be referenced"
      )
      viaStore <- store.create(record(f).copy(catalogCapability = g.capability.toString)).attempt
      _ <- assertRefused(
        insertDirect(f, "PENDING", None, f.capability, f.resource, g.tenant, Some(f.tenant)),
        "42501",
        "a row for another tenant must fail row-level security"
      )
    yield assert(viaStore.isLeft, "the store must not create an approval over another tenant's capability")
  }
