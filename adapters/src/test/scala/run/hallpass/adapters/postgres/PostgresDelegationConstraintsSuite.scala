package run.hallpass.adapters.postgres

import java.sql.DriverManager
import java.time.Instant
import cats.effect.IO
import cats.syntax.all.*
import org.typelevel.doobie.*
import munit.CatsEffectSuite
import org.testcontainers.containers.PostgreSQLContainer
import org.testcontainers.DockerClientFactory
import scala.compiletime.uninitialized
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

final class PostgresDelegationConstraintsSuite extends CatsEffectSuite:
  private var container: PostgreSQLContainer[?] = uninitialized
  private var config: DatabaseConfig = uninitialized
  private var dockerAvailable = false

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      container = PostgreSQLContainer("postgres:18.6-alpine")
      container.start()
      val admin = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
      try
        val statement = admin.createStatement()
        statement.execute(
          "create role hallpass login password 'test-password' nosuperuser nocreatedb nocreaterole noreplication"
        )
        statement.execute("grant connect on database test to hallpass")
        statement.execute("grant usage, create on schema public to hallpass")
      finally admin.close()
      config = DatabaseConfig
        .fromEnvironment(
          Map(
            "HALLPASS_DB_URL" -> container.getJdbcUrl,
            "HALLPASS_DB_USER" -> "hallpass",
            "HALLPASS_DB_PASSWORD" -> "test-password"
          )
        )
        .toOption
        .get

  override def afterAll(): Unit = if dockerAvailable then container.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for PostgreSQL integration tests")

  private def key(raw: String) = ContextKey.parse(raw).getOrElse(fail("key"))
  private def values(raw: String*) =
    NonEmptySet.from(raw.map(v => ContextValue.parse(v).getOrElse(fail("value"))).toSet).getOrElse(fail("empty"))
  private def valueIn(k: String, vs: String*) = Constraint.ValueIn(key(k), values(vs*))
  private def ok[A](result: Either[DelegationError, A]): IO[A] =
    result.fold(e => IO.raiseError(RuntimeException(s"$e")), IO.pure)

  private final case class Setup(
      repository: PostgresControlPlane,
      agent: Agent,
      capability: CatalogCapability,
      resource: ResourceId
  )

  private def setup(xa: Transactor[IO], name: String): IO[Setup] =
    val repository = PostgresControlPlane(xa)
    for
      _ <- DemoBootstrap.run(xa)
      agent <- repository.create(DemoBootstrap.Tenant, CreateAgent(name, None)).flatMap:
        _.fold(_ => IO.raiseError(RuntimeException("agent")), IO.pure)
      capabilities <- repository.capabilities(DemoBootstrap.Tenant)
      read = capabilities.find(_.name == "Slack.Message.Read").getOrElse(fail("capability"))
      slack <- SlackConnectionFixture.ensure(xa, Instant.now())
    yield Setup(repository, agent, read, slack.resource)

  private def grant(s: Setup, constraints: Constraints): IO[Either[DelegationError, Delegation]] =
    s.repository.create(
      DemoBootstrap.Tenant,
      CreateDelegation(
        DemoBootstrap.Human,
        Principal.Agent(s.agent.id),
        s.capability.id,
        s.resource,
        s.capability.descriptor.action,
        None,
        constraints
      )
    )

  private def ownerSql(sql: String): Unit =
    val c = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
    try c.createStatement().execute(sql)
    finally c.close()

  private def jsonbOctetLength(json: String): Int =
    val c = DriverManager.getConnection(container.getJdbcUrl, container.getUsername, container.getPassword)
    try
      val statement = c.prepareStatement("select octet_length(?::jsonb::text)")
      try
        statement.setString(1, json)
        val rows = statement.executeQuery()
        try
          rows.next()
          rows.getInt(1)
        finally rows.close()
      finally statement.close()
    finally c.close()

  private def evaluate(s: Setup, context: AuthorizationContext): IO[AuthorizationDecision] =
    s.repository.snapshotFor(DemoBootstrap.Tenant, Principal.Agent(s.agent.id), "slack_search_messages").map:
      case Left(error)     => fail(s"snapshot failed: $error")
      case Right(snapshot) =>
        val request = AuthorizationRequest(
          AuthorizationRequestId.random(),
          DemoBootstrap.Tenant,
          IdentityChain(Principal.Agent(s.agent.id), snapshot.delegations.map(_.id), None, ExecutionContext.LocalProcess),
          snapshot.scope,
          s.capability.descriptor.capability,
          s.capability.descriptor.action,
          context
        )
        AuthorizationEngine.evaluate(snapshot.policies, request, snapshot.delegations, Instant.now())

  test("ValueIn constraints round trip create to load and an empty grant stays unconstrained") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      for
        s <- setup(xa, "Constraint Round Trip")
        constraints = Constraints(
          Set(valueIn("gmail.recipients", "b@example.com", "a@example.com"), valueIn("crm.properties", "email"))
        )
        created <- grant(s, constraints).flatMap(ok)
        listed <- s.repository.listForGrantee(DemoBootstrap.Tenant, Principal.Agent(s.agent.id))
        snapshot <- s.repository.snapshotFor(DemoBootstrap.Tenant, Principal.Agent(s.agent.id), "slack_search_messages")
        _ <- IO(ownerSql(s"update delegations set revoked_at = now() where id = '${created.id}'"))
        plain <- grant(s, Constraints.empty)
      yield
        assertEquals(created.constraints, constraints)
        assertEquals(listed.map(_.constraints), Vector(constraints))
        assertEquals(snapshot.map(_.delegations.map(_.constraints)), Right(Vector(constraints)))
        assertEquals(plain.map(_.constraints), Right(Constraints.empty))
  }

  test("a delegation with ValueIn allows facts inside the allowlist and denies outside or missing facts") {
    requireDocker()
    PostgresDatabase.resource(config).use: xa =>
      for
        s <- setup(xa, "Constraint Evaluation")
        _ <- grant(s, Constraints(Set(valueIn("slack.channels", "c1", "c2")))).flatMap(ok)
        inside <- evaluate(s, AuthorizationContext.withFacts(Map.empty, Map(key("slack.channels") -> Set(ContextValue("c1")))))
        outside <- evaluate(
          s,
          AuthorizationContext.withFacts(Map.empty, Map(key("slack.channels") -> Set(ContextValue("c1"), ContextValue("c9"))))
        )
        missing <- evaluate(s, AuthorizationContext.empty)
      yield
        assert(inside.isInstanceOf[AuthorizationDecision.Allow], s"inside: $inside")
        assert(outside.isInstanceOf[AuthorizationDecision.Deny], s"outside: $outside")
        assert(missing.isInstanceOf[AuthorizationDecision.Deny], s"missing: $missing")
  }

  test("stored malformed delegation constraints fail authority loading closed") {
    requireDocker()
    val malformed = Vector(
      """{"other":1}""",
      """{"value_in":[]}""",
      """{"value_in":{"Bad Key":["a"]}}""",
      """{"value_in":{"k.a":[]}}""",
      """{"value_in":{"k.a":["a","a"]}}""",
      """{"value_in":{"k.a":[1]}}""",
      """{"value_in":{"k.a":[""]}}""",
      """{"value_in":{"k.a":"a"}}""",
      """{"value_in":{"k.a":["a"]},"extra":{}}""",
      s"""{"value_in":{"k.a":[${(1 to 201).map(i => "\"v" + i + "\"").mkString(",")}]}}""",
      s"""{"value_in":{${(1 to 21).map(i => "\"k" + i + "\":[\"a\"]").mkString(",")}}}"""
    )
    PostgresDatabase.resource(config).use: xa =>
      for
        s <- setup(xa, "Constraint Malformed")
        created <- grant(s, Constraints.empty).flatMap(ok)
        results <- malformed.traverse: doc =>
          IO(ownerSql(s"update delegations set constraints = '${doc.replace("'", "''")}'::jsonb where id = '${created.id}'")) *>
            s.repository.snapshotFor(DemoBootstrap.Tenant, Principal.Agent(s.agent.id), "slack_search_messages")
      yield results.zip(malformed).foreach: (result, doc) =>
        assertEquals(result.map(_ => ()), Left(AuthorityLoadError.InvalidStoredAuthority), doc.take(60))
  }

  test("creating a delegation refuses unsupported or out of bound constraints") {
    requireDocker()
    val tooManyValues = (1 to 201).map(i => s"v$i")
    val tooLargeToStore = (1 to 200).map: i =>
      val suffix = i.toString
      "x" * (ContextValue.MaximumLength - suffix.length) + suffix
    val tooManyKeys = (1 to 21).map(i => valueIn(s"k$i", "a"))
    PostgresDatabase.resource(config).use: xa =>
      for
        s <- setup(xa, "Constraint Refusal")
        refused <- Vector(
          Constraints(Set(Constraint.RequireContext(key("a.b"), ContextValue("x")))),
          Constraints(Set(Constraint.ValueIn(ContextKey("Bad Key"), values("a")))),
          Constraints(Set(Constraint.ValueIn(key("a.b"), NonEmptySet.one(ContextValue(""))))),
          Constraints(Set(valueIn("a.b", tooManyValues*))),
          Constraints(Set(valueIn("a.b", tooLargeToStore*))),
          Constraints(tooManyKeys.toSet),
          Constraints(Set(valueIn("a.b", "x"), valueIn("a.b", "y")))
        ).traverse(grant(s, _))
        listed <- s.repository.listForGrantee(DemoBootstrap.Tenant, Principal.Agent(s.agent.id))
      yield
        assertEquals(refused, Vector.fill(7)(Left(DelegationError.InvalidRequest)))
        assertEquals(listed, Vector.empty)
  }

  test("near-limit UTF-8 constraints fit JSONB storage and round trip through Postgres") {
    requireDocker()
    val asciiValues = (1 to 124).map: i =>
      val suffix = i.toString
      ContextValue("a" * (ContextValue.MaximumLength - suffix.length) + suffix)
    val multibyteValues = (1 to 41).map: i =>
      val suffix = i.toString
      ContextValue("界" * (ContextValue.MaximumLength - suffix.length) + suffix)
    val cases = Vector(
      Constraints(Set(Constraint.ValueIn(key("limits.ascii"), NonEmptySet.from(asciiValues.toSet).get))),
      Constraints(Set(Constraint.ValueIn(key("limits.unicode"), NonEmptySet.from(multibyteValues.toSet).get)))
    )
    PostgresDatabase.resource(config).use: xa =>
      for
        s <- setup(xa, "Constraint Near Limit")
        results <- cases.traverse: constraints =>
          val encoded = DelegationConstraintsJson.encode(constraints).getOrElse(fail("encoding near-limit constraints"))
          val rendered = encoded.noSpaces
          val storedBytes = IO.blocking(jsonbOctetLength(rendered))
          storedBytes.flatMap: size =>
            grant(s, constraints).flatMap(ok).flatMap: created =>
              s.repository.listForGrantee(DemoBootstrap.Tenant, Principal.Agent(s.agent.id)).map: listed =>
                (size, created, listed.find(_.id == created.id).map(_.constraints))
      yield results.foreach: (size, created, loaded) =>
        assert(size <= DelegationConstraintsJson.MaximumStoredBytes, s"stored size: $size")
        assertEquals(loaded, Some(created.constraints))
  }
