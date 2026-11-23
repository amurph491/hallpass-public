package run.hallpass.adapters.postgres

import java.sql.DriverManager
import java.time.Instant
import java.util.UUID
import scala.compiletime.uninitialized
import cats.effect.IO
import cats.effect.unsafe.implicits.global
import cats.syntax.all.*
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.PostgreSQLContainer
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.application.*
import run.hallpass.kernel.*

/** The durable binding of OAuth state to its session, provider, redirect, intended connection, and PKCE verifier
  * reference. The schema is migrated by a separate owner role and every state operation runs as the non-owner runtime
  * role, as in production. A verifier itself is never stored here; only its secret-store reference is. */
final class PostgresOAuthStatePkceSuite extends CatsEffectSuite:
  private var container: PostgreSQLContainer[?] = uninitialized
  private var dockerAvailable = false
  private var ownerXa: Transactor[IO] = uninitialized
  private var runtimeXa: Transactor[IO] = uninitialized
  private var releaseTransactors: IO[Unit] = IO.unit
  private val Owner = "authai_owner"
  private val App = "authai_app"
  private val Password = "test-password"
  private val runtimeRole = RuntimeRole.parse(App).toOption.get
  private val random = java.security.SecureRandom()
  private val sessionA = SessionToken.generate(random).oauthBinding
  private val sessionB = SessionToken.generate(random).oauthBinding
  private val redirect = Array.fill[Byte](32)(7)
  private val otherRedirect = Array.fill[Byte](32)(9)
  // The table requires expires_at to be after the database's own created_at, so the base time is the real clock.
  private val t0 = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MILLIS)

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

  private def states = new PostgresOAuthStateRepository(runtimeXa)
  private def connections = new PostgresConnectionRepository(runtimeXa)

  private final case class Fixture(ids: ProvisioningIds):
    def tenant: TenantId = ids.tenant
    def admin: Principal.Human = Principal.Human(ids.administratorPrincipal)
    def catalog: ResourceId = ids.slackResource

  private def fixture(): IO[Fixture] =
    val ids = ProvisioningIds.random()
    val subject = UUID.randomUUID().toString
    val request = TenantProvisioningRequest
      .from("OAuth state", s"os-${subject.take(8)}", ExternalIdentity.from("https://idp.example.com", subject).toOption.get)
      .toOption
      .get
    TenantProvisioning.program(request, ids).transact(ownerXa).as(Fixture(ids))

  private def reserved(f: Fixture): IO[ConnectionId] =
    val id = ConnectionId.random()
    connections.reserve(f.tenant, id, "SLACK", f.admin, t0).as(id)

  private def newState(seed: Char): OAuthState = OAuthState.parse(seed.toString * 43).get

  private def reference(): SecretReference = SecretReference.random()

  private def storedReference(f: Fixture, state: OAuthState): IO[Option[String]] =
    val hash = java.security.MessageDigest.getInstance("SHA-256").digest(state.value.getBytes(java.nio.charset.StandardCharsets.US_ASCII))
    (TenantSession.establish(f.tenant) *>
      sql"select pkce_verifier_reference from oauth_states where tenant_id=${f.tenant.toString}::uuid and state_hash=$hash"
        .query[Option[String]].unique).transact(runtimeXa)

  test("createBound persists the verifier reference, and consumeBound returns it with the intended connection") {
    requireDocker()
    for
      f <- fixture()
      connection <- reserved(f)
      ref = reference()
      state = newState('a')
      _ <- states.createBound(
        f.tenant, f.catalog, ProviderId.Slack, connection, redirect, Some(ref), state, sessionA, t0.plusSeconds(60)
      )
      persisted <- storedReference(f, state)
      consumed <- states.consumeBound(f.tenant, ProviderId.Slack, redirect, state, sessionA, t0.plusSeconds(1))
    yield
      assertEquals(persisted, Some(ref.value))
      assertEquals(consumed, Right(OAuthStateBinding(f.catalog, ProviderId.Slack, connection, Some(ref))))
  }

  test("a PKCE state is consumed once, and the replay is StateAlreadyUsed") {
    requireDocker()
    for
      f <- fixture()
      connection <- reserved(f)
      state = newState('b')
      _ <- states.createBound(
        f.tenant, f.catalog, ProviderId.Slack, connection, redirect, Some(reference()), state, sessionA, t0.plusSeconds(60)
      )
      first <- states.consumeBound(f.tenant, ProviderId.Slack, redirect, state, sessionA, t0.plusSeconds(1))
      second <- states.consumeBound(f.tenant, ProviderId.Slack, redirect, state, sessionA, t0.plusSeconds(2))
    yield
      assert(first.exists(_.pkceVerifier.isDefined))
      assertEquals(second, Left(OAuthError.StateAlreadyUsed))
  }

  test("a PKCE state is consumed only by the same session, provider, and redirect, and a refusal does not consume it") {
    requireDocker()
    for
      f <- fixture()
      connection <- reserved(f)
      ref = reference()
      state = newState('c')
      _ <- states.createBound(
        f.tenant, f.catalog, ProviderId.Slack, connection, redirect, Some(ref), state, sessionA, t0.plusSeconds(60)
      )
      otherSession <- states.consumeBound(f.tenant, ProviderId.Slack, redirect, state, sessionB, t0.plusSeconds(1))
      otherProvider <- states.consumeBound(f.tenant, ProviderId.GitHub, redirect, state, sessionA, t0.plusSeconds(1))
      otherRedirectResult <- states.consumeBound(f.tenant, ProviderId.Slack, otherRedirect, state, sessionA, t0.plusSeconds(1))
      owner <- states.consumeBound(f.tenant, ProviderId.Slack, redirect, state, sessionA, t0.plusSeconds(1))
    yield
      assertEquals(otherSession, Left(OAuthError.InvalidState))
      assertEquals(otherProvider, Left(OAuthError.InvalidState))
      assertEquals(otherRedirectResult, Left(OAuthError.InvalidState))
      assertEquals(owner.map(_.pkceVerifier), Right(Some(ref)))
  }

  test("an expired PKCE state is ExpiredState and does not yield the reference") {
    requireDocker()
    for
      f <- fixture()
      connection <- reserved(f)
      state = newState('d')
      _ <- states.createBound(
        f.tenant, f.catalog, ProviderId.Slack, connection, redirect, Some(reference()), state, sessionA, t0.plusSeconds(60)
      )
      expired <- states.consumeBound(f.tenant, ProviderId.Slack, redirect, state, sessionA, t0.plusSeconds(61))
    yield assertEquals(expired, Left(OAuthError.ExpiredState))
  }

  test("a non-PKCE createBound state consumes with pkceVerifier = None and the intended connection") {
    requireDocker()
    for
      f <- fixture()
      connection <- reserved(f)
      state = newState('e')
      _ <- states.createBound(f.tenant, f.catalog, ProviderId.Slack, connection, redirect, None, state, sessionA, t0.plusSeconds(60))
      persisted <- storedReference(f, state)
      consumed <- states.consumeBound(f.tenant, ProviderId.Slack, redirect, state, sessionA, t0.plusSeconds(1))
    yield
      assertEquals(persisted, None)
      assertEquals(consumed, Right(OAuthStateBinding(f.catalog, ProviderId.Slack, connection, None)))
  }

  test("another tenant cannot consume the state, and the intended connection must exist in the tenant") {
    requireDocker()
    for
      f <- fixture()
      g <- fixture()
      connection <- reserved(f)
      state = newState('f')
      _ <- states.createBound(
        f.tenant, f.catalog, ProviderId.Slack, connection, redirect, Some(reference()), state, sessionA, t0.plusSeconds(60)
      )
      foreign <- states.consumeBound(g.tenant, ProviderId.Slack, redirect, state, sessionA, t0.plusSeconds(1))
      crossTenant <- states
        .createBound(g.tenant, g.catalog, ProviderId.Slack, connection, redirect, Some(reference()), newState('g'), sessionA, t0.plusSeconds(60))
        .attempt
    yield
      assertEquals(foreign, Left(OAuthError.InvalidState))
      assert(crossTenant.isLeft, "a state cannot name another tenant's connection")
  }

  test("a malformed verifier reference cannot be persisted") {
    requireDocker()
    for
      f <- fixture()
      connection <- reserved(f)
      hash = java.security.MessageDigest.getInstance("SHA-256").digest("x".getBytes)
      attempted <- (TenantSession.establish(f.tenant) *>
        sql"""insert into oauth_states (tenant_id, state_hash, provider, resource_id, session_binding, expires_at,
                                          intended_connection_id, redirect_binding_digest, pkce_verifier_reference)
               values (${f.tenant.toString}::uuid, $hash, 'SLACK', ${f.catalog.toString}::uuid, $hash, $t0,
                       ${connection.toString}::uuid, $hash, 'not-a-reference')""".update.run).transact(runtimeXa).attempt
    yield assert(attempted.isLeft)
  }
