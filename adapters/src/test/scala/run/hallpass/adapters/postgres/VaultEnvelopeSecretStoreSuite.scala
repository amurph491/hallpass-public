package run.hallpass.adapters.postgres

import java.net.URI
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.nio.file.{Files, Path}
import java.sql.DriverManager
import java.util.UUID
import scala.compiletime.uninitialized
import cats.effect.IO
import cats.syntax.all.*
import munit.CatsEffectSuite
import org.testcontainers.DockerClientFactory
import org.testcontainers.containers.{GenericContainer, PostgreSQLContainer}
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.utility.DockerImageName
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import org.typelevel.doobie.util.transactor.Transactor
import run.hallpass.adapters.secrets.*
import run.hallpass.application.*
import run.hallpass.kernel.*

/** Envelope encryption against a real Vault Transit engine and PostgreSQL, as the split runtime role. The owner stands
  * in for operators: it provisions tenants, tampers with rows, and runs the rewrap job. */
final class VaultEnvelopeSecretStoreSuite extends CatsEffectSuite:
  override val munitIOTimeout: scala.concurrent.duration.Duration = scala.concurrent.duration.Duration(180, "s")
  private var postgres: PostgreSQLContainer[?] = uninitialized
  private var vault: GenericContainer[?] = uninitialized
  private var dockerAvailable = false
  private val Owner = "authai_owner"
  private val App = "authai_app"
  private val Password = "test-password"
  private val RootToken = "root-token-for-tests"
  private val runtimeRole = RuntimeRole.parse(App).toOption.get
  private val http = HttpClient.newHttpClient()
  private lazy val tokenFile: Path =
    val file = Files.createTempFile("vault-token", ".txt")
    Files.writeString(file, RootToken)
    file

  override def beforeAll(): Unit =
    dockerAvailable = DockerClientFactory.instance().isDockerAvailable
    if dockerAvailable then
      postgres = PostgreSQLContainer("postgres:18.6-alpine")
      postgres.start()
      val connection = DriverManager.getConnection(postgres.getJdbcUrl, postgres.getUsername, postgres.getPassword)
      try
        val statement = connection.createStatement()
        statement.execute(s"create role $Owner login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"create role $App login password '$Password' nosuperuser nocreatedb nocreaterole noreplication")
        statement.execute(s"grant connect on database test to $Owner, $App")
        statement.execute("revoke create on schema public from public")
        statement.execute(s"grant usage, create on schema public to $Owner")
        statement.execute(s"grant usage on schema public to $App")
      finally connection.close()
      val container = GenericContainer(DockerImageName.parse("hashicorp/vault:2.1.1"))
      container.withEnv("VAULT_DEV_ROOT_TOKEN_ID", RootToken)
      container.withExposedPorts(8200)
      container.waitingFor(Wait.forHttp("/v1/sys/health").forStatusCode(200))
      vault = container
      vault.start()
      vaultCall("POST", "sys/mounts/transit", """{"type":"transit"}""")
      vaultCall("POST", "transit/keys/hallpass", """{"type":"aes256-gcm96","derived":true}""")
      vaultCall("POST", "transit/keys/not-derived", """{"type":"aes256-gcm96"}""")

  override def afterAll(): Unit =
    if dockerAvailable then
      vault.stop()
      postgres.stop()

  private def requireDocker(): Unit = assume(dockerAvailable, "Docker is required for Vault and PostgreSQL integration tests")

  private def vaultAddress: String = s"http://${vault.getHost}:${vault.getMappedPort(8200)}"

  private def vaultCall(method: String, path: String, body: String): Int =
    val request = HttpRequest
      .newBuilder(URI.create(s"$vaultAddress/v1/$path"))
      .header("X-Vault-Token", RootToken)
      .method(method, HttpRequest.BodyPublishers.ofString(body))
      .build()
    val status = http.send(request, HttpResponse.BodyHandlers.discarding()).statusCode()
    assert(status == 200 || status == 204, s"$method $path answered $status")
    status

  private def keys(key: String = "hallpass", address: => String = vaultAddress, token: Path = tokenFile): IO[VaultTransitKeyEncryption] =
    IO.fromEither(VaultTransitConfig.from(address, token.toString, "transit", key, None, requireHttps = false).leftMap(IllegalArgumentException(_)))
      .flatMap(VaultTransitKeyEncryption.create(_))

  private def config(user: String): DatabaseConfig =
    DatabaseConfig
      .fromEnvironment(Map("HALLPASS_DB_URL" -> postgres.getJdbcUrl, "HALLPASS_DB_USER" -> user, "HALLPASS_DB_PASSWORD" -> Password))
      .toOption
      .get

  private lazy val prepared: IO[Unit] = PostgresDatabase.migrateAsOwner(config(Owner), runtimeRole).void

  private def asOwner[A](program: Transactor[IO] => IO[A]): IO[A] =
    prepared *> PostgresDatabase.ownerResource(config(Owner)).use(program)

  private def asRuntimeRole[A](program: Transactor[IO] => IO[A]): IO[A] =
    prepared *> PostgresDatabase.resourceWithSchema(config(App), MigrationMode.External).use((xa, _) => program(xa))

  private def tenant(): IO[TenantId] =
    val subject = UUID.randomUUID().toString
    val request = TenantProvisioningRequest
      .from("Secrets tenant", s"secrets-${subject.take(8)}", ExternalIdentity.from("https://idp.example.com", subject).toOption.get)
      .toOption
      .get
    asOwner(xa => TenantProvisioning.provision(xa, request)).map(_.tenant)

  private def text(secret: Either[SecretStoreError, ProviderSecret]): Either[SecretStoreError, String] =
    secret.map(value => String(ProviderSecret.bytes(value), java.nio.charset.StandardCharsets.UTF_8))

  private def row(owner: TenantId, reference: SecretReference): IO[(String, Array[Byte])] =
    asOwner(xa =>
      (TenantSession.establish(owner) *>
        sql"select wrapped_key, ciphertext from provider_secrets where tenant_id = ${owner.toString}::uuid and reference = ${reference.value}"
          .query[(String, Array[Byte])].unique).transact(xa)
    )

  test("a secret round-trips through Vault-wrapped envelope encryption and is never stored in plaintext") {
    requireDocker()
    val secret = "xoxb-envelope-" + UUID.randomUUID()
    for
      owner <- tenant()
      binding = SecretBinding(owner, ConnectionId.random())
      service <- keys()
      restored <- asRuntimeRole: xa =>
        val store = EnvelopeSecretStore(service, PostgresProviderSecrets(xa))
        store.put(binding, ProviderSecret.fromUtf8(secret)).flatMap(reference => store.get(binding, reference).map(reference -> _))
      (reference, value) = restored
      stored <- row(owner, reference)
    yield
      assertEquals(text(value), Right(secret))
      assert(stored._1.startsWith("vault:v1:"), "only the Vault-wrapped data key is stored")
      assert(!String(stored._2, java.nio.charset.StandardCharsets.ISO_8859_1).contains(secret))
  }

  test("ciphertext copied to another tenant, presented for another connection, or tampered with does not decrypt") {
    requireDocker()
    for
      owner <- tenant()
      other <- tenant()
      binding = SecretBinding(owner, ConnectionId.random())
      service <- keys()
      reference <- asRuntimeRole(xa => EnvelopeSecretStore(service, PostgresProviderSecrets(xa)).put(binding, ProviderSecret.fromUtf8("owned")))
      // An attacker with database write access copies the row into another tenant under the same connection ID.
      stolen <- row(owner, reference)
      nonce <- asOwner(xa =>
        (TenantSession.establish(owner) *>
          sql"select connection_id, key_name, nonce from provider_secrets where reference = ${reference.value}"
            .query[(UUID, String, Array[Byte])].unique).transact(xa)
      )
      copied <- asOwner(xa =>
        (TenantSession.establish(other) *>
          sql"""insert into provider_secrets (tenant_id, reference, connection_id, key_name, wrapped_key, nonce, ciphertext)
                values (${other.toString}::uuid, ${reference.value}, ${nonce._1}, ${nonce._2}, ${stolen._1}, ${nonce._3}, ${stolen._2})"""
            .update.run).transact(xa)
      )
      results <- asRuntimeRole: xa =>
        val store = EnvelopeSecretStore(service, PostgresProviderSecrets(xa))
        (
          store.get(binding.copy(tenant = other), reference),
          store.get(binding.copy(connection = ConnectionId.random()), reference)
        ).tupled
      _ <- asOwner(xa =>
        (TenantSession.establish(owner) *>
          sql"update provider_secrets set ciphertext = set_byte(ciphertext, 0, (get_byte(ciphertext, 0) + 1) % 256) where reference = ${reference.value}".update.run).transact(xa)
      )
      tampered <- asRuntimeRole(xa => EnvelopeSecretStore(service, PostgresProviderSecrets(xa)).get(binding, reference))
    yield
      val (copiedRead, otherConnection) = results
      assertEquals(copied, 1, "the attacker's copy exists in the other tenant")
      assertEquals(copiedRead, Left(SecretStoreError.DecryptionFailed))
      assertEquals(otherConnection, Left(SecretStoreError.NotFound))
      assertEquals(tampered, Left(SecretStoreError.DecryptionFailed))
  }

  test("a Vault outage or missing token fails closed: reads are unavailable and writes store nothing") {
    requireDocker()
    for
      owner <- tenant()
      binding = SecretBinding(owner, ConnectionId.random())
      working <- keys()
      reference <- asRuntimeRole(xa => EnvelopeSecretStore(working, PostgresProviderSecrets(xa)).put(binding, ProviderSecret.fromUtf8("kept")))
      unreachable <- keys(address = "http://127.0.0.1:1")
      noToken <- keys(token = Path.of("/nonexistent/vault-token"))
      outcome <- asRuntimeRole: xa =>
        val rows = PostgresProviderSecrets(xa)
        (
          EnvelopeSecretStore(unreachable, rows).get(binding, reference),
          EnvelopeSecretStore(noToken, rows).get(binding, reference),
          EnvelopeSecretStore(unreachable, rows).put(binding, ProviderSecret.fromUtf8("lost")).attempt
        ).tupled
      count <- asOwner(xa =>
        (TenantSession.establish(owner) *> sql"select count(*) from provider_secrets where tenant_id = ${owner.toString}::uuid".query[Long].unique).transact(xa)
      )
    yield
      val (readDown, readNoToken, writeDown) = outcome
      assertEquals(readDown, Left(SecretStoreError.Unavailable))
      assertEquals(readNoToken, Left(SecretStoreError.Unavailable))
      assertEquals(writeDown.left.toOption.map(_.getClass), Some(classOf[SecretStoreUnavailable]))
      assertEquals(count, 1L, "a failed write stores nothing")
  }

  test("a transit key that is not tenant-derived is refused before it protects anything") {
    requireDocker()
    for
      owner <- tenant()
      service <- keys(key = "not-derived")
      attempt <- asRuntimeRole(xa =>
        EnvelopeSecretStore(service, PostgresProviderSecrets(xa)).put(SecretBinding(owner, ConnectionId.random()), ProviderSecret.fromUtf8("x")).attempt
      )
    yield assertEquals(attempt.left.toOption.map(_.getClass), Some(classOf[SecretStoreUnavailable]))
  }

  test("after key rotation the owner job rewraps every data key, and secrets survive retiring the old version") {
    requireDocker()
    for
      first <- tenant()
      second <- tenant()
      bindings = Vector(SecretBinding(first, ConnectionId.random()), SecretBinding(second, ConnectionId.random()))
      service <- keys()
      references <- asRuntimeRole(xa =>
        bindings.traverse(binding => EnvelopeSecretStore(service, PostgresProviderSecrets(xa)).put(binding, ProviderSecret.fromUtf8(s"secret-${binding.tenant}")))
      )
      _ <- IO.blocking(vaultCall("POST", "transit/keys/hallpass/rotate", "{}"))
      report <- asOwner(xa => ProviderSecretRewrap.run(xa, service))
      again <- asOwner(xa => ProviderSecretRewrap.run(xa, service))
      runtimeUpdate <- asRuntimeRole(xa =>
        (TenantSession.establish(first) *> sql"update provider_secrets set rewrapped_at = now()".update.run).transact(xa).attempt
      )
      // Retire every older key version: only rewrapped data keys still decrypt.
      latest <- IO.blocking:
        val request = HttpRequest.newBuilder(URI.create(s"$vaultAddress/v1/transit/keys/hallpass")).header("X-Vault-Token", RootToken).build()
        io.circe.parser.parse(http.send(request, HttpResponse.BodyHandlers.ofString()).body()).toOption
          .flatMap(_.hcursor.downField("data").get[Int]("latest_version").toOption).get
      _ <- IO.blocking(vaultCall("POST", "transit/keys/hallpass/config", s"""{"min_decryption_version":$latest}"""))
      restored <- asRuntimeRole(xa =>
        bindings.zip(references).traverse((binding, reference) => EnvelopeSecretStore(service, PostgresProviderSecrets(xa)).get(binding, reference))
      )
      _ <- IO.blocking(vaultCall("POST", "transit/keys/hallpass/config", """{"min_decryption_version":1}"""))
      wrapped <- bindings.zip(references).traverse((binding, reference) => row(binding.tenant, reference).map(_._1))
    yield
      // Rows written by earlier tests in this suite are rewrapped too. The one row an earlier test copied into another
      // tenant cannot be rewrapped (Vault refuses it under that tenant's context), so the job reports it as failed and
      // exits non-zero, which is how an operator learns of a row that does not belong where it is.
      assert(report.rewrapped >= 2, report.toString)
      assertEquals(report.failed, 1, "only the foreign copy fails")
      assert(wrapped.forall(_.startsWith(s"vault:v$latest:")), wrapped.toString)
      assertEquals(again.rewrapped, 0)
      assert(again.alreadyCurrent >= 2, again.toString)
      assert(runtimeUpdate.isLeft, "the runtime role cannot rewrite ciphertext")
      assertEquals(restored.map(text), bindings.map(binding => Right(s"secret-${binding.tenant}")))
  }

  test("Vault configuration requires https in production and well-formed names") {
    assert(VaultTransitConfig.from("http://vault:8200", "/run/secrets/vault-token", "transit", "hallpass", None, requireHttps = true).isLeft)
    assert(VaultTransitConfig.from("https://vault:8200/v1", "/run/secrets/vault-token", "transit", "hallpass", None, requireHttps = true).isLeft)
    assert(VaultTransitConfig.from("https://vault:8200", "", "transit", "hallpass", None, requireHttps = true).isLeft)
    assert(VaultTransitConfig.from("https://vault:8200", "/t", "../sys", "hallpass", None, requireHttps = true).isLeft)
    assert(VaultTransitConfig.from("https://vault:8200", "/t", "transit", "bad key", None, requireHttps = true).isLeft)
    assert(VaultTransitConfig.from("https://vault:8200", "/t", "transit", "hallpass", Some("team/prod"), requireHttps = true).isRight)
  }
