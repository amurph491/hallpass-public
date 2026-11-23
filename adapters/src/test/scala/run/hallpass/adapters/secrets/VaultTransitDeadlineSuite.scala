package run.hallpass.adapters.secrets

import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.util.concurrent.{CountDownLatch, Executors}
import com.sun.net.httpserver.HttpServer
import scala.concurrent.duration.*
import cats.effect.{IO, Ref, Resource}
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.application.SingleProcessTenantExecutionMutationGate
import run.hallpass.kernel.TenantId

final class VaultTransitDeadlineSuite extends CatsEffectSuite:
  private val plaintext = """{"data":{"plaintext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}"""
  private val tenant = TenantId.random()
  private val wrapped = WrappedDataKey.fromStored("vault:v1:test")

  private final case class Endpoint(config: VaultTransitConfig, headersSent: CountDownLatch)

  private def endpoint(body: String = plaintext, stalled: Boolean = false, status: Int = 200): Resource[IO, Endpoint] =
    Resource.make(IO.blocking:
      val token = Files.createTempFile("vault-deadline-token", ".txt")
      Files.writeString(token, "test-only-token")
      val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
      val executor = Executors.newCachedThreadPool()
      val headersSent = CountDownLatch(1)
      val release = CountDownLatch(1)
      val bytes = body.getBytes(StandardCharsets.UTF_8)
      server.setExecutor(executor)
      server.createContext("/", exchange =>
        exchange.getRequestBody.readAllBytes()
        exchange.sendResponseHeaders(status, bytes.length.toLong)
        headersSent.countDown()
        try
          if stalled then release.await()
          exchange.getResponseBody.write(bytes)
        finally exchange.close()
      )
      server.start()
      val config = VaultTransitConfig.from(s"http://127.0.0.1:${server.getAddress.getPort}", token.toString, "transit", "test", None, false)
        .fold(error => throw IllegalArgumentException(error), identity)
      (Endpoint(config, headersSent), server, executor, release, token)
    )((_, server, executor, release, token) => IO.blocking:
      release.countDown()
      server.stop(0)
      executor.shutdownNow()
      Files.delete(token)
    ).map(_._1)

  test("a stalled body fails closed within the deadline and releases the execution gate") {
    endpoint(stalled = true).use: server =>
      for
        keys <- VaultTransitKeyEncryption.create(server.config, timeout = 500.millis)
        gate <- SingleProcessTenantExecutionMutationGate.create
        dispatched <- Ref.of[IO, Boolean](false)
        result <- gate.withinExecution(tenant)(_ => keys.unwrap(wrapped, tenant).flatTap(value => dispatched.set(true).whenA(value.isRight)))
          .timeout(2.seconds)
        _ <- gate.withinMutation(tenant)(IO.unit).timeout(1.second)
        called <- dispatched.get
      yield
        assertEquals(server.headersSent.getCount, 0L, "the deadline must cover a body stalled after headers")
        assertEquals(result, Left(KeyServiceError.Unavailable))
        assert(!called)
  }

  test("caller cancellation after headers promptly releases the execution gate") {
    endpoint(stalled = true).use: server =>
      for
        keys <- VaultTransitKeyEncryption.create(server.config, timeout = 30.seconds)
        gate <- SingleProcessTenantExecutionMutationGate.create
        fiber <- gate.withinExecution(tenant)(_ => keys.unwrap(wrapped, tenant)).start
        _ <- IO.interruptible(server.headersSent.await()).timeout(2.seconds)
        _ <- fiber.cancel.timeout(1.second)
        _ <- gate.withinMutation(tenant)(IO.unit).timeout(1.second)
      yield ()
  }

  test("an oversized response is unavailable even when it contains valid plaintext") {
    endpoint(body = plaintext + (" " * (64 * 1024))).use: server =>
      VaultTransitKeyEncryption.create(server.config).flatMap(_.unwrap(wrapped, tenant)).map: result =>
        assertEquals(result, Left(KeyServiceError.Unavailable))
  }

  test("complete responses preserve plaintext and Vault rejection semantics") {
    val success = endpoint().use: server =>
      VaultTransitKeyEncryption.create(server.config).flatMap(_.unwrap(wrapped, tenant)).map: result =>
        assertEquals(result.map(_.toVector), Right(Vector.fill[Byte](32)(0)))
    val rejected = endpoint(body = "{}", status = 400).use: server =>
      VaultTransitKeyEncryption.create(server.config).flatMap(_.unwrap(wrapped, tenant)).map: result =>
        assertEquals(result, Left(KeyServiceError.Rejected))
    success *> rejected
  }
