package run.hallpass.adapters.oidc

import java.net.InetSocketAddress
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.concurrent.{CountDownLatch, Executors}
import java.util.concurrent.atomic.AtomicInteger
import com.sun.net.httpserver.HttpServer
import scala.concurrent.duration.*
import cats.effect.{IO, Resource}
import munit.CatsEffectSuite
import run.hallpass.application.*

final class OidcDeadlineSuite extends CatsEffectSuite:
  private val random = SecureRandom()
  private final case class Endpoint(config: OidcConfig, headersSent: CountDownLatch, tokenRequests: AtomicInteger)

  private def endpoint(stalledPath: String, padding: Int = 0): Resource[IO, Endpoint] =
    Resource.make(IO.blocking:
      val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
      val executor = Executors.newCachedThreadPool()
      val headersSent = CountDownLatch(1)
      val release = CountDownLatch(1)
      val tokenRequests = AtomicInteger(0)
      val issuer = s"http://127.0.0.1:${server.getAddress.getPort}"
      val discovery = s"""{"issuer":"$issuer","authorization_endpoint":"$issuer/authorize","token_endpoint":"$issuer/token","jwks_uri":"$issuer/jwks"}"""
      server.setExecutor(executor)
      server.createContext("/", exchange =>
        val path = exchange.getRequestURI.getPath
        exchange.getRequestBody.readAllBytes()
        val body = if path == "/token" then
          tokenRequests.incrementAndGet()
          """{"id_token":"test-token"}"""
        else discovery
        val bytes = (body + (" " * padding)).getBytes(StandardCharsets.UTF_8)
        exchange.sendResponseHeaders(200, bytes.length.toLong)
        try
          if path == stalledPath then
            headersSent.countDown()
            release.await()
          exchange.getResponseBody.write(bytes)
        finally exchange.close()
      )
      server.start()
      val config = OidcConfig.from(issuer, "test-client", None, s"$issuer/callback", false)
        .fold(error => throw IllegalArgumentException(error), identity)
      (Endpoint(config, headersSent, tokenRequests), server, executor, release)
    )((_, server, executor, release) => IO.blocking:
      release.countDown()
      server.stop(0)
      executor.shutdownNow()
    ).map(_._1)

  private def discover(provider: OidcIdentityProvider) =
    provider.authorizationUri(LoginState.generate(random), OidcNonce.generate(random), PkceVerifier.generate(random))

  test("discovery fails unavailable when its body stalls after headers") {
    endpoint("/.well-known/openid-configuration").use: server =>
      for
        provider <- OidcIdentityProvider.create(server.config, requestTimeout = 500.millis)
        result <- discover(provider).timeout(2.seconds)
      yield
        assertEquals(server.headersSent.getCount, 0L)
        assertEquals(result, Left(IdentityProviderError.Unavailable))
        assertEquals(server.tokenRequests.get(), 0)
  }

  test("code exchange has a full body deadline even after discovery has been cached") {
    endpoint("/token").use: server =>
      for
        provider <- OidcIdentityProvider.create(server.config, requestTimeout = 500.millis)
        metadata <- discover(provider)
        result <- provider.verify(AuthorizationCode.parse("test-code").get,
          PendingLogin(OidcNonce.generate(random), PkceVerifier.generate(random))).timeout(2.seconds)
      yield
        assert(metadata.isRight)
        assertEquals(server.headersSent.getCount, 0L)
        assertEquals(result, Left(IdentityProviderError.Unavailable))
        assertEquals(server.tokenRequests.get(), 1, "a timed out code exchange is never retried")
  }

  test("caller cancellation after headers does not wait for the discovery body") {
    endpoint("/.well-known/openid-configuration").use: server =>
      for
        provider <- OidcIdentityProvider.create(server.config, requestTimeout = 30.seconds)
        fiber <- discover(provider).start
        _ <- IO.interruptible(server.headersSent.await()).timeout(2.seconds)
        _ <- fiber.cancel.timeout(1.second)
      yield ()
  }

  test("discovery still refuses responses larger than 512 KiB") {
    endpoint("/unused", padding = 512 * 1024).use: server =>
      OidcIdentityProvider.create(server.config).flatMap(discover).map: result =>
        assertEquals(result, Left(IdentityProviderError.Unavailable))
  }
