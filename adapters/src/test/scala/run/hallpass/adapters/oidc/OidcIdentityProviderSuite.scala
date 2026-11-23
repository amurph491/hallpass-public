package run.hallpass.adapters.oidc

import java.net.{InetSocketAddress, URI, URLDecoder}
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.time.Instant
import java.util.Date
import java.util.concurrent.atomic.AtomicReference
import scala.concurrent.duration.*
import scala.jdk.CollectionConverters.*
import com.nimbusds.jose.{JOSEObjectType, JWSAlgorithm, JWSHeader, JWSSigner, PlainHeader}
import com.nimbusds.jose.crypto.{ECDSASigner, MACSigner, RSASSASigner}
import com.nimbusds.jose.jwk.{Curve, JWKSet, RSAKey}
import com.nimbusds.jose.jwk.gen.{ECKeyGenerator, RSAKeyGenerator}
import com.nimbusds.jwt.{JWTClaimsSet, PlainJWT, SignedJWT}
import com.sun.net.httpserver.{HttpExchange, HttpServer}
import cats.effect.{IO, Resource}
import cats.syntax.all.*
import munit.CatsEffectSuite
import run.hallpass.application.*

/** The relying party against an in-process identity provider that serves discovery, a JWKS, and a token endpoint. */
final class OidcIdentityProviderSuite extends CatsEffectSuite:
  private val random = SecureRandom()
  private val clientId = "hallpass-admin"
  private val clientSecret = "client-secret-value"
  private val signingKey: RSAKey = RSAKeyGenerator(2048).keyID("key-1").generate()

  /** What the fake provider serves and what it received. */
  private final class FakeProvider(server: HttpServer):
    val issuer: String = s"http://127.0.0.1:${server.getAddress.getPort}"
    val discoveryIssuer = AtomicReference(issuer)
    val jwks = AtomicReference(JWKSet(signingKey.toPublicJWK))
    val tokenStatus = AtomicReference(200)
    val idToken = AtomicReference("")
    val tokenRequests = AtomicReference(Vector.empty[(Map[String, String], Option[String])])
    val jwksFetches = AtomicReference(0)
    val jwksStatus = AtomicReference(200)

  private def respond(exchange: HttpExchange, status: Int, body: String): Unit =
    val bytes = body.getBytes(StandardCharsets.UTF_8)
    exchange.getResponseHeaders.add("Content-Type", "application/json")
    exchange.sendResponseHeaders(status, bytes.length.toLong)
    exchange.getResponseBody.write(bytes)
    exchange.close()

  private val providerResource: Resource[IO, FakeProvider] =
    Resource.make(IO.blocking:
      val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
      val fake = FakeProvider(server)
      server.createContext("/.well-known/openid-configuration", exchange =>
        respond(exchange, 200, s"""{"issuer":"${fake.discoveryIssuer.get}","authorization_endpoint":"${fake.issuer}/authorize",
          "token_endpoint":"${fake.issuer}/token","jwks_uri":"${fake.issuer}/jwks","code_challenge_methods_supported":["S256"]}""")
      )
      server.createContext("/jwks", exchange =>
        fake.jwksFetches.updateAndGet(_ + 1)
        if fake.jwksStatus.get == 200 then respond(exchange, 200, fake.jwks.get.toString)
        else respond(exchange, fake.jwksStatus.get, """{"error":"unavailable"}""")
      )
      server.createContext("/token", exchange =>
        val body = String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)
        val form = body.split("&").toVector.map(_.split("=", 2)).collect { case Array(k, v) =>
          URLDecoder.decode(k, StandardCharsets.UTF_8) -> URLDecoder.decode(v, StandardCharsets.UTF_8)
        }.toMap
        fake.tokenRequests.updateAndGet(_ :+ (form -> Option(exchange.getRequestHeaders.getFirst("Authorization"))))
        if fake.tokenStatus.get == 200 then respond(exchange, 200, s"""{"id_token":"${fake.idToken.get}","token_type":"Bearer"}""")
        else respond(exchange, fake.tokenStatus.get, """{"error":"invalid_grant"}""")
      )
      server.start()
      server -> fake
    )((server, _) => IO.blocking(server.stop(0))).map(_._2)

  private def relyingParty(fake: FakeProvider, secret: Option[String] = Some(clientSecret)): IO[OidcIdentityProvider] =
    val config = OidcConfig
      .from(fake.issuer, clientId, secret, "http://localhost:3000/api/auth/oidc/callback", requireHttps = false)
      .fold(error => fail(error), identity)
    OidcIdentityProvider.create(config, 2.seconds, jwksRefetchInterval = 1.millisecond)

  private def claims(fake: FakeProvider, nonce: OidcNonce, change: JWTClaimsSet.Builder => JWTClaimsSet.Builder = identity): JWTClaimsSet =
    val now = Instant.now()
    change(
      JWTClaimsSet
        .Builder()
        .issuer(fake.issuer)
        .subject("person-1")
        .audience(clientId)
        .issueTime(Date.from(now))
        .expirationTime(Date.from(now.plusSeconds(300)))
        .claim("nonce", nonce.value)
    ).build()

  private def signed(claims: JWTClaimsSet, key: RSAKey = signingKey): String =
    val token = SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID).`type`(JOSEObjectType.JWT).build(), claims)
    token.sign(RSASSASigner(key))
    token.serialize()

  private def login(): (PendingLogin, AuthorizationCode) =
    PendingLogin(OidcNonce.generate(random), PkceVerifier.generate(random)) -> AuthorizationCode.parse("code-123").get

  /** Signs in with an ID token produced from the pending login's nonce. */
  private def verifyWith(fake: FakeProvider, rp: OidcIdentityProvider)(token: OidcNonce => String): IO[Either[IdentityProviderError, ExternalIdentity]] =
    val (pending, code) = login()
    fake.idToken.set(token(pending.nonce))
    rp.verify(code, pending)

  test("a valid ID token yields the issuer and subject, and the code is redeemed with the PKCE verifier and client secret") {
    providerResource.use: fake =>
      for
        rp <- relyingParty(fake)
        (pending, code) = login()
        _ = fake.idToken.set(signed(claims(fake, pending.nonce)))
        verified <- rp.verify(code, pending)
      yield
        assertEquals(verified.toOption, ExternalIdentity.from(fake.issuer, "person-1").toOption)
        val (form, authorization) = fake.tokenRequests.get.last
        assertEquals(form.get("grant_type"), Some("authorization_code"))
        assertEquals(form.get("code"), Some("code-123"))
        assertEquals(form.get("code_verifier"), Some(pending.verifier.value))
        assertEquals(form.get("redirect_uri"), Some("http://localhost:3000/api/auth/oidc/callback"))
        assert(!form.contains("client_secret"), "the secret travels only in the Authorization header")
        assert(authorization.exists(_.startsWith("Basic ")))
  }

  test("the authorization redirect carries state, nonce, and an S256 challenge, never the verifier") {
    providerResource.use: fake =>
      for
        rp <- relyingParty(fake)
        state = LoginState.generate(random)
        nonce = OidcNonce.generate(random)
        verifier = PkceVerifier.generate(random)
        uri <- rp.authorizationUri(state, nonce, verifier)
      yield
        val value = uri.fold(error => fail(s"expected a redirect: $error"), identity)
        val query = value.getRawQuery.split("&").toVector.map(_.split("=", 2)).collect { case Array(k, v) =>
          k -> URLDecoder.decode(v, StandardCharsets.UTF_8)
        }.toMap
        assertEquals(value.getPath, "/authorize")
        assertEquals(query.get("state"), Some(state.value))
        assertEquals(query.get("nonce"), Some(nonce.value))
        assertEquals(query.get("code_challenge"), Some(verifier.challenge))
        assertEquals(query.get("code_challenge_method"), Some("S256"))
        assertEquals(query.get("client_id"), Some(clientId))
        assertEquals(query.get("scope"), Some("openid"))
        assert(!value.toString.contains(verifier.value))
  }

  test("tokens with the wrong nonce, issuer, audience, expiry, or missing subject are rejected") {
    providerResource.use: fake =>
      for
        rp <- relyingParty(fake)
        results <- Vector[OidcNonce => String](
          _ => signed(claims(fake, OidcNonce.generate(random))),
          nonce => signed(claims(fake, nonce, _.issuer("https://attacker.example"))),
          nonce => signed(claims(fake, nonce, _.audience("another-client"))),
          nonce => signed(claims(fake, nonce, _.expirationTime(Date.from(Instant.now().minusSeconds(600))))),
          nonce => signed(claims(fake, nonce, _.subject(null))),
          nonce => signed(claims(fake, nonce, _.claim("nonce", null)))
        ).traverse(verifyWith(fake, rp))
      yield assertEquals(results, Vector.fill(6)(Left(IdentityProviderError.Rejected)))
  }

  test("several audiences require an authorized party equal to this client") {
    providerResource.use: fake =>
      for
        rp <- relyingParty(fake)
        withoutParty <- verifyWith(fake, rp)(nonce => signed(claims(fake, nonce, _.audience(List(clientId, "other").asJava))))
        otherParty <- verifyWith(fake, rp)(nonce =>
          signed(claims(fake, nonce, _.audience(List(clientId, "other").asJava).claim("azp", "other")))
        )
        thisParty <- verifyWith(fake, rp)(nonce =>
          signed(claims(fake, nonce, _.audience(List(clientId, "other").asJava).claim("azp", clientId)))
        )
      yield
        assertEquals(withoutParty, Left(IdentityProviderError.Rejected))
        assertEquals(otherParty, Left(IdentityProviderError.Rejected))
        assert(thisParty.isRight, thisParty.toString)
  }

  test("unsigned, HMAC, and foreign-key tokens are rejected") {
    providerResource.use: fake =>
      val foreign = RSAKeyGenerator(2048).keyID("key-1").generate()
      for
        rp <- relyingParty(fake)
        none <- verifyWith(fake, rp)(nonce => PlainJWT(PlainHeader(), claims(fake, nonce)).serialize())
        // Algorithm confusion: an HMAC signed with the client secret must not be accepted as the provider's signature.
        hmac <- verifyWith(fake, rp): nonce =>
          val token = SignedJWT(JWSHeader.Builder(JWSAlgorithm.HS256).keyID("key-1").build(), claims(fake, nonce))
          token.sign(MACSigner((clientSecret * 4).getBytes(StandardCharsets.UTF_8)))
          token.serialize()
        forged <- verifyWith(fake, rp)(nonce => signed(claims(fake, nonce), foreign))
        accessTokenType <- verifyWith(fake, rp): nonce =>
          val token = SignedJWT(JWSHeader.Builder(JWSAlgorithm.RS256).keyID("key-1").`type`(JOSEObjectType("at+jwt")).build(), claims(fake, nonce))
          token.sign(RSASSASigner(signingKey))
          token.serialize()
      yield assertEquals(Vector(none, hmac, forged, accessTokenType), Vector.fill(4)(Left(IdentityProviderError.Rejected)))
  }

  test("a rotated signing key is picked up from the JWKS without a restart") {
    providerResource.use: fake =>
      val rotated = ECKeyGenerator(Curve.P_256).keyID("key-2").generate()
      for
        rp <- relyingParty(fake)
        before <- verifyWith(fake, rp)(nonce => signed(claims(fake, nonce)))
        _ = fake.jwks.set(JWKSet(List(signingKey.toPublicJWK, rotated.toPublicJWK).asJava))
        _ <- IO.sleep(10.millis)
        after <- verifyWith(fake, rp): nonce =>
          val token = SignedJWT(JWSHeader.Builder(JWSAlgorithm.ES256).keyID("key-2").build(), claims(fake, nonce))
          token.sign(ECDSASigner(rotated))
          token.serialize()
      yield
        assert(before.isRight, before.toString)
        assert(after.isRight, after.toString)
        assert(fake.jwksFetches.get >= 2, "the unknown key ID triggers a refetch")
  }

  test("a refused code is rejected, and an unreachable or inconsistent provider is unavailable") {
    for
      refused <- providerResource.use: fake =>
        fake.tokenStatus.set(400)
        relyingParty(fake).flatMap(rp => verifyWith(fake, rp)(nonce => signed(claims(fake, nonce))))
      mismatched <- providerResource.use: fake =>
        fake.discoveryIssuer.set("https://impostor.example")
        relyingParty(fake).flatMap(_.authorizationUri(LoginState.generate(random), OidcNonce.generate(random), PkceVerifier.generate(random)))
      // A provider that goes away after discovery: the token exchange cannot connect.
      stopped <- providerResource.allocated.flatMap: (fake, release) =>
        for
          rp <- relyingParty(fake)
          _ <- rp.authorizationUri(LoginState.generate(random), OidcNonce.generate(random), PkceVerifier.generate(random))
          _ <- release
          result <- verifyWith(fake, rp)(nonce => signed(claims(fake, nonce)))
        yield result
      serverError <- providerResource.use: fake =>
        fake.tokenStatus.set(503)
        relyingParty(fake).flatMap(rp => verifyWith(fake, rp)(nonce => signed(claims(fake, nonce))))
    yield
      assertEquals(refused, Left(IdentityProviderError.Rejected))
      assertEquals(mismatched, Left(IdentityProviderError.Unavailable))
      assertEquals(stopped, Left(IdentityProviderError.Unavailable))
      assertEquals(serverError, Left(IdentityProviderError.Unavailable))
  }

  test("a JWKS outage after discovery and code exchange is unavailable, never a rejection or acceptance") {
    for
      cold <- providerResource.use: fake =>
        fake.jwksStatus.set(503)
        relyingParty(fake).flatMap(rp => verifyWith(fake, rp)(nonce => signed(claims(fake, nonce))))
      // Keys were cached, then the provider rotates to a key the JWKS endpoint cannot currently serve.
      rotatedDuringOutage <- providerResource.use: fake =>
        val rotated = RSAKeyGenerator(2048).keyID("key-2").generate()
        for
          rp <- relyingParty(fake)
          before <- verifyWith(fake, rp)(nonce => signed(claims(fake, nonce)))
          _ = fake.jwksStatus.set(503)
          _ <- IO.sleep(10.millis)
          during <- verifyWith(fake, rp)(nonce => signed(claims(fake, nonce), rotated))
        yield before.isRight -> during
    yield
      assertEquals(cold, Left(IdentityProviderError.Unavailable))
      assertEquals(rotatedDuringOutage, true -> Left(IdentityProviderError.Unavailable))
  }

  test("a public client sends its client ID in the form and no Authorization header") {
    providerResource.use: fake =>
      for
        rp <- relyingParty(fake, secret = None)
        result <- verifyWith(fake, rp)(nonce => signed(claims(fake, nonce)))
      yield
        assert(result.isRight, result.toString)
        val (form, authorization) = fake.tokenRequests.get.last
        assertEquals(form.get("client_id"), Some(clientId))
        assertEquals(authorization, None)
  }

  test("configuration requires https in production and a well-formed issuer and redirect") {
    val redirect = "https://admin.example.test/api/auth/oidc/callback"
    assert(OidcConfig.from("http://idp.example.test", clientId, None, redirect, requireHttps = true).isLeft)
    assert(OidcConfig.from("https://idp.example.test", clientId, None, "http://admin.example.test/cb", requireHttps = true).isLeft)
    assert(OidcConfig.from("https://idp.example.test?x=1", clientId, None, redirect, requireHttps = true).isLeft)
    assert(OidcConfig.from("https://idp.example.test", "", None, redirect, requireHttps = true).isLeft)
    assert(OidcConfig.from("https://idp.example.test", clientId, Some(""), redirect, requireHttps = true).isLeft)
    val valid = OidcConfig.from("https://idp.example.test/tenant/v2.0", clientId, Some(clientSecret), redirect, requireHttps = true)
    assertEquals(valid.map(_.issuer), Right("https://idp.example.test/tenant/v2.0"))
    assert(!valid.toString.contains(clientSecret), "the configuration must not print its secret")
  }
