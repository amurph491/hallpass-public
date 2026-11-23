package run.hallpass.adapters.oidc

import java.net.{URI, URLEncoder}
import java.net.http.{HttpClient, HttpRequest}
import java.nio.charset.StandardCharsets
import java.util.Base64
import scala.concurrent.duration.*
import scala.jdk.CollectionConverters.*
import scala.util.Try
import cats.effect.{IO, Ref}
import cats.syntax.all.*
import io.circe.parser.parse
import com.nimbusds.jose.{JOSEObjectType, JWSAlgorithm, KeySourceException}
import com.nimbusds.jose.jwk.source.{JWKSource, JWKSourceBuilder}
import com.nimbusds.jose.proc.{DefaultJOSEObjectTypeVerifier, JWSVerificationKeySelector, SecurityContext}
import com.nimbusds.jose.util.DefaultResourceRetriever
import com.nimbusds.jwt.{JWTClaimsSet, SignedJWT}
import com.nimbusds.jwt.proc.{DefaultJWTClaimsVerifier, DefaultJWTProcessor}
import run.hallpass.application.*
import run.hallpass.adapters.http.BoundedHttpResponse

/** Relying-party configuration for one OpenID Connect provider. The client secret is optional: without it the client is
  * public and relies on PKCE alone. */
final class OidcConfig private (
    val issuer: String,
    val clientId: String,
    private[oidc] val clientSecret: Option[String],
    val redirectUri: URI,
    val requireHttps: Boolean
):
  override def toString: String =
    s"OidcConfig(issuer=$issuer, clientId=$clientId, redirectUri=$redirectUri, clientSecret=${clientSecret.fold("<none>")(_ => "<redacted>")})"

object OidcConfig:
  def from(
      issuer: String,
      clientId: String,
      clientSecret: Option[String],
      redirectUri: String,
      requireHttps: Boolean
  ): Either[String, OidcConfig] =
    for
      _ <- absolute(issuer, requireHttps, allowQuery = false)
        .toRight("the OIDC issuer must be an absolute URL without query or fragment")
      _ <- Either.cond(ExternalIdentity.from(issuer, "subject").isRight, (), "the OIDC issuer is too long or malformed")
      _ <- Either.cond(
        clientId.nonEmpty && clientId.length <= 255 && clientId.forall(c => c > ' ' && c < 127),
        (),
        "the OIDC client ID is malformed"
      )
      _ <- Either.cond(clientSecret.forall(_.nonEmpty), (), "the OIDC client secret is empty")
      redirect <- absolute(redirectUri, requireHttps, allowQuery = false)
        .toRight("the OIDC redirect URI must be an absolute URL without query or fragment")
    // The issuer is kept exactly as configured: it is compared byte-for-byte with discovery and with each ID token.
    yield OidcConfig(issuer, clientId, clientSecret, redirect, requireHttps)

  /** An absolute http(s) URL with a host and no fragment. Plain http is accepted only when `requireHttps` is off. */
  private[oidc] def absolute(value: String, requireHttps: Boolean, allowQuery: Boolean): Option[URI] =
    Try(URI.create(value)).toOption.filter: uri =>
      uri.isAbsolute && uri.getHost != null && (allowQuery || uri.getRawQuery == null) && uri.getRawFragment == null &&
        (uri.getScheme == "https" || (!requireHttps && uri.getScheme == "http"))

/** Endpoints from the provider's discovery document. */
private[oidc] final case class OidcMetadata(authorization: URI, token: URI, jwks: URI)

/** OpenID Connect authorization code flow with PKCE (S256).
  *
  * Discovery is lazy and retried on failure, so a provider outage at startup does not stop the API; existing sessions
  * do not depend on the provider. ID tokens are verified with nimbus-jose-jwt against the provider's JWKS, which is
  * cached and refetched when a token names an unknown key (rate-limited), so key rotation needs no restart.
  *
  * Validation: an asymmetric signature from the provider's keys (no `none`, no HMAC); `iss` exactly equal to the
  * configured issuer; `aud` containing the client ID, and `azp` equal to it when present or when there are several
  * audiences; `exp` in the future and `nbf` not in the future (60 s skew); `sub` present; and `nonce` equal to the one
  * stored for this login. */
final class OidcIdentityProvider private (
    config: OidcConfig,
    http: HttpClient,
    metadata: Ref[IO, Option[(OidcMetadata, DefaultJWTProcessor[SecurityContext])]],
    requestTimeout: FiniteDuration,
    jwksRefetchInterval: FiniteDuration
) extends IdentityProvider:
  import OidcIdentityProvider.*

  def authorizationUri(state: LoginState, nonce: OidcNonce, verifier: PkceVerifier): IO[Either[IdentityProviderError, URI]] =
    resolved.map(_.map: (endpoints, _) =>
      val parameters = Vector(
        "response_type" -> "code",
        "client_id" -> config.clientId,
        "redirect_uri" -> config.redirectUri.toString,
        "scope" -> "openid",
        "state" -> state.value,
        "nonce" -> nonce.value,
        "code_challenge" -> verifier.challenge,
        "code_challenge_method" -> "S256"
      )
      val base = endpoints.authorization.toString
      URI.create(base + (if base.contains("?") then "&" else "?") + form(parameters))
    )

  def verify(code: AuthorizationCode, pending: PendingLogin): IO[Either[IdentityProviderError, ExternalIdentity]] =
    resolved.flatMap:
      case Left(error) => IO.pure(Left(error))
      case Right((endpoints, processor)) =>
        exchange(endpoints.token, code, pending.verifier).flatMap:
          case Left(error)    => IO.pure(Left(error))
          case Right(idToken) => IO.blocking(validate(processor, idToken, pending.nonce))

  private def resolved: IO[Either[IdentityProviderError, (OidcMetadata, DefaultJWTProcessor[SecurityContext])]] =
    metadata.get.flatMap:
      case Some(value) => IO.pure(Right(value))
      case None =>
        discover.flatMap:
          case Left(error) => IO.pure(Left(error))
          case Right(endpoints) =>
            val value = endpoints -> processor(endpoints.jwks)
            // Concurrent first requests may each discover; the first stored result wins and all are equivalent.
            metadata.modify:
              case Some(existing) => Some(existing) -> Right(existing)
              case None           => Some(value) -> Right(value)

  private def discover: IO[Either[IdentityProviderError, OidcMetadata]] =
    val location = URI.create(config.issuer.stripSuffix("/") + "/.well-known/openid-configuration")
    send(HttpRequest.newBuilder(location).GET().header("Accept", "application/json")).map:
      case Left(error) => Left(error)
      case Right((status, body)) if status == 200 =>
        (for
          json <- parse(body).toOption
          cursor = json.hcursor
          issuer <- cursor.get[String]("issuer").toOption
          // OpenID Connect Discovery 1.0 §4.3: the document's issuer must equal the configured issuer exactly.
          if issuer == config.issuer
          authorization <- cursor.get[String]("authorization_endpoint").toOption.flatMap(endpoint)
          token <- cursor.get[String]("token_endpoint").toOption.flatMap(endpoint)
          jwks <- cursor.get[String]("jwks_uri").toOption.flatMap(endpoint)
          methods = cursor.get[Vector[String]]("code_challenge_methods_supported").toOption
          // A provider that lists PKCE methods must list S256. One that lists none is accepted: many support S256
          // without advertising it, and the code is also bound to the client.
          if methods.forall(_.contains("S256"))
        yield OidcMetadata(authorization, token, jwks)).toRight(IdentityProviderError.Unavailable)
      case Right(_) => Left(IdentityProviderError.Unavailable)

  // Endpoints may carry a query string; some providers' authorization endpoints do.
  private def endpoint(value: String): Option[URI] = OidcConfig.absolute(value, config.requireHttps, allowQuery = true)

  private def exchange(
      tokenEndpoint: URI,
      code: AuthorizationCode,
      verifier: PkceVerifier
  ): IO[Either[IdentityProviderError, String]] =
    val common = Vector(
      "grant_type" -> "authorization_code",
      "code" -> code.value,
      "redirect_uri" -> config.redirectUri.toString,
      "code_verifier" -> verifier.value
    )
    val builder = HttpRequest.newBuilder(tokenEndpoint).header("Accept", "application/json").header("Content-Type", "application/x-www-form-urlencoded")
    val request = config.clientSecret match
      case Some(secret) =>
        // client_secret_basic (RFC 6749 §2.3.1): each part is form-encoded before base64.
        val credentials = s"${encode(config.clientId)}:${encode(secret)}"
        builder
          .header("Authorization", "Basic " + Base64.getEncoder.encodeToString(credentials.getBytes(StandardCharsets.UTF_8)))
          .POST(HttpRequest.BodyPublishers.ofString(form(common)))
      case None =>
        builder.POST(HttpRequest.BodyPublishers.ofString(form(common :+ ("client_id" -> config.clientId))))
    send(request).map:
      case Left(error) => Left(error)
      case Right((200, body)) =>
        parse(body).toOption.flatMap(_.hcursor.get[String]("id_token").toOption).toRight(IdentityProviderError.Rejected)
      // The provider refused the code: invalid, expired, reused, or a PKCE mismatch.
      case Right((status, _)) if status >= 400 && status < 500 => Left(IdentityProviderError.Rejected)
      case Right(_) => Left(IdentityProviderError.Unavailable)

  private def validate(
      processor: DefaultJWTProcessor[SecurityContext],
      idToken: String,
      nonce: OidcNonce
  ): Either[IdentityProviderError, ExternalIdentity] =
    Try(processor.process(SignedJWT.parse(idToken), null)).toEither match
      case Left(_: KeySourceException) => Left(IdentityProviderError.Unavailable)
      case Left(_)                     => Left(IdentityProviderError.Rejected)
      case Right(claims) =>
        val audiences = Option(claims.getAudience).map(_.asScala.toVector).getOrElse(Vector.empty)
        val authorizedParty = Option(claims.getStringClaim("azp"))
        val presentedNonce = Option(claims.getStringClaim("nonce"))
        val partyValid = authorizedParty match
          case Some(party) => party == config.clientId
          case None        => audiences.size == 1
        if !partyValid || !presentedNonce.exists(nonce.matches) then Left(IdentityProviderError.Rejected)
        else ExternalIdentity.from(claims.getIssuer, claims.getSubject).leftMap(_ => IdentityProviderError.Rejected)

  private def processor(jwks: URI): DefaultJWTProcessor[SecurityContext] =
    val retriever = DefaultResourceRetriever(
      ConnectTimeoutMillis,
      requestTimeout.toMillis.toInt,
      MaximumResponseBytes
    )
    val source: JWKSource[SecurityContext] = JWKSourceBuilder
      .create[SecurityContext](jwks.toURL, retriever)
      .cache(JwksCacheTtl.toMillis, requestTimeout.toMillis)
      .rateLimited(jwksRefetchInterval.toMillis)
      .retrying(false)
      .build()
    val processor = DefaultJWTProcessor[SecurityContext]()
    // Accept `typ: JWT` or no `typ`; reject other token types, such as access tokens presented as ID tokens.
    processor.setJWSTypeVerifier(DefaultJOSEObjectTypeVerifier[SecurityContext](JOSEObjectType.JWT, null))
    processor.setJWSKeySelector(JWSVerificationKeySelector[SecurityContext](AllowedAlgorithms.asJava, source))
    processor.setJWTClaimsSetVerifier(
      DefaultJWTClaimsVerifier[SecurityContext](
        Set(config.clientId).asJava,
        JWTClaimsSet.Builder().issuer(config.issuer).build(),
        Set("sub", "exp", "iat", "nonce").asJava,
        null
      )
    )
    processor

  /** Sends one request with a bounded response. Transport failures and timeouts are `Unavailable`. Redirects are not
    * followed (the client is built with `Redirect.NEVER`). */
  private def send(builder: HttpRequest.Builder): IO[Either[IdentityProviderError, (Int, String)]] =
    IO(builder.timeout(java.time.Duration.ofMillis(requestTimeout.toMillis)).build())
      .flatMap(request => BoundedHttpResponse.send(http, request, MaximumResponseBytes, requestTimeout))
    .attempt
    .map:
      case Right(response) => Right(response.statusCode() -> String(response.body(), StandardCharsets.UTF_8))
      case _               => Left(IdentityProviderError.Unavailable)

object OidcIdentityProvider:
  private val AllowedAlgorithms = Set(
    JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
    JWSAlgorithm.PS256, JWSAlgorithm.PS384, JWSAlgorithm.PS512,
    JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512
  )
  private val ConnectTimeoutMillis = 5000
  private val MaximumResponseBytes = 512 * 1024
  private val JwksCacheTtl = 15.minutes

  /** `jwksRefetchInterval` bounds how often an unknown key ID can make the provider refetch the JWKS. */
  def create(
      config: OidcConfig,
      requestTimeout: FiniteDuration = 5.seconds,
      jwksRefetchInterval: FiniteDuration = 30.seconds
  ): IO[OidcIdentityProvider] =
    Ref.of[IO, Option[(OidcMetadata, DefaultJWTProcessor[SecurityContext])]](None).map: metadata =>
      val http = HttpClient
        .newBuilder()
        .connectTimeout(java.time.Duration.ofMillis(ConnectTimeoutMillis.toLong))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build()
      OidcIdentityProvider(config, http, metadata, requestTimeout, jwksRefetchInterval)

  private def encode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8)
  private def form(parameters: Vector[(String, String)]): String =
    parameters.map((key, value) => s"${encode(key)}=${encode(value)}").mkString("&")
