package run.hallpass.adapters.github

import java.net.http.{HttpClient, HttpRequest, HttpResponse, HttpTimeoutException}
import java.net.{ConnectException, URI, URLEncoder}
import java.nio.ByteBuffer
import java.nio.charset.{CodingErrorAction, StandardCharsets}
import java.security.interfaces.RSAPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.{KeyFactory, Signature}
import java.time.{Duration, Instant}
import java.util.Base64
import scala.concurrent.duration.*
import cats.effect.IO
import io.circe.Json
import io.circe.parser.parse
import run.hallpass.adapters.http.BoundedHttpResponse
import run.hallpass.application.Clock

/** GitHub App and user-to-server endpoints used by the connector and the credential strategy.
  *
  * Every method bounds its request (timeout, response size), follows no redirects, never retries, and returns a
  * credential-free [[GitHubApiError]] instead of raising for an HTTP or decoding failure. Tokens never appear in an
  * error, exception message, or `toString`.
  */
trait GitHubAppApi:
  /** `POST /app/installations/{id}/access_tokens`, authenticated with an App JWT.
    *
    * `repositories = Some(ids)` sends `repository_ids` and narrows the token to exactly those repositories; `None`
    * requests the installation's whole repository set (used only by management discovery). `permissions` is sent as
    * the `permissions` object and must be non-empty. The response's `repositories` (when present), `permissions`, and
    * `expires_at` are decoded into the result. */
  def installationToken(
      installation: GitHubInstallationId,
      repositories: Option[Vector[GitHubRepositoryId]],
      permissions: Set[GitHubPermission]
  ): IO[Either[GitHubApiError, MintedInstallationToken]]

  /** `GET /app/installations/{id}`, authenticated with an App JWT: the account the installation is on. */
  def installation(id: GitHubInstallationId): IO[Either[GitHubApiError, GitHubInstallationAccount]]

  /** `GET /installation/repositories` with an installation token, following `page` up to `limit` repositories in
    * pages of 100. Reaching `limit` truncates; it is not an error. */
  def installationRepositories(token: MintedInstallationToken, limit: Int): IO[Either[GitHubApiError, Vector[GitHubRepositorySummary]]]

  /** `POST {web}/login/oauth/access_token` with the App's client ID and secret: exchanges an install-callback code for
    * a user-to-server token. */
  def exchangeUserCode(code: String, redirectUri: java.net.URI): IO[Either[GitHubApiError, GitHubUserToken]]

  /** Whether the user can access the installation: `GET /user/installations` (paginated, at most `MaximumUserPages`
    * pages of 100) contains it. */
  def userCanAccessInstallation(user: GitHubUserToken, installation: GitHubInstallationId): IO[Either[GitHubApiError, Boolean]]

/** Signs GitHub App JWTs (RS256). */
object GitHubAppJwt:
  /** `iat` is 60 seconds in the past to tolerate clock drift; `exp` is 9 minutes ahead (GitHub's maximum is 10).
    * `iss` is the App's client ID, which GitHub accepts in place of the App ID. */
  def sign(issuer: String, key: RSAPrivateKey, now: Instant): String =
    val encoder = Base64.getUrlEncoder.withoutPadding()
    def part(json: Json): String = encoder.encodeToString(json.noSpaces.getBytes(StandardCharsets.UTF_8))
    val header = part(Json.obj("alg" -> Json.fromString("RS256"), "typ" -> Json.fromString("JWT")))
    val claims = part(Json.obj(
      "iat" -> Json.fromLong(now.getEpochSecond - 60),
      "exp" -> Json.fromLong(now.getEpochSecond + 540),
      "iss" -> Json.fromString(issuer)
    ))
    val signingInput = s"$header.$claims"
    val signature = Signature.getInstance("SHA256withRSA")
    signature.initSign(key)
    signature.update(signingInput.getBytes(StandardCharsets.US_ASCII))
    signingInput + "." + encoder.encodeToString(signature.sign())

/** Parses the App private key that GitHub generates. GitHub downloads PKCS#1 (`BEGIN RSA PRIVATE KEY`); PKCS#8
  * (`BEGIN PRIVATE KEY`) is also accepted. The error never contains key material. */
object GitHubPrivateKey:
  private val Invalid = "GitHub App private key is not a supported unencrypted RSA key of at least 2048 bits"
  private val Pkcs1 = ("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----")
  private val Pkcs8 = ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----")
  private val MinimumBits = 2048
  /** AlgorithmIdentifier { rsaEncryption, NULL } */
  private val RsaAlgorithm: Array[Byte] =
    Array(0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00).map(_.toByte)

  def parsePem(pem: String): Either[String, RSAPrivateKey] =
    val text = Option(pem).getOrElse("").trim
    val framing =
      if text.startsWith(Pkcs1._1) && text.endsWith(Pkcs1._2) then Some((Pkcs1, true))
      else if text.startsWith(Pkcs8._1) && text.endsWith(Pkcs8._2) then Some((Pkcs8, false))
      else None
    framing match
      case None => Left(Invalid)
      case Some(((begin, end), wrap)) =>
        val encoded = text.substring(begin.length, text.length - end.length).filterNot(_.isWhitespace)
        // A header line such as Proc-Type leaves a non-Base64 character here and fails to decode.
        scala.util.Try(Base64.getDecoder.decode(encoded)).toOption match
          case None => Left(Invalid)
          case Some(der) =>
            var wrapped: Array[Byte] = null
            try
              wrapped = if wrap then wrapPkcs1(der) else der
              val key = scala.util.Try(KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(wrapped))).toOption
              key match
                case Some(rsa: RSAPrivateKey) if rsa.getModulus.bitLength >= MinimumBits => Right(rsa)
                case _ => Left(Invalid)
            finally
              java.util.Arrays.fill(der, 0.toByte)
              if wrapped != null then java.util.Arrays.fill(wrapped, 0.toByte)

  /** PrivateKeyInfo { version 0, rsaEncryption, OCTET STRING { RSAPrivateKey } } */
  private def wrapPkcs1(pkcs1: Array[Byte]): Array[Byte] =
    val octets = Array(0x04.toByte) ++ derLength(pkcs1.length) ++ pkcs1
    val inner = Array(0x02.toByte, 0x01.toByte, 0x00.toByte) ++ RsaAlgorithm ++ octets
    val result = Array(0x30.toByte) ++ derLength(inner.length) ++ inner
    java.util.Arrays.fill(octets, 0.toByte)
    java.util.Arrays.fill(inner, 0.toByte)
    result

  private def derLength(length: Int): Array[Byte] =
    if length < 0x80 then Array(length.toByte)
    else if length < 0x100 then Array(0x81.toByte, length.toByte)
    else if length < 0x10000 then Array(0x82.toByte, (length >> 8).toByte, length.toByte)
    else Array(0x83.toByte, (length >> 16).toByte, (length >> 8).toByte, length.toByte)

/** The JDK HTTP implementation of [[GitHubAppApi]]. */
final class GitHubAppClient(
    registration: GitHubAppRegistration,
    secrets: GitHubAppSecrets,
    endpoints: GitHubEndpoints,
    http: HttpClient,
    clock: Clock[IO],
    requestTimeout: Duration = Duration.ofSeconds(10)
) extends GitHubAppApi:
  import GitHubAppClient.*

  def installationToken(
      installation: GitHubInstallationId,
      repositories: Option[Vector[GitHubRepositoryId]],
      permissions: Set[GitHubPermission]
  ): IO[Either[GitHubApiError, MintedInstallationToken]] =
    val byName = permissions.toVector.groupBy(_.name).view.mapValues(_.map(_.level).distinct).toMap
    // Empty or contradictory (two levels for one name) permissions, or an empty repository set, fail closed.
    val ambiguous = byName.values.exists(_.size != 1)
    if permissions.isEmpty || ambiguous || repositories.exists(_.isEmpty) then IO.pure(Left(GitHubApiError.Rejected))
    else
      val permissionJson = Json.fromFields(byName.toVector.sortBy(_._1).map((name, levels) => name -> Json.fromString(levels.head)))
      val fields = Vector("permissions" -> permissionJson) ++
        repositories.map(ids => "repository_ids" -> Json.fromValues(ids.map(id => Json.fromLong(id.value))))
      val body = Json.fromFields(fields).noSpaces
      appJwt.flatMap:
        case Left(error) => IO.pure(Left(error))
        case Right(jwt) =>
          val request = apiRequest(s"/app/installations/${installation.value}/access_tokens", jwt)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
            .build()
          call(request, 201).map(_.flatMap(decodeToken))

  def installation(id: GitHubInstallationId): IO[Either[GitHubApiError, GitHubInstallationAccount]] =
    appJwt.flatMap:
      case Left(error) => IO.pure(Left(error))
      case Right(jwt) =>
        val request = apiRequest(s"/app/installations/${id.value}", jwt).GET().build()
        call(request, 200).map(_.flatMap(decodeInstallation(id, _)))

  def installationRepositories(token: MintedInstallationToken, limit: Int): IO[Either[GitHubApiError, Vector[GitHubRepositorySummary]]] =
    if limit < 1 then IO.pure(Left(GitHubApiError.Rejected))
    else
      def page(number: Int, collected: Vector[GitHubRepositorySummary]): IO[Either[GitHubApiError, Vector[GitHubRepositorySummary]]] =
        val request = apiRequest(s"/installation/repositories?per_page=$PageSize&page=$number", token.raw).GET().build()
        call(request, 200).map(_.flatMap(json => field(json, "repositories").flatMap(decodeRepositories))).flatMap:
          case Left(error) => IO.pure(Left(error))
          case Right(entries) =>
            val all = collected ++ entries
            if all.size >= limit then IO.pure(Right(all.take(limit)))
            else if entries.size < PageSize then IO.pure(Right(all))
            else page(number + 1, all)
      page(1, Vector.empty)

  def exchangeUserCode(code: String, redirectUri: URI): IO[Either[GitHubApiError, GitHubUserToken]] =
    val form = Vector(
      "client_id" -> registration.clientId,
      "client_secret" -> secrets.clientSecret,
      "code" -> code,
      "redirect_uri" -> redirectUri.toString
    ).map((key, value) => URLEncoder.encode(key, StandardCharsets.UTF_8) + "=" + URLEncoder.encode(value, StandardCharsets.UTF_8))
      .mkString("&")
    scala.util.Try:
      baseRequest(endpoints.web.resolve("/login/oauth/access_token"))
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
        .build()
    .toOption match
      case None => IO.pure(Left(GitHubApiError.Rejected))
      case Some(request) =>
        call(request, 200).map(_.flatMap: json =>
          // GitHub reports a failed exchange as HTTP 200 with an `error` field.
          if json.asObject.exists(_.contains("error")) then Left(GitHubApiError.Rejected)
          else
            json.hcursor.get[String]("access_token").toOption.filter(validToken)
              .map(token => GitHubUserToken(token))
              .toRight(GitHubApiError.InvalidResponse))

  def userCanAccessInstallation(user: GitHubUserToken, installation: GitHubInstallationId): IO[Either[GitHubApiError, Boolean]] =
    def page(number: Int): IO[Either[GitHubApiError, Boolean]] =
      val request = apiRequest(s"/user/installations?per_page=$PageSize&page=$number", user.raw).GET().build()
      call(request, 200).map(_.flatMap(json => field(json, "installations").flatMap(decodeInstallationIds))).flatMap:
        case Left(error) => IO.pure(Left(error))
        case Right(ids) =>
          if ids.contains(installation.value) then IO.pure(Right(true))
          else if ids.size < PageSize || number >= MaximumUserPages then IO.pure(Right(false))
          else page(number + 1)
    page(1)

  private def appJwt: IO[Either[GitHubApiError, String]] =
    clock.now.flatMap: now =>
      IO.blocking(GitHubAppJwt.sign(registration.clientId, secrets.privateKey, now)).attempt
        .map(_.left.map(_ => GitHubApiError.Rejected))

  private def baseRequest(uri: URI): HttpRequest.Builder =
    HttpRequest.newBuilder(uri)
      .timeout(requestTimeout)
      .header("User-Agent", "hallpass")
      .header("Accept-Encoding", "identity")

  private def apiRequest(path: String, bearer: String): HttpRequest.Builder =
    baseRequest(endpoints.api.resolve(path))
      .header("Accept", "application/vnd.github+json")
      .header("X-GitHub-Api-Version", ApiVersion)
      .header("Authorization", "Bearer " + bearer)

  /** One bounded exchange. Status is checked here, so the JDK redirect policy cannot matter: any 3xx is Rejected. */
  private def call(request: HttpRequest, expected: Int): IO[Either[GitHubApiError, Json]] =
    BoundedHttpResponse.send(http, request, MaximumResponseBytes, requestTimeout.toMillis.millis).attempt.map:
      case Left(error) => Left(classify(error))
      case Right(response) =>
        val bytes = response.body()
        try
          val status = response.statusCode()
          if status == expected then decodeJson(bytes)
          else if status >= 200 && status < 300 then Left(GitHubApiError.InvalidResponse)
          else Left(mapStatus(status, response))
        finally java.util.Arrays.fill(bytes, 0.toByte)

  private def mapStatus(status: Int, response: HttpResponse[?]): GitHubApiError =
    val exhausted = response.headers().firstValue("x-ratelimit-remaining").filter(_.trim == "0").isPresent
    status match
      case 401 => GitHubApiError.Unauthorized
      case 429 => GitHubApiError.RateLimited
      case 403 => if exhausted then GitHubApiError.RateLimited else GitHubApiError.Forbidden
      case 404 => GitHubApiError.NotFound
      case _ => GitHubApiError.Rejected

  /** Failure messages are discarded: they can carry request detail. An oversized body is an invalid response. */
  private def classify(error: Throwable): GitHubApiError =
    val chain = Iterator.iterate(error)(_.getCause).takeWhile(_ != null).take(8).toVector
    if chain.exists(e =>
        e.isInstanceOf[HttpTimeoutException] || e.isInstanceOf[ConnectException] ||
          e.isInstanceOf[java.util.concurrent.TimeoutException])
    then GitHubApiError.Timeout
    else if chain.exists(e => e.isInstanceOf[IllegalStateException] && e.getMessage == SizeLimitMessage) then
      GitHubApiError.InvalidResponse
    else GitHubApiError.Rejected

  private def decodeJson(bytes: Array[Byte]): Either[GitHubApiError, Json] =
    scala.util.Try(
      StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString
    ).toOption.flatMap(parse(_).toOption).filter(_.isObject).toRight(GitHubApiError.InvalidResponse)

  private def field(json: Json, name: String): Either[GitHubApiError, Json] =
    json.hcursor.downField(name).focus.toRight(GitHubApiError.InvalidResponse)

  private def decodeToken(json: Json): Either[GitHubApiError, MintedInstallationToken] =
    val cursor = json.hcursor
    for
      token <- cursor.get[String]("token").toOption.filter(validToken).toRight(GitHubApiError.InvalidResponse)
      expires <- cursor.get[String]("expires_at").toOption.flatMap(value => scala.util.Try(Instant.parse(value)).toOption)
        .toRight(GitHubApiError.InvalidResponse)
      permissions <- cursor.get[Map[String, String]]("permissions").toOption.toRight(GitHubApiError.InvalidResponse)
      repositories <- cursor.downField("repositories").focus match
        case None => Right(Vector.empty[GitHubRepositorySummary])
        case Some(present) => decodeRepositories(present)
    yield MintedInstallationToken(token, expires, repositories, permissions)

  private def decodeRepositories(json: Json): Either[GitHubApiError, Vector[GitHubRepositorySummary]] =
    json.asArray.toRight(GitHubApiError.InvalidResponse).flatMap: entries =>
      entries.foldLeft[Either[GitHubApiError, Vector[GitHubRepositorySummary]]](Right(Vector.empty)): (acc, entry) =>
        for
          collected <- acc
          id <- entry.hcursor.get[Long]("id").toOption.flatMap(GitHubRepositoryId.from).toRight(GitHubApiError.InvalidResponse)
          name <- entry.hcursor.get[String]("full_name").toOption.flatMap(GitHubRepositoryName.parse)
            .toRight(GitHubApiError.InvalidResponse)
        yield collected :+ GitHubRepositorySummary(id, name)

  private def decodeInstallationIds(json: Json): Either[GitHubApiError, Vector[Long]] =
    json.asArray.toRight(GitHubApiError.InvalidResponse).flatMap: entries =>
      entries.foldLeft[Either[GitHubApiError, Vector[Long]]](Right(Vector.empty)): (acc, entry) =>
        for
          collected <- acc
          id <- entry.hcursor.get[Long]("id").toOption.toRight(GitHubApiError.InvalidResponse)
        yield collected :+ id

  private def decodeInstallation(requested: GitHubInstallationId, json: Json): Either[GitHubApiError, GitHubInstallationAccount] =
    val cursor = json.hcursor
    val account = cursor.downField("account")
    for
      id <- cursor.get[Long]("id").toOption.flatMap(GitHubInstallationId.from).filter(_.value == requested.value)
        .toRight(GitHubApiError.InvalidResponse)
      accountId <- account.get[Long]("id").toOption.filter(_ > 0).toRight(GitHubApiError.InvalidResponse)
      login <- account.get[String]("login").toOption.filter(_.nonEmpty).toRight(GitHubApiError.InvalidResponse)
      accountType <- account.get[String]("type").toOption.filter(_.nonEmpty).toRight(GitHubApiError.InvalidResponse)
    yield GitHubInstallationAccount(id, accountId, login, accountType)

  private def validToken(value: String): Boolean =
    value.nonEmpty && value.forall(c => !c.isWhitespace && !Character.isISOControl(c))

object GitHubAppClient:
  val MaximumUserPages = 10
  val MaximumResponseBytes: Int = 1024 * 1024
  private val PageSize = 100
  private val ApiVersion = "2022-11-28"
  private val SizeLimitMessage = "HTTP response exceeds the size limit"
