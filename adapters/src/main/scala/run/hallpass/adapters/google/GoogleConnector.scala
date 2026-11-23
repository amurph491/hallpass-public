package run.hallpass.adapters.google

import java.net.{URI, URLEncoder}
import java.net.http.{HttpClient, HttpRequest}
import java.nio.ByteBuffer
import java.nio.charset.{CodingErrorAction, StandardCharsets}
import scala.concurrent.duration.*
import cats.data.EitherT
import cats.effect.IO
import io.circe.JsonObject
import io.circe.parser.parse
import run.hallpass.adapters.http.BoundedHttpResponse
import run.hallpass.adapters.oauth.OAuthTokenJsonCodec
import run.hallpass.application.*

/** Google OAuth 2.0 (web server flow) with PKCE (S256), for a PERSONAL connection.
  *
  * Start: `{authorize}?client_id&redirect_uri&response_type=code&scope=<DriveScopes space-separated>&state&
  * code_challenge&code_challenge_method=S256&access_type=offline&prompt=consent&include_granted_scopes=false`.
  * Callback: POST `{token}` form (grant_type=authorization_code, code, redirect_uri, client_id, client_secret,
  * code_verifier); require access_token, refresh_token, positive expires_in (≤ 1 day), and a `scope` that contains
  * drive.file and no broader Drive scope (`drive`, `drive.readonly`, `drive.metadata*`) — refuse otherwise. Then GET
  * `{userinfo}` with the access token for `sub` (and `email` for display only).
  *
  * Grant: secret = OAuthTokenJsonCodec-encoded OAuthTokens; externalAccountId and rootExternalId = `sub`;
  * rootDisplayName / accountLabel = email when present, else "Google account"; expiresAt = token expiry. The service
  * sets the custodian to the connecting human (PERSONAL root).
  *
  * `selectableResources`: receives the unexpired access token from OAuthConnectionService (which decodes the stored
  * token record and never refreshes during management discovery), then GETs `{driveApi}/drive/v3/files?pageSize=100&fields=nextPageToken,files(id,name,mimeType,
  * trashed)&q=trashed=false`, following nextPageToken up to `fileLimit`; with drive.file this returns only files the
  * user picked or the app created.
  *
  * With `gmailSend`, `Google.GmailSendScope` is requested as well, a granted Gmail scope broader than gmail.send
  * (`https://mail.google.com/`, gmail.readonly, gmail.modify, ...) is refused, and discovery additionally offers the
  * account's mailbox (kind google.mailbox, external ID = `sub`) with no network request. Without it, any granted Gmail
  * scope is refused.
  */
final class GoogleConnector(
    client: GoogleOAuthClient,
    endpoints: GoogleEndpoints,
    http: HttpClient,
    clock: Clock[IO],
    val redirectUri: URI,
    fileLimit: Int = 1000,
    gmailSend: Boolean = false
) extends ProviderConnector:
  val provider: ProviderId = ProviderId.Google
  val rootKind: ResourceKind[?] = Google.account
  val credentialType: String = Google.CredentialType
  override val usesPkce: Boolean = true
  /** Drive operations address a selected file, never the root, so several Google accounts may be connected. */
  val singleActiveRoot: Boolean = false
  val resourceDiscovery: Option[ResourceDiscovery] = Some(new ResourceDiscovery:
    def selectableResources(credential: ProviderSecret, root: ConnectionResource) =
      GoogleConnector.this.selectableResources(credential, root)
  )

  /** Without a challenge this provider refuses to start; PKCE is mandatory here. */
  def authorizationUri(state: OAuthState): IO[URI] = IO.raiseError(IllegalStateException("Google requires PKCE"))
  override def authorizationUri(state: OAuthState, pkce: Option[PkceVerifier]): IO[URI] = pkce match
    case None => IO.raiseError(IllegalStateException("Google requires PKCE"))
    case Some(challenge) =>
      IO.delay:
        val query = form(Vector(
          "client_id" -> client.clientId,
          "redirect_uri" -> redirectUri.toString,
          "response_type" -> "code",
          "scope" -> requestedScopes.mkString(" "),
          "state" -> state.value,
          "code_challenge" -> challenge.challenge,
          "code_challenge_method" -> "S256",
          "access_type" -> "offline",
          "prompt" -> "consent",
          "include_granted_scopes" -> "false"
        ))
        URI.create(endpoints.authorize.toString + (if endpoints.authorize.getRawQuery == null then "?" else "&") + query)

  private val requestedScopes: Vector[String] =
    if gmailSend then Google.DriveScopes :+ Google.GmailSendScope else Google.DriveScopes

  def exchange(callback: OAuthCallback): IO[Either[OAuthError, OAuthGrant]] = IO.pure(Left(OAuthError.InvalidState))
  override def exchange(callback: OAuthCallback, pkce: Option[PkceVerifier]): IO[Either[OAuthError, OAuthGrant]] = pkce match
    case None => IO.pure(Left(OAuthError.InvalidState))
    case Some(verifier) =>
      (for
        tokens <- EitherT(requestTokens(callback, verifier))
        identity <- EitherT(identify(tokens))
      yield
        val label = identity.email.getOrElse(GoogleConnector.DefaultLabel)
        OAuthGrant(
          secret = OAuthTokenJsonCodec().encode(tokens),
          externalAccountId = identity.subject,
          rootExternalId = identity.subject,
          rootDisplayName = label,
          accountLabel = Some(label),
          workspaceLabel = None,
          expiresAt = Some(tokens.expiresAt)
        )).value

  private def requestTokens(callback: OAuthCallback, verifier: PkceVerifier): IO[Either[OAuthError, OAuthTokens]] =
    IO.delay:
      HttpRequest.newBuilder(endpoints.token)
        .timeout(RequestTimeout)
        .header("Accept", "application/json")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .header("User-Agent", "hallpass")
        .POST(HttpRequest.BodyPublishers.ofString(
          form(Vector(
            "grant_type" -> "authorization_code",
            "code" -> callback.code,
            "redirect_uri" -> redirectUri.toString,
            "client_id" -> client.clientId,
            "client_secret" -> client.secretForRefresh,
            "code_verifier" -> verifier.value
          )),
          StandardCharsets.UTF_8))
        .build()
    .attempt.flatMap:
      case Left(_) => IO.pure(Left(OAuthError.ProviderRejected))
      case Right(request) =>
        fetch(request, GoogleConnector.MaximumTokenResponseBytes)(GoogleConnector.decodeTokenResponse(_, gmailSend)).flatMap:
          case Left(error) => IO.pure(Left(error))
          case Right((access, refresh, lifetime)) =>
            clock.now.attempt.map:
              case Left(_) => Left(OAuthError.ProviderRejected)
              case Right(now) =>
                scala.util.Try(now.plusSeconds(lifetime)).toOption
                  .flatMap(expiresAt => OAuthTokens.from(access, Some(refresh), expiresAt))
                  .toRight(OAuthError.InvalidProviderResponse)

  /** Sends one request with no redirect, no retry, and a bounded body. Only a 200 is parsed; the body bytes are
    * zeroed afterwards. Transport failure, timeout, oversize, and any other status are one rejection. */
  private def fetch[A](request: HttpRequest, maximumBytes: Int)(parseBody: Array[Byte] => Either[OAuthError, A]): IO[Either[OAuthError, A]] =
    BoundedHttpResponse.send(http, request, maximumBytes, RequestTimeout.toMillis.millis).attempt.map:
      case Left(_) => Left(OAuthError.ProviderRejected)
      case Right(response) =>
        val bytes = response.body()
        try
          if response.statusCode() == 200 then parseBody(bytes) else Left(OAuthError.ProviderRejected)
        finally java.util.Arrays.fill(bytes, 0.toByte)

  private def authorizedGet(uri: URI, token: String): IO[Either[OAuthError, HttpRequest]] =
    IO.delay:
      HttpRequest.newBuilder(uri)
        .timeout(RequestTimeout)
        .header("Accept", "application/json")
        .header("Authorization", "Bearer " + token)
        .header("User-Agent", "hallpass")
        .GET()
        .build()
    .attempt.map(_.left.map(_ => OAuthError.ProviderRejected))

  private def identify(tokens: OAuthTokens): IO[Either[OAuthError, GoogleConnector.Identity]] =
    authorizedGet(endpoints.userinfo, tokens.accessToken).flatMap:
      case Left(error) => IO.pure(Left(error))
      case Right(request) => fetch(request, GoogleConnector.MaximumIdentityResponseBytes)(GoogleConnector.decodeIdentity)

  def selectableResources(credential: ProviderSecret, root: ConnectionResource): IO[Either[OAuthError, Vector[SelectableProviderResource]]] =
    if root.kind != Google.account.wire then IO.pure(Left(OAuthError.InvalidState))
    else
      val bytes = ProviderSecret.bytes(credential)
      val accessToken = try new String(bytes, StandardCharsets.UTF_8)
      finally java.util.Arrays.fill(bytes, 0.toByte)
      if !GoogleConnector.validToken(accessToken) then IO.pure(Left(OAuthError.InvalidState))
      else
        listFiles(accessToken, None, Vector.empty).map(_.map: files =>
          val mailbox = Option.when(gmailSend)(
            SelectableProviderResource(Google.mailbox, root.externalId, GoogleConnector.mailboxLabel(root.displayName), root.externalId)
          ).toVector
          files.distinctBy(_.id.value).map(file =>
            SelectableProviderResource(Google.driveFile, file.id.externalId, file.name, root.externalId)
          ).sortBy(_.displayName) ++ mailbox
        )

  private def listFiles(token: String, after: Option[String], collected: Vector[GoogleConnector.FileRow]): IO[Either[OAuthError, Vector[GoogleConnector.FileRow]]] =
    val query = form(
      Vector(
        "pageSize" -> GoogleConnector.PageSize.toString,
        "fields" -> "nextPageToken,files(id,name,mimeType,trashed)",
        "q" -> "trashed=false"
      ) ++ after.map("pageToken" -> _)
    )
    val base = endpoints.driveApi.toString.stripSuffix("/")
    authorizedGet(URI.create(s"$base/drive/v3/files?$query"), token).flatMap:
      case Left(error) => IO.pure(Left(error))
      case Right(request) =>
        fetch(request, GoogleConnector.MaximumListResponseBytes)(GoogleConnector.decodeFiles).flatMap:
          case Left(error) => IO.pure(Left(error))
          case Right((found, next)) =>
            val all = (collected ++ found).take(fileLimit)
            if next.isEmpty || all.size >= fileLimit then IO.pure(Right(all))
            else next match
              case Some(cursor) if !after.contains(cursor) => listFiles(token, Some(cursor), all)
              case _ => IO.pure(Left(OAuthError.InvalidProviderResponse))

  private val RequestTimeout = java.time.Duration.ofSeconds(10)

  private def form(fields: Vector[(String, String)]): String =
    fields.map((key, value) => encode(key) + "=" + encode(value)).mkString("&")
  private def encode(value: String): String = URLEncoder.encode(value, StandardCharsets.UTF_8)

object GoogleConnector:
  val MaximumTokenResponseBytes: Int = 64 * 1024
  val MaximumIdentityResponseBytes: Int = 64 * 1024
  val MaximumListResponseBytes: Int = 1024 * 1024
  val MaximumLifetimeSeconds: Long = 24L * 60 * 60
  val PageSize: Int = 100
  val DefaultLabel: String = "Google account"

  private final case class Identity(subject: ExternalId, email: Option[String])
  private final case class FileRow(id: DriveFileId, name: String)

  private val DriveFileScope = "https://www.googleapis.com/auth/drive.file"
  private val DriveScopeFamily = "https://www.googleapis.com/auth/drive"

  private def validLabel(value: String): Boolean =
    value.trim.nonEmpty && value.length <= 200 && !value.exists(Character.isISOControl)

  private def validToken(value: String): Boolean =
    value.nonEmpty && value.length <= 16384 && value.forall(c => !c.isWhitespace && !Character.isISOControl(c))

  /** drive.file must be granted and nothing else in the Drive scope family (`drive`, `drive.readonly`,
    * `drive.metadata*`, `drive.appdata`, ...): an over-broad consent is refused, never stored. */
  private def scopeAcceptable(scope: String, gmailSend: Boolean): Boolean =
    val granted = scope.split("\\s+").filter(_.nonEmpty).toSet
    granted.contains(DriveFileScope) && !granted.exists: s =>
      (s != DriveFileScope && (s == DriveScopeFamily || s.startsWith(DriveScopeFamily + ".") || s.startsWith(DriveScopeFamily + "/"))) ||
        (isGmailScope(s) && !(gmailSend && s == Google.GmailSendScope))

  /** Every Gmail scope, including the full-mailbox `https://mail.google.com/`. Only gmail.send is ever acceptable. */
  private def isGmailScope(scope: String): Boolean =
    scope.startsWith("https://mail.google.com") || scope.startsWith("https://www.googleapis.com/auth/gmail.")

  private[google] def mailboxLabel(rootDisplayName: String): String = s"Mailbox (send) — $rootDisplayName"

  private def jsonObject(bytes: Array[Byte]): Option[JsonObject] =
    scala.util.Try(
      StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes)).toString
    ).toOption.flatMap(parse(_).toOption).flatMap(_.asObject)

  private def decodeTokenResponse(bytes: Array[Byte], gmailSend: Boolean): Either[OAuthError, (String, String, Long)] =
    jsonObject(bytes) match
      case None => Left(OAuthError.InvalidProviderResponse)
      case Some(obj) =>
        val fields = for
          _ <- Option.when(!obj.contains("error"))(())
          _ <- obj("token_type").fold(Some(()))(_.asString.filter(_.equalsIgnoreCase("Bearer")).map(_ => ()))
          access <- obj("access_token").flatMap(_.asString).filter(validToken)
          refresh <- obj("refresh_token").flatMap(_.asString).filter(validToken)
          lifetime <- obj("expires_in").flatMap(_.asNumber).flatMap(_.toLong)
            .filter(seconds => seconds > 0 && seconds <= MaximumLifetimeSeconds)
          scope <- obj("scope").flatMap(_.asString)
        yield (access, refresh, lifetime, scope)
        fields match
          case None => Left(OAuthError.InvalidProviderResponse)
          case Some((access, refresh, lifetime, scope)) =>
            if scopeAcceptable(scope, gmailSend) then Right((access, refresh, lifetime)) else Left(OAuthError.ProviderRejected)

  /** The identity is `sub`; the email is display text only and is dropped when it is not a plain label. */
  private def decodeIdentity(bytes: Array[Byte]): Either[OAuthError, Identity] =
    jsonObject(bytes).flatMap: obj =>
      obj("sub").flatMap(_.asString).filter(_.length <= 255).flatMap(ExternalId.parse).map: subject =>
        Identity(subject, obj("email").flatMap(_.asString).filter(validLabel))
    .toRight(OAuthError.InvalidProviderResponse)

  private def decodeFiles(bytes: Array[Byte]): Either[OAuthError, (Vector[FileRow], Option[String])] =
    jsonObject(bytes).flatMap: obj =>
      for
        nodes <- obj("files").flatMap(_.asArray).map(_.toVector)
        rows <-
          val decoded = nodes.map: node =>
            for
              id <- node.hcursor.get[String]("id").toOption.flatMap(DriveFileId.parse)
              name <- node.hcursor.get[String]("name").toOption.map(sanitizeName)
            yield (FileRow(id, name), node.hcursor.get[Boolean]("trashed").toOption.contains(true))
          Option.when(decoded.forall(_.isDefined))(decoded.flatten.filterNot(_._2).map(_._1))
        next <- obj("nextPageToken") match
          case None => Some(None)
          case Some(token) => token.asString.filter(c => c.nonEmpty && c.length <= 2048).map(Some(_))
      yield (rows, next)
    .toRight(OAuthError.InvalidProviderResponse)

  /** File names are user text: control characters become spaces and length is bounded, so one odd name cannot
    * make the whole listing invalid. */
  private def sanitizeName(raw: String): String =
    val cleaned = raw.map(c => if Character.isISOControl(c) then ' ' else c).trim.take(200).trim
    if cleaned.isEmpty then "Untitled" else cleaned
