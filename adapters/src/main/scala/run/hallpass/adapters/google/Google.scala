package run.hallpass.adapters.google

import java.net.URI
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** Google's resource topology. The root is one person's Google account under PERSONAL custody,
  * keyed by the account's stable `sub`. Drive files the user picked are selectable below it, keyed by file ID. */
object Google:
  sealed trait Account
  sealed trait DriveFile

  given account: ResourceKind[Account] =
    ResourceKind.root("google.account", ProviderId.Google, ResourceType.Account, Custody.Personal)
  given driveFile: ResourceKind[DriveFile] = ResourceKind.child[DriveFile, Account]("google.drive_file", ResourceType.Document)
  /** One person's mailbox, selectable under their account root; external ID = the account's `sub`. */
  sealed trait Mailbox
  given mailbox: ResourceKind[Mailbox] = ResourceKind.child[Mailbox, Account]("google.mailbox", ResourceType.Channel)
  /** Send only. Never a read or modify Gmail scope. Requested only when Gmail send is enabled for the deployment. */
  val GmailSendScope = "https://www.googleapis.com/auth/gmail.send"
  /** The valued fact a send carries: its normalized recipients (To, Cc, and Bcc), for ValueIn limits. */
  val RecipientsFact: ContextKey = ContextKey.parse("gmail.recipients").get

  /** Expiring access tokens with refresh tokens: the refreshable shape. */
  val CredentialType = "OAUTH_REFRESHABLE"
  /** drive.file only: per-file access to files the user picked or the app created. Never a Drive-wide scope. */
  /** `email` is display-only (the connection label); identity is the stable `sub`. */
  val DriveScopes: Vector[String] = Vector("openid", "email", "https://www.googleapis.com/auth/drive.file")

object GoogleExecutorAudience:
  val drive: ExecutorAudience =
    ExecutorAudience.parse("hallpass.local.google.drive").getOrElse(throw IllegalStateException("static executor audience is invalid"))
  val gmail: ExecutorAudience =
    ExecutorAudience.parse("hallpass.local.google.gmail").getOrElse(throw IllegalStateException("static executor audience is invalid"))

final case class GoogleEndpoints(authorize: URI, token: URI, userinfo: URI, driveApi: URI, gmailApi: URI = URI.create("https://gmail.googleapis.com"))
object GoogleEndpoints:
  val Production: GoogleEndpoints = GoogleEndpoints(
    URI.create("https://accounts.google.com/o/oauth2/v2/auth"),
    URI.create("https://oauth2.googleapis.com/token"),
    URI.create("https://openidconnect.googleapis.com/v1/userinfo"),
    URI.create("https://www.googleapis.com")
  )

/** The Google OAuth web client. The secret is a mounted file, never rendered. `pickerApiKey` and `appId` (the Cloud
  * project number) are browser-visible configuration for Google Picker, not secrets. */
final class GoogleOAuthClient(
    val clientId: String,
    private[google] val clientSecret: String,
    val pickerApiKey: Option[String],
    val appId: Option[String]
):
  require(clientId.matches("[A-Za-z0-9._-]{1,200}"), "Google client ID is invalid")
  override def toString: String = s"GoogleOAuthClient($clientId, <redacted>)"
  def secretForRefresh: String = clientSecret

/** A Drive file ID. */
opaque type DriveFileId = String
object DriveFileId:
  private val Pattern = "[A-Za-z0-9_-]{10,200}".r
  def parse(value: String): Option[DriveFileId] = Option.when(Pattern.matches(value))(value)
  def fromExternal(value: ExternalId): Option[DriveFileId] = parse(value.value)
  extension (value: DriveFileId)
    def value: String = value
    def externalId: ExternalId = ExternalId.parse(value).get

/** What a Drive operation dispatches with. Executor-private. */
final class GoogleAccess private[google] (private[google] val accessToken: String):
  override def toString: String = "GoogleAccess(<redacted>)"

/** Refreshable OAuth for the lease's selected file. Custody is enforced by the kernel before this runs. */
final class GoogleDriveCredentials(oauth: CredentialStrategy[Google.DriveFile, OAuthTokens])
    extends CredentialStrategy[Google.DriveFile, GoogleAccess]:
  def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[Google.DriveFile]) =
    if lease.tenant != target.tenant || lease.resource != target.resource || !(target.kind eq Google.driveFile) then
      cats.effect.IO.pure(Left(ConnectionError.InvalidState))
    else oauth.credentialFor(lease, target).map(_.map(tokens => GoogleAccess(tokens.accessToken)))

/** What a Gmail send dispatches with. Executor-private. */
final class GmailAccess private[google] (private[google] val accessToken: String):
  override def toString: String = "GmailAccess(<redacted>)"

/** Refreshable OAuth for the lease's selected mailbox. Custody (only the account's owner can be the root of
  * authority) is enforced by the kernel before this runs. */
final class GmailCredentials(oauth: CredentialStrategy[Google.Mailbox, OAuthTokens])
    extends CredentialStrategy[Google.Mailbox, GmailAccess]:
  def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[Google.Mailbox]) =
    if lease.tenant != target.tenant || lease.resource != target.resource || !(target.kind eq Google.mailbox) then
      cats.effect.IO.pure(Left(ConnectionError.InvalidState))
    else oauth.credentialFor(lease, target).map(_.map(tokens => GmailAccess(tokens.accessToken)))

/** A normalized email address: lowercase, `local@domain`, ASCII, no display name, no comments, no CR/LF or other
  * control characters, at most 254 characters. The only form recipients take anywhere in Hallpass (facts, canonical
  * input, the approval preview, and the message headers), so what an approver or allowlist sees is what is sent. */
opaque type EmailAddress = String
object EmailAddress:
  private val Pattern = "[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+".r
  def parse(value: String): Option[EmailAddress] =
    val normalized = value.trim.toLowerCase(java.util.Locale.ROOT)
    Option.when(normalized.length <= 254 && Pattern.matches(normalized))(normalized)
  extension (value: EmailAddress) def value: String = value
