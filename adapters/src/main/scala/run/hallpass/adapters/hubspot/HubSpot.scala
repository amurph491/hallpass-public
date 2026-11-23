package run.hallpass.adapters.hubspot

import java.net.URI
import cats.effect.IO
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** HubSpot's resource topology. */
object HubSpot:
  sealed trait Portal
  sealed trait ObjectType

  given portal: ResourceKind[Portal] =
    ResourceKind.root("hubspot.portal", ProviderId.HubSpot, ResourceType.Account, Custody.Workspace)
  given objectType: ResourceKind[ObjectType] = ResourceKind.child[ObjectType, Portal]("hubspot.object_type", ResourceType.Custom)

  val CredentialType = "OAUTH_REFRESHABLE"
  /** CRM object-type names. A selected resource uses a portal-qualified HubSpotObjectRef. */
  val Contacts: ExternalId = ExternalId.parse("contacts").get
  val Deals: ExternalId = ExternalId.parse("deals").get
  val SelectableObjectTypes: Vector[(ExternalId, String)] = Vector(Contacts -> "Contacts", Deals -> "Deals")
  /** Scopes for the HubSpot operations. Verify names against current HubSpot docs. */
  val Scopes: Vector[String] = Vector("oauth", "crm.objects.contacts.read", "crm.objects.deals.read", "crm.objects.deals.write")
  /** The valued fact a property update carries: the set of property names it writes (ValueIn). */
  val PropertiesFact: ContextKey = ContextKey.parse("hubspot.properties").get

/** A CRM object type belongs to a portal; `deals` alone does not identify a resource.
  * The same kind may be selected in several connected portals without colliding. */
opaque type HubSpotObjectRef = String
object HubSpotObjectRef:
  private val PortalPattern = "[1-9][0-9]{0,19}".r
  def parse(value: String): Option[HubSpotObjectRef] = value.split(":", -1) match
    case Array(portal, kind) if PortalPattern.matches(portal) && HubSpot.SelectableObjectTypes.exists(_._1.value == kind) =>
      Some(value)
    case _ => None
  def forPortal(portal: ExternalId, kind: ExternalId): Option[HubSpotObjectRef] = parse(s"${portal.value}:${kind.value}")
  extension (ref: HubSpotObjectRef)
    def value: String = ref
    def externalId: ExternalId = ExternalId.parse(ref).get
    def portal: String = ref.takeWhile(_ != ':')
    def objectType: ExternalId = ExternalId.parse(ref.dropWhile(_ != ':').drop(1)).get

object HubSpotExecutorAudience:
  val local: ExecutorAudience =
    ExecutorAudience.parse("hallpass.local.hubspot").getOrElse(throw IllegalStateException("static executor audience is invalid"))

final case class HubSpotEndpoints(authorize: URI, api: URI)
object HubSpotEndpoints:
  val Production: HubSpotEndpoints =
    HubSpotEndpoints(URI.create("https://app.hubspot.com/oauth/authorize"), URI.create("https://api.hubapi.com"))
  extension (endpoints: HubSpotEndpoints) def token: URI = endpoints.api.resolve("/oauth/v1/token")

final class HubSpotOAuthClient(val clientId: String, private[hubspot] val clientSecret: String):
  require(clientId.matches("[A-Za-z0-9._-]{1,128}"), "HubSpot client ID is invalid")
  override def toString: String = s"HubSpotOAuthClient($clientId, <redacted>)"
  def secretForRefresh: String = clientSecret

/** A HubSpot record ID (numeric). */
opaque type HubSpotRecordId = String
object HubSpotRecordId:
  private val Pattern = "[1-9][0-9]{0,19}".r
  def parse(value: String): Option[HubSpotRecordId] = Option.when(Pattern.matches(value))(value)
  extension (value: HubSpotRecordId) def value: String = value

/** A CRM property's internal name, e.g. `dealstage`. Values are facts for ValueIn constraints. */
opaque type HubSpotPropertyName = String
object HubSpotPropertyName:
  private val Pattern = "[a-z][a-z0-9_]{0,99}".r
  def parse(value: String): Option[HubSpotPropertyName] = Option.when(Pattern.matches(value))(value)
  extension (value: HubSpotPropertyName) def value: String = value

final class HubSpotAccess private[hubspot] (private[hubspot] val accessToken: String):
  override def toString: String = "HubSpotAccess(<redacted>)"

/** Refreshable OAuth for the lease's object type. */
final class HubSpotCredentials(oauth: CredentialStrategy[HubSpot.ObjectType, OAuthTokens])
    extends CredentialStrategy[HubSpot.ObjectType, HubSpotAccess]:
  def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[HubSpot.ObjectType]) =
    if lease.tenant != target.tenant || lease.resource != target.resource || !(target.kind eq HubSpot.objectType) then
      IO.pure(Left(ConnectionError.InvalidState))
    else oauth.credentialFor(lease, target).map(_.map(tokens => HubSpotAccess(tokens.accessToken)))
