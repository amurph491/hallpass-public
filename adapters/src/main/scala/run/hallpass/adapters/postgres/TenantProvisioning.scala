package run.hallpass.adapters.postgres

import java.util.UUID
import cats.effect.IO
import cats.syntax.all.*
import scala.util.chaining.*
import org.typelevel.doobie.*
import org.typelevel.doobie.implicits.*
import org.typelevel.doobie.postgres.implicits.*
import run.hallpass.application.*
import run.hallpass.kernel.*

enum TenantProvisioningError:
  case InvalidName, InvalidSlug

/** A new tenant and the identity-provider account of its first administrator. */
final case class TenantProvisioningRequest private (name: String, slug: String, administrator: ExternalIdentity)
object TenantProvisioningRequest:
  private val SlugPattern = "[a-z0-9][a-z0-9-]{0,62}".r

  def from(
      name: String,
      slug: String,
      administrator: ExternalIdentity
  ): Either[TenantProvisioningError, TenantProvisioningRequest] =
    if name.trim.isEmpty || name != name.trim || name.length > 200 || name.exists(Character.isISOControl) then
      Left(TenantProvisioningError.InvalidName)
    else
      slug match
        case SlugPattern() => Right(TenantProvisioningRequest(name, slug, administrator))
        case _             => Left(TenantProvisioningError.InvalidSlug)

final case class ProvisionedTenant(tenant: TenantId, administrator: DirectoryUserId, administratorPrincipal: Principal.Human)

/** Row identifiers for one provisioning run. Production uses fresh random identifiers; the development fixture uses
  * fixed ones so repeated local startups converge on the same rows. */
private[postgres] final case class ProvisioningIds(
    tenant: TenantId,
    candidateUser: DirectoryUserId,
    administratorPrincipal: UserId,
    slackResource: ResourceId,
    readCapability: UUID,
    sendCapability: UUID,
    searchTool: UUID,
    sendTool: UUID,
    readPolicy: UUID,
    sendPolicy: UUID,
    readBinding: UUID,
    sendBinding: UUID,
    github: GitHubCatalogIds,
    linear: LinearCatalogIds,
    notion: NotionCatalogIds,
    google: GoogleCatalogIds,
    hubspot: HubSpotCatalogIds
)

/** Identifiers of one GitHub catalog provisioning: the provider resource, its capabilities, tools, and owner policy. */
private[postgres] final case class GitHubCatalogIds(
    resource: ResourceId,
    issueCapability: UUID,
    pullRequestCapability: UUID,
    issuesListTool: UUID,
    issuesGetTool: UUID,
    pullsListTool: UUID,
    pullsGetTool: UUID,
    policy: UUID,
    binding: UUID,
    createCapability: UUID,
    issuesCreateTool: UUID,
    writePolicy: UUID,
    writeBinding: UUID
)

private[postgres] object GitHubCatalogIds:
  def random(): GitHubCatalogIds =
    GitHubCatalogIds(
      ResourceId.random(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
      UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
      UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID()
    )

/** Identifiers of one Linear catalog provisioning: the provider resource, its capabilities, tools, and owner policies. */
private[postgres] final case class LinearCatalogIds(
    resource: ResourceId,
    issueReadCapability: UUID,
    issueCreateCapability: UUID,
    issuesListTool: UUID,
    issuesGetTool: UUID,
    issuesCreateTool: UUID,
    readPolicy: UUID,
    readBinding: UUID,
    writePolicy: UUID,
    writeBinding: UUID
)

private[postgres] object LinearCatalogIds:
  def random(): LinearCatalogIds =
    LinearCatalogIds(
      ResourceId.random(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
      UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID()
    )

/** Identifiers of one Notion catalog provisioning: the provider resource, its capabilities, tools, and owner policies. */
private[postgres] final case class NotionCatalogIds(
    resource: ResourceId,
    pageReadCapability: UUID,
    pageAppendCapability: UUID,
    pagesGetTool: UUID,
    blocksChildrenListTool: UUID,
    blocksAppendTool: UUID,
    readPolicy: UUID,
    readBinding: UUID,
    appendPolicy: UUID,
    appendBinding: UUID
)

private[postgres] object NotionCatalogIds:
  def random(): NotionCatalogIds =
    NotionCatalogIds(
      ResourceId.random(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
      UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID()
    )

/** Identifiers of one Google catalog provisioning: the provider resource, its capability, tools, and owner policy. */
private[postgres] final case class GoogleCatalogIds(
    resource: ResourceId,
    driveFileReadCapability: UUID,
    filesGetTool: UUID,
    filesExportTextTool: UUID,
    readPolicy: UUID,
    readBinding: UUID,
    mailSendCapability: UUID,
    messagesSendTool: UUID,
    sendPolicy: UUID,
    sendBinding: UUID
)

private[postgres] object GoogleCatalogIds:
  def random(): GoogleCatalogIds =
    GoogleCatalogIds(
      ResourceId.random(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
      UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID()
    )

/** Identifiers of one HubSpot catalog provisioning: the provider resource, its capabilities, tools, and owner policies. */
private[postgres] final case class HubSpotCatalogIds(
    resource: ResourceId,
    contactReadCapability: UUID,
    dealReadCapability: UUID,
    dealUpdateCapability: UUID,
    contactsGetTool: UUID,
    dealsGetTool: UUID,
    dealsUpdatePropertiesTool: UUID,
    readPolicy: UUID,
    readBinding: UUID,
    updatePolicy: UUID,
    updateBinding: UUID
)

private[postgres] object HubSpotCatalogIds:
  def random(): HubSpotCatalogIds =
    HubSpotCatalogIds(
      ResourceId.random(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
      UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID()
    )

private[postgres] object ProvisioningIds:
  def random(): ProvisioningIds =
    ProvisioningIds(
      TenantId.random(),
      DirectoryUserId.random(),
      UserId.random(),
      ResourceId.random(),
      UUID.randomUUID(),
      UUID.randomUUID(),
      UUID.randomUUID(),
      UUID.randomUUID(),
      UUID.randomUUID(),
      UUID.randomUUID(),
      UUID.randomUUID(),
      UUID.randomUUID(),
      GitHubCatalogIds.random(),
      LinearCatalogIds.random(),
      NotionCatalogIds.random(),
      GoogleCatalogIds.random(),
      HubSpotCatalogIds.random()
    )

/** Creates a tenant, its first administrator's membership, the Slack, GitHub, Linear, Notion, Google, and HubSpot provider catalogs, and the administrator's owner
  * policies, in one transaction.
  *
  * This is an operator action. It must run as the schema owner (see `HallpassProvisionMain`): the runtime role can read
  * tenants, the catalog, and policies but cannot create them, and it has no access to the directory at all. Tenant
  * rows are still written under that tenant's RLS context, because the owner is subject to forced RLS too. */
object TenantProvisioning:
  /** Connects as the owner in `config`, checks the schema matches this release, and provisions in one transaction. */
  def provision(config: DatabaseConfig, request: TenantProvisioningRequest): IO[ProvisionedTenant] =
    PostgresDatabase.ownerResource(config).use(provision(_, request))

  def provision(xa: Transactor[IO], request: TenantProvisioningRequest): IO[ProvisionedTenant] =
    program(request, ProvisioningIds.random()).transact(xa)

  /** Inserts that already exist (by primary key) are skipped, so a fixed-ID run is idempotent. A slug held by a
    * different tenant fails the transaction. */
  private[postgres] def program(request: TenantProvisioningRequest, ids: ProvisioningIds): ConnectionIO[ProvisionedTenant] =
    val tenant = ids.tenant.toString
    val human = ids.administratorPrincipal.toString
    val resource = ids.slackResource.toString
    // Bind JSON as data. Embedding escaped JSON inside a Doobie SQL interpolator
    // causes PostgreSQL to receive the backslashes as JSON input.
    val readPolicyDefinition = """{"action":"READ","effect":"ALLOW"}"""
    val sendPolicyDefinition = """{"action":"WRITE","effect":"REQUIRE_APPROVAL"}"""
    val tenantRows: ConnectionIO[Unit] = for
      _ <-
        sql"insert into tenants(id,name,slug) values ($tenant::uuid,${request.name},${request.slug}) on conflict (id) do nothing".update.run
      _ <-
        sql"insert into principals(id,tenant_id,kind) values ($human::uuid,$tenant::uuid,'HUMAN') on conflict (id) do nothing".update.run
      _ <-
        sql"insert into human_identities(tenant_id,principal_id) values ($tenant::uuid,$human::uuid) on conflict (principal_id) do nothing".update.run
      _ <-
        sql"insert into resources(id,tenant_id,resource_type,name,provider,external_id) values ($resource::uuid,$tenant::uuid,'PROVIDER','Slack workspace','slack','slack-workspace') on conflict (id) do nothing".update.run
      _ <-
        sql"insert into capabilities(id,tenant_id,namespace,name,action,resource_id) values (${ids.readCapability}::uuid,$tenant::uuid,'Slack.Message','Read','READ',$resource::uuid) on conflict (id) do nothing".update.run
      _ <-
        sql"insert into capabilities(id,tenant_id,namespace,name,action,resource_id) values (${ids.sendCapability}::uuid,$tenant::uuid,'Slack.Message','Send','WRITE',$resource::uuid) on conflict (id) do nothing".update.run
      _ <-
        sql"insert into resources(id,tenant_id,resource_type,name,provider,parent_resource_id,external_id) values (${ids.searchTool}::uuid,$tenant::uuid,'TOOL','Search Slack messages','slack',$resource::uuid,'slack_search_messages') on conflict (id) do nothing".update.run
      _ <-
        sql"insert into resources(id,tenant_id,resource_type,name,provider,parent_resource_id,external_id) values (${ids.sendTool}::uuid,$tenant::uuid,'TOOL','Send Slack message','slack',$resource::uuid,'slack_send_message') on conflict (id) do nothing".update.run
      _ <-
        sql"insert into tools(tenant_id,resource_id,protocol) values ($tenant::uuid,${ids.searchTool}::uuid,'MCP') on conflict do nothing".update.run
      _ <-
        sql"insert into tools(tenant_id,resource_id,protocol) values ($tenant::uuid,${ids.sendTool}::uuid,'MCP') on conflict do nothing".update.run
      _ <-
        sql"insert into tool_capability_mappings(tenant_id,tool_id,capability_id,mapping_source,trusted) values ($tenant::uuid,${ids.searchTool}::uuid,${ids.readCapability}::uuid,'PROVIDER_DEFINED',true) on conflict do nothing".update.run
      _ <-
        sql"insert into tool_capability_mappings(tenant_id,tool_id,capability_id,mapping_source,trusted) values ($tenant::uuid,${ids.sendTool}::uuid,${ids.sendCapability}::uuid,'PROVIDER_DEFINED',true) on conflict do nothing".update.run
      _ <-
        sql"insert into policies(id,tenant_id,name,version,status,definition,created_by) values (${ids.readPolicy}::uuid,$tenant::uuid,'Slack read owner authority',1,'ACTIVE',$readPolicyDefinition::jsonb,$human::uuid) on conflict (id) do nothing".update.run
      _ <-
        sql"insert into policies(id,tenant_id,name,version,status,definition,created_by) values (${ids.sendPolicy}::uuid,$tenant::uuid,'Slack send owner authority',1,'ACTIVE',$sendPolicyDefinition::jsonb,$human::uuid) on conflict (id) do nothing".update.run
      _ <-
        sql"insert into policy_bindings(id,tenant_id,policy_id,subject_principal_id,resource_id) values (${ids.readBinding}::uuid,$tenant::uuid,${ids.readPolicy}::uuid,$human::uuid,$resource::uuid) on conflict (id) do nothing".update.run
      _ <-
        sql"insert into policy_bindings(id,tenant_id,policy_id,subject_principal_id,resource_id) values (${ids.sendBinding}::uuid,$tenant::uuid,${ids.sendPolicy}::uuid,$human::uuid,$resource::uuid) on conflict (id) do nothing".update.run
    yield ()

    for
      _ <- TenantSession.establish(ids.tenant)
      _ <- tenantRows
      _ <- ProviderCatalogProvisioning.github(ids.tenant, List(ids.administratorPrincipal), ids.github)
      _ <- ProviderCatalogProvisioning.linear(ids.tenant, List(ids.administratorPrincipal), ids.linear)
      _ <- ProviderCatalogProvisioning.notion(ids.tenant, List(ids.administratorPrincipal), ids.notion)
      _ <- ProviderCatalogProvisioning.google(ids.tenant, List(ids.administratorPrincipal), ids.google)
      _ <- ProviderCatalogProvisioning.hubspot(ids.tenant, List(ids.administratorPrincipal), ids.hubspot)
      user <- directoryUser(request.administrator, ids.candidateUser)
      _ <-
        sql"""insert into directory_tenant_memberships(tenant_id,user_id,human_principal_id,role,status)
              values ($tenant::uuid,${user.toString}::uuid,$human::uuid,'ADMIN','ACTIVE')
              on conflict (tenant_id, user_id) do nothing""".update.run
    yield ProvisionedTenant(ids.tenant, user, Principal.Human(ids.administratorPrincipal))

  /** The existing user for this identity-provider account, or a new active user. One person keeps one directory user
    * across the tenants they are provisioned into. */
  private def directoryUser(identity: ExternalIdentity, candidate: DirectoryUserId): ConnectionIO[DirectoryUserId] =
    sql"select user_id from directory_external_identities where issuer=${identity.issuer} and subject=${identity.subject}"
      .query[UUID]
      .option
      .flatMap:
        case Some(existing) =>
          DirectoryUserId.parse(existing.toString) match
            case Right(user) => user.pure[ConnectionIO]
            case Left(_)     => FC.raiseError(IllegalStateException("directory user identifier is invalid"))
        case None =>
          sql"insert into directory_users(id,status) values (${candidate.toString}::uuid,'ACTIVE')".update.run *>
            sql"""insert into directory_external_identities(issuer,subject,user_id)
                  values (${identity.issuer},${identity.subject},${candidate.toString}::uuid)""".update.run
              .as(candidate)

/** Provider catalogs: the provider resource, its capabilities, its tools with trusted PROVIDER_DEFINED mappings, and
  * owner policies. Shared by tenant provisioning and by adding a provider to an existing tenant. Owner policies grant
  * administrators READ and WRITE (issue creation) on GitHub and Linear without approval. */
object ProviderCatalogProvisioning:
  /** The row-by-row inserts shared by every provider catalog. `providerKey` is the lower-case provider name stored on
    * the catalog's resources. Each helper inserts only when its natural key is missing and says whether it wrote. */
  private final class CatalogRows(tenant: TenantId, administrators: List[UserId], providerKey: String):
    private val tenantId = tenant.toString

    /** The existing row's id, or the supplied one after inserting it; the flag says whether a row was inserted. */
    def ensure(existing: ConnectionIO[Option[UUID]], candidate: UUID, insert: ConnectionIO[Int]): ConnectionIO[(UUID, Boolean)] =
      existing.flatMap:
        case Some(found) => (found, false).pure[ConnectionIO]
        case None        => insert.map(_ => (candidate, true))

    def provider(resourceId: UUID, name: String): ConnectionIO[(UUID, Boolean)] =
      ensure(
        sql"select id from resources where tenant_id=$tenantId::uuid and resource_type='PROVIDER' and provider=$providerKey order by id limit 1".query[UUID].option,
        resourceId,
        sql"insert into resources(id,tenant_id,resource_type,name,provider,external_id) values ($resourceId::uuid,$tenantId::uuid,'PROVIDER',$name,$providerKey,$providerKey) on conflict (id) do nothing".update.run
      )

    def capability(resource: UUID, id: UUID, namespace: String, name: String, action: String): ConnectionIO[(UUID, Boolean)] =
      ensure(
        sql"select id from capabilities where tenant_id=$tenantId::uuid and namespace=$namespace and name=$name order by id limit 1".query[UUID].option,
        id,
        sql"insert into capabilities(id,tenant_id,namespace,name,action,resource_id) values ($id::uuid,$tenantId::uuid,$namespace,$name,$action,$resource::uuid) on conflict (id) do nothing".update.run
      )

    def tool(resource: UUID, id: UUID, name: String, external: String, capabilityId: UUID): ConnectionIO[Boolean] =
      for
        row <- ensure(
          sql"select id from resources where tenant_id=$tenantId::uuid and resource_type='TOOL' and provider=$providerKey and external_id=$external order by id limit 1".query[UUID].option,
          id,
          sql"insert into resources(id,tenant_id,resource_type,name,provider,parent_resource_id,external_id) values ($id::uuid,$tenantId::uuid,'TOOL',$name,$providerKey,$resource::uuid,$external) on conflict (id) do nothing".update.run
        )
        toolRow <-
          sql"insert into tools(tenant_id,resource_id,protocol) values ($tenantId::uuid,${row._1}::uuid,'MCP') on conflict do nothing".update.run
        mapping <-
          sql"insert into tool_capability_mappings(tenant_id,tool_id,capability_id,mapping_source,trusted) values ($tenantId::uuid,${row._1}::uuid,$capabilityId::uuid,'PROVIDER_DEFINED',true) on conflict do nothing".update.run
      yield row._2 || toolRow > 0 || mapping > 0

    /** An owner policy by name, bound to every administrator on the provider resource. No administrator, no policy. */
    def ownerPolicy(resource: UUID, policy: UUID, firstBinding: UUID, name: String, definition: String): ConnectionIO[Boolean] =
      administrators.headOption match
        case None          => false.pure[ConnectionIO]
        case Some(creator) =>
          for
            row <- ensure(
              sql"select id from policies where tenant_id=$tenantId::uuid and name=$name order by id limit 1".query[UUID].option,
              policy,
              sql"insert into policies(id,tenant_id,name,version,status,definition,created_by) values ($policy::uuid,$tenantId::uuid,$name,1,'ACTIVE',$definition::jsonb,${creator.toString}::uuid) on conflict (id) do nothing".update.run
            )
            bindings <- administrators.zipWithIndex.traverse: (administrator, index) =>
              val binding = if index == 0 then firstBinding else UUID.randomUUID()
              ensure(
                sql"select id from policy_bindings where tenant_id=$tenantId::uuid and policy_id=${row._1}::uuid and subject_principal_id=${administrator.toString}::uuid and resource_id=$resource::uuid order by id limit 1".query[UUID].option,
                binding,
                sql"insert into policy_bindings(id,tenant_id,policy_id,subject_principal_id,resource_id) values ($binding::uuid,$tenantId::uuid,${row._1}::uuid,${administrator.toString}::uuid,$resource::uuid) on conflict (id) do nothing".update.run
              ).map(_._2)
          yield row._2 || bindings.exists(identity)

  private val ReadDefinition = """{"action":"READ","effect":"ALLOW"}"""
  private val WriteDefinition = """{"action":"WRITE","effect":"ALLOW"}"""

  /** Provisions the GitHub catalog row by row: each provider resource, capability, tool, mapping, policy, and binding
    * is inserted only if its natural key is missing, so a repeat run changes nothing and a tenant provisioned with an
    * earlier catalog gains exactly the rows it lacks. Rows are written under the tenant's RLS context, which the
    * caller has already established. Returns whether anything was written. */
  private[postgres] def github(tenant: TenantId, administrators: List[UserId], ids: GitHubCatalogIds): ConnectionIO[Boolean] =
    val rows = CatalogRows(tenant, administrators, "github")
    import rows.*
    for
      root <- provider(ids.resource.toString.pipe(UUID.fromString), "GitHub")
      resource = root._1
      issueRead <- capability(resource, ids.issueCapability, "GitHub.Issue", "Read", "READ")
      pullRead <- capability(resource, ids.pullRequestCapability, "GitHub.PullRequest", "Read", "READ")
      issueCreate <- capability(resource, ids.createCapability, "GitHub.Issue", "Create", "WRITE")
      listIssues <- tool(resource, ids.issuesListTool, "List GitHub issues", "github_issues_list", issueRead._1)
      getIssue <- tool(resource, ids.issuesGetTool, "Get GitHub issue", "github_issues_get", issueRead._1)
      listPulls <- tool(resource, ids.pullsListTool, "List GitHub pull requests", "github_pulls_list", pullRead._1)
      getPull <- tool(resource, ids.pullsGetTool, "Get GitHub pull request", "github_pulls_get", pullRead._1)
      createIssue <- tool(resource, ids.issuesCreateTool, "Create GitHub issue", "github_issues_create", issueCreate._1)
      readPolicy <- ownerPolicy(resource, ids.policy, ids.binding, "GitHub read owner authority", ReadDefinition)
      writePolicy <- ownerPolicy(resource, ids.writePolicy, ids.writeBinding, "GitHub write owner authority", WriteDefinition)
    yield List(root._2, issueRead._2, pullRead._2, issueCreate._2, listIssues, getIssue, listPulls, getPull, createIssue, readPolicy, writePolicy)
      .exists(identity)

  /** Provisions the Linear catalog with the same per-row idempotence as GitHub: Linear.Issue.Read (list, get) and
    * Linear.Issue.Create, with owner policies that allow administrators READ and WRITE on the provider resource. */
  private[postgres] def linear(tenant: TenantId, administrators: List[UserId], ids: LinearCatalogIds): ConnectionIO[Boolean] =
    val rows = CatalogRows(tenant, administrators, "linear")
    import rows.*
    for
      root <- provider(ids.resource.toString.pipe(UUID.fromString), "Linear")
      resource = root._1
      issueRead <- capability(resource, ids.issueReadCapability, "Linear.Issue", "Read", "READ")
      issueCreate <- capability(resource, ids.issueCreateCapability, "Linear.Issue", "Create", "WRITE")
      listIssues <- tool(resource, ids.issuesListTool, "List Linear issues", "linear_issues_list", issueRead._1)
      getIssue <- tool(resource, ids.issuesGetTool, "Get Linear issue", "linear_issues_get", issueRead._1)
      createIssue <- tool(resource, ids.issuesCreateTool, "Create Linear issue", "linear_issues_create", issueCreate._1)
      readPolicy <- ownerPolicy(resource, ids.readPolicy, ids.readBinding, "Linear read owner authority", ReadDefinition)
      writePolicy <- ownerPolicy(resource, ids.writePolicy, ids.writeBinding, "Linear write owner authority", WriteDefinition)
    yield List(root._2, issueRead._2, issueCreate._2, listIssues, getIssue, createIssue, readPolicy, writePolicy).exists(identity)

  private val AppendDefinition = """{"action":"WRITE","effect":"REQUIRE_APPROVAL"}"""

  /** Provisions the Notion catalog with the same per-row idempotence: Notion.Page.Read (page get, block children list)
    * allowed for administrators, and Notion.Page.Append, which requires approval. */
  private[postgres] def notion(tenant: TenantId, administrators: List[UserId], ids: NotionCatalogIds): ConnectionIO[Boolean] =
    val rows = CatalogRows(tenant, administrators, "notion")
    import rows.*
    for
      root <- provider(ids.resource.toString.pipe(UUID.fromString), "Notion")
      resource = root._1
      pageRead <- capability(resource, ids.pageReadCapability, "Notion.Page", "Read", "READ")
      pageAppend <- capability(resource, ids.pageAppendCapability, "Notion.Page", "Append", "WRITE")
      getPage <- tool(resource, ids.pagesGetTool, "Get Notion page", "notion_pages_get", pageRead._1)
      listBlocks <- tool(resource, ids.blocksChildrenListTool, "List Notion block children", "notion_blocks_children_list", pageRead._1)
      appendBlocks <- tool(resource, ids.blocksAppendTool, "Append Notion blocks", "notion_blocks_append", pageAppend._1)
      readPolicy <- ownerPolicy(resource, ids.readPolicy, ids.readBinding, "Notion read owner authority", ReadDefinition)
      appendPolicy <- ownerPolicy(resource, ids.appendPolicy, ids.appendBinding, "Notion append owner authority", AppendDefinition)
    yield List(root._2, pageRead._2, pageAppend._2, getPage, listBlocks, appendBlocks, readPolicy, appendPolicy).exists(identity)

  /** Provisions the Google catalog: Google.DriveFile.Read (files get, export text), allowed for administrators, and
    * Google.Mail.Send (gmail_messages_send), which requires approval. */
  private[postgres] def google(tenant: TenantId, administrators: List[UserId], ids: GoogleCatalogIds): ConnectionIO[Boolean] =
    val rows = CatalogRows(tenant, administrators, "google")
    import rows.*
    for
      root <- provider(ids.resource.toString.pipe(UUID.fromString), "Google")
      resource = root._1
      fileRead <- capability(resource, ids.driveFileReadCapability, "Google.DriveFile", "Read", "READ")
      getFile <- tool(resource, ids.filesGetTool, "Get Google Drive file", "drive_files_get", fileRead._1)
      exportText <- tool(resource, ids.filesExportTextTool, "Export Google Drive file as text", "drive_files_export_text", fileRead._1)
      mailSend <- capability(resource, ids.mailSendCapability, "Google.Mail", "Send", "WRITE")
      sendMessage <- tool(resource, ids.messagesSendTool, "Send Gmail message", "gmail_messages_send", mailSend._1)
      readPolicy <- ownerPolicy(resource, ids.readPolicy, ids.readBinding, "Google Drive read owner authority", ReadDefinition)
      sendPolicy <- ownerPolicy(resource, ids.sendPolicy, ids.sendBinding, "Gmail send owner authority", AppendDefinition)
    yield List(root._2, fileRead._2, mailSend._2, getFile, exportText, sendMessage, readPolicy, sendPolicy).exists(identity)

  /** Provisions the HubSpot catalog: HubSpot.Contact.Read and HubSpot.Deal.Read allowed for administrators, and
    * HubSpot.Deal.Update, which requires approval. */
  private[postgres] def hubspot(tenant: TenantId, administrators: List[UserId], ids: HubSpotCatalogIds): ConnectionIO[Boolean] =
    val rows = CatalogRows(tenant, administrators, "hubspot")
    import rows.*
    for
      root <- provider(ids.resource.toString.pipe(UUID.fromString), "HubSpot")
      resource = root._1
      contactRead <- capability(resource, ids.contactReadCapability, "HubSpot.Contact", "Read", "READ")
      dealRead <- capability(resource, ids.dealReadCapability, "HubSpot.Deal", "Read", "READ")
      dealUpdate <- capability(resource, ids.dealUpdateCapability, "HubSpot.Deal", "Update", "WRITE")
      getContact <- tool(resource, ids.contactsGetTool, "Get HubSpot contact", "hubspot_contacts_get", contactRead._1)
      getDeal <- tool(resource, ids.dealsGetTool, "Get HubSpot deal", "hubspot_deals_get", dealRead._1)
      updateDeal <- tool(resource, ids.dealsUpdatePropertiesTool, "Update HubSpot deal properties", "hubspot_deals_update_properties", dealUpdate._1)
      readPolicy <- ownerPolicy(resource, ids.readPolicy, ids.readBinding, "HubSpot read owner authority", ReadDefinition)
      updatePolicy <- ownerPolicy(resource, ids.updatePolicy, ids.updateBinding, "HubSpot deal update owner authority", AppendDefinition)
    yield List(root._2, contactRead._2, dealRead._2, dealUpdate._2, getContact, getDeal, updateDeal, readPolicy, updatePolicy).exists(identity)

  /** Adds a provider catalog to an existing tenant, as the schema owner, in one transaction. A missing slug writes
    * nothing. The tenant is found by establishing each candidate's RLS context (the owner is subject to forced RLS on
    * `tenants`, so a slug cannot be read without one); candidates come from the directory memberships. */
  def addToExisting(xa: Transactor[IO], slug: String, provider: ExistingTenantProvider): IO[Option[AddedProvider]] =
    val program: ConnectionIO[Option[AddedProvider]] =
      for
        candidates <- sql"select distinct tenant_id from directory_tenant_memberships".query[UUID].to[List]
        found <- candidates.foldLeft(Option.empty[TenantId].pure[ConnectionIO]): (previous, candidate) =>
          previous.flatMap:
            case some @ Some(_) => some.pure[ConnectionIO]
            case None =>
              TenantId.parse(candidate.toString).toOption match
                case None => Option.empty[TenantId].pure[ConnectionIO]
                case Some(id) =>
                  TenantSession.establish(id) *>
                    sql"select id from tenants where slug=$slug".query[UUID].option.map(_.flatMap(_ => Some(id)))
        result <- found match
          case None => Option.empty[AddedProvider].pure[ConnectionIO]
          case Some(tenant) =>
            for
              _ <- TenantSession.establish(tenant)
              admins <-
                sql"""select human_principal_id from directory_tenant_memberships
                       where tenant_id=${tenant.toString}::uuid and role='ADMIN' and status='ACTIVE'
                       order by human_principal_id""".query[UUID].to[List]
              administrators = admins.flatMap(id => UserId.parse(id.toString).toOption)
              written <- provider match
                case ExistingTenantProvider.GitHub => github(tenant, administrators, GitHubCatalogIds.random())
                case ExistingTenantProvider.Linear => linear(tenant, administrators, LinearCatalogIds.random())
                case ExistingTenantProvider.Notion => notion(tenant, administrators, NotionCatalogIds.random())
                case ExistingTenantProvider.Google => google(tenant, administrators, GoogleCatalogIds.random())
                case ExistingTenantProvider.HubSpot => hubspot(tenant, administrators, HubSpotCatalogIds.random())
            yield Some(AddedProvider(tenant, administrators.size, written))
      yield result
    program.transact(xa)

  def addToExisting(config: DatabaseConfig, slug: String, provider: ExistingTenantProvider): IO[Option[AddedProvider]] =
    PostgresDatabase.ownerResource(config).use(addToExisting(_, slug, provider))

/** Providers that can be added to an existing tenant. */
enum ExistingTenantProvider:
  case GitHub, Linear, Notion, Google, HubSpot
object ExistingTenantProvider:
  def parse(name: String): Option[ExistingTenantProvider] = name match
    case "github" => Some(GitHub)
    case "linear" => Some(Linear)
    case "notion" => Some(Notion)
    case "google" => Some(Google)
    case "hubspot" => Some(HubSpot)
    case _        => None

/** The outcome of adding a provider catalog to an existing tenant; `written` is false when it was already present. */
final case class AddedProvider(tenant: TenantId, administrators: Int, written: Boolean)
