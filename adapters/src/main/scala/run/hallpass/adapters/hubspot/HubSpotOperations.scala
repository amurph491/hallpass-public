package run.hallpass.adapters.hubspot

import java.net.http.HttpClient
import java.time.Duration
import cats.effect.IO
import io.circe.{ACursor, Json, JsonObject}
import run.hallpass.application.*
import run.hallpass.kernel.*
import run.hallpass.kernel.authorization.*

/** HubSpot's operations. Fixed contract:
  *
  * | operation                             | tool                              | capability            | action |
  * |---------------------------------------|-----------------------------------|-----------------------|--------|
  * | `hubspot.contacts.get@1`              | `hubspot_contacts_get`            | `HubSpot.Contact.Read`| READ   |
  * | `hubspot.deals.get@1`                 | `hubspot_deals_get`               | `HubSpot.Deal.Read`   | READ   |
  * | `hubspot.deals.update_properties@1`   | `hubspot_deals_update_properties` | `HubSpot.Deal.Update` | WRITE  |
  *
  * Contacts operations target the `contacts` object type and deals operations the `deals` object type:
  * `locate` uses the required portal-qualified `object_type` argument, with the object suffix fixed by each operation;
  * `targetArgument` binds that argument to the selected resource. get: required `record_id` (HubSpotRecordId) and optional
  * `properties` (up to 50 HubSpotPropertyName values to return; default a small fixed set per type). update: required
  * `deal_id` and `properties`, an object of 1–20 HubSpotPropertyName → string (≤ 2,000 chars, no control characters).
  * Its `facts` are `AuthorizationContext.withFacts(Map.empty, Map(HubSpot.PropertiesFact -> <the property names>))`, so
  * a grant can limit which fields an agent may write. Its canonical form is exactly what is sent, so the
  * approver (owner policy REQUIRE_APPROVAL) sees the exact changes.
  * Requests: GET `{api}/crm/v3/objects/{contacts|deals}/{id}?properties=…`; PATCH `{api}/crm/v3/objects/deals/{id}`
  * with `{"properties": {...}}`. The object type in the path comes from the target's external ID.
  */
object HubSpotOperations:
  def all(
      credentials: HubSpotCredentials,
      endpoints: HubSpotEndpoints,
      http: HttpClient,
      requestTimeout: Duration = Duration.ofSeconds(10)
  ): Vector[RegisteredOperation[?, ?, ?]] =
    val rest = HubSpotRestClient(endpoints, http, requestTimeout)
    Vector(
      RegisteredOperation(HubSpotContactsGetOperation, HubSpotGetClient(rest, HubSpot.Contacts), credentials),
      RegisteredOperation(HubSpotDealsGetOperation, HubSpotGetClient(rest, HubSpot.Deals), credentials),
      RegisteredOperation(HubSpotDealsUpdatePropertiesOperation, HubSpotUpdateClient(rest), credentials)
    )

final case class HubSpotGetInput(objectType: HubSpotObjectRef, record: HubSpotRecordId, properties: Vector[HubSpotPropertyName])
final case class HubSpotUpdateInput(objectType: HubSpotObjectRef, deal: HubSpotRecordId, properties: Vector[(HubSpotPropertyName, String)])

private[hubspot] object HubSpotArguments:
  val GetPropertiesMaximum = 50
  val UpdatePropertiesMaximum = 20
  val ValueMaximum = 2000
  val ContactDefaults: Vector[String] = Vector("firstname", "lastname", "email", "company", "lifecyclestage")
  val DealDefaults: Vector[String] = Vector("dealname", "amount", "dealstage", "pipeline", "closedate")

  private def text(value: String): Json = Json.fromString(value)

  def names(values: Vector[String]): Vector[HubSpotPropertyName] = values.flatMap(HubSpotPropertyName.parse)

  val recordSchema: Json = Json.obj("type" -> text("string"), "pattern" -> text("^[1-9][0-9]{0,19}$"), "description" -> text("HubSpot record ID"))
  def objectTypeSchema(expected: String): Json = Json.obj(
    "type" -> text("string"),
    "pattern" -> text(s"^[1-9][0-9]{0,19}:$expected$$"),
    "description" -> text(s"Selected HubSpot portal and $expected object type")
  )
  val nameSchema: Json = Json.obj("type" -> text("string"), "pattern" -> text("^[a-z][a-z0-9_]{0,99}$"))

  def schema(properties: Vector[(String, Json)], required: Vector[String]): Json = Json.obj(
    "type" -> text("object"),
    "properties" -> Json.obj(properties*),
    "required" -> Json.arr(required.map(text)*),
    "additionalProperties" -> Json.False
  )

  def fields(arguments: Json, allowed: Set[String]): Either[ArgumentError, JsonObject] =
    arguments.asObject.toRight(ArgumentError.NotAnObject).flatMap: obj =>
      Either.cond(obj.keys.forall(allowed.contains), obj, ArgumentError.UnexpectedField)

  def record(fields: JsonObject, field: String): Either[ArgumentError, HubSpotRecordId] =
    fields(field) match
      case None        => Left(ArgumentError.MissingField(field))
      case Some(value) => value.asString.flatMap(HubSpotRecordId.parse).toRight(ArgumentError.InvalidField(field))

  /** Absent selects the type's defaults; otherwise 1 to 50 property names (duplicates collapsed, order kept). */
  def getProperties(fields: JsonObject, defaults: Vector[String]): Either[ArgumentError, Vector[HubSpotPropertyName]] =
    fields("properties") match
      case None        => Right(names(defaults))
      case Some(value) =>
        value.asArray
          .filter(items => items.nonEmpty && items.size <= GetPropertiesMaximum)
          .flatMap: items =>
            val parsed = items.flatMap(_.asString.flatMap(HubSpotPropertyName.parse))
            Option.when(parsed.size == items.size)(parsed.distinct)
          .toRight(ArgumentError.InvalidField("properties"))

  private def validValue(value: String): Boolean =
    value.codePointCount(0, value.length) <= ValueMaximum && !value.exists(Character.isISOControl)

  /** 1 to 20 property names mapped to strings; sorted by name so the form is deterministic. */
  def updateProperties(fields: JsonObject): Either[ArgumentError, Vector[(HubSpotPropertyName, String)]] =
    val invalid = ArgumentError.InvalidField("properties")
    fields("properties") match
      case None        => Left(ArgumentError.MissingField("properties"))
      case Some(value) =>
        value.asObject.filter(o => o.size >= 1 && o.size <= UpdatePropertiesMaximum).toRight(invalid).flatMap: obj =>
          val entries = obj.toVector.map((k, v) => (HubSpotPropertyName.parse(k), v.asString.filter(validValue)))
          if entries.forall((k, v) => k.nonEmpty && v.nonEmpty) then
            Right(entries.flatMap((k, v) => k.zip(v)).sortBy(_._1.value))
          else Left(invalid)

  def propertiesJson(properties: Vector[(HubSpotPropertyName, String)]): Json =
    Json.obj(properties.map((k, v) => k.value -> Json.fromString(v))*)

private def staticId(value: String): OperationId =
  OperationId.parse(value).getOrElse(throw IllegalStateException("static operation is invalid"))
private def staticTool(value: String): ExternalToolId =
  ExternalToolId.parse(value).getOrElse(throw IllegalStateException("static tool is invalid"))
private def staticCapability(value: String): CapabilityKey =
  CapabilityKey.parse(value).getOrElse(throw IllegalStateException("static capability is invalid"))

private def locateType(objectType: HubSpotObjectRef): ResourceLocator[HubSpot.ObjectType] =
  ResourceLocator.Selected(ExternalRef[HubSpot.ObjectType](objectType.externalId)(using HubSpot.objectType))

private def getSchema(expected: String): Json =
  HubSpotArguments.schema(
    Vector(
      "object_type" -> HubSpotArguments.objectTypeSchema(expected),
      "record_id" -> HubSpotArguments.recordSchema,
      "properties" -> Json.obj(
        "type" -> Json.fromString("array"),
        "minItems" -> Json.fromInt(1),
        "maxItems" -> Json.fromInt(HubSpotArguments.GetPropertiesMaximum),
        "items" -> HubSpotArguments.nameSchema,
        "description" -> Json.fromString("Property names to return (optional; a default set is used when omitted)")
      )
    ),
    Vector("object_type", "record_id")
  )

private def decodeObjectType(fields: JsonObject, expected: String): Either[ArgumentError, HubSpotObjectRef] =
  fields("object_type") match
    case None => Left(ArgumentError.MissingField("object_type"))
    case Some(value) =>
      value.asString.flatMap(HubSpotObjectRef.parse).filter(_.objectType.value == expected)
        .toRight(ArgumentError.InvalidField("object_type"))

private def decodeGet(arguments: Json, expected: String, defaults: Vector[String]): Either[ArgumentError, HubSpotGetInput] =
  HubSpotArguments.fields(arguments, Set("object_type", "record_id", "properties")).flatMap: f =>
    for
      objectType <- decodeObjectType(f, expected)
      record <- HubSpotArguments.record(f, "record_id")
      properties <- HubSpotArguments.getProperties(f, defaults)
    yield HubSpotGetInput(objectType, record, properties)

private def canonicalGet(input: HubSpotGetInput): Json = Json.obj(
  "record_id" -> Json.fromString(input.record.value),
  "object_type" -> Json.fromString(input.objectType.value),
  "properties" -> Json.arr(input.properties.map(p => Json.fromString(p.value))*)
)

object HubSpotContactsGetOperation extends OperationDescriptor[HubSpotGetInput, HubSpot.ObjectType]:
  val id: OperationId = staticId("hubspot.contacts.get@1")
  val tool: ExternalToolId = staticTool("hubspot_contacts_get")
  val capability: CapabilityKey = staticCapability("HubSpot.Contact.Read")
  val description: String =
    "Get one HubSpot contact by record ID, returning the requested properties (default: firstname, lastname, email, company, lifecyclestage)."
  val action: Action = Action.Read
  val target: ResourceKind[HubSpot.ObjectType] = HubSpot.objectType
  val audience: ExecutorAudience = HubSpotExecutorAudience.local
  val inputSchema: Json = getSchema("contacts")

  override val targetArgument: Option[String] = Some("object_type")
  def decode(arguments: Json): Either[ArgumentError, HubSpotGetInput] = decodeGet(arguments, "contacts", HubSpotArguments.ContactDefaults)
  def locate(input: HubSpotGetInput): ResourceLocator[HubSpot.ObjectType] = locateType(input.objectType)
  def facts(input: HubSpotGetInput): AuthorizationContext = AuthorizationContext.empty
  /** Defaults are filled in, so omitted and explicit defaults bind identically. */
  def canonical(input: HubSpotGetInput): Json = canonicalGet(input)

object HubSpotDealsGetOperation extends OperationDescriptor[HubSpotGetInput, HubSpot.ObjectType]:
  val id: OperationId = staticId("hubspot.deals.get@1")
  val tool: ExternalToolId = staticTool("hubspot_deals_get")
  val capability: CapabilityKey = staticCapability("HubSpot.Deal.Read")
  val description: String =
    "Get one HubSpot deal by record ID, returning the requested properties (default: dealname, amount, dealstage, pipeline, closedate)."
  val action: Action = Action.Read
  val target: ResourceKind[HubSpot.ObjectType] = HubSpot.objectType
  val audience: ExecutorAudience = HubSpotExecutorAudience.local
  val inputSchema: Json = getSchema("deals")

  override val targetArgument: Option[String] = Some("object_type")
  def decode(arguments: Json): Either[ArgumentError, HubSpotGetInput] = decodeGet(arguments, "deals", HubSpotArguments.DealDefaults)
  def locate(input: HubSpotGetInput): ResourceLocator[HubSpot.ObjectType] = locateType(input.objectType)
  def facts(input: HubSpotGetInput): AuthorizationContext = AuthorizationContext.empty
  def canonical(input: HubSpotGetInput): Json = canonicalGet(input)

object HubSpotDealsUpdatePropertiesOperation extends OperationDescriptor[HubSpotUpdateInput, HubSpot.ObjectType]:
  val id: OperationId = staticId("hubspot.deals.update_properties@1")
  val tool: ExternalToolId = staticTool("hubspot_deals_update_properties")
  val capability: CapabilityKey = staticCapability("HubSpot.Deal.Update")
  val description: String =
    "Update 1 to 20 properties of one HubSpot deal (each value a string of at most 2,000 characters). Only the named properties change."
  val action: Action = Action.Write
  val target: ResourceKind[HubSpot.ObjectType] = HubSpot.objectType
  val audience: ExecutorAudience = HubSpotExecutorAudience.local
  val inputSchema: Json = HubSpotArguments.schema(
    Vector(
      "deal_id" -> HubSpotArguments.recordSchema,
      "object_type" -> HubSpotArguments.objectTypeSchema("deals"),
      "properties" -> Json.obj(
        "type" -> Json.fromString("object"),
        "minProperties" -> Json.fromInt(1),
        "maxProperties" -> Json.fromInt(HubSpotArguments.UpdatePropertiesMaximum),
        "propertyNames" -> HubSpotArguments.nameSchema,
        "additionalProperties" -> Json.obj(
          "type" -> Json.fromString("string"),
          "maxLength" -> Json.fromInt(HubSpotArguments.ValueMaximum)
        ),
        "description" -> Json.fromString("Property name to new value")
      )
    ),
    Vector("object_type", "deal_id", "properties")
  )
  override val targetArgument: Option[String] = Some("object_type")

  def decode(arguments: Json): Either[ArgumentError, HubSpotUpdateInput] =
    HubSpotArguments.fields(arguments, Set("object_type", "deal_id", "properties")).flatMap: f =>
      for
        objectType <- decodeObjectType(f, "deals")
        deal <- HubSpotArguments.record(f, "deal_id")
        properties <- HubSpotArguments.updateProperties(f)
      yield HubSpotUpdateInput(objectType, deal, properties)
  def locate(input: HubSpotUpdateInput): ResourceLocator[HubSpot.ObjectType] = locateType(input.objectType)
  /** Exactly the set of property names the update writes. */
  def facts(input: HubSpotUpdateInput): AuthorizationContext =
    AuthorizationContext.withFacts(
      Map.empty,
      Map(HubSpot.PropertiesFact -> input.properties.flatMap((name, _) => ContextValue.parse(name.value)).toSet)
    )
  /** Exactly what is sent: the deal and the PATCH body's properties. */
  def canonical(input: HubSpotUpdateInput): Json = Json.obj(
    "object_type" -> Json.fromString(input.objectType.value),
    "deal_id" -> Json.fromString(input.deal.value),
    "properties" -> HubSpotArguments.propertiesJson(input.properties)
  )

private def failWith(error: ProviderError): IO[ToolResult] = IO.raiseError(ProviderExecutionException(error))

/** The response must describe the requested record; unexpected read IDs remain a rejection. */
private[hubspot] final class HubSpotGetClient(rest: HubSpotRestClient, objectType: ExternalId)
    extends ProviderOperationClient[HubSpotGetInput, HubSpot.ObjectType, HubSpotAccess]:
  def dispatch(target: SelectedResource[HubSpot.ObjectType], input: HubSpotGetInput, access: HubSpotAccess): IO[ToolResult] =
    rest.get(target, objectType, access, input.record, input.properties).flatMap: json =>
      if !json.hcursor.get[String]("id").toOption.contains(input.record.value) then failWith(ProviderError.Rejected)
      else
        HubSpotRender.record(json) match
          case Right(text) => IO.pure(ToolResult(text))
          case Left(error) => failWith(error)

/** One PATCH, expecting 200, never retried. The body is exactly the decoded properties. */
private[hubspot] final class HubSpotUpdateClient(rest: HubSpotRestClient)
    extends ProviderOperationClient[HubSpotUpdateInput, HubSpot.ObjectType, HubSpotAccess]:
  def dispatch(target: SelectedResource[HubSpot.ObjectType], input: HubSpotUpdateInput, access: HubSpotAccess): IO[ToolResult] =
    val body = Json.obj("properties" -> HubSpotArguments.propertiesJson(input.properties))
    rest.patch(target, HubSpot.Deals, access, input.deal, body).flatMap: json =>
      if !json.hcursor.get[String]("id").toOption.contains(input.deal.value) then failWith(ProviderError.InvalidResponse)
      else IO.pure(ToolResult(s"Updated deal ${input.deal.value}: ${input.properties.map(_._1.value).mkString(", ")}"))

/** Plain-text rendering, capped at 60,000 characters. Provider content is data and never interpreted. */
private[hubspot] object HubSpotRender:
  val ContentLimit = 60000
  private val ValueLimit = 2000
  private val PropertyLimit = 200
  private val Dash = "—"

  private def flat(value: String): String = value.replaceAll("\\s+", " ").trim
  private def cap(value: String, limit: Int): String =
    if value.length <= limit then value else value.take(limit) + "...[truncated]"
  private def str(cursor: ACursor, field: String): Option[String] = cursor.get[Option[String]](field).toOption.flatten

  private def value(json: Json): Option[String] =
    if json.isNull then Some(Dash)
    else if json.isString || json.isNumber || json.isBoolean then Some(cap(flat(json.asString.getOrElse(json.noSpaces)), ValueLimit))
    else None

  def record(json: Json): Either[ProviderError, String] =
    val cursor = json.hcursor
    cursor.downField("properties").focus.flatMap(_.asObject).toRight(ProviderError.InvalidResponse).flatMap: properties =>
      val rendered = properties.toVector.take(PropertyLimit).map((name, v) => value(v).map(text => cap(flat(name), 100) + ": " + text))
      if rendered.exists(_.isEmpty) then Left(ProviderError.InvalidResponse)
      else
        val tail = Vector(
          "id: " + str(cursor, "id").getOrElse(""),
          "createdAt: " + str(cursor, "createdAt").getOrElse(Dash),
          "updatedAt: " + str(cursor, "updatedAt").getOrElse(Dash),
          "archived: " + cursor.get[Option[Boolean]]("archived").toOption.flatten.getOrElse(false)
        )
        val text = (rendered.flatten ++ tail).mkString("\n")
        Right(if text.length <= ContentLimit then text else text.take(ContentLimit) + "\n...[truncated]")
