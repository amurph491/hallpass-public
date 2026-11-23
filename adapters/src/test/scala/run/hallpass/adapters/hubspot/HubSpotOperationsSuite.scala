package run.hallpass.application:
  import run.hallpass.adapters.hubspot.{HubSpot, HubSpotObjectRef}
  import run.hallpass.kernel.*
  import run.hallpass.kernel.authorization.*

  /** Test-only access to `SelectedResource.trusted`, which is `private[application]`. */
  object HubSpotTestSupport:
    private val tenant = TenantId.random()

    def objectTarget(externalId: String, parentPortal: Option[String] = None): SelectedResource[HubSpot.ObjectType] =
      val portalId = parentPortal.getOrElse(externalId.takeWhile(_ != ':'))
      val parent = Resource(ResourceId.random(), tenant, ResourceType.Account, None, portalId, None)
      val resource = Resource(ResourceId.random(), tenant, ResourceType.Custom, Some(parent.id), externalId, None)
      SelectedResource.trusted(
        HubSpot.objectType,
        HubSpotObjectRef.parse(externalId).getOrElse(throw IllegalStateException("external id")).externalId,
        ResourceScope.fromPath(Vector(resource, parent)).getOrElse(throw IllegalStateException("scope"))
      )

package run.hallpass.adapters.hubspot:
  import java.net.{InetSocketAddress, URI}
  import java.net.http.HttpClient
  import java.nio.charset.StandardCharsets
  import java.time.Duration
  import java.util.concurrent.atomic.AtomicReference
  import scala.jdk.CollectionConverters.*
  import com.sun.net.httpserver.HttpServer
  import cats.effect.{IO, Resource as CatsResource}
  import io.circe.Json
  import io.circe.parser.parse
  import munit.CatsEffectSuite
  import run.hallpass.application.*
  import run.hallpass.kernel.{AuthorizationContext, ContextValue}

  final class HubSpotOperationsSuite extends CatsEffectSuite:
    private val tokenText = "pat-na1-hubspottokenvalue"
    private val access = HubSpotAccess(tokenText)
    private val contactsTarget = HubSpotTestSupport.objectTarget("44332211:contacts")
    private val dealsTarget = HubSpotTestSupport.objectTarget("44332211:deals")
    private val record = HubSpotRecordId.parse("12345").getOrElse(fail("id"))

    private def str(value: String): Json = Json.fromString(value)
    private def args(fields: (String, Json)*): Json = Json.obj(fields*)
    private def invalid(field: String) = Left(ArgumentError.InvalidField(field))
    private def name(value: String) = HubSpotPropertyName.parse(value).getOrElse(fail("name"))

    private def withObjectType(fields: Seq[(String, Json)], default: String) =
      if fields.exists(_._1 == "object_type") then fields else ("object_type" -> str(default)) +: fields
    private def contactArgs(fields: (String, Json)*) = HubSpotContactsGetOperation.decode(args(withObjectType(fields, "44332211:contacts")*))
    private def dealArgs(fields: (String, Json)*) = HubSpotDealsGetOperation.decode(args(withObjectType(fields, "44332211:deals")*))
    private def updateArgs(fields: (String, Json)*) = HubSpotDealsUpdatePropertiesOperation.decode(args(withObjectType(fields, "44332211:deals")*))
    private def props(entries: (String, String)*): Json = Json.obj(entries.map((k, v) => k -> str(v))*)

    private final case class Captured(method: String, path: String, headers: Map[String, String], body: String)
    private final class Fake(val captured: AtomicReference[Vector[Captured]], val uri: URI)

    private def withServer(
        statusCode: Int = 200,
        response: String = "{}",
        delayMillis: Long = 0,
        bodyDelayMillis: Long = 0,
        location: Option[String] = None,
        closeWithoutResponse: Boolean = false
    ): CatsResource[IO, Fake] =
      CatsResource
        .make(IO.blocking:
          val captured = new AtomicReference(Vector.empty[Captured])
          val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
          server.createContext(
            "/",
            exchange =>
              val headers = exchange.getRequestHeaders.asScala.map((n, v) => n.toLowerCase -> v.asScala.mkString(",")).toMap
              val body = String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)
              captured.updateAndGet(_ :+ Captured(exchange.getRequestMethod, exchange.getRequestURI.toString, headers, body))
              if delayMillis > 0 then Thread.sleep(delayMillis)
              if closeWithoutResponse then
                exchange.close()
              else
                location.foreach(exchange.getResponseHeaders.add("Location", _))
                val bytes = response.getBytes(StandardCharsets.UTF_8)
                try
                  exchange.sendResponseHeaders(statusCode, bytes.length.toLong)
                  val output = exchange.getResponseBody
                  try
                    if bodyDelayMillis > 0 then Thread.sleep(bodyDelayMillis)
                    output.write(bytes)
                  finally output.close()
                catch case _: java.io.IOException => ()
          )
          server.start()
          (captured, server))((_, server) => IO.blocking(server.stop(0)))
        .map((captured, server) => new Fake(captured, URI.create(s"http://127.0.0.1:${server.getAddress.getPort}")))

    private def rest(uri: URI, timeout: Duration = Duration.ofSeconds(2)) =
      HubSpotRestClient(HubSpotEndpoints(uri, uri), HttpClient.newHttpClient(), timeout)

    private def providerError[A](io: IO[A]): IO[ProviderError] =
      io.attempt.map:
        case Left(error: ProviderExecutionException) =>
          assert(!String.valueOf(error.getMessage).contains(tokenText))
          error.error
        case other => fail(s"expected a provider error, received $other")

    private def recordJson(id: String = "12345", properties: String = """{"dealname":"Big","amount":null}""") =
      s"""{"id":"$id","properties":$properties,"createdAt":"2026-01-01T00:00:00Z","updatedAt":"2026-02-01T00:00:00Z","archived":false}"""

    private val dealRef = HubSpotObjectRef.parse("44332211:deals").get
    private val getInput = HubSpotGetInput(dealRef, record, Vector(name("dealname"), name("amount")))
    private val updateInput = HubSpotUpdateInput(dealRef, record, Vector(name("amount") -> "100", name("dealstage") -> "won"))

    private def getStatus(status: Int, response: String = "{}", location: Option[String] = None) =
      withServer(status, response, location = location).use: server =>
        providerError(HubSpotGetClient(rest(server.uri), HubSpot.Deals).dispatch(dealsTarget, getInput, access))

    private def patchStatus(status: Int, response: String = recordJson()) =
      withServer(status, response).use: server =>
        providerError(HubSpotUpdateClient(rest(server.uri)).dispatch(dealsTarget, updateInput, access))

    // ---- descriptors ----------------------------------------------------------------------------------------------
    test("descriptors carry the contract ids, tools, capabilities, actions, and audience") {
      val table = Vector(
        (HubSpotContactsGetOperation, "hubspot.contacts.get@1", "hubspot_contacts_get", "HubSpot.Contact.Read", run.hallpass.kernel.Action.Read),
        (HubSpotDealsGetOperation, "hubspot.deals.get@1", "hubspot_deals_get", "HubSpot.Deal.Read", run.hallpass.kernel.Action.Read),
        (HubSpotDealsUpdatePropertiesOperation, "hubspot.deals.update_properties@1", "hubspot_deals_update_properties", "HubSpot.Deal.Update", run.hallpass.kernel.Action.Write)
      )
      table.foreach: (d, id, tool, capability, action) =>
        assertEquals(d.id.value, id)
        assertEquals(d.tool.value, tool)
        assertEquals(d.capability.value, capability)
        assertEquals(d.action, action)
        assertEquals(d.target.wire, "hubspot.object_type")
        assertEquals(d.audience, HubSpotExecutorAudience.local)
        assertEquals(d.targetArgument, Some("object_type"))
        assertEquals(d.inputSchema.hcursor.get[Boolean]("additionalProperties"), Right(false))
    }

    test("locators select the portal-qualified object type from the decoded input") {
      def selected(locator: ResourceLocator[HubSpot.ObjectType]) = locator match
        case ResourceLocator.Selected(ref) => ref.id.value
        case other                         => fail(s"unexpected locator $other")
      assertEquals(selected(HubSpotContactsGetOperation.locate(contactArgs("record_id" -> str("1")).getOrElse(fail("decode")))), "44332211:contacts")
      assertEquals(selected(HubSpotDealsGetOperation.locate(getInput)), "44332211:deals")
      assertEquals(selected(HubSpotDealsUpdatePropertiesOperation.locate(updateInput)), "44332211:deals")
    }

    // ---- decoding -------------------------------------------------------------------------------------------------
    test("record ids: positive decimal strings up to 20 digits, nothing else") {
      assertEquals(contactArgs("record_id" -> str("1")).map(_.record.value), Right("1"))
      assertEquals(dealArgs("record_id" -> str("9" * 20)).map(_.record.value), Right("9" * 20))
      Vector(
        str(""), str("0"), str("01"), str("9" * 21), str("-1"), str("1.5"), str("1/2"), str("../1"), str(" 1"), str("a1"),
        Json.fromInt(1), Json.Null, Json.True
      ).foreach: value =>
        assertEquals(contactArgs("record_id" -> value), invalid("record_id"))
        assertEquals(dealArgs("record_id" -> value), invalid("record_id"))
        assertEquals(updateArgs("deal_id" -> value, "properties" -> props("a" -> "b")), invalid("deal_id"))
      assertEquals(contactArgs(), Left(ArgumentError.MissingField("record_id")))
      assertEquals(updateArgs("properties" -> props("a" -> "b")), Left(ArgumentError.MissingField("deal_id")))
    }

    test("get defaults the properties per object type") {
      assertEquals(
        contactArgs("record_id" -> str("1")).map(_.properties.map(_.value)),
        Right(Vector("firstname", "lastname", "email", "company", "lifecyclestage"))
      )
      assertEquals(
        dealArgs("record_id" -> str("1")).map(_.properties.map(_.value)),
        Right(Vector("dealname", "amount", "dealstage", "pipeline", "closedate"))
      )
    }

    test("get properties: 1 to 50 valid names, duplicates collapsed") {
      def p(values: Json*) = dealArgs("record_id" -> str("1"), "properties" -> Json.arr(values*))
      assertEquals(p(str("amount")).map(_.properties.map(_.value)), Right(Vector("amount")))
      assertEquals(p(str("amount"), str("dealname"), str("amount")).map(_.properties.map(_.value)), Right(Vector("amount", "dealname")))
      assert(p((1 to 50).map(i => str(s"p$i"))*).isRight)
      assertEquals(p((1 to 51).map(i => str(s"p$i"))*), invalid("properties"))
      assertEquals(p(), invalid("properties"))
      Vector(str("Amount"), str("1abc"), str(""), str("a-b"), str("a" * 101), str("a b"), str("a,b"), Json.Null, Json.fromInt(1))
        .foreach(v => assertEquals(p(str("ok"), v), invalid("properties")))
      assert(p(str("a" * 100)).isRight)
      assertEquals(dealArgs("record_id" -> str("1"), "properties" -> str("amount")), invalid("properties"))
      assertEquals(dealArgs("record_id" -> str("1"), "properties" -> Json.Null), invalid("properties"))
    }

    test("update properties: 1 to 20 names, string values up to 2,000 characters without control characters") {
      def u(entries: (String, String)*) = updateArgs("deal_id" -> str("1"), "properties" -> props(entries*))
      assert(u("amount" -> "5").isRight)
      assert(u("amount" -> "").isRight)
      assert(u((1 to 20).map(i => s"p$i" -> "v")*).isRight)
      assertEquals(u((1 to 21).map(i => s"p$i" -> "v")*), invalid("properties"))
      assertEquals(updateArgs("deal_id" -> str("1"), "properties" -> Json.obj()), invalid("properties"))
      assert(u("amount" -> ("x" * 2000)).isRight)
      assertEquals(u("amount" -> ("x" * 2001)), invalid("properties"))
      Vector("a\nb", "a\tb", "a\u0000b", "a\u009fb", "a\rb").foreach(v => assertEquals(u("amount" -> v), invalid("properties")))
      Vector("Amount", "1a", "", "a-b", "a" * 101, "a.b").foreach(k => assertEquals(u(k -> "v"), invalid("properties")))
      assertEquals(updateArgs("deal_id" -> str("1"), "properties" -> Json.obj("amount" -> Json.fromInt(5))), invalid("properties"))
      assertEquals(updateArgs("deal_id" -> str("1"), "properties" -> Json.obj("amount" -> Json.Null)), invalid("properties"))
      assertEquals(updateArgs("deal_id" -> str("1"), "properties" -> Json.arr(str("amount"))), invalid("properties"))
      assertEquals(updateArgs("deal_id" -> str("1")), Left(ArgumentError.MissingField("properties")))
    }

    test("decode rejects unknown fields and non-objects on every operation") {
      assertEquals(contactArgs("record_id" -> str("1"), "extra" -> str("x")), Left(ArgumentError.UnexpectedField))
      assertEquals(dealArgs("record_id" -> str("1"), "object_type" -> str("44332211:contacts")), invalid("object_type"))
      assertEquals(
        updateArgs("deal_id" -> str("1"), "properties" -> props("a" -> "b"), "object_type" -> str("44332211:contacts")),
        invalid("object_type")
      )
      assertEquals(HubSpotContactsGetOperation.decode(Json.arr()), Left(ArgumentError.NotAnObject))
      assertEquals(HubSpotDealsGetOperation.decode(str("x")), Left(ArgumentError.NotAnObject))
      assertEquals(HubSpotDealsUpdatePropertiesOperation.decode(Json.Null), Left(ArgumentError.NotAnObject))
    }

    test("object_type requires a numeric portal and the operation's fixed object type") {
      val base = Vector("record_id" -> str("1"))
      assertEquals(HubSpotContactsGetOperation.decode(args(base*)), Left(ArgumentError.MissingField("object_type")))
      Vector("contacts", "0:contacts", "01:contacts", "x:contacts", "44332211:deals", "44332211:tickets", "44332211:contacts:extra")
        .foreach(ref => assertEquals(HubSpotContactsGetOperation.decode(args(("object_type" -> str(ref)) +: base*)), invalid("object_type")))
    }

    // ---- facts and canonical --------------------------------------------------------------------------------------
    test("update facts are exactly the set of property names written") {
      val input = updateArgs("deal_id" -> str("1"), "properties" -> props("dealstage" -> "won", "amount" -> "1")).getOrElse(fail("decode"))
      val expected = AuthorizationContext.withFacts(
        Map.empty,
        Map(HubSpot.PropertiesFact -> Set("amount", "dealstage").map(n => ContextValue.parse(n).getOrElse(fail("value"))))
      )
      assertEquals(HubSpotDealsUpdatePropertiesOperation.facts(input), expected)
      val one = updateArgs("deal_id" -> str("1"), "properties" -> props("amount" -> "1")).getOrElse(fail("decode"))
      assertNotEquals(HubSpotDealsUpdatePropertiesOperation.facts(one), expected)
      assertEquals(HubSpotDealsGetOperation.facts(getInput), AuthorizationContext.empty)
      assertEquals(HubSpotContactsGetOperation.facts(getInput), AuthorizationContext.empty)
    }

    test("update canonical form ignores key order and differs for different content") {
      def canon(id: String, entries: (String, String)*) =
        HubSpotDealsUpdatePropertiesOperation.canonical(updateArgs("deal_id" -> str(id), "properties" -> props(entries*)).getOrElse(fail("decode")))
      assertEquals(canon("1", "a" -> "1", "b" -> "2"), canon("1", "b" -> "2", "a" -> "1"))
      assertNotEquals(canon("1", "a" -> "1", "b" -> "2"), canon("1", "a" -> "1", "b" -> "3"))
      assertNotEquals(canon("1", "a" -> "1"), canon("1", "a" -> "1", "b" -> "2"))
      assertNotEquals(canon("1", "a" -> "1"), canon("2", "a" -> "1"))
      assertNotEquals(canon("1", "a" -> "1"), canon("1", "b" -> "1"))
      assertNotEquals(
        HubSpotDealsUpdatePropertiesOperation.canonical(updateInput),
        HubSpotDealsUpdatePropertiesOperation.canonical(updateInput.copy(objectType = HubSpotObjectRef.parse("99887766:deals").get))
      )
    }

    test("update decoder requires object_type") {
      assertEquals(
        HubSpotDealsUpdatePropertiesOperation.decode(args("deal_id" -> str("1"), "properties" -> props("amount" -> "1"))),
        Left(ArgumentError.MissingField("object_type"))
      )
    }

    test("get canonical form fills defaults and differs for different content") {
      val omitted = contactArgs("record_id" -> str("1")).getOrElse(fail("decode"))
      val explicit = contactArgs(
        "record_id" -> str("1"),
        "properties" -> Json.arr(Vector("firstname", "lastname", "email", "company", "lifecyclestage").map(str)*)
      ).getOrElse(fail("decode"))
      assertEquals(HubSpotContactsGetOperation.canonical(omitted), HubSpotContactsGetOperation.canonical(explicit))
      assertNotEquals(HubSpotContactsGetOperation.canonical(omitted), HubSpotContactsGetOperation.canonical(omitted.copy(properties = Vector(name("email")))))
      assertNotEquals(HubSpotContactsGetOperation.canonical(omitted), HubSpotContactsGetOperation.canonical(omitted.copy(record = HubSpotRecordId.parse("2").get)))
      assertNotEquals(HubSpotContactsGetOperation.canonical(omitted), HubSpotContactsGetOperation.canonical(omitted.copy(objectType = HubSpotObjectRef.parse("99887766:contacts").get)))
    }

    test("update canonical form is exactly the deal and the PATCH body") {
      withServer(response = recordJson()).use: server =>
        HubSpotUpdateClient(rest(server.uri)).dispatch(dealsTarget, updateInput, access).map: _ =>
          val canonical = HubSpotDealsUpdatePropertiesOperation.canonical(updateInput)
          val sent = parse(server.captured.get.head.body).getOrElse(fail("body"))
          assertEquals(sent, Json.obj("properties" -> canonical.hcursor.downField("properties").focus.getOrElse(fail("properties"))))
          assertEquals(canonical.hcursor.get[String]("deal_id"), Right("12345"))
    }

    // ---- registry -------------------------------------------------------------------------------------------------
    private object StubOAuth extends CredentialStrategy[HubSpot.ObjectType, OAuthTokens]:
      def credentialFor(lease: RedeemedExecutionLease, target: SelectedResource[HubSpot.ObjectType]) =
        IO.pure(Left(ConnectionError.InvalidState))

    test("all() registers three operations with unique ids and tools") {
      val operations = HubSpotOperations.all(HubSpotCredentials(StubOAuth), HubSpotEndpoints.Production, HttpClient.newHttpClient())
      assertEquals(
        operations.map(_.descriptor.id.value),
        Vector("hubspot.contacts.get@1", "hubspot.deals.get@1", "hubspot.deals.update_properties@1")
      )
      assertEquals(operations.map(_.descriptor.tool.value).toSet.size, 3)
      val registry = OperationRegistry.from(operations).getOrElse(fail("registry"))
      assertEquals(registry.all.size, 3)
    }

    // ---- get ------------------------------------------------------------------------------------------------------
    test("deals get sends GET to the path built from the target with the contract headers and renders the record") {
      withServer(response = recordJson()).use: server =>
        HubSpotGetClient(rest(server.uri), HubSpot.Deals).dispatch(dealsTarget, getInput, access).map: result =>
          assertEquals(server.captured.get.size, 1)
          val request = server.captured.get.head
          assertEquals(request.method, "GET")
          assertEquals(request.path, "/crm/v3/objects/deals/12345?properties=dealname,amount")
          assertEquals(request.headers.get("authorization"), Some("Bearer " + tokenText))
          assertEquals(request.headers.get("accept-encoding"), Some("identity"))
          assertEquals(request.headers.get("user-agent"), Some("hallpass"))
          assertEquals(
            result.content,
            "dealname: Big\namount: —\nid: 12345\ncreatedAt: 2026-01-01T00:00:00Z\nupdatedAt: 2026-02-01T00:00:00Z\narchived: false"
          )
          assert(!result.content.contains(tokenText))
    }

    test("contacts get uses the contacts path from its target") {
      val input = HubSpotGetInput(HubSpotObjectRef.parse("44332211:contacts").get, record, Vector(name("email")))
      withServer(response = recordJson(properties = """{"email":"a@example.com"}""")).use: server =>
        HubSpotGetClient(rest(server.uri), HubSpot.Contacts).dispatch(contactsTarget, input, access).map: result =>
          assertEquals(server.captured.get.head.path, "/crm/v3/objects/contacts/12345?properties=email")
          assert(result.content.startsWith("email: a@example.com"))
    }

    test("a contacts operation given a deals target (and the reverse) is refused before any request") {
      withServer(response = recordJson()).use: server =>
        for
          a <- providerError(HubSpotGetClient(rest(server.uri), HubSpot.Contacts).dispatch(dealsTarget, getInput, access))
          b <- providerError(HubSpotGetClient(rest(server.uri), HubSpot.Deals).dispatch(contactsTarget, getInput, access))
          other = HubSpotTestSupport.objectTarget("44332211:contacts")
          c <- providerError(HubSpotGetClient(rest(server.uri), HubSpot.Deals).dispatch(other, getInput, access))
          d <- providerError(HubSpotUpdateClient(rest(server.uri)).dispatch(contactsTarget, updateInput, access))
        yield
          assertEquals(Vector(a, b, c, d), Vector.fill(4)(ProviderError.Rejected))
          assert(server.captured.get.isEmpty)
    }

    test("a portal prefix that disagrees with the selected resource scope is refused before a request") {
      val mismatched = HubSpotTestSupport.objectTarget("44332211:deals", Some("99887766"))
      withServer(response = recordJson()).use: server =>
        providerError(HubSpotGetClient(rest(server.uri), HubSpot.Deals).dispatch(mismatched, getInput, access)).map: error =>
          assertEquals(error, ProviderError.Rejected)
          assert(server.captured.get.isEmpty)
    }

    test("a returned id that differs from the requested record is rejected") {
      withServer(response = recordJson(id = "99999")).use: server =>
        providerError(HubSpotGetClient(rest(server.uri), HubSpot.Deals).dispatch(dealsTarget, getInput, access)).map: error =>
          assertEquals(error, ProviderError.Rejected)
    }

    test("a response without a string id or a properties object is not accepted") {
      for
        a <- getStatus(200, """{"properties":{}}""")
        b <- getStatus(200, """{"id":12345,"properties":{}}""")
        c <- getStatus(200, """{"id":"12345"}""")
        d <- getStatus(200, """{"id":"12345","properties":{"a":{"nested":1}}}""")
      yield
        assertEquals(Vector(a, b, c, d), Vector(ProviderError.Rejected, ProviderError.Rejected, ProviderError.InvalidResponse, ProviderError.InvalidResponse))
    }

    test("rendering caps the result at 60,000 characters") {
      val big = "x" * 1900
      val properties = Json.obj((1 to 150).map(i => s"p$i" -> str(big))*).noSpaces
      withServer(response = recordJson(properties = properties)).use: server =>
        HubSpotGetClient(rest(server.uri), HubSpot.Deals).dispatch(dealsTarget, getInput, access).map: result =>
          assert(result.content.length <= HubSpotRender.ContentLimit + 20)
          assert(result.content.endsWith("...[truncated]"))
    }

    test("get error mapping") {
      for
        s401 <- getStatus(401)
        s403 <- getStatus(403)
        s404 <- getStatus(404)
        s400 <- getStatus(400)
        s409 <- getStatus(409)
        s429 <- getStatus(429)
        s500 <- getStatus(500)
        s302 <- getStatus(302, location = Some("http://127.0.0.1:1/elsewhere"))
        bad <- getStatus(200, "not json")
      yield
        assertEquals(Vector(s401, s403), Vector.fill(2)(ProviderError.AuthenticationFailed))
        assertEquals(Vector(s404, s400, s409, s429, s500, s302), Vector.fill(6)(ProviderError.Rejected))
        assertEquals(bad, ProviderError.InvalidResponse)
    }

    test("a redirect is never followed") {
      withServer(302, location = Some("/crm/v3/objects/deals/other")).use: server =>
        providerError(HubSpotGetClient(rest(server.uri), HubSpot.Deals).dispatch(dealsTarget, getInput, access)).map: error =>
          assertEquals(error, ProviderError.Rejected)
          assertEquals(server.captured.get.size, 1)
    }

    test("an oversized response is an invalid response") {
      val huge = "x" * (HubSpotRestClient.MaximumBodyBytes + 10)
      getStatus(200, s"""{"id":"12345","properties":{"a":"$huge"}}""").map(error => assertEquals(error, ProviderError.InvalidResponse))
    }

    test("a get timeout is Timeout") {
      withServer(response = recordJson(), delayMillis = 1500).use: server =>
        providerError(HubSpotGetClient(rest(server.uri, Duration.ofMillis(300)), HubSpot.Deals).dispatch(dealsTarget, getInput, access)).map: error =>
          assertEquals(error, ProviderError.Timeout)
    }

    // ---- update ---------------------------------------------------------------------------------------------------
    test("update sends one PATCH to the deals path with the exact body and headers") {
      withServer(response = recordJson()).use: server =>
        HubSpotUpdateClient(rest(server.uri)).dispatch(dealsTarget, updateInput, access).map: result =>
          assertEquals(server.captured.get.size, 1)
          val request = server.captured.get.head
          assertEquals(request.method, "PATCH")
          assertEquals(request.path, "/crm/v3/objects/deals/12345")
          assertEquals(request.headers.get("authorization"), Some("Bearer " + tokenText))
          assertEquals(request.headers.get("content-type"), Some("application/json"))
          assertEquals(request.headers.get("accept-encoding"), Some("identity"))
          assertEquals(request.headers.get("user-agent"), Some("hallpass"))
          assertEquals(request.body, """{"properties":{"amount":"100","dealstage":"won"}}""")
          assertEquals(result.content, "Updated deal 12345: amount, dealstage")
          assert(!result.content.contains(tokenText))
    }

    test("update with a mismatched returned id is an invalid response") {
      patchStatus(200, recordJson(id = "999")).map(error => assertEquals(error, ProviderError.InvalidResponse))
    }

    test("update error mapping: only 200 succeeds") {
      for
        s401 <- patchStatus(401)
        s403 <- patchStatus(403)
        s404 <- patchStatus(404)
        s400 <- patchStatus(400)
        s409 <- patchStatus(409)
        s429 <- patchStatus(429)
        s500 <- patchStatus(500)
        s302 <- patchStatus(302)
        s201 <- patchStatus(201)
        bad <- patchStatus(200, "not json")
      yield
        assertEquals(Vector(s401, s403), Vector.fill(2)(ProviderError.AuthenticationFailed))
        assertEquals(Vector(s404, s400, s409, s429, s302), Vector.fill(5)(ProviderError.Rejected))
        assertEquals(s500, ProviderError.OutcomeUnknown)
        assertEquals(Vector(s201, bad), Vector.fill(2)(ProviderError.InvalidResponse))
    }

    test("an update that times out has unknown outcome and was sent exactly once") {
      withServer(response = recordJson(), delayMillis = 1500).use: server =>
        providerError(HubSpotUpdateClient(rest(server.uri, Duration.ofMillis(300))).dispatch(dealsTarget, updateInput, access)).flatMap: error =>
          assertEquals(error, ProviderError.OutcomeUnknown)
          IO.sleep(scala.concurrent.duration.DurationInt(1).second).map(_ => assertEquals(server.captured.get.size, 1))
    }

    test("a PATCH response lost after the request body is received has unknown outcome and is not retried") {
      withServer(closeWithoutResponse = true).use: server =>
        providerError(HubSpotUpdateClient(rest(server.uri)).dispatch(dealsTarget, updateInput, access)).map: error =>
          assertEquals(error, ProviderError.OutcomeUnknown)
          val requests = server.captured.get
          assertEquals(requests.size, 1)
          assertEquals(requests.head.method, "PATCH")
          assertEquals(requests.head.body, """{"properties":{"amount":"100","dealstage":"won"}}""")
    }

    test("an update whose response body stalls has unknown outcome and is not retried") {
      withServer(response = recordJson(), bodyDelayMillis = 1500).use: server =>
        providerError(HubSpotUpdateClient(rest(server.uri, Duration.ofMillis(300))).dispatch(dealsTarget, updateInput, access)).flatMap: error =>
          assertEquals(error, ProviderError.OutcomeUnknown)
          IO.sleep(scala.concurrent.duration.DurationInt(1).second).map(_ => assertEquals(server.captured.get.size, 1))
    }

    test("the token never appears in access rendering or in errors") {
      assert(!access.toString.contains(tokenText))
      getStatus(401).map(error => assertEquals(error, ProviderError.AuthenticationFailed))
    }
