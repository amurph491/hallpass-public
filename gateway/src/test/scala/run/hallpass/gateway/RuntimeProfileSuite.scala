package run.hallpass.gateway

import munit.FunSuite

final class RuntimeProfileSuite extends FunSuite:
  /** Every environment-controlled development component switched to its production alternative. */
  private val productionShaped = Map(
    "HALLPASS_ENV" -> "production",
    "HALLPASS_TENANT_GATE" -> "postgres",
    "HALLPASS_AGENT_HTTP_BIND_HOST" -> "0.0.0.0",
    "HALLPASS_DB_MIGRATIONS" -> "external",
    "HALLPASS_SECRET_STORE" -> "vault-transit",
    "OTEL_EXPORTER_OTLP_ENDPOINT" -> "https://otel-collector.example.test:4318",
    "HALLPASS_TRUSTED_PROXY_COUNT" -> "1",
    "HALLPASS_AGENT_PUBLIC_URL" -> "https://agents.example.test"
  )

  test("the profile is required and closed") {
    assert(RuntimeProfile.fromEnvironment(Map.empty).isLeft)
    assert(RuntimeProfile.fromEnvironment(Map("HALLPASS_ENV" -> "staging")).isLeft)
    assertEquals(RuntimeProfile.fromEnvironment(Map("HALLPASS_ENV" -> "development")), Right(RuntimeProfile.Development))
    assertEquals(RuntimeProfile.fromEnvironment(Map("HALLPASS_ENV" -> " Production ")), Right(RuntimeProfile.Production))
  }

  test("development accepts development-only components") {
    assertEquals(ProductionGuard.check(RuntimeProfile.Development, Map("HALLPASS_ENV" -> "development")), Right(()))
  }

  test("production requires the KMS-backed secret store") {
    val withoutKms = productionShaped - "HALLPASS_SECRET_STORE"
    assertEquals(ProductionGuard.componentsInUse(withoutKms), Vector.empty)
    val refusal = ProductionGuard.check(RuntimeProfile.Production, withoutKms)
    assert(refusal.left.exists(_.contains(MissingProductionRequirement.KmsSecretStore.description)), refusal.toString)
    assert(!refusal.left.exists(_.contains("development-only components")), refusal.toString)
    assert(!ProductionGuard.missingRequirements(productionShaped).contains(MissingProductionRequirement.KmsSecretStore))
  }

  test("nothing structural remains, and a fully configured production environment passes the guard") {
    assertEquals(MissingProductionRequirement.structural, Vector.empty)
    assertEquals(ProductionGuard.componentsInUse(productionShaped), Vector.empty)
    assertEquals(ProductionGuard.missingRequirements(productionShaped), Vector.empty)
    assertEquals(ProductionGuard.check(RuntimeProfile.Production, productionShaped), Right(()))
  }

  test("production must state how many trusted proxies front the agent listener") {
    val refusal = ProductionGuard.check(RuntimeProfile.Production, productionShaped - "HALLPASS_TRUSTED_PROXY_COUNT")
    assert(refusal.left.exists(_.contains(MissingProductionRequirement.TrustedProxyCount.description)), refusal.toString)
    assertEquals(ClientAddress.fromEnvironment(Map("HALLPASS_TRUSTED_PROXY_COUNT" -> "0")), Right(0))
    assert(ClientAddress.fromEnvironment(Map("HALLPASS_TRUSTED_PROXY_COUNT" -> "9")).isLeft)
    assert(ClientAddress.fromEnvironment(Map("HALLPASS_TRUSTED_PROXY_COUNT" -> "one")).isLeft)
  }

  test("production must state the public agent URL, and it must be https") {
    val refusal = ProductionGuard.check(RuntimeProfile.Production, productionShaped - AgentPublicUrl.Key)
    assert(refusal.left.exists(_.contains(MissingProductionRequirement.AgentPublicUrl.description)), refusal.toString)
    val insecure = AgentPublicUrl.fromEnvironment(productionShaped.updated(AgentPublicUrl.Key, "http://127.0.0.1:8081"), RuntimeProfile.Production, 8081)
    assert(insecure.left.exists(_.contains("https")), insecure.toString)
  }

  test("selecting the local secret store explicitly is refused in production") {
    detects(productionShaped.updated("HALLPASS_SECRET_STORE", "local"), DevelopmentOnlyComponent.LocalEncryptedSecretStore)
  }

  test("the bootstrap admin login is refused in production whenever it is configured") {
    detects(productionShaped.updated("HALLPASS_ADMIN_BOOTSTRAP", "x" * 48), DevelopmentOnlyComponent.AdminBootstrapSecret)
    detects(productionShaped.updated("HALLPASS_ADMIN_BOOTSTRAP_FILE", "/run/secrets/admin_bootstrap"), DevelopmentOnlyComponent.AdminBootstrapSecret)
  }

  test("the break-glass job validates its request before connecting") {
    val tenant = "10000000-0000-4000-8000-000000000001"
    val grant = List(
      "grant", "--tenant", tenant, "--issuer", "https://idp.example.com", "--subject", "00u1",
      "--minutes", "60", "--operator", "on-call", "--reason", "INC-1: administrators locked out"
    )
    assert(HallpassBreakGlassMain.commandFromArguments(grant).isRight)
    assert(HallpassBreakGlassMain.commandFromArguments(grant.updated(8, "241")).left.exists(_.contains("InvalidDuration")))
    assert(HallpassBreakGlassMain.commandFromArguments(grant.updated(8, "0")).left.exists(_.contains("InvalidDuration")))
    assert(HallpassBreakGlassMain.commandFromArguments(grant.updated(12, "short")).left.exists(_.contains("InvalidReason")))
    assert(HallpassBreakGlassMain.commandFromArguments(grant.updated(2, "demo")).left.exists(_.contains("tenant ID")))
    assert(HallpassBreakGlassMain.commandFromArguments(grant.take(11)).left.exists(_.startsWith("usage:")))
    assert(HallpassBreakGlassMain.commandFromArguments(List("revoke", "--grant", tenant)).isRight)
    assert(HallpassBreakGlassMain.commandFromArguments(List("login")).left.exists(_.startsWith("usage:")))
  }

  test("in-process migrations are refused in production unless an external migration job owns the schema") {
    detects(productionShaped - "HALLPASS_DB_MIGRATIONS", DevelopmentOnlyComponent.InProcessMigrations)
    detects(productionShaped.updated("HALLPASS_DB_MIGRATIONS", "in-process"), DevelopmentOnlyComponent.InProcessMigrations)
    assert(!ProductionGuard.componentsInUse(productionShaped).contains(DevelopmentOnlyComponent.InProcessMigrations))
  }

  test("demo tenant seeding happens only with in-process migrations, and is refused in production") {
    detects(productionShaped - "HALLPASS_DB_MIGRATIONS", DevelopmentOnlyComponent.DemoCatalogSeed)
    assert(!ProductionGuard.componentsInUse(productionShaped).contains(DevelopmentOnlyComponent.DemoCatalogSeed))
  }

  test("the provisioning job validates the tenant and administrator before connecting") {
    val valid = List("--name", "Example Corp", "--slug", "example", "--admin-issuer", "https://idp.example.com", "--admin-subject", "00u1")
    assertEquals(HallpassProvisionMain.requestFromArguments(valid).map(_.slug), Right("example"))
    assert(HallpassProvisionMain.requestFromArguments(valid.take(6)).left.exists(_.startsWith("usage:")))
    assert(HallpassProvisionMain.requestFromArguments(valid ++ List("--name", "Twice")).left.exists(_.startsWith("usage:")))
    assert(HallpassProvisionMain.requestFromArguments(valid.updated(3, "Not A Slug")).left.exists(_.contains("InvalidSlug")))
    assert(HallpassProvisionMain.requestFromArguments(valid.updated(7, " padded")).left.exists(_.contains("InvalidSubject")))
  }

  test("the migration job requires a valid, explicit runtime role") {
    val database = Map("HALLPASS_DB_URL" -> "jdbc:postgresql://db/authai", "HALLPASS_DB_USER" -> "authai_owner")
    assert(HallpassMigrateMain.configFromEnvironment(database).left.exists(_.contains("HALLPASS_DB_RUNTIME_ROLE is required")))
    assert(HallpassMigrateMain.configFromEnvironment(database.updated("HALLPASS_DB_RUNTIME_ROLE", "App; drop table x")).isLeft)
    assertEquals(
      HallpassMigrateMain.configFromEnvironment(database.updated("HALLPASS_DB_RUNTIME_ROLE", "authai_app")).map(_._2.value),
      Right("authai_app")
    )
  }

  private def detects(environment: Map[String, String], component: DevelopmentOnlyComponent): Unit =
    assert(ProductionGuard.componentsInUse(environment).contains(component), s"$component was not detected")
    val refusal = ProductionGuard.check(RuntimeProfile.Production, environment)
    assert(refusal.left.exists(_.contains(component.description)), s"refusal did not name $component: $refusal")

  test("the local encrypted secret store is refused in production") {
    detects(productionShaped.updated("HALLPASS_SECRET_DIRECTORY", "/var/lib/hallpass-secrets"), DevelopmentOnlyComponent.LocalEncryptedSecretStore)
    detects(productionShaped.updated("HALLPASS_SECRET_MASTER_KEY_FILE", "/run/secrets/key"), DevelopmentOnlyComponent.LocalEncryptedSecretStore)
    assert(!ProductionGuard.componentsInUse(productionShaped).contains(DevelopmentOnlyComponent.LocalEncryptedSecretStore))
  }

  test("the single-process tenant gate is refused in production") {
    detects(productionShaped - "HALLPASS_TENANT_GATE", DevelopmentOnlyComponent.SingleProcessTenantGate)
    detects(productionShaped.updated("HALLPASS_TENANT_GATE", "single-process"), DevelopmentOnlyComponent.SingleProcessTenantGate)
  }

  test("a loopback-only agent listener is refused in production") {
    detects(productionShaped - "HALLPASS_AGENT_HTTP_BIND_HOST", DevelopmentOnlyComponent.LoopbackAgentListener)
    detects(productionShaped.updated("HALLPASS_AGENT_HTTP_BIND_HOST", "127.0.0.1"), DevelopmentOnlyComponent.LoopbackAgentListener)
  }

  test("each structural component is named in the production refusal") {
    DevelopmentOnlyComponent.values
      .filter(component => ProductionGuard.componentsInUse(productionShaped).contains(component))
      .foreach(component => detects(productionShaped, component))
  }

  test("server configuration refuses production before reading any other configuration") {
    val refused = ServerConfig.fromEnvironment(Nil, productionShaped - "HALLPASS_SECRET_STORE")
    assert(refused.left.exists(_.startsWith("HALLPASS_ENV=production refused")), refused.toString)
    assert(!refused.left.exists(_.contains("HALLPASS_DB_URL")), "the guard runs before other configuration")
    // With the guard satisfied, startup proceeds to ordinary configuration, here failing on the missing database.
    val next = ServerConfig.fromEnvironment(Nil, productionShaped)
    assert(next.left.exists(_.contains("HALLPASS_DB_URL")), next.toString)
    assert(ServerConfig.fromEnvironment(Nil, Map.empty).left.exists(_.contains("HALLPASS_ENV is required")))
  }

  test("drain delay defaults by profile and is bounded") {
    assertEquals(RuntimeProfile.Development.defaultDrainDelay.toMillis, 0L)
    assertEquals(RuntimeProfile.Production.defaultDrainDelay.toSeconds, 10L)
    assertEquals(ServerConfig.drainDelay(RuntimeProfile.Production, Map.empty).map(_.toSeconds), Right(10L))
    assertEquals(
      ServerConfig.drainDelay(RuntimeProfile.Development, Map("HALLPASS_SHUTDOWN_DRAIN_DELAY_MS" -> "2500")).map(_.toMillis),
      Right(2500L)
    )
    assert(ServerConfig.drainDelay(RuntimeProfile.Development, Map("HALLPASS_SHUTDOWN_DRAIN_DELAY_MS" -> "999999")).isLeft)
    assert(ServerConfig.drainDelay(RuntimeProfile.Development, Map("HALLPASS_SHUTDOWN_DRAIN_DELAY_MS" -> "-1")).isLeft)
  }

  test("production requires telemetry exported to an https collector") {
    def missing(environment: Map[String, String]) =
      ProductionGuard.missingRequirements(environment).contains(MissingProductionRequirement.Observability)
    assert(missing(productionShaped - "OTEL_EXPORTER_OTLP_ENDPOINT"))
    assert(missing(productionShaped.updated("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4318")))
    assert(!missing(productionShaped))
    assertEquals(TelemetryRuntime.fromEnvironment(Map.empty), Right(TelemetryRuntime.Selection.Disabled))
    assert(TelemetryRuntime.fromEnvironment(Map("OTEL_EXPORTER_OTLP_ENDPOINT" -> "http://localhost:4318")).isRight)
    assert(TelemetryRuntime.fromEnvironment(Map("HALLPASS_ENV" -> "production", "OTEL_EXPORTER_OTLP_ENDPOINT" -> "http://collector:4318")).isLeft)
    assert(TelemetryRuntime.fromEnvironment(Map("OTEL_EXPORTER_OTLP_ENDPOINT" -> "not a url")).isLeft)
  }

  test("overriding the provider endpoint is refused in production") {
    detects(productionShaped.updated("HALLPASS_SLACK_SEARCH_URL", "https://attacker.example/api"), DevelopmentOnlyComponent.ProviderEndpointOverride)
  }

  test("overriding either GitHub endpoint is refused in production and allowed in development") {
    List(GitHubRuntime.ApiUrlKey, GitHubRuntime.WebUrlKey).foreach { key =>
      detects(productionShaped.updated(key, "https://attacker.example"), DevelopmentOnlyComponent.ProviderEndpointOverride)
      assert(ProductionGuard.check(RuntimeProfile.Production, productionShaped.updated(key, "https://attacker.example")).isLeft)
      assert(ProductionGuard.check(RuntimeProfile.Development, Map(key -> "http://localhost:9999")).isRight)
    }
  }

  test("overriding any Notion endpoint is refused in production and allowed in development") {
    NotionRuntime.EndpointOverrideKeys.foreach { key =>
      detects(productionShaped.updated(key, "https://attacker.example"), DevelopmentOnlyComponent.ProviderEndpointOverride)
      assert(ProductionGuard.check(RuntimeProfile.Production, productionShaped.updated(key, "https://attacker.example")).isLeft)
      assert(ProductionGuard.check(RuntimeProfile.Development, Map(key -> "http://localhost:9999")).isRight)
    }
  }

  test("overriding any Google endpoint is refused in production and allowed in development") {
    GoogleRuntime.EndpointOverrideKeys.foreach { key =>
      detects(productionShaped.updated(key, "https://attacker.example"), DevelopmentOnlyComponent.ProviderEndpointOverride)
      assert(ProductionGuard.check(RuntimeProfile.Production, productionShaped.updated(key, "https://attacker.example")).isLeft)
      assert(ProductionGuard.check(RuntimeProfile.Development, Map(key -> "http://localhost:9999")).isRight)
    }
  }

  test("overriding any HubSpot endpoint is refused in production and allowed in development") {
    HubSpotRuntime.EndpointOverrideKeys.foreach { key =>
      detects(productionShaped.updated(key, "https://attacker.example"), DevelopmentOnlyComponent.ProviderEndpointOverride)
      assert(ProductionGuard.check(RuntimeProfile.Production, productionShaped.updated(key, "https://attacker.example")).isLeft)
      assert(ProductionGuard.check(RuntimeProfile.Development, Map(key -> "http://localhost:9999")).isRight)
    }
  }

  test("overriding any Linear endpoint is refused in production and allowed in development") {
    LinearRuntime.EndpointOverrideKeys.foreach { key =>
      detects(productionShaped.updated(key, "https://attacker.example"), DevelopmentOnlyComponent.ProviderEndpointOverride)
      assert(ProductionGuard.check(RuntimeProfile.Production, productionShaped.updated(key, "https://attacker.example")).isLeft)
      assert(ProductionGuard.check(RuntimeProfile.Development, Map(key -> "http://localhost:9999")).isRight)
    }
  }

