ThisBuild / organization := "run.hallpass"
ThisBuild / version := "0.1.0-SNAPSHOT"
ThisBuild / scalaVersion := "3.9.0"
ThisBuild / scalacOptions ++= Seq("-deprecation", "-feature", "-unchecked")

lazy val stageRuntimeClasspath = taskKey[Unit](
  "Package project products as jars and stage the complete runtime classpath for a container image"
)

lazy val commonSettings = Seq(
  Test / fork := true
)

lazy val root = (project in file("."))
  .aggregate(kernel, application, adapters, gateway, workers, api, bridge)
  .settings(
    name := "hallpass",
    publish / skip := true
  )

lazy val kernel = (project in file("kernel"))
  .settings(commonSettings)
  .settings(
    name := "hallpass-kernel",
    libraryDependencies ++= Seq(
      "org.scalameta" %% "munit" % "1.3.6" % Test,
      "org.scalameta" %% "munit-scalacheck" % "1.3.1" % Test
    )
  )

lazy val api = (project in file("api"))
  .settings(commonSettings)
  .settings(name := "hallpass-api")

lazy val application = (project in file("application"))
  .dependsOn(kernel, api)
  .settings(commonSettings)
  .settings(
    name := "hallpass-application",
    libraryDependencies ++= Seq(
      "org.typelevel" %% "cats-effect" % "3.7.1",
      // Operation arguments stay JSON at the application edge; security semantics are decoded into typed input.
      "io.circe" %% "circe-core" % "0.14.17",
      "org.scalameta" %% "munit" % "1.3.6" % Test,
      "org.typelevel" %% "munit-cats-effect" % "2.2.1" % Test
    )
  )

lazy val adapters = (project in file("adapters"))
  .dependsOn(application, api)
  .settings(commonSettings)
  .settings(
    name := "hallpass-adapters",
    libraryDependencies ++= Seq(
      "org.typelevel" %% "doobie-core" % "1.0.0-RC14",
      "org.typelevel" %% "doobie-hikari" % "1.0.0-RC14",
      "org.typelevel" %% "doobie-postgres" % "1.0.0-RC14",
      "org.postgresql" % "postgresql" % "42.7.14",
      "org.flywaydb" % "flyway-core" % "13.10.3",
      "org.flywaydb" % "flyway-database-postgresql" % "13.10.3",
      "io.circe" %% "circe-core" % "0.14.17",
      "io.circe" %% "circe-parser" % "0.14.17",
      // JWS and JWKS verification for OIDC ID tokens only; the code exchange uses the JDK HTTP client.
      "com.nimbusds" % "nimbus-jose-jwt" % "10.10",
      "org.testcontainers" % "postgresql" % "1.21.4" % Test,
      "org.scalameta" %% "munit" % "1.3.6" % Test,
      "org.typelevel" %% "munit-cats-effect" % "2.2.1" % Test
    )
  )

lazy val gateway = (project in file("gateway"))
  .dependsOn(application, adapters, api)
  .settings(commonSettings)
  .settings(
    name := "hallpass-gateway",
    stageRuntimeClasspath := {
      val output = (LocalRootProject / baseDirectory).value / ".docker-stage" / "gateway" / "lib"
      val classpath = (Runtime / fullClasspathAsJars).value.map(_.data).distinct
      IO.delete(output)
      IO.createDirectory(output)
      classpath.foreach { virtualFile =>
        val source = fileConverter.value.toPath(virtualFile).toFile
        IO.copyFile(source, output / source.getName)
      }
      ()
    },
    libraryDependencies ++= Seq(
      "io.modelcontextprotocol.sdk" % "mcp" % "2.2.0",
      "io.circe" %% "circe-core" % "0.14.17",
      "io.circe" %% "circe-parser" % "0.14.17",
      "org.http4s" %% "http4s-ember-server" % "0.23.39",
      "org.typelevel" %% "log4cats-noop" % "2.8.0",
      // OpenTelemetry at the composition root only; application code sees the Telemetry port. OTel artifacts are
      // pinned to the version otel4s is built against.
      "org.typelevel" %% "otel4s-oteljava" % "1.2.0",
      "io.opentelemetry" % "opentelemetry-exporter-otlp" % "1.68.0",
      "io.opentelemetry" % "opentelemetry-sdk-extension-autoconfigure" % "1.68.0",
      "org.typelevel" %% "otel4s-oteljava-testkit" % "1.2.0" % Test,
      // The two-instance canary runs real servers against PostgreSQL.
      "org.testcontainers" % "postgresql" % "1.21.4" % Test,
      "org.scalameta" %% "munit" % "1.3.6" % Test,
      "org.typelevel" %% "munit-cats-effect" % "2.2.1" % Test
    )
  )

// The local MCP bridge production/runtime classpath is deliberately edge-only:
// never add gateway, adapters, kernel, or application as production dependencies.
// Gateway and adapters are test-scoped below only for the end-to-end boundary test.
lazy val bridge = (project in file("bridge"))
  .dependsOn(api, gateway % Test, adapters % Test)
  .settings(commonSettings)
  .settings(
    name := "hallpass-local-agent-bridge",
    Test / test := (Test / test).dependsOn(stageRuntimeClasspath).evaluated,
    stageRuntimeClasspath := {
      val output = baseDirectory.value / "target" / "bridge-dist" / "lib"
      val classpath = (Runtime / fullClasspathAsJars).value.map(_.data).map(fileConverter.value.toPath(_).toFile).distinct
      val forbidden = Seq("kernel", "application", "adapters", "gateway", "workers")
      val serverOnlyJarPrefixes = Seq(
        "hallpass-kernel_", "hallpass-application_", "hallpass-adapters_", "hallpass-gateway_",
        "hallpass-workers_", "doobie-", "postgresql-", "flyway-"
      )
      val unexpected = classpath.filter(file =>
        forbidden.exists(component => file.getAbsolutePath.contains(s"/$component/")) ||
          serverOnlyJarPrefixes.exists(file.getName.startsWith)
      )
      if unexpected.nonEmpty then
        sys.error(s"Bridge runtime classpath includes server-only projects or libraries: ${unexpected.mkString(", ")}")
      val duplicateNames = classpath.groupBy(_.getName).collect { case (name, files) if files.size > 1 => name }
      if duplicateNames.nonEmpty then
        sys.error(s"Bridge runtime jars have duplicate filenames: ${duplicateNames.mkString(", ")}")
      IO.delete(output)
      IO.createDirectory(output)
      classpath.foreach(source => IO.copyFile(source, output / source.getName))
      streams.value.log.info(s"Staged ${classpath.size} bridge runtime jars in $output")
    },
    libraryDependencies ++= Seq(
      "io.modelcontextprotocol.sdk" % "mcp" % "2.2.0",
      "org.typelevel" %% "cats-effect" % "3.7.1",
      "io.circe" %% "circe-core" % "0.14.17",
      "io.circe" %% "circe-parser" % "0.14.17",
      "org.testcontainers" % "postgresql" % "1.21.4" % Test,
      "org.scalameta" %% "munit" % "1.3.6" % Test,
      "org.typelevel" %% "munit-cats-effect" % "2.2.1" % Test
    )
  )

lazy val workers = (project in file("workers"))
  .dependsOn(application, adapters, api)
  .settings(commonSettings)
  .settings(name := "hallpass-workers")
