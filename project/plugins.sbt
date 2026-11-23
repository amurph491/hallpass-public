// Add build plugins only when a concrete build concern requires them.

// Scalastyle 1.0.0 uses the Scala 2 Scalariform parser and cannot parse this
// Scala 3 project (notably top-level definitions and opaque types). Keep
// formatting enforcement on Scalafmt instead.
addSbtPlugin("org.scalameta" % "sbt-scalafmt" % "2.6.2")
