package run.hallpass.application

import io.circe.Json
import io.circe.Printer
import run.hallpass.kernel.*

/** The one strict wire format for delegation constraints, shared by storage and the admin API:
  * `{}` or `{"value_in": {"<context key>": ["v1", ...], ...}}`. Anything else is rejected. `RequireContext` has no
  * wire form and cannot be persisted. */
object DelegationConstraintsJson:
  val MaximumKeys = 20
  val MaximumStoredBytes = 65536

  // PostgreSQL jsonb::text inserts spaces after separators. Measure that representation
  // in UTF-8 because the database constraint uses octet_length, not character count.
  private val storedJsonPrinter = Printer.noSpaces.copy(
    colonRight = " ",
    objectCommaRight = " ",
    arrayCommaRight = " "
  )

  private def withinStoredByteLimit(json: Json): Boolean =
    storedJsonPrinter.print(json).getBytes(java.nio.charset.StandardCharsets.UTF_8).length <= MaximumStoredBytes

  def decode(json: Json): Either[String, Constraints] =
    json.asObject.toRight("constraints must be an object").flatMap: obj =>
      if obj.keys.exists(_ != "value_in") then Left("unknown constraint field")
      else if !withinStoredByteLimit(json) then Left("constraints exceed stored size limit")
      else
        obj("value_in") match
          case None => Right(Constraints.empty)
          case Some(valueIn) =>
            valueIn.asObject.toRight("value_in must be an object").flatMap: entries =>
              if entries.size > MaximumKeys then Left("too many constraint keys")
              else
                entries.toVector.foldLeft[Either[String, Set[Constraint]]](Right(Set.empty)):
                  case (Right(acc), (rawKey, rawValues)) => decodeEntry(rawKey, rawValues).map(acc + _)
                  case (left, _)                         => left
                .map(Constraints(_))

  private def decodeEntry(rawKey: String, rawValues: Json): Either[String, Constraint] =
    for
      key <- ContextKey.parse(rawKey).toRight("invalid constraint key")
      array <- rawValues.asArray.toRight("allowed values must be an array")
      _ <- Either.cond(array.nonEmpty, (), "allowed values must not be empty")
      _ <- Either.cond(array.size <= Constraint.MaximumAllowedValues, (), "too many allowed values")
      parsed <- array.foldLeft[Either[String, Vector[ContextValue]]](Right(Vector.empty)): (acc, element) =>
        acc.flatMap(values =>
          element.asString.flatMap(ContextValue.parse).toRight("invalid allowed value").map(values :+ _)
        )
      set = parsed.toSet
      _ <- Either.cond(set.size == parsed.size, (), "duplicate allowed value")
      allowed <- NonEmptySet.from(set).toRight("allowed values must not be empty")
    yield Constraint.ValueIn(key, allowed)

  /** Deterministic: sorted keys and values. Left when the constraints contain a form with no wire representation or
    * violate the bounds the decoder enforces, so what is written can always be read back. */
  def encode(constraints: Constraints): Either[String, Json] =
    val valueIns = constraints.values.toVector.collect { case v: Constraint.ValueIn => v }
    if valueIns.size != constraints.values.size then Left("unsupported constraint")
    else if valueIns.map(_.key).distinct.size != valueIns.size then Left("duplicate constraint key")
    else
      val json =
        if valueIns.isEmpty then Json.obj()
        else
          Json.obj(
            "value_in" -> Json.obj(
              valueIns.sortBy(v => v.key.toString).map(v =>
                v.key.toString -> Json.arr(v.allowed.toSet.toVector.map(_.toString).sorted.map(Json.fromString)*)
              )*
            )
          )
      decode(json).map(_ => json)

  def render(constraints: Constraints): Json = encode(constraints).getOrElse(Json.obj())
