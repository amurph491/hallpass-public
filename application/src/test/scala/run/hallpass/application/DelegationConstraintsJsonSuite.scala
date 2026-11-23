package run.hallpass.application

import io.circe.Json
import munit.FunSuite
import run.hallpass.kernel.*

final class DelegationConstraintsJsonSuite extends FunSuite:
  private def document(value: String, count: Int = 1, keys: Int = 1): Json =
    val entries = (1 to keys).map: keyIndex =>
      s"k.key$keyIndex" -> Json.arr((1 to count).map: i =>
        val suffix = i.toString
        Json.fromString(value.take(512 - suffix.length) + suffix)
      *)
    Json.obj("value_in" -> Json.obj(entries*))

  test("accepts a valid constraints document close to the PostgreSQL storage limit and round trips it") {
    val json = document("x" * 500, count = 125)
    val decoded = DelegationConstraintsJson.decode(json)
    assert(decoded.isRight)
    assertEquals(DelegationConstraintsJson.encode(decoded.toOption.get).map(DelegationConstraintsJson.decode), Right(Right(decoded.toOption.get)))
  }

  test("rejects valid values whose PostgreSQL JSONB text exceeds the byte limit") {
    val oversizedAscii = document("a" * 512, count = 200, keys = 20)
    val oversizedMultibyte = document("界" * 512, count = 3, keys = 20)
    val oversizedEscaped = document("\\\"" * 256, count = 100, keys = 2)

    Vector(oversizedAscii, oversizedMultibyte, oversizedEscaped).foreach: json =>
      assertEquals(DelegationConstraintsJson.decode(json).left.toOption, Some("constraints exceed stored size limit"))
  }
