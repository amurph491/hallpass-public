package run.hallpass.adapters.github

import java.nio.charset.StandardCharsets
import java.security.interfaces.{RSAPrivateKey, RSAPublicKey}
import java.security.{KeyPair, KeyPairGenerator, Signature}
import java.time.Instant
import java.util.Base64
import io.circe.parser.parse
import munit.FunSuite

final class GitHubAppJwtSuite extends FunSuite:
  private def generate(bits: Int): KeyPair =
    val generator = KeyPairGenerator.getInstance("RSA")
    generator.initialize(bits)
    generator.generateKeyPair()

  private val pair = generate(2048)
  private val private2048 = pair.getPrivate.asInstanceOf[RSAPrivateKey]

  private def pem(label: String, der: Array[Byte]): String =
    val body = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
    s"-----BEGIN $label-----\n$body\n-----END $label-----\n"

  /** Strips the PKCS#8 wrapper (version, algorithm identifier, OCTET STRING header) to obtain the PKCS#1 DER. */
  private def pkcs1Der(pkcs8: Array[Byte]): Array[Byte] =
    def lengthAt(i: Int): (Int, Int) =
      val first = pkcs8(i) & 0xff
      if first < 0x80 then (first, 1)
      else
        val n = first & 0x7f
        ((0 until n).foldLeft(0)((acc, k) => (acc << 8) | (pkcs8(i + 1 + k) & 0xff)), 1 + n)
    val (_, outer) = lengthAt(1)
    var i = 1 + outer
    i += 3 // INTEGER 0
    assertEquals(pkcs8(i).toInt, 0x30)
    val (algLength, algHeader) = lengthAt(i + 1)
    i += 1 + algHeader + algLength
    assertEquals(pkcs8(i).toInt, 0x04)
    val (octetLength, octetHeader) = lengthAt(i + 1)
    pkcs8.slice(i + 1 + octetHeader, i + 1 + octetHeader + octetLength)

  test("JWT verifies with the public key and carries the fixed-clock claims") {
    val now = Instant.parse("2026-03-04T05:06:07Z")
    val jwt = GitHubAppJwt.sign("Iv1.client", private2048, now)
    val Array(header, claims, signature) = jwt.split('.')
    assert(!jwt.contains("=") && !jwt.contains("+") && !jwt.contains("/"))
    val decoder = Base64.getUrlDecoder
    assertEquals(parse(String(decoder.decode(header), StandardCharsets.UTF_8)), parse("""{"alg":"RS256","typ":"JWT"}"""))
    val claimJson = parse(String(decoder.decode(claims), StandardCharsets.UTF_8)).toOption.get.hcursor
    assertEquals(claimJson.get[Long]("iat"), Right(now.getEpochSecond - 60))
    assertEquals(claimJson.get[Long]("exp"), Right(now.getEpochSecond + 540))
    assertEquals(claimJson.get[String]("iss"), Right("Iv1.client"))
    val verifier = Signature.getInstance("SHA256withRSA")
    verifier.initVerify(pair.getPublic.asInstanceOf[RSAPublicKey])
    verifier.update(s"$header.$claims".getBytes(StandardCharsets.US_ASCII))
    assert(verifier.verify(decoder.decode(signature)))
  }

  test("JWT signature does not verify under a different key") {
    val jwt = GitHubAppJwt.sign("Iv1.client", private2048, Instant.parse("2026-03-04T05:06:07Z"))
    val Array(header, claims, signature) = jwt.split('.')
    val verifier = Signature.getInstance("SHA256withRSA")
    verifier.initVerify(generate(2048).getPublic)
    verifier.update(s"$header.$claims".getBytes(StandardCharsets.US_ASCII))
    assert(!verifier.verify(Base64.getUrlDecoder.decode(signature)))
  }

  test("PKCS#8 PEM parses to an equivalent key") {
    val parsed = GitHubPrivateKey.parsePem(pem("PRIVATE KEY", private2048.getEncoded)).toOption.get
    assertEquals(parsed.getModulus, private2048.getModulus)
    assertEquals(parsed.getPrivateExponent, private2048.getPrivateExponent)
  }

  test("PKCS#1 PEM parses to an equivalent key") {
    val parsed = GitHubPrivateKey.parsePem(pem("RSA PRIVATE KEY", pkcs1Der(private2048.getEncoded))).toOption.get
    assertEquals(parsed.getModulus, private2048.getModulus)
    assertEquals(parsed.getPrivateExponent, private2048.getPrivateExponent)
    val jwt = GitHubAppJwt.sign("Iv1.client", parsed, Instant.EPOCH)
    assertEquals(jwt.count(_ == '.'), 2)
  }

  test("a 3072-bit key (long DER lengths) parses") {
    val big = generate(3072).getPrivate.asInstanceOf[RSAPrivateKey]
    assert(GitHubPrivateKey.parsePem(pem("RSA PRIVATE KEY", pkcs1Der(big.getEncoded))).isRight)
  }

  test("keys under 2048 bits are rejected") {
    val small = generate(1024).getPrivate.asInstanceOf[RSAPrivateKey]
    assert(GitHubPrivateKey.parsePem(pem("PRIVATE KEY", small.getEncoded)).isLeft)
    assert(GitHubPrivateKey.parsePem(pem("RSA PRIVATE KEY", pkcs1Der(small.getEncoded))).isLeft)
  }

  test("garbage, encrypted, wrong-type, and mislabeled input are rejected with a generic error") {
    val ec = KeyPairGenerator.getInstance("EC").generateKeyPair().getPrivate.getEncoded
    val body = Base64.getEncoder.encodeToString(private2048.getEncoded)
    val inputs = Vector(
      "",
      "not a pem",
      pem("PRIVATE KEY", "garbage".getBytes(StandardCharsets.UTF_8)),
      pem("RSA PRIVATE KEY", "garbage".getBytes(StandardCharsets.UTF_8)),
      pem("ENCRYPTED PRIVATE KEY", private2048.getEncoded),
      pem("EC PRIVATE KEY", ec),
      pem("PRIVATE KEY", ec),
      s"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n$body\n-----END RSA PRIVATE KEY-----",
      pem("PRIVATE KEY", private2048.getEncoded).replace("-----END PRIVATE KEY-----", ""),
      pem("RSA PRIVATE KEY", private2048.getEncoded) // PKCS#8 bytes mislabeled as PKCS#1
    )
    inputs.foreach: input =>
      val result = GitHubPrivateKey.parsePem(input)
      assert(result.isLeft, input.take(40))
      val message = result.left.toOption.get
      assert(!message.contains(body.take(40)))
      assert(!message.contains("BEGIN"))
    assertEquals(GitHubPrivateKey.parsePem(null).left.toOption.isDefined, true)
  }
