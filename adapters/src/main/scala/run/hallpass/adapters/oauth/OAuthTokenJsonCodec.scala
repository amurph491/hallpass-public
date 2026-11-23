package run.hallpass.adapters.oauth

import java.nio.charset.StandardCharsets
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.time.Instant
import io.circe.parser.parse
import io.circe.syntax.*
import io.circe.Json
import run.hallpass.application.*

/** JSON representation for OAuth credentials stored only through the encrypted SecretStore. */
final class OAuthTokenJsonCodec extends OAuthTokenCodec:
  def encode(tokens: OAuthTokens): ProviderSecret =
    val fields = Vector(
      Some("access_token" -> Json.fromString(tokens.accessToken)),
      tokens.refreshToken.map(value => "refresh_token" -> Json.fromString(value)),
      Some("expires_at" -> Json.fromString(tokens.expiresAt.toString))
    ).flatten
    ProviderSecret.fromUtf8(Json.obj(fields*).noSpaces)

  def decode(secret: ProviderSecret): Either[ConnectionError, OAuthTokens] =
    val bytes = ProviderSecret.bytes(secret)
    try
      val decoded = scala.util.Try(
        StandardCharsets.UTF_8.newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes)).toString
      ).toOption
      decoded.flatMap(parse(_).toOption).flatMap: json =>
        json.asObject.flatMap: fields =>
          val allowed = Set("access_token", "refresh_token", "expires_at")
          val exactShape = fields.keys.forall(allowed.contains) && fields.contains("access_token") && fields.contains("expires_at")
          if !exactShape then None
          else
            val access = fields("access_token").flatMap(_.asString).filter(validToken)
            val refresh = fields("refresh_token") match
              case None        => Some(None)
              case Some(value) => value.asString.filter(validToken).map(Some(_))
            val expiry = fields("expires_at").flatMap(_.asString).flatMap(value => scala.util.Try(Instant.parse(value)).toOption)
            for
              accessToken <- access
              refreshToken <- refresh
              expiresAt <- expiry
              tokens <- OAuthTokens.from(accessToken, refreshToken, expiresAt)
            yield tokens
      .toRight(ConnectionError.MissingCredential)
    finally java.util.Arrays.fill(bytes, 0.toByte)

  private def validToken(value: String): Boolean =
    value.nonEmpty && value.forall(character => !character.isWhitespace && !Character.isISOControl(character))
