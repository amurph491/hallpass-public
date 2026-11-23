package run.hallpass.gateway

import java.net.URI
import java.nio.charset.StandardCharsets
import com.sun.net.httpserver.Headers
import scala.jdk.CollectionConverters.*
import run.hallpass.application.PresentedAgentCredential

/**
  * Parses the narrow local agent authentication boundary.
  *
  * This deliberately only turns a syntactically valid bearer value into a
  * [[PresentedAgentCredential]]. Credential lookup and verification belong to
  * the application authentication boundary, not to HTTP parsing.
  */
private[gateway] object AgentHttpAuthentication:
  /** Bounds untrusted header allocation before credential parsing. */
  val MaxAuthorizationHeaderBytes = 512

  /** A valid `ac1` credential is currently at most 80 ASCII characters. */
  val MaxBearerCredentialBytes = 128

  /** Safe HTTP-boundary failures. These cases intentionally carry no request data. */
  enum Rejection:
    case QueryNotAllowed
    case CookieNotAllowed
    case MissingAuthorization
    case MultipleAuthorizationValues
    case AuthorizationTooLarge
    case BearerCredentialTooLarge
    case InvalidAuthorization

  /**
    * Requires a request without query or cookie state and exactly one canonical
    * `Authorization: Bearer <credential>` field-value. Header contents are
    * never included in a rejection or retained outside the secret credential
    * wrapper returned on success.
    */
  def parse(headers: Headers, requestUri: URI): Either[Rejection, PresentedAgentCredential] =
    if Option(requestUri.getRawQuery).exists(_.nonEmpty) then Left(Rejection.QueryNotAllowed)
    else if headerValues(headers, "Cookie").nonEmpty then Left(Rejection.CookieNotAllowed)
    else
      headerValues(headers, "Authorization") match
        case Vector()      => Left(Rejection.MissingAuthorization)
        case Vector(value) => parseAuthorization(value)
        case _             => Left(Rejection.MultipleAuthorizationValues)

  private def parseAuthorization(value: String): Either[Rejection, PresentedAgentCredential] =
    if byteLength(value) > MaxAuthorizationHeaderBytes then Left(Rejection.AuthorizationTooLarge)
    else
      value.stripPrefix("Bearer ") match
        case credential if credential == value => Left(Rejection.InvalidAuthorization)
        case credential if credential.contains(',') => Left(Rejection.InvalidAuthorization)
        case credential if byteLength(credential) > MaxBearerCredentialBytes =>
          Left(Rejection.BearerCredentialTooLarge)
        case credential =>
          PresentedAgentCredential.parse(credential).left.map(_ => Rejection.InvalidAuthorization)

  /** Collect all field-values case-insensitively, including repeated field names. */
  private def headerValues(headers: Headers, name: String): Vector[String] =
    headers.asScala.iterator
      .filter { case (headerName, _) => headerName.equalsIgnoreCase(name) }
      .flatMap { case (_, values) => values.asScala.iterator }
      .toVector

  private def byteLength(value: String): Int = value.getBytes(StandardCharsets.ISO_8859_1).length
