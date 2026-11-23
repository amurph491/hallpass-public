package run.hallpass.gateway

import java.net.InetAddress
import scala.jdk.CollectionConverters.*
import scala.util.Try
import com.sun.net.httpserver.Headers

/** The address a request came from, for throttling and the rejection audit.
  *
  * With no trusted proxies it is the socket's peer. Behind `trustedProxies` proxies that each append the address they
  * received from to `X-Forwarded-For`, it is the entry the outermost trusted proxy appended: the last
  * `trustedProxies` entries are ours, and anything to their left was supplied by the client and cannot be trusted. If
  * the header is missing or too short, the peer (the nearest proxy) is used, which throttles more, never less. Only IP
  * literals are accepted; nothing here performs a DNS lookup. */
private[gateway] object ClientAddress:
  val TrustedProxiesKey = "HALLPASS_TRUSTED_PROXY_COUNT"
  private val Literal = "[0-9A-Fa-f:.]{2,45}".r

  def fromEnvironment(environment: Map[String, String]): Either[String, Int] =
    environment.get(TrustedProxiesKey).map(_.trim).filter(_.nonEmpty) match
      case None      => Right(0)
      case Some(raw) => raw.toIntOption.filter(count => count >= 0 && count <= 5).toRight(s"$TrustedProxiesKey must be 0-5")

  def resolve(peer: Option[InetAddress], headers: Headers, trustedProxies: Int): Option[InetAddress] =
    if trustedProxies == 0 then peer
    else
      val forwarded = headers.asScala.iterator
        .filter(_._1.equalsIgnoreCase("X-Forwarded-For"))
        .flatMap(_._2.asScala)
        .flatMap(_.split(",").iterator.map(_.trim))
        .toVector
      val index = forwarded.size - trustedProxies
      Option.when(index >= 0)(forwarded(index)).flatMap(literal).orElse(peer)

  private def literal(value: String): Option[InetAddress] =
    value match
      case Literal() if value.exists(_.isDigit) => Try(InetAddress.getByName(value)).toOption
      case _                                     => None
