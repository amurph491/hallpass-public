package run.hallpass.gateway

import java.net.InetAddress
import com.sun.net.httpserver.Headers
import munit.FunSuite

final class ClientAddressSuite extends FunSuite:
  private val proxy = Some(InetAddress.getByName("10.0.0.5"))

  private def forwarded(values: String*): Headers =
    val headers = new Headers()
    values.foreach(headers.add("X-Forwarded-For", _))
    headers

  test("without trusted proxies the socket peer is the client, whatever the header says") {
    assertEquals(ClientAddress.resolve(proxy, forwarded("203.0.113.9"), 0), proxy)
  }

  test("behind one proxy, the entry that proxy appended is the client; earlier entries are client-supplied") {
    val resolved = ClientAddress.resolve(proxy, forwarded("198.51.100.66, 203.0.113.9"), 1)
    assertEquals(resolved, Some(InetAddress.getByName("203.0.113.9")), "a forged leading entry is ignored")
    assertEquals(
      ClientAddress.resolve(proxy, forwarded("198.51.100.66", "203.0.113.9, 10.0.0.4"), 2),
      Some(InetAddress.getByName("203.0.113.9"))
    )
    assertEquals(ClientAddress.resolve(proxy, forwarded("2001:db8::1"), 1), Some(InetAddress.getByName("2001:db8::1")))
  }

  test("a missing, short, or non-literal header falls back to the peer, never to a lookup") {
    assertEquals(ClientAddress.resolve(proxy, new Headers(), 1), proxy)
    assertEquals(ClientAddress.resolve(proxy, forwarded("203.0.113.9"), 2), proxy)
    assertEquals(ClientAddress.resolve(proxy, forwarded("evil.example"), 1), proxy)
    assertEquals(ClientAddress.resolve(proxy, forwarded("unknown"), 1), proxy)
  }
