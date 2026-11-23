package run.hallpass.bridge

import java.net.{InetSocketAddress, URI}
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentLinkedQueue
import com.sun.net.httpserver.HttpServer
import cats.effect.{IO, Resource}
import scala.jdk.CollectionConverters.*

/** A loopback stand-in for the agent API that answers every bridge path with one canned response and records requests. */
private[bridge] object AgentApiFixture:
  val credential = "ac1.abcdefghijklmnop.abcdefghijklmnopqrstuvwxyz0123456789-_ABCDE"

  /** One request as the fake server saw it. */
  final case class Seen(method: String, path: String, headers: Map[String, List[String]], body: String):
    def authorization: Option[String] = headers.get("Authorization").flatMap(_.headOption)

  final class Recorder private[AgentApiFixture] (queue: ConcurrentLinkedQueue[Seen]):
    def requests: List[Seen] = queue.asScala.toList

  def endpointAndClientRecording(
      response: String,
      status: Int = 200,
      headers: List[(String, String)] = Nil,
      truncateResponse: Boolean = false,
      delayMillis: Long = 0
  ): Resource[IO, (URI, AgentApiClient, Recorder)] =
    val seen = new ConcurrentLinkedQueue[Seen]()
    Resource
      .make(IO.blocking:
        val server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0)
        // The context matches every path below it, so the tool list and any tool call answer identically.
        server.createContext("/api/agent/tools", exchange =>
          val requestHeaders = exchange.getRequestHeaders.asScala.map((name, values) => name -> values.asScala.toList).toMap
          val requestBody = new String(exchange.getRequestBody.readAllBytes(), StandardCharsets.UTF_8)
          seen.add(Seen(exchange.getRequestMethod, exchange.getRequestURI.getRawPath, requestHeaders, requestBody))
          if delayMillis > 0 then Thread.sleep(delayMillis)
          val bytes = response.getBytes(StandardCharsets.UTF_8)
          headers.foreach((name, value) => exchange.getResponseHeaders.add(name, value))
          try
            exchange.sendResponseHeaders(status, bytes.length + (if truncateResponse then 16 else 0))
            val output = exchange.getResponseBody
            try output.write(bytes)
            finally output.close()
          catch case _: java.io.IOException => ()
          finally exchange.close()
        )
        server.start()
        server
      )(server => IO.blocking(server.stop(0)))
      .flatMap: server =>
        val endpoint = URI.create(s"http://127.0.0.1:${server.getAddress.getPort}")
        val config = BridgeConfig
          .fromEnvironment(Map("HALLPASS_AGENT_API_URL" -> endpoint.toString, "HALLPASS_AGENT_CREDENTIAL" -> credential))
          .fold(error => throw AssertionError(s"bridge config: $error"), identity)
        AgentApiClient.resource(config).map(client => (endpoint, client, Recorder(seen)))

  def endpointAndClient(
      response: String,
      status: Int = 200,
      headers: List[(String, String)] = Nil
  ): Resource[IO, (URI, AgentApiClient)] =
    endpointAndClientRecording(response, status, headers).map((endpoint, client, _) => (endpoint, client))

  def client(response: String, status: Int = 200, headers: List[(String, String)] = Nil): Resource[IO, AgentApiClient] =
    endpointAndClient(response, status, headers).map(_._2)
