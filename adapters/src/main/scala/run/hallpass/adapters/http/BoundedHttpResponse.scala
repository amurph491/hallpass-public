package run.hallpass.adapters.http

import java.io.ByteArrayOutputStream
import java.net.http.{HttpClient, HttpRequest, HttpResponse}
import java.nio.ByteBuffer
import java.util.concurrent.{CompletableFuture, CompletionStage, Flow}
import scala.concurrent.duration.FiniteDuration
import scala.jdk.CollectionConverters.*
import cats.effect.IO

/** Bounds the entire exchange, including a body that stalls after the headers. Cancellation of the future aborts
  * the JDK HTTP exchange; no blocking stream read can delay cancellation or resource finalizers. */
private[adapters] object BoundedHttpResponse:
  def send(
      client: HttpClient,
      request: HttpRequest,
      maximumBytes: Int,
      timeout: FiniteDuration
  ): IO[HttpResponse[Array[Byte]]] =
    IO.fromCompletableFuture(IO:
      client.sendAsync(request, _ => LimitedBody(maximumBytes))
    ).timeout(timeout)

  /** Subscriber callbacks are serialized by Flow. Reject before copying a chunk that would exceed the limit. */
  private final class LimitedBody(maximumBytes: Int) extends HttpResponse.BodySubscriber[Array[Byte]]:
    private val result = CompletableFuture[Array[Byte]]()
    private val bytes = ByteArrayOutputStream(math.min(maximumBytes, 8192))
    private var subscription: Flow.Subscription = null

    def getBody(): CompletionStage[Array[Byte]] = result

    def onSubscribe(value: Flow.Subscription): Unit =
      subscription = value
      subscription.request(1)

    def onNext(buffers: java.util.List[ByteBuffer]): Unit =
      val incoming = buffers.asScala.iterator.map(_.remaining().toLong).sum
      if incoming > maximumBytes.toLong - bytes.size() then
        subscription.cancel()
        result.completeExceptionally(IllegalStateException("HTTP response exceeds the size limit"))
      else
        buffers.asScala.foreach: buffer =>
          val chunk = new Array[Byte](buffer.remaining())
          buffer.get(chunk)
          bytes.write(chunk)
        subscription.request(1)

    def onError(error: Throwable): Unit =
      result.completeExceptionally(error)

    def onComplete(): Unit =
      result.complete(bytes.toByteArray)
