package network.crypta.support.compress

import java.io.*
import java.util.concurrent.CountDownLatch
import org.sevenzip.compression.lzma.Decoder

/**
 * Streaming LZMA decoder exposed as a standard [InputStream].
 *
 * This class reads an LZMA stream that starts with the traditional 5‑byte coder properties followed
 * by an 8‑byte little‑endian uncompressed size, and produces the decoded bytes on demand. It runs
 * the SevenZip LZMA [Decoder] on a background daemon thread and connects it to the public
 * `InputStream` via a `PipedInputStream`/`PipedOutputStream` pair.
 *
 * Construction starts the decoder thread and blocks until the header (properties and size) is
 * parsed or an error occurs. If header parsing fails, the constructor throws an [IOException].
 * After startup, any decoding error emitted by the background thread is surfaced from subsequent
 * `read(...)` calls on this stream.
 *
 * Threading and safety:
 * - A dedicated daemon thread named "LZMA-Decoder" performs I/O and decoding.
 * - Instances are not thread‑safe for concurrent reads beyond the guarantees of [PipedInputStream].
 *   Use from a single reader thread.
 *
 * Resource management:
 * - Closing this stream closes both the internal pipe and the underlying `source` stream.
 *
 * @param source input containing the LZMA payload. The caller retains ownership, but it will be
 *   closed when this stream is closed.
 * @constructor creates a decoder over the given LZMA source stream.
 * @throws IOException if the current thread is interrupted while waiting for the decoder to start,
 *   or if the header is invalid/truncated.
 */
class LzmaInputStream(private val source: InputStream) : InputStream() {
  private val pipeIn = PipedInputStream()
  private val pipeOut = PipedOutputStream(pipeIn)
  private val started = CountDownLatch(1)
  @Volatile private var thrown: IOException? = null

  init {
    // Spin up the background decoder early so readers can consume as data becomes available.
    val worker = Thread(this::decodeLoop, "LZMA-Decoder")
    worker.isDaemon = true
    worker.start()
    try {
      // Wait until the header is parsed (or an error has been recorded) before returning.
      started.await()
    } catch (ie: InterruptedException) {
      Thread.currentThread().interrupt()
      throw IOException("Interrupted while starting LZMA decoder", ie)
    }
    // If the worker failed during startup, rethrow here so construction signals the failure.
    thrown?.let { throw it }
  }

  private fun decodeLoop() {
    try {
      // Buffer source reads a bit to amortize small header/runtime reads.
      BufferedInputStream(source).use { inBuf ->
        // Connect the decoder output to the pipe consumed by the public read(...) methods.
        pipeOut.use { out ->
          // Read 5‑byte coder properties as per classic .lzma header.
          val props = ByteArray(5)
          readFully(inBuf, props)

          // Read 8‑byte little‑endian uncompressed size. A value of 0 means an empty payload.
          var outSize = 0L
          repeat(8) { i ->
            val b = inBuf.read()
            if (b < 0) throw IOException("Unexpected EOF reading LZMA size header")
            outSize = outSize or ((b.toLong() and 0xFFL) shl (8 * i))
          }

          val decoder = Decoder()
          if (!decoder.setDecoderProperties(props)) {
            throw IOException("Invalid LZMA properties")
          }
          // Signal constructor/readers that header parsing finished; decoding may proceed.
          started.countDown()

          // Stream-decode exactly 'outSize' bytes. A false return indicates a format error.
          if (!decoder.code(inBuf, out, outSize)) {
            throw IOException("LZMA decode error")
          }
          out.flush()
        }
      }
    } catch (ioe: IOException) {
      thrown = ioe
      // Ensure constructor/readers are unblocked even when failing early.
      started.countDown()
      try {
        pipeOut.close()
      } catch (_: IOException) {
        // Intentionally ignore: the pipe may already be closed if decoding aborted early.
      }
    }
  }

  // Reads exactly `buf.size` bytes or throws if EOF is reached prematurely.
  private fun readFully(input: InputStream, buf: ByteArray) {
    var pos = 0
    val end = buf.size
    while (pos < end) {
      val r = input.read(buf, pos, end - pos)
      if (r < 0) throw IOException("Unexpected EOF")
      pos += r
    }
  }

  /**
   * Reads one decoded byte.
   *
   * @return next byte in the range `0..255`, or `-1` on end of stream.
   * @throws IOException if a decoding error occurred on the background thread or the pipe is
   *   otherwise broken.
   */
  override fun read(): Int {
    thrown?.let { throw it }
    val b = pipeIn.read()
    if (b < 0) thrown?.let { throw it }
    return b
  }

  /**
   * Reads up to `len` decoded bytes into `b` starting at `off`.
   *
   * This method may block until data becomes available from the decoder or the end of the stream is
   * reached.
   *
   * @return number of bytes read, or `-1` if the end of stream has been reached.
   * @throws IOException if a decoding error occurred on the background thread or the pipe is
   *   otherwise broken.
   */
  override fun read(b: ByteArray, off: Int, len: Int): Int {
    thrown?.let { throw it }
    val r = pipeIn.read(b, off, len)
    if (r < 0) thrown?.let { throw it }
    return r
  }

  /**
   * Closes this stream and the underlying source.
   *
   * Closing unblocks the decoder (if still running) by closing the pipe. The underlying `source`
   * input stream is always closed.
   *
   * @throws IOException if closing the underlying streams fails.
   */
  override fun close() {
    source.use { _ -> pipeIn.close() }
  }
}
