package network.crypta.support.compress

import SevenZip.Compression.LZMA.Decoder
import java.io.BufferedInputStream
import java.io.IOException
import java.io.InputStream
import java.io.PipedInputStream
import java.io.PipedOutputStream
import java.util.concurrent.CountDownLatch

/**
 * LZMA [InputStream] compatible with the historical lzmajio API.
 *
 * - Expects an .lzma stream with 5-byte properties followed by 8-byte little-endian uncompressed size.
 * - Uses the vendored SevenZip Java decoder to stream decoded bytes via a pipe.
 */
class LzmaInputStream(private val source: InputStream) : InputStream() {
  private val pipeIn = PipedInputStream()
  private val pipeOut = PipedOutputStream(pipeIn)
  private val started = CountDownLatch(1)
  @Volatile private var thrown: IOException? = null

  init {
    val worker = Thread(this::decodeLoop, "LZMA-Decoder")
    worker.isDaemon = true
    worker.start()
    try {
      started.await()
    } catch (ie: InterruptedException) {
      Thread.currentThread().interrupt()
      throw IOException("Interrupted while starting LZMA decoder", ie)
    }
    thrown?.let { throw it }
  }

  private fun decodeLoop() {
    try {
      BufferedInputStream(source).use { inBuf ->
        pipeOut.use { out ->
          val props = ByteArray(5)
          readFully(inBuf, props, 0, props.size)
          var outSize = 0L
          repeat(8) { i ->
            val b = inBuf.read()
            if (b < 0) throw IOException("Unexpected EOF reading LZMA size header")
            outSize = outSize or ((b.toLong() and 0xFFL) shl (8 * i))
          }

          val decoder = Decoder()
          if (!decoder.SetDecoderProperties(props)) {
            throw IOException("Invalid LZMA properties")
          }
          // Ready for readers
          started.countDown()

          if (!decoder.Code(inBuf, out, outSize)) {
            throw IOException("LZMA decode error")
          }
          out.flush()
        }
      }
    } catch (ioe: IOException) {
      thrown = ioe
      started.countDown()
      try { pipeOut.close() } catch (_: IOException) {}
    }
  }

  private fun readFully(input: InputStream, buf: ByteArray, off: Int, len: Int) {
    var pos = off
    val end = off + len
    while (pos < end) {
      val r = input.read(buf, pos, end - pos)
      if (r < 0) throw IOException("Unexpected EOF")
      pos += r
    }
  }

  override fun read(): Int {
    thrown?.let { throw it }
    val b = pipeIn.read()
    if (b < 0) thrown?.let { throw it }
    return b
  }

  override fun read(b: ByteArray, off: Int, len: Int): Int {
    thrown?.let { throw it }
    val r = pipeIn.read(b, off, len)
    if (r < 0) thrown?.let { throw it }
    return r
  }

  override fun close() {
    try {
      pipeIn.close()
    } finally {
      source.close()
    }
  }
}

