package network.crypta.support.compress

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.util.stream.Stream
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import org.mockito.ArgumentMatchers.any
import org.mockito.ArgumentMatchers.anyInt
import org.mockito.Mockito.atLeastOnce
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify
import org.mockito.Mockito.`when` as whenever
import org.sevenzip.compression.lzma.Encoder

/**
 * Unit tests for LzmaInputStream in AAA style (JUnit 6 + Mockito).
 *
 * Notes
 * - We build small, deterministic .lzma streams in-memory using the vendored SevenZip Encoder.
 * - Seeds are fixed for reproducibility and to avoid flakiness.
 * - External I/O interactions (close semantics) are verified with Mockito.
 */
class LzmaInputStreamTest {

  // ---------------------------- Helpers ----------------------------

  /**
   * Build a classic .lzma stream: 5-byte properties + 8-byte little-endian uncompressed size +
   * payload.
   *
   * Encoder is configured without an end marker so the decoder relies solely on the known output
   * size.
   */
  private fun buildLzmaStream(data: ByteArray): ByteArray {
    val encoder = Encoder()
    encoder.setEndMarkerMode(false)

    val propsOut = ByteArrayOutputStream()
    encoder.writeCoderProperties(propsOut)
    val props = propsOut.toByteArray()

    val payloadOut = ByteArrayOutputStream()
    encoder.code(ByteArrayInputStream(data), payloadOut, null)
    val payload = payloadOut.toByteArray()

    val combined = ByteArrayOutputStream(props.size + 8 + payload.size)
    // properties
    combined.write(props)
    // 8-byte little-endian uncompressed size
    val size = data.size.toLong()
    repeat(8) { i -> combined.write(((size shr (8 * i)) and 0xFF).toInt()) }
    // payload
    combined.write(payload)
    return combined.toByteArray()
  }

  /** Build only the header (props + size=0) for tests that need a header without payload. */
  private fun buildHeader(): ByteArray {
    val encoder = Encoder()
    val propsOut = ByteArrayOutputStream()
    encoder.writeCoderProperties(propsOut)
    val props = propsOut.toByteArray()
    val header = ByteArrayOutputStream(13)
    header.write(props)
    // Write a zero uncompressed size (8 bytes little-endian)
    repeat(8) { _ -> header.write(0) }
    return header.toByteArray()
  }

  // (removed unused helper per Sonar S1144)

  companion object {
    @JvmStatic
    fun readModes(): Stream<Arguments> =
      Stream.of(Arguments.of("single-byte", true), Arguments.of("buffered", false))
  }

  // ---------------------------- Constructor error paths ----------------------------

  @Test
  fun constructor_whenPropsTooShort_expectIOException() {
    // Arrange: only 4 bytes (needs 5)
    val tooShort = byteArrayOf(0x5D, 0, 0, 0) // 0x5D is a common LZMA props byte (lc=3,lp=0,pb=2)

    // Act + Assert
    val ex =
      assertThrows(IOException::class.java) { LzmaInputStream(ByteArrayInputStream(tooShort)) }
    assertTrue(ex.message!!.contains("Unexpected EOF"))
  }

  @Test
  fun constructor_whenSizeHeaderTruncated_expectIOException() {
    // Arrange: valid 5-byte props, but only 7/8 bytes of the size header
    val props = buildHeader().copyOfRange(0, 5)
    val truncatedSizeHeader =
      ByteArrayOutputStream(12)
        .apply {
          write(props)
          // Write only 7 size bytes instead of 8
          repeat(7) { write(0) }
        }
        .toByteArray()

    // Act + Assert
    val ex =
      assertThrows(IOException::class.java) {
        LzmaInputStream(ByteArrayInputStream(truncatedSizeHeader))
      }
    assertTrue(ex.message!!.contains("Unexpected EOF reading LZMA size header"))
  }

  @Test
  fun constructor_whenInvalidProps_expectIOException() {
    // Arrange: craft 5-byte properties that Decoder.setDecoderProperties(...) rejects.
    // Use a valid lc/lp/pb (0x5D), but set dictionary size to 0xFFFFFFFF which overflows to
    // negative.
    val invalidProps =
      byteArrayOf(0x5D.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())
    val header =
      ByteArrayOutputStream(13)
        .apply {
          write(invalidProps)
          // 8-byte size (any value is fine here)
          repeat(8) { write(0) }
        }
        .toByteArray()

    // Act + Assert
    val ex = assertThrows(IOException::class.java) { LzmaInputStream(ByteArrayInputStream(header)) }
    assertTrue(ex.message!!.contains("Invalid LZMA properties"))
  }

  // ---------------------------- Read success paths ----------------------------

  @ParameterizedTest(name = "read-valid: {0}")
  @MethodSource("readModes")
  fun read_whenValidCompressedStream_expectOriginalBytes(
    @Suppress("UNUSED_PARAMETER") label: String,
    singleByte: Boolean,
  ) {
    // Arrange
    val original = ("hello-lzma-" + "x".repeat(128)).toByteArray(StandardCharsets.UTF_8)
    val streamBytes = buildLzmaStream(original)
    val lis = LzmaInputStream(ByteArrayInputStream(streamBytes))

    // Act
    val out = ByteArrayOutputStream(original.size)
    if (singleByte) {
      while (true) {
        val b = lis.read()
        if (b == -1) break
        out.write(b)
      }
    } else {
      val buf = ByteArray(17) // intentionally odd buffer size
      while (true) {
        val r = lis.read(buf, 0, buf.size)
        if (r == -1) break
        out.write(buf, 0, r)
      }
    }

    // Assert
    assertArrayEquals(original, out.toByteArray())
  }

  @Test
  fun read_whenOutSizeZero_expectEofImmediately() {
    // Arrange: header with uncompressed size = 0, no payload
    val headerOnly = buildHeader()
    val lis = LzmaInputStream(ByteArrayInputStream(headerOnly))

    // Act + Assert: both read paths should immediately return -1
    assertEquals(-1, lis.read())
    val buf = ByteArray(8)
    assertEquals(-1, lis.read(buf, 0, buf.size))
  }

  @Test
  fun read_whenCorruptPayload_expectIOExceptionOrCorruptedOutput() {
    // Arrange: create a valid stream, then flip one byte in the payload
    val original = ("data-" + "q".repeat(2048)).toByteArray(StandardCharsets.UTF_8)
    val good = buildLzmaStream(original)
    // Copy and corrupt one byte past the 13-byte header
    val corrupted = good.copyOf()
    val flipIndex = 13 + (corrupted.size - 13) / 2
    corrupted[flipIndex] = (corrupted[flipIndex].toInt() xor 0xFF).toByte()

    val lis = LzmaInputStream(ByteArrayInputStream(corrupted))

    // Act: try to read all expected bytes; either we get an IOException or corrupted content
    val out = ByteArrayOutputStream(original.size)
    val buf = ByteArray(64)
    try {
      while (true) {
        val r = lis.read(buf)
        if (r == -1) break
        out.write(buf, 0, r)
      }
      val decoded = out.toByteArray()
      // Assert: if no exception, the decoded output should not equal the original
      assertTrue(
        decoded.size != original.size || !decoded.contentEquals(original),
        "Expected corrupted output or shorter read when payload is corrupted",
      )
    } catch (_: IOException) {
      // Expected path for many corruptions: decoder surfaces an error
      assertTrue(true)
    }
  }

  // ---------------------------- Close semantics ----------------------------

  @Test
  fun close_whenCalled_expectUnderlyingClosed() {
    // Arrange
    // Deterministic non-crypto byte pattern (LCG) to avoid Random() and satisfy Sonar rules
    val data =
      ByteArray(1536).also { arr ->
        var state = 42L xor -0x61C8864680B583EBL
        for (i in arr.indices) {
          state = state * 6364136223846793005L + 1
          arr[i] = (state ushr 24).toByte()
        }
      }
    val streamBytes = buildLzmaStream(data)
    val underlying = mock(InputStream::class.java)

    // Delegate spy to a real byte-array stream for read() calls
    val delegate = ByteArrayInputStream(streamBytes)
    // Forward read(byte[], off, len) and read() to the delegate
    whenever(underlying.read(any(), anyInt(), anyInt())).thenAnswer { inv ->
      val b = inv.getArgument<ByteArray>(0)
      val off = inv.getArgument<Int>(1)
      val len = inv.getArgument<Int>(2)
      delegate.read(b, off, len)
    }
    whenever(underlying.read()).thenAnswer { delegate.read() }

    val lis = LzmaInputStream(underlying)
    // Drain the stream to let the worker finish
    val sink = ByteArrayOutputStream()
    val buf = ByteArray(64)
    while (true) {
      val r = lis.read(buf)
      if (r == -1) break
      sink.write(buf, 0, r)
    }

    // Act
    lis.close()

    // Assert: the underlying source must have been closed (by worker and/or close()).
    verify(underlying, atLeastOnce()).close()
    assertArrayEquals(data, sink.toByteArray())
  }
}
