package network.crypta.support.compress;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.stream.Stream;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentMatchers;
import org.mockito.InOrder;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Additional and edge-case tests for {@link GzipCompressor}.
 *
 * <p>Style: AAA (Arrange, Act, Assert). Deterministic inputs only.
 */
class GzipCompressorAdvancedTest {

  // Deterministic RNG for any random data in tests.
  private static final long SEED = 0xC0FFEE_1234ABCDL;

  private static byte[] randomBytes(int size) {
    byte[] data = new byte[size];
    SecureRandom sr = new SecureRandom();
    sr.setSeed(SEED + size); // deterministic for tests
    sr.nextBytes(data);
    return data;
  }

  // -----------------------
  // Public API enumeration
  // -----------------------
  @Test
  @DisplayName("compress(InputStream,…, ratio-check) throws on negative maxReadLength")
  void compress_whenMaxReadLengthNegative_throwsIllegalArgumentException() {
    // Arrange
    GzipCompressor gzip = new GzipCompressor();
    InputStream in = new ByteArrayInputStream(new byte[0]);
    OutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> gzip.compress(in, out, -1, Long.MAX_VALUE, Long.MAX_VALUE, 0));
  }

  @Test
  @DisplayName("compress(InputStream,…) fails fast when InputStream.read() returns 0")
  void compress_whenInputReturnsZero_throwIOException() throws Exception {
    // Arrange
    GzipCompressor gzip = new GzipCompressor();
    try (InputStream in = mock(InputStream.class)) {
      OutputStream out = new ByteArrayOutputStream();
      when(in.read(
              ArgumentMatchers.any(byte[].class),
              ArgumentMatchers.anyInt(),
              ArgumentMatchers.anyInt()))
          .thenReturn(0);

      // Act + Assert
      assertThrows(
          IOException.class,
          () -> gzip.compress(in, out, 32 * 1024L, Long.MAX_VALUE, Long.MAX_VALUE, 0));
    }
  }

  @Test
  @DisplayName("compress(InputStream,…) enforces maxWriteLength even for empty input (header)")
  void compress_whenMaxWriteLengthTooSmallForHeader_throwsCompressionOutputSizeException() {
    // Arrange
    GzipCompressor gzip = new GzipCompressor();
    InputStream in = new ByteArrayInputStream(new byte[0]);
    OutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    assertThrows(
        CompressionOutputSizeException.class,
        () -> gzip.compress(in, out, 0, 1, Long.MAX_VALUE, 0));
  }

  @Test
  @DisplayName("compress(InputStream,…) ratio-check triggers and throws when minimum=100%")
  void compress_whenRatioCheckTriggers_failsWithCompressionRatioException() {
    // Arrange
    GzipCompressor gzip = new GzipCompressor();
    byte[] raw = randomBytes(32 * 1024); // exactly one internal buffer
    InputStream in = new ByteArrayInputStream(raw);
    OutputStream out = new ByteArrayOutputStream();

    long amountToCheck = 32 * 1024L; // check after first iteration
    int minPercent = 100; // impossible to achieve => guaranteed failure

    // Act + Assert
    assertThrows(
        CompressionRatioException.class,
        () -> gzip.compress(in, out, raw.length, Long.MAX_VALUE, amountToCheck, minPercent));
  }

  @Test
  @DisplayName("compress(Bucket,…) sets GZIP header OS byte (offset 9) to 0 and closes streams")
  void compress_whenUsingBucket_headerOsByteIsZero_andStreamsClosed() throws Exception {
    // Arrange
    GzipCompressor gzip = new GzipCompressor();

    // Mock input bucket returning a spy InputStream so we can assert close() was called.
    Bucket inputBucket = mock(Bucket.class);
    ByteArrayInputStream rawIn =
        spy(new ByteArrayInputStream("hello world".getBytes(StandardCharsets.UTF_8)));
    when(inputBucket.getInputStream()).thenReturn(rawIn);

    // Mock factory + output bucket whose OutputStream we can inspect and verify close() on.
    BucketFactory factory = mock(BucketFactory.class);
    RandomAccessBucket outputBucket = mock(RandomAccessBucket.class);
    ByteArrayOutputStream outputOs = spy(new ByteArrayOutputStream());
    when(factory.makeBucket(anyLong())).thenReturn(outputBucket);
    when(outputBucket.getOutputStream()).thenReturn(outputOs);

    // Act
    Bucket returned = gzip.compress(inputBucket, factory, 64 * 1024L, Long.MAX_VALUE);

    // Assert
    assertSame(outputBucket, returned, "compress() must return the output bucket instance");
    byte[] gz = outputOs.toByteArray();
    assertThat("GZIP header must be at least 10 bytes", gz.length, greaterThanOrEqualTo(10));
    assertEquals(0, gz[9] & 0xFF, "GZIP OS byte (offset 9) must be forced to 0");

    // Verify resource handling (try-with-resources closes both streams)
    InOrder order = inOrder(inputBucket, outputBucket, rawIn, outputOs);
    order.verify(inputBucket).getInputStream();
    order.verify(outputBucket).getOutputStream();
    verify(rawIn, atLeastOnce()).close();
    verify(outputOs, atLeastOnce()).close();
  }

  @Test
  @DisplayName("compress(InputStream,…) respects maxReadLength and truncates input")
  void compress_whenMaxReadLengthLessThanInput_truncatesToMax() throws Exception {
    // Arrange
    GzipCompressor gzip = new GzipCompressor();
    byte[] raw = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8); // 26 bytes
    int readLimit = 13; // Half
    InputStream in = new ByteArrayInputStream(raw);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    long written = gzip.compress(in, out, readLimit, Long.MAX_VALUE, Long.MAX_VALUE, 0);

    // Assert (decompress and compare only the prefix up to readLimit)
    byte[] compressed = out.toByteArray();
    ByteArrayOutputStream decompressed = new ByteArrayOutputStream();
    Compressor.COMPRESSOR_TYPE.GZIP.decompress(
        new ByteArrayInputStream(compressed), decompressed, readLimit, -1);
    assertEquals(readLimit, decompressed.size());
    assertArrayEquals(
        Arrays.copyOfRange(raw, 0, readLimit),
        decompressed.toByteArray(),
        "Decompressed data must match the truncated input prefix");
    assertTrue(written > 0, "Some bytes must be written even for small inputs (header+footer)");
  }

  @Test
  @DisplayName("decompress(InputStream,…) returns written bytes and flushes output on EOF")
  void decompress_whenExactLimit_succeedsAndFlushesOutput() throws Exception {
    // Arrange
    byte[] raw = randomBytes(2048);
    // Encode using streams to avoid coupling to a particular Bucket implementation
    ByteArrayOutputStream compressedOs = new ByteArrayOutputStream();
    new GzipCompressor()
        .compress(
            new ByteArrayInputStream(raw),
            compressedOs,
            raw.length,
            Long.MAX_VALUE,
            Long.MAX_VALUE,
            0);
    byte[] compressed = compressedOs.toByteArray();

    OutputStream spyOut = spy(new ByteArrayOutputStream());

    // Act
    long written =
        Compressor.COMPRESSOR_TYPE.GZIP.decompress(
            new ByteArrayInputStream(compressed), spyOut, raw.length, -1);

    // Assert
    assertEquals(raw.length, written, "All bytes must be produced when within limit");
    verify(spyOut, atLeastOnce()).flush();
  }

  @Test
  @DisplayName(
      "decompress(InputStream,…) throws with estimated size when limit exceeded and estimate"
          + " enabled")
  void decompress_whenOutputLimitExceededAndEstimateRequested_throwsAndReportsEstimatedSize()
      throws Exception {
    // Arrange
    byte[] raw = new byte[5 * 1024];
    Arrays.fill(raw, (byte) 1);
    ByteArrayOutputStream compressedOs = new ByteArrayOutputStream();
    new GzipCompressor()
        .compress(
            new ByteArrayInputStream(raw),
            compressedOs,
            raw.length,
            Long.MAX_VALUE,
            Long.MAX_VALUE,
            0);
    byte[] compressed = compressedOs.toByteArray();

    // Act + Assert
    CompressionOutputSizeException ex =
        assertThrows(
            CompressionOutputSizeException.class,
            () ->
                Compressor.COMPRESSOR_TYPE.GZIP.decompress(
                    new ByteArrayInputStream(compressed), new ByteArrayOutputStream(), 4096, 8192));
    assertEquals(5 * 1024L, ex.estimatedSize, "Estimated size should equal full uncompressed size");
  }

  @Test
  @DisplayName(
      "decompress(InputStream,…) throws without estimated size when limit exceeded and estimate"
          + " disabled")
  void decompress_whenOutputLimitExceededAndNoEstimate_throwsWithoutEstimatedSize()
      throws Exception {
    // Arrange
    byte[] raw = randomBytes(4097);
    ByteArrayOutputStream compressedOs = new ByteArrayOutputStream();
    new GzipCompressor()
        .compress(
            new ByteArrayInputStream(raw),
            compressedOs,
            raw.length,
            Long.MAX_VALUE,
            Long.MAX_VALUE,
            0);
    byte[] compressed = compressedOs.toByteArray();

    // Act + Assert
    CompressionOutputSizeException ex =
        assertThrows(
            CompressionOutputSizeException.class,
            () ->
                Compressor.COMPRESSOR_TYPE.GZIP.decompress(
                    new ByteArrayInputStream(compressed), new ByteArrayOutputStream(), 1024, -1));
    assertEquals(-1L, ex.estimatedSize, "Estimated size must be -1 when not computed");
  }

  // -----------------------
  // Parameterized round-trip
  // -----------------------
  static Stream<Integer> roundTripSizes() {
    return Stream.of(0, 1, 2, 31, 32, 33, 100, 1024, 32767, 32768, 32769, 65536 + 13);
  }

  @ParameterizedTest(name = "roundTrip size={0}")
  @MethodSource("roundTripSizes")
  void roundTrip_withVariousSizes_expectIdenticalData(int size) throws Exception {
    // Arrange
    byte[] raw = randomBytes(size);
    ByteArrayOutputStream compressed = new ByteArrayOutputStream();
    GzipCompressor gzip = new GzipCompressor();

    // Act
    gzip.compress(
        new ByteArrayInputStream(raw), compressed, size, Long.MAX_VALUE, Long.MAX_VALUE, 0);

    ByteArrayOutputStream out = new ByteArrayOutputStream(size);
    Compressor.COMPRESSOR_TYPE.GZIP.decompress(
        new ByteArrayInputStream(compressed.toByteArray()), out, size, -1);

    // Assert
    assertArrayEquals(raw, out.toByteArray());
  }

  // -----------------------
  // Byte-array API edge cases
  // -----------------------
  static Stream<Integer> smallerOutputs() {
    return Stream.of(512, 1024, 2048);
  }

  @ParameterizedTest(name = "decompress(byte[]) with outputSize={0} < actual")
  @MethodSource("smallerOutputs")
  void decompressByteArray_whenOutputTooSmall_expectErrorWrappingCompressionOutputSizeException(
      int outputSize) throws Exception {
    // Arrange
    byte[] raw = new byte[4096];
    for (int i = 0; i < raw.length; i++) raw[i] = (byte) (i & 0xFF);
    ByteArrayOutputStream compressedOs = new ByteArrayOutputStream();
    new GzipCompressor()
        .compress(
            new ByteArrayInputStream(raw),
            compressedOs,
            raw.length,
            Long.MAX_VALUE,
            Long.MAX_VALUE,
            0);
    byte[] compressed = compressedOs.toByteArray();

    byte[] tooSmall = new byte[outputSize];

    // Act + Assert: the byte[] overload wraps IOExceptions into Error
    Error err =
        assertThrows(
            Error.class,
            () ->
                Compressor.COMPRESSOR_TYPE.GZIP.decompress(
                    compressed, 0, compressed.length, tooSmall));
    assertThat(err.getCause(), instanceOf(CompressionOutputSizeException.class));
  }

  @Test
  @DisplayName("decompress(byte[], off,len, out) honors input offset and length")
  void decompressByteArray_whenOffsetAndLengthUsed_readsCorrectSegment() throws Exception {
    // Arrange
    byte[] raw = "Quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);
    ByteArrayOutputStream fullCompressed = new ByteArrayOutputStream();
    new GzipCompressor()
        .compress(
            new ByteArrayInputStream(raw),
            fullCompressed,
            raw.length,
            Long.MAX_VALUE,
            Long.MAX_VALUE,
            0);
    byte[] c = fullCompressed.toByteArray();
    // place compressed data at an offset inside a larger array
    byte[] container = new byte[c.length + 10];
    System.arraycopy(c, 0, container, 5, c.length);
    byte[] out = new byte[raw.length];

    // Act
    int written = Compressor.COMPRESSOR_TYPE.GZIP.decompress(container, 5, c.length, out);

    // Assert
    assertEquals(raw.length, written);
    assertArrayEquals(raw, out);
  }
}
