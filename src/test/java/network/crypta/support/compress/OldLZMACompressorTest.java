package network.crypta.support.compress;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ArrayBucketFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;

/**
 * Tests for {@link OldLZMACompressor}.
 *
 * <p>These tests intentionally exercise the legacy behavior retained for reinserting old keys. They
 * verify current invariants without changing production code, and use deterministic inputs to avoid
 * flakiness.
 */
@SuppressWarnings({"java:S1874", "removal"})
class OldLZMACompressorTest {

  private OldLZMACompressor compressor;

  @BeforeEach
  void setUp() {
    compressor = new OldLZMACompressor();
  }

  // Utility: readable, highly compressible content.
  private static byte[] patternedBytes(int repeats) {
    String unit = "The quick brown fox jumps over the lazy dog. ";
    return unit.repeat(Math.max(0, repeats)).getBytes(StandardCharsets.UTF_8);
  }

  @Test
  @DisplayName(
      "compress(InputStream,OutputStream,...) when write limit too small throws"
          + " CompressionOutputSizeException")
  void compress_whenWriteLimitTooSmall_expectCompressionOutputSizeException() {
    // Arrange
    byte[] input = patternedBytes(4);
    ByteArrayInputStream is = new ByteArrayInputStream(input);
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    // Act + Assert
    assertThrows(
        CompressionOutputSizeException.class,
        () ->
            compressor.compress(
                is, os, /* maxReadLength= */ input.length, /* maxWriteLength= */ 0));
    // Ensure the output stream received some data despite the post-check throwing.
    assertTrue(os.toByteArray().length > 0);
  }

  @Test
  @DisplayName("compress(InputStream,OutputStream,...) ignores maxReadLength and reads full input")
  void compress_whenReadLimitLessThanData_expectReadsAllData() throws Exception {
    // Arrange
    byte[] input = patternedBytes(8); // > 0 bytes
    ByteArrayInputStream is = new ByteArrayInputStream(input);
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    // Act
    long written =
        compressor.compress(is, os, /* maxReadLength= */ 10, /* maxWriteLength= */ Long.MAX_VALUE);

    // Assert: decompress using the legacy decoder should round-trip to the full input.
    byte[] compressed = os.toByteArray();
    ByteArrayOutputStream roundtrip = new ByteArrayOutputStream();
    long out =
        compressor.decompress(new ByteArrayInputStream(compressed), roundtrip, Long.MAX_VALUE, -1);

    assertTrue(written > 0);
    assertEquals(input.length, out);
    assertArrayEquals(input, roundtrip.toByteArray());
  }

  @Test
  @DisplayName("compress(Bucket,...) uses BucketFactory and produces decompressible data")
  void compress_withBucket_whenValid_expectFactoryUsedAndDecompressible() throws Exception {
    // Arrange
    byte[] input = patternedBytes(6);

    class CountingBucketFactory implements BucketFactory {
      int calls;
      long lastSize;

      @Override
      public RandomAccessBucket makeBucket(long size) {
        calls++;
        lastSize = size;
        return new ArrayBucket();
      }
    }
    CountingBucketFactory bf = new CountingBucketFactory();

    try (Bucket inBucket = Mockito.mock(Bucket.class)) {
      when(inBucket.getInputStream()).thenReturn(new ByteArrayInputStream(input));
      when(inBucket.size()).thenReturn((long) input.length);
      try (Bucket result = compressor.compress(inBucket, bf, input.length, Long.MAX_VALUE)) {
        // Assert
        assertEquals(1, bf.calls);
        assertEquals(Long.MAX_VALUE, bf.lastSize);
        ByteArrayOutputStream decompressed = new ByteArrayOutputStream();
        try (InputStream ris = result.getInputStream()) {
          compressor.decompress(ris, decompressed, Long.MAX_VALUE, -1);
        }
        assertArrayEquals(input, decompressed.toByteArray());
      }
    }
  }

  @Test
  @DisplayName(
      "compress(InputStream,OutputStream,...) w/ ratio-check overload throws"
          + " UnsupportedEncodingException")
  void compress_extendedOverload_whenCalled_expectUnsupportedEncodingException() {
    // Arrange
    byte[] input = patternedBytes(2);
    ByteArrayInputStream is = new ByteArrayInputStream(input);
    ByteArrayOutputStream os = new ByteArrayOutputStream();

    // Act + Assert
    assertThrows(
        UnsupportedEncodingException.class,
        () ->
            compressor.compress(
                is, os, Long.MAX_VALUE, Long.MAX_VALUE, /* checkAfter= */ 1024L, /* minPct= */ 10));
  }

  @ParameterizedTest
  @ValueSource(ints = {1, 5, 16, 64})
  @DisplayName(
      "decompress(InputStream,OutputStream,...) respects maxLength; output is partial (may"
          + " overshoot)")
  void decompress_whenMaxLengthSmallerThanRealSize_expectPartialOutputPossiblyOvershooting(
      int limit) throws Exception {
    // Arrange: compress some content first using the legacy compressor
    byte[] original = patternedBytes(10);
    ByteArrayOutputStream compressedOut = new ByteArrayOutputStream();
    compressor.compress(
        new ByteArrayInputStream(original), compressedOut, Long.MAX_VALUE, Long.MAX_VALUE);

    ByteArrayInputStream compressedIn = new ByteArrayInputStream(compressedOut.toByteArray());
    ByteArrayOutputStream partial = new ByteArrayOutputStream();

    // Act
    long written = compressor.decompress(compressedIn, partial, limit, -1);

    // Assert: Decoder may overshoot limit by a few bytes because of block copies
    assertTrue(written >= limit, "written should be at least the limit");
    assertTrue(written <= original.length, "written should not exceed original length");
    assertArrayEquals(copyOf(original, (int) written), partial.toByteArray());
  }

  @Test
  @DisplayName("decompress(byte[]) returns full size and exact bytes on valid input")
  void decompress_bytes_whenValidCompressed_expectExactOutputAndCount() throws Exception {
    // Arrange
    byte[] original = patternedBytes(12);
    ByteArrayOutputStream compressed = new ByteArrayOutputStream();
    compressor.compress(
        new ByteArrayInputStream(original), compressed, Long.MAX_VALUE, Long.MAX_VALUE);

    byte[] outBuf = new byte[original.length];

    // Act
    int n = compressor.decompress(compressed.toByteArray(), 0, compressed.size(), outBuf);

    // Assert
    assertEquals(original.length, n);
    assertArrayEquals(original, outBuf);
  }

  @ParameterizedTest
  @ValueSource(ints = {1, 7, 33, 100})
  @DisplayName(
      "decompress(byte[]) with too-small output either truncates or throws (legacy overshoot)")
  void decompress_bytes_whenOutputTooSmall_expectTruncationOrArrayIndexOutOfBounds(int outLen)
      throws Exception {
    // Arrange
    byte[] original = patternedBytes(8);
    ByteArrayOutputStream compressed = new ByteArrayOutputStream();
    compressor.compress(
        new ByteArrayInputStream(original), compressed, Long.MAX_VALUE, Long.MAX_VALUE);

    byte[] outBuf = new byte[outLen];

    // Act: legacy code may either stop at limit or overshoot and throw during arraycopy
    try {
      int n = compressor.decompress(compressed.toByteArray(), 0, compressed.size(), outBuf);
      assertEquals(outLen, n);
      assertArrayEquals(copyOf(original, outLen), outBuf);
    } catch (ArrayIndexOutOfBoundsException _) {
      // Expected for some buffer lengths due to overshoot
    }
  }

  @Test
  @DisplayName("decompress(byte[]) on truncated data throws a runtime exception (legacy behavior)")
  void decompress_bytes_whenInputCorrupted_expectSomeRuntimeException() throws Exception {
    // Arrange: create a valid compressed blob then truncate it to force I/O failure in decoder
    byte[] original = patternedBytes(6);
    ByteArrayOutputStream compressed = new ByteArrayOutputStream();
    compressor.compress(
        new ByteArrayInputStream(original), compressed, Long.MAX_VALUE, Long.MAX_VALUE);
    byte[] corrupt = copyOf(compressed.toByteArray(), 5); // highly likely to be invalid

    byte[] outBuf = new byte[original.length];

    // Act + Assert
    assertThrows(
        RuntimeException.class, () -> compressor.decompress(corrupt, 0, corrupt.length, outBuf));
  }

  @Nested
  @DisplayName("Null and argument edge cases")
  class NullArgTests {
    @Test
    @DisplayName("compress(Bucket,...) with null bucket throws NPE")
    void compress_withNullBucket_expectNullPointerException() {
      // Arrange
      BucketFactory bf = new ArrayBucketFactory();
      // Act + Assert: wrap the AutoCloseable in try-with-resources and ensure non-empty block
      assertThrows(
          NullPointerException.class,
          () -> {
            try (var _ = compressor.compress(null, bf, 0, 0)) {
              fail("Expected NullPointerException");
            }
          });
    }

    @Test
    @DisplayName(
        "compress(InputStream,OutputStream,...) with null InputStream throws ISE from"
            + " CountedInputStream")
    void compress_withNullInputStream_expectIllegalStateException() {
      // Arrange
      OutputStream os = new ByteArrayOutputStream();
      // Act + Assert
      assertThrows(IllegalStateException.class, () -> compressor.compress(null, os, 0, 0));
    }

    @Test
    @DisplayName(
        "decompress(InputStream,OutputStream,...) with null OutputStream throws NPE once data is"
            + " written")
    void decompress_withNullOutputStream_expectNullPointerException() throws Exception {
      // Arrange: create a valid compressed blob so the decoder attempts to write
      byte[] original = patternedBytes(2);
      ByteArrayOutputStream compressed = new ByteArrayOutputStream();
      compressor.compress(
          new ByteArrayInputStream(original), compressed, Long.MAX_VALUE, Long.MAX_VALUE);

      InputStream is = new ByteArrayInputStream(compressed.toByteArray());
      // Act + Assert
      assertThrows(
          NullPointerException.class, () -> compressor.decompress(is, null, Long.MAX_VALUE, -1));
    }
  }

  // Small helper to avoid pulling in java.util.Arrays in assertions and keep intent clear
  private static byte[] copyOf(byte[] src, int newLen) {
    byte[] dst = new byte[newLen];
    System.arraycopy(src, 0, dst, 0, Math.min(src.length, newLen));
    return dst;
  }
}
