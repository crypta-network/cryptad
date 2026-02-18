package network.crypta.support.compress;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.util.Arrays;
import java.util.SplittableRandom;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link NewLZMACompressor} focusing on boundary conditions and invariants.
 *
 * <p>Style: AAA (Arrange-Act-Assert). Randomized inputs use deterministic seeds to avoid flakiness.
 */
class NewLzmaCompressorTest {

  private final NewLZMACompressor compressor = new NewLZMACompressor();
  private static final String PATTERN_ZEROS = "zeros";
  private static final String PATTERN_RANDOM = "random";
  private static final String PATTERN_ONES = "ones";

  // -------------------------------------------------------------------------------------
  // Public API, invariants, and edge cases (from source inspection)
  // -------------------------------------------------------------------------------------
  // Public methods under test:
  // - compress(Bucket, BucketFactory, long, long) [exercised indirectly where applicable]
  // - compress(InputStream, OutputStream, long, long)
  // - compress(InputStream, OutputStream, long, long, long, int)
  // - decompress(InputStream, OutputStream, long, long)
  // - decompress(byte[], int, int, byte[])
  // Invariants and edge cases:
  // - Always writes 5-byte coder properties before compressed data; these count against maxWrite.
  // - Enforces read and write budgets via bounded Counted streams; exceeding read ->
  //   CompressionInputSizeException; exceeding write -> CompressionOutputSizeException.
  // - Dictionary size read from properties (little-endian) must be 0 to MAX_DICTIONARY_SIZE; sizes
  //   beyond MAX_DICTIONARY_SIZE -> TooBigDictionaryException; negative (int overflow) ->
  //   InvalidCompressedDataException.
  // - decompress(byte[], ...) wraps IO failures into UncheckedIOException.

  // -------------------------------------------------------------------------------------
  // Happy-path round-trips (parameterized)
  // -------------------------------------------------------------------------------------

  @ParameterizedTest(name = "roundtrip size={0}, pattern={1}")
  @MethodSource("roundtripInputs")
  @DisplayName("compressDecompress_whenVariousInputs_expectExactRoundTrip")
  void compressDecompress_whenVariousInputs_expectExactRoundTrip(int size, String pattern)
      throws Exception {
    // Arrange
    byte[] original = buildPayload(size, pattern);
    ByteArrayOutputStream compressedOut = new ByteArrayOutputStream();

    // Act
    long written =
        compressor.compress(
            new ByteArrayInputStream(original),
            compressedOut,
            size,
            size + 1024L); // generous cap to avoid output-limit trips

    byte[] compressed = compressedOut.toByteArray();
    assertTrue(written > 0, "Compressed size should be positive");
    ByteArrayOutputStream decompressedOut = new ByteArrayOutputStream(original.length);
    long decompressed =
        compressor.decompress(
            new ByteArrayInputStream(compressed), decompressedOut, original.length, -1);

    // Assert
    assertEquals(original.length, decompressed);
    assertArrayEquals(original, decompressedOut.toByteArray());
  }

  private static Stream<Arguments> roundtripInputs() {
    return Stream.of(
        Arguments.of(0, PATTERN_ZEROS),
        Arguments.of(1, PATTERN_ONES),
        Arguments.of(16, PATTERN_ZEROS),
        Arguments.of(256, PATTERN_RANDOM),
        Arguments.of(1024, PATTERN_RANDOM));
  }

  private static byte[] buildPayload(int size, String pattern) {
    byte[] data = new byte[size];
    return switch (pattern) {
      case PATTERN_ZEROS -> data;
      case PATTERN_ONES -> {
        Arrays.fill(data, (byte) 1);
        yield data;
      }
      case PATTERN_RANDOM -> {
        SplittableRandom r = new SplittableRandom(0xC0FFEE); // deterministic, not java.util.Random
        r.nextBytes(data);
        yield data;
      }
      default -> throw new IllegalArgumentException("unknown pattern: " + pattern);
    };
  }

  // -------------------------------------------------------------------------------------
  // Write budget enforcement
  // -------------------------------------------------------------------------------------

  @Test
  void compress_whenMaxWriteSmallerThanCoderProps_expectCompressionOutputSizeException() {
    // Arrange: any small input; set maxWriteLength smaller than 5 coder properties bytes
    byte[] original = new byte[] {1, 2, 3};
    InputStream in = new ByteArrayInputStream(original);
    OutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    CompressionOutputSizeException ex =
        assertThrows(
            CompressionOutputSizeException.class,
            () -> compressor.compress(in, out, original.length, 4));
    assertEquals(5, ex.estimatedSize);
  }

  // -------------------------------------------------------------------------------------
  // Read budget enforcement
  // -------------------------------------------------------------------------------------

  @Test
  void compress_whenInputExceedsMaxRead_expectCompressionInputSizeException() {
    // Arrange: input is larger than read budget
    byte[] original = buildPayload(256, PATTERN_RANDOM);
    InputStream in = new ByteArrayInputStream(original);
    OutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    CompressionInputSizeException ex =
        assertThrows(
            CompressionInputSizeException.class, () -> compressor.compress(in, out, 128, 1 << 20));
    assertEquals(128, ex.maxAllowed);
  }

  @Test
  void compress_whenInputSizeEqualsMaxRead_expectSuccess() throws Exception {
    // Arrange
    byte[] original = buildPayload(512, PATTERN_ONES);
    InputStream in = new ByteArrayInputStream(original);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    long written = compressor.compress(in, out, original.length, original.length + 4096);

    // Assert
    assertTrue(written >= 5, "At least coder properties must be written");
  }

  // -------------------------------------------------------------------------------------
  // Error propagation with mocked I/O
  // -------------------------------------------------------------------------------------

  @Test
  void compress_whenUnderlyingOutputThrows_expectIOException() throws Exception {
    // Arrange
    byte[] original = buildPayload(64, PATTERN_ZEROS);
    InputStream in = new ByteArrayInputStream(original);
    OutputStream out = mock(OutputStream.class);
    // First write occurs when encoder writes 5-byte coder properties
    doThrow(new IOException("boom")).when(out).write(any(byte[].class), anyInt(), anyInt());

    // Act + Assert
    assertThrows(IOException.class, () -> compressor.compress(in, out, original.length, 1 << 20));
  }

  // -------------------------------------------------------------------------------------
  // Decompression header validation
  // -------------------------------------------------------------------------------------

  @Test
  void decompress_whenDictionaryTooBig_expectTooBigDictionaryException() {
    // Arrange: props[1..4] encode 2MB (0x00200000) > MAX_DICTIONARY_SIZE (1MB)
    byte[] props = new byte[] {(byte) 0x5D, 0x00, 0x00, 0x20, 0x00};
    InputStream in = new ByteArrayInputStream(props);
    OutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    assertThrows(TooBigDictionaryException.class, () -> compressor.decompress(in, out, 10_000, -1));
  }

  @Test
  void decompress_whenDictionarySignBitSet_expectInvalidCompressedDataException() {
    // Arrange: props[1..4] encode 0x80000000 -> negative int when combined
    byte[] props = new byte[] {(byte) 0x5D, 0x00, 0x00, 0x00, (byte) 0x80};
    InputStream in = new ByteArrayInputStream(props);
    OutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    assertThrows(
        InvalidCompressedDataException.class, () -> compressor.decompress(in, out, 10_000, -1));
  }

  @Test
  void decompressByteArray_whenTruncatedProps_expectUncheckedIOException() {
    // Arrange: fewer than 5 property bytes
    byte[] truncated = new byte[] {0x01, 0x02, 0x03, 0x04};
    byte[] outBuf = new byte[16];

    // Act + Assert
    assertThrows(
        UncheckedIOException.class,
        () ->
            Compressor.COMPRESSOR_TYPE.LZMA_NEW.decompress(truncated, 0, truncated.length, outBuf));
  }

  @Test
  void decompress_whenTruncatedPropsViaStreams_expectIOException() {
    // Arrange: fewer than 5 property bytes
    InputStream in = new ByteArrayInputStream(new byte[] {0x01, 0x02, 0x03, 0x04});
    OutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    assertThrows(IOException.class, () -> compressor.decompress(in, out, 1024, -1));
  }

  // -------------------------------------------------------------------------------------
  // Null handling (defensive expectations — NPEs are acceptable contracts here)
  // -------------------------------------------------------------------------------------

  @Test
  void compress_whenNullInput_expectIllegalStateException() {
    OutputStream out = new ByteArrayOutputStream();
    assertThrows(IllegalStateException.class, () -> compressor.compress(null, out, 1, 10));
  }

  @Test
  void compress_whenNullOutput_expectNullPointerException() {
    InputStream in = new ByteArrayInputStream(new byte[] {1});
    assertThrows(NullPointerException.class, () -> compressor.compress(in, null, 1, 10));
  }

  @Test
  void decompress_whenNullInput_expectNullPointerException() {
    OutputStream out = new ByteArrayOutputStream();
    assertThrows(NullPointerException.class, () -> compressor.decompress(null, out, 1, -1));
  }
}
