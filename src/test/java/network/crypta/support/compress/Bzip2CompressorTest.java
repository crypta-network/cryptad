package network.crypta.support.compress;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;
import java.util.stream.Stream;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link Bzip2Compressor} in AAA style.
 *
 * <p>Notes: - Uses deterministic Random seeds to avoid flakiness. - Mocks external I/O
 * (BucketFactory/Bucket and InputStream error cases) with Mockito.
 */
class Bzip2CompressorTest {

  private static final Bzip2Compressor compressor = new Bzip2Compressor();

  // ------------------ Helpers ------------------

  private static byte[] repeat(byte value, int n) {
    byte[] arr = new byte[n];
    Arrays.fill(arr, value);
    return arr;
  }

  private static byte[] randomBytes(int n, long seed) {
    byte[] arr = new byte[n];
    new Random(seed).nextBytes(arr);
    return arr;
  }

  private static byte[] compressHeaderless(byte[] data) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    // Use 4-arg overload (no ratio check) for simplicity
    compressor.compress(new ByteArrayInputStream(data), out, data.length, Long.MAX_VALUE);
    return out.toByteArray();
  }

  private static Stream<Arguments> roundTripInputs() {
    return Stream.of(
        Arguments.of((Object) new byte[0]),
        Arguments.of((Object) "hello world".getBytes(StandardCharsets.UTF_8)),
        Arguments.of((Object) repeat((byte) 'A', 10_000)),
        Arguments.of((Object) randomBytes(1_000, 42L)),
        Arguments.of((Object) repeat((byte) 'Z', 32_768)),
        Arguments.of((Object) repeat((byte) 'Y', 32_769)));
  }

  // ------------------ Round-trip ------------------

  @ParameterizedTest(name = "roundTrip[{index}]")
  @MethodSource("roundTripInputs")
  void compressAndDecompress_roundTrip_success(byte[] original) throws Exception {
    // Arrange
    ByteArrayOutputStream compressed = new ByteArrayOutputStream();

    // Act
    long written =
        compressor.compress(
            new ByteArrayInputStream(original),
            compressed,
            Math.max(1, original.length),
            Long.MAX_VALUE);

    // Assert
    assertTrue(written > 0, "Compressed size should be > 0");

    ByteArrayInputStream in = new ByteArrayInputStream(compressed.toByteArray());
    ByteArrayOutputStream out = new ByteArrayOutputStream(original.length);
    long decompressed = compressor.decompress(in, out, original.length, -1);
    assertEquals(original.length, decompressed, "Decompressed length");
    assertArrayEquals(original, out.toByteArray(), "Round-trip content equality");
  }

  // ------------------ compress(InputStream,OutputStream,...) error cases ------------------

  @Test
  void compress_withZeroMaxReadLength_expectIllegalArgumentException() {
    // Arrange
    ByteArrayInputStream in = new ByteArrayInputStream(new byte[0]);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    assertThrows(
        IllegalArgumentException.class,
        () -> compressor.compress(in, out, 0, Long.MAX_VALUE, Long.MAX_VALUE, 0));
  }

  @Test
  void compress_withNullInputStream_expectNullPointerException() {
    // Arrange
    OutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    assertThrows(
        NullPointerException.class, () -> compressor.compress(null, out, 16, Long.MAX_VALUE, 0, 0));
  }

  @Test
  void compress_whenOutputExceedsMaxWriteLength_expectCompressionOutputSizeException() {
    // Arrange
    byte[] data = repeat((byte) 'A', 2_000);
    ByteArrayInputStream in = new ByteArrayInputStream(data);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    assertThrows(
        CompressionOutputSizeException.class, () -> compressor.compress(in, out, data.length, 1));
  }

  @Test
  void compress_whenInputReadReturnsZero_expectIOException() throws IOException {
    // Arrange
    //noinspection resource
    InputStream in = mock(InputStream.class);
    when(in.read(any(byte[].class), anyInt(), anyInt())).thenReturn(0); // force zero-length read
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    IOException ex =
        assertThrows(
            IOException.class, () -> compressor.compress(in, out, 1024, Long.MAX_VALUE, 0, 0));
    assertTrue(ex.getMessage().contains("Returned zero from read"));
  }

  @Test
  void compress_whenMinCompressionRequirementTooHigh_expectCompressionRatioException() {
    // Arrange: random data is effectively incompressible
    byte[] data = randomBytes(65_536, 1234L);
    ByteArrayInputStream in = new ByteArrayInputStream(data);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    long amountToCheckAfter = 32_768; // equals internal buffer size to trigger exactly once
    int minCompressionPercent = 101; // impossible requirement → must fail deterministically

    // Act + Assert
    assertThrows(
        CompressionRatioException.class,
        () ->
            compressor.compress(
                in, out, data.length, Long.MAX_VALUE, amountToCheckAfter, minCompressionPercent));
  }

  // ------------------ decompress(InputStream,OutputStream,...) error cases ------------------

  @Test
  void decompress_whenExceedsMaxLength_noEstimate_expectCompressionOutputSizeException()
      throws Exception {
    // Arrange
    byte[] original = repeat((byte) 'B', 50_000);
    byte[] compressed = compressHeaderless(original);
    ByteArrayInputStream in = new ByteArrayInputStream(compressed);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    CompressionOutputSizeException ex =
        assertThrows(
            CompressionOutputSizeException.class, () -> compressor.decompress(in, out, 1_024, 0));
    assertEquals(-1, ex.estimatedSize, "No estimate when maxCheckSizeBytes == 0");
  }

  @Test
  void decompress_whenExceedsMaxLength_withEstimate_expectCompressionOutputSize() throws Exception {
    // Arrange
    byte[] original = repeat((byte) 'C', 50_000);
    byte[] compressed = compressHeaderless(original);
    ByteArrayInputStream in = new ByteArrayInputStream(compressed);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act + Assert
    CompressionOutputSizeException ex =
        assertThrows(
            CompressionOutputSizeException.class,
            () -> compressor.decompress(in, out, 1_024, 200_000));
    assertEquals(
        50_000, ex.estimatedSize, "Estimated size should reflect actual decompressed length");
  }

  // ------------------ decompress(byte[], ..) ------------------

  @Test
  void decompressByteArray_whenExactSize_expectCorrectData() throws Exception {
    // Arrange
    byte[] original = repeat((byte) 'Q', 8_000);
    byte[] compressed = compressHeaderless(original);
    byte[] out = new byte[original.length];

    // Act
    int written = compressor.decompress(compressed, 0, compressed.length, out);

    // Assert
    assertEquals(original.length, written);
    assertArrayEquals(original, out);
  }

  @Test
  void decompressByteArray_whenOutputBufferTooSmall_expectCompressionOutputSizeException()
      throws Exception {
    // Arrange
    byte[] original = repeat((byte) 'R', 9_000);
    byte[] compressed = compressHeaderless(original);
    byte[] out = new byte[1_000];

    // Act + Assert
    assertThrows(
        CompressionOutputSizeException.class,
        () -> compressor.decompress(compressed, 0, compressed.length, out));
  }

  // ------------------ compress(Bucket, BucketFactory, ...) ------------------

  @Test
  void compressBucket_whenValidStreams_expectBucketWithCompressedData() throws Exception {
    // Arrange
    byte[] original = "bucket-data-hello".getBytes(StandardCharsets.UTF_8);

    Bucket dataBucket = mock(Bucket.class);
    when(dataBucket.getInputStream()).thenReturn(new ByteArrayInputStream(original));

    RandomAccessBucket outputBucket = mock(RandomAccessBucket.class);
    ByteArrayOutputStream capturedOut = new ByteArrayOutputStream();
    // Provide a OutputStream to collect compressed bytes
    when(outputBucket.getOutputStream()).thenReturn(capturedOut);
    // Allow test to later read what was written
    when(outputBucket.getInputStream())
        .thenAnswer(_ -> new ByteArrayInputStream(capturedOut.toByteArray()));

    BucketFactory bf = mock(BucketFactory.class);
    when(bf.makeBucket(anyLong())).thenReturn(outputBucket);

    // Act
    Bucket result = compressor.compress(dataBucket, bf, original.length, Long.MAX_VALUE);

    // Assert
    assertSame(outputBucket, result, "Should return the bucket created by the factory");
    // Verify factory interaction
    //noinspection resource
    verify(bf).makeBucket(Long.MAX_VALUE);
    verify(dataBucket).getInputStream();
    verify(outputBucket).getOutputStream();

    // Decompress to verify content
    ByteArrayInputStream in = new ByteArrayInputStream(capturedOut.toByteArray());
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    long decompressed = compressor.decompress(in, out, original.length, -1);
    assertEquals(original.length, decompressed);
    assertArrayEquals(original, out.toByteArray());
  }
}
