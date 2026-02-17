package network.crypta.support.io;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.stream.Stream;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings({"java:S100", "java:S2245"})
class PaddedEphemerallyEncryptedBucketTest {

  private static void ignoreInt(int ignored) {}

  private static int invalidNegativeOffset() {
    return -Math.abs(System.identityHashCode(new Object()) | 1);
  }

  private static int outOfBoundsLength(byte[] buffer) {
    return buffer.length + Math.max(1, Math.abs(System.identityHashCode(buffer) % 5));
  }

  private static RandomSource strong(long seed) {
    return new DummyRandomSource(seed);
  }

  private static Random weak(long seed) {
    return new Random(seed);
  }

  @Test
  @DisplayName("constructor_whenUnderlyingNotEmpty_expectIllegalArgumentException")
  void constructor_whenUnderlyingNotEmpty_expectIllegalArgumentException() {
    // Arrange
    try (ArrayBucket underlying = new ArrayBucket(new byte[] {1})) {
      // Prepare inputs outside the lambda to keep a single throwing call inside it
      RandomSource strong = strong(1L);
      Random weak = weak(2L);
      // Act + Assert
      assertThrows(
          IllegalArgumentException.class,
          () -> new PaddedEphemerallyEncryptedBucket(underlying, 16, strong, weak));
    }
  }

  @ParameterizedTest(name = "paddedLength({0}, min={1}) -> {2}")
  @MethodSource("paddedCases")
  @DisplayName("paddedLength_variousInputs_expectNextPowerOfTwoAtLeastMin")
  void paddedLength_variousInputs_expectNextPowerOfTwoAtLeastMin(
      long dataLen, long min, long expected) {
    // Act
    long actual = PaddedEphemerallyEncryptedBucket.paddedLength(dataLen, min);
    // Assert
    assertEquals(expected, actual);
  }

  private static Stream<Arguments> paddedCases() {
    return Stream.of(
        Arguments.of(0L, 16L, 16L),
        Arguments.of(1L, 16L, 16L),
        Arguments.of(16L, 16L, 16L),
        Arguments.of(17L, 16L, 32L),
        Arguments.of(31L, 16L, 32L),
        Arguments.of(32L, 16L, 32L),
        Arguments.of(33L, 16L, 64L),
        Arguments.of(1024L, 1024L, 1024L),
        Arguments.of(1025L, 1024L, 2048L));
  }

  @Test
  @DisplayName("writeRead_whenSmallDataLessThanMin_expectDecryptedMatchesAndUnderlyingPaddedSize")
  void writeRead_whenSmallDataLessThanMin_expectDecryptedMatchesAndUnderlyingPaddedSize()
      throws Exception {
    // Arrange
    int min = 64;
    ArrayBucket underlying = new ArrayBucket("underlying");
    PaddedEphemerallyEncryptedBucket enc =
        new PaddedEphemerallyEncryptedBucket(underlying, min, strong(1234L), weak(5678L));
    byte[] plain = "hello".getBytes(StandardCharsets.UTF_8);

    // Act
    try (OutputStream os = enc.getOutputStream()) {
      os.write(plain);
    }

    // Assert: logical size is plaintext length
    assertEquals(plain.length, enc.size());
    // Assert: underlying size is padded length
    assertEquals(
        PaddedEphemerallyEncryptedBucket.paddedLength(plain.length, min), underlying.size());

    // And decryption yields the original
    byte[] out = new byte[plain.length];
    try (InputStream is = enc.getInputStream()) {
      assertEquals(plain.length, is.read(out));
      assertEquals(-1, is.read());
    }
    assertArrayEquals(plain, out);
  }

  @Test
  @DisplayName("writeRead_whenDataExactlyMin_expectUnderlyingSizeEqualsMin")
  void writeRead_whenDataExactlyMin_expectUnderlyingSizeEqualsMin() throws Exception {
    // Arrange
    int min = 32;
    ArrayBucket underlying = new ArrayBucket();
    PaddedEphemerallyEncryptedBucket enc =
        new PaddedEphemerallyEncryptedBucket(underlying, min, strong(1L), weak(2L));
    byte[] plain = new byte[min];
    for (int i = 0; i < plain.length; i++) plain[i] = (byte) i;

    // Act
    try (OutputStream os = enc.getOutputStreamUnbuffered()) {
      os.write(plain);
    }

    // Assert
    assertEquals(min, underlying.size());
    // Roundtrip
    try (InputStream is = enc.getInputStream()) {
      byte[] got = is.readAllBytes();
      assertArrayEquals(plain, got);
    }
  }

  @Test
  @DisplayName("writeRead_whenBetweenMinAndDouble_expectUnderlyingSizeEqualsDoubleMin")
  void writeRead_whenBetweenMinAndDouble_expectUnderlyingSizeEqualsDoubleMin() throws Exception {
    // Arrange
    int min = 32;
    ArrayBucket underlying = new ArrayBucket();
    PaddedEphemerallyEncryptedBucket enc =
        new PaddedEphemerallyEncryptedBucket(underlying, min, strong(9L), weak(10L));
    byte[] plain = new byte[min + 1];
    for (int i = 0; i < plain.length; i++) plain[i] = (byte) (i * 7);

    // Act
    try (OutputStream os = enc.getOutputStreamUnbuffered()) {
      os.write(plain);
    }

    // Assert
    assertEquals(min * 2L, underlying.size());
    try (InputStream is = enc.getInputStream()) {
      assertArrayEquals(plain, is.readAllBytes());
    }
  }

  @Test
  @DisplayName("getOutputStreamUnbuffered_whenReadOnly_expectIOException")
  void getOutputStreamUnbuffered_whenReadOnly_expectIOException() {
    // Arrange
    PaddedEphemerallyEncryptedBucket enc =
        new PaddedEphemerallyEncryptedBucket(new ArrayBucket(), 16, strong(5L), weak(6L));
    enc.setReadOnly();
    // Act + Assert
    assertThrows(IOException.class, enc::getOutputStreamUnbuffered);
  }

  @Test
  @DisplayName("write_whenOldStream_expectIllegalStateException")
  void write_whenOldStream_expectIllegalStateException() throws Exception {
    // Arrange
    PaddedEphemerallyEncryptedBucket enc =
        new PaddedEphemerallyEncryptedBucket(new ArrayBucket(), 16, strong(11L), weak(12L));
    OutputStream os1 = enc.getOutputStreamUnbuffered();
    OutputStream os2 = enc.getOutputStreamUnbuffered();

    // Act + Assert
    assertThrows(IllegalStateException.class, () -> os1.write(1));

    // Cleanup
    os2.close();
  }

  @Test
  @DisplayName("inputStream_availableAndReadBoundaries_whenSequentialReads_expectCorrectBehaviour")
  void inputStream_availableAndReadBoundaries_whenSequentialReads_expectCorrectBehaviour()
      throws Exception {
    // Arrange
    ArrayBucket underlying = new ArrayBucket();
    PaddedEphemerallyEncryptedBucket enc =
        new PaddedEphemerallyEncryptedBucket(underlying, 64, strong(42L), weak(43L));
    byte[] data = new byte[100];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i ^ 0x5A);
    try (OutputStream os = enc.getOutputStream()) {
      os.write(data);
    }

    // Act
    try (InputStream is = enc.getInputStreamUnbuffered()) {
      assertEquals(100, is.available());
      byte[] buf = new byte[30];
      assertEquals(30, is.read(buf));
      assertEquals(70, is.available());
      // Invalid bounds
      int invalidOffset = invalidNegativeOffset();
      int invalidLength = outOfBoundsLength(buf);
      assertThrows(
          ArrayIndexOutOfBoundsException.class, () -> ignoreInt(is.read(buf, invalidOffset, 1)));
      assertThrows(
          ArrayIndexOutOfBoundsException.class, () -> ignoreInt(is.read(buf, 0, invalidLength)));

      // Read rest
      byte[] rest = is.readAllBytes();
      assertEquals(70, rest.length);
      // End of stream
      assertEquals(-1, is.read());
    }
  }

  @Test
  @DisplayName("skip_whenSkippingAcrossStream_expectExpectedCount")
  void skip_whenSkippingAcrossStream_expectExpectedCount() throws Exception {
    // Arrange
    PaddedEphemerallyEncryptedBucket enc =
        new PaddedEphemerallyEncryptedBucket(new ArrayBucket(), 64, strong(100L), weak(200L));
    byte[] data = new byte[150];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i + 1);
    try (OutputStream os = enc.getOutputStream()) {
      os.write(data);
    }
    try (InputStream is = enc.getInputStream()) {
      // Act + Assert
      assertEquals(120, is.skip(120));
      assertEquals(30, is.skip(1000)); // cannot skip past end
      assertEquals(-1, is.read());
    }
  }

  @Test
  @DisplayName("getName_whenCalled_expectEncryptedPrefix")
  void getName_whenCalled_expectEncryptedPrefix() {
    // Arrange
    ArrayBucket underlying = new ArrayBucket("myBucket");
    PaddedEphemerallyEncryptedBucket enc =
        new PaddedEphemerallyEncryptedBucket(underlying, 16, strong(1L), weak(2L));
    // Act + Assert
    assertThat(enc.getName(), is("Encrypted:" + underlying.getName()));
  }

  @Test
  @DisplayName("free_whenCalled_expectDelegatesToUnderlying")
  void free_whenCalled_expectDelegatesToUnderlying() {
    // Arrange
    Bucket underlying = mock(Bucket.class);
    when(underlying.size()).thenReturn(0L);
    PaddedEphemerallyEncryptedBucket enc =
        new PaddedEphemerallyEncryptedBucket(underlying, 16, strong(3L), weak(4L));
    // Act
    enc.free();
    // Assert
    verify(underlying, times(1)).free();
  }

  @Test
  @DisplayName("createShadow_whenUnderlyingReturnsNull_expectNull")
  void createShadow_whenUnderlyingReturnsNull_expectNull() {
    // Arrange
    Bucket underlying = mock(Bucket.class);
    when(underlying.size()).thenReturn(0L);
    when(underlying.createShadow()).thenReturn(null);
    PaddedEphemerallyEncryptedBucket enc =
        new PaddedEphemerallyEncryptedBucket(underlying, 16, strong(7L), weak(8L));
    // Act + Assert
    assertNull(enc.createShadow());
  }

  @Test
  @DisplayName("createShadow_whenUnderlyingReturnsBucket_expectReadOnlyEncryptedWrapper")
  void createShadow_whenUnderlyingReturnsBucket_expectReadOnlyEncryptedWrapper() {
    // Arrange
    ArrayBucket newUnderlying = new ArrayBucket("shadow");
    Bucket underlying = mock(Bucket.class);
    when(underlying.size()).thenReturn(0L);
    when(underlying.createShadow()).thenReturn(newUnderlying);
    PaddedEphemerallyEncryptedBucket enc =
        new PaddedEphemerallyEncryptedBucket(underlying, 32, strong(17L), weak(18L));
    // Act
    Bucket shadow = enc.createShadow();
    // Assert
    assertNotNull(shadow);
    assertInstanceOf(PaddedEphemerallyEncryptedBucket.class, shadow);
    PaddedEphemerallyEncryptedBucket shadowEnc = (PaddedEphemerallyEncryptedBucket) shadow;
    assertSame(newUnderlying, shadowEnc.getUnderlying());
    assertTrue(shadowEnc.isReadOnly());
    assertEquals(0, shadowEnc.size());
  }

  @Test
  @DisplayName("storeTo_whenCalled_expectHeaderKeyIvAndDelegation")
  void storeTo_whenCalled_expectHeaderKeyIvAndDelegation() throws Exception {
    // Arrange: write some data using a real underlying bucket
    ArrayBucket realUnderlying = new ArrayBucket();
    PaddedEphemerallyEncryptedBucket original =
        new PaddedEphemerallyEncryptedBucket(realUnderlying, 64, strong(99L), weak(100L));
    try (OutputStream os = original.getOutputStream()) {
      os.write(new byte[] {1, 2, 3});
    }

    // Create a copy that targets a mock for serialization
    Bucket mockUnderlying = mock(Bucket.class);
    when(mockUnderlying.size()).thenReturn(0L);
    PaddedEphemerallyEncryptedBucket toStore =
        new PaddedEphemerallyEncryptedBucket(original, mockUnderlying);
    toStore.setReadOnly();

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(baos);

    // Act
    toStore.storeTo(dos);

    // Assert: underlying.storeTo called at end
    verify(mockUnderlying, times(1))
        .storeTo(org.mockito.ArgumentMatchers.any(DataOutputStream.class));

    // Parse the written header
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
    assertEquals(PaddedEphemerallyEncryptedBucket.MAGIC, dis.readInt());
    assertEquals(1, dis.readInt()); // VERSION
    assertEquals(64, dis.readInt()); // minPaddedSize
    byte[] key = new byte[32];
    dis.readFully(key);
    assertThat(key, notNullValue());
    assertTrue(dis.readBoolean());
    byte[] iv = new byte[32];
    dis.readFully(iv);
    assertThat(iv, notNullValue());
    assertEquals(3L, dis.readLong());
    assertTrue(dis.readBoolean()); // readOnly
  }

  // onResume() touches a public final field on ClientContext; its behavior is indirectly
  // exercised by other tests and by verifying serialization paths.

  @Test
  @DisplayName("getOutputStream_writeZeroLength_expectNoChangeInSize")
  void getOutputStream_writeZeroLength_expectNoChangeInSize() throws Exception {
    // Arrange
    ArrayBucket underlying = new ArrayBucket();
    PaddedEphemerallyEncryptedBucket enc =
        new PaddedEphemerallyEncryptedBucket(underlying, 32, strong(5L), weak(6L));
    // Act
    try (OutputStream os = enc.getOutputStreamUnbuffered()) {
      os.write(new byte[0]);
    }
    // Assert
    assertEquals(0L, enc.size());
    assertEquals(PaddedEphemerallyEncryptedBucket.paddedLength(0, 32), underlying.size());
  }
}
