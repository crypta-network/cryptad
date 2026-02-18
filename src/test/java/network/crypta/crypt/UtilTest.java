package network.crypta.crypt;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import java.util.stream.Stream;
import network.crypta.support.Fields;
import network.crypta.support.math.MersenneTwister;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class UtilTest {

  // ----- Helpers for parameterized inputs -----

  private static Stream<Arguments> bigIntegers() {
    return Stream.of(
        Arguments.of(BigInteger.ZERO),
        Arguments.of(BigInteger.ONE),
        Arguments.of(new BigInteger("ff", 16)), // 255
        Arguments.of(new BigInteger("100", 16)), // 256
        Arguments.of(new BigInteger("ffff", 16)), // 65535
        Arguments.of(BigInteger.ONE.shiftLeft(127)),
        Arguments.of(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)));
  }

  // ----- fillByteArrayFrom[Ints|Longs] -----

  @Test
  @DisplayName("fillByteArrayFromInts_whenBigEndian_expectCorrectBytes")
  void fillByteArrayFromInts_whenBigEndian_expectCorrectBytes() {
    int[] ints = {0x01020304, 0xA0B0C0D0, -1};
    byte[] out = new byte[ints.length * 4];

    // Act
    Util.fillByteArrayFromInts(ints, out);

    // Assert (big-endian per int)
    assertArrayEquals(
        new byte[] {
          0x01,
          0x02,
          0x03,
          0x04,
          (byte) 0xA0,
          (byte) 0xB0,
          (byte) 0xC0,
          (byte) 0xD0,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF
        },
        out);
  }

  @Test
  @DisplayName("fillByteArrayFromLongs_whenBigEndian_expectCorrectBytes")
  void fillByteArrayFromLongs_whenBigEndian_expectCorrectBytes() {
    long[] longs = {0x0102030405060708L, -1L};
    byte[] out = new byte[longs.length * 8];

    // Act
    Util.fillByteArrayFromLongs(longs, out);

    // Assert
    assertArrayEquals(
        new byte[] {
          0x01,
          0x02,
          0x03,
          0x04,
          0x05,
          0x06,
          0x07,
          0x08,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF,
          (byte) 0xFF
        },
        out);
  }

  // ----- MPI encode/decode -----

  @ParameterizedTest
  @MethodSource("bigIntegers")
  @DisplayName("MPIbytes_and_readMPI_whenRoundTrip_preserveValue")
  void MPIbytes_and_readMPI_whenRoundTrip_preserveValue(BigInteger value) throws IOException {
    // Arrange
    byte[] mpi = Util.mpiBytes(value);

    // Sanity: first two bytes encode bit length.
    int bitLen = value.bitLength();
    assertEquals((byte) (bitLen >>> 8), mpi[0]);
    assertEquals((byte) bitLen, mpi[1]);

    // Act
    BigInteger decoded = Util.readMPI(new ByteArrayInputStream(mpi));

    // Assert
    assertEquals(value, decoded);
  }

  @Test
  @DisplayName("readMPI_whenEOF_throwsEOFException")
  void readMPI_whenEOF_throwsEOFException() {
    assertThrows(EOFException.class, () -> Util.readMPI(new ByteArrayInputStream(new byte[0])));
  }

  @Test
  @DisplayName("writeMPI_whenEncoded_canBeReadBack")
  void writeMPI_whenEncoded_canBeReadBack() throws IOException {
    // Arrange
    BigInteger value = new BigInteger("123456789ABCDEF", 16);
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    // Act
    Util.writeMPI(value, out);
    BigInteger decoded = Util.readMPI(new ByteArrayInputStream(out.toByteArray()));

    // Assert
    assertEquals(value, decoded);
  }

  // ----- hashBytes / hashString -----

  @Test
  @DisplayName("hashBytes_whenOffsetAndLength_matchesDirectDigest")
  void hashBytes_whenOffsetAndLength_matchesDirectDigest() throws Exception {
    // Arrange
    byte[] data = "hello world".getBytes(StandardCharsets.UTF_8);
    int offset = 0;
    int length = 5; // "hello"
    MessageDigest a = MessageDigest.getInstance("SHA-256");
    MessageDigest b = MessageDigest.getInstance("SHA-256");

    // Act
    byte[] viaUtil = Util.hashBytes(a, data, offset, length);
    b.update(data, offset, length);
    byte[] direct = b.digest();

    // Assert
    assertArrayEquals(direct, viaUtil);
  }

  @Test
  @DisplayName("hashString_whenUtf8_matchesHashOfUtf8Bytes")
  void hashString_whenUtf8_matchesHashOfUtf8Bytes() throws Exception {
    // Arrange
    String text = "Grüße – 你好"; // includes non-ASCII characters
    MessageDigest d1 = MessageDigest.getInstance("SHA-256");
    MessageDigest d2 = MessageDigest.getInstance("SHA-256");

    // Act
    byte[] fromString = Util.hashString(d1, text);
    byte[] fromBytes = Util.hashBytes(d2, text.getBytes(StandardCharsets.UTF_8));

    // Assert
    assertArrayEquals(fromBytes, fromString);
  }

  // ----- xor -----

  @Test
  @DisplayName("xor_whenSameLength_returnsElementwiseXor")
  void xor_whenSameLength_returnsElementwiseXor() {
    // Arrange
    byte[] a = {1, 2, 3, 4};
    byte[] b = {5, 6, 7, 8};

    // Act
    byte[] out = Util.xor(a, b);

    // Assert
    assertArrayEquals(new byte[] {4, 4, 4, 12}, out);
  }

  @Test
  @DisplayName("xor_whenDifferentLengths_resultSizeIsMaxAndTailZeroed")
  void xor_whenDifferentLengths_resultSizeIsMaxAndTailZeroed() {
    // Arrange
    byte[] a = {1, 2, 3, 4};
    byte[] b = {5, 6};

    // Act
    byte[] out = Util.xor(a, b);

    // Assert: first min length are XORed; remaining bytes are zero
    assertArrayEquals(new byte[] {4, 4, 0, 0}, out);
  }

  // ----- randomBytes(Random/SecureRandom) -----

  @Test
  @DisplayName("randomBytes_withRandomFullRange_equalsNextBytes")
  void randomBytes_withRandomFullRange_equalsNextBytes() {
    // Arrange
    int seed = 12345;
    Random r1 = new Random(seed);
    Random r2 = new Random(seed);
    byte[] got = new byte[32];
    byte[] expected = new byte[32];

    // Act
    Util.randomBytes(r1, got); // full buffer path
    r2.nextBytes(expected);

    // Assert
    assertArrayEquals(expected, got);
  }

  @Test
  @DisplayName("randomBytes_withRandomSubrange_matchesNextBytesOfSubrange")
  void randomBytes_withRandomSubrange_matchesNextBytesOfSubrange() {
    // Arrange
    int seed = 24680;
    Random r1 = new Random(seed);
    Random r2 = new Random(seed);
    byte[] got = new byte[16];
    byte[] expected = new byte[16];
    int from = 3;
    int len = 9;

    // Expected produced by Java's nextBytes(len) then copied into subrange
    byte[] tmp = new byte[len];
    r2.nextBytes(tmp);
    System.arraycopy(tmp, 0, expected, from, len);

    // Act
    Util.randomBytes(r1, got, from, len);

    // Assert
    assertArrayEquals(expected, got);
  }

  @Test
  @DisplayName("randomBytes_withMersenneTwisterSubrange_consistentWithNextBytes")
  void randomBytes_withMersenneTwisterSubrange_consistentWithNextBytes() {
    // Arrange
    byte[] seed = Fields.intsToBytes(new int[] {0x01234567, 0x89ABCDEF});
    MersenneTwister mt1 = MersenneTwister.createUnsynchronized(seed);
    MersenneTwister mt2 = MersenneTwister.createUnsynchronized(seed);
    byte[] got = new byte[20];
    byte[] expected = new byte[20];
    int from = 2;
    int len = 13;

    // Produce expected using Random.nextBytes(len) API
    byte[] tmp = new byte[len];
    mt2.nextBytes(tmp);
    System.arraycopy(tmp, 0, expected, from, len);

    // Act
    Util.randomBytes(mt1, got, from, len);

    // Assert
    assertArrayEquals(expected, got);
  }

  @Test
  @DisplayName("randomBytes_withSecureRandom_invokesNextBytesOnce")
  void randomBytes_withSecureRandom_invokesNextBytesOnce() {
    // Arrange: spy on a real SecureRandom instance
    SecureRandom sr = spy(new SecureRandom());
    byte[] full = new byte[16];
    byte[] sub = new byte[16];

    // Act
    Util.randomBytes(sr, full); // whole buffer → direct nextBytes(buf)
    Util.randomBytes(sr, sub, 4, 8); // subrange → internal nextBytes(tmp) once

    // Assert: nextBytes invoked exactly twice (one per call above)
    verify(sr, times(2)).nextBytes(org.mockito.ArgumentMatchers.any(byte[].class));
  }

  // ----- byteArrayEqual (deprecated wrapper) -----

  @Test
  @DisplayName("byteArrayEqual_whenSameOffsetAndLength_true")
  void byteArrayEqual_whenSameOffsetAndLength_true() {
    // Arrange
    byte[] a = {10, 20, 30, 40, 50};
    byte[] b = {10, 20, 30, 40, 50};

    // Act & Assert
    assertTrue(Util.byteArrayEqual(a, b, 1, 3)); // compare [20,30,40]
  }

  @Test
  @DisplayName("byteArrayEqual_whenLengthExceedsArray_false")
  void byteArrayEqual_whenLengthExceedsArray_false() {
    // Arrange
    byte[] a = {1, 2, 3};
    byte[] b = {1, 2};

    // Act & Assert
    assertFalse(Util.byteArrayEqual(a, b, 1, 3));
  }

  // ----- getCipherByName -----

  @Test
  @DisplayName("getCipherByName_whenRijndael_encryptThenDecryptRoundTrip")
  void getCipherByName_whenRijndael_encryptThenDecryptRoundTrip() {
    // Arrange
    BlockCipher c = Util.getCipherByName("Rijndael");
    assertNotNull(c, "Expected Rijndael instance");

    byte[] key = new byte[c.getKeySize() / 8];
    for (int i = 0; i < key.length; i++) key[i] = (byte) i;
    c.initialize(key);

    byte[] pt = new byte[c.getBlockSize() / 8];
    for (int i = 0; i < pt.length; i++) pt[i] = (byte) (i * 3 + 1);
    byte[] ct = new byte[pt.length];
    byte[] rt = new byte[pt.length];

    // Act
    c.encipher(pt, ct);
    c.decipher(ct, rt);

    // Assert
    assertArrayEquals(pt, rt);
  }

  @Test
  @DisplayName("getCipherByName_whenUnknown_returnsNull")
  void getCipherByName_whenUnknown_returnsNull() {
    assertNull(Util.getCipherByName("NoSuchCipher"));
  }

  @Test
  @DisplayName("getCipherByName_withKeySizeConstructorNotPresent_returnsNull")
  void getCipherByName_withKeySizeConstructorNotPresent_returnsNull() {
    // Rijndael has (int keySize, int blockSize) and no (Integer) constructor; expect null
    assertNull(Util.getCipherByName("Rijndael", 128));
  }

  // ----- log2 -----

  @Test
  @DisplayName("log2_whenVariousInputs_roundsUp")
  void log2_whenVariousInputs_roundsUp() {
    assertEquals(0, Util.log2(0));
    assertEquals(0, Util.log2(1));
    assertEquals(1, Util.log2(2));
    assertEquals(2, Util.log2(3));
    assertEquals(2, Util.log2(4));
    assertEquals(3, Util.log2(5));
    assertEquals(63, Util.log2(Long.MAX_VALUE));
  }

  // ----- readFully -----

  @Test
  @DisplayName("readFully_whenPartialReads_fillsBuffer")
  void readFully_whenPartialReads_fillsBuffer() throws IOException {
    byte[] src = new byte[64];
    for (int i = 0; i < src.length; i++) src[i] = (byte) i;

    // Simulate small-chunk reads via ByteArrayInputStream; JDK may return less than requested.
    ByteArrayInputStream in = new ByteArrayInputStream(src);
    byte[] dst = new byte[64];

    Util.readFully(in, dst, 0, dst.length);
    assertArrayEquals(src, dst);
  }

  @Test
  @DisplayName("readFully_whenInsufficientBytes_throwsEOFException")
  void readFully_whenInsufficientBytes_throwsEOFException() {
    ByteArrayInputStream in = new ByteArrayInputStream(new byte[] {1, 2, 3});
    byte[] dst = new byte[10];
    assertThrows(EOFException.class, () -> Util.readFully(in, dst, 0, 10));
  }

  // ----- keyDigestAsNormalizedDouble -----

  @Test
  @DisplayName("keyDigestAsNormalizedDouble_whenZeroBytes_returnsZero")
  void keyDigestAsNormalizedDouble_whenZeroBytes_returnsZero() {
    byte[] digest = new byte[32]; // first 8 are zero
    assertEquals(0.0d, Util.keyDigestAsNormalizedDouble(digest));
  }

  @Test
  @DisplayName("keyDigestAsNormalizedDouble_whenLongMax_returnsOne")
  void keyDigestAsNormalizedDouble_whenLongMax_returnsOne() {
    byte[] digest = new byte[32];
    // Fields.bytesToLong reads buf[7] as MSB and buf[0] as LSB.
    // Arrange bytes so that the decoded long is Long.MAX_VALUE (0x7FFF...FFFF).
    for (int i = 0; i < 7; i++) digest[i] = (byte) 0xFF; // LSB..next
    digest[7] = 0x7F; // MSB
    assertEquals(1.0d, Util.keyDigestAsNormalizedDouble(digest));
  }

  @Test
  @DisplayName("keyDigestAsNormalizedDouble_whenLongMin_mapsToOne")
  void keyDigestAsNormalizedDouble_whenLongMin_mapsToOne() {
    byte[] digest = new byte[32];
    // Arrange bytes so decoded long is Long.MIN_VALUE (0x8000...0000)
    for (int i = 0; i < 7; i++) digest[i] = 0x00;
    digest[7] = (byte) 0x80;
    assertEquals(1.0d, Util.keyDigestAsNormalizedDouble(digest));
  }
}
