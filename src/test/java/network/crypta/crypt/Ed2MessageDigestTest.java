package network.crypta.crypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.bitpedia.collider.core.Md4Handler;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // test method naming style: method_whenCondition_expectOutcome
class Ed2MessageDigestTest {

  private static final int EDSEG_SIZE = 1024 * 9500; // 9,728,000 bytes

  @Test
  @DisplayName("constructor sets algorithm name and digest length")
  void constructor_whenCreated_expectED2KAlgorithmAnd16ByteLength() {
    // Arrange & Act
    MessageDigest md = new Ed2MessageDigest();
    // Assert
    assertEquals("ED2K", md.getAlgorithm());
    assertEquals(16, md.getDigestLength());
  }

  @Test
  void digest_whenEmpty_expectMd4OfEmpty() {
    // Arrange
    MessageDigest md = new Ed2MessageDigest();
    // Act
    byte[] digest = md.digest();
    // Assert (MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0)
    assertArrayEquals(
        hex("31d6cfe0d16ae931b73c59d7e0c089c0"),
        digest,
        "ED2K digest for empty input must equal MD4(empty)");
  }

  @Test
  void digest_whenSmallString_expectEqualsMd4OfData() {
    // Arrange
    MessageDigest md = new Ed2MessageDigest();
    byte[] data = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.US_ASCII);
    // Act
    md.update(data);
    byte[] digest = md.digest();
    // Assert (MD4 of the sentence is 1bee69a46ba811185c194762abaeae90)
    assertArrayEquals(
        hex("1bee69a46ba811185c194762abaeae90"),
        digest,
        "ED2K digest for data within a single segment must equal MD4(data)");
  }

  @Test
  void update_withOffsetAndLength_expectSameAsSingleChunk() {
    // Arrange
    byte[] data = patternBytes(1024, 7);
    MessageDigest md1 = new Ed2MessageDigest();
    md1.update(data);
    byte[] expected = md1.digest();

    MessageDigest md2 = new Ed2MessageDigest();
    // Act: feed in chunks using offset/length
    md2.update(data, 0, 100);
    md2.update(data, 100, 512);
    md2.update(data, 612, 412);
    byte[] actual = md2.digest();

    // Assert
    assertArrayEquals(expected, actual);
  }

  @Test
  void update_usingSingleByteCalls_expectSameAsBulkUpdate() {
    // Arrange
    byte[] data = patternBytes(4096, 23);
    MessageDigest mdBulk = new Ed2MessageDigest();
    mdBulk.update(data);
    byte[] expected = mdBulk.digest();

    MessageDigest mdByteWise = new Ed2MessageDigest();
    // Act
    for (byte b : data) {
      mdByteWise.update(b);
    }
    byte[] actual = mdByteWise.digest();

    // Assert
    assertArrayEquals(expected, actual);
  }

  @Test
  void reset_betweenDigests_expectIndependentResults() {
    // Arrange
    byte[] data1 = "abc".getBytes(StandardCharsets.US_ASCII);
    byte[] data2 = "abcd".getBytes(StandardCharsets.US_ASCII);
    MessageDigest md = new Ed2MessageDigest();

    // Act
    md.update(data1);
    byte[] digest1 = md.digest();

    md.reset();
    md.update(data2);
    byte[] digest2 = md.digest();

    // Assert
    assertNotEquals(bytesToHex(digest1), bytesToHex(digest2));
    assertArrayEquals(computeMd4(data1), digest1, "First digest must be MD4(data1)");
    assertArrayEquals(computeMd4(data2), digest2, "Second digest must be MD4(data2)");
  }

  @Test
  void digest_whenExactSegmentSize_expectEqualsMd4OfData() {
    // Arrange: exactly one ED2K segment
    byte[] data = patternBytes(EDSEG_SIZE, 101);
    MessageDigest md = new Ed2MessageDigest();
    md.update(data);

    // Act
    byte[] actual = md.digest();

    // Assert
    assertArrayEquals(computeMd4(data), actual, "Exact segment-size input must yield MD4(data)");
  }

  @Test
  void digest_whenCrossingSegmentBoundary_expectMd4OfConcatenatedSegmentMd4s() {
    // Arrange: cross boundary by 1 byte (two segments)
    byte[] data = patternBytes(EDSEG_SIZE + 1, 17);
    // expected = MD4( MD4(seg1) || MD4(seg2) )
    byte[] seg1 = new byte[EDSEG_SIZE];
    System.arraycopy(data, 0, seg1, 0, EDSEG_SIZE);
    byte[] seg2 = new byte[1];
    seg2[0] = data[EDSEG_SIZE];

    byte[] md4seg1 = computeMd4(seg1);
    byte[] md4seg2 = computeMd4(seg2);

    byte[] concat = new byte[md4seg1.length + md4seg2.length];
    System.arraycopy(md4seg1, 0, concat, 0, md4seg1.length);
    System.arraycopy(md4seg2, 0, concat, md4seg1.length, md4seg2.length);
    byte[] expected = computeMd4(concat);

    MessageDigest md = new Ed2MessageDigest();
    md.update(data);

    // Act
    byte[] actual = md.digest();

    // Assert
    assertArrayEquals(expected, actual);
  }

  @Test
  void update_withInvalidOffsetOrLength_expectIllegalArgument() {
    MessageDigest md = new Ed2MessageDigest();
    byte[] data = new byte[10];
    assertInvalidUpdateThrows(md, data, -1, 5);
    assertInvalidUpdateThrows(md, data, 0, -1);
    assertInvalidUpdateThrows(md, data, 5, 6);
  }

  @Test
  void update_withNullArray_expectNullPointerOrIllegalArgument() {
    MessageDigest md = new Ed2MessageDigest();
    Throwable t = assertThrows(RuntimeException.class, () -> md.update(null, 0, 0));
    assertTrue(
        (t instanceof NullPointerException) || (t instanceof IllegalArgumentException),
        "Expected NullPointerException or IllegalArgumentException but got: "
            + t.getClass().getName());
  }

  // --- helpers ---

  private static byte[] computeMd4(byte[] data) {
    Md4Handler md4 = new Md4Handler();
    md4.analyzeInit();
    md4.analyzeUpdate(data, data.length);
    return md4.analyzeFinal();
  }

  private static byte[] patternBytes(int length, int seed) {
    byte[] out = new byte[length];
    int v = seed & 0xFF;
    for (int i = 0; i < length; i++) {
      // simple deterministic pattern (no Random to avoid S2245)
      v = (v * 1103515245 + 12345) & 0x7fffffff;
      out[i] = (byte) (v & 0xFF);
    }
    return out;
  }

  private static byte[] hex(String s) {
    int len = s.length();
    byte[] out = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
      int hi = Character.digit(s.charAt(i), 16);
      int lo = Character.digit(s.charAt(i + 1), 16);
      out[i / 2] = (byte) ((hi << 4) + lo);
    }
    return out;
  }

  private static String bytesToHex(byte[] b) {
    StringBuilder sb = new StringBuilder(b.length * 2);
    for (byte value : b) {
      sb.append(String.format("%02x", value));
    }
    return sb.toString();
  }

  private static void assertInvalidUpdateThrows(MessageDigest md, byte[] data, int off, int len) {
    Throwable t = assertThrows(RuntimeException.class, () -> md.update(data, off, len));
    assertTrue(
        (t instanceof IllegalArgumentException) || (t instanceof ArrayIndexOutOfBoundsException),
        "Expected IllegalArgumentException or ArrayIndexOutOfBoundsException but got: "
            + t.getClass().getName());
  }
}
