package network.crypta.crypt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({"java:S100", "java:S4790"})
@ExtendWith(MockitoExtension.class)
class MultiHashDigesterTest {

  @Test
  void fromBitmask_whenSingleType_returnsOnlyThatType() {
    for (HashType hashType : HashType.values()) {
      MultiHashDigester digester = MultiHashDigester.fromBitmask(hashType.bitmask);

      List<HashResult> results = digester.getResults();

      assertEquals(1, results.size());
      assertEquals(hashType, results.getFirst().type);
    }
  }

  @Test
  void fromBitmask_whenZero_returnsEmptyResults() {
    MultiHashDigester digester = MultiHashDigester.fromBitmask(0);

    List<HashResult> results = digester.getResults();

    assertTrue(results.isEmpty());
  }

  @Test
  void fromBitmask_whenMultipleBits_resultsOrderedByEnum() {
    MultiHashDigester digester =
        MultiHashDigester.fromBitmask(
            HashType.MD5.bitmask | HashType.SHA512.bitmask | HashType.SHA1.bitmask);

    List<HashResult> results = digester.getResults();

    assertEquals(3, results.size());
    // Order must follow HashType.values(): SHA1, MD5, SHA256, SHA384, SHA512, ED2K, TTH
    assertEquals(HashType.SHA1, results.get(0).type);
    assertEquals(HashType.MD5, results.get(1).type);
    assertEquals(HashType.SHA512, results.get(2).type);
  }

  @Test
  void getResults_whenNoUpdate_hashesEmptyInput_matchKnownHex() {
    MultiHashDigester digester =
        MultiHashDigester.fromBitmask(
            HashType.SHA1.bitmask | HashType.MD5.bitmask | HashType.SHA256.bitmask);

    List<HashResult> results = digester.getResults();

    assertEquals("da39a3ee5e6b4b0d3255bfef95601890afd80709", results.get(0).hashAsHex());
    assertEquals("d41d8cd98f00b204e9800998ecf8427e", results.get(1).hashAsHex());
    assertEquals(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        results.get(2).hashAsHex());
  }

  @Test
  void update_whenSingleByte_producesExpectedJcaDigests() throws NoSuchAlgorithmException {
    MultiHashDigester digester =
        MultiHashDigester.fromBitmask(
            HashType.SHA1.bitmask | HashType.MD5.bitmask | HashType.SHA256.bitmask);

    byte[] input = "$".getBytes(StandardCharsets.UTF_8);
    digester.update(input, 0, 1);

    List<HashResult> results = digester.getResults();

    assertEquals(hex(MessageDigest.getInstance("SHA1").digest(input)), results.get(0).hashAsHex());
    assertEquals(hex(MessageDigest.getInstance("MD5").digest(input)), results.get(1).hashAsHex());
    assertEquals(
        hex(MessageDigest.getInstance("SHA-256").digest(input)), results.get(2).hashAsHex());
  }

  @ParameterizedTest
  @EnumSource(
      value = HashType.class,
      names = {"SHA1", "MD5", "SHA256", "SHA384", "SHA512"})
  void update_whenJcaType_matchesIndependentJca(HashType type) throws NoSuchAlgorithmException {
    MultiHashDigester digester = MultiHashDigester.fromBitmask(type.bitmask);

    byte[] input = "Hello, Crypta!".getBytes(StandardCharsets.UTF_8);
    digester.update(input, 0, input.length);

    byte[] expected = MessageDigest.getInstance(type.javaName).digest(input);

    List<HashResult> results = digester.getResults();

    assertEquals(1, results.size());
    assertEquals(type, results.getFirst().type);
    assertArrayEquals(expected, HashResult.get(results.toArray(new HashResult[0]), type));
  }

  @Test
  void update_whenOffsetAndLength_hashesSubrangeOnly() throws NoSuchAlgorithmException {
    MultiHashDigester digester = MultiHashDigester.fromBitmask(HashType.MD5.bitmask);

    byte[] input = "abcXYZdef".getBytes(StandardCharsets.UTF_8); // hash should be for "XYZ"
    digester.update(input, 3, 3);

    byte[] expected =
        MessageDigest.getInstance("MD5").digest("XYZ".getBytes(StandardCharsets.UTF_8));

    List<HashResult> results = digester.getResults();
    assertEquals(1, results.size());
    assertArrayEquals(expected, HashResult.get(results.toArray(new HashResult[0]), HashType.MD5));
  }

  @Test
  void update_whenZeroLength_isNoOpAndEqualsEmptyDigest() throws NoSuchAlgorithmException {
    MultiHashDigester digester = MultiHashDigester.fromBitmask(HashType.SHA1.bitmask);

    byte[] input = "ignored".getBytes(StandardCharsets.UTF_8);
    digester.update(input, 0, 0);

    byte[] expectedEmpty = MessageDigest.getInstance("SHA1").digest(new byte[0]);

    List<HashResult> results = digester.getResults();
    assertEquals(1, results.size());
    assertArrayEquals(
        expectedEmpty, HashResult.get(results.toArray(new HashResult[0]), HashType.SHA1));
  }

  @Test
  void update_whenInvalidBounds_throwsRuntimeBoundsException() {
    MultiHashDigester digester = MultiHashDigester.fromBitmask(HashType.SHA256.bitmask);
    byte[] input = new byte[] {1, 2, 3};

    RuntimeException ex1 =
        assertThrows(RuntimeException.class, () -> digester.update(input, -1, 1));
    assertTrue(
        ex1 instanceof IndexOutOfBoundsException || ex1 instanceof IllegalArgumentException,
        "expected IndexOutOfBoundsException or IllegalArgumentException");

    RuntimeException ex2 = assertThrows(RuntimeException.class, () -> digester.update(input, 1, 5));
    assertTrue(
        ex2 instanceof IndexOutOfBoundsException || ex2 instanceof IllegalArgumentException,
        "expected IndexOutOfBoundsException or IllegalArgumentException");
  }

  @Test
  void ed2kAndTth_whenSelected_produceResultsWithDeclaredLengths() {
    long mask = HashType.ED2K.bitmask | HashType.TTH.bitmask;
    MultiHashDigester digester = MultiHashDigester.fromBitmask(mask);

    List<HashResult> results = digester.getResults();

    assertEquals(2, results.size());
    assertEquals(HashType.ED2K, results.get(0).type);
    assertEquals(HashType.TTH, results.get(1).type);
    assertEquals(HashType.ED2K.hashLength, results.get(0).hashAsHex().length() / 2);
    assertEquals(HashType.TTH.hashLength, results.get(1).hashAsHex().length() / 2);
  }

  // ----- helpers -----
  private static String hex(byte[] bytes) {
    StringBuilder sb = new StringBuilder(bytes.length * 2);
    for (byte b : bytes) {
      sb.append(String.format("%02x", b));
    }
    return sb.toString();
  }
}
