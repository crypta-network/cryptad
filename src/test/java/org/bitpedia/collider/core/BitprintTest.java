package org.bitpedia.collider.core;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Stream;
import org.bitpedia.util.Base32;
import org.bitpedia.util.Sha1;
import org.bitpedia.util.TigerTree;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // Intentional method naming: method_whenCondition_expectOutcome
class BitprintTest {

  @ParameterizedTest(name = "{0}")
  @MethodSource("knownVectors")
  @DisplayName("analyzeFinal returns expected SHA-1 and TigerTree digests for known vectors")
  void analyzeFinal_whenDataMatchesKnownVectors_returnsExpectedBase32Digests(
      String description, byte[] input, String expectedShaBase32, String expectedTigerBase32) {

    Bitprint bitprint = new Bitprint();

    assertTrue(bitprint.analyzeInit(), "hash sanity check should pass");

    if (input.length > 0) {
      bitprint.analyzeUpdate(input, 0, input.length);
    }

    byte[] combinedDigest = bitprint.analyzeFinal();

    assertEquals(Bitprint.BITPRINT_RAW_LEN, combinedDigest.length, "combined digest length");

    int shaLength = Base32.decode(expectedShaBase32).length;
    byte[] shaPortion = Arrays.copyOfRange(combinedDigest, 0, shaLength);
    byte[] tigerPortion = Arrays.copyOfRange(combinedDigest, shaLength, combinedDigest.length);

    assertEquals(expectedShaBase32, Base32.encode(shaPortion), "SHA-1 digest");
    assertEquals(expectedTigerBase32, Base32.encode(tigerPortion), "TigerTree digest");
  }

  @Test
  void analyzeUpdate_whenUsingOffset_hashesOnlySpecifiedRange() {
    byte[] buffer = "abcde".getBytes(StandardCharsets.US_ASCII);
    int offset = 1; // start at 'b'
    int length = 3; // "bcd"

    Bitprint bitprint = new Bitprint();
    assertTrue(bitprint.analyzeInit(), "hash sanity check should pass");

    bitprint.analyzeUpdate(buffer, offset, length);
    byte[] combinedDigest = bitprint.analyzeFinal();

    DigestComponents expected = computeExpectedDigests(buffer, offset, length);
    byte[] shaPortion = Arrays.copyOfRange(combinedDigest, 0, expected.shaBytes.length);
    byte[] tigerPortion =
        Arrays.copyOfRange(combinedDigest, expected.shaBytes.length, combinedDigest.length);

    assertEquals(expected.shaBase32, Base32.encode(shaPortion), "SHA-1 digest respects offset");
    assertEquals(
        expected.tigerBase32, Base32.encode(tigerPortion), "TigerTree digest respects offset");
  }

  private static Stream<Arguments> knownVectors() {
    byte[] singleOne = new byte[] {'1'};
    byte[] oneK = new byte[1025];
    Arrays.fill(oneK, (byte) 'a');

    return Stream.of(
        Arguments.of(
            "empty input",
            new byte[0],
            "3I42H3S6NNFQ2MSVX7XZKYAYSCX5QBYJ",
            "LWPNACQDBZRYXW3VHJVCJ64QBZNGHOHHHZWCLNQ"),
        Arguments.of(
            "single byte '1'",
            singleOne,
            "GVVBSK3ZCOYEYVCXJUMMFDKG4Y4VIKFL",
            "QMLU34VTTAIWJQM5RVN4RIQKRM2JWIFZQFDYY3Y"),
        Arguments.of(
            "1025 bytes of 'a'",
            oneK,
            "CAE54LXWDA55NWGAR4PNRX2II7TR66WL",
            "CDYY2OW6F6DTGCH3Q6NMSDLSRV7PNMAL3CED3DA"));
  }

  private static DigestComponents computeExpectedDigests(byte[] data, int offset, int length) {
    Sha1 sha1 = new Sha1();
    sha1.update(data, offset, length);
    byte[] shaBytes = sha1.digest();

    TigerTree tigerTree = new TigerTree();
    tigerTree.update(data, offset, length);
    byte[] tigerBytes = tigerTree.digest();

    return new DigestComponents(shaBytes, Base32.encode(shaBytes), Base32.encode(tigerBytes));
  }

  private static final class DigestComponents {
    private final byte[] shaBytes;
    private final String shaBase32;
    private final String tigerBase32;

    private DigestComponents(byte[] shaBytes, String shaBase32, String tigerBase32) {
      this.shaBytes = shaBytes;
      this.shaBase32 = shaBase32;
      this.tigerBase32 = tigerBase32;
    }
  }
}
