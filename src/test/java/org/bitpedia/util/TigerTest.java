package org.bitpedia.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100") // Intentional method naming: method_whenCondition_expectOutcome
class TigerTest {

  private static final HexFormat HEX = HexFormat.of();

  private static final String DIGEST_EMPTY = "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3";
  private static final String DIGEST_ABC = "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93";
  private static final String DIGEST_A = "77befbef2e7ef8ab2ec8f93bf587a7fc613e247f5f247809";
  private static final String DIGEST_BCD = "10a436914463e1af490fdb26eb225c92ea5c68c957212923";
  private static final String DIGEST_ABCDEF = "9895d378382b1e93a4a2f5ccd425453f01ddbab2137ce35e";
  private static final String DIGEST_ABCXYZ = "61720a99b68600d217c7d1b4806b12af9437e6b9045cf6a3";

  @Test
  void engineGetDigestLength_whenCalled_returnsTigerDigestSize() {
    Tiger tiger = new Tiger();

    assertEquals(24, tiger.engineGetDigestLength());
  }

  @Test
  void engineDigest_whenInputEmpty_returnsKnownVector() {
    Tiger tiger = new Tiger();

    byte[] digest = tiger.engineDigest();

    assertNotNull(digest);
    assertEquals(DIGEST_EMPTY, HEX.formatHex(digest));
  }

  @Test
  void engineDigest_whenInputIsAbc_returnsKnownVector() {
    Tiger tiger = new Tiger();
    tiger.engineUpdate("abc".getBytes(StandardCharsets.US_ASCII), 0, 3);

    byte[] digest = tiger.engineDigest();

    assertNotNull(digest);
    assertEquals(DIGEST_ABC, HEX.formatHex(digest));
  }

  @Test
  void engineUpdate_whenOffsetAndLengthUsed_hashesOnlySpecifiedBytes() {
    byte[] buffer = "abcde".getBytes(StandardCharsets.US_ASCII);
    Tiger tiger = new Tiger();

    tiger.engineUpdate(buffer, 1, 3); // "bcd"
    byte[] digest = tiger.engineDigest();

    assertNotNull(digest);
    assertEquals(DIGEST_BCD, HEX.formatHex(digest));
  }

  @Test
  void engineDigest_whenCalledTwice_resetsInternalState() {
    Tiger tiger = new Tiger();
    tiger.engineUpdate((byte) 'a');

    byte[] first = tiger.engineDigest();
    byte[] second = tiger.engineDigest();

    assertNotNull(first);
    assertNotNull(second);
    assertArrayEquals(HEX.parseHex(DIGEST_A), first);
    assertEquals(DIGEST_EMPTY, HEX.formatHex(second));
  }

  @Test
  void copy_whenCopiedMidStream_producesIndependentDigests() {
    Tiger tiger = new Tiger();
    tiger.engineUpdate("abc".getBytes(StandardCharsets.US_ASCII), 0, 3);

    Tiger clone = tiger.copy();

    tiger.engineUpdate("def".getBytes(StandardCharsets.US_ASCII), 0, 3);
    clone.engineUpdate("xyz".getBytes(StandardCharsets.US_ASCII), 0, 3);

    byte[] tigerDigest = tiger.engineDigest();
    byte[] cloneDigest = clone.engineDigest();

    assertNotNull(tigerDigest);
    assertNotNull(cloneDigest);
    assertEquals(DIGEST_ABCDEF, HEX.formatHex(tigerDigest));
    assertEquals(DIGEST_ABCXYZ, HEX.formatHex(cloneDigest));
  }

  @Test
  void engineUpdate_whenIndicesOutOfRange_throwsArrayIndexOutOfBoundsException() {
    Tiger tiger = new Tiger();
    byte[] input = new byte[2];

    assertThrows(ArrayIndexOutOfBoundsException.class, () -> tiger.engineUpdate(input, 3, 1));
  }

  @Test
  void engineDigest_whenLenTooSmall_throwsDigestException() {
    Tiger tiger = new Tiger();
    byte[] output = new byte[10];

    assertThrows(DigestException.class, () -> tiger.engineDigest(output, 0, 10));
  }

  @Test
  void engineDigest_whenBufferHasInsufficientRemainingSpace_throwsDigestException() {
    Tiger tiger = new Tiger();
    byte[] output = new byte[30];

    assertThrows(DigestException.class, () -> tiger.engineDigest(output, 10, 24));
  }
}
