package org.bitpedia.util;

import java.nio.charset.StandardCharsets;
import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class Sha1Test {

  @Test
  void digest_whenEmpty_returnsStandardSha1() throws NoSuchAlgorithmException {
    Sha1 sha1 = new Sha1();

    byte[] digest = sha1.digest();

    assertArrayEquals(referenceSha1(new byte[0]), digest);
  }

  @Test
  void digest_whenSmallMessage_matchesReference() throws NoSuchAlgorithmException {
    Sha1 sha1 = new Sha1();
    byte[] data = "abc".getBytes(StandardCharsets.US_ASCII);

    sha1.update(data);
    byte[] digest = sha1.digest();

    assertArrayEquals(referenceSha1(data), digest);
  }

  @Test
  void digest_whenUpdatedInChunks_matchesReference() throws NoSuchAlgorithmException {
    Sha1 sha1 = new Sha1();
    byte[] data = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.US_ASCII);

    sha1.update(data, 0, 10);
    sha1.update(data, 10, 15);
    sha1.update(data, 25, data.length - 25);
    byte[] digest = sha1.digest();

    assertArrayEquals(referenceSha1(data), digest);
  }

  @Test
  void engineDigest_withProvidedBuffer_returnsLengthAndResets() throws Exception {
    Sha1 sha1 = new Sha1();
    byte[] data = "digest-me".getBytes(StandardCharsets.US_ASCII);
    sha1.update(data);
    byte[] buffer = new byte[32];

    int written = sha1.engineDigest(buffer, 5, Sha1.HASH_LENGTH);

    assertEquals(Sha1.HASH_LENGTH, written);
    byte[] writtenDigest = new byte[Sha1.HASH_LENGTH];
    System.arraycopy(buffer, 5, writtenDigest, 0, Sha1.HASH_LENGTH);
    assertArrayEquals(referenceSha1(data), writtenDigest);

    // engineDigest() must reset the instance
    assertArrayEquals(referenceSha1(new byte[0]), sha1.digest());
  }

  @Test
  void engineDigest_whenLenTooSmall_throwsDigestException() {
    Sha1 sha1 = new Sha1();
    byte[] buffer = new byte[Sha1.HASH_LENGTH];

    assertThrows(DigestException.class, () -> sha1.engineDigest(buffer, 0, Sha1.HASH_LENGTH - 1));
  }

  @Test
  void engineDigest_whenBufferTooShort_throwsDigestException() {
    Sha1 sha1 = new Sha1();
    byte[] buffer = new byte[Sha1.HASH_LENGTH - 1];

    assertThrows(DigestException.class, () -> sha1.engineDigest(buffer, 0, Sha1.HASH_LENGTH));
  }

  @Test
  void engineUpdate_whenRangeInvalid_throwsArrayIndexOutOfBounds() {
    Sha1 sha1 = new Sha1();
    byte[] buffer = new byte[4];

    assertThrows(ArrayIndexOutOfBoundsException.class, () -> sha1.engineUpdate(buffer, 3, 2));
  }

  @Test
  void copy_whenMutatedIndependently_producesSeparateDigests() throws NoSuchAlgorithmException {
    Sha1 original = new Sha1();
    byte[] seed = "shared".getBytes(StandardCharsets.US_ASCII);
    original.update(seed);

    Sha1 clone = original.copy();

    original.update("-orig".getBytes(StandardCharsets.US_ASCII));
    clone.update("-clone".getBytes(StandardCharsets.US_ASCII));

    assertArrayEquals(
        referenceSha1("shared-orig".getBytes(StandardCharsets.US_ASCII)), original.digest());
    assertArrayEquals(
        referenceSha1("shared-clone".getBytes(StandardCharsets.US_ASCII)), clone.digest());
  }

  @Test
  void getDigestLength_alwaysReturnsHashLength() {
    Sha1 sha1 = new Sha1();

    assertEquals(Sha1.HASH_LENGTH, sha1.getDigestLength());
  }

  private static byte[] referenceSha1(byte[] data) throws NoSuchAlgorithmException {
    MessageDigest reference = MessageDigest.getInstance("SHA-1");
    return reference.digest(data);
  }
}
