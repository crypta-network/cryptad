package org.bitpedia.collider.core;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.CRC32;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SuppressWarnings("java:S100")
class FtuuHandlerTest {

  private static final int FTSEG_SIZE = 307200;

  @Test
  void hashSmallHash_whenProcessingKnownBytes_matchesCrc32Complement() {
    byte[] data = "123456789".getBytes(StandardCharsets.US_ASCII);

    int actual = FtuuHandler.hashSmallHash(data, 0, data.length, 0xffffffff);

    CRC32 crc32 = new CRC32();
    crc32.update(data, 0, data.length);
    int expected = (int) (crc32.getValue() ^ 0xffffffffL);

    assertEquals(expected, actual);
  }

  @Test
  void bitziEncodeBase64_whenLengthNotMultipleOfThree_encodesWithoutPaddingAndNullTerminated() {
    byte[] raw = {(byte) 0xFF, (byte) 0xEE};
    byte[] out = new byte[5];

    FtuuHandler.bitziEncodeBase64(raw, raw.length, out);

    String encoded = new String(out, 0, 3, StandardCharsets.US_ASCII);
    assertEquals("/+4", encoded);
    assertEquals(0, out[3]);
  }

  @Test
  void analyzeFinal_whenFileSmallerThanSegment_usesLengthXorForSmallHash() {
    byte[] data = "crypta".getBytes(StandardCharsets.UTF_8);

    byte[] actualDigest = runHandler(data);

    byte[] expectedMd5 = md5(data, data.length);
    int expectedSmallHash = ~data.length;
    byte[] expectedDigest = appendSmallHash(expectedMd5, expectedSmallHash);

    assertArrayEquals(expectedDigest, actualDigest);
  }

  @Test
  void analyzeFinal_whenFileBetweenOneAndTwoSegments_hashesTrailingBytesOnly() {
    int totalLength = FTSEG_SIZE + 10;
    byte[] data = buildSequentialData(totalLength);

    byte[] actualDigest = runHandler(data);

    byte[] expectedMd5 = md5(data, FTSEG_SIZE);
    int expectedSmallHash = crcComplement(data, FTSEG_SIZE, totalLength - FTSEG_SIZE) ^ totalLength;
    byte[] expectedDigest = appendSmallHash(expectedMd5, expectedSmallHash);

    assertArrayEquals(expectedDigest, actualDigest);
  }

  @Test
  void analyzeFinal_whenFileBetweenTwoAndSampleStart_hashesLastFullSegment() {
    int totalLength = 700_000;
    byte[] data = buildSequentialData(totalLength);

    byte[] actualDigest = runHandler(data);

    byte[] expectedMd5 = md5(data, FTSEG_SIZE);
    int expectedSmallHash = crcComplement(data, totalLength - FTSEG_SIZE, FTSEG_SIZE) ^ totalLength;
    byte[] expectedDigest = appendSmallHash(expectedMd5, expectedSmallHash);

    assertArrayEquals(expectedDigest, actualDigest);
  }

  @Test
  void analyzeFinal_whenSamplingRangeOverlapsEnd_usesBackupSmallHash() {
    int totalLength = 1_400_000;
    byte[] data = buildSequentialData(totalLength);

    byte[] actualDigest = runHandler(data);
    int actualSmallHash = readSmallHash(actualDigest);

    byte[] expectedMd5 = md5(data, FTSEG_SIZE);
    byte[] endSegment = sliceSegment(data, totalLength - FTSEG_SIZE);
    int expectedRollbackHash = crcComplement(endSegment, 0, endSegment.length) ^ totalLength;
    byte[] expectedDigest = appendSmallHash(expectedMd5, expectedRollbackHash);

    byte[] sampleSegment = sliceSegment(data, 0x100000);
    CRC32 crc32 = new CRC32();
    crc32.update(sampleSegment, 0, sampleSegment.length);
    crc32.update(endSegment, 0, endSegment.length);
    int expectedWithoutRollback = (int) (crc32.getValue() ^ 0xffffffffL) ^ totalLength;

    assertArrayEquals(expectedDigest, actualDigest);
    assertEquals(expectedRollbackHash, actualSmallHash);
    assertNotEquals(expectedWithoutRollback, actualSmallHash);
  }

  private static byte[] runHandler(byte[] data) {
    FtuuHandler handler = new FtuuHandler();
    handler.analyzeInit();
    handler.analyzeUpdate(data, 0, data.length);
    return handler.analyzeFinal();
  }

  private static byte[] md5(byte[] data, int length) {
    try {
      MessageDigest messageDigest = MessageDigest.getInstance("MD5");
      messageDigest.update(data, 0, length);
      return messageDigest.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("MD5 must be available in JRE", e);
    }
  }

  private static int crcComplement(byte[] data, int offset, int length) {
    CRC32 crc32 = new CRC32();
    crc32.update(data, offset, length);
    return (int) (crc32.getValue() ^ 0xffffffffL);
  }

  private static byte[] appendSmallHash(byte[] md5Digest, int smallHash) {
    byte[] digest = new byte[20];
    System.arraycopy(md5Digest, 0, digest, 0, md5Digest.length);
    ByteBuffer buffer = ByteBuffer.allocate(4);
    buffer.putInt(smallHash);
    byte[] smallHashBytes = buffer.array();
    digest[16] = smallHashBytes[3];
    digest[17] = smallHashBytes[2];
    digest[18] = smallHashBytes[1];
    digest[19] = smallHashBytes[0];
    return digest;
  }

  private static byte[] buildSequentialData(int length) {
    byte[] data = new byte[length];
    for (int i = 0; i < length; i++) {
      data[i] = (byte) (i & 0xFF);
    }
    return data;
  }

  private static byte[] sliceSegment(byte[] data, int offset) {
    byte[] slice = new byte[FTSEG_SIZE];
    System.arraycopy(data, offset, slice, 0, FTSEG_SIZE);
    return slice;
  }

  private static int readSmallHash(byte[] digest) {
    int b0 = digest[16] & 0xFF;
    int b1 = digest[17] & 0xFF;
    int b2 = digest[18] & 0xFF;
    int b3 = digest[19] & 0xFF;
    return (b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
  }
}
