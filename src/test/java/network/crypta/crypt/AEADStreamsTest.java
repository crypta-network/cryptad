package network.crypta.crypt;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Random;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import network.crypta.testsupport.NoCloseProxyOutputStream;
import org.junit.jupiter.api.Test;

import static network.crypta.testsupport.TestRandomData.fillBucketWithRandom;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AEADStreamsTest {

  private static void copyAndClose(Bucket decoded, AEADInputStream cis) throws IOException {
    BucketTools.copyFrom(decoded, cis, -1);
    cis.close();
  }

  private static void closeIgnoringAeadVerification(AEADInputStream cis) throws IOException {
    try {
      cis.close();
    } catch (AEADVerificationFailedException _) {
      // Expected for intentionally corrupted tails in negative tests.
    }
  }

  @Test
  void testSuccessfulRoundTrip() throws IOException {
    Random random = new Random(0x96231307L);
    for (int i = 0; i < 10; i++) {
      ArrayBucket input = new ArrayBucket();
      fillBucketWithRandom(input, random, 65536L, true);
      checkSuccessfulRoundTrip(16, random, input, new ArrayBucket(), new ArrayBucket());
      checkSuccessfulRoundTrip(24, random, input, new ArrayBucket(), new ArrayBucket());
      checkSuccessfulRoundTrip(32, random, input, new ArrayBucket(), new ArrayBucket());
    }
  }

  @Test
  void testCorruptedRoundTrip() throws IOException {
    Random random = new Random(0x96231307L); // Same seed as the first test, intentionally.
    for (int i = 0; i < 10; i++) {
      ArrayBucket input = new ArrayBucket();
      fillBucketWithRandom(input, random, 65536L, true);
      checkFailedCorruptedRoundTrip(16, random, input, new ArrayBucket(), new ArrayBucket());
      checkFailedCorruptedRoundTrip(24, random, input, new ArrayBucket(), new ArrayBucket());
      checkFailedCorruptedRoundTrip(32, random, input, new ArrayBucket(), new ArrayBucket());
    }
  }

  @Test
  void testTruncatedReadsWritesRoundTrip() throws IOException {
    Random random = new Random(0x49ee92f5);
    ArrayBucket input = new ArrayBucket();
    fillBucketWithRandom(input, random, 512L * 1024L, true);
    checkSuccessfulRoundTripRandomSplits(16, random, input, new ArrayBucket(), new ArrayBucket());
    checkSuccessfulRoundTripRandomSplits(24, random, input, new ArrayBucket(), new ArrayBucket());
    checkSuccessfulRoundTripRandomSplits(32, random, input, new ArrayBucket(), new ArrayBucket());
  }

  void checkSuccessfulRoundTrip(
      int keysize, Random random, Bucket input, Bucket output, Bucket decoded) throws IOException {
    byte[] key = new byte[keysize];
    random.nextBytes(key);
    try (OutputStream os = output.getOutputStream();
        AEADOutputStream cos = AEADOutputStream.innerCreateAES(os, key, random)) {
      BucketTools.copyTo(input, cos, -1);
    }
    assertTrue(output.size() > input.size());
    try (InputStream is = output.getInputStream();
        AEADInputStream cis = AEADInputStream.createAES(is, key)) {
      BucketTools.copyFrom(decoded, cis, -1);
    }
    assertEquals(decoded.size(), input.size());
    assertTrue(BucketTools.equalBuckets(decoded, input));
  }

  void checkFailedCorruptedRoundTrip(
      int keysize, Random random, Bucket input, Bucket output, Bucket decoded) throws IOException {
    byte[] key = new byte[keysize];
    random.nextBytes(key);
    try (OutputStream os = output.getOutputStream();
        CorruptingOutputStream kos =
            new CorruptingOutputStream(os, 16L, input.size() + 16, 10, random);
        AEADOutputStream cos = AEADOutputStream.innerCreateAES(kos, key, random)) {
      BucketTools.copyTo(input, cos, -1);
    }
    assertTrue(output.size() > input.size());
    try (InputStream is = output.getInputStream()) {
      AEADInputStream cis = AEADInputStream.createAES(is, key);
      try {
        assertThrows(AEADVerificationFailedException.class, () -> copyAndClose(decoded, cis));
      } finally {
        closeIgnoringAeadVerification(cis);
      }
    }
    assertEquals(decoded.size(), input.size());
    assertFalse(BucketTools.equalBuckets(decoded, input));
  }

  void checkSuccessfulRoundTripRandomSplits(
      int keysize, Random random, Bucket input, Bucket output, Bucket decoded) throws IOException {
    byte[] key = new byte[keysize];
    random.nextBytes(key);
    try (OutputStream os = output.getOutputStream();
        AEADOutputStream cos = AEADOutputStream.innerCreateAES(os, key, random)) {
      BucketTools.copyTo(input, new RandomShortWriteOutputStream(cos, random), -1);
    }
    assertTrue(output.size() > input.size());
    try (InputStream is = output.getInputStream();
        AEADInputStream cis = AEADInputStream.createAES(is, key)) {
      BucketTools.copyFrom(decoded, new RandomShortReadInputStream(cis, random), -1);
    }
    assertEquals(decoded.size(), input.size());
    assertTrue(BucketTools.equalBuckets(decoded, input));
  }

  /** Check whether we can close the stream early. */
  @Test
  void testCloseEarly() throws IOException {
    ArrayBucket input = new ArrayBucket();
    BucketTools.fill(input, 2048);
    int keysize = 16;
    Random random = new Random(0x47f6709f);
    byte[] key = new byte[keysize];
    random.nextBytes(key);
    try (ArrayBucket output = new ArrayBucket()) {
      try (OutputStream os = output.getOutputStream();
          AEADOutputStream cos = AEADOutputStream.innerCreateAES(os, key, random)) {
        BucketTools.copyTo(input, cos, 2048);
      }
      byte[] first1KReadEncrypted = new byte[1024];
      byte[] first1KReadOriginal = new byte[1024];
      try (InputStream is = output.getInputStream();
          AEADInputStream cis = AEADInputStream.createAES(is, key);
          DataInputStream encryptedIn = new DataInputStream(cis);
          InputStream originalIs = input.getInputStream();
          DataInputStream originalIn = new DataInputStream(originalIs)) {
        encryptedIn.readFully(first1KReadEncrypted);
        originalIn.readFully(first1KReadOriginal);
      }
      assertArrayEquals(first1KReadEncrypted, first1KReadOriginal);
    }
  }

  /**
   * If we close the stream early but there is garbage after that point, it should throw on close().
   */
  @Test
  void testGarbageAfterClose() throws IOException {
    ArrayBucket input = new ArrayBucket();
    BucketTools.fill(input, 1024);
    int keysize = 16;
    Random random = new Random(0x47f6709f);
    byte[] key = new byte[keysize];
    random.nextBytes(key);
    try (ArrayBucket output = new ArrayBucket()) {
      try (OutputStream os = output.getOutputStream()) {
        try (AEADOutputStream cos =
            AEADOutputStream.innerCreateAES(new NoCloseProxyOutputStream(os), key, random)) {
          BucketTools.copyTo(input, cos, -1);
        }
        // Now write garbage.
        FileUtil.fill(os, 1024);
      }
      byte[] first1KReadEncrypted = new byte[1024];
      byte[] first1KReadOriginal = new byte[1024];
      assertThrows(
          AEADVerificationFailedException.class,
          () -> {
            try (InputStream is = output.getInputStream();
                AEADInputStream cis = AEADInputStream.createAES(is, key);
                DataInputStream encryptedIn = new DataInputStream(cis);
                InputStream originalIs = input.getInputStream();
                DataInputStream originalIn = new DataInputStream(originalIs)) {
              encryptedIn.readFully(first1KReadEncrypted);
              originalIn.readFully(first1KReadOriginal);
              assertArrayEquals(first1KReadEncrypted, first1KReadOriginal);
            }
          });
    }
  }
}
