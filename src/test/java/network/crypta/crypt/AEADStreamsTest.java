package network.crypta.crypt;

import static network.crypta.testsupport.TestRandomData.fillBucketWithRandom;
import static org.junit.jupiter.api.Assertions.*;

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

class AEADStreamsTest {

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
    Random random = new Random(0x96231307L); // Same seed as first test, intentionally.
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
    OutputStream os = output.getOutputStream();
    AEADOutputStream cos = AEADOutputStream.innerCreateAES(os, key, random);
    BucketTools.copyTo(input, cos, -1);
    cos.close();
    assertTrue(output.size() > input.size());
    InputStream is = output.getInputStream();
    AEADInputStream cis = AEADInputStream.createAES(is, key);
    BucketTools.copyFrom(decoded, cis, -1);
    assertEquals(decoded.size(), input.size());
    assertTrue(BucketTools.equalBuckets(decoded, input));
  }

  void checkFailedCorruptedRoundTrip(
      int keysize, Random random, Bucket input, Bucket output, Bucket decoded) throws IOException {
    byte[] key = new byte[keysize];
    random.nextBytes(key);
    OutputStream os = output.getOutputStream();
    CorruptingOutputStream kos = new CorruptingOutputStream(os, 16L, input.size() + 16, 10, random);
    AEADOutputStream cos = AEADOutputStream.innerCreateAES(kos, key, random);
    BucketTools.copyTo(input, cos, -1);
    cos.close();
    assertTrue(output.size() > input.size());
    InputStream is = output.getInputStream();
    AEADInputStream cis = AEADInputStream.createAES(is, key);
    try {
      BucketTools.copyFrom(decoded, cis, -1);
      cis.close();
      fail("Checksum error should have been seen");
    } catch (AEADVerificationFailedException _) {
      // Expected.
    }
    assertEquals(decoded.size(), input.size());
    assertFalse(BucketTools.equalBuckets(decoded, input));
  }

  void checkSuccessfulRoundTripRandomSplits(
      int keysize, Random random, Bucket input, Bucket output, Bucket decoded) throws IOException {
    byte[] key = new byte[keysize];
    random.nextBytes(key);
    OutputStream os = output.getOutputStream();
    AEADOutputStream cos = AEADOutputStream.innerCreateAES(os, key, random);
    BucketTools.copyTo(input, new RandomShortWriteOutputStream(cos, random), -1);
    cos.close();
    assertTrue(output.size() > input.size());
    InputStream is = output.getInputStream();
    AEADInputStream cis = AEADInputStream.createAES(is, key);
    BucketTools.copyFrom(decoded, new RandomShortReadInputStream(cis, random), -1);
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
    Bucket output = new ArrayBucket();
    OutputStream os = output.getOutputStream();
    AEADOutputStream cos = AEADOutputStream.innerCreateAES(os, key, random);
    BucketTools.copyTo(input, cos, 2048);
    cos.close();
    InputStream is = output.getInputStream();
    AEADInputStream cis = AEADInputStream.createAES(is, key);
    byte[] first1KReadEncrypted = new byte[1024];
    new DataInputStream(cis).readFully(first1KReadEncrypted);
    byte[] first1KReadOriginal = new byte[1024];
    new DataInputStream(input.getInputStream()).readFully(first1KReadOriginal);
    assertArrayEquals(first1KReadEncrypted, first1KReadOriginal);
    cis.close();
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
    Bucket output = new ArrayBucket();
    OutputStream os = output.getOutputStream();
    AEADOutputStream cos =
        AEADOutputStream.innerCreateAES(new NoCloseProxyOutputStream(os), key, random);
    BucketTools.copyTo(input, cos, -1);
    cos.close();
    // Now write garbage.
    FileUtil.fill(os, 1024);
    os.close();
    InputStream is = output.getInputStream();
    AEADInputStream cis = AEADInputStream.createAES(is, key);
    byte[] first1KReadEncrypted = new byte[1024];
    new DataInputStream(cis).readFully(first1KReadEncrypted);
    byte[] first1KReadOriginal = new byte[1024];
    new DataInputStream(input.getInputStream()).readFully(first1KReadOriginal);
    assertArrayEquals(first1KReadEncrypted, first1KReadOriginal);
    try {
      cis.close();
      fail("Hash should be bogus due to garbage data at end");
    } catch (AEADVerificationFailedException _) {
      // Expected.
    }
  }
}
