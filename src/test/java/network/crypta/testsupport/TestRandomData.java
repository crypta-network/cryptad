package network.crypta.testsupport;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;

/** Deterministic random-data fillers used across tests. */
public final class TestRandomData {
  private static final int DEFAULT_BUFFER_SIZE = 64 * 1024;

  private TestRandomData() {}

  public static void fillRandomAccessBuffer(
      LockableRandomAccessBuffer buffer, Random random, long offset, long length)
      throws IOException {
    fillRandomAccessBuffer(buffer, random, offset, length, DEFAULT_BUFFER_SIZE);
  }

  public static void fillRandomAccessBuffer(
      LockableRandomAccessBuffer buffer, Random random, long offset, long length, int chunkSize)
      throws IOException {
    if (chunkSize <= 0) {
      throw new IllegalArgumentException("chunkSize must be positive");
    }
    if (length <= 0) {
      return;
    }

    long remaining = length;
    long position = offset;
    byte[] chunk = new byte[(int) Math.min((long) chunkSize, remaining)];
    while (remaining > 0) {
      int toWrite = (int) Math.min((long) chunk.length, remaining);
      random.nextBytes(chunk);
      buffer.pwrite(position, chunk, 0, toWrite);
      position += toWrite;
      remaining -= toWrite;
    }
  }

  public static void fillBucketWithRandom(Bucket bucket, Random random, long length)
      throws IOException {
    fillBucketWithRandom(bucket, random, length, false, DEFAULT_BUFFER_SIZE);
  }

  public static void fillBucketWithRandom(
      Bucket bucket, Random random, long length, boolean useUnbufferedStream) throws IOException {
    fillBucketWithRandom(bucket, random, length, useUnbufferedStream, DEFAULT_BUFFER_SIZE);
  }

  public static void fillBucketWithRandom(
      Bucket bucket, Random random, long length, boolean useUnbufferedStream, int chunkSize)
      throws IOException {
    if (chunkSize <= 0) {
      throw new IllegalArgumentException("chunkSize must be positive");
    }

    if (length <= 0) {
      try (OutputStream ignored =
          useUnbufferedStream ? bucket.getOutputStreamUnbuffered() : bucket.getOutputStream()) {
        // Open+close to preserve original helper semantics.
      }
      return;
    }

    byte[] chunk = new byte[(int) Math.min((long) chunkSize, length)];
    long remaining = length;
    try (OutputStream out =
        useUnbufferedStream ? bucket.getOutputStreamUnbuffered() : bucket.getOutputStream()) {
      while (remaining > 0) {
        int toWrite = (int) Math.min((long) chunk.length, remaining);
        random.nextBytes(chunk);
        out.write(chunk, 0, toWrite);
        remaining -= toWrite;
      }
    }
  }
}
