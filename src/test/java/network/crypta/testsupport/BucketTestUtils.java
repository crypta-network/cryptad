package network.crypta.testsupport;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Random;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBuffer;
import network.crypta.support.io.FileUtil;

/**
 * Test-only helpers for filling buckets and random-access buffers with deterministic bytes.
 *
 * <p>These utilities intentionally live under src/test to avoid leaking test helpers into
 * production binaries. Methods mirror the historical test-only helpers that previously lived in
 * BucketTools.
 */
public final class BucketTestUtils {
  private BucketTestUtils() {}

  /** Fill an entire Bucket with bytes from the provided {@link Random}. */
  public static void fill(Bucket bucket, Random random, long length) throws IOException {
    try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
      FileUtil.fill(os, random, length);
    }
  }

  /** Write random bytes into a {@link RandomAccessBuffer} at the given offset and length. */
  public static void fill(RandomAccessBuffer raf, Random random, long offset, long length)
      throws IOException {
    long moved = 0;
    final int bufferSize = FileUtil.BUFFER_SIZE; // reuse the project-wide buffer size
    byte[] buf = new byte[bufferSize];
    while (moved < length) {
      int toWrite = (int) Math.min(bufferSize, length - moved);
      random.nextBytes(buf);
      raf.pwrite(offset + moved, buf, 0, toWrite);
      moved += toWrite;
    }
  }
}
