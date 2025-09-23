package network.crypta.support.api;

import java.io.IOException;

public interface BucketFactory {
  /**
   * Create a bucket.
   *
   * @param size The maximum size of the data, or -1 or Long.MAX_VALUE if we don't know. Some
   *     buckets will throw IOException if you go over this length.
   * @return
   * @throws IOException
   */
  RandomAccessBucket makeBucket(long size) throws IOException;
}
