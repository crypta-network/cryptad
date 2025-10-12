package network.crypta.support.io;

import java.io.IOException;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;

/**
 * Simple {@link BucketFactory} that creates in-memory {@link ArrayBucket} instances.
 *
 * <p>The {@code size} hint passed to {@link #makeBucket(long)} is ignored because {@link
 * ArrayBucket} grows as needed in memory.
 */
public class ArrayBucketFactory implements BucketFactory {

  @Override
  public RandomAccessBucket makeBucket(long size) throws IOException {
    return new ArrayBucket();
  }
}
