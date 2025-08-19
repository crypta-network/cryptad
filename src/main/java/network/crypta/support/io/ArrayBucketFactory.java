package network.crypta.support.io;

import java.io.IOException;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;

public class ArrayBucketFactory implements BucketFactory {

  @Override
  public RandomAccessBucket makeBucket(long size) throws IOException {
    return new ArrayBucket();
  }

  public void freeBucket(Bucket b) throws IOException {
    b.free();
  }
}
