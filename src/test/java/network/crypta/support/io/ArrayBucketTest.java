package network.crypta.support.io;

import java.io.IOException;
import network.crypta.support.api.Bucket;

public class ArrayBucketTest extends BucketTestBase {
  public ArrayBucketFactory abf = new ArrayBucketFactory();

  @Override
  protected Bucket makeBucket(long size) throws IOException {
    return abf.makeBucket(size);
  }

  @Override
  protected void freeBucket(Bucket bucket) throws IOException {
    bucket.free();
  }
}
