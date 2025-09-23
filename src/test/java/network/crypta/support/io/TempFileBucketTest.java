package network.crypta.support.io;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.Random;
import network.crypta.support.api.Bucket;

public class TempFileBucketTest extends BucketTestBase {
  @Override
  protected Bucket makeBucket(long size) throws IOException {
    FilenameGenerator filenameGenerator = new FilenameGenerator(weakPRNG, false, null, "junit");
    BaseFileBucket bfb =
        new TempFileBucket(filenameGenerator.makeRandomFilename(), filenameGenerator);

    assertTrue("deleteOnFree", bfb.deleteOnFree());

    return bfb;
  }

  @Override
  protected void freeBucket(Bucket bucket) throws IOException {
    File file = ((BaseFileBucket) bucket).getFile();
    if (bucket.size() != 0) {
      assertTrue("TempFile not exist", file.exists());
    }
    bucket.free();
    assertFalse("TempFile not deleted", file.exists());
  }

  private final Random weakPRNG = new Random(12345);
}
