package network.crypta.support.io;

import static org.junit.jupiter.api.Assertions.*;

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

    assertTrue(bfb.deleteOnFree(), "deleteOnFree");

    return bfb;
  }

  @Override
  protected void freeBucket(Bucket bucket) throws IOException {
    File file = ((BaseFileBucket) bucket).getFile();
    if (bucket.size() != 0) {
      assertTrue(file.exists(), "TempFile not exist");
    }
    bucket.free();
    assertFalse(file.exists(), "TempFile not deleted");
  }

  private final Random weakPRNG = new Random(12345);
}
