package network.crypta.support.io;

import java.io.IOException;
import java.util.Random;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.support.api.Bucket;

public class PaddedEphemerallyEncryptedBucketTest extends BucketTestBase {
  @Override
  protected Bucket makeBucket(long size) throws IOException {
    FilenameGenerator filenameGenerator = new FilenameGenerator(weakPRNG, false, null, "junit");
    TempFileBucket fileBucket =
        new TempFileBucket(filenameGenerator.makeRandomFilename(), filenameGenerator);
    return new PaddedEphemerallyEncryptedBucket(fileBucket, 1024, strongPRNG, weakPRNG);
  }

  @Override
  protected void freeBucket(Bucket bucket) throws IOException {
    bucket.free();
  }

  private final RandomSource strongPRNG = new DummyRandomSource(12345);
  private final Random weakPRNG = new DummyRandomSource(54321);
}
