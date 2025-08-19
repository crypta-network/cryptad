package network.crypta.store;

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKDecodeException;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.support.PooledExecutor;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.SpeedyTicker;
import network.crypta.support.TrivialTicker;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.TempBucketFactory;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class SlashdotStoreTest {

  @Before
  public void setUp() throws java.lang.Exception {
    tempDir = new File("tmp-slashdotstoretest");
    tempDir.mkdir();
    fg = new FilenameGenerator(weakPRNG, true, tempDir, "temp-");
    tbf = new TempBucketFactory(exec, fg, 4096, 65536, weakPRNG, false, 2 * 1024 * 1024, null);
    exec.start();
  }

  @After
  public void tearDown() {
    FileUtil.removeAll(tempDir);
  }

  @Test
  public void testSimple()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    CHKStore store = new CHKStore();
    new SlashdotStore<>(store, 10, 30 * 1000, 5 * 1000, new TrivialTicker(exec), tbf);

    // Encode a block
    String test = "test";
    ClientCHKBlock block = encodeBlock(test);
    store.put(block.getBlock(), false);

    ClientCHK key = block.getClientKey();

    CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
    String data = decodeBlock(verify, key);
    assertEquals(test, data);
  }

  @Test
  public void testDeletion()
      throws IOException,
          CHKEncodeException,
          CHKVerifyException,
          CHKDecodeException,
          InterruptedException {
    CHKStore store = new CHKStore();
    SpeedyTicker st = new SpeedyTicker();
    SlashdotStore<CHKBlock> ss = new SlashdotStore<>(store, 10, 0, 100, st, tbf);

    // Encode a block
    String test = "test";
    ClientCHKBlock block = encodeBlock(test);
    store.put(block.getBlock(), false);

    // Do the same as what the ticker would have done...
    ss.purgeOldData();

    ClientCHK key = block.getClientKey();

    CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
    if (verify == null) {
      return; // Expected outcome
    }
    String data = decodeBlock(verify, key);
    System.err.println("Got data: " + data + " but should have been deleted!");
    fail();
  }

  private String decodeBlock(CHKBlock verify, ClientCHK key)
      throws CHKVerifyException, CHKDecodeException, IOException {
    ClientCHKBlock cb = new ClientCHKBlock(verify, key);
    Bucket output = cb.decode(new ArrayBucketFactory(), 32768, false);
    byte[] buf = BucketTools.toByteArray(output);
    return new String(buf, StandardCharsets.UTF_8);
  }

  private ClientCHKBlock encodeBlock(String test) throws CHKEncodeException, IOException {
    byte[] data = test.getBytes(StandardCharsets.UTF_8);
    SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data);
    return ClientCHKBlock.encode(
        bucket,
        false,
        false,
        (short) -1,
        bucket.size(),
        Compressor.DEFAULT_COMPRESSORDESCRIPTOR,
        null,
        (byte) 0);
  }

  private final RandomSource strongPRNG = new DummyRandomSource(43210);
  private final Random weakPRNG = new Random(12340);
  private final PooledExecutor exec = new PooledExecutor();
  private FilenameGenerator fg;
  private TempBucketFactory tbf;
  private File tempDir;
}
