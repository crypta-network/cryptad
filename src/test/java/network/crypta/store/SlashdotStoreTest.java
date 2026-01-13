package network.crypta.store;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import network.crypta.keys.BlockEncodeParams;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKDecodeException;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.KeyVerifyException;
import network.crypta.node.stats.StoreAccessStats;
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SlashdotStoreTest {

  @BeforeEach
  void setUp() throws Exception {
    tempDir = new File("tmp-slashdotstoretest");
    boolean created = tempDir.mkdir();
    if (!created && !tempDir.isDirectory()) {
      fail("Failed to create temp directory: " + tempDir.getAbsolutePath());
    }
    FilenameGenerator fg = new FilenameGenerator(weakPRNG, true, tempDir, "temp-");
    tbf = new TempBucketFactory(exec, fg, 4096, 65536, false, 2 * 1024 * 1024, null);
    exec.start();
  }

  @AfterEach
  void tearDown() {
    FileUtil.removeAll(tempDir);
  }

  @Test
  void testSimple() throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    CHKStore store = new CHKStore();
    try (var _ =
        new SlashdotStore<>(store, 10, 30 * 1000, 5 * 1000, new TrivialTicker(exec), tbf)) {
      // Encode a block
      String test = "test";
      ClientCHKBlock block = encodeBlock(test);
      store.put(block.getBlock(), false);

      ClientCHK key = block.getClientKey();

      CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
      String data = decodeBlock(verify, key);
      assertEquals(test, data);
    }
  }

  @Test
  void testDeletion()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    CHKStore store = new CHKStore();
    SpeedyTicker st = new SpeedyTicker();
    try (SlashdotStore<CHKBlock> ss = new SlashdotStore<>(store, 10, 0, 100, st, tbf)) {
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
  }

  // ------------------------ Additional coverage below ------------------------

  @Test
  void fetch_whenDontPromote_true_evictsOnCapacity() throws Exception {
    // Arrange
    TestCallback cb = new TestCallback();
    SpeedyTicker ticker = new SpeedyTicker();
    try (SlashdotStore<TestBlock> ss =
        new SlashdotStore<>(cb, 3, /*lifetime*/ 60_000, 1_000, ticker, tbf)) {

      byte[] rkA = new byte[] {1, 1, 1};
      byte[] fkA = new byte[] {4, 5, 6, 7};
      byte[] header = new byte[] {8, 9};
      byte[] data = new byte[] {10, 11, 12};
      TestBlock a = new TestBlock(rkA, fkA);
      ss.put(a, data, header, false, false);

      byte[] rkB = new byte[] {2, 2, 2};
      byte[] fkB = new byte[] {40, 50, 60, 70};
      TestBlock b = new TestBlock(rkB, fkB);
      ss.put(b, data, header, false, false);

      // Precondition: both entries present with capacity 3
      assertTrue(ss.probablyInStore(rkA));
      assertTrue(ss.probablyInStore(rkB));

      // Act: fetch A without promoting
      assertNotNull(
          ss.fetch(rkA, fkA, /*dontPromote*/ true, false, true, false, null),
          "A should be returned before eviction");

      // Add C to exceed capacity 2 -> should evict LRU (A, since not promoted)
      byte[] rkC = new byte[] {3, 3, 3};
      byte[] fkC = new byte[] {1, 2, 3, 4};
      TestBlock c = new TestBlock(rkC, fkC);
      ss.put(c, data, header, false, false);

      // Assert
      assertTrue(ss.probablyInStore(rkB), "B must remain (A was LRU)");
      assertTrue(ss.probablyInStore(rkC), "C must be present (just inserted)");
      assertFalse(ss.probablyInStore(rkA), "A must be evicted as LRU");
    }
  }

  @Test
  void fetch_whenDontPromote_false_preservesOnCapacity() throws Exception {
    // Arrange
    TestCallback cb = new TestCallback();
    SpeedyTicker ticker = new SpeedyTicker();
    try (SlashdotStore<TestBlock> ss =
        new SlashdotStore<>(cb, 3, /*lifetime*/ 60_000, 1_000, ticker, tbf)) {
      byte[] header = new byte[] {8, 9};
      byte[] data = new byte[] {10, 11, 12};

      byte[] rkA = new byte[] {1, 1, 1};
      byte[] fkA = new byte[] {4, 5, 6, 7};
      ss.put(new TestBlock(rkA, fkA), data, header, false, false);

      byte[] rkB = new byte[] {2, 2, 2};
      byte[] fkB = new byte[] {40, 50, 60, 70};
      ss.put(new TestBlock(rkB, fkB), data, header, false, false);

      // Precondition: both entries present with capacity 3
      assertTrue(ss.probablyInStore(rkA));
      assertTrue(ss.probablyInStore(rkB));

      // Act: fetch A and promote it (dontPromote=false)
      assertNotNull(ss.fetch(rkA, fkA, /*dontPromote*/ false, false, true, false, null));

      // Insert C to trigger eviction; B should be LRU now and evicted
      byte[] rkC = new byte[] {3, 3, 3};
      byte[] fkC = new byte[] {1, 2, 3, 4};
      ss.put(new TestBlock(rkC, fkC), data, header, false, false);

      // Assert
      assertTrue(ss.probablyInStore(rkA), "A was promoted and must remain");
      assertTrue(ss.probablyInStore(rkC), "C must be present (just inserted)");
      assertFalse(ss.probablyInStore(rkB), "B must be evicted as LRU");
    }
  }

  @Test
  void fetch_whenCallbackThrowsKeyVerifyException_removesBlockAndCountsMiss() throws Exception {
    // Arrange: Mockito-based callback that always throws on construct
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> cb = (StoreCallback<TestBlock>) mock(StoreCallback.class);
    when(cb.headerLength()).thenReturn(2);
    when(cb.dataLength()).thenReturn(3);
    when(cb.fullKeyLength()).thenReturn(4);
    when(cb.construct(
            any(byte[].class),
            any(byte[].class),
            any(byte[].class),
            any(byte[].class),
            anyBoolean(),
            anyBoolean(),
            any(),
            any()))
        .thenThrow(new KeyVerifyException("bad"));

    SpeedyTicker ticker = new SpeedyTicker();
    try (SlashdotStore<TestBlock> ss = new SlashdotStore<>(cb, 10, 60_000, 1_000, ticker, tbf)) {
      byte[] rk = new byte[] {1, 1, 1};
      byte[] fk = new byte[] {4, 5, 6, 7};
      byte[] header = new byte[] {8, 9};
      byte[] data = new byte[] {10, 11, 12};
      ss.put(new TestBlock(rk, fk), data, header, false, false);
      assertTrue(ss.probablyInStore(rk), "Precondition: key present before fetch");

      // Act
      TestBlock out = ss.fetch(rk, fk, false, false, true, false, null);

      // Assert: block removed and miss counted
      assertNull(out, "Construct failure should return null");
      assertFalse(ss.probablyInStore(rk), "Entry must be removed on KeyVerifyException");
      assertEquals(1, ss.misses(), "Misses increment on verify failure");
      assertEquals(1, ss.writes(), "Writes counted on put");
      assertEquals(0, ss.hits(), "No successful hit recorded");
    }
  }

  @Test
  void probablyInStore_andCounters_andSessionAccessStats() throws Exception {
    // Arrange
    TestCallback cb = new TestCallback();
    try (SlashdotStore<TestBlock> ss =
        new SlashdotStore<>(cb, 10, 60_000, 1_000, new SpeedyTicker(), tbf)) {
      byte[] rk = new byte[] {7, 7, 7};
      byte[] fk = new byte[] {1, 2, 3, 4};
      byte[] header = new byte[] {8, 9};
      byte[] data = new byte[] {10, 11, 12};
      ss.put(new TestBlock(rk, fk), data, header, false, false);
      assertTrue(ss.probablyInStore(rk));

      // Act: one hit, one miss
      assertNotNull(ss.fetch(rk, fk, false, false, true, false, null));
      byte[] unknown = new byte[] {9, 9, 9};
      assertNull(ss.fetch(unknown, fk, false, false, true, false, null));

      // Assert metrics
      assertEquals(1, ss.hits());
      assertEquals(1, ss.misses());
      assertEquals(1, ss.writes());
      StoreAccessStats s = ss.getSessionAccessStats();
      assertEquals(1, s.hits());
      assertEquals(1, s.misses());
      assertEquals(0, s.falsePos());
      assertEquals(1, s.writes());
    }
  }

  @Test
  void setMaxKeys_whenExceedsIntegerMax_throws() {
    TestCallback cb = new TestCallback();
    try (SlashdotStore<TestBlock> ss =
        new SlashdotStore<>(cb, 10, 60_000, 1_000, new SpeedyTicker(), tbf)) {
      assertThrows(
          IllegalArgumentException.class,
          () -> ss.setMaxKeys(((long) Integer.MAX_VALUE) + 1L, true));
    }
  }

  @Test
  void setMaxKeys_whenShrinkNowTrue_immediateEviction() throws Exception {
    // Arrange
    TestCallback cb = new TestCallback();
    try (SlashdotStore<TestBlock> ss =
        new SlashdotStore<>(cb, 10, 60_000, 1_000, new SpeedyTicker(), tbf)) {
      byte[] header = new byte[] {8, 9};
      byte[] data = new byte[] {10, 11, 12};
      byte[] rk1 = new byte[] {1, 1, 1};
      byte[] fk1 = new byte[] {4, 5, 6, 7};
      byte[] rk2 = new byte[] {2, 2, 2};
      byte[] fk2 = new byte[] {40, 50, 60, 70};
      ss.put(new TestBlock(rk1, fk1), data, header, false, false);
      ss.put(new TestBlock(rk2, fk2), data, header, false, false);
      assertEquals(2, ss.keyCount());

      // Act: shrink to 1 and request immediate purge
      ss.setMaxKeys(1, true);

      // Assert: purger enforces a strict '< maxKeys' invariant; size must be <= 1
      assertTrue(ss.keyCount() <= 1);
    }
  }

  @Test
  void getters_basicBehaviors() {
    TestCallback cb = new TestCallback();
    try (SlashdotStore<TestBlock> ss =
        new SlashdotStore<>(cb, 10, 60_000, 1_000, new SpeedyTicker(), tbf)) {
      assertEquals(-1, ss.getBloomFalsePositive());
      assertEquals(10, ss.getMaxKeys());
      assertEquals(ss, ss.getUnderlyingStore());
      assertNull(ss.getTotalAccessStats());

      // lifetime get/set
      assertEquals(60_000L, ss.getLifetime());
      ss.setLifetime(1234L);
      assertEquals(1234L, ss.getLifetime());
    }
  }

  @Test
  void start_returnsFalse() throws IOException {
    TestCallback cb = new TestCallback();
    try (SlashdotStore<TestBlock> ss =
        new SlashdotStore<>(cb, 10, 60_000, 1_000, new SpeedyTicker(), tbf)) {
      assertFalse(ss.start(new SpeedyTicker(), true));
    }
  }

  // --- helpers ---

  private static final class TestBlock implements StorableBlock {
    private final byte[] routingKey;
    private final byte[] fullKey;

    TestBlock(byte[] routingKey, byte[] fullKey) {
      this.routingKey = routingKey;
      this.fullKey = fullKey;
    }

    @Override
    public byte[] getRoutingKey() {
      return routingKey;
    }

    @Override
    public byte[] getFullKey() {
      return fullKey;
    }
  }

  private static final class TestCallback extends StoreCallback<TestBlock> {
    @Override
    public int dataLength() {
      return 3;
    }

    @Override
    public int headerLength() {
      return 2;
    }

    @Override
    public int routingKeyLength() {
      return 3;
    }

    @Override
    public boolean storeFullKeys() {
      return true;
    }

    @Override
    public boolean constructNeedsKey() {
      return false;
    }

    @Override
    public int fullKeyLength() {
      return 4;
    }

    @Override
    public boolean collisionPossible() {
      return false;
    }

    @Override
    public TestBlock construct(
        byte[] data,
        byte[] headers,
        byte[] routingKey,
        byte[] fullKey,
        boolean canReadClientCache,
        boolean canReadSlashdotCache,
        BlockMetadata meta,
        network.crypta.crypt.DSAPublicKey knownPubKey) {
      // For tests, just return a block echoing the keys we were asked for
      return new TestBlock(routingKey, fullKey);
    }

    @Override
    public byte[] routingKeyFromFullKey(byte[] keyBuf) {
      // Simple mapping used only if needed by callers
      return new byte[] {keyBuf[0], keyBuf[1], keyBuf[2]};
    }
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
        new BlockEncodeParams(
            bucket,
            false,
            false,
            (short) -1,
            bucket.size(),
            Compressor.DEFAULT_COMPRESSORDESCRIPTOR),
        null,
        (byte) 0);
  }

  private final Random weakPRNG = new Random(12340);
  private final PooledExecutor exec = new PooledExecutor();
  private TempBucketFactory tbf;
  private File tempDir;
}
