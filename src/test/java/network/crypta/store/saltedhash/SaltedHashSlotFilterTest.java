package network.crypta.store.saltedhash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKDecodeException;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.store.CHKStore;
import network.crypta.support.PooledExecutor;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.TestProperty;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Test the slot filter mechanism */
class SaltedHashSlotFilterTest {

  @BeforeAll
  static void setupClass() {
    FileUtil.removeAll(TEMP_DIR);

    if (!TEMP_DIR.mkdir()) {
      throw new IllegalStateException("Could not create temporary directory for store tests");
    }
  }

  @AfterAll
  static void cleanup() {
    FileUtil.removeAll(TEMP_DIR);
  }

  @BeforeEach
  void setUpTest() {
    ResizablePersistentIntBuffer.setPersistenceTime(-1);
    exec.start();
  }

  @Test
  @SuppressWarnings("UnnecessaryLocalVariable")
  void chkPresent_whenPersistenceImmediate_expectKeysPresent()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    int persistenceTime = -1;
    int testCount = TEST_COUNT;
    int acceptableFalsePositives = ACCEPTABLE_FALSE_POSITIVES;
    int storeSize = STORE_SIZE;
    String testName = "chkPresent_whenPersistenceImmediate_expectKeysPresent";

    // Act
    CheckResult result = checkCHKPresent(persistenceTime, testCount, storeSize, testName);

    // Assert
    assertTrue(result.falsePositives <= acceptableFalsePositives);
    assertEquals(testCount, result.verifiedKeys);
  }

  // Much longer than the test will take.
  @Test
  @SuppressWarnings("UnnecessaryLocalVariable")
  void chkPresent_whenPersistenceVeryLong_expectKeysPresent()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    int persistenceTime = 600 * 1000;
    int testCount = TEST_COUNT;
    int acceptableFalsePositives = ACCEPTABLE_FALSE_POSITIVES;
    int storeSize = STORE_SIZE;
    String testName = "chkPresent_whenPersistenceVeryLong_expectKeysPresent";

    // Act
    CheckResult result = checkCHKPresent(persistenceTime, testCount, storeSize, testName);

    // Assert
    assertTrue(result.falsePositives <= acceptableFalsePositives);
    assertEquals(testCount, result.verifiedKeys);
  }

  // Check that it doesn't reuse slots if it can avoid it.
  @Test
  void chkPresent_whenStoreFull_expectNoSlotReuse()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    int persistenceTime = -1;
    int testCount = SaltedHashFreenetStore.OPTION_MAX_PROBE;
    int acceptableFalsePositives = 1;
    int storeSize = SaltedHashFreenetStore.OPTION_MAX_PROBE;
    String testName = "chkPresent_whenStoreFull_expectNoSlotReuse";

    // Act
    CheckResult result = checkCHKPresent(persistenceTime, testCount, storeSize, testName);

    // Assert
    assertTrue(result.falsePositives <= acceptableFalsePositives);
    assertEquals(testCount, result.verifiedKeys);
  }

  @Test
  void chkPresent_whenStoreSpaceSmall_expectKeysPresent()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    int persistenceTime = -1;
    int testCount = 10;
    int acceptableFalsePositives = 1;
    int storeSize = 20;
    String testName = "chkPresent_whenStoreSpaceSmall_expectKeysPresent";

    // Act
    CheckResult result = checkCHKPresent(persistenceTime, testCount, storeSize, testName);

    // Assert
    assertTrue(result.falsePositives <= acceptableFalsePositives);
    assertEquals(testCount, result.verifiedKeys);
  }

  @Test
  void chkPresentWithClose_whenPersistenceImmediate_expectKeysPresentAfterReopen()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    int persistenceTime = -1;
    String testName = "chkPresentWithClose_whenPersistenceImmediate_expectKeysPresentAfterReopen";

    // Act
    CheckResult result = checkCHKPresentWithClose(persistenceTime, testName);

    // Assert
    assertTrue(result.falsePositives <= ACCEPTABLE_FALSE_POSITIVES);
    assertTrue(result.verifiedKeys > 0);
  }

  @Test
  void chkPresentWithClose_whenPersistenceVeryLong_expectKeysPresentAfterReopen()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    int persistenceTime = 600 * 1000;
    String testName = "chkPresentWithClose_whenPersistenceVeryLong_expectKeysPresentAfterReopen";

    // Act
    CheckResult result = checkCHKPresentWithClose(persistenceTime, testName);

    // Assert
    assertTrue(result.falsePositives <= ACCEPTABLE_FALSE_POSITIVES);
    assertTrue(result.verifiedKeys > 0);
  }

  private CheckResult checkCHKPresentWithClose(int persistenceTime, String testName)
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    ResizablePersistentIntBuffer.setPersistenceTime(persistenceTime);
    File f = getStorePath(testName);

    CHKStore store = new CHKStore();
    int falsePositives;
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            f,
            "testCachingFreenetStoreCHK",
            store,
            weakPRNG,
            STORE_SIZE,
            true,
            SemiOrderedShutdownHook.get(),
            true,
            true,
            null)) {
      saltStore.start(null, true);

      falsePositives = populateStore(store, saltStore, TEST_COUNT);
      saltStore.close(true);
    }

    store = new CHKStore();
    int verifiedKeys;
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            f,
            "testCachingFreenetStoreCHK",
            store,
            weakPRNG,
            STORE_SIZE,
            true,
            SemiOrderedShutdownHook.get(),
            true,
            true,
            null)) {
      saltStore.start(null, true);

      verifiedKeys = checkStore(store, saltStore, TEST_COUNT, false);
    }
    return new CheckResult(falsePositives, verifiedKeys);
  }

  @Test
  void chkPresent_whenStoreClosedWithAbort_expectKeysPresentAfterReopen()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    ResizablePersistentIntBuffer.setPersistenceTime(1000);
    File f = getStorePath("chkPresent_whenStoreClosedWithAbort_expectKeysPresentAfterReopen");

    // Act
    CHKStore store = new CHKStore();
    int falsePositives;
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            f,
            "testCachingFreenetStoreCHK",
            store,
            weakPRNG,
            STORE_SIZE,
            true,
            SemiOrderedShutdownHook.get(),
            true,
            true,
            null)) {
      saltStore.start(null, true);

      falsePositives = populateStore(store, saltStore, TEST_COUNT);
      saltStore.close(true);
    }

    store = new CHKStore();
    int verifiedKeys;
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            f,
            "testCachingFreenetStoreCHK",
            store,
            weakPRNG,
            STORE_SIZE,
            true,
            SemiOrderedShutdownHook.get(),
            true,
            true,
            null)) {
      saltStore.start(null, true);

      verifiedKeys = checkStore(store, saltStore, TEST_COUNT, false);
    }

    // Assert
    assertTrue(falsePositives <= ACCEPTABLE_FALSE_POSITIVES);
    assertTrue(verifiedKeys > 0);
  }

  @Test
  void chkPresent_whenSlotFiltersEnabledAfterPopulate_expectKeysPresent()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    ResizablePersistentIntBuffer.setPersistenceTime(1000);
    File f = getStorePath("chkPresent_whenSlotFiltersEnabledAfterPopulate_expectKeysPresent");

    // Act
    CHKStore store = new CHKStore();
    int falsePositives;
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            f,
            "testCachingFreenetStoreCHK",
            store,
            weakPRNG,
            STORE_SIZE,
            false,
            SemiOrderedShutdownHook.get(),
            true,
            true,
            null)) {
      saltStore.start(null, true);

      falsePositives = populateStore(store, saltStore, TEST_COUNT);
    }

    store = new CHKStore();
    // Now turn on slot filters. Does it still work?
    int verifiedKeys;
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            f,
            "testCachingFreenetStoreCHK",
            store,
            weakPRNG,
            STORE_SIZE,
            true,
            SemiOrderedShutdownHook.get(),
            true,
            true,
            null)) {
      saltStore.start(null, true);

      verifiedKeys = checkStore(store, saltStore, TEST_COUNT, false);
    }

    // Assert
    assertEquals(TEST_COUNT, falsePositives);
    assertTrue(verifiedKeys > 0);
  }

  @Test
  void chkPresent_whenSlotFiltersEnabledWithCleaner_expectKeysPresent()
      throws IOException,
          CHKEncodeException,
          CHKVerifyException,
          CHKDecodeException,
          InterruptedException {
    // Arrange
    ResizablePersistentIntBuffer.setPersistenceTime(1000);
    File f = getStorePath("chkPresent_whenSlotFiltersEnabledWithCleaner_expectKeysPresent");

    // Act
    CHKStore store = new CHKStore();
    int falsePositives;
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            f,
            "testCachingFreenetStoreCHK",
            store,
            weakPRNG,
            STORE_SIZE,
            false,
            SemiOrderedShutdownHook.get(),
            true,
            true,
            null)) {
      saltStore.start(null, true);

      falsePositives = populateStore(store, saltStore, TEST_COUNT);
    }

    store = new CHKStore();
    // Now turn on slot filters. Does it still work?
    SaltedHashFreenetStore.setNoCleanerSleep(true);
    int verifiedKeys;
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            f,
            "testCachingFreenetStoreCHK",
            store,
            weakPRNG,
            STORE_SIZE,
            true,
            SemiOrderedShutdownHook.get(),
            true,
            true,
            null)) {
      saltStore.start(null, true);
      saltStore.testingWaitForCleanerDone();

      verifiedKeys = checkStore(store, saltStore, TEST_COUNT, false);
    }

    // Assert
    assertEquals(TEST_COUNT, falsePositives);
    assertTrue(verifiedKeys > 0);
  }

  private File getStorePath(String testname) {
    File storePath = new File(TEMP_DIR, "CachingFreenetStoreTest_" + testname);
    FileUtil.removeAll(storePath);
    if (!storePath.mkdirs()) {
      throw new IllegalStateException("Could not create temporary test store path: " + storePath);
    }
    return storePath;
  }

  private int populateStore(CHKStore store, SaltedHashFreenetStore<CHKBlock> saltStore, int numKeys)
      throws CHKEncodeException, IOException, CHKVerifyException, CHKDecodeException {
    int falsePositives = 0;
    for (int i = 0; i < numKeys; i++) {
      String testValue = "test" + i;
      ClientCHKBlock block = encodeBlockCHK(testValue);
      ClientCHK key = block.getClientKey();
      byte[] routingKey = key.getRoutingKey();
      if (saltStore.probablyInStore(routingKey)) {
        falsePositives++;
      }
      store.put(block.getBlock(), false);
      assertTrue(saltStore.probablyInStore(routingKey));
      CHKBlock verifyBlock = store.fetch(key.getNodeCHK(), false, false, null);
      String verifyValue = decodeBlockCHK(verifyBlock, key);
      assertEquals(testValue, verifyValue);
    }
    return falsePositives;
  }

  private int checkStore(
      CHKStore store, SaltedHashFreenetStore<CHKBlock> saltStore, int numKeys, boolean requireAll)
      throws CHKEncodeException, IOException, CHKVerifyException, CHKDecodeException {
    int verifiedKeys = 0;
    for (int i = 0; i < numKeys; i++) {
      String value = "test" + i;
      ClientCHKBlock block = encodeBlockCHK(value);
      ClientCHK key = block.getClientKey();
      byte[] routingKey = key.getRoutingKey();
      CHKBlock verifyBlock = store.fetch(key.getNodeCHK(), false, false, null);
      if (!requireAll && verifyBlock == null) {
        continue;
      }

      assertTrue(saltStore.probablyInStore(routingKey));
      String verifyValue = decodeBlockCHK(verifyBlock, key);
      assertEquals(value, verifyValue);

      verifiedKeys++;
    }
    return verifiedKeys;
  }

  private CheckResult checkCHKPresent(
      int persistenceTime, int testCount, int storeSize, String testName)
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    ResizablePersistentIntBuffer.setPersistenceTime(persistenceTime);
    File f = getStorePath(testName);

    CHKStore store = new CHKStore();
    int falsePositives;
    int verifiedKeys;
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            f,
            "testCachingFreenetStoreCHK",
            store,
            weakPRNG,
            storeSize,
            true,
            SemiOrderedShutdownHook.get(),
            true,
            true,
            null)) {
      saltStore.start(null, true);

      falsePositives = populateStore(store, saltStore, testCount);
      verifiedKeys = checkStore(store, saltStore, testCount, true);
    }
    return new CheckResult(falsePositives, verifiedKeys);
  }

  private String decodeBlockCHK(CHKBlock verify, ClientCHK key)
      throws CHKVerifyException, CHKDecodeException, IOException {
    ClientCHKBlock cb = new ClientCHKBlock(verify, key);
    Bucket output = cb.decode(new ArrayBucketFactory(), 32768, false);
    byte[] buf = BucketTools.toByteArray(output);
    return new String(buf, StandardCharsets.UTF_8);
  }

  private ClientCHKBlock encodeBlockCHK(String test) throws CHKEncodeException, IOException {
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

  private static final int TEST_COUNT = TestProperty.EXTENSIVE ? 100 : 20;
  private static final int ACCEPTABLE_FALSE_POSITIVES = TestProperty.EXTENSIVE ? 5 : 2;
  private static final int STORE_SIZE = TEST_COUNT * 5;
  private static final File TEMP_DIR = new File("tmp-SaltedHashSlotFilterTest");
  private final Random weakPRNG = new Random(12340);
  private final PooledExecutor exec = new PooledExecutor();

  private record CheckResult(int falsePositives, int verifiedKeys) {}
}
