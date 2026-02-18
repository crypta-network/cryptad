package network.crypta.store;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;
import java.util.function.BooleanSupplier;
import java.util.stream.Stream;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.BlockEncodeParams;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKDecodeException;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.Key;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.store.saltedhash.ResizablePersistentIntBuffer;
import network.crypta.store.saltedhash.SaltedHashFreenetStore;
import network.crypta.store.saltedhash.SaltedHashStoreDependencies;
import network.crypta.store.saltedhash.SaltedHashStoreLocation;
import network.crypta.store.saltedhash.SaltedHashStoreParams;
import network.crypta.store.saltedhash.SaltedHashStoreSizing;
import network.crypta.support.PooledExecutor;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.Ticker;
import network.crypta.support.TrivialTicker;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Test migration from a RAMFreenetStore to a SaltedHashFreenetStore */
final class RAMSaltMigrationTest {

  private static final File TEMP_DIR = new File("tmp-RAMSaltMigrationTest");
  private static final String STORE_NAME = "teststore";
  private static final String COLLISIONS_MESSAGE_PREFIX =
      "The number of inserts minus the number of collissions should be the same as the number of"
          + " keys in the store. Collisions ";

  private final RandomSource strongPRNG = new DummyRandomSource(43210);
  private final Random weakPRNG = createSecureRandom();
  private final PooledExecutor exec = new PooledExecutor();
  private final Ticker ticker = new TrivialTicker(exec);

  @BeforeAll
  static void setupClass() {
    FileUtil.removeAll(TEMP_DIR);

    if (!TEMP_DIR.mkdir()) {
      throw new IllegalStateException("Could not create temporary directory for store tests");
    }
  }

  @BeforeEach
  void setUpTest() {
    ResizablePersistentIntBuffer.setPersistenceTime(-1);
    exec.start();
  }

  @AfterAll
  static void cleanup() {
    FileUtil.removeAll(TEMP_DIR);
  }

  private File getStorePath(String testname) {
    File storePath = new File(TEMP_DIR, "CachingFreenetStoreTest_" + testname);
    FileUtil.removeAll(storePath);
    if (!storePath.mkdirs()) {
      throw new IllegalStateException("Could not create temporary test store path: " + storePath);
    }
    return storePath;
  }

  /**
   * Insert Standard testing data
   *
   * @param keycount Number of keys to insert
   * @param store Store to put data to
   * @param dummyValueInsertedList The inserted values will be added to this list
   * @param blockInsertedList The inserted Blocks will be added to this list
   * @return number of collisions during the insert
   * @throws CHKEncodeException when block encoding fails
   * @throws IOException when writing blocks to the store fails
   */
  private int insertStandardTestBlocksIntoStore(
      int keycount,
      CHKStore store,
      List<String> dummyValueInsertedList,
      List<ClientCHKBlock> blockInsertedList)
      throws CHKEncodeException, IOException {

    int collisions = 0;
    for (int i = 0; i < keycount; i++) {
      String dummyValueInserted = "test" + i;
      ClientCHKBlock blockInserted = encodeBlock(dummyValueInserted, true);
      store.put(blockInserted.getBlock(), true);

      dummyValueInsertedList.add(dummyValueInserted);
      blockInsertedList.add(blockInserted);

      // Did we have a collision during the put and the actual size did not increase?
      if (store.keyCount() + collisions == i) {
        collisions++;
      }
    }
    return collisions;
  }

  /**
   * Probe all inserted keys and see what is actually there, after collisions might have happened
   * during insert or resize
   *
   * @param store to check for keys
   * @param dummyValueInsertedList to check for in store
   * @param blockInsertedList to check for in store
   * @param dummyValueActuallyStoredList found values will be added to this list
   * @param blockActuallyStoredList found blocks will be added to this list
   * @throws IOException when store fetches fail
   */
  private void probeStoreBlocks(
      CHKStore store,
      List<String> dummyValueInsertedList,
      List<ClientCHKBlock> blockInsertedList,
      List<String> dummyValueActuallyStoredList,
      List<ClientCHKBlock> blockActuallyStoredList)
      throws IOException {
    for (int i = 0; i < dummyValueInsertedList.size(); i++) {

      CHKBlock verify =
          store.fetch(blockInsertedList.get(i).getClientKey().getNodeCHK(), false, false, null);
      if (verify != null) {
        dummyValueActuallyStoredList.add(dummyValueInsertedList.get(i));
        blockActuallyStoredList.add(blockInsertedList.get(i));
      }
    }
    assertFalse(dummyValueActuallyStoredList.isEmpty(), "Inserts failed, not a single key stored");
  }

  /**
   * Checks if the store contains the given blocks and values
   *
   * @param store to check
   * @param dummyValueActuallyStoredList of values expected
   * @param blockActuallyStoredList of blocks expecte
   * @param expectAll true, if all keys must be in the store, or at least one will be enough to
   *     succeed
   * @throws CHKVerifyException when block verification fails
   * @throws CHKDecodeException when block decoding fails
   * @throws IOException when store fetches fail
   */
  private void checkStandardTestBlocks(
      CHKStore store,
      List<String> dummyValueActuallyStoredList,
      List<ClientCHKBlock> blockActuallyStoredList,
      boolean expectAll)
      throws CHKVerifyException, CHKDecodeException, IOException {

    int numberOfHits = 0;
    for (int i = 0; i < blockActuallyStoredList.size(); i++) {

      String value = dummyValueActuallyStoredList.get(i);
      ClientCHK key = blockActuallyStoredList.get(i).getClientKey();
      CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);

      if (expectAll) {
        assertNotNull(verify, "Expect all keys to be in store. Not found: " + value);
      } else if (verify == null) {
        continue;
      }

      String decodedValue = decodeBlock(verify, key);
      assertEquals(value, decodedValue);
      numberOfHits++;
    }

    assertTrue(numberOfHits > 0, "Not all keys in store were a hit");
  }

  @Test
  void ramStore_whenNewFormat_expectStoredBlockReadable()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    boolean newFormat = true;

    // Act
    checkRAMStore(newFormat);

    // Assert
    // Assertions are performed in checkRAMStore.
  }

  @Test
  void ramStore_whenOldFormat_expectStoredBlockReadable()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    boolean newFormat = false;

    // Act
    checkRAMStore(newFormat);

    // Assert
    // Assertions are performed in checkRAMStore.
  }

  private void checkRAMStore(boolean newFormat)
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    CHKStore store = new CHKStore();
    RAMFreenetStore<CHKBlock> ramFreenetStore = new RAMFreenetStore<>(store, 10);
    store.setStore(ramFreenetStore);

    // Encode a block
    String test = "test";
    ClientCHKBlock block = encodeBlock(test, newFormat);
    store.put(block.getBlock(), false);

    ClientCHK key = block.getClientKey();

    CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
    String data = decodeBlock(verify, key);
    assertEquals(test, data);
  }

  @Test
  void ramStore_whenOldBlocksWritten_expectFlagRespectedAndCleared()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    CHKStore store = new CHKStore();
    RAMFreenetStore<CHKBlock> ramFreenetStore = new RAMFreenetStore<>(store, 10);
    store.setStore(ramFreenetStore);

    String test = "test";
    ClientCHKBlock block = encodeBlock(test, false);

    // Act
    store.put(block.getBlock(), true);

    ClientCHK key = block.getClientKey();

    // Assert
    CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
    String data = decodeBlock(verify, key);
    assertEquals(test, data);

    // ignoreOldBlocks works.
    assertNull(store.fetch(key.getNodeCHK(), false, true, null));

    // Put it with oldBlock = false should unset the flag.
    store.put(block.getBlock(), false);

    verify = store.fetch(key.getNodeCHK(), false, true, null);
    data = decodeBlock(verify, key);
    assertEquals(test, data);
  }

  @Test
  void saltedStore_whenOldFormat_expectStoredBlocksReadable()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    boolean newFormat = false;
    String testName = "saltedStore_whenOldFormat_expectStoredBlocksReadable";

    // Act
    checkSaltedStore(newFormat, testName);

    // Assert
    // Assertions are performed in checkSaltedStore.
  }

  @Test
  void saltedStore_whenNewFormat_expectStoredBlocksReadable()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    boolean newFormat = true;
    String testName = "saltedStore_whenNewFormat_expectStoredBlocksReadable";

    // Act
    checkSaltedStore(newFormat, testName);

    // Assert
    // Assertions are performed in checkSaltedStore.
  }

  void checkSaltedStore(boolean newFormat, String testName)
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    CHKStore store = new CHKStore();

    File f = getStorePath(testName);
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, STORE_NAME),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(10, false, true, true)))) {
      saltStore.start(null, true);

      for (int i = 0; i < 5; i++) {

        // Encode a block
        String test = "test" + i;
        ClientCHKBlock block = encodeBlock(test, newFormat);
        store.put(block.getBlock(), false);

        ClientCHK key = block.getClientKey();

        CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
        String data = decodeBlock(verify, key);
        assertEquals(test, data);
      }
    }
  }

  private void innerTestSaltedStoreWithClose(int persistenceTime, String testName)
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    ResizablePersistentIntBuffer.setPersistenceTime(persistenceTime);

    int keycount = 5;

    CHKStore store = new CHKStore();
    File f = getStorePath(testName);
    List<String> dummyValueActuallyStoredList = new ArrayList<>(keycount);
    List<ClientCHKBlock> blockActuallyStoredList = new ArrayList<>(keycount);
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, STORE_NAME),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(10, false, true, true)))) {
      saltStore.start(null, true);

      List<String> dummyValueInsertedList = new ArrayList<>(keycount);
      List<ClientCHKBlock> blockInsertedList = new ArrayList<>(keycount);
      int collisions =
          insertStandardTestBlocksIntoStore(
              keycount, store, dummyValueInsertedList, blockInsertedList);

      probeStoreBlocks(
          store,
          dummyValueInsertedList,
          blockInsertedList,
          dummyValueActuallyStoredList,
          blockActuallyStoredList);
      assertEquals(
          dummyValueInsertedList.size() - collisions,
          blockActuallyStoredList.size(),
          COLLISIONS_MESSAGE_PREFIX + collisions);
    }

    store = new CHKStore();
    try (var _ =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, STORE_NAME),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(10, false, true, true)))) {
      checkStandardTestBlocks(store, dummyValueActuallyStoredList, blockActuallyStoredList, true);
    }
  }

  private void checkBlocks(CHKStore store, boolean write, boolean expectFailure)
      throws CHKEncodeException, IOException, CHKVerifyException, CHKDecodeException {

    for (int i = 0; i < 5; i++) {

      // Encode a block
      String test = "test" + i;
      // Use a new format for every other block to ensure they are mixed in the same store.
      ClientCHKBlock block = encodeBlock(test, (i & 1) == 1);
      if (write) store.put(block.getBlock(), false);

      ClientCHK key = block.getClientKey();

      CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
      if (expectFailure) assertNull(verify);
      else {
        String data = decodeBlock(verify, key);
        assertEquals(test, data);
      }
    }
  }

  private void innerTestSaltedStoreSlotFilterWithAbort(
      int persistenceTime,
      int delay,
      boolean expectFailure,
      boolean forceValidEmpty,
      String testName)
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    ResizablePersistentIntBuffer.setPersistenceTime(persistenceTime);

    File f = getStorePath(testName);

    CHKStore store = new CHKStore();
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, STORE_NAME),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(10, true, true, true)))) {
      saltStore.start(ticker, true);

      // Make sure it's clear.
      checkBlocks(store, false, true);

      checkBlocks(store, true, false);

      waitForDuration(Duration.ofMillis(delay));
    }

    store = new CHKStore();
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, STORE_NAME),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(10, true, true, true)))) {
      saltStore.start(ticker, true);
      if (forceValidEmpty) saltStore.forceValidEmpty();

      checkBlocks(store, false, expectFailure);
    }
  }

  @ParameterizedTest(name = "{1}")
  @MethodSource("saltedStoreWithCloseCases")
  void saltedStoreWithClose_whenVariedPersistenceTime_expectPersistedBlocks(
      int persistenceTime, String testName)
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange

    // Act
    innerTestSaltedStoreWithClose(persistenceTime, testName);

    // Assert
    // Assertions are performed in the innerTestSaltedStoreWithClose.
  }

  @Test
  void saltedStoreSlotFilter_whenWriteImmediatelyAndAbort_expectBlocksPersisted()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    int persistenceTime = -1;
    int delay = 0;
    boolean expectFailure = false;
    boolean forceValidEmpty = false;
    String testName = "saltedStoreSlotFilter_whenWriteImmediatelyAndAbort_expectBlocksPersisted";

    // Act
    innerTestSaltedStoreSlotFilterWithAbort(
        persistenceTime, delay, expectFailure, forceValidEmpty, testName);

    // Assert
    // Assertions are performed in innerTestSaltedStoreSlotFilterWithAbort.
  }

  @Test
  void saltedStoreSlotFilter_whenWaitLongerThanPersistenceTimeAndAbort_expectBlocksPersisted()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    int persistenceTime = 1000;
    int delay = 2000;
    boolean expectFailure = false;
    boolean forceValidEmpty = false;
    String testName =
        "saltedStoreSlotFilter_whenWaitLongerThanPersistenceTimeAndAbort_expectBlocksPersisted";

    // Act
    innerTestSaltedStoreSlotFilterWithAbort(
        persistenceTime, delay, expectFailure, forceValidEmpty, testName);

    // Assert
    // Assertions are performed in innerTestSaltedStoreSlotFilterWithAbort.
  }

  @Test
  void
      saltedStoreSlotFilter_whenNoWaitWithPersistenceTimeAndAbortSlotsUnknown_expectBlocksPersisted()
          throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    int persistenceTime = 5000;
    int delay = 0;
    boolean expectFailure = false;
    boolean forceValidEmpty = false;
    String testName =
        "saltedStoreSlotFilter_whenNoWaitWithPersistenceTimeAndAbortSlotsUnknown_expectBlocksPersisted";

    // Act
    innerTestSaltedStoreSlotFilterWithAbort(
        persistenceTime, delay, expectFailure, forceValidEmpty, testName);

    // Assert
    // Assertions are performed in innerTestSaltedStoreSlotFilterWithAbort.
  }

  @Test
  void saltedStoreSlotFilter_whenNoWaitWithPersistenceTimeForceKnownEmpty_expectBlocksPersisted()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    int persistenceTime = 5000;
    int delay = 0;
    boolean expectFailure = false;
    boolean forceValidEmpty = true;
    String testName =
        "saltedStoreSlotFilter_whenNoWaitWithPersistenceTimeForceKnownEmpty_expectBlocksPersisted";

    // Act
    innerTestSaltedStoreSlotFilterWithAbort(
        persistenceTime, delay, expectFailure, forceValidEmpty, testName);

    // Assert
    // Assertions are performed in innerTestSaltedStoreSlotFilterWithAbort.
  }

  @Test
  void saltedStoreSlotFilter_whenWriteImmediatelyForceKnownEmpty_expectBlocksPersisted()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    int persistenceTime = -1;
    int delay = 0;
    boolean expectFailure = false;
    boolean forceValidEmpty = true;
    String testName =
        "saltedStoreSlotFilter_whenWriteImmediatelyForceKnownEmpty_expectBlocksPersisted";

    // Act
    innerTestSaltedStoreSlotFilterWithAbort(
        persistenceTime, delay, expectFailure, forceValidEmpty, testName);

    // Assert
    // Assertions are performed in innerTestSaltedStoreSlotFilterWithAbort.
  }

  @Test
  void saltedStoreSlotFilter_whenPersistenceTimeAndLongWaitForceKnownEmpty_expectBlocksPersisted()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    int persistenceTime = 1000;
    int delay = 2000;
    boolean expectFailure = false;
    boolean forceValidEmpty = true;
    String testName =
        "saltedStoreSlotFilter_whenPersistenceTimeAndLongWaitForceKnownEmpty_expectBlocksPersisted";

    // Act
    innerTestSaltedStoreSlotFilterWithAbort(
        persistenceTime, delay, expectFailure, forceValidEmpty, testName);

    // Assert
    // Assertions are performed in innerTestSaltedStoreSlotFilterWithAbort.
  }

  @ParameterizedTest(name = "{2}")
  @MethodSource("saltedStoreOldBlocksCases")
  void saltedStoreOldBlocks_whenVariedSlotFilter_expectFlagsCleared(
      int keycount, int size, boolean useSlotFilter, String testName)
      throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
    // Arrange

    // Act
    checkSaltedStoreOldBlocks(keycount, size, useSlotFilter, testName);

    // Assert
    // Assertions are performed in checkSaltedStoreOldBlocks.
  }

  void checkSaltedStoreOldBlocks(int keycount, int size, boolean useSlotFilter, String testName)
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    int delay = 1000;
    ResizablePersistentIntBuffer.setPersistenceTime(delay);

    CHKStore store = new CHKStore();

    File f = getStorePath(testName);
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, STORE_NAME),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(size, useSlotFilter, true, true)))) {
      saltStore.start(null, true);

      List<String> dummyValueInsertedList = new ArrayList<>(keycount);
      List<ClientCHKBlock> blockInsertedList = new ArrayList<>(keycount);
      int collisions =
          insertStandardTestBlocksIntoStore(
              keycount, store, dummyValueInsertedList, blockInsertedList);

      List<String> dummyValueActuallyStoredList = new ArrayList<>(keycount);
      List<ClientCHKBlock> blockActuallyStoredList = new ArrayList<>(keycount);
      probeStoreBlocks(
          store,
          dummyValueInsertedList,
          blockInsertedList,
          dummyValueActuallyStoredList,
          blockActuallyStoredList);
      assertEquals(
          dummyValueInsertedList.size() - collisions,
          blockActuallyStoredList.size(),
          COLLISIONS_MESSAGE_PREFIX + collisions);

      for (int i = 0; i < dummyValueActuallyStoredList.size(); i++) {

        String value = dummyValueActuallyStoredList.get(i);
        ClientCHKBlock block = blockActuallyStoredList.get(i);

        ClientCHK key = block.getClientKey();

        CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
        String decodedValue = decodeBlock(verify, key);
        assertEquals(value, decodedValue);

        // ignoreOldBlocks works.
        assertNull(store.fetch(key.getNodeCHK(), false, true, null));

        // Put it with oldBlock = false should unset the flag.
        store.put(block.getBlock(), false);

        verify = store.fetch(key.getNodeCHK(), false, true, null);
        decodedValue = decodeBlock(verify, key);
        assertEquals(value, decodedValue);
      }
    }
  }

  @Test
  void saltedStoreResize_whenNoSlotFilterWriteImmediatelyNoAbortAndOpenNewSize_expectBlocksPresent()
      throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
    // Arrange
    int keycount = 5;
    int size = 10;
    int newSize = 20;
    boolean useSlotFilter = false;
    int persistenceTime = -1;
    boolean abort = false;
    boolean openNewSize = true;
    String testName =
        "saltedStoreResize_whenNoSlotFilterWriteImmediatelyNoAbortAndOpenNewSize_expectBlocksPresent";

    // Act
    checkSaltedStoreResize(
        keycount, size, newSize, useSlotFilter, persistenceTime, abort, openNewSize, testName);

    // Assert
    // Assertions are performed in checkSaltedStoreResize.
  }

  @Test
  void saltedStoreResize_whenSlotFilterWriteImmediatelyNoAbortAndOpenNewSize_expectBlocksPresent()
      throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
    // Arrange
    int keycount = 5;
    int size = 10;
    int newSize = 20;
    boolean useSlotFilter = true;
    int persistenceTime = -1;
    boolean abort = false;
    boolean openNewSize = true;
    String testName =
        "saltedStoreResize_whenSlotFilterWriteImmediatelyNoAbortAndOpenNewSize_expectBlocksPresent";

    // Act
    checkSaltedStoreResize(
        keycount, size, newSize, useSlotFilter, persistenceTime, abort, openNewSize, testName);

    // Assert
    // Assertions are performed in checkSaltedStoreResize.
  }

  @ParameterizedTest(name = "{7}")
  @MethodSource("saltedStoreResizeCases")
  void saltedStoreResize_whenSlotFilterAndLongPersistence_expectExpectedBlocksPresent(
      int keycount,
      int size,
      int newSize,
      boolean useSlotFilter,
      int persistenceTime,
      boolean abort,
      boolean openNewSize,
      String testName)
      throws CHKEncodeException, CHKVerifyException, CHKDecodeException, IOException {
    // Arrange

    // Act
    checkSaltedStoreResize(
        keycount, size, newSize, useSlotFilter, persistenceTime, abort, openNewSize, testName);

    // Assert
    // Assertions are performed in checkSaltedStoreResize.
  }

  void checkSaltedStoreResize(
      int keycount,
      int size,
      int newSize,
      boolean useSlotFilter,
      int persistenceTime,
      boolean abort,
      boolean openNewSize,
      String testName)
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    File f = getStorePath(testName);

    ResizablePersistentIntBuffer.setPersistenceTime(persistenceTime);

    CHKStore store = new CHKStore();
    SaltedHashFreenetStore.setNoCleanerSleep(true);
    List<String> dummyValueActuallyStoredList = new ArrayList<>(keycount);
    List<ClientCHKBlock> blockActuallyStoredList = new ArrayList<>(keycount);
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, STORE_NAME),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(size, useSlotFilter, true, true)))) {
      saltStore.start(ticker, true);

      List<String> dummyValueInsertedList = new ArrayList<>(keycount);
      List<ClientCHKBlock> blockInsertedList = new ArrayList<>(keycount);
      int collisions =
          insertStandardTestBlocksIntoStore(
              keycount, store, dummyValueInsertedList, blockInsertedList);
      saltStore.setMaxKeys(newSize, true);
      probeStoreBlocks(
          store,
          dummyValueInsertedList,
          blockInsertedList,
          dummyValueActuallyStoredList,
          blockActuallyStoredList);
      assertEquals(
          dummyValueInsertedList.size() - collisions,
          blockActuallyStoredList.size(),
          COLLISIONS_MESSAGE_PREFIX + collisions);

      saltStore.close(abort);
    }

    store = new CHKStore();
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, STORE_NAME),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(
                    openNewSize ? newSize : size, useSlotFilter, true, true)))) {
      saltStore.start(ticker, true);

      // If we did open the new size, we expect all previously matched keys to be present.
      // If we open the old size, it causes a resize again, which might create new collisions and
      // keys might be lost again.

      checkStandardTestBlocks(
          store, dummyValueActuallyStoredList, blockActuallyStoredList, openNewSize);
    }
  }

  @Test
  void migrate_whenRAMStoreMigrated_expectBlockReadableInNewStore()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    CHKStore store = new CHKStore();
    RAMFreenetStore<CHKBlock> ramStore = new RAMFreenetStore<>(store, 10);
    store.setStore(ramStore);

    String test = "test";
    ClientCHKBlock block = encodeBlock(test, true);

    // Act
    store.put(block.getBlock(), false);

    ClientCHK key = block.getClientKey();

    // Assert
    CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
    String data = decodeBlock(verify, key);
    assertEquals(test, data);

    CHKStore newStore = new CHKStore();
    File f = getStorePath("migrate_whenRAMStoreMigrated_expectBlockReadableInNewStore");
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, STORE_NAME),
                new SaltedHashStoreDependencies<>(
                    newStore, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(10, false, true, true)))) {
      saltStore.start(null, true);

      ramStore.migrateTo(newStore, false);

      CHKBlock newVerify = store.fetch(key.getNodeCHK(), false, false, null);
      String newData = decodeBlock(newVerify, key);
      assertEquals(test, newData);
    }
  }

  @Test
  void migrate_whenKeyedRAMStoreMigrated_expectBlockReadableInNewStore()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    CHKStore store = new CHKStore();
    RAMFreenetStore<CHKBlock> ramStore = new RAMFreenetStore<>(store, 10);
    store.setStore(ramStore);

    String test = "test";
    ClientCHKBlock block = encodeBlock(test, true);

    // Act
    store.put(block.getBlock(), false);

    ClientCHK key = block.getClientKey();

    // Assert
    CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
    String data = decodeBlock(verify, key);
    assertEquals(test, data);

    byte[] storeKey = new byte[32];
    strongPRNG.nextBytes(storeKey);

    CHKStore newStore = new CHKStore();
    File f = getStorePath("migrate_whenKeyedRAMStoreMigrated_expectBlockReadableInNewStore");
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, STORE_NAME),
                new SaltedHashStoreDependencies<>(
                    newStore, weakPRNG, SemiOrderedShutdownHook.get(), storeKey),
                new SaltedHashStoreSizing(10, false, true, true)))) {
      saltStore.start(null, true);

      ramStore.migrateTo(newStore, false);

      CHKBlock newVerify = store.fetch(key.getNodeCHK(), false, false, null);
      String newData = decodeBlock(newVerify, key);
      assertEquals(test, newData);
    }
  }

  private String decodeBlock(CHKBlock verify, ClientCHK key)
      throws CHKVerifyException, CHKDecodeException, IOException {
    ClientCHKBlock cb = new ClientCHKBlock(verify, key);
    Bucket output = cb.decode(new ArrayBucketFactory(), 32768, false);
    byte[] buf = BucketTools.toByteArray(output);
    return new String(buf, StandardCharsets.UTF_8);
  }

  private ClientCHKBlock encodeBlock(String test, boolean newFormat)
      throws CHKEncodeException, IOException {
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
        newFormat ? Key.ALGO_AES_CTR_256_SHA256 : Key.ALGO_AES_PCFB_256_SHA256);
  }

  private static Stream<Arguments> saltedStoreWithCloseCases() {
    return Stream.of(
        Arguments.of(-1, "saltedStoreWithClose_whenWriteImmediately_expectPersistedBlocks"),
        Arguments.of(0, "saltedStoreWithClose_whenWriteOnShutdown_expectPersistedBlocks"),
        Arguments.of(
            1000, "saltedStoreWithClose_whenWaitLongerThanPersistenceTime_expectPersistedBlocks"),
        Arguments.of(
            5000,
            "saltedStoreWithClose_whenNoWaitWithPersistenceTime_expectPersistedBlocksOnClose"));
  }

  private static Stream<Arguments> saltedStoreOldBlocksCases() {
    return Stream.of(
        Arguments.of(
            5, 10, false, "saltedStoreOldBlocks_whenNoSlotFiltersAndBloomZero_expectFlagsCleared"),
        Arguments.of(
            5, 10, false, "saltedStoreOldBlocks_whenNoSlotFiltersAndBloomFifty_expectFlagsCleared"),
        Arguments.of(
            5, 10, true, "saltedStoreOldBlocks_whenSlotFiltersAndBloomZero_expectFlagsCleared"));
  }

  private static Stream<Arguments> saltedStoreResizeCases() {
    return Stream.of(
        Arguments.of(
            5,
            10,
            20,
            true,
            60000,
            false,
            true,
            "saltedStoreResize_whenSlotFilterAndLongPersistenceNoAbortOpenNewSize_expectBlocksPresent"),
        Arguments.of(
            5,
            10,
            20,
            true,
            60000,
            false,
            false,
            "saltedStoreResize_whenSlotFilterAndLongPersistenceNoAbortNoOpenNewSize_expectSomeBlocksPresent"),
        Arguments.of(
            5,
            10,
            20,
            true,
            60000,
            true,
            true,
            "saltedStoreResize_whenSlotFilterAndLongPersistenceAbortOpenNewSize_expectBlocksPresent"),
        Arguments.of(
            5,
            10,
            20,
            true,
            60000,
            true,
            false,
            "saltedStoreResize_whenSlotFilterAndLongPersistenceAbortNoOpenNewSize_expectSomeBlocksPresent"));
  }

  private static SecureRandom createSecureRandom() {
    try {
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
      random.setSeed(12340L);
      return random;
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA1PRNG unavailable", e);
    }
  }

  private static void waitForDuration(Duration duration) {
    waitForCondition(() -> false, duration);
  }

  private static void waitForCondition(BooleanSupplier condition, Duration timeout) {
    long deadline = System.nanoTime() + timeout.toNanos();
    while (System.nanoTime() < deadline && !condition.getAsBoolean()) {
      long remainingNanos = deadline - System.nanoTime();
      long parkNanos = Math.min(remainingNanos, TimeUnit.MILLISECONDS.toNanos(10));
      LockSupport.parkNanos(parkNanos);
      if (Thread.interrupted()) {
        // Preserve prior behavior of ignoring interrupts in these tests.
        LockSupport.parkNanos(0L);
      }
    }
  }
}
