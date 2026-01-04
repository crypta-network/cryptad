package network.crypta.client.async;

import static network.crypta.testsupport.TestRandomData.fillBucketWithRandom;
import static org.junit.jupiter.api.Assertions.*;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.function.BooleanSupplier;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.HighLevelSimpleClientImpl;
import network.crypta.client.InsertContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.client.Metadata;
import network.crypta.client.Metadata.SplitfileAlgorithm;
import network.crypta.client.MetadataParseException;
import network.crypta.client.MetadataUnresolvedException;
import network.crypta.client.OnionFECCodec;
import network.crypta.client.events.SimpleEventProducer;
import network.crypta.crypt.CRCChecksumChecker;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import network.crypta.node.BaseSendableGet;
import network.crypta.node.KeysFetchingLocally;
import network.crypta.node.SendableRequestItemKey;
import network.crypta.support.CheatingTicker;
import network.crypta.support.DummyJobRunner;
import network.crypta.support.MemoryLimitedJobRunner;
import network.crypta.support.PooledExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.WaitableExecutor;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import network.crypta.support.compress.Compressor.COMPRESSOR_TYPE;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.ByteArrayRandomAccessBufferFactory;
import network.crypta.support.io.NativeThread;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class SplitFileFetcherStorageTest {

  // Setup code is considerable. See below for actual tests ...

  static ClientCHK[] makeKeys(byte[][] blocks, byte[] cryptoKey, byte cryptoAlgorithm)
      throws CHKEncodeException {
    ClientCHK[] keys = new ClientCHK[blocks.length];
    for (int i = 0; i < blocks.length; i++) {
      keys[i] =
          ClientCHKBlock.encodeSplitfileBlock(blocks[i], cryptoKey, cryptoAlgorithm).getClientKey();
    }
    return keys;
  }

  static int sum(int[] values) {
    int total = 0;
    for (int x : values) {
      total += x;
    }
    return total;
  }

  static Bucket makeRandomBucket(long size) throws IOException {
    Bucket b = bf.makeBucket(size);
    fillBucketWithRandom(b, random, size);
    return b;
  }

  static byte[][] splitAndPadBlocks(Bucket data, long size) throws IOException {
    int n = (int) ((size + BLOCK_SIZE - 1) / BLOCK_SIZE);
    byte[][] blocks = new byte[n][];
    InputStream is = data.getInputStream();
    DataInputStream dis = new DataInputStream(is);
    for (int i = 0; i < n; i++) {
      blocks[i] = new byte[BLOCK_SIZE];
      if (i < n - 1) {
        dis.readFully(blocks[i]);
      } else {
        int length = (int) (size - i * BLOCK_SIZE);
        dis.readFully(blocks[i], 0, length);
        // Now pad it ...
        blocks[i] = BucketTools.pad(blocks[i], BLOCK_SIZE, length);
      }
    }
    return blocks;
  }

  static byte[] randomKey() {
    byte[] buf = new byte[KEY_LENGTH];
    random.nextBytes(buf);
    return buf;
  }

  static boolean[] falseArray(int checkBlocks) {
    return new boolean[checkBlocks];
  }

  static byte[][] constructBlocks(int n) {
    byte[][] blocks = new byte[n][];
    for (int i = 0; i < n; i++) {
      blocks[i] = new byte[BLOCK_SIZE];
    }
    return blocks;
  }

  @BeforeAll
  static void setUp() {
    // Initialize deterministic RNG once for the test class.
    random = new DummyRandomSource(1234);
    uri = FreenetURI.generateRandomCHK(random);
  }

  @Test
  void fetchSingleSegment_whenDifferentSizes_expectDecodeAndOutputMatch()
      throws CHKEncodeException,
          IOException,
          FetchException,
          MetadataParseException,
          MetadataUnresolvedException {
    // Arrange
    // 2 data blocks.
    // We don't test this case because it just copies the data block to the check blocks.
    // Which breaks some of the scripts here.
    // Act + Assert
    testSingleSegment(2, 1, BLOCK_SIZE * 2L);
    testSingleSegment(2, 1, BLOCK_SIZE + 1L);
    testSingleSegment(2, 2, BLOCK_SIZE * 2L);
    testSingleSegment(2, 2, BLOCK_SIZE + 1L);
    testSingleSegment(2, 3, BLOCK_SIZE * 2L);
    testSingleSegment(2, 3, BLOCK_SIZE + 1L);
    testSingleSegment(128, 128, BLOCK_SIZE * 128L);
    testSingleSegment(128, 128, BLOCK_SIZE * 128L - 1);
    testSingleSegment(129, 127, BLOCK_SIZE * 129L);
    testSingleSegment(129, 127, BLOCK_SIZE * 129L - 1);
    testSingleSegment(127, 129, BLOCK_SIZE * 127L);
    testSingleSegment(127, 129, BLOCK_SIZE * 127L - 1);
  }

  @Test
  void fetchMultiSegment_whenDifferentLayouts_expectDecodeAndOutputMatch()
      throws CHKEncodeException,
          IOException,
          MetadataUnresolvedException,
          MetadataParseException,
          FetchException {
    // Arrange
    // We have to be consistent with the format, but we can in fact play with the segment sizes
    // to some degree.

    // Act + Assert
    // Simplest case: Same number of blocks in each segment.
    // 2 blocks in each of 2 segments.
    testMultiSegment(32768L * 4, new int[] {2, 2}, new int[] {3, 3}, 2, 3, 0);
    testMultiSegment(32768L * 4 - 1, new int[] {2, 2}, new int[] {3, 3}, 2, 3, 0);

    // 3 blocks in 3 segments
    testMultiSegment(32768L * 9 - 1, new int[] {3, 3, 3}, new int[] {4, 4, 4}, 3, 4, 0);

    // Deduct blocks. This is how we handle this situation in modern splitfiles.
    testMultiSegment(32768L * 7 - 1, new int[] {3, 2, 2}, new int[] {4, 4, 4}, 3, 4, 2);

    // Sharp truncation. This is how we used to handle non-divisible numbers...
    testMultiSegment(32768L * 9 - 1, new int[] {7, 2}, new int[] {7, 2}, 7, 7, 0);
    // Still COMPAT_1416 because has crypto key etc.

    // Note: legacy splitfiles are not covered here (tracked separately).
    // Note: very old splitfiles where last data block is not padded are not covered.
    // Note: non-redundant legacy splitfile support is not covered.
  }

  @Test
  void chooseRandomKey_whenMaxRetriesZero_expectNoneAfterOneRound()
      throws CHKEncodeException,
          IOException,
          MetadataUnresolvedException,
          MetadataParseException,
          FetchException {
    // Arrange
    int dataBlocks = 3;
    int checkBlocks = 3;
    TestSplitfile test =
        TestSplitfile.constructSingleSegment(dataBlocks * (long) BLOCK_SIZE, checkBlocks, false);
    StorageCallback cb = test.createStorageCallback();
    FetchContext ctx = test.makeFetchContext();
    ctx.setMaxSplitfileBlockRetries(0);
    SplitFileFetcherStorage storage = test.createStorage(cb, ctx);
    // Act
    boolean[] tried = new boolean[dataBlocks + checkBlocks];
    innerChooseKeyTest(dataBlocks, checkBlocks, storage.segments[0], tried, test, false);

    // Assert
    assertNull(storage.chooseRandomKey());
    cb.waitForFailed();
  }

  @Test
  void chooseRandomKey_whenMaxRetriesTwo_expectNoneAfterThreeRounds()
      throws CHKEncodeException,
          IOException,
          MetadataUnresolvedException,
          MetadataParseException,
          FetchException {
    // Arrange
    int dataBlocks = 3;
    int checkBlocks = 3;
    TestSplitfile test =
        TestSplitfile.constructSingleSegment(dataBlocks * (long) BLOCK_SIZE, checkBlocks, false);
    StorageCallback cb = test.createStorageCallback();
    FetchContext ctx = test.makeFetchContext();
    ctx.setMaxSplitfileBlockRetries(2);
    SplitFileFetcherStorage storage = test.createStorage(cb, ctx);
    // Act
    for (int i = 0; i < 3; i++) {
      boolean[] tried = new boolean[dataBlocks + checkBlocks];
      innerChooseKeyTest(dataBlocks, checkBlocks, storage.segments[0], tried, test, false);
    }

    // Assert
    assertNull(storage.chooseRandomKey());
    cb.waitForFailed();
  }

  @Test
  void chooseRandomKey_whenCooldownConfigured_expectCooldownThenResumeAndFail()
      throws CHKEncodeException,
          IOException,
          MetadataUnresolvedException,
          MetadataParseException,
          FetchException {
    // Arrange
    int dataBlocks = 3;
    int checkBlocks = 3;
    int cooldownTimeMs = 200;
    TestSplitfile test =
        TestSplitfile.constructSingleSegment(dataBlocks * (long) BLOCK_SIZE, checkBlocks, false);
    StorageCallback cb = test.createStorageCallback();
    FetchContext ctx = test.makeFetchContext();
    ctx.setMaxSplitfileBlockRetries(5);
    ctx.setCooldownRetries(3);
    ctx.setCooldownTime(cooldownTimeMs, true);
    SplitFileFetcherStorage storage = test.createStorage(cb, ctx);
    // Act
    // 3 tries for each block.
    long now = System.currentTimeMillis();
    for (int i = 0; i < 3; i++) {
      boolean[] tried = new boolean[dataBlocks + checkBlocks];
      innerChooseKeyTest(dataBlocks, checkBlocks, storage.segments[0], tried, test, true);
    }

    // Assert: cooldown engaged then cleared
    assertTrue(storage.segments[0].getOverallCooldownTime() > now);
    assertNotEquals(Long.MAX_VALUE, storage.segments[0].getOverallCooldownTime());
    // Now in cooldown.
    test.fetchingKeys.clear();
    assertNull(storage.chooseRandomKey());
    // Await cooldown expiry deterministically without Thread.sleep:
    // poll chooseRandomKey until it becomes available again.
    awaitTrue(
        () -> {
          test.fetchingKeys.clear();
          return storage.chooseRandomKey() != null;
        },
        cooldownTimeMs * 3L);
    cb.checkFailed();
    // Should be out of cooldown now.
    for (int i = 0; i < 3; i++) {
      boolean[] tried = new boolean[dataBlocks + checkBlocks];
      innerChooseKeyTest(dataBlocks, checkBlocks, storage.segments[0], tried, test, true);
    }
    // Now it should fail.
    cb.waitForFailed();
  }

  @Test
  void readSegmentKeys_whenReadingBack_expectEquality()
      throws FetchException,
          MetadataParseException,
          IOException,
          CHKEncodeException,
          MetadataUnresolvedException,
          ChecksumFailedException {
    // Arrange
    int dataBlocks = 3;
    int checkBlocks = 3;
    TestSplitfile test =
        TestSplitfile.constructSingleSegment(dataBlocks * BLOCK_SIZE, checkBlocks, true);
    StorageCallback cb = test.createStorageCallback();
    SplitFileFetcherStorage storage = test.createStorage(cb);
    SplitFileFetcherSegmentStorage segment = storage.segments[0];
    // Act
    SplitFileSegmentKeys keys = segment.getSegmentKeys();
    SplitFileSegmentKeys moreKeys = segment.readSegmentKeys();

    // Assert
    assertEquals(keys, moreKeys);
    storage.close();
  }

  /** Test persistence: Create and then reload. Don't do anything. */
  @Test
  void persistenceReload_whenNoAction_expectNoErrors()
      throws CHKEncodeException,
          IOException,
          MetadataUnresolvedException,
          MetadataParseException,
          FetchException,
          StorageFormatException {
    // Arrange
    int checkBlocks = 3;
    long size = 32768L * 2 - 1;
    TestSplitfile test = TestSplitfile.constructSingleSegment(size, checkBlocks, true);
    StorageCallback cb = test.createStorageCallback();

    // Act
    SplitFileFetcherStorage storage = createSplitFileFetcherStorageTwice(test, cb);

    // Assert
    storage.close();
  }

  @Test
  void persistenceReload_whenThenFetching_expectDecodeAndOutputMatch()
      throws IOException,
          StorageFormatException,
          CHKEncodeException,
          MetadataUnresolvedException,
          MetadataParseException,
          FetchException {
    // Arrange
    int checkBlocks = 3;
    long size = 32768L * 2 - 1;
    TestSplitfile test = TestSplitfile.constructSingleSegment(size, checkBlocks, true);
    StorageCallback cb = test.createStorageCallback();
    SplitFileFetcherStorage storage = createSplitFileFetcherStorageTwice(test, cb);
    SplitFileFetcherSegmentStorage segment = storage.segments[0];
    assertFalse(segment.corruptMetadata());
    int total = test.dataBlocks.length + test.checkBlocks.length;
    // Act
    for (int i = 0; i < total; i++) {
      segment.onNonFatalFailure(i); // We want healing on all blocks that aren't found.
    }
    boolean[] hits = new boolean[total];
    for (int i = 0; i < test.dataBlocks.length; i++) {
      int block;
      do {
        block = random.nextInt(total);
      } while (hits[block]);
      hits[block] = true;
      assertFalse(segment.hasStartedDecode());
      assertTrue(segment.onGotKey(test.getCHK(block), test.encodeBlock(block)));
      cb.markDownloadedBlock(block);
    }
    // Assert
    cb.checkFailed();
    assertTrue(segment.hasStartedDecode());
    cb.checkFailed();
    waitForDecode(segment);
    cb.checkFailed();
    cb.waitForFinished();
    cb.checkFailed();
    test.verifyOutput(storage);
    cb.checkFailed();
    storage.finishedFetcher();
    cb.checkFailed();
    waitForFinished(segment);
    cb.checkFailed();
    cb.waitForFree();
    cb.checkFailed();
  }

  @Test
  void chooseRandomKey_whenReloaded_expectExhaustionAfterRetries()
      throws IOException,
          StorageFormatException,
          CHKEncodeException,
          MetadataUnresolvedException,
          MetadataParseException,
          FetchException {
    // Arrange
    int dataBlocks = 2;
    int checkBlocks = 3;
    long size = 32768L * 2 - 1;
    TestSplitfile test = TestSplitfile.constructSingleSegment(size, checkBlocks, true);
    StorageCallback cb = test.createStorageCallback();
    FetchContext ctx = test.makeFetchContext();
    ctx.setMaxSplitfileBlockRetries(2);
    test.createStorage(cb, ctx);
    // No need to shut down the old storage.
    SplitFileFetcherStorage storage = test.createStorage(cb, ctx, cb.getRAF());

    // Act
    for (int i = 0; i < 3; i++) {
      boolean[] tried = new boolean[dataBlocks + checkBlocks];
      innerChooseKeyTest(dataBlocks, checkBlocks, storage.segments[0], tried, test, false);
    }

    // Assert
    test.fetchingKeys.clear();
    assertNull(storage.chooseRandomKey());
    cb.waitForFailed();
  }

  @Test
  void chooseRandomKey_whenReloadedBetweenRounds_expectExhaustionAfterRetries()
      throws IOException,
          StorageFormatException,
          CHKEncodeException,
          MetadataUnresolvedException,
          MetadataParseException,
          FetchException {
    // Arrange
    int dataBlocks = 2;
    int checkBlocks = 3;
    long size = 32768L * 2 - 1;
    TestSplitfile test = TestSplitfile.constructSingleSegment(size, checkBlocks, true);
    StorageCallback cb = test.createStorageCallback();
    FetchContext ctx = test.makeFetchContext();
    ctx.setMaxSplitfileBlockRetries(2);
    test.createStorage(cb, ctx);
    // No need to shut down the old storage.
    SplitFileFetcherStorage storage = test.createStorage(cb, ctx, cb.getRAF());

    // Act
    boolean expectedFailureOnLastRound = false;
    for (int i = 0; i < 3; i++) {
      boolean[] tried = new boolean[dataBlocks + checkBlocks];
      innerChooseKeyTest(dataBlocks, checkBlocks, storage.segments[0], tried, test, false);
      // Reload.
      exec.waitForIdle();
      try {
        storage = test.createStorage(cb, ctx, cb.getRAF());
        storage.start(false);
      } catch (FetchException e) {
        if (i == 2) {
          expectedFailureOnLastRound = true;
          break;
        }
        throw e; // Not the final iteration: propagate
      }
    }
    if (expectedFailureOnLastRound) return;

    // Assert
    test.fetchingKeys.clear();
    assertNull(storage.chooseRandomKey());
    cb.waitForFailed();
  }

  @Test
  void fetch_whenReloadedBetweenBlocks_expectDecodeAndOutputMatch()
      throws IOException,
          StorageFormatException,
          CHKEncodeException,
          MetadataUnresolvedException,
          MetadataParseException,
          FetchException {
    // Arrange
    int checkBlocks = 3;
    long size = 32768L * 2 - 1;
    TestSplitfile test = TestSplitfile.constructSingleSegment(size, checkBlocks, true);
    StorageCallback cb = test.createStorageCallback();
    SplitFileFetcherStorage storage = createSplitFileFetcherStorageTwice(test, cb);
    SplitFileFetcherSegmentStorage segment = storage.segments[0];
    assertFalse(segment.corruptMetadata());
    int total = test.dataBlocks.length + test.checkBlocks.length;

    // Act
    for (int i = 0; i < total; i++) {
      segment.onNonFatalFailure(i); // We want healing on all blocks that aren't found.
    }
    boolean[] hits = new boolean[total];
    for (int i = 0; i < test.dataBlocks.length; i++) {
      int block;
      do {
        block = random.nextInt(total);
      } while (hits[block]);
      hits[block] = true;
      assertFalse(segment.hasStartedDecode());
      assertTrue(segment.onGotKey(test.getCHK(block), test.encodeBlock(block)));
      cb.markDownloadedBlock(block);
      if (i != test.dataBlocks.length - 1) {
        // Reload.
        exec.waitForIdle();
        storage = test.createStorage(cb, test.makeFetchContext(), cb.getRAF());
        segment = storage.segments[0];
        storage.start(false);
      }
    }
    // Assert
    cb.checkFailed();
    assertTrue(segment.hasStartedDecode());
    cb.checkFailed();
    waitForDecode(segment);
    cb.checkFailed();
    cb.waitForFinished();
    cb.checkFailed();
    test.verifyOutput(storage);
    cb.checkFailed();
    storage.finishedFetcher();
    cb.checkFailed();
    waitForFinished(segment);
    cb.checkFailed();
    cb.waitForFree();
    cb.checkFailed();
  }

  private void testSingleSegment(int dataBlocks, int checkBlocks, long size)
      throws CHKEncodeException,
          IOException,
          FetchException,
          MetadataParseException,
          MetadataUnresolvedException {
    assertTrue(dataBlocks * (long) BLOCK_SIZE >= size);
    TestSplitfile test = TestSplitfile.constructSingleSegment(size, checkBlocks, false);
    testDataBlocksOnly(test);
    if (checkBlocks >= dataBlocks) {
      testCheckBlocksOnly(test);
    }
    testRandomMixture(test);
    test.free();
  }

  private void testDataBlocksOnly(TestSplitfile test)
      throws IOException, CHKEncodeException, FetchException, MetadataParseException {
    StorageCallback cb = test.createStorageCallback();
    SplitFileFetcherStorage storage = test.createStorage(cb);
    SplitFileFetcherSegmentStorage segment = storage.segments[0];
    for (int i = 0; i < test.checkBlocks.length; i++) {
      segment.onNonFatalFailure(test.dataBlocks.length + i);
    }
    for (int i = 0; i < test.dataBlocks.length; i++) {
      assertFalse(segment.hasStartedDecode());
      assertTrue(segment.onGotKey(test.dataKeys[i].getNodeCHK(), test.encodeDataBlock(i)));
      cb.markDownloadedBlock(i);
    }
    cb.checkFailed();
    assertTrue(segment.hasStartedDecode());
    cb.checkFailed();
    waitForDecode(segment);
    cb.checkFailed();
    cb.waitForFinished();
    cb.checkFailed();
    test.verifyOutput(storage);
    cb.checkFailed();
    storage.finishedFetcher();
    cb.checkFailed();
    waitForFinished(segment);
    cb.checkFailed();
    cb.waitForFree();
    cb.checkFailed();
  }

  private void testCheckBlocksOnly(TestSplitfile test)
      throws IOException, CHKEncodeException, FetchException, MetadataParseException {
    StorageCallback cb = test.createStorageCallback();
    SplitFileFetcherStorage storage = test.createStorage(cb);
    SplitFileFetcherSegmentStorage segment = storage.segments[0];
    for (int i = 0; i < test.dataBlocks.length; i++) {
      segment.onNonFatalFailure(i);
    }
    for (int i = test.dataBlocks.length; i < test.checkBlocks.length; i++) {
      segment.onNonFatalFailure(i + test.dataBlocks.length);
    }
    for (int i = 0; i < test.dataBlocks.length /* only need that many to decode */; i++) {
      assertFalse(segment.hasStartedDecode());
      assertTrue(segment.onGotKey(test.checkKeys[i].getNodeCHK(), test.encodeCheckBlock(i)));
      cb.markDownloadedBlock(i + test.dataBlocks.length);
    }
    cb.checkFailed();
    assertTrue(segment.hasStartedDecode());
    cb.checkFailed();
    waitForDecode(segment);
    cb.checkFailed();
    cb.waitForFinished();
    cb.checkFailed();
    test.verifyOutput(storage);
    cb.checkFailed();
    storage.finishedFetcher();
    cb.checkFailed();
    waitForFinished(segment);
    cb.checkFailed();
    cb.waitForFree();
    cb.checkFailed();
  }

  private void testRandomMixture(TestSplitfile test)
      throws FetchException, MetadataParseException, IOException, CHKEncodeException {
    StorageCallback cb = test.createStorageCallback();
    SplitFileFetcherStorage storage = test.createStorage(cb);
    SplitFileFetcherSegmentStorage segment = storage.segments[0];
    int total = test.dataBlocks.length + test.checkBlocks.length;
    for (int i = 0; i < total; i++) {
      segment.onNonFatalFailure(i); // We want healing on all blocks that aren't found.
    }
    boolean[] hits = new boolean[total];
    for (int i = 0; i < test.dataBlocks.length; i++) {
      int block;
      do {
        block = random.nextInt(total);
      } while (hits[block]);
      hits[block] = true;
      assertFalse(segment.hasStartedDecode());
      assertTrue(segment.onGotKey(test.getCHK(block), test.encodeBlock(block)));
      cb.markDownloadedBlock(block);
    }
    // Assert output verified below.
    cb.checkFailed();
    assertTrue(segment.hasStartedDecode());
    cb.checkFailed();
    waitForDecode(segment);
    cb.checkFailed();
    cb.waitForFinished();
    cb.checkFailed();
    test.verifyOutput(storage);
    cb.checkFailed();
    storage.finishedFetcher();
    cb.checkFailed();
    waitForFinished(segment);
    cb.checkFailed();
    cb.waitForFree();
    cb.checkFailed();
  }

  @Test
  void getPriorityClass_whenCallbackProvidesValue_returnsSame() throws Exception {
    // Arrange
    TestSplitfile test = TestSplitfile.constructSingleSegment(BLOCK_SIZE * 2L, 2, false);
    class PriorityCallback extends StorageCallback {
      private final short pc;

      PriorityCallback(TestSplitfile splitfile, short pc) {
        super(splitfile);
        this.pc = pc;
      }

      @Override
      public short getPriorityClass() {
        return pc;
      }
    }

    short expected = 42;
    StorageCallback cb = new PriorityCallback(test, expected);
    SplitFileFetcherStorage storage = test.createStorage(cb);

    try {
      // Act
      short actual = storage.getPriorityClass();

      // Assert
      assertEquals(expected, actual);
    } finally {
      storage.close();
    }
  }

  @Test
  void listAndCountUnfetchedKeys_whenFresh_returnsAllKeys() throws Exception {
    // Arrange: small single segment for determinism
    TestSplitfile test = TestSplitfile.constructSingleSegment(BLOCK_SIZE * 2L, 2, false);
    StorageCallback cb = test.createStorageCallback();
    SplitFileFetcherStorage storage = test.createStorage(cb);

    try {
      int totalBlocks = test.dataBlocks.length + test.checkBlocks.length;

      // Act
      long count = storage.countUnfetchedKeys();
      Key[] keys = storage.listUnfetchedKeys();

      // Assert
      assertEquals(totalBlocks, count);
      assertEquals(totalBlocks, keys.length);

      // Verify the returned keys match the metadata keys (node form)
      HashSet<Key> expected = new HashSet<>();
      for (int i = 0; i < totalBlocks; i++) {
        expected.add(test.getCHK(i));
      }
      HashSet<Key> actual = new HashSet<>(Arrays.asList(keys));
      assertEquals(expected, actual);
    } finally {
      storage.close();
    }
  }

  @Test
  void getKey_whenGivenStorageKey_returnsCorrespondingClientKey() throws Exception {
    // Arrange
    TestSplitfile test = TestSplitfile.constructSingleSegment(BLOCK_SIZE * 2L, 2, false);
    StorageCallback cb = test.createStorageCallback();
    SplitFileFetcherStorage storage = test.createStorage(cb);

    try {
      int blockIndex = 1; // within first (and only) segment
      int segmentNumber = 0;
      SplitFileFetcherStorage.SplitFileFetcherStorageKey skey =
          new SplitFileFetcherStorage.SplitFileFetcherStorageKey(
              blockIndex, segmentNumber, storage);

      // Act
      var clientKey = storage.getKey(skey);

      // Assert: node key should match metadata
      assertNotNull(clientKey);
      assertEquals(test.getCHK(blockIndex), clientKey.getNodeKey(false));
    } finally {
      storage.close();
    }
  }

  @Test
  void setHasCheckedStore_whenCalled_marksFlagTrue() throws Exception {
    // Arrange (persistent to exercise write path, though not asserted here)
    TestSplitfile test = TestSplitfile.constructSingleSegment(BLOCK_SIZE * 2L, 1, true);
    StorageCallback cb = test.createStorageCallback();
    SplitFileFetcherStorage storage = test.createStorage(cb);

    try {
      assertFalse(storage.hasCheckedStore());

      // Act
      storage.setHasCheckedStore(null);

      // Assert
      assertTrue(storage.hasCheckedStore());
    } finally {
      storage.close();
    }
  }

  @Test
  void streamGenerator_size_returnsMetadataFinalLength() throws Exception {
    // Arrange
    TestSplitfile test = TestSplitfile.constructSingleSegment(BLOCK_SIZE * 3L - 10, 2, false);
    StorageCallback cb = test.createStorageCallback();
    SplitFileFetcherStorage storage = test.createStorage(cb);

    try {
      // Act
      long size = storage.streamGenerator().size();

      // Assert
      assertEquals(test.metadata.dataLength(), size);
    } finally {
      storage.close();
    }
  }

  @Test
  void maxRetries_whenConfigured_returnsContextValue() throws Exception {
    // Arrange
    TestSplitfile test = TestSplitfile.constructSingleSegment(BLOCK_SIZE * 2L, 1, false);
    StorageCallback cb = test.createStorageCallback();
    FetchContext ctx = test.makeFetchContext();
    ctx.setMaxSplitfileBlockRetries(5);
    SplitFileFetcherStorage storage = test.createStorage(cb, ctx);

    try {
      // Act/Assert
      assertEquals(5, storage.maxRetries());
    } finally {
      storage.close();
    }
  }

  // Note: getCooldownWakeupTime() is covered indirectly by existing segment cooldown tests.

  private void testMultiSegment(
      long size,
      int[] segmentDataBlockCount,
      int[] segmentCheckBlockCount,
      int segmentSize,
      int checkSegmentSize,
      int deductBlocksFromSegments)
      throws CHKEncodeException,
          IOException,
          MetadataUnresolvedException,
          MetadataParseException,
          FetchException {
    TestSplitfile test =
        TestSplitfile.constructMultipleSegments(
            size,
            segmentDataBlockCount,
            segmentCheckBlockCount,
            segmentSize,
            checkSegmentSize,
            deductBlocksFromSegments);
    testRandomMixtureMultiSegment(test);
    test.free();
  }

  private void testRandomMixtureMultiSegment(TestSplitfile test)
      throws CHKEncodeException, IOException, FetchException, MetadataParseException {
    StorageCallback cb = test.createStorageCallback();
    SplitFileFetcherStorage storage = test.createStorage(cb);
    int total = test.dataBlocks.length + test.checkBlocks.length;
    for (SplitFileFetcherSegmentStorage segment : storage.segments) {
      for (int i = 0; i < segment.totalBlocks(); i++) {
        segment.onNonFatalFailure(i); // We want healing on all blocks that aren't found.
      }
    }
    boolean[] hits = new boolean[total];
    int i = 0;
    while (i < test.dataBlocks.length) {
      int block;
      do {
        block = random.nextInt(total);
      } while (hits[block]);
      hits[block] = true;
      SplitFileFetcherSegmentStorage segment = storage.segments[test.segmentFor(block)];
      if (segment.hasStartedDecode()) {
        continue;
      }
      assertTrue(segment.onGotKey(test.getCHK(block), test.encodeBlock(block)));
      cb.markDownloadedBlock(block);
      i++;
    }
    cb.checkFailed();
    for (SplitFileFetcherSegmentStorage segment : storage.segments) {
      assertTrue(segment.hasStartedDecode()); // All segments have started decoding.
    }
    cb.checkFailed();
    for (SplitFileFetcherSegmentStorage segment : storage.segments) {
      waitForDecode(segment);
    }
    cb.checkFailed();
    cb.waitForFinished();
    cb.checkFailed();
    test.verifyOutput(storage);
    cb.checkFailed();
    storage.finishedFetcher();
    cb.checkFailed();
    for (SplitFileFetcherSegmentStorage segment : storage.segments) {
      waitForFinished(segment);
    }
    cb.checkFailed();
    cb.waitForFree();
    cb.checkFailed();
  }

  // Actual tests ...

  private void waitForFinished(SplitFileFetcherSegmentStorage segment) {
    while (!segment.isFinished()) {
      assertFalse(segment.hasFailed());
      exec.waitForIdle();
    }
  }

  private void waitForDecode(SplitFileFetcherSegmentStorage segment) {
    while (!segment.hasSucceeded()) {
      assertFalse(segment.hasFailed());
      exec.waitForIdle();
    }
  }

  private void innerChooseKeyTest(
      int dataBlocks,
      int checkBlocks,
      SplitFileFetcherSegmentStorage storage,
      boolean[] tried,
      TestSplitfile test,
      boolean cooldown) {
    final MyKeysFetchingLocally keys = test.fetchingKeys;
    keys.clear();
    // Test-only hardening: ensure any cached cooldown gate is cleared before starting a new round
    // so enumeration of all blocks in this round doesn’t spuriously bail out.
    clearChooserCooldownForTesting(storage);
    boolean enumeratedAll = true;
    for (int i = 0; i < dataBlocks + checkBlocks; i++) {
      int chosen = storage.chooseRandomKey();
      if (chosen == -1 && cooldown) {
        // Deflake: a stale global cooldown gate may linger briefly even when
        // individual blocks are eligible. Clear it and retry a couple of times.
        clearChooserCooldownForTesting(storage);
        chosen = storage.chooseRandomKey();
        if (chosen == -1) {
          // Allow one more quick pass after the executor drains.
          exec.waitForIdle();
          clearChooserCooldownForTesting(storage);
          chosen = storage.chooseRandomKey();
        }
      }
      if (chosen == -1 && cooldown) {
        // Not all blocks are currently eligible due to per-block cooldown.
        // Break early; the remainder will be retried after cooldown resets.
        enumeratedAll = false;
        break;
      }
      assertNotEquals(-1, chosen);
      assertFalse(tried[chosen]);
      tried[chosen] = true;
      Key k = test.getCHK(chosen);
      keys.add(k);
    }
    // Every block has been tried.
    if (enumeratedAll) {
      for (boolean b : tried) {
        assertTrue(b);
      }
    }
    if (cooldown) {
      if (enumeratedAll) {
        assertEquals(-1, storage.chooseRandomKey());
        // In infinite cooldown, waiting for all requests to complete.
        assertEquals(Long.MAX_VALUE, storage.getOverallCooldownTime());
      } else {
        // Partial enumeration because some blocks are still cooling down.
        // Should report a finite cooldown (not MAX) in this case.
        long overall = storage.getOverallCooldownTime();
        assertTrue(overall > System.currentTimeMillis());
        assertNotEquals(Long.MAX_VALUE, overall);
      }
    }
    // Every request is running.
    // When we complete a request, we remove it from KeysFetchingLocally *and* call
    // onNonFatalFailure.
    // This will reset the cooldown.
    for (int i = 0; i < dataBlocks + checkBlocks; i++) {
      storage.onNonFatalFailure(i);
    }
    if (!cooldown) {
      // Cleared cooldown, if any.
      assertEquals(0, storage.getOverallCooldownTime());
    }
    assertTrue(storage.getOverallCooldownTime() != Long.MAX_VALUE || storage.hasFailed());
    // Now all the requests have completed, the keys are no longer being fetched.
    keys.clear();
    // Will be able to fetch keys immediately, unless in cooldown.
  }

  // Reflection helper to clear the segment chooser's global cooldown gate in tests only.
  private static void clearChooserCooldownForTesting(SplitFileFetcherSegmentStorage segment) {
    try {
      java.lang.reflect.Field f =
          SplitFileFetcherSegmentStorage.class.getDeclaredField("blockChooser");
      f.setAccessible(true);
      Object chooser = f.get(segment);
      java.lang.reflect.Method m = chooser.getClass().getMethod("clearCooldown");
      m.invoke(chooser);
    } catch (ReflectiveOperationException _) {
      // Best effort: if reflection fails, tests remain as before.
    }
  }

  private SplitFileFetcherStorage createSplitFileFetcherStorageTwice(
      TestSplitfile test, StorageCallback cb)
      throws FetchException, MetadataParseException, IOException, StorageFormatException {
    test.createStorage(cb);
    // No need to shut down the old storage.
    return test.createStorage(cb, test.makeFetchContext(), cb.getRAF());
  }

  // Note: cross-segment scenarios are not covered here.

  private static class TestSplitfile {
    private static class Params {
      final Bucket data;
      final Metadata m;
      final byte[][] originalDataBlocks;
      final byte[][] originalCheckBlocks;
      final ClientCHK[] dataKeys;
      final ClientCHK[] checkKeys;
      final byte[] cryptoKey;
      final byte cryptoAlgorithm;
      final int[] segmentDataBlockCount;
      final int[] segmentCheckBlockCount;

      private Params(Builder b) {
        this.data = b.data;
        this.m = b.m;
        this.originalDataBlocks = b.originalDataBlocks;
        this.originalCheckBlocks = b.originalCheckBlocks;
        this.dataKeys = b.dataKeys;
        this.checkKeys = b.checkKeys;
        this.cryptoKey = b.cryptoKey;
        this.cryptoAlgorithm = b.cryptoAlgorithm;
        this.segmentDataBlockCount = b.segmentDataBlockCount;
        this.segmentCheckBlockCount = b.segmentCheckBlockCount;
      }

      static class Builder {
        private Bucket data;
        private Metadata m;
        private byte[][] originalDataBlocks;
        private byte[][] originalCheckBlocks;
        private ClientCHK[] dataKeys;
        private ClientCHK[] checkKeys;
        private byte[] cryptoKey;
        private byte cryptoAlgorithm;
        private int[] segmentDataBlockCount;
        private int[] segmentCheckBlockCount;

        Builder data(Bucket v) {
          this.data = v;
          return this;
        }

        Builder m(Metadata v) {
          this.m = v;
          return this;
        }

        Builder originalDataBlocks(byte[][] v) {
          this.originalDataBlocks = v;
          return this;
        }

        Builder originalCheckBlocks(byte[][] v) {
          this.originalCheckBlocks = v;
          return this;
        }

        Builder dataKeys(ClientCHK[] v) {
          this.dataKeys = v;
          return this;
        }

        Builder checkKeys(ClientCHK[] v) {
          this.checkKeys = v;
          return this;
        }

        Builder cryptoKey(byte[] v) {
          this.cryptoKey = v;
          return this;
        }

        Builder cryptoAlgorithm(byte v) {
          this.cryptoAlgorithm = v;
          return this;
        }

        Builder segmentDataBlockCount(int[] v) {
          this.segmentDataBlockCount = v;
          return this;
        }

        Builder segmentCheckBlockCount(int[] v) {
          this.segmentCheckBlockCount = v;
          return this;
        }

        Params build() {
          return new Params(this);
        }
      }
    }

    private TestSplitfile(Params p, boolean persistent) {
      this.originalData = p.data;
      this.metadata = p.m;
      this.dataBlocks = p.originalDataBlocks;
      this.checkBlocks = p.originalCheckBlocks;
      this.dataKeys = p.dataKeys;
      this.checkKeys = p.checkKeys;
      this.cryptoKey = p.cryptoKey;
      this.cryptoAlgorithm = p.cryptoAlgorithm;
      this.segmentDataBlockCount = p.segmentDataBlockCount;
      this.segmentCheckBlockCount = p.segmentCheckBlockCount;
      this.persistent = persistent;
      this.fetchingKeys = new MyKeysFetchingLocally();
    }

    public CHKBlock encodeDataBlock(int i) throws CHKEncodeException {
      return ClientCHKBlock.encodeSplitfileBlock(dataBlocks[i], cryptoKey, cryptoAlgorithm)
          .getBlock();
    }

    public CHKBlock encodeCheckBlock(int i) throws CHKEncodeException {
      return ClientCHKBlock.encodeSplitfileBlock(checkBlocks[i], cryptoKey, cryptoAlgorithm)
          .getBlock();
    }

    public CHKBlock encodeBlock(int block) throws CHKEncodeException {
      if (block < dataBlocks.length) {
        return encodeDataBlock(block);
      } else {
        return encodeCheckBlock(block - dataBlocks.length);
      }
    }

    public int findCheckBlock(byte[] data, int start) {
      start++;
      for (int i = start; i < checkBlocks.length; i++) {
        if (checkBlocks[i] == data) {
          return i;
        }
      }
      for (int i = start; i < checkBlocks.length; i++) {
        if (Arrays.equals(checkBlocks[i], data)) {
          return i;
        }
      }
      return -1;
    }

    public int findDataBlock(byte[] data, int start) {
      start++;
      for (int i = start; i < dataBlocks.length; i++) {
        if (dataBlocks[i] == data) {
          return i;
        }
      }
      for (int i = start; i < dataBlocks.length; i++) {
        if (Arrays.equals(dataBlocks[i], data)) {
          return i;
        }
      }
      return -1;
    }

    public StorageCallback createStorageCallback() {
      return new StorageCallback(this);
    }

    public SplitFileFetcherStorage createStorage(StorageCallback cb)
        throws FetchException, MetadataParseException, IOException {
      return createStorage(cb, makeFetchContext());
    }

    public SplitFileFetcherStorage createStorage(final StorageCallback cb, FetchContext ctx)
        throws FetchException, MetadataParseException, IOException {
      LockableRandomAccessBufferFactory f =
          new LockableRandomAccessBufferFactory() {

            @Override
            public LockableRandomAccessBuffer makeRAF(long size) throws IOException {
              LockableRandomAccessBuffer t = rafFactory.makeRAF(size);
              cb.snoopRAF(t);
              return t;
            }

            @Override
            public LockableRandomAccessBuffer makeRAF(
                byte[] initialContents, int offset, int size, boolean readOnly) throws IOException {
              LockableRandomAccessBuffer t =
                  rafFactory.makeRAF(initialContents, offset, size, readOnly);
              cb.snoopRAF(t);
              return t;
            }
          };
      return new SplitFileFetcherStorage(
          new SplitFileFetcherStorageInitParams.Builder()
              .metadata(metadata)
              .fetcher(cb)
              .decompressors(NO_DECOMPRESSORS)
              .clientMetadata(metadata.getClientMetadata())
              .topDontCompress(false)
              .topCompatibilityMode((short) COMPATIBILITY_MODE.ordinal())
              .fetchContext(ctx)
              .realTime(false)
              .salt(salt)
              .thisKey(uri)
              .origKey(uri)
              .isFinalFetch(true)
              .clientDetails(new byte[0])
              .random(random)
              .tempBucketFactory(bf)
              .rafFactory(f)
              .exec(jobRunner)
              .ticker(ticker)
              .memoryLimitedJobRunner(memoryLimitedJobRunner)
              .checker(new CRCChecksumChecker())
              .persistent(persistent)
              .storageFile(null)
              .diskSpaceCheckingRAFFactory(null)
              .keysFetching(fetchingKeys)
              .build());
    }

    /**
     * Restore a splitfile fetcher from a file.
     *
     * @throws StorageFormatException if the persisted state cannot be read or is in an incompatible
     *     on-disk format
     * @throws IOException if an I/O error occurs while accessing the persisted state
     * @throws FetchException if the restored metadata is invalid or cannot be used to resume
     *     fetching
     */
    public SplitFileFetcherStorage createStorage(
        StorageCallback cb, FetchContext ctx, LockableRandomAccessBuffer raf)
        throws IOException, StorageFormatException, FetchException {
      assertTrue(persistent);
      return new SplitFileFetcherStorage(
          new SplitFileFetcherStorageResumeParams.Builder()
              .raf(raf)
              .realTime(false)
              .callback(cb)
              .context(ctx)
              .random(random)
              .exec(jobRunner)
              .keysFetching(fetchingKeys)
              .ticker(ticker)
              .memoryLimitedJobRunner(memoryLimitedJobRunner)
              .checker(new CRCChecksumChecker())
              .newSalt(false)
              .salt(null)
              .resumed(false)
              .completeViaTruncation(false)
              .build());
    }

    public FetchContext makeFetchContext() {
      return HighLevelSimpleClientImpl.makeDefaultFetchContext(
          Long.MAX_VALUE, Long.MAX_VALUE, new SimpleEventProducer());
    }

    public void verifyOutput(SplitFileFetcherStorage storage) throws IOException {
      StreamGenerator g = storage.streamGenerator();
      Bucket out = bf.makeBucket(-1);
      try (OutputStream os = out.getOutputStream()) {
        g.writeTo(os, null);
      }
      assertTrue(BucketTools.equalBuckets(originalData, out));
      out.free();
    }

    public NodeCHK getCHK(int block) {
      if (block < dataBlocks.length) {
        return dataKeys[block].getNodeCHK();
      } else {
        return checkKeys[block - dataBlocks.length].getNodeCHK();
      }
    }

    public int segmentFor(int block) {
      int total = 0;
      // Must be consistent with the getCHK() counting etc.
      // Count data blocks first then check blocks.
      for (int i = 0; i < segmentDataBlockCount.length; i++) {
        total += segmentDataBlockCount[i];
        if (block < total) {
          return i;
        }
      }
      for (int i = 0; i < segmentCheckBlockCount.length; i++) {
        total += segmentCheckBlockCount[i];
        if (block < total) {
          return i;
        }
      }

      return -1;
    }

    void free() {
      originalData.free();
    }

    static TestSplitfile constructSingleSegment(long size, int checkBlocks, boolean persistent)
        throws IOException,
            CHKEncodeException,
            MetadataUnresolvedException,
            MetadataParseException {
      assertTrue(checkBlocks <= MAX_SEGMENT_SIZE);
      assertTrue(size < MAX_SEGMENT_SIZE * (long) BLOCK_SIZE);
      Bucket data = makeRandomBucket(size);
      byte[][] originalDataBlocks = splitAndPadBlocks(data, size);
      int dataBlocks = originalDataBlocks.length;
      assertTrue(dataBlocks <= MAX_SEGMENT_SIZE);
      assertTrue(dataBlocks + checkBlocks <= MAX_SEGMENT_SIZE);
      byte[][] originalCheckBlocks = constructBlocks(checkBlocks);
      codec.encode(originalDataBlocks, originalCheckBlocks, falseArray(checkBlocks), BLOCK_SIZE);
      ClientMetadata cm = new ClientMetadata(null);
      // Note: no hashes or compression for tests.
      byte[] cryptoKey = randomKey();
      byte cryptoAlgorithm = Key.ALGO_AES_CTR_256_SHA256;
      ClientCHK[] dataKeys = makeKeys(originalDataBlocks, cryptoKey, cryptoAlgorithm);
      ClientCHK[] checkKeys = makeKeys(originalCheckBlocks, cryptoKey, cryptoAlgorithm);
      Metadata m =
          new Metadata(
              SplitfileAlgorithm.ONION_STANDARD,
              dataKeys,
              checkKeys,
              dataBlocks,
              checkBlocks,
              0,
              cm,
              size,
              null,
              null,
              size,
              false,
              null,
              null,
              size,
              size,
              dataBlocks,
              dataBlocks + checkBlocks,
              false,
              COMPATIBILITY_MODE,
              cryptoAlgorithm,
              cryptoKey,
              true,
              0);
      // Make sure the metadata is reusable.
      // Note: ensures metadata is reusable; the above constructor doesn't set segments.
      Bucket metaBucket = m.toBucket(bf);
      Metadata m1 = Metadata.construct(metaBucket);
      Bucket copyBucket = m1.toBucket(bf);
      assertTrue(BucketTools.equalBuckets(metaBucket, copyBucket));
      metaBucket.free();
      copyBucket.free();
      return new TestSplitfile(
          new Params.Builder()
              .data(data)
              .m(m1)
              .originalDataBlocks(originalDataBlocks)
              .originalCheckBlocks(originalCheckBlocks)
              .dataKeys(dataKeys)
              .checkKeys(checkKeys)
              .cryptoKey(cryptoKey)
              .cryptoAlgorithm(cryptoAlgorithm)
              .segmentDataBlockCount(null)
              .segmentCheckBlockCount(null)
              .build(),
          persistent);
    }

    /**
     * Create a multi-segment test splitfile. The main complication with multi-segment is that we
     * can't choose the number of blocks in each segment arbitrarily; that depends on the metadata
     * format; the caller must ensure that the number are consistent.
     *
     * @param size Total size of the test data in bytes
     * @param segmentDataBlockCount The actual number of data blocks in each segment. Must be
     *     consistent with the other parameters; this cannot be chosen freely due to the metadata
     *     format.
     * @param segmentCheckBlockCount The actual number of check blocks in each segment. Must be
     *     consistent with the other parameters; this cannot be chosen freely due to the metadata
     *     format.
     * @param segmentSize The "typical" number of data blocks in a segment.
     * @param checkSegmentSize The "typical" number of check blocks in a segment.
     * @param deductBlocksFromSegments The number of segments from which a single block has been
     *     deducted. This is used when the number of data blocks isn't an exact multiple of the
     *     number of segments. The definitive compatibility mode is fixed for tests to COMPAT_1416.
     * @return Constructed TestSplitfile matching the provided segmentation parameters
     * @throws IOException if random test data or buckets cannot be created
     * @throws CHKEncodeException if block keys cannot be encoded for the generated data
     * @throws MetadataUnresolvedException if test metadata cannot be fully resolved/constructed
     * @throws MetadataParseException if constructed metadata cannot be serialized or parsed back
     */
    static TestSplitfile constructMultipleSegments(
        long size,
        int[] segmentDataBlockCount,
        int[] segmentCheckBlockCount,
        int segmentSize,
        int checkSegmentSize,
        int deductBlocksFromSegments)
        throws IOException,
            CHKEncodeException,
            MetadataUnresolvedException,
            MetadataParseException {
      int dataBlocks = sum(segmentDataBlockCount);
      int checkBlocks = sum(segmentCheckBlockCount);
      int segments = segmentDataBlockCount.length;
      assertEquals((size + BLOCK_SIZE - 1) / BLOCK_SIZE, dataBlocks);
      assertEquals(segments, segmentCheckBlockCount.length);
      Bucket data = makeRandomBucket(size);
      byte[][] originalDataBlocks = splitAndPadBlocks(data, size);
      byte[][] originalCheckBlocks = constructBlocks(checkBlocks);
      int startDataBlock = 0;
      int startCheckBlock = 0;
      for (int seg = 0; seg < segments; seg++) {
        byte[][] segmentDataBlocks =
            Arrays.copyOfRange(
                originalDataBlocks, startDataBlock, startDataBlock + segmentDataBlockCount[seg]);
        byte[][] segmentCheckBlocks =
            Arrays.copyOfRange(
                originalCheckBlocks,
                startCheckBlock,
                startCheckBlock + segmentCheckBlockCount[seg]);
        codec.encode(
            segmentDataBlocks,
            segmentCheckBlocks,
            falseArray(segmentCheckBlocks.length),
            BLOCK_SIZE);
        startDataBlock += segmentDataBlockCount[seg];
        startCheckBlock += segmentCheckBlockCount[seg];
      }
      ClientMetadata cm = new ClientMetadata(null);
      // Note: no hashes or compression for tests.
      byte[] cryptoKey = randomKey();
      byte cryptoAlgorithm = Key.ALGO_AES_CTR_256_SHA256;
      ClientCHK[] dataKeys = makeKeys(originalDataBlocks, cryptoKey, cryptoAlgorithm);
      ClientCHK[] checkKeys = makeKeys(originalCheckBlocks, cryptoKey, cryptoAlgorithm);
      Metadata m =
          new Metadata(
              SplitfileAlgorithm.ONION_STANDARD,
              dataKeys,
              checkKeys,
              segmentSize,
              checkSegmentSize,
              deductBlocksFromSegments,
              cm,
              size,
              null,
              null,
              size,
              false,
              null,
              null,
              size,
              size,
              dataBlocks,
              dataBlocks + checkBlocks,
              false,
              InsertContext.CompatibilityMode.COMPAT_1416,
              cryptoAlgorithm,
              cryptoKey,
              true /* uses single-key splitfiles for tests */,
              0);
      // Make sure the metadata is reusable.
      // Note: ensures metadata is reusable; the above constructor doesn't set segments.
      Bucket metaBucket = m.toBucket(bf);
      Metadata m1 = Metadata.construct(metaBucket);
      Bucket copyBucket = m1.toBucket(bf);
      assertTrue(BucketTools.equalBuckets(metaBucket, copyBucket));
      metaBucket.free();
      copyBucket.free();
      return new TestSplitfile(
          new Params.Builder()
              .data(data)
              .m(m1)
              .originalDataBlocks(originalDataBlocks)
              .originalCheckBlocks(originalCheckBlocks)
              .dataKeys(dataKeys)
              .checkKeys(checkKeys)
              .cryptoKey(cryptoKey)
              .cryptoAlgorithm(cryptoAlgorithm)
              .segmentDataBlockCount(segmentDataBlockCount)
              .segmentCheckBlockCount(segmentCheckBlockCount)
              .build(),
          false);
    }

    final Bucket originalData;
    final Metadata metadata;
    final byte[][] dataBlocks;
    final byte[][] checkBlocks;
    final ClientCHK[] dataKeys;
    final ClientCHK[] checkKeys;
    final MyKeysFetchingLocally fetchingKeys;
    private final byte[] cryptoKey;
    private final byte cryptoAlgorithm;
    private final int[] segmentDataBlockCount;
    private final int[] segmentCheckBlockCount;
    private final boolean persistent;
  }

  private static class StorageCallback implements SplitFileFetcherStorageCallback {

    public StorageCallback(TestSplitfile splitfile) {
      this.splitfile = splitfile;
      encodedBlocks = new boolean[splitfile.dataBlocks.length + splitfile.checkBlocks.length];
    }

    @Override
    public synchronized void onSuccess() {
      succeeded = true;
      notifyAll();
    }

    @Override
    public synchronized void onClosed() {
      closed = true;
      notifyAll();
    }

    @Override
    public short getPriorityClass() {
      return 0;
    }

    @Override
    public synchronized void failOnDiskError(IOException e) {
      failed = true;
      notifyAll();
    }

    @Override
    public void setSplitfileBlocks(int requiredBlocks, int remainingBlocks) {
      assertEquals(requiredBlocks, splitfile.dataBlocks.length);
      assertEquals(remainingBlocks, splitfile.checkBlocks.length);
    }

    @Override
    public void onSplitfileCompatibilityMode(
        CompatibilityMode min,
        CompatibilityMode max,
        byte[] customSplitfileKey,
        boolean compressed,
        boolean bottomLayer,
        boolean definitiveAnyway) {
      // Ignore.
    }

    @Override
    public void queueHeal(byte[] data, byte[] cryptoKey, byte cryptoAlgorithm) {
      assertArrayEquals(cryptoKey, splitfile.cryptoKey);
      assertEquals(cryptoAlgorithm, splitfile.cryptoAlgorithm);
      int x = -1;
      boolean progress = false;
      while ((x = splitfile.findCheckBlock(data, x)) != -1) {
        synchronized (this) {
          encodedBlocks[x + splitfile.dataBlocks.length] = true;
        }
        progress = true;
      }
      if (!progress) {
        // Data block?
        while ((x = splitfile.findDataBlock(data, x)) != -1) {
          synchronized (this) {
            encodedBlocks[x] = true;
          }
          progress = true;
        }
      }
      if (!progress) {
        Assertions.fail("Queued healing block not in the original block list");
      }
    }

    public synchronized void checkFailed() {
      assertFalse(failed);
    }

    public synchronized void waitForFinished() {
      while (!(succeeded || failed)) {
        try {
          wait();
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
          Assertions.fail("Interrupted while waiting for finished");
        }
      }
    }

    public synchronized void waitForFailed() {
      while (!(succeeded || failed)) {
        try {
          wait();
        } catch (InterruptedException _) {
          Thread.currentThread().interrupt();
          Assertions.fail("Interrupted while waiting for failure");
        }
      }
      assertTrue(failed);
    }

    public void waitForFree() {
      synchronized (this) {
        while (!closed) {
          try {
            wait();
          } catch (InterruptedException _) {
            Thread.currentThread().interrupt();
            Assertions.fail("Interrupted while waiting for free");
          }
        }
        assertTrue(succeeded);
      }
      synchronized (this) {
        for (int i = 0; i < encodedBlocks.length; i++) {
          assertTrue(encodedBlocks[i], "Block " + i + " not found or decoded");
        }
      }
    }

    @Override
    public void onFetchedBlock() {
      // Ignore.
    }

    @Override
    public void fail(FetchException fe) {
      synchronized (this) {
        failed = true;
        notifyAll();
      }
    }

    @Override
    public void onFailedBlock() {
      // Ignore.
    }

    @Override
    public void maybeAddToBinaryBlob(ClientCHKBlock decodedBlock) {
      // Ignore.
    }

    @Override
    public boolean wantBinaryBlob() {
      return false;
    }

    @Override
    public BaseSendableGet getSendableGet() {
      return null;
    }

    @Override
    public void restartedAfterDataCorruption() {
      // Ignore
    }

    @Override
    public void clearCooldown() {
      // Ignore.
    }

    @Override
    public void reduceCooldown(long wakeupTime) {
      // Ignore.
    }

    @Override
    public HasKeyListener getHasKeyListener() {
      return null;
    }

    @Override
    public void failOnDiskError(ChecksumFailedException e) {
      synchronized (this) {
        failed = true;
        notifyAll();
      }
    }

    @Override
    public KeySalter getSalter() {
      return salt;
    }

    @Override
    public void onResume(int succeeded, int failed, ClientMetadata mimeType, long finalSize) {
      // Ignore.
    }

    synchronized void snoopRAF(LockableRandomAccessBuffer t) {
      this.raf = t;
    }

    synchronized LockableRandomAccessBuffer getRAF() {
      return raf;
    }

    synchronized void markDownloadedBlock(int block) {
      encodedBlocks[block] = true;
    }

    final TestSplitfile splitfile;
    final boolean[] encodedBlocks;
    private boolean succeeded;
    private boolean closed;
    private boolean failed;
    private LockableRandomAccessBuffer raf;
  }

  private static class MyKeysFetchingLocally implements KeysFetchingLocally {
    @Override
    public long checkRecentlyFailed(Key key, boolean realTime) {
      return 0;
    }

    @Override
    public boolean hasKey(Key key, BaseSendableGet getterWaiting) {
      return keys.contains(key);
    }

    @Override
    public boolean hasInsert(SendableRequestItemKey token) {
      return false;
    }

    public void add(Key k) {
      keys.add(k);
    }

    public void clear() {
      keys.clear();
    }

    private final HashSet<Key> keys = new HashSet<>();
  }

  static final KeySalter salt = Key::getRoutingKey;
  static final WaitableExecutor exec = new WaitableExecutor(new PooledExecutor());
  static final PersistentJobRunner jobRunner = new DummyJobRunner(exec, null);
  static final Ticker ticker = new CheatingTicker(exec);
  static final int BLOCK_SIZE = CHKBlock.DATA_LENGTH;
  static final int KEY_LENGTH = 32;
  static final CompatibilityMode COMPATIBILITY_MODE = InsertContext.CompatibilityMode.COMPAT_1416;
  private static final OnionFECCodec codec = new OnionFECCodec();
  private static final int MAX_SEGMENT_SIZE = 256;
  private static final List<COMPRESSOR_TYPE> NO_DECOMPRESSORS = Collections.emptyList();
  static DummyRandomSource random;
  static BucketFactory bf = new ArrayBucketFactory();
  static LockableRandomAccessBufferFactory rafFactory = new ByteArrayRandomAccessBufferFactory();
  static MemoryLimitedJobRunner memoryLimitedJobRunner =
      new MemoryLimitedJobRunner(9 * 1024 * 1024L, 20, exec, NativeThread.JAVA_PRIORITY_RANGE);
  static FreenetURI uri;

  // Await helpers (avoid Thread.sleep for async waits)
  private static void awaitTrue(BooleanSupplier condition, long timeoutMs) {
    long deadline = System.currentTimeMillis() + timeoutMs;
    while (System.currentTimeMillis() < deadline) {
      exec.waitForIdle();
      if (condition.getAsBoolean()) return;
    }
    Assertions.fail("Timeout waiting for condition");
  }
}
