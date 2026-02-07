package network.crypta.store.caching;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import network.crypta.crypt.DSAGroup;
import network.crypta.crypt.DSAPrivateKey;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.Global;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.SHA256;
import network.crypta.keys.BlockEncodeParams;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.CHKDecodeException;
import network.crypta.keys.CHKEncodeException;
import network.crypta.keys.CHKVerifyException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientCHKBlock;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.ClientSSKBlock;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.keys.Key;
import network.crypta.keys.KeyDecodeException;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKEncodeException;
import network.crypta.keys.SSKVerifyException;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.store.CHKStore;
import network.crypta.store.FetchOptions;
import network.crypta.store.FreenetStore;
import network.crypta.store.GetPubkey;
import network.crypta.store.KeyCollisionException;
import network.crypta.store.PubkeyStore;
import network.crypta.store.RAMFreenetStore;
import network.crypta.store.SSKStore;
import network.crypta.store.SimpleGetPubkey;
import network.crypta.store.StorableBlock;
import network.crypta.store.StoreCallback;
import network.crypta.store.WriteBlockableFreenetStore;
import network.crypta.store.saltedhash.ResizablePersistentIntBuffer;
import network.crypta.store.saltedhash.SaltedHashFreenetStore;
import network.crypta.store.saltedhash.SaltedHashStoreDependencies;
import network.crypta.store.saltedhash.SaltedHashStoreLocation;
import network.crypta.store.saltedhash.SaltedHashStoreParams;
import network.crypta.store.saltedhash.SaltedHashStoreSizing;
import network.crypta.support.Fields;
import network.crypta.support.PooledExecutor;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.Ticker;
import network.crypta.support.TrivialTicker;
import network.crypta.support.api.Bucket;
import network.crypta.support.compress.Compressor;
import network.crypta.support.compress.InvalidCompressionCodecException;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * CachingFreenetStoreTest Test for CachingFreenetStore
 *
 * @author Simon Vocella <voxsim@gmail.com>
 */
@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class CachingFreenetStoreTest {

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

  /* Simple test with CHK for CachingFreenetStore */
  @Test
  void putAndFetch_whenCHKInserted_expectCacheHitAndUnderlyingMiss()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    CHKStore store = new CHKStore();
    File f = getStorePath("testSimpleCHK");
    try (SaltedHashFreenetStore<CHKBlock> saltStore = newSaltedHashStore(f, store)) {
      CachingFreenetStoreTracker tracker = newTracker(cachingFreenetStoreMaxSize);
      try (CachingFreenetStore<CHKBlock> cachingStore =
          new CachingFreenetStore<>(store, saltStore, tracker)) {
        cachingStore.start(null, true);
        // Act
        for (int i = 0; i < 5; i++) {
          String test = "test" + i;
          ClientCHKBlock block = encodeBlockCHK(test);
          store.put(block.getBlock(), false);

          ClientCHK key = block.getClientKey();
          // Assert: cache hit, underlying miss
          assertNull(
              saltStore.fetch(
                  key.getRoutingKey(),
                  key.getNodeCHK().getFullKey(),
                  false,
                  false,
                  false,
                  false,
                  null));
          CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
          String data = decodeBlockCHK(verify, key);
          assertEquals(test, data);
        }
      }
    }
  }

  /*
   * Check that if the size limit is 0 (and therefore presumably if it is smaller
   * than the key being cached), we will pass through immediately.
   */
  @Test
  void put_whenCacheSizeZero_expectWriteThroughToUnderlying()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    File f = getStorePath("testZeroSize");
    CHKStore store = new CHKStore();
    try (SaltedHashFreenetStore<CHKBlock> saltStore = newSaltedHashStore(f, store)) {
      CachingFreenetStoreTracker tracker = newTracker(0);
      try (CachingFreenetStore<CHKBlock> cachingStore =
          new CachingFreenetStore<>(store, saltStore, tracker)) {
        cachingStore.start(null, true);
        // Act
        for (int i = 0; i < 5; i++) {
          String test = "test" + i;
          ClientCHKBlock block = encodeBlockCHK(test);
          store.put(block.getBlock(), false);

          ClientCHK key = block.getClientKey();
          // Assert: write-through to the underlying store
          assertNotNull(
              saltStore.fetch(
                  key.getRoutingKey(),
                  key.getNodeCHK().getFullKey(),
                  false,
                  false,
                  false,
                  false,
                  null));
          CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
          String data = decodeBlockCHK(verify, key);
          assertEquals(test, data);
        }
      }
    }
  }

  /*
   * Check that if we are going over the maximum size, the caching store will call
   * pushAll and all blocks is in the *underlying* store and the size is 0
   */
  @Test
  void put_whenExceedingMaxSize_expectUnderlyingContainsAndTrackerZero()
      throws IOException,
          CHKEncodeException,
          CHKVerifyException,
          CHKDecodeException,
          InterruptedException {
    // Arrange
    File f = getStorePath("testOverMaximumSize");

    String test = "test0";
    ClientCHKBlock block = encodeBlockCHK(test);
    byte[] data = block.getBlock().getRawData();
    byte[] header = block.getBlock().getRawHeaders();
    byte[] routingKey = block.getBlock().getRoutingKey();
    long sizeBlock =
        (long) data.length
            + header.length
            + block.getBlock().getFullKey().length
            + routingKey.length;
    int howManyBlocks = ((int) (cachingFreenetStoreMaxSize / sizeBlock)) + 1;

    CHKStore store = new CHKStore();

    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, "testCachingFreenetStoreCHK"),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(howManyBlocks * 5L, false, true, true)))) {
      WaitableCachingFreenetStoreTracker tracker =
          new WaitableCachingFreenetStoreTracker(
              cachingFreenetStoreMaxSize, cachingFreenetStorePeriod, ticker);
      try (CachingFreenetStore<CHKBlock> cachingStore =
          new CachingFreenetStore<>(store, saltStore, tracker)) {
        cachingStore.start(null, true);
        List<ClientCHKBlock> chkBlocks = new ArrayList<>();
        List<String> tests = new ArrayList<>();
        // Act: insert enough blocks to exceed the limit and trigger flush
        store.put(block.getBlock(), false);
        chkBlocks.add(block);
        tests.add(test);

        for (int i = 1; i < howManyBlocks; i++) {
          test = "test" + i;
          tests.add(test);

          block = encodeBlockCHK(test);
          store.put(block.getBlock(), false);
          chkBlocks.add(block);
        }

        tracker.waitForZero();
        // Assert: data present in underlying store and decodable via cache
        boolean atLeastOneKey = false;
        for (int i = 0; i < howManyBlocks; i++) {
          test = tests.get(i);
          block = chkBlocks.get(i);
          ClientCHK key = block.getClientKey();

          CHKBlock verifyInStore =
              saltStore.fetch(
                  key.getRoutingKey(),
                  key.getNodeCHK().getFullKey(),
                  false,
                  false,
                  false,
                  false,
                  null);
          // Since SaltedHashFreenetStore is lossy, it might have been replaced in a
          // collision
          if (verifyInStore == null) {
            continue;
          }
          // If it's in the Store, it should be obtainable through the Cache
          CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
          String receivedData = decodeBlockCHK(verify, key);
          assertEquals(test, receivedData);

          atLeastOneKey = true;
        }

        assertTrue(atLeastOneKey, "At least one key should have matched");
      }
    }
  }

  @Test
  void put_whenSSKCollisionsAndExceedMax_expectEvictionAndCorrectWrites()
      throws IOException,
          SSKEncodeException,
          InvalidCompressionCodecException,
          InterruptedException {
    // Arrange
    PubkeyStore pk = new PubkeyStore();
    try (var _ = new RAMFreenetStore<>(pk, 10)) {
      GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
      SSKStore store = new SSKStore(pubkeyCache);
      int sskBlockSize = store.getTotalBlockSize();

      // Create a cache with a size limit of 1.5 SSK's.
      File f = getStorePath("testCollisionsOverMaximumSize");
      try (SaltedHashFreenetStore<SSKBlock> saltStore =
          SaltedHashFreenetStore.construct(
              SaltedHashStoreParams.of(
                  new SaltedHashStoreLocation(f, TEST_CACHING_FREENET_STORE_SSK),
                  new SaltedHashStoreDependencies<>(
                      store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                  new SaltedHashStoreSizing(20, true, true, true)))) {
        WaitableCachingFreenetStoreTracker tracker =
            new WaitableCachingFreenetStoreTracker(
                (sskBlockSize * 3L) / 2, cachingFreenetStorePeriod, ticker);
        try (CachingFreenetStore<SSKBlock> cachingStore =
            new CachingFreenetStore<>(store, saltStore, tracker)) {
          cachingStore.start(null, true);
          RandomSource random = new DummyRandomSource(12345);

          final int CRYPTO_KEY_LENGTH = 32;
          byte[] ckey = new byte[CRYPTO_KEY_LENGTH];
          random.nextBytes(ckey);
          DSAGroup g = Global.DSAgroupBigA;
          DSAPrivateKey privKey = new DSAPrivateKey(g, random);
          DSAPublicKey pubKey = new DSAPublicKey(g, privKey);
          byte[] pkHash = SHA256.digest(pubKey.asBytes());
          String docName = DOC_NAME;
          InsertableClientSSK ik =
              new InsertableClientSSK(
                  docName, pkHash, pubKey, privKey, ckey, Key.ALGO_AES_PCFB_256_SHA256);

          // Act: write one key to the store.
          String test = "test";
          SimpleReadOnlyArrayBucket bucket =
              new SimpleReadOnlyArrayBucket(test.getBytes(StandardCharsets.UTF_8));
          ClientSSKBlock block =
              ik.encode(
                  new BlockEncodeParams(
                      bucket,
                      false,
                      false,
                      (short) -1,
                      bucket.size(),
                      Compressor.DEFAULT_COMPRESSORDESCRIPTOR));

          SSKBlock sskBlock = (SSKBlock) block.getBlock();
          pubkeyCache.cacheKey(
              sskBlock.getKey().getPubKeyHash(),
              sskBlock.getPubKey(),
              false,
              false,
              false,
              false,
              false);
          try {
            store.put(sskBlock, false, false);
          } catch (KeyCollisionException _) {
            fail();
          }

          assertEquals(sskBlockSize, tracker.getSizeOfCache());

          // Act: write a colliding key and then a second distinct key
          test = TEST_1;
          bucket = new SimpleReadOnlyArrayBucket(test.getBytes(StandardCharsets.UTF_8));
          block =
              ik.encode(
                  new BlockEncodeParams(
                      bucket,
                      false,
                      false,
                      (short) -1,
                      bucket.size(),
                      Compressor.DEFAULT_COMPRESSORDESCRIPTOR));

          sskBlock = (SSKBlock) block.getBlock();
          try {
            store.put(sskBlock, false, false);
            fail();
          } catch (KeyCollisionException _) {
            // Expected.
          }
          try {
            store.put(sskBlock, true, false);
          } catch (KeyCollisionException _) {
            fail();
          }

          // Size is still one key.
          assertEquals(sskBlockSize, tracker.getSizeOfCache());

          // Write a second key, should trigger writing to disk.
          DSAPrivateKey privKey2 = new DSAPrivateKey(g, random);
          DSAPublicKey pubKey2 = new DSAPublicKey(g, privKey2);
          byte[] pkHash2 = SHA256.digest(pubKey2.asBytes());
          InsertableClientSSK ik2 =
              new InsertableClientSSK(
                  docName, pkHash2, pubKey2, privKey2, ckey, Key.ALGO_AES_PCFB_256_SHA256);
          block =
              ik2.encode(
                  new BlockEncodeParams(
                      bucket,
                      false,
                      false,
                      (short) -1,
                      bucket.size(),
                      Compressor.DEFAULT_COMPRESSORDESCRIPTOR));
          SSKBlock sskBlock2 = (SSKBlock) block.getBlock();
          pubkeyCache.cacheKey(
              sskBlock2.getKey().getPubKeyHash(),
              sskBlock2.getPubKey(),
              false,
              false,
              false,
              false,
              false);

          try {
            store.put(sskBlock2, false, false);
          } catch (KeyCollisionException _) {
            fail();
          }

          // Assert: after a flush both keys are accessible via cache/backing
          tracker.waitForZero();

          assertEquals(store.fetch(sskBlock.getKey(), false, false, false, false, null), sskBlock);
          assertEquals(
              store.fetch(sskBlock2.getKey(), false, false, false, false, null), sskBlock2);
        }
      }
    }
  }

  @Test
  void pushLeastRecentlyBlock_whenSingleCached_expectWriteAndThenEmpty()
      throws IOException, SSKEncodeException, InvalidCompressionCodecException {
    // Arrange
    PubkeyStore pk = new PubkeyStore();
    try (var _ = new RAMFreenetStore<>(pk, 10)) {
      GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
      SSKStore store = new SSKStore(pubkeyCache);
      int sskBlockSize = store.getTotalBlockSize();

      File f = getStorePath("testSimpleManualWrite");
      try (SaltedHashFreenetStore<SSKBlock> saltStore =
          SaltedHashFreenetStore.construct(
              SaltedHashStoreParams.of(
                  new SaltedHashStoreLocation(f, TEST_CACHING_FREENET_STORE_SSK),
                  new SaltedHashStoreDependencies<>(
                      store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                  new SaltedHashStoreSizing(20, true, true, true)))) {
        CachingFreenetStoreTracker tracker =
            new CachingFreenetStoreTracker((sskBlockSize * 3L), cachingFreenetStorePeriod, ticker);
        try (CachingFreenetStore<SSKBlock> cachingStore =
            new CachingFreenetStore<>(store, saltStore, tracker)) {
          cachingStore.start(null, true);
          RandomSource random = new DummyRandomSource(12345);

          final int CRYPTO_KEY_LENGTH = 32;
          byte[] ckey = new byte[CRYPTO_KEY_LENGTH];
          random.nextBytes(ckey);
          DSAGroup g = Global.DSAgroupBigA;
          DSAPrivateKey privKey = new DSAPrivateKey(g, random);
          DSAPublicKey pubKey = new DSAPublicKey(g, privKey);
          byte[] pkHash = SHA256.digest(pubKey.asBytes());
          InsertableClientSSK ik =
              new InsertableClientSSK(
                  DOC_NAME, pkHash, pubKey, privKey, ckey, Key.ALGO_AES_PCFB_256_SHA256);

          // Assert precondition: nothing to write yet
          assertEquals(0, tracker.getSizeOfCache());
          assert (cachingStore.pushLeastRecentlyBlock() == -1);
          // Act: write one key to the cache
          String test = "test";
          SimpleReadOnlyArrayBucket bucket =
              new SimpleReadOnlyArrayBucket(test.getBytes(StandardCharsets.UTF_8));
          ClientSSKBlock block =
              ik.encode(
                  new BlockEncodeParams(
                      bucket,
                      false,
                      false,
                      (short) -1,
                      bucket.size(),
                      Compressor.DEFAULT_COMPRESSORDESCRIPTOR));

          SSKBlock sskBlock = (SSKBlock) block.getBlock();
          pubkeyCache.cacheKey(
              sskBlock.getKey().getPubKeyHash(),
              sskBlock.getPubKey(),
              false,
              false,
              false,
              false,
              false);
          try {
            store.put(sskBlock, false, false);
          } catch (KeyCollisionException _) {
            fail();
          }

          // Assert: push writes one and empties the cache
          assertEquals(tracker.getSizeOfCache(), sskBlockSize);
          assertEquals(cachingStore.pushLeastRecentlyBlock(), sskBlockSize);
          // Assert: nothing left to write
          assertEquals(-1, cachingStore.pushLeastRecentlyBlock());
        }
      }
    }
  }

  /**
   * pushLeastRecentlyBlock() with collisions: Lock { Grab a block for key K. (Do not remove it) }
   * Write the block. Lock { Detected a different block for key K. Return 0 rather than removing it.
   * }
   */
  @Test
  void pushLeastRecentlyBlock_whenConcurrentOverwrite_expectReturnZero()
      throws IOException,
          SSKEncodeException,
          InvalidCompressionCodecException,
          InterruptedException,
          ExecutionException {
    // Arrange
    PubkeyStore pk = new PubkeyStore();
    RAMFreenetStore<DSAPublicKey> ramFreenetStore = new RAMFreenetStore<>(pk, 10);
    pk.setStore(ramFreenetStore);

    GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
    SSKStore store = new SSKStore(pubkeyCache);
    int sskBlockSize = store.getTotalBlockSize();

    File f = getStorePath("testManualWriteCollision");
    try (SaltedHashFreenetStore<SSKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, TEST_CACHING_FREENET_STORE_SSK),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(20, true, true, true)))) {
      // Don't let the writing complete until we say so...
      WriteBlockableFreenetStore<SSKBlock> delayStore =
          new WriteBlockableFreenetStore<>(saltStore, true);
      CachingFreenetStoreTracker tracker =
          new CachingFreenetStoreTracker((sskBlockSize * 3L), cachingFreenetStorePeriod, ticker);
      try (final CachingFreenetStore<SSKBlock> cachingStore =
          new CachingFreenetStore<>(store, delayStore, tracker)) {
        cachingStore.start(null, true);
        RandomSource random = new DummyRandomSource(12345);

        final int CRYPTO_KEY_LENGTH = 32;
        byte[] ckey = new byte[CRYPTO_KEY_LENGTH];
        random.nextBytes(ckey);
        DSAGroup g = Global.DSAgroupBigA;
        DSAPrivateKey privKey = new DSAPrivateKey(g, random);
        DSAPublicKey pubKey = new DSAPublicKey(g, privKey);
        byte[] pkHash = SHA256.digest(pubKey.asBytes());
        InsertableClientSSK ik =
            new InsertableClientSSK(
                DOC_NAME, pkHash, pubKey, privKey, ckey, Key.ALGO_AES_PCFB_256_SHA256);

        // Assert precondition: nothing to write yet
        assertEquals(0, tracker.getSizeOfCache());
        assertEquals(-1, cachingStore.pushLeastRecentlyBlock());
        // Act: write one key to the cache. It will not be written through to the disk.
        String test = "test";
        SimpleReadOnlyArrayBucket bucket =
            new SimpleReadOnlyArrayBucket(test.getBytes(StandardCharsets.UTF_8));
        ClientSSKBlock block =
            ik.encode(
                new BlockEncodeParams(
                    bucket,
                    false,
                    false,
                    (short) -1,
                    bucket.size(),
                    Compressor.DEFAULT_COMPRESSORDESCRIPTOR));
        SSKBlock sskBlock = (SSKBlock) block.getBlock();
        pubkeyCache.cacheKey(
            sskBlock.getKey().getPubKeyHash(),
            sskBlock.getPubKey(),
            false,
            false,
            false,
            false,
            false);
        try {
          store.put(sskBlock, false, false);
        } catch (KeyCollisionException _) {
          fail();
        }

        // Act: start a background push which will block
        FutureTask<Long> future = new FutureTask<>(cachingStore::pushLeastRecentlyBlock);
        try (AutoClosingExecutor pool =
            new AutoClosingExecutor(java.util.concurrent.Executors.newCachedThreadPool())) {
          pool.execute(future);

          delayStore.waitForSomeBlocked();

          // Write a colliding key. Should cause the writing above to return 0: After it
          // unlocks, it will see
          // there is a new, different block for that key, and therefore it cannot remove
          // the block, and
          // thus must return 0.
          test = TEST_1;
          bucket = new SimpleReadOnlyArrayBucket(test.getBytes(StandardCharsets.UTF_8));
          block =
              ik.encode(
                  new BlockEncodeParams(
                      bucket,
                      false,
                      false,
                      (short) -1,
                      bucket.size(),
                      Compressor.DEFAULT_COMPRESSORDESCRIPTOR));

          SSKBlock sskBlock2 = (SSKBlock) block.getBlock();
          try {
            store.put(sskBlock2, false, false);
            fail();
          } catch (KeyCollisionException _) {
            // Expected.
          }
          try {
            store.put(sskBlock2, true, false);
          } catch (KeyCollisionException _) {
            fail();
          }

          // Size is still one key.
          assertEquals(tracker.getSizeOfCache(), sskBlockSize);

          // Act: now let the writing through and assert results
          delayStore.setBlocked(false);

          assertEquals(0L, future.get().longValue());
          NodeSSK key = sskBlock.getKey();
          assertEquals(
              saltStore.fetch(
                  key.getRoutingKey(), key.getFullKey(), false, false, false, false, null),
              sskBlock);
          assertEquals(store.fetch(key, false, false, false, false, null), sskBlock2);

          // Still needs writing.
          assertEquals(cachingStore.pushLeastRecentlyBlock(), sskBlockSize);
          assertEquals(store.fetch(key, false, false, false, false, null), sskBlock2);
        }
      }
    }
  }

  /* Simple test with SSK for CachingFreenetStore */
  @Test
  void putAndFetch_whenSSKInserted_expectCacheHitAndUnderlyingMiss()
      throws IOException,
          KeyCollisionException,
          SSKVerifyException,
          KeyDecodeException,
          SSKEncodeException,
          InvalidCompressionCodecException {
    // Arrange
    final int keys = 5;
    PubkeyStore pk = new PubkeyStore();
    RAMFreenetStore<DSAPublicKey> ramFreenetStore = new RAMFreenetStore<>(pk, keys);
    pk.setStore(ramFreenetStore);

    GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
    SSKStore store = new SSKStore(pubkeyCache);
    File f = getStorePath("testSimpleSSK");
    try (SaltedHashFreenetStore<SSKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, TEST_CACHING_FREENET_STORE_SSK),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(20, true, true, true)))) {
      CachingFreenetStoreTracker tracker =
          new CachingFreenetStoreTracker(
              cachingFreenetStoreMaxSize, cachingFreenetStorePeriod, ticker);
      try (CachingFreenetStore<SSKBlock> cachingStore =
          new CachingFreenetStore<>(store, saltStore, tracker)) {
        cachingStore.start(null, true);
        RandomSource random = new DummyRandomSource(12345);
        // Act
        for (int i = 0; i < 5; i++) {
          String test = "test" + i;
          ClientSSKBlock block = encodeBlockSSK(test, random);
          SSKBlock sskBlock = (SSKBlock) block.getBlock();
          store.put(sskBlock, false, false);

          ClientSSK key = block.getClientKey();
          NodeSSK ssk = (NodeSSK) key.getNodeKey();
          pubkeyCache.cacheKey(
              ssk.getPubKeyHash(), ssk.getPubKey(), false, false, false, false, false);
          // Assert: cache hit, underlying miss
          assertNull(
              saltStore.fetch(
                  ssk.getRoutingKey(), ssk.getFullKey(), false, false, false, false, null));
          SSKBlock verify = store.fetch(ssk, false, false, false, false, null);
          String data = decodeBlockSSK(verify, key);
          assertEquals(test, data);
        }
      }
    }
  }

  /* Test to re-open after close */
  @Test
  void close_whenReopenCHK_expectBlocksPersistedInUnderlying()
      throws IOException, CHKEncodeException, CHKVerifyException, CHKDecodeException {
    // Arrange
    CHKStore store = new CHKStore();
    File f = getStorePath("testOnCloseCHK");
    List<String> tests = new ArrayList<>();
    List<ClientCHKBlock> chkBlocks = new ArrayList<>();
    CachingFreenetStoreTracker tracker =
        new CachingFreenetStoreTracker(
            cachingFreenetStoreMaxSize, cachingFreenetStorePeriod, ticker);

    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, "testCachingFreenetStoreOnClose"),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(10, false, true, true)))) {
      try (CachingFreenetStore<CHKBlock> cachingStore =
          new CachingFreenetStore<>(store, saltStore, tracker)) {
        cachingStore.start(null, true);
        // Act: insert Keys then close store
        for (int i = 0; i < 5; i++) {
          String test = "test" + i;
          ClientCHKBlock block = encodeBlockCHK(test);
          store.put(block.getBlock(), false);
          tests.add(test);
          chkBlocks.add(block);
          // Assert during the write phase: in cache only
          assertNull(
              saltStore.fetch(
                  block.getKey().getRoutingKey(),
                  block.getKey().getFullKey(),
                  false,
                  false,
                  false,
                  false,
                  null));
        }
      }
    }

    store = new CHKStore();
    try (SaltedHashFreenetStore<CHKBlock> saltStore2 =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, "testCachingFreenetStoreOnClose"),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(10, false, true, true)))) {
      try (CachingFreenetStore<CHKBlock> cachingStore =
          new CachingFreenetStore<>(store, saltStore2, tracker)) {
        cachingStore.start(null, true);
        // Assert after reopen: data present in underlying
        boolean atLeastOneKey = false;
        for (int i = 0; i < 5; i++) {
          ClientCHKBlock block = chkBlocks.get(i);
          ClientCHK key = block.getClientKey();
          CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
          // Key might not be present because of collisions in store
          if (verify == null) {
            continue;
          }
          String data = decodeBlockCHK(verify, key);
          String test = tests.get(i);
          assertEquals(test, data);

          // Check it's really in the underlying store
          assertNotNull(
              saltStore2.fetch(
                  block.getKey().getRoutingKey(),
                  block.getKey().getFullKey(),
                  false,
                  false,
                  false,
                  false,
                  null));

          atLeastOneKey = true;
        }
        assertTrue(atLeastOneKey, "Atl least one Key should have been present in the store");
      }
    }
  }

  /* Test whether stuff gets written to disk after the caching period expires */
  @Test
  void pushOffThreadDelayed_whenDelayExpires_expectFlushedToUnderlyingCHK()
      throws IOException,
          CHKEncodeException,
          CHKVerifyException,
          CHKDecodeException,
          InterruptedException {
    // Arrange
    File f = getStorePath("testTimeExpireCHK");
    long delay = 100;

    CHKStore store = new CHKStore();
    try (SaltedHashFreenetStore<CHKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, "testCachingFreenetStoreTimeExpire"),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(10, false, true, true)))) {
      WaitableCachingFreenetStoreTracker tracker =
          new WaitableCachingFreenetStoreTracker(cachingFreenetStoreMaxSize, delay, ticker);
      try (CachingFreenetStore<CHKBlock> cachingStore =
          new CachingFreenetStore<>(store, saltStore, tracker)) {
        cachingStore.start(null, true);
        // Act: put five blocks and wait for a flush
        List<ClientCHKBlock> chkBlocks = new ArrayList<>();
        List<String> tests = new ArrayList<>();

        // Put five chk blocks
        for (int i = 0; i < 5; i++) {
          String test = "test" + i;
          tests.add(test);

          ClientCHKBlock block = encodeBlockCHK(test);
          chkBlocks.add(block);

          store.put(block.getBlock(), false);
          // Check that it's in the cache, *not* the underlying store.
          assertNull(
              saltStore.fetch(
                  block.getKey().getRoutingKey(),
                  block.getKey().getFullKey(),
                  false,
                  false,
                  false,
                  false,
                  null));
        }

        tracker.waitForZero();
        // Assert: at least one key persisted to underlying store
        boolean atLeastOneKey = false;
        for (int i = 0; i < 5; i++) {
          String test = tests.get(i);
          ClientCHKBlock block = chkBlocks.get(i);
          ClientCHK key = block.getClientKey();
          CHKBlock verify = store.fetch(key.getNodeCHK(), false, false, null);
          // Key might not be present because of collisions in store
          if (verify == null) {
            continue;
          }
          String data = decodeBlockCHK(verify, key);
          assertEquals(test, data);
          // Check that it's in the underlying store now.
          assertNotNull(
              saltStore.fetch(
                  block.getKey().getRoutingKey(),
                  block.getKey().getFullKey(),
                  false,
                  false,
                  false,
                  false,
                  null));

          atLeastOneKey = true;
        }
        assertTrue(atLeastOneKey, "Atl least one Key should have been present in the store");
      }
    }
  }

  /* Test with SSK to re-open after close */
  @Test
  void close_whenReopenSSK_expectBlocksPersistedInUnderlying()
      throws IOException,
          SSKEncodeException,
          InvalidCompressionCodecException,
          KeyCollisionException,
          SSKVerifyException,
          KeyDecodeException {
    // Arrange
    File f = getStorePath("testOnCloseSSK");

    final int keys = 5;
    PubkeyStore pk = new PubkeyStore();
    RAMFreenetStore<DSAPublicKey> ramFreenetStore = new RAMFreenetStore<>(pk, keys);
    pk.setStore(ramFreenetStore);
    GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
    SSKStore store = new SSKStore(pubkeyCache);

    List<ClientSSKBlock> sskBlocks = new ArrayList<>();
    List<String> tests = new ArrayList<>();
    CachingFreenetStoreTracker tracker =
        new CachingFreenetStoreTracker(
            cachingFreenetStoreMaxSize, cachingFreenetStorePeriod, ticker);

    try (SaltedHashFreenetStore<SSKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, TEST_CACHING_FREENET_STORE_ON_CLOSE_SSK),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(10, false, true, true)))) {
      try (CachingFreenetStore<SSKBlock> cachingStore =
          new CachingFreenetStore<>(store, saltStore, tracker)) {
        cachingStore.start(null, true);
        RandomSource random = new DummyRandomSource(12345);

        for (int i = 0; i < 5; i++) {
          String test = "test" + i;
          ClientSSKBlock block = encodeBlockSSK(test, random);
          SSKBlock sskBlock = (SSKBlock) block.getBlock();
          store.put(sskBlock, false, false);
          pubkeyCache.cacheKey(
              sskBlock.getKey().getPubKeyHash(),
              sskBlock.getKey().getPubKey(),
              false,
              false,
              false,
              false,
              false);
          tests.add(test);
          sskBlocks.add(block);
        }
      }
    }

    try (SaltedHashFreenetStore<SSKBlock> saltStore2 =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, TEST_CACHING_FREENET_STORE_ON_CLOSE_SSK),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(10, false, true, true)))) {
      try (CachingFreenetStore<SSKBlock> cachingStore =
          new CachingFreenetStore<>(store, saltStore2, tracker)) {
        cachingStore.start(null, true);
        // Assert after reopen: data present in underlying
        boolean atLeastOneKey = false;
        for (int i = 0; i < 5; i++) {
          String test = tests.removeFirst(); // get the first element
          ClientSSKBlock block = sskBlocks.removeFirst(); // get the first element
          ClientSSK key = block.getClientKey();
          NodeSSK ssk = (NodeSSK) key.getNodeKey();
          SSKBlock verify = store.fetch(ssk, false, false, false, false, null);
          // Key might not be present, because of collisions in the store
          if (verify == null) {
            continue;
          }
          String data = decodeBlockSSK(verify, key);
          assertEquals(test, data);
          // Check that it's in the underlying store now.
          assertNotNull(
              saltStore2.fetch(
                  block.getKey().getRoutingKey(),
                  block.getKey().getFullKey(),
                  false,
                  false,
                  false,
                  false,
                  null));

          atLeastOneKey = true;
        }
        assertTrue(atLeastOneKey, "At least on key should have been present");
      }
    }
  }

  /*
   * Test with SSK whether stuff gets written to disk after the caching period
   * expires
   */
  @Test
  void pushOffThreadDelayed_whenDelayExpires_expectFlushedToUnderlyingSSK()
      throws IOException,
          SSKEncodeException,
          InvalidCompressionCodecException,
          KeyCollisionException,
          SSKVerifyException,
          KeyDecodeException,
          InterruptedException {
    // Arrange
    File f = getStorePath("testTimeExpireSSK");

    final int keys = 5;
    PubkeyStore pk = new PubkeyStore();
    RAMFreenetStore<DSAPublicKey> ramFreenetStore = new RAMFreenetStore<>(pk, keys);
    pk.setStore(ramFreenetStore);
    GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
    SSKStore store = new SSKStore(pubkeyCache);

    try (SaltedHashFreenetStore<SSKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, TEST_CACHING_FREENET_STORE_ON_CLOSE_SSK),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(10, true, true, true)))) {
      WaitableCachingFreenetStoreTracker tracker =
          new WaitableCachingFreenetStoreTracker(cachingFreenetStoreMaxSize, 100, ticker);
      try (CachingFreenetStore<SSKBlock> cachingStore =
          new CachingFreenetStore<>(store, saltStore, tracker)) {
        cachingStore.start(null, true);
        RandomSource random = new DummyRandomSource(12345);
        // Act: enqueue blocks and wait for the tracker to flush
        List<ClientSSKBlock> sskBlocks = new ArrayList<>();
        List<String> tests = new ArrayList<>();

        for (int i = 0; i < 5; i++) {
          String test = "test" + i;
          ClientSSKBlock block = encodeBlockSSK(test, random);
          SSKBlock sskBlock = (SSKBlock) block.getBlock();
          store.put(sskBlock, false, false);
          pubkeyCache.cacheKey(
              sskBlock.getKey().getPubKeyHash(),
              sskBlock.getKey().getPubKey(),
              false,
              false,
              false,
              false,
              false);
          tests.add(test);
          sskBlocks.add(block);
        }

        tracker.waitForZero();
        // Assert: at least one key persisted to underlying store
        boolean atLeastOneKey = false;
        for (int i = 0; i < 5; i++) {
          String test = tests.get(i);
          ClientSSKBlock block = sskBlocks.get(i);
          ClientSSK key = block.getClientKey();
          NodeSSK ssk = (NodeSSK) key.getNodeKey();
          SSKBlock verify = store.fetch(ssk, false, false, false, false, null);
          if (verify == null) {
            continue;
          }
          String data = decodeBlockSSK(verify, key);
          assertEquals(test, data);
          // Check that it's in the underlying store now.
          assertNotNull(
              saltStore.fetch(
                  block.getKey().getRoutingKey(),
                  block.getKey().getFullKey(),
                  false,
                  false,
                  false,
                  false,
                  null));

          atLeastOneKey = true;
        }
        assertTrue(atLeastOneKey, "At least one key should have been present");
      }
    }
  }

  @Test
  void collisions_whenUseSlotFilter_expectCacheComparisonNoThrow()
      throws IOException,
          SSKEncodeException,
          InvalidCompressionCodecException,
          SSKVerifyException,
          KeyDecodeException,
          KeyCollisionException {
    // Arrange/Act/Assert: helper covers AAA with useSlotFilter=true.
    // With slot filters on, it should be cached and not thrown if they're the same block.
    checkOnCollisionsSSK(true);
  }

  @Test
  void collisions_whenDontUseSlotFilter_expectWriteThrough()
      throws IOException,
          SSKEncodeException,
          InvalidCompressionCodecException,
          SSKVerifyException,
          KeyDecodeException,
          KeyCollisionException {
    // Arrange/Act/Assert: helper covers AAA with useSlotFilter=false.
    // With slot filters off, it goes straight to disk (probablyInStore() true).
    checkOnCollisionsSSK(false);
  }

  private File getStorePath(String testname) {
    File storePath = new File(TEMP_DIR, "CachingFreenetStoreTest_" + testname);
    FileUtil.removeAll(storePath);
    if (!storePath.mkdirs()) {
      throw new IllegalStateException("Could not create temporary test store path: " + storePath);
    }
    return storePath;
  }

  // Common helper with constants used by the simple CHK tests
  private <T extends StorableBlock> SaltedHashFreenetStore<T> newSaltedHashStore(
      File dir, StoreCallback<T> frontStore) throws IOException {
    SaltedHashStoreParams<T> params =
        SaltedHashStoreParams.of(
            new SaltedHashStoreLocation(dir, "testCachingFreenetStoreCHK"),
            new SaltedHashStoreDependencies<>(
                frontStore, weakPRNG, SemiOrderedShutdownHook.get(), null),
            new SaltedHashStoreSizing(10L, false, true, true));
    return SaltedHashFreenetStore.construct(params);
  }

  private CachingFreenetStoreTracker newTracker(long maxSize) {
    return new CachingFreenetStoreTracker(maxSize, cachingFreenetStorePeriod, ticker);
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

  /* Test collisions on SSK */
  private void checkOnCollisionsSSK(boolean useSlotFilter)
      throws IOException,
          SSKEncodeException,
          InvalidCompressionCodecException,
          SSKVerifyException,
          KeyDecodeException,
          KeyCollisionException {

    FileUtil.removeAll(TEMP_DIR);

    final int keys = 5;
    PubkeyStore pk = new PubkeyStore();
    RAMFreenetStore<DSAPublicKey> ramFreenetStore = new RAMFreenetStore<>(pk, keys);
    pk.setStore(ramFreenetStore);
    GetPubkey pubkeyCache = new SimpleGetPubkey(pk);
    SSKStore store = new SSKStore(pubkeyCache);
    File f = getStorePath("checkOnCollisionsSSK");

    try (SaltedHashFreenetStore<SSKBlock> saltStore =
        SaltedHashFreenetStore.construct(
            SaltedHashStoreParams.of(
                new SaltedHashStoreLocation(f, TEST_CACHING_FREENET_STORE_ON_CLOSE_SSK),
                new SaltedHashStoreDependencies<>(
                    store, weakPRNG, SemiOrderedShutdownHook.get(), null),
                new SaltedHashStoreSizing(10, useSlotFilter, true, true)))) {
      CachingFreenetStoreTracker tracker =
          new CachingFreenetStoreTracker(
              cachingFreenetStoreMaxSize, cachingFreenetStorePeriod, ticker);
      try (CachingFreenetStore<SSKBlock> cachingStore =
          new CachingFreenetStore<>(store, saltStore, tracker)) {
        cachingStore.start(null, true);
        RandomSource random = new DummyRandomSource(12345);

        final int CRYPTO_KEY_LENGTH = 32;
        byte[] ckey = new byte[CRYPTO_KEY_LENGTH];
        random.nextBytes(ckey);
        DSAGroup g = Global.DSAgroupBigA;
        DSAPrivateKey privKey = new DSAPrivateKey(g, random);
        DSAPublicKey pubKey = new DSAPublicKey(g, privKey);
        byte[] pkHash = SHA256.digest(pubKey.asBytes());
        InsertableClientSSK ik =
            new InsertableClientSSK(
                DOC_NAME, pkHash, pubKey, privKey, ckey, Key.ALGO_AES_PCFB_256_SHA256);

        String test = "test";
        SimpleReadOnlyArrayBucket bucket =
            new SimpleReadOnlyArrayBucket(test.getBytes(StandardCharsets.UTF_8));
        ClientSSKBlock block =
            ik.encode(
                new BlockEncodeParams(
                    bucket,
                    false,
                    false,
                    (short) -1,
                    bucket.size(),
                    Compressor.DEFAULT_COMPRESSORDESCRIPTOR));
        SSKBlock sskBlock = (SSKBlock) block.getBlock();
        store.put(sskBlock, false, false);

        // If the block is the same, then there should not be a collision
        try {
          store.put(sskBlock, false, false);
          assertTrue(true);
        } catch (KeyCollisionException _) {
          fail();
        }

        SimpleReadOnlyArrayBucket bucket1 =
            new SimpleReadOnlyArrayBucket(TEST_1.getBytes(StandardCharsets.UTF_8));
        ClientSSKBlock block1 =
            ik.encode(
                new BlockEncodeParams(
                    bucket1,
                    false,
                    false,
                    (short) -1,
                    bucket1.size(),
                    Compressor.DEFAULT_COMPRESSORDESCRIPTOR));
        SSKBlock sskBlock1 = (SSKBlock) block1.getBlock();

        // if it's different (e.g., different content, same key), there should be a KCE
        // thrown
        try {
          store.put(sskBlock1, false, false);
          fail();
        } catch (KeyCollisionException _) {
          assertTrue(true);
        }

        // if overwrite is set, then no collision should be thrown
        try {
          store.put(sskBlock1, true, false);
          assertTrue(true);
        } catch (KeyCollisionException _) {
          fail();
        }

        ClientSSK key = block1.getClientKey();
        pubkeyCache.cacheKey(
            sskBlock.getKey().getPubKeyHash(),
            sskBlock.getKey().getPubKey(),
            false,
            false,
            false,
            false,
            false);
        NodeSSK ssk = (NodeSSK) key.getNodeKey();
        SSKBlock verify = store.fetch(ssk, false, false, false, false, null);
        String data = decodeBlockSSK(verify, key);
        assertEquals(TEST_1, data);

        if (useSlotFilter) {
          // Check that it's in the cache
          assertNull(
              saltStore.fetch(
                  block.getKey().getRoutingKey(),
                  block.getKey().getFullKey(),
                  false,
                  false,
                  false,
                  false,
                  null));
        } else {
          // Check that it's in the underlying store now.
          assertNotNull(
              saltStore.fetch(
                  block.getKey().getRoutingKey(),
                  block.getKey().getFullKey(),
                  false,
                  false,
                  false,
                  false,
                  null));
        }
      }
    }
  }

  private String decodeBlockSSK(SSKBlock verify, ClientSSK key)
      throws SSKVerifyException, KeyDecodeException, IOException {
    ClientSSKBlock cb = ClientSSKBlock.construct(verify, key);
    Bucket output = cb.decode(new ArrayBucketFactory(), 32768, false);
    byte[] buf = BucketTools.toByteArray(output);
    return new String(buf, StandardCharsets.UTF_8);
  }

  private ClientSSKBlock encodeBlockSSK(String test, RandomSource random)
      throws IOException, SSKEncodeException, InvalidCompressionCodecException {
    byte[] data = test.getBytes(StandardCharsets.UTF_8);
    SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data);
    InsertableClientSSK ik = InsertableClientSSK.createRandom(random, test);
    return ik.encode(
        new BlockEncodeParams(
            bucket,
            false,
            false,
            (short) -1,
            bucket.size(),
            Compressor.DEFAULT_COMPRESSORDESCRIPTOR));
  }

  static class WaitableCachingFreenetStoreTracker extends CachingFreenetStoreTracker {
    public WaitableCachingFreenetStoreTracker(
        long cachingFreenetStoreMaxSize, long cachingFreenetStorePeriod, Ticker ticker) {
      super(cachingFreenetStoreMaxSize, cachingFreenetStorePeriod, ticker);
    }

    public void waitForZero() throws InterruptedException {
      synchronized (sync) {
        long observedPushGeneration = pushGeneration;
        while (getSizeOfCache() > 0) {
          while (getSizeOfCache() > 0 && observedPushGeneration == pushGeneration) {
            sync.wait();
          }
          observedPushGeneration = pushGeneration;
        }
      }
    }

    @Override
    void pushAllCachingStores() {
      super.pushAllCachingStores();
      synchronized (sync) {
        pushGeneration++;
        sync.notifyAll();
      }
    }

    /* Don't reuse (this), avoid changing locking behavior of the parent class */
    private final Object sync = new Object();
    private long pushGeneration;
  }

  private static final File TEMP_DIR = new File("tmp-CachingFreenetStoreTest");
  private static final String TEST_CACHING_FREENET_STORE_SSK = "testCachingFreenetStoreSSK";
  private static final String TEST_CACHING_FREENET_STORE_ON_CLOSE_SSK =
      "testCachingFreenetStoreOnCloseSSK";
  private static final String DOC_NAME = "myDOC";
  private static final String TEST_1 = "test1";
  private final SecureRandom weakPRNG = new SecureRandom();
  private final PooledExecutor exec = new PooledExecutor();
  private final Ticker ticker = new TrivialTicker(exec);
  private final long cachingFreenetStoreMaxSize = Fields.parseLong("1M");
  private final long cachingFreenetStorePeriod = Fields.parseLong("300k");

  // ------------------------------------------------------------
  // Lightweight, Mockito-based unit tests for CachingFreenetStore
  // ------------------------------------------------------------

  // Simple concrete block used by the Mockito-focused tests in this class
  private static final class TestBlock implements StorableBlock {
    private final byte[] routingKey;
    private final byte[] fullKey;

    private TestBlock(byte[] routingKey, byte[] fullKey) {
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

    @Override
    @SuppressWarnings("RedundantMethodOverride")
    public boolean equals(Object other) {
      return this == other;
    }

    @Override
    public int hashCode() {
      return System.identityHashCode(this);
    }

    @Override
    public @NonNull String toString() {
      return "TestBlock{routingKey="
          + Arrays.toString(routingKey)
          + ", fullKey="
          + Arrays.toString(fullKey)
          + "}";
    }
  }

  // AutoCloseable wrapper for ExecutorService so we can use try-with-resources
  private static final class AutoClosingExecutor implements AutoCloseable {
    private final java.util.concurrent.ExecutorService delegate;

    AutoClosingExecutor(java.util.concurrent.ExecutorService delegate) {
      this.delegate = delegate;
    }

    void execute(Runnable task) {
      delegate.execute(task);
    }

    @Override
    public void close() {
      delegate.shutdownNow();
    }
  }

  private static int totalSize(byte[] data, byte[] header, byte[] fullKey, byte[] routingKey) {
    return data.length + header.length + fullKey.length + routingKey.length;
  }

  @Test
  void fetch_whenCacheHit_constructsAndReturns() throws Exception {
    // Arrange
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    byte[] rk = new byte[] {1, 2, 3};
    byte[] fk = new byte[] {9, 9};
    byte[] data = new byte[] {10, 11, 12, 13};
    byte[] header = new byte[] {5, 6};
    TestBlock block = new TestBlock(rk, fk);
    TestBlock constructed = new TestBlock(rk, fk);

    when(callback.getTotalBlockSize()).thenReturn(totalSize(data, header, fk, rk));
    when(callback.collisionPossible()).thenReturn(false);
    when(tracker.add(org.mockito.ArgumentMatchers.anyLong())).thenReturn(true);

    // Broad stub for construct; verify arguments later via captors
    org.mockito.Mockito.doReturn(constructed)
        .when(callback)
        .construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any());

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);

    // Cache one entry via put (should not write through)
    store.put(block, data, header, false, false);
    verify(back, never()).put(any(), any(), any(), anyBoolean(), anyBoolean());

    // Act
    TestBlock fetched = store.fetch(rk, null, false, false, false, false, null);

    // Assert
    assertEquals(constructed, fetched);
    // Ensure construct() saw the routingKey we requested and the cached fullKey
    ArgumentCaptor<StoreCallback.BlockPayload> payloadCap =
        ArgumentCaptor.forClass(StoreCallback.BlockPayload.class);
    ArgumentCaptor<StoreCallback.ConstructOptions> optionsCap =
        ArgumentCaptor.forClass(StoreCallback.ConstructOptions.class);
    verify(callback, times(1))
        .construct(
            payloadCap.capture(), optionsCap.capture(), org.mockito.ArgumentMatchers.isNull());
    org.junit.jupiter.api.Assertions.assertArrayEquals(rk, payloadCap.getValue().routingKey());
    org.junit.jupiter.api.Assertions.assertArrayEquals(fk, payloadCap.getValue().fullKey());
    assertArrayEquals(data, payloadCap.getValue().data());
    assertArrayEquals(header, payloadCap.getValue().headers());
    assertFalse(optionsCap.getValue().canReadClientCache());
    assertFalse(optionsCap.getValue().canReadSlashdotCache());
    assertNull(optionsCap.getValue().meta());
    verify(back, never())
        .fetch(any(), any(), anyBoolean(), anyBoolean(), anyBoolean(), anyBoolean(), any());
  }

  @Test
  void fetch_whenCacheHit_constructThrows_fallsBackToDelegate() throws Exception {
    // Arrange
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    byte[] rk = new byte[] {42};
    byte[] fk = new byte[] {7, 7};
    byte[] data = new byte[] {1};
    byte[] header = new byte[] {2};
    TestBlock block = new TestBlock(rk, fk);
    TestBlock delegateResult = new TestBlock(rk, fk);

    when(callback.getTotalBlockSize()).thenReturn(totalSize(data, header, fk, rk));
    when(callback.collisionPossible()).thenReturn(false);
    when(tracker.add(org.mockito.ArgumentMatchers.anyLong())).thenReturn(true);
    when(callback.construct(
            any(StoreCallback.BlockPayload.class),
            any(StoreCallback.ConstructOptions.class),
            any()))
        .thenThrow(new network.crypta.keys.KeyVerifyException("boom"));
    when(back.fetch(
            eq(rk),
            org.mockito.ArgumentMatchers.isNull(),
            eq(new FetchOptions(false, false, false, false, null))))
        .thenReturn(delegateResult);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    store.put(block, data, header, false, false);

    // Act
    TestBlock out = store.fetch(rk, null, false, false, false, false, null);

    // Assert
    assertEquals(delegateResult, out);
    verify(back, times(1))
        .fetch(
            eq(rk),
            org.mockito.ArgumentMatchers.isNull(),
            eq(new FetchOptions(false, false, false, false, null)));
  }

  @Test
  void fetch_whenCacheMiss_delegatesToBack() throws Exception {
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    byte[] rk = new byte[] {4, 5};
    TestBlock delegateResult = new TestBlock(rk, new byte[] {0});
    when(back.fetch(
            eq(rk),
            org.mockito.ArgumentMatchers.isNull(),
            eq(new FetchOptions(false, false, false, false, null))))
        .thenReturn(delegateResult);
    when(callback.getTotalBlockSize()).thenReturn(0);
    when(callback.collisionPossible()).thenReturn(false);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    TestBlock out = store.fetch(rk, null, false, false, false, false, null);
    assertEquals(delegateResult, out);
    verify(back, times(1))
        .fetch(
            eq(rk),
            org.mockito.ArgumentMatchers.isNull(),
            eq(new FetchOptions(false, false, false, false, null)));
  }

  @Test
  void probablyInStore_whenCached_returnsTrueWithoutDelegate() throws Exception {
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    byte[] rk = new byte[] {1};
    byte[] fk = new byte[] {2};
    byte[] data = new byte[] {3};
    byte[] header = new byte[] {};

    when(callback.getTotalBlockSize()).thenReturn(totalSize(data, header, fk, rk));
    when(callback.collisionPossible()).thenReturn(false);
    when(tracker.add(org.mockito.ArgumentMatchers.anyLong())).thenReturn(true);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    store.put(new TestBlock(rk, fk), data, header, false, false);

    assertTrue(store.probablyInStore(rk));
    verify(back, never()).probablyInStore(any());
  }

  @Test
  void probablyInStore_whenNotCached_delegates() {
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    byte[] rk = new byte[] {1};
    when(callback.getTotalBlockSize()).thenReturn(0);
    when(callback.collisionPossible()).thenReturn(false);
    when(back.probablyInStore(rk)).thenReturn(true);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    assertTrue(store.probablyInStore(rk));
    verify(back, times(1)).probablyInStore(rk);
  }

  @Test
  void put_whenCollisionNotPossibleAndAddedToCache_doesNotWriteThrough() throws Exception {
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    byte[] rk = new byte[] {8};
    byte[] fk = new byte[] {9};
    byte[] data = new byte[] {10};
    byte[] header = new byte[] {11};

    when(callback.getTotalBlockSize()).thenReturn(totalSize(data, header, fk, rk));
    when(callback.collisionPossible()).thenReturn(false);
    when(tracker.add(org.mockito.ArgumentMatchers.anyLong())).thenReturn(true);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    assertTrue(store.isEmpty());
    store.put(new TestBlock(rk, fk), data, header, false, false);
    verify(back, never()).put(any(), any(), any(), anyBoolean(), anyBoolean());
    assertFalse(store.isEmpty());
  }

  @Test
  void put_whenTrackerRejects_writeThroughAndSkipCache() throws Exception {
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    byte[] rk = new byte[] {1};
    byte[] fk = new byte[] {2};
    byte[] data = new byte[] {3};
    byte[] header = new byte[] {};

    when(callback.getTotalBlockSize()).thenReturn(totalSize(data, header, fk, rk));
    when(callback.collisionPossible()).thenReturn(false);
    when(tracker.add(org.mockito.ArgumentMatchers.anyLong())).thenReturn(false);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    store.put(new TestBlock(rk, fk), data, header, false, false);
    verify(back, times(1)).put(any(), eq(data), eq(header), eq(false), eq(false));
    assertTrue(store.isEmpty());
  }

  @Test
  void put_whenCollisionPossible_andSameBlockAlreadyCached_noop() throws Exception {
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    byte[] rk = new byte[] {1};
    byte[] fk = new byte[] {2};
    byte[] data = new byte[] {3};
    byte[] header = new byte[] {};
    TestBlock same = new TestBlock(rk, fk);

    when(callback.getTotalBlockSize()).thenReturn(totalSize(data, header, fk, rk));
    when(callback.collisionPossible()).thenReturn(true);
    when(tracker.add(org.mockito.ArgumentMatchers.anyLong())).thenReturn(true);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    store.put(same, data, header, false, false);
    // Second put with same instance should no-op (no collision, no write-through)
    store.put(same, data, header, false, false);
    verify(back, never()).put(any(), any(), any(), anyBoolean(), anyBoolean());
  }

  @Test
  void put_whenCollisionPossible_andDifferentInstanceWithSameKey_throwsKCE() throws Exception {
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    byte[] rk = new byte[] {1};
    byte[] fk = new byte[] {2};
    byte[] data = new byte[] {3};
    byte[] header = new byte[] {};
    TestBlock first = new TestBlock(rk, fk);
    TestBlock secondDifferentInstance = new TestBlock(rk, fk);

    when(callback.getTotalBlockSize()).thenReturn(totalSize(data, header, fk, rk));
    when(callback.collisionPossible()).thenReturn(true);
    when(tracker.add(org.mockito.ArgumentMatchers.anyLong())).thenReturn(true);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    store.put(first, data, header, false, false);
    assertThrows(
        KeyCollisionException.class,
        () -> store.put(secondDifferentInstance, data, header, false, false));
  }

  @Test
  void put_whenCollisionPossible_andProbablyInStoreTrue_writeThrough() throws Exception {
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    byte[] rk = new byte[] {1};
    byte[] fk = new byte[] {2};
    byte[] data = new byte[] {3};
    byte[] header = new byte[] {};

    when(callback.getTotalBlockSize()).thenReturn(totalSize(data, header, fk, rk));
    when(callback.collisionPossible()).thenReturn(true);
    when(back.probablyInStore(rk)).thenReturn(true);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    store.put(new TestBlock(rk, fk), data, header, false, false);
    verify(back, times(1)).put(any(), eq(data), eq(header), eq(false), eq(false));
    assertTrue(store.isEmpty());
  }

  @Test
  void put_whenCollisionPossible_andProbablyInStoreFalse_addTrue_caches() throws Exception {
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    byte[] rk = new byte[] {1};
    byte[] fk = new byte[] {2};
    byte[] data = new byte[] {3};
    byte[] header = new byte[] {};

    when(callback.getTotalBlockSize()).thenReturn(totalSize(data, header, fk, rk));
    when(callback.collisionPossible()).thenReturn(true);
    when(back.probablyInStore(rk)).thenReturn(false);
    when(tracker.add(org.mockito.ArgumentMatchers.anyLong())).thenReturn(true);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    store.put(new TestBlock(rk, fk), data, header, false, false);
    verify(back, never()).put(any(), any(), any(), anyBoolean(), anyBoolean());
    assertFalse(store.isEmpty());
  }

  @Test
  void pushLeastRecentlyBlock_whenEmpty_returnsMinusOne() {
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    when(callback.getTotalBlockSize()).thenReturn(0);
    when(callback.collisionPossible()).thenReturn(false);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    assertEquals(-1, store.pushLeastRecentlyBlock());
  }

  @Test
  void pushLeastRecentlyBlock_whenHasEntry_writesThroughAndEvicts() throws Exception {
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    byte[] rk = new byte[] {1};
    byte[] fk = new byte[] {2};
    byte[] data = new byte[] {3, 4};
    byte[] header = new byte[] {5};
    int size = totalSize(data, header, fk, rk);

    when(callback.getTotalBlockSize()).thenReturn(size);
    when(callback.collisionPossible()).thenReturn(false);
    when(tracker.add(org.mockito.ArgumentMatchers.anyLong())).thenReturn(true);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    store.put(new TestBlock(rk, fk), data, header, false, false);
    long written = store.pushLeastRecentlyBlock();
    assertEquals(size, written);
    verify(back, times(1)).put(any(), eq(data), eq(header), eq(false), eq(false));
    assertTrue(store.isEmpty());
  }

  @Test
  void pushLeastRecentlyBlock_whenBlockChangedDuringWrite_returnsZeroAndKeepsCached()
      throws Exception {
    // Arrange
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    byte[] rk = new byte[] {1};
    byte[] fkA = new byte[] {2};
    byte[] fkB = new byte[] {3};
    byte[] dataA = new byte[] {10};
    byte[] headerA = new byte[] {};
    byte[] dataB = new byte[] {11};
    byte[] headerB = new byte[] {12};
    int size = totalSize(dataA, headerA, fkA, rk);

    when(callback.getTotalBlockSize()).thenReturn(size);
    when(callback.collisionPossible()).thenReturn(false);
    when(tracker.add(org.mockito.ArgumentMatchers.anyLong())).thenReturn(true);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    TestBlock a = new TestBlock(rk, fkA);
    store.put(a, dataA, headerA, false, false);

    // While pushLeastRecentlyBlock() calls delegate.put(a,...), replace the cached block with b
    doAnswer(
            _ -> {
              // Simulate overwriting happening while write is in progress
              TestBlock b = new TestBlock(rk, fkB);
              store.put(b, dataB, headerB, true, false);
              return null;
            })
        .when(back)
        .put(a, dataA, headerA, false, false);

    // Act
    long result = store.pushLeastRecentlyBlock();

    // Assert: changed during writing => return 0 and keep cached entry
    assertEquals(0, result);
    assertFalse(store.isEmpty());
  }

  @Test
  void start_whenCalled_registersWithTracker_andDelegates() throws Exception {
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);
    when(callback.getTotalBlockSize()).thenReturn(0);
    when(callback.collisionPossible()).thenReturn(false);
    when(back.start(org.mockito.ArgumentMatchers.isNull(), eq(true))).thenReturn(true);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    boolean ok = store.start(null, true);
    assertTrue(ok);
    verify(tracker, times(1)).registerCachingFS(store);
    verify(back, times(1)).start(org.mockito.ArgumentMatchers.isNull(), eq(true));
  }

  @Test
  void close_idempotent_unregistersAndClosesOnce_andWriteThroughAfterClose() throws Exception {
    @SuppressWarnings("unchecked")
    StoreCallback<TestBlock> callback =
        (StoreCallback<TestBlock>) org.mockito.Mockito.mock(StoreCallback.class);
    @SuppressWarnings("unchecked")
    FreenetStore<TestBlock> back =
        (FreenetStore<TestBlock>) org.mockito.Mockito.mock(FreenetStore.class);
    CachingFreenetStoreTracker tracker = org.mockito.Mockito.mock(CachingFreenetStoreTracker.class);

    when(callback.getTotalBlockSize()).thenReturn(0);
    when(callback.collisionPossible()).thenReturn(false);

    CachingFreenetStore<TestBlock> store = new CachingFreenetStore<>(callback, back, tracker);
    store.close();
    store.close();
    verify(back, times(1)).close();
    verify(tracker, times(1)).unregisterCachingFS(store);

    // After close, put should not cache and must write through
    byte[] rk = new byte[] {1};
    byte[] fk = new byte[] {2};
    byte[] data = new byte[] {3};
    byte[] header = new byte[] {};
    store.put(new TestBlock(rk, fk), data, header, false, false);
    verify(back, times(1)).put(any(), eq(data), eq(header), eq(false), eq(false));
  }
}
